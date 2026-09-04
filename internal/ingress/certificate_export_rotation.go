package ingress

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

// PublicCertificateExportRotation is one bounded public-only file snapshot.
// Private key material never enters this object.
type PublicCertificateExportRotation struct {
	mu sync.Mutex

	destination    string
	temporary      string
	previous       []byte
	candidate      []byte
	previousExists bool
	activated      bool
	closed         bool
}

func (*PublicCertificateExportRotation) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func PreparePublicCertificateExportRotation(
	before model.State,
	candidate model.State,
	secrets PublicCertificateSecretStore,
	destination string,
) (*PublicCertificateExportRotation, error) {
	if secrets == nil {
		return nil, fmt.Errorf("public certificate source is required")
	}
	if destination == "" || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return nil, fmt.Errorf("%w: destination must be a clean absolute path", ErrPublicCertificateUnsafePath)
	}
	if err := before.Validate(); err != nil {
		return nil, fmt.Errorf("validate prior public certificate state: %w", err)
	}
	if err := model.ValidateTransition(before, candidate); err != nil {
		return nil, fmt.Errorf("validate public certificate rotation state: %w", err)
	}
	current, err := publicCertificateRecord(before)
	if err != nil {
		return nil, err
	}
	next, err := publicCertificateRecord(candidate)
	if err != nil {
		return nil, err
	}
	wantGeneration, generationErr := model.NextGeneration(current.Generation)
	if generationErr != nil || next.ID != current.ID || next.Kind != current.Kind || next.OwnerKind != current.OwnerKind ||
		next.OwnerID != current.OwnerID || next.Generation != wantGeneration {
		return nil, fmt.Errorf("%w: certificate rotation identity or generation is invalid", ErrPublicCertificateInvalid)
	}
	currentPEM, err := secrets.Get(model.SecretRef(current.CertificateRef))
	if err != nil {
		return nil, fmt.Errorf("read prior public ingress certificate: %w", err)
	}
	defer clear(currentPEM)
	if _, err := ValidatePublicCertificatePEM(currentPEM, current, before.Host.PublicIPv4); err != nil {
		return nil, err
	}
	nextPEM, err := secrets.Get(model.SecretRef(next.CertificateRef))
	if err != nil {
		return nil, fmt.Errorf("read candidate public ingress certificate: %w", err)
	}
	defer clear(nextPEM)
	if _, err := ValidatePublicCertificatePEM(nextPEM, next, candidate.Host.PublicIPv4); err != nil {
		return nil, err
	}

	previous, previousExists, err := readExpectedPublicCertificateExport(destination, currentPEM)
	if err != nil {
		return nil, err
	}
	temporary, err := stagePublicCertificateReplacement(destination, nextPEM)
	if err != nil {
		return nil, err
	}
	return &PublicCertificateExportRotation{
		destination: destination, temporary: temporary,
		previous: previous, candidate: append([]byte(nil), nextPEM...), previousExists: previousExists,
	}, nil
}

func (rotation *PublicCertificateExportRotation) Activate() error {
	if rotation == nil {
		return fmt.Errorf("public certificate export rotation is required")
	}
	rotation.mu.Lock()
	defer rotation.mu.Unlock()
	if rotation.closed || rotation.activated || rotation.temporary == "" {
		return fmt.Errorf("public certificate export rotation is not activatable")
	}
	if err := verifyPublicCertificateExportSnapshot(rotation.destination, rotation.previous, rotation.previousExists); err != nil {
		return err
	}
	if err := os.Rename(rotation.temporary, rotation.destination); err != nil {
		return fmt.Errorf("activate public certificate export: %w", err)
	}
	rotation.temporary = ""
	rotation.activated = true
	if err := syncPublicCertificateDirectory(filepath.Dir(rotation.destination)); err != nil {
		return fmt.Errorf("sync public certificate export directory: %w", err)
	}
	return nil
}

func (rotation *PublicCertificateExportRotation) Rollback() error {
	if rotation == nil {
		return fmt.Errorf("public certificate export rotation is required")
	}
	rotation.mu.Lock()
	defer rotation.mu.Unlock()
	if rotation.closed {
		return nil
	}
	if !rotation.activated {
		return rotation.abortLocked()
	}
	if err := verifyPublicCertificateExportSnapshot(rotation.destination, rotation.candidate, true); err != nil {
		return fmt.Errorf("refuse public certificate export rollback: %w", err)
	}
	if rotation.previousExists {
		temporary, err := stagePublicCertificateReplacement(rotation.destination, rotation.previous)
		if err != nil {
			return err
		}
		if err := os.Rename(temporary, rotation.destination); err != nil {
			_ = os.Remove(temporary)
			return fmt.Errorf("restore public certificate export: %w", err)
		}
	} else if err := os.Remove(rotation.destination); err != nil {
		return fmt.Errorf("remove rotated public certificate export: %w", err)
	}
	rotation.closed = true
	if err := syncPublicCertificateDirectory(filepath.Dir(rotation.destination)); err != nil {
		return fmt.Errorf("sync restored public certificate export directory: %w", err)
	}
	return nil
}

func (rotation *PublicCertificateExportRotation) Abort() error {
	if rotation == nil {
		return nil
	}
	rotation.mu.Lock()
	defer rotation.mu.Unlock()
	return rotation.abortLocked()
}

func (rotation *PublicCertificateExportRotation) abortLocked() error {
	if rotation.closed {
		return nil
	}
	if rotation.activated {
		return fmt.Errorf("activated public certificate export requires rollback")
	}
	if rotation.temporary != "" {
		if err := os.Remove(rotation.temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove staged public certificate export: %w", err)
		}
		rotation.temporary = ""
	}
	rotation.closed = true
	return nil
}

func readExpectedPublicCertificateExport(destination string, current []byte) ([]byte, bool, error) {
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect public certificate export: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > publicCertificateMaximumBytes {
		return nil, false, fmt.Errorf("%w: existing public certificate export is unsafe", ErrPublicCertificateUnsafePath)
	}
	existing, err := os.ReadFile(destination)
	if err != nil {
		return nil, false, fmt.Errorf("read public certificate export: %w", err)
	}
	if !bytes.Equal(existing, current) {
		return nil, false, fmt.Errorf("%w: %s", ErrPublicCertificateExported, destination)
	}
	return existing, true, nil
}

func verifyPublicCertificateExportSnapshot(destination string, expected []byte, exists bool) error {
	info, err := os.Lstat(destination)
	if !exists && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("public certificate export changed before activation: %w", err)
	}
	if !exists || !info.Mode().IsRegular() || info.Size() != int64(len(expected)) {
		return fmt.Errorf("%w: public certificate export changed before activation", ErrPublicCertificateExported)
	}
	content, err := os.ReadFile(destination)
	if err != nil {
		return fmt.Errorf("read public certificate export before activation: %w", err)
	}
	if !bytes.Equal(content, expected) {
		return fmt.Errorf("%w: public certificate export changed before activation", ErrPublicCertificateExported)
	}
	return nil
}

func stagePublicCertificateReplacement(destination string, content []byte) (string, error) {
	directory := filepath.Dir(destination)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: destination directory is unavailable", ErrPublicCertificateUnsafePath)
	}
	temporary, err := os.CreateTemp(directory, ".gateway.crt.rotate.")
	if err != nil {
		return "", fmt.Errorf("create public certificate rotation candidate: %w", err)
	}
	path := temporary.Name()
	keep := true
	defer func() {
		_ = temporary.Close()
		if keep {
			_ = os.Remove(path)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return "", fmt.Errorf("set public certificate rotation mode: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return "", fmt.Errorf("write public certificate rotation candidate: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync public certificate rotation candidate: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close public certificate rotation candidate: %w", err)
	}
	keep = false
	return path, nil
}
