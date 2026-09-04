package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const BackupFileMode os.FileMode = 0o600

var (
	ErrBackupConflict = errors.New("gateway backup conflict")
	ErrBackupExists   = errors.New("gateway backup target already exists")
)

type GatewayBackupStateStore interface {
	Load() (model.State, error)
	Save(uint64, model.State) error
}

type GatewayBackupRuntime struct {
	State      GatewayBackupStateStore
	Payloads   BackupPayloadSource
	BackupsDir string
	Now        func() time.Time
	NewUUID    model.UUIDGenerator
	Random     io.Reader
}

type GatewayBackupPlan struct {
	BackupID                string
	OutputPath              string
	ExpectedStateGeneration uint64
	PublicIPv4              string
	CreatedAt               time.Time

	state   model.State
	payload BackupPayload
}

type GatewayBackupResult struct {
	BackupID        string
	OutputPath      string
	FileMode        os.FileMode
	SHA256          string
	SizeBytes       int64
	StateGeneration uint64
	CreatedAt       time.Time
}

type GatewayBackupper struct {
	runtime GatewayBackupRuntime
	codec   backupArchiveCodec
	mu      sync.Mutex
}

func NewGatewayBackupper(runtime GatewayBackupRuntime) (*GatewayBackupper, error) {
	return newGatewayBackupper(runtime, productionBackupArchiveCodec())
}

func newGatewayBackupper(runtime GatewayBackupRuntime, codec backupArchiveCodec) (*GatewayBackupper, error) {
	if runtime.State == nil || runtime.Payloads == nil || codec.deriveKey == nil {
		return nil, fmt.Errorf("gateway backup dependencies are incomplete")
	}
	if !filepath.IsAbs(runtime.BackupsDir) || filepath.Clean(runtime.BackupsDir) != runtime.BackupsDir {
		return nil, fmt.Errorf("gateway backup directory must be clean and absolute")
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	if runtime.Random == nil {
		runtime.Random = rand.Reader
	}
	return &GatewayBackupper{runtime: runtime, codec: codec}, nil
}

func (backupper *GatewayBackupper) Plan(ctx context.Context, requestedPath string) (GatewayBackupPlan, error) {
	if ctx == nil || backupper == nil || backupper.runtime.State == nil || backupper.runtime.Payloads == nil {
		return GatewayBackupPlan{}, fmt.Errorf("gateway backup planner is incomplete")
	}
	backupper.mu.Lock()
	defer backupper.mu.Unlock()
	state, err := backupper.runtime.State.Load()
	if err != nil {
		return GatewayBackupPlan{}, fmt.Errorf("load gateway backup state: %w", err)
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return GatewayBackupPlan{}, fmt.Errorf("gateway backup requires valid initialized gateway state")
	}
	now := backupper.runtime.Now().UTC().Truncate(time.Second)
	outputPath, err := backupOutputPath(backupper.runtime.BackupsDir, requestedPath, now)
	if err != nil {
		return GatewayBackupPlan{}, err
	}
	if err := validateBackupDestination(outputPath); err != nil {
		return GatewayBackupPlan{}, err
	}
	occupied := make(map[string]struct{}, len(state.Backups))
	for _, backup := range state.Backups {
		occupied[backup.ID] = struct{}{}
	}
	backupID, err := model.AllocateUUID(occupied, backupper.runtime.NewUUID)
	if err != nil {
		return GatewayBackupPlan{}, fmt.Errorf("allocate backup ID: %w", err)
	}
	payload, err := backupper.runtime.Payloads.Prepare(ctx, state)
	if err != nil {
		return GatewayBackupPlan{}, fmt.Errorf("prepare gateway backup payload: %w", err)
	}
	plan := GatewayBackupPlan{
		BackupID: backupID, OutputPath: outputPath, ExpectedStateGeneration: state.Generation,
		PublicIPv4: state.Host.PublicIPv4, CreatedAt: now, state: state, payload: payload,
	}
	if err := plan.Validate(); err != nil {
		_ = payload.Close()
		return GatewayBackupPlan{}, err
	}
	return plan, nil
}

func (plan GatewayBackupPlan) Validate() error {
	if !filepath.IsAbs(plan.OutputPath) || filepath.Clean(plan.OutputPath) != plan.OutputPath || strings.ContainsAny(plan.OutputPath, "\x00\r\n") {
		return fmt.Errorf("gateway backup output path must be clean, absolute, and single-line")
	}
	probe := model.Backup{
		SchemaVersion: model.ResourceSchemaVersion, ID: plan.BackupID, State: model.BackupComplete,
		Format: BackupArchiveFormat, Path: plan.OutputPath, SHA256: strings.Repeat("0", 64), SizeBytes: 1,
		StateGeneration: plan.ExpectedStateGeneration, PublicIPv4: plan.PublicIPv4, CreatedAt: plan.CreatedAt,
	}
	if err := probe.Validate(); err != nil {
		return fmt.Errorf("gateway backup plan identity is invalid: %w", err)
	}
	return nil
}

func (backupper *GatewayBackupper) Apply(ctx context.Context, plan GatewayBackupPlan, passphrase []byte) (result GatewayBackupResult, returnErr error) {
	if ctx == nil || backupper == nil {
		wipeBackupBytes(passphrase)
		return GatewayBackupResult{}, fmt.Errorf("gateway backup writer is incomplete")
	}
	defer wipeBackupBytes(passphrase)
	if len(passphrase) == 0 {
		return GatewayBackupResult{}, fmt.Errorf("gateway backup passphrase is required")
	}
	if err := plan.Validate(); err != nil {
		return GatewayBackupResult{}, err
	}
	if plan.payload == nil {
		return GatewayBackupResult{}, fmt.Errorf("prepared gateway backup payload is unavailable")
	}
	backupper.mu.Lock()
	defer backupper.mu.Unlock()
	defer plan.payload.Close()
	current, err := backupper.runtime.State.Load()
	if err != nil || !reflect.DeepEqual(current, plan.state) {
		return GatewayBackupResult{}, fmt.Errorf("%w: authoritative state changed after backup planning", ErrBackupConflict)
	}
	if err := validateBackupDestination(plan.OutputPath); err != nil {
		return GatewayBackupResult{}, err
	}
	sha256Value, sizeBytes, err := backupper.writeArchive(ctx, plan.OutputPath, plan.payload, passphrase)
	if err != nil {
		return GatewayBackupResult{}, err
	}
	removeArchive := true
	defer func() {
		if removeArchive {
			removeErr := os.Remove(plan.OutputPath)
			if removeErr == nil {
				removeErr = syncLifecycleDirectory(filepath.Dir(plan.OutputPath))
			}
			if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove incomplete gateway backup: %w", removeErr))
			}
		}
	}()
	nextGeneration, err := model.NextGeneration(current.Generation)
	if err != nil {
		return GatewayBackupResult{}, err
	}
	candidate := current
	candidate.Generation = nextGeneration
	candidate.Backups = append(append([]model.Backup{}, current.Backups...), model.Backup{
		SchemaVersion: model.ResourceSchemaVersion, ID: plan.BackupID, State: model.BackupComplete,
		Format: BackupArchiveFormat, Path: plan.OutputPath, SHA256: sha256Value, SizeBytes: sizeBytes,
		StateGeneration: plan.ExpectedStateGeneration, PublicIPv4: plan.PublicIPv4, CreatedAt: plan.CreatedAt,
	})
	if err := model.ValidateTransition(current, candidate); err != nil {
		return GatewayBackupResult{}, fmt.Errorf("validate completed backup metadata: %w", err)
	}
	if err := backupper.saveState(current, candidate); err != nil {
		return GatewayBackupResult{}, fmt.Errorf("record completed gateway backup: %w", err)
	}
	removeArchive = false
	return GatewayBackupResult{
		BackupID: plan.BackupID, OutputPath: plan.OutputPath, FileMode: BackupFileMode,
		SHA256: sha256Value, SizeBytes: sizeBytes, StateGeneration: plan.ExpectedStateGeneration, CreatedAt: plan.CreatedAt,
	}, nil
}

func (backupper *GatewayBackupper) Discard(plan GatewayBackupPlan) error {
	if plan.payload == nil {
		return nil
	}
	return plan.payload.Close()
}

func (backupper *GatewayBackupper) writeArchive(ctx context.Context, outputPath string, payload BackupPayload, passphrase []byte) (returnHash string, returnSize int64, returnErr error) {
	parent := filepath.Dir(outputPath)
	temporary, err := os.CreateTemp(parent, ".vpnctl-backup-*.tmp")
	if err != nil {
		return "", 0, fmt.Errorf("create backup temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	temporaryRemoved := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, temporary.Close())
		}
		if !temporaryRemoved {
			removeErr := os.Remove(temporaryPath)
			if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				returnErr = errors.Join(returnErr, removeErr)
			}
		}
	}()
	removePublished := func(cause error) error {
		removeErr := os.Remove(outputPath)
		if removeErr == nil {
			removeErr = syncLifecycleDirectory(parent)
		}
		if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return errors.Join(cause, fmt.Errorf("remove incompletely published gateway backup: %w", removeErr))
		}
		return cause
	}
	if err := temporary.Chmod(BackupFileMode); err != nil {
		return "", 0, fmt.Errorf("set backup temporary mode: %w", err)
	}
	hash := sha256.New()
	destination := io.MultiWriter(temporary, hash)
	if err := backupper.codec.encrypt(destination, passphrase, backupper.runtime.Random, func(writer io.Writer) error {
		return payload.WriteTo(ctx, writer)
	}); err != nil {
		return "", 0, fmt.Errorf("encrypt gateway backup: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return "", 0, fmt.Errorf("sync gateway backup: %w", err)
	}
	info, err := temporary.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("inspect gateway backup: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", 0, fmt.Errorf("close gateway backup: %w", err)
	}
	closed = true
	if err := os.Link(temporaryPath, outputPath); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", 0, fmt.Errorf("%w: %s", ErrBackupExists, outputPath)
		}
		return "", 0, fmt.Errorf("publish gateway backup: %w", err)
	}
	if err := syncLifecycleDirectory(parent); err != nil {
		return "", 0, removePublished(err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return "", 0, removePublished(fmt.Errorf("remove backup temporary link: %w", err))
	}
	temporaryRemoved = true
	if err := syncLifecycleDirectory(parent); err != nil {
		return "", 0, removePublished(err)
	}
	return hex.EncodeToString(hash.Sum(nil)), info.Size(), nil
}

func (backupper *GatewayBackupper) saveState(before, candidate model.State) error {
	err := backupper.runtime.State.Save(before.Generation, candidate)
	if err == nil {
		return nil
	}
	observed, loadErr := backupper.runtime.State.Load()
	if loadErr == nil && reflect.DeepEqual(observed, candidate) {
		return nil
	}
	if loadErr != nil {
		return errors.Join(err, fmt.Errorf("reconcile backup state write: %w", loadErr))
	}
	if !reflect.DeepEqual(observed, before) {
		return errors.Join(err, fmt.Errorf("%w: state diverged while recording backup", ErrBackupConflict))
	}
	return err
}

func backupOutputPath(backupsDir, requested string, now time.Time) (string, error) {
	if requested == "" {
		return filepath.Join(backupsDir, "vpnctl-"+now.Format("20060102T150405Z")+".v2b"), nil
	}
	if strings.TrimSpace(requested) != requested || strings.ContainsAny(requested, "\x00\r\n") {
		return "", fmt.Errorf("gateway backup output path must be a trimmed single line")
	}
	absolute := requested
	if !filepath.IsAbs(absolute) {
		var err error
		absolute, err = filepath.Abs(absolute)
		if err != nil {
			return "", fmt.Errorf("resolve gateway backup output path: %w", err)
		}
	}
	absolute = filepath.Clean(absolute)
	if filepath.Base(absolute) == "." || filepath.Base(absolute) == string(filepath.Separator) {
		return "", fmt.Errorf("gateway backup output path must name a file")
	}
	return absolute, nil
}

func validateBackupDestination(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("gateway backup output path must be clean and absolute")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect gateway backup parent: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("gateway backup parent must be a real directory")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%w: %s", ErrBackupExists, path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect gateway backup target: %w", err)
	}
	return nil
}
