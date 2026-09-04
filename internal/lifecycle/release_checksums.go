package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	ReleaseBinaryAsset              = "vpnctl-linux-amd64"
	ReleaseBundleAsset              = "vpnctl-v2-linux-amd64.bundle"
	ReleaseChecksumsAsset           = "release-checksums.txt"
	ReleaseChecksumsSignatureAsset  = "release-checksums.txt.sig"
	ReleaseChecksumsHeader          = "vpnctl-release-checksums-v1"
	ReleaseChecksumsSignatureDomain = "vpnctl-release-checksums-v1\x00"

	ReleaseInstallDirectory       = "/usr/local/lib/vpnctl/release"
	ReleaseInstalledBundlePath    = ReleaseInstallDirectory + "/vpnctl.bundle"
	ReleaseInstalledChecksumsPath = ReleaseInstallDirectory + "/checksums.txt"
	ReleaseInstalledSignaturePath = ReleaseInstallDirectory + "/checksums.txt.sig"

	MaximumStandaloneVPNCTLBytes = int64(128 << 20)
)

var ErrInvalidReleaseChecksums = errors.New("invalid release checksums")

type ReleaseChecksumRecord struct {
	Name      string
	SHA256    string
	SizeBytes int64
}

type ReleaseChecksums struct {
	Version string
	Binary  ReleaseChecksumRecord
	Bundle  ReleaseChecksumRecord
}

func NewReleaseChecksums(version, binarySHA256 string, binarySize int64, bundleSHA256 string, bundleSize int64) (ReleaseChecksums, error) {
	value := ReleaseChecksums{
		Version: version,
		Binary:  ReleaseChecksumRecord{Name: ReleaseBinaryAsset, SHA256: binarySHA256, SizeBytes: binarySize},
		Bundle:  ReleaseChecksumRecord{Name: ReleaseBundleAsset, SHA256: bundleSHA256, SizeBytes: bundleSize},
	}
	if err := value.Validate(); err != nil {
		return ReleaseChecksums{}, err
	}
	return value, nil
}

func (value ReleaseChecksums) Validate() error {
	if !validReleaseVersion(value.Version) {
		return releaseChecksumsInvalid("release version must be a safe v-prefixed tag")
	}
	for _, record := range []ReleaseChecksumRecord{value.Binary, value.Bundle} {
		if !validReleaseSHA256(record.SHA256) {
			return releaseChecksumsInvalid("%s checksum must be canonical SHA-256", record.Name)
		}
		if record.SizeBytes <= 0 {
			return releaseChecksumsInvalid("%s size must be positive", record.Name)
		}
	}
	if value.Binary.Name != ReleaseBinaryAsset || value.Binary.SizeBytes > MaximumStandaloneVPNCTLBytes {
		return releaseChecksumsInvalid("standalone vpnctl record is invalid")
	}
	if value.Bundle.Name != ReleaseBundleAsset || value.Bundle.SizeBytes > maximumReleaseBundleBytes {
		return releaseChecksumsInvalid("release bundle record is invalid")
	}
	return nil
}

func EncodeReleaseChecksums(value ReleaseChecksums) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded := fmt.Sprintf("%s\nversion  %s\n%s  %d  %s\n%s  %d  %s\n",
		ReleaseChecksumsHeader, value.Version,
		value.Binary.SHA256, value.Binary.SizeBytes, value.Binary.Name,
		value.Bundle.SHA256, value.Bundle.SizeBytes, value.Bundle.Name,
	)
	return []byte(encoded), nil
}

func DecodeReleaseChecksums(encoded []byte) (ReleaseChecksums, error) {
	if len(encoded) == 0 || len(encoded) > 4096 || !bytes.HasSuffix(encoded, []byte("\n")) {
		return ReleaseChecksums{}, releaseChecksumsInvalid("metadata size or final newline is invalid")
	}
	lines := strings.Split(string(encoded), "\n")
	if len(lines) != 5 || lines[0] != ReleaseChecksumsHeader || lines[4] != "" || !strings.HasPrefix(lines[1], "version  ") {
		return ReleaseChecksums{}, releaseChecksumsInvalid("metadata framing is invalid")
	}
	version := strings.TrimPrefix(lines[1], "version  ")
	binary, err := decodeReleaseChecksumRecord(lines[2], ReleaseBinaryAsset)
	if err != nil {
		return ReleaseChecksums{}, err
	}
	bundle, err := decodeReleaseChecksumRecord(lines[3], ReleaseBundleAsset)
	if err != nil {
		return ReleaseChecksums{}, err
	}
	value := ReleaseChecksums{Version: version, Binary: binary, Bundle: bundle}
	if err := value.Validate(); err != nil {
		return ReleaseChecksums{}, err
	}
	canonical, _ := EncodeReleaseChecksums(value)
	if !bytes.Equal(canonical, encoded) {
		return ReleaseChecksums{}, releaseChecksumsInvalid("metadata is not canonical")
	}
	return value, nil
}

func SignReleaseChecksums(encoded []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if _, err := DecodeReleaseChecksums(encoded); err != nil {
		return nil, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, releaseChecksumsInvalid("signing key must be Ed25519")
	}
	return ed25519.Sign(privateKey, releaseChecksumsMessage(encoded)), nil
}

func VerifyReleaseChecksums(encoded, signature []byte, publicKey ed25519.PublicKey) (ReleaseChecksums, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, releaseChecksumsMessage(encoded), signature) {
		return ReleaseChecksums{}, releaseChecksumsInvalid("signature verification failed")
	}
	return DecodeReleaseChecksums(encoded)
}

func VerifyReleaseChecksumRecord(record ReleaseChecksumRecord, size int64, content io.Reader) error {
	if content == nil || size != record.SizeBytes {
		return releaseChecksumsInvalid("%s byte size differs from signed metadata", record.Name)
	}
	digest := sha256.New()
	read, err := io.Copy(digest, io.LimitReader(content, record.SizeBytes+1))
	if err != nil || read != record.SizeBytes || hex.EncodeToString(digest.Sum(nil)) != record.SHA256 {
		return releaseChecksumsInvalid("%s checksum differs from signed metadata", record.Name)
	}
	return nil
}

func decodeReleaseChecksumRecord(line, name string) (ReleaseChecksumRecord, error) {
	parts := strings.Split(line, "  ")
	if len(parts) != 3 || parts[2] != name {
		return ReleaseChecksumRecord{}, releaseChecksumsInvalid("%s record framing is invalid", name)
	}
	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || strconv.FormatInt(size, 10) != parts[1] {
		return ReleaseChecksumRecord{}, releaseChecksumsInvalid("%s size is invalid", name)
	}
	return ReleaseChecksumRecord{Name: name, SHA256: parts[0], SizeBytes: size}, nil
}

func releaseChecksumsMessage(encoded []byte) []byte {
	result := make([]byte, 0, len(ReleaseChecksumsSignatureDomain)+len(encoded))
	result = append(result, ReleaseChecksumsSignatureDomain...)
	return append(result, encoded...)
}

func releaseChecksumsInvalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidReleaseChecksums, fmt.Sprintf(format, arguments...))
}

func validReleaseVersion(value string) bool {
	if len(value) < 2 || len(value) > 65 || value[0] != 'v' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
