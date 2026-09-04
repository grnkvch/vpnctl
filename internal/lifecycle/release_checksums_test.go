package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestSignedReleaseChecksumsBindBothBootstrapAssets(t *testing.T) {
	t.Parallel()
	binary := []byte("standalone-vpnctl")
	bundle := []byte("complete-release-bundle")
	checksums, err := NewReleaseChecksums("v2.0.0", releaseDigest(binary), int64(len(binary)), releaseDigest(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeReleaseChecksums(checksums)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signature, err := SignReleaseChecksums(encoded, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyReleaseChecksums(encoded, signature, publicKey)
	if err != nil || verified != checksums {
		t.Fatalf("VerifyReleaseChecksums() = %+v, %v", verified, err)
	}
	if err := VerifyReleaseChecksumRecord(verified.Binary, int64(len(binary)), bytes.NewReader(binary)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyReleaseChecksumRecord(verified.Bundle, int64(len(bundle)), bytes.NewReader(bundle)); err != nil {
		t.Fatal(err)
	}

	tamperedMetadata := append([]byte(nil), encoded...)
	tamperedMetadata[len(ReleaseChecksumsHeader)+2] ^= 1
	if _, err := VerifyReleaseChecksums(tamperedMetadata, signature, publicKey); !errors.Is(err, ErrInvalidReleaseChecksums) {
		t.Fatalf("tampered metadata error = %v", err)
	}
	tamperedSignature := append([]byte(nil), signature...)
	tamperedSignature[0] ^= 1
	if _, err := VerifyReleaseChecksums(encoded, tamperedSignature, publicKey); !errors.Is(err, ErrInvalidReleaseChecksums) {
		t.Fatalf("tampered signature error = %v", err)
	}
	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyReleaseChecksums(encoded, signature, wrongPublic); !errors.Is(err, ErrInvalidReleaseChecksums) {
		t.Fatalf("wrong key error = %v", err)
	}
	if _, err := SignReleaseChecksums(encoded, ed25519.PrivateKey{1}); !errors.Is(err, ErrInvalidReleaseChecksums) {
		t.Fatalf("invalid private key error = %v", err)
	}
}

func TestReleaseChecksumsRejectNonCanonicalOrUnboundedMetadata(t *testing.T) {
	t.Parallel()
	valid, _ := NewReleaseChecksums("v2.0.0", strings.Repeat("a", 64), 123, strings.Repeat("b", 64), 456)
	encoded, _ := EncodeReleaseChecksums(valid)
	for name, mutate := range map[string]func([]byte) []byte{
		"missing-final-newline": func(value []byte) []byte { return value[:len(value)-1] },
		"extra-line":            func(value []byte) []byte { return append(value, '\n') },
		"wrong-header": func(value []byte) []byte {
			result := append([]byte(nil), value...)
			result[0] = 'x'
			return result
		},
		"record-order": func(value []byte) []byte {
			lines := strings.Split(string(value), "\n")
			lines[1], lines[2] = lines[2], lines[1]
			return []byte(strings.Join(lines, "\n"))
		},
		"noncanonical-size": func(value []byte) []byte {
			return []byte(strings.Replace(string(value), "  123  ", "  0123  ", 1))
		},
		"uppercase-checksum": func(value []byte) []byte {
			result := append([]byte(nil), value...)
			result[len(ReleaseChecksumsHeader)+1] = 'A'
			return result
		},
	} {
		candidate := mutate(append([]byte(nil), encoded...))
		if _, err := DecodeReleaseChecksums(candidate); !errors.Is(err, ErrInvalidReleaseChecksums) {
			t.Errorf("%s error = %v", name, err)
		}
	}

	for name, value := range map[string]ReleaseChecksums{
		"invalid version":     {Version: "latest", Binary: valid.Binary, Bundle: valid.Bundle},
		"empty binary":        {Version: "v2.0.0", Binary: ReleaseChecksumRecord{Name: ReleaseBinaryAsset, SHA256: strings.Repeat("a", 64)}, Bundle: valid.Bundle},
		"oversized binary":    mustReleaseChecksumsForTest(t, MaximumStandaloneVPNCTLBytes+1, 456),
		"oversized bundle":    mustReleaseChecksumsForTest(t, 123, maximumReleaseBundleBytes+1),
		"unexpected filename": {Version: "v2.0.0", Binary: ReleaseChecksumRecord{Name: "vpnctl", SHA256: strings.Repeat("a", 64), SizeBytes: 123}, Bundle: valid.Bundle},
	} {
		if _, err := EncodeReleaseChecksums(value); !errors.Is(err, ErrInvalidReleaseChecksums) {
			t.Errorf("%s error = %v", name, err)
		}
	}
	if err := VerifyReleaseChecksumRecord(valid.Binary, 122, bytes.NewReader([]byte("wrong"))); !errors.Is(err, ErrInvalidReleaseChecksums) {
		t.Fatalf("wrong asset size error = %v", err)
	}
}

func mustReleaseChecksumsForTest(t *testing.T, binarySize, bundleSize int64) ReleaseChecksums {
	t.Helper()
	return ReleaseChecksums{
		Version: "v2.0.0",
		Binary:  ReleaseChecksumRecord{Name: ReleaseBinaryAsset, SHA256: strings.Repeat("a", 64), SizeBytes: binarySize},
		Bundle:  ReleaseChecksumRecord{Name: ReleaseBundleAsset, SHA256: strings.Repeat("b", 64), SizeBytes: bundleSize},
	}
}
