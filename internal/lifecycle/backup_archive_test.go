package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func fastBackupArchiveCodec() backupArchiveCodec {
	return backupArchiveCodec{deriveKey: func(passphrase, salt []byte, parameters backupKDFParameters) []byte {
		digest := sha256.New()
		_, _ = digest.Write([]byte("vpnctl-fast-backup-test\x00"))
		_, _ = digest.Write(passphrase)
		_, _ = digest.Write(salt)
		var encoded [9]byte
		binary.BigEndian.PutUint32(encoded[0:4], parameters.MemoryKiB)
		binary.BigEndian.PutUint32(encoded[4:8], parameters.Time)
		encoded[8] = parameters.Lanes
		_, _ = digest.Write(encoded[:])
		return digest.Sum(nil)
	}}
}

func deterministicBackupRandom() io.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x31, 0x72, 0xa5, 0x4c}, 8))
}

func encryptedBackupFixture(t *testing.T, plaintext, passphrase []byte) []byte {
	t.Helper()
	var encrypted bytes.Buffer
	err := fastBackupArchiveCodec().encrypt(&encrypted, passphrase, deterministicBackupRandom(), func(writer io.Writer) error {
		_, err := writer.Write(plaintext)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return encrypted.Bytes()
}

func TestBackupArchiveStreamsAuthenticatedRecordsAndFinalMarker(t *testing.T) {
	plaintext := bytes.Repeat([]byte("streamed gateway payload\n"), 100000)
	passphrase := []byte("correct horse battery staple")
	encrypted := encryptedBackupFixture(t, plaintext, passphrase)
	if len(encrypted) <= int(backupFixedHeaderBytes)+backupRecordHeaderBytes || bytes.Contains(encrypted, passphrase) || bytes.Contains(encrypted, plaintext[:128]) {
		t.Fatal("encrypted backup exposed plaintext/passphrase or lacked records")
	}
	var restored bytes.Buffer
	if err := fastBackupArchiveCodec().decrypt(bytes.NewReader(encrypted), &restored, passphrase); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes(), plaintext) {
		t.Fatal("streaming backup round trip changed plaintext")
	}

	header, err := parseBackupArchiveHeader(encrypted[:backupFixedHeaderBytes])
	if err != nil || header.KDF != selectedBackupKDFParameters() || header.ChunkBytes != backupSelectedChunk {
		t.Fatalf("backup header = %+v, %v", header, err)
	}
	offset := int(backupFixedHeaderBytes)
	var recordCount int
	for {
		if offset+backupRecordHeaderBytes > len(encrypted) {
			t.Fatal("backup record framing is truncated")
		}
		record := encrypted[offset : offset+backupRecordHeaderBytes]
		offset += backupRecordHeaderBytes
		ciphertextBytes := int(binary.BigEndian.Uint32(record[13:17]))
		offset += ciphertextBytes
		recordCount++
		if record[8] == 1 {
			if offset != len(encrypted) || binary.BigEndian.Uint32(record[9:13]) != 0 {
				t.Fatal("final backup record is not empty exact EOF")
			}
			break
		}
	}
	if recordCount < 3 {
		t.Fatalf("large payload used only %d records", recordCount)
	}
}

func TestBackupArchiveRejectsWrongPassphraseAndAuthenticatedCorruption(t *testing.T) {
	passphrase := []byte("correct backup passphrase")
	original := encryptedBackupFixture(t, []byte("authenticated payload"), passphrase)
	if err := fastBackupArchiveCodec().decrypt(bytes.NewReader(original), io.Discard, []byte("wrong backup passphrase")); !errors.Is(err, ErrBackupAuthentication) {
		t.Fatalf("wrong passphrase error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "header", mutate: func(value []byte) []byte { value[32] ^= 0x80; return value }},
		{name: "record-order", mutate: func(value []byte) []byte { value[backupFixedHeaderBytes] ^= 0x01; return value }},
		{name: "ciphertext", mutate: func(value []byte) []byte {
			value[int(backupFixedHeaderBytes)+backupRecordHeaderBytes] ^= 0x80
			return value
		}},
		{name: "truncated", mutate: func(value []byte) []byte { return value[:len(value)-1] }},
		{name: "appended", mutate: func(value []byte) []byte { return append(value, 0x42) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			corrupt := test.mutate(append([]byte(nil), original...))
			if err := fastBackupArchiveCodec().decrypt(bytes.NewReader(corrupt), io.Discard, passphrase); err == nil {
				t.Fatal("corrupt backup was accepted")
			}
		})
	}
}

func TestBackupArchiveRejectsResourceHeaderBeforeKeyDerivation(t *testing.T) {
	header, err := newBackupArchiveHeader(selectedBackupKDFParameters(), backupSelectedChunk, deterministicBackupRandom())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalBackupArchiveHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(encoded[18:22], backupMaximumMemoryKiB+1)
	deriveCalls := 0
	codec := backupArchiveCodec{deriveKey: func(_, _ []byte, _ backupKDFParameters) []byte {
		deriveCalls++
		return make([]byte, 32)
	}}
	err = codec.decrypt(bytes.NewReader(encoded), io.Discard, []byte("passphrase"))
	if !errors.Is(err, ErrBackupArchiveInvalid) || deriveCalls != 0 || !strings.Contains(err.Error(), "outside restore limits") {
		t.Fatalf("resource header error=%v derive_calls=%d", err, deriveCalls)
	}
}

func TestProductionBackupKDFBindsPassphraseAndSelectedParameters(t *testing.T) {
	codec := productionBackupArchiveCodec()
	first := codec.deriveKey([]byte("first"), []byte("0123456789abcdef"), selectedBackupKDFParameters())
	defer wipeBackupBytes(first)
	second := codec.deriveKey([]byte("second"), []byte("0123456789abcdef"), selectedBackupKDFParameters())
	defer wipeBackupBytes(second)
	if len(first) != 32 || len(second) != 32 || bytes.Equal(first, second) {
		t.Fatal("production Argon2id derivation did not bind the passphrase")
	}
}
