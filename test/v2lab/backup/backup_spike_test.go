package backupspike

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	spikeEnvironment  = "VPNCTL_V2_BACKUP_SPIKE"
	archiveMagic      = "VPNCTLBK"
	formatVersion     = uint16(1)
	fixedHeaderBytes  = uint16(64)
	recordHeaderBytes = 17
	kdfArgon2id       = byte(1)
	aeadXChaCha       = byte(1)
	argonVersion      = byte(0x13)
	selectedMemoryKiB = uint32(64 * 1024)
	selectedTime      = uint32(3)
	selectedLanes     = uint8(4)
	selectedChunk     = uint32(1024 * 1024)
	minimumMemoryKiB  = uint32(64 * 1024)
	maximumMemoryKiB  = uint32(128 * 1024)
	minimumTime       = uint32(3)
	maximumTime       = uint32(6)
	minimumLanes      = uint8(1)
	maximumLanes      = uint8(4)
	minimumChunk      = uint32(64 * 1024)
	maximumChunk      = uint32(4 * 1024 * 1024)
	benchmarkBytes    = int64(64 * 1024 * 1024)
)

var recordDomain = []byte("vpnctl-backup-record-v1\x00")

type kdfParameters struct {
	MemoryKiB uint32
	Time      uint32
	Lanes     uint8
}

type archiveHeader struct {
	KDF         kdfParameters
	Salt        [16]byte
	ChunkBytes  uint32
	NoncePrefix [16]byte
}

type manifest struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Format        struct {
		Name              string `json:"name"`
		HeaderBytes       int    `json:"header_bytes"`
		RecordHeaderBytes int    `json:"record_header_bytes"`
		KDF               string `json:"kdf"`
		SaltBytes         int    `json:"salt_bytes"`
		KeyBytes          int    `json:"key_bytes"`
		AEAD              string `json:"aead"`
		NonceBytes        int    `json:"nonce_bytes"`
		NoncePrefixBytes  int    `json:"nonce_prefix_bytes"`
		TagBytes          int    `json:"tag_bytes"`
		ChunkBytes        int    `json:"chunk_bytes"`
	} `json:"format"`
	SelectedKDF struct {
		MemoryKiB uint32 `json:"memory_kib"`
		Time      uint32 `json:"time"`
		Lanes     uint8  `json:"lanes"`
	} `json:"selected_kdf"`
}

func spikeEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv(spikeEnvironment) != "1" {
		t.Skip("backup spike runs only in the constrained v2 lab")
	}
}

func TestManifestContract(t *testing.T) {
	data, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var value manifest
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if value.SchemaVersion != 1 || (value.Status != "candidate" && value.Status != "accepted") {
		t.Fatalf("unexpected manifest identity: version=%d status=%q", value.SchemaVersion, value.Status)
	}
	if value.Format.Name != "vpnctl-backup-v1" || value.Format.HeaderBytes != int(fixedHeaderBytes) || value.Format.RecordHeaderBytes != recordHeaderBytes {
		t.Fatal("manifest binary framing differs from the fixture")
	}
	if value.Format.KDF != "argon2id-v19" || value.Format.SaltBytes != 16 || value.Format.KeyBytes != 32 {
		t.Fatal("manifest KDF differs from the fixture")
	}
	if value.Format.AEAD != "xchacha20-poly1305" || value.Format.NonceBytes != chacha20poly1305.NonceSizeX || value.Format.NoncePrefixBytes != 16 || value.Format.TagBytes != 16 || value.Format.ChunkBytes != int(selectedChunk) {
		t.Fatal("manifest AEAD framing differs from the fixture")
	}
	if value.SelectedKDF.MemoryKiB != selectedMemoryKiB || value.SelectedKDF.Time != selectedTime || value.SelectedKDF.Lanes != selectedLanes {
		t.Fatal("manifest selected KDF differs from the fixture")
	}
}

func selectedParameters() kdfParameters {
	return kdfParameters{MemoryKiB: selectedMemoryKiB, Time: selectedTime, Lanes: selectedLanes}
}

func validateKDF(parameters kdfParameters) error {
	if parameters.MemoryKiB < minimumMemoryKiB || parameters.MemoryKiB > maximumMemoryKiB {
		return fmt.Errorf("argon2 memory %d KiB is outside restore limits", parameters.MemoryKiB)
	}
	if parameters.Time < minimumTime || parameters.Time > maximumTime {
		return fmt.Errorf("argon2 time %d is outside restore limits", parameters.Time)
	}
	if parameters.Lanes < minimumLanes || parameters.Lanes > maximumLanes {
		return fmt.Errorf("argon2 lanes %d is outside restore limits", parameters.Lanes)
	}
	return nil
}

func validateChunkSize(size uint32) error {
	if size < minimumChunk || size > maximumChunk {
		return fmt.Errorf("chunk size %d is outside restore limits", size)
	}
	return nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func deriveKey(passphrase []byte, salt []byte, parameters kdfParameters) []byte {
	return argon2.IDKey(passphrase, salt, parameters.Time, parameters.MemoryKiB, parameters.Lanes, chacha20poly1305.KeySize)
}

func newHeader(parameters kdfParameters, chunkBytes uint32, random io.Reader) (archiveHeader, error) {
	if err := validateKDF(parameters); err != nil {
		return archiveHeader{}, err
	}
	if err := validateChunkSize(chunkBytes); err != nil {
		return archiveHeader{}, err
	}
	value := archiveHeader{KDF: parameters, ChunkBytes: chunkBytes}
	if _, err := io.ReadFull(random, value.Salt[:]); err != nil {
		return archiveHeader{}, fmt.Errorf("read salt: %w", err)
	}
	if _, err := io.ReadFull(random, value.NoncePrefix[:]); err != nil {
		return archiveHeader{}, fmt.Errorf("read nonce prefix: %w", err)
	}
	return value, nil
}

func marshalHeader(value archiveHeader) ([]byte, error) {
	if err := validateKDF(value.KDF); err != nil {
		return nil, err
	}
	if err := validateChunkSize(value.ChunkBytes); err != nil {
		return nil, err
	}
	buffer := bytes.NewBuffer(make([]byte, 0, fixedHeaderBytes))
	buffer.WriteString(archiveMagic)
	for _, item := range []any{
		formatVersion,
		fixedHeaderBytes,
		kdfArgon2id,
		argonVersion,
		value.KDF.Time,
		value.KDF.MemoryKiB,
		value.KDF.Lanes,
		byte(chacha20poly1305.KeySize),
		byte(len(value.Salt)),
	} {
		if err := binary.Write(buffer, binary.BigEndian, item); err != nil {
			return nil, err
		}
	}
	buffer.Write(value.Salt[:])
	for _, item := range []any{
		aeadXChaCha,
		byte(len(value.NoncePrefix)),
		value.ChunkBytes,
	} {
		if err := binary.Write(buffer, binary.BigEndian, item); err != nil {
			return nil, err
		}
	}
	buffer.Write(value.NoncePrefix[:])
	buffer.WriteByte(0)
	if buffer.Len() != int(fixedHeaderBytes) {
		return nil, fmt.Errorf("internal header size %d", buffer.Len())
	}
	return buffer.Bytes(), nil
}

func parseHeader(data []byte) (archiveHeader, error) {
	if len(data) != int(fixedHeaderBytes) {
		return archiveHeader{}, errors.New("invalid backup header length")
	}
	reader := bytes.NewReader(data)
	magic := make([]byte, len(archiveMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != archiveMagic {
		return archiveHeader{}, errors.New("invalid backup magic")
	}
	var version uint16
	var headerBytes uint16
	var kdfID byte
	var versionID byte
	var value archiveHeader
	var keyBytes byte
	var saltBytes byte
	for _, item := range []any{&version, &headerBytes, &kdfID, &versionID, &value.KDF.Time, &value.KDF.MemoryKiB, &value.KDF.Lanes, &keyBytes, &saltBytes} {
		if err := binary.Read(reader, binary.BigEndian, item); err != nil {
			return archiveHeader{}, errors.New("invalid backup header")
		}
	}
	if version != formatVersion || headerBytes != fixedHeaderBytes || kdfID != kdfArgon2id || versionID != argonVersion || keyBytes != chacha20poly1305.KeySize || int(saltBytes) != len(value.Salt) {
		return archiveHeader{}, errors.New("unsupported backup cryptographic header")
	}
	if _, err := io.ReadFull(reader, value.Salt[:]); err != nil {
		return archiveHeader{}, errors.New("invalid backup salt")
	}
	var aeadID byte
	var noncePrefixBytes byte
	if err := binary.Read(reader, binary.BigEndian, &aeadID); err != nil {
		return archiveHeader{}, errors.New("invalid backup AEAD")
	}
	if err := binary.Read(reader, binary.BigEndian, &noncePrefixBytes); err != nil {
		return archiveHeader{}, errors.New("invalid backup nonce prefix")
	}
	if err := binary.Read(reader, binary.BigEndian, &value.ChunkBytes); err != nil {
		return archiveHeader{}, errors.New("invalid backup chunk size")
	}
	if _, err := io.ReadFull(reader, value.NoncePrefix[:]); err != nil {
		return archiveHeader{}, errors.New("invalid backup nonce prefix")
	}
	reserved, err := reader.ReadByte()
	if err != nil || reserved != 0 || reader.Len() != 0 || aeadID != aeadXChaCha || int(noncePrefixBytes) != len(value.NoncePrefix) {
		return archiveHeader{}, errors.New("unsupported backup framing")
	}
	if err := validateKDF(value.KDF); err != nil {
		return archiveHeader{}, err
	}
	if err := validateChunkSize(value.ChunkBytes); err != nil {
		return archiveHeader{}, err
	}
	return value, nil
}

func marshalRecordHeader(index uint64, final bool, plaintextBytes, ciphertextBytes uint32) []byte {
	value := make([]byte, recordHeaderBytes)
	binary.BigEndian.PutUint64(value[0:8], index)
	if final {
		value[8] = 1
	}
	binary.BigEndian.PutUint32(value[9:13], plaintextBytes)
	binary.BigEndian.PutUint32(value[13:17], ciphertextBytes)
	return value
}

func recordNonce(prefix [16]byte, index uint64) []byte {
	value := make([]byte, chacha20poly1305.NonceSizeX)
	copy(value, prefix[:])
	binary.BigEndian.PutUint64(value[16:], index)
	return value
}

func recordAAD(header []byte, record []byte) []byte {
	hash := sha256.Sum256(header)
	value := make([]byte, 0, len(recordDomain)+len(hash)+len(record))
	value = append(value, recordDomain...)
	value = append(value, hash[:]...)
	return append(value, record...)
}

func writeRecord(writer io.Writer, aead cipher.AEAD, header []byte, prefix [16]byte, index uint64, final bool, plaintext []byte) error {
	record := marshalRecordHeader(index, final, uint32(len(plaintext)), uint32(len(plaintext)+aead.Overhead()))
	ciphertext := aead.Seal(nil, recordNonce(prefix, index), plaintext, recordAAD(header, record))
	if _, err := writer.Write(record); err != nil {
		return err
	}
	if _, err := writer.Write(ciphertext); err != nil {
		return err
	}
	return nil
}

func encryptArchive(reader io.Reader, writer io.Writer, passphrase []byte, parameters kdfParameters, chunkBytes uint32, random io.Reader) error {
	headerValue, err := newHeader(parameters, chunkBytes, random)
	if err != nil {
		return err
	}
	header, err := marshalHeader(headerValue)
	if err != nil {
		return err
	}
	key := deriveKey(passphrase, headerValue.Salt[:], parameters)
	defer wipe(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	plaintext := make([]byte, chunkBytes)
	defer wipe(plaintext)
	var index uint64
	for {
		count, readErr := io.ReadFull(reader, plaintext)
		if count > 0 {
			if err := writeRecord(writer, aead, header, headerValue.NoncePrefix, index, false, plaintext[:count]); err != nil {
				return err
			}
			if index == math.MaxUint64 {
				return errors.New("backup record counter exhausted")
			}
			index++
		}
		switch readErr {
		case nil:
			continue
		case io.EOF, io.ErrUnexpectedEOF:
			return writeRecord(writer, aead, header, headerValue.NoncePrefix, index, true, nil)
		default:
			return readErr
		}
	}
}

func decryptArchive(reader io.Reader, writer io.Writer, passphrase []byte) error {
	header := make([]byte, fixedHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return errors.New("truncated backup header")
	}
	value, err := parseHeader(header)
	if err != nil {
		return err
	}
	key := deriveKey(passphrase, value.Salt[:], value.KDF)
	defer wipe(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	var expected uint64
	for {
		record := make([]byte, recordHeaderBytes)
		if _, err := io.ReadFull(reader, record); err != nil {
			return errors.New("backup lacks authenticated final record")
		}
		index := binary.BigEndian.Uint64(record[0:8])
		flags := record[8]
		plaintextBytes := binary.BigEndian.Uint32(record[9:13])
		ciphertextBytes := binary.BigEndian.Uint32(record[13:17])
		if index != expected || flags > 1 {
			return errors.New("backup record order or flags are invalid")
		}
		final := flags == 1
		if final {
			if plaintextBytes != 0 || ciphertextBytes != uint32(aead.Overhead()) {
				return errors.New("invalid final backup record")
			}
		} else if plaintextBytes == 0 || plaintextBytes > value.ChunkBytes || ciphertextBytes != plaintextBytes+uint32(aead.Overhead()) {
			return errors.New("backup record length is invalid")
		}
		ciphertext := make([]byte, ciphertextBytes)
		if _, err := io.ReadFull(reader, ciphertext); err != nil {
			return errors.New("truncated backup record")
		}
		plaintext, err := aead.Open(ciphertext[:0], recordNonce(value.NoncePrefix, index), ciphertext, recordAAD(header, record))
		if err != nil {
			return errors.New("backup authentication failed")
		}
		if final {
			var trailing [1]byte
			if count, readErr := reader.Read(trailing[:]); count != 0 || readErr != io.EOF {
				return errors.New("data follows authenticated final record")
			}
			return nil
		}
		if _, err := writer.Write(plaintext); err != nil {
			return err
		}
		if expected == math.MaxUint64 {
			return errors.New("backup record counter exhausted")
		}
		expected++
	}
}

func decryptToPath(sourcePath, destinationPath string, passphrase []byte) (returnErr error) {
	if _, err := os.Lstat(destinationPath); err == nil {
		return errors.New("restore destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	temporary, err := os.CreateTemp(filepath.Dir(destinationPath), ".vpnctl-restore-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if returnErr != nil {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if err := decryptArchive(source, temporary, passphrase); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destinationPath); err != nil {
		return err
	}
	return nil
}

type patternReader struct {
	remaining int64
	offset    uint64
}

func (reader *patternReader) Read(destination []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(destination)) > reader.remaining {
		destination = destination[:reader.remaining]
	}
	for index := range destination {
		destination[index] = byte((reader.offset*131 + uint64(index)*17 + 29) % 251)
	}
	reader.offset += uint64(len(destination))
	reader.remaining -= int64(len(destination))
	return len(destination), nil
}

func fileSHA256(path string) ([32]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer file.Close()
	value := sha256.New()
	if _, err := io.Copy(value, file); err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], value.Sum(nil))
	return result, nil
}

func copyFile(sourcePath, destinationPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(destination, source); err != nil {
		destination.Close()
		return err
	}
	return destination.Close()
}

func mutateByte(path string, offset int64) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	var value [1]byte
	if _, err := file.ReadAt(value[:], offset); err != nil {
		return err
	}
	value[0] ^= 0x80
	_, err = file.WriteAt(value[:], offset)
	return err
}

func expectRestoreFailure(t *testing.T, archivePath, destinationPath string, passphrase []byte) {
	t.Helper()
	if err := decryptToPath(archivePath, destinationPath, passphrase); err == nil {
		t.Fatalf("restore unexpectedly accepted %s", filepath.Base(archivePath))
	}
	if _, err := os.Lstat(destinationPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed restore left destination behind: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(destinationPath), ".vpnctl-restore-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("failed restore left temporary output: matches=%v err=%v", matches, err)
	}
}

func TestArchiveRoundTripAndFailureAtomicity(t *testing.T) {
	spikeEnabled(t)
	directory := t.TempDir()
	archivePath := filepath.Join(directory, "gateway.backup")
	passphrase := []byte("correct horse battery staple for vpnctl spike")
	defer wipe(passphrase)
	inputBytes := int64(17*1024*1024 + 123)
	expectedHash := sha256.New()
	archive, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encryptStarted := time.Now()
	err = encryptArchive(io.TeeReader(&patternReader{remaining: inputBytes}, expectedHash), archive, passphrase, selectedParameters(), selectedChunk, rand.Reader)
	encryptDuration := time.Since(encryptStarted)
	if closeErr := archive.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("encrypt archive: %v", err)
	}
	archiveInfo, err := os.Stat(archivePath)
	if err != nil || archiveInfo.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode: info=%v err=%v", archiveInfo, err)
	}
	archiveData, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, 4096)
	count, _ := archiveData.Read(prefix)
	archiveData.Close()
	if bytes.Contains(prefix[:count], passphrase) {
		t.Fatal("archive header contains the passphrase")
	}

	restoredPath := filepath.Join(directory, "restored.tar")
	decryptStarted := time.Now()
	if err := decryptToPath(archivePath, restoredPath, passphrase); err != nil {
		t.Fatalf("decrypt archive: %v", err)
	}
	decryptDuration := time.Since(decryptStarted)
	restoredInfo, err := os.Stat(restoredPath)
	if err != nil || restoredInfo.Mode().Perm() != 0o600 || restoredInfo.Size() != inputBytes {
		t.Fatalf("restored file metadata: info=%v err=%v", restoredInfo, err)
	}
	actualHash, err := fileSHA256(restoredPath)
	if err != nil || !bytes.Equal(actualHash[:], expectedHash.Sum(nil)) {
		t.Fatalf("restored content mismatch: err=%v", err)
	}
	if err := decryptToPath(archivePath, restoredPath, passphrase); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal("restore silently overwrote an existing target")
	}

	expectRestoreFailure(t, archivePath, filepath.Join(directory, "wrong-pass.tar"), []byte("wrong passphrase"))

	variants := []struct {
		name   string
		mutate func(string) error
	}{
		{name: "authenticated-header", mutate: func(path string) error { return mutateByte(path, 32) }},
		{name: "record-index", mutate: func(path string) error { return mutateByte(path, int64(fixedHeaderBytes)) }},
		{name: "ciphertext", mutate: func(path string) error { return mutateByte(path, int64(fixedHeaderBytes)+recordHeaderBytes+127) }},
		{name: "truncated-final", mutate: func(path string) error {
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			return os.Truncate(path, info.Size()-1)
		}},
		{name: "appended-data", mutate: func(path string) error {
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			_, writeErr := file.Write([]byte{0x42})
			closeErr := file.Close()
			if writeErr != nil {
				return writeErr
			}
			return closeErr
		}},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			corruptPath := filepath.Join(directory, variant.name+".backup")
			if err := copyFile(archivePath, corruptPath); err != nil {
				t.Fatal(err)
			}
			if err := variant.mutate(corruptPath); err != nil {
				t.Fatal(err)
			}
			expectRestoreFailure(t, corruptPath, filepath.Join(directory, variant.name+".tar"), passphrase)
		})
	}
	metric, _ := json.Marshal(map[string]any{
		"plaintext_bytes": inputBytes,
		"archive_bytes":   archiveInfo.Size(),
		"encrypt_ms":      float64(encryptDuration.Microseconds()) / 1000,
		"decrypt_ms":      float64(decryptDuration.Microseconds()) / 1000,
	})
	t.Logf("ARCHIVE_METRIC %s", metric)
}

func TestHeaderResourceLimitsBeforeKDF(t *testing.T) {
	spikeEnabled(t)
	headerValue, err := newHeader(selectedParameters(), selectedChunk, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	header, err := marshalHeader(headerValue)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		offset int
		value  uint32
	}{
		{name: "memory", offset: 18, value: maximumMemoryKiB + 1},
		{name: "time", offset: 14, value: maximumTime + 1},
		{name: "chunk", offset: 43, value: maximumChunk + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			malicious := append([]byte(nil), header...)
			binary.BigEndian.PutUint32(malicious[test.offset:test.offset+4], test.value)
			started := time.Now()
			if _, err := parseHeader(malicious); err == nil {
				t.Fatal("accepted resource-exhaustion header")
			}
			if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
				t.Fatalf("header limit was not rejected before KDF: %s", elapsed)
			}
		})
	}
}

func requiredEnvironmentUint(t *testing.T, name string, bitSize int) uint64 {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	parsed, err := strconv.ParseUint(value, 10, bitSize)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return parsed
}

func TestKDFCandidate(t *testing.T) {
	spikeEnabled(t)
	parameters := kdfParameters{
		MemoryKiB: uint32(requiredEnvironmentUint(t, "VPNCTL_V2_BACKUP_ARGON_MEMORY_KIB", 32)),
		Time:      uint32(requiredEnvironmentUint(t, "VPNCTL_V2_BACKUP_ARGON_TIME", 32)),
		Lanes:     uint8(requiredEnvironmentUint(t, "VPNCTL_V2_BACKUP_ARGON_LANES", 8)),
	}
	if parameters.MemoryKiB < 8*1024 || parameters.MemoryKiB > maximumMemoryKiB || parameters.Time == 0 || parameters.Time > maximumTime || parameters.Lanes == 0 || parameters.Lanes > maximumLanes {
		t.Fatal("benchmark parameter is outside the fixture safety envelope")
	}
	passphrase := []byte("synthetic benchmark passphrase with no production value")
	salt := []byte("0123456789abcdef")
	defer wipe(passphrase)
	durations := make([]float64, 0, 3)
	var expected [32]byte
	for run := 0; run < 3; run++ {
		runtime.GC()
		started := time.Now()
		key := deriveKey(passphrase, salt, parameters)
		durations = append(durations, float64(time.Since(started).Microseconds())/1000)
		checksum := sha256.Sum256(key)
		wipe(key)
		if run == 0 {
			expected = checksum
		} else if checksum != expected {
			t.Fatal("Argon2id derivation is not deterministic")
		}
	}
	sort.Float64s(durations)
	metric, _ := json.Marshal(map[string]any{
		"memory_kib": parameters.MemoryKiB,
		"time":       parameters.Time,
		"lanes":      parameters.Lanes,
		"runs":       len(durations),
		"minimum_ms": durations[0],
		"median_ms":  durations[1],
		"maximum_ms": durations[2],
	})
	t.Logf("KDF_METRIC %s", metric)
}

func benchmarkAEAD(t *testing.T, name string, aead cipher.AEAD, noncePrefixBytes, chunkBytes int) {
	t.Helper()
	plaintext := make([]byte, chunkBytes)
	for index := range plaintext {
		plaintext[index] = byte((index*17 + 29) % 251)
	}
	nonce := make([]byte, aead.NonceSize())
	for index := 0; index < noncePrefixBytes; index++ {
		nonce[index] = byte(index + 1)
	}
	aad := []byte("vpnctl-backup-aead-benchmark-v1")
	chunks := int(benchmarkBytes / int64(chunkBytes))
	if benchmarkBytes%int64(chunkBytes) != 0 {
		chunks++
	}
	started := time.Now()
	for index := 0; index < chunks; index++ {
		binary.BigEndian.PutUint64(nonce[noncePrefixBytes:], uint64(index))
		ciphertext := aead.Seal(nil, nonce, plaintext, aad)
		opened, err := aead.Open(ciphertext[:0], nonce, ciphertext, aad)
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Fatalf("%s round trip failed: %v", name, err)
		}
	}
	duration := time.Since(started)
	processedMiB := float64(benchmarkBytes*2) / (1024 * 1024)
	metric, _ := json.Marshal(map[string]any{
		"id":               name,
		"chunk_bytes":      chunkBytes,
		"processed_bytes":  benchmarkBytes * 2,
		"elapsed_ms":       float64(duration.Microseconds()) / 1000,
		"throughput_mib_s": processedMiB / duration.Seconds(),
	})
	t.Logf("AEAD_METRIC %s", metric)
	wipe(plaintext)
}

func TestAEADCandidates(t *testing.T) {
	spikeEnabled(t)
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	defer wipe(key)
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		t.Fatal(err)
	}
	benchmarkAEAD(t, "aes-256-gcm-1m", aesGCM, aesGCM.NonceSize()-8, 1024*1024)
	xchacha, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	benchmarkAEAD(t, "xchacha20-poly1305-64k", xchacha, xchacha.NonceSize()-8, 64*1024)
	benchmarkAEAD(t, "xchacha20-poly1305-1m", xchacha, xchacha.NonceSize()-8, 1024*1024)
	benchmarkAEAD(t, "xchacha20-poly1305-4m", xchacha, xchacha.NonceSize()-8, 4*1024*1024)
}
