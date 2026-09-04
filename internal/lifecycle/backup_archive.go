package lifecycle

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	BackupArchiveFormat = "vpnctl-backup-v1"

	backupArchiveMagic      = "VPNCTLBK"
	backupFormatVersion     = uint16(1)
	backupFixedHeaderBytes  = uint16(64)
	backupRecordHeaderBytes = 17
	backupKDFArgon2id       = byte(1)
	backupAEADXChaCha       = byte(1)
	backupArgonVersion      = byte(0x13)

	backupSelectedMemoryKiB = uint32(64 * 1024)
	backupSelectedTime      = uint32(3)
	backupSelectedLanes     = uint8(4)
	backupSelectedChunk     = uint32(1024 * 1024)

	backupMinimumMemoryKiB = uint32(64 * 1024)
	backupMaximumMemoryKiB = uint32(128 * 1024)
	backupMinimumTime      = uint32(3)
	backupMaximumTime      = uint32(6)
	backupMinimumLanes     = uint8(1)
	backupMaximumLanes     = uint8(4)
	backupMinimumChunk     = uint32(64 * 1024)
	backupMaximumChunk     = uint32(4 * 1024 * 1024)
)

var (
	ErrBackupArchiveInvalid = errors.New("invalid vpnctl backup archive")
	ErrBackupAuthentication = errors.New("vpnctl backup authentication failed")
	backupRecordDomain      = []byte("vpnctl-backup-record-v1\x00")
)

type backupKDFParameters struct {
	MemoryKiB uint32
	Time      uint32
	Lanes     uint8
}

type backupArchiveHeader struct {
	KDF         backupKDFParameters
	Salt        [16]byte
	ChunkBytes  uint32
	NoncePrefix [16]byte
}

type backupKeyDeriver func([]byte, []byte, backupKDFParameters) []byte

type backupArchiveCodec struct {
	deriveKey backupKeyDeriver
}

func productionBackupArchiveCodec() backupArchiveCodec {
	return backupArchiveCodec{deriveKey: func(passphrase, salt []byte, parameters backupKDFParameters) []byte {
		return argon2.IDKey(passphrase, salt, parameters.Time, parameters.MemoryKiB, parameters.Lanes, chacha20poly1305.KeySize)
	}}
}

func selectedBackupKDFParameters() backupKDFParameters {
	return backupKDFParameters{MemoryKiB: backupSelectedMemoryKiB, Time: backupSelectedTime, Lanes: backupSelectedLanes}
}

func validateBackupKDF(parameters backupKDFParameters) error {
	if parameters.MemoryKiB < backupMinimumMemoryKiB || parameters.MemoryKiB > backupMaximumMemoryKiB {
		return fmt.Errorf("%w: Argon2 memory %d KiB is outside restore limits", ErrBackupArchiveInvalid, parameters.MemoryKiB)
	}
	if parameters.Time < backupMinimumTime || parameters.Time > backupMaximumTime {
		return fmt.Errorf("%w: Argon2 time %d is outside restore limits", ErrBackupArchiveInvalid, parameters.Time)
	}
	if parameters.Lanes < backupMinimumLanes || parameters.Lanes > backupMaximumLanes {
		return fmt.Errorf("%w: Argon2 lanes %d is outside restore limits", ErrBackupArchiveInvalid, parameters.Lanes)
	}
	return nil
}

func validateBackupChunkSize(size uint32) error {
	if size < backupMinimumChunk || size > backupMaximumChunk {
		return fmt.Errorf("%w: chunk size %d is outside restore limits", ErrBackupArchiveInvalid, size)
	}
	return nil
}

func wipeBackupBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func newBackupArchiveHeader(parameters backupKDFParameters, chunkBytes uint32, random io.Reader) (backupArchiveHeader, error) {
	if random == nil {
		return backupArchiveHeader{}, fmt.Errorf("backup random source is required")
	}
	if err := validateBackupKDF(parameters); err != nil {
		return backupArchiveHeader{}, err
	}
	if err := validateBackupChunkSize(chunkBytes); err != nil {
		return backupArchiveHeader{}, err
	}
	value := backupArchiveHeader{KDF: parameters, ChunkBytes: chunkBytes}
	if _, err := io.ReadFull(random, value.Salt[:]); err != nil {
		return backupArchiveHeader{}, fmt.Errorf("read backup salt: %w", err)
	}
	if _, err := io.ReadFull(random, value.NoncePrefix[:]); err != nil {
		return backupArchiveHeader{}, fmt.Errorf("read backup nonce prefix: %w", err)
	}
	return value, nil
}

func marshalBackupArchiveHeader(value backupArchiveHeader) ([]byte, error) {
	if err := validateBackupKDF(value.KDF); err != nil {
		return nil, err
	}
	if err := validateBackupChunkSize(value.ChunkBytes); err != nil {
		return nil, err
	}
	buffer := bytes.NewBuffer(make([]byte, 0, backupFixedHeaderBytes))
	buffer.WriteString(backupArchiveMagic)
	for _, item := range []any{
		backupFormatVersion, backupFixedHeaderBytes, backupKDFArgon2id, backupArgonVersion,
		value.KDF.Time, value.KDF.MemoryKiB, value.KDF.Lanes, byte(chacha20poly1305.KeySize), byte(len(value.Salt)),
	} {
		if err := binary.Write(buffer, binary.BigEndian, item); err != nil {
			return nil, fmt.Errorf("marshal backup header: %w", err)
		}
	}
	buffer.Write(value.Salt[:])
	for _, item := range []any{backupAEADXChaCha, byte(len(value.NoncePrefix)), value.ChunkBytes} {
		if err := binary.Write(buffer, binary.BigEndian, item); err != nil {
			return nil, fmt.Errorf("marshal backup header: %w", err)
		}
	}
	buffer.Write(value.NoncePrefix[:])
	buffer.WriteByte(0)
	if buffer.Len() != int(backupFixedHeaderBytes) {
		return nil, fmt.Errorf("internal backup header size %d", buffer.Len())
	}
	return buffer.Bytes(), nil
}

func parseBackupArchiveHeader(data []byte) (backupArchiveHeader, error) {
	fail := func(message string) (backupArchiveHeader, error) {
		return backupArchiveHeader{}, fmt.Errorf("%w: %s", ErrBackupArchiveInvalid, message)
	}
	if len(data) != int(backupFixedHeaderBytes) {
		return fail("header length")
	}
	reader := bytes.NewReader(data)
	magic := make([]byte, len(backupArchiveMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != backupArchiveMagic {
		return fail("magic")
	}
	var version, headerBytes uint16
	var kdfID, versionID, keyBytes, saltBytes byte
	var value backupArchiveHeader
	for _, item := range []any{
		&version, &headerBytes, &kdfID, &versionID, &value.KDF.Time, &value.KDF.MemoryKiB,
		&value.KDF.Lanes, &keyBytes, &saltBytes,
	} {
		if err := binary.Read(reader, binary.BigEndian, item); err != nil {
			return fail("cryptographic header")
		}
	}
	if version != backupFormatVersion || headerBytes != backupFixedHeaderBytes || kdfID != backupKDFArgon2id ||
		versionID != backupArgonVersion || keyBytes != chacha20poly1305.KeySize || int(saltBytes) != len(value.Salt) {
		return fail("unsupported cryptographic header")
	}
	if _, err := io.ReadFull(reader, value.Salt[:]); err != nil {
		return fail("salt")
	}
	var aeadID, noncePrefixBytes byte
	if err := binary.Read(reader, binary.BigEndian, &aeadID); err != nil {
		return fail("AEAD")
	}
	if err := binary.Read(reader, binary.BigEndian, &noncePrefixBytes); err != nil {
		return fail("nonce prefix")
	}
	if err := binary.Read(reader, binary.BigEndian, &value.ChunkBytes); err != nil {
		return fail("chunk size")
	}
	if _, err := io.ReadFull(reader, value.NoncePrefix[:]); err != nil {
		return fail("nonce prefix")
	}
	reserved, err := reader.ReadByte()
	if err != nil || reserved != 0 || reader.Len() != 0 || aeadID != backupAEADXChaCha || int(noncePrefixBytes) != len(value.NoncePrefix) {
		return fail("unsupported framing")
	}
	if err := validateBackupKDF(value.KDF); err != nil {
		return backupArchiveHeader{}, err
	}
	if err := validateBackupChunkSize(value.ChunkBytes); err != nil {
		return backupArchiveHeader{}, err
	}
	return value, nil
}

func marshalBackupRecordHeader(index uint64, final bool, plaintextBytes, ciphertextBytes uint32) []byte {
	value := make([]byte, backupRecordHeaderBytes)
	binary.BigEndian.PutUint64(value[0:8], index)
	if final {
		value[8] = 1
	}
	binary.BigEndian.PutUint32(value[9:13], plaintextBytes)
	binary.BigEndian.PutUint32(value[13:17], ciphertextBytes)
	return value
}

func backupRecordNonce(prefix [16]byte, index uint64) []byte {
	value := make([]byte, chacha20poly1305.NonceSizeX)
	copy(value, prefix[:])
	binary.BigEndian.PutUint64(value[16:], index)
	return value
}

func backupRecordAAD(header, record []byte) []byte {
	hash := sha256.Sum256(header)
	value := make([]byte, 0, len(backupRecordDomain)+len(hash)+len(record))
	value = append(value, backupRecordDomain...)
	value = append(value, hash[:]...)
	return append(value, record...)
}

func writeBackupBytes(writer io.Writer, value []byte) error {
	written, err := writer.Write(value)
	if err != nil {
		return err
	}
	if written != len(value) {
		return io.ErrShortWrite
	}
	return nil
}

func writeBackupRecord(writer io.Writer, aead cipher.AEAD, header []byte, prefix [16]byte, index uint64, final bool, plaintext []byte) error {
	record := marshalBackupRecordHeader(index, final, uint32(len(plaintext)), uint32(len(plaintext)+aead.Overhead()))
	ciphertext := aead.Seal(nil, backupRecordNonce(prefix, index), plaintext, backupRecordAAD(header, record))
	if err := writeBackupBytes(writer, record); err != nil {
		return err
	}
	return writeBackupBytes(writer, ciphertext)
}

type backupPlaintextWriter struct {
	destination io.Writer
	aead        cipher.AEAD
	header      []byte
	prefix      [16]byte
	chunk       []byte
	used        int
	index       uint64
	closed      bool
}

func (writer *backupPlaintextWriter) Write(value []byte) (int, error) {
	if writer == nil || writer.closed {
		return 0, errors.New("backup plaintext writer is closed")
	}
	total := 0
	for len(value) > 0 {
		count := copy(writer.chunk[writer.used:], value)
		writer.used += count
		total += count
		value = value[count:]
		if writer.used == len(writer.chunk) {
			if err := writer.flush(false); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func (writer *backupPlaintextWriter) flush(final bool) error {
	if !final && writer.used == 0 {
		return nil
	}
	if err := writeBackupRecord(writer.destination, writer.aead, writer.header, writer.prefix, writer.index, final, writer.chunk[:writer.used]); err != nil {
		return err
	}
	wipeBackupBytes(writer.chunk[:writer.used])
	writer.used = 0
	if !final {
		if writer.index == math.MaxUint64 {
			return errors.New("backup record counter exhausted")
		}
		writer.index++
	}
	return nil
}

func (writer *backupPlaintextWriter) Close() error {
	if writer == nil || writer.closed {
		return nil
	}
	writer.closed = true
	if err := writer.flush(false); err != nil {
		wipeBackupBytes(writer.chunk)
		return err
	}
	err := writeBackupRecord(writer.destination, writer.aead, writer.header, writer.prefix, writer.index, true, nil)
	wipeBackupBytes(writer.chunk)
	return err
}

func (codec backupArchiveCodec) encrypt(writer io.Writer, passphrase []byte, random io.Reader, writePlaintext func(io.Writer) error) error {
	if writer == nil || len(passphrase) == 0 || writePlaintext == nil || codec.deriveKey == nil {
		return fmt.Errorf("backup encryption inputs are incomplete")
	}
	headerValue, err := newBackupArchiveHeader(selectedBackupKDFParameters(), backupSelectedChunk, random)
	if err != nil {
		return err
	}
	header, err := marshalBackupArchiveHeader(headerValue)
	if err != nil {
		return err
	}
	key := codec.deriveKey(passphrase, headerValue.Salt[:], headerValue.KDF)
	defer wipeBackupBytes(key)
	if len(key) != chacha20poly1305.KeySize {
		return fmt.Errorf("backup KDF returned an invalid key size")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("initialize backup AEAD: %w", err)
	}
	if err := writeBackupBytes(writer, header); err != nil {
		return fmt.Errorf("write backup header: %w", err)
	}
	plaintext := &backupPlaintextWriter{
		destination: writer, aead: aead, header: header, prefix: headerValue.NoncePrefix,
		chunk: make([]byte, headerValue.ChunkBytes),
	}
	if err := writePlaintext(plaintext); err != nil {
		wipeBackupBytes(plaintext.chunk)
		plaintext.closed = true
		return fmt.Errorf("write backup payload: %w", err)
	}
	if err := plaintext.Close(); err != nil {
		return fmt.Errorf("finalize backup payload: %w", err)
	}
	return nil
}

func (codec backupArchiveCodec) decrypt(reader io.Reader, writer io.Writer, passphrase []byte) error {
	if reader == nil || writer == nil || len(passphrase) == 0 || codec.deriveKey == nil {
		return fmt.Errorf("backup decryption inputs are incomplete")
	}
	header := make([]byte, backupFixedHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("%w: truncated header", ErrBackupArchiveInvalid)
	}
	value, err := parseBackupArchiveHeader(header)
	if err != nil {
		return err
	}
	key := codec.deriveKey(passphrase, value.Salt[:], value.KDF)
	defer wipeBackupBytes(key)
	if len(key) != chacha20poly1305.KeySize {
		return fmt.Errorf("backup KDF returned an invalid key size")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("initialize backup AEAD: %w", err)
	}
	var expected uint64
	for {
		record := make([]byte, backupRecordHeaderBytes)
		if _, err := io.ReadFull(reader, record); err != nil {
			return fmt.Errorf("%w: authenticated final record is absent", ErrBackupArchiveInvalid)
		}
		index := binary.BigEndian.Uint64(record[0:8])
		flags := record[8]
		plaintextBytes := binary.BigEndian.Uint32(record[9:13])
		ciphertextBytes := binary.BigEndian.Uint32(record[13:17])
		if index != expected || flags > 1 {
			return fmt.Errorf("%w: record order or flags", ErrBackupArchiveInvalid)
		}
		final := flags == 1
		if final {
			if plaintextBytes != 0 || ciphertextBytes != uint32(aead.Overhead()) {
				return fmt.Errorf("%w: final record", ErrBackupArchiveInvalid)
			}
		} else if plaintextBytes == 0 || plaintextBytes > value.ChunkBytes || ciphertextBytes != plaintextBytes+uint32(aead.Overhead()) {
			return fmt.Errorf("%w: record length", ErrBackupArchiveInvalid)
		}
		ciphertext := make([]byte, ciphertextBytes)
		if _, err := io.ReadFull(reader, ciphertext); err != nil {
			return fmt.Errorf("%w: truncated record", ErrBackupArchiveInvalid)
		}
		plaintext, err := aead.Open(ciphertext[:0], backupRecordNonce(value.NoncePrefix, index), ciphertext, backupRecordAAD(header, record))
		if err != nil {
			return ErrBackupAuthentication
		}
		if final {
			var trailing [1]byte
			if count, readErr := reader.Read(trailing[:]); count != 0 || readErr != io.EOF {
				return fmt.Errorf("%w: data follows authenticated final record", ErrBackupArchiveInvalid)
			}
			return nil
		}
		if err := writeBackupBytes(writer, plaintext); err != nil {
			wipeBackupBytes(plaintext)
			return fmt.Errorf("write decrypted backup payload: %w", err)
		}
		wipeBackupBytes(plaintext)
		if expected == math.MaxUint64 {
			return fmt.Errorf("%w: record counter exhausted", ErrBackupArchiveInvalid)
		}
		expected++
	}
}
