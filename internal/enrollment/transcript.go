package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	EnrollmentTranscriptSchemaVersion = 1
	EnrollmentTranscriptDomain        = "vpnctl-enrollment-transcript-v1"
	EnrollmentSignatureAlgorithm      = "Ed25519"
	EnrollmentNonceBytes              = 16
	EnrollmentClockSkew               = 120 * time.Second
	EnrollmentRecoveryPath            = model.ReservedRecoveryPath
	maximumTranscriptPresets          = 64
	maximumTranscriptPublicKeyHashes  = 16
	maximumEnrollmentTranscriptBytes  = 64 << 10
)

type EnrollmentPurpose string

const (
	PurposeEnroll  EnrollmentPurpose = "enroll"
	PurposeRecover EnrollmentPurpose = "recover"
)

var (
	ErrInvalidEnrollmentTranscript = errors.New("invalid enrollment transcript")
	ErrEnrollmentSignature         = errors.New("invalid enrollment signature")
	ErrEnrollmentTranscriptExpired = errors.New("enrollment transcript is outside its validity window")
	transcriptInviteIDPattern      = regexp.MustCompile(`^inv-[A-Z2-7]{6}$`)
	transcriptRecoveryIDPattern    = regexp.MustCompile(`^rec-[A-Z2-7]{6}$`)
	transcriptUUIDPattern          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	transcriptHashNamePattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
)

type EnrollmentTranscript struct {
	Purpose          EnrollmentPurpose
	InviteID         string
	Endpoint         string
	NodeID           string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	NodeNonce        [EnrollmentNonceBytes]byte
	GatewayNonce     [EnrollmentNonceBytes]byte
	Transport        model.TransportKind
	Presets          []string
	PublicKeyHashes  map[string][sha256.Size]byte
	AssignmentSHA256 [sha256.Size]byte
}

func NewEnrollmentTranscript(
	purpose EnrollmentPurpose,
	inviteID, endpoint, nodeID string,
	issuedAt, expiresAt time.Time,
	nodeNonce, gatewayNonce [EnrollmentNonceBytes]byte,
	transport model.TransportKind,
	presets []string,
	publicKeyHashes map[string][sha256.Size]byte,
	assignmentSHA256 [sha256.Size]byte,
) (EnrollmentTranscript, error) {
	transcript := EnrollmentTranscript{
		Purpose: purpose, InviteID: inviteID, Endpoint: endpoint, NodeID: nodeID,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, NodeNonce: nodeNonce, GatewayNonce: gatewayNonce,
		Transport: transport, Presets: append([]string(nil), presets...),
		PublicKeyHashes: cloneTranscriptHashes(publicKeyHashes), AssignmentSHA256: assignmentSHA256,
	}
	if err := transcript.Validate(); err != nil {
		return EnrollmentTranscript{}, err
	}
	transcript.Presets = canonicalTranscriptPresets(transcript.Presets)
	return transcript, nil
}

func (transcript EnrollmentTranscript) Validate() error {
	if transcript.Purpose != PurposeEnroll && transcript.Purpose != PurposeRecover {
		return fmt.Errorf("%w: unsupported purpose", ErrInvalidEnrollmentTranscript)
	}
	wantedIDPattern := transcriptInviteIDPattern
	if transcript.Purpose == PurposeRecover {
		wantedIDPattern = transcriptRecoveryIDPattern
	}
	if !wantedIDPattern.MatchString(transcript.InviteID) {
		return fmt.Errorf("%w: invite ID is invalid", ErrInvalidEnrollmentTranscript)
	}
	if !transcriptUUIDPattern.MatchString(transcript.NodeID) {
		return fmt.Errorf("%w: node ID is invalid", ErrInvalidEnrollmentTranscript)
	}
	if err := validateTranscriptEndpoint(transcript.Purpose, transcript.Endpoint); err != nil {
		return err
	}
	if transcript.IssuedAt.IsZero() || transcript.ExpiresAt.IsZero() ||
		!transcript.IssuedAt.Equal(canonicalTime(transcript.IssuedAt)) ||
		!transcript.ExpiresAt.Equal(canonicalTime(transcript.ExpiresAt)) ||
		!transcript.ExpiresAt.Equal(transcript.IssuedAt.Add(model.InviteTTL)) {
		return fmt.Errorf("%w: timestamps must be canonical and span exactly 15 minutes", ErrInvalidEnrollmentTranscript)
	}
	if allZero(transcript.NodeNonce[:]) || allZero(transcript.GatewayNonce[:]) {
		return fmt.Errorf("%w: nonces must be independent non-zero 16-byte values", ErrInvalidEnrollmentTranscript)
	}
	if transcript.NodeNonce == transcript.GatewayNonce {
		return fmt.Errorf("%w: node and gateway nonces must differ", ErrInvalidEnrollmentTranscript)
	}
	if transcript.Transport != model.TransportStandard && transcript.Transport != model.TransportRestricted {
		return fmt.Errorf("%w: transport is invalid", ErrInvalidEnrollmentTranscript)
	}
	if len(transcript.Presets) > maximumTranscriptPresets {
		return fmt.Errorf("%w: too many presets", ErrInvalidEnrollmentTranscript)
	}
	seenPresets := make(map[string]struct{}, len(transcript.Presets))
	for _, preset := range transcript.Presets {
		if err := validateInviteName(preset); err != nil {
			return fmt.Errorf("%w: preset name is invalid", ErrInvalidEnrollmentTranscript)
		}
		key := strings.ToLower(preset)
		if _, duplicate := seenPresets[key]; duplicate {
			return fmt.Errorf("%w: duplicate preset", ErrInvalidEnrollmentTranscript)
		}
		seenPresets[key] = struct{}{}
	}
	if len(transcript.PublicKeyHashes) == 0 || len(transcript.PublicKeyHashes) > maximumTranscriptPublicKeyHashes {
		return fmt.Errorf("%w: public key hash set is outside its limit", ErrInvalidEnrollmentTranscript)
	}
	for name, hash := range transcript.PublicKeyHashes {
		if !transcriptHashNamePattern.MatchString(name) || allZero(hash[:]) {
			return fmt.Errorf("%w: public key hash entry is invalid", ErrInvalidEnrollmentTranscript)
		}
	}
	if allZero(transcript.AssignmentSHA256[:]) {
		return fmt.Errorf("%w: assignment hash is required", ErrInvalidEnrollmentTranscript)
	}
	return nil
}

func (transcript EnrollmentTranscript) CanonicalBytes() ([]byte, error) {
	if err := transcript.Validate(); err != nil {
		return nil, err
	}
	buffer := bytes.NewBuffer(nil)
	appendTranscriptFrame(buffer, "domain", []byte(EnrollmentTranscriptDomain))
	appendTranscriptFrame(buffer, "purpose", []byte(transcript.Purpose))
	appendTranscriptFrame(buffer, "invite_id", []byte(transcript.InviteID))
	appendTranscriptFrame(buffer, "endpoint", []byte(transcript.Endpoint))
	appendTranscriptFrame(buffer, "node_id", []byte(transcript.NodeID))
	appendTranscriptFrame(buffer, "issued_at", []byte(transcript.IssuedAt.UTC().Format(time.RFC3339Nano)))
	appendTranscriptFrame(buffer, "expires_at", []byte(transcript.ExpiresAt.UTC().Format(time.RFC3339Nano)))
	appendTranscriptFrame(buffer, "node_nonce", transcript.NodeNonce[:])
	appendTranscriptFrame(buffer, "gateway_nonce", transcript.GatewayNonce[:])
	appendTranscriptFrame(buffer, "transport", []byte(transcript.Transport))
	for _, preset := range canonicalTranscriptPresets(transcript.Presets) {
		appendTranscriptFrame(buffer, "preset", []byte(preset))
	}
	hashNames := make([]string, 0, len(transcript.PublicKeyHashes))
	for name := range transcript.PublicKeyHashes {
		hashNames = append(hashNames, name)
	}
	sort.Strings(hashNames)
	for _, name := range hashNames {
		hash := transcript.PublicKeyHashes[name]
		appendTranscriptFrame(buffer, "public_key_hash:"+name, hash[:])
	}
	appendTranscriptFrame(buffer, "assignment_sha256", transcript.AssignmentSHA256[:])
	return buffer.Bytes(), nil
}

type SignedEnrollmentTranscript struct {
	SchemaVersion  int    `json:"schema_version"`
	Algorithm      string `json:"algorithm"`
	KeyFingerprint string `json:"key_fingerprint"`
	Transcript     string `json:"transcript"`
	Signature      string `json:"signature"`
}

type EnrollmentTranscriptSigner struct {
	privateKey  ed25519.PrivateKey
	fingerprint string
}

func NewEnrollmentTranscriptSigner(privateKeyPEM []byte, expectedFingerprint string) (*EnrollmentTranscriptSigner, error) {
	privateKey, err := parseEnrollmentPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	fingerprint, err := enrollmentPublicKeyFingerprint(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if expectedFingerprint != fingerprint {
		return nil, fmt.Errorf("%w: enrollment private key fingerprint mismatch", ErrEnrollmentSignature)
	}
	return &EnrollmentTranscriptSigner{privateKey: append(ed25519.PrivateKey(nil), privateKey...), fingerprint: fingerprint}, nil
}

func (signer *EnrollmentTranscriptSigner) Fingerprint() string {
	if signer == nil {
		return ""
	}
	return signer.fingerprint
}

func (signer *EnrollmentTranscriptSigner) Sign(transcript EnrollmentTranscript) (SignedEnrollmentTranscript, error) {
	if signer == nil || len(signer.privateKey) != ed25519.PrivateKeySize || !fingerprintPattern.MatchString(signer.fingerprint) {
		return SignedEnrollmentTranscript{}, fmt.Errorf("%w: enrollment signer is incomplete", ErrEnrollmentSignature)
	}
	canonical, err := transcript.CanonicalBytes()
	if err != nil {
		return SignedEnrollmentTranscript{}, err
	}
	defer clear(canonical)
	signature := ed25519.Sign(signer.privateKey, canonical)
	defer clear(signature)
	return SignedEnrollmentTranscript{
		SchemaVersion: EnrollmentTranscriptSchemaVersion, Algorithm: EnrollmentSignatureAlgorithm,
		KeyFingerprint: signer.fingerprint, Transcript: tokenEncoding.EncodeToString(canonical),
		Signature: tokenEncoding.EncodeToString(signature),
	}, nil
}

func VerifyEnrollmentTranscript(
	signed SignedEnrollmentTranscript,
	expected EnrollmentTranscript,
	publicKeyPEM []byte,
	expectedFingerprint string,
	now time.Time,
) (string, error) {
	if signed.SchemaVersion != EnrollmentTranscriptSchemaVersion || signed.Algorithm != EnrollmentSignatureAlgorithm ||
		signed.KeyFingerprint != expectedFingerprint || !fingerprintPattern.MatchString(expectedFingerprint) {
		return "", ErrEnrollmentSignature
	}
	publicKey, err := parseEnrollmentPublicKey(publicKeyPEM)
	if err != nil {
		return "", ErrEnrollmentSignature
	}
	fingerprint, err := enrollmentPublicKeyFingerprint(publicKey)
	if err != nil || fingerprint != expectedFingerprint {
		return "", ErrEnrollmentSignature
	}
	canonical, err := expected.CanonicalBytes()
	if err != nil {
		return "", err
	}
	defer clear(canonical)
	if len(signed.Transcript) != tokenEncoding.EncodedLen(len(canonical)) ||
		len(signed.Signature) != tokenEncoding.EncodedLen(ed25519.SignatureSize) {
		return "", ErrEnrollmentSignature
	}
	presented, err := decodeCanonicalBase64(signed.Transcript)
	if err != nil || !bytes.Equal(presented, canonical) {
		clear(presented)
		return "", ErrEnrollmentSignature
	}
	defer clear(presented)
	signature, err := decodeCanonicalBase64(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, presented, signature) {
		clear(signature)
		return "", ErrEnrollmentSignature
	}
	defer clear(signature)
	now = now.UTC()
	if now.Before(expected.IssuedAt.Add(-EnrollmentClockSkew)) || !now.Before(expected.ExpiresAt) {
		return "", ErrEnrollmentTranscriptExpired
	}
	return enrollmentReplayHash(presented, signature), nil
}

func EnrollmentReplayHash(signed SignedEnrollmentTranscript) (string, error) {
	if len(signed.Transcript) == 0 || len(signed.Transcript) > tokenEncoding.EncodedLen(maximumEnrollmentTranscriptBytes) ||
		len(signed.Signature) != tokenEncoding.EncodedLen(ed25519.SignatureSize) {
		return "", ErrEnrollmentSignature
	}
	transcript, err := decodeCanonicalBase64(signed.Transcript)
	if err != nil {
		return "", ErrEnrollmentSignature
	}
	defer clear(transcript)
	signature, err := decodeCanonicalBase64(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		clear(signature)
		return "", ErrEnrollmentSignature
	}
	defer clear(signature)
	return enrollmentReplayHash(transcript, signature), nil
}

func enrollmentReplayHash(transcript, signature []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("vpnctl-enrollment-replay-v1\x00"))
	_, _ = digest.Write(transcript)
	_, _ = digest.Write(signature)
	return hex.EncodeToString(digest.Sum(nil))
}

func validateTranscriptEndpoint(purpose EnrollmentPurpose, value string) error {
	endpoint, err := url.Parse(value)
	wantedPath := InviteEnrollmentPath
	if purpose == PurposeRecover {
		wantedPath = EnrollmentRecoveryPath
	}
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Port() != "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != wantedPath {
		return fmt.Errorf("%w: endpoint is invalid", ErrInvalidEnrollmentTranscript)
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || !address.Is4() || address.String() != endpoint.Hostname() {
		return fmt.Errorf("%w: endpoint must use canonical IPv4", ErrInvalidEnrollmentTranscript)
	}
	return nil
}

func parseEnrollmentPrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	der, err := decodeEnrollmentPEM(encoded, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: parse PKCS#8 enrollment private key", ErrEnrollmentSignature)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: enrollment private key must use Ed25519", ErrEnrollmentSignature)
	}
	return privateKey, nil
}

func parseEnrollmentPublicKey(encoded []byte) (ed25519.PublicKey, error) {
	der, err := decodeEnrollmentPEM(encoded, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: parse enrollment public key", ErrEnrollmentSignature)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: enrollment public key must use Ed25519", ErrEnrollmentSignature)
	}
	return publicKey, nil
}

func decodeEnrollmentPEM(encoded []byte, wantedType string) ([]byte, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != wantedType || len(bytes.TrimSpace(rest)) != 0 || len(block.Bytes) == 0 {
		return nil, fmt.Errorf("%w: enrollment key PEM is invalid", ErrEnrollmentSignature)
	}
	return block.Bytes, nil
}

func enrollmentPublicKeyFingerprint(publicKey ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("%w: marshal enrollment public key", ErrEnrollmentSignature)
	}
	digest := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func appendTranscriptFrame(buffer *bytes.Buffer, name string, value []byte) {
	for _, field := range [][]byte{[]byte(name), value} {
		_ = binary.Write(buffer, binary.BigEndian, uint32(len(field)))
		_, _ = buffer.Write(field)
	}
}

func canonicalTranscriptPresets(values []string) []string {
	result := append([]string(nil), values...)
	sort.Slice(result, func(left, right int) bool {
		leftKey, rightKey := strings.ToLower(result[left]), strings.ToLower(result[right])
		if leftKey == rightKey {
			return result[left] < result[right]
		}
		return leftKey < rightKey
	})
	return result
}

func cloneTranscriptHashes(values map[string][sha256.Size]byte) map[string][sha256.Size]byte {
	result := make(map[string][sha256.Size]byte, len(values))
	for name, hash := range values {
		result[name] = hash
	}
	return result
}

func allZero(value []byte) bool {
	var result byte
	for _, item := range value {
		result |= item
	}
	return result == 0
}
