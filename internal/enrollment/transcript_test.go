package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestEnrollmentTranscriptSignVerifyAndCanonicalOrdering(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	transcript := testEnrollmentTranscript(t, PurposeEnroll, now)
	signer, publicPEM, fingerprint := testEnrollmentSigner(t)

	signed, err := signer.Sign(transcript)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	replayHash, err := VerifyEnrollmentTranscript(signed, transcript, publicPEM, fingerprint, now)
	if err != nil {
		t.Fatalf("VerifyEnrollmentTranscript() error = %v", err)
	}
	wantReplayHash, err := EnrollmentReplayHash(signed)
	if err != nil || replayHash != wantReplayHash || !hashPattern.MatchString(replayHash) {
		t.Fatalf("replay hash = %q, direct = %q, error = %v", replayHash, wantReplayHash, err)
	}

	reordered := transcript
	reordered.Presets = []string{"telegram", "Anthropic"}
	reordered.PublicKeyHashes = map[string][sha256.Size]byte{
		"wireguard":   transcript.PublicKeyHashes["wireguard"],
		"control_csr": transcript.PublicKeyHashes["control_csr"],
	}
	left, err := transcript.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	right, err := reordered.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatal("canonical transcript depends on preset or key-hash insertion order")
	}
}

func TestEnrollmentTranscriptRejectsContextAndSignatureSubstitution(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	transcript := testEnrollmentTranscript(t, PurposeEnroll, now)
	signer, publicPEM, fingerprint := testEnrollmentSigner(t)
	signed, err := signer.Sign(transcript)
	if err != nil {
		t.Fatal(err)
	}

	alterations := map[string]func(*EnrollmentTranscript){
		"endpoint":      func(value *EnrollmentTranscript) { value.Endpoint = "https://203.0.113.11" + InviteEnrollmentPath },
		"node nonce":    func(value *EnrollmentTranscript) { value.NodeNonce[0] ^= 0xff },
		"gateway nonce": func(value *EnrollmentTranscript) { value.GatewayNonce[0] ^= 0xff },
		"assignment":    func(value *EnrollmentTranscript) { value.AssignmentSHA256[0] ^= 0xff },
		"transport":     func(value *EnrollmentTranscript) { value.Transport = model.TransportStandard },
	}
	for name, alter := range alterations {
		t.Run(name, func(t *testing.T) {
			expected := transcript
			alter(&expected)
			if _, err := VerifyEnrollmentTranscript(signed, expected, publicPEM, fingerprint, now); !errors.Is(err, ErrEnrollmentSignature) {
				t.Fatalf("substitution error = %v", err)
			}
		})
	}

	other := transcript
	other.NodeNonce[0] ^= 0x7f
	otherSigned, err := signer.Sign(other)
	if err != nil {
		t.Fatal(err)
	}
	substitutedSignature := signed
	substitutedSignature.Signature = otherSigned.Signature
	if _, err := VerifyEnrollmentTranscript(substitutedSignature, transcript, publicPEM, fingerprint, now); !errors.Is(err, ErrEnrollmentSignature) {
		t.Fatalf("signature substitution error = %v", err)
	}

	_, wrongPublicPEM, wrongFingerprint := testEnrollmentSigner(t)
	if _, err := VerifyEnrollmentTranscript(signed, transcript, wrongPublicPEM, wrongFingerprint, now); !errors.Is(err, ErrEnrollmentSignature) {
		t.Fatalf("wrong-key verification error = %v", err)
	}
}

func TestEnrollmentTranscriptValidityWindowAndPurposeIDs(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	transcript := testEnrollmentTranscript(t, PurposeEnroll, now)
	signer, publicPEM, fingerprint := testEnrollmentSigner(t)
	signed, _ := signer.Sign(transcript)

	if _, err := VerifyEnrollmentTranscript(signed, transcript, publicPEM, fingerprint, transcript.IssuedAt.Add(-EnrollmentClockSkew)); err != nil {
		t.Fatalf("lower skew boundary rejected: %v", err)
	}
	if _, err := VerifyEnrollmentTranscript(signed, transcript, publicPEM, fingerprint, transcript.IssuedAt.Add(-EnrollmentClockSkew-time.Second)); !errors.Is(err, ErrEnrollmentTranscriptExpired) {
		t.Fatalf("pre-window error = %v", err)
	}
	if _, err := VerifyEnrollmentTranscript(signed, transcript, publicPEM, fingerprint, transcript.ExpiresAt); !errors.Is(err, ErrEnrollmentTranscriptExpired) {
		t.Fatalf("exact-expiry error = %v", err)
	}

	recovery := transcript
	recovery.Purpose = PurposeRecover
	recovery.InviteID = "rec-ABC234"
	recovery.Endpoint = "https://203.0.113.10" + EnrollmentRecoveryPath
	if err := recovery.Validate(); err != nil {
		t.Fatalf("valid recovery transcript rejected: %v", err)
	}
	recovery.InviteID = transcript.InviteID
	if err := recovery.Validate(); !errors.Is(err, ErrInvalidEnrollmentTranscript) {
		t.Fatalf("recovery accepted enrollment ID: %v", err)
	}
	transcript.Purpose = PurposeRecover
	transcript.Endpoint = "https://203.0.113.10" + EnrollmentRecoveryPath
	if err := transcript.Validate(); !errors.Is(err, ErrInvalidEnrollmentTranscript) {
		t.Fatalf("recovery purpose accepted enrollment ID: %v", err)
	}
}

func testEnrollmentTranscript(t *testing.T, purpose EnrollmentPurpose, now time.Time) EnrollmentTranscript {
	t.Helper()
	nodeNonce := [EnrollmentNonceBytes]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	gatewayNonce := [EnrollmentNonceBytes]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	controlHash := sha256.Sum256([]byte("control-csr"))
	wireGuardHash := sha256.Sum256([]byte("wireguard-public-key"))
	assignmentHash := sha256.Sum256([]byte("normalized-assignment"))
	id := "inv-ABC234"
	path := InviteEnrollmentPath
	if purpose == PurposeRecover {
		id = "rec-ABC234"
		path = EnrollmentRecoveryPath
	}
	transcript, err := NewEnrollmentTranscript(
		purpose, id, "https://203.0.113.10"+path,
		"20000000-0000-4000-8000-000000000001", now.Add(-time.Minute), now.Add(14*time.Minute),
		nodeNonce, gatewayNonce, model.TransportRestricted, []string{"Anthropic", "telegram"},
		map[string][sha256.Size]byte{"control_csr": controlHash, "wireguard": wireGuardHash}, assignmentHash,
	)
	if err != nil {
		t.Fatalf("NewEnrollmentTranscript() error = %v", err)
	}
	return transcript
}

func testEnrollmentSigner(t *testing.T) (*EnrollmentTranscriptSigner, []byte, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := enrollmentPublicKeyFingerprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEnrollmentTranscriptSigner(
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), fingerprint
}
