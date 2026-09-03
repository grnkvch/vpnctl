package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	HandshakeHostBundleSchemaVersion   = 1
	HandshakeHostDeliverySchemaVersion = 1
	HandshakeHostSignatureAlgorithm    = "Ed25519"
	DefaultHandshakeHostProbeTimeout   = 3 * time.Second
	maximumHandshakeHostCandidates     = 8
	handshakeHostSignatureDomain       = "vpnctl-handshake-host-bundle-v1\x00"
)

var (
	ErrInvalidHandshakeHostBundle = errors.New("invalid handshake-host bundle")
	ErrNoHandshakeHostCandidate   = errors.New("no handshake-host candidate passed validation")
)

const bundledHandshakeHostPublicKey = "tCAzV5kpvCXDidVel5aefc6NLYtrgyT5h0vppG_r8JM"

//go:embed handshake_hosts.v1.json
var bundledHandshakeHostEnvelope []byte

// NewBundledHandshakeHostSelector constructs the production init selector
// from the release-pinned public key and signed candidate list embedded in the
// current development bundle. Task 14 will move the same verified artifacts
// into the self-contained release archive without changing this boundary.
func NewBundledHandshakeHostSelector() (*HandshakeHostSelector, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(bundledHandshakeHostPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode bundled handshake-host public key: %w", err)
	}
	prober, err := NewTLSHandshakeHostProber(TLSHandshakeHostProbeOptions{})
	if err != nil {
		return nil, err
	}
	return NewHandshakeHostSelector(bundledHandshakeHostEnvelope, ed25519.PublicKey(publicKey), prober, DefaultHandshakeHostProbeTimeout)
}

type HandshakeHostCandidate struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

type HandshakeHostBundle struct {
	SchemaVersion int                      `json:"schema_version"`
	ListVersion   int                      `json:"list_version"`
	Candidates    []HandshakeHostCandidate `json:"candidates"`
}

// SignedHandshakeHostBundle signs the exact canonical payload bytes. The key
// remains outside the envelope and is pinned by the release verifier.
type SignedHandshakeHostBundle struct {
	SchemaVersion int    `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	Payload       string `json:"payload"`
	Signature     string `json:"signature"`
}

func (bundle HandshakeHostBundle) Validate() error {
	if bundle.SchemaVersion != HandshakeHostBundleSchemaVersion {
		return fmt.Errorf("%w: bundle schema must be %d", ErrInvalidHandshakeHostBundle, HandshakeHostBundleSchemaVersion)
	}
	if bundle.ListVersion < 1 {
		return fmt.Errorf("%w: list version must be positive", ErrInvalidHandshakeHostBundle)
	}
	if len(bundle.Candidates) == 0 || len(bundle.Candidates) > maximumHandshakeHostCandidates {
		return fmt.Errorf("%w: candidate count must be between 1 and %d", ErrInvalidHandshakeHostBundle, maximumHandshakeHostCandidates)
	}
	ids := make(map[string]struct{}, len(bundle.Candidates))
	hostnames := make(map[string]struct{}, len(bundle.Candidates))
	for index, candidate := range bundle.Candidates {
		if err := validateHandshakeHostCandidate(candidate); err != nil {
			return fmt.Errorf("%w: candidate %d: %v", ErrInvalidHandshakeHostBundle, index, err)
		}
		if _, duplicate := ids[candidate.ID]; duplicate {
			return fmt.Errorf("%w: candidate %d duplicates ID %s", ErrInvalidHandshakeHostBundle, index, candidate.ID)
		}
		if _, duplicate := hostnames[candidate.Hostname]; duplicate {
			return fmt.Errorf("%w: candidate %d duplicates hostname %s", ErrInvalidHandshakeHostBundle, index, candidate.Hostname)
		}
		ids[candidate.ID] = struct{}{}
		hostnames[candidate.Hostname] = struct{}{}
	}
	return nil
}

func validateHandshakeHostCandidate(candidate HandshakeHostCandidate) error {
	if candidate.ID == "" || len(candidate.ID) > 32 || candidate.ID[0] < 'a' || candidate.ID[0] > 'z' {
		return fmt.Errorf("ID must be a canonical lower-case token")
	}
	for _, character := range candidate.ID {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return fmt.Errorf("ID must be a canonical lower-case token")
		}
	}
	selection := model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1,
		CandidateID: candidate.ID, Hostname: candidate.Hostname, SelectedAt: time.Unix(1, 0).UTC(),
	}
	if err := selection.Validate(); err != nil {
		return err
	}
	return nil
}

func DecodeAndVerifyHandshakeHostBundle(data []byte, publicKey ed25519.PublicKey) (HandshakeHostBundle, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return HandshakeHostBundle{}, fmt.Errorf("%w: release public key must be Ed25519", ErrInvalidHandshakeHostBundle)
	}
	var envelope SignedHandshakeHostBundle
	if err := decodeStrictHandshakeHostJSON(data, &envelope); err != nil {
		return HandshakeHostBundle{}, fmt.Errorf("%w: decode envelope: %v", ErrInvalidHandshakeHostBundle, err)
	}
	if envelope.SchemaVersion != HandshakeHostBundleSchemaVersion || envelope.Algorithm != HandshakeHostSignatureAlgorithm {
		return HandshakeHostBundle{}, fmt.Errorf("%w: unsupported signature envelope", ErrInvalidHandshakeHostBundle)
	}
	wantKeyID := handshakeHostKeyID(publicKey)
	if envelope.KeyID != wantKeyID {
		return HandshakeHostBundle{}, fmt.Errorf("%w: release key ID mismatch", ErrInvalidHandshakeHostBundle)
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != envelope.Payload {
		return HandshakeHostBundle{}, fmt.Errorf("%w: payload must be canonical base64url", ErrInvalidHandshakeHostBundle)
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != envelope.Signature || len(signature) != ed25519.SignatureSize {
		return HandshakeHostBundle{}, fmt.Errorf("%w: signature must be canonical Ed25519 base64url", ErrInvalidHandshakeHostBundle)
	}
	if !ed25519.Verify(publicKey, handshakeHostSignedMessage(payload), signature) {
		return HandshakeHostBundle{}, fmt.Errorf("%w: signature verification failed", ErrInvalidHandshakeHostBundle)
	}
	var bundle HandshakeHostBundle
	if err := decodeStrictHandshakeHostJSON(payload, &bundle); err != nil {
		return HandshakeHostBundle{}, fmt.Errorf("%w: decode payload: %v", ErrInvalidHandshakeHostBundle, err)
	}
	canonical, err := json.Marshal(bundle)
	if err != nil || !bytes.Equal(canonical, payload) {
		return HandshakeHostBundle{}, fmt.Errorf("%w: payload is not canonical JSON", ErrInvalidHandshakeHostBundle)
	}
	if err := bundle.Validate(); err != nil {
		return HandshakeHostBundle{}, err
	}
	return cloneHandshakeHostBundle(bundle), nil
}

func handshakeHostSignedMessage(payload []byte) []byte {
	message := make([]byte, 0, len(handshakeHostSignatureDomain)+len(payload))
	message = append(message, handshakeHostSignatureDomain...)
	return append(message, payload...)
}

func handshakeHostKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func cloneHandshakeHostBundle(bundle HandshakeHostBundle) HandshakeHostBundle {
	bundle.Candidates = append([]HandshakeHostCandidate(nil), bundle.Candidates...)
	return bundle
}

type HandshakeHostProbeResult struct {
	CandidateID      string
	Hostname         string
	ObservedAt       time.Time
	Reachable        bool
	TLS13            bool
	CertificateValid bool
	Latency          time.Duration
	Code             string
}

func (result HandshakeHostProbeResult) passes(candidate HandshakeHostCandidate, maximumLatency time.Duration) bool {
	return result.CandidateID == candidate.ID && result.Hostname == candidate.Hostname &&
		result.Reachable && result.TLS13 && result.CertificateValid && result.Latency > 0 && result.Latency <= maximumLatency
}

type HandshakeHostProber interface {
	Probe(context.Context, HandshakeHostCandidate) HandshakeHostProbeResult
}

type HandshakeHostSelector struct {
	bundle         HandshakeHostBundle
	prober         HandshakeHostProber
	maximumLatency time.Duration
}

func NewHandshakeHostSelector(signedBundle []byte, publicKey ed25519.PublicKey, prober HandshakeHostProber, maximumLatency time.Duration) (*HandshakeHostSelector, error) {
	if prober == nil {
		return nil, fmt.Errorf("handshake-host prober is required")
	}
	if maximumLatency <= 0 || maximumLatency > 30*time.Second {
		return nil, fmt.Errorf("handshake-host maximum latency must be between zero and 30 seconds")
	}
	bundle, err := DecodeAndVerifyHandshakeHostBundle(signedBundle, publicKey)
	if err != nil {
		return nil, err
	}
	return &HandshakeHostSelector{bundle: bundle, prober: prober, maximumLatency: maximumLatency}, nil
}

// Select is an init-only ordered search. It returns the first passing entry,
// never the lowest-latency entry, and has no method that can rotate a saved
// selection at runtime.
func (selector *HandshakeHostSelector) Select(ctx context.Context, expectedListVersion int, selectedAt time.Time) (model.HandshakeHost, error) {
	if ctx == nil {
		return model.HandshakeHost{}, fmt.Errorf("context is required")
	}
	if selector == nil || selector.prober == nil {
		return model.HandshakeHost{}, fmt.Errorf("handshake-host selector is incomplete")
	}
	if selector.bundle.ListVersion != expectedListVersion {
		return model.HandshakeHost{}, fmt.Errorf("%w: list version %d does not match manifest version %d", ErrInvalidHandshakeHostBundle, selector.bundle.ListVersion, expectedListVersion)
	}
	if selectedAt.IsZero() || selectedAt.Location() != time.UTC {
		return model.HandshakeHost{}, fmt.Errorf("handshake-host selection time must use UTC")
	}
	for _, candidate := range selector.bundle.Candidates {
		if err := ctx.Err(); err != nil {
			return model.HandshakeHost{}, err
		}
		result := selector.prober.Probe(ctx, candidate)
		if result.passes(candidate, selector.maximumLatency) {
			selection := model.HandshakeHost{
				SchemaVersion: model.ResourceSchemaVersion, ListVersion: selector.bundle.ListVersion,
				CandidateID: candidate.ID, Hostname: candidate.Hostname, SelectedAt: selectedAt,
			}
			if err := selection.Validate(); err != nil {
				return model.HandshakeHost{}, fmt.Errorf("selected handshake host: %w", err)
			}
			return selection, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return model.HandshakeHost{}, err
	}
	return model.HandshakeHost{}, ErrNoHandshakeHostCandidate
}

type TLSHandshakeHostProbeOptions struct {
	Port        int
	Timeout     time.Duration
	RootCAs     *x509.CertPool
	DialContext func(context.Context, string, string) (net.Conn, error)
	Now         func() time.Time
}

type TLSHandshakeHostProber struct {
	options TLSHandshakeHostProbeOptions
}

func NewTLSHandshakeHostProber(options TLSHandshakeHostProbeOptions) (*TLSHandshakeHostProber, error) {
	if options.Port == 0 {
		options.Port = 443
	}
	if options.Port < 1 || options.Port > 65535 {
		return nil, fmt.Errorf("handshake-host probe port is invalid")
	}
	if options.Timeout == 0 {
		options.Timeout = DefaultHandshakeHostProbeTimeout
	}
	if options.Timeout <= 0 || options.Timeout > 30*time.Second {
		return nil, fmt.Errorf("handshake-host probe timeout must be between zero and 30 seconds")
	}
	if options.DialContext == nil {
		dialer := &net.Dialer{Timeout: options.Timeout}
		options.DialContext = dialer.DialContext
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &TLSHandshakeHostProber{options: options}, nil
}

func (prober *TLSHandshakeHostProber) Probe(ctx context.Context, candidate HandshakeHostCandidate) HandshakeHostProbeResult {
	result := HandshakeHostProbeResult{CandidateID: candidate.ID, Hostname: candidate.Hostname, Code: "reachability-failed"}
	if ctx == nil || prober == nil || prober.options.DialContext == nil || validateHandshakeHostCandidate(candidate) != nil {
		return result
	}
	started := prober.options.Now()
	probeContext, cancel := context.WithTimeout(ctx, prober.options.Timeout)
	defer cancel()
	address := net.JoinHostPort(candidate.Hostname, strconv.Itoa(prober.options.Port))
	raw, err := prober.options.DialContext(probeContext, "tcp", address)
	if err != nil {
		result.ObservedAt = prober.options.Now().UTC()
		result.Latency = result.ObservedAt.Sub(started)
		return result
	}
	defer raw.Close()
	result.Reachable = true
	connection := tls.Client(raw, &tls.Config{
		ServerName: candidate.Hostname, RootCAs: prober.options.RootCAs,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
	})
	if err := connection.HandshakeContext(probeContext); err != nil {
		result.Code = "tls-or-certificate-failed"
		result.ObservedAt = prober.options.Now().UTC()
		result.Latency = result.ObservedAt.Sub(started)
		return result
	}
	state := connection.ConnectionState()
	result.TLS13 = state.Version == tls.VersionTLS13
	result.CertificateValid = len(state.VerifiedChains) != 0
	result.ObservedAt = prober.options.Now().UTC()
	result.Latency = result.ObservedAt.Sub(started)
	switch {
	case !result.TLS13:
		result.Code = "tls13-unavailable"
	case !result.CertificateValid:
		result.Code = "certificate-invalid"
	case result.Latency > prober.options.Timeout:
		result.Code = "latency-exceeded"
	default:
		result.Code = "passed"
	}
	return result
}

type HandshakeHostDelivery struct {
	SchemaVersion int       `json:"schema_version"`
	ListVersion   int       `json:"list_version"`
	CandidateID   string    `json:"candidate_id"`
	Hostname      string    `json:"hostname"`
	SelectedAt    time.Time `json:"selected_at"`
}

func (delivery HandshakeHostDelivery) Validate() error {
	if delivery.SchemaVersion != HandshakeHostDeliverySchemaVersion {
		return fmt.Errorf("handshake-host delivery schema must be %d", HandshakeHostDeliverySchemaVersion)
	}
	return delivery.Selection().Validate()
}

func (delivery HandshakeHostDelivery) Selection() model.HandshakeHost {
	return model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: delivery.ListVersion,
		CandidateID: delivery.CandidateID, Hostname: delivery.Hostname, SelectedAt: delivery.SelectedAt,
	}
}

// HandshakeHostDeliveryFor returns the same pinned value for node enrollment
// and client export. It never consults the candidate bundle or health state.
func HandshakeHostDeliveryFor(state model.State, ownerKind model.TargetKind, ownerID string) (HandshakeHostDelivery, error) {
	if err := state.Validate(); err != nil {
		return HandshakeHostDelivery{}, fmt.Errorf("validate handshake-host delivery state: %w", err)
	}
	if state.HandshakeHost == nil {
		return HandshakeHostDelivery{}, fmt.Errorf("authoritative handshake host is absent")
	}
	found := false
	for _, value := range state.Transports {
		if value.OwnerKind == ownerKind && value.OwnerID == ownerID && value.Kind == model.TransportRestricted && value.State != model.TransportDisabled {
			found = true
			break
		}
	}
	if !found {
		return HandshakeHostDelivery{}, fmt.Errorf("%s %s has no enabled restricted transport", ownerKind, ownerID)
	}
	delivery := HandshakeHostDelivery{
		SchemaVersion: HandshakeHostDeliverySchemaVersion, ListVersion: state.HandshakeHost.ListVersion,
		CandidateID: state.HandshakeHost.CandidateID, Hostname: state.HandshakeHost.Hostname, SelectedAt: state.HandshakeHost.SelectedAt,
	}
	return delivery, delivery.Validate()
}

type HandshakeHostHealth struct {
	Condition      HealthCondition
	Code           string
	RequiresAction bool
	Selection      model.HandshakeHost
}

// EvaluatePinnedHandshakeHost is passive: status/doctor pass in the latest
// observation of the one pinned host. This function cannot probe the bundle,
// select another candidate, or mutate authoritative state.
func EvaluatePinnedHandshakeHost(selection model.HandshakeHost, observation HandshakeHostProbeResult, maximumLatency time.Duration) (HandshakeHostHealth, error) {
	if err := selection.Validate(); err != nil {
		return HandshakeHostHealth{}, err
	}
	if maximumLatency <= 0 || maximumLatency > 30*time.Second {
		return HandshakeHostHealth{}, fmt.Errorf("handshake-host maximum latency must be between zero and 30 seconds")
	}
	candidate := HandshakeHostCandidate{ID: selection.CandidateID, Hostname: selection.Hostname}
	health := HandshakeHostHealth{Condition: HealthDegraded, Code: "handshake-host-degraded", RequiresAction: true, Selection: selection}
	if observation.CandidateID != candidate.ID || observation.Hostname != candidate.Hostname {
		return HandshakeHostHealth{}, fmt.Errorf("handshake-host observation does not describe the pinned candidate")
	}
	if observation.ObservedAt.IsZero() || observation.ObservedAt.Location() != time.UTC || observation.ObservedAt.Before(selection.SelectedAt) {
		return HandshakeHostHealth{}, fmt.Errorf("handshake-host observation time is invalid")
	}
	if observation.passes(candidate, maximumLatency) {
		health.Condition = HealthHealthy
		health.Code = "handshake-host-healthy"
		health.RequiresAction = false
	}
	return health, nil
}

func decodeStrictHandshakeHostJSON(data []byte, destination any) error {
	if err := rejectHandshakeHostDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON documents")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func rejectHandshakeHostDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		if err := walkHandshakeHostJSON(decoder); err != nil {
			return err
		}
		if _, err := decoder.Token(); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		return fmt.Errorf("multiple JSON documents")
	}
}

func walkHandshakeHostJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			keys[key] = struct{}{}
			if err := walkHandshakeHostJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkHandshakeHostJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
