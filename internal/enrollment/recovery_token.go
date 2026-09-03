package enrollment

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const (
	RecoveryTokenSchemaVersion = 1
	RecoverySecretBytes        = 32
	recoveryPurpose            = "recover"
)

var (
	ErrRecoveryTokenInvalid = errors.New("recovery token is invalid")
	ErrRecoveryNotFound     = errors.New("recovery invite does not exist")
	ErrRecoveryExpired      = errors.New("recovery invite has expired")
	ErrRecoveryConsumed     = errors.New("recovery invite is already consumed")
	ErrRecoveryNodeInactive = errors.New("only an active node with an expired control certificate can be recovered")
	ErrRecoveryPlanStale    = errors.New("recovery invite plan is stale")
	recoveryIDPattern       = regexp.MustCompile(`^rec-[A-Z2-7]{6}$`)
)

type RecoveryIssuePlan struct {
	NodeID                  string
	NodeName                string
	CredentialGeneration    uint64
	BindingFingerprint      string
	ControlProtocol         string
	GatewayEndpoint         string
	EnrollmentFingerprint   string
	IssuedAt                time.Time
	ExpiresAt               time.Time
	ExpectedStateGeneration uint64
}

type RecoveryIssueResult struct {
	RecoveryID      string
	NodeID          string
	NodeName        string
	ExpiresAt       time.Time
	StateGeneration uint64
	Token           *output.Secret
}

type RecoveryAuthorization struct {
	RecoveryID                    string
	NodeID                        string
	NodeName                      string
	CredentialGeneration          uint64
	BindingFingerprint            string
	ControlProtocol               string
	GatewayEndpoint               string
	EnrollmentFingerprint         string
	IssuedAt                      time.Time
	ExpiresAt                     time.Time
	ExpectedStateGeneration       uint64
	RequestedCredentialGeneration uint64
	ActiveTransport               model.TransportKind
	Presets                       []string
	OverlayIPv4                   string
	PolicyGeneration              uint64
	PolicyEffectiveHash           string
	ExposeIDs                     []string

	invite model.Invite
}

type RecoveryManager struct {
	state   InviteStateStore
	entropy io.Reader
	now     func() time.Time
}

func NewRecoveryManager(state InviteStateStore, entropy io.Reader, now func() time.Time) (*RecoveryManager, error) {
	if state == nil {
		return nil, fmt.Errorf("recovery manager state store is required")
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	if now == nil {
		now = time.Now
	}
	return &RecoveryManager{state: state, entropy: entropy, now: now}, nil
}

func (manager *RecoveryManager) PlanIssue(reference string) (RecoveryIssuePlan, error) {
	if manager == nil {
		return RecoveryIssuePlan{}, fmt.Errorf("recovery manager is required")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return RecoveryIssuePlan{}, err
	}
	node, err := resolveVisibleNode(state.Nodes, reference)
	if err != nil {
		return RecoveryIssuePlan{}, err
	}
	now := canonicalTime(manager.now())
	certificate, err := validateRecoverableNode(state, node, now)
	if err != nil {
		return RecoveryIssuePlan{}, err
	}
	if state.EnrollmentIdentity == nil {
		return RecoveryIssuePlan{}, fmt.Errorf("gateway enrollment identity is unavailable")
	}
	return RecoveryIssuePlan{
		NodeID: node.ID, NodeName: node.Name, CredentialGeneration: node.CredentialGeneration,
		BindingFingerprint: certificate.Fingerprint, ControlProtocol: state.Components.ControlProtocols[0],
		GatewayEndpoint:       recoveryGatewayEndpoint(state.Host.PublicIPv4),
		EnrollmentFingerprint: state.EnrollmentIdentity.Fingerprint,
		IssuedAt:              now, ExpiresAt: now.Add(model.InviteTTL), ExpectedStateGeneration: state.Generation,
	}, nil
}

func (manager *RecoveryManager) CommitIssue(ctx context.Context, plan RecoveryIssuePlan) (RecoveryIssueResult, error) {
	if manager == nil || ctx == nil {
		return RecoveryIssueResult{}, fmt.Errorf("recovery issue input is incomplete")
	}
	if err := validateRecoveryIssuePlan(plan); err != nil {
		return RecoveryIssueResult{}, err
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return RecoveryIssueResult{}, err
	}
	if state.Generation != plan.ExpectedStateGeneration || state.EnrollmentIdentity == nil ||
		state.EnrollmentIdentity.Fingerprint != plan.EnrollmentFingerprint ||
		recoveryGatewayEndpoint(state.Host.PublicIPv4) != plan.GatewayEndpoint ||
		!containsString(state.Components.ControlProtocols, plan.ControlProtocol) {
		return RecoveryIssueResult{}, ErrRecoveryPlanStale
	}
	node, err := activeRecoveryNode(state, plan.NodeID, plan.CredentialGeneration)
	if err != nil || node.Name != plan.NodeName {
		return RecoveryIssueResult{}, ErrRecoveryPlanStale
	}
	now := canonicalTime(manager.now())
	certificate, err := validateRecoverableNode(state, node, now)
	if err != nil || certificate.Fingerprint != plan.BindingFingerprint || now.Before(plan.IssuedAt) || !now.Before(plan.ExpiresAt) {
		return RecoveryIssueResult{}, ErrRecoveryPlanStale
	}
	if err := ctx.Err(); err != nil {
		return RecoveryIssueResult{}, err
	}
	recoveryID, err := manager.allocateRecoveryID(state.Invites)
	if err != nil {
		return RecoveryIssueResult{}, err
	}
	secret := make([]byte, RecoverySecretBytes)
	if _, err := io.ReadFull(manager.entropy, secret); err != nil || allZero(secret) {
		clear(secret)
		return RecoveryIssueResult{}, fmt.Errorf("read recovery secret entropy")
	}
	defer clear(secret)
	issuedAt := now
	nextStateGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return RecoveryIssueResult{}, err
	}
	invite := model.Invite{
		SchemaVersion: model.ResourceSchemaVersion, ID: recoveryID, Purpose: recoveryPurpose,
		NodeName: node.Name, NodeID: node.ID, CredentialGeneration: node.CredentialGeneration,
		BindingFingerprint: certificate.Fingerprint, ControlProtocol: plan.ControlProtocol,
		GatewayEndpoint: plan.GatewayEndpoint, EnrollmentFingerprint: plan.EnrollmentFingerprint,
		SecretHash: hashRecoverySecret(secret), State: model.InviteActive,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(model.InviteTTL),
	}
	token, err := encodeRecoveryToken(invite, nextStateGeneration, secret)
	if err != nil {
		return RecoveryIssueResult{}, err
	}
	candidate := state
	candidate.Generation = nextStateGeneration
	candidate.Invites = append(append([]model.Invite(nil), state.Invites...), invite)
	if err := model.ValidateTransition(state, candidate); err != nil {
		token.Destroy()
		return RecoveryIssueResult{}, fmt.Errorf("build recovery invite transition: %w", err)
	}
	if err := manager.state.Save(state.Generation, candidate); err != nil {
		token.Destroy()
		return RecoveryIssueResult{}, fmt.Errorf("persist recovery invite: %w", err)
	}
	return RecoveryIssueResult{
		RecoveryID: recoveryID, NodeID: node.ID, NodeName: node.Name,
		ExpiresAt: invite.ExpiresAt, StateGeneration: candidate.Generation, Token: token,
	}, nil
}

func (manager *RecoveryManager) Authorize(encoded []byte) (RecoveryAuthorization, error) {
	if manager == nil || manager.state == nil {
		return RecoveryAuthorization{}, fmt.Errorf("recovery manager is required")
	}
	token, err := DecodeRecoveryToken(encoded)
	if err != nil {
		return RecoveryAuthorization{}, err
	}
	defer token.Destroy()
	state, err := manager.loadGatewayState()
	if err != nil {
		return RecoveryAuthorization{}, err
	}
	if state.EnrollmentIdentity == nil || state.EnrollmentIdentity.Fingerprint != token.EnrollmentFingerprint ||
		recoveryGatewayEndpoint(state.Host.PublicIPv4) != token.GatewayEndpoint ||
		!containsString(state.Components.ControlProtocols, token.ControlProtocol) {
		return RecoveryAuthorization{}, ErrRecoveryTokenInvalid
	}
	index := inviteIndex(state.Invites, token.RecoveryID)
	if index < 0 || state.Invites[index].Purpose != recoveryPurpose {
		return RecoveryAuthorization{}, ErrRecoveryNotFound
	}
	invite := state.Invites[index]
	if !recoveryTokenMatchesInvite(*token, invite) {
		return RecoveryAuthorization{}, ErrRecoveryTokenInvalid
	}
	var presentedHash string
	if err := token.secret.Use(func(secret []byte) error {
		presentedHash = hashRecoverySecret(secret)
		return nil
	}); err != nil || !hmac.Equal([]byte(presentedHash), []byte(invite.SecretHash)) {
		return RecoveryAuthorization{}, ErrRecoveryTokenInvalid
	}
	switch invite.State {
	case model.InviteConsumed:
		return RecoveryAuthorization{}, ErrRecoveryConsumed
	case model.InviteCancelled:
		return RecoveryAuthorization{}, ErrRecoveryTokenInvalid
	}
	if state.Generation != token.ExpectedGatewayStateGeneration {
		return RecoveryAuthorization{}, ErrRecoveryPlanStale
	}
	now := canonicalTime(manager.now())
	if now.Before(invite.IssuedAt) || !now.Before(invite.ExpiresAt) {
		return RecoveryAuthorization{}, ErrRecoveryExpired
	}
	node, err := activeRecoveryNode(state, invite.NodeID, invite.CredentialGeneration)
	if err != nil || node.Name != invite.NodeName {
		return RecoveryAuthorization{}, ErrRecoveryNodeInactive
	}
	certificate, err := validateRecoverableNode(state, node, now)
	if err != nil || certificate.Fingerprint != invite.BindingFingerprint {
		return RecoveryAuthorization{}, ErrRecoveryNodeInactive
	}
	nextGeneration, err := model.NextGeneration(node.CredentialGeneration)
	if err != nil {
		return RecoveryAuthorization{}, err
	}
	authorization := RecoveryAuthorization{
		RecoveryID: invite.ID, NodeID: node.ID, NodeName: node.Name,
		CredentialGeneration: node.CredentialGeneration, RequestedCredentialGeneration: nextGeneration,
		BindingFingerprint: invite.BindingFingerprint, ControlProtocol: invite.ControlProtocol,
		GatewayEndpoint: invite.GatewayEndpoint, EnrollmentFingerprint: invite.EnrollmentFingerprint,
		IssuedAt: invite.IssuedAt, ExpiresAt: invite.ExpiresAt,
		ExpectedStateGeneration: state.Generation, ActiveTransport: node.ActiveTransport,
		Presets: append([]string{}, node.AssignedPresets...), OverlayIPv4: node.OverlayIPv4, invite: invite,
	}
	for _, policy := range state.Policies {
		if policy.TargetKind == model.TargetNode && policy.TargetID == node.ID {
			authorization.PolicyGeneration = policy.Generation
			authorization.PolicyEffectiveHash = policy.EffectiveHash
		}
	}
	for _, expose := range state.Exposes {
		if expose.NodeID == node.ID {
			authorization.ExposeIDs = append(authorization.ExposeIDs, expose.ID)
		}
	}
	sortStrings(authorization.Presets)
	sortStrings(authorization.ExposeIDs)
	return authorization, nil
}

func consumeRecoveryCandidate(
	current model.State,
	candidate *model.State,
	authorization RecoveryAuthorization,
	consumptionHash string,
	now time.Time,
) error {
	if candidate == nil || !hashPattern.MatchString(consumptionHash) || current.Generation != authorization.ExpectedStateGeneration ||
		authorization.invite.ID != authorization.RecoveryID {
		return ErrRecoveryPlanStale
	}
	index := inviteIndex(current.Invites, authorization.RecoveryID)
	if index < 0 || !reflect.DeepEqual(current.Invites[index], authorization.invite) || current.Invites[index].State != model.InviteActive {
		return classifyRecoveryConflict(current, authorization)
	}
	now = canonicalTime(now)
	if now.Before(authorization.IssuedAt) || !now.Before(authorization.ExpiresAt) {
		return ErrRecoveryExpired
	}
	if _, err := activeRecoveryNode(current, authorization.NodeID, authorization.CredentialGeneration); err != nil {
		return ErrRecoveryNodeInactive
	}
	candidate.Invites = append([]model.Invite(nil), current.Invites...)
	consumed := candidate.Invites[index]
	consumed.State = model.InviteConsumed
	consumed.ConsumedAt = &now
	consumed.ConsumptionHash = consumptionHash
	candidate.Invites[index] = consumed
	return nil
}

func classifyRecoveryConflict(state model.State, authorization RecoveryAuthorization) error {
	index := inviteIndex(state.Invites, authorization.RecoveryID)
	if index < 0 {
		return ErrRecoveryNotFound
	}
	if state.Invites[index].State == model.InviteConsumed {
		return ErrRecoveryConsumed
	}
	return ErrRecoveryPlanStale
}

type recoveryTokenEnvelope struct {
	SchemaVersion                  int    `json:"schema_version"`
	Purpose                        string `json:"purpose"`
	ControlProtocol                string `json:"control_protocol"`
	GatewayEndpoint                string `json:"gateway_endpoint"`
	EnrollmentFingerprint          string `json:"enrollment_fingerprint"`
	RecoveryID                     string `json:"recovery_id"`
	Secret                         string `json:"secret"`
	NodeID                         string `json:"node_id"`
	NodeName                       string `json:"node_name"`
	CredentialGeneration           uint64 `json:"credential_generation"`
	BindingFingerprint             string `json:"binding_fingerprint"`
	ExpectedGatewayStateGeneration uint64 `json:"expected_gateway_state_generation"`
	IssuedAt                       string `json:"issued_at"`
	ExpiresAt                      string `json:"expires_at"`
}

type DecodedRecoveryToken struct {
	RecoveryID                     string
	NodeID                         string
	NodeName                       string
	CredentialGeneration           uint64
	BindingFingerprint             string
	ControlProtocol                string
	GatewayEndpoint                string
	EnrollmentFingerprint          string
	ExpectedGatewayStateGeneration uint64
	IssuedAt                       time.Time
	ExpiresAt                      time.Time
	secret                         output.Secret
}

func (token DecodedRecoveryToken) String() string   { return output.RedactedMarker }
func (token DecodedRecoveryToken) GoString() string { return output.RedactedMarker }
func (DecodedRecoveryToken) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}
func (token *DecodedRecoveryToken) Destroy() {
	if token != nil {
		token.secret.Destroy()
	}
}

func encodeRecoveryToken(invite model.Invite, gatewayGeneration uint64, secret []byte) (*output.Secret, error) {
	if invite.Purpose != recoveryPurpose || gatewayGeneration == 0 || len(secret) != RecoverySecretBytes ||
		hashRecoverySecret(secret) != invite.SecretHash {
		return nil, ErrRecoveryTokenInvalid
	}
	envelope := recoveryTokenEnvelope{
		SchemaVersion: RecoveryTokenSchemaVersion, Purpose: recoveryPurpose,
		ControlProtocol: invite.ControlProtocol, GatewayEndpoint: invite.GatewayEndpoint,
		EnrollmentFingerprint: invite.EnrollmentFingerprint, RecoveryID: invite.ID,
		Secret: tokenEncoding.EncodeToString(secret), NodeID: invite.NodeID, NodeName: invite.NodeName,
		CredentialGeneration: invite.CredentialGeneration, BindingFingerprint: invite.BindingFingerprint,
		ExpectedGatewayStateGeneration: gatewayGeneration,
		IssuedAt:                       formatTokenTime(invite.IssuedAt), ExpiresAt: formatTokenTime(invite.ExpiresAt),
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	tag := recoveryTokenTag(secret, payload)
	defer clear(tag)
	encoded := RecoveryTokenPrefix + "." + tokenEncoding.EncodeToString(payload) + "." + tokenEncoding.EncodeToString(tag)
	value, err := output.NewSecretString(encoded)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func DecodeRecoveryToken(encoded []byte) (*DecodedRecoveryToken, error) {
	if len(encoded) == 0 || len(encoded) > maximumInviteTokenBytes || bytes.ContainsAny(encoded, " \t\r\n\x00") {
		return nil, ErrRecoveryTokenInvalid
	}
	parts := strings.Split(string(encoded), ".")
	if len(parts) != 3 || parts[0] != RecoveryTokenPrefix {
		return nil, ErrRecoveryTokenInvalid
	}
	payload, err := decodeCanonicalBase64(parts[1])
	if err != nil {
		return nil, ErrRecoveryTokenInvalid
	}
	defer clear(payload)
	tag, err := decodeCanonicalBase64(parts[2])
	if err != nil || len(tag) != sha256.Size {
		clear(tag)
		return nil, ErrRecoveryTokenInvalid
	}
	defer clear(tag)
	var envelope recoveryTokenEnvelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil {
		return nil, ErrRecoveryTokenInvalid
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, ErrRecoveryTokenInvalid
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, payload) {
		clear(canonical)
		return nil, ErrRecoveryTokenInvalid
	}
	clear(canonical)
	secret, err := decodeCanonicalBase64(envelope.Secret)
	if err != nil || len(secret) != RecoverySecretBytes {
		clear(secret)
		return nil, ErrRecoveryTokenInvalid
	}
	wantedTag := recoveryTokenTag(secret, payload)
	valid := hmac.Equal(tag, wantedTag)
	clear(wantedTag)
	if !valid {
		clear(secret)
		return nil, ErrRecoveryTokenInvalid
	}
	issuedAt, expiresAt, err := validateRecoveryTokenEnvelope(envelope)
	if err != nil {
		clear(secret)
		return nil, ErrRecoveryTokenInvalid
	}
	secretValue, err := output.NewSecret(secret)
	clear(secret)
	if err != nil {
		return nil, ErrRecoveryTokenInvalid
	}
	return &DecodedRecoveryToken{
		RecoveryID: envelope.RecoveryID, NodeID: envelope.NodeID, NodeName: envelope.NodeName,
		CredentialGeneration: envelope.CredentialGeneration, BindingFingerprint: envelope.BindingFingerprint,
		ControlProtocol: envelope.ControlProtocol, GatewayEndpoint: envelope.GatewayEndpoint,
		EnrollmentFingerprint:          envelope.EnrollmentFingerprint,
		ExpectedGatewayStateGeneration: envelope.ExpectedGatewayStateGeneration,
		IssuedAt:                       issuedAt, ExpiresAt: expiresAt, secret: secretValue,
	}, nil
}

func validateRecoveryTokenEnvelope(envelope recoveryTokenEnvelope) (time.Time, time.Time, error) {
	if envelope.SchemaVersion != RecoveryTokenSchemaVersion || envelope.Purpose != recoveryPurpose ||
		!recoveryIDPattern.MatchString(envelope.RecoveryID) || !transcriptUUIDPattern.MatchString(envelope.NodeID) ||
		validateInviteName(envelope.NodeName) != nil || envelope.CredentialGeneration == 0 ||
		!fingerprintPattern.MatchString(envelope.BindingFingerprint) || !protocolPattern.MatchString(envelope.ControlProtocol) ||
		!fingerprintPattern.MatchString(envelope.EnrollmentFingerprint) || envelope.ExpectedGatewayStateGeneration == 0 {
		return time.Time{}, time.Time{}, ErrRecoveryTokenInvalid
	}
	endpoint, err := url.Parse(envelope.GatewayEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Port() != "" || endpoint.Path != EnrollmentRecoveryPath {
		return time.Time{}, time.Time{}, ErrRecoveryTokenInvalid
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || !address.Is4() || address.String() != endpoint.Hostname() {
		return time.Time{}, time.Time{}, ErrRecoveryTokenInvalid
	}
	issuedAt, err := parseTokenTime(envelope.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expiresAt, err := parseTokenTime(envelope.ExpiresAt)
	if err != nil || !expiresAt.Equal(issuedAt.Add(model.InviteTTL)) {
		return time.Time{}, time.Time{}, ErrRecoveryTokenInvalid
	}
	return issuedAt, expiresAt, nil
}

func recoveryTokenMatchesInvite(token DecodedRecoveryToken, invite model.Invite) bool {
	return invite.ID == token.RecoveryID && invite.NodeID == token.NodeID && invite.NodeName == token.NodeName &&
		invite.CredentialGeneration == token.CredentialGeneration && invite.BindingFingerprint == token.BindingFingerprint &&
		invite.ControlProtocol == token.ControlProtocol && invite.GatewayEndpoint == token.GatewayEndpoint &&
		invite.EnrollmentFingerprint == token.EnrollmentFingerprint && invite.IssuedAt.Equal(token.IssuedAt) &&
		invite.ExpiresAt.Equal(token.ExpiresAt)
}

func validateRecoverableNode(state model.State, node model.Node, now time.Time) (model.Certificate, error) {
	if node.Lifecycle != model.LifecycleActive {
		return model.Certificate{}, ErrRecoveryNodeInactive
	}
	certificate, err := currentNodeControlCertificate(state, node)
	if err != nil {
		return model.Certificate{}, err
	}
	condition, _ := evaluateNodeCertificate(certificate, now)
	if condition != NodeCertificateExpired {
		return model.Certificate{}, ErrRecoveryNodeInactive
	}
	return certificate, nil
}

func activeRecoveryNode(state model.State, nodeID string, generation uint64) (model.Node, error) {
	for _, node := range state.Nodes {
		if node.ID == nodeID {
			if node.Lifecycle != model.LifecycleActive || node.CredentialGeneration != generation {
				return model.Node{}, ErrRecoveryNodeInactive
			}
			return node, nil
		}
	}
	return model.Node{}, ErrRecoveryNotFound
}

func validateRecoveryIssuePlan(plan RecoveryIssuePlan) error {
	if !transcriptUUIDPattern.MatchString(plan.NodeID) || validateInviteName(plan.NodeName) != nil ||
		plan.CredentialGeneration == 0 || !fingerprintPattern.MatchString(plan.BindingFingerprint) ||
		!protocolPattern.MatchString(plan.ControlProtocol) || !fingerprintPattern.MatchString(plan.EnrollmentFingerprint) ||
		plan.ExpectedStateGeneration == 0 || !plan.ExpiresAt.Equal(plan.IssuedAt.Add(model.InviteTTL)) ||
		!plan.IssuedAt.Equal(canonicalTime(plan.IssuedAt)) || !plan.ExpiresAt.Equal(canonicalTime(plan.ExpiresAt)) {
		return fmt.Errorf("invalid recovery issue plan")
	}
	if recoveryGatewayEndpointFromURL(plan.GatewayEndpoint) == "" {
		return fmt.Errorf("invalid recovery issue endpoint")
	}
	return nil
}

func (manager *RecoveryManager) loadGatewayState() (model.State, error) {
	state, err := manager.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load authoritative recovery state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate authoritative recovery state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return model.State{}, fmt.Errorf("recovery manager requires gateway state")
	}
	return state, nil
}

func (manager *RecoveryManager) allocateRecoveryID(invites []model.Invite) (string, error) {
	occupied := make(map[string]struct{}, len(invites))
	for _, invite := range invites {
		occupied[invite.ID] = struct{}{}
	}
	for attempt := 0; attempt < inviteIDCollisionRetries; attempt++ {
		var entropy [4]byte
		if _, err := io.ReadFull(manager.entropy, entropy[:]); err != nil {
			return "", fmt.Errorf("read recovery ID entropy: %w", err)
		}
		encoded := inviteIDEncoding.EncodeToString(entropy[:])
		id := "rec-" + encoded[:inviteIDCharacters]
		if _, found := occupied[id]; !found {
			return id, nil
		}
	}
	return "", ErrInviteIDCollision
}

func recoveryGatewayEndpoint(publicIPv4 string) string {
	return "https://" + publicIPv4 + EnrollmentRecoveryPath
}

func recoveryGatewayEndpointFromURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Path != EnrollmentRecoveryPath || parsed.User != nil ||
		parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.Is4() || address.String() != parsed.Hostname() {
		return ""
	}
	return value
}

func hashRecoverySecret(secret []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("vpnctl-recovery-secret-v1\x00"))
	_, _ = digest.Write(secret)
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func recoveryTokenTag(secret, payload []byte) []byte {
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write([]byte("vpnctl-recovery-token-v1\x00"))
	_, _ = digest.Write(payload)
	return digest.Sum(nil)
}

func sortStrings(values []string) {
	sort.Strings(values)
}
