package enrollment

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	InviteTokenSchemaVersion = 1
	InviteSecretBytes        = 32
	InviteTokenPrefix        = "vpnctl-invite-v1"
	InviteEnrollmentPath     = "/.well-known/vpnctl/enroll"
	invitePurpose            = string(PurposeEnroll)
	inviteIDCharacters       = 6
	inviteIDCollisionRetries = 32
	maximumInviteTokenBytes  = 4096
)

var (
	ErrInviteTokenInvalid = errors.New("invite token is invalid")
	ErrInviteNotFound     = errors.New("invite does not exist")
	ErrInviteNameConflict = errors.New("node name is already reserved")
	ErrInviteExpired      = errors.New("invite has expired")
	ErrInviteCancelled    = errors.New("invite is cancelled")
	ErrInviteConsumed     = errors.New("invite is already consumed; revoke the enrolled node instead")
	ErrInvitePlanStale    = errors.New("invite plan is stale")
	ErrInviteIDCollision  = errors.New("invite ID collision retry limit reached")
	inviteNamePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	inviteIDPattern       = regexp.MustCompile(`^inv-[A-Z2-7]{6}$`)
	protocolPattern       = regexp.MustCompile(`^[1-9][0-9]*\.(?:0|[1-9][0-9]*)$`)
	fingerprintPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hashPattern           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	inviteIDEncoding      = base32.StdEncoding.WithPadding(base32.NoPadding)
	tokenEncoding         = base64.RawURLEncoding
)

type InviteStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

type InviteIssuePlan struct {
	NodeName                string
	ControlProtocol         string
	GatewayEndpoint         string
	EnrollmentFingerprint   string
	IssuedAt                time.Time
	ExpiresAt               time.Time
	ExpectedStateGeneration uint64
}

type InviteIssueResult struct {
	Invite          InviteStatus
	StateGeneration uint64
	Token           *output.Secret
}

type InviteCancelPlan struct {
	InviteID                string
	NodeName                string
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64
	Changed                 bool

	candidate model.State
}

type InviteCancelResult struct {
	InviteID        string
	NodeName        string
	Changed         bool
	StateGeneration uint64
}

type InviteConsumeResult struct {
	InviteID        string
	NodeName        string
	StateGeneration uint64
}

// InviteAuthorization is the public, non-secret result of successfully
// matching one presented token to one active authoritative invite. The private
// snapshot prevents callers from constructing or retargeting authorizations.
type InviteAuthorization struct {
	InviteID                string
	NodeName                string
	ControlProtocol         string
	GatewayEndpoint         string
	EnrollmentFingerprint   string
	IssuedAt                time.Time
	ExpiresAt               time.Time
	ExpectedStateGeneration uint64

	invite model.Invite
}

type InviteDisplayState string

const (
	InviteDisplayActive    InviteDisplayState = "active"
	InviteDisplayExpired   InviteDisplayState = "expired"
	InviteDisplayCancelled InviteDisplayState = "cancelled"
	InviteDisplayConsumed  InviteDisplayState = "consumed"
)

// InviteStatus deliberately excludes the persisted secret hash. It is the
// only invitation shape intended for status and command output.
type InviteStatus struct {
	ID              string             `json:"id"`
	NodeName        string             `json:"node_name"`
	State           InviteDisplayState `json:"state"`
	ControlProtocol string             `json:"control_protocol"`
	GatewayEndpoint string             `json:"gateway_endpoint"`
	IssuedAt        time.Time          `json:"issued_at"`
	ExpiresAt       time.Time          `json:"expires_at"`
}

type InviteManager struct {
	state   InviteStateStore
	entropy io.Reader
	now     func() time.Time
}

func NewInviteManager(state InviteStateStore, entropy io.Reader, now func() time.Time) (*InviteManager, error) {
	if state == nil {
		return nil, fmt.Errorf("invite manager state store is required")
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	if now == nil {
		now = time.Now
	}
	return &InviteManager{state: state, entropy: entropy, now: now}, nil
}

// PlanIssue is read-only and consumes no entropy. A dry-run can therefore
// validate the exact public metadata without creating a usable token.
func (manager *InviteManager) PlanIssue(nodeName string) (InviteIssuePlan, error) {
	if manager == nil {
		return InviteIssuePlan{}, fmt.Errorf("invite manager is required")
	}
	if err := validateInviteName(nodeName); err != nil {
		return InviteIssuePlan{}, err
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return InviteIssuePlan{}, err
	}
	issuedAt := canonicalTime(manager.now())
	if err := ensureNodeNameAvailable(state, nodeName, issuedAt); err != nil {
		return InviteIssuePlan{}, err
	}
	if state.EnrollmentIdentity == nil {
		return InviteIssuePlan{}, fmt.Errorf("gateway enrollment identity is unavailable")
	}
	return InviteIssuePlan{
		NodeName: nodeName, ControlProtocol: state.Components.ControlProtocols[0],
		GatewayEndpoint:       gatewayEnrollmentEndpoint(state.Host.PublicIPv4),
		EnrollmentFingerprint: state.EnrollmentIdentity.Fingerprint,
		IssuedAt:              issuedAt, ExpiresAt: issuedAt.Add(model.InviteTTL), ExpectedStateGeneration: state.Generation,
	}, nil
}

func (manager *InviteManager) CommitIssue(ctx context.Context, plan InviteIssuePlan) (InviteIssueResult, error) {
	if manager == nil {
		return InviteIssueResult{}, fmt.Errorf("invite manager is required")
	}
	if ctx == nil {
		return InviteIssueResult{}, fmt.Errorf("invite issue context is required")
	}
	if err := validateIssuePlan(plan); err != nil {
		return InviteIssueResult{}, err
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return InviteIssueResult{}, err
	}
	if state.Generation != plan.ExpectedStateGeneration || state.EnrollmentIdentity == nil ||
		state.Components.ControlProtocols[0] != plan.ControlProtocol || state.EnrollmentIdentity.Fingerprint != plan.EnrollmentFingerprint ||
		gatewayEnrollmentEndpoint(state.Host.PublicIPv4) != plan.GatewayEndpoint {
		return InviteIssueResult{}, fmt.Errorf("%w: gateway metadata changed after planning", ErrInvitePlanStale)
	}
	commitTime := canonicalTime(manager.now())
	if commitTime.Before(plan.IssuedAt) || !commitTime.Before(plan.ExpiresAt) {
		return InviteIssueResult{}, fmt.Errorf("%w: planned invite issuance window elapsed", ErrInvitePlanStale)
	}
	if err := ensureNodeNameAvailable(state, plan.NodeName, commitTime); err != nil {
		return InviteIssueResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return InviteIssueResult{}, err
	}

	inviteID, err := manager.allocateInviteID(state.Invites)
	if err != nil {
		return InviteIssueResult{}, err
	}
	secret := make([]byte, InviteSecretBytes)
	if _, err := io.ReadFull(manager.entropy, secret); err != nil {
		clear(secret)
		return InviteIssueResult{}, fmt.Errorf("read invite secret entropy: %w", err)
	}
	defer clear(secret)
	issuedAt := commitTime
	expiresAt := issuedAt.Add(model.InviteTTL)
	invite := model.Invite{
		SchemaVersion: model.ResourceSchemaVersion, ID: inviteID, NodeName: plan.NodeName,
		ControlProtocol: plan.ControlProtocol, GatewayEndpoint: plan.GatewayEndpoint,
		EnrollmentFingerprint: plan.EnrollmentFingerprint, SecretHash: hashInviteSecret(secret),
		State: model.InviteActive, IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
	token, err := encodeInviteToken(invite, secret)
	if err != nil {
		return InviteIssueResult{}, err
	}
	candidate := state
	candidate.Generation, err = model.NextGeneration(state.Generation)
	if err != nil {
		token.Destroy()
		return InviteIssueResult{}, err
	}
	candidate.Invites = append(append([]model.Invite(nil), state.Invites...), invite)
	if err := model.ValidateTransition(state, candidate); err != nil {
		token.Destroy()
		return InviteIssueResult{}, fmt.Errorf("build invite issue transition: %w", err)
	}
	if err := ctx.Err(); err != nil {
		token.Destroy()
		return InviteIssueResult{}, err
	}
	if err := manager.state.Save(state.Generation, candidate); err != nil {
		token.Destroy()
		return InviteIssueResult{}, fmt.Errorf("persist invite: %w", err)
	}
	return InviteIssueResult{
		Invite: inviteStatus(invite, issuedAt), StateGeneration: candidate.Generation, Token: token,
	}, nil
}

func (manager *InviteManager) PlanCancel(inviteID string) (InviteCancelPlan, error) {
	if manager == nil {
		return InviteCancelPlan{}, fmt.Errorf("invite manager is required")
	}
	if !inviteIDPattern.MatchString(inviteID) {
		return InviteCancelPlan{}, fmt.Errorf("%w: malformed invite ID", ErrInviteNotFound)
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return InviteCancelPlan{}, err
	}
	index := inviteIndex(state.Invites, inviteID)
	if index < 0 {
		return InviteCancelPlan{}, fmt.Errorf("%w: %s", ErrInviteNotFound, inviteID)
	}
	invite := state.Invites[index]
	if invite.State == model.InviteConsumed {
		return InviteCancelPlan{}, fmt.Errorf("%w: %s", ErrInviteConsumed, inviteID)
	}
	plan := InviteCancelPlan{
		InviteID: invite.ID, NodeName: invite.NodeName, ExpectedStateGeneration: state.Generation,
		NextStateGeneration: state.Generation, Changed: invite.State == model.InviteActive, candidate: state,
	}
	if !plan.Changed {
		return plan, nil
	}
	cancelledAt := canonicalTime(manager.now())
	invite.State = model.InviteCancelled
	invite.CancelledAt = &cancelledAt
	plan.candidate.Invites = append([]model.Invite(nil), state.Invites...)
	plan.candidate.Invites[index] = invite
	plan.candidate.Generation, err = model.NextGeneration(state.Generation)
	if err != nil {
		return InviteCancelPlan{}, err
	}
	plan.NextStateGeneration = plan.candidate.Generation
	if err := model.ValidateTransition(state, plan.candidate); err != nil {
		return InviteCancelPlan{}, fmt.Errorf("build invite cancellation transition: %w", err)
	}
	return plan, nil
}

func (manager *InviteManager) CommitCancel(plan InviteCancelPlan) (InviteCancelResult, error) {
	if manager == nil {
		return InviteCancelResult{}, fmt.Errorf("invite manager is required")
	}
	if plan.InviteID == "" || plan.ExpectedStateGeneration == 0 || plan.NextStateGeneration == 0 ||
		(plan.Changed && plan.NextStateGeneration != plan.ExpectedStateGeneration+1) ||
		(!plan.Changed && plan.NextStateGeneration != plan.ExpectedStateGeneration) {
		return InviteCancelResult{}, fmt.Errorf("invalid invite cancellation plan")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return InviteCancelResult{}, err
	}
	if state.Generation != plan.ExpectedStateGeneration {
		index := inviteIndex(state.Invites, plan.InviteID)
		if index >= 0 && state.Invites[index].State == model.InviteCancelled {
			return InviteCancelResult{
				InviteID: plan.InviteID, NodeName: state.Invites[index].NodeName,
				Changed: false, StateGeneration: state.Generation,
			}, nil
		}
		if index >= 0 && state.Invites[index].State == model.InviteConsumed {
			return InviteCancelResult{}, fmt.Errorf("%w: %s", ErrInviteConsumed, plan.InviteID)
		}
		return InviteCancelResult{}, fmt.Errorf("%w: expected state generation %d, current %d", ErrInvitePlanStale, plan.ExpectedStateGeneration, state.Generation)
	}
	index := inviteIndex(state.Invites, plan.InviteID)
	if index < 0 {
		return InviteCancelResult{}, fmt.Errorf("%w: %s", ErrInviteNotFound, plan.InviteID)
	}
	if state.Invites[index].State == model.InviteConsumed {
		return InviteCancelResult{}, fmt.Errorf("%w: %s", ErrInviteConsumed, plan.InviteID)
	}
	if !plan.Changed {
		if state.Invites[index].State != model.InviteCancelled {
			return InviteCancelResult{}, fmt.Errorf("%w: cancellation state changed after planning", ErrInvitePlanStale)
		}
		return InviteCancelResult{InviteID: plan.InviteID, NodeName: plan.NodeName, Changed: false, StateGeneration: state.Generation}, nil
	}
	if err := model.ValidateTransition(state, plan.candidate); err != nil {
		return InviteCancelResult{}, fmt.Errorf("%w: %v", ErrInvitePlanStale, err)
	}
	if err := manager.state.Save(state.Generation, plan.candidate); err != nil {
		return InviteCancelResult{}, fmt.Errorf("persist invite cancellation: %w", err)
	}
	return InviteCancelResult{InviteID: plan.InviteID, NodeName: plan.NodeName, Changed: true, StateGeneration: plan.candidate.Generation}, nil
}

// AuthorizeInvite verifies a token without changing state. A caller must bind
// the returned authorization to its exact signed response and then invoke
// CommitAuthorized; an authorization alone never consumes an invite.
func (manager *InviteManager) AuthorizeInvite(encoded []byte) (InviteAuthorization, error) {
	if manager == nil {
		return InviteAuthorization{}, fmt.Errorf("invite manager is required")
	}
	token, err := DecodeInviteToken(encoded)
	if err != nil {
		return InviteAuthorization{}, err
	}
	defer token.Destroy()
	state, err := manager.loadGatewayState()
	if err != nil {
		return InviteAuthorization{}, err
	}
	now := canonicalTime(manager.now())
	index, err := verifyDecodedToken(state, token, now)
	if err != nil {
		return InviteAuthorization{}, err
	}
	invite := state.Invites[index]
	return InviteAuthorization{
		InviteID: invite.ID, NodeName: invite.NodeName, ControlProtocol: invite.ControlProtocol,
		GatewayEndpoint: invite.GatewayEndpoint, EnrollmentFingerprint: invite.EnrollmentFingerprint,
		IssuedAt: invite.IssuedAt, ExpiresAt: invite.ExpiresAt, ExpectedStateGeneration: state.Generation,
		invite: invite,
	}, nil
}

// CommitAuthorized atomically consumes the invite and the exact signed
// exchange replay hash in one authoritative state generation.
func (manager *InviteManager) CommitAuthorized(ctx context.Context, authorization InviteAuthorization, consumptionHash string) (InviteConsumeResult, error) {
	return manager.commitAuthorizedMutation(ctx, authorization, consumptionHash, nil)
}

// commitAuthorizedMutation is the single gateway-state commit point used by
// join. mutate may add the prepared node resources to candidate, but must not
// perform I/O: invite consumption and resource publication then share one
// validated state generation and one compare-and-swap Save.
func (manager *InviteManager) commitAuthorizedMutation(
	ctx context.Context,
	authorization InviteAuthorization,
	consumptionHash string,
	mutate func(current model.State, candidate *model.State) error,
) (InviteConsumeResult, error) {
	if manager == nil {
		return InviteConsumeResult{}, fmt.Errorf("invite manager is required")
	}
	if ctx == nil {
		return InviteConsumeResult{}, fmt.Errorf("invite consume context is required")
	}
	if authorization.ExpectedStateGeneration == 0 || authorization.InviteID == "" ||
		authorization.invite.ID != authorization.InviteID || authorization.invite.NodeName != authorization.NodeName ||
		authorization.invite.ControlProtocol != authorization.ControlProtocol ||
		authorization.invite.GatewayEndpoint != authorization.GatewayEndpoint ||
		authorization.invite.EnrollmentFingerprint != authorization.EnrollmentFingerprint ||
		!authorization.invite.IssuedAt.Equal(authorization.IssuedAt) ||
		!authorization.invite.ExpiresAt.Equal(authorization.ExpiresAt) || !hashPattern.MatchString(consumptionHash) {
		return InviteConsumeResult{}, fmt.Errorf("invalid invite authorization")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return InviteConsumeResult{}, err
	}
	if state.Generation != authorization.ExpectedStateGeneration {
		return InviteConsumeResult{}, manager.classifyAuthorizedConflict(state, authorization)
	}
	index := inviteIndex(state.Invites, authorization.InviteID)
	if index < 0 || !reflect.DeepEqual(state.Invites[index], authorization.invite) {
		return InviteConsumeResult{}, fmt.Errorf("%w: invite changed after authorization", ErrInvitePlanStale)
	}
	if state.EnrollmentIdentity == nil || authorization.EnrollmentFingerprint != state.EnrollmentIdentity.Fingerprint ||
		authorization.GatewayEndpoint != gatewayEnrollmentEndpoint(state.Host.PublicIPv4) ||
		!containsString(state.Components.ControlProtocols, authorization.ControlProtocol) {
		return InviteConsumeResult{}, ErrInviteTokenInvalid
	}
	now := canonicalTime(manager.now())
	if now.Before(authorization.IssuedAt) || !now.Before(authorization.ExpiresAt) {
		return InviteConsumeResult{}, ErrInviteExpired
	}
	if err := ctx.Err(); err != nil {
		return InviteConsumeResult{}, err
	}
	candidate := state
	candidate.Invites = append([]model.Invite(nil), state.Invites...)
	consumed := candidate.Invites[index]
	consumed.State = model.InviteConsumed
	consumed.ConsumedAt = &now
	consumed.ConsumptionHash = consumptionHash
	candidate.Invites[index] = consumed
	candidate.Generation, err = model.NextGeneration(state.Generation)
	if err != nil {
		return InviteConsumeResult{}, err
	}
	if mutate != nil {
		if err := mutate(state, &candidate); err != nil {
			return InviteConsumeResult{}, fmt.Errorf("build authorized enrollment transition: %w", err)
		}
	}
	if err := model.ValidateTransition(state, candidate); err != nil {
		return InviteConsumeResult{}, fmt.Errorf("build invite consumption transition: %w", err)
	}
	if err := manager.state.Save(state.Generation, candidate); err != nil {
		if errors.Is(err, store.ErrStateConflict) {
			current, loadErr := manager.loadGatewayState()
			if loadErr == nil {
				return InviteConsumeResult{}, manager.classifyAuthorizedConflict(current, authorization)
			}
		}
		return InviteConsumeResult{}, fmt.Errorf("persist invite consumption: %w", err)
	}
	return InviteConsumeResult{InviteID: consumed.ID, NodeName: consumed.NodeName, StateGeneration: candidate.Generation}, nil
}

func (manager *InviteManager) classifyAuthorizedConflict(state model.State, authorization InviteAuthorization) error {
	index := inviteIndex(state.Invites, authorization.InviteID)
	if index < 0 {
		return fmt.Errorf("%w: %s", ErrInviteNotFound, authorization.InviteID)
	}
	switch state.Invites[index].State {
	case model.InviteConsumed:
		return ErrInviteConsumed
	case model.InviteCancelled:
		return ErrInviteCancelled
	default:
		return fmt.Errorf("%w: authoritative generation changed", ErrInvitePlanStale)
	}
}

// Consume is the token-only primitive retained for non-HTTP callers. Public
// enrollment binds CommitAuthorized to a signed transcript instead.
func (manager *InviteManager) Consume(ctx context.Context, encoded []byte) (InviteConsumeResult, error) {
	authorization, err := manager.AuthorizeInvite(encoded)
	if err != nil {
		return InviteConsumeResult{}, err
	}
	return manager.CommitAuthorized(ctx, authorization, hashConsumptionEvidence("vpnctl-invite-token-consumption-v1", encoded))
}

func (manager *InviteManager) Status() ([]InviteStatus, error) {
	if manager == nil {
		return nil, fmt.Errorf("invite manager is required")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return nil, err
	}
	now := canonicalTime(manager.now())
	statuses := make([]InviteStatus, 0, len(state.Invites))
	for _, invite := range state.Invites {
		statuses = append(statuses, inviteStatus(invite, now))
	}
	sort.Slice(statuses, func(left, right int) bool {
		if statuses[left].IssuedAt.Equal(statuses[right].IssuedAt) {
			return statuses[left].ID < statuses[right].ID
		}
		return statuses[left].IssuedAt.Before(statuses[right].IssuedAt)
	})
	return statuses, nil
}

func (manager *InviteManager) ActiveStatus() ([]InviteStatus, error) {
	statuses, err := manager.Status()
	if err != nil {
		return nil, err
	}
	active := make([]InviteStatus, 0, len(statuses))
	for _, status := range statuses {
		if status.State == InviteDisplayActive {
			active = append(active, status)
		}
	}
	return active, nil
}

type inviteTokenEnvelope struct {
	SchemaVersion         int    `json:"schema_version"`
	Purpose               string `json:"purpose"`
	ControlProtocol       string `json:"control_protocol"`
	GatewayEndpoint       string `json:"gateway_endpoint"`
	EnrollmentFingerprint string `json:"enrollment_fingerprint"`
	InviteID              string `json:"invite_id"`
	Secret                string `json:"secret"`
	NodeName              string `json:"node_name"`
	IssuedAt              string `json:"issued_at"`
	ExpiresAt             string `json:"expires_at"`
}

// DecodedInviteToken keeps the token secret behind an opaque Secret and
// refuses serialization. Callers can inspect only the public binding fields.
type DecodedInviteToken struct {
	InviteID              string
	NodeName              string
	ControlProtocol       string
	GatewayEndpoint       string
	EnrollmentFingerprint string
	IssuedAt              time.Time
	ExpiresAt             time.Time
	secret                output.Secret
}

func (token DecodedInviteToken) String() string   { return output.RedactedMarker }
func (token DecodedInviteToken) GoString() string { return output.RedactedMarker }
func (token DecodedInviteToken) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}
func (token *DecodedInviteToken) Destroy() {
	if token != nil {
		token.secret.Destroy()
	}
}

func encodeInviteToken(invite model.Invite, secret []byte) (*output.Secret, error) {
	if len(secret) != InviteSecretBytes || hashInviteSecret(secret) != invite.SecretHash {
		return nil, fmt.Errorf("encode invite token: invalid secret")
	}
	envelope := inviteTokenEnvelope{
		SchemaVersion: InviteTokenSchemaVersion, Purpose: invitePurpose,
		ControlProtocol: invite.ControlProtocol, GatewayEndpoint: invite.GatewayEndpoint,
		EnrollmentFingerprint: invite.EnrollmentFingerprint, InviteID: invite.ID,
		Secret: tokenEncoding.EncodeToString(secret), NodeName: invite.NodeName,
		IssuedAt: formatTokenTime(invite.IssuedAt), ExpiresAt: formatTokenTime(invite.ExpiresAt),
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode invite token payload: %w", err)
	}
	tag := inviteTokenTag(secret, payload)
	defer clear(tag)
	encoded := InviteTokenPrefix + "." + tokenEncoding.EncodeToString(payload) + "." + tokenEncoding.EncodeToString(tag)
	result, err := output.NewSecretString(encoded)
	clear(payload)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func DecodeInviteToken(encoded []byte) (*DecodedInviteToken, error) {
	if len(encoded) == 0 || len(encoded) > maximumInviteTokenBytes || bytes.ContainsAny(encoded, " \t\r\n\x00") {
		return nil, ErrInviteTokenInvalid
	}
	parts := strings.Split(string(encoded), ".")
	if len(parts) != 3 || parts[0] != InviteTokenPrefix {
		return nil, ErrInviteTokenInvalid
	}
	payload, err := decodeCanonicalBase64(parts[1])
	if err != nil {
		return nil, ErrInviteTokenInvalid
	}
	defer clear(payload)
	tag, err := decodeCanonicalBase64(parts[2])
	if err != nil || len(tag) != sha256.Size {
		clear(tag)
		return nil, ErrInviteTokenInvalid
	}
	defer clear(tag)
	var envelope inviteTokenEnvelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, ErrInviteTokenInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, ErrInviteTokenInvalid
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(payload, canonical) {
		clear(canonical)
		return nil, ErrInviteTokenInvalid
	}
	clear(canonical)
	secret, err := decodeCanonicalBase64(envelope.Secret)
	if err != nil || len(secret) != InviteSecretBytes {
		clear(secret)
		return nil, ErrInviteTokenInvalid
	}
	wantTag := inviteTokenTag(secret, payload)
	validTag := hmac.Equal(tag, wantTag)
	clear(wantTag)
	if !validTag {
		clear(secret)
		return nil, ErrInviteTokenInvalid
	}
	issuedAt, expiresAt, err := validateTokenEnvelope(envelope)
	if err != nil {
		clear(secret)
		return nil, ErrInviteTokenInvalid
	}
	secretValue, err := output.NewSecret(secret)
	clear(secret)
	if err != nil {
		return nil, ErrInviteTokenInvalid
	}
	return &DecodedInviteToken{
		InviteID: envelope.InviteID, NodeName: envelope.NodeName, ControlProtocol: envelope.ControlProtocol,
		GatewayEndpoint: envelope.GatewayEndpoint, EnrollmentFingerprint: envelope.EnrollmentFingerprint,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, secret: secretValue,
	}, nil
}

func validateTokenEnvelope(envelope inviteTokenEnvelope) (time.Time, time.Time, error) {
	if envelope.SchemaVersion != InviteTokenSchemaVersion || envelope.Purpose != invitePurpose ||
		!inviteIDPattern.MatchString(envelope.InviteID) || validateInviteName(envelope.NodeName) != nil ||
		!protocolPattern.MatchString(envelope.ControlProtocol) || !fingerprintPattern.MatchString(envelope.EnrollmentFingerprint) {
		return time.Time{}, time.Time{}, ErrInviteTokenInvalid
	}
	endpoint, err := url.Parse(envelope.GatewayEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Port() != "" || endpoint.Path != InviteEnrollmentPath {
		return time.Time{}, time.Time{}, ErrInviteTokenInvalid
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || !address.Is4() || address.String() != endpoint.Hostname() {
		return time.Time{}, time.Time{}, ErrInviteTokenInvalid
	}
	issuedAt, err := parseTokenTime(envelope.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expiresAt, err := parseTokenTime(envelope.ExpiresAt)
	if err != nil || !expiresAt.Equal(issuedAt.Add(model.InviteTTL)) {
		return time.Time{}, time.Time{}, ErrInviteTokenInvalid
	}
	return issuedAt, expiresAt, nil
}

func verifyDecodedToken(state model.State, token *DecodedInviteToken, now time.Time) (int, error) {
	if state.EnrollmentIdentity == nil || token.EnrollmentFingerprint != state.EnrollmentIdentity.Fingerprint ||
		token.GatewayEndpoint != gatewayEnrollmentEndpoint(state.Host.PublicIPv4) ||
		!containsString(state.Components.ControlProtocols, token.ControlProtocol) {
		return -1, ErrInviteTokenInvalid
	}
	index := inviteIndex(state.Invites, token.InviteID)
	if index < 0 {
		return -1, ErrInviteNotFound
	}
	invite := state.Invites[index]
	if invite.NodeName != token.NodeName || invite.ControlProtocol != token.ControlProtocol ||
		invite.GatewayEndpoint != token.GatewayEndpoint || invite.EnrollmentFingerprint != token.EnrollmentFingerprint ||
		!invite.IssuedAt.Equal(token.IssuedAt) || !invite.ExpiresAt.Equal(token.ExpiresAt) {
		return -1, ErrInviteTokenInvalid
	}
	var presentedHash string
	if err := token.secret.Use(func(secret []byte) error {
		presentedHash = hashInviteSecret(secret)
		return nil
	}); err != nil {
		return -1, ErrInviteTokenInvalid
	}
	if !hmac.Equal([]byte(invite.SecretHash), []byte(presentedHash)) {
		return -1, ErrInviteTokenInvalid
	}
	switch invite.State {
	case model.InviteCancelled:
		return -1, ErrInviteCancelled
	case model.InviteConsumed:
		return -1, ErrInviteConsumed
	}
	if now.Before(invite.IssuedAt) || !now.Before(invite.ExpiresAt) {
		return -1, ErrInviteExpired
	}
	return index, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (manager *InviteManager) loadGatewayState() (model.State, error) {
	state, err := manager.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load authoritative invite state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate authoritative invite state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return model.State{}, fmt.Errorf("invite manager requires gateway state")
	}
	return state, nil
}

func (manager *InviteManager) allocateInviteID(invites []model.Invite) (string, error) {
	occupied := make(map[string]struct{}, len(invites))
	for _, invite := range invites {
		occupied[invite.ID] = struct{}{}
	}
	for attempt := 0; attempt < inviteIDCollisionRetries; attempt++ {
		var entropy [4]byte
		if _, err := io.ReadFull(manager.entropy, entropy[:]); err != nil {
			return "", fmt.Errorf("read invite ID entropy: %w", err)
		}
		encoded := inviteIDEncoding.EncodeToString(entropy[:])
		id := "inv-" + encoded[:inviteIDCharacters]
		if _, collision := occupied[id]; !collision {
			return id, nil
		}
	}
	return "", ErrInviteIDCollision
}

func ensureNodeNameAvailable(state model.State, nodeName string, now time.Time) error {
	for _, node := range state.Nodes {
		if strings.EqualFold(node.Name, nodeName) {
			return fmt.Errorf("%w: existing node %s", ErrInviteNameConflict, node.ID)
		}
	}
	for _, invite := range state.Invites {
		reserved := invite.State == model.InviteConsumed ||
			(invite.State == model.InviteActive && !now.Before(invite.IssuedAt) && now.Before(invite.ExpiresAt))
		if reserved && strings.EqualFold(invite.NodeName, nodeName) {
			return fmt.Errorf("%w: invite %s", ErrInviteNameConflict, invite.ID)
		}
	}
	return nil
}

func validateIssuePlan(plan InviteIssuePlan) error {
	if err := validateInviteName(plan.NodeName); err != nil {
		return err
	}
	if plan.ExpectedStateGeneration == 0 || !protocolPattern.MatchString(plan.ControlProtocol) ||
		!fingerprintPattern.MatchString(plan.EnrollmentFingerprint) || plan.GatewayEndpoint == "" ||
		plan.IssuedAt.IsZero() || !plan.ExpiresAt.Equal(plan.IssuedAt.Add(model.InviteTTL)) ||
		!plan.IssuedAt.Equal(canonicalTime(plan.IssuedAt)) || !plan.ExpiresAt.Equal(canonicalTime(plan.ExpiresAt)) {
		return fmt.Errorf("invalid invite issue plan")
	}
	return nil
}

func validateInviteName(name string) error {
	if !inviteNamePattern.MatchString(name) {
		return fmt.Errorf("invalid node name %q", name)
	}
	return nil
}

func inviteIndex(invites []model.Invite, id string) int {
	for index := range invites {
		if invites[index].ID == id {
			return index
		}
	}
	return -1
}

func inviteStatus(invite model.Invite, now time.Time) InviteStatus {
	state := InviteDisplayActive
	switch invite.State {
	case model.InviteCancelled:
		state = InviteDisplayCancelled
	case model.InviteConsumed:
		state = InviteDisplayConsumed
	case model.InviteActive:
		if now.Before(invite.IssuedAt) || !now.Before(invite.ExpiresAt) {
			state = InviteDisplayExpired
		}
	}
	return InviteStatus{
		ID: invite.ID, NodeName: invite.NodeName, State: state, ControlProtocol: invite.ControlProtocol,
		GatewayEndpoint: invite.GatewayEndpoint, IssuedAt: invite.IssuedAt, ExpiresAt: invite.ExpiresAt,
	}
}

func gatewayEnrollmentEndpoint(publicIPv4 string) string {
	return "https://" + publicIPv4 + InviteEnrollmentPath
}

func hashInviteSecret(secret []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("vpnctl-invite-secret-v1\x00"))
	_, _ = digest.Write(secret)
	return hex.EncodeToString(digest.Sum(nil))
}

func hashConsumptionEvidence(domain string, evidence []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(evidence)
	return hex.EncodeToString(digest.Sum(nil))
}

func inviteTokenTag(secret, payload []byte) []byte {
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write([]byte("vpnctl-invite-token-v1\x00"))
	_, _ = digest.Write(payload)
	return digest.Sum(nil)
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := tokenEncoding.DecodeString(value)
	if err != nil || tokenEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, ErrInviteTokenInvalid
	}
	return decoded, nil
}

func canonicalTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Second)
}

func formatTokenTime(value time.Time) string {
	return canonicalTime(value).Format(time.RFC3339)
}

func parseTokenTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value || !parsed.Equal(canonicalTime(parsed)) {
		return time.Time{}, ErrInviteTokenInvalid
	}
	return parsed.UTC(), nil
}
