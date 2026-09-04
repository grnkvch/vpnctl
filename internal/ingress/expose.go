package ingress

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const (
	GeneratedExposePathPrefix       = "/hooks/"
	GeneratedExposePathEntropyBytes = 32
	GeneratedExposePathRetryLimit   = 32
	ExposeNonLoopbackWarningCode    = "non_loopback_upstream"
	ExposeNonLoopbackWarningMessage = "The application upstream is outside loopback; vpnctl will connect to a network endpoint from this node."
)

var (
	ErrExposeInvalidInput     = errors.New("expose input is invalid")
	ErrExposeNameConflict     = errors.New("expose name already exists on this node")
	ErrExposeRouteConflict    = errors.New("expose route overlaps an existing route")
	ErrExposeReservedPath     = errors.New("expose route uses the reserved vpnctl namespace")
	ErrExposeNonLoopbackOptIn = errors.New("non-loopback expose upstream requires explicit opt-in")
	ErrExposePathGeneration   = errors.New("could not allocate a unique generated expose path")
	ErrExposeNamespaceInvalid = errors.New("expose namespace is invalid")
)

type ExposeCreateRequest struct {
	Upstream         string
	Name             string
	Path             string
	Prefix           bool
	AllowNonLoopback bool
	LimitOverrides   ExposeLimitOverrides
}

// ExposeNamespace is the authoritative global route/identity scope plus the
// target node used for node-local name ownership. It contains no provider or
// activation state.
type ExposeNamespace struct {
	NodeID          string
	StateGeneration uint64
	Existing        []model.Expose
}

type ExposePlanWarning struct {
	Code    string
	Message string
}

// ExposePlan contains immutable identity and normalized routing input. Tunnel
// allocation, limits, state mutation, and cross-host activation are later saga
// responsibilities.
type ExposePlan struct {
	ExposeID                string
	NodeID                  string
	Name                    string
	Upstream                string
	RouteMode               model.RouteMode
	Path                    string
	NonLoopback             bool
	Warnings                []ExposePlanWarning
	Limits                  ExposeLimits
	CreatedAt               time.Time
	ExpectedStateGeneration uint64
}

func (ExposePlan) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type ExposeNormalizerRuntime struct {
	Entropy io.Reader
	NewUUID model.UUIDGenerator
	Now     func() time.Time
}

type ExposeNormalizer struct {
	runtime ExposeNormalizerRuntime
}

func NewExposeNormalizer(runtime ExposeNormalizerRuntime) *ExposeNormalizer {
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	return &ExposeNormalizer{runtime: runtime}
}

func (normalizer *ExposeNormalizer) Normalize(namespace ExposeNamespace, request ExposeCreateRequest) (ExposePlan, error) {
	if normalizer == nil || normalizer.runtime.Entropy == nil || normalizer.runtime.NewUUID == nil || normalizer.runtime.Now == nil {
		return ExposePlan{}, fmt.Errorf("%w: normalizer is incomplete", ErrExposeNamespaceInvalid)
	}
	if err := validateExposeNamespace(namespace); err != nil {
		return ExposePlan{}, err
	}
	limits, err := ResolveExposeLimits(DefaultGatewayHardLimits(), request.LimitOverrides)
	if err != nil {
		return ExposePlan{}, err
	}
	if request.Name != "" {
		if err := model.ValidateExposeName(request.Name); err != nil {
			return ExposePlan{}, fmt.Errorf("%w: %v", ErrExposeInvalidInput, err)
		}
		for _, existing := range namespace.Existing {
			if existing.NodeID == namespace.NodeID && existing.Name != "" && strings.EqualFold(existing.Name, request.Name) {
				return ExposePlan{}, fmt.Errorf("%w: %s", ErrExposeNameConflict, request.Name)
			}
		}
	}

	upstream, err := NormalizeExposeUpstream(request.Upstream)
	if err != nil {
		return ExposePlan{}, err
	}
	if !upstream.Loopback && !request.AllowNonLoopback {
		return ExposePlan{}, ErrExposeNonLoopbackOptIn
	}

	mode := model.RouteExact
	if request.Prefix {
		mode = model.RoutePrefix
	}
	path := request.Path
	if path == "" {
		if request.Prefix {
			return ExposePlan{}, fmt.Errorf("%w: --prefix requires an explicit path", ErrExposeInvalidInput)
		}
		path, err = normalizer.generatePath(namespace.Existing)
		if err != nil {
			return ExposePlan{}, err
		}
	} else {
		path, err = NormalizeExposePath(path, mode)
		if err != nil {
			return ExposePlan{}, err
		}
		if conflict, owner := findExposeRouteConflict(namespace.Existing, mode, path); conflict {
			return ExposePlan{}, fmt.Errorf("%w: existing expose %s", ErrExposeRouteConflict, owner)
		}
	}

	occupied := make(map[string]struct{}, len(namespace.Existing))
	for _, existing := range namespace.Existing {
		occupied[existing.ID] = struct{}{}
	}
	exposeID, err := model.AllocateUUID(occupied, normalizer.runtime.NewUUID)
	if err != nil {
		return ExposePlan{}, fmt.Errorf("allocate expose identity: %w", err)
	}
	createdAt := normalizer.runtime.Now().UTC()
	if createdAt.IsZero() {
		return ExposePlan{}, fmt.Errorf("%w: creation time is required", ErrExposeInvalidInput)
	}
	plan := ExposePlan{
		ExposeID: exposeID, NodeID: namespace.NodeID, Name: request.Name,
		Upstream: upstream.Value, RouteMode: mode, Path: path, NonLoopback: !upstream.Loopback,
		Warnings: []ExposePlanWarning{}, Limits: limits, CreatedAt: createdAt, ExpectedStateGeneration: namespace.StateGeneration,
	}
	if plan.NonLoopback {
		plan.Warnings = append(plan.Warnings, ExposePlanWarning{
			Code:    ExposeNonLoopbackWarningCode,
			Message: ExposeNonLoopbackWarningMessage,
		})
	}
	if err := plan.Validate(); err != nil {
		return ExposePlan{}, err
	}
	return plan, nil
}

func (plan ExposePlan) Validate() error {
	if err := model.ValidateResourceID(plan.ExposeID); err != nil {
		return fmt.Errorf("%w: expose identity is invalid", ErrExposeInvalidInput)
	}
	if err := model.ValidateResourceID(plan.NodeID); err != nil {
		return fmt.Errorf("%w: node identity is invalid", ErrExposeInvalidInput)
	}
	if plan.Name != "" {
		if err := model.ValidateExposeName(plan.Name); err != nil {
			return fmt.Errorf("%w: %v", ErrExposeInvalidInput, err)
		}
	}
	upstream, err := NormalizeExposeUpstream(plan.Upstream)
	wantNonLoopback := !upstream.Loopback
	if err != nil || upstream.Value != plan.Upstream || plan.NonLoopback != wantNonLoopback {
		return fmt.Errorf("%w: upstream plan is not canonical", ErrExposeInvalidInput)
	}
	path, err := NormalizeExposePath(plan.Path, plan.RouteMode)
	if err != nil || path != plan.Path {
		return fmt.Errorf("%w: route plan is not canonical", ErrExposeInvalidInput)
	}
	if plan.ExpectedStateGeneration == 0 || plan.CreatedAt.IsZero() {
		return fmt.Errorf("%w: state generation and creation time are required", ErrExposeInvalidInput)
	}
	if err := plan.Limits.Validate(DefaultGatewayHardLimits()); err != nil {
		return err
	}
	_, offset := plan.CreatedAt.Zone()
	if offset != 0 {
		return fmt.Errorf("%w: creation time must use UTC", ErrExposeInvalidInput)
	}
	if plan.NonLoopback {
		if len(plan.Warnings) != 1 || plan.Warnings[0].Code != ExposeNonLoopbackWarningCode || plan.Warnings[0].Message != ExposeNonLoopbackWarningMessage {
			return fmt.Errorf("%w: non-loopback warning is required", ErrExposeInvalidInput)
		}
	} else if len(plan.Warnings) != 0 {
		return fmt.Errorf("%w: loopback plan must not carry warnings", ErrExposeInvalidInput)
	}
	return nil
}

type NormalizedExposeUpstream struct {
	Value    string
	Loopback bool
}

func NormalizeExposeUpstream(value string) (NormalizedExposeUpstream, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return NormalizedExposeUpstream{}, fmt.Errorf("%w: upstream must be a non-empty single-line value", ErrExposeInvalidInput)
	}
	if allDecimal(value) {
		port, err := parseExposePort(value)
		if err != nil {
			return NormalizedExposeUpstream{}, err
		}
		return NormalizedExposeUpstream{Value: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Loopback: true}, nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" {
		return NormalizedExposeUpstream{}, fmt.Errorf("%w: upstream must be a port or host:port", ErrExposeInvalidInput)
	}
	port, err := parseExposePort(portText)
	if err != nil {
		return NormalizedExposeUpstream{}, err
	}
	normalizedHost, loopback, err := normalizeExposeHost(host)
	if err != nil {
		return NormalizedExposeUpstream{}, err
	}
	normalized := net.JoinHostPort(normalizedHost, strconv.Itoa(port))
	if err := model.ValidateExposeUpstream(normalized); err != nil {
		return NormalizedExposeUpstream{}, fmt.Errorf("%w: %v", ErrExposeInvalidInput, err)
	}
	return NormalizedExposeUpstream{Value: normalized, Loopback: loopback}, nil
}

func NormalizeExposePath(value string, mode model.RouteMode) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("%w: path must be a non-empty trimmed value", ErrExposeInvalidInput)
	}
	if mode == model.RoutePrefix && value != "/" {
		value = strings.TrimSuffix(value, "/")
	}
	if model.IsReservedExposePath(value) {
		return "", ErrExposeReservedPath
	}
	if err := model.ValidateExposePath(value, mode); err != nil {
		return "", fmt.Errorf("%w: %v", ErrExposeInvalidInput, err)
	}
	return value, nil
}

func (normalizer *ExposeNormalizer) generatePath(existing []model.Expose) (string, error) {
	raw := make([]byte, GeneratedExposePathEntropyBytes)
	defer clear(raw)
	for attempt := 0; attempt < GeneratedExposePathRetryLimit; attempt++ {
		if _, err := io.ReadFull(normalizer.runtime.Entropy, raw); err != nil {
			return "", fmt.Errorf("%w: entropy source: %v", ErrExposePathGeneration, err)
		}
		candidate := GeneratedExposePathPrefix + base64.RawURLEncoding.EncodeToString(raw)
		if conflict, _ := findExposeRouteConflict(existing, model.RouteExact, candidate); !conflict {
			return candidate, nil
		}
	}
	return "", ErrExposePathGeneration
}

func validateExposeNamespace(namespace ExposeNamespace) error {
	if err := model.ValidateResourceID(namespace.NodeID); err != nil || namespace.StateGeneration == 0 {
		return fmt.Errorf("%w: node identity and state generation are required", ErrExposeNamespaceInvalid)
	}
	ids := make(map[string]struct{}, len(namespace.Existing))
	names := make(map[string]map[string]struct{})
	for index, existing := range namespace.Existing {
		if err := existing.Validate(); err != nil {
			return fmt.Errorf("%w: existing expose %d is invalid", ErrExposeNamespaceInvalid, index)
		}
		if _, duplicate := ids[existing.ID]; duplicate {
			return fmt.Errorf("%w: duplicate expose identity", ErrExposeNamespaceInvalid)
		}
		ids[existing.ID] = struct{}{}
		if existing.Name != "" {
			nodeNames := names[existing.NodeID]
			if nodeNames == nil {
				nodeNames = make(map[string]struct{})
				names[existing.NodeID] = nodeNames
			}
			key := strings.ToLower(existing.Name)
			if _, duplicate := nodeNames[key]; duplicate {
				return fmt.Errorf("%w: duplicate node-local expose name", ErrExposeNamespaceInvalid)
			}
			nodeNames[key] = struct{}{}
		}
	}
	routes := model.NewExposeRouteIndex()
	for _, existing := range namespace.Existing {
		if existing.State == model.ExposeDisabled {
			continue
		}
		if owner, err := routes.Add(existing.RouteMode, existing.Path, existing.ID); err != nil || owner != "" {
			return fmt.Errorf("%w: existing routes overlap or are invalid", ErrExposeNamespaceInvalid)
		}
	}
	return nil
}

func findExposeRouteConflict(existing []model.Expose, mode model.RouteMode, path string) (bool, string) {
	for _, candidate := range existing {
		if candidate.State != model.ExposeDisabled && model.ExposeRoutesOverlap(candidate.RouteMode, candidate.Path, mode, path) {
			return true, candidate.ID
		}
	}
	return false, ""
}

func normalizeExposeHost(host string) (string, bool, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || (!address.IsLoopback() && !address.IsGlobalUnicast()) {
			return "", false, fmt.Errorf("%w: upstream IP address is unsupported", ErrExposeInvalidInput)
		}
		return address.String(), address.IsLoopback(), nil
	}
	if looksLikeIPv4Literal(host) {
		return "", false, fmt.Errorf("%w: upstream IPv4 address must be canonical", ErrExposeInvalidInput)
	}
	normalized := strings.ToLower(host)
	if err := validateExposeHostname(normalized); err != nil {
		return "", false, err
	}
	return normalized, normalized == "localhost", nil
}

func looksLikeIPv4Literal(value string) bool {
	if !strings.Contains(value, ".") {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '.' {
			return false
		}
	}
	return true
}

func validateExposeHostname(value string) error {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return fmt.Errorf("%w: upstream hostname is invalid", ErrExposeInvalidInput)
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: upstream hostname is invalid", ErrExposeInvalidInput)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("%w: upstream hostname is invalid", ErrExposeInvalidInput)
			}
		}
	}
	return nil
}

func parseExposePort(value string) (int, error) {
	if !allDecimal(value) {
		return 0, fmt.Errorf("%w: upstream port must be decimal", ErrExposeInvalidInput)
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w: upstream port must be between 1 and 65535", ErrExposeInvalidInput)
	}
	return port, nil
}

func allDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
