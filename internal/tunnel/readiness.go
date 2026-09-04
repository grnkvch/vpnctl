package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	FRPClientStatusAddress       = "127.0.0.1:17400"
	FRPClientStatusPath          = "/api/status"
	FRPClientStatusMaximumBytes  = 64 << 10
	FRPUpstreamProbeConcurrency  = 8
	FRPIngressDegradedHTTPStatus = http.StatusServiceUnavailable

	frpClientStatusTimeout  = 2 * time.Second
	frpUpstreamProbeTimeout = time.Second
)

var ErrTunnelNotReady = errors.New("node tunnel is not ready")

// FRPReconnectContract records the retry behavior of the exact pinned frpc
// release. The retry loop remains provider-owned; vpnctl validates and tests
// this contract instead of adding a second dialer or a standby endpoint.
type FRPReconnectContract struct {
	InitialDelay      time.Duration
	Factor            float64
	Jitter            float64
	InitialMaxDelay   time.Duration
	ReconnectMaxDelay time.Duration
	FastRetryCount    int
	FastRetryDelay    time.Duration
	FastRetryWindow   time.Duration
	FastRetryJitter   float64
}

func PinnedFRPReconnectContract() FRPReconnectContract {
	return FRPReconnectContract{
		InitialDelay: time.Second, Factor: 2, Jitter: 0.1,
		InitialMaxDelay: 10 * time.Second, ReconnectMaxDelay: 20 * time.Second,
		FastRetryCount: 3, FastRetryDelay: 200 * time.Millisecond,
		FastRetryWindow: time.Minute, FastRetryJitter: 0.5,
	}
}

type TunnelProbeState string

const (
	TunnelProbePassed TunnelProbeState = "passed"
	TunnelProbeFailed TunnelProbeState = "failed"
)

type TunnelProbeResult struct {
	State TunnelProbeState `json:"state"`
	Code  string           `json:"code"`
}

func (result TunnelProbeResult) Validate() error {
	if result.State != TunnelProbePassed && result.State != TunnelProbeFailed {
		return fmt.Errorf("tunnel probe has invalid state")
	}
	if result.Code == "" || strings.TrimSpace(result.Code) != result.Code || strings.ContainsAny(result.Code, " \t\r\n") {
		return fmt.Errorf("tunnel probe has invalid code")
	}
	return nil
}

type TunnelMappingReadiness struct {
	ExposeID     string            `json:"expose_id"`
	Name         string            `json:"name"`
	Generation   uint64            `json:"generation"`
	Registration TunnelProbeResult `json:"registration"`
	Upstream     TunnelProbeResult `json:"upstream"`
}

func (mapping TunnelMappingReadiness) validate(nodeID string) error {
	if err := validateUUID("tunnel readiness expose ID", mapping.ExposeID); err != nil {
		return err
	}
	wantName, _ := MappingName(nodeID, mapping.ExposeID)
	if mapping.Name != wantName || mapping.Generation == 0 {
		return fmt.Errorf("tunnel readiness mapping identity is invalid")
	}
	if err := mapping.Registration.Validate(); err != nil {
		return fmt.Errorf("registration readiness: %w", err)
	}
	if err := mapping.Upstream.Validate(); err != nil {
		return fmt.Errorf("upstream readiness: %w", err)
	}
	return nil
}

type TunnelReadinessResult struct {
	Candidate     CandidateDescriptor      `json:"candidate"`
	Configuration TunnelProbeResult        `json:"configuration"`
	Connection    TunnelProbeResult        `json:"connection"`
	MappingSet    TunnelProbeResult        `json:"mapping_set"`
	Mappings      []TunnelMappingReadiness `json:"mappings"`
}

func (result TunnelReadinessResult) Validate() error {
	if err := result.Candidate.Validate(); err != nil {
		return err
	}
	if result.Candidate.HostRole != model.RoleNode {
		return fmt.Errorf("tunnel readiness candidate must belong to a node")
	}
	for name, probe := range map[string]TunnelProbeResult{
		"configuration": result.Configuration, "connection": result.Connection, "mapping_set": result.MappingSet,
	} {
		if err := probe.Validate(); err != nil {
			return fmt.Errorf("%s readiness: %w", name, err)
		}
	}
	if result.Mappings == nil {
		return fmt.Errorf("tunnel readiness mappings must be present")
	}
	previousName := ""
	for index, mapping := range result.Mappings {
		if err := mapping.validate(result.Candidate.NodeID); err != nil {
			return fmt.Errorf("tunnel readiness mapping %d: %w", index, err)
		}
		if previousName != "" && mapping.Name <= previousName {
			return fmt.Errorf("tunnel readiness mappings must be ordered and unique")
		}
		previousName = mapping.Name
	}
	return nil
}

func (result TunnelReadinessResult) Ready() bool {
	if result.Validate() != nil || result.Configuration.State != TunnelProbePassed ||
		result.Connection.State != TunnelProbePassed || result.MappingSet.State != TunnelProbePassed {
		return false
	}
	for _, mapping := range result.Mappings {
		if mapping.Registration.State != TunnelProbePassed || mapping.Upstream.State != TunnelProbePassed {
			return false
		}
	}
	return true
}

// IngressHTTPStatus binds an ingress decision to the exact desired candidate
// and expose generation. Zero means the provider may forward; every absent,
// stale, disabled, or degraded observation returns 503.
func (result TunnelReadinessResult) IngressHTTPStatus(expected CandidateDescriptor, expose model.Expose) int {
	if result.Validate() != nil || expected.Validate() != nil || result.Candidate != expected ||
		result.Configuration.State != TunnelProbePassed || result.Connection.State != TunnelProbePassed ||
		result.MappingSet.State != TunnelProbePassed || expose.Validate() != nil || expose.State == model.ExposeDisabled ||
		expose.NodeID != expected.NodeID {
		return FRPIngressDegradedHTTPStatus
	}
	for _, mapping := range result.Mappings {
		if mapping.ExposeID == expose.ID && mapping.Generation == expose.Generation &&
			mapping.Registration.State == TunnelProbePassed && mapping.Upstream.State == TunnelProbePassed {
			return 0
		}
	}
	return FRPIngressDegradedHTTPStatus
}

func (result TunnelReadinessResult) EffectiveExposeState(expected CandidateDescriptor, expose model.Expose) model.ExposeState {
	if expose.Validate() == nil && expose.State == model.ExposeDisabled {
		return model.ExposeDisabled
	}
	if result.IngressHTTPStatus(expected, expose) == 0 {
		return model.ExposeReady
	}
	return model.ExposeDegraded
}

type TunnelReadinessProber interface {
	Probe(context.Context, FRPCandidate) (TunnelReadinessResult, error)
}

type TunnelReadinessGate struct{ prober TunnelReadinessProber }

func NewTunnelReadinessGate(prober TunnelReadinessProber) (*TunnelReadinessGate, error) {
	if prober == nil {
		return nil, fmt.Errorf("tunnel readiness prober is required")
	}
	return &TunnelReadinessGate{prober: prober}, nil
}

type TunnelReadyCandidate struct {
	candidate FRPCandidate
	result    TunnelReadinessResult
	verified  bool
}

func (candidate TunnelReadyCandidate) Descriptor() CandidateDescriptor {
	return candidate.candidate.Descriptor()
}
func (candidate TunnelReadyCandidate) Bytes() []byte                    { return candidate.candidate.Bytes() }
func (candidate TunnelReadyCandidate) Readiness() TunnelReadinessResult { return candidate.result }
func (candidate TunnelReadyCandidate) Valid() bool {
	return candidate.verified && candidate.result.Ready() && candidate.result.Candidate == candidate.candidate.Descriptor()
}

type TunnelNotReadyError struct{ Code string }

func (failure *TunnelNotReadyError) Error() string {
	if failure == nil || failure.Code == "" {
		return ErrTunnelNotReady.Error()
	}
	return ErrTunnelNotReady.Error() + ": " + failure.Code
}

func (failure *TunnelNotReadyError) Unwrap() error { return ErrTunnelNotReady }

func (gate *TunnelReadinessGate) Check(ctx context.Context, candidate FRPCandidate) (TunnelReadyCandidate, TunnelReadinessResult, error) {
	if ctx == nil {
		return TunnelReadyCandidate{}, TunnelReadinessResult{}, fmt.Errorf("context is required")
	}
	if gate == nil || gate.prober == nil {
		return TunnelReadyCandidate{}, TunnelReadinessResult{}, fmt.Errorf("tunnel readiness gate is incomplete")
	}
	if err := candidate.Descriptor().Validate(); err != nil {
		return TunnelReadyCandidate{}, TunnelReadinessResult{}, err
	}
	if candidate.Descriptor().HostRole != model.RoleNode {
		return TunnelReadyCandidate{}, TunnelReadinessResult{}, fmt.Errorf("tunnel readiness requires a node candidate")
	}
	content := candidate.Bytes()
	defer clear(content)
	if err := ValidateFRPClientConfig(content); err != nil {
		return TunnelReadyCandidate{}, TunnelReadinessResult{}, fmt.Errorf("validate tunnel candidate before readiness: %w", err)
	}
	result, err := gate.prober.Probe(ctx, candidate)
	if err != nil {
		return TunnelReadyCandidate{}, TunnelReadinessResult{}, fmt.Errorf("probe tunnel readiness: %w", err)
	}
	if err := result.Validate(); err != nil {
		return TunnelReadyCandidate{}, TunnelReadinessResult{}, err
	}
	if result.Candidate != candidate.Descriptor() || !sameReadinessMappings(candidate, result.Mappings) {
		return TunnelReadyCandidate{}, result, fmt.Errorf("tunnel readiness belongs to another candidate generation")
	}
	if !result.Ready() {
		return TunnelReadyCandidate{}, result, &TunnelNotReadyError{Code: tunnelReadinessFailureCode(result)}
	}
	return TunnelReadyCandidate{candidate: candidate, result: result, verified: true}, result, nil
}

func sameReadinessMappings(candidate FRPCandidate, observed []TunnelMappingReadiness) bool {
	content := candidate.Bytes()
	defer clear(content)
	document, err := parseFRPClientConfig(content)
	if err != nil || len(document.Mappings) != len(observed) {
		return false
	}
	for index, mapping := range document.Mappings {
		if observed[index].ExposeID != mapping.ExposeID || observed[index].Name != mapping.Name || observed[index].Generation != mapping.Generation {
			return false
		}
	}
	return true
}

func tunnelReadinessFailureCode(result TunnelReadinessResult) string {
	for _, probe := range []TunnelProbeResult{result.Configuration, result.Connection, result.MappingSet} {
		if probe.State != TunnelProbePassed {
			return probe.Code
		}
	}
	for _, mapping := range result.Mappings {
		if mapping.Registration.State != TunnelProbePassed {
			return mapping.Registration.Code
		}
		if mapping.Upstream.State != TunnelProbePassed {
			return mapping.Upstream.Code
		}
	}
	return "tunnel-readiness-invalid"
}

type FRPProxyStatus struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Err        string `json:"err"`
	LocalAddr  string `json:"local_addr"`
	Plugin     string `json:"plugin"`
	RemoteAddr string `json:"remote_addr"`
	Source     string `json:"source,omitempty"`
}

type FRPClientStatusSource interface {
	Status(context.Context, string) ([]FRPProxyStatus, error)
}

type frpHTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type FRPHTTPStatusSource struct{ client frpHTTPDoer }

func NewFRPHTTPStatusSource() *FRPHTTPStatusSource {
	dialer := &net.Dialer{Timeout: frpClientStatusTimeout}
	transport := &http.Transport{
		Proxy:                  nil,
		ResponseHeaderTimeout:  frpClientStatusTimeout,
		MaxResponseHeaderBytes: 8 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != FRPClientStatusAddress {
				return nil, fmt.Errorf("refuse non-local frpc status endpoint")
			}
			return dialer.DialContext(ctx, "tcp4", FRPClientStatusAddress)
		},
		DisableKeepAlives: true,
	}
	return &FRPHTTPStatusSource{client: &http.Client{
		Transport: transport, Timeout: frpClientStatusTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func newFRPHTTPStatusSource(client frpHTTPDoer) (*FRPHTTPStatusSource, error) {
	if client == nil {
		return nil, fmt.Errorf("frpc status HTTP client is required")
	}
	return &FRPHTTPStatusSource{client: client}, nil
}

func (source *FRPHTTPStatusSource) Status(ctx context.Context, adminPassword string) ([]FRPProxyStatus, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if source == nil || source.client == nil || len(adminPassword) != sha256.Size*2 {
		return nil, fmt.Errorf("frpc status source is incomplete")
	}
	decodedPassword, passwordErr := hex.DecodeString(adminPassword)
	defer clear(decodedPassword)
	if passwordErr != nil || len(decodedPassword) != sha256.Size ||
		hex.EncodeToString(decodedPassword) != adminPassword {
		return nil, fmt.Errorf("frpc status source is incomplete")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+FRPClientStatusAddress+FRPClientStatusPath, nil)
	if err != nil {
		return nil, fmt.Errorf("create local frpc status request")
	}
	request.SetBasicAuth("vpnctl", adminPassword)
	request.Header.Set("Accept", "application/json")
	response, err := source.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("local frpc status unavailable")
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("local frpc status unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("local frpc status unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, FRPClientStatusMaximumBytes+1))
	if err != nil || len(body) == 0 || len(body) > FRPClientStatusMaximumBytes {
		clear(body)
		return nil, fmt.Errorf("local frpc status response is invalid")
	}
	defer clear(body)
	statuses, err := decodeFRPStatus(body)
	if err != nil {
		return nil, fmt.Errorf("local frpc status response is invalid")
	}
	return statuses, nil
}

func decodeFRPStatus(data []byte) ([]FRPProxyStatus, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkAuthorizationJSON(decoder, 1); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing frpc status JSON")
	}
	var envelope map[string]json.RawMessage
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, err
	}
	if len(envelope) == 0 {
		return []FRPProxyStatus{}, nil
	}
	if len(envelope) != 1 {
		return nil, fmt.Errorf("frpc status contains unsupported proxy types")
	}
	raw, ok := envelope["tcp"]
	if !ok {
		return nil, fmt.Errorf("frpc status contains unsupported proxy type")
	}
	var statuses []FRPProxyStatus
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&statuses); err != nil || statuses == nil || len(statuses) > DefaultLoopbackPortLast-DefaultLoopbackPortFirst+1 {
		return nil, fmt.Errorf("invalid frpc TCP status list")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("trailing frpc TCP status JSON")
	}
	return statuses, nil
}

type TunnelUpstreamProber interface {
	Probe(context.Context, string) error
}

type NetTunnelUpstreamProber struct{ dialer net.Dialer }

func NewNetTunnelUpstreamProber() *NetTunnelUpstreamProber {
	return &NetTunnelUpstreamProber{dialer: net.Dialer{Timeout: frpUpstreamProbeTimeout}}
}

func (prober *NetTunnelUpstreamProber) Probe(ctx context.Context, address string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if prober == nil || prober.dialer.Timeout <= 0 || validateUpstream(address) != nil {
		return fmt.Errorf("tunnel upstream probe is invalid")
	}
	connection, err := prober.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("tunnel upstream unavailable")
	}
	_ = connection.Close()
	return nil
}

type FRPClientSystemReadinessProber struct {
	paths    store.Paths
	status   FRPClientStatusSource
	upstream TunnelUpstreamProber
}

func NewFRPClientSystemReadinessProber(paths store.Paths, status FRPClientStatusSource, upstream TunnelUpstreamProber) (*FRPClientSystemReadinessProber, error) {
	if status == nil || upstream == nil {
		return nil, fmt.Errorf("tunnel system readiness dependencies are incomplete")
	}
	wantConfigDir := filepath.Join(paths.Root, "etc", "vpnctl")
	if paths.Root == "" || !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root || paths.ConfigDir != wantConfigDir {
		return nil, fmt.Errorf("tunnel system readiness paths are invalid")
	}
	return &FRPClientSystemReadinessProber{paths: paths, status: status, upstream: upstream}, nil
}

func (prober *FRPClientSystemReadinessProber) Probe(ctx context.Context, candidate FRPCandidate) (TunnelReadinessResult, error) {
	if ctx == nil {
		return TunnelReadinessResult{}, fmt.Errorf("context is required")
	}
	if prober == nil || prober.status == nil || prober.upstream == nil {
		return TunnelReadinessResult{}, fmt.Errorf("tunnel system readiness prober is incomplete")
	}
	if candidate.Descriptor().HostRole != model.RoleNode {
		return TunnelReadinessResult{}, fmt.Errorf("tunnel system readiness requires a node candidate")
	}
	candidateContent := candidate.Bytes()
	defer clear(candidateContent)
	document, err := parseFRPClientConfig(candidateContent)
	if err != nil {
		return TunnelReadinessResult{}, fmt.Errorf("validate tunnel readiness candidate: %w", err)
	}
	result := newTunnelReadinessResult(candidate.Descriptor(), document.Mappings)
	configPath, _ := frpServicePaths(prober.paths, model.RoleNode)
	installed, err := readFRPServiceFile(configPath, true, maximumFRPConfigBytes, "client config")
	if err == nil {
		digest := sha256.Sum256(installed)
		if bytes.Equal(installed, candidateContent) && hex.EncodeToString(digest[:]) == candidate.Descriptor().ConfigHash {
			result.Configuration = passedTunnelProbe("tunnel-generation-ready")
		}
	}
	clear(installed)
	probeTunnelUpstreams(ctx, prober.upstream, document.Mappings, result.Mappings)
	if result.Configuration.State != TunnelProbePassed {
		return result, result.Validate()
	}
	statuses, statusErr := prober.status.Status(ctx, frpAdminPassword(document.TunnelCredential))
	if statusErr != nil {
		return result, result.Validate()
	}
	applyFRPStatus(document, statuses, &result)
	return result, result.Validate()
}

func newTunnelReadinessResult(descriptor CandidateDescriptor, mappings []Mapping) TunnelReadinessResult {
	result := TunnelReadinessResult{
		Candidate:     descriptor,
		Configuration: failedTunnelProbe("tunnel-generation-mismatch"),
		Connection:    failedTunnelProbe("tunnel-connection-unavailable"),
		MappingSet:    failedTunnelProbe("tunnel-mapping-set-unavailable"),
		Mappings:      make([]TunnelMappingReadiness, len(mappings)),
	}
	for index, mapping := range mappings {
		result.Mappings[index] = TunnelMappingReadiness{
			ExposeID: mapping.ExposeID, Name: mapping.Name, Generation: mapping.Generation,
			Registration: failedTunnelProbe("tunnel-mapping-unavailable"),
			Upstream:     failedTunnelProbe("tunnel-upstream-unavailable"),
		}
	}
	return result
}

func probeTunnelUpstreams(ctx context.Context, prober TunnelUpstreamProber, mappings []Mapping, results []TunnelMappingReadiness) {
	semaphore := make(chan struct{}, FRPUpstreamProbeConcurrency)
	var wait sync.WaitGroup
	for index := range mappings {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			if prober.Probe(ctx, mappings[index].NodeUpstream) == nil {
				results[index].Upstream = passedTunnelProbe("tunnel-upstream-ready")
			}
		}()
	}
	wait.Wait()
}

func applyFRPStatus(document frpClientDocument, statuses []FRPProxyStatus, result *TunnelReadinessResult) {
	if result == nil || len(document.Mappings) == 0 || len(statuses) != len(document.Mappings) {
		return
	}
	byName := make(map[string]FRPProxyStatus, len(statuses))
	for _, status := range statuses {
		if _, duplicate := byName[status.Name]; duplicate {
			return
		}
		byName[status.Name] = status
	}
	allExact := true
	for index, mapping := range document.Mappings {
		status, present := byName[mapping.Name]
		wantRemote := net.JoinHostPort(document.ServerEndpoint.Addr().String(), fmt.Sprintf("%d", mapping.GatewayEndpoint.Port()))
		if !present || status.Type != "tcp" || status.LocalAddr != mapping.NodeUpstream || status.RemoteAddr != wantRemote ||
			status.Plugin != "" || status.Source != "" || !validFRPProxyPhase(status.Status) {
			allExact = false
			continue
		}
		if status.Status == "running" && status.Err == "" {
			result.Mappings[index].Registration = passedTunnelProbe("tunnel-mapping-ready")
		}
	}
	if !allExact {
		return
	}
	result.MappingSet = passedTunnelProbe("tunnel-mapping-set-ready")
	result.Connection = passedTunnelProbe("tunnel-connection-ready")
}

func validFRPProxyPhase(value string) bool {
	switch value {
	case "new", "wait start", "start error", "running", "check failed", "closed":
		return true
	default:
		return false
	}
}

func passedTunnelProbe(code string) TunnelProbeResult {
	return TunnelProbeResult{State: TunnelProbePassed, Code: code}
}
func failedTunnelProbe(code string) TunnelProbeResult {
	return TunnelProbeResult{State: TunnelProbeFailed, Code: code}
}

var _ FRPClientStatusSource = (*FRPHTTPStatusSource)(nil)
var _ TunnelUpstreamProber = (*NetTunnelUpstreamProber)(nil)
var _ TunnelReadinessProber = (*FRPClientSystemReadinessProber)(nil)
