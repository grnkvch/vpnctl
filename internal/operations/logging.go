package operations

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	MaximumLoggingDuration = time.Hour
	LoggingFileMaxBytes    = int64(8 << 20)
	LoggingFileMaxArchives = 3
)

var (
	ErrLoggingInvalid  = errors.New("invalid logging request")
	ErrLoggingConflict = errors.New("logging scope conflict")
)

type LoggingStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

// LoggingRuntimePolicy is the complete, non-secret effective policy consumed
// by component logging adapters. Consumers must also compare ExpiresAt with
// their current clock before every emission so expiry does not depend on a
// controller, timer, or process restart.
type LoggingRuntimePolicy struct {
	SchemaVersion int                     `json:"schema_version"`
	Generation    uint64                  `json:"generation"`
	Active        []LoggingRuntimeSession `json:"active"`
	NextExpiry    *time.Time              `json:"next_expiry,omitempty"`
	FileMaxBytes  int64                   `json:"file_max_bytes"`
	FileArchives  int                     `json:"file_archives"`
}

type LoggingRuntimeSession struct {
	ID          string               `json:"id"`
	Scope       model.LogScope       `json:"scope"`
	Level       model.LogLevel       `json:"level"`
	Destination model.LogDestination `json:"destination"`
	FilePath    string               `json:"file_path,omitempty"`
	ExpiresAt   time.Time            `json:"expires_at"`
}

type LoggingRuntime interface {
	ApplyLogging(context.Context, LoggingRuntimePolicy) error
}

type LoggingEnableRequest struct {
	Scope    model.LogScope
	Level    model.LogLevel
	Duration time.Duration
	File     bool
}

type LoggingOptIn struct {
	ID               string               `json:"id"`
	Scope            model.LogScope       `json:"scope"`
	Level            model.LogLevel       `json:"level"`
	Destination      model.LogDestination `json:"destination"`
	StartedAt        time.Time            `json:"started_at"`
	ExpiresAt        time.Time            `json:"expires_at"`
	RemainingSeconds int64                `json:"remaining_seconds"`
}

type LoggingStatusReport struct {
	Role       model.Role
	Generation uint64
	Active     []LoggingOptIn
}

type LoggingChange struct {
	Role        model.Role    `json:"role"`
	Changed     bool          `json:"changed"`
	Generation  uint64        `json:"generation"`
	Enabled     *LoggingOptIn `json:"enabled,omitempty"`
	DisabledIDs []string      `json:"disabled_ids"`
	ExpiredIDs  []string      `json:"expired_ids"`
}

type LoggingManagerOptions struct {
	Now           func() time.Time
	NewUUID       model.UUIDGenerator
	FileDirectory string
}

type LoggingManager struct {
	state         LoggingStateStore
	runtime       LoggingRuntime
	now           func() time.Time
	newUUID       model.UUIDGenerator
	fileDirectory string
}

func NewLoggingManager(state LoggingStateStore, runtime LoggingRuntime, options LoggingManagerOptions) (*LoggingManager, error) {
	if state == nil || runtime == nil {
		return nil, fmt.Errorf("logging manager dependencies are incomplete")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewUUID == nil {
		options.NewUUID = model.NewUUID
	}
	if !filepath.IsAbs(options.FileDirectory) || filepath.Clean(options.FileDirectory) != options.FileDirectory {
		return nil, fmt.Errorf("logging file directory must be clean and absolute")
	}
	return &LoggingManager{
		state: state, runtime: runtime, now: options.Now, newUUID: options.NewUUID,
		fileDirectory: options.FileDirectory,
	}, nil
}

func (manager *LoggingManager) Status(ctx context.Context) (LoggingStatusReport, error) {
	if ctx == nil {
		return LoggingStatusReport{}, fmt.Errorf("context is required")
	}
	if manager == nil || manager.state == nil {
		return LoggingStatusReport{}, fmt.Errorf("logging manager is incomplete")
	}
	state, err := manager.state.Load()
	if err != nil {
		return LoggingStatusReport{}, fmt.Errorf("load logging state: %w", err)
	}
	now := normalizedLoggingTime(manager.now())
	return loggingStatus(state, now)
}

func (manager *LoggingManager) PreviewEnable(ctx context.Context, request LoggingEnableRequest) (LoggingChange, error) {
	if ctx == nil {
		return LoggingChange{}, fmt.Errorf("context is required")
	}
	state, err := manager.loadState()
	if err != nil {
		return LoggingChange{}, err
	}
	_, change, err := manager.enableCandidate(state, request, normalizedLoggingTime(manager.now()), true)
	return change, err
}

func (manager *LoggingManager) Enable(ctx context.Context, request LoggingEnableRequest) (LoggingChange, error) {
	if ctx == nil {
		return LoggingChange{}, fmt.Errorf("context is required")
	}
	state, err := manager.loadState()
	if err != nil {
		return LoggingChange{}, err
	}
	candidate, change, err := manager.enableCandidate(state, request, normalizedLoggingTime(manager.now()), false)
	if err != nil {
		return LoggingChange{}, err
	}
	if err := manager.activate(ctx, state, candidate, true); err != nil {
		return LoggingChange{}, err
	}
	return change, nil
}

func (manager *LoggingManager) PreviewDisable(ctx context.Context, scope model.LogScope) (LoggingChange, error) {
	if ctx == nil {
		return LoggingChange{}, fmt.Errorf("context is required")
	}
	state, err := manager.loadState()
	if err != nil {
		return LoggingChange{}, err
	}
	_, change, err := manager.disableCandidate(state, scope, normalizedLoggingTime(manager.now()))
	return change, err
}

func (manager *LoggingManager) Disable(ctx context.Context, scope model.LogScope) (LoggingChange, error) {
	if ctx == nil {
		return LoggingChange{}, fmt.Errorf("context is required")
	}
	state, err := manager.loadState()
	if err != nil {
		return LoggingChange{}, err
	}
	candidate, change, err := manager.disableCandidate(state, scope, normalizedLoggingTime(manager.now()))
	if err != nil {
		return LoggingChange{}, err
	}
	if !change.Changed {
		return change, nil
	}
	// A failed disable must never re-enable expanded logging as rollback.
	if err := manager.activate(ctx, state, candidate, false); err != nil {
		return LoggingChange{}, err
	}
	return change, nil
}

// Reconcile applies the effective policy and persists active sessions whose
// absolute expiry has passed. It is safe to call at process startup and more
// than once; importantly, it derives expiry from persisted timestamps rather
// than the restart time.
func (manager *LoggingManager) Reconcile(ctx context.Context) (LoggingChange, error) {
	if ctx == nil {
		return LoggingChange{}, fmt.Errorf("context is required")
	}
	state, err := manager.loadState()
	if err != nil {
		return LoggingChange{}, err
	}
	now := normalizedLoggingTime(manager.now())
	candidate, expired := expireLoggingSessions(state, now)
	change := LoggingChange{
		Role: state.Host.Role, Changed: len(expired) != 0, Generation: state.Generation,
		ExpiredIDs: append([]string{}, expired...), DisabledIDs: []string{},
	}
	if change.Changed {
		candidate.Generation, err = model.NextGeneration(state.Generation)
		if err != nil {
			return LoggingChange{}, err
		}
		change.Generation = candidate.Generation
	}
	policy, err := EffectiveLoggingPolicy(candidate, now)
	if err != nil {
		return LoggingChange{}, err
	}
	if err := manager.runtime.ApplyLogging(ctx, policy); err != nil {
		return LoggingChange{}, fmt.Errorf("apply effective logging policy: %w", err)
	}
	if change.Changed {
		if err := manager.state.Save(state.Generation, candidate); err != nil {
			// Keep the already-applied no-expired-session policy: logging expiry
			// is fail-closed even when its bookkeeping write is not acknowledged.
			return LoggingChange{}, fmt.Errorf("persist expired logging sessions: %w", err)
		}
	}
	return change, nil
}

func (manager *LoggingManager) loadState() (model.State, error) {
	if manager == nil || manager.state == nil || manager.runtime == nil {
		return model.State{}, fmt.Errorf("logging manager is incomplete")
	}
	state, err := manager.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load logging state: %w", err)
	}
	if _, err := cloneLoggingState(state); err != nil {
		return model.State{}, err
	}
	return state, nil
}

func (manager *LoggingManager) enableCandidate(state model.State, request LoggingEnableRequest, now time.Time, preview bool) (model.State, LoggingChange, error) {
	if err := validateLoggingEnableRequest(request); err != nil {
		return model.State{}, LoggingChange{}, err
	}
	candidate, expired := expireLoggingSessions(state, now)
	for _, session := range candidate.Logging {
		if session.State == model.LogActive && loggingScopesOverlap(session.Scope, request.Scope) {
			return model.State{}, LoggingChange{}, fmt.Errorf("%w: scope %s overlaps active session %s", ErrLoggingConflict, request.Scope, session.ID)
		}
	}
	occupied := make(map[string]struct{}, len(candidate.Logging))
	for _, session := range candidate.Logging {
		occupied[session.ID] = struct{}{}
	}
	id := previewLoggingUUID(occupied)
	if !preview {
		var err error
		id, err = model.AllocateUUID(occupied, manager.newUUID)
		if err != nil {
			return model.State{}, LoggingChange{}, err
		}
	}
	destination, path := model.LogToJournald, ""
	if request.File {
		destination = model.LogToFile
		path = filepath.Join(manager.fileDirectory, string(request.Scope)+".log")
	}
	session := model.LoggingSession{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, Scope: request.Scope, Level: request.Level,
		Destination: destination, FilePath: path, State: model.LogActive,
		StartedAt: now, ExpiresAt: now.Add(request.Duration),
	}
	candidate.Logging = append(candidate.Logging, session)
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, LoggingChange{}, err
	}
	candidate.Generation = nextGeneration
	if _, err := cloneLoggingState(candidate); err != nil {
		return model.State{}, LoggingChange{}, err
	}
	optIn := projectLoggingOptIn(session, now)
	return candidate, LoggingChange{
		Role: state.Host.Role, Changed: true, Generation: candidate.Generation, Enabled: &optIn,
		DisabledIDs: []string{}, ExpiredIDs: append([]string{}, expired...),
	}, nil
}

func (manager *LoggingManager) disableCandidate(state model.State, scope model.LogScope, now time.Time) (model.State, LoggingChange, error) {
	if !validLoggingScope(scope) {
		return model.State{}, LoggingChange{}, fmt.Errorf("%w: unsupported scope %q", ErrLoggingInvalid, scope)
	}
	candidate, expired := expireLoggingSessions(state, now)
	disabled := make([]string, 0)
	for index := range candidate.Logging {
		session := &candidate.Logging[index]
		if session.State != model.LogActive || (scope != model.LogAll && session.Scope != scope) {
			continue
		}
		session.State = model.LogDisabled
		disabled = append(disabled, session.ID)
	}
	sort.Strings(disabled)
	change := LoggingChange{
		Role: state.Host.Role, Changed: len(expired) != 0 || len(disabled) != 0, Generation: state.Generation,
		DisabledIDs: disabled, ExpiredIDs: append([]string{}, expired...),
	}
	if change.Changed {
		var err error
		candidate.Generation, err = model.NextGeneration(state.Generation)
		if err != nil {
			return model.State{}, LoggingChange{}, err
		}
		change.Generation = candidate.Generation
		if _, err := cloneLoggingState(candidate); err != nil {
			return model.State{}, LoggingChange{}, err
		}
	}
	return candidate, change, nil
}

func (manager *LoggingManager) activate(ctx context.Context, before, candidate model.State, rollback bool) error {
	now := normalizedLoggingTime(manager.now())
	policy, err := EffectiveLoggingPolicy(candidate, now)
	if err != nil {
		return err
	}
	if err := manager.runtime.ApplyLogging(ctx, policy); err != nil {
		return fmt.Errorf("apply logging policy: %w", err)
	}
	if err := manager.state.Save(before.Generation, candidate); err != nil {
		if !rollback {
			return fmt.Errorf("persist logging policy after fail-closed runtime disable: %w", err)
		}
		previous, previousErr := EffectiveLoggingPolicy(before, now)
		if previousErr == nil {
			previousErr = manager.runtime.ApplyLogging(ctx, previous)
		}
		if previousErr != nil {
			return errors.Join(fmt.Errorf("persist logging policy: %w", err), fmt.Errorf("restore prior logging runtime: %w", previousErr))
		}
		return fmt.Errorf("persist logging policy: %w", err)
	}
	return nil
}

func EffectiveLoggingPolicy(state model.State, now time.Time) (LoggingRuntimePolicy, error) {
	if _, err := cloneLoggingState(state); err != nil {
		return LoggingRuntimePolicy{}, err
	}
	now = normalizedLoggingTime(now)
	policy := LoggingRuntimePolicy{
		SchemaVersion: 1, Generation: state.Generation, Active: []LoggingRuntimeSession{},
		FileMaxBytes: LoggingFileMaxBytes, FileArchives: LoggingFileMaxArchives,
	}
	for _, session := range state.Logging {
		if session.State != model.LogActive || now.Before(session.StartedAt) || !now.Before(session.ExpiresAt) {
			continue
		}
		policy.Active = append(policy.Active, LoggingRuntimeSession{
			ID: session.ID, Scope: session.Scope, Level: session.Level, Destination: session.Destination,
			FilePath: session.FilePath, ExpiresAt: session.ExpiresAt.UTC(),
		})
	}
	sort.Slice(policy.Active, func(left, right int) bool {
		if policy.Active[left].Scope != policy.Active[right].Scope {
			return policy.Active[left].Scope < policy.Active[right].Scope
		}
		return policy.Active[left].ID < policy.Active[right].ID
	})
	for _, session := range policy.Active {
		if policy.NextExpiry == nil || session.ExpiresAt.Before(*policy.NextExpiry) {
			expires := session.ExpiresAt
			policy.NextExpiry = &expires
		}
	}
	if err := policy.Validate(); err != nil {
		return LoggingRuntimePolicy{}, err
	}
	return policy, nil
}

func (policy LoggingRuntimePolicy) Validate() error {
	if policy.SchemaVersion != 1 || policy.Active == nil || policy.FileMaxBytes != LoggingFileMaxBytes || policy.FileArchives != LoggingFileMaxArchives {
		return fmt.Errorf("invalid logging runtime policy envelope")
	}
	seen := make(map[string]struct{}, len(policy.Active))
	seenScopes := make(map[model.LogScope]struct{}, len(policy.Active))
	var calculatedNext *time.Time
	for _, session := range policy.Active {
		if session.ID == "" || !validLoggingScope(session.Scope) || session.ExpiresAt.IsZero() {
			return fmt.Errorf("invalid active logging runtime session")
		}
		switch session.Level {
		case model.LogError, model.LogInfo, model.LogDebug, model.LogTrace:
		default:
			return fmt.Errorf("invalid active logging level")
		}
		if session.Destination == model.LogToJournald {
			if session.FilePath != "" {
				return fmt.Errorf("journald logging session contains a file path")
			}
		} else if session.Destination != model.LogToFile || !validManagedLoggingFilePath(session.FilePath, session.Scope) {
			return fmt.Errorf("invalid file logging destination")
		}
		if _, duplicate := seen[session.ID]; duplicate {
			return fmt.Errorf("duplicate active logging runtime session")
		}
		seen[session.ID] = struct{}{}
		if _, duplicate := seenScopes[session.Scope]; duplicate {
			return fmt.Errorf("duplicate active logging scope")
		}
		if session.Scope == model.LogAll && len(seenScopes) != 0 {
			return fmt.Errorf("all logging scope overlaps another session")
		}
		if _, overlaps := seenScopes[model.LogAll]; overlaps {
			return fmt.Errorf("logging scope overlaps all session")
		}
		seenScopes[session.Scope] = struct{}{}
		if calculatedNext == nil || session.ExpiresAt.Before(*calculatedNext) {
			expires := session.ExpiresAt
			calculatedNext = &expires
		}
	}
	if (calculatedNext == nil) != (policy.NextExpiry == nil) || calculatedNext != nil && !calculatedNext.Equal(*policy.NextExpiry) {
		return fmt.Errorf("logging runtime next expiry is inconsistent")
	}
	return nil
}

// ValidatingLoggingRuntime is used until task 13.10 connects each component's
// source logger. Authoritative state is already the runtime source of truth;
// this adapter ensures only a complete, bounded policy can be committed.
type ValidatingLoggingRuntime struct{}

func (ValidatingLoggingRuntime) ApplyLogging(_ context.Context, policy LoggingRuntimePolicy) error {
	return policy.Validate()
}

func loggingStatus(state model.State, now time.Time) (LoggingStatusReport, error) {
	policy, err := EffectiveLoggingPolicy(state, now)
	if err != nil {
		return LoggingStatusReport{}, err
	}
	report := LoggingStatusReport{Role: state.Host.Role, Generation: state.Generation, Active: []LoggingOptIn{}}
	for _, session := range policy.Active {
		for _, persisted := range state.Logging {
			if persisted.ID == session.ID {
				report.Active = append(report.Active, projectLoggingOptIn(persisted, now))
				break
			}
		}
	}
	return report, nil
}

func projectLoggingOptIn(session model.LoggingSession, now time.Time) LoggingOptIn {
	remaining := session.ExpiresAt.Sub(now)
	seconds := int64(remaining / time.Second)
	if remaining%time.Second != 0 {
		seconds++
	}
	if seconds < 0 {
		seconds = 0
	}
	return LoggingOptIn{
		ID: session.ID, Scope: session.Scope, Level: session.Level, Destination: session.Destination,
		StartedAt: session.StartedAt.UTC(), ExpiresAt: session.ExpiresAt.UTC(), RemainingSeconds: seconds,
	}
}

func expireLoggingSessions(state model.State, now time.Time) (model.State, []string) {
	candidate := state
	candidate.Logging = append([]model.LoggingSession{}, state.Logging...)
	expired := make([]string, 0)
	for index := range candidate.Logging {
		session := &candidate.Logging[index]
		if session.State == model.LogActive && !now.Before(session.ExpiresAt) {
			session.State = model.LogExpired
			expired = append(expired, session.ID)
		}
	}
	sort.Strings(expired)
	return candidate, expired
}

func validateLoggingEnableRequest(request LoggingEnableRequest) error {
	if !validLoggingScope(request.Scope) {
		return fmt.Errorf("%w: unsupported scope %q", ErrLoggingInvalid, request.Scope)
	}
	switch request.Level {
	case model.LogError, model.LogInfo, model.LogDebug, model.LogTrace:
	default:
		return fmt.Errorf("%w: unsupported level %q", ErrLoggingInvalid, request.Level)
	}
	if request.Duration <= 0 || request.Duration > MaximumLoggingDuration || request.Duration%time.Second != 0 {
		return fmt.Errorf("%w: duration must be a whole number of seconds no greater than one hour", ErrLoggingInvalid)
	}
	return nil
}

func validLoggingScope(scope model.LogScope) bool {
	switch scope {
	case model.LogControl, model.LogTransport, model.LogRouting, model.LogDNS, model.LogTunnel, model.LogIngress, model.LogAll:
		return true
	default:
		return false
	}
}

func validManagedLoggingFilePath(path string, scope model.LogScope) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != string(scope)+".log" {
		return false
	}
	wantSuffix := filepath.Join("var", "log", "vpnctl")
	directory := filepath.Clean(filepath.Dir(path))
	return directory == string(filepath.Separator)+wantSuffix ||
		len(directory) > len(wantSuffix) && filepath.Base(directory) == "vpnctl" && filepath.Base(filepath.Dir(directory)) == "log" && filepath.Base(filepath.Dir(filepath.Dir(directory))) == "var"
}

func loggingScopesOverlap(left, right model.LogScope) bool {
	return left == right || left == model.LogAll || right == model.LogAll
}

func previewLoggingUUID(occupied map[string]struct{}) string {
	for value := 0; ; value++ {
		candidate := fmt.Sprintf("00000000-0000-4000-8000-%012x", value)
		if _, exists := occupied[candidate]; !exists {
			return candidate
		}
	}
}

func normalizedLoggingTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Second)
}

func cloneLoggingState(state model.State) (model.State, error) {
	encoded, err := model.EncodeState(state)
	if err != nil {
		return model.State{}, fmt.Errorf("validate logging state: %w", err)
	}
	clone, err := model.DecodeState(encoded)
	if err != nil {
		return model.State{}, fmt.Errorf("clone logging state: %w", err)
	}
	return clone, nil
}
