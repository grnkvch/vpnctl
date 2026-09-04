package operations

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestLoggingDefaultOffAndEveryExplicitScopeAndLevel(t *testing.T) {
	now := time.Date(2026, time.September, 4, 15, 0, 0, 0, time.UTC)
	base := loggingTestState(t, now)
	for _, scope := range []model.LogScope{
		model.LogControl, model.LogTransport, model.LogRouting, model.LogDNS, model.LogTunnel, model.LogIngress, model.LogAll,
	} {
		for _, level := range []model.LogLevel{model.LogError, model.LogInfo, model.LogDebug, model.LogTrace} {
			t.Run(string(scope)+"/"+string(level), func(t *testing.T) {
				stateStore := &memoryLoggingState{state: cloneStatusTestState(t, base)}
				runtime := &recordingLoggingRuntime{}
				manager := newLoggingTestManager(t, stateStore, runtime, now)

				status, err := manager.Status(context.Background())
				if err != nil || len(status.Active) != 0 || stateStore.saves != 0 || len(runtime.policies) != 0 {
					t.Fatalf("default status = %+v err=%v saves=%d runtime=%d", status, err, stateStore.saves, len(runtime.policies))
				}
				change, err := manager.Enable(context.Background(), LoggingEnableRequest{Scope: scope, Level: level, Duration: 15 * time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				if !change.Changed || change.Enabled == nil || change.Enabled.Scope != scope || change.Enabled.Level != level ||
					change.Enabled.Destination != model.LogToJournald || change.Enabled.RemainingSeconds != 900 {
					t.Fatalf("enable change = %+v", change)
				}
				if stateStore.saves != 1 || len(runtime.policies) != 1 || len(runtime.policies[0].Active) != 1 ||
					runtime.policies[0].Active[0].FilePath != "" || runtime.policies[0].NextExpiry == nil ||
					!runtime.policies[0].NextExpiry.Equal(now.Add(15*time.Minute)) {
					t.Fatalf("persisted/runtime = saves %d policy %+v", stateStore.saves, runtime.policies)
				}
			})
		}
	}
}

func TestLoggingEnableRequiresBoundedExplicitInputsAndRejectsOverlap(t *testing.T) {
	now := time.Date(2026, time.September, 4, 15, 0, 0, 0, time.UTC)
	tests := []LoggingEnableRequest{
		{Scope: "unknown", Level: model.LogDebug, Duration: time.Minute},
		{Scope: model.LogDNS, Level: "verbose", Duration: time.Minute},
		{Scope: model.LogDNS, Level: model.LogDebug},
		{Scope: model.LogDNS, Level: model.LogDebug, Duration: time.Hour + time.Second},
		{Scope: model.LogDNS, Level: model.LogDebug, Duration: time.Second + time.Nanosecond},
	}
	for _, request := range tests {
		stateStore := &memoryLoggingState{state: loggingTestState(t, now)}
		runtime := &recordingLoggingRuntime{}
		manager := newLoggingTestManager(t, stateStore, runtime, now)
		if _, err := manager.Enable(context.Background(), request); !errors.Is(err, ErrLoggingInvalid) {
			t.Fatalf("Enable(%+v) error = %v", request, err)
		}
		if stateStore.saves != 0 || len(runtime.policies) != 0 {
			t.Fatalf("invalid request mutated state/runtime: %d/%d", stateStore.saves, len(runtime.policies))
		}
	}

	for _, pair := range [][2]model.LogScope{{model.LogDNS, model.LogDNS}, {model.LogAll, model.LogIngress}, {model.LogTunnel, model.LogAll}} {
		state := loggingTestState(t, now)
		state.Logging = []model.LoggingSession{loggingSession("11111111-1111-4111-8111-111111111111", pair[0], now, now.Add(time.Hour))}
		stateStore := &memoryLoggingState{state: state}
		manager := newLoggingTestManager(t, stateStore, &recordingLoggingRuntime{}, now)
		_, err := manager.Enable(context.Background(), LoggingEnableRequest{Scope: pair[1], Level: model.LogInfo, Duration: time.Minute})
		if !errors.Is(err, ErrLoggingConflict) {
			t.Fatalf("overlap %v error = %v", pair, err)
		}
	}
}

func TestLoggingDifferentScopesCoexistAndFilePathIsManaged(t *testing.T) {
	now := time.Date(2026, time.September, 4, 15, 0, 0, 0, time.UTC)
	state := loggingTestState(t, now)
	state.Logging = []model.LoggingSession{loggingSession("11111111-1111-4111-8111-111111111111", model.LogDNS, now, now.Add(time.Hour))}
	stateStore := &memoryLoggingState{state: state}
	runtime := &recordingLoggingRuntime{}
	manager := newLoggingTestManager(t, stateStore, runtime, now)
	change, err := manager.Enable(context.Background(), LoggingEnableRequest{
		Scope: model.LogIngress, Level: model.LogTrace, Duration: 5 * time.Minute, File: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if change.Enabled == nil || change.Enabled.Destination != model.LogToFile {
		t.Fatalf("file change = %+v", change)
	}
	policy := runtime.policies[0]
	if len(policy.Active) != 2 || policy.Active[1].Scope != model.LogIngress || policy.Active[1].FilePath != "/var/log/vpnctl/ingress.log" ||
		policy.FileMaxBytes != LoggingFileMaxBytes || policy.FileArchives != LoggingFileMaxArchives {
		t.Fatalf("file policy = %+v", policy)
	}
	status, err := manager.Status(context.Background())
	if err != nil || len(status.Active) != 2 {
		t.Fatalf("status = %+v, %v", status, err)
	}
	// Public status deliberately has no file-path field.
	if _, exists := reflect.TypeOf(status.Active[0]).FieldByName("FilePath"); exists {
		t.Fatal("logging status exposes the local file path")
	}
}

func TestLoggingDisableScopeAndAllAreExplicitAndFailClosed(t *testing.T) {
	now := time.Date(2026, time.September, 4, 15, 0, 0, 0, time.UTC)
	state := loggingTestState(t, now)
	state.Logging = []model.LoggingSession{
		loggingSession("11111111-1111-4111-8111-111111111111", model.LogDNS, now, now.Add(time.Hour)),
		loggingSession("22222222-2222-4222-8222-222222222222", model.LogIngress, now, now.Add(time.Hour)),
	}
	stateStore := &memoryLoggingState{state: state}
	runtime := &recordingLoggingRuntime{}
	manager := newLoggingTestManager(t, stateStore, runtime, now)

	change, err := manager.Disable(context.Background(), model.LogDNS)
	if err != nil || !reflect.DeepEqual(change.DisabledIDs, []string{"11111111-1111-4111-8111-111111111111"}) || len(runtime.policies[0].Active) != 1 {
		t.Fatalf("disable dns = %+v runtime=%+v err=%v", change, runtime.policies, err)
	}
	change, err = manager.Disable(context.Background(), model.LogAll)
	if err != nil || !reflect.DeepEqual(change.DisabledIDs, []string{"22222222-2222-4222-8222-222222222222"}) || len(runtime.policies[1].Active) != 0 {
		t.Fatalf("disable all = %+v runtime=%+v err=%v", change, runtime.policies, err)
	}
	noChange, err := manager.Disable(context.Background(), model.LogAll)
	if err != nil || noChange.Changed || stateStore.saves != 2 || len(runtime.policies) != 2 {
		t.Fatalf("second disable = %+v saves=%d runtime=%d err=%v", noChange, stateStore.saves, len(runtime.policies), err)
	}
}

func TestLoggingAbsoluteExpirySurvivesManagerRestarts(t *testing.T) {
	started := time.Date(2026, time.September, 4, 15, 0, 0, 0, time.UTC)
	now := started
	stateStore := &memoryLoggingState{state: loggingTestState(t, started)}
	firstRuntime := &recordingLoggingRuntime{}
	first := newLoggingTestManagerWithClock(t, stateStore, firstRuntime, func() time.Time { return now })
	change, err := first.Enable(context.Background(), LoggingEnableRequest{Scope: model.LogRouting, Level: model.LogDebug, Duration: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	wantExpiry := change.Enabled.ExpiresAt

	now = started.Add(10 * time.Minute)
	restartedRuntime := &recordingLoggingRuntime{}
	restarted := newLoggingTestManagerWithClock(t, stateStore, restartedRuntime, func() time.Time { return now })
	if _, err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := restarted.Status(context.Background())
	if err != nil || len(status.Active) != 1 || status.Active[0].RemainingSeconds != 300 || !status.Active[0].ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("restarted status = %+v, %v", status, err)
	}

	now = wantExpiry
	secondRestartRuntime := &recordingLoggingRuntime{}
	secondRestart := newLoggingTestManagerWithClock(t, stateStore, secondRestartRuntime, func() time.Time { return now })
	expired, err := secondRestart.Reconcile(context.Background())
	if err != nil || !expired.Changed || !reflect.DeepEqual(expired.ExpiredIDs, []string{change.Enabled.ID}) {
		t.Fatalf("expiry reconcile = %+v, %v", expired, err)
	}
	if len(secondRestartRuntime.policies) != 1 || len(secondRestartRuntime.policies[0].Active) != 0 || secondRestartRuntime.policies[0].NextExpiry != nil {
		t.Fatalf("expired runtime policy = %+v", secondRestartRuntime.policies)
	}
	status, err = secondRestart.Status(context.Background())
	if err != nil || len(status.Active) != 0 || stateStore.state.Logging[0].State != model.LogExpired || !stateStore.state.Logging[0].ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expired status/state = %+v / %+v, %v", status, stateStore.state.Logging, err)
	}
	if again, err := secondRestart.Reconcile(context.Background()); err != nil || again.Changed || stateStore.saves != 2 {
		t.Fatalf("idempotent reconcile = %+v saves=%d err=%v", again, stateStore.saves, err)
	}
}

func TestLoggingDryRunDoesNotGenerateIdentityApplyRuntimeOrPersist(t *testing.T) {
	now := time.Date(2026, time.September, 4, 15, 0, 0, 0, time.UTC)
	stateStore := &memoryLoggingState{state: loggingTestState(t, now)}
	runtime := &recordingLoggingRuntime{}
	manager, err := NewLoggingManager(stateStore, runtime, LoggingManagerOptions{
		Now: func() time.Time { return now }, FileDirectory: "/var/log/vpnctl",
		NewUUID: func() (string, error) { t.Fatal("dry-run generated an identity"); return "", errors.New("unexpected") },
	})
	if err != nil {
		t.Fatal(err)
	}
	change, err := manager.PreviewEnable(context.Background(), LoggingEnableRequest{Scope: model.LogControl, Level: model.LogInfo, Duration: time.Minute})
	if err != nil || !change.Changed || change.Enabled == nil || stateStore.saves != 0 || len(runtime.policies) != 0 || len(stateStore.state.Logging) != 0 {
		t.Fatalf("preview = %+v saves=%d runtime=%d state=%+v err=%v", change, stateStore.saves, len(runtime.policies), stateStore.state.Logging, err)
	}
}

func TestLoggingRuntimeAndPersistenceFailuresDoNotLeaveNewLoggingEnabled(t *testing.T) {
	now := time.Date(2026, time.September, 4, 15, 0, 0, 0, time.UTC)
	request := LoggingEnableRequest{Scope: model.LogControl, Level: model.LogTrace, Duration: time.Minute}

	stateStore := &memoryLoggingState{state: loggingTestState(t, now)}
	runtime := &recordingLoggingRuntime{failAt: 1}
	manager := newLoggingTestManager(t, stateStore, runtime, now)
	if _, err := manager.Enable(context.Background(), request); err == nil || stateStore.saves != 0 || len(stateStore.state.Logging) != 0 {
		t.Fatalf("runtime failure err=%v saves=%d state=%+v", err, stateStore.saves, stateStore.state.Logging)
	}

	stateStore = &memoryLoggingState{state: loggingTestState(t, now), saveErr: errors.New("disk full")}
	runtime = &recordingLoggingRuntime{}
	manager = newLoggingTestManager(t, stateStore, runtime, now)
	if _, err := manager.Enable(context.Background(), request); err == nil || len(runtime.policies) != 2 || len(runtime.policies[0].Active) != 1 || len(runtime.policies[1].Active) != 0 || len(stateStore.state.Logging) != 0 {
		t.Fatalf("save rollback err=%v runtime=%+v state=%+v", err, runtime.policies, stateStore.state.Logging)
	}
}

func loggingTestState(t *testing.T, now time.Time) model.State {
	t.Helper()
	state := statusGatewayState(t, now)
	state.Invites = []model.Invite{}
	state.Logging = []model.LoggingSession{}
	state.Certificates[0].NotAfter = now.AddDate(1, 0, 0)
	state.Backups[0].CreatedAt = now
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	return state
}

func loggingSession(id string, scope model.LogScope, start, expiry time.Time) model.LoggingSession {
	return model.LoggingSession{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, Scope: scope, Level: model.LogDebug,
		Destination: model.LogToJournald, State: model.LogActive, StartedAt: start, ExpiresAt: expiry,
	}
}

func newLoggingTestManager(t *testing.T, state *memoryLoggingState, runtime *recordingLoggingRuntime, now time.Time) *LoggingManager {
	t.Helper()
	return newLoggingTestManagerWithClock(t, state, runtime, func() time.Time { return now })
}

func newLoggingTestManagerWithClock(t *testing.T, state *memoryLoggingState, runtime *recordingLoggingRuntime, now func() time.Time) *LoggingManager {
	t.Helper()
	manager, err := NewLoggingManager(state, runtime, LoggingManagerOptions{
		Now: now, FileDirectory: "/var/log/vpnctl",
		NewUUID: func() (string, error) {
			return "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa" + string(rune('0'+state.saves)), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

type memoryLoggingState struct {
	state   model.State
	saves   int
	saveErr error
}

func (state *memoryLoggingState) Load() (model.State, error) {
	data, err := model.EncodeState(state.state)
	if err != nil {
		return model.State{}, err
	}
	return model.DecodeState(data)
}

func (state *memoryLoggingState) Save(expected uint64, candidate model.State) error {
	if state.saveErr != nil {
		return state.saveErr
	}
	if expected != state.state.Generation {
		return errors.New("generation conflict")
	}
	if err := model.ValidateTransition(state.state, candidate); err != nil {
		return err
	}
	state.state = candidate
	state.saves++
	return nil
}

type recordingLoggingRuntime struct {
	policies []LoggingRuntimePolicy
	failAt   int
}

func (runtime *recordingLoggingRuntime) ApplyLogging(_ context.Context, policy LoggingRuntimePolicy) error {
	runtime.policies = append(runtime.policies, policy)
	if runtime.failAt != 0 && len(runtime.policies) == runtime.failAt {
		return errors.New("runtime unavailable")
	}
	return nil
}
