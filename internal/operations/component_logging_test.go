package operations

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/observability"
)

const componentLoggingCanary = "vpnctl-secret-canary-Authorization-Bearer-/telegram/webhook"

func TestComponentLoggerDefaultOffAvoidsEveryDestination(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	state := &fixedComponentLoggingState{state: loggingTestState(t, now)}
	var journal bytes.Buffer
	opened := 0
	logger, err := NewComponentLogger(state, ComponentLoggerOptions{
		Now: func() time.Time { return now }, Journal: &journal,
		OpenFile: func(string) (boundedLoggingDestination, error) {
			opened++
			return &memoryLoggingDestination{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	event, _ := observability.NewEvent(observability.ControlServiceStarted)
	if err := logger.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if journal.Len() != 0 || opened != 0 || state.loads != 1 {
		t.Fatalf("default-off journal=%q opens=%d loads=%d", journal.String(), opened, state.loads)
	}
}

func TestComponentLoggerFiltersEveryScopeAndLevel(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	scopeEvents := map[model.LogScope]observability.EventCode{
		model.LogControl: observability.ControlServiceStarted, model.LogTransport: observability.TransportServiceStarted,
		model.LogRouting: observability.RoutingServiceStarted, model.LogDNS: observability.DNSServiceStarted,
		model.LogTunnel: observability.TunnelServiceStarted, model.LogIngress: observability.IngressReloadStarted,
	}
	for scope, code := range scopeEvents {
		scope, code := scope, code
		t.Run(string(scope), func(t *testing.T) {
			state := loggingTestState(t, now)
			state.Logging = []model.LoggingSession{componentLoggingSession(scope, model.LogInfo, model.LogToJournald, "", now)}
			var journal bytes.Buffer
			logger := newComponentTestLogger(t, &fixedComponentLoggingState{state: state}, &journal, now, nil)
			event, _ := observability.NewEvent(code)
			if err := logger.Emit(context.Background(), event); err != nil || journal.Len() == 0 {
				t.Fatalf("Emit(%s) journal=%q err=%v", code, journal.String(), err)
			}
			journal.Reset()
			other, _ := observability.NewEvent(observability.ControlServiceStarted)
			if scope == model.LogControl {
				other, _ = observability.NewEvent(observability.DNSServiceStarted)
			}
			if err := logger.Emit(context.Background(), other); err != nil || journal.Len() != 0 {
				t.Fatalf("cross-scope journal=%q err=%v", journal.String(), err)
			}
		})
	}

	tests := []struct {
		name      string
		level     model.LogLevel
		code      observability.EventCode
		wantWrite bool
	}{
		{"error blocks info", model.LogError, observability.TransportServiceStarted, false},
		{"error admits error", model.LogError, observability.TransportRuntimeFailed, true},
		{"info admits error", model.LogInfo, observability.TransportRuntimeFailed, true},
		{"info admits info", model.LogInfo, observability.TransportServiceStarted, true},
		{"info blocks debug", model.LogInfo, observability.ControlRequestRejected, false},
		{"debug admits debug", model.LogDebug, observability.ControlRequestRejected, true},
		{"trace admits debug", model.LogTrace, observability.ControlRequestRejected, true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			scope := model.LogTransport
			if test.code == observability.ControlRequestRejected {
				scope = model.LogControl
			}
			state := loggingTestState(t, now)
			state.Logging = []model.LoggingSession{componentLoggingSession(scope, test.level, model.LogToJournald, "", now)}
			var journal bytes.Buffer
			logger := newComponentTestLogger(t, &fixedComponentLoggingState{state: state}, &journal, now, nil)
			event, _ := observability.NewEvent(test.code)
			if err := logger.Emit(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			if got := journal.Len() != 0; got != test.wantWrite {
				t.Fatalf("write=%t, want %t; record=%q", got, test.wantWrite, journal.String())
			}
		})
	}

	state := loggingTestState(t, now)
	state.Logging = []model.LoggingSession{componentLoggingSession(model.LogAll, model.LogTrace, model.LogToJournald, "", now)}
	var journal bytes.Buffer
	logger := newComponentTestLogger(t, &fixedComponentLoggingState{state: state}, &journal, now, nil)
	event, _ := observability.NewEvent(observability.IngressReloadCompleted)
	if err := logger.Emit(context.Background(), event); err != nil || journal.Len() == 0 {
		t.Fatalf("all scope journal=%q err=%v", journal.String(), err)
	}
}

func TestComponentLoggerExpiryIsExactAcrossRestart(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	expires := started.Add(15 * time.Minute)
	state := loggingTestState(t, started)
	state.Logging = []model.LoggingSession{componentLoggingSession(model.LogRouting, model.LogInfo, model.LogToJournald, "", started)}
	state.Logging[0].ExpiresAt = expires
	clock := started.Add(14*time.Minute + 59*time.Second)
	var journal bytes.Buffer
	logger := newComponentTestLoggerWithClock(t, &fixedComponentLoggingState{state: state}, &journal, func() time.Time { return clock }, nil)
	event, _ := observability.NewEvent(observability.RoutingServiceStarted)
	if err := logger.Emit(context.Background(), event); err != nil || journal.Len() == 0 {
		t.Fatalf("before expiry journal=%q err=%v", journal.String(), err)
	}
	journal.Reset()
	clock = expires
	if err := logger.Emit(context.Background(), event); err != nil || journal.Len() != 0 {
		t.Fatalf("at expiry journal=%q err=%v", journal.String(), err)
	}
	restarted := newComponentTestLoggerWithClock(t, &fixedComponentLoggingState{state: state}, &journal, func() time.Time { return expires.Add(time.Second) }, nil)
	if err := restarted.Emit(context.Background(), event); err != nil || journal.Len() != 0 {
		t.Fatalf("after restart journal=%q err=%v", journal.String(), err)
	}
}

func TestComponentLoggerUsesIdenticalCanonicalJournalAndFileRecords(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	event, _ := observability.NewEvent(observability.IngressReloadCompleted)
	event = event.WithGeneration(19)

	journalState := loggingTestState(t, now)
	journalState.Logging = []model.LoggingSession{componentLoggingSession(model.LogIngress, model.LogInfo, model.LogToJournald, "", now)}
	var journal bytes.Buffer
	journalLogger := newComponentTestLogger(t, &fixedComponentLoggingState{state: journalState}, &journal, now, nil)
	if err := journalLogger.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(t.TempDir(), "var", "log", "vpnctl", "ingress.log")
	fileState := loggingTestState(t, now)
	fileState.Logging = []model.LoggingSession{componentLoggingSession(model.LogIngress, model.LogInfo, model.LogToFile, filePath, now)}
	destination := &memoryLoggingDestination{}
	opened := ""
	fileLogger := newComponentTestLogger(t, &fixedComponentLoggingState{state: fileState}, &bytes.Buffer{}, now, func(path string) (boundedLoggingDestination, error) {
		opened = path
		return destination, nil
	})
	if err := fileLogger.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if opened != filePath || !bytes.Equal(journal.Bytes(), destination.Bytes()) {
		t.Fatalf("journal=%q file=%q opened=%q", journal.String(), destination.String(), opened)
	}
	if err := fileLogger.Close(); err != nil || !destination.closed {
		t.Fatalf("Close() = %v, closed=%t", err, destination.closed)
	}
}

func TestComponentLoggerWritesOnlyBoundedMode0600File(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	directory := filepath.Join(t.TempDir(), "var", "log", "vpnctl")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "dns.log")
	state := loggingTestState(t, now)
	state.Logging = []model.LoggingSession{componentLoggingSession(model.LogDNS, model.LogInfo, model.LogToFile, path, now)}
	logger := newComponentTestLogger(t, &fixedComponentLoggingState{state: state}, &bytes.Buffer{}, now, nil)
	event, _ := observability.NewEvent(observability.DNSServiceStarted)
	if err := logger.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() == 0 || info.Size() > LoggingFileMaxBytes {
		t.Fatalf("bounded log info=%v err=%v", info, err)
	}
}

func TestComponentLoggerSanitizesFailuresAndSerializesConcurrentWrites(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	failing, err := NewComponentLogger(componentLoggingLoadFailure{}, ComponentLoggerOptions{Now: func() time.Time { return now }, Journal: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	event, _ := observability.NewEvent(observability.TunnelServiceStarted)
	if err := failing.Emit(context.Background(), event); err == nil || strings.Contains(err.Error(), componentLoggingCanary) {
		t.Fatalf("state failure = %v", err)
	}

	state := loggingTestState(t, now)
	state.Logging = []model.LoggingSession{componentLoggingSession(model.LogTunnel, model.LogInfo, model.LogToJournald, "", now)}
	journal := &lockedBuffer{}
	logger := newComponentTestLogger(t, &fixedComponentLoggingState{state: state}, journal, now, nil)
	const writers = 32
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if emitErr := logger.Emit(context.Background(), event); emitErr != nil {
				t.Errorf("Emit: %v", emitErr)
			}
		}()
	}
	wait.Wait()
	if lines := bytes.Count(journal.Bytes(), []byte{'\n'}); lines != writers || strings.Contains(journal.String(), componentLoggingCanary) {
		t.Fatalf("lines=%d record=%q", lines, journal.String())
	}
}

func componentLoggingSession(scope model.LogScope, level model.LogLevel, destination model.LogDestination, path string, now time.Time) model.LoggingSession {
	return model.LoggingSession{
		SchemaVersion: model.ResourceSchemaVersion, ID: "11111111-1111-4111-8111-111111111111",
		Scope: scope, Level: level, Destination: destination, FilePath: path, State: model.LogActive,
		StartedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func newComponentTestLogger(t *testing.T, state LoggingStateStore, journal interface{ Write([]byte) (int, error) }, now time.Time, opener func(string) (boundedLoggingDestination, error)) *ComponentLogger {
	t.Helper()
	return newComponentTestLoggerWithClock(t, state, journal, func() time.Time { return now }, opener)
}

func newComponentTestLoggerWithClock(t *testing.T, state LoggingStateStore, journal interface{ Write([]byte) (int, error) }, now func() time.Time, opener func(string) (boundedLoggingDestination, error)) *ComponentLogger {
	t.Helper()
	logger, err := NewComponentLogger(state, ComponentLoggerOptions{Now: now, Journal: journal, OpenFile: opener})
	if err != nil {
		t.Fatal(err)
	}
	return logger
}

type fixedComponentLoggingState struct {
	mu    sync.Mutex
	state model.State
	loads int
}

func (state *fixedComponentLoggingState) Load() (model.State, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.loads++
	return state.state, nil
}

func (*fixedComponentLoggingState) Save(uint64, model.State) error {
	return errors.New("read-only test state")
}

type componentLoggingLoadFailure struct{}

func (componentLoggingLoadFailure) Load() (model.State, error) {
	return model.State{}, errors.New(componentLoggingCanary)
}

func (componentLoggingLoadFailure) Save(uint64, model.State) error {
	return errors.New(componentLoggingCanary)
}

type memoryLoggingDestination struct {
	bytes.Buffer
	closed bool
}

func (destination *memoryLoggingDestination) Close() error {
	destination.closed = true
	return nil
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (buffer *lockedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.Write(value)
}

func (buffer *lockedBuffer) Bytes() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return append([]byte(nil), buffer.Buffer.Bytes()...)
}

func (buffer *lockedBuffer) String() string {
	return string(buffer.Bytes())
}
