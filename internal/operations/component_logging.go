package operations

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/observability"
)

type boundedLoggingDestination interface {
	io.Writer
	io.Closer
}

type ComponentLoggerOptions struct {
	Now      func() time.Time
	Journal  io.Writer
	OpenFile func(string) (boundedLoggingDestination, error)
}

// ComponentLogger is the single formatter/destination boundary for expanded
// vpnctl logs. The event is a closed typed value before policy lookup, and the
// exact same canonical record bytes go to journald or a bounded local file.
type ComponentLogger struct {
	state LoggingStateStore
	now   func() time.Time

	mu       sync.Mutex
	journal  io.Writer
	openFile func(string) (boundedLoggingDestination, error)
	files    map[string]boundedLoggingDestination
}

func NewComponentLogger(state LoggingStateStore, options ComponentLoggerOptions) (*ComponentLogger, error) {
	if state == nil || options.Journal == nil {
		return nil, fmt.Errorf("component logging dependencies are incomplete")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.OpenFile == nil {
		options.OpenFile = func(path string) (boundedLoggingDestination, error) {
			return OpenBoundedLoggingFile(path)
		}
	}
	return &ComponentLogger{
		state: state, now: options.Now, journal: options.Journal, openFile: options.OpenFile,
		files: make(map[string]boundedLoggingDestination),
	}, nil
}

func (logger *ComponentLogger) Emit(ctx context.Context, event observability.Event) error {
	if ctx == nil {
		return fmt.Errorf("component logging context is required")
	}
	if logger == nil || logger.state == nil || logger.now == nil || logger.journal == nil || logger.openFile == nil {
		return fmt.Errorf("component logger is incomplete")
	}
	descriptor, err := observability.Describe(event)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := logger.state.Load()
	if err != nil {
		return fmt.Errorf("authoritative logging policy is unavailable")
	}
	now := normalizedLoggingTime(logger.now())
	policy, err := EffectiveLoggingPolicy(state, now)
	if err != nil {
		return fmt.Errorf("authoritative logging policy is invalid")
	}
	session, enabled := selectedLoggingSession(policy, descriptor)
	if !enabled {
		return nil
	}
	record, err := observability.EncodeRecord(event, now)
	if err != nil {
		return err
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	switch session.Destination {
	case model.LogToJournald:
		if err := writeCompleteLoggingRecord(logger.journal, record); err != nil {
			return fmt.Errorf("write journald operational event")
		}
	case model.LogToFile:
		destination := logger.files[session.FilePath]
		if destination == nil {
			destination, err = logger.openFile(session.FilePath)
			if err != nil {
				return fmt.Errorf("open bounded operational log destination")
			}
			logger.files[session.FilePath] = destination
		}
		if err := writeCompleteLoggingRecord(destination, record); err != nil {
			return fmt.Errorf("write bounded operational event")
		}
	default:
		return fmt.Errorf("unsupported operational log destination")
	}
	return nil
}

func (logger *ComponentLogger) Close() error {
	if logger == nil {
		return nil
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	var first error
	for path, destination := range logger.files {
		if err := destination.Close(); err != nil && first == nil {
			first = fmt.Errorf("close bounded operational log destination")
		}
		delete(logger.files, path)
	}
	return first
}

func selectedLoggingSession(policy LoggingRuntimePolicy, event observability.Descriptor) (LoggingRuntimeSession, bool) {
	for _, session := range policy.Active {
		if session.Scope != model.LogAll && session.Scope != event.Scope {
			continue
		}
		if loggingLevelRank(event.Level) <= loggingLevelRank(session.Level) {
			return session, true
		}
	}
	return LoggingRuntimeSession{}, false
}

func loggingLevelRank(level model.LogLevel) int {
	switch level {
	case model.LogError:
		return 0
	case model.LogInfo:
		return 1
	case model.LogDebug:
		return 2
	case model.LogTrace:
		return 3
	default:
		return -1
	}
}

func writeCompleteLoggingRecord(destination io.Writer, record []byte) error {
	written, err := destination.Write(record)
	if err != nil {
		return err
	}
	if written != len(record) {
		return io.ErrShortWrite
	}
	return nil
}

var _ observability.Emitter = (*ComponentLogger)(nil)
