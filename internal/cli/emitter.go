package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/output"
)

var ErrResultAlreadyEmitted = errors.New("command result already emitted")

type ResultEmitter struct {
	stdout   io.Writer
	stderr   io.Writer
	jsonMode bool

	mu      sync.Mutex
	emitted bool
}

func NewResultEmitter(stdout, stderr io.Writer, jsonMode bool) (*ResultEmitter, error) {
	if stdout == nil || stderr == nil {
		return nil, fmt.Errorf("stdout and stderr writers are required")
	}
	return &ResultEmitter{stdout: stdout, stderr: stderr, jsonMode: jsonMode}, nil
}

// Progress always writes to stderr. It is rejected after the final result so
// stdout remains the sole automation stream and the result stays the last event.
func (emitter *ResultEmitter) Progress(message string) error {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	if emitter.emitted {
		return ErrResultAlreadyEmitted
	}
	if message == "" || strings.TrimSpace(message) != message || strings.ContainsAny(message, "\x00\r\n") {
		return fmt.Errorf("progress message must be a non-empty trimmed single line")
	}
	if _, err := fmt.Fprintln(emitter.stderr, message); err != nil {
		return fmt.Errorf("write progress: %w", err)
	}
	return nil
}

// Emit writes one final result and returns its frozen process exit code.
func (emitter *ResultEmitter) Emit(result output.Result) (int, error) {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	if emitter.emitted {
		return ExitInternal, ErrResultAlreadyEmitted
	}

	var rendered bytes.Buffer
	var err error
	if emitter.jsonMode {
		err = output.RenderJSON(&rendered, result)
	} else {
		err = output.RenderHuman(&rendered, result)
	}
	if err != nil {
		return ExitInternal, err
	}
	emitter.emitted = true
	if _, err := emitter.stdout.Write(rendered.Bytes()); err != nil {
		return ExitInternal, fmt.Errorf("write command result: %w", err)
	}
	return ExitCode(ResultCategory(result.ExitCategory)), nil
}
