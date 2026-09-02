package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestJSONEmitterSeparatesProgressAndEmitsOnce(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	emitter, err := NewResultEmitter(&stdout, &stderr, true)
	if err != nil {
		t.Fatalf("NewResultEmitter() error = %v", err)
	}
	if err := emitter.Progress("validating candidate"); err != nil {
		t.Fatalf("Progress() error = %v", err)
	}
	if err := emitter.Progress("candidate rejected"); err != nil {
		t.Fatalf("Progress() error = %v", err)
	}
	result := output.NewResult("policy.set", output.StatusFailed, output.CategoryValidation, output.SafeObject{"changed": false})
	code, err := emitter.Emit(result)
	if err != nil || code != ExitValidation {
		t.Fatalf("Emit() = %d, %v", code, err)
	}
	if got := stderr.String(); got != "validating candidate\ncandidate rejected\n" {
		t.Fatalf("stderr = %q", got)
	}
	if strings.Contains(stdout.String(), "validating") || strings.Contains(stdout.String(), "rejected") {
		t.Fatalf("stdout contains progress: %q", stdout.String())
	}

	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	var decoded output.Result
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode JSON stdout: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("JSON stdout has a second document: %v", err)
	}
	before := stdout.String()
	if code, err := emitter.Emit(result); code != ExitInternal || !errors.Is(err, ErrResultAlreadyEmitted) {
		t.Fatalf("second Emit() = %d, %v", code, err)
	}
	if err := emitter.Progress("too late"); !errors.Is(err, ErrResultAlreadyEmitted) {
		t.Fatalf("late Progress() error = %v", err)
	}
	if stdout.String() != before {
		t.Fatal("second Emit() changed stdout")
	}
}

func TestEmitterMapsEveryOutputCategoryToFrozenExitCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   output.Status
		category output.ExitCategory
		want     int
	}{
		{status: output.StatusOK, category: output.CategorySuccess, want: ExitSuccess},
		{status: output.StatusFailed, category: output.CategoryValidation, want: ExitValidation},
		{status: output.StatusFailed, category: output.CategoryConflict, want: ExitConflict},
		{status: output.StatusDegraded, category: output.CategoryUnavailable, want: ExitUnavailable},
		{status: output.StatusFailed, category: output.CategoryInternal, want: ExitInternal},
	}
	for _, test := range tests {
		t.Run(string(test.category), func(t *testing.T) {
			var stdout bytes.Buffer
			emitter, err := NewResultEmitter(&stdout, io.Discard, true)
			if err != nil {
				t.Fatalf("NewResultEmitter() error = %v", err)
			}
			result := output.NewResult("validate", test.status, test.category, output.SafeObject{"valid": test.status == output.StatusOK})
			got, err := emitter.Emit(result)
			if err != nil || got != test.want {
				t.Fatalf("Emit() = %d, %v; want %d", got, err, test.want)
			}
		})
	}
}

func TestHumanEmitterUsesSameResultAndExitContract(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	emitter, err := NewResultEmitter(&stdout, &stderr, false)
	if err != nil {
		t.Fatalf("NewResultEmitter() error = %v", err)
	}
	result := output.NewResult("status", output.StatusDegraded, output.CategoryUnavailable, output.SafeObject{
		"role": "node", "overall": "degraded", "generation": 9,
	})
	code, err := emitter.Emit(result)
	if err != nil || code != ExitUnavailable {
		t.Fatalf("Emit() = %d, %v", code, err)
	}
	if !strings.HasPrefix(stdout.String(), "DEGRADED status\n") || stderr.Len() != 0 {
		t.Fatalf("human streams stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
