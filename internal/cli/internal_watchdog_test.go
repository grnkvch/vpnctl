package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestInternalWatchdogRollbackModeIsHiddenAndStrict(t *testing.T) {
	previous := runInternalWatchdogRollback
	t.Cleanup(func() { runInternalWatchdogRollback = previous })

	called := ""
	runInternalWatchdogRollback = func(_ context.Context, id string) error {
		called = id
		return nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	id := "12345678-1234-4234-8234-123456789abc"
	if code := Execute([]string{"__watchdog-rollback", id}, &stdout, &stderr); code != 0 {
		t.Fatalf("Execute(internal) code = %d, stderr = %q", code, stderr.String())
	}
	if called != id || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("internal dispatch called=%q stdout=%q stderr=%q", called, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("Execute(help) code = %d", code)
	}
	if strings.Contains(stdout.String(), "__watchdog") {
		t.Fatal("private watchdog service mode appeared in public help")
	}

	stderr.Reset()
	if code := Execute([]string{"__watchdog-rollback"}, &stdout, &stderr); code != 2 {
		t.Fatalf("Execute(missing ID) code = %d", code)
	}
	runInternalWatchdogRollback = func(context.Context, string) error { return errors.New("injected") }
	stderr.Reset()
	if code := Execute([]string{"__watchdog-rollback", id}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "injected") {
		t.Fatalf("Execute(failure) code = %d, stderr = %q", code, stderr.String())
	}
}
