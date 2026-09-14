package controller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGatewayMutationLockSerializesCLIAndControllerProcesses(t *testing.T) {
	runtimeDirectory := filepath.Join(t.TempDir(), "run", "vpnctl")
	if err := os.MkdirAll(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := AcquireGatewayMutationLock(context.Background(), runtimeDirectory, false)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			first()
		}
	}()
	if _, err := AcquireGatewayMutationLock(context.Background(), runtimeDirectory, false); !errors.Is(err, ErrGatewayMutationBusy) {
		t.Fatalf("non-waiting lock error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := AcquireGatewayMutationLock(ctx, runtimeDirectory, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting lock error = %v", err)
	}
	first()
	released = true
	second, err := AcquireGatewayMutationLock(context.Background(), runtimeDirectory, false)
	if err != nil {
		t.Fatalf("lock after release = %v", err)
	}
	second()
}

func TestGatewayMutationLockRejectsForeignResourceWithoutAdoption(t *testing.T) {
	for _, test := range []struct {
		name string
		make func(string) error
	}{
		{name: "symlink", make: func(path string) error { return os.Symlink("foreign", path) }},
		{name: "unsafe mode", make: func(path string) error { return os.WriteFile(path, []byte("foreign"), 0o644) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtimeDirectory := filepath.Join(t.TempDir(), "run", "vpnctl")
			if err := os.MkdirAll(runtimeDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(runtimeDirectory, gatewayMutationLockName)
			if err := test.make(path); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(path)
			if _, err := AcquireGatewayMutationLock(context.Background(), runtimeDirectory, false); err == nil {
				t.Fatal("foreign mutation lock was accepted")
			}
			after, err := os.Lstat(path)
			if err != nil || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatalf("foreign resource changed: before=%v after=%v err=%v", before, after, err)
			}
		})
	}
}
