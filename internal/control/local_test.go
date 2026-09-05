package control

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCallLocalMutationCancellationInterruptsAcceptedRequest(t *testing.T) {
	t.Parallel()

	directory, err := os.MkdirTemp("/tmp", "vpnctl-local-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socketPath := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	release := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = io.ReadAll(connection)
		close(accepted)
		<-release
	}()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, callErr := CallLocalMutation(ctx, socketPath, LocalRequest{
			SchemaVersion: LocalSchemaVersion, Method: LocalMutate, Operation: "repair.gateway",
		})
		result <- callErr
	}()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("local mutation was not accepted")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled local mutation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled local mutation remained blocked")
	}
}
