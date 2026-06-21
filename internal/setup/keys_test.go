package setup

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeWGRunner struct {
	calls []struct {
		args  []string
		stdin string
	}
}

func (r *fakeWGRunner) Run(_ context.Context, _ string, args []string, stdin string) (string, error) {
	r.calls = append(r.calls, struct {
		args  []string
		stdin string
	}{args: append([]string(nil), args...), stdin: stdin})
	if reflect.DeepEqual(args, []string{"genkey"}) {
		return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", nil
	}
	if reflect.DeepEqual(args, []string{"pubkey"}) {
		return "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n", nil
	}
	return "", errors.New("unexpected wg args")
}

func TestServerKeyGeneratorUsesWireGuardRunner(t *testing.T) {
	runner := &fakeWGRunner{}
	generator := ServerKeyGenerator{Runner: runner}

	got, err := generator.GenerateServerKeyPair(context.Background())
	if err != nil {
		t.Fatalf("generate server key pair: %v", err)
	}
	if got.PrivateKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Fatalf("unexpected private key")
	}
	if got.PublicKey != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" {
		t.Fatalf("unexpected public key")
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected two wg calls, got %#v", runner.calls)
	}
}
