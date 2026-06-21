package wireguard

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

const (
	testPrivateKey   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	testPublicKey    = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	testPresharedKey = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
)

type fakeRunner struct {
	calls []fakeCall
	err   error
}

type fakeCall struct {
	name  string
	args  []string
	stdin string
}

func (r *fakeRunner) Run(_ context.Context, name string, args []string, stdin string) (string, error) {
	r.calls = append(r.calls, fakeCall{name: name, args: append([]string(nil), args...), stdin: stdin})
	if r.err != nil {
		return "", r.err
	}
	switch {
	case name == "wg" && reflect.DeepEqual(args, []string{"genkey"}):
		return testPrivateKey + "\n", nil
	case name == "wg" && reflect.DeepEqual(args, []string{"pubkey"}):
		return testPublicKey + "\n", nil
	case name == "wg" && reflect.DeepEqual(args, []string{"genpsk"}):
		return testPresharedKey + "\n", nil
	default:
		return "", errors.New("unexpected command")
	}
}

func TestGenerateKeyPairUsesWGCommands(t *testing.T) {
	runner := &fakeRunner{}

	got, err := GenerateKeyPair(context.Background(), runner)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	if got.PrivateKey != testPrivateKey {
		t.Fatalf("unexpected private key")
	}
	if got.PublicKey != testPublicKey {
		t.Fatalf("unexpected public key: %q", got.PublicKey)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected two wg calls, got %#v", runner.calls)
	}
	if !reflect.DeepEqual(runner.calls[0].args, []string{"genkey"}) {
		t.Fatalf("unexpected first call: %#v", runner.calls[0])
	}
	if !reflect.DeepEqual(runner.calls[1].args, []string{"pubkey"}) {
		t.Fatalf("unexpected second call: %#v", runner.calls[1])
	}
	if runner.calls[1].stdin != testPrivateKey+"\n" {
		t.Fatalf("expected private key to be provided on stdin")
	}
}

func TestGeneratePresharedKey(t *testing.T) {
	got, err := GeneratePresharedKey(context.Background(), &fakeRunner{})
	if err != nil {
		t.Fatalf("generate preshared key: %v", err)
	}
	if got != testPresharedKey {
		t.Fatalf("unexpected preshared key")
	}
}

func TestValidateKey(t *testing.T) {
	if err := ValidateKey(testPrivateKey); err != nil {
		t.Fatalf("expected valid key: %v", err)
	}
	if err := ValidateKey("not-a-key"); err == nil {
		t.Fatalf("expected invalid key error")
	}
	if err := ValidateKey("AQE="); err == nil {
		t.Fatalf("expected short key error")
	}
}
