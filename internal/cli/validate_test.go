package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type validationMemoryStore struct {
	state model.State
	err   error
}

func (memory validationMemoryStore) Load() (model.State, error) {
	return memory.state, memory.err
}

func TestExecuteValidateReadsStrictStateAndEmitsValidationContract(t *testing.T) {
	oldPaths, oldRole, oldStore := validateSystemPaths, validateLoadRole, validateNewStore
	t.Cleanup(func() { validateSystemPaths, validateLoadRole, validateNewStore = oldPaths, oldRole, oldStore })
	paths, _ := store.NewPaths(t.TempDir())
	validateSystemPaths = func() store.Paths { return paths }
	validateLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	validateNewStore = func(store.Paths) (validationStateStore, error) {
		return validationMemoryStore{state: cliDNSState(model.RoleGateway)}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"--json", "validate"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("Execute(validate) code = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, `"command":"validate"`) || !strings.Contains(got, `"valid":true`) || !strings.Contains(got, `"issues":[]`) {
		t.Fatalf("unexpected validation result: %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestExecuteValidateReportsInvalidStateWithoutLeakingDecoderDetail(t *testing.T) {
	oldPaths, oldRole, oldStore := validateSystemPaths, validateLoadRole, validateNewStore
	t.Cleanup(func() { validateSystemPaths, validateLoadRole, validateNewStore = oldPaths, oldRole, oldStore })
	paths, _ := store.NewPaths(t.TempDir())
	validateSystemPaths = func() store.Paths { return paths }
	validateLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	validateNewStore = func(store.Paths) (validationStateStore, error) {
		return validationMemoryStore{err: errors.New("secret decoder canary")}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"validate", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("Execute(validate invalid) code = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, `"valid":false`) || !strings.Contains(got, `"code":"state_invalid"`) || strings.Contains(got, "secret decoder canary") {
		t.Fatalf("unexpected invalid-state result: %q", got)
	}
}

func TestValidateArgumentsRejectUnlistedOptions(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"--json", "validate", "--dry-run"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("Execute(validate --dry-run) code = %d", code)
	}
	if !strings.Contains(stdout.String(), `"code":"invalid_arguments"`) {
		t.Fatalf("missing argument failure: %q", stdout.String())
	}
}
