package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const cliPolicyNodeID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

type cliPolicyStore struct{ state model.State }

func (store *cliPolicyStore) Load() (model.State, error) { return store.state, nil }
func (store *cliPolicyStore) Save(_ uint64, candidate model.State) error {
	store.state = candidate
	return nil
}

type cliPolicyRemote struct {
	plan        operations.RemotePolicyPlan
	commit      routing.PolicyCommitResult
	planCalls   int
	commitCalls int
}

func (remote *cliPolicyRemote) Plan(_ context.Context, command routing.PolicyCommand, presets []string, deferred bool) (operations.RemotePolicyPlan, error) {
	remote.planCalls++
	result := remote.plan
	result.Command, result.PresetNames, result.Deferred = command, append([]string{}, presets...), deferred
	return result, nil
}

func (remote *cliPolicyRemote) Commit(context.Context, operations.RemotePolicyPlan) (routing.PolicyCommitResult, error) {
	remote.commitCalls++
	return remote.commit, nil
}

func TestExecutePolicyNodeDryRunAndDeferUseGatewayAuthoritativeRPC(t *testing.T) {
	oldPaths, oldRole, oldStore, oldRemote := policySystemPaths, policyLoadRole, policyNewStore, policyBuildRemote
	t.Cleanup(func() {
		policySystemPaths, policyLoadRole, policyNewStore, policyBuildRemote = oldPaths, oldRole, oldStore, oldRemote
	})
	paths, _ := store.NewPaths(t.TempDir())
	stateStore := &cliPolicyStore{}
	desired := routing.DesiredPolicy{
		TargetKind: model.TargetNode, TargetID: cliPolicyNodeID, PresetNames: []string{"telegram"},
		Selectors:     []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}},
		EffectiveHash: strings.Repeat("a", 64), GatewayPolicyGeneration: 1, GatewayStateGeneration: 2,
	}
	remote := &cliPolicyRemote{
		plan: operations.RemotePolicyPlan{
			TargetID: cliPolicyNodeID, TargetName: "private-node", PreviousPresetNames: []string{},
			ExpectedStateGeneration: 1, NextStateGeneration: 2, Changed: true, Desired: desired,
		},
		commit: routing.PolicyCommitResult{
			Command: routing.PolicySet, Changed: true, Pending: true,
			OperationID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", StateGeneration: 2, Desired: desired,
		},
	}
	policySystemPaths = func() store.Paths { return paths }
	policyLoadRole = func(store.Paths) (HostRole, error) { return RoleNode, nil }
	policyNewStore = func(store.Paths) (policyStateStore, error) { return stateStore, nil }
	policyBuildRemote = func(store.Paths) (nodePolicyGateway, error) { return remote, nil }

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"policy", "set", "telegram", "--dry-run", "--json"}, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("dry-run exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"command":"policy.set"`) || !strings.Contains(stdout.String(), `"changed":true`) || remote.planCalls != 1 || remote.commitCalls != 0 {
		t.Fatalf("dry-run output/calls = %q %d/%d", stdout.String(), remote.planCalls, remote.commitCalls)
	}

	stdout.Reset()
	if code := Execute([]string{"--json", "policy", "set", "telegram", "--defer"}, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("defer exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"pending"`) || !strings.Contains(stdout.String(), `"operation_id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd"`) || remote.planCalls != 2 || remote.commitCalls != 1 {
		t.Fatalf("defer output/calls = %q %d/%d", stdout.String(), remote.planCalls, remote.commitCalls)
	}
}

func TestExecutePolicyEnforcesRoleSpecificTargetBeforeConstructingServices(t *testing.T) {
	oldPaths, oldRole, oldStore, oldRemote := policySystemPaths, policyLoadRole, policyNewStore, policyBuildRemote
	t.Cleanup(func() {
		policySystemPaths, policyLoadRole, policyNewStore, policyBuildRemote = oldPaths, oldRole, oldStore, oldRemote
	})
	paths, _ := store.NewPaths(t.TempDir())
	policySystemPaths = func() store.Paths { return paths }
	policyNewStore = func(store.Paths) (policyStateStore, error) {
		t.Fatal("policy store constructed before role/target rejection")
		return nil, nil
	}
	policyBuildRemote = func(store.Paths) (nodePolicyGateway, error) {
		t.Fatal("policy RPC constructed before role/target rejection")
		return nil, nil
	}

	for _, test := range []struct {
		role HostRole
		args []string
	}{
		{RoleGateway, []string{"policy", "show", "--json"}},
		{RoleNode, []string{"policy", "clear", "--client", "phone", "--json"}},
	} {
		policyLoadRole = func(store.Paths) (HostRole, error) { return test.role, nil }
		var stdout, stderr bytes.Buffer
		if code := Execute(test.args, &stdout, &stderr); code != ExitValidation || !strings.Contains(stdout.String(), `"code":"invalid_target"`) {
			t.Fatalf("Execute(%v, %s) exit/output=%d %q stderr=%q", test.args, test.role, code, stdout.String(), stderr.String())
		}
	}
}

func TestPolicyShowOutputIsSecretFreeAndCarriesClassificationBoundary(t *testing.T) {
	result := policyShowOutput(routing.PolicyView{
		TargetKind: model.TargetClient, TargetID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", TargetName: "phone",
		PresetNames: []string{"telegram"}, Selectors: []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}},
		EffectiveHash: strings.Repeat("b", 64), PolicyGeneration: 3, StateGeneration: 7,
	})
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if result.ResourceIDs["client_id"] == "" || len(result.Warnings) != 1 || result.Data["resource"] == nil {
		t.Fatalf("policy show result = %+v", result)
	}
	content, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(content)
	for _, forbidden := range []string{"credential_ref", "private_key", "secret"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("policy show leaked %q: %s", forbidden, encoded)
		}
	}
}
