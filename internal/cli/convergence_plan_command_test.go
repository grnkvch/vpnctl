package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestPlanCommandRoutesGlobalJSONThroughPublicPlanner(t *testing.T) {
	oldPaths, oldRole, oldBuild, oldRun := planSystemPaths, planLoadRole, planBuild, planRun
	t.Cleanup(func() { planSystemPaths, planLoadRole, planBuild, planRun = oldPaths, oldRole, oldBuild, oldRun })
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	planSystemPaths = func() store.Paths { return paths }
	planLoadRole = func(received store.Paths) (HostRole, error) {
		if received != paths {
			t.Fatalf("role paths = %+v", received)
		}
		return RoleNode, nil
	}
	built := false
	planBuild = func(received store.Paths) (*operations.ConvergencePlanner, error) {
		built = true
		if received != paths {
			t.Fatalf("build paths = %+v", received)
		}
		return &operations.ConvergencePlanner{}, nil
	}
	run := false
	planRun = func(ctx context.Context, role HostRole, planner ConvergencePlanReader) (output.Result, error) {
		run = true
		if ctx == nil || role != RoleNode || planner == nil {
			t.Fatalf("run = ctx:%v role:%s planner:%v", ctx, role, planner)
		}
		return ConvergencePlanOutput(operations.ConvergencePlan{
			DesiredGeneration: 3, AppliedGeneration: 3, Impact: operations.ConvergenceImpactNone,
			Changes: []operations.DesiredChange{}, Drift: []operations.OwnedDrift{},
		})
	}

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"--json", "plan"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !built || !run || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"command":"plan"`) || !strings.Contains(stdout.String(), `"changes":[]`) {
		t.Fatalf("built=%t run=%t stdout=%s stderr=%s", built, run, stdout.String(), stderr.String())
	}
}

func TestPlanCommandClassifiesMissingAndInvalidSnapshots(t *testing.T) {
	oldPaths, oldRole := planSystemPaths, planLoadRole
	t.Cleanup(func() { planSystemPaths, planLoadRole = oldPaths, oldRole })
	planLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, store.Paths)
		exit    int
		code    string
	}{
		{name: "missing", prepare: func(*testing.T, store.Paths) {}, exit: ExitUnavailable, code: "convergence_snapshot_unavailable"},
		{name: "invalid", prepare: func(t *testing.T, paths store.Paths) {
			if err := os.MkdirAll(filepath.Dir(paths.ConvergenceFile), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(paths.ConvergenceFile, []byte(`{"invalid":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, exit: ExitValidation, code: "invalid_convergence_state"},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths, err := store.NewPaths(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			test.prepare(t, paths)
			planSystemPaths = func() store.Paths { return paths }
			var stdout, stderr bytes.Buffer
			if exit := Execute([]string{"plan", "--json"}, &stdout, &stderr); exit != test.exit {
				t.Fatalf("exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
			}
			if stderr.Len() != 0 || !strings.Contains(stdout.String(), `"code":"`+test.code+`"`) || !strings.Contains(stdout.String(), `"drift":[]`) {
				t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
		})
	}
}

func TestPlanCommandRejectsArgumentsBeforeHostReads(t *testing.T) {
	oldPaths := planSystemPaths
	t.Cleanup(func() { planSystemPaths = oldPaths })
	planSystemPaths = func() store.Paths {
		t.Fatal("invalid plan arguments reached host paths")
		return store.Paths{}
	}
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"--json", "plan", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"code":"invalid_arguments"`) || stderr.Len() != 0 {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestClassifyPlanCommandErrorKeepsStableCategories(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err      error
		category output.ExitCategory
		code     string
	}{
		{err: operations.ErrConvergencePlanInvalid, category: output.CategoryValidation, code: "invalid_convergence_state"},
		{err: operations.ErrConvergenceSnapshotUnavailable, category: output.CategoryUnavailable, code: "convergence_snapshot_unavailable"},
		{err: operations.ErrOwnedResourceDiscoveryUnsupported, category: output.CategoryUnavailable, code: "owned_discovery_unsupported"},
		{err: context.Canceled, category: output.CategoryUnavailable, code: "plan_cancelled"},
		{err: errors.New("failure"), category: output.CategoryUnavailable, code: "owned_discovery_unavailable"},
	} {
		category, code, _ := classifyPlanCommandError(test.err)
		if category != test.category || code != test.code {
			t.Fatalf("classify(%v)=%s/%s", test.err, category, code)
		}
	}
}
