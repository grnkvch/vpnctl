package regression

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2FailureE2EAcceptsExactCanonicalDependencies(t *testing.T) {
	repository, fakeBin, tunnelResult, tunnelSHA, ingressResult, ingressSHA := newFailureDependencyFixture(t)
	command := exec.Command(filepath.Join(repository, "scripts", "v2failure-e2e.sh"),
		"verify-dependencies", tunnelResult, tunnelSHA, ingressResult, ingressSHA)
	command.Dir = repository
	command.Env = append(os.Environ(), "PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "dependency-bound ingress and tunnel failure E2E evidence") {
		t.Fatalf("verify-dependencies: %v: %s", err, output)
	}
}

func TestV2FailureE2ERejectsTamperedDependencyHash(t *testing.T) {
	repository, fakeBin, tunnelResult, _, ingressResult, ingressSHA := newFailureDependencyFixture(t)
	command := exec.Command(filepath.Join(repository, "scripts", "v2failure-e2e.sh"),
		"verify-dependencies", tunnelResult, strings.Repeat("0", 64), ingressResult, ingressSHA)
	command.Dir = repository
	command.Env = append(os.Environ(), "PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	exitError, ok := err.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 3 || !strings.Contains(string(output), "result hash mismatch") {
		t.Fatalf("tampered dependency: %v: %s", err, output)
	}
}

func TestV2FailureE2EStandaloneModeRetainsProviderCoverage(t *testing.T) {
	t.Parallel()
	script := readContractFile(t, filepath.Join("..", "..", "scripts", "v2failure-e2e.sh"))
	for _, required := range []string{
		`env -u VPNCTL_V2_TIMING_OUTPUT "$repository_root/scripts/v2tunnel-release-gate.sh" run`,
		`env -u VPNCTL_V2_TIMING_OUTPUT "$repository_root/scripts/v2ingress-release-gate.sh" run`,
		`verify) [ "$#" -eq 1 ]`, `verify-dependencies) [ "$#" -eq 5 ]`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("failure harness is missing %q", required)
		}
	}
}

func TestV2FailureE2ERejectsInvalidCanonicalDependencyShapes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string) string
	}{
		{name: "missing", mutate: func(t *testing.T, path string) string {
			directory := filepath.Dir(path)
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			return strings.Repeat("0", 64)
		}},
		{name: "failed", mutate: mutateFailureDependencyField("status", "failed", 0o400)},
		{name: "malformed", mutate: func(t *testing.T, path string) string {
			directory := filepath.Dir(path)
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("{\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, 0o500); err != nil {
				t.Fatal(err)
			}
			return fileSHA256(t, path)
		}},
		{name: "cross-commit", mutate: mutateFailureDependencyField("source_commit", strings.Repeat("0", 40), 0o400)},
		{name: "wrong-version", mutate: mutateFailureDependencyField("release_version", "v9.9.9", 0o400)},
		{name: "wrong-image", mutate: mutateFailureDependencyField("lima_image_digest", "sha256:"+strings.Repeat("0", 64), 0o400)},
		{name: "wrong-mode", mutate: mutateFailureDependencyField("status", "passed", 0o600)},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, fakeBin, tunnelResult, _, ingressResult, ingressSHA := newFailureDependencyFixture(t)
			tunnelSHA := test.mutate(t, tunnelResult)
			command := exec.Command(filepath.Join(repository, "scripts", "v2failure-e2e.sh"),
				"verify-dependencies", tunnelResult, tunnelSHA, ingressResult, ingressSHA)
			command.Dir = repository
			command.Env = append(os.Environ(), "PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
			output, err := command.CombinedOutput()
			exitError, ok := err.(*exec.ExitError)
			if !ok || exitError.ExitCode() != 3 {
				t.Fatalf("invalid dependency accepted: %v: %s", err, output)
			}
		})
	}
}

func mutateFailureDependencyField(field string, value any, mode os.FileMode) func(*testing.T, string) string {
	return func(t *testing.T, path string) string {
		t.Helper()
		directory := filepath.Dir(path)
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		result := readJSONObject(t, path)
		result[field] = value
		writeJSONObject(t, path, result, mode)
		if err := os.Chmod(directory, 0o500); err != nil {
			t.Fatal(err)
		}
		return fileSHA256(t, path)
	}
}

func newFailureDependencyFixture(t *testing.T) (repository, fakeBin, tunnelResult, tunnelSHA, ingressResult, ingressSHA string) {
	t.Helper()
	temporary := t.TempDir()
	repository = filepath.Join(temporary, "repo")
	t.Cleanup(func() {
		_ = filepath.Walk(repository, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				_ = os.Chmod(path, 0o700)
			} else {
				_ = os.Chmod(path, 0o600)
			}
			return nil
		})
	})
	fakeBin = filepath.Join(repository, "fake-bin")
	if err := os.MkdirAll(filepath.Join(repository, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	copyTestFile(t, filepath.Join("..", "..", "scripts", "v2failure-e2e.sh"), filepath.Join(repository, "scripts", "v2failure-e2e.sh"), 0o755)
	copyTestFile(t, filepath.Join("..", "..", "scripts", "lib", "v2-stage-timing.sh"), filepath.Join(repository, "scripts", "lib", "v2-stage-timing.sh"), 0o644)
	writeTestFile(t, filepath.Join(repository, ".gitignore"), "artifacts/\n", 0o644)
	writeTestFile(t, filepath.Join(fakeBin, "go"), failureDependencyFakeGo(), 0o755)
	runGit := func(arguments ...string) {
		command := exec.Command("git", arguments...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}
	runGit("init", "-q")
	runGit("config", "user.email", "failure-test@example.invalid")
	runGit("config", "user.name", "Failure Test")
	runGit("add", ".")
	runGit("commit", "-q", "-m", "fixture")
	commitOutput := exec.Command("git", "rev-parse", "HEAD")
	commitOutput.Dir = repository
	commitBytes, err := commitOutput.Output()
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.TrimSpace(string(commitBytes))

	tunnelSummary := filepath.Join(repository, "artifacts", "v2lab", "tunnel-release-gate", "canonical", "summary.json")
	ingressSummary := filepath.Join(repository, "artifacts", "v2lab", "ingress-release-gate", "canonical", "summary.json")
	writeJSONAny(t, tunnelSummary, map[string]any{
		"production_native": map[string]any{"status": "passed"},
		"spike_regression": map[string]any{
			"lifecycle":       map[string]any{"reconnect_without_frpc_restart": true},
			"authorization":   map[string]any{"controller_unavailable_rejected": true, "revoke_reconnect_rejected": true},
			"dynamic_mapping": map[string]any{"remove_without_restart": true},
		},
	}, 0o600)
	writeJSONAny(t, ingressSummary, map[string]any{
		"production_native": map[string]any{"status": "passed", "unknown_status": 404, "body_limit_status": 413, "unavailable_status": 503, "timeout_status": 504, "request_replay": false},
	}, 0o600)
	tunnelResult = writeFailureDependencyResult(t, repository, "tunnel-release", commit, tunnelSummary)
	ingressResult = writeFailureDependencyResult(t, repository, "ingress-release", commit, ingressSummary)
	return repository, fakeBin, tunnelResult, fileSHA256(t, tunnelResult), ingressResult, fileSHA256(t, ingressResult)
}

func writeFailureDependencyResult(t *testing.T, repository, stage, commit, summary string) string {
	t.Helper()
	directory := filepath.Join(repository, "artifacts", "v2lab", "deployed-release-gate", "evidence-test", "automated-attempts", stage, "attempt-0001")
	result := filepath.Join(directory, "result.json")
	writeJSONAny(t, result, map[string]any{
		"schema_version": 2, "stage": stage, "status": "passed", "exit_code": 0,
		"source_commit": commit, "release_version": "v2.0.0", "lima_image_digest": deployedGateTestImageDigest,
		"contract_sha256": strings.Repeat("a", 64), "dependencies": map[string]any{},
		"artifact": map[string]any{"summary_path": summary, "summary_sha256": fileSHA256(t, summary)},
	}, 0o400)
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal(err)
	}
	return result
}

func writeJSONAny(t *testing.T, path string, value any, mode os.FileMode) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, string(append(data, '\n')), mode)
}

func failureDependencyFakeGo() string {
	return `#!/bin/bash
set -euo pipefail
for name in \
  TestControllerOutageKeepsAppliedDataPlaneAndReturnsManagementUnavailable \
  TestControllerRestartOnlyObservesDataPlane \
  TestFRPClientConfigurationReloadFailureRestoresFileAndRuntime \
  TestGatewayTunnelServicesKeepAuthorizationWithFRPAndOutsideControllerLifetime \
  TestNginxActivationReloadFailureRestoresPriorServingGeneration \
  TestExposeRemoveSagaUnpublishesDrainsAndRemovesOnlyTargetBeforePortRelease; do
  printf '%s\n' "--- PASS: $name (0.00s)"
done
`
}
