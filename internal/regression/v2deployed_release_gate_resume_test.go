package regression

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const deployedGateTestImageDigest = "sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7"

type deployedGateFixture struct {
	repository string
	script     string
	fakeBin    string
	runLog     string
	limaState  string
}

func TestV2DeployedReleaseGateResumesFailedCapacityWithoutOverwritingAttempts(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-capacity-resume")

	output, code := fixture.run(t, "capacity", "run-automated", evidence)
	if code != 9 || !strings.Contains(output, "run-automated --resume") {
		t.Fatalf("first run code=%d output=%s", code, output)
	}
	if _, err := os.Stat(filepath.Join(evidence, "automated.json")); !os.IsNotExist(err) {
		t.Fatalf("automated.json after failed capacity = %v", err)
	}
	failedAttempt := filepath.Join(evidence, "automated-attempts", "capacity", "attempt-0001")
	before := snapshotAttempt(t, failedAttempt)

	output, code = fixture.run(t, "", "run-automated", evidence)
	if code != 3 || !strings.Contains(output, "continue explicitly") {
		t.Fatalf("non-resume retry code=%d output=%s", code, output)
	}
	if got := countStageRuns(t, fixture.runLog, "capacity"); got != 1 {
		t.Fatalf("capacity runs after refused retry = %d, want 1", got)
	}

	output, code = fixture.run(t, "", "run-automated", "--resume", evidence)
	if code != 0 || !strings.Contains(output, "reusing release gate: adversarial") {
		t.Fatalf("resume code=%d output=%s", code, output)
	}
	after := snapshotAttempt(t, failedAttempt)
	if before != after {
		t.Fatalf("failed capacity attempt changed across resume\nbefore=%s\nafter=%s", before, after)
	}
	if got := countStageRuns(t, fixture.runLog, "traceability"); got != 1 {
		t.Fatalf("traceability runs = %d, want 1", got)
	}
	if got := countStageRuns(t, fixture.runLog, "capacity"); got != 2 {
		t.Fatalf("capacity runs = %d, want 2", got)
	}
	assertAttemptCount(t, evidence, "capacity", 2)
	assertAutomatedAggregate(t, evidence, "capacity", "attempt-0002")

	runsBefore := readLines(t, fixture.runLog)
	output, code = fixture.run(t, "", "run-automated", "--resume", evidence)
	if code != 0 || !strings.Contains(output, "already complete") {
		t.Fatalf("completed resume code=%d output=%s", code, output)
	}
	if runsAfter := readLines(t, fixture.runLog); strings.Join(runsBefore, "\n") != strings.Join(runsAfter, "\n") {
		t.Fatal("completed resume executed another stage")
	}
}

func TestV2DeployedReleaseGateInvalidatesOutdatedStageFingerprints(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-input-invalidation")
	if output, code := fixture.run(t, "capacity", "run-automated", evidence); code != 9 {
		t.Fatalf("first run code=%d output=%s", code, output)
	}

	invalidateAttemptFingerprint(t, filepath.Join(evidence, "automated-attempts", "go-test", "attempt-0001"), false)
	invalidateAttemptFingerprint(t, filepath.Join(evidence, "automated-attempts", "node-transport", "attempt-0001"), true)
	corruptAttemptResult(t, filepath.Join(evidence, "automated-attempts", "go-vet", "attempt-0001"))
	if output, code := fixture.run(t, "", "run-automated", "--resume", evidence); code != 0 {
		t.Fatalf("resume after invalidation code=%d output=%s", code, output)
	}
	if got := countStageRuns(t, fixture.runLog, "go-test"); got != 2 {
		t.Fatalf("go-test runs = %d, want 2", got)
	}
	if got := countStageRuns(t, fixture.runLog, "node-transport"); got != 2 {
		t.Fatalf("node-transport runs = %d, want 2", got)
	}
	if got := countStageRuns(t, fixture.runLog, "go-race"); got != 1 {
		t.Fatalf("unaffected go-race runs = %d, want 1", got)
	}
	if got := countStageRuns(t, fixture.runLog, "go-vet"); got != 2 {
		t.Fatalf("go-vet runs = %d, want 2", got)
	}
	assertAutomatedAggregate(t, evidence, "go-test", "attempt-0002")
	assertAutomatedAggregate(t, evidence, "node-transport", "attempt-0002")
	assertAutomatedAggregate(t, evidence, "go-vet", "attempt-0002")
}

func TestV2DeployedReleaseGateRestoresFixturesAfterSharedStageFailure(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-shared-cleanup")
	output, code := fixture.run(t, "restricted-process", "run-automated", evidence)
	if code != 9 || !strings.Contains(output, "release gate stage failed: restricted-process") {
		t.Fatalf("shared failure code=%d output=%s", code, output)
	}
	fixture.assertLimaStopped(t)
	assertMode(t, filepath.Join(evidence, "automated-fixture-sessions", "session-0001"), 0o500)
	assertMode(t, filepath.Join(evidence, "automated-fixture-sessions", "session-0001", "session.log"), 0o400)

	if output, code = fixture.run(t, "", "run-automated", "--resume", evidence); code != 0 {
		t.Fatalf("shared resume code=%d output=%s", code, output)
	}
	fixture.assertLimaStopped(t)
	if got := countStageRuns(t, fixture.runLog, "personal-client"); got != 1 {
		t.Fatalf("personal-client runs = %d, want 1", got)
	}
	if got := countStageRuns(t, fixture.runLog, "restricted-process"); got != 2 {
		t.Fatalf("restricted-process runs = %d, want 2", got)
	}
	assertAttemptCount(t, evidence, "restricted-process", 2)
}

func TestV2DeployedReleaseGateResumePreservesInterruptedLedgerEntries(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-interrupted")
	interruptedAttempt := filepath.Join(evidence, "automated-attempts", "traceability", "attempt-0001")
	interruptedSession := filepath.Join(evidence, "automated-fixture-sessions", "session-0001")
	for _, directory := range []string{interruptedAttempt, interruptedSession} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	if output, code := fixture.run(t, "", "run-automated", "--resume", evidence); code != 0 {
		t.Fatalf("resume after interruption code=%d output=%s", code, output)
	}
	assertAttemptCount(t, evidence, "traceability", 2)
	entries, err := os.ReadDir(interruptedAttempt)
	if err != nil || len(entries) != 0 {
		t.Fatalf("interrupted attempt changed: entries=%v err=%v", entries, err)
	}
	assertMode(t, interruptedAttempt, 0o700)
	entries, err = os.ReadDir(interruptedSession)
	if err != nil || len(entries) != 0 {
		t.Fatalf("interrupted fixture session changed: entries=%v err=%v", entries, err)
	}
	assertMode(t, interruptedSession, 0o700)
	assertMode(t, filepath.Join(evidence, "automated-fixture-sessions", "session-0002"), 0o500)
	assertAutomatedAggregate(t, evidence, "traceability", "attempt-0002")
}

func TestV2DeployedReleaseGateRefusesLegacyAndDifferentCommitEvidence(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		fixture := newDeployedGateFixture(t)
		evidence := fixture.prepare(t, "evidence-legacy")
		candidatePath := filepath.Join(evidence, "candidate.json")
		candidate := readJSONObject(t, candidatePath)
		candidate["schema_version"] = float64(1)
		delete(candidate, "automated_attempts_schema_version")
		writeJSONObject(t, candidatePath, candidate, 0o600)
		if err := os.RemoveAll(filepath.Join(evidence, "automated-attempts")); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(evidence, "automated-fixture-sessions")); err != nil {
			t.Fatal(err)
		}
		before := fileSHA256(t, candidatePath)
		output, code := fixture.run(t, "", "run-automated", "--resume", evidence)
		if code != 3 || !strings.Contains(output, "legacy release evidence is read-only") {
			t.Fatalf("legacy resume code=%d output=%s", code, output)
		}
		if after := fileSHA256(t, candidatePath); after != before {
			t.Fatal("legacy candidate was modified")
		}
	})

	t.Run("source-commit", func(t *testing.T) {
		fixture := newDeployedGateFixture(t)
		evidence := fixture.prepare(t, "evidence-old-commit")
		writeTestFile(t, filepath.Join(fixture.repository, "new-contract.txt"), "changed\n", 0o644)
		fixture.git(t, "add", "new-contract.txt")
		fixture.git(t, "commit", "-q", "-m", "change contract")
		output, code := fixture.run(t, "", "run-automated", "--resume", evidence)
		if code != 3 || !strings.Contains(output, "does not match the clean source commit") {
			t.Fatalf("old commit resume code=%d output=%s", code, output)
		}
		if entries, err := os.ReadDir(filepath.Join(evidence, "automated-attempts")); err != nil || len(entries) != 0 {
			t.Fatalf("attempts after source mismatch = %v, %v", entries, err)
		}
	})
}

func newDeployedGateFixture(t *testing.T) deployedGateFixture {
	t.Helper()
	temporary := t.TempDir()
	repository := filepath.Join(temporary, "repo")
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
	fakeBin := filepath.Join(temporary, "bin")
	for _, directory := range []string{
		filepath.Join(repository, "scripts"),
		filepath.Join(repository, "openspec", "changes", "vpnctl-v2"),
		filepath.Join(repository, "test", "v2lab", "deployed-release-gate"),
		fakeBin,
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	sourceScript := filepath.Join("..", "..", "scripts", "v2deployed-release-gate.sh")
	copyTestFile(t, sourceScript, filepath.Join(repository, "scripts", "v2deployed-release-gate.sh"), 0o755)
	copyTestFile(t, filepath.Join("..", "..", "test", "v2lab", "deployed-release-gate", "deployment.example.json"), filepath.Join(repository, "test", "v2lab", "deployed-release-gate", "deployment.example.json"), 0o644)
	copyTestFile(t, filepath.Join("..", "..", "test", "v2lab", "deployed-release-gate", "clash-mi.example.json"), filepath.Join(repository, "test", "v2lab", "deployed-release-gate", "clash-mi.example.json"), 0o644)
	writeTestFile(t, filepath.Join(repository, "test", "v2lab", "ingress", "telegram_webhook_gate.py"), "#!/usr/bin/env python3\n", 0o755)
	writeTestFile(t, filepath.Join(repository, "openspec", "changes", "vpnctl-v2", "tasks.md"), "- [ ] 16.11 deployed release gate\n", 0o644)
	writeTestFile(t, filepath.Join(repository, ".gitignore"), "artifacts/\n", 0o644)

	stageScripts := map[string]string{
		"v2credential-lifecycle-e2e.sh":   "credential-lifecycle",
		"v2update-restore-e2e.sh":         "update-restore",
		"v2node-transport-e2e.sh":         "node-transport",
		"v2fleet-isolation-e2e.sh":        "fleet-isolation",
		"v2failure-e2e.sh":                "failure",
		"v2adversarial-e2e.sh":            "adversarial",
		"v2capacity-e2e.sh":               "capacity",
		"v2personal-client-test.sh":       "personal-client",
		"v2transport-supervision-test.sh": "transport-supervision",
		"v2restricted-test.sh":            "restricted-process",
		"v2tunnel-release-gate.sh":        "tunnel-release",
		"v2ingress-release-gate.sh":       "ingress-release",
	}
	for name, stage := range stageScripts {
		writeTestFile(t, filepath.Join(repository, "scripts", name), fakeStageScript(stage), 0o755)
	}
	writeTestFile(t, filepath.Join(repository, "scripts", "v2watchdog-test.sh"), fakeWatchdogScript(), 0o755)
	writeTestFile(t, filepath.Join(fakeBin, "go"), fakeGoScript(), 0o755)
	writeTestFile(t, filepath.Join(fakeBin, "openspec"), fakeStageScript("openspec"), 0o755)
	writeTestFile(t, filepath.Join(fakeBin, "limactl"), fakeLimaScript(), 0o755)

	fixture := deployedGateFixture{
		repository: repository,
		script:     filepath.Join(repository, "scripts", "v2deployed-release-gate.sh"),
		fakeBin:    fakeBin,
		runLog:     filepath.Join(temporary, "stages.log"),
		limaState:  filepath.Join(temporary, "lima"),
	}
	if err := os.MkdirAll(fixture.limaState, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.git(t, "init", "-q")
	fixture.git(t, "config", "user.email", "release-gate-test@example.invalid")
	fixture.git(t, "config", "user.name", "Release Gate Test")
	fixture.git(t, "add", ".")
	fixture.git(t, "commit", "-q", "-m", "fixture")
	return fixture
}

func (fixture deployedGateFixture) prepare(t *testing.T, name string) string {
	t.Helper()
	evidence := filepath.Join(fixture.repository, "artifacts", "v2lab", "deployed-release-gate", name)
	if output, code := fixture.run(t, "", "prepare", "v2.0.0", evidence); code != 0 {
		t.Fatalf("prepare code=%d output=%s", code, output)
	}
	return evidence
}

func (fixture deployedGateFixture) run(t *testing.T, failStage string, arguments ...string) (string, int) {
	t.Helper()
	command := exec.Command(fixture.script, arguments...)
	command.Dir = fixture.repository
	command.Env = append(os.Environ(),
		"PATH="+fixture.fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"VPNCTL_TEST_RUN_LOG="+fixture.runLog,
		"VPNCTL_TEST_LIMA_STATE="+fixture.limaState,
		"VPNCTL_TEST_FAIL_STAGE="+failStage,
	)
	output, err := command.CombinedOutput()
	if err == nil {
		return string(output), 0
	}
	if exitError, ok := err.(*exec.ExitError); ok {
		return string(output), exitError.ExitCode()
	}
	t.Fatalf("run release gate: %v", err)
	return "", -1
}

func (fixture deployedGateFixture) git(t *testing.T, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = fixture.repository
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}

func (fixture deployedGateFixture) assertLimaStopped(t *testing.T) {
	t.Helper()
	for _, name := range []string{"vpnctl-v2-gateway", "vpnctl-v2-node"} {
		path := filepath.Join(fixture.limaState, name)
		data, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(data)) != "Stopped" {
			t.Fatalf("Lima state %s = %q, %v", name, data, err)
		}
	}
}

func fakeStageScript(stage string) string {
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
stage=%q
printf '%%s\n' "$stage" >> "$VPNCTL_TEST_RUN_LOG"
if [ "${VPNCTL_TEST_FAIL_STAGE:-}" = "$stage" ]; then
  echo "forced failure: $stage" >&2
  exit 9
fi
`, stage)
}

func fakeWatchdogScript() string {
	return `#!/bin/bash
set -euo pipefail
stage=watchdog-timeout
if [ "${1:-}" = verify-confirm ]; then stage=watchdog-confirm; fi
printf '%s\n' "$stage" >> "$VPNCTL_TEST_RUN_LOG"
if [ "${VPNCTL_TEST_FAIL_STAGE:-}" = "$stage" ]; then
  echo "forced failure: $stage" >&2
  exit 9
fi
`
}

func fakeGoScript() string {
	return `#!/bin/bash
set -euo pipefail
stage=go-test
case " $* " in
  *TestV2RequirementTraceabilityIsComplete*) stage=traceability ;;
  *' -race '*) stage=go-race ;;
  *' vet '*) stage=go-vet ;;
esac
printf '%s\n' "$stage" >> "$VPNCTL_TEST_RUN_LOG"
if [ "${VPNCTL_TEST_FAIL_STAGE:-}" = "$stage" ]; then
  echo "forced failure: $stage" >&2
  exit 9
fi
`
}

func fakeLimaScript() string {
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
state_dir=${VPNCTL_TEST_LIMA_STATE:?}
status_for() {
  if [ -f "$state_dir/$1" ]; then cat "$state_dir/$1"; else printf 'Stopped'; fi
}
case "${1:-}" in
  list)
    for name in vpnctl-v2-gateway vpnctl-v2-node; do
      status=$(status_for "$name")
      printf '{"name":"%%s","status":"%%s","vmType":"qemu","arch":"x86_64","cpus":1,"memory":536870912,"disk":10737418240,"config":{"images":[{"digest":"%s"}]},"network":[{"lima":"user-v2"}]}\n' "$name" "$status"
    done
    ;;
  start)
    printf 'Running\n' > "$state_dir/$2"
    printf 'fixture:start:%%s\n' "$2" >> "$VPNCTL_TEST_RUN_LOG"
    ;;
  stop)
    printf 'Stopped\n' > "$state_dir/$2"
    printf 'fixture:stop:%%s\n' "$2" >> "$VPNCTL_TEST_RUN_LOG"
    ;;
  *) exit 2 ;;
esac
`, deployedGateTestImageDigest)
}

func invalidateAttemptFingerprint(t *testing.T, directory string, lima bool) {
	t.Helper()
	inputPath := filepath.Join(directory, "input.json")
	resultPath := filepath.Join(directory, "result.json")
	input := readJSONObject(t, inputPath)
	result := readJSONObject(t, resultPath)
	invalid := strings.Repeat("0", 64)
	input["contract_sha256"] = invalid
	result["contract_sha256"] = invalid
	if lima {
		wrongImage := "sha256:" + invalid
		input["lima_image_digest"] = wrongImage
		result["lima_image_digest"] = wrongImage
	}
	writeJSONObject(t, inputPath, input, 0o400)
	result["input_sha256"] = fileSHA256(t, inputPath)
	result["log_sha256"] = fileSHA256(t, filepath.Join(directory, "output.log"))
	writeJSONObject(t, resultPath, result, 0o400)
}

func corruptAttemptResult(t *testing.T, directory string) {
	t.Helper()
	path := filepath.Join(directory, "result.json")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
}

func assertAutomatedAggregate(t *testing.T, evidence, stage, attempt string) {
	t.Helper()
	automated := readJSONObject(t, filepath.Join(evidence, "automated.json"))
	if automated["schema_version"] != float64(2) || automated["status"] != "passed" {
		t.Fatalf("automated aggregate header = %+v", automated)
	}
	stageAttempts, ok := automated["stage_attempts"].(map[string]any)
	if !ok || len(stageAttempts) != 19 {
		t.Fatalf("stage attempts = %#v", automated["stage_attempts"])
	}
	selected, ok := stageAttempts[stage].(map[string]any)
	if !ok || selected["attempt"] != attempt {
		t.Fatalf("selected %s attempt = %#v, want %s", stage, selected, attempt)
	}
}

func assertAttemptCount(t *testing.T, evidence, stage string, want int) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(evidence, "automated-attempts", stage))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != want {
		t.Fatalf("%s attempt count = %d, want %d", stage, len(entries), want)
	}
}

func snapshotAttempt(t *testing.T, directory string) string {
	t.Helper()
	parts := []string{fmt.Sprintf("dir:%o", fileMode(t, directory))}
	for _, name := range []string{"input.json", "output.log", "result.json"} {
		path := filepath.Join(directory, name)
		parts = append(parts, fmt.Sprintf("%s:%o:%s", name, fileMode(t, path), fileSHA256(t, path)))
	}
	return strings.Join(parts, "|")
}

func countStageRuns(t *testing.T, path, stage string) int {
	t.Helper()
	count := 0
	for _, line := range readLines(t, path) {
		if line == stage {
			count++
		}
	}
	return count
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func readJSONObject(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}

func writeJSONObject(t *testing.T, path string, value map[string]any, mode os.FileMode) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if got := fileMode(t, path); got != want {
		t.Fatalf("mode(%s) = %o, want %o", path, got, want)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func copyTestFile(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, destination, string(data), mode)
}

func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
