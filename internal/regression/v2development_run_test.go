package regression

import (
	"archive/tar"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func developmentRunDirectory(t *testing.T, fixture deployedGateFixture) string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(fixture.repository, "artifacts", "v2lab", "development-runs", "run-*"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("development runs: %v, %v", paths, err)
	}
	return paths[len(paths)-1]
}

func developmentSnapshot(t *testing.T, directory string) map[string]string {
	t.Helper()
	file, err := os.Open(filepath.Join(directory, "inputs.tar"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	files := map[string]string{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		files[header.Name] = string(data)
	}
}

func TestV2DevelopmentRunSupportsDirtyUnbornSource(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	fixture.git(t, "checkout", "--orphan", "development-unborn")
	helper := fakeStageScript("credential-lifecycle") + "\n# uncommitted helper bytes\n"
	writeTestFile(t, filepath.Join(fixture.repository, "scripts", "v2credential-lifecycle-e2e.sh"), helper, 0o755)
	writeTestFile(t, filepath.Join(fixture.repository, "internal", "development.go"), "package development\n", 0o644)
	writeTestFile(t, filepath.Join(fixture.repository, "bot_token"), "SYNTHETIC-DO-NOT-CAPTURE\n", 0o600)
	writeTestFile(t, filepath.Join(fixture.repository, "artifacts", "ignored.txt"), "ignored\n", 0o600)
	output, code := fixture.runExtra(t, []string{"VPNCTL_TEST_FORBID_LIMA=true"}, "", "run-dev", "credential-lifecycle")
	if code != 0 {
		t.Fatalf("dirty unborn run code=%d: %s", code, output)
	}
	if countLimaInvocations(t, fixture.runLog) != 0 || countStageRuns(t, fixture.runLog, "go-test") != 0 {
		t.Fatal("selected host stage ran unrelated work")
	}
	directory := developmentRunDirectory(t, fixture)
	result := readJSONObject(t, filepath.Join(directory, "development.json"))
	if result["mode"] != "development" || result["status"] != "passed" || result["source_commit"] != nil || result["production_ready"] != false {
		t.Fatalf("development result: %#v", result)
	}
	inputs := readJSONObject(t, filepath.Join(directory, "input.json"))
	if inputs["inputs_sha256"] != fileSHA256(t, filepath.Join(directory, "inputs.json")) ||
		inputs["snapshot_sha256"] != fileSHA256(t, filepath.Join(directory, "inputs.tar")) {
		t.Fatal("input content identity was not retained")
	}
	files := developmentSnapshot(t, directory)
	if files["scripts/v2credential-lifecycle-e2e.sh"] != helper || files["internal/development.go"] != "package development\n" {
		t.Fatal("snapshot did not retain current working files")
	}
	for name, data := range files {
		if strings.Contains(name, "bot_token") || strings.HasPrefix(name, "artifacts/") || strings.Contains(data, "SYNTHETIC-DO-NOT-CAPTURE") {
			t.Fatalf("private or ignored local file entered snapshot: %s", name)
		}
	}
	assertMode(t, directory, 0o700)
	assertMode(t, filepath.Join(directory, "inputs.tar"), 0o400)
	for _, name := range []string{"candidate.json", "automated.json", "final-summary.json"} {
		if _, err := os.Stat(filepath.Join(directory, name)); !os.IsNotExist(err) {
			t.Fatalf("development created release receipt %s: %v", name, err)
		}
	}
	command := exec.Command("git", "rev-parse", "--verify", "HEAD")
	command.Dir = fixture.repository
	if err := command.Run(); err == nil {
		t.Fatal("development runner created a commit")
	}
}

func TestV2DevelopmentRunIgnoresHEADChangesAndRetainsEarlierResults(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	if output, code := fixture.run(t, "", "run-dev", "go-vet"); code != 0 {
		t.Fatalf("first run code=%d: %s", code, output)
	}
	first := developmentRunDirectory(t, fixture)
	before := fileSHA256(t, filepath.Join(first, "development.json"))
	writeTestFile(t, filepath.Join(fixture.repository, "docs", "notes.md"), "Documentation only.\n", 0o644)
	fixture.git(t, "add", "docs/notes.md")
	fixture.git(t, "commit", "-q", "-m", "documentation only")
	if output, code := fixture.run(t, "", "run-dev", "go-vet"); code != 0 {
		t.Fatalf("new HEAD run code=%d: %s", code, output)
	}
	paths, _ := filepath.Glob(filepath.Join(fixture.repository, "artifacts", "v2lab", "development-runs", "run-*"))
	if len(paths) != 2 || fileSHA256(t, filepath.Join(first, "development.json")) != before {
		t.Fatal("new invocation replaced earlier evidence")
	}
	if countStageRuns(t, fixture.runLog, "go-vet") != 2 || countStageRuns(t, fixture.runLog, "go-test") != 0 {
		t.Fatal("HEAD change triggered unrelated checks or automatic reuse")
	}
}

func TestV2DevelopmentRunDetectsInputDrift(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	writeTestFile(t, filepath.Join(fixture.repository, "scripts", "v2credential-lifecycle-e2e.sh"),
		"#!/bin/bash\nprintf '# changed during execution\\n' >> scripts/v2credential-lifecycle-e2e.sh\n", 0o755)
	output, code := fixture.run(t, "", "run-dev", "credential-lifecycle")
	if code != 3 || !strings.Contains(output, "inputs changed") {
		t.Fatalf("drift code=%d: %s", code, output)
	}
	result := readJSONObject(t, filepath.Join(developmentRunDirectory(t, fixture), "development.json"))
	if result["status"] != "failed" || result["inputs_unchanged"] != false {
		t.Fatalf("drift result: %#v", result)
	}
}

func TestV2DevelopmentRunPreservesVMFailureAndCleanup(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	writeTestFile(t, filepath.Join(fixture.repository, "docs", "working.md"), "uncommitted\n", 0o644)
	output, code := fixture.run(t, "restricted-process", "run-dev", "restricted-process")
	if code != 9 || !strings.Contains(output, "run-dev restricted-process") || strings.Contains(output, "run-dev --resume") {
		t.Fatalf("VM failure code=%d: %s", code, output)
	}
	fixture.assertLimaStopped(t)
	failed := developmentRunDirectory(t, fixture)
	before := fileSHA256(t, filepath.Join(failed, "development.json"))
	result := readJSONObject(t, filepath.Join(failed, "development.json"))
	if result["status"] != "failed" || result["exit_code"] != float64(9) {
		t.Fatalf("failure result: %#v", result)
	}
	if output, code = fixture.run(t, "", "run-dev", "personal-client"); code != 0 {
		t.Fatalf("independent next stage code=%d: %s", code, output)
	}
	fixture.assertLimaStopped(t)
	if before != fileSHA256(t, filepath.Join(failed, "development.json")) || countStageRuns(t, fixture.runLog, "go-test") != 0 {
		t.Fatal("independent run erased failure or required full fast phase")
	}
}

func TestV2DevelopmentRunSelectsOnlyActualDependencies(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	output, code := fixture.run(t, "", "run-dev", "failure")
	if code != 0 {
		t.Fatalf("dependency run code=%d: %s", code, output)
	}
	fixture.assertLimaStopped(t)
	for _, stage := range []string{"tunnel-release", "ingress-release", "failure"} {
		if countStageRuns(t, fixture.runLog, stage) != 1 {
			t.Fatalf("required stage did not run exactly once: %s", stage)
		}
	}
	for _, stage := range []string{"go-test", "personal-client", "adversarial", "capacity"} {
		if countStageRuns(t, fixture.runLog, stage) != 0 {
			t.Fatalf("unselected stage ran: %s", stage)
		}
	}
}

func TestV2DevelopmentRunKeepsFinalBoundary(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "strict-final")
	if output, code := fixture.run(t, "", "run-dev", "go-vet"); code != 0 {
		t.Fatalf("dev run code=%d: %s", code, output)
	}
	directory := developmentRunDirectory(t, fixture)
	output, code := fixture.run(t, "", "finalize", directory, filepath.Join(fixture.repository, "assets"))
	if code == 0 || !strings.Contains(output, "evidence directory must be below") {
		t.Fatalf("finalize dev evidence code=%d: %s", code, output)
	}
	writeTestFile(t, filepath.Join(fixture.repository, "docs", "dirty.md"), "dirty\n", 0o644)
	output, code = fixture.runExtra(t, []string{"VPNCTL_V2_DEVELOPMENT_RUN=" + directory}, "", "run-fast", evidence)
	if code != 3 || !strings.Contains(output, "requires a clean source tree") {
		t.Fatalf("inherited context weakened final gate code=%d: %s", code, output)
	}
}

func TestV2DevelopmentRunRejectsInvalidSelectionBeforeMutation(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	for _, arguments := range [][]string{{"run-dev", "unknown"}, {"run-dev", "--resume", "old-run"}} {
		if output, code := fixture.run(t, "", arguments...); code != 2 {
			t.Fatalf("invalid selection %v code=%d: %s", arguments, code, output)
		}
	}
	if _, err := os.Stat(filepath.Join(fixture.repository, "artifacts", "v2lab", "development-runs")); !os.IsNotExist(err) {
		t.Fatalf("invalid selection allocated evidence: %v", err)
	}
	if _, err := os.Stat(fixture.runLog); err == nil {
		t.Fatal("invalid selection invoked a stage or fixture command")
	}
}

func TestV2DevelopmentRunRealNestedHarnessDoesNotRequireCommit(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	copyTestFile(t, filepath.Join("..", "..", "scripts", "v2update-restore-e2e.sh"),
		filepath.Join(fixture.repository, "scripts", "v2update-restore-e2e.sh"), 0o755)
	writeTestFile(t, filepath.Join(fixture.fakeBin, "go"), `#!/bin/bash
set -euo pipefail
while [ "$#" -gt 0 ]; do
  if [ "$1" = -run ]; then
    pattern=$2
    pattern=${pattern#^(}
    pattern=${pattern%)$}
    IFS='|' read -r -a names <<< "$pattern"
    for name in "${names[@]}"; do printf '%s\n' "--- PASS: $name (0.00s)"; done
    exit 0
  fi
  shift
done
exit 7
`, 0o755)
	fixture.git(t, "checkout", "--orphan", "nested-unborn")
	output, code := fixture.runExtra(t, []string{"VPNCTL_TEST_FORBID_LIMA=true"}, "", "run-dev", "update-restore")
	if code != 0 {
		t.Fatalf("real nested harness code=%d: %s", code, output)
	}
	paths, _ := filepath.Glob(filepath.Join(fixture.repository, "artifacts", "v2lab", "update-restore-e2e", "run-*", "summary.json"))
	if len(paths) != 1 {
		t.Fatalf("nested summaries: %v", paths)
	}
	if result := readJSONObject(t, paths[0]); result["source_commit"] != "development" || result["status"] != "passed" {
		t.Fatalf("nested source identity: %#v", result)
	}
	command := exec.Command(filepath.Join(fixture.repository, "scripts", "v2update-restore-e2e.sh"), "verify")
	command.Dir = fixture.repository
	command.Env = append(os.Environ(), "VPNCTL_V2_DEVELOPMENT_RUN=")
	data, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(data), "requires a clean source tree") {
		t.Fatalf("ordinary nested entry lost strict default: %v: %s", err, data)
	}
}

func TestV2DevelopmentRunStopsFixturesOnSignals(t *testing.T) {
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			fixture := newDeployedGateFixture(t)
			command := exec.Command(fixture.script, "run-dev", "personal-client")
			command.Dir = fixture.repository
			command.Env = append(os.Environ(),
				"PATH="+fixture.fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"VPNCTL_TEST_RUN_LOG="+fixture.runLog,
				"VPNCTL_TEST_LIMA_STATE="+fixture.limaState,
				"VPNCTL_TEST_BLOCK_STAGE=personal-client",
			)
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(10 * time.Second)
			for countStageRuns(t, fixture.runLog, "personal-client") == 0 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if countStageRuns(t, fixture.runLog, "personal-client") == 0 {
				_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
				_ = command.Wait()
				t.Fatal("dev stage did not begin before signal timeout")
			}
			if err := syscall.Kill(-command.Process.Pid, signal); err != nil {
				t.Fatal(err)
			}
			if err := command.Wait(); err == nil {
				t.Fatal("interrupted development run unexpectedly succeeded")
			}
			fixture.assertLimaStopped(t)
			result := readJSONObject(t, filepath.Join(developmentRunDirectory(t, fixture), "development.json"))
			if result["status"] != "failed" || result["production_ready"] != false {
				t.Fatalf("interrupted result: %#v", result)
			}
		})
	}
}
