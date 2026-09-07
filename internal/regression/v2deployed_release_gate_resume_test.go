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
	"syscall"
	"testing"
	"time"
)

const deployedGateTestImageDigest = "sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7"

type deployedGateFixture struct {
	repository string
	script     string
	fakeBin    string
	runLog     string
	limaState  string
}

func TestV2DeployedReleaseGateSplitsFastAndVMPhases(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-split-phases")

	output, code := fixture.runExtra(t, []string{"VPNCTL_TEST_FORBID_LIMA=true"}, "go-test", "run-fast", evidence)
	if code != 9 || !strings.Contains(output, "run-fast --resume") {
		t.Fatalf("failed fast phase code=%d output=%s", code, output)
	}
	if countLimaInvocations(t, fixture.runLog) != 0 {
		t.Fatal("run-fast invoked Lima")
	}
	if output, code = fixture.run(t, "", "run-fast", evidence); code != 3 || !strings.Contains(output, "run-fast --resume") {
		t.Fatalf("implicit fast retry code=%d output=%s", code, output)
	}
	if output, code = fixture.run(t, "", "run-fast", "--resume", evidence); code != 0 {
		t.Fatalf("fast resume code=%d output=%s", code, output)
	}
	if _, err := os.Stat(filepath.Join(evidence, "automated.json")); !os.IsNotExist(err) {
		t.Fatalf("fast phase created automated.json: %v", err)
	}

	output, code = fixture.run(t, "capacity", "run-vm", evidence)
	if code != 9 || !strings.Contains(output, "run-vm --resume") {
		t.Fatalf("failed VM phase code=%d output=%s", code, output)
	}
	fixture.assertLimaStopped(t)
	if got := countLogLine(t, fixture.runLog, "fixture:start:vpnctl-v2-gateway"); got != 2 {
		t.Fatalf("gateway starts = %d, want parent start plus the transport boot-recovery restart", got)
	}
	if got := countLogLine(t, fixture.runLog, "fixture:start:vpnctl-v2-node"); got != 1 {
		t.Fatalf("node starts = %d, want 1", got)
	}
	operations := countFixtureOperations(t, fixture.runLog)
	if output, code = fixture.run(t, "", "run-vm", evidence); code != 3 || !strings.Contains(output, "run-vm --resume") {
		t.Fatalf("implicit VM retry code=%d output=%s", code, output)
	}
	if countFixtureOperations(t, fixture.runLog) != operations {
		t.Fatal("refused VM retry mutated fixtures")
	}
	if output, code = fixture.run(t, "", "run-vm", "--resume", evidence); code != 0 {
		t.Fatalf("VM resume code=%d output=%s", code, output)
	}
	assertAutomatedAggregate(t, evidence, "capacity", "attempt-0002")
	assertSessionEvidence(t, filepath.Join(evidence, "automated-fixture-sessions", "session-0001"), "failed")
	assertSessionEvidence(t, filepath.Join(evidence, "automated-fixture-sessions", "session-0002"), "passed")
	automatedPath := filepath.Join(evidence, "automated.json")
	automatedBefore := fileSHA256(t, automatedPath)
	witnessPath := filepath.Join(evidence, "automated-fixture-sessions", "session-0002", "witness-0001.json")
	witness := readJSONObject(t, witnessPath)
	witness["status"] = "tampered"
	writeJSONObject(t, witnessPath, witness, 0o400)
	output, code = fixture.run(t, "", "run-automated", "--resume", evidence)
	if code != 3 || !strings.Contains(output, "no reusable passing VM session") {
		t.Fatalf("tampered witness resume code=%d output=%s", code, output)
	}
	if fileSHA256(t, automatedPath) != automatedBefore {
		t.Fatal("tampered witness caused automated evidence replacement")
	}
}

func TestV2DeployedReleaseGateRefusesVMBeforeFastWithoutLima(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-vm-before-fast")
	output, code := fixture.runExtra(t, []string{"VPNCTL_TEST_FORBID_LIMA=true"}, "", "run-vm", evidence)
	if code != 3 || !strings.Contains(output, "requires complete reusable fast-phase evidence") {
		t.Fatalf("run-vm before fast code=%d output=%s", code, output)
	}
	if countLimaInvocations(t, fixture.runLog) != 0 {
		t.Fatal("rejected run-vm mutated fixtures")
	}
}

func TestV2DeployedReleaseGateRefusesReadinessProbeDriftBeforeMutation(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-probe-drift")
	if output, code := fixture.run(t, "", "run-fast", evidence); code != 0 {
		t.Fatalf("run-fast code=%d output=%s", code, output)
	}
	operations := countFixtureOperations(t, fixture.runLog)
	output, code := fixture.runExtra(t, []string{"VPNCTL_TEST_DRIFT_PROBE_INSTANCE=vpnctl-v2-node"}, "", "run-vm", evidence)
	if code != 4 || !strings.Contains(output, "readiness probe does not match topology contract") ||
		!strings.Contains(output, "resource-only limactl edit is insufficient") {
		t.Fatalf("probe drift code=%d output=%s", code, output)
	}
	if countFixtureOperations(t, fixture.runLog) != operations {
		t.Fatal("probe-drift preflight mutated fixtures")
	}
	entries, err := os.ReadDir(filepath.Join(evidence, "automated-fixture-sessions"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("probe-drift preflight created session entries=%v err=%v", entries, err)
	}
	fixture.assertLimaStopped(t)
}

func TestV2DeployedReleaseGateSealsStartupFailureAndResumes(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-startup-failure")
	if output, code := fixture.run(t, "", "run-fast", evidence); code != 0 {
		t.Fatalf("run-fast code=%d output=%s", code, output)
	}
	output, code := fixture.runExtra(t, []string{"VPNCTL_TEST_FAIL_START_INSTANCE=vpnctl-v2-node"}, "", "run-vm", evidence)
	if code != 12 || !strings.Contains(output, "release fixture startup failed: node/vpnctl-v2-node") ||
		!strings.Contains(output, "session-0001/session.log") || !strings.Contains(output, "run-vm --resume "+evidence) {
		t.Fatalf("startup failure code=%d output=%s", code, output)
	}
	fixture.assertLimaStopped(t)
	session := filepath.Join(evidence, "automated-fixture-sessions", "session-0001")
	assertMode(t, session, 0o500)
	result := readJSONObject(t, filepath.Join(session, "result.json"))
	timings, ok := result["timings"].(map[string]any)
	if result["status"] != "failed" || !ok || timings["startup_ms"].(float64) <= 0 {
		t.Fatalf("startup failure result = %#v", result)
	}
	if witnesses, ok := result["witnesses"].([]any); !ok || len(witnesses) != 0 {
		t.Fatalf("startup failure witnesses = %#v", result["witnesses"])
	}
	before := snapshotSealedSession(t, session)
	if output, code = fixture.run(t, "", "run-vm", "--resume", evidence); code != 0 {
		t.Fatalf("startup resume code=%d output=%s", code, output)
	}
	if after := snapshotSealedSession(t, session); after != before {
		t.Fatalf("startup failure session changed across resume\nbefore=%s\nafter=%s", before, after)
	}
	assertSessionEvidence(t, filepath.Join(evidence, "automated-fixture-sessions", "session-0002"), "passed")
}

func TestV2DeployedReleaseGateInstallsVersionedHelpersBeforeFirstWitness(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-helper-setup")
	if output, code := fixture.run(t, "", "run-fast", evidence); code != 0 {
		t.Fatalf("run-fast code=%d output=%s", code, output)
	}
	output, code := fixture.runExtra(t, []string{"VPNCTL_TEST_FAIL_HELPER_INSTANCE=vpnctl-v2-node"}, "", "run-vm", evidence)
	if code != 4 || !strings.Contains(output, "release fixture helper setup failed") ||
		!strings.Contains(output, "session-0001/session.log") || !strings.Contains(output, "run-vm --resume "+evidence) {
		t.Fatalf("helper setup failure code=%d output=%s", code, output)
	}
	fixture.assertLimaStopped(t)
	if countStageRuns(t, fixture.runLog, "personal-client") != 0 {
		t.Fatal("VM stage began after helper setup failure")
	}
	session := filepath.Join(evidence, "automated-fixture-sessions", "session-0001")
	assertMode(t, session, 0o500)
	result := readJSONObject(t, filepath.Join(session, "result.json"))
	if result["status"] != "failed" || len(result["witnesses"].([]any)) != 0 {
		t.Fatalf("helper setup failure result = %#v", result)
	}
	before := snapshotSealedSession(t, session)
	if output, code = fixture.run(t, "", "run-vm", "--resume", evidence); code != 0 {
		t.Fatalf("helper setup resume code=%d output=%s", code, output)
	}
	if after := snapshotSealedSession(t, session); after != before {
		t.Fatalf("helper setup failure session changed across resume\nbefore=%s\nafter=%s", before, after)
	}
	for _, instance := range []string{"vpnctl-v2-gateway", "vpnctl-v2-node"} {
		for _, helper := range []string{"vpnctl-v2-lab-report", "vpnctl-v2-lab-fault"} {
			want := 1
			if instance == "vpnctl-v2-gateway" && helper == "vpnctl-v2-lab-report" {
				want = 2
			}
			if got := countLogLine(t, fixture.runLog, "helper:install:"+instance+":"+helper); got != want {
				t.Fatalf("%s/%s successful helper installs = %d, want %d", instance, helper, got, want)
			}
		}
	}
}

func TestV2DeployedReleaseGateDoesNotLeakPrivateVMEnvironmentIntoFastStages(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-fast-environment")
	output, code := fixture.runExtra(t, []string{
		"VPNCTL_TEST_REQUIRE_FAST_ENV_CLEAN=true",
		"VPNCTL_V2_TIMING_OUTPUT=/tmp/foreign-child-timing.json",
		"VPNCTL_V2_SHARED_LIMA_SESSION=true",
	}, "", "run-fast", evidence)
	if code != 0 {
		t.Fatalf("run-fast leaked private VM environment: code=%d output=%s", code, output)
	}
	if countLimaInvocations(t, fixture.runLog) != 0 {
		t.Fatal("environment-isolated run-fast invoked Lima")
	}
}

func TestV2DeployedReleaseGateRejectsInvalidStageRegistries(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]any) []any
	}{
		{name: "missing", mutate: func(stages []any) []any { return stages[:len(stages)-1] }},
		{name: "duplicate", mutate: func(stages []any) []any {
			stages[1].(map[string]any)["name"] = stages[0].(map[string]any)["name"]
			return stages
		}},
		{name: "reordered", mutate: func(stages []any) []any {
			stages[0], stages[1] = stages[1], stages[0]
			return stages
		}},
		{name: "unknown", mutate: func(stages []any) []any {
			stages[0].(map[string]any)["name"] = "unknown-stage"
			return stages
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeployedGateFixture(t)
			path := filepath.Join(fixture.repository, "test", "v2lab", "deployed-release-gate", "stages.json")
			registry := readJSONObject(t, path)
			registry["stages"] = test.mutate(registry["stages"].([]any))
			writeJSONObject(t, path, registry, 0o644)
			fixture.git(t, "add", "test/v2lab/deployed-release-gate/stages.json")
			fixture.git(t, "commit", "-q", "-m", "invalid registry")
			evidence := filepath.Join(fixture.repository, "artifacts", "v2lab", "deployed-release-gate", "evidence-invalid-registry")
			output, code := fixture.run(t, "", "prepare", "v2.0.0", evidence)
			if code != 3 || !strings.Contains(output, "stage registry is invalid") {
				t.Fatalf("invalid registry code=%d output=%s", code, output)
			}
		})
	}
}

func TestV2DeployedReleaseGateFailsClosedOnPostStageWitnessResidue(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-witness-failure")
	output, code := fixture.runExtra(t, []string{"VPNCTL_TEST_FAIL_CLEANUP_STAGE=personal-client"}, "clean-witness-after", "run-automated", evidence)
	if code != 4 || !strings.Contains(output, "release gate stage failed: personal-client") {
		t.Fatalf("witness failure code=%d output=%s", code, output)
	}
	fixture.assertLimaStopped(t)
	if _, err := os.Stat(filepath.Join(evidence, "automated.json")); !os.IsNotExist(err) {
		t.Fatalf("witness failure created automated.json: %v", err)
	}
	result := readJSONObject(t, filepath.Join(evidence, "automated-attempts", "personal-client", "attempt-0001", "result.json"))
	if result["status"] != "failed" || result["post_clean_witness_sha256"] != nil || result["cleanup_adapter_exit_code"] != float64(8) {
		t.Fatalf("witness-failed attempt = %#v", result)
	}
	assertSessionEvidence(t, filepath.Join(evidence, "automated-fixture-sessions", "session-0001"), "failed")

	if output, code = fixture.run(t, "", "run-automated", "--resume", evidence); code != 0 {
		t.Fatalf("resume after witness failure code=%d output=%s", code, output)
	}
	assertAttemptCount(t, evidence, "personal-client", 2)
}

func TestV2DeployedReleaseGateDiagnosticTimingMagnitudeDoesNotInvalidatePass(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-diagnostic-timing")
	if output, code := fixture.run(t, "", "run-fast", evidence); code != 0 {
		t.Fatalf("run-fast code=%d output=%s", code, output)
	}
	resultPath := filepath.Join(evidence, "automated-attempts", "go-test", "attempt-0001", "result.json")
	result := readJSONObject(t, resultPath)
	timings := result["timings"].(map[string]any)
	timings["execution_ms"] = float64(987654)
	writeJSONObject(t, resultPath, result, 0o400)
	output, code := fixture.run(t, "", "run-fast", evidence)
	if code != 0 || !strings.Contains(output, "phase already complete: fast") {
		t.Fatalf("completed fast phase code=%d output=%s", code, output)
	}
	if got := countStageRuns(t, fixture.runLog, "go-test"); got != 1 {
		t.Fatalf("diagnostic timing caused rerun: %d", got)
	}
}

func TestV2DeployedReleaseGateStopsFixturesOnSignals(t *testing.T) {
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			fixture := newDeployedGateFixture(t)
			evidence := fixture.prepare(t, "evidence-signal-"+strings.ToLower(signal.String()))
			if output, code := fixture.run(t, "", "run-fast", evidence); code != 0 {
				t.Fatalf("run-fast code=%d output=%s", code, output)
			}
			command := exec.Command(fixture.script, "run-vm", evidence)
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
				t.Fatal("VM stage did not begin before signal timeout")
			}
			if err := syscall.Kill(-command.Process.Pid, signal); err != nil {
				t.Fatal(err)
			}
			if err := command.Wait(); err == nil {
				t.Fatal("signal run unexpectedly succeeded")
			}
			fixture.assertLimaStopped(t)
		})
	}
}

func TestV2DeployedReleaseGateRecoversOneStopFailureWithoutRerunningStages(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-stop-failure")
	if output, code := fixture.run(t, "", "run-fast", evidence); code != 0 {
		t.Fatalf("run-fast code=%d output=%s", code, output)
	}
	output, code := fixture.runExtra(t, []string{"VPNCTL_TEST_FAIL_STOP_ONCE=true"}, "", "run-vm", evidence)
	if code != 4 {
		t.Fatalf("stop failure code=%d output=%s", code, output)
	}
	fixture.assertLimaStopped(t)
	if _, err := os.Stat(filepath.Join(evidence, "automated.json")); !os.IsNotExist(err) {
		t.Fatalf("failed stop created automated.json: %v", err)
	}
	if output, code = fixture.run(t, "", "run-vm", "--resume", evidence); code != 0 {
		t.Fatalf("stop-failure resume code=%d output=%s", code, output)
	}
	if got := countStageRuns(t, fixture.runLog, "capacity"); got != 1 {
		t.Fatalf("validation-only resume reran capacity: %d", got)
	}
	assertSessionEvidence(t, filepath.Join(evidence, "automated-fixture-sessions", "session-0002"), "passed")
}

func TestV2DeployedReleaseGateResumesFailedCapacityWithoutOverwritingAttempts(t *testing.T) {
	fixture := newDeployedGateFixture(t)
	evidence := fixture.prepare(t, "evidence-capacity-resume")

	output, code := fixture.run(t, "capacity", "run-automated", evidence)
	if code != 9 || !strings.Contains(output, "run-automated --resume") {
		logs, _ := filepath.Glob(filepath.Join(evidence, "automated-attempts", "*", "*", "*"))
		var details []string
		for _, log := range logs {
			data, _ := os.ReadFile(log)
			details = append(details, log+": "+string(data))
		}
		t.Fatalf("first run code=%d output=%s logs=%s", code, output, strings.Join(details, "\n"))
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
	failureInput := readJSONObject(t, filepath.Join(evidence, "automated-attempts", "failure", "attempt-0001", "input.json"))
	fastInput := readJSONObject(t, filepath.Join(evidence, "automated-attempts", "go-test", "attempt-0001", "input.json"))
	if fastInput["fixture_contract_sha256"] != nil {
		t.Fatalf("fast attempt unexpectedly carries VM topology fingerprint: %#v", fastInput)
	}
	if topology, ok := failureInput["fixture_contract_sha256"].(string); !ok || len(topology) != 64 {
		t.Fatalf("VM attempt topology fingerprint = %#v", failureInput["fixture_contract_sha256"])
	}
	dependencies, ok := failureInput["dependencies"].(map[string]any)
	if !ok || len(dependencies) != 2 {
		t.Fatalf("failure dependency input = %#v", failureInput["dependencies"])
	}
	for _, stage := range []string{"tunnel-release", "ingress-release"} {
		dependency, ok := dependencies[stage].(map[string]any)
		if !ok || dependency["attempt"] != "attempt-0001" {
			t.Fatalf("failure dependency %s = %#v", stage, dependencies[stage])
		}
		resultPath := filepath.Join(evidence, "automated-attempts", stage, "attempt-0001", "result.json")
		if dependency["result_sha256"] != fileSHA256(t, resultPath) {
			t.Fatalf("failure dependency %s does not bind result SHA", stage)
		}
	}

	invalidateAttemptFingerprint(t, filepath.Join(evidence, "automated-attempts", "go-test", "attempt-0001"), false)
	invalidateAttemptFingerprint(t, filepath.Join(evidence, "automated-attempts", "node-transport", "attempt-0001"), true)
	corruptAttemptResult(t, filepath.Join(evidence, "automated-attempts", "go-vet", "attempt-0001"))
	corruptAttemptResult(t, filepath.Join(evidence, "automated-attempts", "tunnel-release", "attempt-0001"))
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
	if got := countStageRuns(t, fixture.runLog, "tunnel-release"); got != 2 {
		t.Fatalf("tunnel-release runs = %d, want 2", got)
	}
	if got := countStageRuns(t, fixture.runLog, "ingress-release"); got != 1 {
		t.Fatalf("unaffected ingress-release runs = %d, want 1", got)
	}
	if got := countStageRuns(t, fixture.runLog, "failure"); got != 2 {
		t.Fatalf("dependency-invalidated failure runs = %d, want 2", got)
	}
	assertAutomatedAggregate(t, evidence, "go-test", "attempt-0002")
	assertAutomatedAggregate(t, evidence, "node-transport", "attempt-0002")
	assertAutomatedAggregate(t, evidence, "go-vet", "attempt-0002")
	assertAutomatedAggregate(t, evidence, "tunnel-release", "attempt-0002")
	assertAutomatedAggregate(t, evidence, "failure", "attempt-0002")
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

	t.Run("attempt-schema-1", func(t *testing.T) {
		fixture := newDeployedGateFixture(t)
		evidence := fixture.prepare(t, "evidence-attempt-schema-1")
		candidatePath := filepath.Join(evidence, "candidate.json")
		candidate := readJSONObject(t, candidatePath)
		candidate["automated_attempts_schema_version"] = float64(1)
		writeJSONObject(t, candidatePath, candidate, 0o600)
		before := fileSHA256(t, candidatePath)
		output, code := fixture.run(t, "", "run-fast", "--resume", evidence)
		if code != 3 || !strings.Contains(output, "legacy release evidence is read-only") {
			t.Fatalf("schema-1 attempt resume code=%d output=%s", code, output)
		}
		if after := fileSHA256(t, candidatePath); after != before {
			t.Fatal("schema-1 attempt candidate was modified")
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
		filepath.Join(repository, "test", "v2lab", "capacity"),
		fakeBin,
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	sourceScript := filepath.Join("..", "..", "scripts", "v2deployed-release-gate.sh")
	copyTestFile(t, sourceScript, filepath.Join(repository, "scripts", "v2deployed-release-gate.sh"), 0o755)
	copyTestFile(t, filepath.Join("..", "..", "test", "v2lab", "deployed-release-gate", "stages.json"), filepath.Join(repository, "test", "v2lab", "deployed-release-gate", "stages.json"), 0o644)
	copyTestFile(t, filepath.Join("..", "..", "test", "v2lab", "deployed-release-gate", "clean-state.json"), filepath.Join(repository, "test", "v2lab", "deployed-release-gate", "clean-state.json"), 0o644)
	copyTestFile(t, filepath.Join("..", "..", "test", "v2lab", "deployed-release-gate", "deployment.example.json"), filepath.Join(repository, "test", "v2lab", "deployed-release-gate", "deployment.example.json"), 0o644)
	copyTestFile(t, filepath.Join("..", "..", "test", "v2lab", "deployed-release-gate", "clash-mi.example.json"), filepath.Join(repository, "test", "v2lab", "deployed-release-gate", "clash-mi.example.json"), 0o644)
	for _, path := range []string{
		"test/v2lab/fixtures.json",
		"test/v2lab/lima.yaml",
		"test/v2lab/lima-node.yaml",
		"test/v2lab/provision.sh",
		"test/v2lab/guest/report.sh",
		"test/v2lab/guest/fault.sh",
		"test/v2lab/capacity/manifest.json",
		"test/v2lab/capacity/load.py",
		"test/v2lab/capacity/client_load.py",
		"test/v2lab/capacity/monitor.py",
		"test/v2lab/capacity/fault.sh",
		"test/v2lab/capacity/evaluate.py",
	} {
		copyTestFile(t, filepath.Join("..", "..", filepath.FromSlash(path)), filepath.Join(repository, filepath.FromSlash(path)), 0o644)
	}
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
	writeTestFile(t, filepath.Join(repository, "scripts", "v2release-clean-state.sh"), fakeCleanStateScript(), 0o755)
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
	for _, name := range []string{"vpnctl-v2-gateway", "vpnctl-v2-node"} {
		writeTestFile(t, filepath.Join(fixture.limaState, name), "Stopped\n", 0o600)
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
	return fixture.runExtra(t, nil, failStage, arguments...)
}

func (fixture deployedGateFixture) runExtra(t *testing.T, extraEnvironment []string, failStage string, arguments ...string) (string, int) {
	t.Helper()
	command := exec.Command(fixture.script, arguments...)
	command.Dir = fixture.repository
	command.Env = append(os.Environ(),
		"PATH="+fixture.fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"VPNCTL_TEST_RUN_LOG="+fixture.runLog,
		"VPNCTL_TEST_LIMA_STATE="+fixture.limaState,
		"VPNCTL_TEST_FAIL_STAGE="+failStage,
	)
	command.Env = append(command.Env, extraEnvironment...)
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
if [ "${VPNCTL_TEST_REQUIRE_FAST_ENV_CLEAN:-}" = true ] && [ "$stage" = openspec ] && \
   { [ -n "${VPNCTL_V2_TIMING_OUTPUT:-}" ] || [ -n "${VPNCTL_V2_SHARED_LIMA_SESSION:-}" ]; }; then
  echo "private VM environment leaked into fast stage: $stage" >&2
  exit 10
fi
if [ "${1:-}" = cleanup ] && [ "${VPNCTL_TEST_FAIL_CLEANUP_STAGE:-}" = "$stage" ]; then
  exit 8
fi
if [ "${VPNCTL_TEST_BLOCK_STAGE:-}" = "$stage" ]; then
  while :; do sleep 1; done
fi
if [ "${VPNCTL_TEST_FAIL_STAGE:-}" = "$stage" ]; then
  echo "forced failure: $stage" >&2
  exit 9
fi
if [ "$stage" = transport-supervision ] && [ "${VPNCTL_V2_SHARED_LIMA_SESSION:-}" = true ]; then
  limactl stop vpnctl-v2-gateway
  limactl start vpnctl-v2-gateway
fi
case "$stage" in
  tunnel-release|ingress-release)
    case "$2" in
      /*) ;;
      *) echo "provider release evidence path is not absolute: $2" >&2; exit 11 ;;
    esac
    mkdir -p "$2"
    printf '{"schema_version":1,"status":"passed"}\n' > "$2/summary.json"
    ;;
esac
`, stage)
}

func fakeCleanStateScript() string {
	return `#!/bin/bash
set -euo pipefail
case "${1:-}" in
  validate-manifest) exit 0 ;;
  capture)
    count_file="$VPNCTL_TEST_LIMA_STATE/witness-count"
    count=0
    [ ! -f "$count_file" ] || count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s\n' "$count" > "$count_file"
    if [ "${VPNCTL_TEST_FAIL_STAGE:-}" = clean-witness ] || { [ "${VPNCTL_TEST_FAIL_STAGE:-}" = clean-witness-after ] && [ "$count" -gt 1 ]; }; then exit 9; fi
    jq -n '{schema_version:1,status:"passed",manifest_sha256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",lima_image_digest:"sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7",fixtures:["vpnctl-v2-gateway","vpnctl-v2-node"],timings:{verification_ms:0}}' > "$2"
    chmod 0400 "$2"
    ;;
  *) exit 2 ;;
esac
`
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
if [ "${VPNCTL_TEST_REQUIRE_FAST_ENV_CLEAN:-}" = true ] && \
   { [ -n "${VPNCTL_V2_TIMING_OUTPUT:-}" ] || [ -n "${VPNCTL_V2_SHARED_LIMA_SESSION:-}" ]; }; then
  echo "private VM environment leaked into fast stage: $stage" >&2
  exit 10
fi
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
printf 'lima:%%s\n' "$*" >> "$VPNCTL_TEST_RUN_LOG"
[ "${VPNCTL_TEST_FORBID_LIMA:-}" != true ] || exit 97
	case "${1:-}" in
	  list)
	    for name in vpnctl-v2-gateway vpnctl-v2-node; do
	      status=$(status_for "$name")
	      cpus=1
	      memory=536870912
	      probe_description='vpnctl v2 lab prerequisites'
	      probe_cpus=1
	      if [ "$name" = vpnctl-v2-node ]; then
	        cpus=4
	        memory=2147483648
	        probe_description='vpnctl v2 functional node prerequisites'
	        probe_cpus=4
	      fi
	      probe_script=$(printf '%%s\n' '#!/bin/sh' 'set -eu' 'test "$(dpkg --print-architecture)" = amd64' "grep -q '^VERSION_ID=\"24.04\"$' /etc/os-release" "test \"\$(nproc)\" -eq $probe_cpus" 'command -v jq >/dev/null' 'command -v nft >/dev/null' 'command -v ss >/dev/null' 'command -v tc >/dev/null' 'command -v vmstat >/dev/null')
	      probe_script="${probe_script}"$'\n'
	      if [ "${VPNCTL_TEST_DRIFT_PROBE_INSTANCE:-}" = "$name" ]; then probe_description='drifted readiness probe'; fi
	      jq -cn --arg name "$name" --arg status "$status" --argjson cpus "$cpus" --argjson memory "$memory" \
	        --arg digest "%s" --arg description "$probe_description" --arg script "$probe_script" \
	        '{name:$name,status:$status,vmType:"qemu",arch:"x86_64",cpus:$cpus,memory:$memory,disk:10737418240,config:{images:[{digest:$digest}],probes:[{mode:"readiness",description:$description,script:$script,hint:"See /var/log/cloud-init-output.log in the guest"}]},network:[{lima:"user-v2"}]}'
	    done
    ;;
  start)
	    if [ "${VPNCTL_TEST_FAIL_START_INSTANCE:-}" = "$2" ]; then sleep 0.03; exit 12; fi
    printf 'Running\n' > "$state_dir/$2"
    printf 'fixture:start:%%s\n' "$2" >> "$VPNCTL_TEST_RUN_LOG"
    ;;
  stop)
    failure_marker="$state_dir/stop-failed-$2"
    if [ "${VPNCTL_TEST_FAIL_STOP_ONCE:-}" = true ] && [ ! -e "$failure_marker" ]; then
      : > "$failure_marker"
      exit 9
    fi
    printf 'Stopped\n' > "$state_dir/$2"
    printf 'fixture:stop:%%s\n' "$2" >> "$VPNCTL_TEST_RUN_LOG"
    ;;
	  shell)
	    instance=
	    for value in "$@"; do
	      case "$value" in vpnctl-v2-gateway|vpnctl-v2-node) instance=$value; break ;; esac
	    done
	    case "$*" in
	      *vpnctl-v2-release-gate.tmp*)
	        if [ "${VPNCTL_TEST_FAIL_HELPER_INSTANCE:-}" = "$instance" ]; then sleep 0.03; exit 13; fi
	        previous=
	        last=
	        for value in "$@"; do previous=$last; last=$value; done
	        case "$previous" in
	          /usr/local/libexec/vpnctl-v2-lab-report) helper=vpnctl-v2-lab-report ;;
	          /usr/local/libexec/vpnctl-v2-lab-fault) helper=vpnctl-v2-lab-fault ;;
	          *) exit 14 ;;
	        esac
	        printf 'helper:install:%%s:%%s\n' "$instance" "$helper" >> "$VPNCTL_TEST_RUN_LOG"
	        ;;
	      *sha256sum*vpnctl-v2-lab-report*)
	        shasum -a 256 "$PWD/test/v2lab/guest/report.sh"
	        ;;
	      *sha256sum*vpnctl-v2-lab-fault*)
	        shasum -a 256 "$PWD/test/v2lab/guest/fault.sh"
	        ;;
	      *) exit 15 ;;
	    esac
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
		input["fixture_contract_sha256"] = invalid
		result["fixture_contract_sha256"] = invalid
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
	if topology, ok := automated["fixture_contract_sha256"].(string); !ok || len(topology) != 64 {
		t.Fatalf("automated topology fingerprint = %#v", automated["fixture_contract_sha256"])
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
	for _, name := range []string{"input.json", "output.log", "child-timing.json", "result.json"} {
		path := filepath.Join(directory, name)
		parts = append(parts, fmt.Sprintf("%s:%o:%s", name, fileMode(t, path), fileSHA256(t, path)))
	}
	return strings.Join(parts, "|")
}

func snapshotSealedSession(t *testing.T, directory string) string {
	t.Helper()
	parts := []string{fmt.Sprintf("dir:%o", fileMode(t, directory))}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		parts = append(parts, fmt.Sprintf("%s:%o:%s", entry.Name(), fileMode(t, path), fileSHA256(t, path)))
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

func countLogLine(t *testing.T, path, value string) int {
	t.Helper()
	count := 0
	for _, line := range readLines(t, path) {
		if line == value {
			count++
		}
	}
	return count
}

func countFixtureOperations(t *testing.T, path string) int {
	t.Helper()
	count := 0
	for _, line := range readLines(t, path) {
		if strings.HasPrefix(line, "fixture:") {
			count++
		}
	}
	return count
}

func countLimaInvocations(t *testing.T, path string) int {
	t.Helper()
	count := 0
	for _, line := range readLines(t, path) {
		if strings.HasPrefix(line, "lima:") {
			count++
		}
	}
	return count
}

func assertSessionEvidence(t *testing.T, directory, status string) {
	t.Helper()
	assertMode(t, directory, 0o500)
	result := readJSONObject(t, filepath.Join(directory, "result.json"))
	if result["schema_version"] != float64(2) || result["status"] != status {
		t.Fatalf("session result = %#v", result)
	}
	if topology, ok := result["fixture_contract_sha256"].(string); !ok || len(topology) != 64 {
		t.Fatalf("session topology fingerprint = %#v", result["fixture_contract_sha256"])
	}
	timings, ok := result["timings"].(map[string]any)
	if !ok || len(timings) != 6 {
		t.Fatalf("session timings = %#v", result["timings"])
	}
	for name, value := range timings {
		if number, ok := value.(float64); !ok || number < 0 || number != float64(int64(number)) {
			t.Fatalf("session timing %s = %#v", name, value)
		}
	}
	witnesses, ok := result["witnesses"].([]any)
	if !ok || len(witnesses) == 0 {
		t.Fatalf("session witnesses = %#v", result["witnesses"])
	}
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
