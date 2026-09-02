package regression

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestV2WatchdogHarnessContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	harness := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2watchdog-test.sh"))
	for _, required := range []string{
		"assert_lab_instance", "assert_other_spikes_inactive", "assert_owned_or_absent",
		"arm-kill", "kill -KILL", "wait_for_rollback", "timer-start-monotonic-nsec",
		"monotonic_elapsed_nsec", "120000000000",
		"capture_owned", "capture_foreign", "assert_capture_equal", "assert_foreign_equal",
		"trap 'cleanup_internal; cleanup_host_build' EXIT",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("watchdog harness is missing %q", required)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "journalctl", "rm -rf /etc", "rm -rf /var/lib"} {
		if strings.Contains(harness, forbidden) {
			t.Errorf("watchdog harness contains unsafe surface %q", forbidden)
		}
	}

	dropin := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "watchdog", "vpnctl-watchdog-test.conf"))
	if !strings.Contains(dropin, "NetworkNamespacePath=/run/netns/vpnctl-v2-watchdog-test") {
		t.Fatal("watchdog test service is not isolated in the exact namespace")
	}
}
