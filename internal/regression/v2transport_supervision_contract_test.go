package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransportSupervisionHarnessIsOwnedAndReversible(t *testing.T) {
	t.Parallel()
	repositoryRoot := filepath.Join("..", "..")
	script, err := os.ReadFile(filepath.Join(repositoryRoot, "scripts", "v2transport-supervision-test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, required := range []string{
		"vpnctl-v2-task86-v1", "assert_owned_scope", "verify_failure_restart",
		"verify_boot_restore", "systemctl disable --now", "rm -rf -- \"$runtime_root\"", "assert_host_ports_free",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("transport supervision harness is missing %q", required)
		}
	}
	for _, forbidden := range []string{"journalctl", "rm -rf /etc", "rm -rf /var", "killall", "pkill"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("transport supervision harness contains unsafe surface %q", forbidden)
		}
	}
	for _, name := range []string{"standard.service", "restricted.service"} {
		unit, err := os.ReadFile(filepath.Join(repositoryRoot, "test", "v2lab", "transport-supervision", name))
		if err != nil {
			t.Fatal(err)
		}
		content := string(unit)
		for _, required := range []string{"StartLimitIntervalSec=0", "Restart=on-failure", "RestartSec=2s", "WantedBy=multi-user.target", "StandardOutput=null", "StandardError=null"} {
			if !strings.Contains(content, required) {
				t.Errorf("%s is missing %q", name, required)
			}
		}
	}
}
