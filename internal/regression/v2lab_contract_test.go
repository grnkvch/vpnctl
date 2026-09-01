package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2MinimumHostLabContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	template := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "lima.yaml"))
	for _, required := range []string{
		"vmType: qemu",
		"arch: x86_64",
		"cpus: 1",
		"memory: 512MiB",
		"disk: 10GiB",
		"ubuntu-24.04-server-cloudimg-amd64.img",
		"sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7",
		"lima: user-v2",
		"url: ./provision.sh",
	} {
		if !strings.Contains(template, required) {
			t.Errorf("v2 lab template is missing %q", required)
		}
	}

	files := []string{
		filepath.Join(repositoryRoot, "scripts", "v2lab.sh"),
		filepath.Join(repositoryRoot, "test", "v2lab", "provision.sh"),
		filepath.Join(repositoryRoot, "test", "v2lab", "guest", "report.sh"),
		filepath.Join(repositoryRoot, "test", "v2lab", "guest", "fault.sh"),
	}
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat v2 lab script %s: %v", path, err)
		}
		if info.Mode()&0o111 == 0 {
			t.Errorf("v2 lab script is not executable: %s", path)
		}
	}

	orchestratorScript := readContractFile(t, files[0])
	if !strings.Contains(orchestratorScript, "install -D -m 0755") {
		t.Error("v2 lab helper installation must create its owned parent directory")
	}
	for _, guard := range []string{
		"assert_instance_contract", "refusing to operate on non-lab or drifted Lima instance",
		"refusing to delete running lab instance", "operate_existing_instances",
	} {
		if !strings.Contains(orchestratorScript, guard) {
			t.Errorf("v2 lab orchestration is missing conflict guard %q", guard)
		}
	}

	reportScript := readContractFile(t, files[2])
	for _, metric := range []string{
		"vcpus", "memory_bytes", "swap_bytes", "disk_bytes", "cpu_user_percent",
		"total_rss_kib", "processes", "sockets", "latency_ms", "packet_loss_percent",
	} {
		if !strings.Contains(reportScript, metric) {
			t.Errorf("v2 lab report does not capture %q", metric)
		}
	}

	faultScript := readContractFile(t, files[3])
	for _, fault := range []string{"clear)", "latency)", "loss)", "partition)"} {
		if !strings.Contains(faultScript, fault) {
			t.Errorf("v2 lab fault control is missing %q", fault)
		}
	}
	if !strings.Contains(faultScript, "fault_qdisc_handle=1abc:") {
		t.Error("v2 lab netem control must use a dedicated qdisc handle")
	}

	documentation := readContractFile(t, filepath.Join(repositoryRoot, "docs", "v2", "TEST_LAB.md"))
	for _, command := range []string{
		"./scripts/v2lab.sh up",
		"./scripts/v2lab.sh report",
		"./scripts/v2lab.sh fault node partition",
		"./scripts/v2lab.sh fault node clear",
	} {
		if !strings.Contains(documentation, command) {
			t.Errorf("v2 lab documentation is missing %q", command)
		}
	}
	if !strings.Contains(documentation, "HOST_CHANGELOG.md") {
		t.Error("v2 lab documentation does not require the host change journal")
	}
}

func readContractFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read contract file %s: %v", path, err)
	}
	return string(data)
}
