package lifecycle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	v1state "github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

func TestV1InspectorReportsCompleteInstallationWithoutExposingPrivateMaterial(t *testing.T) {
	workspace, systemRoot, serverPrivate, clientPrivate := completeV1InspectionFixture(t)
	before := snapshotV1InspectionTrees(t, workspace, systemRoot)
	inspector, err := NewV1InstallationInspector(workspace, systemRoot)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := inspector.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after := snapshotV1InspectionTrees(t, workspace, systemRoot)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("read-only v1 inspection changed a fixture file")
	}
	report := inspection.Report
	if report.Status != V1InspectionReady || !report.StatePresent || report.StateSchemaVersion != 1 {
		t.Fatalf("inspection status/state = %s/%t/%d issues=%+v", report.Status, report.StatePresent, report.StateSchemaVersion, report.Issues)
	}
	if !report.Server.PrivateKeyPresent || !report.Server.PrivateKeyValid || !report.Server.KeyPairMatches ||
		report.Server.WireGuardSubnet != "10.66.0.0/24" {
		t.Fatalf("server summary = %+v", report.Server)
	}
	if len(report.Clients) != 1 || report.Clients[0].ID != "iphone" || report.Clients[0].AssignedIP != "10.66.0.2" ||
		!report.Clients[0].PrivateKeyValid || !report.Clients[0].KeyPairMatches {
		t.Fatalf("client summaries = %+v", report.Clients)
	}
	if len(report.Rulesets) != 1 || report.Rulesets[0].ID != "default" || report.Rulesets[0].DomainCount != 4 {
		t.Fatalf("rulesets = %+v", report.Rulesets)
	}
	if len(report.Generated) != 2 || report.Generated[0].ClientID != "iphone" || report.Generated[1].ClientID != "iphone" {
		t.Fatalf("generated artifacts = %+v", report.Generated)
	}
	if !report.WireGuardConfig.Present || !report.WireGuardConfig.MatchesState ||
		!report.ForwardingConfig.Present || !report.ForwardingConfig.MatchesState {
		t.Fatalf("system artifacts = %+v / %+v", report.WireGuardConfig, report.ForwardingConfig)
	}
	if report.UFW.Enabled == nil || !*report.UFW.Enabled || countV1UFWClassification(report.UFW.Rules, "wireguard") != 2 ||
		countV1UFWClassification(report.UFW.Rules, "ssh_candidate") != 2 {
		t.Fatalf("UFW report = %+v", report.UFW)
	}
	encoded, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(encoded), inspection.String(), fmt.Sprintf("%#v", inspection)} {
		if strings.Contains(rendered, serverPrivate) || strings.Contains(rendered, clientPrivate) ||
			strings.Contains(rendered, workspace) || strings.Contains(rendered, systemRoot) {
			t.Fatalf("inspection projection exposed private material or physical root: %s", rendered)
		}
	}
	serverKey := inspection.privateKeys["server"]
	profile := inspection.generated["generated/delivery/iphone.conf"]
	inspection.Destroy()
	if inspection.privateKeys != nil || inspection.generated != nil || inspection.systemWireGuard != nil || inspection.rulesets != nil ||
		!allV1BytesZero(serverKey) || !allV1BytesZero(profile) {
		t.Fatal("Destroy did not erase retained private inspection data")
	}
}

func TestV1InspectorMalformedPartialUnsupportedAndAbsentAreNoMutationReports(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string)
		status  V1InspectionStatus
		code    string
	}{
		{name: "absent", status: V1InspectionAbsent},
		{name: "partial", status: V1InspectionPartial, code: "server_missing", prepare: func(t *testing.T, workspace string) {
			t.Helper()
			if _, err := v1state.Init(filepath.Join(workspace, ".vpnctl"), false); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "malformed", status: V1InspectionInvalid, code: "state_malformed", prepare: func(t *testing.T, workspace string) {
			t.Helper()
			stateDir := filepath.Join(workspace, ".vpnctl")
			if _, err := v1state.Init(stateDir, false); err != nil {
				t.Fatal(err)
			}
			writeV1FixtureFile(t, filepath.Join(stateDir, "state.json"), []byte("{broken\n"), 0o644)
		}},
		{name: "unsupported", status: V1InspectionUnsupported, code: "unsupported_state_schema", prepare: func(t *testing.T, workspace string) {
			t.Helper()
			stateDir := filepath.Join(workspace, ".vpnctl")
			if _, err := v1state.Init(stateDir, false); err != nil {
				t.Fatal(err)
			}
			writeV1FixtureFile(t, filepath.Join(stateDir, "state.json"), []byte("{\"schema_version\":2,\"server\":null,\"clients\":[]}\n"), 0o644)
		}},
		{name: "unsafe-state-root", status: V1InspectionInvalid, code: "unsafe_state_directory", prepare: func(t *testing.T, workspace string) {
			t.Helper()
			target := t.TempDir()
			if err := os.Symlink(target, filepath.Join(workspace, ".vpnctl")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			workspace, systemRoot := t.TempDir(), t.TempDir()
			if test.prepare != nil {
				test.prepare(t, workspace)
			}
			before := snapshotV1InspectionTrees(t, workspace, systemRoot)
			inspector, err := NewV1InstallationInspector(workspace, systemRoot)
			if err != nil {
				t.Fatal(err)
			}
			inspection, err := inspector.Inspect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer inspection.Destroy()
			if inspection.Report.Status != test.status {
				t.Fatalf("status=%s want=%s issues=%+v", inspection.Report.Status, test.status, inspection.Report.Issues)
			}
			if test.code != "" && !hasV1InspectionIssue(inspection.Report.Issues, test.code) {
				t.Fatalf("missing issue %q: %+v", test.code, inspection.Report.Issues)
			}
			after := snapshotV1InspectionTrees(t, workspace, systemRoot)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("inspection changed malformed/partial/unsupported fixture")
			}
		})
	}
}

func TestV1InspectorRejectsGeneratedAndSystemSymlinksWithoutFollowingThem(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	delivery := filepath.Join(workspace, ".vpnctl", "generated", "delivery", "iphone.conf")
	if err := os.Remove(delivery); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(t.TempDir(), "private-canary")
	writeV1FixtureFile(t, canary, []byte("do-not-read-this-private-canary"), 0o600)
	if err := os.Symlink(canary, delivery); err != nil {
		t.Fatal(err)
	}
	wireGuardDir := filepath.Join(systemRoot, "etc", "wireguard")
	if err := os.Remove(filepath.Join(wireGuardDir, "wg0.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(wireGuardDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(canary), wireGuardDir); err != nil {
		t.Fatal(err)
	}
	before := snapshotV1InspectionTrees(t, workspace, systemRoot)
	inspector, _ := NewV1InstallationInspector(workspace, systemRoot)
	inspection, err := inspector.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer inspection.Destroy()
	if inspection.Report.Status != V1InspectionInvalid ||
		!hasV1InspectionIssue(inspection.Report.Issues, "generated_entry_unsupported") ||
		!hasV1InspectionIssue(inspection.Report.Issues, "wireguard_config_unsafe") {
		t.Fatalf("unsafe inspection = %s %+v", inspection.Report.Status, inspection.Report.Issues)
	}
	encoded, _ := json.Marshal(inspection)
	if bytes.Contains(encoded, []byte("do-not-read-this-private-canary")) {
		t.Fatal("symlink target content entered the report")
	}
	if after := snapshotV1InspectionTrees(t, workspace, systemRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("unsafe inspection changed fixture")
	}
}

func TestV1InspectorRejectsReservedClientAddressAndMismatchedKeyPair(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	stateDir := filepath.Join(workspace, ".vpnctl")
	state, err := v1state.Load(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state.Clients[0].AssignedIP = "10.66.0.1"
	state.Clients[0].WireGuardPublicKey = state.Server.WireGuardPublicKey
	if err := v1state.Save(stateDir, state); err != nil {
		t.Fatal(err)
	}
	before := snapshotV1InspectionTrees(t, workspace, systemRoot)
	inspector, _ := NewV1InstallationInspector(workspace, systemRoot)
	inspection, err := inspector.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer inspection.Destroy()
	if inspection.Report.Status != V1InspectionInvalid ||
		!hasV1InspectionIssue(inspection.Report.Issues, "client_address_invalid") ||
		!hasV1InspectionIssue(inspection.Report.Issues, "client_key_pair_mismatch") {
		t.Fatalf("invalid client inspection = %s %+v", inspection.Report.Status, inspection.Report.Issues)
	}
	if after := snapshotV1InspectionTrees(t, workspace, systemRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("invalid client inspection changed fixture")
	}
}

func completeV1InspectionFixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	workspace, systemRoot := t.TempDir(), t.TempDir()
	stateDir := filepath.Join(workspace, ".vpnctl")
	if _, err := v1state.Init(stateDir, false); err != nil {
		t.Fatal(err)
	}
	serverPrivate, serverPublic := v1TestKeyPair(t, 1)
	clientPrivate, clientPublic := v1TestKeyPair(t, 2)
	config := v1state.DefaultServerConfig()
	config.PublicEndpoint = "198.51.100.10"
	config.DNSServers = []string{"1.1.1.1", "8.8.8.8"}
	config.ExternalInterface = "eth0"
	if err := v1state.ConfigureServer(stateDir, config, false); err != nil {
		t.Fatal(err)
	}
	state, err := v1state.Load(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state.Server.WireGuardPublicKey = serverPublic
	state.Clients = []v1state.ClientState{{
		ID: "iphone", Name: "iPhone", Platform: "ios", Status: v1state.ClientStatusActive,
		AssignedIP: "10.66.0.2", WireGuardPublicKey: clientPublic,
		Tags: []string{"personal"}, CreatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}}
	if err := v1state.Save(stateDir, state); err != nil {
		t.Fatal(err)
	}
	writeV1FixtureFile(t, v1state.ServerPrivateKeyPath(stateDir), []byte(serverPrivate+"\n"), 0o600)
	writeV1FixtureFile(t, v1state.ClientPrivateKeyPath(stateDir, "iphone"), []byte(clientPrivate+"\n"), 0o600)
	writeV1FixtureFile(t, filepath.Join(stateDir, "generated", "delivery", "iphone.conf"), []byte("PrivateKey = "+clientPrivate+"\n"), 0o600)
	writeV1FixtureFile(t, filepath.Join(stateDir, "generated", "delivery", "iphone.clash.yaml"), []byte("private-key: \""+clientPrivate+"\"\n"), 0o600)

	address, err := wireguard.ServerAddress(state.Server.WireGuardSubnet)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := wireguard.RenderServerConfig(wireguard.ServerConfig{
		InterfaceName: state.Server.WireGuardInterface, Address: address, ListenPort: state.Server.WireGuardPort,
		PrivateKey: serverPrivate, ExternalInterface: state.Server.ExternalInterface,
		Peers: []wireguard.ServerPeer{{
			Name: "iphone", PublicKey: clientPublic, AllowedIPs: "10.66.0.2/32", Status: v1state.ClientStatusActive,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeV1FixtureFile(t, filepath.Join(systemRoot, "etc", "wireguard", "wg0.conf"), []byte(rendered), 0o600)
	writeV1FixtureFile(t, filepath.Join(systemRoot, "etc", "sysctl.d", "99-vpnctl.conf"), []byte("net.ipv4.ip_forward=1\n"), 0o644)
	writeV1FixtureFile(t, filepath.Join(systemRoot, "etc", "ufw", "ufw.conf"), []byte("ENABLED=yes\n"), 0o644)
	rules := []byte(strings.Join([]string{
		"### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
		"### tuple ### allow udp 51820 0.0.0.0/0 any 0.0.0.0/0 in",
		"",
	}, "\n"))
	writeV1FixtureFile(t, filepath.Join(systemRoot, "etc", "ufw", "user.rules"), rules, 0o640)
	writeV1FixtureFile(t, filepath.Join(systemRoot, "etc", "ufw", "user6.rules"), rules, 0o640)
	return workspace, systemRoot, serverPrivate, clientPrivate
}

func v1TestKeyPair(t *testing.T, seed byte) (string, string) {
	t.Helper()
	raw := bytes.Repeat([]byte{seed}, 32)
	private := base64.StdEncoding.EncodeToString(raw)
	public, err := v1WireGuardPublicKey([]byte(private))
	if err != nil {
		t.Fatal(err)
	}
	clear(raw)
	return private, public
}

func writeV1FixtureFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func countV1UFWClassification(rules []V1UFWRule, classification string) int {
	count := 0
	for _, rule := range rules {
		if rule.Classification == classification {
			count++
		}
	}
	return count
}

func hasV1InspectionIssue(issues []V1InspectionIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func allV1BytesZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func snapshotV1InspectionTrees(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	result := map[string]string{}
	for rootIndex, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			key := fmt.Sprintf("%d:%s", rootIndex, filepath.ToSlash(relative))
			value := fmt.Sprintf("%s:%o:%d:%d", info.Mode().String(), info.Mode().Perm(), info.Size(), info.ModTime().UnixNano())
			if info.Mode().IsRegular() {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				value += ":" + string(data)
			} else if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(path)
				if err != nil {
					return err
				}
				value += ":" + target
			}
			result[key] = value
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	keys := make([]string, 0, len(result))
	for key := range result {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return result
}
