package lifecycle

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestSystemUpdateRuntimeChecksPackagesAndOnlyRestartsChangedLocalServices(t *testing.T) {
	manifest, _ := releaseManifestFixture()
	runner := &updateSystemRunner{versions: map[string]string{
		"nftables": "1.0.9-1build1", "nginx": "1.24.0-2ubuntu7.17", "wireguard-tools": "1.0.20210914-1ubuntu4",
	}}
	runtime, err := NewSystemUpdateHostRuntime("/", runner)
	if err != nil {
		t.Fatal(err)
	}
	checks, err := runtime.Preflight(context.Background(), model.RoleGateway, manifest)
	if err != nil || len(checks) != 3 {
		t.Fatalf("package checks = %+v, %v", checks, err)
	}
	for _, check := range checks {
		if !check.Compatible || check.InstalledVersion == "" {
			t.Fatalf("package check = %+v", check)
		}
	}
	runner.calls = nil
	change := UpdateComponentChange{Name: "frp", FileChanged: true, AffectedServices: []string{"vpnctl-tunnel-server.service"}}
	if err := runtime.ActivateAndHealth(context.Background(), model.RoleGateway, change); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl restart vpnctl-tunnel-server.service",
		"systemctl is-active --quiet vpnctl-tunnel-server.service",
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("service calls = %q, want %q", runner.calls, want)
	}
}

func TestSystemUpdateRuntimeReportsIncompatiblePackageAndManagesGatewayController(t *testing.T) {
	manifest, _ := releaseManifestFixture()
	runner := &updateSystemRunner{versions: map[string]string{
		"nftables": "0.9", "nginx": "1.24.0-2ubuntu7.17", "wireguard-tools": "1.0.20210914-1ubuntu4",
	}}
	runtime, _ := NewSystemUpdateHostRuntime("/fixture", runner)
	checks, err := runtime.Preflight(context.Background(), model.RoleGateway, manifest)
	if err != nil {
		t.Fatal(err)
	}
	foundIncompatible := false
	for _, check := range checks {
		if check.Component == "nftables" {
			foundIncompatible = !check.Compatible
		}
	}
	if !foundIncompatible {
		t.Fatalf("incompatible checks = %+v", checks)
	}
	runner.calls = nil
	if err := runtime.QuiesceManagement(context.Background(), model.RoleGateway); err != nil {
		t.Fatal(err)
	}
	if err := runtime.ActivateAndHealth(context.Background(), model.RoleGateway, UpdateComponentChange{Name: "vpnctl", TargetVersion: "v2.1.0"}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.ResumeManagement(context.Background(), model.RoleGateway); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl stop vpnctl-controller.service", "/fixture/usr/local/bin/vpnctl version",
		"systemctl start vpnctl-controller.service", "systemctl is-active --quiet vpnctl-controller.service",
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("management calls = %q, want %q", runner.calls, want)
	}
}

func TestSystemUpdateRuntimeDoesNotControlGatewayServiceOnNode(t *testing.T) {
	runner := &updateSystemRunner{versions: map[string]string{}}
	runtime, _ := NewSystemUpdateHostRuntime("/", runner)
	if err := runtime.QuiesceManagement(context.Background(), model.RoleNode); err != nil {
		t.Fatal(err)
	}
	if err := runtime.ResumeManagement(context.Background(), model.RoleNode); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("node update controlled gateway service: %q", runner.calls)
	}
}

func TestSystemUpdateRuntimeVerifiesExactRestoredVPNCTLVersion(t *testing.T) {
	runner := &updateSystemRunner{versions: map[string]string{}, binaryVersion: "v2.0.0"}
	runtime, _ := NewSystemUpdateHostRuntime("/fixture", runner)
	change := UpdateComponentChange{Name: "vpnctl", CurrentVersion: "v2.0.0", TargetVersion: "v2.1.0"}
	if err := runtime.RollbackAndHealth(context.Background(), model.RoleGateway, change); err != nil {
		t.Fatal(err)
	}
	runner.binaryVersion = "v2.0.1"
	if err := runtime.RollbackAndHealth(context.Background(), model.RoleGateway, change); err == nil {
		t.Fatal("rollback health accepted the wrong vpnctl version")
	}
}

type updateSystemRunner struct {
	versions      map[string]string
	binaryVersion string
	calls         []string
}

func (runner *updateSystemRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	key := strings.TrimSpace(command.Name + " " + strings.Join(command.Args, " "))
	runner.calls = append(runner.calls, key)
	switch command.Name {
	case "dpkg-query":
		name := command.Args[len(command.Args)-1]
		installed, found := runner.versions[name]
		if !found {
			return linuxplatform.ProbeResult{ExitCode: 1}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte("install ok installed\t" + installed + "\n")}, nil
	case "dpkg":
		installed, operation, boundary := command.Args[1], command.Args[2], command.Args[3]
		compatible := true
		if installed == "0.9" && operation == "ge" {
			compatible = false
		}
		if boundary == "" {
			return linuxplatform.ProbeResult{}, fmt.Errorf("empty version boundary")
		}
		if !compatible {
			return linuxplatform.ProbeResult{ExitCode: 1}, nil
		}
		return linuxplatform.ProbeResult{}, nil
	case "systemctl":
		return linuxplatform.ProbeResult{}, nil
	default:
		if strings.HasSuffix(command.Name, "/usr/local/bin/vpnctl") {
			version := runner.binaryVersion
			if version == "" {
				version = "v2.1.0"
			}
			return linuxplatform.ProbeResult{Stdout: []byte("vpnctl " + version + "\n")}, nil
		}
		return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected command %s", key)
	}
}
