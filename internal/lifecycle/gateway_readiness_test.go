package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayBootstrapReadinessIsPassiveAndReportsEveryMissingBoundary(t *testing.T) {
	t.Parallel()
	paths, state, manifest := gatewayReadinessFixture(t)
	packages := &readinessPackages{plan: readinessPackagePlan(manifest, false)}
	runner := &readinessRunner{missing: true}
	inspector, err := NewGatewayBootstrapReadinessInspector(paths, packages, runner)
	if err != nil {
		t.Fatal(err)
	}
	report, err := inspector.Inspect(context.Background(), state, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready || report.CandidateSHA256 == "" {
		t.Fatalf("missing readiness = %+v", report)
	}
	for _, code := range []string{
		"package_missing", "nginx_drop_in_missing", "nginx_tree_missing", "nginx_service_unavailable",
		"nginx_runtime_unavailable", "public_https_observation_unavailable", "enrollment_loopback_observation_unavailable",
	} {
		if !gatewayReadinessHasCode(report, code) {
			t.Errorf("missing readiness code %q in %+v", code, report.Checks)
		}
	}
	for _, command := range runner.commands {
		joined := command.Name + " " + strings.Join(command.Args, " ")
		for _, forbidden := range []string{"apt-get", " update", " install", " start", " stop", " restart", " reload", " enable", " disable", " mask", " unmask"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("readiness mutated host with %q", joined)
			}
		}
	}
}

func TestGatewayBootstrapReadinessAcceptsOnlyExactOwnedRuntime(t *testing.T) {
	t.Parallel()
	paths, state, manifest := gatewayReadinessFixture(t)
	candidate := materializeGatewayReadinessIngress(t, paths, state)
	packages := &readinessPackages{plan: readinessPackagePlan(manifest, true)}
	runner := &readinessRunner{}
	inspector, _ := NewGatewayBootstrapReadinessInspector(paths, packages, runner)
	report, err := inspector.Inspect(context.Background(), state, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready || report.CandidateSHA256 != candidate.ConfigHash() {
		t.Fatalf("healthy readiness = %+v", report)
	}
	for _, check := range report.Checks {
		if check.Condition != GatewayReadinessHealthy {
			t.Fatalf("unhealthy check = %+v", check)
		}
	}

	current := ingress.NginxActiveRoot(paths)
	link, err := os.Readlink(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("generations", strings.Replace(link, "g1-", "g2-", 1)), current); err != nil {
		t.Fatal(err)
	}
	report, err = inspector.Inspect(context.Background(), state, manifest)
	if err != nil || report.Ready || !gatewayReadinessHasCode(report, "nginx_tree_drifted") {
		// The forged link points at an absent generation and is classified as
		// structural drift; Inspect must never adopt it as a mere missing tree.
		t.Fatalf("foreign active tree was not classified: report=%+v err=%v", report, err)
	}
}

func TestGatewayBootstrapReadinessRetainsHealthyTreeAcrossMetadataOnlyGeneration(t *testing.T) {
	t.Parallel()
	paths, state, manifest := gatewayReadinessFixture(t)
	active := materializeGatewayReadinessIngress(t, paths, state)
	inspector, err := NewGatewayBootstrapReadinessInspector(
		paths,
		&readinessPackages{plan: readinessPackagePlan(manifest, true)},
		&readinessRunner{},
	)
	if err != nil {
		t.Fatal(err)
	}

	state.Generation++
	report, err := inspector.Inspect(context.Background(), state, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready || report.Generation != state.Generation || report.CandidateSHA256 != active.ConfigHash() ||
		gatewayReadinessHasCode(report, "nginx_tree_generation_mismatch") {
		t.Fatalf("metadata-only generation invalidated ingress: %+v", report)
	}

	state.Host.PublicIPv4 = "203.0.113.11"
	report, err = inspector.Inspect(context.Background(), state, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready || !gatewayReadinessHasCode(report, "nginx_tree_generation_mismatch") || report.CandidateSHA256 == active.ConfigHash() {
		t.Fatalf("semantic ingress change retained stale tree: %+v", report)
	}
}

func TestGatewayBootstrapReadinessRejectsNginxVersionPrefix(t *testing.T) {
	t.Parallel()
	paths, state, manifest := gatewayReadinessFixture(t)
	materializeGatewayReadinessIngress(t, paths, state)
	runner := &readinessRunner{nginxVersion: ingress.NginxProviderRuntimeVersion + ".1"}
	inspector, _ := NewGatewayBootstrapReadinessInspector(paths, &readinessPackages{plan: readinessPackagePlan(manifest, true)}, runner)
	report, err := inspector.Inspect(context.Background(), state, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready || !gatewayReadinessHasCode(report, "nginx_runtime_incompatible") {
		t.Fatalf("nginx version prefix was accepted: %+v", report)
	}
}

func gatewayReadinessFixture(t *testing.T) (store.Paths, model.State, ReleaseManifest) {
	t.Helper()
	root := t.TempDir()
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := releaseManifestFixture()
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	handshake := model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: manifest.ComponentManifest.HandshakeHostListVersion,
		CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now,
	}
	state := initialGatewayState("a1000000-0000-4000-8000-000000000001", now, linuxplatform.GatewayNetworkPlan{
		PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
	}, 22, manifest.ComponentManifest, handshake)
	state.Certificates = append(state.Certificates, model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: "a1000000-0000-4000-8000-000000000002",
		Kind: model.CertificatePublicIngress, OwnerKind: "host", OwnerID: state.Host.ID,
		Fingerprint: "sha256:" + strings.Repeat("a", 64), SerialHex: "01", Subject: "CN=" + state.Host.PublicIPv4,
		SANs: []string{"IP:" + state.Host.PublicIPv4}, NotBefore: now, NotAfter: now.Add(ingress.PublicCertificateValidity),
		WarningDays: ingress.PublicCertificateWarningDays, Generation: 1,
		CertificateRef: ingress.PublicCertificateRef, PrivateKeyRef: ingress.PublicCertificatePrivateKeyRef,
	})
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	return paths, state, manifest
}

func materializeGatewayReadinessIngress(t *testing.T, paths store.Paths, state model.State) ingress.NginxCandidate {
	t.Helper()
	for _, directory := range []string{
		filepath.Dir(ingress.NginxServiceDropInPath(paths)),
		filepath.Join(ingress.NginxGeneratedRoot(paths), "generations"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(ingress.NginxGeneratedRoot(paths), "generations"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ingress.NginxGeneratedRoot(paths), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ingress.NginxServiceDropInPath(paths), ingress.RenderNginxServiceDropIn(paths), 0o644); err != nil {
		t.Fatal(err)
	}
	certificatePath, _ := gatewayInitSecretPath(paths, model.SecretRef(ingress.PublicCertificateRef))
	privateKeyPath, _ := gatewayInitSecretPath(paths, ingress.PublicCertificatePrivateKeyRef)
	candidate, err := ingress.RenderNginxConfig(ingress.NginxRenderRequest{
		StateGeneration: state.Generation, PublicIPv4: state.Host.PublicIPv4,
		CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath,
		RuntimeDirectory: ingress.NginxRuntimeDirectory(paths), Limits: ingress.DefaultGatewayHardLimits(), Exposes: state.Exposes,
	})
	if err != nil {
		t.Fatal(err)
	}
	name := "g1-" + candidate.ConfigHash()
	generation := filepath.Join(ingress.NginxGeneratedRoot(paths), "generations", name)
	if err := os.Mkdir(generation, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(generation, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range candidate.Artifacts() {
		path := filepath.Join(generation, filepath.FromSlash(artifact.RelativePath()))
		if err := os.WriteFile(path, artifact.Bytes(), artifact.Mode()); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("generations", name), ingress.NginxActiveRoot(paths)); err != nil {
		t.Fatal(err)
	}
	return candidate
}

func readinessPackagePlan(manifest ReleaseManifest, present bool) RolePackagePlan {
	action := RolePackageInstall
	installed, candidate := "", "1.24.0-2ubuntu7.17"
	if present {
		action, installed, candidate = RolePackagePresent, "1.24.0-2ubuntu7.17", ""
	}
	return RolePackagePlan{
		SchemaVersion: RolePackagePlanSchemaVersion, Role: model.RoleGateway,
		ManifestSHA256: readinessSHA256([]byte("readiness-manifest")),
		Packages: []RolePackagePlanItem{{
			Component: "nginx", Package: "nginx", Source: "ubuntu:noble-updates",
			MinimumVersion: "1.24.0-2ubuntu7.17", MaximumVersionExclusive: "1.25",
			InstalledVersion: installed, CandidateVersion: candidate, Action: action,
		}},
	}
}

type readinessPackages struct {
	plan RolePackagePlan
	err  error
}

func (packages *readinessPackages) Plan(context.Context, ReleaseManifest, model.Role) (RolePackagePlan, error) {
	return packages.plan, packages.err
}
func (*readinessPackages) Apply(context.Context, ReleaseManifest, RolePackagePlan) (RolePackageInstallation, error) {
	panic("readiness must not apply packages")
}
func (*readinessPackages) Commit(context.Context, RolePackageInstallation) error {
	panic("readiness must not commit packages")
}
func (*readinessPackages) Rollback(context.Context, RolePackageInstallation) error {
	panic("readiness must not roll back packages")
}

type readinessRunner struct {
	missing      bool
	nginxVersion string
	commands     []linuxplatform.ProbeCommand
}

func (runner *readinessRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.commands = append(runner.commands, command)
	if runner.missing {
		return linuxplatform.ProbeResult{ExitCode: 1}, nil
	}
	switch command.Name + " " + strings.Join(command.Args, " ") {
	case "systemctl show --no-pager --property=LoadState --property=ActiveState --property=SubState nginx.service":
		return linuxplatform.ProbeResult{Stdout: []byte("LoadState=loaded\nActiveState=active\nSubState=running\n")}, nil
	case "systemctl is-enabled nginx.service":
		return linuxplatform.ProbeResult{Stdout: []byte("enabled\n")}, nil
	}
	if command.Args != nil && reflect.DeepEqual(command.Args, []string{"-v"}) && strings.HasSuffix(command.Name, "/usr/sbin/nginx") {
		version := runner.nginxVersion
		if version == "" {
			version = ingress.NginxProviderRuntimeVersion
		}
		return linuxplatform.ProbeResult{Stderr: []byte("nginx version: nginx/" + version + "\n")}, nil
	}
	if reflect.DeepEqual(command.Args, []string{"-H", "-ltnp", "sport = :443"}) {
		return linuxplatform.ProbeResult{Stdout: []byte(`LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=40,fd=7))` + "\n")}, nil
	}
	if reflect.DeepEqual(command.Args, []string{"-H", "-ltnp", "sport = :19092"}) {
		return linuxplatform.ProbeResult{Stdout: []byte(`LISTEN 0 4096 127.0.0.1:19092 0.0.0.0:* users:(("vpnctl",pid=41,fd=8))` + "\n")}, nil
	}
	return linuxplatform.ProbeResult{}, nil
}

func gatewayReadinessHasCode(report GatewayBootstrapReadinessReport, code string) bool {
	for _, check := range report.Checks {
		if check.Code == code {
			return true
		}
	}
	return false
}
