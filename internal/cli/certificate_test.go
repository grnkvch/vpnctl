package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestCertificateGrammarShowExportAndValidation(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		args       []string
		action     string
		outputPath string
		jsonMode   bool
		wantError  bool
	}{
		{args: []string{"cert", "show"}, action: "show"},
		{args: []string{"--json", "cert", "show"}, action: "show", jsonMode: true},
		{args: []string{"cert", "export"}, action: "export"},
		{args: []string{"cert", "export", "/tmp/gateway.crt", "--json"}, action: "export", outputPath: "/tmp/gateway.crt", jsonMode: true},
		{args: []string{"cert"}, wantError: true},
		{args: []string{"cert", "rotate"}, wantError: true},
		{args: []string{"cert", "show", "extra"}, wantError: true},
		{args: []string{"cert", "export", "relative.crt"}, wantError: true},
		{args: []string{"cert", "export", "/tmp/a", "/tmp/b"}, wantError: true},
		{args: []string{"cert", "show", "--json", "--json"}, wantError: true},
	} {
		parsed, err := parseCertificateArguments(test.args)
		if (err != nil) != test.wantError {
			t.Fatalf("parseCertificateArguments(%v) error = %v", test.args, err)
		}
		if err == nil && (parsed.Action != test.action || parsed.OutputPath != test.outputPath || parsed.JSON != test.jsonMode) {
			t.Fatalf("parseCertificateArguments(%v) = %+v", test.args, parsed)
		}
	}
}

func TestExecuteCertificateShowAndExportExposeNoPrivateMaterial(t *testing.T) {
	paths, stateStore, secrets, privateCanary := cliPublicCertificateFixture(t)
	restore := stubCertificateCommand(t, paths, RoleGateway, stateStore, secrets)
	defer restore()
	certificate := stateStore.state.Certificates[0]
	certificateNow = func() time.Time { return certificate.NotAfter.Add(-ingress.PublicCertificateWarningWindow) }

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"cert", "show", "--json"}, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("cert show code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), privateCanary) || bytes.Contains(stdout.Bytes(), []byte("private_key")) ||
		bytes.Contains(stdout.Bytes(), []byte("certificate_ref")) {
		t.Fatalf("cert show leaked private/reference material: %s", stdout.Bytes())
	}
	var shown output.Result
	if err := json.Unmarshal(stdout.Bytes(), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Command != "cert.show" || shown.Status != output.StatusOK || shown.ExitCategory != output.CategorySuccess ||
		shown.Data["condition"] != string(ingress.PublicCertificateExpiring) || shown.Data["public_ipv4"] != stateStore.state.Host.PublicIPv4 ||
		len(shown.Warnings) != 1 || shown.Warnings[0].Code != "public_certificate_expiring" ||
		len(shown.RequiresAction) != 1 || shown.RequiresAction[0].Command != "sudo vpnctl cert rotate" {
		t.Fatalf("cert show result = %+v", shown)
	}

	stdout.Reset()
	if code := Execute([]string{"--json", "cert", "export"}, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("cert export code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var exported output.Result
	if err := json.Unmarshal(stdout.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	wantPath := ingress.DefaultPublicCertificateExportPath(paths.ExportsDir)
	if exported.Command != "cert.export" || exported.Data["output_path"] != wantPath || exported.Data["changed"] != true ||
		!strings.Contains(exported.Data["scp_command"].(string), "root@"+stateStore.state.Host.PublicIPv4+":"+wantPath) {
		t.Fatalf("cert export result = %+v", exported)
	}
	content, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, privateCanary) || bytes.Contains(content, []byte("PRIVATE KEY")) ||
		bytes.Contains(stdout.Bytes(), privateCanary) {
		t.Fatalf("cert export leaked private material: result=%s file=%s", stdout.Bytes(), content)
	}

	stdout.Reset()
	if code := Execute([]string{"cert", "export", "--json"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("idempotent cert export code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &exported); err != nil || exported.Data["changed"] != false {
		t.Fatalf("idempotent cert export result = %+v, %v", exported, err)
	}
}

func TestExecuteCertificateRejectsNodeAndExistingDifferentExport(t *testing.T) {
	paths, stateStore, secrets, _ := cliPublicCertificateFixture(t)
	restore := stubCertificateCommand(t, paths, RoleNode, stateStore, secrets)
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"cert", "show", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("node cert show code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	restore()

	restore = stubCertificateCommand(t, paths, RoleGateway, stateStore, secrets)
	defer restore()
	destination := filepath.Join(paths.ExportsDir, "occupied.crt")
	if err := os.WriteFile(destination, []byte("operator-owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"cert", "export", destination, "--json"}, &stdout, &stderr); code != ExitConflict {
		t.Fatalf("occupied cert export code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	content, _ := os.ReadFile(destination)
	if string(content) != "operator-owned\n" {
		t.Fatalf("occupied export changed to %q", content)
	}
}

type cliCertificateState struct{ state model.State }

func (source *cliCertificateState) Load() (model.State, error) { return source.state, nil }

func cliPublicCertificateFixture(t *testing.T) (store.Paths, *cliCertificateState, *store.SecretStore, []byte) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.StateDir, paths.SecretsDir, paths.ExportsDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	state := cliDNSState(model.RoleGateway)
	provisioner, err := ingress.NewPublicCertificateProvisioner(secrets, ingress.PublicCertificateRuntime{
		Entropy: rand.Reader,
		NewUUID: func() (string, error) { return "82000000-0000-4000-8000-000000000001", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	installation, err := provisioner.Provision(context.Background(), ingress.PublicCertificateRequest{
		GatewayID: state.Host.ID, PublicIPv4: state.Host.PublicIPv4, IssuedAt: state.Host.InitializedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	state.Certificates = []model.Certificate{installation.Certificate}
	privateKey, err := secrets.Get(ingress.PublicCertificatePrivateKeyRef)
	if err != nil {
		t.Fatal(err)
	}
	return paths, &cliCertificateState{state: state}, secrets, privateKey
}

func stubCertificateCommand(t *testing.T, paths store.Paths, role HostRole, stateSource certificateStateStore, secrets ingress.PublicCertificateSecretStore) func() {
	t.Helper()
	oldPaths, oldRole := certificateSystemPaths, certificateLoadRole
	oldState, oldSecrets, oldNow := certificateNewState, certificateNewSecrets, certificateNow
	certificateSystemPaths = func() store.Paths { return paths }
	certificateLoadRole = func(store.Paths) (HostRole, error) { return role, nil }
	certificateNewState = func(store.Paths) (certificateStateStore, error) { return stateSource, nil }
	certificateNewSecrets = func(store.Paths) (ingress.PublicCertificateSecretStore, error) { return secrets, nil }
	return func() {
		certificateSystemPaths, certificateLoadRole = oldPaths, oldRole
		certificateNewState, certificateNewSecrets, certificateNow = oldState, oldSecrets, oldNow
	}
}

func TestPublicCertificateShowOutputRejectsSensitiveFields(t *testing.T) {
	_, stateStore, _, privateCanary := cliPublicCertificateFixture(t)
	status, err := ingress.InspectPublicCertificate(stateStore.state, stateStore.state.Host.InitializedAt)
	if err != nil {
		t.Fatal(err)
	}
	result := publicCertificateShowResult(status)
	if err := result.Validate(); err != nil {
		t.Fatalf("public certificate show result: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{privateCanary, []byte("private_key"), []byte("certificate_ref"), []byte(ingress.PublicCertificatePrivateKeyRef)} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("certificate show output contains %q: %s", forbidden, encoded)
		}
	}
	if !reflect.DeepEqual(result.ResourceIDs, map[string]string{"certificate_id": status.CertificateID}) {
		t.Fatalf("certificate show resource IDs = %v", result.ResourceIDs)
	}
}

func TestPublicCertificateExportOutputUsesExplicitPublicPathClass(t *testing.T) {
	t.Parallel()

	result := publicCertificateExportResult("192.0.2.10", ingress.PublicCertificateExport{
		Path: "/var/lib/vpnctl/exports/gateway.crt", Fingerprint: "sha256:" + strings.Repeat("a", 64), Changed: true,
	})
	if err := result.Validate(); err != nil {
		t.Fatalf("public certificate export result: %v", err)
	}
	if _, forbidden := result.Data["path"]; forbidden || result.Data["output_path"] != "/var/lib/vpnctl/exports/gateway.crt" {
		t.Fatalf("public certificate export path fields = %+v", result.Data)
	}
}

func TestPublicCertificateExpiredShowIsUnavailableAndActionable(t *testing.T) {
	t.Parallel()

	status := ingress.PublicCertificateStatus{
		PublicIPv4: "192.0.2.10", CertificateID: "82000000-0000-4000-8000-000000000001",
		Fingerprint: "sha256:" + strings.Repeat("a", 64), SerialHex: "01", Subject: "CN=192.0.2.10",
		SANs: []string{"IP:192.0.2.10"}, NotBefore: time.Date(2021, 9, 5, 0, 0, 0, 0, time.UTC),
		NotAfter: time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC), WarningStartsAt: time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC),
		WarningDays: ingress.PublicCertificateWarningDays, Generation: 1, Condition: ingress.PublicCertificateExpired,
	}
	result := publicCertificateShowResult(status)
	if err := result.Validate(); err != nil {
		t.Fatalf("expired public certificate result: %v", err)
	}
	if result.Status != output.StatusDegraded || result.ExitCategory != output.CategoryUnavailable ||
		len(result.Warnings) != 1 || result.Warnings[0].Code != "public_certificate_expired" ||
		len(result.RequiresAction) != 1 || result.RequiresAction[0].Command != "sudo vpnctl cert rotate" {
		t.Fatalf("expired public certificate result = %+v", result)
	}
}

func TestCertificateCommandDependencyErrorsAreSanitized(t *testing.T) {
	paths, stateStore, secrets, privateCanary := cliPublicCertificateFixture(t)
	restore := stubCertificateCommand(t, paths, RoleGateway, stateStore, secrets)
	defer restore()
	certificateNewState = func(store.Paths) (certificateStateStore, error) {
		return nil, errors.New("private-key-canary-should-not-be-shown")
	}
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"cert", "show", "--json"}, &stdout, &stderr); code != ExitInternal {
		t.Fatalf("cert dependency error code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte("canary")) || bytes.Contains(stdout.Bytes(), privateCanary) {
		t.Fatalf("cert dependency error leaked detail: %s", stdout.Bytes())
	}
}
