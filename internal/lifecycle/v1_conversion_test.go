package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/mihomo"
	"github.com/vgrinkevich/vpnctl/internal/model"
	v1state "github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestV1ConversionStagesDeterministicValidatedGatewayGolden(t *testing.T) {
	workspace, systemRoot, serverPrivate, clientPrivate := completeV1InspectionFixture(t)
	writeExactV1ClashProfile(t, workspace, clientPrivate)
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
	if inspection.Report.Status != V1InspectionReady {
		t.Fatalf("fixture inspection status = %s: %+v", inspection.Report.Status, inspection.Report.Issues)
	}

	parent := canonicalConversionTestRoot(t)
	input := V1ConversionInput{
		Inspection: &inspection, PublicIPv4: "8.8.4.4", SSHPort: 22,
		ConvertedAt: time.Date(2026, time.September, 4, 12, 30, 0, 0, time.UTC),
		Components:  gatewayTestManifest(), HandshakeHost: gatewayTestHandshakeHost(),
	}
	input.StageRoot = filepath.Join(parent, "stage-one")
	first, err := ConvertV1ToV2Stage(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	input.StageRoot = filepath.Join(parent, "stage-two")
	second, err := ConvertV1ToV2Stage(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated conversion result differs:\nfirst=%#v\nsecond=%#v", first, second)
	}
	firstTree := snapshotV1ConversionStage(t, filepath.Join(parent, "stage-one"))
	secondTree := snapshotV1ConversionStage(t, filepath.Join(parent, "stage-two"))
	if !reflect.DeepEqual(firstTree, secondTree) {
		t.Fatal("two independent conversions did not produce byte-identical logical stage trees")
	}
	after := snapshotV1InspectionTrees(t, workspace, systemRoot)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("conversion changed the inspected v1 installation")
	}

	assertV1ConversionGolden(t, first)
	paths, err := store.NewPaths(filepath.Join(parent, "stage-one"))
	if err != nil {
		t.Fatal(err)
	}
	stateStore, _ := store.NewStateStore(paths)
	converted, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := converted.Validate(); err != nil {
		t.Fatal(err)
	}
	if converted.Generation != 1 || converted.Host.Role != model.RoleGateway || converted.Host.PublicIPv4 != "8.8.4.4" ||
		converted.Host.ClientCIDR != model.DefaultClientCIDR || converted.Host.NodeCIDR != model.DefaultNodeCIDR ||
		converted.Host.ExternalInterface != "eth0" || converted.Host.SSHPort != 22 {
		t.Fatalf("converted host = %+v", converted.Host)
	}
	if len(converted.Clients) != 1 || converted.Clients[0].OverlayIPv4 != "10.66.0.2" ||
		!reflect.DeepEqual(converted.Clients[0].AssignedPresets, []string{"default"}) {
		t.Fatalf("converted clients = %+v", converted.Clients)
	}
	if len(converted.Presets) != 1 || converted.Presets[0].Name != "default" || len(converted.Presets[0].Selectors) != 4 ||
		len(converted.Policies) != 1 || converted.Policies[0].TargetID != converted.Clients[0].ID {
		t.Fatalf("converted preset/policy = %+v / %+v", converted.Presets, converted.Policies)
	}
	if len(converted.Transports) != 1 || converted.Transports[0].State != model.TransportActive ||
		converted.Transports[0].OwnerID != converted.Clients[0].ID {
		t.Fatalf("converted transports = %+v", converted.Transports)
	}
	secretStore, _ := store.NewSecretStore(paths)
	assertV1ConvertedSecret(t, secretStore, transport.GatewayStandardCredentialRef, serverPrivate)
	assertV1ConvertedSecret(t, secretStore, converted.Transports[0].CredentialRef, clientPrivate)
	preserved := filepath.Join(paths.ExportsDir, "v1-preserved", "generated", "delivery", "iphone.clash.yaml")
	wantProfile := inspection.generated["generated/delivery/iphone.clash.yaml"]
	gotProfile, err := os.ReadFile(preserved)
	if err != nil || !bytes.Equal(gotProfile, wantProfile) {
		t.Fatalf("preserved Clash profile differs: %v", err)
	}
	encodedResult, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{first.String(), first.GoString(), fmt.Sprintf("%#v", first), string(encodedResult)} {
		if strings.Contains(rendered, serverPrivate) || strings.Contains(rendered, clientPrivate) ||
			strings.Contains(rendered, workspace) || strings.Contains(rendered, parent) {
			t.Fatal("conversion result exposed a credential or physical path")
		}
	}
}

func TestV1ConversionPreservesCanonicalUUIDAndMapsConflictsDeterministically(t *testing.T) {
	gatewayID := "10000000-0000-4000-8000-000000000001"
	preservedClient := "20000000-0000-4000-8000-000000000002"
	clients := []v1state.ClientState{{ID: "iphone"}, {ID: preservedClient}, {ID: gatewayID}}
	gateway, mappings := mapV1Identities(gatewayID, clients)
	if !gateway.IDPreserved || gateway.TargetID != gatewayID {
		t.Fatalf("gateway mapping = %+v", gateway)
	}
	if !mappings[preservedClient].IDPreserved || mappings[preservedClient].TargetID != preservedClient {
		t.Fatalf("preserved client mapping = %+v", mappings[preservedClient])
	}
	for _, source := range []string{"iphone", gatewayID} {
		mapping := mappings[source]
		if mapping.IDPreserved || !v2IdentityPattern.MatchString(mapping.TargetID) || mapping.TargetID == gatewayID {
			t.Fatalf("mapped client %s = %+v", source, mapping)
		}
	}
	_, repeated := mapV1Identities(gatewayID, clients)
	if !reflect.DeepEqual(mappings, repeated) {
		t.Fatal("identity mapping is not deterministic")
	}
}

func TestV1ConversionRefusesInvalidOrExistingStageWithoutMutation(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	inspector, _ := NewV1InstallationInspector(workspace, systemRoot)
	inspection, err := inspector.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parent := canonicalConversionTestRoot(t)
	existing := filepath.Join(parent, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(existing, "canary")
	if err := os.WriteFile(canary, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := V1ConversionInput{
		Inspection: &inspection, StageRoot: existing, PublicIPv4: "8.8.4.4", SSHPort: 22,
		ConvertedAt: time.Date(2026, time.September, 4, 12, 30, 0, 0, time.UTC),
		Components:  gatewayTestManifest(), HandshakeHost: gatewayTestHandshakeHost(),
	}
	if _, err := ConvertV1ToV2Stage(context.Background(), base); !errors.Is(err, ErrV1StageExists) {
		t.Fatalf("existing stage error = %v", err)
	}
	if data, err := os.ReadFile(canary); err != nil || string(data) != "keep" {
		t.Fatalf("existing stage canary changed: %q, %v", data, err)
	}
	inspection.Destroy()
	base.StageRoot = filepath.Join(parent, "destroyed")
	if _, err := ConvertV1ToV2Stage(context.Background(), base); !errors.Is(err, ErrV1ConversionNotReady) {
		t.Fatalf("destroyed inspection error = %v", err)
	}
	if _, err := os.Lstat(base.StageRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid conversion created a stage: %v", err)
	}
}

type v1ConversionStageFile struct {
	Mode fs.FileMode
	Data []byte
}

func snapshotV1ConversionStage(t *testing.T, root string) map[string]v1ConversionStageFile {
	t.Helper()
	files := map[string]v1ConversionStageFile{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			t.Fatalf("stage contains symlink %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("stage contains a non-regular artifact")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = v1ConversionStageFile{Mode: info.Mode().Perm(), Data: data}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func canonicalConversionTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(root)
}

func writeExactV1ClashProfile(t *testing.T, workspace, privateKey string) {
	t.Helper()
	stateDir := filepath.Join(workspace, ".vpnctl")
	state, err := v1state.Load(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := v1state.LoadRuleset(stateDir, "default")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := mihomo.RenderConfig(mihomo.Config{
		DNSServers: state.Server.DNSServers, Server: state.Server.PublicEndpoint, Port: state.Server.WireGuardPort,
		ClientIP: state.Clients[0].AssignedIP, PrivateKey: privateKey, ServerPublicKey: state.Server.WireGuardPublicKey,
		RulesetType: ruleset.Type, Domains: ruleset.Domains,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeV1FixtureFile(t, filepath.Join(stateDir, "generated", "delivery", "iphone.clash.yaml"), []byte(profile), 0o600)
}

func assertV1ConvertedSecret(t *testing.T, secrets *store.SecretStore, reference model.SecretRef, want string) {
	t.Helper()
	got, err := secrets.Get(reference)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { clear(got) }()
	if string(got) != want {
		t.Fatalf("converted secret %s differs", reference)
	}
}

func assertV1ConversionGolden(t *testing.T, result V1ConversionResult) {
	t.Helper()
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	golden, err := os.ReadFile(filepath.Join("testdata", "v1_conversion_result.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, golden) {
		t.Fatalf("conversion result differs from golden:\n%s", encoded)
	}
}
