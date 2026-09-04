package regression

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/vgrinkevich/vpnctl/internal/cli"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestV2EmitterCoversEveryResultFamilyAndKeepsStreamsSeparate(t *testing.T) {
	t.Parallel()

	examples := readV2JSONExamples(t)
	resolved := make(map[string]*jsonschema.Resolved)
	seenFamilies := make(map[string]struct{})
	for registryCommand, example := range examples {
		raw, err := json.Marshal(example.Result)
		if err != nil {
			t.Fatalf("marshal example %s: %v", registryCommand, err)
		}
		var result output.Result
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("decode example %s into result model: %v", registryCommand, err)
		}

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		emitter, err := cli.NewResultEmitter(&stdout, &stderr, true)
		if err != nil {
			t.Fatalf("create emitter for %s: %v", registryCommand, err)
		}
		if err := emitter.Progress("fixture progress"); err != nil {
			t.Fatalf("emit progress for %s: %v", registryCommand, err)
		}
		exitCode, err := emitter.Emit(result)
		if err != nil {
			t.Errorf("emit %s: %v", registryCommand, err)
			continue
		}
		if exitCode != cli.ExitSuccess {
			t.Errorf("example %s exit code = %d, want %d", registryCommand, exitCode, cli.ExitSuccess)
		}
		if stderr.String() != "fixture progress\n" {
			t.Errorf("example %s stderr = %q", registryCommand, stderr.String())
		}
		if bytes.Contains(stdout.Bytes(), []byte("fixture progress")) {
			t.Errorf("example %s leaked progress into JSON stdout", registryCommand)
		}

		decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
		var document map[string]any
		if err := decoder.Decode(&document); err != nil {
			t.Errorf("decode emitted %s document: %v", registryCommand, err)
			continue
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			t.Errorf("emitted %s contains more than one JSON document: %v", registryCommand, err)
		}
		schema := resolved[example.ResultSchema]
		if schema == nil {
			schema = resolveV2ResultSchema(t, example.ResultSchema)
			resolved[example.ResultSchema] = schema
		}
		if err := schema.Validate(document); err != nil {
			t.Errorf("emitted %s does not validate against %s: %v", registryCommand, example.ResultSchema, err)
		}
		seenFamilies[example.ResultSchema] = struct{}{}
	}

	for _, family := range []string{
		"artifact-v1", "collection-v1", "diagnostic-v1", "export-v1", "operation-v1",
		"plan-v1", "resource-v1", "secret-issue-v1", "status-v1", "validation-v1",
	} {
		if _, found := seenFamilies[family]; !found {
			t.Errorf("result family %s was not exercised through the emitter", family)
		}
	}
}

func TestV2JSONResultExamplesValidateAndCoverCLI(t *testing.T) {
	t.Parallel()

	contracts := readCLIJSONResultContracts(t)
	examples := readV2JSONExamples(t)
	resolved := make(map[string]*jsonschema.Resolved)

	for command, contract := range contracts {
		if contract == "plain-text" {
			if _, exists := examples[command]; exists {
				t.Errorf("plain-text command unexpectedly has a JSON example: %s", command)
			}
			continue
		}
		example, ok := examples[command]
		if !ok {
			t.Errorf("JSON-capable CLI command has no result example: %s", command)
			continue
		}
		parts := strings.Split(contract, ":")
		if len(parts) != 2 {
			t.Fatalf("invalid JSON result contract for %s: %s", command, contract)
		}
		if example.ResultSchema != parts[0] {
			t.Errorf("example schema for %s = %s, want %s", command, example.ResultSchema, parts[0])
			continue
		}
		if got, _ := example.Result["command"].(string); got != parts[1] {
			t.Errorf("example command ID for %s = %q, want %q", command, got, parts[1])
		}

		schema := resolved[example.ResultSchema]
		if schema == nil {
			schema = resolveV2ResultSchema(t, example.ResultSchema)
			resolved[example.ResultSchema] = schema
		}
		if err := schema.Validate(example.Result); err != nil {
			t.Errorf("JSON result example for %s does not validate against %s: %v", command, example.ResultSchema, err)
		}
	}
	for command := range examples {
		if _, ok := contracts[command]; !ok {
			t.Errorf("JSON result example has no CLI contract row: %s", command)
		}
	}
}

func TestV2CommonResultSchemaForbidsSensitiveFields(t *testing.T) {
	t.Parallel()

	schema := resolveV2SchemaFile(t, filepath.Join(v2SchemaRoot(), "common-result-v1.schema.json"))
	valid := map[string]any{
		"schema_version":  float64(1),
		"command":         "status",
		"status":          "ok",
		"exit_category":   "success",
		"resource_ids":    map[string]any{"node_id": "node-1"},
		"warnings":        []any{},
		"requires_action": []any{},
		"data":            map[string]any{"nested": map[string]any{"healthy": true}},
	}
	if err := schema.Validate(valid); err != nil {
		t.Fatalf("valid common result rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "top-level token",
			mutate: func(value map[string]any) {
				value["invite_token"] = "secret"
			},
		},
		{
			name: "nested private key",
			mutate: func(value map[string]any) {
				value["data"] = map[string]any{"nested": map[string]any{"private_key": "secret"}}
			},
		},
		{
			name: "sensitive resource identifier",
			mutate: func(value map[string]any) {
				value["resource_ids"] = map[string]any{"recovery_token": "secret"}
			},
		},
		{
			name: "request body in nested array",
			mutate: func(value map[string]any) {
				value["data"] = map[string]any{"items": []any{map[string]any{"request_body": "secret"}}}
			},
		},
		{
			name: "webhook path",
			mutate: func(value map[string]any) {
				value["data"] = map[string]any{"webhook_path": "/sensitive"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneJSONValue(t, valid)
			test.mutate(candidate)
			if err := schema.Validate(candidate); err == nil {
				t.Fatal("sensitive field unexpectedly validated")
			}
		})
	}
}

func TestV2StatusSchemaAcceptsFullProjectionAndRejectsCredentialReferences(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := regressionStatusState(now)
	key := operations.ManagedResourceKey{Component: "control", Kind: operations.ManagedResourceState, ID: "fleet"}
	resource := operations.ManagedResource{
		Key: key, RevisionSHA256: operations.ManagedFingerprint([]byte("state")), RuntimeSHA256: operations.ManagedFingerprint([]byte("runtime")),
		ApplyImpact: operations.ConvergenceImpactNone, RemoveImpact: operations.ConvergenceImpactNone,
	}
	manifest, err := operations.NewConvergenceManifest(1, []operations.ManagedResource{resource})
	if err != nil {
		t.Fatal(err)
	}
	planner, err := operations.NewConvergencePlanner(
		regressionStatusConvergenceSource{snapshot: operations.ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []operations.PendingOperation{}}},
		regressionStatusDiscovery{observed: []operations.OwnedResourceObservation{{Key: key, RuntimeSHA256: resource.RuntimeSHA256, RemoveImpact: resource.RemoveImpact}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := operations.NewStatusCollector(
		model.RoleNode, "v2.0.0", func() time.Time { return now }, regressionStatusStateSource{state: state}, planner,
		regressionStatusObserver{snapshot: operations.PassiveStatusSnapshot{Resources: []operations.PassiveStatusResource{
			{
				Class:     operations.PassiveStatusConnectivity,
				Resource:  operations.ManagedResourceKey{Component: "control", Kind: operations.ManagedResourceState, ID: "control"},
				Condition: operations.PassiveHealthy, Mandatory: true, Active: true, Version: "v2.0.0", Protocol: "1.0",
				Generation: 1, RuntimeSHA256: operations.ManagedFingerprint([]byte("control")), Code: "control_socket_ready",
			},
			{
				Class:     operations.PassiveStatusDataPlane,
				Resource:  operations.ManagedResourceKey{Component: "routing", Kind: operations.ManagedResourceUnit, ID: "vpnctl-routing.service"},
				Condition: operations.PassiveHealthy, Mandatory: true, Active: true, Version: "v1.19.30",
				Generation: 1, RuntimeSHA256: operations.ManagedFingerprint([]byte("routing")), Code: "process_ready",
			},
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := cli.RunStatus(context.Background(), cli.RoleNode, false, collector)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	schema := resolveV2ResultSchema(t, "status-v1")
	if err := schema.Validate(document); err != nil {
		t.Fatalf("full status projection does not validate: %v\n%s", err, encoded)
	}

	unsafe := cloneJSONValue(t, document)
	data := unsafe["data"].(map[string]any)
	data["resources"] = []any{map[string]any{
		"kind": "transport", "id": "node:id:restricted", "credential_ref": "secret:must-never-appear",
	}}
	if err := schema.Validate(unsafe); err == nil {
		t.Fatal("status schema accepted a credential reference")
	}
}

type v2JSONExample struct {
	RegistryCommand string         `json:"registry_command"`
	ResultSchema    string         `json:"result_schema"`
	Result          map[string]any `json:"result"`
}

func readV2JSONExamples(t *testing.T) map[string]v2JSONExample {
	t.Helper()
	path := filepath.Join(v2SchemaRoot(), "examples-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read v2 JSON examples: %v", err)
	}
	var document struct {
		SchemaVersion int             `json:"schema_version"`
		Examples      []v2JSONExample `json:"examples"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse v2 JSON examples: %v", err)
	}
	if document.SchemaVersion != 1 {
		t.Fatalf("JSON examples schema_version = %d, want 1", document.SchemaVersion)
	}
	result := make(map[string]v2JSONExample, len(document.Examples))
	for _, example := range document.Examples {
		if _, duplicate := result[example.RegistryCommand]; duplicate {
			t.Fatalf("duplicate JSON example for CLI command: %s", example.RegistryCommand)
		}
		result[example.RegistryCommand] = example
	}
	return result
}

func readCLIJSONResultContracts(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "v2", "CLI_CONTRACT.md")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open v2 CLI contract: %v", err)
	}
	defer file.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "| `vpnctl ") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) != 10 {
			t.Fatalf("invalid v2 CLI registry row: %s", line)
		}
		command := strings.Trim(strings.TrimSpace(columns[1]), "`")
		contract := strings.Trim(strings.TrimSpace(columns[2]), "`")
		if _, duplicate := result[command]; duplicate {
			t.Fatalf("duplicate v2 CLI registry command: %s", command)
		}
		result[command] = contract
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan v2 CLI contract: %v", err)
	}
	return result
}

func resolveV2ResultSchema(t *testing.T, name string) *jsonschema.Resolved {
	t.Helper()
	return resolveV2SchemaFile(t, filepath.Join(v2SchemaRoot(), "results", name+".schema.json"))
}

func resolveV2SchemaFile(t *testing.T, path string) *jsonschema.Resolved {
	t.Helper()
	schema, err := readJSONSchema(path)
	if err != nil {
		t.Fatalf("read JSON schema %s: %v", path, err)
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{
		Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
			const uriPrefix = "/schemas/v2/"
			if uri.Scheme != "https" || uri.Host != "vpnctl.dev" || !strings.HasPrefix(uri.Path, uriPrefix) {
				return nil, fmt.Errorf("unsupported schema URI: %s", uri)
			}
			localPath := filepath.Join(v2SchemaRoot(), filepath.FromSlash(strings.TrimPrefix(uri.Path, uriPrefix)))
			return readJSONSchema(localPath)
		},
	})
	if err != nil {
		t.Fatalf("resolve JSON schema %s: %v", path, err)
	}
	return resolved
}

func readJSONSchema(path string) (*jsonschema.Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, err
	}
	return &schema, nil
}

func v2SchemaRoot() string {
	return filepath.Join("..", "..", "docs", "v2", "schemas")
}

func cloneJSONValue(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON clone: %v", err)
	}
	var clone map[string]any
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatalf("unmarshal JSON clone: %v", err)
	}
	return clone
}

type regressionStatusStateSource struct{ state model.State }

func (source regressionStatusStateSource) ReadStatusState(context.Context) (model.State, error) {
	return source.state, nil
}

type regressionStatusConvergenceSource struct {
	snapshot operations.ConvergenceSnapshot
}

func (source regressionStatusConvergenceSource) ReadConvergenceSnapshot(context.Context) (operations.ConvergenceSnapshot, error) {
	return source.snapshot, nil
}

type regressionStatusDiscovery struct {
	observed []operations.OwnedResourceObservation
}

func (source regressionStatusDiscovery) DiscoverOwnedResources(context.Context, operations.ConvergenceManifest) ([]operations.OwnedResourceObservation, error) {
	return append([]operations.OwnedResourceObservation{}, source.observed...), nil
}

type regressionStatusObserver struct {
	snapshot operations.PassiveStatusSnapshot
}

func (source regressionStatusObserver) ReadPassiveStatus(context.Context, model.State) (operations.PassiveStatusSnapshot, error) {
	return source.snapshot, nil
}

func regressionStatusState(now time.Time) model.State {
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			Role: model.RoleNode, OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: now,
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{},
		Policies: []model.Policy{}, Transports: []model.Transport{}, Exposes: []model.Expose{},
		Certificates: []model.Certificate{}, Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
			Components: []model.ComponentPin{{
				Name: "vpnctl", Version: "v2.0.0", Source: "bundle:vpnctl", Bundled: true,
				SHA256: strings.Repeat("a", 64), Capabilities: []string{"cli", "controller"},
			}},
		},
	}
}
