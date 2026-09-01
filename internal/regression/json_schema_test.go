package regression

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

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
