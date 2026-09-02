package regression

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/routing"
	"go.yaml.in/yaml/v3"
)

func TestV2PresetYAMLSchemaAndParserAgreeOnPublicBoundary(t *testing.T) {
	t.Parallel()
	schema := resolveV2SchemaFile(t, filepath.Join(v2SchemaRoot(), "preset-v1.schema.json"))
	examplePath := filepath.Join(v2SchemaRoot(), "preset-v1.example.yaml")
	example, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := yaml.Unmarshal(example, &document); err != nil {
		t.Fatalf("decode preset example: %v", err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("preset example does not validate against public schema: %v", err)
	}
	ast, err := routing.DecodePresetDocument(example)
	if err != nil || ast.Name != "telegram" || len(ast.Selectors) != 4 {
		t.Fatalf("preset example AST = %#v, %v", ast, err)
	}

	invalid := map[string]string{
		"action":            "schema_version: 1\nname: bad\naction: DIRECT\ninclude: [{type: domain, value: example.com}]\nexclude: []\n",
		"outbound":          "schema_version: 1\nname: bad\noutbound: proxy\ninclude: [{type: domain, value: example.com}]\nexclude: []\n",
		"raw-mihomo":        "schema_version: 1\nname: bad\nmihomo: {rules: [MATCH,DIRECT]}\ninclude: [{type: domain, value: example.com}]\nexclude: []\n",
		"unknown-selector":  "schema_version: 1\nname: bad\ninclude: [{type: geosite, value: telegram}]\nexclude: []\n",
		"selector-action":   "schema_version: 1\nname: bad\ninclude: [{type: domain, value: example.com, action: direct}]\nexclude: []\n",
		"selector-outbound": "schema_version: 1\nname: bad\ninclude: [{type: domain, value: example.com, outbound: proxy}]\nexclude: []\n",
	}
	for name, source := range invalid {
		t.Run(name, func(t *testing.T) {
			var candidate any
			if err := yaml.Unmarshal([]byte(source), &candidate); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(candidate); err == nil {
				t.Fatal("public preset schema accepted forbidden input")
			}
			if ast, err := routing.DecodePresetDocument([]byte(source)); err == nil {
				t.Fatalf("runtime preset parser accepted forbidden input as %#v", ast)
			}
		})
	}
}
