package routing

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"go.yaml.in/yaml/v3"
)

const (
	PresetDocumentSchemaVersion = 1
	PresetMaximumDocumentBytes  = 256 << 10
	PresetMaximumSelectors      = 4096
)

type PresetDocument struct {
	SchemaVersion int                      `yaml:"schema_version" json:"schema_version"`
	Name          string                   `yaml:"name" json:"name"`
	Include       []PresetDocumentSelector `yaml:"include" json:"include"`
	Exclude       []PresetDocumentSelector `yaml:"exclude" json:"exclude"`
}

type PresetDocumentSelector struct {
	Type  model.SelectorKind `yaml:"type" json:"type"`
	Value string             `yaml:"value" json:"value"`
}

// PresetAST is provider-neutral. Selectors are canonical and sorted; the only
// semantic flag is exclusion. Routing actions and outbound identities cannot
// be represented, so a later compiler can only implement gateway-or-block.
type PresetAST struct {
	SchemaVersion int
	Name          string
	Selectors     []model.Selector
}

func DecodePresetDocument(data []byte) (PresetAST, error) {
	if len(data) == 0 {
		return PresetAST{}, fmt.Errorf("preset YAML document is empty")
	}
	if len(data) > PresetMaximumDocumentBytes {
		return PresetAST{}, fmt.Errorf("preset YAML document exceeds %d bytes", PresetMaximumDocumentBytes)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return PresetAST{}, fmt.Errorf("preset YAML document contains a NUL byte")
	}
	if err := validatePresetYAMLShape(data); err != nil {
		return PresetAST{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var document PresetDocument
	if err := decoder.Decode(&document); err != nil {
		return PresetAST{}, fmt.Errorf("decode preset YAML: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return PresetAST{}, fmt.Errorf("preset YAML must contain exactly one document")
		}
		return PresetAST{}, fmt.Errorf("decode trailing preset YAML: %w", err)
	}
	return document.Normalize()
}

func (document PresetDocument) Normalize() (PresetAST, error) {
	if document.SchemaVersion != PresetDocumentSchemaVersion {
		return PresetAST{}, fmt.Errorf("unsupported preset schema_version %d; want %d", document.SchemaVersion, PresetDocumentSchemaVersion)
	}
	if err := validatePresetName(document.Name); err != nil {
		return PresetAST{}, err
	}
	if document.Include == nil || document.Exclude == nil {
		return PresetAST{}, fmt.Errorf("preset include and exclude must be present as YAML arrays")
	}
	if len(document.Include) == 0 {
		return PresetAST{}, fmt.Errorf("preset must contain at least one include selector")
	}
	if len(document.Include)+len(document.Exclude) > PresetMaximumSelectors {
		return PresetAST{}, fmt.Errorf("preset exceeds %d total selectors", PresetMaximumSelectors)
	}
	selectors := make([]model.Selector, 0, len(document.Include)+len(document.Exclude))
	seen := make(map[string]struct{}, len(document.Include)+len(document.Exclude))
	appendSelectors := func(values []PresetDocumentSelector, exclude bool) error {
		for index, value := range values {
			selector := model.Selector{Kind: value.Type, Value: value.Value, Exclude: exclude}
			if err := selector.Validate(); err != nil {
				section := "include"
				if exclude {
					section = "exclude"
				}
				return fmt.Errorf("%s[%d]: %w", section, index, err)
			}
			key := string(selector.Kind) + "\x00" + selector.Value + fmt.Sprintf("\x00%t", selector.Exclude)
			if _, duplicate := seen[key]; duplicate {
				section := "include"
				if exclude {
					section = "exclude"
				}
				return fmt.Errorf("preset duplicates %s selector %s:%s", section, selector.Kind, selector.Value)
			}
			seen[key] = struct{}{}
			selectors = append(selectors, selector)
		}
		return nil
	}
	if err := appendSelectors(document.Include, false); err != nil {
		return PresetAST{}, err
	}
	if err := appendSelectors(document.Exclude, true); err != nil {
		return PresetAST{}, err
	}
	sort.Slice(selectors, func(left, right int) bool {
		return presetSelectorLess(selectors[left], selectors[right])
	})
	ast := PresetAST{SchemaVersion: PresetDocumentSchemaVersion, Name: document.Name, Selectors: selectors}
	if err := ast.Validate(); err != nil {
		return PresetAST{}, err
	}
	return ast, nil
}

func (ast PresetAST) Validate() error {
	if ast.SchemaVersion != PresetDocumentSchemaVersion {
		return fmt.Errorf("unsupported preset AST schema_version %d", ast.SchemaVersion)
	}
	if err := validatePresetName(ast.Name); err != nil {
		return err
	}
	if len(ast.Selectors) == 0 || len(ast.Selectors) > PresetMaximumSelectors {
		return fmt.Errorf("preset AST selector count is outside the accepted range")
	}
	includeCount := 0
	for index, selector := range ast.Selectors {
		if err := selector.Validate(); err != nil {
			return fmt.Errorf("selectors[%d]: %w", index, err)
		}
		if !selector.Exclude {
			includeCount++
		}
		if index > 0 && !presetSelectorLess(ast.Selectors[index-1], selector) {
			return fmt.Errorf("preset AST selectors must be strictly sorted and unique")
		}
	}
	if includeCount == 0 {
		return fmt.Errorf("preset AST requires at least one include selector")
	}
	return nil
}

func validatePresetYAMLShape(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("parse preset YAML: %w", err)
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("preset YAML root must be a mapping")
	}
	if err := rejectYAMLIndirection(root.Content[0]); err != nil {
		return err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("preset YAML must contain exactly one document")
		}
		return fmt.Errorf("parse trailing preset YAML: %w", err)
	}
	return nil
}

func rejectYAMLIndirection(node *yaml.Node) error {
	if node == nil {
		return fmt.Errorf("preset YAML contains an empty node")
	}
	if node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" {
		return fmt.Errorf("preset YAML aliases and anchors are not supported")
	}
	if node.Tag != "" && node.Tag != "!!map" && node.Tag != "!!seq" && node.Tag != "!!str" && node.Tag != "!!int" {
		return fmt.Errorf("preset YAML tag %q is not supported", node.Tag)
	}
	for _, child := range node.Content {
		if err := rejectYAMLIndirection(child); err != nil {
			return err
		}
	}
	return nil
}

func validatePresetName(value string) error {
	if value == "" || len(value) > 63 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("preset name must be a non-empty single-line identifier of at most 63 bytes")
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return fmt.Errorf("preset name must start with an alphanumeric character and contain only letters, digits, dots, underscores, or dashes")
	}
	return nil
}

func presetSelectorLess(left, right model.Selector) bool {
	if left.Exclude != right.Exclude {
		return !left.Exclude
	}
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	return left.Value < right.Value
}
