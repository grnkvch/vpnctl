package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

var humanScalarFields = map[string]struct{}{
	"changed":          {},
	"displayed_to_tty": {},
	"expires_at":       {},
	"file_mode":        {},
	"generation":       {},
	"impact":           {},
	"operation_id":     {},
	"output_path":      {},
	"overall":          {},
	"role":             {},
	"scope":            {},
	"sha256":           {},
	"valid":            {},
}

// RenderHuman writes a deterministic concise view. It intentionally ignores
// arbitrary structured data: command-specific renderers may add safe detail,
// while profiles, request bodies, and opaque config never become generic text.
func RenderHuman(writer io.Writer, result Result) error {
	if writer == nil {
		return fmt.Errorf("human output writer must not be nil")
	}
	if err := result.Validate(); err != nil {
		return fmt.Errorf("validate result: %w", err)
	}

	var output strings.Builder
	fmt.Fprintf(&output, "%s %s\n", strings.ToUpper(string(result.Status)), result.Command)
	writeIdentifiers(&output, result.ResourceIDs, "")
	writeHumanData(&output, result.Data)
	for _, warning := range result.Warnings {
		fmt.Fprintf(&output, "warning %s: %s\n", warning.Code, warning.Message)
		writeIdentifiers(&output, warning.ResourceIDs, "  ")
	}
	for _, action := range result.RequiresAction {
		fmt.Fprintf(&output, "action %s: %s\n", action.Code, action.Message)
		writeIdentifiers(&output, action.ResourceIDs, "  ")
		if action.Command != "" {
			fmt.Fprintf(&output, "  %s\n", action.Command)
		}
	}
	if _, err := io.WriteString(writer, output.String()); err != nil {
		return fmt.Errorf("write human result: %w", err)
	}
	return nil
}

func writeIdentifiers(output *strings.Builder, identifiers map[string]string, prefix string) {
	keys := make([]string, 0, len(identifiers))
	for key := range identifiers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(output, "%s%s: %s\n", prefix, humanLabel(key), identifiers[key])
	}
}

func writeHumanData(output *strings.Builder, data SafeObject) {
	keys := make([]string, 0, len(data))
	for key := range data {
		if _, visible := humanScalarFields[key]; visible && humanScalar(data[key]) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(output, "%s: %v\n", humanLabel(key), data[key])
	}
}

func humanScalar(value any) bool {
	switch typed := value.(type) {
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return true
	case string:
		return len(typed) <= MaximumSafeString && !strings.ContainsAny(typed, "\r\n\x00")
	default:
		return false
	}
}

func humanLabel(value string) string {
	return strings.ReplaceAll(value, "_", " ")
}
