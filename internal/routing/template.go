package routing

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
)

const BuiltinPresetTemplateRevision = 1

//go:embed templates/*.yaml
var builtinPresetTemplateFiles embed.FS

// BuiltinPresetTemplate is immutable release input. Source returns as an
// independent byte slice so callers cannot modify the embedded catalog. The
// installed copy becomes user-owned source immediately after fresh init.
type BuiltinPresetTemplate struct {
	Name     string
	Filename string
	Revision uint64
	SHA256   string
	Source   []byte
}

// BuiltinPresetTemplates returns the complete catalog in stable display and
// installation order. Merely reading the catalog has no filesystem effects.
func BuiltinPresetTemplates() ([]BuiltinPresetTemplate, error) {
	templates := make([]BuiltinPresetTemplate, 0, len(builtinPresetTemplateNames))
	for _, name := range builtinPresetTemplateNames {
		filename := name + ".yaml"
		source, err := builtinPresetTemplateFiles.ReadFile("templates/" + filename)
		if err != nil {
			return nil, fmt.Errorf("read embedded preset template %s: %w", name, err)
		}
		ast, err := DecodePresetDocument(source)
		if err != nil {
			return nil, fmt.Errorf("validate embedded preset template %s: %w", name, err)
		}
		if ast.Name != name {
			return nil, fmt.Errorf("embedded preset template %s declares name %s", name, ast.Name)
		}
		digest := sha256.Sum256(source)
		templates = append(templates, BuiltinPresetTemplate{
			Name: name, Filename: filename, Revision: BuiltinPresetTemplateRevision,
			SHA256: hex.EncodeToString(digest[:]), Source: append([]byte(nil), source...),
		})
	}
	return templates, nil
}

var builtinPresetTemplateNames = [...]string{"telegram", "openai", "anthropic"}
