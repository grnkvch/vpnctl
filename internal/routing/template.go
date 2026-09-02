package routing

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

const BuiltinPresetTemplateRevision = 1

//go:embed templates
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
		template, err := validateBuiltinPresetTemplate(BuiltinPresetTemplate{
			Name: name, Filename: filename, Revision: BuiltinPresetTemplateRevision,
			SHA256: hex.EncodeToString(digest[:]), Source: append([]byte(nil), source...),
		})
		if err != nil {
			return nil, fmt.Errorf("validate embedded preset template metadata %s: %w", name, err)
		}
		templates = append(templates, template)
	}
	return templates, nil
}

// BuiltinPresetTemplateHistory returns current templates plus every retained
// adjacent base under templates/history/<name>@<revision>.yaml. Embedding the
// directory rather than a file glob makes future history additions automatic.
func BuiltinPresetTemplateHistory() ([]BuiltinPresetTemplate, error) {
	current, err := BuiltinPresetTemplates()
	if err != nil {
		return nil, err
	}
	history := make([]BuiltinPresetTemplate, 0)
	entries, err := builtinPresetTemplateFiles.ReadDir("templates/history")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read embedded preset template history: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		stem := strings.TrimSuffix(entry.Name(), ".yaml")
		name, revisionText, found := strings.Cut(stem, "@")
		revision, parseErr := strconv.ParseUint(revisionText, 10, 64)
		if !found || parseErr != nil || revision == 0 || strconv.FormatUint(revision, 10) != revisionText {
			return nil, fmt.Errorf("embedded preset history filename %s must be <name>@<revision>.yaml", entry.Name())
		}
		source, readErr := builtinPresetTemplateFiles.ReadFile("templates/history/" + entry.Name())
		if readErr != nil {
			return nil, fmt.Errorf("read embedded preset history %s: %w", entry.Name(), readErr)
		}
		digest := sha256.Sum256(source)
		template, validateErr := validateBuiltinPresetTemplate(BuiltinPresetTemplate{
			Name: name, Filename: name + ".yaml", Revision: revision,
			SHA256: hex.EncodeToString(digest[:]), Source: source,
		})
		if validateErr != nil {
			return nil, fmt.Errorf("validate embedded preset history %s: %w", entry.Name(), validateErr)
		}
		history = append(history, template)
	}
	history = append(history, current...)
	sort.Slice(history, func(left, right int) bool {
		if history[left].Name != history[right].Name {
			return history[left].Name < history[right].Name
		}
		return history[left].Revision < history[right].Revision
	})
	return history, nil
}

var builtinPresetTemplateNames = [...]string{"telegram", "openai", "anthropic"}
