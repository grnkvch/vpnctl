package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultDir    = ".vpnctl"
	SchemaVersion = 1
)

var defaultRulesetDomains = []string{
	"chatgpt.com",
	"openai.com",
	"claude.ai",
	"anthropic.com",
}

type State struct {
	SchemaVersion int           `json:"schema_version"`
	Server        *ServerState  `json:"server"`
	Clients       []ClientState `json:"clients"`
}

type ServerState struct {
	ID string `json:"id"`
}

type ClientState struct {
	ID string `json:"id"`
}

type Ruleset struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Domains []string `json:"domains"`
}

type InitResult struct {
	StateDir string
	Created  []string
}

func Init(dir string, force bool) (InitResult, error) {
	if dir == "" {
		dir = DefaultDir
	}

	result := InitResult{StateDir: dir}

	dirs := []string{
		dir,
		filepath.Join(dir, "rulesets"),
		filepath.Join(dir, "secrets"),
		filepath.Join(dir, "secrets", "clients"),
		filepath.Join(dir, "generated"),
		filepath.Join(dir, "generated", "wireguard"),
		filepath.Join(dir, "generated", "mihomo"),
		filepath.Join(dir, "generated", "delivery"),
	}

	for _, path := range dirs {
		mode := os.FileMode(0o755)
		if isSecretPath(dir, path) {
			mode = 0o700
		}
		if err := mkdir(path, mode, &result); err != nil {
			return result, err
		}
	}

	if err := writeJSON(filepath.Join(dir, "state.json"), initialState(), 0o644, force, &result); err != nil {
		return result, err
	}
	if err := writeJSON(filepath.Join(dir, "rulesets", "default.json"), defaultRuleset(), 0o644, force, &result); err != nil {
		return result, err
	}
	if err := writeFile(filepath.Join(dir, ".gitignore"), []byte("secrets/\ngenerated/\n"), 0o644, force, &result); err != nil {
		return result, err
	}

	return result, nil
}

func initialState() State {
	return State{
		SchemaVersion: SchemaVersion,
		Server:        nil,
		Clients:       []ClientState{},
	}
}

func defaultRuleset() Ruleset {
	return Ruleset{
		ID:      "default",
		Name:    "Default",
		Type:    "domain-suffix",
		Domains: append([]string(nil), defaultRulesetDomains...),
	}
}

func mkdir(path string, mode os.FileMode, result *InitResult) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("create directory %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("set permissions on %s: %w", path, err)
	}
	result.Created = append(result.Created, path)
	return nil
}

func writeJSON(path string, value any, mode os.FileMode, force bool, result *InitResult) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	data = append(data, '\n')
	return writeFile(path, data, mode, force, result)
}

func writeFile(path string, data []byte, mode os.FileMode, force bool, result *InitResult) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
	}

	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("set permissions on %s: %w", path, err)
	}
	result.Created = append(result.Created, path)
	return nil
}

func isSecretPath(root string, path string) bool {
	secrets := filepath.Join(root, "secrets")
	rel, err := filepath.Rel(secrets, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != "" && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."))
}
