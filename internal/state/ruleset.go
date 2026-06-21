package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const RulesetTypeDomainSuffix = "domain-suffix"

var (
	rulesetIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	domainPattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
)

type RulesetConfig struct {
	ID      string
	Name    string
	Type    string
	Domains []string
}

func SaveRuleset(dir string, cfg RulesetConfig) (Ruleset, error) {
	if dir == "" {
		dir = DefaultDir
	}

	ruleset := Ruleset{
		ID:      strings.TrimSpace(cfg.ID),
		Name:    rulesetName(cfg),
		Type:    rulesetType(cfg),
		Domains: normalizeDomains(cfg.Domains),
	}
	if err := ValidateRuleset(ruleset); err != nil {
		return Ruleset{}, err
	}
	if _, err := Init(dir, false); err != nil {
		return Ruleset{}, err
	}

	result := InitResult{StateDir: dir}
	if err := writeJSON(RulesetPath(dir, ruleset.ID), ruleset, 0o644, true, &result); err != nil {
		return Ruleset{}, err
	}
	return ruleset, nil
}

func LoadRuleset(dir string, id string) (Ruleset, error) {
	if dir == "" {
		dir = DefaultDir
	}
	if !rulesetIDPattern.MatchString(id) {
		return Ruleset{}, fmt.Errorf("ruleset id may contain only letters, digits, dots, underscores, and dashes")
	}

	data, err := os.ReadFile(RulesetPath(dir, id))
	if err != nil {
		return Ruleset{}, fmt.Errorf("read ruleset %q: %w", id, err)
	}
	var ruleset Ruleset
	if err := json.Unmarshal(data, &ruleset); err != nil {
		return Ruleset{}, fmt.Errorf("parse ruleset %q: %w", id, err)
	}
	if err := ValidateRuleset(ruleset); err != nil {
		return Ruleset{}, err
	}
	return ruleset, nil
}

func ListRulesets(dir string) ([]Ruleset, error) {
	if dir == "" {
		dir = DefaultDir
	}
	entries, err := os.ReadDir(filepath.Join(dir, "rulesets"))
	if err != nil {
		return nil, fmt.Errorf("read rulesets: %w", err)
	}

	var out []Ruleset
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		ruleset, err := LoadRuleset(dir, id)
		if err != nil {
			return nil, err
		}
		out = append(out, ruleset)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func ValidateRuleset(ruleset Ruleset) error {
	if strings.TrimSpace(ruleset.ID) == "" {
		return fmt.Errorf("ruleset id is required")
	}
	if !rulesetIDPattern.MatchString(ruleset.ID) {
		return fmt.Errorf("ruleset id may contain only letters, digits, dots, underscores, and dashes")
	}
	if strings.TrimSpace(ruleset.Name) == "" {
		return fmt.Errorf("ruleset name is required")
	}
	if ruleset.Type != RulesetTypeDomainSuffix {
		return fmt.Errorf("unsupported ruleset type: %s", ruleset.Type)
	}
	if len(ruleset.Domains) == 0 {
		return fmt.Errorf("ruleset must contain at least one domain")
	}
	seen := map[string]bool{}
	for _, domain := range ruleset.Domains {
		if strings.TrimSpace(domain) != domain || domain == "" {
			return fmt.Errorf("ruleset contains invalid domain: %q", domain)
		}
		if strings.Contains(domain, "://") || strings.ContainsAny(domain, "/ ") {
			return fmt.Errorf("ruleset contains invalid domain: %q", domain)
		}
		if !domainPattern.MatchString(domain) {
			return fmt.Errorf("ruleset contains invalid domain: %q", domain)
		}
		if seen[domain] {
			return fmt.Errorf("ruleset contains duplicate domain: %s", domain)
		}
		seen[domain] = true
	}
	return nil
}

func RulesetPath(dir string, id string) string {
	if dir == "" {
		dir = DefaultDir
	}
	return filepath.Join(dir, "rulesets", id+".json")
}

func rulesetName(cfg RulesetConfig) string {
	if strings.TrimSpace(cfg.Name) == "" {
		return strings.TrimSpace(cfg.ID)
	}
	return strings.TrimSpace(cfg.Name)
}

func rulesetType(cfg RulesetConfig) string {
	if strings.TrimSpace(cfg.Type) == "" {
		return RulesetTypeDomainSuffix
	}
	return strings.TrimSpace(cfg.Type)
}

func normalizeDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSpace(strings.ToLower(domain))
		if domain != "" {
			out = append(out, domain)
		}
	}
	return out
}
