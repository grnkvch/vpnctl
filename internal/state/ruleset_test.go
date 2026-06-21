package state

import (
	"path/filepath"
	"testing"
)

func TestSaveRulesetWritesEditableJSON(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")

	ruleset, err := SaveRuleset(dir, RulesetConfig{
		ID:      "custom-ai",
		Domains: []string{"ChatGPT.com", " openai.com ", "claude.ai"},
	})
	if err != nil {
		t.Fatalf("save ruleset: %v", err)
	}
	if ruleset.ID != "custom-ai" {
		t.Fatalf("unexpected id: %q", ruleset.ID)
	}
	if ruleset.Name != "custom-ai" {
		t.Fatalf("unexpected name: %q", ruleset.Name)
	}
	if ruleset.Type != RulesetTypeDomainSuffix {
		t.Fatalf("unexpected type: %q", ruleset.Type)
	}
	if got := ruleset.Domains[0]; got != "chatgpt.com" {
		t.Fatalf("expected normalized domain, got %q", got)
	}

	loaded, err := LoadRuleset(dir, "custom-ai")
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}
	if len(loaded.Domains) != 3 {
		t.Fatalf("expected three domains, got %#v", loaded.Domains)
	}
}

func TestSaveRulesetReplacesExistingRuleset(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	if _, err := SaveRuleset(dir, RulesetConfig{ID: "default", Domains: []string{"chatgpt.com"}}); err != nil {
		t.Fatalf("save first ruleset: %v", err)
	}
	if _, err := SaveRuleset(dir, RulesetConfig{ID: "default", Domains: []string{"openai.com"}}); err != nil {
		t.Fatalf("replace ruleset: %v", err)
	}

	loaded, err := LoadRuleset(dir, "default")
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}
	if len(loaded.Domains) != 1 || loaded.Domains[0] != "openai.com" {
		t.Fatalf("unexpected domains after replace: %#v", loaded.Domains)
	}
}

func TestValidateRulesetRejectsInvalidTypeAndDomains(t *testing.T) {
	for _, ruleset := range []Ruleset{
		{ID: "../bad", Name: "Bad", Type: RulesetTypeDomainSuffix, Domains: []string{"chatgpt.com"}},
		{ID: "bad", Name: "Bad", Type: "ip-cidr", Domains: []string{"chatgpt.com"}},
		{ID: "bad", Name: "Bad", Type: RulesetTypeDomainSuffix, Domains: []string{"https://chatgpt.com"}},
		{ID: "bad", Name: "Bad", Type: RulesetTypeDomainSuffix, Domains: []string{"chatgpt.com", "chatgpt.com"}},
	} {
		if err := ValidateRuleset(ruleset); err == nil {
			t.Fatalf("expected validation error for %#v", ruleset)
		}
	}
}

func TestListRulesets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	if _, err := SaveRuleset(dir, RulesetConfig{ID: "b", Domains: []string{"b.example"}}); err != nil {
		t.Fatalf("save b: %v", err)
	}
	if _, err := SaveRuleset(dir, RulesetConfig{ID: "a", Domains: []string{"a.example"}}); err != nil {
		t.Fatalf("save a: %v", err)
	}

	rulesets, err := ListRulesets(dir)
	if err != nil {
		t.Fatalf("list rulesets: %v", err)
	}
	if len(rulesets) != 3 {
		t.Fatalf("expected default plus two custom rulesets, got %#v", rulesets)
	}
	if rulesets[0].ID != "a" || rulesets[1].ID != "b" || rulesets[2].ID != "default" {
		t.Fatalf("unexpected list order: %#v", rulesets)
	}
}
