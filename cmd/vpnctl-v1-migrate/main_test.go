package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
)

func TestDocumentedV1MigrationCommandsExecuteThroughCLIParser(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "v2", "V1_MIGRATION.md"))
	if err != nil {
		t.Fatalf("read v1 migration guide: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	parsedCount := 0
	for index := 0; index < len(lines); index++ {
		line := strings.TrimSpace(lines[index])
		if !strings.HasPrefix(line, "sudo vpnctl-v1-migrate") {
			continue
		}
		parts := make([]string, 0)
		for {
			continued := strings.HasSuffix(line, "\\")
			line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
			parts = append(parts, strings.Fields(line)...)
			if !continued {
				break
			}
			index++
			if index >= len(lines) {
				t.Fatal("migration guide ends inside a continued command")
			}
			line = strings.TrimSpace(lines[index])
		}
		if len(parts) < 3 || parts[0] != "sudo" || parts[1] != "vpnctl-v1-migrate" {
			t.Fatalf("invalid documented migration command: %q", strings.Join(parts, " "))
		}
		if _, _, help, parseErr := parseOptions(parts[2:]); parseErr != nil || help {
			t.Errorf("documented migration command does not execute through parser: %q: help=%t err=%v", strings.Join(parts, " "), help, parseErr)
		}
		parsedCount++
	}
	if parsedCount != 4 {
		t.Fatalf("executed documented migration commands = %d, want 4", parsedCount)
	}
}

func TestParseOptionsRequiresExplicitBundlePublicIPAndDowntimeMode(t *testing.T) {
	options, port, help, err := parseOptions([]string{
		"--bundle", "/tmp/vpnctl.bundle", "--public-ip", "8.8.8.8",
		"--workspace", "/srv/vpnctl-v1", "--ssh-port", "2222", "--dry-run", "--json",
	})
	if err != nil || help || !options.dryRun || !options.json || port.value == nil || *port.value != 2222 {
		t.Fatalf("parsed options = %+v, port=%+v, help=%t, err=%v", options, port, help, err)
	}
	for name, arguments := range map[string][]string{
		"missing bundle": {"--public-ip", "8.8.8.8", "--dry-run"},
		"missing ip":     {"--bundle", "/tmp/vpnctl.bundle", "--dry-run"},
		"bad port":       {"--bundle", "/tmp/vpnctl.bundle", "--public-ip", "8.8.8.8", "--ssh-port", "22x", "--dry-run"},
		"mixed modes":    {"--bundle", "/tmp/vpnctl.bundle", "--public-ip", "8.8.8.8", "--dry-run", "--yes"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := parseOptions(arguments); err == nil {
				t.Fatal("parseOptions() error = nil")
			}
		})
	}
}

func TestParseOptionsSeparatesMigrationRollbackAndAcceptance(t *testing.T) {
	for name, arguments := range map[string][]string{
		"rollback": {"--rollback", "--yes", "--workspace", "/srv/vpnctl-v1"},
		"accept":   {"--accept", "--yes", "--maintenance-root", "/var/lib/vpnctl-v1-migration"},
	} {
		t.Run(name, func(t *testing.T) {
			options, port, help, err := parseOptions(arguments)
			_, recovery := options.recoveryAction()
			if err != nil || help || !recovery || !options.yes || port.value != nil {
				t.Fatalf("parsed recovery = %+v, port=%+v, help=%t, err=%v", options, port, help, err)
			}
		})
	}
	for name, arguments := range map[string][]string{
		"both actions":     {"--rollback", "--accept", "--yes"},
		"recovery dry-run": {"--rollback", "--dry-run"},
		"recovery bundle":  {"--accept", "--bundle", "/tmp/vpnctl.bundle", "--yes"},
		"recovery ip":      {"--rollback", "--public-ip", "8.8.8.8", "--yes"},
		"recovery port":    {"--accept", "--ssh-port", "22", "--yes"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := parseOptions(arguments); err == nil {
				t.Fatal("parseOptions() error = nil")
			}
		})
	}
}

func TestEmitResultContainsOnlySafeMigrationMetadata(t *testing.T) {
	result := lifecycle.V1MigrationResult{
		SchemaVersion: 1, MigrationID: "mig-0123456789abcdef", Status: "awaiting_network_confirmation",
		DowntimeAccepted: true, ReleaseVersion: "v2.0.0",
		CompletedPhases: []lifecycle.V1MigrationPhase{lifecycle.V1MigrationNetworkActivated},
		NextPhase:       lifecycle.V1MigrationNetworkConfirmed, WatchdogTransactionID: "fw-7K3M2P",
		Clients:        []lifecycle.V1MigrationClientValidation{},
		RequiresAction: []string{"open a new SSH session and run vpnctl confirm fw-7K3M2P"},
	}
	for _, jsonMode := range []bool{false, true} {
		var output bytes.Buffer
		if err := emitResult(&output, result, jsonMode); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		if !strings.Contains(text, "fw-7K3M2P") || strings.Contains(text, "PrivateKey") || strings.Contains(text, "/srv/vpnctl-v1") {
			t.Fatalf("unsafe/incomplete output = %q", text)
		}
	}
}

func TestEmitRecoveryResultContainsOnlySafeMetadata(t *testing.T) {
	result := lifecycle.V1MigrationRecoveryResult{
		SchemaVersion: 1, MigrationID: "mig-0123456789abcdef", Action: lifecycle.V1MigrationRecoveryRollback,
		Status: "rolled_back", CompletedPhases: []lifecycle.V1MigrationRecoveryPhase{lifecycle.V1MigrationRecoveryPayloadRemoved},
		RequiresAction: []string{"validate v1 clients"},
	}
	for _, jsonMode := range []bool{false, true} {
		var output bytes.Buffer
		if err := emitRecoveryResult(&output, result, jsonMode); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		if !strings.Contains(text, "rolled_back") || !strings.Contains(text, "validate v1 clients") || strings.Contains(text, "/srv/vpnctl-v1") {
			t.Fatalf("unsafe/incomplete recovery output = %q", text)
		}
	}
}
