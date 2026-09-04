package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
)

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
