package output

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHumanResultGolden(t *testing.T) {
	t.Parallel()

	result := NewResult("client.export", StatusOK, CategorySuccess, SafeObject{
		"output_path": "/var/lib/vpnctl/exports/clients/iphone.clash.yaml",
		"file_mode":   "0600",
		"generation":  uint64(12),
		"profile":     "profile-secret-canary",
		"resource": SafeObject{
			"credential": "credential-secret-canary",
		},
	})
	result.ResourceIDs = map[string]string{
		"operation_id": "op-7K3M2P",
		"client_id":    "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
	}
	result.Warnings = []Message{{
		Code:    "certificate_expiring",
		Message: "The gateway certificate expires in 30 days.",
		ResourceIDs: map[string]string{
			"certificate_id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		},
	}}
	result.RequiresAction = []Action{
		{
			Code:    "copy_client_profile",
			Message: "Copy the exported profile to the client device.",
			Command: "scp root@203.0.113.10:/var/lib/vpnctl/exports/clients/iphone.clash.yaml .",
			ResourceIDs: map[string]string{
				"client_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
			},
		},
		{
			Code:    "register_webhook",
			Message: "Register the webhook in the application project after deployment.",
			Command: "telegram-bot register-webhook --host 203.0.113.10 --certificate gateway.crt",
		},
	}

	var rendered bytes.Buffer
	if err := RenderHuman(&rendered, result); err != nil {
		t.Fatalf("RenderHuman() error = %v", err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "human-result.golden"))
	if err != nil {
		t.Fatalf("read golden result: %v", err)
	}
	if !bytes.Equal(rendered.Bytes(), want) {
		t.Fatalf("human result mismatch\nwant:\n%s\ngot:\n%s", want, rendered.Bytes())
	}
	for _, forbidden := range []string{"profile-secret-canary", "credential-secret-canary", "private-key", "wireguard-private-key"} {
		if strings.Contains(rendered.String(), forbidden) {
			t.Errorf("human result leaked %q", forbidden)
		}
	}
}

func TestResultValidationRejectsUnsafeOrInconsistentValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Result)
	}{
		{name: "schema", mutate: func(result *Result) { result.SchemaVersion++ }},
		{name: "command", mutate: func(result *Result) { result.Command = "Client Export" }},
		{name: "status", mutate: func(result *Result) { result.Status = "unknown" }},
		{name: "success failure", mutate: func(result *Result) { result.Status = StatusFailed }},
		{name: "degraded success", mutate: func(result *Result) { result.Status = StatusDegraded }},
		{name: "missing resource ids", mutate: func(result *Result) { result.ResourceIDs = nil }},
		{name: "unsafe resource key", mutate: func(result *Result) { result.ResourceIDs["webhook_path"] = "hidden" }},
		{name: "missing warnings", mutate: func(result *Result) { result.Warnings = nil }},
		{name: "multiline warning", mutate: func(result *Result) { result.Warnings = []Message{{Code: "bad", Message: "line one\nline two"}} }},
		{name: "missing actions", mutate: func(result *Result) { result.RequiresAction = nil }},
		{name: "multiline action command", mutate: func(result *Result) {
			result.RequiresAction = []Action{{Code: "run", Message: "Run it.", Command: "vpnctl status\ncat /etc/shadow"}}
		}},
		{name: "missing data", mutate: func(result *Result) { result.Data = nil }},
		{name: "unsafe data key", mutate: func(result *Result) { result.Data["private_key"] = "canary" }},
		{name: "unsupported data type", mutate: func(result *Result) { result.Data["created_at"] = struct{}{} }},
		{name: "non-finite number", mutate: func(result *Result) { result.Data["latency"] = math.Inf(1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := NewResult("client.export", StatusOK, CategorySuccess, SafeObject{})
			test.mutate(&result)
			if err := result.Validate(); err == nil {
				t.Fatal("Result.Validate() accepted invalid value")
			}
		})
	}
}

func TestRenderHumanValidatesBeforeWriting(t *testing.T) {
	t.Parallel()

	result := NewResult("status", StatusOK, CategorySuccess, SafeObject{})
	result.Data["request_body"] = "must-not-be-written"
	var output bytes.Buffer
	if err := RenderHuman(&output, result); err == nil {
		t.Fatal("RenderHuman() accepted invalid result")
	}
	if output.Len() != 0 {
		t.Fatalf("RenderHuman() wrote partial output: %q", output.String())
	}
}

func TestNewResultCreatesRequiredEmptyCollections(t *testing.T) {
	t.Parallel()

	result := NewResult("validate", StatusOK, CategorySuccess, nil)
	if err := result.Validate(); err != nil {
		t.Fatalf("NewResult().Validate() error = %v", err)
	}
	if result.ResourceIDs == nil || result.Warnings == nil || result.RequiresAction == nil || result.Data == nil {
		t.Fatal("NewResult() omitted a required collection")
	}
}

func TestSafeResultAcceptsTypedJSONCollections(t *testing.T) {
	t.Parallel()

	result := NewResult("client.list", StatusOK, CategorySuccess, SafeObject{
		"items":  []SafeObject{{"name": "iphone", "active": true}},
		"labels": []string{"personal", "ios"},
	})
	if err := result.Validate(); err != nil {
		t.Fatalf("Result.Validate() error = %v", err)
	}
}
