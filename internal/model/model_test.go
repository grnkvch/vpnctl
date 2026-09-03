package model

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	gatewayID    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	nodeID       = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	clientID     = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	exposeID     = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	publicCertID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	nodeCertID   = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	operationID  = "11111111-1111-4111-8111-111111111111"
	loggingID    = "22222222-2222-4222-8222-222222222222"
	backupID     = "33333333-3333-4333-8333-333333333333"
	requestID    = "44444444-4444-4444-8444-444444444444"
	nodeHostID   = "55555555-5555-4555-8555-555555555555"
)

func TestStateJSONRoundTrip(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]State{
		"gateway": gatewayState(),
		"node":    nodeState(),
	} {
		input := input
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			encoded, err := EncodeState(input)
			if err != nil {
				t.Fatalf("EncodeState() error = %v", err)
			}
			if !bytes.HasSuffix(encoded, []byte("\n")) {
				t.Fatal("EncodeState() did not append a final newline")
			}
			if bytes.Contains(encoded, []byte("raw-secret-canary")) {
				t.Fatal("EncodeState() serialized raw secret material")
			}

			decoded, err := DecodeState(encoded)
			if err != nil {
				t.Fatalf("DecodeState() error = %v", err)
			}
			if !reflect.DeepEqual(decoded, input) {
				t.Fatalf("round trip mismatch\nwant: %#v\n got: %#v", input, decoded)
			}

			reencoded, err := EncodeState(decoded)
			if err != nil {
				t.Fatalf("second EncodeState() error = %v", err)
			}
			if !bytes.Equal(reencoded, encoded) {
				t.Fatal("state encoding is not deterministic")
			}
		})
	}
}

func TestStateValidationRejectsInvalidStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*State)
		want   string
	}{
		{name: "state schema", mutate: func(state *State) { state.SchemaVersion++ }, want: "schema_version"},
		{name: "zero generation", mutate: func(state *State) { state.Generation = 0 }, want: "generation"},
		{name: "unknown role", mutate: func(state *State) { state.Host.Role = Role("proxy") }, want: "role"},
		{name: "unsupported platform", mutate: func(state *State) { state.Host.Architecture = "arm64" }, want: "platform"},
		{name: "missing explicit public ip", mutate: func(state *State) { state.Host.PublicIPv4 = "" }, want: "public_ipv4"},
		{name: "overlapping pools", mutate: func(state *State) { state.Host.NodeCIDR = state.Host.ClientCIDR }, want: "overlaps"},
		{name: "missing root collection", mutate: func(state *State) { state.Logging = nil }, want: "collections"},
		{name: "missing invite collection", mutate: func(state *State) { state.Invites = nil }, want: "collections"},
		{name: "invalid invite endpoint", mutate: func(state *State) {
			state.Invites = append(state.Invites, validInvite(state))
			state.Invites[0].GatewayEndpoint = "https://gateway.example/.well-known/vpnctl/enroll"
		}, want: "canonical IPv4 host"},
		{name: "invalid invite ttl", mutate: func(state *State) {
			state.Invites = append(state.Invites, validInvite(state))
			state.Invites[0].ExpiresAt = state.Invites[0].ExpiresAt.Add(time.Second)
		}, want: "exactly 15 minutes"},
		{name: "active invite has cancellation time", mutate: func(state *State) {
			state.Invites = append(state.Invites, validInvite(state))
			cancelled := state.Invites[0].IssuedAt.Add(time.Minute)
			state.Invites[0].CancelledAt = &cancelled
		}, want: "active invite cannot"},
		{name: "missing authoritative handshake host", mutate: func(state *State) { state.HandshakeHost = nil }, want: "requires an authoritative handshake-host selection"},
		{name: "handshake list differs from manifest", mutate: func(state *State) { state.HandshakeHost.ListVersion++ }, want: "must match the installed component manifest"},
		{name: "invalid handshake candidate id", mutate: func(state *State) { state.HandshakeHost.CandidateID = "Microsoft" }, want: "candidate_id"},
		{name: "duplicate node id", mutate: func(state *State) {
			duplicate := state.Nodes[0]
			duplicate.Name = "another-node"
			state.Nodes = append(state.Nodes, duplicate)
		}, want: "duplicates node"},
		{name: "duplicate active node name", mutate: func(state *State) {
			duplicate := state.Nodes[0]
			duplicate.ID = "66666666-6666-4666-8666-666666666666"
			duplicate.Name = strings.ToUpper(duplicate.Name)
			state.Nodes = append(state.Nodes, duplicate)
		}, want: "duplicates active node name"},
		{name: "gateway embeds node-local trust", mutate: func(state *State) {
			state.Nodes[0].Gateway = gatewayTrust()
		}, want: "must not embed local gateway trust"},
		{name: "missing assigned presets array", mutate: func(state *State) { state.Nodes[0].AssignedPresets = nil }, want: "assigned_presets"},
		{name: "missing idempotency records array", mutate: func(state *State) { state.Nodes[0].IdempotencyRecords = nil }, want: "idempotency_records"},
		{name: "unknown policy target", mutate: func(state *State) {
			state.Policies[0].TargetID = "77777777-7777-4777-8777-777777777777"
		}, want: "unknown node"},
		{name: "unknown preset", mutate: func(state *State) {
			state.Policies[0].PresetNames = []string{"missing"}
			state.Nodes[0].AssignedPresets = []string{"missing"}
		}, want: "unknown preset"},
		{name: "policy differs from assignment", mutate: func(state *State) {
			state.Nodes[0].AssignedPresets = []string{}
		}, want: "differ from its policy"},
		{name: "duplicate preset name case insensitive", mutate: func(state *State) {
			duplicate := state.Presets[0]
			duplicate.Name = "Telegram"
			state.Presets = append(state.Presets, duplicate)
		}, want: "duplicates preset"},
		{name: "active node without transports", mutate: func(state *State) {
			state.Transports = append([]Transport(nil), state.Transports[2:]...)
		}, want: "has no transport records"},
		{name: "selected transport is standby", mutate: func(state *State) {
			state.Transports[1].State = TransportStandby
		}, want: "active transport does not match"},
		{name: "inactive transport is active", mutate: func(state *State) {
			state.Transports[0].State = TransportActive
		}, want: "non-standby inactive transport"},
		{name: "unknown transport state", mutate: func(state *State) {
			state.Transports[0].State = TransportState("automatic")
		}, want: "unsupported value"},
		{name: "transport credential generation mismatch", mutate: func(state *State) {
			state.Transports[0].CredentialGeneration++
		}, want: "does not match its owner generation"},
		{name: "wrong restricted port", mutate: func(state *State) {
			state.Transports[1].Port = 443
		}, want: "TCP/8443"},
		{name: "restricted transport differs from authoritative handshake host", mutate: func(state *State) {
			state.Transports[1].HandshakeHost = "www.apple.com"
		}, want: "must match the authoritative handshake-host selection"},
		{name: "non-numeric expose port", mutate: func(state *State) {
			state.Exposes[0].Upstream = "127.0.0.1:http"
		}, want: "invalid port"},
		{name: "unsafe expose path", mutate: func(state *State) {
			state.Exposes[0].Path = "/telegram//webhook"
		}, want: "normalized HTTP path"},
		{name: "duplicate expose route", mutate: func(state *State) {
			duplicate := state.Exposes[0]
			duplicate.ID = "88888888-8888-4888-8888-888888888888"
			state.Exposes = append(state.Exposes, duplicate)
		}, want: "duplicates active route"},
		{name: "non-active node has live expose", mutate: func(state *State) {
			revoked := utc(2026, time.September, 3, 12, 0)
			state.Nodes[0].Lifecycle = LifecycleRevoked
			state.Nodes[0].RevokedAt = &revoked
			state.Transports[0].State = TransportDisabled
			state.Transports[1].State = TransportDisabled
		}, want: "non-active node expose must be disabled"},
		{name: "unknown certificate owner", mutate: func(state *State) {
			state.Certificates[1].OwnerID = "99999999-9999-4999-8999-999999999999"
		}, want: "unknown node"},
		{name: "certificate lifetime reversed", mutate: func(state *State) {
			state.Certificates[0].NotAfter = state.Certificates[0].NotBefore
		}, want: "must follow not_before"},
		{name: "wrong enrollment algorithm", mutate: func(state *State) {
			state.EnrollmentIdentity.Algorithm = "RSA"
		}, want: "Ed25519"},
		{name: "shared enrollment key refs", mutate: func(state *State) {
			state.EnrollmentIdentity.PublicKeyRef = state.EnrollmentIdentity.PrivateKeyRef.String()
		}, want: "must differ"},
		{name: "failed operation without code", mutate: func(state *State) {
			state.Operations[0].State = OperationFailed
			state.Operations[0].Steps[0].State = OperationFailed
		}, want: "requires a stable error code"},
		{name: "operation steps omitted", mutate: func(state *State) {
			state.Operations[0].Steps = nil
		}, want: "steps"},
		{name: "logging exceeds one hour", mutate: func(state *State) {
			state.Logging[0].ExpiresAt = state.Logging[0].StartedAt.Add(time.Hour + time.Second)
		}, want: "no more than one hour"},
		{name: "journald has a file path", mutate: func(state *State) {
			state.Logging[0].FilePath = "/var/log/vpnctl.log"
		}, want: "only for file destination"},
		{name: "relative backup path", mutate: func(state *State) {
			state.Backups[0].Path = "backup.v2"
		}, want: "must be absolute"},
		{name: "manifest does not support state", mutate: func(state *State) {
			state.Components.StateSchemaMinimum = 2
			state.Components.StateSchemaMaximum = 2
		}, want: "outside supported range"},
		{name: "duplicate component", mutate: func(state *State) {
			state.Components.Components = append(state.Components.Components, state.Components.Components[0])
		}, want: "duplicates component"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := cloneState(t, gatewayState())
			test.mutate(&state)
			err := state.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %q, want substring %q", err, test.want)
			}
		})
	}
}

func TestRevokedResourceRequiresDisabledTransports(t *testing.T) {
	t.Parallel()

	state := gatewayState()
	revoked := utc(2026, time.September, 3, 12, 0)
	state.Nodes[0].Lifecycle = LifecycleRevoked
	state.Nodes[0].RevokedAt = &revoked
	state.Exposes[0].State = ExposeDisabled
	state.Transports[0].State = TransportDisabled

	if err := state.Validate(); err == nil || !strings.Contains(err.Error(), "retains an enabled transport") {
		t.Fatalf("Validate() error = %v, want enabled transport rejection", err)
	}
	state.Transports[1].State = TransportDisabled
	if err := state.Validate(); err != nil {
		t.Fatalf("Validate() after disabling transports error = %v", err)
	}
}

func TestNodeRoleStateBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*State)
		want   string
	}{
		{name: "more than one identity", mutate: func(state *State) {
			duplicate := state.Nodes[0]
			duplicate.ID = "66666666-6666-4666-8666-666666666666"
			duplicate.Name = "old-node"
			duplicate.Lifecycle = LifecycleRevoked
			revoked := utc(2026, time.September, 3, 12, 0)
			duplicate.RevokedAt = &revoked
			duplicate.AssignedPresets = []string{}
			state.Nodes = append(state.Nodes, duplicate)
		}, want: "at most one"},
		{name: "client collection", mutate: func(state *State) {
			client := gatewayState().Clients[0]
			client.Lifecycle = LifecycleRevoked
			revoked := utc(2026, time.September, 3, 12, 0)
			client.RevokedAt = &revoked
			client.AssignedPresets = []string{}
			state.Clients = append(state.Clients, client)
		}, want: "gateway client"},
		{name: "missing gateway trust", mutate: func(state *State) { state.Nodes[0].Gateway = nil }, want: "requires gateway trust"},
		{name: "invalid trusted node cidr", mutate: func(state *State) { state.Nodes[0].Gateway.NodeCIDR = "10.67.0.1/24" }, want: "node_cidr"},
		{name: "wrong trusted gateway overlay", mutate: func(state *State) { state.Nodes[0].Gateway.GatewayOverlayIPv4 = "10.67.0.2" }, want: "first host"},
		{name: "missing trusted control protocol", mutate: func(state *State) { state.Nodes[0].Gateway.ControlProtocol = "" }, want: "control_protocol"},
		{name: "missing enrollment public ref", mutate: func(state *State) { state.Nodes[0].Gateway.EnrollmentPublicKeyRef = "" }, want: "enrollment_public_key_ref"},
		{name: "mismatched trusted ca refs", mutate: func(state *State) { state.Nodes[0].Gateway.ControlCACertificateRefs = []string{} }, want: "must match"},
		{name: "invalid trusted standard public key", mutate: func(state *State) { state.Nodes[0].Gateway.StandardPublicKey = "invalid" }, want: "standard_public_key"},
		{name: "missing restricted upstream ref", mutate: func(state *State) { state.Nodes[0].Gateway.RestrictedServerCredentialRef = "" }, want: "restricted_server_credential_ref"},
		{name: "local overlay outside trusted cidr", mutate: func(state *State) { state.Nodes[0].OverlayIPv4 = "10.68.0.2" }, want: "inside gateway.node_cidr"},
		{name: "gateway-only host field", mutate: func(state *State) { state.Host.PublicIPv4 = "203.0.113.10" }, want: "gateway-only"},
		{name: "gateway enrollment signer", mutate: func(state *State) { state.EnrollmentIdentity = gatewayState().EnrollmentIdentity }, want: "gateway-only"},
		{name: "foreign policy", mutate: func(state *State) { state.Policies[0].TargetID = clientID }, want: "unknown node"},
		{name: "gateway idempotency history", mutate: func(state *State) {
			state.Nodes[0].IdempotencyRecords = []IdempotencyRecord{idempotencyRecord(state.Generation, state.Host.InitializedAt)}
		}, want: "gateway idempotency history"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := cloneState(t, nodeState())
			test.mutate(&state)
			err := state.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestStrictJSONDecode(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeState(gatewayState())
	if err != nil {
		t.Fatalf("EncodeState() error = %v", err)
	}
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "unknown top-level field",
			data: bytes.Replace(encoded, []byte("{\n"), []byte("{\n  \"unknown\": true,\n"), 1),
			want: "unknown field",
		},
		{
			name: "unknown nested field",
			data: bytes.Replace(encoded, []byte("\"name\": \"private-1\","), []byte("\"name\": \"private-1\",\n      \"unexpected\": true,"), 1),
			want: "unknown field",
		},
		{
			name: "raw secret field",
			data: bytes.Replace(encoded, []byte("\"credential_ref\": \"secret:node-standard\","), []byte("\"credential_ref\": \"secret:node-standard\",\n      \"private_key\": \"raw-secret-canary\","), 1),
			want: "unknown field",
		},
		{
			name: "duplicate field",
			data: bytes.Replace(encoded, []byte("\"generation\": 7,"), []byte("\"generation\": 7,\n  \"generation\": 8,"), 1),
			want: "duplicate JSON field",
		},
		{
			name: "trailing document",
			data: append(append([]byte(nil), encoded...), []byte("{}")...),
			want: "multiple JSON documents",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeState(test.data)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("DecodeState() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestStandaloneVersionedModelCodecs(t *testing.T) {
	t.Parallel()

	preset := gatewayState().Presets[0]
	presetJSON, err := EncodePreset(preset)
	if err != nil {
		t.Fatalf("EncodePreset() error = %v", err)
	}
	decodedPreset, err := DecodePreset(presetJSON)
	if err != nil {
		t.Fatalf("DecodePreset() error = %v", err)
	}
	if !reflect.DeepEqual(decodedPreset, preset) {
		t.Fatal("preset round trip mismatch")
	}
	unknownPreset := bytes.Replace(presetJSON, []byte("{\n"), []byte("{\n  \"unknown\": true,\n"), 1)
	if _, err := DecodePreset(unknownPreset); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodePreset() unknown field error = %v", err)
	}

	manifest := componentManifest()
	manifestJSON, err := EncodeComponentManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeComponentManifest() error = %v", err)
	}
	decodedManifest, err := DecodeComponentManifest(manifestJSON)
	if err != nil {
		t.Fatalf("DecodeComponentManifest() error = %v", err)
	}
	if !reflect.DeepEqual(decodedManifest, manifest) {
		t.Fatal("component manifest round trip mismatch")
	}
	duplicateManifest := bytes.Replace(manifestJSON, []byte("\"manifest_version\": 1,"), []byte("\"manifest_version\": 1,\n  \"manifest_version\": 2,"), 1)
	if _, err := DecodeComponentManifest(duplicateManifest); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("DecodeComponentManifest() duplicate field error = %v", err)
	}
}

func TestComponentManifestControlProtocolCompatibilityWindow(t *testing.T) {
	t.Parallel()

	manifest := componentManifest()
	manifest.ControlProtocols = []string{"2.3", "1.5"}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("Validate(current/previous) error = %v", err)
	}
	for name, versions := range map[string][]string{
		"empty":              {},
		"minor-leading-zero": {"1.00"},
		"too-many":           {"3.0", "2.0", "1.0"},
		"same-major":         {"2.3", "2.1"},
		"non-adjacent":       {"3.0", "1.9"},
		"wrong-order":        {"1.9", "2.0"},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := manifest
			candidate.ControlProtocols = versions
			if err := candidate.Validate(); err == nil {
				t.Fatalf("Validate(%v) error = nil", versions)
			}
		})
	}
}

func TestSecretReferenceJSONBoundary(t *testing.T) {
	t.Parallel()

	reference, err := ParseSecretRef("control-key:gateway")
	if err != nil {
		t.Fatalf("ParseSecretRef() error = %v", err)
	}
	kind, id, err := reference.Parts()
	if err != nil || kind != "control-key" || id != "gateway" {
		t.Fatalf("SecretRef.Parts() = %q, %q, %v", kind, id, err)
	}
	constructed, err := NewSecretRef(kind, id)
	if err != nil || constructed != reference {
		t.Fatalf("NewSecretRef() = %q, %v", constructed, err)
	}
	for _, invalid := range []string{"", "missing-separator", "../key:value", "key:../value", "UPPER:key"} {
		if _, err := ParseSecretRef(invalid); err == nil {
			t.Errorf("ParseSecretRef(%q) error = nil", invalid)
		}
	}

	state := gatewayState()
	encoded, err := EncodeState(state)
	if err != nil {
		t.Fatalf("EncodeState() error = %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"credential_ref": "secret:node-standard"`)) {
		t.Fatal("encoded state omitted the opaque secret reference")
	}
	if bytes.Contains(encoded, []byte("raw-private-material-canary")) {
		t.Fatal("encoded state contains raw secret material")
	}
}

func gatewayState() State {
	created := utc(2026, time.September, 2, 10, 0)
	return State{
		SchemaVersion: StateSchemaVersion,
		Generation:    7,
		Host: Host{
			SchemaVersion:     ResourceSchemaVersion,
			ID:                gatewayID,
			Role:              RoleGateway,
			OS:                "ubuntu",
			OSVersion:         "24.04",
			Architecture:      "amd64",
			InitializedAt:     created,
			PublicIPv4:        "203.0.113.10",
			ExternalInterface: "eth0",
			SSHPort:           22,
			ClientCIDR:        "10.66.0.0/24",
			NodeCIDR:          "10.67.0.0/24",
			ManagedSwap:       &ManagedSwap{Path: "/var/lib/vpnctl/swapfile", SizeBytes: 1 << 30, Enabled: true},
		},
		HandshakeHost: &HandshakeHost{
			SchemaVersion: ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft",
			Hostname: "www.microsoft.com", SelectedAt: created,
		},
		EnrollmentIdentity: &EnrollmentIdentity{
			SchemaVersion: ResourceSchemaVersion,
			Algorithm:     "Ed25519",
			Fingerprint:   fingerprint("e"),
			PublicKeyRef:  "enrollment-public:gateway",
			PrivateKeyRef: "enrollment-key:gateway",
			Generation:    1,
			CreatedAt:     created,
		},
		Invites: []Invite{},
		Nodes: []Node{{
			SchemaVersion:        ResourceSchemaVersion,
			ID:                   nodeID,
			Name:                 "private-1",
			Lifecycle:            LifecycleActive,
			OverlayIPv4:          "10.67.0.2",
			CredentialGeneration: 3,
			AssignedPresets:      []string{"telegram"},
			ActiveTransport:      TransportRestricted,
			IdempotencyRecords:   []IdempotencyRecord{},
			CreatedAt:            created,
		}},
		Clients: []Client{{
			SchemaVersion:        ResourceSchemaVersion,
			ID:                   clientID,
			Name:                 "iphone",
			Platform:             "ios",
			Lifecycle:            LifecycleActive,
			OverlayIPv4:          "10.66.0.2",
			CredentialGeneration: 3,
			AssignedPresets:      []string{"telegram"},
			ActiveTransport:      TransportStandard,
			CreatedAt:            created,
		}},
		Presets: []Preset{{
			SchemaVersion: ResourceSchemaVersion,
			Name:          "telegram",
			SourceHash:    digest("a"),
			EffectiveHash: digest("b"),
			Selectors: []Selector{
				{Kind: SelectorDomainSuffix, Value: "telegram.org"},
				{Kind: SelectorIPCIDR, Value: "149.154.160.0/20"},
			},
			Generation: 4,
			AppliedAt:  created,
		}},
		Policies: []Policy{
			policy(TargetNode, nodeID),
			policy(TargetClient, clientID),
		},
		Transports: []Transport{
			standardTransport(TargetNode, nodeID, TransportStandby, "secret:node-standard"),
			restrictedTransport(TargetNode, nodeID, TransportActive, "secret:node-restricted"),
			standardTransport(TargetClient, clientID, TransportActive, "secret:client-standard"),
			restrictedTransport(TargetClient, clientID, TransportStandby, "secret:client-restricted"),
		},
		Exposes: []Expose{{
			SchemaVersion:          ResourceSchemaVersion,
			ID:                     exposeID,
			NodeID:                 nodeID,
			Name:                   "telegram-webhook",
			Upstream:               "127.0.0.1:3000",
			RouteMode:              RouteExact,
			Path:                   "/telegram/webhook-a1b2c3",
			BodyLimitBytes:         1 << 20,
			UpstreamTimeoutSeconds: 30,
			ConcurrentRequests:     16,
			TunnelPort:             20001,
			State:                  ExposeReady,
			Generation:             2,
			CreatedAt:              created,
		}},
		Certificates: []Certificate{
			certificate(publicCertID, CertificatePublicIngress, "host", gatewayID, "pki:public-cert", "pki:public-key", created, created.AddDate(5, 0, 0)),
			certificate(nodeCertID, CertificateControlNode, "node", nodeID, "pki:node-cert", "", created, created.AddDate(5, 0, 0)),
		},
		Operations: []Operation{{
			SchemaVersion:      ResourceSchemaVersion,
			ID:                 operationID,
			Type:               OperationApply,
			State:              OperationCompleted,
			TargetKind:         "preset",
			TargetID:           "telegram",
			RequestID:          requestID,
			ExpectedGeneration: 6,
			DesiredGeneration:  7,
			Steps:              []OperationStep{{Name: "activate", State: OperationCompleted, UpdatedAt: created.Add(time.Minute)}},
			CreatedAt:          created,
			UpdatedAt:          created.Add(time.Minute),
		}},
		Logging: []LoggingSession{{
			SchemaVersion: ResourceSchemaVersion,
			ID:            loggingID,
			Scope:         LogDNS,
			Level:         LogDebug,
			Destination:   LogToJournald,
			State:         LogActive,
			StartedAt:     created,
			ExpiresAt:     created.Add(30 * time.Minute),
		}},
		Backups: []Backup{{
			SchemaVersion:   ResourceSchemaVersion,
			ID:              backupID,
			State:           BackupComplete,
			Format:          "vpnctl-backup-v1",
			Path:            "/var/lib/vpnctl/backups/vpnctl-20260902.v2b",
			SHA256:          digest("c"),
			SizeBytes:       4096,
			StateGeneration: 7,
			PublicIPv4:      "203.0.113.10",
			CreatedAt:       created,
		}},
		Components: componentManifest(),
	}
}

func nodeState() State {
	state := gatewayState()
	state.Host = Host{
		SchemaVersion: ResourceSchemaVersion,
		ID:            nodeHostID,
		Role:          RoleNode,
		OS:            "ubuntu",
		OSVersion:     "24.04",
		Architecture:  "amd64",
		InitializedAt: state.Host.InitializedAt,
	}
	state.Nodes[0].Gateway = gatewayTrust()
	state.EnrollmentIdentity = nil
	state.Clients = []Client{}
	state.Presets = []Preset{}
	state.Policies = state.Policies[:1]
	state.Transports = state.Transports[:2]
	state.Certificates = state.Certificates[1:]
	state.Backups = []Backup{}
	return state
}

func gatewayTrust() *GatewayTrust {
	return &GatewayTrust{
		PublicIPv4: "203.0.113.10", NodeCIDR: "10.67.0.0/24", GatewayOverlayIPv4: "10.67.0.1",
		ControlProtocol: "1.0", EnrollmentFingerprint: fingerprint("d"),
		EnrollmentPublicKeyRef: "enrollment-public:gateway", ControlCAFingerprints: []string{fingerprint("e")},
		ControlCACertificateRefs:      []string{"control-cert:gateway-ca-g1"},
		StandardPublicKey:             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		RestrictedServerCredentialRef: "restricted-upstream:gateway-g1", LastKnownGatewayGeneration: 7,
	}
}

func validInvite(state *State) Invite {
	issuedAt := utc(2026, time.September, 3, 10, 0)
	return Invite{
		SchemaVersion: ResourceSchemaVersion, ID: "inv-ABC234", NodeName: "invited-node",
		ControlProtocol: state.Components.ControlProtocols[0], GatewayEndpoint: "https://" + state.Host.PublicIPv4 + "/.well-known/vpnctl/enroll",
		EnrollmentFingerprint: state.EnrollmentIdentity.Fingerprint, SecretHash: digest("7"), State: InviteActive,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(InviteTTL),
	}
}

func idempotencyRecord(generation uint64, recordedAt time.Time) IdempotencyRecord {
	return IdempotencyRecord{
		RequestID:       requestID,
		Operation:       OperationApply,
		ResultStatus:    ResultOK,
		ResultHash:      digest("9"),
		StateGeneration: generation,
		RecordedAt:      recordedAt,
	}
}

func policy(kind TargetKind, id string) Policy {
	return Policy{
		SchemaVersion: ResourceSchemaVersion,
		TargetKind:    kind,
		TargetID:      id,
		PresetNames:   []string{"telegram"},
		Selectors: []Selector{
			{Kind: SelectorDomainSuffix, Value: "telegram.org"},
			{Kind: SelectorIPCIDR, Value: "149.154.160.0/20"},
		},
		EffectiveHash: digest("b"),
		Generation:    4,
	}
}

func standardTransport(kind TargetKind, id string, state TransportState, credentialRef SecretRef) Transport {
	return Transport{
		SchemaVersion:        ResourceSchemaVersion,
		OwnerKind:            kind,
		OwnerID:              id,
		Kind:                 TransportStandard,
		State:                state,
		Provider:             "wireguard",
		Protocol:             ProtocolUDP,
		Port:                 51820,
		CredentialGeneration: 3,
		CredentialRef:        credentialRef,
		PublicKey:            "example-public-key",
		ConfigHash:           digest("d"),
	}
}

func restrictedTransport(kind TargetKind, id string, state TransportState, credentialRef SecretRef) Transport {
	return Transport{
		SchemaVersion:        ResourceSchemaVersion,
		OwnerKind:            kind,
		OwnerID:              id,
		Kind:                 TransportRestricted,
		State:                state,
		Provider:             "mihomo",
		Protocol:             ProtocolTCP,
		Port:                 8443,
		CredentialGeneration: 3,
		CredentialRef:        credentialRef,
		HandshakeHost:        "www.microsoft.com",
		ConfigHash:           digest("e"),
	}
}

func certificate(id string, kind CertificateKind, ownerKind, ownerID, certificateRef string, privateKeyRef SecretRef, notBefore, notAfter time.Time) Certificate {
	return Certificate{
		SchemaVersion:  ResourceSchemaVersion,
		ID:             id,
		Kind:           kind,
		OwnerKind:      ownerKind,
		OwnerID:        ownerID,
		Fingerprint:    fingerprint("f"),
		SerialHex:      "01",
		Subject:        "vpnctl test certificate",
		SANs:           []string{"IP:203.0.113.10"},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		WarningDays:    180,
		Generation:     1,
		CertificateRef: certificateRef,
		PrivateKeyRef:  privateKeyRef,
	}
}

func componentManifest() ComponentManifest {
	return ComponentManifest{
		SchemaVersion:            ComponentManifestSchemaVersion,
		ManifestVersion:          1,
		VPNCTLVersion:            "v2.0.0-dev",
		ControlProtocols:         []string{"1.0"},
		StateSchemaMinimum:       StateSchemaVersion,
		StateSchemaMaximum:       StateSchemaVersion,
		TargetOS:                 "ubuntu 24.04",
		TargetArchitecture:       "amd64",
		HandshakeHostListVersion: 1,
		MigrationReversible:      true,
		Components: []ComponentPin{{
			Name:         "vpnctl",
			Version:      "v2.0.0-dev",
			Source:       "bundle:vpnctl",
			Bundled:      true,
			SHA256:       digest("1"),
			Capabilities: []string{"cli", "controller"},
		}},
	}
}

func cloneState(t *testing.T, state State) State {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	var clone State
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return clone
}

func digest(character string) string {
	return strings.Repeat(character, 64)
}

func fingerprint(character string) string {
	return "sha256:" + digest(character)
}

func utc(year int, month time.Month, day, hour, minute int) time.Time {
	return time.Date(year, month, day, hour, minute, 0, 0, time.UTC)
}
