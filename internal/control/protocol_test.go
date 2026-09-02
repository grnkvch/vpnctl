package control

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestRPCProtocolVersionUsesCanonicalMajorMinor(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"1.0", "2.17", "123.456"} {
		version, err := ParseRPCProtocolVersion(value)
		if err != nil || version.String() != value {
			t.Errorf("ParseRPCProtocolVersion(%q) = %+v, %v", value, version, err)
		}
	}
	for _, value := range []string{"", "0.1", "01.0", "1.00", "1", "1.-1", "1.2.3", "v1.0", " 1.0"} {
		if _, err := ParseRPCProtocolVersion(value); err == nil {
			t.Errorf("ParseRPCProtocolVersion(%q) error = nil", value)
		}
	}
}

func TestRPCProtocolRegistryDispatchesAdditiveMinorAndPreviousMajor(t *testing.T) {
	t.Parallel()

	current := &recordingProtocolHandler{name: "current"}
	previous := &recordingProtocolHandler{name: "previous"}
	registry, err := NewRPCProtocolRegistryFromVersions(
		[]string{"2.3", "1.5"},
		map[int]RPCHandler{1: previous, 2: current},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.SupportedVersions(); !reflect.DeepEqual(got, []RPCProtocolVersion{{Major: 2, Minor: 3}, {Major: 1, Minor: 5}}) {
		t.Fatalf("SupportedVersions() = %+v", got)
	}

	for _, version := range []RPCProtocolVersion{{Major: 2, Minor: 0}, {Major: 2, Minor: 3}, {Major: 1, Minor: 0}, {Major: 1, Minor: 5}} {
		request := validRPCRequest(time.Now().UTC())
		request.ProtocolMajor, request.ProtocolMinor = version.Major, version.Minor
		result, err := registry.HandleRPC(context.Background(), RPCPeer{NodeID: testNodeID}, request)
		if err != nil || result.StatusCode != http.StatusOK || result.Response.ProtocolMajor != version.Major || result.Response.ProtocolMinor != version.Minor {
			t.Fatalf("HandleRPC(%s) = %+v, %v", version, result, err)
		}
	}
	if !reflect.DeepEqual(current.versions, []RPCProtocolVersion{{Major: 2, Minor: 0}, {Major: 2, Minor: 3}}) ||
		!reflect.DeepEqual(previous.versions, []RPCProtocolVersion{{Major: 1, Minor: 0}, {Major: 1, Minor: 5}}) {
		t.Fatalf("dispatch current/previous = %+v / %+v", current.versions, previous.versions)
	}

	for _, version := range []RPCProtocolVersion{{Major: 2, Minor: 4}, {Major: 1, Minor: 6}, {Major: 3, Minor: 0}} {
		request := validRPCRequest(time.Now().UTC())
		request.ProtocolMajor, request.ProtocolMinor = version.Major, version.Minor
		result, err := registry.HandleRPC(context.Background(), RPCPeer{NodeID: testNodeID}, request)
		if err != nil || result.StatusCode != http.StatusConflict || result.Response.ErrorCode != "incompatible_protocol" ||
			result.Response.ProtocolMajor != version.Major || result.Response.ProtocolMinor != version.Minor {
			t.Fatalf("incompatible HandleRPC(%s) = %+v, %v", version, result, err)
		}
	}
	if len(current.versions) != 2 || len(previous.versions) != 2 {
		t.Fatal("incompatible protocol reached an operation handler")
	}
}

func TestRPCProtocolRegistryRejectsInvalidCompatibilityWindows(t *testing.T) {
	t.Parallel()

	handler := successRPCHandler()
	for name, versions := range map[string][]string{
		"empty": {}, "too-many": {"3.0", "2.0", "1.0"}, "non-canonical": {"01.0"}, "non-adjacent": {"3.0", "1.9"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRPCProtocolRegistryFromVersions(versions, map[int]RPCHandler{1: handler, 2: handler, 3: handler}); err == nil {
				t.Fatalf("NewRPCProtocolRegistryFromVersions(%v) error = nil", versions)
			}
		})
	}
	if _, err := NewRPCProtocolRegistryFromVersions([]string{"2.0", "1.0"}, map[int]RPCHandler{2: handler}); err == nil {
		t.Fatal("registry accepted a previous major without a compiled handler")
	}
}

func TestRPCGatewayFirstRollingCompatibilityOverMTLS(t *testing.T) {
	t.Parallel()

	current := &recordingProtocolHandler{name: "current"}
	previous := &recordingProtocolHandler{name: "previous"}
	protocols, err := NewRPCProtocolRegistryFromVersions(
		[]string{"2.2", "1.4"},
		map[int]RPCHandler{1: previous, 2: current},
	)
	if err != nil {
		t.Fatal(err)
	}
	material, node := rpcTestIdentities(t)
	server, err := newRPCServer(RPCServerConfig{
		GatewayID: testGatewayID, NodeCIDR: "127.0.0.0/8",
		CertificatePEM: material.GatewayCertificatePEM, PrivateKeyPEM: material.GatewayPrivateKeyPEM,
		ClientCACertificatePEM: material.ControlCACertificatePEM, Protocols: protocols, Authorizer: allowAllRPCAuthorizer(),
	}, defaultRPCLimits())
	if err != nil {
		t.Fatal(err)
	}
	fixture := startRPCTestFixture(t, server, material, node)

	for _, test := range []struct {
		version  RPCProtocolVersion
		status   int
		category string
	}{
		{version: RPCProtocolVersion{Major: 1, Minor: 3}, status: http.StatusOK, category: "success"},
		{version: RPCProtocolVersion{Major: 2, Minor: 1}, status: http.StatusOK, category: "success"},
		{version: RPCProtocolVersion{Major: 2, Minor: 3}, status: http.StatusConflict, category: "conflict"},
		{version: RPCProtocolVersion{Major: 3, Minor: 0}, status: http.StatusConflict, category: "conflict"},
	} {
		request := validRPCRequest(time.Now().UTC())
		request.ProtocolMajor, request.ProtocolMinor = test.version.Major, test.version.Minor
		result, err := fixture.client.Call(context.Background(), request)
		if err != nil || result.StatusCode != test.status || result.Response.Category != test.category ||
			result.Response.ProtocolMajor != test.version.Major || result.Response.ProtocolMinor != test.version.Minor {
			t.Fatalf("rolling call %s = %+v, %v", test.version, result, err)
		}
	}

	mismatch := validRPCRequest(time.Now().UTC())
	mismatch.ProtocolMajor, mismatch.ProtocolMinor = 2, 0
	body, _ := json.Marshal(mismatch)
	response := fixture.rawRequest(t, body, RPCContentType, rpcPath(1, mismatch.Operation))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("path/envelope breaking-major mismatch status = %d", response.StatusCode)
	}
	assertTypedRPCFailure(t, response, "protocol_path_mismatch")
}

type recordingProtocolHandler struct {
	name     string
	mu       sync.Mutex
	versions []RPCProtocolVersion
}

func (handler *recordingProtocolHandler) HandleRPC(_ context.Context, _ RPCPeer, request RPCRequest) (RPCHandlerResult, error) {
	handler.mu.Lock()
	handler.versions = append(handler.versions, RPCProtocolVersion{Major: request.ProtocolMajor, Minor: request.ProtocolMinor})
	handler.mu.Unlock()
	response := NewRPCResponse("success", 42, json.RawMessage(`{"handler":"`+handler.name+`"}`))
	return RPCHandlerResult{StatusCode: http.StatusOK, Response: response}, nil
}
