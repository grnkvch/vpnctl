package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestSystemControlRPCServesNodeUpdatePreflightOnOverlay(t *testing.T) {
	fixture := newGatewayRenewalFixture(t)
	server, err := newSystemControlRPC(context.Background(), fixture.controller, fixture.state, fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveContext, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(serveContext, listener) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("system control RPC shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("system control RPC did not stop")
		}
	})

	state, err := fixture.state.Load()
	if err != nil {
		t.Fatal(err)
	}
	target := state.Components
	target.VPNCTLVersion = "v2.0.0"
	for index := range target.Components {
		if target.Components[index].Name == "vpnctl" {
			target.Components[index].Version = target.VPNCTLVersion
		}
	}
	payload, err := json.Marshal(lifecycle.NodeUpdatePreflightPayload{TargetManifest: target})
	if err != nil {
		t.Fatal(err)
	}
	client, err := control.NewRPCClient(control.RPCClientConfig{
		Address: listener.Addr().String(), GatewayID: state.Host.ID, NodeID: mutationTestNodeID,
		CACertificatePEM: fixture.preservedSecrets[model.SecretRef(control.ControlCACertificateRef)],
		CertificatePEM:   fixture.preservedSecrets[model.SecretRef(fixture.initialNodeCertificate.CertificateRef)],
		PrivateKeyPEM:    fixture.clientPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Call(context.Background(), control.RPCRequest{
		ProtocolMajor: 1, ProtocolMinor: 0, RequestID: "76000000-0000-4000-8000-000000000001",
		ExpectedStateGeneration: state.Generation, NodeID: mutationTestNodeID, CredentialGeneration: 1,
		Timestamp: time.Now().UTC(), Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, control.RPCNonceBytes)),
		Operation: lifecycle.NodeUpdatePreflightOperation, Payload: payload,
	})
	if err != nil || result.StatusCode != http.StatusOK || result.Response.Category != "success" {
		t.Fatalf("system update preflight = %+v, %v", result, err)
	}
	var compatibility lifecycle.NodeUpdateCompatibility
	if err := control.DecodeRPCPayload(result.Response.Data, &compatibility); err != nil {
		t.Fatal(err)
	}
	if !compatibility.Compatible || compatibility.SelectedProtocol != "1.0" {
		t.Fatalf("system update compatibility = %+v", compatibility)
	}
}

func TestRunSystemManagementCancelsSiblingAndReturnsFailure(t *testing.T) {
	want := errors.New("local listener failed")
	siblingStopped := make(chan struct{})
	err := runSystemManagement(context.Background(),
		func(context.Context) error { return want },
		func(ctx context.Context) error {
			<-ctx.Done()
			close(siblingStopped)
			return nil
		},
	)
	if !errors.Is(err, want) {
		t.Fatalf("runSystemManagement() error = %v, want %v", err, want)
	}
	select {
	case <-siblingStopped:
	default:
		t.Fatal("sibling management service was not stopped")
	}
}

func TestRunSystemManagementTreatsUnexpectedCleanExitAsFailure(t *testing.T) {
	err := runSystemManagement(context.Background(), func(context.Context) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Fatalf("runSystemManagement() error = %v", err)
	}
}

func TestRunSystemManagementReturnsCleanlyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runSystemManagement(ctx, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("runSystemManagement() error = %v", err)
	}
}
