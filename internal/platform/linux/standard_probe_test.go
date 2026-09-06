package linux

import (
	"context"
	"strings"
	"testing"
)

func TestStandardProbePathRejectsAnyUnmarkedOrNonGatewayShape(t *testing.T) {
	path := NewStandardProbePath()
	for _, test := range []struct {
		network string
		address string
	}{
		{network: "udp", address: "10.67.0.1:53"},
		{network: "tcp", address: "127.0.0.1:9443"},
		{network: "tcp", address: "0.0.0.0:9443"},
		{network: "tcp", address: "gateway.example:9443"},
		{network: "tcp", address: "10.67.0.1:0"},
	} {
		if connection, err := path.DialContext(context.Background(), test.network, test.address); err == nil {
			_ = connection.Close()
			t.Fatalf("unsafe standard probe dial accepted %s %s", test.network, test.address)
		}
	}
	if _, err := path.ExchangeUDP(context.Background(), "10.67.0.1:53", nil); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("empty standard probe UDP payload error = %v", err)
	}
	if _, err := path.ExchangeUDP(nil, "10.67.0.1:53", []byte("probe")); err == nil {
		t.Fatal("nil standard probe context was accepted")
	}
}
