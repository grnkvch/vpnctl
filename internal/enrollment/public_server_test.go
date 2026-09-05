package enrollment

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPublicEnrollmentServerServesOnlyLoopbackAndStopsWithContext(t *testing.T) {
	server, err := NewPublicEnrollmentServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != InviteEnrollmentPath {
			t.Fatalf("path = %q", request.URL.Path)
		}
		writer.Header().Set("Connection", "close")
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener) }()

	request, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+InviteEnrollmentPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Close = true
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", response.StatusCode)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve() shutdown error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("public enrollment server did not stop")
	}
}

func TestPublicEnrollmentServerRejectsNonLoopbackListener(t *testing.T) {
	server, err := NewPublicEnrollmentServer(http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	listener := &stubPublicEnrollmentListener{address: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 19092}}
	err = server.Serve(context.Background(), listener)
	if err == nil || !strings.Contains(err.Error(), "IPv4 loopback") || !listener.closed {
		t.Fatalf("Serve() error = %v, closed = %t", err, listener.closed)
	}
}

func TestPublicEnrollmentServerListenUsesFixedAddress(t *testing.T) {
	server, err := NewPublicEnrollmentServer(http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("sentinel listen failure")
	server.listen = func(network, address string) (net.Listener, error) {
		if network != "tcp4" || address != PublicEnrollmentLoopbackAddress {
			t.Fatalf("listen(%q, %q)", network, address)
		}
		return nil, want
	}
	if err := server.ListenAndServe(context.Background()); !errors.Is(err, want) {
		t.Fatalf("ListenAndServe() error = %v", err)
	}
}

type stubPublicEnrollmentListener struct {
	address net.Addr
	closed  bool
}

func (*stubPublicEnrollmentListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (listener *stubPublicEnrollmentListener) Close() error {
	listener.closed = true
	return nil
}
func (listener *stubPublicEnrollmentListener) Addr() net.Addr { return listener.address }
