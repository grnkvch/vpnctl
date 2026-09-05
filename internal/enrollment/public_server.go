package enrollment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"

	"github.com/vgrinkevich/vpnctl/internal/control"
)

const PublicEnrollmentLoopbackAddress = "127.0.0.1:19092"

// PublicEnrollmentServer serves the public enrollment handler only on the
// fixed loopback upstream consumed by the managed nginx configuration. TLS,
// rate limiting, and the public health endpoint remain edge responsibilities.
type PublicEnrollmentServer struct {
	handler http.Handler
	listen  func(string, string) (net.Listener, error)
}

func NewPublicEnrollmentServer(handler http.Handler) (*PublicEnrollmentServer, error) {
	if handler == nil {
		return nil, fmt.Errorf("public enrollment handler is required")
	}
	return &PublicEnrollmentServer{handler: handler, listen: net.Listen}, nil
}

func (server *PublicEnrollmentServer) ListenAndServe(ctx context.Context) error {
	if server == nil || server.handler == nil || server.listen == nil || ctx == nil {
		return fmt.Errorf("public enrollment server is incomplete")
	}
	listener, err := server.listen("tcp4", PublicEnrollmentLoopbackAddress)
	if err != nil {
		return fmt.Errorf("listen on public enrollment loopback: %w", err)
	}
	return server.Serve(ctx, listener)
}

// Serve is exposed for bounded socket-level tests. Production callers use
// ListenAndServe, which fixes the exact address before reaching this boundary.
func (server *PublicEnrollmentServer) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || server.handler == nil || ctx == nil || listener == nil {
		return fmt.Errorf("public enrollment server is incomplete")
	}
	if err := validatePublicEnrollmentListener(listener.Addr()); err != nil {
		_ = listener.Close()
		return err
	}
	httpServer := &http.Server{
		Handler:           server.handler,
		ReadHeaderTimeout: control.RPCReadHeaderTimeout,
		ReadTimeout:       control.RPCReadBodyTimeout,
		WriteTimeout:      control.RPCWriteTimeout,
		IdleTimeout:       control.RPCIdleTimeout,
		MaxHeaderBytes:    control.RPCMaximumHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	httpServer.SetKeepAlivesEnabled(false)

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), control.RPCWriteTimeout)
			defer cancel()
			_ = httpServer.Shutdown(shutdownContext)
		case <-stopped:
		}
	}()
	err := httpServer.Serve(listener)
	close(stopped)
	if ctx.Err() != nil && (err == nil || errors.Is(err, http.ErrServerClosed)) {
		return nil
	}
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("public enrollment server stopped unexpectedly")
	}
	return fmt.Errorf("serve public enrollment loopback: %w", err)
}

func validatePublicEnrollmentListener(address net.Addr) error {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("public enrollment listener must use TCP")
	}
	parsed, ok := netip.AddrFromSlice(tcpAddress.IP)
	if !ok || parsed.Unmap() != netip.MustParseAddr("127.0.0.1") || tcpAddress.Port < 1 || tcpAddress.Port > 65535 {
		return fmt.Errorf("public enrollment listener must use IPv4 loopback")
	}
	return nil
}

var _ interface {
	ListenAndServe(context.Context) error
} = (*PublicEnrollmentServer)(nil)
