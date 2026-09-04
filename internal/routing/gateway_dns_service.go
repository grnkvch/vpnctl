package routing

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/observability"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"golang.org/x/sys/unix"
)

const (
	gatewayDNSExchangeTimeout = 5 * time.Second
	gatewayDNSMaximumUDPBytes = 4096
	gatewayDNSMaximumTCPBytes = 65535
	gatewayDNSMaximumQueries  = 128
	gatewayDNSMaximumTCPTurns = 64
)

type gatewayDNSForwarder struct {
	listenEndpoints   []string
	upstreamEndpoints []string
	timeout           time.Duration
	maximumQueries    int
}

func newGatewayDNSForwarder(config GatewayDNSConfig) (*gatewayDNSForwarder, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	listeners := make([]string, 0, len(config.ListenIPv4))
	for _, address := range config.ListenIPv4 {
		listeners = append(listeners, net.JoinHostPort(address, fmt.Sprint(GatewayDNSPort)))
	}
	upstreams := make([]string, 0, len(config.UpstreamIPv4))
	for _, address := range config.UpstreamIPv4 {
		upstreams = append(upstreams, net.JoinHostPort(address, fmt.Sprint(GatewayDNSPort)))
	}
	return &gatewayDNSForwarder{
		listenEndpoints: listeners, upstreamEndpoints: upstreams,
		timeout: gatewayDNSExchangeTimeout, maximumQueries: gatewayDNSMaximumQueries,
	}, nil
}

// RunGatewayDNSService loads one identity-free gateway configuration and
// serves it until cancellation. It emits no query, answer, or upstream logs.
func RunGatewayDNSService(ctx context.Context, paths store.Paths) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return fmt.Errorf("gateway DNS service paths are invalid")
	}
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	content, err := readGatewayDNSConfigFile(filepath.Join(paths.ConfigDir, "generated", "gateway", GatewayDNSConfigFileName))
	if err != nil {
		return err
	}
	config, err := DecodeGatewayDNSConfig(content)
	if err != nil {
		return err
	}
	canonical, err := encodeGatewayDNSConfig(config)
	if err != nil || !bytes.Equal(content, canonical) {
		return fmt.Errorf("gateway DNS config is not canonical")
	}
	forwarder, err := newGatewayDNSForwarder(config)
	if err != nil {
		return err
	}
	_ = observability.EmitCode(ctx, observability.DNSServiceStarted)
	if err := forwarder.Serve(ctx); err != nil {
		_ = observability.EmitCode(context.WithoutCancel(ctx), observability.DNSRuntimeFailed)
		return err
	}
	_ = observability.EmitCode(context.WithoutCancel(ctx), observability.DNSServiceStopped)
	return nil
}

func (forwarder *gatewayDNSForwarder) Serve(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if forwarder == nil || len(forwarder.listenEndpoints) == 0 || len(forwarder.upstreamEndpoints) == 0 || forwarder.timeout <= 0 || forwarder.maximumQueries <= 0 {
		return fmt.Errorf("gateway DNS forwarder is incomplete")
	}
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	udpListeners := make([]*net.UDPConn, 0, len(forwarder.listenEndpoints))
	tcpListeners := make([]net.Listener, 0, len(forwarder.listenEndpoints))
	closeListeners := func() {
		for _, listener := range udpListeners {
			_ = listener.Close()
		}
		for _, listener := range tcpListeners {
			_ = listener.Close()
		}
	}
	for _, endpoint := range forwarder.listenEndpoints {
		address, err := net.ResolveUDPAddr("udp4", endpoint)
		if err != nil {
			closeListeners()
			return fmt.Errorf("resolve gateway DNS UDP listener: %w", err)
		}
		udpListener, err := net.ListenUDP("udp4", address)
		if err != nil {
			closeListeners()
			return fmt.Errorf("listen for gateway DNS UDP: %w", err)
		}
		udpListeners = append(udpListeners, udpListener)
		tcpListener, err := net.Listen("tcp4", endpoint)
		if err != nil {
			closeListeners()
			return fmt.Errorf("listen for gateway DNS TCP: %w", err)
		}
		tcpListeners = append(tcpListeners, tcpListener)
	}
	defer closeListeners()
	return forwarder.serveBound(ctx, udpListeners, tcpListeners)
}

func (forwarder *gatewayDNSForwarder) serveBound(ctx context.Context, udpListeners []*net.UDPConn, tcpListeners []net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	semaphore := make(chan struct{}, forwarder.maximumQueries)
	errorsOut := make(chan error, len(udpListeners)+len(tcpListeners))
	var listeners sync.WaitGroup
	var handlers sync.WaitGroup
	var connections sync.Map

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			for _, listener := range udpListeners {
				_ = listener.Close()
			}
			for _, listener := range tcpListeners {
				_ = listener.Close()
			}
			connections.Range(func(key, _ any) bool {
				_ = key.(net.Conn).Close()
				return true
			})
		case <-stop:
		}
	}()
	defer close(stop)

	for _, listener := range udpListeners {
		listener := listener
		listeners.Add(1)
		go func() {
			defer listeners.Done()
			errorsOut <- forwarder.serveUDP(ctx, listener, semaphore, &handlers)
		}()
	}
	for _, listener := range tcpListeners {
		listener := listener
		listeners.Add(1)
		go func() {
			defer listeners.Done()
			errorsOut <- forwarder.serveTCP(ctx, listener, semaphore, &handlers, &connections)
		}()
	}

	var result error
	select {
	case <-ctx.Done():
	case err := <-errorsOut:
		if err != nil {
			result = err
		}
		cancel()
	}
	listeners.Wait()
	handlers.Wait()
	if result != nil {
		return result
	}
	return nil
}

func (forwarder *gatewayDNSForwarder) serveUDP(ctx context.Context, listener *net.UDPConn, semaphore chan struct{}, handlers *sync.WaitGroup) error {
	buffer := make([]byte, gatewayDNSMaximumUDPBytes+1)
	for {
		count, client, err := listener.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read gateway DNS UDP request: %w", err)
		}
		if count > gatewayDNSMaximumUDPBytes || validateDNSQuery(buffer[:count]) != nil {
			continue
		}
		select {
		case semaphore <- struct{}{}:
			query := append([]byte(nil), buffer[:count]...)
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { <-semaphore }()
				response, err := forwarder.exchange(ctx, "udp4", query, gatewayDNSMaximumUDPBytes)
				if err == nil {
					_, _ = listener.WriteToUDP(response, client)
				}
			}()
		default:
		}
	}
}

func (forwarder *gatewayDNSForwarder) serveTCP(ctx context.Context, listener net.Listener, semaphore chan struct{}, handlers *sync.WaitGroup, connections *sync.Map) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept gateway DNS TCP connection: %w", err)
		}
		select {
		case semaphore <- struct{}{}:
			connections.Store(connection, struct{}{})
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { <-semaphore }()
				defer connections.Delete(connection)
				defer connection.Close()
				forwarder.handleTCP(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (forwarder *gatewayDNSForwarder) handleTCP(ctx context.Context, connection net.Conn) {
	length := make([]byte, 2)
	for turn := 0; turn < gatewayDNSMaximumTCPTurns; turn++ {
		_ = connection.SetDeadline(time.Now().Add(forwarder.timeout))
		if _, err := io.ReadFull(connection, length); err != nil {
			return
		}
		count := int(binary.BigEndian.Uint16(length))
		if count < 12 || count > gatewayDNSMaximumTCPBytes {
			return
		}
		query := make([]byte, count)
		if _, err := io.ReadFull(connection, query); err != nil || validateDNSQuery(query) != nil {
			return
		}
		response, err := forwarder.exchange(ctx, "tcp4", query, gatewayDNSMaximumTCPBytes)
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(length, uint16(len(response)))
		if err := writeAll(connection, length); err != nil || writeAll(connection, response) != nil {
			return
		}
	}
}

func (forwarder *gatewayDNSForwarder) exchange(ctx context.Context, network string, query []byte, maximumResponse int) ([]byte, error) {
	if err := validateDNSQuery(query); err != nil {
		return nil, err
	}
	var lastErr error
	for _, endpoint := range forwarder.upstreamEndpoints {
		exchangeCtx, cancel := context.WithTimeout(ctx, forwarder.timeout)
		var response []byte
		connection, err := (&net.Dialer{}).DialContext(exchangeCtx, network, endpoint)
		if err == nil {
			_ = connection.SetDeadline(time.Now().Add(forwarder.timeout))
			if network == "udp4" {
				response, err = exchangeDNSUDP(connection, query, maximumResponse)
			} else {
				response, err = exchangeDNSTCP(connection, query, maximumResponse)
			}
			_ = connection.Close()
		}
		cancel()
		if err == nil && validateDNSResponse(query, response) == nil {
			return response, nil
		}
		if err == nil {
			err = fmt.Errorf("upstream returned an invalid DNS response")
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no gateway DNS upstream is available")
	}
	return nil, lastErr
}

func exchangeDNSUDP(connection net.Conn, query []byte, maximum int) ([]byte, error) {
	if err := writeAll(connection, query); err != nil {
		return nil, err
	}
	response := make([]byte, maximum+1)
	count, err := connection.Read(response)
	if err != nil {
		return nil, err
	}
	if count > maximum {
		return nil, fmt.Errorf("gateway DNS UDP response exceeds size limit")
	}
	return append([]byte(nil), response[:count]...), nil
}

func exchangeDNSTCP(connection net.Conn, query []byte, maximum int) ([]byte, error) {
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if err := writeAll(connection, frame); err != nil {
		return nil, err
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	count := int(binary.BigEndian.Uint16(header))
	if count < 12 || count > maximum {
		return nil, fmt.Errorf("gateway DNS TCP response has invalid size")
	}
	response := make([]byte, count)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, nil
}

func validateDNSQuery(message []byte) error {
	if len(message) < 12 || message[2]&0x80 != 0 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return fmt.Errorf("invalid DNS query")
	}
	if _, err := dnsQuestionEnd(message); err != nil {
		return err
	}
	return nil
}

func validateDNSResponse(query, response []byte) error {
	if len(response) < 12 || !bytes.Equal(query[:2], response[:2]) || response[2]&0x80 == 0 || response[2]&0x78 != query[2]&0x78 ||
		binary.BigEndian.Uint16(response[4:6]) != binary.BigEndian.Uint16(query[4:6]) {
		return fmt.Errorf("invalid DNS response")
	}
	queryEnd, queryErr := dnsQuestionEnd(query)
	responseEnd, responseErr := dnsQuestionEnd(response)
	if queryErr != nil || responseErr != nil || !bytes.Equal(query[12:queryEnd], response[12:responseEnd]) {
		return fmt.Errorf("DNS response question does not match request")
	}
	return nil
}

func dnsQuestionEnd(message []byte) (int, error) {
	offset := 12
	for labels := 0; labels < 128; labels++ {
		if offset >= len(message) {
			return 0, fmt.Errorf("DNS question name is truncated")
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			if offset+4 > len(message) {
				return 0, fmt.Errorf("DNS question type or class is truncated")
			}
			return offset + 4, nil
		}
		if length&0xc0 == 0xc0 {
			if offset >= len(message) {
				return 0, fmt.Errorf("DNS question compression pointer is truncated")
			}
			offset++
			if offset+4 > len(message) {
				return 0, fmt.Errorf("DNS question type or class is truncated")
			}
			return offset + 4, nil
		}
		if length > 63 || offset+length > len(message) {
			return 0, fmt.Errorf("DNS question label is invalid")
		}
		offset += length
	}
	return 0, fmt.Errorf("DNS question has too many labels")
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) != 0 {
		count, err := writer.Write(content)
		if err != nil {
			return err
		}
		if count <= 0 {
			return io.ErrShortWrite
		}
		content = content[count:]
	}
	return nil
}

func encodeGatewayDNSConfig(config GatewayDNSConfig) ([]byte, error) {
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func readGatewayDNSConfigFile(path string) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open gateway DNS config: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("open gateway DNS config")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maximumGatewayDNSConfigBytes {
		return nil, fmt.Errorf("gateway DNS config must be a bounded root-only regular file")
	}
	return io.ReadAll(io.LimitReader(file, maximumGatewayDNSConfigBytes+1))
}
