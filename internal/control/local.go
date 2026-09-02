package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"
)

const (
	LocalSchemaVersion = 1
	LocalMaximumBytes  = 64 << 10
	LocalTimeout       = 5 * time.Second
)

type LocalMethod string

const (
	LocalObserve LocalMethod = "observe"
	LocalMutate  LocalMethod = "mutate"
)

type LocalRequest struct {
	SchemaVersion      int             `json:"schema_version"`
	Method             LocalMethod     `json:"method"`
	Operation          string          `json:"operation,omitempty"`
	ExpectedGeneration uint64          `json:"expected_generation,omitempty"`
	Payload            json.RawMessage `json:"payload,omitempty"`
}

type LocalResponse struct {
	SchemaVersion int             `json:"schema_version"`
	OK            bool            `json:"ok"`
	Generation    uint64          `json:"generation,omitempty"`
	ErrorCode     string          `json:"error_code,omitempty"`
	Message       string          `json:"message,omitempty"`
	Data          json.RawMessage `json:"data,omitempty"`
}

// CallLocal performs one bounded request over the root-only controller socket.
// Application failures remain represented by a valid response; the returned
// error is reserved for transport and protocol-boundary failures.
func CallLocal(ctx context.Context, socketPath string, request LocalRequest) (LocalResponse, error) {
	if ctx == nil {
		return LocalResponse{}, fmt.Errorf("context is required")
	}
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return LocalResponse{}, fmt.Errorf("local controller socket path must be clean and absolute")
	}
	if request.SchemaVersion != LocalSchemaVersion {
		return LocalResponse{}, fmt.Errorf("unsupported local request schema")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return LocalResponse{}, fmt.Errorf("encode local controller request: %w", err)
	}
	if len(encoded) > LocalMaximumBytes {
		return LocalResponse{}, fmt.Errorf("local controller request exceeds the size limit")
	}

	deadline := time.Now().Add(LocalTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return LocalResponse{}, fmt.Errorf("connect to local controller: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(deadline); err != nil {
		return LocalResponse{}, fmt.Errorf("bound local controller request: %w", err)
	}
	if _, err := connection.Write(encoded); err != nil {
		return LocalResponse{}, fmt.Errorf("write local controller request: %w", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return LocalResponse{}, fmt.Errorf("local controller connection is not Unix")
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return LocalResponse{}, fmt.Errorf("finish local controller request: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(connection, LocalMaximumBytes+1))
	if err != nil {
		return LocalResponse{}, fmt.Errorf("read local controller response: %w", err)
	}
	if len(data) > LocalMaximumBytes {
		return LocalResponse{}, fmt.Errorf("local controller response exceeds the size limit")
	}
	response, err := DecodeLocalResponse(data)
	if err != nil {
		return LocalResponse{}, fmt.Errorf("decode local controller response: %w", err)
	}
	return response, nil
}
