package control

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type RPCProtocolVersion struct {
	Major int
	Minor int
}

func (version RPCProtocolVersion) String() string {
	return strconv.Itoa(version.Major) + "." + strconv.Itoa(version.Minor)
}

func ParseRPCProtocolVersion(value string) (RPCProtocolVersion, error) {
	majorText, minorText, found := strings.Cut(value, ".")
	if !found || majorText == "" || minorText == "" || strings.Contains(minorText, ".") ||
		(len(majorText) > 1 && majorText[0] == '0') || (len(minorText) > 1 && minorText[0] == '0') {
		return RPCProtocolVersion{}, fmt.Errorf("control protocol must be canonical major.minor")
	}
	major, majorErr := strconv.Atoi(majorText)
	minor, minorErr := strconv.Atoi(minorText)
	if majorErr != nil || minorErr != nil || major < 1 || minor < 0 {
		return RPCProtocolVersion{}, fmt.Errorf("control protocol must be canonical major.minor")
	}
	return RPCProtocolVersion{Major: major, Minor: minor}, nil
}

func rpcPath(major int, operation string) string {
	return "/rpc/v" + strconv.Itoa(major) + "/" + operation
}

type RPCProtocolRegistration struct {
	MaximumVersion RPCProtocolVersion
	Handler        RPCHandler
}

type RPCProtocolRegistry struct {
	current  RPCProtocolRegistration
	previous *RPCProtocolRegistration
}

func NewRPCProtocolRegistry(current RPCProtocolRegistration, previous *RPCProtocolRegistration) (*RPCProtocolRegistry, error) {
	if err := validateProtocolRegistration("current", current); err != nil {
		return nil, err
	}
	registry := &RPCProtocolRegistry{current: current}
	if previous == nil {
		return registry, nil
	}
	if err := validateProtocolRegistration("previous", *previous); err != nil {
		return nil, err
	}
	if previous.MaximumVersion.Major != current.MaximumVersion.Major-1 {
		return nil, fmt.Errorf("previous control protocol major must immediately precede current major")
	}
	copy := *previous
	registry.previous = &copy
	return registry, nil
}

// NewRPCProtocolRegistryFromVersions binds the release manifest's ordered
// protocol versions to handlers without consulting the vpnctl binary version.
// The first entry is current; an optional second entry is the immediately
// previous major. Each version is that major's maximum additive minor.
func NewRPCProtocolRegistryFromVersions(versions []string, handlers map[int]RPCHandler) (*RPCProtocolRegistry, error) {
	if len(versions) < 1 || len(versions) > 2 {
		return nil, fmt.Errorf("control protocol registry requires current and at most one previous version")
	}
	parsed := make([]RPCProtocolVersion, len(versions))
	for index, value := range versions {
		version, err := ParseRPCProtocolVersion(value)
		if err != nil {
			return nil, fmt.Errorf("control protocol version %d: %w", index, err)
		}
		if handlers[version.Major] == nil {
			return nil, fmt.Errorf("control protocol major %d has no handler", version.Major)
		}
		parsed[index] = version
	}
	current := RPCProtocolRegistration{MaximumVersion: parsed[0], Handler: handlers[parsed[0].Major]}
	if len(parsed) == 1 {
		return NewRPCProtocolRegistry(current, nil)
	}
	previous := RPCProtocolRegistration{MaximumVersion: parsed[1], Handler: handlers[parsed[1].Major]}
	return NewRPCProtocolRegistry(current, &previous)
}

func (registry *RPCProtocolRegistry) SupportedVersions() []RPCProtocolVersion {
	if registry == nil {
		return []RPCProtocolVersion{}
	}
	versions := []RPCProtocolVersion{registry.current.MaximumVersion}
	if registry.previous != nil {
		versions = append(versions, registry.previous.MaximumVersion)
	}
	return versions
}

func (registry *RPCProtocolRegistry) HandleRPC(ctx context.Context, peer RPCPeer, request RPCRequest) (RPCHandlerResult, error) {
	if registry == nil || registry.current.Handler == nil {
		return RPCHandlerResult{}, fmt.Errorf("control protocol registry is incomplete")
	}
	registration, ok := registry.registration(request.ProtocolMajor)
	if !ok || request.ProtocolMinor > registration.MaximumVersion.Minor {
		return incompatibleProtocolResult(request, registry.SupportedVersions()), nil
	}
	result, err := registration.Handler.HandleRPC(ctx, peer, request)
	if err != nil {
		return RPCHandlerResult{}, err
	}
	result.Response.ProtocolMajor = request.ProtocolMajor
	result.Response.ProtocolMinor = request.ProtocolMinor
	return result, nil
}

func (registry *RPCProtocolRegistry) registration(major int) (RPCProtocolRegistration, bool) {
	if registry.current.MaximumVersion.Major == major {
		return registry.current, true
	}
	if registry.previous != nil && registry.previous.MaximumVersion.Major == major {
		return *registry.previous, true
	}
	return RPCProtocolRegistration{}, false
}

func validateProtocolRegistration(name string, registration RPCProtocolRegistration) error {
	if registration.MaximumVersion.Major < 1 || registration.MaximumVersion.Minor < 0 || registration.Handler == nil {
		return fmt.Errorf("%s control protocol registration is invalid", name)
	}
	return nil
}

func incompatibleProtocolResult(request RPCRequest, supported []RPCProtocolVersion) RPCHandlerResult {
	response := NewRPCResponse("conflict", 0, []byte(`{}`))
	response.ProtocolMajor = request.ProtocolMajor
	response.ProtocolMinor = request.ProtocolMinor
	response.ErrorCode = "incompatible_protocol"
	response.Message = "the gateway does not support the requested control protocol version"
	response.RequiresAction = []string{"update vpnctl to a mutually supported control protocol"}
	for _, version := range supported {
		response.Warnings = append(response.Warnings, "supported:"+version.String())
	}
	return RPCHandlerResult{StatusCode: http.StatusConflict, Response: response}
}
