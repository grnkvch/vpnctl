package model

import (
	"fmt"
	"strings"
)

const ReservedExposePathPrefix = "/.well-known/vpnctl"

const (
	MaximumExposeBodyLimitBytes         int64 = 8 * 1024 * 1024
	MaximumExposeUpstreamTimeoutSeconds       = 60
	MaximumExposeConcurrentRequests           = 40
)

// ValidateExposeName applies the same stable resource-name grammar used by an
// authoritative Expose record. Empty names remain valid only when the Expose
// field itself is optional.
func ValidateExposeName(value string) error {
	return validateName("name", value)
}

func ValidateResourceID(value string) error {
	return validateUUID("id", value)
}

func ValidateExposeUpstream(value string) error {
	return validateUpstream("upstream", value)
}

// IsReservedExposePath protects the complete vpnctl internal HTTP namespace,
// including its slashless root, from user routes.
func IsReservedExposePath(value string) bool {
	return value == ReservedExposePathPrefix || strings.HasPrefix(value, ReservedExposePathPrefix+"/")
}

// ValidateExposePath enforces the implementation-neutral route grammar. Prefix
// routes are stored without a trailing slash (except root) so every subtree has
// exactly one representation.
func ValidateExposePath(value string, mode RouteMode) error {
	if mode != RouteExact && mode != RoutePrefix {
		return invalid("route_mode", "unsupported value %q", mode)
	}
	if err := validateHTTPPath("path", value); err != nil {
		return err
	}
	if mode == RoutePrefix && value != "/" && strings.HasSuffix(value, "/") {
		return invalid("path", "prefix path must not end with a slash")
	}
	if IsReservedExposePath(value) {
		return invalid("path", "uses the reserved vpnctl namespace")
	}
	return nil
}

// ExposeRoutesOverlap reports whether two valid exact/prefix routes could
// select the same request path. Prefix matching is segment-aware: /api is an
// ancestor of /api and /api/..., but not /apiv2.
func ExposeRoutesOverlap(firstMode RouteMode, firstPath string, secondMode RouteMode, secondPath string) bool {
	switch {
	case firstMode == RouteExact && secondMode == RouteExact:
		return firstPath == secondPath
	case firstMode == RoutePrefix && secondMode == RouteExact:
		return exposePrefixContains(firstPath, secondPath)
	case firstMode == RouteExact && secondMode == RoutePrefix:
		return exposePrefixContains(secondPath, firstPath)
	case firstMode == RoutePrefix && secondMode == RoutePrefix:
		return exposePrefixContains(firstPath, secondPath) || exposePrefixContains(secondPath, firstPath)
	default:
		return false
	}
}

// ExposeRouteIndex detects active-route conflicts in time proportional to path
// depth, avoiding pairwise scans at the 10,000-port namespace ceiling.
type ExposeRouteIndex struct {
	root *exposeRouteNode
}

type exposeRouteNode struct {
	children    map[string]*exposeRouteNode
	exactOwner  string
	prefixOwner string
	firstOwner  string
}

func NewExposeRouteIndex() *ExposeRouteIndex {
	return &ExposeRouteIndex{root: &exposeRouteNode{children: make(map[string]*exposeRouteNode)}}
}

// Add returns the owner of an overlapping route. The empty result means the
// route was indexed successfully.
func (index *ExposeRouteIndex) Add(mode RouteMode, path, owner string) (string, error) {
	if index == nil || owner == "" {
		return "", fmt.Errorf("expose route index and owner are required")
	}
	if err := ValidateExposePath(path, mode); err != nil {
		return "", err
	}
	if index.root == nil {
		index.root = &exposeRouteNode{children: make(map[string]*exposeRouteNode)}
	}
	node := index.root
	visited := []*exposeRouteNode{node}
	segments := exposePathSegments(path)
	for _, segment := range segments {
		if node.prefixOwner != "" {
			return node.prefixOwner, nil
		}
		child := node.children[segment]
		if child == nil {
			child = &exposeRouteNode{children: make(map[string]*exposeRouteNode)}
			node.children[segment] = child
		}
		node = child
		visited = append(visited, node)
	}
	if node.prefixOwner != "" {
		return node.prefixOwner, nil
	}
	switch mode {
	case RouteExact:
		if node.exactOwner != "" {
			return node.exactOwner, nil
		}
		node.exactOwner = owner
	case RoutePrefix:
		if node.firstOwner != "" {
			return node.firstOwner, nil
		}
		node.prefixOwner = owner
	}
	for _, current := range visited {
		if current.firstOwner == "" {
			current.firstOwner = owner
		}
	}
	return "", nil
}

func exposePrefixContains(prefix, candidate string) bool {
	if prefix == "/" {
		return strings.HasPrefix(candidate, "/")
	}
	return candidate == prefix || strings.HasPrefix(candidate, prefix+"/")
}

func exposePathSegments(value string) []string {
	if value == "/" {
		return nil
	}
	trimmed := strings.TrimPrefix(value, "/")
	return strings.Split(trimmed, "/")
}
