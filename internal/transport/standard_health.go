package transport

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const DefaultStandardHandshakeMaxAge = 3 * time.Minute

type StandardHealthExpectation struct {
	Identity           Identity
	RuntimeRole        RuntimeRole
	HostRole           model.Role
	InterfacePublicKey string
	LocalAddresses     []string
	PeerPublicKey      string
	PeerAllowedIPs     []string
	RequireHandshake   bool
	HandshakeMaxAge    time.Duration
}

type StandardHealthObserver struct {
	runner linuxplatform.ProbeRunner
	now    func() time.Time
}

func NewStandardHealthObserver(runner linuxplatform.ProbeRunner, now func() time.Time) (*StandardHealthObserver, error) {
	if runner == nil {
		return nil, fmt.Errorf("standard health runner is required")
	}
	if now == nil {
		now = time.Now
	}
	return &StandardHealthObserver{runner: runner, now: now}, nil
}

// Observe uses only read-only wg/ip queries. It reports runtime reachability
// independently from the authoritative active/standby role and never probes,
// repairs, restarts, or switches either transport.
func (observer *StandardHealthObserver) Observe(ctx context.Context, expected StandardHealthExpectation) (Health, error) {
	health := Health{Identity: expected.Identity, Kind: model.TransportStandard, Role: expected.RuntimeRole}
	if ctx == nil {
		return Health{}, fmt.Errorf("context is required")
	}
	if observer == nil || observer.runner == nil || observer.now == nil {
		return Health{}, fmt.Errorf("standard health observer is incomplete")
	}
	if expected.RequireHandshake && expected.HandshakeMaxAge == 0 {
		expected.HandshakeMaxAge = DefaultStandardHandshakeMaxAge
	}
	if err := validateStandardHealthExpectation(expected); err != nil {
		return Health{}, err
	}

	publicKey, available, err := observer.query(ctx, "wg", "show", StandardInterfaceName, "public-key")
	if err != nil {
		return Health{}, err
	}
	if !available {
		return standardHealthResult(health, HealthUnavailable, "wireguard-interface-unavailable")
	}
	if strings.TrimSpace(publicKey) != expected.InterfacePublicKey {
		return standardHealthResult(health, HealthUnavailable, "wireguard-interface-key-mismatch")
	}
	if expected.HostRole == model.RoleGateway {
		listenPort, ok, err := observer.query(ctx, "wg", "show", StandardInterfaceName, "listen-port")
		if err != nil {
			return Health{}, err
		}
		if !ok || strings.TrimSpace(listenPort) != strconv.Itoa(StandardUDPPort) {
			return standardHealthResult(health, HealthUnavailable, "wireguard-listen-port-mismatch")
		}
	}

	addresses, ok, err := observer.query(ctx, "ip", "-4", "-o", "address", "show", "dev", StandardInterfaceName)
	if err != nil {
		return Health{}, err
	}
	if !ok || !equalStrings(parseInterfaceAddresses(addresses), normalizedStrings(expected.LocalAddresses)) {
		return standardHealthResult(health, HealthUnavailable, "wireguard-overlay-address-mismatch")
	}

	allowed, ok, err := observer.query(ctx, "wg", "show", StandardInterfaceName, "allowed-ips")
	if err != nil {
		return Health{}, err
	}
	if !ok {
		return standardHealthResult(health, HealthUnavailable, "wireguard-peer-state-unavailable")
	}
	peerAllowed, found := parsePeerValues(allowed)[expected.PeerPublicKey]
	if !found {
		return standardHealthResult(health, HealthUnavailable, "wireguard-peer-missing")
	}
	if !equalStrings(peerAllowed, normalizedStrings(expected.PeerAllowedIPs)) {
		return standardHealthResult(health, HealthUnavailable, "wireguard-allowed-ips-mismatch")
	}

	if expected.RequireHandshake {
		handshakes, ok, err := observer.query(ctx, "wg", "show", StandardInterfaceName, "latest-handshakes")
		if err != nil {
			return Health{}, err
		}
		if !ok {
			return standardHealthResult(health, HealthUnavailable, "wireguard-peer-state-unavailable")
		}
		values, found := parsePeerValues(handshakes)[expected.PeerPublicKey]
		if !found || len(values) != 1 {
			return standardHealthResult(health, HealthUnavailable, "wireguard-peer-missing")
		}
		seconds, parseErr := strconv.ParseInt(values[0], 10, 64)
		if parseErr != nil || seconds < 0 {
			return standardHealthResult(health, HealthUnavailable, "wireguard-handshake-invalid")
		}
		if seconds == 0 {
			return standardHealthResult(health, HealthDegraded, "wireguard-handshake-missing")
		}
		age := observer.now().Sub(time.Unix(seconds, 0))
		if age < 0 || age > expected.HandshakeMaxAge {
			return standardHealthResult(health, HealthDegraded, "wireguard-handshake-stale")
		}
	}
	return standardHealthResult(health, HealthHealthy, "wireguard-healthy")
}

func (observer *StandardHealthObserver) query(ctx context.Context, name string, arguments ...string) (string, bool, error) {
	result, err := observer.runner.Run(ctx, linuxplatform.ProbeCommand{Name: name, Args: arguments})
	if err != nil {
		return "", false, fmt.Errorf("observe standard transport: %w", err)
	}
	if result.ExitCode != 0 {
		return "", false, nil
	}
	return string(result.Stdout), true, nil
}

func validateStandardHealthExpectation(expected StandardHealthExpectation) error {
	if err := expected.Identity.Validate(); err != nil {
		return err
	}
	if expected.RuntimeRole != RuntimeActive && expected.RuntimeRole != RuntimeStandby {
		return fmt.Errorf("standard runtime role must be active or standby")
	}
	if expected.HostRole != model.RoleGateway && expected.HostRole != model.RoleNode {
		return fmt.Errorf("standard host role must be gateway or node")
	}
	if err := wireguard.ValidateKey(expected.InterfacePublicKey); err != nil {
		return fmt.Errorf("standard interface public key is invalid: %w", err)
	}
	if err := wireguard.ValidateKey(expected.PeerPublicKey); err != nil {
		return fmt.Errorf("standard peer public key is invalid: %w", err)
	}
	if expected.InterfacePublicKey == expected.PeerPublicKey {
		return fmt.Errorf("standard interface and peer public keys must differ")
	}
	if len(expected.LocalAddresses) == 0 || len(expected.PeerAllowedIPs) == 0 {
		return fmt.Errorf("standard local addresses and peer allowed IPs are required")
	}
	for _, values := range [][]string{expected.LocalAddresses, expected.PeerAllowedIPs} {
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !prefix.Addr().Is4() || prefix.String() != value {
				return fmt.Errorf("standard health addresses must be canonical IPv4 prefixes")
			}
			if _, duplicate := seen[value]; duplicate {
				return fmt.Errorf("standard health addresses must be unique")
			}
			seen[value] = struct{}{}
		}
	}
	if expected.HostRole == model.RoleGateway {
		if len(expected.LocalAddresses) != 2 || len(expected.PeerAllowedIPs) != 1 {
			return fmt.Errorf("gateway standard health requires two local pools and one peer /32")
		}
		peer, _ := netip.ParsePrefix(expected.PeerAllowedIPs[0])
		if peer.Bits() != 32 {
			return fmt.Errorf("gateway standard peer must own exactly one IPv4 /32")
		}
	} else {
		local, _ := netip.ParsePrefix(expected.LocalAddresses[0])
		if len(expected.LocalAddresses) != 1 || local.Bits() != 32 || len(expected.PeerAllowedIPs) != 1 || expected.PeerAllowedIPs[0] != "0.0.0.0/0" {
			return fmt.Errorf("node standard health requires one local /32 and gateway 0.0.0.0/0")
		}
	}
	if expected.RequireHandshake {
		if expected.HandshakeMaxAge < time.Second || expected.HandshakeMaxAge > time.Hour {
			return fmt.Errorf("standard handshake maximum age must be between one second and one hour")
		}
	}
	return nil
}

func standardHealthResult(base Health, condition HealthCondition, code string) (Health, error) {
	base.Condition = condition
	base.Code = code
	return base, base.Validate()
}

func parseInterfaceAddresses(output string) []string {
	values := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for index := range fields {
			if fields[index] == "inet" && index+1 < len(fields) {
				if prefix, err := netip.ParsePrefix(fields[index+1]); err == nil {
					values = append(values, prefix.String())
				}
				break
			}
		}
	}
	return normalizedStrings(values)
}

func parsePeerValues(output string) map[string][]string {
	result := make(map[string][]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result[fields[0]] = append([]string(nil), fields[1:]...)
		}
	}
	return result
}

func normalizedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
