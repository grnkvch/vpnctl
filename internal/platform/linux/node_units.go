package linux

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const nodeBootstrapConfig = `schema_version=1
role=node
enrollment_status=unjoined
`

// RenderNodeRoleInstallation returns the node-owned process units in a staged
// state. init --node establishes only the immutable host role; join writes the
// enrolled identity and generated configs before enabling or starting these
// units.
func RenderNodeRoleInstallation(binaryPath string) (RoleInstallationRequest, error) {
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath || strings.ContainsAny(binaryPath, " \t\r\n%") {
		return RoleInstallationRequest{}, fmt.Errorf("node service binary path must be clean, absolute, and systemd-safe")
	}
	modes := map[string]string{
		"vpnctl-routing-guard.service": "node-routing-guard",
		"vpnctl-routing.service":       "node-routing",
		"vpnctl-standard.service":      "node-standard",
		"vpnctl-tunnel-client.service": "node-tunnel-client",
	}
	names := make([]string, 0, len(modes))
	for name := range modes {
		names = append(names, name)
	}
	sort.Strings(names)
	units := make([]RoleUnitFile, 0, len(names))
	for _, name := range names {
		mode := modes[name]
		if name == "vpnctl-routing-guard.service" {
			content := fmt.Sprintf(`[Unit]
Description=vpnctl node routing fail-closed guard
After=network-online.target vpnctl-standard.service
Wants=network-online.target systemd-resolved.service
Before=vpnctl-routing.service
ConditionPathExists=/etc/vpnctl/generated/node/node-routing-guard.ready
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=%s __service node-routing-guard
ExecStartPost=%s __service node-dns-install
ExecStopPost=%s __service node-dns-restore
RemainAfterExit=yes
Restart=on-failure
RestartSec=2s
StandardOutput=null
StandardError=null
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadOnlyPaths=/etc/vpnctl
ReadWritePaths=/var/lib/vpnctl /run/systemd /run/vpnctl /proc/sys/net/ipv4/conf
MemoryMax=32M
TasksMax=32

[Install]
WantedBy=multi-user.target
`, binaryPath, binaryPath, binaryPath)
			units = append(units, RoleUnitFile{Name: name, Content: []byte(content)})
			continue
		}
		extraUnit := ""
		extraService := ""
		if name == "vpnctl-routing.service" {
			extraUnit = "Requires=vpnctl-routing-guard.service\nAfter=vpnctl-routing-guard.service\n"
			extraService = fmt.Sprintf("ExecStartPre=%s __service node-routing-not-ready\nExecStartPost=%s __service node-routing-wait-ready\nExecStopPost=%s __service node-routing-not-ready\nTimeoutStartSec=20s\nTimeoutStopSec=10s\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\nDevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\n", binaryPath, binaryPath, binaryPath)
		}
		content := fmt.Sprintf(`[Unit]
Description=vpnctl %s
After=network-online.target
Wants=network-online.target
%sConditionPathExists=/etc/vpnctl/generated/node/%s.ready

[Service]
Type=simple
ExecStart=%s __service %s
%sRestart=on-failure
RestartSec=2s
StandardOutput=null
StandardError=null
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/vpnctl /run/vpnctl
MemoryMax=128M
TasksMax=128

[Install]
WantedBy=multi-user.target
`, mode, extraUnit, mode, binaryPath, mode, extraService)
		units = append(units, RoleUnitFile{Name: name, Content: []byte(content)})
	}
	return RoleInstallationRequest{
		Role: model.RoleNode, Units: units,
		Configs: []RoleConfigFile{{Name: "bootstrap.conf", Content: []byte(nodeBootstrapConfig)}},
	}, nil
}
