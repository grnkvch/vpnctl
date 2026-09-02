package linux

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	WatchdogSeconds         = 120
	WatchdogServiceUnitName = "vpnctl-watchdog@.service"
	WatchdogTimerUnitName   = "vpnctl-watchdog@.timer"
	DefaultVPNCTLBinaryPath = "/usr/local/bin/vpnctl"
)

var systemdInstanceIDPattern = regexp.MustCompile(`^fw-[0-9A-HJKMNP-TV-Z]{6}$`)

type WatchdogUnitFile struct {
	Name    string
	Content []byte
}

func RenderWatchdogUnits(binaryPath string) ([]WatchdogUnitFile, error) {
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath || strings.ContainsAny(binaryPath, " \t\r\n%") {
		return nil, fmt.Errorf("watchdog binary path must be clean, absolute, and systemd-safe")
	}
	service := fmt.Sprintf(`[Unit]
Description=vpnctl network rollback for transaction %%i
After=local-fs.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=%s __watchdog-rollback %%i
Restart=on-failure
RestartSec=1s
StandardOutput=null
StandardError=null
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_NETLINK
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/vpnctl/operations /proc/sys/net/ipv4
MemoryMax=32M
TasksMax=32
`, binaryPath)
	timer := fmt.Sprintf(`[Unit]
Description=vpnctl %d-second network rollback timer for transaction %%i

[Timer]
OnActiveSec=%ds
AccuracySec=1ms
RandomizedDelaySec=0
Unit=vpnctl-watchdog@%%i.service
RemainAfterElapse=no
`, WatchdogSeconds, WatchdogSeconds)
	return []WatchdogUnitFile{
		{Name: WatchdogServiceUnitName, Content: []byte(service)},
		{Name: WatchdogTimerUnitName, Content: []byte(timer)},
	}, nil
}

func WatchdogTimerInstance(transactionID string) (string, error) {
	if !systemdInstanceIDPattern.MatchString(transactionID) {
		return "", fmt.Errorf("invalid watchdog transaction ID")
	}
	return "vpnctl-watchdog@" + transactionID + ".timer", nil
}

func WatchdogServiceInstance(transactionID string) (string, error) {
	if !systemdInstanceIDPattern.MatchString(transactionID) {
		return "", fmt.Errorf("invalid watchdog transaction ID")
	}
	return "vpnctl-watchdog@" + transactionID + ".service", nil
}
