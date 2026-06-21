package mihomo

import (
	"fmt"
	"strings"
)

const (
	DefaultProxyName   = "DO-WG"
	DefaultGroupName   = "VPN"
	DefaultMTU         = 1420
	DefaultMode        = "rule"
	DefaultRulesetType = "domain-suffix"
)

type Config struct {
	DNSServers      []string
	ProxyName       string
	GroupName       string
	Server          string
	Port            int
	ClientIP        string
	PrivateKey      string
	ServerPublicKey string
	MTU             int
	RulesetType     string
	Domains         []string
}

func RenderConfig(cfg Config) (string, error) {
	if len(cfg.DNSServers) == 0 {
		return "", fmt.Errorf("dns servers are required")
	}
	if strings.TrimSpace(cfg.Server) == "" {
		return "", fmt.Errorf("server is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return "", fmt.Errorf("port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.ClientIP) == "" {
		return "", fmt.Errorf("client ip is required")
	}
	if strings.TrimSpace(cfg.PrivateKey) == "" {
		return "", fmt.Errorf("private key is required")
	}
	if strings.TrimSpace(cfg.ServerPublicKey) == "" {
		return "", fmt.Errorf("server public key is required")
	}
	if rulesetType(cfg) != DefaultRulesetType {
		return "", fmt.Errorf("unsupported ruleset type: %s", rulesetType(cfg))
	}
	if len(cfg.Domains) == 0 {
		return "", fmt.Errorf("ruleset domains are required")
	}

	proxyName := valueOrDefault(cfg.ProxyName, DefaultProxyName)
	groupName := valueOrDefault(cfg.GroupName, DefaultGroupName)
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}

	var b strings.Builder
	fmt.Fprintf(&b, "mode: %s\n\n", DefaultMode)
	fmt.Fprintln(&b, "dns:")
	fmt.Fprintln(&b, "  enable: true")
	fmt.Fprintln(&b, "  nameserver:")
	for _, server := range cfg.DNSServers {
		fmt.Fprintf(&b, "    - %s\n", server)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "proxies:")
	fmt.Fprintf(&b, "  - name: %s\n", proxyName)
	fmt.Fprintln(&b, "    type: wireguard")
	fmt.Fprintf(&b, "    server: %s\n", cfg.Server)
	fmt.Fprintf(&b, "    port: %d\n", cfg.Port)
	fmt.Fprintf(&b, "    ip: %s\n", cfg.ClientIP)
	fmt.Fprintf(&b, "    private-key: %q\n", cfg.PrivateKey)
	fmt.Fprintf(&b, "    public-key: %q\n", cfg.ServerPublicKey)
	fmt.Fprintf(&b, "    mtu: %d\n", mtu)
	fmt.Fprintln(&b, "    udp: true")
	fmt.Fprintln(&b, "    allowed-ips:")
	fmt.Fprintln(&b, "      - 0.0.0.0/0")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "proxy-groups:")
	fmt.Fprintf(&b, "  - name: %s\n", groupName)
	fmt.Fprintln(&b, "    type: select")
	fmt.Fprintln(&b, "    proxies:")
	fmt.Fprintf(&b, "      - %s\n", proxyName)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "rules:")
	for _, domain := range cfg.Domains {
		fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,%s,%s\n", domain, groupName)
	}
	fmt.Fprintln(&b, "  - MATCH,DIRECT")

	return b.String(), nil
}

func valueOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func rulesetType(cfg Config) string {
	if strings.TrimSpace(cfg.RulesetType) == "" {
		return DefaultRulesetType
	}
	return strings.TrimSpace(cfg.RulesetType)
}
