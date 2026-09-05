package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const (
	frpcBinaryPath = "/usr/local/libexec/vpnctl-v2-spike/frpc"
	frpcConfigPath = "/etc/vpnctl-v2-spike/tunnel/frpc.toml"
	adminPassword  = "cacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca"
)

func main() {
	gatewayIPText := flag.String("gateway-ip", "", "private IPv4 address of the capacity gateway")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal("unexpected positional argument")
	}
	gatewayIP, err := netip.ParseAddr(*gatewayIPText)
	if err != nil || !gatewayIP.Is4() || !gatewayIP.IsPrivate() || gatewayIP.String() != *gatewayIPText {
		fatal("gateway IP must be a canonical private IPv4 address")
	}
	recovery, err := tunnel.NewFRPClientStatusRecoveryProber(
		tunnel.NewFRPHTTPStatusSource(),
		adminPassword,
		[]tunnel.FRPClientRecoveryMapping{{
			Name: "node-a-expose-1", LocalAddr: "127.0.0.1:18121",
			RemoteAddr: netip.AddrPortFrom(gatewayIP, 18111).String(),
		}},
	)
	if err != nil {
		fatal("prepare capacity frpc recovery probe")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := tunnel.RunFRPClientProcessWithRecovery(
		ctx, tunnel.OSFRPProcessRunner{}, frpcBinaryPath, []string{"-c", frpcConfigPath}, recovery,
	); err != nil {
		fatal("capacity frpc supervisor failed")
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
