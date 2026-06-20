package setup

import (
	"bytes"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	opts := Defaults("")

	if opts.StateDir != DefaultStateDir {
		t.Fatalf("unexpected state dir: %q", opts.StateDir)
	}
	if opts.Name != DefaultName {
		t.Fatalf("unexpected name: %q", opts.Name)
	}
	if opts.Port != DefaultPort {
		t.Fatalf("unexpected port: %d", opts.Port)
	}
	if opts.Interface != DefaultInterface {
		t.Fatalf("unexpected interface: %q", opts.Interface)
	}
	if opts.Subnet != DefaultSubnet {
		t.Fatalf("unexpected subnet: %q", opts.Subnet)
	}
	if opts.SSHPort != DefaultSSHPort {
		t.Fatalf("unexpected ssh port: %d", opts.SSHPort)
	}
	if !opts.EnableUFW {
		t.Fatalf("expected UFW to be enabled by default")
	}
}

func TestValidateRequiresEndpoint(t *testing.T) {
	opts := Defaults("")

	if err := opts.Validate(); err == nil {
		t.Fatalf("expected missing endpoint error")
	}
}

func TestValidateRejectsInvalidSubnetAndDNS(t *testing.T) {
	opts := Defaults("")
	opts.Endpoint = "198.211.99.116"
	opts.Subnet = "not-cidr"

	if err := opts.Validate(); err == nil {
		t.Fatalf("expected invalid subnet error")
	}

	opts.Subnet = DefaultSubnet
	opts.DNS = []string{"not-ip"}
	if err := opts.Validate(); err == nil {
		t.Fatalf("expected invalid DNS error")
	}
}

func TestPrintDryRun(t *testing.T) {
	opts := Defaults(".vpnctl")
	opts.Endpoint = "198.211.99.116"

	var out bytes.Buffer
	PrintDryRun(&out, opts)

	for _, want := range []string{
		"setup plan (dry-run)",
		"endpoint: 198.211.99.116",
		"would initialize vpnctl state if needed",
		"would install required VPN packages",
		"would not perform a full system upgrade",
		"would start and enable WireGuard service",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("expected output to contain %q, got %q", want, out.String())
		}
	}
}
