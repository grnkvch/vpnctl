package linux

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type sshPortFixture struct {
	Cases []struct {
		Name          string     `json:"name"`
		Connection    string     `json:"ssh_connection"`
		ExplicitPort  *int       `json:"explicit_port"`
		Listeners     []Listener `json:"listeners"`
		WantPort      int        `json:"want_port"`
		WantSource    string     `json:"want_source"`
		WantAddresses []string   `json:"want_addresses"`
		WantCode      string     `json:"want_code"`
	} `json:"cases"`
}

func TestResolveSSHPortFixtures(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/ssh-port/cases.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fixture sshPortFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	for _, test := range fixture.Cases {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			snapshot := HostSnapshot{SchemaVersion: HostSnapshotSchemaVersion, Listeners: test.Listeners}
			plan, resolveErr := ResolveSSHPort(SSHPortInput{ExplicitPort: test.ExplicitPort, SSHConnection: test.Connection}, snapshot)
			if test.WantCode != "" {
				assertSSHPortError(t, resolveErr, test.WantCode)
				if !reflect.DeepEqual(plan, SSHPortPlan{}) {
					t.Fatalf("failed plan = %+v, want zero value", plan)
				}
				return
			}
			if resolveErr != nil {
				t.Fatalf("ResolveSSHPort() error = %v", resolveErr)
			}
			if plan.Port != test.WantPort || string(plan.Source) != test.WantSource || !reflect.DeepEqual(plan.ListenerAddresses, test.WantAddresses) {
				t.Fatalf("plan = %+v, want port=%d source=%s addresses=%v", plan, test.WantPort, test.WantSource, test.WantAddresses)
			}
			if plan.Source == SSHPortFromConnection {
				if plan.Connection == nil || plan.Connection.ServerPort != test.WantPort {
					t.Fatalf("connection metadata missing from derived plan: %+v", plan.Connection)
				}
			} else if plan.Connection != nil {
				t.Fatalf("override plan leaked unrelated connection metadata: %+v", plan.Connection)
			}
		})
	}
}

func TestResolveSSHPortValidatesConnectionAndOverride(t *testing.T) {
	t.Parallel()

	snapshot := HostSnapshot{
		SchemaVersion: HostSnapshotSchemaVersion,
		Listeners:     []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: `users:(("sshd",pid=7,fd=3))`}},
	}
	for _, value := range []string{
		"invalid", "192.0.2.4 bad 198.51.100.8 22", "192.0.2.4 50000 bad 22", "192.0.2.4 50000 0.0.0.0 22", "192.0.2.4 50000 127.0.0.1 22", "192.0.2.4 50000 198.51.100.8 0",
	} {
		_, err := ResolveSSHPort(SSHPortInput{SSHConnection: value}, snapshot)
		assertSSHPortError(t, err, "invalid_connection")
	}
	for _, port := range []int{-1, 0, 65536} {
		port := port
		_, err := ResolveSSHPort(SSHPortInput{ExplicitPort: &port}, snapshot)
		assertSSHPortError(t, err, "invalid_override")
	}

	wrongVersion := snapshot
	wrongVersion.SchemaVersion++
	_, err := ResolveSSHPort(SSHPortInput{SSHConnection: "192.0.2.4 50000 198.51.100.8 22"}, wrongVersion)
	assertSSHPortError(t, err, "snapshot_version")
}

func TestResolveSSHPortRejectsUnverifiedOwnersAndBindingMismatch(t *testing.T) {
	t.Parallel()

	base := HostSnapshot{SchemaVersion: HostSnapshotSchemaVersion}
	base.Listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: `users:(("fake-sshd",pid=8,fd=3))`}}
	_, err := ResolveSSHPort(SSHPortInput{SSHConnection: "192.0.2.4 50000 198.51.100.8 22"}, base)
	assertSSHPortError(t, err, "connection_mismatch")

	base.Listeners = []Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: 22, Process: `users:(("sshd",pid=7,fd=3))`}}
	_, err = ResolveSSHPort(SSHPortInput{SSHConnection: "192.0.2.4 50000 198.51.100.8 22"}, base)
	assertSSHPortError(t, err, "connection_mismatch")

	base.Listeners = []Listener{{Protocol: "udp", Address: "0.0.0.0", Port: 22, Process: `users:(("sshd",pid=7,fd=3))`}}
	_, err = ResolveSSHPort(SSHPortInput{SSHConnection: "192.0.2.4 50000 198.51.100.8 22"}, base)
	assertSSHPortError(t, err, "connection_mismatch")
}

func TestResolveSSHPortIsPureAndNeverDefaultsTo22(t *testing.T) {
	t.Parallel()

	snapshot := HostSnapshot{
		SchemaVersion: HostSnapshotSchemaVersion,
		Listeners:     []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: `users:(("sshd",pid=7,fd=3))`}},
	}
	before, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	_, resolveErr := ResolveSSHPort(SSHPortInput{}, snapshot)
	assertSSHPortError(t, resolveErr, "not_ssh")
	after, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("ResolveSSHPort() mutated the discovery snapshot")
	}
	if !strings.Contains(resolveErr.Error(), "provide --ssh-port") {
		t.Fatalf("non-SSH error is not actionable: %v", resolveErr)
	}

	plan, resolveErr := ResolveSSHPort(SSHPortInput{SSHConnection: "192.0.2.4 50000 198.51.100.8 22"}, snapshot)
	if resolveErr != nil {
		t.Fatalf("ResolveSSHPort() error = %v", resolveErr)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "192.0.2.4") || strings.Contains(string(encoded), "198.51.100.8") {
		t.Fatalf("operator-facing plan exposed SSH connection identifiers: %s", encoded)
	}
}

func TestParseSSHConnectionSupportsIPv6(t *testing.T) {
	t.Parallel()

	connection, err := parseSSHConnection("2001:db8::20 50000 2001:db8::10 2222")
	if err != nil {
		t.Fatalf("parseSSHConnection() error = %v", err)
	}
	if connection.ClientAddress != "2001:db8::20" || connection.ServerAddress != "2001:db8::10" || connection.ServerPort != 2222 {
		t.Fatalf("connection = %+v", connection)
	}
	snapshot := HostSnapshot{
		SchemaVersion: HostSnapshotSchemaVersion,
		Listeners:     []Listener{{Protocol: "tcp", Address: "::", Port: 2222, Process: "systemd"}},
	}
	plan, err := ResolveSSHPort(SSHPortInput{SSHConnection: "2001:db8::20 50000 2001:db8::10 2222"}, snapshot)
	if err != nil || plan.Port != 2222 {
		t.Fatalf("IPv6 plan = %+v, %v", plan, err)
	}
}

func assertSSHPortError(t *testing.T, err error, code string) {
	t.Helper()
	if !errors.Is(err, ErrSSHPortUnverified) {
		t.Fatalf("error = %v, want ErrSSHPortUnverified", err)
	}
	var typed *SSHPortError
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error = %#v, want SSHPortError code %q", err, code)
	}
}
