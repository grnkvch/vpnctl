package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestSystemUnitObserverUsesOnlyPassiveSystemctlShow(t *testing.T) {
	runner := &observerProbeRunner{}
	observer, err := NewSystemUnitObserver(runner)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := observer.Observe(context.Background(), model.State{Host: model.Host{Role: model.RoleGateway}})
	if err != nil {
		t.Fatal(err)
	}
	wantNames := linuxplatform.RoleUnitNames(model.RoleGateway)
	if len(runner.commands) != len(wantNames) || len(observed.Units) != len(wantNames) {
		t.Fatalf("commands/units = %d/%d, want %d", len(runner.commands), len(observed.Units), len(wantNames))
	}
	for index, command := range runner.commands {
		if command.Name != "systemctl" || len(command.Args) != 6 || command.Args[0] != "show" || command.Args[5] != wantNames[index] {
			t.Fatalf("observer command = %+v", command)
		}
		joined := strings.Join(command.Args, " ")
		for _, forbidden := range []string{" start ", " stop ", " restart ", " reload ", " enable ", " disable "} {
			if strings.Contains(" "+joined+" ", forbidden) {
				t.Fatalf("observer issued mutating systemctl command: %q", joined)
			}
		}
	}
	if observed.Issues == nil || len(observed.Issues) != 0 {
		t.Fatalf("observation issues = %v", observed.Issues)
	}
	for _, unit := range observed.Units {
		if unit.LoadState != "loaded" || unit.ActiveState != "active" || unit.SubState != "running" {
			t.Fatalf("unit observation = %+v", unit)
		}
	}
}

func TestSystemUnitObserverRecordsInvalidAndUnavailableUnits(t *testing.T) {
	runner := &observerProbeRunner{results: []linuxplatform.ProbeResult{
		{Stdout: []byte("LoadState=loaded\nActiveState=active\n")},
		{ExitCode: 1},
	}}
	observer, _ := NewSystemUnitObserver(runner)
	observed, err := observer.Observe(context.Background(), model.State{Host: model.Host{Role: model.RoleGateway}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"unit_invalid_response:vpnctl-controller.service",
		"unit_unavailable:vpnctl-dns.service",
	}
	if len(observed.Issues) != len(want) {
		t.Fatalf("issues = %v", observed.Issues)
	}
	for index := range want {
		if observed.Issues[index] != want[index] {
			t.Fatalf("issues = %v, want %v", observed.Issues, want)
		}
	}
}

type observerProbeRunner struct {
	commands []linuxplatform.ProbeCommand
	results  []linuxplatform.ProbeResult
}

func (runner *observerProbeRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.commands = append(runner.commands, command)
	if len(runner.results) != 0 {
		result := runner.results[0]
		runner.results = runner.results[1:]
		return result, nil
	}
	return linuxplatform.ProbeResult{Stdout: []byte("LoadState=loaded\nActiveState=active\nSubState=running\n")}, nil
}
