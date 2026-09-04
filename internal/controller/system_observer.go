package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const systemObservationTimeout = 3 * time.Second

type SystemUnitObserver struct {
	runner linuxplatform.ProbeRunner
}

func NewSystemUnitObserver(runner linuxplatform.ProbeRunner) (*SystemUnitObserver, error) {
	if runner == nil {
		return nil, fmt.Errorf("system unit observer runner is required")
	}
	return &SystemUnitObserver{runner: runner}, nil
}

// Observe reads manager state only. It deliberately has no unit mutation or
// reconciliation dependency, so controller startup and status cannot alter the
// applied data plane.
func (observer *SystemUnitObserver) Observe(ctx context.Context, state model.State) (Observation, error) {
	if ctx == nil {
		return Observation{}, fmt.Errorf("context is required")
	}
	if observer == nil || observer.runner == nil {
		return Observation{}, fmt.Errorf("system unit observer is incomplete")
	}
	bounded, cancel := context.WithTimeout(ctx, systemObservationTimeout)
	defer cancel()

	observation := Observation{Units: []UnitObservation{}, Issues: []string{}}
	for _, name := range linuxplatform.RoleUnitNames(state.Host.Role) {
		unit := UnitObservation{Name: name}
		result, err := observer.runner.Run(bounded, linuxplatform.ProbeCommand{
			Name: "systemctl",
			Args: []string{
				"show", "--no-pager", "--property=LoadState", "--property=ActiveState", "--property=SubState", name,
			},
		})
		if err != nil || result.ExitCode != 0 {
			observation.Issues = append(observation.Issues, "unit_unavailable:"+name)
			observation.Units = append(observation.Units, unit)
			continue
		}
		values, err := parseSystemdProperties(result.Stdout)
		if err != nil {
			observation.Issues = append(observation.Issues, "unit_invalid_response:"+name)
		} else {
			unit.LoadState = values["LoadState"]
			unit.ActiveState = values["ActiveState"]
			unit.SubState = values["SubState"]
		}
		observation.Units = append(observation.Units, unit)
	}
	sort.Slice(observation.Units, func(i, j int) bool { return observation.Units[i].Name < observation.Units[j].Name })
	sort.Strings(observation.Issues)
	return observation, nil
}

func parseSystemdProperties(data []byte) (map[string]string, error) {
	values := make(map[string]string, 3)
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("invalid systemd property")
		}
		switch key {
		case "LoadState", "ActiveState", "SubState":
			if value == "" {
				return nil, fmt.Errorf("empty systemd property")
			}
			values[key] = value
		default:
			return nil, fmt.Errorf("unexpected systemd property")
		}
	}
	for _, required := range []string{"LoadState", "ActiveState", "SubState"} {
		if values[required] == "" {
			return nil, fmt.Errorf("missing systemd property")
		}
	}
	return values, nil
}

func NewSystemController(paths store.Paths) (*Controller, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, fmt.Errorf("create controller state store: %w", err)
	}
	observer, err := NewSystemUnitObserver(linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	dnsDispatcher, err := NewGatewayDNSMutationDispatcher(paths, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	loggingDispatcher, err := NewGatewayLoggingMutationDispatcher(paths, nil, nil)
	if err != nil {
		return nil, err
	}
	dispatcher, err := NewGatewayMutationDispatcher(dnsDispatcher, loggingDispatcher)
	if err != nil {
		return nil, err
	}
	return NewController(ControllerRuntime{Paths: paths, State: state, Observer: observer, Dispatcher: dispatcher})
}

func RunSystemController(ctx context.Context, paths store.Paths) error {
	controller, err := NewSystemController(paths)
	if err != nil {
		return err
	}
	return controller.Serve(ctx)
}
