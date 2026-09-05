package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type systemActiveTransportDoctor struct {
	role    model.Role
	nodeID  string
	state   convergenceApplyStateReader
	gateway convergenceApplyGatewayProbe
	network operations.DoctorProbeRunner
}

func buildSystemDoctor(paths store.Paths, role HostRole) (*operations.Doctor, error) {
	modelRole, ok := convergenceApplyModelRole(role)
	if !ok {
		return nil, ErrUnsupportedRole
	}
	stateState, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	state, err := stateState.Load()
	if err != nil {
		return nil, err
	}
	nodeID := ""
	var gateway convergenceApplyGatewayProbe
	if modelRole == model.RoleNode && len(state.Nodes) == 1 && state.Nodes[0].Gateway != nil {
		nodeID = state.Nodes[0].ID
		gateway, err = operations.NewSystemRemoteRepairGatewayProbe(paths, nil)
		if err != nil {
			return nil, err
		}
	}
	networkOnly, err := operations.NewNetworkDoctorProbeRunner(nil)
	if err != nil {
		return nil, err
	}
	active := &systemActiveTransportDoctor{
		role: modelRole, nodeID: nodeID, state: stateState, gateway: gateway, network: networkOnly,
	}
	network, err := operations.NewNetworkDoctorProbeRunner(active)
	if err != nil {
		return nil, err
	}
	runner, err := operations.NewExplicitGETDoctorRunner(network, nil)
	if err != nil {
		return nil, err
	}
	return operations.NewDoctor(modelRole, statusStateReader{state: stateState}, runner, operations.DoctorLimits{}, nil)
}

func (doctor *systemActiveTransportDoctor) ProbeActiveTransport(
	ctx context.Context,
	request operations.DoctorProbeRequest,
) (operations.DoctorProbeObservation, error) {
	if ctx == nil || doctor == nil || doctor.state == nil || doctor.network == nil ||
		request.Kind != operations.DoctorProbeActiveTransport {
		return operations.DoctorProbeObservation{}, fmt.Errorf("active transport doctor is incomplete")
	}
	if doctor.role == model.RoleGateway {
		return operations.DoctorProbeObservation{
			Passed: false, Code: "transport_origin_probe_unavailable",
		}, nil
	}
	before, err := doctor.state.Load()
	if err != nil {
		return operations.DoctorProbeObservation{}, err
	}
	beforeBytes, err := model.EncodeState(before)
	if err != nil || validateRepairAuthority(before, model.RoleNode, doctor.nodeID) != nil {
		return operations.DoctorProbeObservation{}, fmt.Errorf("active transport node state is invalid")
	}
	node := before.Nodes[0]
	if node.ActiveTransport != request.Transport {
		return operations.DoctorProbeObservation{}, fmt.Errorf("active transport changed before probe")
	}
	matched := false
	for _, transportState := range before.Transports {
		if transportState.OwnerKind == model.TargetNode && transportState.OwnerID == doctor.nodeID &&
			transportState.Kind == request.Transport &&
			(transportState.State == model.TransportActive || transportState.State == model.TransportDegraded) {
			matched = transportState.Protocol == request.OuterProtocol
			break
		}
	}
	if !matched {
		return operations.DoctorProbeObservation{}, fmt.Errorf("active transport metadata does not match the probe")
	}

	var observation operations.DoctorProbeObservation
	if request.Protocol == operations.DoctorProtocolTCP {
		if doctor.gateway == nil {
			return operations.DoctorProbeObservation{}, fmt.Errorf("gateway control probe is unavailable")
		}
		if err := doctor.gateway.RequireGateway(ctx, doctor.nodeID); err != nil {
			return operations.DoctorProbeObservation{}, err
		}
		observation = operations.DoctorProbeObservation{Passed: true, Code: "active_transport_tcp_passed"}
	} else {
		if node.Gateway == nil {
			return operations.DoctorProbeObservation{}, fmt.Errorf("gateway DNS target is unavailable")
		}
		dnsRequest := operations.DoctorProbeRequest{
			ProbeID: request.ProbeID, Scope: operations.DoctorScopeDNS,
			Name: "dns.gateway.active_transport_udp", Kind: operations.DoctorProbeGatewayDNS,
			Protocol: operations.DoctorProtocolDNSUDP, ResourceKind: "dns_path", ResourceID: "gateway",
			Endpoint: net.JoinHostPort(node.Gateway.GatewayOverlayIPv4, "53"),
		}
		if _, err := doctor.network.Probe(ctx, dnsRequest); err != nil {
			return operations.DoctorProbeObservation{}, err
		}
		observation = operations.DoctorProbeObservation{Passed: true, Code: "active_transport_udp_passed"}
	}
	after, err := doctor.state.Load()
	if err != nil {
		return operations.DoctorProbeObservation{}, err
	}
	afterBytes, err := model.EncodeState(after)
	if err != nil || !bytes.Equal(beforeBytes, afterBytes) {
		return operations.DoctorProbeObservation{}, fmt.Errorf("active transport state changed during probe")
	}
	return observation, nil
}

var _ operations.ActiveTransportDoctorProber = (*systemActiveTransportDoctor)(nil)
