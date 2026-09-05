package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

// GatewayMutationDispatcher keeps the controller as the sole gateway writer
// while routing each closed operation family to its narrow implementation.
type GatewayMutationDispatcher struct {
	dns         *GatewayDNSMutationDispatcher
	logging     *GatewayLoggingMutationDispatcher
	invites     *GatewayInviteMutationDispatcher
	repair      *GatewayRepairDispatcher
	ownedRepair *GatewayOwnedRepairDispatcher
}

func NewGatewayMutationDispatcherWithRepairs(
	dns *GatewayDNSMutationDispatcher,
	logging *GatewayLoggingMutationDispatcher,
	invites *GatewayInviteMutationDispatcher,
	repair *GatewayRepairDispatcher,
	ownedRepair *GatewayOwnedRepairDispatcher,
) (*GatewayMutationDispatcher, error) {
	if ownedRepair == nil {
		return nil, fmt.Errorf("gateway owned repair dispatcher is required")
	}
	dispatcher, err := NewGatewayMutationDispatcherWithRepair(dns, logging, invites, repair)
	if err != nil {
		return nil, err
	}
	dispatcher.ownedRepair = ownedRepair
	return dispatcher, nil
}

func NewGatewayMutationDispatcher(dns *GatewayDNSMutationDispatcher, logging *GatewayLoggingMutationDispatcher, invites ...*GatewayInviteMutationDispatcher) (*GatewayMutationDispatcher, error) {
	if dns == nil || logging == nil {
		return nil, fmt.Errorf("gateway mutation dispatcher dependencies are incomplete")
	}
	var inviteDispatcher *GatewayInviteMutationDispatcher
	if len(invites) > 1 {
		return nil, fmt.Errorf("gateway mutation dispatcher accepts at most one invite dispatcher")
	}
	if len(invites) == 1 {
		inviteDispatcher = invites[0]
	}
	return &GatewayMutationDispatcher{dns: dns, logging: logging, invites: inviteDispatcher}, nil
}

func NewGatewayMutationDispatcherWithRepair(
	dns *GatewayDNSMutationDispatcher,
	logging *GatewayLoggingMutationDispatcher,
	invites *GatewayInviteMutationDispatcher,
	repair *GatewayRepairDispatcher,
) (*GatewayMutationDispatcher, error) {
	if repair == nil {
		return nil, fmt.Errorf("gateway repair dispatcher is required")
	}
	dispatcher, err := NewGatewayMutationDispatcher(dns, logging, invites)
	if err != nil {
		return nil, err
	}
	dispatcher.repair = repair
	return dispatcher, nil
}

func (dispatcher *GatewayMutationDispatcher) Dispatch(context.Context, model.State, string, json.RawMessage) (model.State, json.RawMessage, error) {
	return model.State{}, nil, fmt.Errorf("gateway mutations require the prepared transaction path")
}

func (dispatcher *GatewayMutationDispatcher) Prepare(ctx context.Context, state model.State, operation string, payload json.RawMessage) (PreparedMutation, error) {
	if dispatcher == nil || dispatcher.dns == nil || dispatcher.logging == nil {
		return PreparedMutation{}, fmt.Errorf("gateway mutation dispatcher is incomplete")
	}
	switch {
	case strings.HasPrefix(operation, "dns."):
		return dispatcher.dns.Prepare(ctx, state, operation, payload)
	case strings.HasPrefix(operation, "log."):
		return dispatcher.logging.Prepare(ctx, state, operation, payload)
	case strings.HasPrefix(operation, "invite.") && dispatcher.invites != nil:
		return dispatcher.invites.Prepare(ctx, state, operation, payload)
	case operation == GatewayRepairOperation && dispatcher.repair != nil:
		return dispatcher.repair.Prepare(ctx, state, operation, payload)
	case operation == GatewayOwnedRepairOperation && dispatcher.ownedRepair != nil:
		return dispatcher.ownedRepair.Prepare(ctx, state, operation, payload)
	default:
		return PreparedMutation{}, fmt.Errorf("unsupported gateway mutation operation")
	}
}
