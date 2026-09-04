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
	dns     *GatewayDNSMutationDispatcher
	logging *GatewayLoggingMutationDispatcher
}

func NewGatewayMutationDispatcher(dns *GatewayDNSMutationDispatcher, logging *GatewayLoggingMutationDispatcher) (*GatewayMutationDispatcher, error) {
	if dns == nil || logging == nil {
		return nil, fmt.Errorf("gateway mutation dispatcher dependencies are incomplete")
	}
	return &GatewayMutationDispatcher{dns: dns, logging: logging}, nil
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
	default:
		return PreparedMutation{}, fmt.Errorf("unsupported gateway mutation operation")
	}
}
