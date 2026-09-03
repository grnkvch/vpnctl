package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	gatewayDNSSetOperation   = "dns.set"
	gatewayDNSResetOperation = "dns.reset"
)

type gatewayDNSMutationPayload struct {
	IPv4 []string `json:"ipv4"`
}

// GatewayDNSMutationDispatcher is intentionally the controller's only local
// DNS writer. It prepares a shared-forwarder-only runtime transaction and
// leaves state serialization to Controller's single mutation lock.
type GatewayDNSMutationDispatcher struct {
	paths  store.Paths
	runner linuxplatform.ProbeRunner
}

func NewGatewayDNSMutationDispatcher(paths store.Paths, runner linuxplatform.ProbeRunner) (*GatewayDNSMutationDispatcher, error) {
	if runner == nil {
		return nil, fmt.Errorf("gateway DNS mutation runner is required")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return nil, fmt.Errorf("gateway DNS mutation paths are invalid")
	}
	return &GatewayDNSMutationDispatcher{paths: paths, runner: runner}, nil
}

func (dispatcher *GatewayDNSMutationDispatcher) Dispatch(context.Context, model.State, string, json.RawMessage) (model.State, json.RawMessage, error) {
	return model.State{}, nil, fmt.Errorf("gateway DNS mutations require the prepared transaction path")
}

func (dispatcher *GatewayDNSMutationDispatcher) Prepare(_ context.Context, state model.State, operation string, raw json.RawMessage) (PreparedMutation, error) {
	if dispatcher == nil || dispatcher.runner == nil {
		return PreparedMutation{}, fmt.Errorf("gateway DNS mutation dispatcher is incomplete")
	}
	if operation != gatewayDNSSetOperation && operation != gatewayDNSResetOperation {
		return PreparedMutation{}, fmt.Errorf("unsupported gateway mutation operation")
	}
	payload, err := decodeGatewayDNSMutationPayload(raw)
	if err != nil {
		return PreparedMutation{}, err
	}
	candidate, changed, err := routing.ReplaceDNSUpstreams(state, payload.IPv4)
	if err != nil {
		return PreparedMutation{}, err
	}
	data, err := json.Marshal(struct {
		Changed bool                   `json:"changed"`
		Scope   model.DNSUpstreamScope `json:"scope"`
		IPv4    []string               `json:"ipv4"`
	}{Changed: changed, Scope: state.DNS.Scope, IPv4: append([]string(nil), payload.IPv4...)})
	if err != nil {
		return PreparedMutation{}, err
	}
	prepared := PreparedMutation{Candidate: candidate, Data: data, Changed: changed}
	if !changed {
		return prepared, nil
	}
	transaction, err := routing.PrepareGatewayDNSConfigTransaction(dispatcher.paths, dispatcher.runner, state, candidate)
	if err != nil {
		return PreparedMutation{}, err
	}
	prepared.Apply = transaction.Apply
	prepared.Rollback = transaction.Rollback
	return prepared, nil
}

func decodeGatewayDNSMutationPayload(raw json.RawMessage) (gatewayDNSMutationPayload, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return gatewayDNSMutationPayload{}, fmt.Errorf("gateway DNS mutation payload has invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload gatewayDNSMutationPayload
	if err := decoder.Decode(&payload); err != nil {
		return gatewayDNSMutationPayload{}, fmt.Errorf("decode gateway DNS mutation payload: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return gatewayDNSMutationPayload{}, fmt.Errorf("decode gateway DNS mutation payload: trailing data")
	}
	return payload, nil
}
