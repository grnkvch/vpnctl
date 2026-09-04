package controller

import "github.com/vgrinkevich/vpnctl/internal/control"

type GatewayStateReader = control.GatewayStateReader
type RPCNodeAuthorizer = control.StateNodeAuthorizer

func NewRPCNodeAuthorizer(state GatewayStateReader) (*RPCNodeAuthorizer, error) {
	return control.NewStateNodeAuthorizer(state)
}
