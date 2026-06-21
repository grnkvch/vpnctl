package setup

import (
	"context"

	"github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

type ServerKeyGenerator struct {
	Runner wireguard.Runner
}

type ClientKeyGenerator struct {
	Runner wireguard.Runner
}

func (g ServerKeyGenerator) GenerateServerKeyPair(ctx context.Context) (state.ServerKeyPair, error) {
	keyPair, err := wireguard.GenerateKeyPair(ctx, g.Runner)
	if err != nil {
		return state.ServerKeyPair{}, err
	}
	return state.ServerKeyPair{
		PrivateKey: keyPair.PrivateKey,
		PublicKey:  keyPair.PublicKey,
	}, nil
}

func (g ClientKeyGenerator) GenerateClientKeyPair(ctx context.Context) (state.ClientKeyPair, error) {
	keyPair, err := wireguard.GenerateKeyPair(ctx, g.Runner)
	if err != nil {
		return state.ClientKeyPair{}, err
	}
	return state.ClientKeyPair{
		PrivateKey: keyPair.PrivateKey,
		PublicKey:  keyPair.PublicKey,
	}, nil
}
