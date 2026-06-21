package setup

import (
	"context"

	"github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

type ServerKeyGenerator struct {
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
