// Package releasetrust owns the public trust anchor shared by release
// manifests, the curl bootstrap, and the signed handshake-host list.
package releasetrust

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

const (
	PublicKeyBase64URL = "tCAzV5kpvCXDidVel5aefc6NLYtrgyT5h0vppG_r8JM"
	PublicKeyPEM       = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAtCAzV5kpvCXDidVel5aefc6NLYtrgyT5h0vppG/r8JM=\n-----END PUBLIC KEY-----\n"
)

func PublicKey() (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(PublicKeyBase64URL)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decode vpnctl release public key")
	}
	return ed25519.PublicKey(append([]byte(nil), decoded...)), nil
}
