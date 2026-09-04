package releasetrust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestRawAndPEMReleaseTrustAnchorsAreIdentical(t *testing.T) {
	t.Parallel()
	publicKey, err := PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	block, trailing := pem.Decode([]byte(PublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(trailing) != 0 {
		t.Fatal("release public key PEM is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pemKey, ok := parsed.(ed25519.PublicKey)
	if !ok || !bytes.Equal(publicKey, pemKey) {
		t.Fatal("raw and PEM release public keys differ")
	}
	publicKey[0] ^= 0xff
	again, _ := PublicKey()
	if bytes.Equal(publicKey, again) {
		t.Fatal("PublicKey returned mutable shared storage")
	}
}
