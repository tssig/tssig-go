package signer

import "crypto/ed25519"

// LocalEd25519IssuerSigner supports signing an Issuer with a locally passed private ed25519 key.
type LocalEd25519IssuerSigner struct {
	PublicKeyUrl string
	Key          ed25519.PrivateKey
}

func (signer *LocalEd25519IssuerSigner) GetKeyUrl() (string, error) {
	return signer.PublicKeyUrl, nil
}

func (signer *LocalEd25519IssuerSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(signer.Key, message), nil
}
