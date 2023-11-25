package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
)

// LocalEcdsaIssuerSigner supports signing an Issuer with a locally passed private ecdsa key.
// Key lengths of 256, 384 and 521 are supported.
type LocalEcdsaIssuerSigner struct {
	PublicKeyUrl string
	Key          *ecdsa.PrivateKey
}

func (signer *LocalEcdsaIssuerSigner) GetKeyUrl() (string, error) {
	return signer.PublicKeyUrl, nil
}

func (signer *LocalEcdsaIssuerSigner) Sign(message []byte) ([]byte, error) {

	var h hash.Hash
	switch signer.Key.Params().BitSize {
	case 256:
		h = sha256.New()
	case 384:
		h = sha512.New384()
	case 521:
		h = sha512.New()
	default:
		return []byte{},
			fmt.Errorf("invalid key size - must be 256, 384 or 521. %d found", signer.Key.Params().BitSize)
	}

	h.Write(message)

	r, s, err := ecdsa.Sign(rand.Reader, signer.Key, h.Sum(nil))
	if err != nil {
		return []byte{}, err
	}

	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}
