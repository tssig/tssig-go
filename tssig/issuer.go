package tssig

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"time"
)

// IssuerSigner Defines the method signature needed to sign an Issuer.
type IssuerSigner interface {
	Sign([]byte) (string, []byte, error)
}

/*
The Issuer represents:
  - A Leaf Public Key, used to verify the signature on the SignedTimeStamp.
  - The URL to a DER encoded Root Public Key, used to verify the signature on the Issuer.
  - The issuer's signature, demonstrating that the left key is signed by the root key.
*/
type Issuer struct {
	KeyUrl                    string `json:"root-pub-key"`
	LeafPublicKeyDer          bytes  `json:"leaf-pub-key"`
	LeafPublicKeyDerSignature bytes  `json:"leaf-pub-key-sig"`

	private ed25519.PrivateKey
}

// NewIssuer Creates a new Issuer with a ed25519 key.
func NewIssuer(public ed25519.PublicKey, private ed25519.PrivateKey) (*Issuer, error) {
	publicDer, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}

	return &Issuer{
		LeafPublicKeyDer: publicDer,
		private:          private,
	}, nil
}

// SignIssuer Signs the Leaf Public Key with the Root Private Key.
func (iss *Issuer) SignIssuer(signer IssuerSigner) error {
	var err error
	iss.KeyUrl, iss.LeafPublicKeyDerSignature, err = signer.Sign(iss.LeafPublicKeyDer)
	return err
}

// SignTimeStamp Signs the Time Stamp with the Leaf Public Key.
func (iss *Issuer) SignTimeStamp(ss *SignedTimeStamp) error {
	if iss.KeyUrl == "" || len(iss.LeafPublicKeyDerSignature) == 0 {
		return errors.New("issuer needs signing before it can be used")
	}

	ss.Issuer = iss
	ss.Datetime = time.Now().UTC()
	ss.Signature = ed25519.Sign(iss.private, ss.BytesToSign())

	return nil
}
