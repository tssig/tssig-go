package tssig

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"time"
)

// IssuerSigner Defines the methods for signing an Issuer
type IssuerSigner interface {
	GetKeyUrl() (string, error)
	Sign([]byte) ([]byte, error)
}

/*
The Issuer represents:
  - A Leaf Public Key, used to verify the signature on the SignedTimeStamp.
  - The URL to a DER encoded Root Public Key, used to verify the signature on the Issuer.
  - The issuer's signature, which signs the Root Key's URL, and the Leaf Key DER.
*/
type Issuer struct {
	RootPublicKeyUrl string   `json:"root-key"`
	LeafPublicKeyDer b64bytes `json:"leaf-key"`
	Signature        b64bytes `json:"signature"`

	leafPrivateKey ed25519.PrivateKey
}

// NewIssuer Creates a new Issuer with a ed25519 key.
func NewIssuer(public ed25519.PublicKey, private ed25519.PrivateKey) (*Issuer, error) {
	publicDer, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}

	return &Issuer{
		LeafPublicKeyDer: publicDer,
		leafPrivateKey:   private,
	}, nil
}

// BytesToSign Returns the bytes to be signed in the Issuer's signature.
func (iss *Issuer) BytesToSign() []byte {
	return append(b64bytes(iss.RootPublicKeyUrl), iss.LeafPublicKeyDer...)
}

// SignIssuer Signs the Key URL, and the Leaf Public Key, with the Root Private Key.
// The data is passed to the IssuerSigner, which performs the actual signing.
func (iss *Issuer) SignIssuer(signer IssuerSigner) error {
	var err error

	iss.RootPublicKeyUrl, err = signer.GetKeyUrl()
	if err != nil {
		return err
	}

	iss.Signature, err = signer.Sign(iss.BytesToSign())
	return err
}

// SignTimeStamp Generate the SignTimeStamp's signature, taking into account:
//   - The Issuer's signature
//   - The originally provided digest
//   - The current datetime
func (iss *Issuer) SignTimeStamp(sts *SignedTimeStamp) error {
	if iss.RootPublicKeyUrl == "" || len(iss.Signature) == 0 {
		return errors.New("issuer needs signing before it can be used")
	}

	sts.Issuer = iss
	sts.Datetime = time.Now().UTC()
	sts.Signature = ed25519.Sign(iss.leafPrivateKey, sts.BytesToSign())

	return nil
}
