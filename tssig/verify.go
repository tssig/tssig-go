package tssig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"time"
)

//------------------------------------
// Verifier

// Verifier Represents the code to verify a SignedTimeStamp, and its Issuer.
type Verifier struct {
	keyLookup      KeyLookup
	trustedIssuers TrustedIssuerKeyCheck
}

// NewVerifier instantiates an instance of Verifier with its default (direct) key lookup.
func NewVerifier(trustedIssuers TrustedIssuerKeyCheck) *Verifier {
	return NewVerifierWithKeyLookup(trustedIssuers, nil)
}

// NewVerifierWithKeyLookup instantiates an instance of Verifier with a custom key lookup.
func NewVerifierWithKeyLookup(trustedIssuers TrustedIssuerKeyCheck, keyLookup KeyLookup) *Verifier {
	if keyLookup == nil {
		keyLookup = &HttpKeyLookup{
			Timeout: time.Second * 5,
		}
	}
	return &Verifier{
		keyLookup:      keyLookup,
		trustedIssuers: trustedIssuers,
	}
}

// VerifyIssuer Verifies that the Leaf's public key has been signed by the Root Private Key,
func (v *Verifier) VerifyIssuer(i *Issuer) error {

	if len(i.RootPublicKeyUrl) == 0 {
		return errors.New("issuer key url has not been set")
	}

	if len(i.LeafPublicKeyDer) == 0 {
		return errors.New("leaf public key der has not been set")
	}

	//---

	// Check if we actually trust the issuer
	if trusted, err := v.trustedIssuers.Trusted(i.RootPublicKeyUrl); !trusted || err != nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("issuer key %s is not trusted", i.RootPublicKeyUrl)
	}

	//---

	der, err := v.keyLookup.Get(i.RootPublicKeyUrl)
	if err != nil {
		return err
	}

	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return err
	}

	var valid bool

	switch typedKey := public.(type) {
	case *ecdsa.PublicKey:
		var h hash.Hash
		switch typedKey.Params().BitSize {
		case 256:
			h = sha256.New()
		case 384:
			h = sha512.New384()
		case 521:
			h = sha512.New()
		default:
			return fmt.Errorf("invalid key size - must be 256, 384 or 521. %d found", typedKey.Params().BitSize)
		}
		h.Write(i.BytesToSign())
		valid = ecdsa.VerifyASN1(typedKey, h.Sum(nil), i.Signature)
	case ed25519.PublicKey:
		valid = ed25519.Verify(typedKey, i.BytesToSign(), i.Signature)
	default:
		err = errors.New("unknown key type")
	}

	if !valid {
		return errors.New("issue has invalid signature")
	}

	return nil
}

// VerifySignedTimeStamp Verifies that the SignedTimeStamp has been signed by the Leaf Private Key.
func (v *Verifier) VerifySignedTimeStamp(sts *SignedTimeStamp) error {
	public, err := x509.ParsePKIXPublicKey(sts.Issuer.LeafPublicKeyDer)
	if err != nil {
		return err
	}

	valid := ed25519.Verify(public.(ed25519.PublicKey), sts.BytesToSign(), sts.Signature)

	if !valid {
		return errors.New("stamp has invalid signature")
	}

	return nil
}

// Verify Combines the calling of the above into one method,
// verifying that both the Issuer and SignedTimeStamp are valid.
func (v *Verifier) Verify(sts *SignedTimeStamp) error {

	// Using a go routine here gives us a slight performance
	// boost when the Root Public Key is locally cached.

	ch := make(chan error, 1)
	go func() {
		ch <- v.VerifyIssuer(sts.Issuer)
	}()

	//---

	// Verify the SignedTimeStamp
	err := v.VerifySignedTimeStamp(sts)
	if err != nil {
		return err
	}

	// Get the result of the Issuer verification.
	return <-ch
}

// VerifyWithDigest Checks the Time Stamps digest matches the expected one passed.
// If so, it goes ahead and does the full verification.
func (v *Verifier) VerifyWithDigest(sts *SignedTimeStamp, digest []byte) error {
	if !bytes.Equal(digest, sts.Digest) {
		return errors.New("the passed digest does not match the one associated with the time stamp")
	}
	return v.Verify(sts)
}
