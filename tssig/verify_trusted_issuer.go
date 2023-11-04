package tssig

import "strings"

// TrustedIssuerKeyCheck Interface for checking if a given Issuer Key URL is trusted.
type TrustedIssuerKeyCheck interface {
	Trusted(string) (bool, error)
}

// TrustedIssuerKeys Basic implementation of a Trusted Issuer Key check.
type TrustedIssuerKeys struct {
	KeyPrefixes []string
}

// Trusted Check if a Issuer key is trusted.
func (t *TrustedIssuerKeys) Trusted(key string) (bool, error) {
	var trusted bool

	// Not very efficient but fine for a small number of trusted issuers.
	for _, k := range t.KeyPrefixes {
		trusted = strings.HasPrefix(key, k)
		if trusted {
			return true, nil
		}
	}

	return false, nil
}
