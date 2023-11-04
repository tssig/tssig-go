package tssig

import (
	"fmt"
	"net/http"
	"time"
)

// MaxHttpDownloadSize Max size in bytes of the allowed body returned from the Issuer Key URL.
const MaxHttpDownloadSize = 128

// KeyLookup An interface for retrieving a root public key.
// Primarily designed to a caching layer can be added.
type KeyLookup interface {
	Get(string) ([]byte, error)
}

// HttpKeyLookup A concrete implementation for retrieving a root public key directly from the URL.
type HttpKeyLookup struct {
	Timeout time.Duration
}

// Get Downloads the root public key directly from the URL.
func (l *HttpKeyLookup) Get(url string) ([]byte, error) {
	client := &http.Client{Timeout: l.Timeout}

	response, err := client.Get(url)
	if err != nil {
		return []byte{}, err
	}
	defer response.Body.Close()

	// ---

	bufferSize := response.ContentLength

	if bufferSize > MaxHttpDownloadSize {
		return []byte{}, fmt.Errorf(
			"the maximum allowed key size is %d bytes. the returned key is %d bytes",
			MaxHttpDownloadSize,
			bufferSize,
		)
	} else if bufferSize < 0 {
		// If the content size is unknown, we'll allow the max size.
		// ecdsa der public keys appear to be about ~90 bytes.
		// ed25519 der public keys are smaller.

		// We add 1 to detect responses' that are too large.
		bufferSize = MaxHttpDownloadSize + 1
	}

	// ---

	der := make([]byte, bufferSize)
	n, err := response.Body.Read(der)
	if err != nil {
		return []byte{}, err
	}

	if n > MaxHttpDownloadSize {
		return []byte{}, fmt.Errorf(
			"the maximum allowed key size is %d bytes. the returned key is bigger",
			MaxHttpDownloadSize,
		)
	}

	return der[:n], nil
}
