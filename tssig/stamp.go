// Package tssig Go implementation of TSSig - a signed timestamp system.
package tssig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

/*
The SignedTimeStamp represents:
  - The Issuer who has signed the time stamp
  - The user provided Digest
  - The Datetime at which we signed it
  - The Signature
*/
type SignedTimeStamp struct {
	Issuer    *Issuer   `json:"issuer"`
	Datetime  time.Time `json:"datetime"`
	Digest    b64bytes  `json:"digest"`
	Signature b64bytes  `json:"signature"`
}

// NewSignedTimeStamp Creates a new instance of SignedTimeStamp
// We pass digest in as a string as we want to ensure that it's URL encoded base64.
func NewSignedTimeStamp(digest string) (*SignedTimeStamp, error) {
	digestBytes, err := base64.URLEncoding.DecodeString(digest)
	if err != nil {
		return nil, err
	}

	switch length := len(digestBytes); length {
	case 224 / 8:
	case 256 / 8:
	case 384 / 8:
	case 512 / 8:
	default:
		return nil, fmt.Errorf(
			"digest must be exactly 224, 256, 384, or 512 bits. %d bits found",
			len(digestBytes)*8,
		)
	}

	ss := &SignedTimeStamp{
		Digest: digestBytes,
	}

	return ss, nil
}

// BytesToSign The bytes which we are signing, made up of:
//   - The originally provided digest
//   - The Issuer's signature
//   - The current datetime
func (ss *SignedTimeStamp) BytesToSign() []byte {
	message := ss.Digest
	message = append(message, ss.Issuer.Signature...)
	return ss.Datetime.AppendFormat(message, time.RFC3339Nano)
}

func (ss *SignedTimeStamp) Json() ([]byte, error) {
	return json.Marshal(ss)
}

func (ss *SignedTimeStamp) PrettyJson() ([]byte, error) {
	return json.MarshalIndent(ss, "", "\t")
}
