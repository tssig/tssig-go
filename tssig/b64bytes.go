package tssig

import "encoding/base64"

// A custom type for []byte to allow URLEncoding with Base64.
type b64bytes []byte

func (s b64bytes) MarshalJSON() ([]byte, error) {
	encodedVal := make([]byte, base64.RawURLEncoding.EncodedLen(len(s)))
	base64.RawURLEncoding.Encode(encodedVal, s)

	// +2 to cover the quote marks each side
	result := make([]byte, 0, len(encodedVal)+2)

	result = append(result, '"')
	result = append(result, encodedVal...)
	result = append(result, '"')

	return result, nil
}

func (s *b64bytes) UnmarshalJSON(data []byte) error {

	// Remove the quote marks (") - the first and last bytes
	dataWithoutQuotes := data[1 : len(data)-1]

	buffer := make(b64bytes, base64.RawURLEncoding.DecodedLen(len(dataWithoutQuotes)))
	l, err := base64.RawURLEncoding.Decode(buffer, dataWithoutQuotes)

	// The original buffer is often too big, thus we only return the length l decoded - the relevant bytes.
	*s = buffer[:l]

	return err
}
