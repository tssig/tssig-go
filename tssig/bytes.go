package tssig

import "encoding/base64"

// A custom type for []byte to allow URLEncoding with Base64.
type bytes []byte

func (s bytes) MarshalJSON() ([]byte, error) {
	encodedVal := make([]byte, base64.URLEncoding.EncodedLen(len(s)))
	base64.URLEncoding.Encode(encodedVal, s)

	// +2 to cover the quote marks each side
	result := make([]byte, 0, len(encodedVal)+2)

	result = append(result, '"')
	result = append(result, encodedVal...)
	result = append(result, '"')

	return result, nil
}

func (s *bytes) UnmarshalJSON(data []byte) error {

	// Remove the quote marks (") - the first and last bytes
	dataWithoutQuotes := data[1 : len(data)-1]

	buffer := make(bytes, base64.URLEncoding.DecodedLen(len(dataWithoutQuotes)))
	l, err := base64.URLEncoding.Decode(buffer, dataWithoutQuotes)

	// The original buffer is often too big, thus we only return the length l decoded - the relevant bytes.
	*s = buffer[:l]

	return err
}
