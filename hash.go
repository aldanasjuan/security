package security

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
)

func NewSha1(value []byte) string {
	h := sha1.New()
	h.Write(value)
	// return fmt.Sprintf("%x", h.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func RandomString() string {
	return fmt.Sprintf("%v", base64.RawURLEncoding.EncodeToString(RandomBytes(64)))
}
