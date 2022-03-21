package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
	"strings"
	"time"

	"github.com/aldanasjuan/errs"
	jsoniter "github.com/json-iterator/go"
)

// Header has timestamp and exp, both in Unix
type Header struct {
	Timestamp int64 `json:"timestamp,omitempty"`
	Exp       int64 `json:"exp,omitempty"`
}

func (h Header) JSON() []byte {
	return []byte(fmt.Sprintf(`{"timestamp": %d, "exp": %d}`, h.Timestamp, h.Exp))
}

/* TODO
Create a tokenA

use tokenA plus signature to sign a tokenB (child)

New()   return tokenA
NewChild() return tokenB
Validate() takes a token and returns claims

*/

func NewToken(payload []byte, timestamp, exp int64, key []byte) (token string, err error) {

	head := Header{Timestamp: timestamp, Exp: exp}.JSON()
	hasher := hmac.New(sha256.New, key)
	//
	hj := append(payload, head...)

	_, err = hasher.Write(hj)
	if err != nil {
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	claims := base64.RawURLEncoding.EncodeToString(payload)
	header := base64.RawURLEncoding.EncodeToString(head)
	token = header + "." + claims + "." + signature
	return token, nil
}

// ValidateToken validates token with a given secret key and returns header and claims
func ValidateToken(token string, key []byte) (*Header, []byte, error) {
	strs := strings.Split(token, ".")
	if len(strs) != 3 {
		return nil, nil, ErrWrongFormat
	}
	a, err := base64.RawURLEncoding.DecodeString(strs[0])
	if err != nil {
		return nil, nil, err
	}
	b, err := base64.RawURLEncoding.DecodeString(strs[1])
	if err != nil {
		return nil, nil, err
	}
	// s,_ := base64.RawURLEncoding.DecodeString(strs[2])
	// fmt.Println(s)

	var h Header
	err = jsoniter.Unmarshal(a, &h)
	if err != nil {
		errs.Log(err)
		return nil, nil, err
	}
	t, err := NewToken(b, h.Timestamp, h.Exp, key)
	if err != nil {
		errs.Log(err)
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
		if h.Exp < time.Now().Unix() {
			return nil, nil, ErrExpired
		}
		return &h, b, nil
	}
	return nil, nil, ErrInvalid

}

// RandomBytes generates n bytes
func RandomBytes(n uint32) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		errs.Log(err)
		for i := 0; i < int(n); i++ {
			mrand.Seed(time.Now().UnixNano())
			min := 0
			max := 255
			b[i] = byte(mrand.Intn(max-min+1) + min)
		}
		return b
	}

	return b
}

func RandomNumber(min, max int64) int64 {
	m := math.Abs(float64(min) - float64(max))
	n, err := rand.Int(rand.Reader, big.NewInt(int64(m)))
	if err != nil {
		mrand.Seed(time.Now().UnixNano())
		r := mrand.Intn(int(max) - int(min) + 1)
		return int64(r) + min
	}
	v := n.Int64()
	return lerpRange(v, 0, int64(m), min, max)
}

func lerpRange(v, minA, maxA, minB, maxB int64) int64 {
	return (v-minA)*(maxB-minB)/(maxA-minA) + minB
}

func NewSignature(value []byte, key []byte) (string, error) {
	hasher := hmac.New(sha256.New, key)
	_, err := hasher.Write(value)
	if err != nil {
		return "", err
	}
	plain := base64.RawURLEncoding.EncodeToString(value)
	signed := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	return plain + "." + signed, nil
}

//ValidateSignature validates signature and returns the decoded value of the token
func ValidateSignature(value string, key []byte) ([]byte, error) {
	split := strings.Split(value, ".")
	if len(split) != 2 {
		return nil, ErrWrongFormat
	}
	bts, err := base64.RawURLEncoding.DecodeString(split[0])
	if err != nil {
		return nil, err
	}
	token, err := NewSignature(bts, key)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(value), []byte(token)) == 1 {
		return bts, nil
	}
	return nil, ErrInvalid
}
