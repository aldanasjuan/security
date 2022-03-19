package security

import (
	"crypto/subtle"
	"encoding/base64"

	jsoniter "github.com/json-iterator/go"
	"golang.org/x/crypto/argon2"
)

type Config struct {
	Hash    string `json:"hash,omitempty"`
	Salt    string `json:"salt,omitempty"`
	Memory  uint32 `json:"memory,omitempty"`
	Time    uint32 `json:"time,omitempty"`
	Threads uint8  `json:"threads,omitempty"`
	Length  uint32 `json:"length,omitempty"`
}

type Hash struct {
	Hash string `json:"hash"`
}

func NewPassword(password string, key []byte) (hash *Hash, err error) {
	config := &Config{
		Memory:  32 * 1024,
		Time:    3,
		Threads: 2,
		Length:  32,
	}
	salt := RandomBytes(24)
	config.Salt = base64.RawStdEncoding.EncodeToString(salt)
	result := argon2.IDKey([]byte(password), salt, config.Time, config.Memory, config.Threads, config.Length)
	config.Hash = base64.RawStdEncoding.EncodeToString(result)
	hash = &Hash{}
	err = hash.FromConfig(config, key)
	if err != nil {
		return nil, err
	}
	return hash, nil
}
func ValidatePassword(password string, hash *Hash, key []byte) (err error) {
	config, err := hash.GetConfig(key)
	if err != nil {
		return err
	}
	salt, err := base64.RawStdEncoding.DecodeString(config.Salt)
	if err != nil {
		return err
	}
	h, err := base64.RawStdEncoding.DecodeString(config.Hash)
	if err != nil {
		return err
	}
	result := argon2.IDKey([]byte(password), salt, config.Time, config.Memory, config.Threads, config.Length)
	if subtle.ConstantTimeCompare(h, result) == 1 {
		return nil
	}
	return nil
}

//creates a hash using a config struct. Key should be 32 bytes long
func (h *Hash) FromConfig(c *Config, key []byte) error {
	bts, err := jsoniter.Marshal(c)
	if err != nil {
		return err
	}
	h.Hash, err = Encrypt(bts, key)
	if err != nil {
		return err
	}
	return nil
}

//gets config from a hash
func (h *Hash) GetConfig(key []byte) (*Config, error) {
	val, err := Decrypt(h.Hash, key)
	if err != nil {
		return nil, err
	}
	var c Config
	err = jsoniter.Unmarshal(val, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
