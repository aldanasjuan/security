package security

import "errors"

var ErrExpired = errors.New("expired token")
var ErrWrongFormat = errors.New("wrong format")
var ErrInvalid = errors.New("invalid")
var ErrNilHash = errors.New("hash can't be nil")
