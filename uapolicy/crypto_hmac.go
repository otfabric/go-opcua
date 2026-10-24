// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto"
	"crypto/hmac"

	"github.com/otfabric/go-opcua/errors"
)

type HMAC struct {
	Hash   crypto.Hash
	Secret []byte
}

// sum returns the MAC of msg. Write of a hash.Hash never returns an error.
func (s *HMAC) sum(msg []byte) []byte {
	h := hmac.New(s.Hash.New, s.Secret)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func (s *HMAC) Signature(msg []byte) ([]byte, error) {
	return s.sum(msg), nil
}

func (s *HMAC) Verify(msg, signature []byte) error {
	if !hmac.Equal(s.sum(msg), signature) {
		return errors.ErrSignatureValidationFailed
	}
	return nil
}
