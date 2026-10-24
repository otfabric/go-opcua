// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/otfabric/go-opcua/errors"
)

const (
	AESBlockSize  = aes.BlockSize
	AESMinPadding = 0
)

type AES struct {
	KeyLength int
	IV        []byte
	Secret    []byte
}

// block returns the cipher for the key. Encrypt and Decrypt use the same key
// and both reject a key whose length is not KeyLength bits, or an IV that is
// not one block long (cipher.NewCBC* panics on that).
func (a *AES) block() (cipher.Block, error) {
	if len(a.Secret)*8 != a.KeyLength {
		return nil, fmt.Errorf("%w: AES key of %d bits, want %d", errors.ErrInvalidSecurityConfig, len(a.Secret)*8, a.KeyLength)
	}
	if len(a.IV) != aes.BlockSize {
		return nil, fmt.Errorf("%w: AES IV of %d bytes, want %d", errors.ErrInvalidSecurityConfig, len(a.IV), aes.BlockSize)
	}
	return aes.NewCipher(a.Secret)
}

func (a *AES) Decrypt(src []byte) ([]byte, error) {
	block, err := a.block()
	if err != nil {
		return nil, err
	}

	if len(src) < aes.BlockSize {
		return nil, errors.ErrInvalidCiphertext
	}

	// CBC mode always works in whole blocks.
	if len(src)%aes.BlockSize != 0 {
		return nil, errors.ErrInvalidCiphertext
	}

	dst := make([]byte, len(src))
	mode := cipher.NewCBCDecrypter(block, a.IV)
	mode.CryptBlocks(dst, src)
	return dst, nil
}

func (a *AES) Encrypt(src []byte) ([]byte, error) {
	// CBC mode always works in whole blocks.
	if len(src)%aes.BlockSize != 0 {
		return nil, errors.ErrInvalidPlaintext
	}

	block, err := a.block()
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))
	mode := cipher.NewCBCEncrypter(block, a.IV)
	mode.CryptBlocks(dst, src)
	return dst, nil
}
