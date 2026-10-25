// SPDX-License-Identifier: MIT

package gds

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // hmacWithSHA1 is the default PRF of PBKDF2 (RFC 8018), accepted for decoding only
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/otfabric/go-opcua/uapolicy"
)

// The private key formats of StartNewKeyPairRequest and UpdateCertificate
// (Part 12 §7.9.4).
const (
	PrivateKeyFormatPEM = "PEM"
	PrivateKeyFormatPFX = "PFX"
)

// pbkdf2Iterations is the iteration count EncodePrivateKey uses.
const pbkdf2Iterations = 100_000

var (
	oidPBES2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1  = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES128CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	errPrivateKey    = errors.New("gds: invalid private key")
	errWrongPassword = fmt.Errorf("%w: wrong password or corrupt key", errPrivateKey)
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm     algorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                 `asn1:"optional"`
	PRF            algorithmIdentifier `asn1:"optional"`
}

// EncodePrivateKey encodes a private key as FinishRequest returns it: with
// format PEM a PKCS #8 "PRIVATE KEY" PEM block, or with a password an
// "ENCRYPTED PRIVATE KEY" (PKCS #8 with PBES2: PBKDF2 with HMAC-SHA-256 and
// AES-256-CBC, RFC 8018). A PFX holds the certificate too: encode it with
// uapolicy.EncodePFX.
func EncodePrivateKey(format string, key crypto.Signer, password string) ([]byte, error) {
	if !strings.EqualFold(format, PrivateKeyFormatPEM) {
		return nil, fmt.Errorf("%w: format %q is not supported", errPrivateKey, format)
	}
	der, err := uapolicy.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	k, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(der)%aes.BlockSize
	data := append(bytes.Clone(der), bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)

	null := asn1.RawValue{Tag: asn1.TagNull}
	kdf, err := asn1.Marshal(pbkdf2Params{Salt: salt, IterationCount: pbkdf2Iterations, KeyLength: 32,
		PRF: algorithmIdentifier{Algorithm: oidHMACWithSHA2, Parameters: null}})
	if err != nil {
		return nil, err
	}
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	params, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		EncryptionScheme:  algorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return nil, err
	}
	out, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		EncryptedData: data,
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: out}), nil
}

// DecodePrivateKey decodes the private key FinishRequest returned for a
// StartNewKeyPairRequest: format PEM (PKCS #8, PKCS #1 or SEC 1, or an
// "ENCRYPTED PRIVATE KEY" with PBES2, PBKDF2 and AES-CBC, decrypted with
// the password) or PFX (PKCS #12 protected with the password, see
// uapolicy.ParsePFX; its certificates are ignored).
func DecodePrivateKey(format string, data []byte, password string) (crypto.Signer, error) {
	if strings.EqualFold(format, PrivateKeyFormatPFX) {
		key, _, err := uapolicy.ParsePFX(data, password)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errPrivateKey, err)
		}
		return key, nil
	}
	if !strings.EqualFold(format, PrivateKeyFormatPEM) {
		return nil, fmt.Errorf("%w: format %q is not supported", errPrivateKey, format)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", errPrivateKey)
	}
	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return uapolicy.ParsePrivateKey(data)
	}
	der, err := decryptPKCS8(block.Bytes, password)
	if err != nil {
		return nil, err
	}
	return uapolicy.ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func decryptPKCS8(b []byte, password string) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(b, &info); err != nil || len(rest) > 0 || !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("%w: not a PBES2 encrypted key", errPrivateKey)
	}
	var params pbes2Params
	if rest, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil || len(rest) > 0 || !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("%w: not PBKDF2", errPrivateKey)
	}
	var kdf pbkdf2Params
	if rest, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil || len(rest) > 0 || kdf.IterationCount <= 0 || kdf.IterationCount > 10_000_000 {
		return nil, fmt.Errorf("%w: invalid PBKDF2 parameters", errPrivateKey)
	}
	var prf func() hash.Hash
	switch {
	case kdf.PRF.Algorithm == nil, kdf.PRF.Algorithm.Equal(oidHMACWithSHA1):
		prf = sha1.New
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA2):
		prf = sha256.New
	default:
		return nil, fmt.Errorf("%w: unsupported PBKDF2 PRF %v", errPrivateKey, kdf.PRF.Algorithm)
	}
	var keyLen int
	switch alg := params.EncryptionScheme.Algorithm; {
	case alg.Equal(oidAES128CBC):
		keyLen = 16
	case alg.Equal(oidAES192CBC):
		keyLen = 24
	case alg.Equal(oidAES256CBC):
		keyLen = 32
	default:
		return nil, fmt.Errorf("%w: unsupported cipher %v", errPrivateKey, alg)
	}
	var iv []byte
	if rest, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil || len(rest) > 0 || len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("%w: invalid IV", errPrivateKey)
	}
	k, err := pbkdf2.Key(prf, password, kdf.Salt, kdf.IterationCount, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	data := info.EncryptedData
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errWrongPassword
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || !bytes.Equal(out[len(out)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errWrongPassword
	}
	return out[:len(out)-pad], nil
}
