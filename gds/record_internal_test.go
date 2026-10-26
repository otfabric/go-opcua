// SPDX-License-Identifier: MIT

package gds

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the PRF of old encrypted keys, under test
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

func TestApplicationRecordCodec(t *testing.T) {
	r := &ApplicationRecord{
		ApplicationURI:     "urn:a",
		ApplicationType:    ua.ApplicationTypeClientAndServer,
		ApplicationNames:   []*ua.LocalizedText{ua.NewLocalizedText("A"), nil},
		ProductURI:         "urn:p",
		DiscoveryURLs:      []string{"opc.tcp://h:1"},
		ServerCapabilities: []string{"DA"},
	}
	eo, err := EncodeApplicationRecord(3, r)
	require.NoError(t, err)
	require.Nil(t, r.ApplicationID, "the record is not changed")
	require.Nil(t, r.ApplicationNames[1])
	require.True(t, eo.TypeID.NodeID.Equal(ApplicationRecordEncodingID(3)))

	// Over the wire: the body is kept in RawBody.
	b, err := ua.Encode(eo)
	require.NoError(t, err)
	var back ua.ExtensionObject
	_, err = ua.Decode(b, &back)
	require.NoError(t, err)
	require.NotEmpty(t, back.RawBody)
	got, err := DecodeApplicationRecord(3, &back)
	require.NoError(t, err)
	require.Equal(t, "urn:a", got.ApplicationURI)
	require.Equal(t, ua.ApplicationTypeClientAndServer, got.ApplicationType)
	require.Len(t, got.ApplicationNames, 2)
	require.True(t, got.ApplicationID.Equal(ua.NewTwoByteNodeID(0)))

	// A []byte Value, a registered *ApplicationRecord.
	got, err = DecodeApplicationRecord(3, eo)
	require.NoError(t, err)
	require.Equal(t, "urn:p", got.ProductURI)
	same, err := DecodeApplicationRecord(9, &ua.ExtensionObject{TypeID: eo.TypeID, Value: r})
	require.NoError(t, err)
	require.Same(t, r, same)

	_, err = EncodeApplicationRecord(3, nil)
	require.ErrorIs(t, err, errNotRecord)
	for name, bad := range map[string]*ua.ExtensionObject{
		"nil":       nil,
		"no type":   {},
		"other ns":  {TypeID: ua.NewExpandedNodeID(ApplicationRecordEncodingID(4), "", 0), Value: eo.Value},
		"no body":   {TypeID: eo.TypeID},
		"truncated": {TypeID: eo.TypeID, Value: eo.Value.([]byte)[:5]},
		"trailing":  {TypeID: eo.TypeID, Value: append(append([]byte(nil), eo.Value.([]byte)...), 0)},
	} {
		_, err := DecodeApplicationRecord(3, bad)
		require.ErrorIs(t, err, errNotRecord, name)
	}
}

// encryptPBES2 encrypts a PKCS #8 key like EncodePrivateKey with other
// parameters.
func encryptPBES2(t *testing.T, der []byte, password string, prf asn1.ObjectIdentifier, cipherOID asn1.ObjectIdentifier, keyLen int) []byte {
	t.Helper()
	salt := make([]byte, 8)
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(iv)
	h := sha1.New
	if prf.Equal(oidHMACWithSHA2) {
		h = sha256.New
	}
	k, err := pbkdf2.Key(h, password, salt, 1000, keyLen)
	require.NoError(t, err)
	block, err := aes.NewCipher(k)
	require.NoError(t, err)
	pad := aes.BlockSize - len(der)%aes.BlockSize
	data := append(append([]byte(nil), der...), make([]byte, pad)...)
	for i := len(der); i < len(data); i++ {
		data[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	params := pbkdf2Params{Salt: salt, IterationCount: 1000}
	if prf != nil {
		params.PRF = algorithmIdentifier{Algorithm: prf, Parameters: asn1.RawValue{Tag: asn1.TagNull}}
	}
	kdf, err := asn1.Marshal(params)
	require.NoError(t, err)
	ivDER, err := asn1.Marshal(iv)
	require.NoError(t, err)
	p, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		EncryptionScheme:  algorithmIdentifier{Algorithm: cipherOID, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	require.NoError(t, err)
	out, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: p}},
		EncryptedData: data,
	})
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: out})
}

func TestPrivateKeyCodec(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	plain, err := EncodePrivateKey("pem", key, "")
	require.NoError(t, err)
	got, err := DecodePrivateKey(PrivateKeyFormatPEM, plain, "")
	require.NoError(t, err)
	require.True(t, key.Equal(got))

	enc, err := EncodePrivateKey(PrivateKeyFormatPEM, key, "pw")
	require.NoError(t, err)
	got, err = DecodePrivateKey(PrivateKeyFormatPEM, enc, "pw")
	require.NoError(t, err)
	require.True(t, key.Equal(got))
	_, err = DecodePrivateKey(PrivateKeyFormatPEM, enc, "wrong")
	require.Error(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	for _, c := range []struct {
		prf    asn1.ObjectIdentifier
		cipher asn1.ObjectIdentifier
		n      int
	}{
		{nil, oidAES128CBC, 16},
		{oidHMACWithSHA1, oidAES192CBC, 24},
		{oidHMACWithSHA2, oidAES256CBC, 32},
	} {
		got, err := DecodePrivateKey(PrivateKeyFormatPEM, encryptPBES2(t, der, "pw", c.prf, c.cipher, c.n), "pw")
		require.NoError(t, err, c.cipher)
		require.True(t, key.Equal(got))
	}
	_, err = DecodePrivateKey(PrivateKeyFormatPEM, encryptPBES2(t, der, "pw", asn1.ObjectIdentifier{1, 2, 3}, oidAES128CBC, 16), "pw")
	require.Error(t, err, "unknown PRF")
	_, err = DecodePrivateKey(PrivateKeyFormatPEM, encryptPBES2(t, der, "pw", nil, asn1.ObjectIdentifier{1, 2, 3}, 16), "pw")
	require.Error(t, err, "unknown cipher")

	_, err = EncodePrivateKey(PrivateKeyFormatPFX, key, "")
	require.Error(t, err)
	_, err = DecodePrivateKey(PrivateKeyFormatPFX, plain, "")
	require.Error(t, err)
	_, err = DecodePrivateKey(PrivateKeyFormatPEM, []byte("no pem"), "")
	require.Error(t, err)
	for name, body := range map[string][]byte{
		"not asn1": []byte("junk"),
		"not pbes2": mustMarshal(t, encryptedPrivateKeyInfo{
			Algorithm: algorithmIdentifier{Algorithm: oidPBKDF2}, EncryptedData: []byte{1},
		}),
		"not pbkdf2": mustMarshal(t, encryptedPrivateKeyInfo{
			Algorithm: algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: mustMarshal(t, pbes2Params{
				KeyDerivationFunc: algorithmIdentifier{Algorithm: oidPBES2},
				EncryptionScheme:  algorithmIdentifier{Algorithm: oidAES128CBC},
			})}}, EncryptedData: []byte{1},
		}),
	} {
		_, err := DecodePrivateKey(PrivateKeyFormatPEM, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: body}), "pw")
		require.Error(t, err, name)
	}
	// Bad parameters and data inside a PBES2 structure.
	mk := func(kdf pbkdf2Params, iv []byte, data []byte) []byte {
		p := mustMarshal(t, pbes2Params{
			KeyDerivationFunc: algorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: mustMarshal(t, kdf)}},
			EncryptionScheme:  algorithmIdentifier{Algorithm: oidAES128CBC, Parameters: asn1.RawValue{FullBytes: mustMarshal(t, iv)}},
		})
		return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: mustMarshal(t, encryptedPrivateKeyInfo{
			Algorithm: algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: p}}, EncryptedData: data,
		})})
	}
	iv := make([]byte, 16)
	for name, b := range map[string][]byte{
		"iterations": mk(pbkdf2Params{Salt: []byte{1}, IterationCount: 0}, iv, make([]byte, 16)),
		"iv":         mk(pbkdf2Params{Salt: []byte{1}, IterationCount: 1}, []byte{1}, make([]byte, 16)),
		"data":       mk(pbkdf2Params{Salt: []byte{1}, IterationCount: 1}, iv, make([]byte, 15)),
		"padding":    mk(pbkdf2Params{Salt: []byte{1}, IterationCount: 1}, iv, make([]byte, 16)),
	} {
		_, err := DecodePrivateKey(PrivateKeyFormatPEM, b, "pw")
		require.Error(t, err, name)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	require.NoError(t, err)
	return b
}

// A Bad Browse result status makes method fall back to the standard method;
// other errors are returned.
func TestBadStatus(t *testing.T) {
	require.True(t, badStatus(ua.StatusBadNodeIDUnknown))
	require.True(t, badStatus(fmt.Errorf("browse: %w", ua.StatusBadUserAccessDenied)))
	require.False(t, badStatus(nil))
	require.False(t, badStatus(ua.StatusUncertain))
	require.False(t, badStatus(errors.New("transport")))
}
