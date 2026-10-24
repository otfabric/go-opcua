// SPDX-License-Identifier: MIT

package uasc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

func testECCCert(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "go-opcua-ecc-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key, der
}

var eccTestPolicies = []struct {
	uri     string
	curve   elliptic.Curve
	sigLen  int
	nonce   int
	hmacLen int
}{
	{ua.SecurityPolicyURIECCNistP256, elliptic.P256(), 64, 64, 32},
	{ua.SecurityPolicyURIECCNistP384, elliptic.P384(), 96, 96, 48},
}

// eccPeers returns the two ends of an ECC OpenSecureChannel exchange: the
// instances a client and a server secure and verify the OPN messages with.
func eccPeers(t *testing.T, uri string, curve elliptic.Curve, mode ua.MessageSecurityMode) (client, server *channelInstance, clientCert, serverCert []byte) {
	t.Helper()
	clientKey, clientCert := testECCCert(t, curve)
	serverKey, serverCert := testECCCert(t, curve)

	calgo, err := uapolicy.AsymmetricKeys(uri, clientKey, &serverKey.PublicKey)
	require.NoError(t, err)
	salgo, err := uapolicy.AsymmetricKeys(uri, serverKey, &clientKey.PublicKey)
	require.NoError(t, err)

	cfg := func() *Config {
		return &Config{SecurityPolicyURI: uri, SecurityMode: mode, Logger: testLogger}
	}
	client = &channelInstance{sc: &SecureChannel{cfg: cfg()}, algo: calgo, zeroBasedSeq: true}
	server = &channelInstance{sc: &SecureChannel{cfg: cfg()}, algo: salgo, zeroBasedSeq: true}
	return client, server, clientCert, serverCert
}

// TestECC_OpenSecureChannelMessage encodes an OpenSecureChannel request the
// way an ECC policy puts it on the wire and decodes it on the other side:
// signed with ECDSA, not encrypted, not padded, with an ephemeral public key
// as the nonce.
func TestECC_OpenSecureChannelMessage(t *testing.T) {
	for _, pol := range eccTestPolicies {
		for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
			t.Run(pol.uri+"/"+mode.String(), func(t *testing.T) {
				client, server, clientCert, serverCert := eccPeers(t, pol.uri, pol.curve, mode)

				kx, err := uapolicy.NewKeyExchange(pol.uri, uapolicy.RoleClient)
				require.NoError(t, err)
				require.Len(t, kx.Nonce(), pol.nonce)

				req := &ua.OpenSecureChannelRequest{
					RequestHeader:     &ua.RequestHeader{AuthenticationToken: ua.NewTwoByteNodeID(0), RequestHandle: 7},
					RequestType:       ua.SecurityTokenRequestTypeIssue,
					SecurityMode:      mode,
					ClientNonce:       kx.Nonce(),
					RequestedLifetime: 3600000,
				}
				msg := &Message{
					MessageHeader: &MessageHeader{
						Header:                   NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, 0),
						AsymmetricSecurityHeader: NewAsymmetricSecurityHeader(pol.uri, clientCert, uapolicy.Thumbprint(serverCert)),
						SequenceHeader:           NewSequenceHeader(client.nextSequenceNumber(), 1),
					},
					TypeID:  ua.NewFourByteExpandedNodeID(0, id.OpenSecureChannelRequestEncodingDefaultBinary),
					Service: req,
				}
				plain, err := msg.Encode()
				require.NoError(t, err)

				wire, err := client.signAndEncrypt(msg, append([]byte(nil), plain...))
				require.NoError(t, err)

				// Signed only: the plaintext is on the wire unchanged, followed
				// by the signature. No padding, no RSA block arithmetic.
				require.Len(t, wire, len(plain)+pol.sigLen)
				require.Equal(t, plain[8:], wire[8:len(plain)], "the message is not encrypted")
				require.Equal(t, uint32(len(wire)), binary.LittleEndian.Uint32(wire[4:8]), "MessageSize covers the signature")
				require.Equal(t, uint32(0), binary.LittleEndian.Uint32(wire[12+len(pol.uri)+4+len(clientCert)+4+20+4:]),
					"the first sequence number of an ECC channel is 0")

				chunk := new(MessageChunk)
				_, err = chunk.Decode(wire)
				require.NoError(t, err)
				require.Equal(t, pol.uri, chunk.SecurityPolicyURI)
				require.Equal(t, clientCert, chunk.SenderCertificate)
				require.Equal(t, uapolicy.Thumbprint(serverCert), chunk.ReceiverCertificateThumbprint)

				body, err := server.verifyAndDecrypt(chunk, wire)
				require.NoError(t, err)
				seq := new(SequenceHeader)
				n, err := seq.Decode(body)
				require.NoError(t, err)
				require.Equal(t, uint32(0), seq.SequenceNumber)
				_, svc, err := ua.DecodeService(body[n:])
				require.NoError(t, err)
				got, ok := svc.(*ua.OpenSecureChannelRequest)
				require.True(t, ok)
				require.Equal(t, kx.Nonce(), got.ClientNonce)
				require.Equal(t, mode, got.SecurityMode)

				// The server can complete the key agreement with that nonce.
				skx, err := uapolicy.NewKeyExchange(pol.uri, uapolicy.RoleServer)
				require.NoError(t, err)
				_, err = skx.Symmetric(got.ClientNonce)
				require.NoError(t, err)

				// Any change to the message invalidates it. Changes to the
				// first 12 bytes are left out: they are the transport header,
				// which the decoder checks before the signature.
				for i := 12; i < len(wire); i += 7 {
					bad := append([]byte(nil), wire...)
					bad[i] ^= 0x04
					c := new(MessageChunk)
					if _, err := c.Decode(bad); err != nil {
						continue
					}
					_, err := server.verifyAndDecrypt(c, bad)
					require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed, "byte %d", i)
				}

				// A message signed by another key is refused.
				other, _, _, _ := eccPeers(t, pol.uri, pol.curve, mode)
				forged, err := other.signAndEncrypt(msg, append([]byte(nil), plain...))
				require.NoError(t, err)
				_, err = server.verifyAndDecrypt(chunk, forged)
				require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)

				// So is one that is too short to hold a signature.
				_, err = server.verifyAndDecrypt(chunk, wire[:12+chunk.AsymmetricSecurityHeader.Len()+pol.sigLen-1])
				require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
			})
		}
	}
}

// TestECC_NoVerificationKeyRejects makes sure a channel that has no key to
// verify with does not fall back to accepting unsigned messages.
func TestECC_NoVerificationKeyRejects(t *testing.T) {
	pol := eccTestPolicies[0]
	client, _, clientCert, serverCert := eccPeers(t, pol.uri, pol.curve, ua.MessageSecurityModeSign)

	msg := &Message{
		MessageHeader: &MessageHeader{
			Header:                   NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, 0),
			AsymmetricSecurityHeader: NewAsymmetricSecurityHeader(pol.uri, clientCert, uapolicy.Thumbprint(serverCert)),
			SequenceHeader:           NewSequenceHeader(0, 1),
		},
		TypeID:  ua.NewFourByteExpandedNodeID(0, id.OpenSecureChannelRequestEncodingDefaultBinary),
		Service: &ua.OpenSecureChannelRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: ua.NewTwoByteNodeID(0)}},
	}
	plain, err := msg.Encode()
	require.NoError(t, err)
	wire, err := client.signAndEncrypt(msg, plain)
	require.NoError(t, err)
	chunk := new(MessageChunk)
	_, err = chunk.Decode(wire)
	require.NoError(t, err)

	keyless, err := uapolicy.AsymmetricKeys(pol.uri, nil, nil)
	require.NoError(t, err)
	receiver := &channelInstance{sc: &SecureChannel{cfg: &Config{SecurityPolicyURI: pol.uri, SecurityMode: ua.MessageSecurityModeSign, Logger: testLogger}}, algo: keyless}
	_, err = receiver.verifyAndDecrypt(chunk, wire)
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)

	// Signing without a key fails as well.
	_, err = receiver.signAndEncrypt(msg, append([]byte(nil), plain...))
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
}

// TestECC_SymmetricMessages secures service messages with the keys of an ECC
// key exchange in both modes and both directions.
func TestECC_SymmetricMessages(t *testing.T) {
	for _, pol := range eccTestPolicies {
		for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
			t.Run(pol.uri+"/"+mode.String(), func(t *testing.T) {
				ckx, err := uapolicy.NewKeyExchange(pol.uri, uapolicy.RoleClient)
				require.NoError(t, err)
				skx, err := uapolicy.NewKeyExchange(pol.uri, uapolicy.RoleServer)
				require.NoError(t, err)
				calgo, err := ckx.Symmetric(skx.Nonce())
				require.NoError(t, err)
				salgo, err := skx.Symmetric(ckx.Nonce())
				require.NoError(t, err)

				cfg := &Config{SecurityPolicyURI: pol.uri, SecurityMode: mode, Logger: testLogger}
				client := &channelInstance{sc: &SecureChannel{cfg: cfg}, algo: calgo, zeroBasedSeq: true, secureChannelID: 9, securityTokenID: 3}
				server := &channelInstance{sc: &SecureChannel{cfg: cfg}, algo: salgo, zeroBasedSeq: true, secureChannelID: 9, securityTokenID: 3}

				for _, pair := range [][2]*channelInstance{{client, server}, {server, client}} {
					from, to := pair[0], pair[1]
					msg := from.newMessage(&ua.ReadRequest{
						RequestHeader: &ua.RequestHeader{AuthenticationToken: ua.NewTwoByteNodeID(0)},
						NodesToRead:   []*ua.ReadValueID{{NodeID: ua.NewNumericNodeID(0, 2258), AttributeID: ua.AttributeIDValue}},
					}, id.ReadRequestEncodingDefaultBinary, 5)
					plain, err := msg.Encode()
					require.NoError(t, err)
					wire, err := from.signAndEncrypt(msg, append([]byte(nil), plain...))
					require.NoError(t, err)

					if mode == ua.MessageSecurityModeSign {
						require.Len(t, wire, len(plain)+pol.hmacLen)
						require.Equal(t, plain[8:], wire[8:len(plain)])
					} else {
						require.Zero(t, (len(wire)-16)%16, "encrypted part is a whole number of AES blocks")
						require.NotContains(t, string(wire[16:]), string(plain[24:]))
					}

					chunk := new(MessageChunk)
					_, err = chunk.Decode(wire)
					require.NoError(t, err)
					body, err := to.verifyAndDecrypt(chunk, wire)
					require.NoError(t, err)
					require.Equal(t, plain[16:], body)

					bad := append([]byte(nil), wire...)
					bad[len(bad)-1] ^= 1
					_, err = to.verifyAndDecrypt(chunk, bad)
					require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)

					// The sender cannot read its own message back: each
					// direction has its own keys.
					_, err = from.verifyAndDecrypt(chunk, wire)
					require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
				}
			})
		}
	}
}

func TestSequenceNumbers(t *testing.T) {
	t.Run("zero based (ECC)", func(t *testing.T) {
		c := &channelInstance{zeroBasedSeq: true, sequenceNumber: 512} // a server's random start is ignored
		require.Equal(t, uint32(0), c.nextSequenceNumber())
		require.Equal(t, uint32(1), c.nextSequenceNumber())
		require.Equal(t, uint32(2), c.nextSequenceNumber())

		// Wraps to 0 after UInt32.MaxValue, not before.
		c.sequenceNumber = math.MaxUint32 - 2
		require.Equal(t, uint32(math.MaxUint32-1), c.nextSequenceNumber())
		require.Equal(t, uint32(math.MaxUint32), c.nextSequenceNumber())
		require.Equal(t, uint32(0), c.nextSequenceNumber())
		require.Equal(t, uint32(1), c.nextSequenceNumber())
	})

	t.Run("legacy (RSA, None)", func(t *testing.T) {
		c := &channelInstance{}
		require.Equal(t, uint32(1), c.nextSequenceNumber())
		require.Equal(t, uint32(2), c.nextSequenceNumber())

		// Wraps to a value below 1024 before UInt32.MaxValue - 1024.
		c.sequenceNumber = math.MaxUint32 - 1024
		require.Equal(t, uint32(math.MaxUint32-1023), c.nextSequenceNumber())
		require.Equal(t, uint32(1), c.nextSequenceNumber())
	})

	require.False(t, uapolicy.LegacySequenceNumbers(ua.SecurityPolicyURIECCNistP256))
	require.True(t, uapolicy.LegacySequenceNumbers(ua.SecurityPolicyURIBasic256Sha256))
	require.True(t, uapolicy.LegacySequenceNumbers(ua.SecurityPolicyURINone))
}

func TestNewRequestMessage_KeepsAdditionalHeader(t *testing.T) {
	sc := &SecureChannel{cfg: &Config{SecurityMode: ua.MessageSecurityModeNone, RequestTimeout: time.Second, Logger: testLogger}}
	c := newChannelInstance(sc)

	hdr := NewECDHPolicyHeader(ua.SecurityPolicyURIECCNistP256)
	req := &ua.CreateSessionRequest{RequestHeader: &ua.RequestHeader{AdditionalHeader: hdr}}
	_, err := c.newRequestMessage(req, 3, nil, time.Second)
	require.NoError(t, err)
	require.Same(t, hdr, req.RequestHeader.AdditionalHeader)
	require.Equal(t, uint32(3), req.RequestHeader.RequestHandle)

	// Without one nothing is added.
	plain := &ua.CreateSessionRequest{}
	_, err = c.newRequestMessage(plain, 4, nil, time.Second)
	require.NoError(t, err)
	require.Nil(t, plain.RequestHeader.AdditionalHeader)
}

// TestNewRequestMessage_KeepsCallerHeaderFields: the request header is built
// for the channel, but the ReturnDiagnostics mask and the AuditEntryId the
// caller set belong to the request and must reach the server.
func TestNewRequestMessage_KeepsCallerHeaderFields(t *testing.T) {
	sc := &SecureChannel{cfg: &Config{SecurityMode: ua.MessageSecurityModeNone, RequestTimeout: time.Second, Logger: testLogger}}
	c := newChannelInstance(sc)

	req := &ua.ReadRequest{RequestHeader: &ua.RequestHeader{
		ReturnDiagnostics: ua.ReturnDiagnosticsAll,
		AuditEntryID:      "audit-1",
		RequestHandle:     99,
	}}
	_, err := c.newRequestMessage(req, 5, nil, time.Second)
	require.NoError(t, err)
	require.Equal(t, uint32(ua.ReturnDiagnosticsAll), req.RequestHeader.ReturnDiagnostics)
	require.Equal(t, "audit-1", req.RequestHeader.AuditEntryID)
	require.Equal(t, uint32(5), req.RequestHeader.RequestHandle, "the handle is the channel's")
}

func TestECDHHeader(t *testing.T) {
	const uri = ua.SecurityPolicyURIECCNistP384

	t.Run("request", func(t *testing.T) {
		got, ok := ECDHPolicyFromHeader(roundTripExtensionObject(t, NewECDHPolicyHeader(uri)))
		require.True(t, ok)
		require.Equal(t, uri, got)
	})

	t.Run("response", func(t *testing.T) {
		key := &ua.EphemeralKeyType{PublicKey: []byte{1, 2, 3}, Signature: []byte{4, 5}}
		hdr := roundTripExtensionObject(t, NewECDHKeyHeader(uri, key))
		got, ok := ECDHPolicyFromHeader(hdr)
		require.True(t, ok)
		require.Equal(t, uri, got)
		gotKey, err := ECDHKeyFromHeader(hdr)
		require.NoError(t, err)
		require.Equal(t, key, gotKey)
	})

	t.Run("absent", func(t *testing.T) {
		for _, hdr := range []*ua.ExtensionObject{
			nil,
			ua.NewExtensionObject(nil),
			ua.NewExtensionObject(&ua.AdditionalParametersType{}),
			ua.NewExtensionObject(&ua.EphemeralKeyType{}), // not an AdditionalParametersType
			ua.NewExtensionObject(&ua.AdditionalParametersType{Parameters: []*ua.KeyValuePair{
				nil,
				{Key: nil, Value: ua.MustVariant("x")},
				{Key: &ua.QualifiedName{NamespaceIndex: 1, Name: "ECDHPolicyUri"}, Value: ua.MustVariant("x")},
				{Key: &ua.QualifiedName{Name: "Other"}, Value: ua.MustVariant("x")},
			}}),
		} {
			_, ok := ECDHPolicyFromHeader(hdr)
			require.False(t, ok)
			key, err := ECDHKeyFromHeader(hdr)
			require.NoError(t, err)
			require.Nil(t, key)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		param := func(name string, v any) *ua.ExtensionObject {
			return ua.NewExtensionObject(&ua.AdditionalParametersType{Parameters: []*ua.KeyValuePair{
				{Key: &ua.QualifiedName{Name: name}, Value: ua.MustVariant(v)},
			}})
		}
		_, ok := ECDHPolicyFromHeader(param("ECDHPolicyUri", int32(1)))
		require.False(t, ok)

		// A server that cannot create a key reports a StatusCode instead.
		_, err := ECDHKeyFromHeader(param("ECDHKey", ua.StatusBadSecurityPolicyRejected))
		require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)
		key, err := ECDHKeyFromHeader(param("ECDHKey", ua.StatusOK))
		require.NoError(t, err)
		require.Nil(t, key)

		_, err = ECDHKeyFromHeader(param("ECDHKey", "not a key"))
		require.ErrorIs(t, err, errors.ErrInvalidResponseType)
		_, err = ECDHKeyFromHeader(param("ECDHKey", ua.NewExtensionObject(&ua.AdditionalParametersType{})))
		require.ErrorIs(t, err, errors.ErrInvalidResponseType)
	})
}

// roundTripExtensionObject encodes and decodes an extension object, so the
// tests see what arrives on the other side of the wire.
func roundTripExtensionObject(t *testing.T, eo *ua.ExtensionObject) *ua.ExtensionObject {
	t.Helper()
	b, err := ua.Encode(eo)
	require.NoError(t, err)
	out := new(ua.ExtensionObject)
	_, err = ua.Decode(b, out)
	require.NoError(t, err)
	return out
}

func eccCryptoChannel(uri string, key crypto.Signer, cert []byte) *SecureChannel {
	return NewCryptoChannel(&Config{
		SecurityPolicyURI: uri,
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		LocalPrivateKey:   key,
		Certificate:       cert,
		Logger:            testLogger,
	})
}

func TestECC_SessionSignatures(t *testing.T) {
	for _, pol := range eccTestPolicies {
		t.Run(pol.uri, func(t *testing.T) {
			clientKey, clientCert := testECCCert(t, pol.curve)
			serverKey, serverCert := testECCCert(t, pol.curve)
			client := eccCryptoChannel(pol.uri, clientKey, clientCert)
			server := eccCryptoChannel(pol.uri, serverKey, serverCert)
			nonce := []byte("0123456789abcdef0123456789abcdef")

			// CreateSession: the server signs clientCertificate | clientNonce.
			sig, alg, err := server.NewSessionSignature(clientCert, nonce)
			require.NoError(t, err)
			require.Len(t, sig, pol.sigLen)
			require.Empty(t, alg, "the SignatureData.Algorithm of an ECC policy is null")
			require.NoError(t, client.VerifySessionSignature(serverCert, nonce, sig))

			require.Error(t, client.VerifySessionSignature(serverCert, []byte("another nonce"), sig))
			require.Error(t, client.VerifySessionSignature(clientCert, nonce, sig), "signed by the server, not the client")
			sig[3] ^= 1
			require.Error(t, client.VerifySessionSignature(serverCert, nonce, sig))

			// The inputs are not modified, even when they have spare capacity.
			certWithCap := append(make([]byte, 0, len(clientCert)+64), clientCert...)
			_, _, err = server.NewSessionSignature(certWithCap, nonce)
			require.NoError(t, err)
			require.Equal(t, clientCert, certWithCap)

			// X.509 user token: signed with the user's key.
			userKey, userCert := testECCCert(t, pol.curve)
			client.cfg.UserPrivateKey = userKey
			sig, alg, err = client.NewUserTokenSignature("", serverCert, nonce)
			require.NoError(t, err)
			require.Empty(t, alg)
			verify, err := uapolicy.AsymmetricKeys(pol.uri, nil, &userKey.PublicKey)
			require.NoError(t, err)
			require.NoError(t, verify.VerifySignature(append(append([]byte(nil), serverCert...), nonce...), sig))
			_ = userCert

			// Garbage where a certificate is expected.
			_, _, err = server.NewSessionSignature([]byte("junk"), nonce)
			require.Error(t, err)
			_, _, err = client.NewUserTokenSignature("", []byte("junk"), nonce)
			require.Error(t, err)
			require.Error(t, client.VerifySessionSignature([]byte("junk"), nonce, sig))

			require.Equal(t, clientCert, client.LocalCertificate())
			require.Nil(t, client.RemoteCertificate())
		})
	}
}

func TestECC_UserSecret(t *testing.T) {
	pol := eccTestPolicies[0]
	clientKey, clientCert := testECCCert(t, pol.curve)
	client := eccCryptoChannel(pol.uri, clientKey, clientCert)
	nonce := []byte("server-session-nonce-0123456789a")

	require.True(t, client.UserTokenPolicyIsECC(""))
	require.True(t, client.UserTokenPolicyIsECC(ua.SecurityPolicyURIECCNistP384))
	require.False(t, client.UserTokenPolicyIsECC(ua.SecurityPolicyURINone))
	require.False(t, client.UserTokenPolicyIsECC(ua.SecurityPolicyURIBasic256Sha256))

	newKey := func() *uapolicy.EphemeralKey {
		k, err := uapolicy.NewEphemeralKey(pol.uri)
		require.NoError(t, err)
		return k
	}

	t.Run("round trip", func(t *testing.T) {
		key := newKey()
		data, err := client.EncryptUserSecret("", []byte("wonderland"), key.PublicKey(), nonce)
		require.NoError(t, err)
		require.NotContains(t, string(data), "wonderland")

		got, err := DecryptUserSecret(key, data, clientCert, nonce)
		require.NoError(t, err)
		require.Equal(t, "wonderland", string(got))
	})

	t.Run("bound to the nonce", func(t *testing.T) {
		key := newKey()
		data, err := client.EncryptUserSecret(pol.uri, []byte("pw"), key.PublicKey(), nonce)
		require.NoError(t, err)
		_, err = DecryptUserSecret(key, data, clientCert, []byte("the nonce of another activation.."))
		require.ErrorIs(t, err, errors.ErrSignatureValidationFailed)
	})

	t.Run("bound to the client certificate", func(t *testing.T) {
		key := newKey()
		data, err := client.EncryptUserSecret("", []byte("pw"), key.PublicKey(), nonce)
		require.NoError(t, err)

		// Another application's certificate: the secret names a different
		// signer, and its signature does not verify with that key either.
		_, otherCert := testECCCert(t, pol.curve)
		_, err = DecryptUserSecret(key, data, otherCert, nonce)
		require.ErrorIs(t, err, errors.ErrSignatureValidationFailed)

		_, err = DecryptUserSecret(key, data, []byte("junk"), nonce)
		require.Error(t, err)
	})

	t.Run("signed by another key under the client's certificate", func(t *testing.T) {
		// An attacker who knows the client certificate but not its key.
		attackerKey, _ := testECCCert(t, pol.curve)
		attacker := eccCryptoChannel(pol.uri, attackerKey, clientCert)
		key := newKey()
		data, err := attacker.EncryptUserSecret("", []byte("pw"), key.PublicKey(), nonce)
		require.NoError(t, err)
		_, err = DecryptUserSecret(key, data, clientCert, nonce)
		require.ErrorIs(t, err, errors.ErrSignatureValidationFailed)
	})

	t.Run("no ephemeral key", func(t *testing.T) {
		_, err := client.EncryptUserSecret("", []byte("pw"), nil, nonce)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	})

	t.Run("rsa encryption is not available", func(t *testing.T) {
		_, serverCert := testECCCert(t, pol.curve)
		_, _, err := client.EncryptUserPassword("", "pw", serverCert, nonce)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	})

	t.Run("ephemeral key signature", func(t *testing.T) {
		serverKey, serverCert := testECCCert(t, pol.curve)
		server := eccCryptoChannel(pol.uri, serverKey, serverCert)
		key := newKey()

		sig, err := server.NewEphemeralKeySignature("", key.PublicKey())
		require.NoError(t, err)
		require.NoError(t, client.VerifyEphemeralKeySignature("", serverCert, key.PublicKey(), sig))

		require.Error(t, client.VerifyEphemeralKeySignature("", serverCert, newKey().PublicKey(), sig), "another key")
		require.Error(t, client.VerifyEphemeralKeySignature("", clientCert, key.PublicKey(), sig), "another signer")
		require.Error(t, client.VerifyEphemeralKeySignature("", serverCert, key.PublicKey(), nil), "no signature")
		require.Error(t, client.VerifyEphemeralKeySignature("", []byte("junk"), key.PublicKey(), sig))
		require.Error(t, client.VerifyEphemeralKeySignature(ua.SecurityPolicyURIBasic256Sha256, serverCert, key.PublicKey(), sig))

		keyless := NewCryptoChannel(&Config{SecurityPolicyURI: pol.uri, Logger: testLogger})
		_, err = keyless.NewEphemeralKeySignature("", key.PublicKey())
		require.Error(t, err)
		_, err = server.NewEphemeralKeySignature(ua.SecurityPolicyURIBasic256Sha256, key.PublicKey())
		require.Error(t, err)
	})
}

func TestConfig_PrivateKeys(t *testing.T) {
	rsaKey, _ := testRSACert(t)
	eccKey, _ := testECCCert(t, elliptic.P256())

	cfg := &Config{}
	require.Nil(t, cfg.localKey())
	require.Nil(t, cfg.userKey())
	require.True(t, cfg.localKey() == nil, "an unset RSA key is not a typed nil")

	cfg.LocalKey, cfg.UserKey = rsaKey, rsaKey
	require.Equal(t, crypto.PrivateKey(rsaKey), cfg.localKey())
	require.Equal(t, crypto.PrivateKey(rsaKey), cfg.userKey())

	// The key-type independent fields take precedence.
	cfg.LocalPrivateKey, cfg.UserPrivateKey = eccKey, eccKey
	require.Equal(t, crypto.PrivateKey(eccKey), cfg.localKey())
	require.Equal(t, crypto.PrivateKey(eccKey), cfg.userKey())
}
