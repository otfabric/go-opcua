// SPDX-License-Identifier: MIT

package uasc

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// aeadTestPolicies are the ECC policies with authenticated encryption.
var aeadTestPolicies = []struct {
	uri          string
	ed25519      bool
	enhancements bool
}{
	{ua.SecurityPolicyURIECCNistP256AesGcm, false, true},
	{ua.SecurityPolicyURIECCNistP256ChaChaPoly, false, true},
	{ua.SecurityPolicyURIECCCurve25519, true, false},
}

var secureModes = []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt}

// aeadTestCert returns an application instance key and certificate of the
// type the policy needs.
func aeadTestCert(t *testing.T, ed bool) (crypto.Signer, []byte) {
	t.Helper()
	if !ed {
		return testECCCert(t, elliptic.P256())
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "go-opcua-ed25519-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	return key, der
}

// aeadPair returns the two ends of an open AEAD channel after the
// OpenSecureChannel exchange: both have sent and received sequence number 0.
func aeadPair(t *testing.T, uri string, mode ua.MessageSecurityMode) (client, server *channelInstance) {
	t.Helper()
	ckx, err := uapolicy.NewKeyExchange(uri, uapolicy.RoleClient)
	require.NoError(t, err)
	skx, err := uapolicy.NewKeyExchange(uri, uapolicy.RoleServer)
	require.NoError(t, err)
	calgo, err := ckx.Symmetric(skx.Nonce())
	require.NoError(t, err)
	salgo, err := skx.Symmetric(ckx.Nonce())
	require.NoError(t, err)

	instance := func(algo *uapolicy.EncryptionAlgorithm) *channelInstance {
		cfg := &Config{SecurityPolicyURI: uri, SecurityMode: mode, Logger: testLogger}
		return &channelInstance{
			sc: &SecureChannel{cfg: cfg}, algo: algo,
			zeroBasedSeq: true, seqStarted: true,
			secureChannelID: 9, securityTokenID: 3,
		}
	}
	return instance(calgo), instance(salgo)
}

// sendChunks encodes a service message the way the channel does and returns
// the secured chunks.
func sendChunks(t *testing.T, from *channelInstance, svc any, typeID uint16) (wire, plain [][]byte) {
	t.Helper()
	m := from.newMessage(svc, typeID, 5)
	chunks, err := m.EncodeChunks(from.maxBodySize)
	require.NoError(t, err)
	for i, chunk := range chunks {
		if i > 0 {
			binary.LittleEndian.PutUint32(chunk[16:], from.nextSequenceNumber())
		}
		plain = append(plain, append([]byte(nil), chunk...))
		sealed, err := from.signAndEncrypt(m, chunk)
		require.NoError(t, err)
		wire = append(wire, sealed)
	}
	return wire, plain
}

// deliver hands a chunk to the receiving end the way readChunk does: verify,
// then remember its sequence number for the next one.
func deliver(to *channelInstance, wire []byte) (*MessageChunk, error) {
	chunk := new(MessageChunk)
	if _, err := chunk.Decode(wire); err != nil {
		return nil, err
	}
	data, err := to.verifyAndDecrypt(chunk, wire)
	if err != nil {
		return nil, err
	}
	n, err := chunk.SequenceHeader.Decode(data)
	if err != nil {
		return nil, err
	}
	chunk.Data = data[n:]
	to.sc.lastReceivedSequenceNumber.Store(chunk.SequenceNumber)
	return chunk, nil
}

func readRequest(nodes int) *ua.ReadRequest {
	req := &ua.ReadRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: ua.NewTwoByteNodeID(0)}}
	for i := 0; i < nodes; i++ {
		req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{
			NodeID: ua.NewStringNodeID(2, "a node with a rather long identifier"), AttributeID: ua.AttributeIDValue,
		})
	}
	return req
}

// TestAEAD_SymmetricMessages secures service messages with the AEAD policies
// in both modes and both directions.
func TestAEAD_SymmetricMessages(t *testing.T) {
	for _, pol := range aeadTestPolicies {
		for _, mode := range secureModes {
			t.Run(pol.uri+"/"+mode.String(), func(t *testing.T) {
				client, server := aeadPair(t, pol.uri, mode)

				for _, pair := range [][2]*channelInstance{{client, server}, {server, client}} {
					from, to := pair[0], pair[1]
					for i := 0; i < 3; i++ {
						wires, plains := sendChunks(t, from, readRequest(1), id.ReadRequestEncodingDefaultBinary)
						require.Len(t, wires, 1)
						wire, plain := wires[0], plains[0]

						// No padding: the chunk grows by the 16 byte tag, in
						// both modes. Header: message header, channel id and
						// token id stay readable.
						require.Len(t, wire, len(plain)+16)
						require.Equal(t, uint32(len(wire)), binary.LittleEndian.Uint32(wire[4:]))
						require.Equal(t, plain[:4], wire[:4])
						require.Equal(t, plain[8:16], wire[8:16])
						if mode == ua.MessageSecurityModeSign {
							require.Equal(t, plain[16:], wire[16:len(plain)], "a signed chunk is readable")
						} else {
							require.NotContains(t, string(wire), "a node with a rather long identifier")
							require.NotEqual(t, plain[16:24], wire[16:24], "the sequence header is encrypted too")
						}

						// Each direction has its own keys.
						chunk := new(MessageChunk)
						_, err := chunk.Decode(wire)
						require.NoError(t, err)
						_, err = from.verifyAndDecrypt(chunk, wire)
						require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)

						got, err := deliver(to, wire)
						require.NoError(t, err)
						require.Equal(t, plain[24:], got.Data)
						require.Equal(t, uint32(i+1), got.SequenceNumber)
					}
				}
			})
		}
	}
}

// TestAEAD_MultiChunkAndTamper sends a message that takes several chunks and
// then damages, replays, reorders and truncates them.
func TestAEAD_MultiChunkAndTamper(t *testing.T) {
	for _, pol := range aeadTestPolicies {
		for _, mode := range secureModes {
			t.Run(pol.uri+"/"+mode.String(), func(t *testing.T) {
				const chunkSize = 512
				client, server := aeadPair(t, pol.uri, mode)
				client.SetMaximumBodySize(chunkSize)

				req := readRequest(40)
				wires, _ := sendChunks(t, client, req, id.ReadRequestEncodingDefaultBinary)
				require.Greater(t, len(wires), 3, "the message must take several chunks")
				for i, wire := range wires {
					require.LessOrEqual(t, len(wire), chunkSize, "chunk %d fits the send buffer with its tag", i)
					want := byte(ChunkTypeIntermediate)
					if i == len(wires)-1 {
						want = ChunkTypeFinal
					}
					require.Equal(t, want, wire[3])
				}

				// In order, every chunk opens and the message is whole again.
				var chunks []*MessageChunk
				for i, wire := range wires {
					chunk, err := deliver(server, wire)
					require.NoError(t, err, "chunk %d", i)
					chunks = append(chunks, chunk)
				}
				_, svc, err := ua.DecodeService(mergeChunks(chunks))
				require.NoError(t, err)
				got, ok := svc.(*ua.ReadRequest)
				require.True(t, ok)
				require.Len(t, got.NodesToRead, 40)

				// A replayed chunk: the receiver has moved on, the nonce of
				// the old position no longer applies.
				for i, wire := range wires {
					_, err := deliver(server, wire)
					require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed, "replay of chunk %d", i)
				}

				// Reordered and dropped chunks, on a receiver at the start of
				// the message.
				rewind := func() { server.sc.lastReceivedSequenceNumber.Store(0) }
				rewind()
				_, err = deliver(server, wires[1])
				require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed, "second chunk first")
				_, err = deliver(server, wires[0])
				require.NoError(t, err)
				_, err = deliver(server, wires[2])
				require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed, "second chunk dropped")

				// Every byte of a chunk is protected. (A change to the first
				// 12 bytes may already fail the decoder.)
				first := wires[0]
				for i := range first {
					rewind()
					bad := append([]byte(nil), first...)
					bad[i] ^= 0x10
					_, err := deliver(server, bad)
					require.Error(t, err, "byte %d", i)
					if i >= 12 {
						require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed, "byte %d", i)
					}
				}
				// Truncated at every length, and extended.
				chunk := new(MessageChunk)
				_, err = chunk.Decode(first)
				require.NoError(t, err)
				rewind()
				for n := 16; n < len(first); n++ {
					_, err := server.verifyAndDecrypt(chunk, first[:n])
					require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed, "truncated to %d", n)
				}
				_, err = server.verifyAndDecrypt(chunk, append(append([]byte(nil), first...), 0))
				require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)

				// A chunk of another SecurityToken of the same channel.
				other := *chunk
				other.SymmetricSecurityHeader = NewSymmetricSecurityHeader(chunk.TokenID + 1)
				_, err = server.verifyAndDecrypt(&other, first)
				require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)

				// The untouched chunk is still good.
				rewind()
				_, err = deliver(server, first)
				require.NoError(t, err)
			})
		}
	}
}

// TestAEAD_SealRefusesNonceReuse: a chunk is not sent with a sequence number
// the SecurityToken has used before.
func TestAEAD_SealRefusesNonceReuse(t *testing.T) {
	client, _ := aeadPair(t, ua.SecurityPolicyURIECCNistP256AesGcm, ua.MessageSecurityModeSignAndEncrypt)
	_, _ = sendChunks(t, client, readRequest(1), id.ReadRequestEncodingDefaultBinary)

	// Wind the sequence numbers back: the next chunk would get the nonce of
	// the one just sent.
	client.sequenceNumber = 0
	m := client.newMessage(readRequest(1), id.ReadRequestEncodingDefaultBinary, 6)
	b, err := m.Encode()
	require.NoError(t, err)
	_, err = client.signAndEncrypt(m, b)
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)

	// Too short to hold a sequence header.
	_, err = client.sealChunk(m, make([]byte, 20), 16)
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
}

// opnMessage builds an OpenSecureChannel request or response message.
func opnMessage(c *channelInstance, uri string, localCert, remoteCert []byte, svc any, typeID uint16) *Message {
	return &Message{
		MessageHeader: &MessageHeader{
			Header:                   NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, 0),
			AsymmetricSecurityHeader: NewAsymmetricSecurityHeader(uri, localCert, uapolicy.Thumbprint(remoteCert)),
			SequenceHeader:           NewSequenceHeader(c.nextSequenceNumber(), 1),
		},
		TypeID:  ua.NewFourByteExpandedNodeID(0, typeID),
		Service: svc,
	}
}

// opnPeer is one end of an OpenSecureChannel exchange.
type opnPeer struct {
	*channelInstance
	key  crypto.Signer
	cert []byte
}

func newOPNPeers(t *testing.T, uri string, ed bool) (client, server *opnPeer) {
	t.Helper()
	clientKey, clientCert := aeadTestCert(t, ed)
	serverKey, serverCert := aeadTestCert(t, ed)
	calgo, err := uapolicy.AsymmetricKeys(uri, clientKey, serverKey.Public())
	require.NoError(t, err)
	salgo, err := uapolicy.AsymmetricKeys(uri, serverKey, clientKey.Public())
	require.NoError(t, err)
	cfg := func(key crypto.Signer, cert, remote []byte) *Config {
		return &Config{
			SecurityPolicyURI: uri, SecurityMode: ua.MessageSecurityModeSignAndEncrypt, Logger: testLogger,
			LocalPrivateKey: key, Certificate: cert, RemoteCertificate: remote,
		}
	}
	client = &opnPeer{key: clientKey, cert: clientCert, channelInstance: &channelInstance{
		sc: &SecureChannel{cfg: cfg(clientKey, clientCert, serverCert), kind: client0}, algo: calgo, zeroBasedSeq: true,
	}}
	server = &opnPeer{key: serverKey, cert: serverCert, channelInstance: &channelInstance{
		sc: &SecureChannel{cfg: cfg(serverKey, serverCert, clientCert), kind: server0}, algo: salgo, zeroBasedSeq: true,
	}}
	return client, server
}

const (
	client0 = client
	server0 = server
)

// exchange runs one OpenSecureChannel exchange between the peers and returns
// the two messages as they are on the wire, and the response before it was
// signed.
func exchange(t *testing.T, uri string, client, server *opnPeer) (request, response, plainResponse []byte, err error) {
	t.Helper()
	req := opnMessage(client.channelInstance, uri, client.cert, server.cert,
		&ua.OpenSecureChannelRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: ua.NewTwoByteNodeID(0)}, ClientNonce: []byte("client nonce")},
		id.OpenSecureChannelRequestEncodingDefaultBinary)
	plain, encErr := req.Encode()
	require.NoError(t, encErr)
	request, encErr = client.signAndEncrypt(req, plain)
	require.NoError(t, encErr)
	if _, err = deliver(server.channelInstance, request); err != nil {
		return request, nil, nil, err
	}

	resp := opnMessage(server.channelInstance, uri, server.cert, client.cert,
		&ua.OpenSecureChannelResponse{
			ResponseHeader: &ua.ResponseHeader{ServiceDiagnostics: &ua.DiagnosticInfo{}, AdditionalHeader: ua.NewExtensionObject(nil)},
			SecurityToken:  &ua.ChannelSecurityToken{}, ServerNonce: []byte("server nonce"),
		},
		id.OpenSecureChannelResponseEncodingDefaultBinary)
	plain, encErr = resp.Encode()
	require.NoError(t, encErr)
	plainResponse = append([]byte(nil), plain...)
	response, encErr = server.signAndEncrypt(resp, plain)
	require.NoError(t, encErr)
	_, err = deliver(client.channelInstance, response)
	return request, response, plainResponse, err
}

// TestAEAD_ChannelThumbprint covers the binding of the first OpenSecureChannel
// exchange (Part 6 §6.7.5).
func TestAEAD_ChannelThumbprint(t *testing.T) {
	for _, pol := range aeadTestPolicies {
		t.Run(pol.uri, func(t *testing.T) {
			client, server := newOPNPeers(t, pol.uri, pol.ed25519)
			require.Nil(t, client.sc.ChannelThumbprint())

			request, response, plainResponse, err := exchange(t, pol.uri, client, server)
			require.NoError(t, err)
			const sigLen = 64
			reqSig, respSig := request[len(request)-sigLen:], response[len(response)-sigLen:]
			// The header carries the final size, as it is signed.
			binary.LittleEndian.PutUint32(plainResponse[4:], uint32(len(response)))
			require.Equal(t, plainResponse, response[:len(response)-sigLen], "the response is not encrypted")

			verify, err := uapolicy.AsymmetricKeys(pol.uri, nil, server.key.Public())
			require.NoError(t, err)

			if !pol.enhancements {
				// A plain signature over the response, and no thumbprint.
				require.NoError(t, verify.VerifySignature(plainResponse, respSig))
				require.Nil(t, client.sc.ChannelThumbprint())
				require.Nil(t, server.sc.ChannelThumbprint())
				return
			}

			// The signature of the first response covers the response
			// followed by the signature of the request ...
			require.NoError(t, verify.VerifySignature(append(append([]byte(nil), plainResponse...), reqSig...), respSig))
			require.Error(t, verify.VerifySignature(plainResponse, respSig), "not the response alone")
			require.Error(t, verify.VerifySignature(append(append([]byte(nil), reqSig...), plainResponse...), respSig), "not in the other order")
			// ... and is the ChannelThumbprint on both sides.
			require.Equal(t, respSig, client.sc.ChannelThumbprint())
			require.Equal(t, respSig, server.sc.ChannelThumbprint())

			// The returned slice is a copy.
			tp := client.sc.ChannelThumbprint()
			tp[0] ^= 0xff
			require.Equal(t, respSig, client.sc.ChannelThumbprint())

			// A renewal is signed the plain way and leaves the thumbprint.
			_, response2, plainResponse2, err := exchange(t, pol.uri, client, server)
			require.NoError(t, err)
			binary.LittleEndian.PutUint32(plainResponse2[4:], uint32(len(response2)))
			require.NoError(t, verify.VerifySignature(plainResponse2, response2[len(response2)-sigLen:]))
			require.Equal(t, respSig, client.sc.ChannelThumbprint())
			require.Equal(t, respSig, server.sc.ChannelThumbprint())

			// A response made for another request is refused: a client that
			// sent a request of its own does not accept the answer to
			// someone else's, even though it is signed by the right server.
			victim, _ := newOPNPeers(t, pol.uri, pol.ed25519)
			victim.algo, err = uapolicy.AsymmetricKeys(pol.uri, victim.key, server.key.Public())
			require.NoError(t, err)
			req := opnMessage(victim.channelInstance, pol.uri, victim.cert, server.cert,
				&ua.OpenSecureChannelRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: ua.NewTwoByteNodeID(0)}},
				id.OpenSecureChannelRequestEncodingDefaultBinary)
			plain, err := req.Encode()
			require.NoError(t, err)
			_, err = victim.signAndEncrypt(req, plain)
			require.NoError(t, err)
			_, err = deliver(victim.channelInstance, response)
			require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
			require.Nil(t, victim.sc.ChannelThumbprint())

			// A server that is handed a plainly signed response to verify
			// (roles confused) gains no thumbprint from it either.
			fresh, freshServer := newOPNPeers(t, pol.uri, pol.ed25519)
			_, _, _, err = exchange(t, pol.uri, fresh, freshServer)
			require.NoError(t, err)
			require.NotEqual(t, respSig, fresh.sc.ChannelThumbprint(), "every channel has its own thumbprint")
		})
	}

	// The policies without the enhancements never get one.
	for _, pol := range eccTestPolicies {
		clientKey, clientCert := testECCCert(t, pol.curve)
		ch := eccCryptoChannel(pol.uri, clientKey, clientCert)
		ch.binding.sent(ch, []byte("signature"))
		ch.binding.received(ch, []byte("signature"))
		require.Nil(t, ch.ChannelThumbprint())
		require.Equal(t, []byte("m"), ch.binding.signedData(ch, []byte("m")))
		require.Equal(t, []byte("m"), ch.binding.verifiedData(ch, []byte("m")))
	}
}

// boundChannels returns the crypto channels of a client and a server that
// share the given ChannelThumbprint.
func boundChannels(t *testing.T, uri string, ed bool, thumbprint []byte) (client, server *SecureChannel, clientCert, serverCert []byte) {
	t.Helper()
	clientKey, clientCert := aeadTestCert(t, ed)
	serverKey, serverCert := aeadTestCert(t, ed)
	client = eccCryptoChannel(uri, clientKey, clientCert)
	client.cfg.RemoteCertificate = serverCert
	server = eccCryptoChannel(uri, serverKey, serverCert)
	server.kind = server0
	server.cfg.RemoteCertificate = clientCert
	client.binding.thumbprint = thumbprint
	server.binding.thumbprint = thumbprint
	return client, server, clientCert, serverCert
}

func sha(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// TestAEAD_SessionSignatures covers the signatures of CreateSession and
// ActivateSession on the AEAD policies: bound to the channel for the policies
// with SecureChannelEnhancements, the classic ones for ECC_curve25519.
func TestAEAD_SessionSignatures(t *testing.T) {
	clientNonce := bytes.Repeat([]byte{0xc1}, 32)
	serverNonce := bytes.Repeat([]byte{0x5e}, 32)

	for _, pol := range aeadTestPolicies {
		t.Run(pol.uri, func(t *testing.T) {
			tp := bytes.Repeat([]byte{0x7b}, 64)
			client, server, clientCert, serverCert := boundChannels(t, pol.uri, pol.ed25519, tp)
			userKey, userCert := aeadTestCert(t, pol.ed25519)
			client.cfg.UserPrivateKey = userKey

			verifyWith := func(cert, data, sig []byte) error {
				key, err := uapolicy.CertificatePublicKey(cert)
				require.NoError(t, err)
				enc, err := uapolicy.AsymmetricKeys(pol.uri, nil, key)
				require.NoError(t, err)
				return enc.VerifySignature(data, sig)
			}
			cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

			// The data each signature covers.
			createData := cat(clientCert, clientNonce)
			activateData := cat(serverCert, serverNonce)
			userData := activateData
			if pol.enhancements {
				createData = cat(tp, clientNonce, sha(serverCert), sha(clientCert), serverNonce)
				activateData = cat(tp, serverNonce, sha(serverCert), sha(serverCert), sha(clientCert), clientNonce)
				userData = cat(tp, serverNonce, sha(serverCert), sha(serverCert), sha(clientCert), sha(clientCert), clientNonce)
			}

			// CreateSession: signed by the server.
			sig, alg, err := server.NewCreateSessionSignature(clientCert, clientNonce, serverNonce)
			require.NoError(t, err)
			require.Empty(t, alg, "SignatureData.Algorithm is empty")
			require.Len(t, sig, 64)
			require.NoError(t, verifyWith(serverCert, createData, sig))
			require.NoError(t, client.VerifyCreateSessionSignature(serverCert, clientNonce, serverNonce, sig))
			require.Error(t, client.VerifyCreateSessionSignature(serverCert, serverNonce, clientNonce, sig))
			require.Error(t, client.VerifyCreateSessionSignature(clientCert, clientNonce, serverNonce, sig), "not signed by the client")
			require.Error(t, client.VerifyCreateSessionSignature([]byte("junk"), clientNonce, serverNonce, sig))

			// ActivateSession: signed by the client.
			sig, alg, err = client.NewActivateSessionSignature(serverCert, serverNonce, clientNonce)
			require.NoError(t, err)
			require.Empty(t, alg)
			require.NoError(t, verifyWith(clientCert, activateData, sig))
			require.NoError(t, server.VerifyActivateSessionSignature(clientCert, serverNonce, clientNonce, sig))
			require.Error(t, server.VerifyActivateSessionSignature(clientCert, []byte("an older server nonce"), clientNonce, sig))
			require.Error(t, server.VerifyActivateSessionSignature(serverCert, serverNonce, clientNonce, sig))
			require.Error(t, server.VerifyActivateSessionSignature(clientCert, serverNonce, clientNonce, nil))

			// X.509 user token: signed with the user's key.
			userSig, alg, err := client.NewSessionUserTokenSignature("", serverCert, serverNonce, clientNonce)
			require.NoError(t, err)
			require.Empty(t, alg)
			require.NoError(t, verifyWith(userCert, userData, userSig))
			require.NoError(t, server.VerifySessionUserTokenSignature("", userCert, serverCert, serverNonce, clientNonce, userSig))
			require.Error(t, server.VerifySessionUserTokenSignature("", clientCert, serverCert, serverNonce, clientNonce, userSig), "the application key is not the user key")
			require.Error(t, server.VerifySessionUserTokenSignature("", userCert, serverCert, serverNonce, clientNonce, sig))
			require.Error(t, server.VerifySessionUserTokenSignature("", []byte("junk"), serverCert, serverNonce, clientNonce, userSig))

			if !pol.enhancements {
				// The classic signatures: the old entry points agree, and
				// the client nonce plays no part.
				require.NoError(t, server.VerifySessionSignature(clientCert, serverNonce, sig))
				require.NoError(t, server.VerifyActivateSessionSignature(clientCert, serverNonce, []byte("ignored"), sig))
				return
			}

			// Bound to the channel: the same applications on another channel
			// do not accept the signatures.
			otherTP := bytes.Repeat([]byte{0x7c}, 64)
			server.binding.thumbprint = otherTP
			require.Error(t, server.VerifyActivateSessionSignature(clientCert, serverNonce, clientNonce, sig))
			require.Error(t, server.VerifySessionUserTokenSignature("", userCert, serverCert, serverNonce, clientNonce, userSig))
			server.binding.thumbprint = tp
			require.Error(t, server.VerifyActivateSessionSignature(clientCert, serverNonce, []byte("another client nonce"), sig))

			// A classic signature (certificate | nonce) is not accepted on a
			// bound channel, and the other way round.
			classic, _, err := client.NewSessionSignature(serverCert, serverNonce)
			require.NoError(t, err)
			require.Error(t, server.VerifyActivateSessionSignature(clientCert, serverNonce, clientNonce, classic))
			require.Error(t, server.VerifySessionSignature(clientCert, serverNonce, sig))

			// A user token whose policy has no enhancements is signed the
			// classic way, also on a bound channel.
			p256Key, p256Cert := testECCCert(t, elliptic.P256())
			client.cfg.UserPrivateKey = p256Key
			userSig, _, err = client.NewSessionUserTokenSignature(ua.SecurityPolicyURIECCNistP256, serverCert, serverNonce, clientNonce)
			require.NoError(t, err)
			require.NoError(t, verifyWith(p256Cert, cat(serverCert, serverNonce), userSig))
			require.NoError(t, server.VerifySessionUserTokenSignature(ua.SecurityPolicyURIECCNistP256, p256Cert, serverCert, serverNonce, clientNonce, userSig))

			// Without a ChannelThumbprint nothing is signed or accepted.
			client.binding.thumbprint, server.binding.thumbprint = nil, nil
			_, _, err = server.NewCreateSessionSignature(clientCert, clientNonce, serverNonce)
			require.Error(t, err)
			_, _, err = client.NewActivateSessionSignature(serverCert, serverNonce, clientNonce)
			require.Error(t, err)
			_, _, err = client.NewSessionUserTokenSignature("", serverCert, serverNonce, clientNonce)
			require.Error(t, err)
			require.Error(t, client.VerifyCreateSessionSignature(serverCert, clientNonce, serverNonce, sig))
			require.Error(t, server.VerifyActivateSessionSignature(clientCert, serverNonce, clientNonce, sig))
			require.Error(t, server.VerifySessionUserTokenSignature("", userCert, serverCert, serverNonce, clientNonce, userSig))

			// A certificate that cannot be hashed.
			client.binding.thumbprint = tp
			_, _, err = client.NewActivateSessionSignature([]byte("junk"), serverNonce, clientNonce)
			require.Error(t, err)
		})
	}

	// Security mode None: no signatures at all, as before.
	none := NewCryptoChannel(&Config{SecurityPolicyURI: ua.SecurityPolicyURINone, SecurityMode: ua.MessageSecurityModeNone, Logger: testLogger})
	sig, alg, err := none.NewCreateSessionSignature(nil, clientNonce, serverNonce)
	require.NoError(t, err)
	require.Nil(t, sig)
	require.Empty(t, alg)
	require.NoError(t, none.VerifyCreateSessionSignature(nil, clientNonce, serverNonce, nil))
	sig, _, err = none.NewActivateSessionSignature(nil, serverNonce, clientNonce)
	require.NoError(t, err)
	require.Nil(t, sig)
	require.NoError(t, none.VerifyActivateSessionSignature(nil, serverNonce, clientNonce, nil))
	require.Nil(t, none.ChannelThumbprint())
}

// TestAEAD_UserSecret protects a password with the EccEncryptedSecret of the
// AEAD policies through the channel API.
func TestAEAD_UserSecret(t *testing.T) {
	for _, pol := range aeadTestPolicies {
		t.Run(pol.uri, func(t *testing.T) {
			client, server, clientCert, serverCert := boundChannels(t, pol.uri, pol.ed25519, nil)
			require.True(t, client.UserTokenPolicyIsECC(""))
			nonce := []byte("the server nonce of the session!")

			key, err := uapolicy.NewEphemeralKey(pol.uri)
			require.NoError(t, err)
			sig, err := server.NewEphemeralKeySignature("", key.PublicKey())
			require.NoError(t, err)
			require.NoError(t, client.VerifyEphemeralKeySignature("", serverCert, key.PublicKey(), sig))
			require.Error(t, client.VerifyEphemeralKeySignature("", clientCert, key.PublicKey(), sig))

			secret, err := client.EncryptUserSecret("", []byte("wonderland"), key.PublicKey(), nonce)
			require.NoError(t, err)
			require.NotContains(t, string(secret), "wonderland")
			got, err := DecryptUserSecret(key, secret, clientCert, nonce)
			require.NoError(t, err)
			require.Equal(t, []byte("wonderland"), got)

			_, err = DecryptUserSecret(key, secret, clientCert, []byte("another nonce"))
			require.Error(t, err)
			_, err = DecryptUserSecret(key, secret, serverCert, nonce)
			require.Error(t, err, "signed by the client, not by the server")
			secret[len(secret)-70] ^= 1
			_, err = DecryptUserSecret(key, secret, clientCert, nonce)
			require.Error(t, err)

			_, _, err = client.EncryptUserPassword("", "pw", serverCert, nonce)
			require.Error(t, err, "no asymmetric encryption")
		})
	}
}

// FuzzAEADChunk feeds arbitrary bytes to the receive path of an AEAD channel:
// decoding and opening must not panic and must accept nothing but the chunks
// the peer sent.
func FuzzAEADChunk(f *testing.F) {
	type target struct {
		server *channelInstance
		valid  []byte
	}
	var targets []target
	for _, pol := range aeadTestPolicies {
		for _, mode := range secureModes {
			ckx, err := uapolicy.NewKeyExchange(pol.uri, uapolicy.RoleClient)
			if err != nil {
				f.Fatal(err)
			}
			skx, err := uapolicy.NewKeyExchange(pol.uri, uapolicy.RoleServer)
			if err != nil {
				f.Fatal(err)
			}
			calgo, err := ckx.Symmetric(skx.Nonce())
			if err != nil {
				f.Fatal(err)
			}
			salgo, err := skx.Symmetric(ckx.Nonce())
			if err != nil {
				f.Fatal(err)
			}
			cfg := &Config{SecurityPolicyURI: pol.uri, SecurityMode: mode, Logger: testLogger}
			client := &channelInstance{sc: &SecureChannel{cfg: cfg}, algo: calgo, zeroBasedSeq: true, seqStarted: true, secureChannelID: 9, securityTokenID: 3}
			server := &channelInstance{sc: &SecureChannel{cfg: cfg}, algo: salgo, zeroBasedSeq: true, seqStarted: true, secureChannelID: 9, securityTokenID: 3}

			m := client.newMessage(readRequest(1), id.ReadRequestEncodingDefaultBinary, 5)
			b, err := m.Encode()
			if err != nil {
				f.Fatal(err)
			}
			wire, err := client.signAndEncrypt(m, b)
			if err != nil {
				f.Fatal(err)
			}
			targets = append(targets, target{server: server, valid: wire})
			f.Add(wire)
			f.Add(wire[:len(wire)-1])
			f.Add(wire[:24])
		}
	}
	f.Add([]byte{})
	f.Add([]byte("MSGF\x10\x00\x00\x00\x09\x00\x00\x00\x03\x00\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		chunk := new(MessageChunk)
		if _, err := chunk.Decode(data); err != nil || chunk.SymmetricSecurityHeader == nil {
			return
		}
		for _, tg := range targets {
			out, err := tg.server.verifyAndDecrypt(chunk, data)
			if err == nil && !bytes.Equal(data, tg.valid) {
				t.Fatalf("accepted a forged chunk: %x -> %x", data, out)
			}
		}
	})
}
