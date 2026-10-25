// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// Certificate chains in the session services (Part 4 §6.1.8, Part 6 §6.2.3):
// an application may send its application instance certificate followed by
// the certificates of its issuers. Session signatures without
// SecureChannelEnhancements are made over the leaf, and verified with the
// leaf first and then with the chain.

const chainPolicy = ua.SecurityPolicyURIBasic256Sha256

type chainSessionFixture struct {
	t          *testing.T
	pki        *testpki.PKI
	svc        *SessionService
	sc         *uasc.SecureChannel // the server end
	client     *uasc.SecureChannel // the client's view, for its crypto helpers
	clientCert []byte              // as the client sends it
	serverCert []byte              // as the server sends it
	users      [][]byte
}

func chainOf(leaf, issuer []byte) []byte {
	return append(append([]byte(nil), leaf...), issuer...)
}

// newChainSessionFixture builds a session service. serverChain selects
// whether the server's certificate (issued by the CA) is configured and sent
// as a chain; otherwise the client's is.
func newChainSessionFixture(t *testing.T, serverChain bool) *chainSessionFixture {
	t.Helper()
	pki, err := testpki.Get()
	require.NoError(t, err)
	f := &chainSessionFixture{t: t, pki: pki}

	var serverKey, clientKey *rsa.PrivateKey
	if serverChain {
		f.serverCert, serverKey = chainOf(pki.IssuedCert, pki.CACert), pki.IssuedKey
		f.clientCert, clientKey = pki.ClientCert, pki.ClientKey
	} else {
		f.serverCert, serverKey = pki.ServerCert, pki.ServerKey
		f.clientCert, clientKey = chainOf(pki.IssuedCert, pki.CACert), pki.IssuedKey
	}

	srv := newTestServer()
	srv.cfg.certificate = f.serverCert
	srv.cfg.privateKey = serverKey
	srv.cfg.x509UserValidator = func(cert []byte) error {
		f.users = append(f.users, cert)
		return nil
	}
	f.svc = &SessionService{srv: srv}
	f.sc = uasc.NewCryptoChannel(&uasc.Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: chainPolicy,
		Certificate:       f.serverCert,
		LocalKey:          serverKey,
		RemoteCertificate: f.clientCert,
	})
	f.client = uasc.NewCryptoChannel(&uasc.Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: chainPolicy,
		Certificate:       f.clientCert,
		LocalKey:          clientKey,
		UserKey:           pki.IssuedKey,
		RemoteCertificate: f.serverCert,
	})
	return f
}

var chainClientNonce = []byte("0123456789abcdef0123456789abcdef")

func (f *chainSessionFixture) create() *ua.CreateSessionResponse {
	f.t.Helper()
	resp, err := f.svc.CreateSession(context.Background(), f.sc, &ua.CreateSessionRequest{
		RequestHeader:           reqHeader(),
		EndpointURL:             "opc.tcp://localhost:4840",
		RequestedSessionTimeout: 5000,
		ClientNonce:             chainClientNonce,
		ClientCertificate:       f.clientCert,
	}, 1)
	require.NoError(f.t, err)
	return resp.(*ua.CreateSessionResponse)
}

func (f *chainSessionFixture) activate(auth *ua.NodeID, clientSignature, userSignature []byte, token ua.IdentityToken) error {
	f.t.Helper()
	req := &ua.ActivateSessionRequest{
		RequestHeader:     &ua.RequestHeader{RequestHandle: 2, AuthenticationToken: auth},
		ClientSignature:   &ua.SignatureData{Signature: clientSignature},
		UserIdentityToken: ua.NewExtensionObject(token),
	}
	if userSignature != nil {
		req.UserTokenSignature = &ua.SignatureData{Signature: userSignature}
	}
	_, err := f.svc.ActivateSession(context.Background(), f.sc, req, 2)
	return err
}

// sign signs data with key the way a peer stack would.
func chainSign(t *testing.T, key *rsa.PrivateKey, data []byte) []byte {
	t.Helper()
	enc, err := uapolicy.AsymmetricKeys(chainPolicy, key, nil)
	require.NoError(t, err)
	sig, err := enc.Signature(data)
	require.NoError(t, err)
	return sig
}

func chainVerifies(t *testing.T, cert, data, sig []byte) bool {
	t.Helper()
	key, err := uapolicy.CertificatePublicKey(cert)
	require.NoError(t, err)
	enc, err := uapolicy.AsymmetricKeys(chainPolicy, nil, key)
	require.NoError(t, err)
	return enc.VerifySignature(data, sig) == nil
}

// A client (UA-.NETStandard does) sends its certificate as a chain.
func TestSessionService_ClientCertificateChain(t *testing.T) {
	f := newChainSessionFixture(t, false)
	leaf := f.pki.IssuedCert

	cs := f.create()
	require.Equal(t, f.pki.ServerCert, cs.ServerCertificate)
	// The ServerSignature is made over the leaf of the client's chain, which
	// every client verifies, and the go client verifies it.
	sig := cs.ServerSignature.Signature
	require.True(t, chainVerifies(t, f.pki.ServerCert, chainOf(leaf, chainClientNonce), sig))
	require.False(t, chainVerifies(t, f.pki.ServerCert, chainOf(f.clientCert, chainClientNonce), sig))
	require.NoError(t, f.client.VerifyCreateSessionSignature(cs.ServerCertificate, chainClientNonce, cs.ServerNonce, sig))

	// The client signs with the key of its leaf.
	clientSig, _, err := f.client.NewActivateSessionSignature(cs.ServerCertificate, cs.ServerNonce, chainClientNonce)
	require.NoError(t, err)
	require.NoError(t, f.activate(cs.AuthenticationToken, clientSig, nil, &ua.AnonymousIdentityToken{}))

	// A signature by the CA's key is not the client's.
	require.ErrorIs(t, f.activate(cs.AuthenticationToken, chainSign(t, f.pki.CAKey, chainOf(f.pki.ServerCert, cs.ServerNonce)), nil, &ua.AnonymousIdentityToken{}),
		ua.StatusBadSecurityChecksFailed)
}

// A server whose certificate is a chain: the ServerCertificate of
// CreateSession is the chain, and clients sign either its leaf
// (open62541, asyncua, go-opcua) or the whole chain (older stacks).
func TestSessionService_ServerCertificateChain(t *testing.T) {
	f := newChainSessionFixture(t, true)
	leaf := f.pki.IssuedCert

	cs := f.create()
	require.Equal(t, f.serverCert, cs.ServerCertificate)
	require.NoError(t, f.client.VerifyCreateSessionSignature(cs.ServerCertificate, chainClientNonce, cs.ServerNonce, cs.ServerSignature.Signature))

	// The X509IdentityToken carries a chain too.
	userChain := chainOf(leaf, f.pki.CACert)
	token := &ua.X509IdentityToken{CertificateData: userChain}

	nonce := cs.ServerNonce
	for _, signed := range []struct {
		name string
		cert []byte
	}{{"leaf", leaf}, {"chain", f.serverCert}} {
		t.Run(signed.name, func(t *testing.T) {
			clientSig := chainSign(t, f.pki.ClientKey, chainOf(signed.cert, nonce))
			userSig := chainSign(t, f.pki.IssuedKey, chainOf(signed.cert, nonce))
			require.NoError(t, f.activate(cs.AuthenticationToken, clientSig, userSig, token))
			sess := f.svc.srv.sb.Session(cs.AuthenticationToken)
			require.NotNil(t, sess)
			nonce = sess.serverNonce
		})
	}
	require.Len(t, f.users, 2)
	require.Equal(t, userChain, f.users[0], "the validator gets the chain as sent")

	// What go-opcua signs as a client is the leaf.
	clientSig, _, err := f.client.NewActivateSessionSignature(cs.ServerCertificate, nonce, chainClientNonce)
	require.NoError(t, err)
	require.True(t, chainVerifies(t, f.pki.ClientCert, chainOf(leaf, nonce), clientSig))
	userSig, _, err := f.client.NewSessionUserTokenSignature("", cs.ServerCertificate, nonce, chainClientNonce)
	require.NoError(t, err)
	require.True(t, chainVerifies(t, leaf, chainOf(leaf, nonce), userSig))
	require.NoError(t, f.activate(cs.AuthenticationToken, clientSig, userSig, token))
	nonce = f.svc.srv.sb.Session(cs.AuthenticationToken).serverNonce

	// Signatures over other data are refused.
	bad := chainSign(t, f.pki.ClientKey, chainOf(f.pki.CACert, nonce))
	require.ErrorIs(t, f.activate(cs.AuthenticationToken, bad, nil, &ua.AnonymousIdentityToken{}), ua.StatusBadSecurityChecksFailed)
	clientSig = chainSign(t, f.pki.ClientKey, chainOf(leaf, nonce))
	badUser := chainSign(t, f.pki.IssuedKey, chainOf(leaf, []byte("another nonce")))
	require.ErrorIs(t, f.activate(cs.AuthenticationToken, clientSig, badUser, token), ua.StatusBadUserSignatureInvalid)
}
