// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// This file runs real client and server SecureChannels against each other over
// a loopback UACP connection, for every kind of security policy.

// covPolicy is a security policy and mode a channel pair is opened with.
type covPolicy struct {
	name  string
	uri   string
	mode  ua.MessageSecurityMode
	curve string // the testpki curve of the certificates; "" for RSA
}

var (
	covNone       = covPolicy{"None", ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, ""}
	covRSA        = covPolicy{"Basic256Sha256/SignAndEncrypt", ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, ""}
	covRSASign    = covPolicy{"Basic256Sha256/Sign", ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, ""}
	covECC        = covPolicy{"ECC_nistP256/SignAndEncrypt", ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt, testpki.CurveP256}
	covAEAD       = covPolicy{"ECC_nistP256_AesGcm/SignAndEncrypt", ua.SecurityPolicyURIECCNistP256AesGcm, ua.MessageSecurityModeSignAndEncrypt, testpki.CurveP256}
	covCurve25519 = covPolicy{"ECC_curve25519/Sign", ua.SecurityPolicyURIECCCurve25519, ua.MessageSecurityModeSign, testpki.CurveEd25519}
)

// covPolicies covers each family of policies: none, RSA with padding and
// block ciphers, ECC with block ciphers, ECC with authenticated encryption
// (with and without the SecureChannelEnhancements), in both secured modes.
var covPolicies = []covPolicy{
	covNone,
	covRSASign,
	covRSA,
	{"Aes256Sha256RsaPss/SignAndEncrypt", ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt, ""},
	{"ECC_nistP256/Sign", ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSign, testpki.CurveP256},
	{"ECC_nistP384/SignAndEncrypt", ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSignAndEncrypt, testpki.CurveP384},
	covAEAD,
	{"ECC_nistP256_ChaChaPoly/Sign", ua.SecurityPolicyURIECCNistP256ChaChaPoly, ua.MessageSecurityModeSign, testpki.CurveP256},
	covCurve25519,
	{"ECC_curve25519/SignAndEncrypt", ua.SecurityPolicyURIECCCurve25519, ua.MessageSecurityModeSignAndEncrypt, testpki.CurveEd25519},
	{"ECC_brainpoolP256r1/Sign", ua.SecurityPolicyURIECCBrainpoolP256r1, ua.MessageSecurityModeSign, testpki.CurveBrainpoolP256r1},
	{"ECC_brainpoolP256r1/SignAndEncrypt", ua.SecurityPolicyURIECCBrainpoolP256r1, ua.MessageSecurityModeSignAndEncrypt, testpki.CurveBrainpoolP256r1},
	{"ECC_brainpoolP384r1/Sign", ua.SecurityPolicyURIECCBrainpoolP384r1, ua.MessageSecurityModeSign, testpki.CurveBrainpoolP384r1},
	{"ECC_brainpoolP384r1/SignAndEncrypt", ua.SecurityPolicyURIECCBrainpoolP384r1, ua.MessageSecurityModeSignAndEncrypt, testpki.CurveBrainpoolP384r1},
	{"ECC_curve448/Sign", ua.SecurityPolicyURIECCCurve448, ua.MessageSecurityModeSign, testpki.CurveEd448},
	{"ECC_curve448/SignAndEncrypt", ua.SecurityPolicyURIECCCurve448, ua.MessageSecurityModeSignAndEncrypt, testpki.CurveEd448},
}

// covIdentity is an application instance certificate and its key.
type covIdentity struct {
	cert []byte
	key  crypto.Signer
}

// covIdentities returns the client and server certificates for a policy.
func covIdentities(t *testing.T, pol covPolicy) (client, server covIdentity) {
	t.Helper()
	pki, err := testpki.Get()
	require.NoError(t, err)
	if pol.curve == "" {
		return covIdentity{pki.ClientCert, pki.ClientKey}, covIdentity{pki.ServerCert, pki.ServerKey}
	}
	c, s := pki.ECC.Client[pol.curve], pki.ECC.Server[pol.curve]
	return covIdentity{c.Cert, c.Key}, covIdentity{s.Cert, s.Key}
}

// covConfigs returns the configurations of a client channel and of a server
// channel for the policy. The server learns the policy from the client's
// OpenSecureChannel request, as a real server does; it picks its certificate
// through LocalIdentity for the ECC policies and has a fixed one otherwise.
func covConfigs(t *testing.T, pol covPolicy) (clientCfg, serverCfg *Config) {
	t.Helper()
	clientCfg = &Config{
		SecurityPolicyURI: pol.uri,
		SecurityMode:      pol.mode,
		RequestTimeout:    10 * time.Second,
		Lifetime:          60_000,
		Logger:            testLogger,
	}
	serverCfg = &Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		RequestTimeout:    10 * time.Second,
		Lifetime:          60_000,
		Logger:            testLogger,
	}
	if pol.mode == ua.MessageSecurityModeNone {
		return clientCfg, serverCfg
	}
	cid, sid := covIdentities(t, pol)
	clientCfg.Certificate = cid.cert
	clientCfg.LocalPrivateKey = cid.key
	clientCfg.RemoteCertificate = sid.cert
	if pol.curve == "" {
		serverCfg.Certificate = sid.cert
		serverCfg.LocalPrivateKey = sid.key
	} else {
		serverCfg.LocalIdentity = func(uri string) ([]byte, crypto.Signer, error) {
			if uri != pol.uri {
				return nil, nil, fmt.Errorf("unexpected policy %s", uri)
			}
			return sid.cert, sid.key, nil
		}
	}
	return clientCfg, serverCfg
}

// covOpts changes how a channel pair is set up.
type covOpts struct {
	serverACK   *uacp.Acknowledge // the listener's limits
	clientACK   *uacp.Acknowledge // the limits the client asks for
	tweakClient func(*Config)
	tweakServer func(*Config)
	// handle is given every request the server receives before the default
	// handling (answering ReadRequests); it returns true if it took care of
	// the request.
	handle  func(p *covPair, msg *MessageBody) bool
	noOpen  bool // do not open the client channel
	noServe bool // no receive loop on the server: the test reads its connection
}

// covPair is a client and a server SecureChannel connected over loopback.
type covPair struct {
	t          *testing.T
	ln         *uacp.Listener
	client     *SecureChannel
	server     *SecureChannel
	clientConn *uacp.Conn
	serverConn *uacp.Conn
	clientErrs chan error
	// srvErrs receives the failed messages the server's receive loop saw.
	srvErrs chan *MessageBody
	srvDone chan struct{}
	handle  func(p *covPair, msg *MessageBody) bool

	closeOnce sync.Once
}

const covEndpoint = "opc.tcp://127.0.0.1:0"

// covConnect returns the two ends of a UACP connection.
func covConnect(t *testing.T, serverACK, clientACK *uacp.Acknowledge) (ln *uacp.Listener, client, server *uacp.Conn) {
	t.Helper()
	ctx := context.Background()
	ln, err := uacp.Listen(ctx, covEndpoint, serverACK)
	require.NoError(t, err)
	type result struct {
		c   *uacp.Conn
		err error
	}
	accepted := make(chan result, 1)
	go func() {
		c, err := ln.Accept(ctx)
		accepted <- result{c, err}
	}()
	client, err = (&uacp.Dialer{ClientACK: clientACK}).Dial(ctx, "opc.tcp://"+ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		require.NoError(t, err)
	}
	r := <-accepted
	require.NoError(t, r.err)
	return ln, client, r.c
}

func newCovPair(t *testing.T, pol covPolicy, o covOpts) *covPair {
	t.Helper()
	ln, cconn, sconn := covConnect(t, o.serverACK, o.clientACK)
	clientCfg, serverCfg := covConfigs(t, pol)
	if o.tweakClient != nil {
		o.tweakClient(clientCfg)
	}
	if o.tweakServer != nil {
		o.tweakServer(serverCfg)
	}
	p := &covPair{
		t:          t,
		ln:         ln,
		clientConn: cconn,
		serverConn: sconn,
		clientErrs: make(chan error, 16),
		srvErrs:    make(chan *MessageBody, 16),
		srvDone:    make(chan struct{}),
		handle:     o.handle,
	}
	var err error
	p.server, err = NewServerSecureChannel(ln.Endpoint(), sconn, serverCfg, make(chan error, 1), 7, 1, 9)
	require.NoError(t, err)
	p.client, err = NewSecureChannel(ln.Endpoint(), cconn, clientCfg, p.clientErrs)
	require.NoError(t, err)
	t.Cleanup(p.close)

	if o.noServe {
		close(p.srvDone)
	} else {
		go p.serve()
	}
	if !o.noOpen {
		require.NoError(t, p.client.Open(context.Background()))
		// The server makes the token active once it has sent it.
		require.Eventually(t, func() bool {
			c, tok := token(p.server)
			cc, ctok := token(p.client)
			return c == cc && tok == ctok
		}, 10*time.Second, time.Millisecond)
	}
	return p
}

// fatalReadError reports whether the server's connection cannot be read any
// more.
func fatalReadError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
}

// serve is the server's receive loop: it answers ReadRequests with the node
// ids that were asked for.
func (p *covPair) serve() {
	defer close(p.srvDone)
	for {
		msg := p.server.Receive(context.Background())
		if msg.Err != nil {
			select {
			case p.srvErrs <- msg:
			default:
			}
			if fatalReadError(msg.Err) {
				return
			}
			continue
		}
		if msg.Request() == nil {
			continue // the OpenSecureChannel exchange was handled by Receive
		}
		if p.handle != nil && p.handle(p, msg) {
			continue
		}
		if req, ok := msg.Request().(*ua.ReadRequest); ok {
			_ = p.server.SendResponseWithContext(context.Background(), msg.RequestID, readResponse(req))
		}
	}
}

func (p *covPair) close() {
	p.closeOnce.Do(func() {
		_ = p.client.Close()
		select {
		case <-p.srvDone:
		case <-time.After(10 * time.Second):
			p.t.Error("the server's receive loop did not end")
		}
		_ = p.server.Close()
		_ = p.ln.Close()
	})
}

func covRespHeader(status ua.StatusCode) *ua.ResponseHeader {
	return &ua.ResponseHeader{
		Timestamp:          time.Now(),
		ServiceResult:      status,
		ServiceDiagnostics: &ua.DiagnosticInfo{},
		StringTable:        []string{},
		AdditionalHeader:   ua.NewExtensionObject(nil),
	}
}

func covReadRequest(nodes int) *ua.ReadRequest {
	req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for i := 0; i < nodes; i++ {
		req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{
			NodeID:       ua.NewNumericNodeID(1, uint32(i)),
			AttributeID:  ua.AttributeIDValue,
			DataEncoding: &ua.QualifiedName{},
		})
	}
	return req
}

// readResponse answers a ReadRequest with the node id of every node as its
// value.
func readResponse(req *ua.ReadRequest) *ua.ReadResponse {
	resp := &ua.ReadResponse{ResponseHeader: covRespHeader(ua.StatusOK)}
	for _, n := range req.NodesToRead {
		resp.Results = append(resp.Results, &ua.DataValue{
			EncodingMask: ua.DataValueValue,
			Value:        ua.MustVariant(n.NodeID.String()),
		})
	}
	return resp
}

// read sends a ReadRequest for the given number of nodes and checks the
// answer.
func (p *covPair) read(t *testing.T, nodes int) {
	t.Helper()
	require.NoError(t, p.tryRead(context.Background(), nodes))
}

func (p *covPair) tryRead(ctx context.Context, nodes int) error {
	var got *ua.ReadResponse
	err := p.client.SendRequest(ctx, covReadRequest(nodes), nil, func(r ua.Response) error {
		var ok bool
		if got, ok = r.(*ua.ReadResponse); !ok {
			return fmt.Errorf("got %T", r)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(got.Results) != nodes {
		return fmt.Errorf("got %d results, want %d", len(got.Results), nodes)
	}
	for i, r := range got.Results {
		if want := ua.NewNumericNodeID(1, uint32(i)).String(); r.Value.Value() != want {
			return fmt.Errorf("result %d is %v, want %s", i, r.Value.Value(), want)
		}
	}
	return nil
}

// token returns the secure channel id and token id of the active token.
func token(s *SecureChannel) (channelID, tokenID uint32) {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	if s.activeInstance == nil {
		return 0, 0
	}
	return s.activeInstance.secureChannelID, s.activeInstance.securityTokenID
}

// TestSecureChannel_EndToEnd opens a channel for every kind of policy, sends
// requests and responses that fit one chunk and ones that need several,
// renews the token twice and keeps using the channel.
func TestSecureChannel_EndToEnd(t *testing.T) {
	for _, pol := range covPolicies {
		t.Run(pol.name, func(t *testing.T) {
			p := newCovPair(t, pol, covOpts{})

			require.Equal(t, pol.uri, p.server.SecurityPolicyURI(), "the server took over the client's policy")
			require.Equal(t, pol.mode, p.server.SecurityMode())
			if pol.mode != ua.MessageSecurityModeNone {
				cid, sid := covIdentities(t, pol)
				require.Equal(t, cid.cert, p.server.RemoteCertificate(), "the server knows the client's certificate")
				require.Equal(t, sid.cert, p.client.RemoteCertificate())
			}
			require.NotNil(t, p.server.RemoteAddr())

			channelID, tokenID := token(p.client)
			require.EqualValues(t, 7, channelID)
			require.EqualValues(t, 9, tokenID)
			sc, st := token(p.server)
			require.Equal(t, channelID, sc)
			require.Equal(t, tokenID, st)

			p.read(t, 3)
			p.read(t, 8000) // several chunks each way

			for renewal := uint32(1); renewal <= 2; renewal++ {
				require.NoError(t, p.client.Renew(context.Background()))
				c, tok := token(p.client)
				require.Equal(t, channelID, c, "a renewal keeps the channel")
				require.Equal(t, tokenID+renewal, tok, "and issues a new token")
				require.Eventually(t, func() bool {
					sc, st := token(p.server)
					return sc == c && st == tok
				}, 10*time.Second, time.Millisecond, "the server uses the new token")
				p.read(t, 8000)
				p.read(t, 1)
			}

			select {
			case err := <-p.clientErrs:
				t.Fatalf("unexpected client error: %v", err)
			default:
			}
		})
	}
}
