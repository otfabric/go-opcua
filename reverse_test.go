// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

func TestSameEndpointURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"opc.tcp://host:4840", "opc.tcp://host:4840", true},
		{"opc.tcp://host:4840/", "opc.tcp://host:4840", true},
		{"opc.tcp://HOST:4840/path", "opc.tcp://host:4840/path/", true},
		{"opc.tcp://host", "opc.tcp://host:4840", true},
		{"OPC.TCP://host:4840", "opc.tcp://host:4840", true},
		{"opc.tcp://host:4840", "opc.tcp://host:4841", false},
		{"opc.tcp://host:4840", "opc.tcp://other:4840", false},
		{"opc.tcp://host:4840/a", "opc.tcp://host:4840/b", false},
		{"opc.https://host:4840", "opc.tcp://host:4840", false},
		{"opc.tcp://host:4840", "://not a url", false},
		{"://not a url", "://not a url", true},
		{"", "", true},
	} {
		require.Equal(t, tc.same, sameEndpointURL(tc.a, tc.b), "%q vs %q", tc.a, tc.b)
		require.Equal(t, tc.same, sameEndpointURL(tc.b, tc.a), "%q vs %q", tc.b, tc.a)
	}
}

func TestMatchReverseHello(t *testing.T) {
	t.Parallel()
	l, err := uacp.ListenReverse(context.Background(), "127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	c, err := NewClient("opc.tcp://server:4840", InsecureNoSecurity(), ReverseConnectListener(l, ReverseServerURI("urn:server"), nil))
	require.NoError(t, err)
	require.NoError(t, c.matchReverseHello(&uacp.ReverseHello{ServerURI: "urn:server", EndpointURL: "opc.tcp://SERVER:4840/"}))
	// A server that announces no endpoint is accepted: the client uses its own.
	require.NoError(t, c.matchReverseHello(&uacp.ReverseHello{ServerURI: "urn:server"}))

	err = c.matchReverseHello(&uacp.ReverseHello{ServerURI: "urn:other", EndpointURL: "opc.tcp://server:4840"})
	require.ErrorIs(t, err, errors.ErrReverseHelloRejected)
	require.ErrorIs(t, err, ua.StatusBadServerURIInvalid)
	err = c.matchReverseHello(&uacp.ReverseHello{ServerURI: "urn:server", EndpointURL: "opc.tcp://other:4840"})
	require.ErrorIs(t, err, errors.ErrReverseHelloRejected)
	require.ErrorIs(t, err, ua.StatusBadTCPEndpointURLInvalid)

	// Without expectations anything goes.
	c, err = NewClient("", InsecureNoSecurity(), ReverseConnectListener(l))
	require.NoError(t, err)
	require.NoError(t, c.matchReverseHello(&uacp.ReverseHello{ServerURI: "urn:any", EndpointURL: "opc.tcp://any:1"}))
	require.Empty(t, c.endpoint())
}

// testCertificate returns a self-signed certificate with the given
// ApplicationUri.
func testCertificate(t *testing.T, appURI string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	u, err := url.Parse(appURI)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "reverse test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

func TestCheckReverseServerCertificate(t *testing.T) {
	t.Parallel()
	cert := testCertificate(t, "urn:server")
	rhe := &uacp.ReverseHello{ServerURI: "urn:server"}
	other := &uacp.ReverseHello{ServerURI: "urn:impostor"}

	newClient := func(mode ua.MessageSecurityMode, der []byte, opts ...Option) *Client {
		c, err := NewClient("", append([]Option{InsecureNoSecurity()}, append([]Option{ReverseConnect("127.0.0.1:0")}, opts...)...)...)
		require.NoError(t, err)
		c.cfg.sechan.SecurityMode = mode
		c.cfg.sechan.RemoteCertificate = der
		return c
	}

	// Without security there is no certificate to compare with.
	require.NoError(t, newClient(ua.MessageSecurityModeNone, cert).checkReverseServerCertificate(other))
	require.NoError(t, newClient(ua.MessageSecurityModeInvalid, cert).checkReverseServerCertificate(other))
	require.ErrorIs(t, newClient(ua.MessageSecurityModeSign, nil).checkReverseServerCertificate(other), errors.ErrNoCertificate)

	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		c := newClient(mode, cert)
		require.NoError(t, c.checkReverseServerCertificate(rhe))
		err := c.checkReverseServerCertificate(other)
		require.ErrorIs(t, err, errors.ErrReverseHelloRejected)
		require.ErrorContains(t, err, "urn:impostor")
		require.ErrorIs(t, c.checkReverseServerCertificate(&uacp.ReverseHello{}), errors.ErrReverseHelloRejected)
	}

	// A chain: the leaf comes first and is the one that counts.
	chain := append(append([]byte{}, cert...), testCertificate(t, "urn:issuer")...)
	c := newClient(ua.MessageSecurityModeSignAndEncrypt, chain)
	require.NoError(t, c.checkReverseServerCertificate(rhe))
	require.Error(t, c.checkReverseServerCertificate(&uacp.ReverseHello{ServerURI: "urn:issuer"}))

	// An unreadable certificate is an error, not a pass.
	err := newClient(ua.MessageSecurityModeSign, []byte("not a certificate")).checkReverseServerCertificate(rhe)
	require.Error(t, err)
	require.NotErrorIs(t, err, errors.ErrReverseHelloRejected)

	// InsecureSkipVerify turns the check off with the rest of the validation.
	require.NoError(t, newClient(ua.MessageSecurityModeSign, cert, InsecureSkipVerify()).checkReverseServerCertificate(other))
}

func TestReverseOptions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A client that connects the usual way has none.
	c, err := NewClient("opc.tcp://server:4840", InsecureNoSecurity())
	require.NoError(t, err)
	opts, err := c.reverseOptions(ctx)
	require.NoError(t, err)
	require.Empty(t, opts)

	// A second client gets the same listener and expectation.
	l, err := uacp.ListenReverse(ctx, "127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	c, err = NewClient("opc.tcp://server:4840", InsecureNoSecurity(), ReverseConnectListener(l, ReverseServerURI("urn:server")), DialTimeout(7*time.Second))
	require.NoError(t, err)
	opts, err = c.reverseOptions(ctx)
	require.NoError(t, err)
	cfg, err := ApplyConfig(opts...)
	require.NoError(t, err)
	require.Same(t, l, cfg.reverse.listener)
	require.Equal(t, "urn:server", cfg.reverse.serverURI)
	require.Equal(t, 7*time.Second, cfg.dialer.Dialer.Timeout)

	// A custom dialer without a net.Dialer has no timeout to pass on.
	c, err = NewClient("", InsecureNoSecurity(), ReverseConnectListener(l), Dialer(&uacp.Dialer{}))
	require.NoError(t, err)
	opts, err = c.reverseOptions(ctx)
	require.NoError(t, err)
	require.Len(t, opts, 1)
}

func TestReverseOwnListener(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, err := NewClient("", InsecureNoSecurity(), ReverseConnect("127.0.0.1:0"))
	require.NoError(t, err)

	// The listener is opened on first use and then kept.
	l, err := c.reverseListener(ctx)
	require.NoError(t, err)
	again, err := c.reverseListener(ctx)
	require.NoError(t, err)
	require.Same(t, l, again)
	addr := l.Addr().String()

	// Other clients of the same client share it.
	opts, err := c.reverseOptions(ctx)
	require.NoError(t, err)
	cfg, err := ApplyConfig(opts...)
	require.NoError(t, err)
	require.Same(t, l, cfg.reverse.listener)

	// A server the client does not expect is turned away at the listener.
	strict, err := NewClient("", InsecureNoSecurity(), ReverseConnect("127.0.0.1:0", ReverseServerURI("urn:expected")))
	require.NoError(t, err)
	sl, err := strict.reverseListener(ctx)
	require.NoError(t, err)
	conn, err := net.Dial("tcp", sl.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	body, err := (&uacp.ReverseHello{ServerURI: "urn:unexpected", EndpointURL: "opc.tcp://server:4840"}).Encode()
	require.NoError(t, err)
	hdr, err := (&uacp.Header{MessageType: uacp.MessageTypeReverseHello, ChunkType: uacp.ChunkTypeFinal, MessageSize: uint32(8 + len(body))}).Encode()
	require.NoError(t, err)
	_, err = conn.Write(append(hdr, body...))
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	reply := make([]byte, 8)
	_, err = conn.Read(reply)
	require.NoError(t, err)
	require.Equal(t, "ERRF", string(reply[:4]))
	require.NoError(t, strict.Close(ctx))

	// Close releases the listener, and a closed client opens no new one.
	require.NoError(t, c.Close(ctx))
	_, err = net.DialTimeout("tcp", addr, time.Second)
	require.Error(t, err)
	_, err = c.reverseListener(ctx)
	require.ErrorIs(t, err, ua.StatusBadConnectionClosed)
	require.ErrorIs(t, c.Dial(ctx), ua.StatusBadConnectionClosed)
	_, err = c.reverseOptions(ctx)
	require.Error(t, err)
	require.Error(t, c.TestingRefetchEndpoints(ctx))

	// An address that cannot be listened on is reported by Dial.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = busy.Close() }()
	c, err = NewClient("", InsecureNoSecurity(), ReverseConnect(busy.Addr().String()))
	require.NoError(t, err)
	require.ErrorContains(t, c.Dial(ctx), "reverse connect")
}
