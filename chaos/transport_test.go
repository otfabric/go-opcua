// SPDX-License-Identifier: MIT

package chaos

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// The scenarios in this file disturb the opc.wss and opc.https transports.
// They check what the opc.tcp scenarios check: no operation hangs, every
// client recovers once the faults stop, nothing leaks. How many operations
// succeed while the faults last is not asserted.

// transportEnv is a server with an opc.wss and an opc.https endpoint, each
// behind a chaos proxy of its own.
type transportEnv struct {
	srv    *server.Server
	direct map[string]string // scheme -> server address, bypassing the proxy
	proxy  map[string]*testutil.ChaosProxy
	tls    *tls.Config // client TLS configuration
}

func newTransportEnv(t *testing.T, seed int64, opts ...server.Option) *transportEnv {
	t.Helper()
	pki := testutil.TLS(t)
	e := &transportEnv{
		direct: make(map[string]string),
		proxy:  make(map[string]*testutil.ChaosProxy),
		tls:    pki.ClientConfig(),
	}
	// The proxies are created before the server so that the server can
	// advertise their ports; the backends are set once the server listens.
	wss := testutil.NewChaosProxy(t, "", seed)
	https := testutil.NewChaosProxy(t, "", seed+1)
	srv, err := server.New(append([]server.Option{
		server.EndPoint("localhost", 0),
		server.ListenOn("localhost:0"),
		server.WebSocketEndPoint("localhost", wss.Port()),
		server.ListenWebSocketOn("localhost:0"),
		server.HTTPSEndPoint("localhost", https.Port()),
		server.ListenHTTPSOn("localhost:0"),
		server.TLSConfig(pki.ServerConfig()),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.SetLogger(debugLogger()),
	}, opts...)...)
	if err != nil {
		t.Fatalf("chaos: new server: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("chaos: start server: %v", err)
	}
	e.srv = srv
	e.direct["opc.wss"] = srv.WebSocketAddr().String()
	e.direct["opc.https"] = srv.HTTPSAddr().String()
	wss.SetBackend(e.direct["opc.wss"])
	https.SetBackend(e.direct["opc.https"])
	e.proxy["opc.wss"] = wss
	e.proxy["opc.https"] = https
	return e
}

// url is the endpoint URL of scheme through its proxy.
func (e *transportEnv) url(scheme string) string {
	return fmt.Sprintf("%s://localhost:%d", scheme, e.proxy[scheme].Port())
}

// directURL is the endpoint URL of scheme without the proxy.
func (e *transportEnv) directURL(scheme string) string {
	_, port, _ := net.SplitHostPort(e.direct[scheme])
	return fmt.Sprintf("%s://localhost:%s", scheme, port)
}

func (e *transportEnv) dial(url string, extra ...opcua.Option) (*opcua.Client, error) {
	opts := []opcua.Option{
		opcua.InsecureNoSecurity(),
		opcua.TLSConfig(e.tls),
		opcua.DialTimeout(5 * time.Second),
		opcua.RequestTimeout(5 * time.Second),
		opcua.AutoReconnect(true),
		opcua.ReconnectInterval(50 * time.Millisecond),
	}
	if l := debugLogger(); l != nil {
		opts = append(opts, opcua.WithLogger(l.With("side", "client")))
	}
	c, err := opcua.NewClient(url, append([]opcua.Option{opcua.InsecureNoSecurity()}, append(opts, extra...)...)...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		closeClient(c, nil)
		return nil, err
	}
	return c, nil
}

// healthy reports whether a fresh client can read from the server over the
// transport of scheme, bypassing the proxy.
func (e *transportEnv) healthy(scheme string, opts ...opcua.Option) error {
	c, err := e.dial(e.directURL(scheme), append([]opcua.Option{opcua.AutoReconnect(false)}, opts...)...)
	if err != nil {
		return err
	}
	defer closeClient(c, nil)
	return readCurrentTime(c)
}

func readCurrentTime(c *opcua.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime), AttributeID: ua.AttributeIDValue},
	}})
	if err != nil {
		return err
	}
	if s := resp.Results[0].Status; s != ua.StatusOK {
		return s
	}
	return nil
}

// TestChaosTransportsManyClients runs many clients over opc.wss and opc.https
// while the connections are dropped, stalled, delayed and refused.
func TestChaosTransportsManyClients(t *testing.T) {
	transportsManyClients(t, false)
}

// transportsManyClients is TestChaosTransportsManyClients, over the UA JSON
// mappings of the transports (wss-uajson, https-uajson) with json.
func transportsManyClients(t *testing.T, json bool) {
	seed := seedFor(t)
	verifyLeaks := leakCheck(t)
	var opts []server.Option
	profiles := map[string]string{}
	if json {
		opts = append(opts, server.EnableUAJSON())
		profiles = map[string]string{"opc.wss": ua.TransportProfileWSSJSON, "opc.https": ua.TransportProfileHTTPSJSON}
	}
	e := newTransportEnv(t, seed, opts...)
	w := newWatchdog(t)
	rng := rand.New(rand.NewSource(seed))

	const perTransport = 6
	var clients []*opcua.Client
	for _, scheme := range []string{"opc.wss", "opc.https"} {
		for i := 0; i < perTransport; i++ {
			c, err := e.dial(e.url(scheme), opcua.TransportProfile(profiles[scheme]))
			if err != nil {
				t.Fatalf("chaos: connect %s: %v", scheme, err)
			}
			clients = append(clients, c)
		}
	}

	var tally errorTally
	var sink errSink
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func(i int, c *opcua.Client) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed + int64(i)))
			for {
				select {
				case <-stop:
					return
				default:
				}
				err := w.do(fmt.Sprintf("client %d op", i), func() error {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if r.Intn(2) == 0 {
						return readCurrentTime(c)
					}
					_, err := c.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
						NodeID: ua.NewNumericNodeID(0, id.ObjectsFolder), BrowseDirection: ua.BrowseDirectionForward,
						IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll),
					}}})
					return err
				})
				tally.add(err)
				if err != nil && !isConnectionError(err) {
					sink.addf("client %d: unexpected error: %v", i, err)
				}
			}
		}(i, c)
	}

	// Inject faults on both proxies.
	deadline := time.Now().Add(chaosDuration(t))
	for time.Now().Before(deadline) {
		p := e.proxy[[]string{"opc.wss", "opc.https"}[rng.Intn(2)]]
		switch rng.Intn(5) {
		case 0:
			p.DropAll()
		case 1:
			d := dir(rng)
			p.SetStall(d, true)
			time.Sleep(time.Duration(50+rng.Intn(300)) * time.Millisecond)
			p.SetStall(d, false)
		case 2:
			p.SetLatency(time.Duration(rng.Intn(50))*time.Millisecond, time.Duration(rng.Intn(20))*time.Millisecond)
		case 3:
			p.SetFragment(1 + rng.Intn(16))
		case 4:
			p.SetRefuse(true)
			p.DropAll()
			time.Sleep(time.Duration(50+rng.Intn(200)) * time.Millisecond)
			p.SetRefuse(false)
		}
		time.Sleep(time.Duration(20+rng.Intn(100)) * time.Millisecond)
	}
	for _, p := range e.proxy {
		p.Heal()
	}
	close(stop)
	w.wait("transport workers", &wg)
	t.Logf("operations while the faults lasted: %s", tally.String())
	sink.report(t)

	// Every client recovers.
	for i, c := range clients {
		var last error
		if !eventually(settleLimit, func() bool { last = readCurrentTime(c); return last == nil }) {
			t.Errorf("client %d did not recover: %v", i, last)
		}
	}
	for _, scheme := range []string{"opc.wss", "opc.https"} {
		if err := e.healthy(scheme, opcua.TransportProfile(profiles[scheme])); err != nil {
			t.Errorf("%s: server not healthy: %v", scheme, err)
		}
	}

	for _, c := range clients {
		closeClient(c, nil)
	}
	w.close()
	_ = e.srv.Close()
	for _, p := range e.proxy {
		p.Close()
	}
	verifyLeaks()
}

// wsUpgrade returns a WebSocket upgrade request for the opcua+uacp
// sub-protocol.
func wsUpgrade(host string) string {
	return "GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: opcua+uacp\r\n\r\n"
}

// wsFrame builds a WebSocket frame; mask is applied when set.
func wsFrame(fin bool, opcode byte, payload []byte, mask []byte, lengthOverride int64) []byte {
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	n := int64(len(payload))
	if lengthOverride >= 0 {
		n = lengthOverride
	}
	out := []byte{b0}
	var maskBit byte
	if mask != nil {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		out = append(out, maskBit|byte(n))
	case n <= 0xFFFF:
		out = append(out, maskBit|126, byte(n>>8), byte(n))
	default:
		out = append(out, maskBit|127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	if mask != nil {
		out = append(out, mask...)
		p := make([]byte, len(payload))
		for i := range payload {
			p[i] = payload[i] ^ mask[i%4]
		}
		payload = p
	}
	return append(out, payload...)
}

// tlsDial opens a TLS connection to addr trusting the test CA.
func (e *transportEnv) tlsDial(addr string) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	cfg := e.tls.Clone()
	cfg.ServerName = "localhost"
	return tls.DialWithDialer(d, "tcp", addr, cfg)
}

// TestChaosWSSMalformedFrames sends hostile byte streams to the WebSocket
// listener. Each connection must be closed by the server (or end in an
// error), and the server must keep serving others.
func TestChaosWSSMalformedFrames(t *testing.T) {
	seed := seedFor(t)
	verifyLeaks := leakCheck(t)
	e := newTransportEnv(t, seed)
	rng := rand.New(rand.NewSource(seed))
	addr := e.direct["opc.wss"]
	mask := []byte{1, 2, 3, 4}

	attacks := []struct {
		name    string
		upgrade bool
		payload func() []byte
	}{
		{"random bytes instead of the upgrade", false, func() []byte { return randBytes(rng, 1+rng.Intn(512)) }},
		{"HTTP request that is not an upgrade", false, func() []byte { return []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n") }},
		{"endless header", false, func() []byte { return []byte("GET / HTTP/1.1\r\nX: " + strings.Repeat("a", 64<<10)) }},
		{"unmasked client frame", true, func() []byte { return wsFrame(true, 2, frame("HEL", 'F', randBytes(rng, 28)), nil, -1) }},
		{"text frame", true, func() []byte { return wsFrame(true, 1, []byte("hello"), mask, -1) }},
		{"reserved opcode", true, func() []byte { return wsFrame(true, 3, nil, mask, -1) }},
		{"RSV bits", true, func() []byte {
			f := wsFrame(true, 2, randBytes(rng, 8), mask, -1)
			f[0] |= 0x70
			return f
		}},
		{"huge length", true, func() []byte { return wsFrame(true, 2, randBytes(rng, 16), mask, 1<<40) }},
		{"fragmented ping", true, func() []byte { return wsFrame(false, 9, nil, mask, -1) }},
		{"continuation without start", true, func() []byte { return wsFrame(true, 0, randBytes(rng, 8), mask, -1) }},
		{"garbage UACP in a binary frame", true, func() []byte { return wsFrame(true, 2, randBytes(rng, 1+rng.Intn(256)), mask, -1) }},
		{"random frame bytes", true, func() []byte { return randBytes(rng, 1+rng.Intn(256)) }},
	}

	for round := 0; round < 3; round++ {
		for _, a := range attacks {
			conn, err := e.tlsDial(addr)
			if err != nil {
				t.Fatalf("%s: dial: %v", a.name, err)
			}
			_ = conn.SetDeadline(time.Now().Add(withinBudget(settleLimit)))
			if a.upgrade {
				if _, err := io.WriteString(conn, wsUpgrade("localhost")); err != nil {
					t.Fatalf("%s: upgrade: %v", a.name, err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
					t.Fatalf("%s: upgrade refused: %v %v", a.name, resp, err)
				}
			}
			_, _ = conn.Write(a.payload())
			// The server answers with a close frame or an HTTP error, or just
			// closes; reading must end. A timeout here would be a hang.
			_, err = io.Copy(io.Discard, conn)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Errorf("%s: the server did not close the connection", a.name)
			}
			_ = conn.Close()
		}
	}
	if err := e.healthy("opc.wss"); err != nil {
		t.Errorf("server not healthy after the attacks: %v", err)
	}
	_ = e.srv.Close()
	for _, p := range e.proxy {
		p.Close()
	}
	verifyLeaks()
}

// TestChaosHTTPSSlowBodies holds many HTTPS connections open with requests
// that never complete (slowloris) and posts malformed bodies, while a normal
// client keeps working over HTTPS.
func TestChaosHTTPSSlowBodies(t *testing.T) {
	seed := seedFor(t)
	verifyLeaks := leakCheck(t)
	e := newTransportEnv(t, seed)
	rng := rand.New(rand.NewSource(seed))
	addr := e.direct["opc.https"]

	c, err := e.dial(e.directURL("opc.https"), opcua.AutoReconnect(false))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Slow requests: a header that never ends, and a body announced but
	// sent a byte at a time.
	var held []net.Conn
	for i := 0; i < 32; i++ {
		conn, err := e.tlsDial(addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		held = append(held, conn)
		if i%2 == 0 {
			_, _ = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
		} else {
			_, _ = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: "+uasc.HTTPSContentType+"\r\nContent-Length: 100000\r\n\r\n")
			_, _ = conn.Write(randBytes(rng, 1+rng.Intn(16)))
		}
	}

	// Malformed bodies over a well-behaved HTTP client.
	hc := uasc.NewHTTPSClient(e.tls)
	defer hc.CloseIdleConnections()
	for i := 0; i < 50; i++ {
		body := randBytes(rng, rng.Intn(1024))
		req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", uasc.HTTPSContentType)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("malformed body: HTTP %d, want 200 with a ServiceFault", resp.StatusCode)
		}
	}

	// The held connections do not keep the server from serving others.
	for i := 0; i < 20; i++ {
		if err := readCurrentTime(c); err != nil {
			t.Fatalf("read while slow connections are held: %v", err)
		}
	}

	// The server ends the slow requests itself; reading must end.
	for _, conn := range held {
		_ = conn.SetReadDeadline(time.Now().Add(withinBudget(settleLimit)))
		_, err := io.Copy(io.Discard, conn)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Errorf("the server did not end a slow request")
		}
		_ = conn.Close()
	}

	closeClient(c, nil)
	_ = e.srv.Close()
	for _, p := range e.proxy {
		p.Close()
	}
	verifyLeaks()
}
