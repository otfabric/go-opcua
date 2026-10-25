// SPDX-License-Identifier: MIT

package chaos

import (
	"bufio"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// The scenarios of transport_test.go over the UA JSON mappings of the
// transports: https-uajson and wss-uajson.

// TestChaosUAJSONManyClients runs many clients over wss-uajson and
// https-uajson while the connections are dropped, stalled, delayed and
// refused.
func TestChaosUAJSONManyClients(t *testing.T) {
	transportsManyClients(t, true)
}

// wsJSONUpgrade returns a WebSocket upgrade request for the opcua+uajson
// sub-protocol.
func wsJSONUpgrade(host string) string {
	return strings.Replace(wsUpgrade(host), "opcua+uacp", "opcua+uajson", 1)
}

// TestChaosWSSJSONMalformedMessages sends hostile WebSocket messages over
// opcua+uajson. A broken frame must end the connection, a message that is
// not a request must be answered (with a ServiceFault) or end it, and the
// server must keep serving others.
func TestChaosWSSJSONMalformedMessages(t *testing.T) {
	seed := seedFor(t)
	verifyLeaks := leakCheck(t)
	e := newTransportEnv(t, seed, server.EnableUAJSON())
	rng := rand.New(rand.NewSource(seed))
	addr := e.direct["opc.wss"]
	mask := []byte{1, 2, 3, 4}
	text := func(s string) []byte { return wsFrame(true, 1, []byte(s), mask, -1) }

	attacks := []struct {
		name    string
		closes  bool // the server ends the connection
		payload func() []byte
	}{
		{"unmasked frame", true, func() []byte { return wsFrame(true, 1, []byte(`{"UaTypeId":"i=426"}`), nil, -1) }},
		{"invalid UTF-8", true, func() []byte { return wsFrame(true, 1, []byte{'{', 0xff, '}'}, mask, -1) }},
		{"huge length", true, func() []byte { return wsFrame(true, 1, randBytes(rng, 16), mask, 1<<40) }},
		{"over the size limit", true, func() []byte { return wsFrame(true, 1, randBytes(rng, 16), mask, 3<<20) }},
		{"reserved opcode", true, func() []byte { return wsFrame(true, 3, nil, mask, -1) }},
		{"random frame bytes", true, func() []byte { return randBytes(rng, 1+rng.Intn(256)) }},
		{"random binary message", false, func() []byte { return wsFrame(true, 2, randBytes(rng, 1+rng.Intn(256)), mask, -1) }},
		{"not JSON", false, func() []byte { return text("hello") }},
		{"deep nesting", false, func() []byte { return text(strings.Repeat("[", 100000)) }},
		{"unknown type", false, func() []byte { return text(`{"UaTypeId":"i=999999"}`) }},
		{"response instead of request", false, func() []byte { return text(`{"UaTypeId":"i=429","ResponseHeader":{}}`) }},
		{"wrong field types", false, func() []byte { return text(`{"UaTypeId":"i=631","NodesToRead":{"a":1}}`) }},
		{"read without a session", false, func() []byte {
			return text(`{"UaTypeId":"i=631","RequestHeader":{"RequestHandle":1},"NodesToRead":[{"NodeId":"i=2258","AttributeId":13}]}`)
		}},
	}

	for round := 0; round < 3; round++ {
		for _, a := range attacks {
			conn, err := e.tlsDial(addr)
			if err != nil {
				t.Fatalf("%s: dial: %v", a.name, err)
			}
			_ = conn.SetDeadline(time.Now().Add(withinBudget(settleLimit)))
			if _, err := io.WriteString(conn, wsJSONUpgrade("localhost")); err != nil {
				t.Fatalf("%s: upgrade: %v", a.name, err)
			}
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil || resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Protocol") != "opcua+uajson" {
				t.Fatalf("%s: upgrade refused: %v %v", a.name, resp, err)
			}
			_, _ = conn.Write(a.payload())
			if a.closes {
				// Reading must end; a timeout here would be a hang.
				_, err = io.Copy(io.Discard, br)
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Errorf("%s: the server did not close the connection", a.name)
				}
			} else if _, err := br.ReadByte(); err != nil {
				// The answer: a ServiceFault, or a Close frame.
				t.Errorf("%s: no answer: %v", a.name, err)
			}
			_ = conn.Close()
		}
	}
	if err := e.healthy("opc.wss", opcua.TransportProfile(ua.TransportProfileWSSJSON)); err != nil {
		t.Errorf("server not healthy after the attacks: %v", err)
	}
	if err := e.healthy("opc.wss"); err != nil {
		t.Errorf("opcua+uacp not healthy after the attacks: %v", err)
	}
	_ = e.srv.Close()
	for _, p := range e.proxy {
		p.Close()
	}
	verifyLeaks()
}

// TestChaosHTTPSJSONBodies posts malformed JSON and gzip bodies to
// https-uajson while a JSON client keeps working.
func TestChaosHTTPSJSONBodies(t *testing.T) {
	seed := seedFor(t)
	verifyLeaks := leakCheck(t)
	e := newTransportEnv(t, seed, server.EnableUAJSON())
	rng := rand.New(rand.NewSource(seed))
	addr := e.direct["opc.https"]

	c, err := e.dial(e.directURL("opc.https"), opcua.AutoReconnect(false), opcua.TransportProfile(ua.TransportProfileHTTPSJSON))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	hc := uasc.NewHTTPSClient(e.tls)
	defer hc.CloseIdleConnections()
	bodies := []func() (string, []byte){
		func() (string, []byte) { return "", randBytes(rng, rng.Intn(1024)) },
		func() (string, []byte) { return "", []byte(strings.Repeat(`{"a":`, 1+rng.Intn(5000))) },
		func() (string, []byte) {
			return "", []byte(`{"UaTypeId":"i=631","NodesToRead":[` + strings.Repeat(`{},`, rng.Intn(2000)) + `{}]}`)
		},
		func() (string, []byte) { return "gzip", randBytes(rng, rng.Intn(256)) },
	}
	for i := 0; i < 60; i++ {
		enc, body := bodies[rng.Intn(len(bodies))]()
		req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", uasc.HTTPSJSONContentType)
		if enc != "" {
			req.Header.Set("Content-Encoding", enc)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK && (enc != "gzip" || resp.StatusCode != http.StatusBadRequest) {
			t.Errorf("malformed body: HTTP %d, want 200 with a ServiceFault", resp.StatusCode)
		}
		if err := readCurrentTime(c); err != nil {
			t.Fatalf("read between malformed bodies: %v", err)
		}
	}

	closeClient(c, nil)
	_ = e.srv.Close()
	for _, p := range e.proxy {
		p.Close()
	}
	verifyLeaks()
}
