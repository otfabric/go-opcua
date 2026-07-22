//go:build interop

// SPDX-License-Identifier: MIT

// Peer trusted-certificate positive tests (C→O / C→M).
// COVERAGE.md: security / security.cert.trusted

package interop

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

// TestOpen62541Server_TrustedCert_Accepted dials an open62541 secure peer with
// mutually trusted certs (Basic256Sha256 SignAndEncrypt) and reads Scalar.Int32.
func TestOpen62541Server_TrustedCert_Accepted(t *testing.T) {
	t.Run("coverage/security.cert.trusted/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541SecureServer(t)
		c := dialSecureClient(t, h.endpoint, "Basic256Sha256", "SignAndEncrypt")
		ctx, nsIdx := findNS(t, c)
		v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
		if err != nil {
			t.Fatalf("Value(Scalar.Int32): %v", err)
		}
		got, ok := v.Value().(int32)
		if !ok {
			t.Fatalf("Scalar.Int32 type %T, want int32", v.Value())
		}
		const want int32 = -123456789
		if got != want {
			t.Errorf("Scalar.Int32: got %d, want %d", got, want)
		}
	})
}

// TestMiloServer_TrustedCert_Accepted dials a Milo secure peer with mutually
// trusted certs (Basic256Sha256 SignAndEncrypt) and reads Scalar.Int32.
func TestMiloServer_TrustedCert_Accepted(t *testing.T) {
	t.Run("coverage/security.cert.trusted/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloSecureServer(t)
		c := dialSecureClient(t, h.endpoint, "Basic256Sha256", "SignAndEncrypt")
		ctx, nsIdx := findNS(t, c)
		v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
		if err != nil {
			t.Fatalf("Value(Scalar.Int32): %v", err)
		}
		got, ok := v.Value().(int32)
		if !ok {
			t.Fatalf("Scalar.Int32 type %T, want int32", v.Value())
		}
		const want int32 = -123456789
		if got != want {
			t.Errorf("Scalar.Int32: got %d, want %d", got, want)
		}
	})
}
