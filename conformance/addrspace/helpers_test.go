// SPDX-License-Identifier: MIT

package addrspace

import (
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/ua"
)

// The helpers of the conformance packages, under the names the tests use.
const (
	waitTimeout  = conformkit.WaitTimeout
	fastInterval = conformkit.FastInterval
	serverAppURI = conformkit.ServerAppURI
)

var (
	eventually         = conformkit.Eventually
	parallel           = conformkit.Parallel
	newServer          = conformkit.NewServer
	setup              = conformkit.Setup
	setupWith          = conformkit.SetupWith
	newClient          = conformkit.NewClient
	dialClient         = conformkit.DialClient
	awaitValue         = conformkit.AwaitValue
	expectNoDataChange = conformkit.ExpectNoDataChange
	nextDataChanges    = conformkit.NextDataChanges
	nextEvents         = conformkit.NextEvents
	writeInt32         = conformkit.WriteInt32
	endpointFor        = conformkit.EndpointFor
	pendingValues      = conformkit.PendingValues

	pki            = conformkit.PKI
	securePolicies = conformkit.SecurePolicies
	secureModes    = conformkit.SecureModes
	secureServer   = conformkit.SecureServer

	element        = conformkit.Element
	elementOperand = conformkit.ElementOperand
	literalOperand = conformkit.LiteralOperand
	lit            = conformkit.Lit
)

type logCounter = conformkit.LogCounter

func mustSendRaw[T any](t *testing.T, c *opcua.Client, req ua.Request) *T {
	t.Helper()
	return conformkit.MustSendRaw[T](t, c, req)
}
