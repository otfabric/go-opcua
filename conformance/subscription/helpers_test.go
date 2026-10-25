// SPDX-License-Identifier: MIT

package subscription

import (
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/ua"
)

// The helpers of the conformance packages, under the names the tests use.
const (
	waitTimeout  = conformkit.WaitTimeout
	fastInterval = conformkit.FastInterval
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
	freeCustomPort     = testport.TCP

	element        = conformkit.Element
	elementOperand = conformkit.ElementOperand
	lit            = conformkit.Lit
)

type (
	dataChange    = conformkit.DataChange
	stateRecorder = conformkit.StateRecorder
)

func sendRaw[T any](t *testing.T, c *opcua.Client, req ua.Request) (*T, error) {
	t.Helper()
	return conformkit.SendRaw[T](t, c, req)
}

func mustSendRaw[T any](t *testing.T, c *opcua.Client, req ua.Request) *T {
	t.Helper()
	return conformkit.MustSendRaw[T](t, c, req)
}
