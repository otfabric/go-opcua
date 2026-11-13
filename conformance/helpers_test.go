// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/server"
)

// The generic helpers are shared with the other conformance packages, see
// conformkit.
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

	pki              = conformkit.PKI
	secureServerOpts = conformkit.SecureServerOpts
	secureClientOpts = conformkit.SecureClientOpts
)

// setupNodeMgmt is setup with the Node Management services enabled.
func setupNodeMgmt(t *testing.T) (*opcua.Client, *testutil.Fixture, context.Context) {
	t.Helper()
	c, f, _, _ := conformkit.SetupWith(t, nil, server.EnableNodeManagement())
	return c, f, context.Background()
}
