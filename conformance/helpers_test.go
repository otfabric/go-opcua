// SPDX-License-Identifier: MIT

package conformance

import "github.com/otfabric/go-opcua/internal/testutil/conformkit"

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
