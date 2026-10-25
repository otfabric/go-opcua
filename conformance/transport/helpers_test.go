// SPDX-License-Identifier: MIT

package transport

import "github.com/otfabric/go-opcua/internal/testutil/conformkit"

// The helpers of the conformance packages, under the names the tests use.
const (
	waitTimeout  = conformkit.WaitTimeout
	fastInterval = conformkit.FastInterval
)

var (
	eventually         = conformkit.Eventually
	parallel           = conformkit.Parallel
	newServer          = conformkit.NewServer
	setupWith          = conformkit.SetupWith
	newClient          = conformkit.NewClient
	dialClient         = conformkit.DialClient
	awaitValue         = conformkit.AwaitValue
	expectNoDataChange = conformkit.ExpectNoDataChange
	nextEvents         = conformkit.NextEvents
	writeInt32         = conformkit.WriteInt32
	endpointFor        = conformkit.EndpointFor
	pendingValues      = conformkit.PendingValues

	pki              = conformkit.PKI
	securePolicies   = conformkit.SecurePolicies
	secureModes      = conformkit.SecureModes
	secureServerOpts = conformkit.SecureServerOpts
	secureClientOpts = conformkit.SecureClientOpts
	shortPolicy      = conformkit.ShortPolicy
	userValidator    = conformkit.UserValidator
)
