// SPDX-License-Identifier: MIT

package security

import "github.com/otfabric/go-opcua/internal/testutil/conformkit"

// The helpers of the conformance packages, under the names the tests use.
const (
	waitTimeout  = conformkit.WaitTimeout
	fastInterval = conformkit.FastInterval
	serverAppURI = conformkit.ServerAppURI
	clientAppURI = conformkit.ClientAppURI
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
	nextDataChanges    = conformkit.NextDataChanges
	nextEvents         = conformkit.NextEvents
	writeInt32         = conformkit.WriteInt32
	endpointFor        = conformkit.EndpointFor
	pendingValues      = conformkit.PendingValues

	securePolicies   = conformkit.SecurePolicies
	secureModes      = conformkit.SecureModes
	secureServerOpts = conformkit.SecureServerOpts
	secureServer     = conformkit.SecureServer
	secureClientOpts = conformkit.SecureClientOpts
	shortPolicy      = conformkit.ShortPolicy
	userValidator    = conformkit.UserValidator

	fastReverseRetry = conformkit.FastReverseRetry
	reverseListener  = conformkit.ReverseListener
)

type stateRecorder = conformkit.StateRecorder
