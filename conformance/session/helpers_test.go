// SPDX-License-Identifier: MIT

package session

import (
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
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
	setupWith          = conformkit.SetupWith
	newClient          = conformkit.NewClient
	dialClient         = conformkit.DialClient
	awaitValue         = conformkit.AwaitValue
	expectNoDataChange = conformkit.ExpectNoDataChange
	nextEvents         = conformkit.NextEvents
	writeInt32         = conformkit.WriteInt32
	endpointFor        = conformkit.EndpointFor
	pendingValues      = conformkit.PendingValues
	ackDialer          = conformkit.AckDialer
	freeCustomPort     = testport.TCP

	secureServerOpts = conformkit.SecureServerOpts
	secureServer     = conformkit.SecureServer
	secureClientOpts = conformkit.SecureClientOpts
	shortPolicy      = conformkit.ShortPolicy

	fastReverseRetry = conformkit.FastReverseRetry
	reverseListener  = conformkit.ReverseListener
)

type (
	stateRecorder = conformkit.StateRecorder
	logCounter    = conformkit.LogCounter
)
