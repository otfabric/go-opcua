// SPDX-License-Identifier: MIT

package fxcm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// TestEnableResultMapping: an AutomationComponent reports the commit
// failure of an EstablishConnections of EnableCommunicationCmd alone in
// EnableCommunicationResult (Part 81 Table 12 and Table 17: the result of
// the command that failed), Bad_ResourceUnavailable for the first
// persistent endpoint and Bad_NothingToDo for the ones it skipped. The
// failure is an EnableCommunicationError; Bad_ResourceUnavailable is
// definite and Bad_InternalError leaves the outcome unknown (decision
// C3-D13). A fenced component's Method status Bad_InvalidState is a
// definite failure.
func TestEnableResultMapping(t *testing.T) {
	t.Parallel()
	res := func(st ...ua.StatusCode) *uafx.EstablishConnectionsResult {
		r := &uafx.EstablishConnectionsResult{Status: ua.StatusUncertain}
		for _, s := range st {
			r.ConnectionEndpointConfigurationResults = append(r.ConnectionEndpointConfigurationResults, &uafx.ConnectionEndpointConfigurationResult{
				VerificationResult: uafx.FunctionalEntityVerificationMatch, EnableCommunicationResult: s,
			})
		}
		return r
	}

	r := res(ua.StatusBadResourceUnavailable, ua.StatusBadNothingToDo)
	require.NoError(t, inconclusive(r, 2, false, false), "Bad_ResourceUnavailable is definite")
	f, ok := elementFailure(r.ConnectionEndpointConfigurationResults[0])
	require.True(t, ok)
	assert.Equal(t, Failure{FxError: uafx.FxErrorEnableCommunicationError, Status: ua.StatusBadResourceUnavailable}, f)
	f, ok = elementFailure(r.ConnectionEndpointConfigurationResults[1])
	require.True(t, ok)
	assert.Equal(t, Failure{FxError: uafx.FxErrorEnableCommunicationError, Status: ua.StatusBadNothingToDo}, f, "the skipped endpoint")

	r = res(ua.StatusBadInternalError, ua.StatusBadNothingToDo)
	err := inconclusive(r, 2, false, false)
	require.ErrorIs(t, err, errAmbiguous, "Bad_InternalError is an unknown outcome")
	assert.Equal(t, ua.StatusBadInternalError, StatusOf(err))
	assert.Equal(t, uafx.FxErrorEnableCommunicationError, failureOf(err, uafx.FxErrorEnableCommunicationError).FxError)

	// The result of an establish that creates: the commit failure of the
	// first persistent endpoint is in its ConnectionEndpointResult.
	f, ok = elementFailure(&uafx.ConnectionEndpointConfigurationResult{ConnectionEndpointResult: ua.StatusBadResourceUnavailable})
	require.True(t, ok)
	assert.Equal(t, uafx.FxErrorCreateConnectionEndpointError, f.FxError)

	// The Method status of a fenced AutomationComponent.
	assert.False(t, ambiguousStatus(ua.StatusBadInvalidState))
	assert.False(t, ambiguousStatus(ua.StatusBadResourceUnavailable))
}
