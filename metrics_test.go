// SPDX-License-Identifier: MIT

package opcua

import (
	stderrors "errors"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestClientServiceName(t *testing.T) {
	require.Equal(t, "Read", serviceName(&ua.ReadRequest{}))
	require.Equal(t, "CreateSubscription", serviceName(&ua.CreateSubscriptionRequest{}))
}

func TestInvalidResponseTypeError(t *testing.T) {
	err := &InvalidResponseTypeError{Got: "*ua.ReadResponse", Want: "*ua.WriteResponse"}
	require.Contains(t, err.Error(), "ReadResponse")
	require.True(t, errors.Is(err, errors.ErrInvalidResponseType))
}

func TestNopMetricsDoesNotPanic(t *testing.T) {
	var m nopMetrics
	m.OnRequest("Read")
	m.OnResponse("Read", time.Millisecond)
	m.OnError("Read", time.Millisecond, stderrors.New("x"))
	m.OnTimeout("Read", time.Millisecond)
}

type nopMetrics struct{}

func (nopMetrics) OnRequest(string)                     {}
func (nopMetrics) OnResponse(string, time.Duration)     {}
func (nopMetrics) OnError(string, time.Duration, error) {}
func (nopMetrics) OnTimeout(string, time.Duration)      {}
