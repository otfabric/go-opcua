// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

type captureServerMetrics struct {
	requests []string
}

func (m *captureServerMetrics) OnRequest(service string)             { m.requests = append(m.requests, service) }
func (m *captureServerMetrics) OnResponse(string, time.Duration)     {}
func (m *captureServerMetrics) OnError(string, time.Duration, error) {}

func TestServerMetrics_WithMetrics(t *testing.T) {
	m := &captureServerMetrics{}
	srv, err := New(WithMetrics(m))
	require.NoError(t, err)
	require.NotNil(t, srv)
}

func TestServerServiceName(t *testing.T) {
	require.Equal(t, "Read", serviceName(&ua.ReadRequest{}))
	require.Equal(t, "Browse", serviceName(&ua.BrowseRequest{}))
}
