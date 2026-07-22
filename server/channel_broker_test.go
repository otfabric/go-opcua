// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestFaultHeader_GenericError(t *testing.T) {
	hdr := faultHeader(fmt.Errorf("some generic error"))
	require.NotNil(t, hdr)
	require.Equal(t, ua.StatusBadDecodingError, hdr.ServiceResult)
}

func TestFaultHeader_StatusCodeError(t *testing.T) {
	hdr := faultHeader(ua.StatusBadUserAccessDenied)
	require.NotNil(t, hdr)
	require.Equal(t, ua.StatusBadUserAccessDenied, hdr.ServiceResult)
}

func TestNewChannelBroker(t *testing.T) {
	b := newChannelBroker(nil, "opc.tcp://localhost:4840", nil)
	require.NotNil(t, b)
	require.Equal(t, "opc.tcp://localhost:4840", b.endpointURL)
}
