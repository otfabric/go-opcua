// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransportProfileScheme(t *testing.T) {
	for profile, scheme := range map[string]string{
		TransportProfileUATCP:     "opc.tcp",
		TransportProfileWSS:       "opc.wss",
		TransportProfileWSSJSON:   "opc.wss",
		TransportProfileHTTPS:     "opc.https",
		TransportProfileHTTPSJSON: "opc.https",
		"urn:other":               "",
	} {
		require.Equal(t, scheme, TransportProfileScheme(profile), profile)
		require.Equal(t, profile == TransportProfileWSSJSON || profile == TransportProfileHTTPSJSON, IsJSONTransportProfile(profile), profile)
	}
}
