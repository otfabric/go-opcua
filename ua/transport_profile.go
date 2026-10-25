// SPDX-License-Identifier: MIT

package ua

import "strings"

// Transport profiles of client/server endpoints (Part 7), the
// TransportProfileUri of an EndpointDescription.
const (
	// TransportProfileUATCP is UA TCP with UA Secure Conversation and UA
	// Binary: opc.tcp endpoints.
	TransportProfileUATCP = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"

	// TransportProfileWSS is UA Secure Conversation and UA Binary over a
	// WebSocket with the sub-protocol opcua+uacp (Part 6 §7.5): opc.wss
	// endpoints.
	TransportProfileWSS = "http://opcfoundation.org/UA-Profile/Transport/wss-uasc-uabinary"

	// TransportProfileHTTPS is UA Binary over HTTPS (Part 6 §7.4):
	// opc.https endpoints.
	TransportProfileHTTPS = "http://opcfoundation.org/UA-Profile/Transport/https-uabinary"
)

// TransportProfileForURL returns the transport profile of this library that
// serves an endpoint URL, by its scheme: opc.tcp, opc.wss, or opc.https (and
// https). It returns "" for any other URL.
func TransportProfileForURL(endpointURL string) string {
	scheme, _, ok := strings.Cut(endpointURL, "://")
	if !ok {
		return ""
	}
	switch strings.ToLower(scheme) {
	case "opc.tcp":
		return TransportProfileUATCP
	case "opc.wss":
		return TransportProfileWSS
	case "opc.https", "https":
		return TransportProfileHTTPS
	}
	return ""
}
