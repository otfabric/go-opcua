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

	// TransportProfileWSSJSON is UA JSON over a WebSocket with the
	// sub-protocol opcua+uajson, without secure conversation (Part 6
	// §7.5.2): opc.wss endpoints.
	TransportProfileWSSJSON = "http://opcfoundation.org/UA-Profile/Transport/wss-uajson"

	// TransportProfileHTTPSJSON is UA JSON over HTTPS (Part 6 §7.4.5):
	// opc.https endpoints.
	TransportProfileHTTPSJSON = "http://opcfoundation.org/UA-Profile/Transport/https-uajson"
)

// IsJSONTransportProfile reports whether a transport profile carries the
// service messages in the JSON encoding: wss-uajson or https-uajson.
func IsJSONTransportProfile(profile string) bool {
	return profile == TransportProfileWSSJSON || profile == TransportProfileHTTPSJSON
}

// TransportProfileScheme returns the URL scheme of the endpoints of a
// transport profile this library implements, "" for any other profile.
func TransportProfileScheme(profile string) string {
	switch profile {
	case TransportProfileUATCP:
		return "opc.tcp"
	case TransportProfileWSS, TransportProfileWSSJSON:
		return "opc.wss"
	case TransportProfileHTTPS, TransportProfileHTTPSJSON:
		return "opc.https"
	}
	return ""
}

// TransportProfileForURL returns the transport profile of this library that
// serves an endpoint URL, by its scheme: opc.tcp, opc.wss, or opc.https (and
// https), with UA Binary. It returns "" for any other URL.
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
