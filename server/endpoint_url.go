// SPDX-License-Identifier: MIT

package server

import (
	"slices"
	"strings"

	"github.com/otfabric/go-opcua/ua"
)

// endpointsForURL returns the endpoints whose URL is requestURL, compared as
// endpointURLKey writes them, or all endpoints when none is (an empty URL
// included). GetEndpoints filters its answer by the endpointUrl of the
// request with it (Part 4 §5.4.4), and CreateSession its serverEndpoints by
// the endpointUrl the client used (§5.6.2). The client verifies the second
// list with the first, so both services answer the same URL with the same
// endpoints. The fallback serves a client that reached the server under a
// name the server does not advertise (a container gateway such as
// host.docker.internal, a NAT, an IP address): it still finds the endpoint
// of its SecureChannel in the list (UA-.NETStandard closes the session with
// Bad_SecurityChecksFailed when it does not).
func endpointsForURL(endpoints []*ua.EndpointDescription, requestURL string) []*ua.EndpointDescription {
	key := endpointURLKey(requestURL)
	matching := make([]*ua.EndpointDescription, 0, len(endpoints))
	for _, ep := range endpoints {
		if endpointURLKey(ep.EndpointURL) == key {
			matching = append(matching, ep)
		}
	}
	if len(matching) == 0 {
		return append(matching, endpoints...)
	}
	return matching
}

// endpointsForProfiles returns the endpoints whose TransportProfileUri is
// one of profileURIs, the "List of Transport Profile that the returned
// Endpoints shall support", or all of them when the list is empty: "All
// Endpoints are returned if the list is empty", and "The Server returns an
// empty list if no Endpoints match the criteria specified by the Client"
// (Part 4 §5.5.4.1, §5.5.4.2). The URIs are compared as they are: the
// Transport Profiles of the server's endpoints carry no query string.
func endpointsForProfiles(endpoints []*ua.EndpointDescription, profileURIs []string) []*ua.EndpointDescription {
	if len(profileURIs) == 0 {
		return endpoints
	}
	matching := make([]*ua.EndpointDescription, 0, len(endpoints))
	for _, ep := range endpoints {
		if slices.Contains(profileURIs, ep.TransportProfileURI) {
			matching = append(matching, ep)
		}
	}
	return matching
}

// endpointURLKey returns u in the form two endpoint URLs are compared in:
// the scheme and the host in lower case (both are case-insensitive, RFC 3986
// §3.1 and §3.2.2), one trailing slash removed, everything else as it is,
// the path included. A u without "://" is only stripped of its trailing
// slash.
func endpointURLKey(u string) string {
	u, _ = strings.CutSuffix(u, "/")
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return u
	}
	authority, path := rest, ""
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	userinfo, host := "", authority
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		userinfo, host = authority[:i+1], authority[i+1:]
	}
	return strings.ToLower(scheme) + "://" + userinfo + strings.ToLower(host) + path
}
