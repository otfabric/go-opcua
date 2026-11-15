// SPDX-License-Identifier: MIT

package opcua

import (
	"bytes"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"weak"

	"github.com/otfabric/go-opcua/ua"
)

// The endpoints a client selects from come from GetEndpoints, over a channel
// without security. CreateSession returns the server's endpoints again, over
// the SecureChannel, and "the Client shall verify this list with the list
// from a DiscoveryEndpoint if it used a DiscoveryEndpoint to fetch the
// EndpointDescriptions" (Part 4 §5.6.2, serverEndpoints): when the lists
// differ, the client closes the session and reports an error.

// discoveredEndpoint is the part of an EndpointDescription the comparison of
// the discovered endpoints with those of CreateSession looks at, copied when
// the client gets the list: later changes to the caller's endpoints do not
// change it.
type discoveredEndpoint struct {
	// server tells whether the endpoint names its application; only then is
	// applicationURI compared.
	server         bool
	applicationURI string
	policy         string
	mode           ua.MessageSecurityMode
	level          uint8
	transport      string
	tokens         []ua.UserTokenPolicy
	certificate    []byte
}

// endpointList is a list of discovered endpoints, see newEndpointList.
type endpointList []discoveredEndpoint

// newEndpointList copies the compared fields of eps. Nil entries are left
// out; a list without endpoints is nil.
func newEndpointList(eps []*ua.EndpointDescription) endpointList {
	var l endpointList
	for _, ep := range eps {
		if ep == nil {
			continue
		}
		l = append(l, newDiscoveredEndpoint(ep))
	}
	return l
}

func newDiscoveredEndpoint(ep *ua.EndpointDescription) discoveredEndpoint {
	d := discoveredEndpoint{
		policy:      ep.SecurityPolicyURI,
		mode:        ep.SecurityMode,
		level:       ep.SecurityLevel,
		transport:   ep.TransportProfileURI,
		certificate: bytes.Clone(ep.ServerCertificate),
	}
	if ep.Server != nil {
		d.server = true
		d.applicationURI = ep.Server.ApplicationURI
	}
	for _, t := range ep.UserIdentityTokens {
		if t != nil {
			d.tokens = append(d.tokens, *t)
		}
	}
	return d
}

// same reports whether a and b are the same endpoint as the comparison sees
// it: the same security policy, security mode, security level, transport
// profile and user token policies (in any order), the same application URI
// when both name their application, and the same certificate, compared as
// bytes, when both carry one. The endpoint URL is not compared: the client
// may have reached the server under another name than the one the server
// uses.
func (a *discoveredEndpoint) same(b *discoveredEndpoint) bool {
	if a.policy != b.policy || a.mode != b.mode || a.level != b.level || a.transport != b.transport {
		return false
	}
	if a.server && b.server && a.applicationURI != b.applicationURI {
		return false
	}
	if len(a.certificate) > 0 && len(b.certificate) > 0 && !bytes.Equal(a.certificate, b.certificate) {
		return false
	}
	return sameTokens(a.tokens, b.tokens) && sameTokens(b.tokens, a.tokens)
}

// sameTokens reports whether a has as many user token policies as b and
// each of them is one of b.
func sameTokens(a, b []ua.UserTokenPolicy) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !slices.ContainsFunc(b, func(t ua.UserTokenPolicy) bool { return sameTokenPolicy(&a[i], &t) }) {
			return false
		}
	}
	return true
}

func (a *discoveredEndpoint) String() string {
	return fmt.Sprintf("%s %s, level %d, %s", a.policy, a.mode, a.level, a.transport)
}

// verifyEndpointList compares the endpoints the client selected from,
// discovered, with the endpoints of the CreateSession response. The lists
// differ when an endpoint of one has no endpoint in the other that is the
// same (see discoveredEndpoint.same); their order does not matter, nor
// does how often an endpoint occurs. Without a discovered list there is
// nothing to compare.
func verifyEndpointList(discovered endpointList, server []*ua.EndpointDescription) error {
	if len(discovered) == 0 {
		return nil
	}
	got := newEndpointList(server)
	if e := firstMissing(discovered, got); e != nil {
		return fmt.Errorf("opcua: the server endpoints of CreateSession do not contain the discovered endpoint %s: %w", e, ua.StatusBadSecurityChecksFailed)
	}
	if e := firstMissing(got, discovered); e != nil {
		return fmt.Errorf("opcua: the server endpoints of CreateSession contain the endpoint %s that discovery did not return: %w", e, ua.StatusBadSecurityChecksFailed)
	}
	return nil
}

// firstMissing returns the first endpoint of a that has no same endpoint in
// b, or nil. The endpoints of b are grouped by the fields that must be equal,
// so that the work grows with the lengths of the lists rather than their
// product.
func firstMissing(a, b endpointList) *discoveredEndpoint {
	type key struct {
		policy, transport string
		mode              ua.MessageSecurityMode
		level             uint8
	}
	groups := make(map[key][]int, len(b))
	for i := range b {
		k := key{b[i].policy, b[i].transport, b[i].mode, b[i].level}
		groups[k] = append(groups[k], i)
	}
	for i := range a {
		found := false
		for _, j := range groups[key{a[i].policy, a[i].transport, a[i].mode, a[i].level}] {
			if a[i].same(&b[j]) {
				found = true
				break
			}
		}
		if !found {
			return &a[i]
		}
	}
	return nil
}

// discovered maps each endpoint a GetEndpoints response brought to the list
// of that response, so that SecurityFromEndpoint finds the list of the
// endpoint it is given. The keys are weak pointers and an entry is removed
// when its endpoint is collected, so the map holds the lists only while the
// caller holds their endpoints.
var discovered = struct {
	mu sync.Mutex
	m  map[weak.Pointer[ua.EndpointDescription]]endpointList
}{m: make(map[weak.Pointer[ua.EndpointDescription]]endpointList)}

// rememberEndpoints records eps, the endpoints of a GetEndpoints response,
// as the list each of them came in.
func rememberEndpoints(eps []*ua.EndpointDescription) {
	l := newEndpointList(eps)
	if l == nil {
		return
	}
	discovered.mu.Lock()
	defer discovered.mu.Unlock()
	for _, ep := range eps {
		if ep == nil {
			continue
		}
		k := weak.Make(ep)
		if _, ok := discovered.m[k]; !ok {
			runtime.AddCleanup(ep, forgetEndpoint, k)
		}
		discovered.m[k] = l
	}
}

// forgetEndpoint removes the entry of an endpoint that has been collected.
func forgetEndpoint(k weak.Pointer[ua.EndpointDescription]) {
	discovered.mu.Lock()
	delete(discovered.m, k)
	discovered.mu.Unlock()
}

// discoveredList returns the list of the GetEndpoints response ep came in,
// or nil if ep did not come from GetEndpoints (a copy of such an endpoint
// did not either).
func discoveredList(ep *ua.EndpointDescription) endpointList {
	if ep == nil {
		return nil
	}
	discovered.mu.Lock()
	defer discovered.mu.Unlock()
	return discovered.m[weak.Make(ep)]
}
