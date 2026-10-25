// SPDX-License-Identifier: MIT

package opcua

import (
	"fmt"
	"sort"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// SelectEndpoint returns the endpoint with the highest security level that
// this client can actually use with its application instance certificate and
// that matches the security policy and mode. policy and mode can be omitted
// ("" and ua.MessageSecurityModeInvalid) so that only one of them, or
// neither, has to match.
//
// The security level is the one the server advertises. Where a server gives
// several usable endpoints the same level (open62541 does, for all its ECC
// policies), the ranking of this library decides: see uapolicy.SecurityLevel.
// The policies with authenticated encryption come first.
//
// It differs from ua.SelectEndpoint, which looks at the security level alone,
// in what it leaves out:
//
//   - endpoints with a security policy this library does not implement,
//   - secured endpoints whose policy does not fit the key of the certificate:
//     a server that offers RSA and ECC endpoints ranks the ECC ones highest,
//     but a client with an RSA certificate cannot use them (and a client with
//     an ECC certificate cannot use the RSA ones),
//   - all secured endpoints if certificate is empty.
//
// certificate is the DER encoded application instance certificate of the
// client, as given to the Certificate option.
//
// A server with opc.wss or opc.https endpoints next to opc.tcp ones returns
// all of them when the URL of the GetEndpoints request matches none exactly.
// SelectEndpoint then keeps to the opc.tcp endpoints, the transport of a
// client that has not asked for another one; with no opc.tcp endpoint in the
// list, every transport is considered. SelectEndpointForTransport selects
// among the endpoints of one transport.
func SelectEndpoint(endpoints []*ua.EndpointDescription, policy string, mode ua.MessageSecurityMode, certificate []byte) (*ua.EndpointDescription, error) {
	if len(endpoints) == 0 {
		return nil, errors.ErrNoEndpoints
	}
	if tcp := endpointsOfTransport(endpoints, ua.TransportProfileUATCP); len(tcp) > 0 {
		endpoints = tcp
	}
	return selectEndpoint(endpoints, policy, mode, certificate)
}

// SelectEndpointForTransport is SelectEndpoint for the endpoints with the
// transport profile transportProfileURI, such as ua.TransportProfileWSS or
// ua.TransportProfileHTTPS. An endpoint without a TransportProfileUri counts
// as opc.tcp.
func SelectEndpointForTransport(endpoints []*ua.EndpointDescription, transportProfileURI, policy string, mode ua.MessageSecurityMode, certificate []byte) (*ua.EndpointDescription, error) {
	if len(endpoints) == 0 {
		return nil, errors.ErrNoEndpoints
	}
	matching := endpointsOfTransport(endpoints, transportProfileURI)
	if len(matching) == 0 {
		return nil, fmt.Errorf("%w: no endpoint with transport profile %s", errors.ErrNoMatchingEndpoint, transportProfileURI)
	}
	return selectEndpoint(matching, policy, mode, certificate)
}

// endpointsOfTransport returns the endpoints with transport profile uri.
func endpointsOfTransport(endpoints []*ua.EndpointDescription, uri string) []*ua.EndpointDescription {
	var out []*ua.EndpointDescription
	for _, ep := range endpoints {
		if ep == nil {
			continue
		}
		profile := ep.TransportProfileURI
		if profile == "" {
			profile = ua.TransportProfileUATCP
		}
		if profile == uri {
			out = append(out, ep)
		}
	}
	return out
}

func selectEndpoint(endpoints []*ua.EndpointDescription, policy string, mode ua.MessageSecurityMode, certificate []byte) (*ua.EndpointDescription, error) {

	supported := make(map[string]bool)
	for _, uri := range uapolicy.SupportedPolicies() {
		supported[uri] = true
	}

	usable := make([]*ua.EndpointDescription, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep == nil || !supported[ep.SecurityPolicyURI] {
			continue
		}
		if ep.SecurityPolicyURI != ua.SecurityPolicyURINone {
			if len(certificate) == 0 || uapolicy.CheckCertificate(ep.SecurityPolicyURI, certificate) != nil {
				continue
			}
		}
		usable = append(usable, ep)
	}
	if len(usable) == 0 {
		return nil, fmt.Errorf("%w: no endpoint this client can use with its certificate (policy=%s mode=%s)",
			errors.ErrNoMatchingEndpoint, ua.FormatSecurityPolicyURI(policy), mode)
	}

	sort.SliceStable(usable, func(i, j int) bool {
		a, b := usable[i], usable[j]
		if a.SecurityLevel != b.SecurityLevel {
			return a.SecurityLevel > b.SecurityLevel
		}
		return uapolicy.SecurityLevel(a.SecurityPolicyURI, a.SecurityMode) > uapolicy.SecurityLevel(b.SecurityPolicyURI, b.SecurityMode)
	})
	policy = ua.FormatSecurityPolicyURI(policy)
	for _, ep := range usable {
		if (policy == "" || ep.SecurityPolicyURI == policy) && (mode == ua.MessageSecurityModeInvalid || ep.SecurityMode == mode) {
			return ep, nil
		}
	}
	return nil, fmt.Errorf("%w: policy=%s mode=%s", errors.ErrNoMatchingEndpoint, policy, mode)
}
