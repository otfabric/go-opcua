// SPDX-License-Identifier: MIT

package sks

import (
	"context"
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// ErrEndpoint is in the chain of the error of EndpointDialer.Dial for an
// EndpointDescription that names no SKS to pull keys from: nil, without a
// Server, an ApplicationType other than SERVER (the push model), or
// without a URL (Part 14 §6.2.5.4 Table 40).
var ErrEndpoint = errors.New("pubsub/sks: no SKS to pull keys from")

// EndpointDialer opens a session with the SKS an element of the
// SecurityKeyServices of a PubSubGroup or DataSetReader describes (Part 14
// §6.2.5.4 Table 40): GetEndpoints on its Server.DiscoveryUrls in order,
// the SignAndEncrypt endpoint of its SecurityPolicyUri (the best policy
// both support when it is empty), and a check that the endpoint has the
// ApplicationUri of its Server, the main key of the SKS. Table 40 leaves
// the EndpointUrl empty; one that is set is tried when there are no
// DiscoveryUrls (a tolerance).
type EndpointDialer struct {
	// Options are the options of every client: the certificate, key and
	// trust of the application and the user identity the SKS grants
	// the keys to. The security of the selected endpoint is added.
	Options []opcua.Option
	// Certificate is the DER certificate given in Options, used to
	// select an endpoint whose policy can use it.
	Certificate []byte
	// AuthType is the user token type of the identity in Options.
	// Default Anonymous.
	AuthType ua.UserTokenType
}

// Dial connects to the SKS ep describes. It is a PullerOptions.Dial.
func (d *EndpointDialer) Dial(ctx context.Context, ep *ua.EndpointDescription) (*opcua.Client, error) {
	if ep == nil || ep.Server == nil {
		return nil, fmt.Errorf("%w: no Server", ErrEndpoint)
	}
	if ep.Server.ApplicationType != ua.ApplicationTypeServer {
		return nil, fmt.Errorf("%w: ApplicationType %v", ErrEndpoint, ep.Server.ApplicationType)
	}
	urls := ep.Server.DiscoveryURLs
	if len(urls) == 0 && ep.EndpointURL != "" {
		urls = []string{ep.EndpointURL}
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("%w: no DiscoveryUrls", ErrEndpoint)
	}
	var errs []error
	for _, u := range urls {
		c, err := d.dial(ctx, u, ep)
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (d *EndpointDialer) dial(ctx context.Context, url string, want *ua.EndpointDescription) (*opcua.Client, error) {
	eps, err := opcua.GetEndpoints(ctx, url, d.Options...)
	if err != nil {
		return nil, fmt.Errorf("pubsub/sks: GetEndpoints %s: %w", url, err)
	}
	ep, err := opcua.SelectEndpoint(eps, want.SecurityPolicyURI, ua.MessageSecurityModeSignAndEncrypt, d.Certificate)
	if err != nil {
		return nil, fmt.Errorf("pubsub/sks: %s: no SignAndEncrypt endpoint for %q: %w", url, want.SecurityPolicyURI, err)
	}
	if uri := want.Server.ApplicationURI; uri != "" && (ep.Server == nil || ep.Server.ApplicationURI != uri) {
		return nil, fmt.Errorf("pubsub/sks: %s is not the SKS %q: %w", url, uri, ua.StatusBadServerURIInvalid)
	}
	c, err := opcua.NewClient(ep.EndpointURL, append([]opcua.Option{opcua.SecurityFromEndpoint(ep, d.AuthType)}, d.Options...)...)
	if err != nil {
		return nil, fmt.Errorf("pubsub/sks: client for %s: %w", url, err)
	}
	if err := c.Connect(ctx); err != nil {
		_ = c.Close(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("pubsub/sks: connect %s: %w", url, err)
	}
	return c, nil
}
