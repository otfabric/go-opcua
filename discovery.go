// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	stderrors "errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/internal/stats"
	"github.com/otfabric/go-opcua/ua"
)

// DiscoveryPort is the well-known port of a Local Discovery Server (OPC UA
// Part 6 §7.6).
const DiscoveryPort = 4840

// DiscoveryURL returns the well-known URL of the Local Discovery Server on a
// host: "opc.tcp://<host>:4840". host may be a name or an IP address; a port
// given with it is kept.
func DiscoveryURL(host string) string {
	if strings.Contains(host, "://") {
		return host
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return "opc.tcp://" + host
	}
	return "opc.tcp://" + net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(DiscoveryPort))
}

// FindServersWithFilter calls FindServers with the optional filters of the
// service (Part 4 §5.4.2): localeIDs selects the language of the returned
// application names, serverURIs restricts the result to the named servers.
// Both may be nil.
func (c *Client) FindServersWithFilter(ctx context.Context, localeIDs, serverURIs []string) (*ua.FindServersResponse, error) {
	stats.Client().Add("FindServers", 1)

	req := &ua.FindServersRequest{
		EndpointURL: c.endpointURL,
		LocaleIDs:   localeIDs,
		ServerURIs:  serverURIs,
	}
	return send[ua.FindServersResponse](ctx, c, req)
}

// FindServersOnNetworkWithFilter calls FindServersOnNetwork with the
// parameters of the service (Part 4 §5.4.3). Only records with an id of at
// least startingRecordID are returned, at most maxRecordsToReturn of them (0
// means no limit), and only servers that have all the capabilities in
// capabilityFilter. To page through a large table, call it again with the id
// after the last record returned; if LastCounterResetTime of the response
// has changed, start over.
func (c *Client) FindServersOnNetworkWithFilter(ctx context.Context, startingRecordID, maxRecordsToReturn uint32, capabilityFilter []string) (*ua.FindServersOnNetworkResponse, error) {
	stats.Client().Add("FindServersOnNetwork", 1)

	req := &ua.FindServersOnNetworkRequest{
		StartingRecordID:       startingRecordID,
		MaxRecordsToReturn:     maxRecordsToReturn,
		ServerCapabilityFilter: capabilityFilter,
	}
	return send[ua.FindServersOnNetworkResponse](ctx, c, req)
}

// RegisterServer registers a server with the discovery server the client is
// connected to, renews its registration, or (server.IsOnline false) removes
// it (Part 4 §5.4.5).
//
// The service needs a SecureChannel but no session: call [Client.Dial], not
// [Client.Connect]. A discovery server normally only accepts registrations
// on a secured channel opened with the certificate of the server that is
// being registered.
//
// A registration expires unless it is renewed; Part 4 recommends every 10
// minutes. A go-opcua server does all of this by itself with
// server.WithDiscoveryRegistration.
func (c *Client) RegisterServer(ctx context.Context, server *ua.RegisteredServer) (*ua.RegisterServerResponse, error) {
	stats.Client().Add("RegisterServer", 1)

	return send[ua.RegisterServerResponse](ctx, c, &ua.RegisterServerRequest{Server: server})
}

// RegisterServer2 is RegisterServer with discovery configurations (Part 4
// §5.4.6), typically one *ua.MdnsDiscoveryConfiguration with the mDNS server
// name and the capabilities of the server. The response has one result per
// configuration: BadNotSupported means that the discovery server ignored that
// configuration; the server is registered nevertheless.
//
// A discovery server that predates the service answers with
// BadServiceUnsupported (or BadNotSupported); use [Client.RegisterServer]
// then.
func (c *Client) RegisterServer2(ctx context.Context, server *ua.RegisteredServer, configurations ...any) (*ua.RegisterServer2Response, error) {
	stats.Client().Add("RegisterServer2", 1)

	req := &ua.RegisterServer2Request{Server: server}
	for _, cfg := range configurations {
		if eo, ok := cfg.(*ua.ExtensionObject); ok {
			req.DiscoveryConfiguration = append(req.DiscoveryConfiguration, eo)
			continue
		}
		req.DiscoveryConfiguration = append(req.DiscoveryConfiguration, ua.NewExtensionObject(cfg))
	}
	return send[ua.RegisterServer2Response](ctx, c, req)
}

// DiscoveryResult is what a discovery server knows, as returned by
// [DiscoverServers].
type DiscoveryResult struct {
	// DiscoveryServerURL is the URL that was queried.
	DiscoveryServerURL string
	// Servers are the applications known to the discovery server
	// (FindServers): itself and the servers registered with it.
	Servers []*ua.ApplicationDescription
	// ServersOnNetwork are the servers the discovery server found on the
	// network with mDNS (FindServersOnNetwork). It is nil if the discovery
	// server does not have the multicast extension.
	ServersOnNetwork []*ua.ServerOnNetwork
	// LastCounterResetTime is when the record ids of ServersOnNetwork last
	// started over.
	LastCounterResetTime time.Time
	// MulticastSupported reports whether the discovery server answered
	// FindServersOnNetwork.
	MulticastSupported bool
}

// DiscoverServers asks the Local Discovery Server of a host which servers it
// knows. host is a host name or IP address, to which the well-known discovery
// port 4840 is added (see [DiscoveryURL]), or a complete opc.tcp URL.
//
// It calls FindServers and FindServersOnNetwork. The latter is optional: a
// discovery server without the multicast extension is not an error.
func DiscoverServers(ctx context.Context, host string, opts ...Option) (*DiscoveryResult, error) {
	endpoint := DiscoveryURL(host)
	opts = append(opts, AutoReconnect(false), discoveryNoSecurity())
	c, err := NewClient(endpoint, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Dial(ctx); err != nil {
		return nil, err
	}
	defer func() { _ = c.Close(ctx) }()

	servers, err := c.FindServers(ctx)
	if err != nil {
		return nil, err
	}
	res := &DiscoveryResult{DiscoveryServerURL: endpoint, Servers: servers.Servers}

	onNetwork, err := c.FindServersOnNetwork(ctx)
	switch {
	case err == nil:
		res.MulticastSupported = true
		res.ServersOnNetwork = onNetwork.Servers
		res.LastCounterResetTime = onNetwork.LastCounterResetTime
	case stderrors.Is(err, ua.StatusBadServiceUnsupported),
		stderrors.Is(err, ua.StatusBadNotImplemented),
		stderrors.Is(err, ua.StatusBadNotSupported):
		// no multicast extension
	default:
		return nil, err
	}
	return res, nil
}
