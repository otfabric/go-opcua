// SPDX-License-Identifier: MIT

package uacp

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/otfabric/go-opcua/errors"
)

const defaultPort = "4840"

// ParseEndpoint parses and validates an OPC UA endpoint URL without performing
// DNS resolution. The returned URL has its Host field normalized to host:port
// form. Hostname resolution is deferred to net.Dialer or net.Listen at
// connection time so the standard library can apply its own address selection,
// including IPv4/IPv6 fallback behavior.
//
// Expected format: "opc.tcp://<host[:port]>/path"
func ParseEndpoint(endpoint string) (network string, u *url.URL, err error) {
	u, err = url.Parse(endpoint)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", errors.ErrInvalidEndpoint, err)
	}

	if u.Scheme != "opc.tcp" {
		return "", nil, fmt.Errorf("%w: unsupported scheme %q", errors.ErrInvalidEndpoint, u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return "", nil, fmt.Errorf("%w: missing host", errors.ErrInvalidEndpoint)
	}

	port := u.Port()
	if port == "" {
		port = defaultPort
	} else if err := validatePort(port); err != nil {
		return "", nil, err
	}

	u.Host = net.JoinHostPort(host, port)

	return "tcp", u, nil
}

func validatePort(port string) error {
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("%w: invalid port %q", errors.ErrInvalidEndpoint, port)
	}
	return nil
}
