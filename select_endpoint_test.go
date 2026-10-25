// SPDX-License-Identifier: MIT

package opcua_test

import (
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestSelectEndpoint(t *testing.T) {
	p, err := testpki.Get()
	require.NoError(t, err)
	rsaCert := p.ClientCert
	eccCert := p.ECC.Client[testpki.CurveP256].Cert

	ep := func(url, profile, policy string, mode ua.MessageSecurityMode, level uint8) *ua.EndpointDescription {
		return &ua.EndpointDescription{
			EndpointURL: url, TransportProfileURI: profile, SecurityPolicyURI: policy,
			SecurityMode: mode, SecurityLevel: level, ServerCertificate: []byte{1},
		}
	}
	const tcp, wss = "opc.tcp://host:4840", "opc.wss://host:4843"
	endpoints := []*ua.EndpointDescription{
		nil,
		ep(tcp, "", ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0),
		ep(tcp, ua.TransportProfileUATCP, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, 5),
		ep(tcp, ua.TransportProfileUATCP, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 10),
		ep(tcp, ua.TransportProfileUATCP, ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt, 20),
		ep(tcp, ua.TransportProfileUATCP, "http://example.com/UA/SecurityPolicy#Unknown", ua.MessageSecurityModeSignAndEncrypt, 99),
		ep(wss, ua.TransportProfileWSS, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 50),
	}

	_, err = opcua.SelectEndpoint(nil, "", ua.MessageSecurityModeInvalid, nil)
	require.ErrorIs(t, err, errors.ErrNoEndpoints)
	_, err = opcua.SelectEndpointForTransport(nil, ua.TransportProfileWSS, "", ua.MessageSecurityModeInvalid, nil)
	require.ErrorIs(t, err, errors.ErrNoEndpoints)

	// The RSA certificate: the best RSA endpoint of opc.tcp, not the ECC
	// one, the unknown policy or the opc.wss one.
	got, err := opcua.SelectEndpoint(endpoints, "", ua.MessageSecurityModeInvalid, rsaCert)
	require.NoError(t, err)
	require.Equal(t, endpoints[3], got)
	got, err = opcua.SelectEndpoint(endpoints, "Basic256Sha256", ua.MessageSecurityModeSign, rsaCert)
	require.NoError(t, err)
	require.Equal(t, endpoints[2], got)

	// The ECC certificate: the ECC endpoint.
	got, err = opcua.SelectEndpoint(endpoints, "", ua.MessageSecurityModeInvalid, eccCert)
	require.NoError(t, err)
	require.Equal(t, endpoints[4], got)

	// No certificate: SecurityPolicy None only.
	got, err = opcua.SelectEndpoint(endpoints, "", ua.MessageSecurityModeInvalid, nil)
	require.NoError(t, err)
	require.Equal(t, endpoints[1], got)
	_, err = opcua.SelectEndpoint(endpoints, "Basic256Sha256", ua.MessageSecurityModeInvalid, nil)
	require.ErrorIs(t, err, errors.ErrNoMatchingEndpoint)

	// Nothing usable at all.
	_, err = opcua.SelectEndpoint(endpoints[4:6], "", ua.MessageSecurityModeInvalid, rsaCert)
	require.ErrorIs(t, err, errors.ErrNoMatchingEndpoint)

	// Only opc.wss endpoints: SelectEndpoint considers them.
	got, err = opcua.SelectEndpoint(endpoints[6:], "", ua.MessageSecurityModeInvalid, rsaCert)
	require.NoError(t, err)
	require.Equal(t, endpoints[6], got)

	// One transport.
	got, err = opcua.SelectEndpointForTransport(endpoints, ua.TransportProfileWSS, "", ua.MessageSecurityModeInvalid, rsaCert)
	require.NoError(t, err)
	require.Equal(t, endpoints[6], got)
	got, err = opcua.SelectEndpointForTransport(endpoints, ua.TransportProfileUATCP, "", ua.MessageSecurityModeNone, rsaCert)
	require.NoError(t, err)
	require.Equal(t, endpoints[1], got)
	_, err = opcua.SelectEndpointForTransport(endpoints, ua.TransportProfileHTTPS, "", ua.MessageSecurityModeInvalid, rsaCert)
	require.ErrorIs(t, err, errors.ErrNoMatchingEndpoint)

	// Equal security levels: the ranking of the library decides.
	same := []*ua.EndpointDescription{
		ep(tcp, "", ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, 1),
		ep(tcp, "", ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 1),
	}
	got, err = opcua.SelectEndpoint(same, "", ua.MessageSecurityModeInvalid, rsaCert)
	require.NoError(t, err)
	require.Equal(t, same[1], got)
}
