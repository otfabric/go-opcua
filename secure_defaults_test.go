// SPDX-License-Identifier: MIT

package opcua

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

const plainEndpoint = "opc.tcp://example.com:4840"

// A client without message security exists only when it was asked for by
// name, however policy None was reached.
func TestNewClient_RefusesNoSecurity(t *testing.T) {
	t.Parallel()
	none := &ua.EndpointDescription{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
	}
	for name, opts := range map[string][]Option{
		"defaults":      nil,
		"explicit None": {SecurityPolicy("None"), SecurityMode(ua.MessageSecurityModeNone)},
		"None endpoint": {SecurityFromEndpoint(none, ua.UserTokenTypeAnonymous)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := NewClient(plainEndpoint, opts...)
			require.ErrorIs(t, err, errors.ErrInsecureNotAllowed)
		})
	}
}

func TestNewClient_NoSecurityOptIn(t *testing.T) {
	t.Parallel()
	c, err := NewClient(plainEndpoint, InsecureNoSecurity())
	require.NoError(t, err)
	require.Equal(t, ua.SecurityPolicyURINone, c.cfg.sechan.SecurityPolicyURI)
	require.Equal(t, ua.MessageSecurityModeNone, c.cfg.sechan.SecurityMode)
}

// TLS transports use security policy None by definition (Part 6 §7.4, §7.5).
func TestNewClient_TLSTransportsNeedNoOptIn(t *testing.T) {
	t.Parallel()
	for _, ep := range []string{"opc.https://h:443/ua", "https://h/ua", "opc.wss://h:443/ua", "OPC.WSS://h/ua"} {
		_, err := NewClient(ep)
		require.NoError(t, err, ep)
	}
}

// The discovery services are defined without security.
func TestDiscoveryNeedsNoOptIn(t *testing.T) {
	t.Parallel()
	_, err := NewClient(plainEndpoint, discoveryNoSecurity())
	require.NoError(t, err)
}

func TestValidateServerCertificate_NoTrustList(t *testing.T) {
	t.Parallel()
	cfg, err := ApplyConfig()
	require.NoError(t, err)
	der := testCertificate(t, "urn:server")
	err = cfg.validateServerCertificate(der, ua.MessageSecurityModeSign)
	require.ErrorIs(t, err, errors.ErrInvalidCertificate)
	require.ErrorContains(t, err, "TrustedCertificates")

	require.NoError(t, cfg.validateServerCertificate(der, ua.MessageSecurityModeNone))

	skip, err := ApplyConfig(InsecureSkipVerify())
	require.NoError(t, err)
	require.NoError(t, skip.validateServerCertificate(der, ua.MessageSecurityModeSign))
}

func TestValidateServerCertificate_NoCertificate(t *testing.T) {
	t.Parallel()
	cfg, err := ApplyConfig(TrustedCertificates())
	require.NoError(t, err)
	require.ErrorIs(t, cfg.validateServerCertificate(nil, ua.MessageSecurityModeSignAndEncrypt), errors.ErrNoCertificate)
}
