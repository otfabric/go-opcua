// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

func TestStart_RefusesNoSecurity(t *testing.T) {
	t.Parallel()
	for name, opts := range map[string][]Option{
		"nothing configured":  nil,
		"None without opt-in": {EnableSecurity("None", ua.MessageSecurityModeNone)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s, err := New(append([]Option{EndPoint("127.0.0.1", 0)}, opts...)...)
			require.NoError(t, err)
			require.ErrorIs(t, s.Start(context.Background()), errors.ErrInsecureNotAllowed)
		})
	}
}

func TestCheckMessageSecurity(t *testing.T) {
	t.Parallel()
	key, cert := genTestKeyAndCert(t)
	apply := func(opts ...Option) *serverConfig {
		s, err := New(opts...)
		require.NoError(t, err)
		return s.cfg
	}
	require.NoError(t, apply(InsecureNoSecurity()).checkMessageSecurity())
	require.NoError(t, apply(InsecureNoSecurity(), InsecureNoSecurity()).checkMessageSecurity(), "idempotent")
	require.NoError(t, apply(EnableSecurity("None", ua.MessageSecurityModeNone), InsecureNoSecurity()).checkMessageSecurity())
	require.NoError(t, apply(
		EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		PrivateKey(key), Certificate(cert),
	).checkMessageSecurity())
}
