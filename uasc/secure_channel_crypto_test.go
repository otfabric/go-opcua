// SPDX-License-Identifier: MIT

package uasc

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestSecureChannelCrypto_NoneMode(t *testing.T) {
	sc := &SecureChannel{cfg: &Config{
		SecurityMode:      ua.MessageSecurityModeNone,
		SecurityPolicyURI: ua.SecurityPolicyURINone,
	}}

	sig, alg, err := sc.NewSessionSignature(nil, nil)
	require.NoError(t, err)
	require.Nil(t, sig)
	require.Empty(t, alg)

	require.NoError(t, sc.VerifySessionSignature(nil, nil, nil))

	pass, passAlg, err := sc.EncryptUserPassword("", "secret", nil, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), pass)
	require.Empty(t, passAlg)

	pass, passAlg, err = sc.EncryptUserPassword(ua.SecurityPolicyURINone, "secret", nil, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), pass)
	require.Empty(t, passAlg)

	sig, alg, err = sc.NewUserTokenSignature(ua.SecurityPolicyURINone, nil, nil)
	require.NoError(t, err)
	require.Nil(t, sig)
	require.Empty(t, alg)

	sig, alg, err = sc.NewUserTokenSignature("", nil, nil)
	require.NoError(t, err)
	require.Nil(t, sig)
	require.Empty(t, alg)
}
