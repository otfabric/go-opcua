// SPDX-License-Identifier: MIT

package uasc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReviseLifetime(t *testing.T) {
	const hour = uint32(time.Hour / time.Millisecond)

	for _, tc := range []struct {
		name      string
		requested uint32
		want      uint32
	}{
		{"client leaves the choice to the server", 0, hour},
		{"shorter than the server maximum is granted", 6000, 6000},
		{"exactly the server maximum", hour, hour},
		{"longer than the server maximum is capped", 2 * hour, hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewCryptoChannel(&Config{Lifetime: hour})
			require.Equal(t, tc.want, s.reviseLifetime(tc.requested))
		})
	}
}

// The configured maximum must survive renewals: handleOpenSecureChannelRequest
// stores the revised lifetime back into the channel config, so the maximum is
// captured once and not derived from the previous (possibly shorter) token.
func TestReviseLifetime_MaximumIsStickyAcrossRenewals(t *testing.T) {
	const hour = uint32(time.Hour / time.Millisecond)
	s := NewCryptoChannel(&Config{Lifetime: hour})

	s.cfg.Lifetime = s.reviseLifetime(5000)
	require.Equal(t, uint32(5000), s.cfg.Lifetime)

	require.Equal(t, uint32(60000), s.reviseLifetime(60000), "a later renewal may ask for more than the previous token had")
	require.Equal(t, hour, s.reviseLifetime(0))
	require.Equal(t, hour, s.reviseLifetime(3*hour))
}

func TestBeginServerRenewal_NotOpenYet(t *testing.T) {
	s := NewCryptoChannel(&Config{})
	s.instances = map[uint32][]*channelInstance{}

	renewing, err := s.beginServerRenewal(&MessageChunk{})
	require.NoError(t, err)
	require.Nil(t, renewing, "the initial Issue request is not a renewal")
}
