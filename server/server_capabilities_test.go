// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// capabilityOf returns the value of a ServerCapabilities Property.
func capabilityOf(t *testing.T, srv *Server, n uint32) any {
	t.Helper()
	dv := srv.Node(ua.NewNumericNodeID(0, n)).Value()
	require.NotNil(t, dv, "node %d has a value", n)
	require.Equal(t, ua.StatusOK, dv.Status)
	return dv.Value.Value()
}

// TestServerCapabilitiesMandatory: every Mandatory Property of
// ServerCapabilitiesType has a value of its DataType (Part 5 §6.3.2).
func TestServerCapabilitiesMandatory(t *testing.T) {
	srv, err := New()
	require.NoError(t, err)
	require.Equal(t, []string{}, capabilityOf(t, srv, id.ServerServerCapabilitiesServerProfileArray))
	require.Equal(t, []string{"en"}, capabilityOf(t, srv, id.ServerServerCapabilitiesLocaleIDArray))
	require.Equal(t, float64(0), capabilityOf(t, srv, id.ServerServerCapabilitiesMinSupportedSampleRate))
	require.Equal(t, uint16(defaultMaxBrowseContinuationPoints), capabilityOf(t, srv, id.ServerServerCapabilitiesMaxBrowseContinuationPoints))
	require.Equal(t, uint16(defaultMaxQueryContinuationPoints), capabilityOf(t, srv, id.ServerServerCapabilitiesMaxQueryContinuationPoints))
	require.Equal(t, uint16(0), capabilityOf(t, srv, id.ServerServerCapabilitiesMaxHistoryContinuationPoints))
	require.Equal(t, []*ua.ExtensionObject{}, capabilityOf(t, srv, id.ServerServerCapabilitiesSoftwareCertificates))
}

func TestServerCapabilitiesOptions(t *testing.T) {
	profiles := []string{"http://opcfoundation.org/UA-Profile/Server/MicroEmbeddedDevice2017"}
	locales := []string{"en", "de"}
	srv, err := New(WithServerProfiles(profiles...), WithLocaleIDs(locales...))
	require.NoError(t, err)
	profiles[0], locales[0] = "changed", "changed"
	require.Equal(t, []string{"http://opcfoundation.org/UA-Profile/Server/MicroEmbeddedDevice2017"}, capabilityOf(t, srv, id.ServerServerCapabilitiesServerProfileArray), "the option keeps a copy")
	require.Equal(t, []string{"en", "de"}, capabilityOf(t, srv, id.ServerServerCapabilitiesLocaleIDArray))

	got := capabilityOf(t, srv, id.ServerServerCapabilitiesServerProfileArray).([]string)
	got[0] = "changed"
	require.Equal(t, "http://opcfoundation.org/UA-Profile/Server/MicroEmbeddedDevice2017", capabilityOf(t, srv, id.ServerServerCapabilitiesServerProfileArray).([]string)[0], "each read is a copy")

	none, err := New(WithServerProfiles(), WithLocaleIDs())
	require.NoError(t, err)
	require.Equal(t, []string{}, capabilityOf(t, none, id.ServerServerCapabilitiesServerProfileArray))
	require.Equal(t, []string{"en"}, capabilityOf(t, none, id.ServerServerCapabilitiesLocaleIDArray), "no LocaleIds is the default")
}

// TestServerProfilesDefault: without WithServerProfiles the
// ServerProfileArray is the list the inventory evidences
// (server_profiles_gen.go, docs/profiles.md), never Null; WithServerProfiles
// with no URIs replaces it with the empty array.
func TestServerProfilesDefault(t *testing.T) {
	require.NotNil(t, evidencedServerProfiles)
	srv, err := New()
	require.NoError(t, err)
	require.Equal(t, evidencedServerProfiles, capabilityOf(t, srv, id.ServerServerCapabilitiesServerProfileArray))

	cfg := &serverConfig{}
	require.NoError(t, WithServerProfiles()(cfg))
	require.NotNil(t, cfg.serverProfiles, "no URIs is a list, not the default")
	require.Equal(t, []string{}, cfg.serverProfileArray())
}

// TestBindServerCapabilitiesWithoutNode: a server without one of the
// Properties binds the others.
func TestBindServerCapabilitiesWithoutNode(t *testing.T) {
	s := newTestServer()
	require.Equal(t, ua.StatusGood, s.ns0().DeleteNode(ua.NewNumericNodeID(0, id.ServerServerCapabilitiesServerProfileArray)))
	s.bindServerCapabilities()
	require.Nil(t, s.Node(ua.NewNumericNodeID(0, id.ServerServerCapabilitiesServerProfileArray)))
	require.Equal(t, []string{"en"}, capabilityOf(t, s, id.ServerServerCapabilitiesLocaleIDArray))
}
