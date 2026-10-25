// SPDX-License-Identifier: MIT

package gdsserver

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/ua"
)

// rawCall calls a method of the Directory with any arguments and returns
// the status of the call.
func (e *env) rawCall(c *opcua.Client, method uint32, args ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	e.t.Helper()
	res, err := c.Call(context.Background(), &ua.CallMethodRequest{
		ObjectID:       e.gds.node(gdsid.Directory),
		MethodID:       e.gds.node(method),
		InputArguments: args,
	})
	require.NoError(e.t, err)
	return res.OutputArguments, res.StatusCode
}

func TestDirectory_RegisterFindGet(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := ctxT(t)
	admin := e.admin()

	rec := record("urn:test:server", "opc.tcp://host1:4840", "opc.tcp://10.0.0.1:4840")
	rec.ApplicationNames = append(rec.ApplicationNames, ua.NewLocalizedTextWithLocale("Anwendung", "de"))
	rec.ServerCapabilities = []string{"DA", "HD"}
	appID, err := admin.RegisterApplication(ctx, rec)
	require.NoError(t, err)
	require.Equal(t, e.gds.Namespace(), appID.Namespace())
	require.Equal(t, ua.NodeIDTypeGUID, appID.Type())

	_, err = admin.RegisterApplication(ctx, rec)
	require.ErrorIs(t, err, ua.StatusBadEntryExists)

	found, err := e.anonymous().FindApplications(ctx, rec.ApplicationURI)
	require.NoError(t, err)
	require.Len(t, found, 1)
	require.True(t, found[0].ApplicationID.Equal(appID))
	require.Equal(t, rec.DiscoveryURLs, found[0].DiscoveryURLs)
	require.Equal(t, rec.ServerCapabilities, found[0].ServerCapabilities)
	require.Len(t, found[0].ApplicationNames, 2)

	none, err := e.anonymous().FindApplications(ctx, "urn:none")
	require.NoError(t, err)
	require.Empty(t, none)
	_, err = e.anonymous().FindApplications(ctx, " ")
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)

	// GetApplication: authenticated users and administrators.
	got, err := e.pull(dialOpts{user: userPlain}).GetApplication(ctx, appID)
	require.NoError(t, err)
	require.Equal(t, rec.ApplicationURI, got.ApplicationURI)
	_, err = e.anonymous().GetApplication(ctx, appID)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, err = admin.GetApplication(ctx, ua.NewGUIDNodeID(e.gds.Namespace(), "00000000-0000-0000-0000-000000000001"))
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	_, err = admin.GetApplication(ctx, ua.NewNumericNodeID(0, 1))
	require.ErrorIs(t, err, ua.StatusBadNotFound)
}

func TestDirectory_RegisterAuthorization(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := ctxT(t)
	for name, p := range map[string]*gds.PullClient{
		"anonymous": e.anonymous(),
		"user":      e.pull(dialOpts{user: userPlain}),
		"caadmin":   e.caAdmin(),
	} {
		_, err := p.RegisterApplication(ctx, record("urn:test:"+name))
		require.ErrorIs(t, err, ua.StatusBadUserAccessDenied, name)
	}
	// Over a channel without security: refused whoever calls.
	_, err := e.pull(dialOpts{mode: ua.MessageSecurityModeNone, user: userDiscoveryAdmin}).RegisterApplication(ctx, record("urn:test:none"))
	require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)
	// Sign suffices for the directory.
	_, err = e.pull(dialOpts{mode: ua.MessageSecurityModeSign, user: userDiscoveryAdmin}).RegisterApplication(ctx, record("urn:test:sign"))
	require.NoError(t, err)
}

func TestDirectory_Validation(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := ctxT(t)
	admin := e.admin()
	long := strings.Repeat("x", maxStringLen+1)
	for name, mod := range map[string]func(r *gds.ApplicationRecord){
		"relative uri": func(r *gds.ApplicationRecord) { r.ApplicationURI = "server" },
		"long uri":     func(r *gds.ApplicationRecord) { r.ApplicationURI = "urn:" + long },
		"type":         func(r *gds.ApplicationRecord) { r.ApplicationType = 4 },
		"no names":     func(r *gds.ApplicationRecord) { r.ApplicationNames = nil },
		"empty name":   func(r *gds.ApplicationRecord) { r.ApplicationNames[0].Text = " " },
		"long locale": func(r *gds.ApplicationRecord) {
			r.ApplicationNames = append(r.ApplicationNames, ua.NewLocalizedTextWithLocale("x", long))
		},
		"too many names":    func(r *gds.ApplicationRecord) { r.ApplicationNames = make([]*ua.LocalizedText, maxNames+1) },
		"product":           func(r *gds.ApplicationRecord) { r.ProductURI = "" },
		"server no url":     func(r *gds.ApplicationRecord) { r.DiscoveryURLs = nil },
		"only reverse url":  func(r *gds.ApplicationRecord) { r.DiscoveryURLs = []string{"rcp+opc.tcp://h:1"} },
		"bad url":           func(r *gds.ApplicationRecord) { r.DiscoveryURLs = []string{"not a url"} },
		"too many urls":     func(r *gds.ApplicationRecord) { r.DiscoveryURLs = make([]string, maxURLs+1) },
		"empty capability":  func(r *gds.ApplicationRecord) { r.ServerCapabilities = []string{""} },
		"too many capabils": func(r *gds.ApplicationRecord) { r.ServerCapabilities = make([]string, maxCapabilities+1) },
	} {
		r := record("urn:test:" + strings.ReplaceAll(name, " ", "-"))
		mod(r)
		_, err := admin.RegisterApplication(ctx, r)
		require.ErrorIs(t, err, ua.StatusBadInvalidArgument, name)
	}
	// A client needs no discovery URL; a reverse connect URL is fine.
	r := clientRecord()
	r.DiscoveryURLs = []string{"rcp+opc.tcp://client:4840"}
	_, err := admin.RegisterApplication(ctx, r)
	require.NoError(t, err)

	// Arguments of the wrong type, or a record of another type.
	c := e.dial(dialOpts{user: userDiscoveryAdmin})
	_, sc := e.rawCall(c, gdsid.DirectoryRegisterApplication, ua.MustVariant("x"))
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	eo := ua.NewExtensionObject(&ua.Range{Low: 1, High: 2})
	_, sc = e.rawCall(c, gdsid.DirectoryRegisterApplication, ua.MustVariant(eo))
	require.Equal(t, ua.StatusBadDecodingError, sc)
}

func TestDirectory_UpdateUnregister(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll})
	ctx := ctxT(t)
	admin := e.admin()

	appID, err := admin.RegisterApplication(ctx, clientRecord())
	require.NoError(t, err)
	otherID, err := admin.RegisterApplication(ctx, record("urn:test:other"))
	require.NoError(t, err)

	// The application itself (its certificate has the URI) may change its
	// record, but not its URI.
	self := e.anonymous()
	rec, err := self.GetApplication(ctx, appID)
	require.NoError(t, err)
	rec.ApplicationNames = []*ua.LocalizedText{ua.NewLocalizedText("Renamed")}
	require.NoError(t, self.UpdateApplication(ctx, rec))
	got, err := admin.GetApplication(ctx, appID)
	require.NoError(t, err)
	require.Equal(t, "Renamed", got.ApplicationNames[0].Text)

	moved := *rec
	moved.ApplicationURI = "urn:test:moved"
	require.ErrorIs(t, self.UpdateApplication(ctx, &moved), ua.StatusBadUserAccessDenied)

	// Not the other application.
	other, err := admin.GetApplication(ctx, otherID)
	require.NoError(t, err)
	require.ErrorIs(t, self.UpdateApplication(ctx, other), ua.StatusBadUserAccessDenied)
	_, err = self.GetApplication(ctx, otherID)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	require.ErrorIs(t, self.UnregisterApplication(ctx, otherID), ua.StatusBadUserAccessDenied)

	// The administrator may change the URI, not to one that is taken.
	require.NoError(t, admin.UpdateApplication(ctx, &moved))
	moved.ApplicationURI = "urn:test:other"
	require.ErrorIs(t, admin.UpdateApplication(ctx, &moved), ua.StatusBadEntryExists)
	moved.ApplicationURI = ""
	require.ErrorIs(t, admin.UpdateApplication(ctx, &moved), ua.StatusBadInvalidArgument)
	found, err := admin.FindApplications(ctx, testClientURI)
	require.NoError(t, err)
	require.Empty(t, found)

	// Unknown application.
	gone := *other
	gone.ApplicationID = ua.NewGUIDNodeID(e.gds.Namespace(), "00000000-0000-0000-0000-000000000002")
	require.ErrorIs(t, admin.UpdateApplication(ctx, &gone), ua.StatusBadNotFound)
	require.ErrorIs(t, admin.UnregisterApplication(ctx, gone.ApplicationID), ua.StatusBadNotFound)

	require.NoError(t, admin.UnregisterApplication(ctx, otherID))
	_, err = admin.GetApplication(ctx, otherID)
	require.ErrorIs(t, err, ua.StatusBadNotFound)

	// Over a channel without security.
	require.ErrorIs(t, e.pull(dialOpts{mode: ua.MessageSecurityModeNone, user: userDiscoveryAdmin}).UnregisterApplication(ctx, appID), ua.StatusBadSecurityModeInsufficient)
	require.ErrorIs(t, e.pull(dialOpts{mode: ua.MessageSecurityModeNone, user: userDiscoveryAdmin}).UpdateApplication(ctx, rec), ua.StatusBadSecurityModeInsufficient)

	c := e.dial(dialOpts{user: userDiscoveryAdmin})
	_, sc := e.rawCall(c, gdsid.DirectoryUnregisterApplication, ua.MustVariant("x"))
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = e.rawCall(c, gdsid.DirectoryUpdateApplication, ua.MustVariant(ua.NewExtensionObject(&ua.Range{})))
	require.Equal(t, ua.StatusBadDecodingError, sc)
}

const testClientURI = "urn:otfabric:conformance:client"

func TestDirectory_QueryApplications(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := ctxT(t)
	admin := e.admin()

	srv1 := record("urn:test:alpha", "opc.tcp://a:1")
	srv1.ServerCapabilities = []string{"DA"}
	srv2 := record("urn:test:beta", "opc.tcp://b:1")
	srv2.ServerCapabilities = []string{"DA", "HD"}
	cli := record("urn:test:gamma")
	cli.ApplicationType = ua.ApplicationTypeClient
	cli.DiscoveryURLs = nil
	both := record("urn:test:delta", "opc.tcp://d:1")
	both.ApplicationType = ua.ApplicationTypeClientAndServer
	for _, r := range []*gds.ApplicationRecord{srv1, srv2, cli, both} {
		_, err := admin.RegisterApplication(ctx, r)
		require.NoError(t, err)
	}
	anon := e.anonymous()
	uris := func(q *gds.ApplicationQuery) []string {
		t.Helper()
		res, err := anon.QueryApplications(ctx, q)
		require.NoError(t, err)
		require.False(t, res.LastCounterResetTime.IsZero())
		var out []string
		for _, a := range res.Applications {
			out = append(out, a.ApplicationURI)
		}
		return out
	}
	all := []string{"urn:test:alpha", "urn:test:beta", "urn:test:gamma", "urn:test:delta"}
	require.Equal(t, all, uris(nil))
	require.Equal(t, all, uris(&gds.ApplicationQuery{ApplicationType: 3}))
	require.Equal(t, []string{"urn:test:alpha", "urn:test:beta", "urn:test:delta"}, uris(&gds.ApplicationQuery{ApplicationType: 1}))
	require.Equal(t, []string{"urn:test:gamma", "urn:test:delta"}, uris(&gds.ApplicationQuery{ApplicationType: 2}))
	require.Equal(t, []string{"urn:test:beta"}, uris(&gds.ApplicationQuery{ApplicationURI: "%bet_"}))
	require.Equal(t, []string{"urn:test:alpha", "urn:test:beta"}, uris(&gds.ApplicationQuery{ApplicationURI: "urn:test:[a-b]%"}))
	require.Equal(t, []string{"urn:test:gamma"}, uris(&gds.ApplicationQuery{ApplicationName: "App urn:test:g%"}))
	require.Equal(t, all, uris(&gds.ApplicationQuery{ProductURI: "urn:otfabric:product"}))
	require.Empty(t, uris(&gds.ApplicationQuery{ProductURI: "urn:other"}))
	require.Equal(t, []string{"urn:test:beta"}, uris(&gds.ApplicationQuery{ServerCapabilities: []string{"HD", "DA"}}))

	// Paging.
	res, err := anon.QueryApplications(ctx, &gds.ApplicationQuery{MaxRecordsToReturn: 2})
	require.NoError(t, err)
	require.Len(t, res.Applications, 2)
	require.NotZero(t, res.NextRecordID)
	res2, err := anon.QueryApplications(ctx, &gds.ApplicationQuery{StartingRecordID: res.NextRecordID, MaxRecordsToReturn: 2})
	require.NoError(t, err)
	require.Len(t, res2.Applications, 2)
	require.Equal(t, "urn:test:gamma", res2.Applications[0].ApplicationURI)
	require.Zero(t, res2.NextRecordID)

	for name, q := range map[string]*gds.ApplicationQuery{
		"type":       {ApplicationType: 4},
		"pattern":    {ApplicationURI: "urn:[x"},
		"empty list": {ApplicationName: "[]"},
		"NA":         {ServerCapabilities: []string{"NA", "DA"}},
	} {
		_, err := anon.QueryApplications(ctx, q)
		require.ErrorIs(t, err, ua.StatusBadInvalidArgument, name)
	}

	c := e.dial(dialOpts{})
	_, sc := e.rawCall(c, gdsid.DirectoryQueryApplications, ua.MustVariant("x"))
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
}

func TestDirectory_QueryServers(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := ctxT(t)
	admin := e.admin()

	a := record("urn:test:a", "opc.tcp://a:1", "rcp+opc.tcp://a:2", "opc.tcp://a:3")
	a.ServerCapabilities = []string{"LDS"}
	b := record("urn:test:b", "opc.tcp://b:1")
	cli := clientRecord()
	for _, r := range []*gds.ApplicationRecord{a, b, cli} {
		_, err := admin.RegisterApplication(ctx, r)
		require.NoError(t, err)
	}
	anon := e.anonymous()
	urls := func(q *gds.ServerQuery) []string {
		t.Helper()
		res, err := anon.QueryServers(ctx, q)
		require.NoError(t, err)
		var out []string
		for _, s := range res.Servers {
			out = append(out, s.DiscoveryURL)
		}
		return out
	}
	require.Equal(t, []string{"opc.tcp://a:1", "opc.tcp://a:3", "opc.tcp://b:1"}, urls(nil))
	require.Equal(t, []string{"opc.tcp://a:1", "opc.tcp://a:3"}, urls(&gds.ServerQuery{ServerCapabilities: []string{"LDS"}}))
	require.Equal(t, []string{"opc.tcp://b:1"}, urls(&gds.ServerQuery{ApplicationURI: "%:b"}))
	require.Equal(t, []string{"opc.tcp://a:1"}, urls(&gds.ServerQuery{MaxRecordsToReturn: 1}))
	require.Empty(t, urls(&gds.ServerQuery{ApplicationName: "nothing"}))

	res, err := anon.QueryServers(ctx, nil)
	require.NoError(t, err)
	first := res.Servers[0].RecordID
	require.Equal(t, []string{"opc.tcp://a:3", "opc.tcp://b:1"}, urls(&gds.ServerQuery{StartingRecordID: first}))

	// A changed record keeps the record ids of the URLs it keeps.
	recA, err := admin.FindApplications(ctx, "urn:test:a")
	require.NoError(t, err)
	recA[0].DiscoveryURLs = []string{"opc.tcp://a:3", "opc.tcp://a:4"}
	require.NoError(t, admin.UpdateApplication(ctx, recA[0]))
	res2, err := anon.QueryServers(ctx, &gds.ServerQuery{ApplicationURI: "urn:test:a"})
	require.NoError(t, err)
	require.Len(t, res2.Servers, 2)
	require.Equal(t, res.Servers[1].RecordID, res2.Servers[0].RecordID)
	require.Greater(t, res2.Servers[1].RecordID, res.Servers[2].RecordID)

	_, err = anon.QueryServers(ctx, &gds.ServerQuery{ProductURI: "[z"})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	c := e.dial(dialOpts{})
	_, sc := e.rawCall(c, gdsid.DirectoryQueryServers, ua.MustVariant(uint32(0)))
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
}
