// SPDX-License-Identifier: MIT

package gds_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

type handler = func(args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)

// fakeServer serves the ServerConfiguration methods with the given
// handlers, which answer what a misbehaving server could.
func fakeServer(t *testing.T, sc map[uint32]handler, tl map[uint32]handler) *opcua.Client {
	t.Helper()
	p := pki(t)
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.InsecureNoSecurity(),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	reg := func(obj uint32, hs map[uint32]handler) {
		for m, h := range hs {
			srv.RegisterMethod(ua.NewNumericNodeID(0, obj), ua.NewNumericNodeID(0, m),
				func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
					return h(args)
				})
		}
	}
	reg(id.ServerConfiguration, sc)
	reg(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList, tl)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	c, err := dial(t, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()), ua.MessageSecurityModeSignAndEncrypt, identity{p.ClientCert, p.ClientKey}, "", "")
	require.NoError(t, err)
	return c
}

func out(vs ...any) handler {
	return func([]*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		res := make([]*ua.Variant, len(vs))
		for i, v := range vs {
			res[i] = ua.MustVariant(v)
		}
		return res, ua.StatusOK
	}
}

func fail(sc ua.StatusCode) handler {
	return func([]*ua.Variant) ([]*ua.Variant, ua.StatusCode) { return nil, sc }
}

const (
	tOpen      = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpen
	tOpenMasks = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenWithMasks
	tRead      = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRead
	tWrite     = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWrite
	tClose     = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListClose
	tCloseUpd  = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListCloseAndUpdate
)

func TestMisbehavingServer(t *testing.T) {
	ctx := context.Background()
	c := fakeServer(t, map[uint32]handler{
		id.ServerConfigurationCreateSigningRequest: out([]byte{}),
		id.ServerConfigurationUpdateCertificate:    out("yes"),
		id.ServerConfigurationGetRejectedList:      out("x"),
		id.ServerConfigurationApplyChanges:         out(),
	}, map[uint32]handler{
		tOpenMasks: out("h"),
		tOpen:      out(uint32(7)),
		tWrite:     fail(ua.StatusBadInvalidState),
		tClose:     out(),
	})
	g := gds.New(c)

	_, err := g.CreateSigningRequest(ctx, &gds.SigningRequest{CertificateGroup: gds.DefaultApplicationGroup})
	require.ErrorContains(t, err, "no certificate request")
	_, err = g.UpdateCertificate(ctx, &gds.CertificateUpdate{CertificateType: gds.RsaSha256ApplicationCertificateType, Certificate: []byte{1}, PrivateKey: []byte{2}})
	require.ErrorContains(t, err, "want a Boolean")
	_, err = g.GetRejectedList(ctx)
	require.ErrorContains(t, err, "want a ByteString array")
	_, err = g.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.ErrorContains(t, err, "want a UInt32")
	_, err = g.WriteTrustList(ctx, &ua.TrustListDataType{SpecifiedLists: 1})
	require.ErrorIs(t, err, ua.StatusBadInvalidState)
	_, err = g.WriteTrustList(ctx, nil)
	require.Error(t, err)
	// A method that is not served.
	err = g.CancelChanges(ctx)
	require.ErrorIs(t, err, ua.StatusBadMethodInvalid)
	var ge *gds.Error
	require.ErrorAs(t, err, &ge)
	require.Contains(t, ge.Error(), "CancelChanges")
	// Fewer outputs than declared.
	c2 := fakeServer(t, map[uint32]handler{id.ServerConfigurationGetRejectedList: out()}, map[uint32]handler{
		tOpenMasks: out(uint32(1)),
		tRead:      fail(ua.StatusBadInvalidArgument),
		tClose:     out(),
		tOpen:      out("h"),
	})
	g2 := gds.New(c2)
	_, err = g2.GetRejectedList(ctx)
	require.ErrorContains(t, err, "output arguments")
	_, err = g2.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = g2.WriteTrustList(ctx, &ua.TrustListDataType{})
	require.ErrorContains(t, err, "want a UInt32")
	_, err = g2.WriteTrustList(ctx, &ua.TrustListDataType{}) // Open itself fails on a second server below
	require.Error(t, err)

	// An empty rejected list, a trust list that is not one, a failing
	// CloseAndUpdate.
	c3 := fakeServer(t, map[uint32]handler{id.ServerConfigurationGetRejectedList: out([][]byte(nil))}, map[uint32]handler{
		tOpenMasks: out(uint32(1)),
		tRead: func() handler {
			n := 0
			return func([]*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
				n++
				if n == 1 {
					return []*ua.Variant{ua.MustVariant([]byte{1, 2, 3})}, ua.StatusOK
				}
				return []*ua.Variant{ua.MustVariant([]byte{})}, ua.StatusOK
			}
		}(),
		tClose:    out(),
		tOpen:     out(uint32(2)),
		tWrite:    out(),
		tCloseUpd: fail(ua.StatusBadCertificateInvalid),
	})
	g3 := gds.New(c3)
	rej, err := g3.GetRejectedList(ctx)
	require.NoError(t, err)
	require.Empty(t, rej)
	_, err = g3.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.Error(t, err)
	_, err = g3.WriteTrustList(ctx, &ua.TrustListDataType{})
	require.ErrorIs(t, err, ua.StatusBadCertificateInvalid)
	c4 := fakeServer(t, nil, map[uint32]handler{tOpen: fail(ua.StatusBadNotWritable), tOpenMasks: fail(ua.StatusBadNotReadable)})
	g4 := gds.New(c4)
	_, err = g4.WriteTrustList(ctx, &ua.TrustListDataType{})
	require.ErrorIs(t, err, ua.StatusBadNotWritable)
	_, err = g4.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.ErrorIs(t, err, ua.StatusBadNotReadable)

	// A closed client: browsing for the method fails, and so does reading.
	require.NoError(t, c4.Close(ctx))
	require.Error(t, gds.New(c4).ApplyChanges(ctx))
	_, err = gds.New(c4).Properties(ctx)
	require.Error(t, err)
	// Without ServerConfiguration properties the values are empty.
	p, err := gds.New(c3).Properties(ctx)
	require.NoError(t, err)
	require.Empty(t, p.SupportedPrivateKeyFormats)
}
