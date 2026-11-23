// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uafx"
)

// eccPolicies lists the ECC security policies with the curve of the
// application instance certificates used with them.
var eccPolicies = []struct {
	uri   string
	curve string
}{
	{ua.SecurityPolicyURIECCNistP256, testpki.CurveP256},
	{ua.SecurityPolicyURIECCNistP384, testpki.CurveP384},
}

// fxServer starts a server with the UAFX test address space and the
// endpoints of opts.
func fxServer(t *testing.T, opts ...server.Option) string {
	t.Helper()
	_, url := conformkit.NewServerPrepared(t, func(srv *server.Server) {
		_, err := fxtest.Prepare(srv, false)
		require.NoError(t, err)
	}, opts...)
	return url
}

// inspect connects a client to url with opts and returns its report.
func inspect(t *testing.T, url string, opts ...opcua.Option) *uafx.Report {
	t.Helper()
	c := conformkit.NewClient(t, url, opts...)
	r, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.NoError(t, err)
	return r
}

// checkBaseline checks the parts of the report that the test address space
// fixes, so that a baseline that is itself wrong fails.
func checkBaseline(t *testing.T, r *uafx.Report) {
	t.Helper()
	require.True(t, r.IsFXServer())
	require.False(t, r.Truncated)
	require.Len(t, r.ConnectionManagers, 1)
	names := map[string]bool{}
	for _, ac := range r.AutomationComponents {
		names[ac.BrowseName.Name] = true
	}
	require.Equal(t, map[string]bool{"Controller": true, "Broken": true}, names)
	require.NotEmpty(t, r.Findings)
	for _, ac := range r.AutomationComponents {
		if ac.BrowseName.Name == "Controller" {
			require.NotNil(t, ac.AggregatedHealth)
			require.Len(t, ac.Assets, 1)
			require.Len(t, ac.FunctionalEntities, 1)
			require.NotNil(t, ac.FunctionalEntities[0].AuthorAssignedVersion)
			require.Equal(t, "1.2.3.4", ac.FunctionalEntities[0].AuthorAssignedVersion.String())
		}
	}
}

// TestInspectSecure inspects the server over every RSA and ECC security
// policy in both secure modes, anonymously and as a user, and compares each
// report with that of a None connection.
func TestInspectSecure(t *testing.T) {
	p := conformkit.PKI(t)
	ecc := p.ECC
	opts := conformkit.SecureServerOpts(t,
		server.ApplicationIdentity(ecc.Server[testpki.CurveP256].Cert, ecc.Server[testpki.CurveP256].Key),
		server.ApplicationIdentity(ecc.Server[testpki.CurveP384].Cert, ecc.Server[testpki.CurveP384].Key),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(conformkit.UserValidator),
	)
	for _, pol := range eccPolicies {
		for _, mode := range conformkit.SecureModes {
			opts = append(opts, server.EnableSecurity(pol.uri, mode))
		}
	}
	url := fxServer(t, opts...)
	baseline := inspect(t, url)
	checkBaseline(t, baseline)

	auths := []struct {
		name  string
		token ua.UserTokenType
		opts  []opcua.Option
	}{
		{"Anonymous", ua.UserTokenTypeAnonymous, nil},
		{"Username", ua.UserTokenTypeUserName, []opcua.Option{opcua.AuthUsername("alice", "wonderland")}},
	}
	for _, mode := range conformkit.SecureModes {
		for _, pol := range conformkit.SecurePolicies {
			for _, auth := range auths {
				t.Run(conformkit.ShortPolicy(pol)+"/"+mode.String()+"/"+auth.name, func(t *testing.T) {
					ep := conformkit.EndpointFor(t, url, pol, mode)
					got := inspect(t, url, append(conformkit.SecureClientOpts(t, ep, auth.token), auth.opts...)...)
					require.Equal(t, baseline, got)
				})
			}
		}
		for _, pol := range eccPolicies {
			for _, auth := range auths {
				t.Run(conformkit.ShortPolicy(pol.uri)+"/"+mode.String()+"/"+auth.name, func(t *testing.T) {
					ep := conformkit.EndpointFor(t, url, pol.uri, mode)
					got := inspect(t, url, append([]opcua.Option{
						opcua.SecurityFromEndpoint(ep, auth.token),
						opcua.Certificate(ecc.Client[pol.curve].Cert),
						opcua.PrivateKeySigner(ecc.Client[pol.curve].Key),
						opcua.TrustedCertificates(ecc.Server[testpki.CurveP256].X509, ecc.Server[testpki.CurveP384].X509),
					}, auth.opts...)...)
					require.Equal(t, baseline, got)
				})
			}
		}
	}
}

// TestInspectMultiChunk inspects the server with UACP buffers so small that
// the responses of Browse and Read span several chunks, in plain and in
// encrypted messages.
func TestInspectMultiChunk(t *testing.T) {
	url := fxServer(t, conformkit.SecureServerOpts(t)...)
	baseline := inspect(t, url)
	checkBaseline(t, baseline)

	small := conformkit.AckDialer(&uacp.Acknowledge{
		ReceiveBufSize: 8192, // the minimum of Part 6 §7.1.2.3
		SendBufSize:    8192,
	})
	t.Run("None", func(t *testing.T) {
		require.Equal(t, baseline, inspect(t, url, small))
	})
	t.Run("Basic256Sha256/SignAndEncrypt", func(t *testing.T) {
		ep := conformkit.EndpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
		require.Equal(t, baseline, inspect(t, url, append(conformkit.SecureClientOpts(t, ep, ua.UserTokenTypeAnonymous), small)...))
	})
}

// TestInspectConcurrent inspects the server from many clients at once, and
// from many goroutines on one client.
func TestInspectConcurrent(t *testing.T) {
	url := fxServer(t)
	baseline := inspect(t, url)
	checkBaseline(t, baseline)

	const workers = 8
	shared := conformkit.NewClient(t, url)
	clients := make([]*opcua.Client, workers)
	for i := range clients {
		clients[i] = conformkit.NewClient(t, url)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	reports := make([]*uafx.Report, 2*workers)
	errs := make([]error, 2*workers)
	for i := range workers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			reports[i], errs[i] = uafx.Inspect(ctx, clients[i], uafx.Limits{})
		}()
		go func() {
			defer wg.Done()
			reports[workers+i], errs[workers+i] = uafx.Inspect(ctx, shared, uafx.Limits{})
		}()
	}
	wg.Wait()
	for i := range reports {
		require.NoError(t, errs[i])
		require.Equal(t, baseline, reports[i])
	}
}

// TestInspectSmallOperationLimits inspects a server whose OperationLimits
// allow one node per Read and Browse (Part 5 §6.3.11): Inspect must stay
// within them and read what it reads without them.
func TestInspectSmallOperationLimits(t *testing.T) {
	baseline := inspect(t, fxServer(t))
	url := fxServer(t, server.WithOperationLimits(server.OperationalLimits{
		MaxNodesPerRead:   1,
		MaxNodesPerBrowse: 1,
	}))
	got := inspect(t, url)
	require.Equal(t, baseline, got)
}
