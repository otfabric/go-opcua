// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/sks"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

// The SecurityKeyServer of a set (Part 81 §6.7.3.2, §6.7.3.3, §9.3, E.5):
// a ConnectionManager adds the SecurityGroups of the set to the SKS, the
// AutomationComponents pull their keys from it (OPC 10000-14 §5.4.5.3) and
// the secured Connection carries data; removing the Connections removes the
// SecurityGroups again.

const sksGroup = "SG"

// sksServer is a go-opcua server that is an SKS (OPC 10000-14 §8) for ks,
// with a Basic256Sha256 SignAndEncrypt endpoint and the users "cm" and
// "ac".
type sksServer struct {
	url string
	ks  *security.KeyService
}

func startSKSServer(t *testing.T, ks *security.KeyService) *sksServer {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert), server.PrivateKey(p.ServerKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if (user == "cm" || user == "ac") && pass == "pw" {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
	)
	require.NoError(t, err)
	_, err = srv.EnableSecurityKeyService(ks)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	cleanup.Register(t, func() { _ = srv.Close() })
	return &sksServer{url: fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()), ks: ks}
}

// sksOptions are the client options of the user over SignAndEncrypt.
func sksOptions(t *testing.T, user string) []opcua.Option {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	return []opcua.Option{
		opcua.AutoReconnect(false), opcua.AuthUsername(user, "pw"),
		opcua.Certificate(p.ClientCert), opcua.PrivateKey(p.ClientKey), opcua.TrustedCertificates(p.ServerCertX509),
	}
}

// remoteSKS is the RemoteSKS of the user "cm".
func remoteSKS(t *testing.T) *fxcm.RemoteSKS {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	return &fxcm.RemoteSKS{Dialer: &fxcm.ClientDialer{Options: sksOptions(t, "cm"), Certificate: p.ClientCert, AuthType: ua.UserTokenTypeUserName}}
}

// keyOptions pull the keys of an AutomationComponent as the user "ac".
func keyOptions(t *testing.T) *sks.PullerOptions {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	d := &sks.EndpointDialer{Options: sksOptions(t, "ac"), Certificate: p.ClientCert, AuthType: ua.UserTokenTypeUserName}
	return &sks.PullerOptions{Dial: d.Dial, Source: sks.Config{MinRetry: 20 * time.Millisecond, MaxRetry: 100 * time.Millisecond}}
}

// newKeyAC is an AutomationComponent that pulls its keys as the user "ac".
func newKeyAC(t *testing.T, name string, opts fxserver.ConnectionOptions) *ac {
	t.Helper()
	opts.SecurityKeys = keyOptions(t)
	return newAC(t, name, opts)
}

// group is the SecurityGroup of the sets of the tests.
func group() *ua.SecurityGroupDataType {
	return &ua.SecurityGroupDataType{
		Name: sksGroup, SecurityGroupID: sksGroup, KeyLifetime: 60000,
		SecurityPolicyURI: security.PolicyURIAes128CTR, MaxFutureKeyCount: 2, MaxPastKeyCount: 1,
	}
}

// securedConf is e2eConf with its groups and readers secured with the
// SecurityGroup sksGroup of the SKS at url.
func securedConf(t *testing.T, name string, a, b *ac, url string) *uafx.ConnectionConfigurationSetConf {
	t.Helper()
	conf := e2eConf(t, name, a, b)
	for _, acc := range conf.AutomationComponentConfigurations {
		cfg := acc.CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration).PubSubConfiguration
		wg := cfg.Connections[0].WriterGroups[0]
		wg.SecurityMode, wg.SecurityGroupID = ua.MessageSecurityModeSignAndEncrypt, sksGroup
		rg := cfg.Connections[1].ReaderGroups[0]
		rg.SecurityMode, rg.SecurityGroupID = ua.MessageSecurityModeSignAndEncrypt, sksGroup
		r := rg.DataSetReaders[0]
		r.SecurityMode, r.SecurityGroupID = ua.MessageSecurityModeSignAndEncrypt, sksGroup
	}
	conf.SecurityKeyServer = &uafx.SecurityKeyServerAddressConf{
		Address: url, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, ServerURI: testpki.ServerAppURI,
		SecurityGroups: []*ua.SecurityGroupDataType{group()},
	}
	return conf
}

// flows waits for the data of the Connection of e2eConf both ways.
func flows(t *testing.T, a, b *ac) {
	t.Helper()
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 42.5 }, 20*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return a.value(t, fxtest.ConnSetpoint) == 17.0 }, 20*time.Second, 10*time.Millisecond)
}

func record(url string) fxcm.SecurityGroupRecord {
	return fxcm.SecurityGroupRecord{Address: url, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, ServerURI: testpki.ServerAppURI, SecurityGroupID: sksGroup}
}

// TestSKSE2E: two AutomationComponents, a remote SKS and a
// ConnectionManager. The establish adds the SecurityGroup to the SKS
// (§6.7.3.2), names the SKS in the SecurityKeyServices of the secured
// groups (E.5; OPC 10000-14 §6.2.5.4 Table 40), the AutomationComponents
// pull the keys and the SignAndEncrypt Connection carries data both ways.
// A disable keeps the SecurityGroup; the removal of the Connections
// removes it (§6.7.3.3) and the keys of the AutomationComponents go.
func TestSKSE2E(t *testing.T) {
	t.Parallel()
	s := startSKSServer(t, security.NewKeyService())
	a, b := newKeyAC(t, "a", fxserver.ConnectionOptions{}), newKeyAC(t, "b", fxserver.ConnectionOptions{})
	require.NoError(t, fxtest.SetValue(b.srv, b.id(fxtest.ConnActual), 17.0))
	m := newManager(t, fxcm.Options{SecurityKeyServer: remoteSKS(t)})
	cfg, err := m.Add(securedConf(t, "Secured", a, b, s.url))
	require.NoError(t, err)
	k := cfg.Key()

	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	have, ok := s.ks.SecurityGroup(sksGroup)
	require.True(t, ok, "the SecurityGroup is on the SKS")
	assert.Equal(t, time.Minute, have.KeyLifetime)
	assert.Equal(t, []fxcm.SecurityGroupRecord{record(s.url)}, m.SecurityGroups())
	for _, x := range []*ac{a, b} {
		wg := x.srv.PubSub().Configuration().Connections[0].WriterGroups[0]
		require.Len(t, wg.SecurityKeyServices, 1)
		e := wg.SecurityKeyServices[0]
		assert.Equal(t, testpki.ServerAppURI, e.Server.ApplicationURI)
		assert.Equal(t, []string{s.url}, e.Server.DiscoveryURLs)
		assert.Equal(t, ua.ApplicationTypeServer, e.Server.ApplicationType)
		assert.Empty(t, e.EndpointURL)
		assert.Equal(t, ua.MessageSecurityModeSignAndEncrypt, e.SecurityMode)
		require.Eventually(t, func() bool { return x.srv.PubSub().KeySource(sksGroup) != nil }, 20*time.Second, 10*time.Millisecond)
	}
	flows(t, a, b)

	// Establishing again finds the SecurityGroup (Good_DataIgnored,
	// OPC 10000-14 §8.5.2).
	res = process(t, m, uafx.ActionDisableConnections, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	_, ok = s.ks.SecurityGroup(sksGroup)
	assert.True(t, ok, "a disable keeps it")
	res = process(t, m, uafx.ActionRemoveConnections, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	_, ok = s.ks.SecurityGroup(sksGroup)
	assert.False(t, ok, "removed with the Connections")
	assert.Empty(t, m.SecurityGroups())
	for _, x := range []*ac{a, b} {
		require.Eventually(t, func() bool { return x.srv.PubSub().KeySource(sksGroup) == nil }, 20*time.Second, 10*time.Millisecond)
	}
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	flows(t, a, b)
	require.NoError(t, m.Remove(context.Background(), k))
	_, ok = s.ks.SecurityGroup(sksGroup)
	assert.False(t, ok, "removed with the set")
}

// TestSKSLocalE2E: the SKS is the KeyService of the ConnectionManager's
// process (§9.3: co-located, internal communication), served to the
// AutomationComponents by a server of it. A SecurityGroup the SKS had
// before is not the Manager's: it stays after the removal. A SecurityGroup
// two sets list stays until the second is removed.
func TestSKSLocalE2E(t *testing.T) {
	t.Parallel()
	ks := security.NewKeyService()
	s := startSKSServer(t, ks)
	a, b := newKeyAC(t, "a", fxserver.ConnectionOptions{}), newKeyAC(t, "b", fxserver.ConnectionOptions{})
	c, d := newKeyAC(t, "c", fxserver.ConnectionOptions{}), newKeyAC(t, "d", fxserver.ConnectionOptions{})
	require.NoError(t, fxtest.SetValue(b.srv, b.id(fxtest.ConnActual), 17.0))
	m := newManager(t, fxcm.Options{SecurityKeyServer: &fxcm.LocalSKS{KeyService: ks}})
	one, err := m.Add(securedConf(t, "One", a, b, s.url))
	require.NoError(t, err)
	two, err := m.Add(securedConf(t, "Two", c, d, s.url))
	require.NoError(t, err)

	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, one.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	flows(t, a, b)
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, two.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Len(t, m.SecurityGroups(), 1)
	res = process(t, m, uafx.ActionRemoveConnections, one.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	_, ok := ks.SecurityGroup(sksGroup)
	assert.True(t, ok, "the set Two lists it")
	res = process(t, m, uafx.ActionRemoveConnections, two.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	_, ok = ks.SecurityGroup(sksGroup)
	assert.False(t, ok)

	// A SecurityGroup the SKS has: found, not owned, kept.
	cfg, err := (&fxcm.LocalSKS{KeyService: ks}).AddSecurityGroup(context.Background(), uafx.SecurityKeyServerAddress{}, group())
	require.NoError(t, err)
	require.True(t, cfg)
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, one.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Empty(t, m.SecurityGroups())
	res = process(t, m, uafx.ActionRemoveConnections, one.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	_, ok = ks.SecurityGroup(sksGroup)
	assert.True(t, ok, "not the Manager's")
}

// TestSKSRestartE2E: the SecurityGroups a Manager added are in its Store; a
// restarted Manager removes them with the Connections. An
// AutomationComponent restarted from its store pulls the keys again and
// the restored persistent Connection carries data.
func TestSKSRestartE2E(t *testing.T) {
	t.Parallel()
	s := startSKSServer(t, security.NewKeyService())
	storeB := &fxstore.MemoryStore{}
	a := newKeyAC(t, "a", fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}})
	b := newKeyAC(t, "b", fxserver.ConnectionOptions{Store: storeB})
	require.NoError(t, fxtest.SetValue(b.srv, b.id(fxtest.ConnActual), 17.0))
	mem := &fxstore.MemoryStore{}
	m := newManager(t, fxcm.Options{Store: mem, SecurityKeyServer: remoteSKS(t)})
	conf := securedConf(t, "Durable", a, b, s.url)
	// A restored secured group publishes again under a key it saw coming
	// (docs/uafx.md#persistence, the restart gate): a short KeyLifetime
	// keeps the wait short.
	conf.SecurityKeyServer.SecurityGroups[0].KeyLifetime = 500
	for _, ep := range []*uafx.ConnectionEndpointConfigurationConf{conf.Connections[0].Endpoint1, conf.Connections[0].Endpoint2} {
		ep.IsPersistent = true
	}
	cfg, err := m.Add(conf)
	require.NoError(t, err)
	k := cfg.Key()
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	flows(t, a, b)
	assert.Len(t, storedKeys(t, mem, "sks/"), 1, "the record of the SecurityGroup")

	// The AutomationComponent b restarts: its endpoint is restored, its
	// keys are pulled again, the data flows.
	b.stop()
	require.NoError(t, fxtest.SetValue(a.srv, a.id(fxtest.ConnSetpoint), 0.0))
	b2 := buildAC(t, "b", fxserver.ConnectionOptions{Store: storeB, SecurityKeys: keyOptions(t)}, "", b.port, nil)
	require.NoError(t, fxtest.SetValue(b2.srv, b2.id(fxtest.ConnActual), 17.0))
	require.Eventually(t, func() bool { return b2.srv.PubSub().KeySource(sksGroup) != nil }, 20*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return a.value(t, fxtest.ConnSetpoint) == 17.0 }, 30*time.Second, 10*time.Millisecond)

	// The Manager restarts: it knows the SecurityGroup it added.
	require.NoError(t, m.Close())
	m2 := newManager(t, fxcm.Options{Store: mem, SecurityKeyServer: remoteSKS(t)})
	assert.Equal(t, []fxcm.SecurityGroupRecord{record(s.url)}, m2.SecurityGroups())
	require.Eventually(t, func() bool {
		st, _ := m2.Status(k)
		return slices.Equal([]fxcm.Ownership{fxcm.KnownOwned, fxcm.KnownOwned}, classes(st))
	}, 20*time.Second, 10*time.Millisecond)
	// The secured endpoints are not kept in place (design §6.6): the
	// adoption does not prove SecurityKeyServices, and a WriterGroup with
	// them is not adoptable. The run closes and creates them again, and
	// the data flows.
	res = process(t, m2, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Empty(t, res.Adopted)
	assert.Len(t, res.Created, 2)
	require.NoError(t, fxtest.SetValue(a.srv, a.id(fxtest.ConnSetpoint), 0.0))
	require.Eventually(t, func() bool { return a.value(t, fxtest.ConnSetpoint) == 17.0 }, 30*time.Second, 10*time.Millisecond)
	_, ok := s.ks.SecurityGroup(sksGroup)
	assert.True(t, ok)
	require.NoError(t, m2.Remove(context.Background(), k))
	_, ok = s.ks.SecurityGroup(sksGroup)
	assert.False(t, ok, "removed by the restarted Manager")
	assert.Empty(t, storedKeys(t, mem, "sks/"))
}

// faultySKS is a SecurityKeyServer whose operations fail with err while it
// is set.
type faultySKS struct {
	fxcm.SecurityKeyServer
	mu        sync.Mutex
	addErr    error
	removeErr error
}

func (f *faultySKS) fail(add, remove error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addErr, f.removeErr = add, remove
}

func (f *faultySKS) AddSecurityGroup(ctx context.Context, at uafx.SecurityKeyServerAddress, g *ua.SecurityGroupDataType) (bool, error) {
	f.mu.Lock()
	err := f.addErr
	f.mu.Unlock()
	if err != nil {
		return false, err
	}
	return f.SecurityKeyServer.AddSecurityGroup(ctx, at, g)
}

func (f *faultySKS) RemoveSecurityGroup(ctx context.Context, at uafx.SecurityKeyServerAddress, id string) error {
	f.mu.Lock()
	err := f.removeErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.SecurityKeyServer.RemoveSecurityGroup(ctx, at, id)
}

// TestSKSFailures: the SKS step of a run fails every Connection of the set
// before an AutomationComponent is configured (§10.19 NOTE; §10.25
// ExternalSksConnectionError, ExternalSksProcessingError,
// ConnectionConfigurationSetInvalid); a failed removal keeps the record
// and the next removal makes it.
func TestSKSFailures(t *testing.T) {
	t.Parallel()
	ks := security.NewKeyService()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	f := &faultySKS{SecurityKeyServer: &fxcm.LocalSKS{KeyService: ks}}
	mem := &failing{Store: &fxstore.MemoryStore{}}
	m := newManager(t, fxcm.Options{SecurityKeyServer: f, Store: mem})
	cases := []struct {
		name  string
		edit  func(*uafx.SecurityKeyServerAddressConf)
		fault error
		fx    uafx.FxError
		st    ua.StatusCode
	}{
		{"session", nil, fmt.Errorf("%w: down", fxcm.ErrSKSConnection), uafx.FxErrorExternalSksConnectionError, ua.StatusBadCommunicationError},
		{"refused", nil, ua.StatusBadUserAccessDenied, uafx.FxErrorExternalSksProcessingError, ua.StatusBadUserAccessDenied},
		{"push model", func(c *uafx.SecurityKeyServerAddressConf) { c.UsePushModel = true }, nil, uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadNotSupported},
		{"push targets", func(c *uafx.SecurityKeyServerAddressConf) {
			c.SecurityGroups, c.PubSubKeyPushTargets = nil, []*ua.PubSubKeyPushTargetDataType{{ApplicationURI: "urn:t"}}
		}, nil, uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadNotSupported},
		{"role permissions", func(c *uafx.SecurityKeyServerAddressConf) {
			c.SecurityGroups[0].RolePermissions = []*ua.RolePermissionType{{RoleID: ua.NewNumericNodeID(0, 1)}}
		}, nil, uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadNotSupported},
		{"id", func(c *uafx.SecurityKeyServerAddressConf) { c.SecurityGroups[0].SecurityGroupID = "other" }, nil, uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError},
		{"lifetime", func(c *uafx.SecurityKeyServerAddressConf) { c.SecurityGroups[0].KeyLifetime = 0 }, nil, uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError},
		{"no name", func(c *uafx.SecurityKeyServerAddressConf) { c.SecurityGroups[0] = nil }, nil, uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError},
	}
	for i, tc := range cases {
		conf := securedConf(t, fmt.Sprintf("F%d", i), a, b, "opc.tcp://sks.invalid:4840")
		if tc.edit != nil {
			tc.edit(conf.SecurityKeyServer)
		}
		cfg, err := m.Add(conf)
		require.NoError(t, err, tc.name)
		f.fail(tc.fault, nil)
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
		require.Equal(t, fxcm.StateError, res.State, tc.name)
		require.Len(t, res.Failures, 2, tc.name)
		for _, fl := range res.Failures {
			assert.Equal(t, tc.fx, fl.FxError, tc.name)
			assert.Equal(t, tc.st, fl.Status, tc.name)
		}
		assert.Equal(t, tc.fx == uafx.FxErrorExternalSksConnectionError, res.Failures[0].Transient(), tc.name)
		assert.Empty(t, res.Created, tc.name)
		assert.Empty(t, a.endpoints(), tc.name)
		require.NoError(t, m.Remove(context.Background(), cfg.Key()), tc.name)
	}
	f.fail(nil, nil)
	_, ok := ks.SecurityGroup(sksGroup)
	assert.False(t, ok)

	// The record of a SecurityGroup that is not written: RuntimeError.
	cfg, err := m.Add(securedConf(t, "Store", a, b, "opc.tcp://sks.invalid:4840"))
	require.NoError(t, err)
	mem.arm(storetest.FailNotCommitted, putsPrefix("sks/"))
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateError, res.State)
	assert.Equal(t, uafx.FxErrorRuntimeError, res.Failures[0].FxError)
	assert.Empty(t, m.SecurityGroups(), "not recorded")
	require.NoError(t, ks.RemoveSecurityGroup(sksGroup))

	// A removal that fails keeps the record; the next one makes it.
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	require.Len(t, m.SecurityGroups(), 1)
	f.fail(nil, fmt.Errorf("%w: down", fxcm.ErrSKSConnection))
	res = process(t, m, uafx.ActionRemoveConnections, cfg.Key())
	require.Equal(t, fxcm.StateError, res.State)
	require.Len(t, res.Failures, 1)
	assert.Equal(t, uafx.FxErrorExternalSksConnectionError, res.Failures[0].FxError)
	assert.Empty(t, a.endpoints(), "the endpoints are removed")
	assert.Len(t, m.SecurityGroups(), 1)
	f.fail(nil, nil)
	mem.arm(storetest.FailNotCommitted, deletesPrefix("sks/"))
	res = process(t, m, uafx.ActionRemoveConnections, cfg.Key())
	require.Equal(t, fxcm.StateError, res.State, "the delete of the record is not written")
	assert.Equal(t, uafx.FxErrorRuntimeError, res.Failures[0].FxError)
	res = process(t, m, uafx.ActionRemoveConnections, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Empty(t, m.SecurityGroups())
	assert.Empty(t, storedKeys(t, mem, "sks/"))
}

// TestSKSWithoutOption: without Options.SecurityKeyServer the
// SecurityKeyServer of a set is not used, as before.
func TestSKSWithoutOption(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	m := newManager(t, fxcm.Options{})
	cfg, err := m.Add(securedConf(t, "Plain", a, b, "opc.tcp://sks.invalid:4840"))
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Empty(t, a.srv.PubSub().Configuration().Connections[0].WriterGroups[0].SecurityKeyServices)
	assert.Empty(t, m.SecurityGroups())
}

// TestRemoteSKS: AddSecurityGroup of a remote SKS adds, finds (OPC
// 10000-14 §8.5.2: Good_DataIgnored) and refuses SecurityGroups;
// RemoveSecurityGroup removes one, and one that is not there is no error.
func TestRemoteSKS(t *testing.T) {
	t.Parallel()
	s := startSKSServer(t, security.NewKeyService())
	r := remoteSKS(t)
	ctx := context.Background()
	at := uafx.SecurityKeyServerAddress{Address: s.url, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, ServerURI: testpki.ServerAppURI}
	created, err := r.AddSecurityGroup(ctx, at, group())
	require.NoError(t, err)
	assert.True(t, created)
	created, err = r.AddSecurityGroup(ctx, at, group())
	require.NoError(t, err)
	assert.False(t, created, "found")
	other := group()
	other.KeyLifetime = 1000
	_, err = r.AddSecurityGroup(ctx, at, other)
	assert.ErrorIs(t, err, ua.StatusBadNodeIDExists)
	_, err = r.AddSecurityGroup(ctx, at, &ua.SecurityGroupDataType{Name: "x"})
	assert.ErrorIs(t, err, fxcm.ErrConfig)
	require.NoError(t, r.RemoveSecurityGroup(ctx, at, sksGroup))
	_, ok := s.ks.SecurityGroup(sksGroup)
	assert.False(t, ok)
	require.NoError(t, r.RemoveSecurityGroup(ctx, at, sksGroup), "not there")

	down := uafx.SecurityKeyServerAddress{Address: "opc.tcp://127.0.0.1:1"}
	_, err = r.AddSecurityGroup(ctx, down, group())
	assert.ErrorIs(t, err, fxcm.ErrSKSConnection)
	assert.ErrorIs(t, r.RemoveSecurityGroup(ctx, down, sksGroup), fxcm.ErrSKSConnection)
	wrong := at
	wrong.ServerURI = "urn:other"
	_, err = r.AddSecurityGroup(ctx, wrong, group())
	assert.True(t, errors.Is(err, fxcm.ErrSKSConnection) && errors.Is(err, ua.StatusBadServerURIInvalid), "%v", err)
}
