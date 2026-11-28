// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// sksSession is a Session of an SKS whose Method calls answer call.
type sksSession struct {
	Session
	call func(req *ua.CallMethodRequest) (*ua.CallMethodResult, error)
}

func (s *sksSession) Call(_ context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	return s.call(req)
}

func (s *sksSession) Close(context.Context) error { return nil }

type sksDialer struct{ s *sksSession }

func (d sksDialer) Dial(context.Context, ServerAddress) (Session, error) { return d.s, nil }

func testGroup() *ua.SecurityGroupDataType {
	return &ua.SecurityGroupDataType{Name: "g", KeyLifetime: 1000, SecurityPolicyURI: security.PolicyURIAes128CTR, MaxFutureKeyCount: 1}
}

// TestRemoteSKSResults: the results of the Methods of an SKS (OPC 10000-14
// §8.3.3, §8.5.2, §8.5.3) as RemoteSKS takes them.
func TestRemoteSKSResults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	errCall := errors.New("call failed")
	nid := ua.NewNumericNodeID(1, 7)
	found := &ua.CallMethodResult{OutputArguments: []*ua.Variant{ua.MustVariant(nid)}}
	type answer struct {
		res *ua.CallMethodResult
		err error
	}
	run := func(answers ...answer) (*RemoteSKS, *[]*ua.CallMethodRequest) {
		var reqs []*ua.CallMethodRequest
		s := &sksSession{call: func(req *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
			a := answers[len(reqs)]
			reqs = append(reqs, req)
			return a.res, a.err
		}}
		return &RemoteSKS{Dialer: sksDialer{s}}, &reqs
	}

	// AddSecurityGroup: the SecurityGroupId is the Name (§6.2.12.2).
	r, reqs := run(answer{res: &ua.CallMethodResult{}})
	created, err := r.AddSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, testGroup())
	require.NoError(t, err)
	assert.True(t, created)
	req := (*reqs)[0]
	assert.Equal(t, ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroupsAddSecurityGroup), req.MethodID)
	assert.Equal(t, "g", req.InputArguments[0].Value())
	r, _ = run(answer{err: errCall})
	_, err = r.AddSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, testGroup())
	assert.ErrorIs(t, err, errCall)
	r, _ = run(answer{res: &ua.CallMethodResult{StatusCode: ua.StatusBadUserAccessDenied}})
	_, err = r.AddSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, testGroup())
	assert.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	// RemoveSecurityGroup.
	for name, tc := range map[string]struct {
		answers []answer
		want    error
	}{
		"removed":              {[]answer{{res: found}, {res: &ua.CallMethodResult{}}}, nil},
		"removed meanwhile":    {[]answer{{res: found}, {res: &ua.CallMethodResult{StatusCode: ua.StatusBadNodeIDUnknown}}}, nil},
		"not there":            {[]answer{{res: &ua.CallMethodResult{StatusCode: ua.StatusBadNoMatch}}}, nil},
		"not found":            {[]answer{{res: &ua.CallMethodResult{StatusCode: ua.StatusBadNotFound}}}, nil},
		"get fails":            {[]answer{{err: errCall}}, errCall},
		"get refused":          {[]answer{{res: &ua.CallMethodResult{StatusCode: ua.StatusBadUserAccessDenied}}}, ua.StatusBadUserAccessDenied},
		"get without a NodeId": {[]answer{{res: &ua.CallMethodResult{}}}, ua.StatusBadUnexpectedError},
		"remove fails":         {[]answer{{res: found}, {err: errCall}}, errCall},
		"remove refused":       {[]answer{{res: found}, {res: &ua.CallMethodResult{StatusCode: ua.StatusBadUserAccessDenied}}}, ua.StatusBadUserAccessDenied},
	} {
		r, reqs := run(tc.answers...)
		err := r.RemoveSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, "g")
		if tc.want == nil {
			assert.NoError(t, err, name)
		} else {
			assert.ErrorIs(t, err, tc.want, name)
		}
		if name == "removed" {
			assert.Equal(t, nid, (*reqs)[1].InputArguments[0].Value(), name)
		}
	}
}

// TestLocalSKS: AddSecurityGroup of a KeyService adds, finds and refuses
// (OPC 10000-14 §8.5.2); RemoveSecurityGroup of one that is not there is
// no error.
func TestLocalSKS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := &LocalSKS{KeyService: security.NewKeyService()}
	created, err := l.AddSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, testGroup())
	require.NoError(t, err)
	assert.True(t, created)
	created, err = l.AddSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, testGroup())
	require.NoError(t, err)
	assert.False(t, created)
	other := testGroup()
	other.MaxPastKeyCount = 3
	_, err = l.AddSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, other)
	assert.ErrorIs(t, err, ua.StatusBadNodeIDExists)
	_, err = l.AddSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, &ua.SecurityGroupDataType{Name: "x", KeyLifetime: 1, GroupProperties: []*ua.KeyValuePair{{}}})
	assert.ErrorIs(t, err, ErrConfig)
	require.NoError(t, l.RemoveSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, "g"))
	require.NoError(t, l.RemoveSecurityGroup(ctx, uafx.SecurityKeyServerAddress{}, "g"))
}

// TestFillSecurityKeyServices: only the secured groups and readers of a
// SecurityGroup of the set that name no SKS get the SKS of the set (E.5;
// OPC 10000-14 §6.2.5.4 Table 40).
func TestFillSecurityKeyServices(t *testing.T) {
	t.Parallel()
	m := &Manager{opts: Options{SecurityKeyServer: &LocalSKS{}}}
	conf := named("s")
	conf.SecurityKeyServer = &uafx.SecurityKeyServerAddressConf{Address: "opc.tcp://sks", ServerURI: "urn:sks", SecurityGroups: []*ua.SecurityGroupDataType{nil, testGroup()}}
	c := &Config{conf: conf}
	own := []*ua.EndpointDescription{{EndpointURL: "opc.tcp://own"}}
	enc := ua.MessageSecurityModeSignAndEncrypt
	cfg := &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{nil, {
		WriterGroups: []*ua.WriterGroupDataType{nil,
			{SecurityMode: enc, SecurityGroupID: "g"},
			{SecurityMode: ua.MessageSecurityModeNone, SecurityGroupID: "g"},
			{SecurityMode: enc, SecurityGroupID: "other"},
			{SecurityMode: enc, SecurityGroupID: "g", SecurityKeyServices: own},
		},
		ReaderGroups: []*ua.ReaderGroupDataType{nil, {
			SecurityMode: ua.MessageSecurityModeSign, SecurityGroupID: "g",
			DataSetReaders: []*ua.DataSetReaderDataType{nil, {SecurityMode: enc, SecurityGroupID: "g"}},
		}},
	}}}
	m.fillSecurityKeyServices(c, cfg)
	wgs := cfg.Connections[1].WriterGroups
	require.Len(t, wgs[1].SecurityKeyServices, 1)
	assert.Equal(t, "urn:sks", wgs[1].SecurityKeyServices[0].Server.ApplicationURI)
	assert.Empty(t, wgs[2].SecurityKeyServices)
	assert.Empty(t, wgs[3].SecurityKeyServices)
	assert.Equal(t, own, wgs[4].SecurityKeyServices)
	rg := cfg.Connections[1].ReaderGroups[1]
	assert.Len(t, rg.SecurityKeyServices, 1)
	assert.Len(t, rg.DataSetReaders[1].SecurityKeyServices, 1)

	// A co-located SKS without an Address, and the push model: nothing.
	for _, edit := range []func(*uafx.SecurityKeyServerAddressConf){
		func(s *uafx.SecurityKeyServerAddressConf) { s.Address = "" },
		func(s *uafx.SecurityKeyServerAddressConf) { s.UsePushModel = true },
	} {
		edit(conf.SecurityKeyServer)
		cfg := &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{{WriterGroups: []*ua.WriterGroupDataType{{SecurityMode: enc, SecurityGroupID: "g"}}}}}
		m.fillSecurityKeyServices(c, cfg)
		assert.Empty(t, cfg.Connections[0].WriterGroups[0].SecurityKeyServices)
		conf.SecurityKeyServer.Address, conf.SecurityKeyServer.UsePushModel = "opc.tcp://sks", false
	}
}

// TestSKSLists: a set lists a SecurityGroup of its own SKS only.
func TestSKSLists(t *testing.T) {
	t.Parallel()
	conf := named("s")
	conf.SecurityKeyServer = &uafx.SecurityKeyServerAddressConf{Address: "opc.tcp://sks", ServerURI: "urn:sks", SecurityGroups: []*ua.SecurityGroupDataType{testGroup()}}
	c := &Config{conf: conf}
	r := SecurityGroupRecord{Address: "opc.tcp://sks", ServerURI: "urn:sks", SecurityGroupID: "g"}
	assert.True(t, lists(c, r))
	r.Address = "opc.tcp://other"
	assert.False(t, lists(c, r))
	assert.False(t, lists(&Config{conf: named("t")}, r))
}

// TestSKSRecords (design §3.2): a SecurityGroup record that does not
// decode or is not valid is failed and retained; it blocks nothing, and the
// Manager does not take the SecurityGroup as its own.
func TestSKSRecords(t *testing.T) {
	t.Parallel()
	good := &sksRecord{Address: "opc.tcp://sks", ServerURI: "urn:sks", SecurityGroupID: "g"}
	k := sksKey(good.Address, good.ServerURI, good.SecurityGroupID)
	for name, tc := range map[string]struct {
		key string
		v   any
	}{
		"no id":     {sksKey("opc.tcp://sks", "urn:sks", ""), &sksRecord{Address: "opc.tcp://sks", ServerURI: "urn:sks"}},
		"wrong key": {sksKey("opc.tcp://sks", "urn:sks", "h"), good},
		"corrupt":   {k, []byte{1, 2, 3}},
	} {
		st := encodeState(t, map[string]any{"counters": &countersRecord{}, tc.key: tc.v})
		l := decodeState(st)
		assert.Contains(t, l.failed, tc.key, name)
		assert.Empty(t, l.sks, name)

		mem := &fxstore.MemoryStore{}
		// A store with its meta (a write of a Manager), and the record.
		m0 := storeManager(t, mem)
		_, err := m0.Add(named("seed"))
		require.NoError(t, err)
		require.NoError(t, m0.Close())
		b := fxstore.Batch{Puts: map[string][]byte{}, Deletes: []string{"cm/" + setStoreKey(KeyOf(named("seed")))}}
		for k, v := range st {
			if k != "counters" {
				b.Puts["cm/"+k] = v
			}
		}
		require.NoError(t, mem.Apply(context.Background(), b))
		m := storeManager(t, mem)
		ss, _ := m.StoreStatus()
		assert.Contains(t, ss.Failed, tc.key, name)
		assert.Empty(t, ss.BlockedAll, name)
		assert.Empty(t, m.SecurityGroups(), name)
		_, err = m.Add(named("s"))
		assert.NoError(t, err, name)
	}
	l := decodeState(encodeState(t, map[string]any{"counters": &countersRecord{}, k: good}))
	assert.Empty(t, l.failed)
	assert.Equal(t, map[string]SecurityGroupRecord{k: good.group()}, groupsOf(l))
}
