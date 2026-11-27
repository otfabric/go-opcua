// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uapolicy"
)

// semanticState is a valid journal: the counters, the set s, the record of
// one endpoint, a run of s with one intent.
func semanticState(t *testing.T) map[string]any {
	t.Helper()
	cfg, err := NewConfig(named("s"))
	require.NoError(t, err)
	conf, fp, err := encodeConf(cfg.conf)
	require.NoError(t, err)
	key := cfg.key
	fe := &qualifiedID{NamespaceURI: "urn:x", ID: "s=fe"}
	addr := ServerAddress{Address: "opc.tcp://x"}
	return map[string]any{
		"counters":       &countersRecord{Generation: 3, RunID: 5},
		setStoreKey(key): &setRecord{Folder: key.Folder, Name: "s", Version: 1, Generation: 2, Fingerprint: fp, Conf: conf},
		epStoreKey(key, addr, fe, "n"): &epStored{Folder: key.Folder, SetName: "s", Connection: "c", Endpoint: 1, Address: addr.Address, Namespaces: []string{"http://opcfoundation.org/UA/", "urn:x"},
			ACNode: &qualifiedID{NamespaceURI: "urn:x", ID: "i=1"}, FunctionalEntity: fe, Name: "n", NodeID: &qualifiedID{NamespaceURI: "urn:x", ID: "i=2"},
			Class: int64(KnownOwned), Run: 4, Version: 1, Generation: 2, Fingerprint: fp},
		runStoreKey(5):     &runRecord{Run: 5, Folder: key.Folder, SetName: "s", Generation: 2, Action: int32(uafx.ActionEstablishConnectionsEnabled), Phase: phaseExecuting},
		callStoreKey(5, 1): &callRecord{Run: 5, Folder: key.Folder, SetName: "s", Kind: callEstablish, Address: addr.Address, Namespaces: []string{"http://opcfoundation.org/UA/", "urn:x"}, Names: []string{"n"}, FunctionalEntities: []*qualifiedID{fe}, EndpointFingerprints: [][]byte{fp}, AbsentBefore: []bool{true}, Preconfigured: []*qualifiedID{{}}, Generation: 2},
	}
}

func encodeState(t *testing.T, recs map[string]any) map[string][]byte {
	t.Helper()
	st := map[string][]byte{}
	for k, v := range recs {
		if b, ok := v.([]byte); ok {
			st[k] = b
			continue
		}
		b, err := encodeRecord(v)
		require.NoError(t, err, k)
		st[k] = b
	}
	return st
}

// TestRecordsSemantic (design §3.2, §6.1): a record that decodes but is
// not valid — against its key, the counters, its kind, or the record it
// belongs to — is failed and retained, and blocks what it could be about:
// its set, every set when it names none, every write when it is the
// counters. A valid journal fails nothing.
func TestRecordsSemantic(t *testing.T) {
	t.Parallel()
	base := semanticState(t)
	l := decodeState(encodeState(t, base))
	require.Empty(t, l.failed)
	require.Len(t, l.sets, 1)
	require.Len(t, l.eps, 1)
	require.Len(t, l.runs, 1)
	require.Len(t, l.calls, 1)

	var setK, epK string
	for k := range base {
		switch {
		case len(k) > 4 && k[:4] == "set/":
			setK = k
		case len(k) > 3 && k[:3] == "ep/":
			epK = k
		}
	}
	edit := func(f func(m map[string]any)) map[string]any {
		st := semanticState(t)
		f(st)
		return st
	}
	for _, tc := range []struct {
		name  string
		state map[string]any
		key   string // the key that fails
		block string // "set", "all", "readonly", "key"
	}{
		{"set under another key", edit(func(m map[string]any) { m["set/00"] = m[setK]; delete(m, setK) }), "set/00", "all-or-key"},
		{"set fingerprint", edit(func(m map[string]any) { m[setK].(*setRecord).Fingerprint = []byte{1} }), setK, "key"},
		{"set Version 0", edit(func(m map[string]any) { m[setK].(*setRecord).Version = 0 }), setK, "key"},
		{"counters below a set", edit(func(m map[string]any) { m[setK].(*setRecord).Generation = 9 }), "counters", "readonly"},
		{"counters missing", edit(func(m map[string]any) { delete(m, "counters") }), "counters", "readonly"},
		{"counters corrupt", edit(func(m map[string]any) { m["counters"] = []byte{1, 2} }), "counters", "readonly"},
		{"endpoint class", edit(func(m map[string]any) { m[epK].(*epStored).Class = 99 }), epK, "set"},
		{"endpoint key", edit(func(m map[string]any) { m[epK].(*epStored).Name = "other" }), epK, "set"},
		{"endpoint run", edit(func(m map[string]any) { m[epK].(*epStored).Run = 0 }), epK, "set"},
		{"endpoint fingerprint", edit(func(m map[string]any) { m[epK].(*epStored).EndpointFingerprint = []byte{1} }), epK, "set"},
		{"endpoint namespace", edit(func(m map[string]any) { m[epK].(*epStored).Namespaces = []string{"urn:y"} }), epK, "set"},
		{"endpoint of no set", edit(func(m map[string]any) { delete(m, setK) }), epK, "set"},
		{"run phase", edit(func(m map[string]any) { m[runStoreKey(5)].(*runRecord).Phase = 9 }), runStoreKey(5), "set"},
		{"run action", edit(func(m map[string]any) { m[runStoreKey(5)].(*runRecord).Action = 77 }), runStoreKey(5), "set"},
		{"run Next of an establish", edit(func(m map[string]any) { m[runStoreKey(5)].(*runRecord).Next = 3 }), runStoreKey(5), "set"},
		{"intent of no run", edit(func(m map[string]any) { delete(m, runStoreKey(5)) }), callStoreKey(5, 1), "set"},
		{"intent lengths", edit(func(m map[string]any) { m[callStoreKey(5, 1)].(*callRecord).AbsentBefore = nil }), callStoreKey(5, 1), "set"},
		{"set change of no set-change run", edit(func(m map[string]any) {
			m[txStoreKey(5)] = &txRecord{Run: 5, Ops: []txOp{{Op: int32(uafx.ElementRemove), Name: "s", Old: 2}}}
		}), txStoreKey(5), "all"},
		{"a key outside the layout", edit(func(m map[string]any) { m["next/1"] = &countersRecord{} }), "next/1", "all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := encodeState(t, tc.state)
			l := decodeState(st)
			require.Contains(t, l.failed, tc.key, "%v", l.failed)

			// The Manager retains it and blocks.
			mem := &fxstore.MemoryStore{}
			// A store with its meta (a write of a Manager), then the
			// journal of the case in place of what that write left.
			m0 := storeManager(t, mem)
			_, err := m0.Add(named("seed"))
			require.NoError(t, err)
			require.NoError(t, m0.Close())
			b := fxstore.Batch{Puts: map[string][]byte{}, Deletes: []string{"cm/" + setStoreKey(KeyOf(named("seed")))}}
			for k, v := range st {
				b.Puts["cm/"+k] = v
			}
			if st["counters"] == nil {
				b.Deletes = append(b.Deletes, "cm/counters")
			}
			require.NoError(t, mem.Apply(context.Background(), b))
			m := storeManager(t, mem)
			ss, _ := m.StoreStatus()
			assert.Contains(t, ss.Failed, tc.key)
			k := KeyOf(named("s"))
			switch tc.block {
			case "readonly":
				assert.NotEmpty(t, ss.ReadOnly)
				_, err := m.Add(named("t"))
				assert.Equal(t, ua.StatusBadInvalidState, StatusOf(err), "%v", err)
			case "all", "all-or-key":
				if tc.block == "all" {
					assert.NotEmpty(t, ss.BlockedAll)
				}
				_, err := m.Add(named("s"))
				assert.Error(t, err)
			case "set", "key":
				if _, ok := m.Status(k); ok && tc.block == "set" {
					st := m.Process(uafx.ActionEstablishConnectionsEnabled, k)
					assert.Equal(t, ua.StatusBadInvalidState, StatusOf(st[0].Err), "%v", st[0].Err)
					s, _ := m.Status(k)
					assert.NotEmpty(t, s.Recovery.Blocked)
				} else {
					_, err := m.Add(named("s"))
					assert.Equal(t, ua.StatusBadInvalidState, StatusOf(err), "the key stays held: %v", err)
				}
			}
			// Nothing is deleted: the record is retained.
			after, err := mem.Load(context.Background())
			require.NoError(t, err)
			if _, ok := st[tc.key]; ok {
				assert.Contains(t, after, "cm/"+tc.key)
			}
		})
	}
}

// TestEndpointKeyNamespaces (§6.1, decision of design §6.5): the store
// key of an endpoint and its qualified NodeIds do not depend on the
// namespace index of a NamespaceArray: the same endpoint on a server whose
// namespaces moved has the same key and resolves to the new index.
func TestEndpointKeyNamespaces(t *testing.T) {
	t.Parallel()
	key := SetKey{Name: "s"}
	addr := ServerAddress{Address: "opc.tcp://x"}
	nsa1 := []string{"http://opcfoundation.org/UA/", "urn:a", "urn:fx"}
	nsa2 := []string{"http://opcfoundation.org/UA/", "urn:fx", "urn:other", "urn:a"}
	fe1, fe2 := ua.NewStringNodeID(2, "fe"), ua.NewStringNodeID(1, "fe")
	q1, q2 := qualify(fe1, nsa1), qualify(fe2, nsa2)
	assert.Equal(t, q1, q2)
	assert.Equal(t, epStoreKey(key, addr, q1, "n"), epStoreKey(key, addr, q2, "n"))
	n, err := unqualify(q1, nsa2)
	require.NoError(t, err)
	assert.True(t, n.Equal(fe2), "%v", n)
	// Another namespace is another key.
	assert.NotEqual(t, epStoreKey(key, addr, q1, "n"), epStoreKey(key, addr, qualify(ua.NewStringNodeID(1, "fe"), nsa1), "n"))
	// Namespace 0, and an index the array does not have.
	assert.Equal(t, &qualifiedID{NamespaceURI: nsa1[0], ID: "i=85"}, qualify(ua.NewNumericNodeID(0, 85), nsa1))
	out := qualify(ua.NewNumericNodeID(9, 1), nsa1)
	assert.Equal(t, "", out.NamespaceURI)
	back, err := unqualify(out, nsa1)
	require.NoError(t, err)
	assert.Equal(t, uint16(9), back.Namespace())
	_, err = unqualify(&qualifiedID{NamespaceURI: "urn:missing", ID: "i=1"}, nsa1)
	assert.ErrorIs(t, err, errRecord)
	assert.Equal(t, "", (*qualifiedID)(nil).String())
}

// TestRecordChecks: each rule of the checks of run records, set changes
// and intents, against the counters (generation 9, run 9).
func TestRecordChecks(t *testing.T) {
	t.Parallel()
	c := countersRecord{Generation: 9, RunID: 9}
	conf, fp, err := encodeConf(named("s"))
	require.NoError(t, err)
	fe := &qualifiedID{NamespaceURI: "urn:x", ID: "s=fe"}
	nsa := []string{"http://opcfoundation.org/UA/", "urn:x"}
	run := func(f func(r *runRecord)) *runRecord {
		r := &runRecord{Run: 3, SetName: "s", Generation: 2, Action: int32(ActionRemoveSet), Phase: phaseExecuting, Next: 4, Endpoints: []string{"ep/x"}}
		f(r)
		return r
	}
	tx := func(f func(r *txRecord)) *txRecord {
		r := &txRecord{Run: 3, Ops: []txOp{
			{Op: int32(uafx.ElementReplace), Name: "s", Version: 1, Old: 2, New: 4, Fingerprint: fp, Conf: conf},
			{Op: int32(uafx.ElementRemove), Name: "t", Old: 3},
		}}
		f(r)
		return r
	}
	est := func(f func(r *callRecord)) *callRecord {
		r := &callRecord{Run: 3, SetName: "s", Kind: callEstablish, Namespaces: nsa, ACNode: &qualifiedID{NamespaceURI: "urn:x", ID: "i=1"},
			Names: []string{"n"}, FunctionalEntities: []*qualifiedID{fe}, EndpointFingerprints: [][]byte{fp}, AbsentBefore: []bool{true}, Preconfigured: []*qualifiedID{{}}}
		f(r)
		return r
	}
	cls := func(f func(r *callRecord)) *callRecord {
		r := &callRecord{Run: 3, SetName: "s", Kind: callClose, Namespaces: nsa, Nodes: []*qualifiedID{{NamespaceURI: "urn:x", ID: "i=2"}}}
		f(r)
		return r
	}
	type checker interface {
		check(k string, c countersRecord) error
	}
	for _, tc := range []struct {
		name string
		k    string
		r    checker
		ok   bool
	}{
		{"run valid", runStoreKey(3), run(func(*runRecord) {}), true},
		{"run key", runStoreKey(4), run(func(*runRecord) {}), false},
		{"run above the counters", runStoreKey(10), run(func(r *runRecord) { r.Run = 10 }), false},
		{"run without a set", runStoreKey(3), run(func(r *runRecord) { r.SetName = "" }), false},
		{"run phase 0", runStoreKey(3), run(func(r *runRecord) { r.Phase = 0 }), false},
		{"run generation", runStoreKey(3), run(func(r *runRecord) { r.Generation = 10 }), false},
		{"run Next", runStoreKey(3), run(func(r *runRecord) { r.Next = 10 }), false},
		{"run endpoint key", runStoreKey(3), run(func(r *runRecord) { r.Endpoints = []string{"set/x"} }), false},
		{"tx valid", txStoreKey(3), tx(func(*txRecord) {}), true},
		{"tx key", txStoreKey(4), tx(func(*txRecord) {}), false},
		{"tx empty", txStoreKey(3), tx(func(r *txRecord) { r.Ops = nil }), false},
		{"tx new 0", txStoreKey(3), tx(func(r *txRecord) { r.Ops[0].New = 0 }), false},
		{"tx fingerprint", txStoreKey(3), tx(func(r *txRecord) { r.Ops[0].Fingerprint = []byte{1} }), false},
		{"tx conf", txStoreKey(3), tx(func(r *txRecord) {
			r.Ops[0].Conf = []byte{1}
			sum := sha256.Sum256(r.Ops[0].Conf)
			r.Ops[0].Fingerprint = sum[:]
		}), false},
		{"tx removal with a generation", txStoreKey(3), tx(func(r *txRecord) { r.Ops[1].New = 5 }), false},
		{"tx op", txStoreKey(3), tx(func(r *txRecord) { r.Ops[1].Op = 8 }), false},
		{"tx name", txStoreKey(3), tx(func(r *txRecord) { r.Ops[1].Name = "" }), false},
		{"tx old", txStoreKey(3), tx(func(r *txRecord) { r.Ops[1].Old = 10 }), false},
		{"establish valid", callStoreKey(3, 1), est(func(*callRecord) {}), true},
		{"close valid", callStoreKey(3, 2), cls(func(*callRecord) {}), true},
		{"call key", "call/3", est(func(*callRecord) {}), false},
		{"call key number", "call/3/0", est(func(*callRecord) {}), false},
		{"call key run", "call/zz/1", est(func(*callRecord) {}), false},
		{"call other run", callStoreKey(4, 1), est(func(*callRecord) {}), false},
		{"call above the counters", callStoreKey(10, 1), est(func(r *callRecord) { r.Run = 10 }), false},
		{"call without a set", callStoreKey(3, 1), est(func(r *callRecord) { r.SetName = "" }), false},
		{"call generation", callStoreKey(3, 1), est(func(r *callRecord) { r.Generation = 10 }), false},
		{"call SecurityMode", callStoreKey(3, 1), est(func(r *callRecord) { r.SecurityMode = 1 << 31 }), false},
		{"establish lengths", callStoreKey(3, 1), est(func(r *callRecord) { r.EndpointFingerprints = nil }), false},
		{"establish namespace", callStoreKey(3, 1), est(func(r *callRecord) { r.FunctionalEntities[0] = &qualifiedID{NamespaceURI: "urn:y", ID: "i=1"} }), false},
		{"establish preconfigured", callStoreKey(3, 1), est(func(r *callRecord) { r.Preconfigured[0] = &qualifiedID{NamespaceURI: "urn:y", ID: "i=1"} }), false},
		{"establish AC", callStoreKey(3, 1), est(func(r *callRecord) { r.ACNode = &qualifiedID{NamespaceURI: "urn:y", ID: "i=1"} }), false},
		{"close without nodes", callStoreKey(3, 1), cls(func(r *callRecord) { r.Nodes = nil }), false},
		{"close node", callStoreKey(3, 1), cls(func(r *callRecord) { r.Nodes[0].NamespaceURI = "urn:y" }), false},
		{"call kind", callStoreKey(3, 1), cls(func(r *callRecord) { r.Kind = 9 }), false},
	} {
		err := tc.r.check(tc.k, c)
		if tc.ok {
			assert.NoError(t, err, tc.name)
		} else {
			assert.ErrorIs(t, err, errRecord, tc.name)
		}
	}
}

// identified is a Session that reports id.
type identified struct {
	offlineSession
	id ServerIdentity
}

func (s identified) ServerIdentity() ServerIdentity { return s.id }

// serverArray is a Session whose Server.ServerArray is uris.
type serverArray struct {
	offlineSession
	uris []string
}

func (s serverArray) Read(context.Context, *ua.ReadRequest) (*ua.ReadResponse, error) {
	return &ua.ReadResponse{Results: []*ua.DataValue{{Value: ua.MustVariant(s.uris), Status: ua.StatusOK}}}, nil
}

// TestIdentitySources (design §6.5, second C3.2 review): the evidence of
// a server says where its identity comes from: the peer of a secured
// channel (authenticated), what the server reported, or nothing; a
// thumbprint that is not of the channel is never taken for proof.
func TestIdentitySources(t *testing.T) {
	t.Parallel()
	thumb := make([]byte, thumbprintSize)
	secured := ServerAddress{Address: "opc.tcp://x", SecurityMode: ua.MessageSecurityModeSignAndEncrypt}
	insecure := ServerAddress{Address: "opc.tcp://x", SecurityMode: ua.MessageSecurityModeNone}
	for _, tc := range []struct {
		name string
		addr ServerAddress
		sess Session
		want serverEvidence
	}{
		{"authenticated", secured, identified{id: ServerIdentity{ApplicationURI: "urn:s", CertificateThumbprint: thumb, Authenticated: true}},
			serverEvidence{ApplicationURI: "urn:s", Secured: true, Thumbprint: thumb, Source: identityAuthenticated}},
		{"thumbprint not of the channel", secured, identified{id: ServerIdentity{ApplicationURI: "urn:s", CertificateThumbprint: thumb}},
			serverEvidence{ApplicationURI: "urn:s", Secured: true, Thumbprint: thumb, Source: identityReported}},
		{"authenticated over None", insecure, identified{id: ServerIdentity{ApplicationURI: "urn:s", CertificateThumbprint: thumb, Authenticated: true}},
			serverEvidence{ApplicationURI: "urn:s", Thumbprint: thumb, Source: identityReported}},
		{"nothing reported", secured, identified{}, serverEvidence{Secured: true}},
		{"ServerArray", secured, serverArray{uris: []string{"urn:s"}}, serverEvidence{ApplicationURI: "urn:s", Secured: true, Source: identityReported}},
		{"ServerArray empty", insecure, serverArray{}, serverEvidence{}},
		{"Read fails", insecure, offlineSession{}, serverEvidence{}},
	} {
		tg := &target{addr: tc.addr, sess: tc.sess}
		tg.identify(context.Background())
		tg.identify(context.Background()) // once
		assert.Equal(t, tc.want, tg.server, tc.name)
		assert.NoError(t, tg.server.check(), tc.name)
	}
	for _, bad := range []serverEvidence{
		{Source: 3},
		{Source: identityAuthenticated, Thumbprint: thumb},
		{Source: identityAuthenticated, Secured: true, Thumbprint: []byte{1}},
		{ApplicationURI: "urn:s"},
	} {
		assert.ErrorIs(t, bad.check(), errRecord, "%+v", bad)
	}
}

// fakePeer is a peerSource whose channel the test changes, as a reconnect
// does.
type fakePeer struct {
	pc opcua.PeerCertificate
	ok bool
}

func (f *fakePeer) PeerCertificate() (opcua.PeerCertificate, bool) { return f.pc, f.ok }

// TestIdentityOfChannel (final C3.2 review): the identity of a
// ClientDialer session comes from the peer of its active channel, read at
// every call: authenticated only when the client verified the certificate
// bound to the endpoint's ApplicationUri, reported otherwise, and it
// follows a reconnect to another channel.
func TestIdentityOfChannel(t *testing.T) {
	t.Parallel()
	certA, certB := []byte("certificate A"), []byte("certificate B")
	verified := func(cert []byte, uri string) opcua.PeerCertificate {
		return opcua.PeerCertificate{Certificate: cert, SecurityMode: ua.MessageSecurityModeSignAndEncrypt, Verified: true, ApplicationURI: uri}
	}
	for _, tc := range []struct {
		name string
		peer fakePeer
		want ServerIdentity
	}{
		{"no channel", fakePeer{}, ServerIdentity{ApplicationURI: "urn:s"}},
		{"no certificate (None, or Options overrode the endpoint)", fakePeer{ok: true, pc: opcua.PeerCertificate{SecurityMode: ua.MessageSecurityModeNone}},
			ServerIdentity{ApplicationURI: "urn:s"}},
		{"not verified (InsecureSkipVerify)", fakePeer{ok: true, pc: opcua.PeerCertificate{Certificate: certA, SecurityMode: ua.MessageSecurityModeSign}},
			ServerIdentity{ApplicationURI: "urn:s", CertificateThumbprint: uapolicy.Thumbprint(certA)}},
		{"verified without the ApplicationUri binding", fakePeer{ok: true, pc: verified(certA, "")},
			ServerIdentity{ApplicationURI: "urn:s", CertificateThumbprint: uapolicy.Thumbprint(certA)}},
		{"verified for another ApplicationUri", fakePeer{ok: true, pc: verified(certA, "urn:other")},
			ServerIdentity{ApplicationURI: "urn:s", CertificateThumbprint: uapolicy.Thumbprint(certA)}},
		{"authenticated", fakePeer{ok: true, pc: verified(certA, "urn:s")},
			ServerIdentity{ApplicationURI: "urn:s", CertificateThumbprint: uapolicy.Thumbprint(certA), Authenticated: true}},
	} {
		assert.Equal(t, tc.want, identityOf(&tc.peer, "urn:s"), tc.name)
	}

	// A session's identity follows its channel: a reconnect with a renewed
	// certificate, a reconnect in progress.
	peer := &fakePeer{ok: true, pc: verified(certA, "urn:s")}
	s := &clientSession{peer: peer, uri: "urn:s"}
	tg := &target{addr: ServerAddress{Address: "opc.tcp://x", SecurityMode: ua.MessageSecurityModeSignAndEncrypt}, sess: s}
	tg.identify(context.Background())
	assert.Equal(t, identityAuthenticated, tg.server.Source)
	assert.Equal(t, uapolicy.Thumbprint(certA), tg.server.Thumbprint)
	peer.pc = verified(certB, "urn:s")
	now := tg.evidenceNow()
	assert.Equal(t, identityAuthenticated, now.Source)
	assert.Equal(t, uapolicy.Thumbprint(certB), now.Thumbprint, "the renewed certificate")
	assert.Equal(t, uapolicy.Thumbprint(certA), tg.server.Thumbprint, "evidenceNow changes nothing in the target")
	peer.ok = false
	now = tg.evidenceNow()
	assert.Equal(t, identityReported, now.Source, "no channel: not authenticated")
	assert.Nil(t, now.Thumbprint)
	assert.NoError(t, now.check())

	// A target not identified yet, and one of another Session.
	assert.Equal(t, serverEvidence{}, (&target{sess: s}).evidenceNow())
	plain := &target{sess: serverArray{uris: []string{"urn:s"}}}
	plain.identify(context.Background())
	assert.Equal(t, plain.server, plain.evidenceNow())
}

// TestSessionScoped: only reservations and verifications are exempt from
// recovery obligations (second C3.2 review).
func TestSessionScoped(t *testing.T) {
	t.Parallel()
	assert.True(t, sessionScoped(uafx.ReserveCommunicationIDsCmd))
	assert.True(t, sessionScoped(uafx.ReserveCommunicationIDsCmd|uafx.VerifyAssetCmd))
	assert.False(t, sessionScoped(0))
	for _, c := range []uafx.FxCommandMask{uafx.CreateConnectionEndpointCmd, uafx.EstablishControlCmd, uafx.SetConfigurationDataCmd,
		uafx.ReassignControlCmd, uafx.SetCommunicationConfigurationCmd, uafx.EnableCommunicationCmd} {
		assert.False(t, sessionScoped(uafx.ReserveCommunicationIDsCmd|c), "%v", c)
	}
}
