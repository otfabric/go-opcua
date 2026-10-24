// SPDX-License-Identifier: MIT

package pubsub

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func diag(t *testing.T, p *PubSub, id ComponentID) Diagnostics {
	t.Helper()
	d, err := p.Diagnostics(id)
	require.NoError(t, err)
	return d
}

func counterOf(t *testing.T, p *PubSub, id ComponentID, c DiagnosticsCounterID) DiagnosticsCounter {
	t.Helper()
	d := diag(t, p, id)
	v, ok := d.Counter(c)
	require.True(t, ok, "component %d has no counter %v", id, c)
	return v
}

func waitCounter(t *testing.T, p *PubSub, id ComponentID, c DiagnosticsCounterID, min uint32) {
	t.Helper()
	require.Eventually(t, func() bool {
		d, err := p.Diagnostics(id)
		if err != nil {
			return false
		}
		v, ok := d.Counter(c)
		return ok && v.Value >= min
	}, 3*time.Second, time.Millisecond, "counter %v of component %d never reached %d", c, id, min)
}

func TestDiagnosticsCounterIDs(t *testing.T) {
	t.Parallel()
	require.Equal(t, "StateError", CounterStateError.String())
	require.Equal(t, "FailedDataSetMessages", CounterFailedDataSetMessages.String())
	require.Equal(t, "DiagnosticsCounterID(200)", DiagnosticsCounterID(200).String())
	require.Equal(t, ua.PubSubDiagnosticsCounterClassificationError, CounterStateError.Classification())
	require.Equal(t, ua.PubSubDiagnosticsCounterClassificationInformation, CounterSentNetworkMessages.Classification())
	require.Equal(t, ua.DiagnosticsLevelAdvanced, CounterDecryptionErrors.Level())
	require.Equal(t, ua.DiagnosticsLevelBasic, CounterFailedTransmissions.Level())

	require.Len(t, DiagnosticsCountersOf(KindPubSub), 6)
	require.Len(t, DiagnosticsCountersOf(KindConnection), 6)
	require.Equal(t, []DiagnosticsCounterID{CounterSentNetworkMessages, CounterFailedTransmissions, CounterEncryptionErrors}, DiagnosticsCountersOf(KindWriterGroup)[6:])
	require.Equal(t, []DiagnosticsCounterID{CounterReceivedNetworkMessages, CounterReceivedInvalidNetworkMessages, CounterDecryptionErrors}, DiagnosticsCountersOf(KindReaderGroup)[6:])
	require.Equal(t, []DiagnosticsCounterID{CounterFailedDataSetMessages}, DiagnosticsCountersOf(KindDataSetWriter)[6:])
	require.Equal(t, []DiagnosticsCounterID{CounterFailedDataSetMessages, CounterDecryptionErrors}, DiagnosticsCountersOf(KindDataSetReader)[6:])
	require.Nil(t, DiagnosticsCountersOf(KindPublishedDataSet))

	var d Diagnostics
	_, ok := d.Counter(CounterStateError)
	require.False(t, ok)
}

func TestDiagnosticsHelpers(t *testing.T) {
	t.Parallel()
	require.Equal(t, uint32(math.MaxUint32), addSat(math.MaxUint32-1, 5))
	require.Equal(t, uint32(7), addSat(3, 4))
	a, b := time.Unix(10, 0), time.Unix(20, 0)
	require.Equal(t, a, earliest(time.Time{}, a))
	require.Equal(t, a, earliest(b, a))
	require.Equal(t, a, earliest(a, b))
	require.Equal(t, a, earliest(a, time.Time{}))

	p, err := New(nil)
	require.NoError(t, err)
	p.lock()
	p.count(&p.root, CounterStateError, math.MaxUint32+10)
	v := p.root.diag.ctr[CounterStateError].v
	p.count(&p.root, CounterStateError, 1)
	v2 := p.root.diag.ctr[CounterStateError].v
	p.count(&p.root, CounterStateError, 0)
	p.unlock()
	require.Equal(t, uint32(math.MaxUint32), v)
	require.Equal(t, uint32(math.MaxUint32), v2, "a counter stops at the largest UInt32")

	require.True(t, isSecurityError(fmt.Errorf("x: %w", uadp.ErrSecurityChecksFailed)))
	require.True(t, isSecurityError(security.ErrNoKeys))
	require.False(t, isSecurityError(uadp.ErrMalformed))

	tok, next := tokenOf(nil)
	require.Zero(t, tok)
	require.Zero(t, next)
	tok, _ = tokenOf(newFakeKeys(4))
	require.Equal(t, uint32(4), tok)
	ring := security.NewKeyRing("sg", security.Aes128CTR())
	key := make([]byte, ring.Policy().KeyLength())
	require.NoError(t, ring.SetKeys(security.PolicyURIAes128CTR, 7, [][]byte{key, key}, time.Hour, time.Hour))
	tok, next = tokenOf(ring)
	require.Equal(t, uint32(7), tok)
	require.Positive(t, next)
	tok, next = tokenOf(ringHolder{ring})
	require.Equal(t, uint32(7), tok)
	require.Positive(t, next)
	_, next = tokenOf(ringHolder{})
	require.Zero(t, next)
}

// ringHolder is a key source that exposes its key ring, as sks.KeySource.
type ringHolder struct{ r *security.KeyRing }

func (h ringHolder) Policy() security.Policy { return nil }
func (h ringHolder) CurrentKeys() (*security.Keys, error) {
	if h.r == nil {
		return nil, security.ErrNoKeys
	}
	return h.r.CurrentKeys()
}
func (h ringHolder) KeysForToken(id uint32) (*security.Keys, error) { return h.r.KeysForToken(id) }
func (h ringHolder) Ring() *security.KeyRing                        { return h.r }

func TestDiagnosticsStateCounters(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	bus.mu.Lock()
	bus.failOpen[url] = 1
	bus.mu.Unlock()
	p := start(t, NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, time.Hour, DataSetWriter("w", 1, "pds")))))
	cid := mustID(t, p, KindConnection, Root, "c")
	wg := mustID(t, p, KindWriterGroup, cid, "wg")
	w := mustID(t, p, KindDataSetWriter, wg, "w")
	waitState(t, p, w, ua.PubSubStateOperational)

	// The runtime: Paused at New, Operational at Start.
	require.Equal(t, uint32(1), counterOf(t, p, Root, CounterStatePausedByParent).Value)
	require.Equal(t, uint32(1), counterOf(t, p, Root, CounterStateOperationalByParent).Value)
	// The connection failed to open once, then recovered.
	c := diag(t, p, cid)
	for id, want := range map[DiagnosticsCounterID]uint32{
		CounterStateError: 1, CounterStateOperationalFromError: 1, CounterStatePausedByParent: 1,
		CounterStateOperationalByParent: 0, CounterStateOperationalByMethod: 0, CounterStateDisabledByMethod: 0,
	} {
		v, _ := c.Counter(id)
		require.Equal(t, want, v.Value, "connection %v %+v", id, c.Counters)
	}
	require.Equal(t, uint32(1), c.TotalError)
	require.Equal(t, uint32(2), c.TotalInformation)
	require.False(t, c.TotalErrorFirstChange.IsZero())
	require.False(t, c.TotalInformationFirstChange.IsZero())
	require.Equal(t, url, c.LiveValues.ResolvedAddress)
	require.True(t, diag(t, p, Root).SubError, "a connection has errors")
	require.Equal(t, uint32(1), counterOf(t, p, wg, CounterStateOperationalByParent).Value)

	// Disable and Enable count as caused by the method; the writer follows
	// its group.
	require.NoError(t, p.Disable(wg))
	require.Equal(t, uint32(1), counterOf(t, p, wg, CounterStateDisabledByMethod).Value)
	// Paused at New and again now.
	require.Equal(t, uint32(2), counterOf(t, p, w, CounterStatePausedByParent).Value)
	require.NoError(t, p.Enable(wg))
	require.Equal(t, uint32(1), counterOf(t, p, wg, CounterStateOperationalByMethod).Value)
	require.Equal(t, uint32(2), counterOf(t, p, w, CounterStateOperationalByParent).Value)

	// A writer enabled while its group is disabled becomes Operational
	// through its parent.
	require.NoError(t, p.Disable(w))
	require.NoError(t, p.Disable(wg))
	require.NoError(t, p.Enable(w))
	require.NoError(t, p.Enable(wg))
	d := diag(t, p, w)
	v, _ := d.Counter(CounterStateOperationalByMethod)
	require.Zero(t, v.Value)
	v, _ = d.Counter(CounterStateOperationalByParent)
	require.Equal(t, uint32(3), v.Value)
	v, _ = d.Counter(CounterStateDisabledByMethod)
	require.Equal(t, uint32(1), v.Value)

	// Reset clears the counters of the object only.
	require.NoError(t, p.ResetDiagnostics(cid))
	c = diag(t, p, cid)
	require.Zero(t, c.TotalError)
	require.Zero(t, c.TotalInformation)
	require.True(t, c.TotalErrorFirstChange.IsZero())
	for _, x := range c.Counters {
		require.Zero(t, x.Value)
		require.True(t, x.TimeFirstChange.IsZero())
	}
	require.False(t, diag(t, p, Root).SubError)
	require.NotZero(t, diag(t, p, wg).TotalInformation)

	// LiveValues of the runtime and the group.
	r := diag(t, p, Root)
	require.Equal(t, uint16(1), r.LiveValues.ConfiguredDataSetWriters)
	require.Equal(t, uint16(1), r.LiveValues.OperationalDataSetWriters)
	g := diag(t, p, wg)
	require.Equal(t, uint16(1), g.LiveValues.ConfiguredDataSetWriters)
	require.Equal(t, uint16(1), g.LiveValues.OperationalDataSetWriters)
	require.Equal(t, KindWriterGroup, g.Kind)

	// Published data sets have no diagnostics, unknown ids none either.
	pds := mustID(t, p, KindPublishedDataSet, Root, "pds")
	_, err := p.Diagnostics(pds)
	require.ErrorIs(t, err, ua.StatusBadNotSupported)
	require.ErrorIs(t, p.ResetDiagnostics(pds), ua.StatusBadNotSupported)
	require.ErrorIs(t, p.SetDiagnosticsLevel(pds, ua.DiagnosticsLevelInfo), ua.StatusBadNotSupported)
	_, err = p.Diagnostics(9999)
	require.ErrorIs(t, err, ua.StatusBadNotFound)

	// Removed components lose their diagnostics.
	require.NoError(t, p.RemoveConnection(cid))
	_, err = p.Diagnostics(w)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	require.Zero(t, diag(t, p, Root).LiveValues.ConfiguredDataSetWriters)
}

func TestDiagnosticsLevel(t *testing.T) {
	t.Parallel()
	p, err := New(nil)
	require.NoError(t, err)
	require.Equal(t, ua.DiagnosticsLevelBasic, diag(t, p, Root).Level)
	require.ErrorIs(t, p.SetDiagnosticsLevel(Root, ua.DiagnosticsLevel(9)), ua.StatusBadOutOfRange)
	require.ErrorIs(t, p.SetDiagnosticsLevel(77, ua.DiagnosticsLevelInfo), ua.StatusBadNotFound)

	q, err := New(nil, WithDiagnosticsLevel(ua.DiagnosticsLevelInfo))
	require.NoError(t, err)
	require.Equal(t, ua.DiagnosticsLevelInfo, diag(t, q, Root).Level)

	cid, err := p.AddConnection(AttachReaderGroups(memConnection("c", memURL(t), nil), ReaderGroup("rg")))
	require.NoError(t, err)
	rg := mustID(t, p, KindReaderGroup, cid, "rg")

	// An inactive counter does not count.
	p.lock()
	p.count(p.comps[rg].b(), CounterDecryptionErrors, 3)
	p.count(p.comps[rg].b(), CounterReceivedNetworkMessages, 2)
	p.unlock()
	c := counterOf(t, p, rg, CounterDecryptionErrors)
	require.False(t, c.Active)
	require.Zero(t, c.Value)
	require.Equal(t, ua.DiagnosticsLevelAdvanced, c.Level)

	// Activated, it counts from 0; deactivated, it keeps its value but
	// does not count in the totals.
	require.NoError(t, p.SetDiagnosticsLevel(rg, ua.DiagnosticsLevelAdvanced))
	p.lock()
	p.count(p.comps[rg].b(), CounterDecryptionErrors, 3)
	p.unlock()
	d := diag(t, p, rg)
	require.Equal(t, ua.DiagnosticsLevelAdvanced, d.Level)
	require.Equal(t, uint32(3), d.TotalError)
	// The two messages and the transition to Paused when it was added.
	require.Equal(t, uint32(3), d.TotalInformation)
	require.True(t, diag(t, p, cid).SubError)
	require.NoError(t, p.SetDiagnosticsLevel(rg, ua.DiagnosticsLevelBasic))
	d = diag(t, p, rg)
	c, _ = d.Counter(CounterDecryptionErrors)
	require.False(t, c.Active)
	require.Equal(t, uint32(3), c.Value)
	require.Zero(t, d.TotalError)
	require.False(t, diag(t, p, cid).SubError)
	require.NoError(t, p.SetDiagnosticsLevel(rg, ua.DiagnosticsLevelDebug))
	c = counterOf(t, p, rg, CounterDecryptionErrors)
	require.True(t, c.Active)
	require.Zero(t, c.Value, "a counter that becomes active starts at 0")
	require.Equal(t, uint32(2), counterOf(t, p, rg, CounterReceivedNetworkMessages).Value)
}

func TestDiagnosticsFailedTransmissions(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	bus.mu.Lock()
	bus.failSend[url] = true
	bus.mu.Unlock()
	p := start(t, NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds")))))
	cid := mustID(t, p, KindConnection, Root, "c")
	wg := mustID(t, p, KindWriterGroup, cid, "wg")
	w := mustID(t, p, KindDataSetWriter, wg, "w")
	waitCounter(t, p, wg, CounterFailedTransmissions, 2)
	waitCounter(t, p, w, CounterFailedDataSetMessages, 2)
	require.True(t, diag(t, p, cid).SubError)
	require.True(t, diag(t, p, wg).SubError)
	require.Positive(t, diag(t, p, w).TotalError)

	bus.mu.Lock()
	bus.failSend[url] = false
	bus.mu.Unlock()
	waitCounter(t, p, wg, CounterSentNetworkMessages, 1)
	require.Eventually(t, func() bool {
		d := diag(t, p, w)
		return d.LiveValues.MessageSequenceNumber > 0
	}, 3*time.Second, time.Millisecond)
	d := diag(t, p, w)
	require.Equal(t, ua.StatusGood, d.LiveValues.StatusCode)
	cfg, err := p.PublishedDataSetConfig(mustID(t, p, KindPublishedDataSet, Root, "pds"))
	require.NoError(t, err)
	require.Equal(t, cfg.DataSetMetaData.ConfigurationVersion.MajorVersion, d.LiveValues.MajorVersion)
	require.Equal(t, cfg.DataSetMetaData.ConfigurationVersion.MinorVersion, d.LiveValues.MinorVersion)
}

// secFailCodec fails to encode secured messages with a security error.
type secFailCodec struct{ fakeCodec }

func (c secFailCodec) Encode(nm *message.NetworkMessage, opts *uadp.EncodeOptions) ([]byte, error) {
	if opts != nil && opts.SecurityMode > ua.MessageSecurityModeNone {
		return nil, fmt.Errorf("%w: sign", uadp.ErrSecurityChecksFailed)
	}
	return c.fakeCodec.Encode(nm, opts)
}

func TestDiagnosticsEncryptionErrors(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	p := start(t, NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachWriterGroups(memConnection("c", url, uint16(1)),
			Secure(WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds")), ua.MessageSecurityModeSign, "sg"))),
		WithKeySource("sg", newFakeKeys(3)), WithDiagnosticsLevel(ua.DiagnosticsLevelInfo),
		func(o *options) { o.codecs = func(e encoding) codec { return secFailCodec{fakeCodec{enc: e}} } })
	wg := mustID(t, p, KindWriterGroup, mustID(t, p, KindConnection, Root, "c"), "wg")
	waitCounter(t, p, wg, CounterEncryptionErrors, 2)
	d := diag(t, p, wg)
	c, _ := d.Counter(CounterFailedTransmissions)
	require.Zero(t, c.Value, "security failures are not counted as failed transmissions")
	require.Equal(t, uint32(3), d.LiveValues.SecurityTokenID)
}

func TestDiagnosticsReceive(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	pdsCfg := testPDS("pds")
	pdsCfg.DataSetMetaData = DataSetMetaDataOf(pdsCfg)
	pdsCfg.DataSetMetaData.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: 5, MinorVersion: 6}
	md := DataSetMetaDataOf(pdsCfg)
	other := DataSetMetaDataOf(pdsCfg)
	other.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: 9, MinorVersion: 9}

	sub := start(t, NewConfiguration(nil, AttachReaderGroups(memConnection("s", url, nil),
		ReaderGroup("rg", DataSetReader("r", uint16(1), 1, 1, md), DataSetReader("bad", uint16(1), 1, 1, other)),
		Secure(ReaderGroup("srg", DataSetReader("sr", uint16(2), 2, 1, md)), ua.MessageSecurityModeSign, "sg"),
	)), WithKeySource("sg", newFakeKeys(1)), WithDiagnosticsLevel(ua.DiagnosticsLevelInfo))
	cid := mustID(t, sub, KindConnection, Root, "s")
	rg := mustID(t, sub, KindReaderGroup, cid, "rg")
	r := mustID(t, sub, KindDataSetReader, rg, "r")
	bad := mustID(t, sub, KindDataSetReader, rg, "bad")
	srg := mustID(t, sub, KindReaderGroup, cid, "srg")
	sr := mustID(t, sub, KindDataSetReader, srg, "sr")
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)

	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(1)))
	// A plain publisher for rg and a secured one with a token the
	// subscriber does not know for srg.
	start(t, NewConfiguration([]*ua.PublishedDataSetDataType{pdsCfg},
		AttachWriterGroups(memConnection("p", url, uint16(1)), WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds")))),
		WithDataSource(ds))
	start(t, NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachWriterGroups(memConnection("p", url, uint16(2)),
			Secure(WriterGroup("wg", 2, 5*time.Millisecond, DataSetWriter("w", 1, "pds")), ua.MessageSecurityModeSign, "sg"))),
		WithDataSource(ds), WithKeySource("sg", newFakeKeys(3)))

	waitCounter(t, sub, rg, CounterReceivedNetworkMessages, 2)
	waitCounter(t, sub, bad, CounterFailedDataSetMessages, 1)
	waitCounter(t, sub, srg, CounterDecryptionErrors, 1)
	waitCounter(t, sub, sr, CounterDecryptionErrors, 1)
	waitState(t, sub, r, ua.PubSubStateOperational)
	require.Eventually(t, func() bool { return diag(t, sub, r).LiveValues.MessageSequenceNumber > 0 }, 3*time.Second, time.Millisecond)
	d := diag(t, sub, r)
	require.Equal(t, uint32(5), d.LiveValues.MajorVersion)
	require.Equal(t, uint32(6), d.LiveValues.MinorVersion)
	require.Equal(t, ua.StatusGood, d.LiveValues.StatusCode)
	c, _ := d.Counter(CounterFailedDataSetMessages)
	require.Zero(t, c.Value)
	require.Equal(t, uint32(1), diag(t, sub, sr).LiveValues.SecurityTokenID)
	require.True(t, diag(t, sub, rg).SubError)
	g := diag(t, sub, rg)
	require.Equal(t, uint16(2), g.LiveValues.ConfiguredDataSetReaders)
	require.Equal(t, uint16(1), g.LiveValues.OperationalDataSetReaders)
	root := diag(t, sub, Root)
	require.Equal(t, uint16(3), root.LiveValues.ConfiguredDataSetReaders)

	// A message that cannot be decoded is invalid for the groups.
	before := counterOf(t, sub, rg, CounterReceivedInvalidNetworkMessages).Value
	bus.inject(url, "", []byte("U{not json"))
	waitCounter(t, sub, rg, CounterReceivedInvalidNetworkMessages, before+1)
	waitCounter(t, sub, srg, CounterReceivedInvalidNetworkMessages, 1)
}

func TestDiagnosticsUnsecuredJSON(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	sub := start(t, NewConfiguration(nil, AttachReaderGroups(memConnection("s", url, nil),
		Secure(ReaderGroup("srg", DataSetReader("sr", uint16(2), 0, 1, nil)), ua.MessageSecurityModeSign, "sg"),
	)), WithKeySource("sg", newFakeKeys(1)), WithDiagnosticsLevel(ua.DiagnosticsLevelAdvanced))
	srg := mustID(t, sub, KindReaderGroup, mustID(t, sub, KindConnection, Root, "s"), "srg")
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)
	bus.inject(url, "", []byte(`{"MessageId":"x"}`))
	waitCounter(t, sub, srg, CounterDecryptionErrors, 1)
}
