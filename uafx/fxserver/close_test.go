// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// operational establishes the endpoint name of Motion with the
// CleanupTimeout timeout (ms) and waits until it is Operational.
func (f *fx) operational(t *testing.T, name string, timeout float64) *ua.NodeID {
	t.Helper()
	r := f.fullRequest(name)
	r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.CleanupTimeout = timeout
	res := f.establish(t, r)
	require.Equal(t, ua.StatusOK, res.Status)
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	require.Eventually(t, func() bool { st, _ := f.conns.Status(ep); return st == uafx.ConnectionEndpointOperational }, 5*time.Second, 5*time.Millisecond)
	return ep
}

// lookup returns the component name of kind below the group of conn.
func (f *fx) lookup(t *testing.T, kind pubsub.ComponentKind, conn, group, name string) pubsub.ComponentID {
	t.Helper()
	rt := f.srv.PubSub()
	c, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, conn)
	require.True(t, ok)
	gk := pubsub.KindWriterGroup
	if kind == pubsub.KindDataSetReader {
		gk = pubsub.KindReaderGroup
	}
	g, ok := rt.Lookup(gk, c, group)
	require.True(t, ok)
	x, ok := rt.Lookup(kind, g, name)
	require.True(t, ok, name)
	return x
}

func (f *fx) close(t *testing.T, remove bool, eps ...*ua.NodeID) (ua.StatusCode, []ua.StatusCode) {
	t.Helper()
	sc, results, err := uafx.CloseConnections(context.Background(), f.c, f.id(ctlID), eps, remove)
	require.NoError(t, err)
	return sc, results
}

// TestCloseConnectionsFailures: a PubSub operation that fails makes the
// result of its endpoint Bad and the call Uncertain (Part 81 §6.2.5,
// Table 23), and the endpoint stays with its References to what is left,
// so that a second CloseConnections can finish the close.
func TestCloseConnectionsFailures(t *testing.T) {
	t.Parallel()
	boom := fmt.Errorf("injected: %w", ua.StatusBadResourceUnavailable)

	t.Run("disable", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		ep := f.operational(t, "D", -1)
		disable, _, _ := fxserver.RuntimeOps(f.conns)
		fxserver.SetPubSubOps(f.conns, func(pubsub.ComponentID) error { return boom }, nil, nil)
		sc, results := f.close(t, false, ep)
		assert.Equal(t, ua.StatusUncertain, sc)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadResourceUnavailable}, results)
		require.NotNil(t, f.srv.Node(ep))

		fxserver.SetPubSubOps(f.conns, disable, nil, nil)
		sc, results = f.close(t, false, ep)
		assert.Equal(t, ua.StatusOK, sc)
		assert.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
		info, err := f.srv.PubSub().Component(f.lookup(t, pubsub.KindDataSetReader, subConn, rgName, readerName))
		require.NoError(t, err)
		assert.False(t, info.Enabled)
	})

	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		ep := f.operational(t, "R", -1)
		_, removeReader, _ := fxserver.RuntimeOps(f.conns)
		fxserver.SetPubSubOps(f.conns, nil, func(pubsub.ComponentID) error { return boom }, nil)
		sc, results := f.close(t, true, ep)
		assert.Equal(t, ua.StatusUncertain, sc)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadResourceUnavailable}, results)
		// The endpoint is not deleted while its reader is left: it keeps
		// tracking it. Its writer is gone.
		require.NotNil(t, f.srv.Node(ep))
		_, ok := f.conns.Status(ep)
		assert.True(t, ok)
		ids := pubsubIDs(f)
		assert.True(t, ids["DataSetReader/"+readerName])
		assert.False(t, ids["DataSetWriter/"+writerName])
		assert.Len(t, f.targets(t, ep, fxacid.ToDataSetReader), 1)
		assert.Empty(t, f.targets(t, ep, fxacid.ToDataSetWriter))

		// The second close finishes: the reader is disabled already, which
		// is not a failure.
		fxserver.SetPubSubOps(f.conns, nil, removeReader, nil)
		sc, results = f.close(t, true, ep)
		assert.Equal(t, ua.StatusOK, sc)
		assert.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
		assert.Nil(t, f.srv.Node(ep))
		assert.False(t, pubsubIDs(f)["DataSetReader/"+readerName])
	})

	t.Run("disable fails, remove succeeds", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		ep := f.operational(t, "S", -1)
		fxserver.SetPubSubOps(f.conns, func(pubsub.ComponentID) error { return boom }, nil, nil)
		sc, results := f.close(t, true, ep)
		assert.Equal(t, ua.StatusOK, sc, "the removal stops what could not be disabled")
		assert.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
		assert.Nil(t, f.srv.Node(ep))
	})

	t.Run("an error without a Bad StatusCode", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		ep := f.operational(t, "I", -1)
		for _, err := range []error{fmt.Errorf("injected"), fmt.Errorf("injected: %w", ua.StatusUncertain)} {
			fxserver.SetPubSubOps(f.conns, func(pubsub.ComponentID) error { return err }, nil, nil)
			_, results := f.close(t, false, ep)
			assert.Equal(t, []ua.StatusCode{ua.StatusBadInternalError}, results, err.Error())
		}
	})

	t.Run("preconfigured", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		r := f.fullRequest("Preset")
		p := r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter
		p.IsPreconfigured, p.Mode, p.OutputVariableIDs = true, uafx.PubSubSubscriber, nil
		r.ConnectionEndpointConfigurations[0].CommunicationLinks.DataSetWriterRef = nil
		res := f.establish(t, r)
		require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
		ep := f.id(presetID)
		_, removeReader, _ := fxserver.RuntimeOps(f.conns)
		fxserver.SetPubSubOps(f.conns, nil, func(pubsub.ComponentID) error { return boom }, nil)
		sc, _ := f.close(t, true, ep)
		assert.Equal(t, ua.StatusUncertain, sc)
		assert.NotNil(t, val(f.srv.Node(f.id(presetID+4)).Value().Value), "the RelatedEndpoint stays while the close is not done")
		fxserver.SetPubSubOps(f.conns, nil, removeReader, nil)
		sc, _ = f.close(t, true, ep)
		assert.Equal(t, ua.StatusOK, sc)
		assert.Nil(t, val(f.srv.Node(f.id(presetID+4)).Value().Value))
	})
}

// TestCleanupFailureRetried: a cleanup whose close fails reports an
// AuditConnectionCleanupEventType event with Status false, keeps the
// endpoint and tries again.
func TestCleanupFailureRetried(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{}, server.WithAuditing(true))
	fxserver.SetRetryCleanup(f.conns, 50*time.Millisecond)
	audit := watchAudit(t, f)
	ep := f.operational(t, "Live", 50)
	_, removeReader, _ := fxserver.RuntimeOps(f.conns)
	var failing atomic.Bool
	failing.Store(true)
	fxserver.SetPubSubOps(f.conns, nil, func(id pubsub.ComponentID) error {
		if failing.Load() {
			return fmt.Errorf("injected: %w", ua.StatusBadResourceUnavailable)
		}
		return removeReader(id)
	}, nil)
	require.NoError(t, f.srv.PubSub().Disable(f.lookup(t, pubsub.KindDataSetWriter, pubConn, wgName, writerName)))

	cleanup := ua.NewNumericNodeID(f.ns.AC, fxacid.AuditConnectionCleanupEventType)
	a := nextFXAudit(t, audit, cleanup)
	assert.False(t, a.status)
	_, ok := f.conns.Status(ep)
	assert.True(t, ok, "kept after a failed cleanup")
	require.NotNil(t, f.srv.Node(ep))

	failing.Store(false)
	for {
		a = nextFXAudit(t, audit, cleanup)
		if a.status {
			break
		}
	}
	require.Eventually(t, func() bool { _, ok := f.conns.Status(ep); return !ok }, 5*time.Second, 5*time.Millisecond)
	assert.False(t, pubsubIDs(f)["DataSetReader/"+readerName])
}

// TestCleanupTimeoutClosedMeanwhile: a CloseConnections that runs after the
// monitor found an expired CleanupTimeout, but before it acted, disables
// the cleanup (Part 81 §6.2.5.2): the endpoint is not removed. The hook
// runs CloseConnections exactly in that window.
func TestCleanupTimeoutClosedMeanwhile(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	var once sync.Once
	var ep *ua.NodeID
	hooked := make(chan ua.StatusCode, 1)
	fxserver.SetBeforeExpire(f.conns, func() {
		once.Do(func() {
			sc, _, err := uafx.CloseConnections(context.Background(), f.c, f.id(ctlID), []*ua.NodeID{ep}, false)
			if err != nil {
				sc = ua.StatusBadUnexpectedError
			}
			hooked <- sc
		})
	})
	ep = f.operational(t, "Live", 50)
	require.NoError(t, f.srv.PubSub().Disable(f.lookup(t, pubsub.KindDataSetWriter, pubConn, wgName, writerName)))
	select {
	case sc := <-hooked:
		require.Equal(t, ua.StatusOK, sc)
	case <-time.After(10 * time.Second):
		t.Fatal("the CleanupTimeout did not expire")
	}
	time.Sleep(200 * time.Millisecond) // many monitor rounds
	_, ok := f.conns.Status(ep)
	assert.True(t, ok, "CloseConnections disabled the cleanup")
	assert.NotNil(t, f.srv.Node(ep))
	assert.True(t, pubsubIDs(f)["DataSetReader/"+readerName], "nothing removed")
}

// TestCleanupTimeoutOperationalAgain: an endpoint that is Operational
// again when the monitor acts on an expired CleanupTimeout is not removed
// (Part 81 §6.6.2). The hook makes it Operational exactly in that window.
func TestCleanupTimeoutOperationalAgain(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	rt := f.srv.PubSub()
	var once sync.Once
	var w, rd pubsub.ComponentID
	hooked := make(chan bool, 1)
	fxserver.SetBeforeExpire(f.conns, func() {
		once.Do(func() {
			ok := rt.Enable(w) == nil
			deadline := time.Now().Add(5 * time.Second)
			for ok && time.Now().Before(deadline) {
				sw, _ := rt.State(w)
				sr, _ := rt.State(rd)
				if sw == ua.PubSubStateOperational && sr == ua.PubSubStateOperational {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			hooked <- ok
		})
	})
	ep := f.operational(t, "Live", 50)
	w = f.lookup(t, pubsub.KindDataSetWriter, pubConn, wgName, writerName)
	rd = f.lookup(t, pubsub.KindDataSetReader, subConn, rgName, readerName)
	require.NoError(t, rt.Disable(w))
	select {
	case ok := <-hooked:
		require.True(t, ok)
	case <-time.After(10 * time.Second):
		t.Fatal("the CleanupTimeout did not expire")
	}
	require.Eventually(t, func() bool { st, _ := f.conns.Status(ep); return st == uafx.ConnectionEndpointOperational }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	_, ok := f.conns.Status(ep)
	assert.True(t, ok, "Operational again: not removed")
}

// TestCleanupTimeoutDuringCall: an endpoint whose CleanupTimeout expires
// while a call runs is closed after the call; the call completes. The hook
// runs a call exactly when an expiry is due.
func TestCleanupTimeoutDuringCall(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	var once sync.Once
	hooked := make(chan error, 1)
	fxserver.SetBeforeExpire(f.conns, func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, err := uafx.CloseConnections(ctx, f.c, f.id(ctlID), nil, false)
			hooked <- err
		})
	})
	ep := f.operational(t, "Live", 50)
	require.NoError(t, f.srv.PubSub().Disable(f.lookup(t, pubsub.KindDataSetWriter, pubConn, wgName, writerName)))
	select {
	case err := <-hooked:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the CleanupTimeout did not expire")
	}
	require.Eventually(t, func() bool { _, ok := f.conns.Status(ep); return !ok }, 5*time.Second, 5*time.Millisecond)
}

// denyRead denies reading the node of the test namespace with the numeric
// id id.
type denyRead struct {
	server.DefaultAccessController
	id uint32
}

func (d denyRead) CheckRead(_ context.Context, _ *server.Session, n *ua.NodeID) ua.StatusCode {
	if n != nil && n.Namespace() != 0 && n.IntID() == d.id {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

// verifyMotion runs VerifyFunctionalEntityCmd on Motion with pairs.
func (f *fx) verifyMotion(t *testing.T, pairs ...*uafx.NodeIDValuePair) *uafx.ConnectionEndpointConfigurationResult {
	t.Helper()
	res := f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.VerifyFunctionalEntityCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{FunctionalEntityNode: f.id(motionID),
			ConnectionEndpoint: node(f, presetID), ExpectedVerificationVariables: pairs}}})
	return res.ConnectionEndpointConfigurationResults[0]
}

func (f *fx) pair(n uint32, v any, idx ...uint32) *uafx.NodeIDValuePair {
	var vv *ua.Variant
	if v != nil {
		vv = ua.MustVariant(v)
	}
	return &uafx.NodeIDValuePair{Key: &uafx.NodeIDArray{Node: f.id(n), ArrayIndex: idx}, Value: vv}
}

// TestVerifyReadAccess: VerifyFunctionalEntityCmd reads with the rights of
// the caller. A caller that may not read a Variable gets the status of the
// refused read for it, whether its guess is right or wrong, so the
// verification does not tell the value.
func TestVerifyReadAccess(t *testing.T) {
	t.Parallel()
	g := newFX(t, fxserver.ConnectionOptions{}, server.WithAccessController(denyRead{id: fixedID}))
	right := g.verifyMotion(t, g.pair(fixedID, 7.0))
	wrong := g.verifyMotion(t, g.pair(fixedID, 8.0))
	for _, r := range []*uafx.ConnectionEndpointConfigurationResult{right, wrong} {
		assert.Equal(t, uafx.FunctionalEntityVerificationMismatch, r.VerificationResult)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied}, r.VerificationVariablesErrors)
	}
	assert.Equal(t, right.VerificationStatus, wrong.VerificationStatus)

	// Existence (a null value) needs no read; a readable Variable verifies.
	r := g.verifyMotion(t, g.pair(fixedID, nil), g.pair(gainID, 1.0))
	assert.Equal(t, uafx.FunctionalEntityVerificationMatch, r.VerificationResult)

	// A Variable whose UserAccessLevel has no CurrentRead.
	h := newFX(t, fxserver.ConnectionOptions{})
	require.NoError(t, h.srv.Node(h.id(fixedID)).SetAttribute(ua.AttributeIDUserAccessLevel, server.DataValueFromValue(byte(0))))
	r = h.verifyMotion(t, h.pair(fixedID, 7.0))
	assert.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied}, r.VerificationVariablesErrors)
}

// applicationIdentifier is the binary body of an
// ApplicationIdentifierDataType (Part 81 §10.3) with the Name name and the
// UniqueIdentifier IdString id (§10.2, union switch 2).
func applicationIdentifier(f *fx, name, id string) *ua.ExtensionObject {
	lt, err := ua.NewLocalizedText(name).Encode()
	if err != nil {
		panic(err)
	}
	b := binary.LittleEndian.AppendUint32(lt, 2)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(id)))
	b = append(b, id...)
	return &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary,
		TypeID: ua.NewNumericExpandedNodeID(f.ns.AC, fxacid.ApplicationIdentifierDataTypeEncodingDefaultBinary), Value: b}
}

// TestVerifyComparison: String values are compared without their leading
// and trailing whitespace, and an ApplicationIdentifier by its
// UniqueIdentifier alone (Part 81 §6.4.3).
func TestVerifyComparison(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	r := f.verifyMotion(t, f.pair(fxtest.ConnLabel, "pump-1"), f.pair(fxtest.ConnLabel, " pump-1\t"))
	assert.Equal(t, uafx.FunctionalEntityVerificationMatch, r.VerificationResult)
	r = f.verifyMotion(t, f.pair(fxtest.ConnLabel, "pump-2"))
	assert.Equal(t, []ua.StatusCode{ua.StatusBadOutOfRange}, r.VerificationVariablesErrors)

	// String arrays, element by element.
	r = f.verifyMotion(t, f.pair(fxtest.ConnLabels, []string{"a", " b\n"}), f.pair(fxtest.ConnLabels, "a ", 0))
	assert.Equal(t, uafx.FunctionalEntityVerificationMatch, r.VerificationResult)
	r = f.verifyMotion(t, f.pair(fxtest.ConnLabels, []string{"a"}))
	assert.Equal(t, []ua.StatusCode{ua.StatusBadOutOfRange}, r.VerificationVariablesErrors)

	// A value that is not a binary ApplicationIdentifierDataType body is
	// compared as a whole.
	other := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewNumericExpandedNodeID(f.ns.AC, 9999), Value: []byte{1, 2}}
	broken := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary,
		TypeID: ua.NewNumericExpandedNodeID(f.ns.AC, fxacid.ApplicationIdentifierDataTypeEncodingDefaultBinary), Value: []byte{0xff}}
	setValue(t, f.srv, f.id(fxtest.ConnAppID), []*ua.ExtensionObject{other})
	for _, c := range []struct {
		name string
		want any
		code ua.StatusCode
	}{
		{"same", []*ua.ExtensionObject{other}, ua.StatusOK},
		{"other body", []*ua.ExtensionObject{{EncodingMask: ua.ExtensionObjectBinary, TypeID: other.TypeID, Value: []byte{1, 3}}}, ua.StatusBadOutOfRange},
		{"other length", []*ua.ExtensionObject{other, other}, ua.StatusBadOutOfRange},
		{"undecodable", []*ua.ExtensionObject{broken}, ua.StatusBadOutOfRange},
	} {
		r := f.verifyMotion(t, f.pair(fxtest.ConnAppID, c.want))
		assert.Equal(t, []ua.StatusCode{c.code}, r.VerificationVariablesErrors, c.name)
	}
	r = f.verifyMotion(t, f.pair(fxtest.ConnAppID, broken, 0), f.pair(fxtest.ConnAppID, other, 0))
	assert.Equal(t, []ua.StatusCode{ua.StatusBadOutOfRange, ua.StatusOK}, r.VerificationVariablesErrors, "elements")

	setValue(t, f.srv, f.id(fxtest.ConnAppID), []*ua.ExtensionObject{
		applicationIdentifier(f, "Line 4", "urn:plant:line4"), applicationIdentifier(f, "Cell", "cell-7"),
	})
	ids := func(xs ...*ua.ExtensionObject) []*ua.ExtensionObject { return xs }
	for _, c := range []struct {
		name string
		want any
		idx  []uint32
		code ua.StatusCode
	}{
		{"other names", ids(applicationIdentifier(f, "Linie 4", "urn:plant:line4"), applicationIdentifier(f, "", "cell-7")), nil, ua.StatusOK},
		{"other id", ids(applicationIdentifier(f, "Line 4", "urn:plant:line5"), applicationIdentifier(f, "Cell", "cell-7")), nil, ua.StatusBadOutOfRange},
		{"shorter", ids(applicationIdentifier(f, "Line 4", "urn:plant:line4")), nil, ua.StatusBadOutOfRange},
		{"element", applicationIdentifier(f, "Zelle", "cell-7"), []uint32{1}, ua.StatusOK},
		{"element, other id", applicationIdentifier(f, "Cell", "cell-8"), []uint32{1}, ua.StatusBadOutOfRange},
	} {
		r := f.verifyMotion(t, f.pair(fxtest.ConnAppID, c.want, c.idx...))
		assert.Equal(t, []ua.StatusCode{c.code}, r.VerificationVariablesErrors, c.name)
	}
}
