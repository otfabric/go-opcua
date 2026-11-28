// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/fakeclock"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// The ControlGroups of fxtest.PrepareControlGroups and their members.
const (
	controlID = fxtest.ConnControl
	monitorID = fxtest.ConnMonitor
	resetID   = fxtest.ConnReset
	homeID    = fxtest.ConnHome
)

// Offsets of the members of a ControlGroup (fxtest.ConnControl).
const (
	blockLock     = 2
	restrictLock  = 12
	lockLocked    = 1 // from the Lock
	lockClient    = 2
	lockUser      = 3
	lockInit      = 5
	lockRenew     = 6
	lockExit      = 7
	lockBreak     = 8
	isControlled  = 23
	establishCtl  = 24
	releaseCtl    = 25
	reassignCtl   = 26
	appA, appB    = "urn:go-opcua:test:a", "urn:go-opcua:test:b"
	unknownNodeID = "ns=1;i=999999"
)

// client connects a client with the ApplicationUri uri to the server of f.
func (f *fx) client(t *testing.T, uri string) *opcua.Client {
	t.Helper()
	ctx := context.Background()
	c, err := opcua.NewClient(fmt.Sprintf("opc.tcp://localhost:%d", f.srv.Port()),
		opcua.InsecureNoSecurity(), opcua.ApplicationURI(uri))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	cleanup.Register(t, func() { _ = c.Close(ctx) })
	return c
}

// plainClient is client without the Role ConnectionAdmin.
func (f *fx) plainClient(t *testing.T, uri string) *opcua.Client {
	t.Helper()
	f.hooks.noAdmin.Store(true)
	defer f.hooks.noAdmin.Store(false)
	return f.client(t, uri)
}

// call calls the Method method of obj and returns its first output
// argument, if any.
func (f *fx) call(t *testing.T, c *opcua.Client, obj, method uint32, args ...any) (any, ua.StatusCode) {
	t.Helper()
	var in []*ua.Variant
	for _, a := range args {
		in = append(in, ua.MustVariant(a))
	}
	res, err := c.Call(context.Background(), &ua.CallMethodRequest{ObjectID: f.id(obj), MethodID: f.id(method), InputArguments: in})
	require.NoError(t, err)
	if len(res.OutputArguments) == 0 {
		return nil, res.StatusCode
	}
	return res.OutputArguments[0].Value(), res.StatusCode
}

// lockStatus calls a Method of a ControlGroup or Lock that returns a
// LockStatus.
func (f *fx) lockStatus(t *testing.T, c *opcua.Client, obj, method uint32, args ...any) int32 {
	t.Helper()
	out, sc := f.call(t, c, obj, method, args...)
	require.Equal(t, ua.StatusOK, sc)
	st, ok := out.(int32)
	require.True(t, ok, "%T", out)
	return st
}

func (f *fx) writeValue(t *testing.T, c *opcua.Client, n uint32, v any) ua.StatusCode {
	t.Helper()
	res, err := c.Write(context.Background(), &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
		NodeID: f.id(n), AttributeID: ua.AttributeIDValue,
		Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
	}}})
	require.NoError(t, err)
	return res.Results[0]
}

// lockProps returns Locked, LockingClient and LockingUser of the Lock l.
func (f *fx) lockProps(t *testing.T, l uint32) (bool, string, string) {
	t.Helper()
	return f.value(t, l+lockLocked).(bool), f.value(t, l+lockClient).(string), f.value(t, l+lockUser).(string)
}

// controlledBy returns the SourceNodes of the Controls References to g.
func (f *fx) controlledBy(t *testing.T, g uint32) []string {
	t.Helper()
	refs, err := f.c.Node(f.id(g)).References(context.Background(), id.Controls, ua.BrowseDirectionInverse, ua.NodeClassAll, false)
	require.NoError(t, err)
	var out []string
	for _, r := range refs {
		out = append(out, r.NodeID.NodeID.String())
	}
	return out
}

// TestControlGroupMethods: EstablishControl, ReleaseControl and
// ReassignControl (Part 81 §6.5.3 to §6.5.5) and what their Locks block and
// restrict (§6.5.2, OPC 10000-100 §7.5).
func TestControlGroupMethods(t *testing.T) {
	t.Parallel()
	f := newControlFX(t, fxserver.ConnectionOptions{})
	ok := func(context.Context, *ua.NodeID, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, ua.StatusOK
	}
	f.srv.RegisterMethod(f.id(motionID), f.id(resetID), ok)
	f.srv.RegisterMethod(f.id(axisID), f.id(homeID), ok)
	a, b := f.client(t, appA), f.client(t, appB)
	callOn := func(c *opcua.Client, obj, method uint32) ua.StatusCode {
		res, err := c.Call(context.Background(), &ua.CallMethodRequest{ObjectID: f.id(obj), MethodID: f.id(method)})
		require.NoError(t, err)
		return res.StatusCode
	}
	callReset := func(c *opcua.Client) ua.StatusCode { return callOn(c, motionID, resetID) }

	// Nothing is locked yet.
	assert.Equal(t, ua.StatusOK, f.writeValue(t, b, gainID, 1.5))
	assert.Equal(t, false, f.value(t, controlID+isControlled))

	// A controls Control: a null LockContext is its ApplicationUri.
	assert.Equal(t, int32(0), f.lockStatus(t, a, controlID, controlID+establishCtl, ""))
	assert.Equal(t, true, f.value(t, controlID+isControlled))
	for _, l := range []uint32{controlID + blockLock, controlID + restrictLock} {
		locked, client, user := f.lockProps(t, l)
		assert.True(t, locked)
		assert.Equal(t, appA, client)
		assert.Equal(t, "Anonymous", user)
	}
	assert.Positive(t, f.value(t, controlID+restrictLock+4).(float64), "RemainingLockTime")
	assert.Empty(t, f.controlledBy(t, controlID), "a client has no Controls Reference")

	// ListToRestrict: the owner only; ListToBlock: no one.
	assert.Equal(t, ua.StatusOK, f.writeValue(t, a, gainID, 2.0))
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, b, gainID, 3.0))
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, a, tableID, []float64{1}))
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, b, tableID, []float64{1}))
	assert.Equal(t, ua.StatusOK, f.writeValue(t, b, setpointID, 1.0), "not in a list")
	assert.Equal(t, ua.StatusOK, callReset(a))
	assert.Equal(t, ua.StatusBadLocked, callReset(b))

	// The Object Axis in ListToRestrict: its Variable AxisIn and Method
	// Home too.
	assert.Equal(t, ua.StatusOK, f.writeValue(t, a, axisInID, 2.0))
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, b, axisInID, 3.0))
	assert.Equal(t, ua.StatusOK, callOn(a, axisID, homeID))
	assert.Equal(t, ua.StatusBadLocked, callOn(b, axisID, homeID))

	// Monitor shares Gain: B cannot control it, A can.
	assert.Equal(t, int32(-1), f.lockStatus(t, b, monitorID, monitorID+establishCtl, ""))
	assert.Equal(t, false, f.value(t, monitorID+isControlled))
	assert.Equal(t, int32(-1), f.lockStatus(t, b, controlID, controlID+establishCtl, ""))
	assert.Equal(t, int32(0), f.lockStatus(t, a, monitorID, monitorID+establishCtl, ""))

	// Only the controller releases or reassigns.
	_, sc := f.call(t, b, controlID, controlID+releaseCtl)
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = f.call(t, b, controlID, controlID+reassignCtl, appB)
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)

	// Reassigning Control to B would put Gain under two owners.
	assert.Equal(t, int32(-2), f.lockStatus(t, a, controlID, controlID+reassignCtl, appB))
	_, sc = f.call(t, a, monitorID, monitorID+releaseCtl)
	require.Equal(t, ua.StatusOK, sc)
	assert.Equal(t, false, f.value(t, monitorID+isControlled))
	assert.Equal(t, int32(0), f.lockStatus(t, a, controlID, controlID+reassignCtl, appB))
	_, client, _ := f.lockProps(t, controlID+restrictLock)
	assert.Equal(t, appB, client)
	assert.Equal(t, ua.StatusOK, f.writeValue(t, b, gainID, 4.0))
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, a, gainID, 5.0))

	// The arguments of ReassignControl (Table 70).
	_, sc = f.call(t, b, controlID, controlID+reassignCtl, "")
	assert.Equal(t, ua.StatusBadInvalidArgument, sc, "null LockContext")
	_, sc = f.call(t, b, controlID, controlID+reassignCtl, unknownNodeID)
	assert.Equal(t, ua.StatusBadInvalidArgument, sc, "not a ConnectionEndpoint")
	_, sc = f.call(t, b, controlID, controlID+reassignCtl, int32(1))
	assert.Equal(t, ua.StatusBadInvalidArgument, sc, "not a String")
	_, sc = f.call(t, b, controlID, controlID+establishCtl, int32(1))
	assert.Equal(t, ua.StatusBadInvalidArgument, sc, "not a String")
	_, sc = f.call(t, b, controlID, controlID+releaseCtl, "x")
	assert.Equal(t, ua.StatusBadTooManyArguments, sc, "Part 4 §5.11.2")

	// B releases: everything is free again.
	_, sc = f.call(t, b, controlID, controlID+releaseCtl)
	require.Equal(t, ua.StatusOK, sc)
	assert.Equal(t, false, f.value(t, controlID+isControlled))
	locked, client, user := f.lockProps(t, controlID+blockLock)
	assert.False(t, locked)
	assert.Empty(t, client)
	assert.Empty(t, user)
	assert.Equal(t, ua.StatusOK, f.writeValue(t, a, tableID, []float64{1}))
	assert.Equal(t, int32(-1), f.lockStatus(t, b, controlID, controlID+reassignCtl, appA), "E_NotLocked")

	// A LockContext names the owner; the NodeId of another node is E_Invalid.
	assert.Equal(t, int32(-2), f.lockStatus(t, a, controlID, controlID+establishCtl, unknownNodeID))
	assert.Equal(t, int32(0), f.lockStatus(t, a, controlID, controlID+establishCtl, appB))
	assert.Equal(t, ua.StatusOK, f.writeValue(t, b, gainID, 6.0))
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, a, gainID, 6.0))

	// Without the Role ConnectionAdmin a client neither controls, for
	// itself or another, nor releases, reassigns or breaks (Part 81
	// §6.5.3 to §6.5.5, OPC 10000-100 §7.8); the LockingServices of a free
	// Lock are its own.
	p := f.plainClient(t, appA)
	for _, lc := range []string{"", appA, appB} {
		_, sc = f.call(t, p, monitorID, monitorID+establishCtl, lc)
		assert.Equal(t, ua.StatusBadUserAccessDenied, sc, lc)
	}
	_, sc = f.call(t, p, controlID, controlID+releaseCtl)
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = f.call(t, p, controlID, controlID+reassignCtl, appA)
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = f.call(t, p, controlID+blockLock, controlID+blockLock+lockBreak)
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	locked, client, _ = f.lockProps(t, controlID+blockLock)
	assert.True(t, locked)
	assert.Equal(t, appB, client)
	assert.Equal(t, false, f.value(t, monitorID+isControlled))
	l := uint32(monitorID + blockLock)
	assert.Equal(t, int32(0), f.lockStatus(t, p, l, l+lockInit, ""))
	assert.Equal(t, int32(0), f.lockStatus(t, p, l, l+lockExit))
}

func TestControlOperation(t *testing.T) {
	t.Parallel()
	for op, name := range map[fxserver.ControlOperation]string{
		fxserver.ControlEstablish: "EstablishControl", fxserver.ControlRelease: "ReleaseControl",
		fxserver.ControlReassign: "ReassignControl", fxserver.ControlBreakLock: "BreakLock",
		fxserver.ControlCloseRemove: "CloseConnections", fxserver.ControlWriteAsEndpoint: "SetConfigurationDataCmd",
		0: "ControlOperation(0)",
	} {
		assert.Equal(t, name, op.String())
	}
	assert.Nil(t, fxserver.Namespaces{}.ConnectionAdmin())
	assert.Equal(t, "ns=2;i=5019", fxserver.Namespaces{Data: 2}.ConnectionAdmin().String())
}

// TestLockingServices: InitLock, RenewLock, ExitLock and BreakLock of the
// Lock of a ControlItemFolder (OPC 10000-100 §7.5 to §7.8, Part 81 §6.5.6),
// and the end of the session that took a Lock (§7.2).
func TestLockingServices(t *testing.T) {
	t.Parallel()
	f := newControlFX(t, fxserver.ConnectionOptions{})
	a, b := f.client(t, appA), f.client(t, appB)
	l := uint32(controlID + restrictLock)

	// A lock request is refused while an operation that the Lock would
	// prevent runs (OPC 10000-100 §7.2). The server handles requests one
	// at a time; a Write a ValueWriter takes runs on after the request
	// handler: B's write of AxisIn, which ListToRestrict of Control
	// covers, waits in its ValueWriter.
	started, release := make(chan struct{}), make(chan struct{})
	axisIn := f.srv.Node(f.id(axisInID))
	require.NotNil(t, axisIn)
	axisIn.SetValueWriter(func(context.Context, *server.ValueWrite) ua.StatusCode {
		close(started)
		<-release
		return ua.StatusOK
	})
	result := make(chan ua.StatusCode, 1)
	go func() {
		res, err := b.Write(context.Background(), &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
			NodeID: f.id(axisInID), AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(1.0)},
		}}})
		if err != nil {
			result <- ua.StatusBadUnexpectedError
			return
		}
		result <- res.Results[0]
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the ValueWriter was not called")
	}
	assert.Equal(t, int32(-1), f.lockStatus(t, a, l, l+lockInit, ""), "B's write runs")
	assert.Equal(t, int32(-1), f.lockStatus(t, a, controlID, controlID+establishCtl, ""), "B's write runs")
	assert.Equal(t, false, f.value(t, controlID+isControlled))
	assert.Equal(t, int32(0), f.lockStatus(t, a, controlID+blockLock, controlID+blockLock+lockInit, ""), "AxisIn is not in ListToBlock")
	assert.Equal(t, int32(0), f.lockStatus(t, a, controlID+blockLock, controlID+blockLock+lockExit))
	assert.Equal(t, int32(0), f.lockStatus(t, b, l, l+lockInit, ""), "B's Lock would not prevent B's write")
	assert.Equal(t, int32(0), f.lockStatus(t, b, l, l+lockExit))
	close(release)
	assert.Equal(t, ua.StatusOK, <-result)
	axisIn.SetValueWriter(nil)
	assert.Equal(t, int32(0), f.lockStatus(t, a, l, l+lockInit, ""), "the write is over")
	assert.Equal(t, int32(0), f.lockStatus(t, a, l, l+lockExit))

	assert.Equal(t, int32(-1), f.lockStatus(t, a, l, l+lockRenew), "E_NotLocked")
	assert.Equal(t, int32(-1), f.lockStatus(t, a, l, l+lockExit), "E_NotLocked")
	assert.Equal(t, int32(-1), f.lockStatus(t, a, l, l+lockBreak), "E_NotLocked")

	assert.Equal(t, int32(0), f.lockStatus(t, a, l, l+lockInit, "editing"))
	assert.Equal(t, int32(-1), f.lockStatus(t, a, l, l+lockInit, "again"), "E_AlreadyLocked")
	assert.Equal(t, int32(-1), f.lockStatus(t, b, monitorID+restrictLock, monitorID+restrictLock+lockInit, ""), "Gain is A's")
	assert.Equal(t, false, f.value(t, controlID+isControlled), "a Lock is not control")
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, b, gainID, 1.0))
	assert.Equal(t, ua.StatusOK, f.writeValue(t, b, tableID, []float64{2}), "ListToBlock is not locked")

	_, sc := f.call(t, b, l, l+lockRenew)
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = f.call(t, b, l, l+lockExit)
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	assert.Equal(t, int32(0), f.lockStatus(t, a, l, l+lockRenew))
	assert.Equal(t, int32(0), f.lockStatus(t, b, l, l+lockBreak), "a ConnectionAdmin breaks it")
	locked, _, _ := f.lockProps(t, l)
	assert.False(t, locked)

	// The Locks of a controlled ControlGroup are its controller's.
	assert.Equal(t, int32(0), f.lockStatus(t, a, controlID, controlID+establishCtl, ""))
	_, sc = f.call(t, b, l, l+lockInit, "")
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	assert.Equal(t, int32(0), f.lockStatus(t, a, l, l+lockExit))
	assert.Equal(t, true, f.value(t, controlID+isControlled), "ExitLock leaves IsControlled (Part 81 §6.5.2)")
	assert.Equal(t, ua.StatusOK, f.writeValue(t, b, gainID, 1.0))
	assert.Equal(t, int32(0), f.lockStatus(t, a, l, l+lockInit, ""))
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, b, gainID, 1.0))
	assert.Equal(t, int32(0), f.lockStatus(t, b, controlID+blockLock, controlID+blockLock+lockBreak))
	assert.Equal(t, true, f.value(t, controlID+isControlled), "BreakLock leaves IsControlled")

	// The Locks a session took go when it ends (OPC 10000-100 §7.2);
	// IsControlled stays.
	require.NoError(t, a.Close(context.Background()))
	require.Eventually(t, func() bool {
		locked, _, _ := f.lockProps(t, l)
		return !locked
	}, 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, true, f.value(t, controlID+isControlled))
	assert.Equal(t, ua.StatusOK, f.writeValue(t, b, gainID, 1.0))
}

// TestLockTime: when Locks go and when they are renewed, on a clock the
// test moves (the monitor runs too, but time stands still for it):
//   - a Lock without activity goes after the MaxInactiveLockTime of its
//     folder, else of the server (Part 81 §6.5.6, OPC 10000-100 §7.4);
//     IsControlled stays;
//   - a write of the owner renews it (OPC 10000-100 §7.7), a write of
//     another client that the Lock refuses does not;
//   - the Locks of a ConnectionEndpoint whose Status is not Error are
//     renewed (Part 81 §6.5.2); without EnableCommunicationCmd the endpoint
//     stays Ready.
func TestLockTime(t *testing.T) {
	t.Parallel()
	f := newControlFX(t, fxserver.ConnectionOptions{MaxInactiveLockTime: time.Hour})
	clock := fakeclock.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	fxserver.SetLockClock(f.conns, clock.Now)
	tick := func(d time.Duration) {
		clock.Advance(d)
		fxserver.TickLocks(f.conns)
	}
	locked := func(l uint32) bool {
		v, _, _ := f.lockProps(t, l)
		return v
	}
	a, b := f.client(t, appA), f.client(t, appB)
	caps := f.srv.Node(ua.NewNumericNodeID(f.ns.DI, 6387))
	require.NotNil(t, caps)
	assert.Equal(t, float64(time.Hour/time.Millisecond), caps.Value().Value.Value(), "ServerCapabilities MaxInactiveLockTime")

	// Monitor: ListToRestrict has 300 ms, ListToBlock the hour of the server.
	require.Equal(t, int32(0), f.lockStatus(t, a, monitorID, monitorID+establishCtl, ""))
	tick(200 * time.Millisecond)
	require.Equal(t, ua.StatusOK, f.writeValue(t, a, gainID, 1.0), "renews to 500 ms")
	require.Equal(t, ua.StatusBadLocked, f.writeValue(t, b, gainID, 1.0), "renews nothing")
	tick(299 * time.Millisecond)
	assert.True(t, locked(monitorID+restrictLock), "at 499 ms")
	tick(2 * time.Millisecond)
	assert.False(t, locked(monitorID+restrictLock), "at 501 ms")
	assert.True(t, locked(monitorID+blockLock), "the hour of the server")
	assert.Equal(t, true, f.value(t, monitorID+isControlled))
	assert.Equal(t, int32(-1), f.lockStatus(t, a, monitorID+restrictLock, monitorID+restrictLock+lockRenew))

	// RenewLock renews.
	tick(59 * time.Minute)
	assert.Equal(t, int32(0), f.lockStatus(t, a, monitorID+blockLock, monitorID+blockLock+lockRenew))
	tick(59 * time.Minute)
	assert.True(t, locked(monitorID+blockLock), "renewed after 59 minutes")
	tick(2 * time.Minute)
	assert.False(t, locked(monitorID+blockLock))
	_, sc := f.call(t, a, monitorID, monitorID+releaseCtl)
	require.Equal(t, ua.StatusOK, sc)

	// An endpoint keeps its Locks; a client's Lock taken with them goes.
	r := f.controlRequest("Renewed")
	r.CommandMask &^= uafx.EnableCommunicationCmd
	res := f.establish(t, r)
	require.Equal(t, ua.StatusOK, res.Status)
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	require.Equal(t, int32(0), f.lockStatus(t, a, monitorID+blockLock, monitorID+blockLock+lockInit, ""))
	tick(2 * time.Hour)
	for _, l := range []uint32{controlID + blockLock, controlID + restrictLock} {
		v, _, user := f.lockProps(t, l)
		assert.True(t, v, "renewed past MaxInactiveLockTime")
		assert.Equal(t, "UAFX", user)
	}
	assert.False(t, locked(monitorID+blockLock), "the client's Lock")
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, f.c, gainID, 9.0))

	// Without ConnectionAdmin a client neither writes through the
	// endpoint's Lock with SetConfigurationDataCmd nor releases its
	// ControlGroups with CloseConnections and Remove; with it, it does.
	p := f.plainClient(t, appA)
	cr := f.configureAs(t, p, ep, gainID, 7.0)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied}, cr.ConnectionEndpointConfigurationResults[0].ConfigurationDataResult)
	assert.NotEqual(t, 7.0, f.value(t, gainID))
	sc, results, err := uafx.CloseConnections(context.Background(), p, f.id(ctlID), []*ua.NodeID{ep}, true)
	require.NoError(t, err)
	assert.Equal(t, ua.StatusUncertain, sc)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied}, results)
	assert.Equal(t, true, f.value(t, controlID+isControlled))
	assert.Len(t, f.conns.Endpoints(), 2, "Preset and Renewed")
	cr = f.configureAs(t, f.c, ep, gainID, 7.0)
	assert.Equal(t, ua.StatusOK, cr.Status)
	assert.Equal(t, 7.0, f.value(t, gainID))
	sc, _ = f.close(t, true, ep)
	require.Equal(t, ua.StatusOK, sc)
	assert.Equal(t, false, f.value(t, controlID+isControlled))
}

// TestControlItemLimit: an item of a ControlItemFolder that stands for more
// nodes than the limit fails EnableConnections instead of leaving the rest
// unprotected. Axis stands for itself, InputData, AxisIn and Home: a limit
// of 3 fails, 4 does not (on the same server, which a failed
// EnableConnections leaves usable).
func TestControlItemLimit(t *testing.T) {
	t.Parallel()
	srv := newServer(t, server.WithPubSub(nil))
	ns, _, err := fxtest.PrepareControlGroups(srv)
	require.NoError(t, err)
	opts := fxserver.ConnectionOptions{Logger: slog.New(slog.DiscardHandler)}
	_, err = fxserver.EnableConnections(srv, ns, fxserver.WithMaxControlled(opts, 3))
	require.ErrorIs(t, err, fxserver.ErrConnections)
	assert.ErrorContains(t, err, "more than 3 nodes")
	c, err := fxserver.EnableConnections(srv, ns, fxserver.WithMaxControlled(opts, 4))
	require.NoError(t, err)
	require.NoError(t, c.Close())
}

// configureAs runs SetConfigurationDataCmd for the existing
// ConnectionEndpoint ep of Motion with the client c: key is written v.
func (f *fx) configureAs(t *testing.T, c *opcua.Client, ep *ua.NodeID, key uint32, v any) *uafx.EstablishConnectionsResult {
	t.Helper()
	res, err := uafx.EstablishConnections(context.Background(), c, f.id(ctlID), &uafx.EstablishConnectionsRequest{
		CommandMask: uafx.SetConfigurationDataCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
			FunctionalEntityNode: f.id(motionID), ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Node: ep},
			ConfigurationData: []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: f.id(key)}, Value: ua.MustVariant(v)}},
		}},
	})
	require.NoError(t, err)
	return res
}

// controlRequest establishes control of Control, writes Gain and reassigns
// control to the created endpoint (the example of Part 81 §D.3).
func (f *fx) controlRequest(name string) *uafx.EstablishConnectionsRequest {
	r := f.fullRequest(name)
	r.CommandMask |= uafx.EstablishControlCmd | uafx.ReassignControlCmd
	r.ConnectionEndpointConfigurations[0].ControlGroups = []*ua.NodeID{f.id(controlID)}
	return r
}

// TestEstablishConnectionsControl: EstablishControlCmd controls a
// ControlGroup for the caller, SetConfigurationDataCmd writes as the owner
// and ReassignControlCmd gives it to the ConnectionEndpoint (Part 81
// §6.2.4.3.6 to §6.2.4.3.8, §6.5.2), which owns it until CloseConnections
// with Remove releases it (§6.2.5.2); and what EstablishControlCmd and
// ReassignControlCmd report when they fail, with the rollback of Table 21.
func TestEstablishConnectionsControl(t *testing.T) {
	t.Parallel()
	// One server: each case leaves it as it found it, which the next
	// checks. Its ControlAuthorizer records what it decides and allows
	// all, unless deny.
	var auth struct {
		sync.Mutex
		reqs []fxserver.ControlRequest
		deny bool
	}
	f := newControlFX(t, fxserver.ConnectionOptions{ControlAuthorizer: func(_ context.Context, r fxserver.ControlRequest) ua.StatusCode {
		auth.Lock()
		defer auth.Unlock()
		auth.reqs = append(auth.reqs, r)
		if auth.deny {
			return ua.StatusBadUserAccessDenied
		}
		return ua.StatusOK
	}})
	b := f.plainClient(t, appB)
	requests := func() []fxserver.ControlRequest {
		auth.Lock()
		defer auth.Unlock()
		out := auth.reqs
		auth.reqs = nil
		return out
	}
	release := func(t *testing.T, g uint32) {
		t.Helper()
		_, sc := f.call(t, b, g, g+releaseCtl)
		require.Equal(t, ua.StatusOK, sc)
	}

	t.Run("control and close", func(t *testing.T) {
		res := f.establish(t, f.controlRequest("Ctl"))
		er := res.ConnectionEndpointConfigurationResults[0]
		require.Equal(t, ua.StatusOK, res.Status, "%+v", er)
		assert.Equal(t, []ua.StatusCode{ua.StatusOK}, er.EstablishControlResult)
		assert.Equal(t, []ua.StatusCode{ua.StatusOK}, er.ReassignControlResult)
		assert.Equal(t, []ua.StatusCode{ua.StatusOK}, er.ConfigurationDataResult)
		assert.Equal(t, 2.5, f.value(t, gainID))
		ep := er.ConnectionEndpointID.String()

		// The commands ask the ControlAuthorizer, with the caller.
		reqs := requests()
		require.Len(t, reqs, 2)
		assert.Equal(t, fxserver.ControlEstablish, reqs[0].Operation)
		assert.Equal(t, f.id(controlID).String(), reqs[0].Group.String())
		require.NotNil(t, reqs[0].Caller)
		assert.Equal(t, reqs[0].Caller.ClientApplicationURI, reqs[0].LockContext)
		assert.Equal(t, fxserver.ControlReassign, reqs[1].Operation)
		assert.Equal(t, ep, reqs[1].LockContext)

		assert.Equal(t, true, f.value(t, controlID+isControlled))
		locked, client, user := f.lockProps(t, controlID+restrictLock)
		assert.True(t, locked)
		assert.Equal(t, ep, client)
		assert.Equal(t, "UAFX", user)
		assert.Equal(t, []string{ep}, f.controlledBy(t, controlID))

		// The endpoint's Locks are changed only as it.
		assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, f.c, gainID, 9.0))
		_, sc := f.call(t, f.c, controlID, controlID+releaseCtl)
		assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
		_, sc = f.call(t, f.c, controlID+restrictLock, controlID+restrictLock+lockExit)
		assert.Equal(t, ua.StatusBadUserAccessDenied, sc)

		// SetConfigurationDataCmd acts as the endpoint: Gain is written, Table
		// is blocked (Bad_UserAccessDenied, Table 14).
		cfg := func(key uint32, v any) *uafx.EstablishConnectionsResult {
			return f.establish(t, &uafx.EstablishConnectionsRequest{
				CommandMask: uafx.SetConfigurationDataCmd,
				ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
					FunctionalEntityNode: f.id(motionID), ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Node: er.ConnectionEndpointID},
					ConfigurationData: []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: f.id(key)}, Value: ua.MustVariant(v)}},
				}},
			})
		}
		requests()
		r := cfg(gainID, 3.5)
		assert.Equal(t, ua.StatusOK, r.Status)
		assert.Equal(t, 3.5, f.value(t, gainID))
		reqs = requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, fxserver.ControlWriteAsEndpoint, reqs[0].Operation)
		assert.Equal(t, ep, reqs[0].Endpoint.String())
		assert.Equal(t, f.id(gainID).String(), reqs[0].Node.String())
		assert.Equal(t, f.id(controlID+restrictLock).String(), reqs[0].Lock.String())
		r = cfg(tableID, []float64{9, 9, 9})
		assert.Equal(t, ua.StatusUncertain, r.Status)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied}, r.ConnectionEndpointConfigurationResults[0].ConfigurationDataResult)

		// CloseConnections without Remove keeps the Locks; with Remove they go.
		sc, _ = f.close(t, false, er.ConnectionEndpointID)
		require.Equal(t, ua.StatusOK, sc)
		locked, _, _ = f.lockProps(t, controlID+restrictLock)
		assert.True(t, locked)
		requests()
		sc, _ = f.close(t, true, er.ConnectionEndpointID)
		require.Equal(t, ua.StatusOK, sc)
		reqs = requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, fxserver.ControlCloseRemove, reqs[0].Operation)
		assert.Equal(t, ep, reqs[0].Endpoint.String())
		assert.Equal(t, false, f.value(t, controlID+isControlled))
		locked, client, _ = f.lockProps(t, controlID+restrictLock)
		assert.False(t, locked)
		assert.Empty(t, client)
		assert.Empty(t, f.controlledBy(t, controlID))
		assert.Equal(t, ua.StatusOK, f.writeValue(t, f.c, gainID, 9.0))
	})

	t.Run("denied", func(t *testing.T) {
		auth.Lock()
		auth.deny = true
		auth.Unlock()
		defer func() {
			auth.Lock()
			auth.deny = false
			auth.Unlock()
		}()
		res := f.establish(t, f.controlRequest("Denied"))
		er := res.ConnectionEndpointConfigurationResults[0]
		assert.Equal(t, ua.StatusUncertain, res.Status)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied}, er.EstablishControlResult)
		assert.Equal(t, false, f.value(t, controlID+isControlled))
		assert.Len(t, f.conns.Endpoints(), 1, "only Preset")
		_, sc := f.call(t, b, controlID, controlID+establishCtl, "")
		assert.Equal(t, ua.StatusBadUserAccessDenied, sc, "the Method too")
		requests()
	})

	// A session that ends during its EstablishConnections: the end waits
	// for the call, so ReassignControlCmd still finds the Locks of
	// EstablishControlCmd. The end is told while SetConfigurationDataCmd
	// writes Gain, between the two.
	t.Run("session ends during the call", func(t *testing.T) {
		ended := make(chan struct{})
		var once sync.Once
		hook := func(s *server.Session, n *ua.NodeID) {
			if s == nil || n.String() != f.id(gainID).String() {
				return
			}
			once.Do(func() {
				go func() {
					fxserver.SessionEnded(f.conns, s)
					close(ended)
				}()
				// Without the wait SessionEnded would be done by now.
				select {
				case <-ended:
				case <-time.After(200 * time.Millisecond):
				}
			})
		}
		f.hooks.onWrite.Store(&hook)
		defer f.hooks.onWrite.Store(nil)
		// Without the communication commands: "control and close" used
		// the PubSub configuration of fullRequest.
		r := f.controlRequest("Ending")
		r.CommandMask &^= uafx.SetCommunicationConfigurationCmd | uafx.EnableCommunicationCmd
		r.CommunicationConfigurations = nil
		r.ConnectionEndpointConfigurations[0].CommunicationLinks = nil
		res := f.establish(t, r)
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Fatal("SessionEnded was not called")
		}
		er := res.ConnectionEndpointConfigurationResults[0]
		require.Equal(t, ua.StatusOK, res.Status, "%+v", er)
		assert.Equal(t, []ua.StatusCode{ua.StatusOK}, er.ReassignControlResult)
		locked, client, _ := f.lockProps(t, controlID+restrictLock)
		assert.True(t, locked)
		assert.Equal(t, er.ConnectionEndpointID.String(), client)
		sc, _ := f.close(t, true, er.ConnectionEndpointID)
		require.Equal(t, ua.StatusOK, sc)
		assert.Equal(t, false, f.value(t, controlID+isControlled))
		requests()
	})

	t.Run("held by another client", func(t *testing.T) {
		require.Equal(t, int32(0), f.lockStatus(t, b, monitorID, monitorID+establishCtl, ""))
		res := f.establish(t, f.controlRequest("Held"))
		er := res.ConnectionEndpointConfigurationResults[0]
		assert.Equal(t, ua.StatusUncertain, res.Status)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadLocked}, er.EstablishControlResult)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadNothingToDo}, er.ReassignControlResult)
		assert.Equal(t, false, f.value(t, controlID+isControlled))
		assert.Len(t, f.conns.Endpoints(), 1, "only Preset")
		release(t, monitorID)
	})

	t.Run("rollback", func(t *testing.T) {
		r := f.controlRequest("Back")
		// Table is in ListToBlock: SetConfigurationDataCmd fails after
		// EstablishControlCmd, which is undone.
		r.ConnectionEndpointConfigurations[0].ConfigurationData = []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: f.id(tableID)}, Value: ua.MustVariant([]float64{1})}}
		res := f.establish(t, r)
		er := res.ConnectionEndpointConfigurationResults[0]
		assert.Equal(t, ua.StatusUncertain, res.Status)
		assert.Equal(t, []ua.StatusCode{ua.StatusOK}, er.EstablishControlResult)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied}, er.ConfigurationDataResult)
		assert.Equal(t, false, f.value(t, controlID+isControlled))
		locked, _, _ := f.lockProps(t, controlID+blockLock)
		assert.False(t, locked)
		assert.Equal(t, ua.StatusOK, f.writeValue(t, f.c, gainID, 1.0))
	})

	t.Run("reassign another's", func(t *testing.T) {
		require.Equal(t, int32(0), f.lockStatus(t, b, controlID, controlID+establishCtl, ""))
		r := f.fullRequest("Other")
		// Without SetConfigurationDataCmd: B restricts Gain.
		r.CommandMask = r.CommandMask&^uafx.SetConfigurationDataCmd | uafx.ReassignControlCmd
		r.ConnectionEndpointConfigurations[0].ControlGroups = []*ua.NodeID{f.id(controlID)}
		r.ConnectionEndpointConfigurations[0].ConfigurationData = nil
		res := f.establish(t, r)
		er := res.ConnectionEndpointConfigurationResults[0]
		assert.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied}, er.ReassignControlResult)
		_, client, _ := f.lockProps(t, controlID+restrictLock)
		assert.Equal(t, appB, client)
		release(t, controlID)
	})

	t.Run("reassign not controlled", func(t *testing.T) {
		r := f.fullRequest("Free")
		r.CommandMask |= uafx.ReassignControlCmd
		r.ConnectionEndpointConfigurations[0].ControlGroups = []*ua.NodeID{f.id(controlID)}
		res := f.establish(t, r)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadInvalidState}, res.ConnectionEndpointConfigurationResults[0].ReassignControlResult)
	})
}
