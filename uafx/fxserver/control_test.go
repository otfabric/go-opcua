// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/fakeclock"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// The ControlGroups of fxtest.PrepareControlGroups and their members.
const (
	controlID = fxtest.ConnControl
	monitorID = fxtest.ConnMonitor
	resetID   = fxtest.ConnReset
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
	t.Cleanup(func() { _ = c.Close(ctx) })
	return c
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
	f.srv.RegisterMethod(f.id(motionID), f.id(resetID), func(context.Context, *ua.NodeID, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, ua.StatusOK
	})
	a, b := f.client(t, appA), f.client(t, appB)
	callReset := func(c *opcua.Client) ua.StatusCode {
		res, err := c.Call(context.Background(), &ua.CallMethodRequest{ObjectID: f.id(motionID), MethodID: f.id(resetID)})
		require.NoError(t, err)
		return res.StatusCode
	}

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
}

// TestLockingServices: InitLock, RenewLock, ExitLock and BreakLock of the
// Lock of a ControlItemFolder (OPC 10000-100 §7.5 to §7.8, Part 81 §6.5.6),
// and the end of the session that took a Lock (§7.2).
func TestLockingServices(t *testing.T) {
	t.Parallel()
	f := newControlFX(t, fxserver.ConnectionOptions{})
	a, b := f.client(t, appA), f.client(t, appB)
	l := uint32(controlID + restrictLock)

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
	assert.Equal(t, int32(0), f.lockStatus(t, b, l, l+lockBreak), "BreakLock is the AccessController's to allow")
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
	require.Equal(t, ua.StatusOK, f.establish(t, r).Status)
	require.Equal(t, int32(0), f.lockStatus(t, a, monitorID+blockLock, monitorID+blockLock+lockInit, ""))
	tick(2 * time.Hour)
	for _, l := range []uint32{controlID + blockLock, controlID + restrictLock} {
		v, _, user := f.lockProps(t, l)
		assert.True(t, v, "renewed past MaxInactiveLockTime")
		assert.Equal(t, "UAFX", user)
	}
	assert.False(t, locked(monitorID+blockLock), "the client's Lock")
	assert.Equal(t, ua.StatusBadLocked, f.writeValue(t, f.c, gainID, 9.0))
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
	// checks.
	f := newControlFX(t, fxserver.ConnectionOptions{})
	b := f.client(t, appB)
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
		r := cfg(gainID, 3.5)
		assert.Equal(t, ua.StatusOK, r.Status)
		assert.Equal(t, 3.5, f.value(t, gainID))
		r = cfg(tableID, []float64{9, 9, 9})
		assert.Equal(t, ua.StatusUncertain, r.Status)
		assert.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied}, r.ConnectionEndpointConfigurationResults[0].ConfigurationDataResult)

		// CloseConnections without Remove keeps the Locks; with Remove they go.
		sc, _ = f.close(t, false, er.ConnectionEndpointID)
		require.Equal(t, ua.StatusOK, sc)
		locked, _, _ = f.lockProps(t, controlID+restrictLock)
		assert.True(t, locked)
		sc, _ = f.close(t, true, er.ConnectionEndpointID)
		require.Equal(t, ua.StatusOK, sc)
		assert.Equal(t, false, f.value(t, controlID+isControlled))
		locked, client, _ = f.lockProps(t, controlID+restrictLock)
		assert.False(t, locked)
		assert.Empty(t, client)
		assert.Empty(t, f.controlledBy(t, controlID))
		assert.Equal(t, ua.StatusOK, f.writeValue(t, f.c, gainID, 9.0))
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
