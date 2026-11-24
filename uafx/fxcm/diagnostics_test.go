// SPDX-License-Identifier: MIT

package fxcm

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

func TestActivity(t *testing.T) {
	for a, want := range map[uafx.FxProcess]uafx.LastActivityMask{
		uafx.ActionEstablishConnectionsEnabled:  uafx.LastActivityEstablishEnabled,
		uafx.ActionEstablishConnectionsDisabled: uafx.LastActivityEstablishDisabled,
		uafx.ActionEstablishConnections:         uafx.LastActivityEstablish,
		uafx.ActionRemoveConnections:            uafx.LastActivityRemove,
		uafx.ActionEnableConnections:            uafx.LastActivityEnable,
		uafx.ActionDisableConnections:           uafx.LastActivityDisable,
		uafx.FxProcess(42):                      0,
	} {
		if got := Activity(a); got != want {
			t.Errorf("%v: %v", a, got)
		}
	}
}

// TestDiagnose checks the rules of §10.19.
func TestDiagnose(t *testing.T) {
	name := &ua.QualifiedName{NamespaceIndex: 5, Name: "C1"}
	ok := Outcome{}
	failed := FailedWith(uafx.FxErrorCreateConnectionEndpointError, ua.StatusBadBrowseNameDuplicated)
	type fields struct {
		act uafx.LastActivityMask
		e1  uafx.FxError
		s1  ua.StatusCode
		e2  uafx.FxError
		s2  ua.StatusCode
	}
	est := uafx.LastActivityEstablish
	errBit := uafx.LastActivityError
	for _, tc := range []struct {
		name string
		ep1  Outcome
		ep2  *Outcome
		want fields
	}{
		{"all succeeded", ok, &ok, fields{est, uafx.FxErrorNoError, ua.StatusGood, uafx.FxErrorNoError, ua.StatusGood}},
		{"autonomous", ok, nil, fields{est, uafx.FxErrorNoError, ua.StatusGood, uafx.FxErrorNoError, ua.StatusGood}},
		{"endpoint 2 failed", ok, &failed, fields{est | errBit, uafx.FxErrorNoError, ua.StatusGood, uafx.FxErrorCreateConnectionEndpointError, ua.StatusBadBrowseNameDuplicated}},
		{"endpoint 1 failed, autonomous", failed, nil, fields{est | errBit, uafx.FxErrorCreateConnectionEndpointError, ua.StatusBadBrowseNameDuplicated, uafx.FxErrorNoError, ua.StatusGood}},
		{"stopped", Outcome{Kind: Stopped}, &Outcome{Kind: Stopped}, fields{est | errBit, uafx.FxErrorProcessingStopped, ua.StatusGood, uafx.FxErrorProcessingStopped, ua.StatusGood}},
		{"rolled back", Outcome{Kind: RolledBack}, &failed, fields{est | errBit, uafx.FxErrorRollback, ua.StatusGood, uafx.FxErrorCreateConnectionEndpointError, ua.StatusBadBrowseNameDuplicated}},
		{"failure without codes", FailedWith(uafx.FxErrorNoError, ua.StatusGood), nil, fields{est | errBit, uafx.FxErrorUnknownStatus, ua.StatusBad, uafx.FxErrorNoError, ua.StatusGood}},
		{"failure with an uncertain code, kept", FailedWith(uafx.FxErrorVerifyAssetError, ua.StatusUncertain), nil, fields{est | errBit, uafx.FxErrorVerifyAssetError, ua.StatusUncertain, uafx.FxErrorNoError, ua.StatusGood}},
		{"failure with a Good code with flags", FailedWith(uafx.FxErrorVerifyAssetError, ua.StatusCode(0x00000400)), nil, fields{est | errBit, uafx.FxErrorVerifyAssetError, ua.StatusBad, uafx.FxErrorNoError, ua.StatusGood}},
	} {
		d := Diagnose(name, uafx.ActionEstablishConnections, uafx.ConnectionNotMonitored, tc.ep1, tc.ep2)
		got := fields{d.LastActivity, d.ErrorEndpoint1, d.Endpoint1Status, d.ErrorEndpoint2, d.Endpoint2Status}
		if got != tc.want || d.Name != name || d.ConnectionState != uafx.ConnectionNotMonitored {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestConnectionStateOf checks §10.20 and Figures 58 and 59.
func TestConnectionStateOf(t *testing.T) {
	const (
		ini = uafx.ConnectionEndpointInitial
		rdy = uafx.ConnectionEndpointReady
		pre = uafx.ConnectionEndpointPreOperational
		op  = uafx.ConnectionEndpointOperational
		er  = uafx.ConnectionEndpointError
	)
	st := func(s uafx.ConnectionEndpointStatus) *uafx.ConnectionEndpointStatus { return &s }
	for _, tc := range []struct {
		monitored, established bool
		ep1                    uafx.ConnectionEndpointStatus
		ep2                    *uafx.ConnectionEndpointStatus
		want                   uafx.ConnectionState
	}{
		{false, true, op, st(op), uafx.ConnectionNotMonitored},
		{true, false, op, st(op), uafx.ConnectionNotEstablished},
		{true, true, op, st(op), uafx.ConnectionOperational},
		{true, true, op, st(pre), uafx.ConnectionPreOperational},
		{true, true, rdy, st(op), uafx.ConnectionReady},
		{true, true, pre, st(rdy), uafx.ConnectionReady},
		{true, true, er, st(ini), uafx.ConnectionInitial},
		{true, true, op, st(ini), uafx.ConnectionInitial},
		{true, true, op, st(er), uafx.ConnectionError},
		{true, true, er, st(rdy), uafx.ConnectionError},
		{true, true, op, st(77), uafx.ConnectionError},
		{true, true, pre, nil, uafx.ConnectionPreOperational},
		{true, true, ini, nil, uafx.ConnectionInitial},
		{true, true, er, nil, uafx.ConnectionError},
		{true, true, 77, nil, uafx.ConnectionError},
	} {
		if got := ConnectionStateOf(tc.monitored, tc.established, tc.ep1, tc.ep2); got != tc.want {
			t.Errorf("%v %v %v %v: %v, want %v", tc.monitored, tc.established, tc.ep1, tc.ep2, got, tc.want)
		}
	}
}
