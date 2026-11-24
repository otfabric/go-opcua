// SPDX-License-Identifier: MIT

package fxcm

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

const me = "urn:cm:me"

func TestOwnershipStrings(t *testing.T) {
	for o, s := range map[Ownership]string{Foreign: "Foreign", KnownOwned: "KnownOwned", TakenPreconfigured: "TakenPreconfigured", Unresolved: "Unresolved", 9: "Ownership(9)"} {
		if o.String() != s {
			t.Errorf("%d: %q", int(o), o.String())
		}
	}
	for v, s := range map[ScanVerdict]string{ScanCreate: "Create", ScanCloseFirst: "CloseFirst", ScanTake: "Take", ScanBlocked: "Blocked", 9: "ScanVerdict(9)"} {
		if v.String() != s {
			t.Errorf("%d: %q", int(v), v.String())
		}
	}
	for o, want := range map[Ownership]bool{Foreign: false, KnownOwned: true, TakenPreconfigured: true, Unresolved: false} {
		if o.MayClose() != want {
			t.Errorf("%v.MayClose %v", o, !want)
		}
	}
}

// TestScan checks the classes of design §5.3 and the verdicts of step 0
// (§5.2).
func TestScan(t *testing.T) {
	n1, n2 := ua.NewNumericNodeID(3, 1), ua.NewNumericNodeID(3, 2)
	other := "urn:cm:other"
	rec := func(c Ownership) *EndpointRecord { return &EndpointRecord{NodeID: n1, Class: c} }
	obs := func(id *ua.NodeID, uri *string) *Observed { return &Observed{NodeID: id, CMApplicationURI: uri} }
	pre := func(inUse bool) *Observed { return &Observed{NodeID: n1, IsPreconfigured: true, InUse: inUse} }
	for _, tc := range []struct {
		name          string
		rec           *EndpointRecord
		obs           *Observed
		preconfigured bool
		class         Ownership
		verdict       ScanVerdict
	}{
		{"nothing there", nil, nil, false, Foreign, ScanCreate},
		{"nothing there, record of a vanished endpoint", rec(KnownOwned), nil, false, Foreign, ScanCreate},
		{"known-owned survivor", rec(KnownOwned), obs(n1, ptr(me)), false, KnownOwned, ScanCloseFirst},
		{"known-owned survivor, AC without the URI", rec(KnownOwned), obs(n1, nil), false, KnownOwned, ScanCloseFirst},
		{"known-owned, URI changed", rec(KnownOwned), obs(n1, ptr(other)), false, Unresolved, ScanBlocked},
		{"taken preconfigured survivor", rec(TakenPreconfigured), pre(false), true, TakenPreconfigured, ScanCloseFirst},
		{"taken preconfigured survivor with our URI", rec(TakenPreconfigured), &Observed{NodeID: n1, IsPreconfigured: true, CMApplicationURI: ptr(me)}, true, TakenPreconfigured, ScanCloseFirst},
		// Another ConnectionManager took it since: never closed (review of #45).
		{"taken preconfigured, now in use by another", rec(TakenPreconfigured), pre(true), true, Unresolved, ScanBlocked},
		{"taken preconfigured, now another URI", rec(TakenPreconfigured), &Observed{NodeID: n1, IsPreconfigured: true, CMApplicationURI: ptr(other)}, true, Unresolved, ScanBlocked},
		{"taken preconfigured, no longer preconfigured", rec(TakenPreconfigured), obs(n1, nil), true, Unresolved, ScanBlocked},
		{"unresolved stays", rec(Unresolved), obs(n1, ptr(me)), false, Unresolved, ScanBlocked},
		{"record of another node, our URI", rec(KnownOwned), obs(n2, ptr(me)), false, Unresolved, ScanBlocked},
		{"record of another node, other URI", rec(KnownOwned), obs(n2, ptr(other)), false, Foreign, ScanBlocked},
		{"a foreign record class", rec(Foreign), obs(n1, nil), false, Foreign, ScanBlocked},
		{"no record, our URI", nil, obs(n1, ptr(me)), false, Unresolved, ScanBlocked},
		{"no record, other URI", nil, obs(n1, ptr(other)), false, Foreign, ScanBlocked},
		{"no record, no URI", nil, obs(n1, nil), false, Foreign, ScanBlocked},
		{"free preconfigured, wanted", nil, pre(false), true, Foreign, ScanTake},
		{"free preconfigured, not wanted", nil, pre(false), false, Foreign, ScanBlocked},
		{"preconfigured in use", nil, pre(true), true, Foreign, ScanBlocked},
		{"record without NodeId", &EndpointRecord{Class: KnownOwned}, obs(n1, ptr(other)), false, Foreign, ScanBlocked},
	} {
		c, v := Scan(tc.rec, tc.obs, me, tc.preconfigured)
		if c != tc.class || v != tc.verdict {
			t.Errorf("%s: %v %v, want %v %v", tc.name, c, v, tc.class, tc.verdict)
		}
	}
	// An empty ApplicationUri of the manager matches nothing.
	if c := Classify(nil, obs(n1, ptr("")), ""); c != Foreign {
		t.Errorf("empty URI: %v", c)
	}
}

// TestResolveLostResponse checks design §5.4: KnownOwned only with every
// proof, including the exclusive ApplicationUri; otherwise Unresolved.
func TestResolveLostResponse(t *testing.T) {
	ours := Observed{NodeID: ua.NewNumericNodeID(3, 1), CMApplicationURI: ptr(me)}
	proof := LostResponse{AbsentBefore: true, Serialized: true, Found: []Observed{ours}}
	for _, tc := range []struct {
		name      string
		lr        LostResponse
		exclusive bool
		class     Ownership
		absent    bool
	}{
		{"proven", proof, true, KnownOwned, false},
		{"not exclusive", proof, false, Unresolved, false},
		{"absent", LostResponse{AbsentBefore: true, Serialized: true}, true, Foreign, true},
		{"present before", LostResponse{Serialized: true, Found: []Observed{ours}}, true, Unresolved, false},
		{"not serialized", LostResponse{AbsentBefore: true, Found: []Observed{ours}}, true, Unresolved, false},
		{"two found", LostResponse{AbsentBefore: true, Serialized: true, Found: []Observed{ours, ours}}, true, Unresolved, false},
		{"no URI", LostResponse{AbsentBefore: true, Serialized: true, Found: []Observed{{NodeID: ours.NodeID}}}, true, Unresolved, false},
		{"other URI", LostResponse{AbsentBefore: true, Serialized: true, Found: []Observed{{NodeID: ours.NodeID, CMApplicationURI: ptr("urn:x")}}}, true, Unresolved, false},
		{"preconfigured taken", LostResponse{Preconfigured: true, RelatedEndpointOurs: true, Found: []Observed{{IsPreconfigured: true}}}, false, TakenPreconfigured, false},
		{"preconfigured, related endpoint not ours", LostResponse{Preconfigured: true, Found: []Observed{{IsPreconfigured: true}}}, true, Unresolved, false},
		{"preconfigured, not preconfigured now", LostResponse{Preconfigured: true, RelatedEndpointOurs: true, Found: []Observed{{}}}, true, Unresolved, false},
		{"preconfigured, in use by another", LostResponse{Preconfigured: true, RelatedEndpointOurs: true, Found: []Observed{{IsPreconfigured: true, InUse: true}}}, true, Unresolved, false},
		{"preconfigured, another URI", LostResponse{Preconfigured: true, RelatedEndpointOurs: true, Found: []Observed{{IsPreconfigured: true, CMApplicationURI: ptr("urn:x")}}}, true, Unresolved, false},
		{"preconfigured taken, our URI", LostResponse{Preconfigured: true, RelatedEndpointOurs: true, Found: []Observed{{IsPreconfigured: true, CMApplicationURI: ptr(me)}}}, false, TakenPreconfigured, false},
		{"preconfigured, two", LostResponse{Preconfigured: true, RelatedEndpointOurs: true, Found: []Observed{{IsPreconfigured: true}, {IsPreconfigured: true}}}, true, Unresolved, false},
	} {
		c, absent := ResolveLostResponse(tc.lr, me, tc.exclusive)
		if c != tc.class || absent != tc.absent {
			t.Errorf("%s: %v %v, want %v %v", tc.name, c, absent, tc.class, tc.absent)
		}
	}
}

func TestRetryAllowed(t *testing.T) {
	tsc := Failure{FxError: uafx.FxErrorTargetServerConnectionError, Status: ua.StatusBadNotConnected}
	timeout := Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadTimeout}
	locked := Failure{FxError: uafx.FxErrorEstablishControlError, Status: ua.StatusBadLocked}
	stopped := Failure{FxError: uafx.FxErrorProcessingStopped}
	rollback := Failure{FxError: uafx.FxErrorRollback}
	permanent := Failure{FxError: uafx.FxErrorResolvingPathsError, Status: ua.StatusBadNoMatch}
	for _, tc := range []struct {
		name       string
		failures   []Failure
		unresolved int
		want       bool
	}{
		{"transient", []Failure{tsc, timeout, locked, stopped, rollback}, 0, true},
		{"busy", []Failure{{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadTooManyOperations}}, 0, true},
		{"communication", []Failure{{FxError: uafx.FxErrorSetCommunicationConfigurationError, Status: ua.StatusBadCommunicationError}}, 0, true},
		{"unresolved endpoint", []Failure{timeout}, 1, false},
		{"a permanent failure", []Failure{tsc, permanent}, 0, false},
		{"only consequences", []Failure{stopped, rollback, {}}, 0, false},
		{"no failure", nil, 0, false},
	} {
		if got := RetryAllowed(tc.failures, tc.unresolved); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}
