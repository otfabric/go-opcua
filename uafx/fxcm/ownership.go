// SPDX-License-Identifier: MIT

package fxcm

import (
	"strconv"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// Ownership is the class of a ConnectionEndpoint a ConnectionManager finds
// under the Name of an endpoint configuration of a set. Library
// interpretation (design §5.3): only a KnownOwned or TakenPreconfigured
// endpoint may be closed; §6.12 makes the Name unique within a
// FunctionalEntity, which identifies an endpoint, not who made it.
type Ownership int

// The ownership classes.
const (
	// Foreign: not made or taken by this ConnectionManager. Never touched.
	Foreign Ownership = iota
	// KnownOwned: this ConnectionManager created it, by the result of its
	// call or by the proof of ResolveLostResponse.
	KnownOwned
	// TakenPreconfigured: a preconfigured endpoint the set names as
	// preconfigured and a call of this ConnectionManager took. Closing it
	// with Remove TRUE releases it; the AC keeps it (§6.2.5.2).
	TakenPreconfigured
	// Unresolved: this ConnectionManager may have made it, without proof.
	// Reported, never closed, until a Reconcile or Settle decides it.
	Unresolved
)

func (o Ownership) String() string {
	switch o {
	case Foreign:
		return "Foreign"
	case KnownOwned:
		return "KnownOwned"
	case TakenPreconfigured:
		return "TakenPreconfigured"
	case Unresolved:
		return "Unresolved"
	}
	return "Ownership(" + strconv.Itoa(int(o)) + ")"
}

// MayClose reports whether a ConnectionManager may close an endpoint of
// the class o (CloseConnections, §6.2.5): KnownOwned and
// TakenPreconfigured.
func (o Ownership) MayClose() bool { return o == KnownOwned || o == TakenPreconfigured }

// RunID identifies one processing of one set within a ConnectionManager.
type RunID uint64

// EndpointRecord is what a ConnectionManager knows of an endpoint it made,
// took or may have made.
type EndpointRecord struct {
	Set      SetKey
	Endpoint EndpointRef
	// ServerURI, FunctionalEntity and Name place the endpoint: the
	// ApplicationUri of the server of the AutomationComponent, the
	// resolved FunctionalEntity and the BrowseName of the endpoint.
	ServerURI        string
	FunctionalEntity *ua.NodeID
	Name             string
	// NodeID is the endpoint, as the result of the call or a browse
	// returned it.
	NodeID *ua.NodeID
	Class  Ownership
	// Run and Version are the run that made or found it and the Version
	// of the set it processed.
	Run     RunID
	Version uint32
	// ClosePending is set when a close of a KnownOwned or
	// TakenPreconfigured endpoint failed or timed out (design §5.5).
	ClosePending bool
}

// Observed is an endpoint a browse of a FunctionalEntity found under a
// Name.
type Observed struct {
	NodeID *ua.NodeID
	// CMApplicationURI is the ConnectionManagerApplicationUri of the
	// endpoint (§6.6.2), nil when the AC does not expose it.
	CMApplicationURI *string
	// IsPreconfigured is the IsPreconfigured of the endpoint (§6.6.2).
	IsPreconfigured bool
	// InUse is set when the endpoint is in use by a Connection this
	// ConnectionManager did not make: for a preconfigured endpoint, a
	// RelatedEndpoint that is not the one this ConnectionManager set.
	InUse bool
}

func (o *Observed) ours(appURI string) bool {
	return o.CMApplicationURI != nil && appURI != "" && *o.CMApplicationURI == appURI
}

// Classify returns the class of obs, found under the Name of an endpoint
// configuration of a set, given rec, the record of this ConnectionManager
// for that endpoint configuration (nil when it has none), and appURI, the
// ApplicationUri of this ConnectionManager.
//
//   - With a record of the same NodeId, the class of the record, unless the
//     endpoint no longer matches it: a KnownOwned endpoint whose
//     ConnectionManagerApplicationUri is another is Unresolved, and so is a
//     TakenPreconfigured one that is no longer preconfigured, is in use by
//     another ConnectionManager (InUse), or has another
//     ConnectionManagerApplicationUri: another ConnectionManager may have
//     taken it since, and §6.2.5.2 keeping preconfigured objects does not
//     make closing its Connection safe. Unresolved is reported and never
//     closed, so that a takeover is seen, not undone.
//   - Without a matching record, an endpoint with this ConnectionManager's
//     ApplicationUri is Unresolved (§6.6.2 names an application, not a
//     call); anything else is Foreign.
func Classify(rec *EndpointRecord, obs *Observed, appURI string) Ownership {
	if rec != nil && rec.NodeID != nil && rec.NodeID.Equal(obs.NodeID) {
		switch rec.Class {
		case KnownOwned:
			if obs.CMApplicationURI != nil && !obs.ours(appURI) {
				return Unresolved
			}
			return KnownOwned
		case TakenPreconfigured:
			if !obs.IsPreconfigured || obs.InUse || obs.CMApplicationURI != nil && !obs.ours(appURI) {
				return Unresolved
			}
			return TakenPreconfigured
		case Unresolved:
			return Unresolved
		case Foreign:
		}
	}
	if obs.ours(appURI) {
		return Unresolved
	}
	return Foreign
}

// ScanVerdict is what step 0 of an establish run does with the Name of an
// endpoint configuration (design §5.2, §5.5).
type ScanVerdict int

// The verdicts of Scan.
const (
	// ScanCreate: nothing is there; create the endpoint.
	ScanCreate ScanVerdict = iota
	// ScanCloseFirst: a KnownOwned or TakenPreconfigured survivor; close it
	// with Remove TRUE, then create or take it again.
	ScanCloseFirst
	// ScanTake: a free preconfigured endpoint the set names as
	// preconfigured; the create command takes it (Table 79).
	ScanTake
	// ScanBlocked: a Foreign or Unresolved endpoint has the Name; the
	// Connection fails with CreateConnectionEndpointError and
	// ua.StatusBadBrowseNameDuplicated, without a call.
	ScanBlocked
)

func (v ScanVerdict) String() string {
	switch v {
	case ScanCreate:
		return "Create"
	case ScanCloseFirst:
		return "CloseFirst"
	case ScanTake:
		return "Take"
	case ScanBlocked:
		return "Blocked"
	}
	return "ScanVerdict(" + strconv.Itoa(int(v)) + ")"
}

// Scan returns the verdict of step 0 for an endpoint configuration that
// wants a preconfigured endpoint (IsPreconfigured, Table 79) or not, given
// rec (nil without one) and obs, the endpoint the browse found under the
// Name (nil when there is none), and the class of obs (Foreign when obs is
// nil).
func Scan(rec *EndpointRecord, obs *Observed, appURI string, preconfigured bool) (Ownership, ScanVerdict) {
	if obs == nil {
		return Foreign, ScanCreate
	}
	switch c := Classify(rec, obs, appURI); {
	case c.MayClose():
		return c, ScanCloseFirst
	case c == Foreign && preconfigured && obs.IsPreconfigured && !obs.InUse:
		return c, ScanTake
	default:
		return c, ScanBlocked
	}
}

// LostResponse is what a ConnectionManager knows of an endpoint that a
// call whose response was lost meant to create or take (design §5.4).
type LostResponse struct {
	// AbsentBefore is set when step 0 of the run found no endpoint under
	// the Name.
	AbsentBefore bool
	// Serialized is set when the (AC, FunctionalEntity) was serialized for
	// the run, so that no other run of this ConnectionManager can have
	// made an endpoint there.
	Serialized bool
	// Preconfigured is set when the call meant to take a preconfigured
	// endpoint.
	Preconfigured bool
	// Found are the endpoints the browse finds now under the Name.
	Found []Observed
	// RelatedEndpointOurs is set, for a preconfigured endpoint, when its
	// RelatedEndpoint is the one the call set.
	RelatedEndpointOurs bool
}

// ResolveLostResponse decides an endpoint after a lost response (design
// §5.4). absent is true when nothing was created or taken. Otherwise class
// is KnownOwned only when all hold: the Name was absent at step 0, the
// browse finds exactly one endpoint, its ConnectionManagerApplicationUri is
// exposed and is appURI, the (AC, FunctionalEntity) was serialized for the
// run, and exclusive is true: the deployment asserts that no other
// ConnectionManager uses appURI (§6.6.2 identifies an application, which a
// redundant pair or a copied configuration may share). A preconfigured
// endpoint is TakenPreconfigured when exactly one is found, its
// RelatedEndpoint is the one the call set, and nothing says another
// ConnectionManager uses it (InUse, another ConnectionManagerApplicationUri). Everything else is Unresolved:
// fail closed.
func ResolveLostResponse(lr LostResponse, appURI string, exclusive bool) (class Ownership, absent bool) {
	if len(lr.Found) == 0 {
		return Foreign, true
	}
	if lr.Preconfigured {
		if f := lr.Found; len(f) == 1 && f[0].IsPreconfigured && lr.RelatedEndpointOurs && !f[0].InUse &&
			(f[0].CMApplicationURI == nil || f[0].ours(appURI)) {
			return TakenPreconfigured, false
		}
		return Unresolved, false
	}
	if lr.AbsentBefore && len(lr.Found) == 1 && lr.Found[0].ours(appURI) && lr.Serialized && exclusive {
		return KnownOwned, false
	}
	return Unresolved, false
}

// Failure is the FxError and StatusCode of one failed operation of a run.
type Failure struct {
	FxError uafx.FxError
	Status  ua.StatusCode
}

// Transient reports whether f may clear when the set is processed again
// (§6.9.1: transient errors are cleared by processing again). Library
// interpretation (design §5.5): the session to the server
// (TargetServerConnectionError), a communication error or timeout, and a
// busy AC (Bad_Locked, Bad_TooManyOperations).
func (f Failure) Transient() bool {
	if f.FxError == uafx.FxErrorTargetServerConnectionError {
		return true
	}
	switch f.Status {
	case ua.StatusBadCommunicationError, ua.StatusBadTimeout, ua.StatusBadLocked, ua.StatusBadTooManyOperations:
		return true
	default:
		return false
	}
}

// consequence reports whether f only follows from another failure:
// ProcessingStopped and Rollback (§10.19), or no error.
func (f Failure) consequence() bool {
	switch f.FxError {
	case uafx.FxErrorNoError, uafx.FxErrorProcessingStopped, uafx.FxErrorRollback:
		return true
	default:
		return false
	}
}

// RetryAllowed reports whether a set in Error may be processed again by
// the ConnectionManager itself (design §5.5, decision D5): only when its
// last run failed, every failure of it is Transient (ProcessingStopped and
// Rollback follow from another failure and do not count), and the run left
// no Unresolved endpoint. An Unresolved endpoint stops automatic retries
// until a Reconcile or Settle clears it.
func RetryAllowed(failures []Failure, unresolved int) bool {
	if unresolved > 0 {
		return false
	}
	n := 0
	for _, f := range failures {
		if f.consequence() {
			continue
		}
		if !f.Transient() {
			return false
		}
		n++
	}
	return n > 0
}
