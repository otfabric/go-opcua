// SPDX-License-Identifier: MIT

package fxcm

import (
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// Activity returns the LastActivity bit of the action (§10.30), 0 for an
// unknown action.
func Activity(action uafx.FxProcess) uafx.LastActivityMask {
	switch action {
	case uafx.ActionEstablishConnectionsEnabled:
		return uafx.LastActivityEstablishEnabled
	case uafx.ActionEstablishConnectionsDisabled:
		return uafx.LastActivityEstablishDisabled
	case uafx.ActionEstablishConnections:
		return uafx.LastActivityEstablish
	case uafx.ActionRemoveConnections:
		return uafx.LastActivityRemove
	case uafx.ActionEnableConnections:
		return uafx.LastActivityEnable
	case uafx.ActionDisableConnections:
		return uafx.LastActivityDisable
	}
	return 0
}

// OutcomeKind is what the last processing did to an endpoint of a
// Connection (§10.19).
type OutcomeKind int

// The kinds of Outcome.
const (
	// Succeeded: all required operations finished successfully.
	Succeeded OutcomeKind = iota
	// Failed: an operation failed; the Outcome has its FxError and
	// StatusCode.
	Failed
	// Stopped: operations were skipped because of a failure not directly
	// related to this Connection.
	Stopped
	// RolledBack: established, then removed by the rollback.
	RolledBack
)

// Outcome is the result of the last processing for one endpoint.
type Outcome struct {
	Kind    OutcomeKind
	FxError uafx.FxError
	Status  ua.StatusCode
}

// FailedWith returns the Outcome of a failed operation.
func FailedWith(fx uafx.FxError, status ua.StatusCode) Outcome {
	return Outcome{Kind: Failed, FxError: fx, Status: status}
}

// fields returns ErrorEndpoint and EndpointStatus of o (§10.19). The
// StatusCode of a failure is kept as reported, Uncertain included (§10.19
// allows a generic Bad, it does not ask for one). Library interpretation:
// the fields of a failure are never NoError and Good, so a Failed Outcome
// without an FxError is UnknownStatus and one with a Good StatusCode is
// Bad.
func (o Outcome) fields() (uafx.FxError, ua.StatusCode) {
	switch o.Kind {
	case Failed:
		fx, st := o.FxError, o.Status
		if fx == uafx.FxErrorNoError {
			fx = uafx.FxErrorUnknownStatus
		}
		if st&0xC0000000 == 0 { // Severity Good: the top two bits are 00
			st = ua.StatusBad
		}
		return fx, st
	case Stopped:
		return uafx.FxErrorProcessingStopped, ua.StatusGood
	case RolledBack:
		return uafx.FxErrorRollback, ua.StatusGood
	default: // Succeeded
		return uafx.FxErrorNoError, ua.StatusGood
	}
}

// Diagnose returns the ConnectionDiagnostics of a Connection after a
// processing of its set with action (§10.19): the bit of the action in
// LastActivity, the others cleared; the Error bit when an endpoint did not
// succeed; per endpoint NoError and Good when it succeeded, its FxError and
// StatusCode when it failed, ProcessingStopped or Rollback with Good. ep2
// is nil for a Connection without Endpoint2, whose fields are NoError and
// Good. state is the ConnectionState (ConnectionStateOf).
func Diagnose(name *ua.QualifiedName, action uafx.FxProcess, state uafx.ConnectionState, ep1 Outcome, ep2 *Outcome) *uafx.ConnectionDiagnostics {
	d := &uafx.ConnectionDiagnostics{
		Name:            name,
		LastActivity:    Activity(action),
		ConnectionState: state,
	}
	d.ErrorEndpoint1, d.Endpoint1Status = ep1.fields()
	d.ErrorEndpoint2, d.Endpoint2Status = uafx.FxErrorNoError, ua.StatusGood
	if ep2 != nil {
		d.ErrorEndpoint2, d.Endpoint2Status = ep2.fields()
	}
	if ep1.Kind != Succeeded || ep2 != nil && ep2.Kind != Succeeded {
		d.LastActivity |= uafx.LastActivityError
	}
	return d
}

// connectionStates maps a ConnectionEndpointStatus (§10.17) to the
// ConnectionState of the same name (§10.20), with the order of Figure 58
// for the states an established Connection can have.
var connectionStates = map[uafx.ConnectionEndpointStatus]uafx.ConnectionState{
	uafx.ConnectionEndpointInitial:        uafx.ConnectionInitial,
	uafx.ConnectionEndpointReady:          uafx.ConnectionReady,
	uafx.ConnectionEndpointPreOperational: uafx.ConnectionPreOperational,
	uafx.ConnectionEndpointOperational:    uafx.ConnectionOperational,
	uafx.ConnectionEndpointError:          uafx.ConnectionError,
}

// ConnectionStateOf returns the ConnectionState of a Connection (§10.20):
// NotMonitored when the ConnectionManager does not monitor it;
// NotEstablished when it is not established (before establishment, after
// removal, or when an endpoint disappeared); otherwise from the Status of
// its endpoints. For a Connection with two endpoints (bidirectional, or
// unidirectional with heartbeat, Figure 58): Initial when either is
// Initial, else Error when either is Error, else the lower of Ready,
// PreOperational and Operational. For an autonomous publisher or
// subscriber, ep2 nil (Figure 59): the state of ep1. A Status outside
// §10.17 is Error: library interpretation, fail closed.
func ConnectionStateOf(monitored, established bool, ep1 uafx.ConnectionEndpointStatus, ep2 *uafx.ConnectionEndpointStatus) uafx.ConnectionState {
	switch {
	case !monitored:
		return uafx.ConnectionNotMonitored
	case !established:
		return uafx.ConnectionNotEstablished
	}
	s1 := endpointState(ep1)
	if ep2 == nil {
		return s1
	}
	s2 := endpointState(*ep2)
	switch {
	case s1 == uafx.ConnectionInitial || s2 == uafx.ConnectionInitial:
		return uafx.ConnectionInitial
	case s1 == uafx.ConnectionError || s2 == uafx.ConnectionError:
		return uafx.ConnectionError
	}
	return min(s1, s2) // Ready < PreOperational < Operational
}

func endpointState(s uafx.ConnectionEndpointStatus) uafx.ConnectionState {
	if c, ok := connectionStates[s]; ok {
		return c
	}
	return uafx.ConnectionError
}
