// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// Run is one processing of one set: from transition 1 or 4 to transition 2
// or 3 (§6.9), of the Config of one Version, for one action.
type Run struct {
	id      RunID
	key     SetKey
	version uint32
	action  uafx.FxProcess
	done    chan struct{}
	result  *RunResult
	// tx is, with a Store, the set change this remove run journals
	// before its closes (design §6.2).
	tx *txPlan
}

// ID returns the id of the run, unique and increasing within its Manager.
func (r *Run) ID() RunID { return r.id }

// Key returns the set of the run.
func (r *Run) Key() SetKey { return r.key }

// Version returns the Version of the Config the run processes.
func (r *Run) Version() uint32 { return r.version }

// Action returns the action of the run: a value of FxProcessEnum,
// ActionReconcile, or ActionRemoveSet.
func (r *Run) Action() uafx.FxProcess { return r.action }

// Done is closed when the run has finished.
func (r *Run) Done() <-chan struct{} { return r.done }

// Wait waits for the end of the run and returns its result, or the error
// of ctx.
func (r *Run) Wait(ctx context.Context) (*RunResult, error) {
	select {
	case <-r.done:
		return r.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RunResult is what a finished run did.
type RunResult struct {
	// State is the state the set ended in, Ready or Error, and Transition
	// the transition that took it there (§6.9.2).
	State      State
	Transition Transition
	// Diagnostics are the ConnectionsDiagnostics after the run (§10.19).
	Diagnostics []*uafx.ConnectionDiagnostics
	// Failures are the failed operations, one per endpoint that failed.
	Failures []Failure
	// Created are the endpoints the run created or took, Closed those it
	// closed, Unresolved those whose ownership it could not decide (design
	// §5.4).
	Created    []EndpointRecord
	Closed     []EndpointRecord
	Unresolved []EndpointRecord
	// RolledBack is set when the run closed the endpoints of the set after
	// a failure (RollbackOnError, §6.8.2); RollbackComplete when every
	// close of the rollback succeeded.
	RolledBack       bool
	RollbackComplete bool
	// Adopted are the endpoints an establish run kept in place: proven
	// its own, of the configuration it processed and as configured
	// (design docs/design/uafx-persistent-connections.md §6.6), with a
	// Store.
	Adopted []EndpointRecord
}

// EventKind is the kind of an Event.
type EventKind int

// The kinds of Event.
const (
	// EventTransition: a set took Transition.
	EventTransition EventKind = iota + 1
	// EventCall: an EstablishConnections or CloseConnections call
	// returned; Method names it, Status is its outcome, Err a failure to
	// get one.
	EventCall
	// EventEndpoint: an endpoint was recorded, reclassified or forgotten
	// (Record; Closed when it was closed).
	EventEndpoint
	// EventSettle: Settle decided Record with Verdict.
	EventSettle
	// EventRetry: the set is processed again after Delay (RetryPolicy).
	EventRetry
	// EventMonitor: the monitor read a new Status of Record, or found it
	// gone (Err).
	EventMonitor
	// EventSetAdded: a set was added with Version 1 (Add, or ElementAdd of
	// Update).
	EventSetAdded
	// EventSetReplaced: a set was replaced by a new one of Version 1
	// (Replace, or ElementReplace of Update).
	EventSetReplaced
	// EventSetRemoved: a set was removed (Remove, or ElementRemove of
	// Update).
	EventSetRemoved
	// EventEditStarted: a set went into edit (StartEditing, §6.7.4).
	EventEditStarted
	// EventCommitted: the edit of a set was committed as Version
	// (CommitUpdates, §6.7.4).
	EventCommitted
	// EventEditEnded: the edit of a set ended without a commit
	// (DiscardUpdates, or its Lock went, §6.7.4).
	EventEditEnded
	// EventVerified: the verification of the records a Manager with a
	// Store loaded (design §6.4) decided Record (its new Class; Closed
	// when the record was dropped: its endpoint is absent or Foreign,
	// nothing was closed), or an attempt on the server at Address failed
	// (Err; Record nil).
	EventVerified
)

// Event is what an Observer receives.
type Event struct {
	Kind       EventKind
	Set        SetKey
	Run        RunID
	Transition Transition
	Method     string
	Address    string
	Status     ua.StatusCode
	Err        error
	Record     *EndpointRecord
	Closed     bool
	Verdict    Verdict
	Attempt    int
	// Version is the Version of the set after EventSetAdded,
	// EventSetReplaced and EventCommitted.
	Version uint32
	// Action is the action of the run of an EventTransition: the Action
	// of the processing events (§8.6 Table 114). ActionRemoveSet and
	// ActionReconcile are the runs of Remove and Reconcile.
	Action uafx.FxProcess
	// Connections are the Connections whose endpoints an EventCall
	// carried, each once, in the order of the call.
	Connections []string
	// CommandMask is the CommandMask of an EventCall of
	// EstablishConnections (§6.2.3).
	CommandMask uafx.FxCommandMask
	// Trace is the TraceContext of an EventCall with Options.TraceCalls:
	// the TraceId of the run and the SpanId of the SpanContext the call
	// passed (OPC 10000-26 §5.6.4, Part 81 §6.7.2). ParentSpanId and
	// ParentIdentifier are not set. Nil without Options.TraceCalls.
	Trace *ua.TraceContextDataType
	// Failures are the failures of the run, on the EventTransition at its
	// end: one per endpoint that failed, with the first failure of the
	// endpoint, and those without a Connection (Part 81 §8.10, §8.11).
	Failures []RunFailure
}

// Observer receives the Events of a Manager: transitions, calls, endpoints,
// settles, retries and monitor findings (design §4.3; the facts a
// ConnectionManagerLog of fxserver records, CM-8). It must not block, and
// it is called from several goroutines at once.
type Observer interface {
	Observe(Event)
}

// ObserverFunc is an Observer.
type ObserverFunc func(Event)

// Observe implements Observer.
func (f ObserverFunc) Observe(e Event) { f(e) }

// AddObserver adds an Observer besides Options.Observer, for example the
// address space of a server that exposes the Manager. remove removes it;
// after remove returns it receives no more Events.
func (m *Manager) AddObserver(o Observer) (remove func()) {
	m.obs.mu.Lock()
	defer m.obs.mu.Unlock()
	m.obs.next++
	n := m.obs.next
	if m.obs.list == nil {
		m.obs.list = map[int]Observer{}
	}
	m.obs.list[n] = o
	return func() {
		m.obs.mu.Lock()
		defer m.obs.mu.Unlock()
		delete(m.obs.list, n)
	}
}

func (m *Manager) observe(e Event) {
	if m.opts.Observer != nil {
		m.opts.Observer.Observe(e)
	}
	// The added Observers are called under a read lock, so that remove
	// waits for a call in progress.
	m.obs.mu.RLock()
	for _, o := range m.obs.list {
		o.Observe(e)
	}
	m.obs.mu.RUnlock()
	m.log.Debug("fxcm", "kind", e.Kind, "set", e.Set.String(), "run", e.Run, "transition", e.Transition,
		"method", e.Method, "address", e.Address, "status", e.Status, "error", e.Err)
}
