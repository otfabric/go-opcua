// SPDX-License-Identifier: MIT

package fxcm

import (
	"strconv"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// State is a state of the ConnectionConfigurationSetStateMachine (§6.9.2
// Table 91); its value is the StateNumber.
type State uint32

// The states of Table 91.
const (
	StateReady      State = 1
	StateProcessing State = 2
	StateError      State = 3
)

func (s State) String() string {
	switch s {
	case StateReady:
		return "Ready"
	case StateProcessing:
		return "Processing"
	case StateError:
		return "Error"
	}
	return "State(" + strconv.FormatUint(uint64(s), 10) + ")"
}

// ID returns the identifier of the state Object of the
// ConnectionConfigurationSetStateMachineType in the CM namespace (package
// fxcmid), 0 for an unknown state.
func (s State) ID() uint32 {
	switch s {
	case StateReady:
		return fxcmid.ConnectionConfigurationSetStateMachineTypeReady
	case StateProcessing:
		return fxcmid.ConnectionConfigurationSetStateMachineTypeProcessing
	case StateError:
		return fxcmid.ConnectionConfigurationSetStateMachineTypeError
	}
	return 0
}

// Transition is a transition of the ConnectionConfigurationSetStateMachine
// (§6.9.2 Table 91); its value is the TransitionNumber.
type Transition uint32

// The transitions of Table 91.
const (
	ReadyToProcessing Transition = 1
	ProcessingToReady Transition = 2
	ProcessingToError Transition = 3
	ErrorToProcessing Transition = 4
)

var transitions = map[Transition]struct {
	name     string
	from, to State
	id       uint32
	event    uint32
}{
	ReadyToProcessing: {"ReadyToProcessing", StateReady, StateProcessing, fxcmid.ConnectionConfigurationSetStateMachineTypeReadyToProcessing, fxcmid.ConnectionConfigurationSetProcessingStartedEventType},
	ProcessingToReady: {"ProcessingToReady", StateProcessing, StateReady, fxcmid.ConnectionConfigurationSetStateMachineTypeProcessingToReady, fxcmid.ConnectionConfigurationSetProcessingSucceededEventType},
	ProcessingToError: {"ProcessingToError", StateProcessing, StateError, fxcmid.ConnectionConfigurationSetStateMachineTypeProcessingToError, fxcmid.ConnectionConfigurationSetProcessingFailedEventType},
	ErrorToProcessing: {"ErrorToProcessing", StateError, StateProcessing, fxcmid.ConnectionConfigurationSetStateMachineTypeErrorToProcessing, fxcmid.ConnectionConfigurationSetProcessingStartedEventType},
}

func (t Transition) String() string {
	if d, ok := transitions[t]; ok {
		return d.name
	}
	return "Transition(" + strconv.FormatUint(uint64(t), 10) + ")"
}

// From returns the state the transition leaves, 0 for an unknown one.
func (t Transition) From() State { return transitions[t].from }

// To returns the state the transition enters, 0 for an unknown one.
func (t Transition) To() State { return transitions[t].to }

// ID returns the identifier of the transition Object in the CM namespace
// (package fxcmid), 0 for an unknown transition.
func (t Transition) ID() uint32 { return transitions[t].id }

// Event returns the identifier of the event type in the CM namespace that
// the transition has (§6.9.2 Table 92): ProcessingStarted for 1 and 4,
// ProcessingSucceeded for 2, ProcessingFailed for 3; 0 for an unknown
// transition.
func (t Transition) Event() uint32 { return transitions[t].event }

// Start returns the transition that starts the processing of a set in the
// state s: ReadyToProcessing or ErrorToProcessing (§6.9.2: transitions 1
// and 4 are started by ProcessConnectionConfigurationSets or by
// vendor-specific means). A set in Processing cannot be processed again:
// ua.StatusBadInvalidState (§6.7.5.2 Table 86).
func Start(s State) (Transition, error) {
	switch s {
	case StateReady:
		return ReadyToProcessing, nil
	case StateError:
		return ErrorToProcessing, nil
	default:
		return 0, managerError(ua.StatusBadInvalidState, "a set in %v cannot be processed", s)
	}
}

// Finish returns the transition that ends the processing of a set in the
// state s: ProcessingToReady when processing of all its Connections
// succeeded, ProcessingToError when any failed (§6.9.2). A set that is not
// in Processing is ua.StatusBadInvalidState.
func Finish(s State, failed bool) (Transition, error) {
	switch {
	case s != StateProcessing:
		return 0, managerError(ua.StatusBadInvalidState, "a set in %v is not being processed", s)
	case failed:
		return ProcessingToError, nil
	}
	return ProcessingToReady, nil
}
