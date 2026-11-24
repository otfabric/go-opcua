// SPDX-License-Identifier: MIT

package fxcm

import (
	"errors"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// TestTransitions checks Table 91 and Table 92 of §6.9.2.
func TestTransitions(t *testing.T) {
	for _, tc := range []struct {
		t        Transition
		name     string
		from, to State
		id       uint32
		event    uint32
	}{
		{ReadyToProcessing, "ReadyToProcessing", StateReady, StateProcessing, fxcmid.ConnectionConfigurationSetStateMachineTypeReadyToProcessing, fxcmid.ConnectionConfigurationSetProcessingStartedEventType},
		{ProcessingToReady, "ProcessingToReady", StateProcessing, StateReady, fxcmid.ConnectionConfigurationSetStateMachineTypeProcessingToReady, fxcmid.ConnectionConfigurationSetProcessingSucceededEventType},
		{ProcessingToError, "ProcessingToError", StateProcessing, StateError, fxcmid.ConnectionConfigurationSetStateMachineTypeProcessingToError, fxcmid.ConnectionConfigurationSetProcessingFailedEventType},
		{ErrorToProcessing, "ErrorToProcessing", StateError, StateProcessing, fxcmid.ConnectionConfigurationSetStateMachineTypeErrorToProcessing, fxcmid.ConnectionConfigurationSetProcessingStartedEventType},
		{Transition(9), "Transition(9)", 0, 0, 0, 0},
	} {
		if tc.t.String() != tc.name || tc.t.From() != tc.from || tc.t.To() != tc.to || tc.t.ID() != tc.id || tc.t.Event() != tc.event {
			t.Errorf("%v: %v %v %d %d", tc.t, tc.t.From(), tc.t.To(), tc.t.ID(), tc.t.Event())
		}
	}
	for _, tc := range []struct {
		s    State
		name string
		id   uint32
	}{
		{StateReady, "Ready", fxcmid.ConnectionConfigurationSetStateMachineTypeReady},
		{StateProcessing, "Processing", fxcmid.ConnectionConfigurationSetStateMachineTypeProcessing},
		{StateError, "Error", fxcmid.ConnectionConfigurationSetStateMachineTypeError},
		{State(0), "State(0)", 0},
	} {
		if tc.s.String() != tc.name || tc.s.ID() != tc.id {
			t.Errorf("%v: %q %d", tc.s, tc.s.String(), tc.s.ID())
		}
	}
}

func TestStartFinish(t *testing.T) {
	if tr, err := Start(StateReady); err != nil || tr != ReadyToProcessing {
		t.Errorf("Start(Ready) %v %v", tr, err)
	}
	if tr, err := Start(StateError); err != nil || tr != ErrorToProcessing {
		t.Errorf("Start(Error) %v %v", tr, err)
	}
	if _, err := Start(StateProcessing); !errors.Is(err, ua.StatusBadInvalidState) || !errors.Is(err, ErrManager) {
		t.Errorf("Start(Processing) %v, want Bad_InvalidState (Table 86)", err)
	}
	if tr, err := Finish(StateProcessing, false); err != nil || tr != ProcessingToReady {
		t.Errorf("Finish ok %v %v", tr, err)
	}
	if tr, err := Finish(StateProcessing, true); err != nil || tr != ProcessingToError {
		t.Errorf("Finish failed %v %v", tr, err)
	}
	for _, s := range []State{StateReady, StateError} {
		if _, err := Finish(s, false); StatusOf(err) != ua.StatusBadInvalidState {
			t.Errorf("Finish(%v) %v", s, err)
		}
	}
}
