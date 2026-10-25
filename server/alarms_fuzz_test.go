// SPDX-License-Identifier: MIT

package server

import (
	"slices"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// fuzzAlarmAnswers are the statuses the condition methods may answer.
var fuzzAlarmAnswers = []ua.StatusCode{
	ua.StatusOK, ua.StatusBadEventIDUnknown, ua.StatusBadConditionBranchAlreadyAcked,
	ua.StatusBadConditionBranchAlreadyConfirmed, ua.StatusBadConditionDisabled,
	ua.StatusBadConditionAlreadyEnabled, ua.StatusBadConditionAlreadyDisabled,
	ua.StatusBadConditionAlreadyShelved, ua.StatusBadConditionNotShelved,
	ua.StatusBadShelvingTimeOutOfRange, ua.StatusBadArgumentsMissing, ua.StatusBadTypeMismatch,
}

// FuzzConditionStateMachine: any sequence of application changes and method
// calls (with current, stale and garbage EventIds and arguments) never
// panics, answers only Part 9 status codes, keeps Retain consistent with the
// state (Part 9 §5.5.2) and keeps the event fields equal to the variables of
// the instance.
func FuzzConditionStateMachine(f *testing.F) {
	f.Add([]byte{0, 1, 4, 0, 5, 0, 2, 3, 6, 0, 7, 1, 8, 9})
	f.Add([]byte{3, 3, 4, 4, 0, 0, 1, 1, 10, 200, 11, 50, 12, 13})
	f.Add([]byte{0, 7, 2, 8, 9, 9, 10, 0, 10, 255, 5, 1, 6, 2})
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 256 {
			return
		}
		s, _, src := alarmTestServer(t)
		hi, lo := 80.0, 20.0
		c, err := s.AddCondition(ConditionConfig{Name: "F", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.ExclusiveLevelAlarmType),
			Confirmable: true, Shelving: true, Suppressible: true, MaxTimeShelved: 1 << 50, Limits: AlarmLimits{High: &hi, Low: &lo}})
		if err != nil {
			t.Fatal(err)
		}
		defer s.alarms.close()
		ctx := callerCtx(&ua.UserNameIdentityToken{UserName: "fuzz"})
		var stale []byte
		for i := 0; i < len(ops); i++ {
			arg := byte(0)
			if i+1 < len(ops) {
				arg = ops[i+1]
			}
			eventID := c.State().EventID
			switch arg % 3 {
			case 1:
				eventID = stale
			case 2:
				eventID = []byte{arg}
			}
			comment := ua.MustVariant(ua.NewLocalizedText(string(rune('a' + arg%26))))
			var sc ua.StatusCode
			switch ops[i] % 14 {
			case 0:
				_ = c.SetActive(arg%2 == 0)
			case 1:
				_ = c.SetSeverity(uint16(arg) * 4)
			case 2:
				_, sc = c.actionMethod(actionAcknowledge)(ctx, nil, nil, []*ua.Variant{ua.MustVariant(eventID), comment})
			case 3:
				_, sc = c.actionMethod(actionConfirm)(ctx, nil, nil, []*ua.Variant{ua.MustVariant(eventID), comment})
			case 4:
				_, sc = c.actionMethod(actionAddComment)(ctx, nil, nil, []*ua.Variant{ua.MustVariant(eventID), comment})
			case 5:
				_, sc = c.enableMethod(arg%2 == 0)(ctx, nil, nil, nil)
			case 6:
				_, sc = c.shelveMethod(OneShotShelved)(ctx, nil, nil, nil)
			case 7:
				_, sc = c.shelveMethod(Unshelved)(ctx, nil, nil, nil)
			case 8:
				// Long enough never to expire during the run; 0 is out of range.
				_, sc = c.shelveMethod(TimedShelved)(ctx, nil, nil, []*ua.Variant{ua.MustVariant(float64(arg) * 3.6e6)})
			case 9:
				_ = c.SetSuppressed(arg%2 == 0)
			case 10:
				_ = c.EvaluateLimits(float64(arg) / 2.55)
			case 11:
				_, sc = c.shelveMethod(TimedShelved)(ctx, nil, nil, []*ua.Variant{ua.MustVariant(int32(arg))})
			case 12:
				_, sc = c.actionMethod(actionAcknowledge)(ctx, nil, nil, []*ua.Variant{ua.MustVariant(eventID)})
			default:
				_ = c.Report()
			}
			if !slices.Contains(fuzzAlarmAnswers, sc) {
				t.Fatalf("op %d: unexpected status %v", ops[i], sc)
			}
			stale = eventID
			checkConditionConsistent(t, c)
		}
	})
}

func checkConditionConsistent(t *testing.T, c *Condition) {
	t.Helper()
	st := c.State()
	if want := st.Enabled && (st.Active || !st.Acked || !st.Confirmed); st.Retain != want {
		t.Fatalf("Retain %v for %+v", st.Retain, st)
	}
	c.mu.RLock()
	ev := c.eventLocked()
	c.mu.RUnlock()
	for i := range c.table {
		f := &c.table[i]
		if f.object || f.path == "ShelvingState/UnshelveTime" {
			continue
		}
		dv := c.valueFunc(f)()
		got := ev.Fields[f.path]
		if !st.Enabled && !f.always {
			if dv.Status != ua.StatusBadConditionDisabled || got.Value() != ua.StatusBadConditionDisabled {
				t.Fatalf("%s: disabled condition reads %v / %v", f.path, dv.Status, got.Value())
			}
			continue
		}
		if !variantEqualForTest(dv.Value, got) {
			t.Fatalf("%s: variable %v, event %v", f.path, dv.Value.Value(), got.Value())
		}
	}
	if so := ev.Fields["SuppressedOrShelved"]; st.Enabled && so.Value() != (st.Suppressed || st.Shelving != Unshelved) {
		t.Fatalf("SuppressedOrShelved %v for %+v", so.Value(), st)
	}
}

func variantEqualForTest(a, b *ua.Variant) bool {
	ea, err1 := ua.Encode(a)
	eb, err2 := ua.Encode(b)
	return err1 == nil && err2 == nil && string(ea) == string(eb)
}
