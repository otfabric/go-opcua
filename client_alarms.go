// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// Alarms & Conditions (Part 9): the condition methods and ConditionRefresh
// on the client side, and an event filter for condition events.

// conditionField is a field of NewConditionEventFilter: a BrowsePath and the
// type that declares it.
type conditionField struct {
	path    string
	typeDef uint32
}

// conditionFields are the fields of NewConditionEventFilter after the
// ConditionId, in order.
var conditionFields = []conditionField{
	{"EventId", id.BaseEventType}, {"EventType", id.BaseEventType}, {"SourceNode", id.BaseEventType},
	{"SourceName", id.BaseEventType}, {"Time", id.BaseEventType}, {"Message", id.BaseEventType},
	{"Severity", id.BaseEventType},
	{"ConditionName", id.ConditionType}, {"ConditionClassId", id.ConditionType}, {"BranchId", id.ConditionType},
	{"Retain", id.ConditionType}, {"EnabledState/Id", id.ConditionType}, {"Quality", id.ConditionType},
	{"LastSeverity", id.ConditionType}, {"Comment", id.ConditionType}, {"ClientUserId", id.ConditionType},
	{"AckedState/Id", id.AcknowledgeableConditionType}, {"ConfirmedState/Id", id.AcknowledgeableConditionType},
	{"ActiveState/Id", id.AlarmConditionType}, {"SuppressedOrShelved", id.AlarmConditionType},
	{"ShelvingState/CurrentState/Id", id.AlarmConditionType},
	// Part 9 1.05 optional states, added after the v1.14.0 fields.
	{"SuppressedState/Id", id.AlarmConditionType}, {"OutOfServiceState/Id", id.AlarmConditionType},
	{"SilenceState/Id", id.AlarmConditionType}, {"LatchedState/Id", id.AlarmConditionType},
	{"DialogState/Id", id.DialogConditionType}, {"Prompt", id.DialogConditionType},
	{"LastResponse", id.DialogConditionType},
}

// conditionFieldsV114 is the number of fields of NewConditionEventFilter in
// v1.14.0; ParseConditionEvent accepts events of such a filter.
const conditionFieldsV114 = 21

// ConditionEventFields lists the fields [NewConditionEventFilter] selects
// after the ConditionId, as "/"-separated BrowsePaths.
func ConditionEventFields() []string {
	out := make([]string, len(conditionFields))
	for i, f := range conditionFields {
		out[i] = f.path
	}
	return out
}

// NewConditionEventFilter returns an EventFilter that selects the
// ConditionId (Part 9 §5.5.2) and the fields of [ConditionEventFields], each
// with the type that declares it, for [ParseConditionEvent]. It has no
// WhereClause: the RefreshStart and RefreshEnd events of a ConditionRefresh
// pass, as do events that are not condition events (with null condition
// fields).
func NewConditionEventFilter() *ua.EventFilter {
	b := ua.NewEventFilter().SelectConditionID()
	for _, f := range conditionFields {
		b.TypeDefinition(ua.NewNumericNodeID(0, f.typeDef)).SelectPaths(f.path)
	}
	return b.Build()
}

// ConditionEvent is a condition event received through
// [NewConditionEventFilter]. The pointer fields are nil when the condition
// does not have the state (or reports it as Bad_ConditionDisabled).
type ConditionEvent struct {
	ConditionID      *ua.NodeID
	EventID          []byte
	EventType        *ua.NodeID
	SourceNode       *ua.NodeID
	SourceName       string
	Time             time.Time
	Message          string
	Severity         uint16
	ConditionName    string
	ConditionClassID *ua.NodeID
	BranchID         *ua.NodeID
	Retain           bool
	Enabled          bool
	Quality          *ua.StatusCode
	LastSeverity     *uint16
	Comment          *ua.LocalizedText
	ClientUserID     string
	Acked            *bool
	Confirmed        *bool
	Active           *bool
	// SuppressedOrShelved and ShelvingState (the NodeId of the current
	// state of the ShelvedStateMachine) are those of an alarm.
	SuppressedOrShelved *bool
	ShelvingState       *ua.NodeID
	// Suppressed, OutOfService, Silenced and Latched are the optional
	// SuppressedState, OutOfServiceState, SilenceState and LatchedState of
	// an alarm (Part 9 §5.8.2); nil when the alarm does not have them.
	Suppressed   *bool
	OutOfService *bool
	Silenced     *bool
	Latched      *bool
	// DialogActive, Prompt and LastResponse are those of a dialog
	// (DialogConditionType, Part 9 §5.6).
	DialogActive *bool
	Prompt       *ua.LocalizedText
	LastResponse *int32
}

// IsBranch reports whether the event is that of a condition branch (Part 9
// §5.5.2): its BranchId is not null.
func (e *ConditionEvent) IsBranch() bool {
	if e.BranchID == nil {
		return false
	}
	if e.BranchID.Namespace() == 0 && e.BranchID.IntID() == 0 {
		k := e.BranchID.Type()
		return k != ua.NodeIDTypeTwoByte && k != ua.NodeIDTypeFourByte && k != ua.NodeIDTypeNumeric
	}
	return true
}

// IsRefreshStart reports whether the event is the RefreshStartEvent of a
// ConditionRefresh (Part 9 §5.11.2).
func (e *ConditionEvent) IsRefreshStart() bool { return isType(e.EventType, id.RefreshStartEventType) }

// IsRefreshEnd reports whether the event is the RefreshEndEvent of a
// ConditionRefresh (Part 9 §5.11.3).
func (e *ConditionEvent) IsRefreshEnd() bool { return isType(e.EventType, id.RefreshEndEventType) }

// isType reports whether n is the ns=0 numeric NodeId t, in any of its
// encodings (TwoByte, FourByte, Numeric; Part 6 §5.2.2.9): peers send the
// compact ones.
func isType(n *ua.NodeID, t uint32) bool {
	if n == nil || n.Namespace() != 0 || n.IntID() != t {
		return false
	}
	k := n.Type()
	return k == ua.NodeIDTypeTwoByte || k == ua.NodeIDTypeFourByte || k == ua.NodeIDTypeNumeric
}

// ParseConditionEvent decodes the fields of an event of an item created with
// [NewConditionEventFilter].
func ParseConditionEvent(ev *ua.EventFieldList) (*ConditionEvent, error) {
	if ev == nil {
		return nil, fmt.Errorf("opcua: condition event: nil event")
	}
	if n := len(ev.EventFields); n != len(conditionFields)+1 && n != conditionFieldsV114+1 {
		return nil, fmt.Errorf("opcua: condition event: %d fields, want %d", n, len(conditionFields)+1)
	}
	f := ev.EventFields
	val := func(i int) any {
		if i >= len(f) || f[i] == nil {
			return nil
		}
		return f[i].Value()
	}
	e := &ConditionEvent{}
	e.ConditionID, _ = val(0).(*ua.NodeID)
	e.EventID, _ = val(1).([]byte)
	e.EventType, _ = val(2).(*ua.NodeID)
	e.SourceNode, _ = val(3).(*ua.NodeID)
	e.SourceName, _ = val(4).(string)
	e.Time, _ = val(5).(time.Time)
	if m, ok := val(6).(*ua.LocalizedText); ok && m != nil {
		e.Message = m.Text
	}
	e.Severity, _ = val(7).(uint16)
	e.ConditionName, _ = val(8).(string)
	e.ConditionClassID, _ = val(9).(*ua.NodeID)
	e.BranchID, _ = val(10).(*ua.NodeID)
	e.Retain, _ = val(11).(bool)
	e.Enabled, _ = val(12).(bool)
	// A Quality of Bad_ConditionDisabled is the disabled condition's
	// placeholder, not its quality.
	if q, ok := val(13).(ua.StatusCode); ok && q != ua.StatusBadConditionDisabled {
		e.Quality = &q
	}
	if s, ok := val(14).(uint16); ok {
		e.LastSeverity = &s
	}
	e.Comment, _ = val(15).(*ua.LocalizedText)
	e.ClientUserID, _ = val(16).(string)
	e.Acked = boolField(val(17))
	e.Confirmed = boolField(val(18))
	e.Active = boolField(val(19))
	e.SuppressedOrShelved = boolField(val(20))
	e.ShelvingState, _ = val(21).(*ua.NodeID)
	e.Suppressed = boolField(val(22))
	e.OutOfService = boolField(val(23))
	e.Silenced = boolField(val(24))
	e.Latched = boolField(val(25))
	e.DialogActive = boolField(val(26))
	e.Prompt, _ = val(27).(*ua.LocalizedText)
	if r, ok := val(28).(int32); ok {
		e.LastResponse = &r
	}
	return e, nil
}

func boolField(v any) *bool {
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

// callStatus calls a method and returns its StatusCode as the error.
func (c *Client) callStatus(ctx context.Context, objectID, methodID *ua.NodeID, args ...*ua.Variant) error {
	res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: objectID, MethodID: methodID, InputArguments: args})
	if err != nil {
		return err
	}
	if res.StatusCode != ua.StatusOK {
		return res.StatusCode
	}
	return nil
}

// eventMethod calls a condition method that takes an EventId and a Comment.
func (c *Client) eventMethod(ctx context.Context, method uint32, conditionID *ua.NodeID, eventID []byte, comment string) error {
	return c.callStatus(ctx, conditionID, ua.NewNumericNodeID(0, method), ua.MustVariant(eventID), c.commentArg(comment))
}

// commentArg is a Comment argument. A non-empty comment carries the first
// session locale (Locales; "en-us" by default): open62541 1.5.9 ignores a
// Comment without a locale.
func (c *Client) commentArg(comment string) *ua.Variant {
	locale := ""
	if ids := c.cfg.session.LocaleIDs; comment != "" && len(ids) > 0 {
		locale = ids[0]
	}
	return ua.MustVariant(ua.NewLocalizedTextWithLocale(comment, locale))
}

// Acknowledge acknowledges the condition state of the event eventID (Part 9
// §5.7.3). An empty comment leaves the condition's Comment unchanged. The
// error is the StatusCode of a refused call, e.g.
// ua.StatusBadConditionBranchAlreadyAcked or ua.StatusBadEventIDUnknown.
func (c *Client) Acknowledge(ctx context.Context, conditionID *ua.NodeID, eventID []byte, comment string) error {
	return c.eventMethod(ctx, id.AcknowledgeableConditionTypeAcknowledge, conditionID, eventID, comment)
}

// Confirm confirms the condition state of the event eventID (Part 9 §5.7.4).
func (c *Client) Confirm(ctx context.Context, conditionID *ua.NodeID, eventID []byte, comment string) error {
	return c.eventMethod(ctx, id.AcknowledgeableConditionTypeConfirm, conditionID, eventID, comment)
}

// AddComment sets the Comment of the condition (Part 9 §5.5.6).
func (c *Client) AddComment(ctx context.Context, conditionID *ua.NodeID, eventID []byte, comment string) error {
	return c.eventMethod(ctx, id.ConditionTypeAddComment, conditionID, eventID, comment)
}

// EnableCondition enables a condition (Part 9 §5.5.4).
func (c *Client) EnableCondition(ctx context.Context, conditionID *ua.NodeID) error {
	return c.callStatus(ctx, conditionID, ua.NewNumericNodeID(0, id.ConditionTypeEnable))
}

// DisableCondition disables a condition (Part 9 §5.5.5).
func (c *Client) DisableCondition(ctx context.Context, conditionID *ua.NodeID) error {
	return c.callStatus(ctx, conditionID, ua.NewNumericNodeID(0, id.ConditionTypeDisable))
}

// ConditionRefresh asks the server to report the retained conditions to
// every event item of the subscription, between a RefreshStartEvent and a
// RefreshEndEvent (Part 9 §5.5.7). subscriptionID is the server's id of the
// subscription; [Subscription.ConditionRefresh] uses the current one.
func (c *Client) ConditionRefresh(ctx context.Context, subscriptionID uint32) error {
	return c.callStatus(ctx, ua.NewNumericNodeID(0, id.ConditionType),
		ua.NewNumericNodeID(0, id.ConditionTypeConditionRefresh), ua.MustVariant(subscriptionID))
}

// ConditionRefresh2 is ConditionRefresh for one event item (Part 9 §5.5.8);
// monitoredItemID is the server's id of the item.
func (c *Client) ConditionRefresh2(ctx context.Context, subscriptionID, monitoredItemID uint32) error {
	return c.callStatus(ctx, ua.NewNumericNodeID(0, id.ConditionType),
		ua.NewNumericNodeID(0, id.ConditionTypeConditionRefresh2), ua.MustVariant(subscriptionID), ua.MustVariant(monitoredItemID))
}

// ConditionRefresh calls ConditionRefresh for the subscription.
func (s *Subscription) ConditionRefresh(ctx context.Context) error {
	return s.c.ConditionRefresh(ctx, s.id())
}

// ConditionRefresh2 calls ConditionRefresh2 for an event item of the
// subscription, given by the id Monitor returned.
func (s *Subscription) ConditionRefresh2(ctx context.Context, monitoredItemID uint32) error {
	s.itemsMu.Lock()
	mid := s.serverItemIDNeedsLock(monitoredItemID)
	s.itemsMu.Unlock()
	return s.c.ConditionRefresh2(ctx, s.id(), mid)
}

// shelvingState resolves the ShelvingState object of an alarm.
func (c *Client) shelvingState(ctx context.Context, conditionID *ua.NodeID) (*ua.NodeID, error) {
	return c.Node(conditionID).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{NamespaceIndex: 0, Name: "ShelvingState"}})
}

// TimedShelve shelves an alarm for d (Part 9 §5.8.10.4).
func (c *Client) TimedShelve(ctx context.Context, conditionID *ua.NodeID, d time.Duration) error {
	ss, err := c.shelvingState(ctx, conditionID)
	if err != nil {
		return err
	}
	return c.callStatus(ctx, ss, ua.NewNumericNodeID(0, id.ShelvedStateMachineTypeTimedShelve),
		ua.MustVariant(float64(d)/float64(time.Millisecond)))
}

// OneShotShelve shelves an alarm until it becomes inactive (Part 9
// §5.8.10.3).
func (c *Client) OneShotShelve(ctx context.Context, conditionID *ua.NodeID) error {
	ss, err := c.shelvingState(ctx, conditionID)
	if err != nil {
		return err
	}
	return c.callStatus(ctx, ss, ua.NewNumericNodeID(0, id.ShelvedStateMachineTypeOneShotShelve))
}

// Unshelve unshelves an alarm (Part 9 §5.8.10.2).
func (c *Client) Unshelve(ctx context.Context, conditionID *ua.NodeID) error {
	ss, err := c.shelvingState(ctx, conditionID)
	if err != nil {
		return err
	}
	return c.callStatus(ctx, ss, ua.NewNumericNodeID(0, id.ShelvedStateMachineTypeUnshelve))
}
