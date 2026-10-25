// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The condition methods of Part 9 1.05: the optional AlarmConditionType
// states, dialogs, the *2 variants with a Comment, GetGroupMemberships, and
// the audit events of the condition methods.

func (c *Client) conditionCall(ctx context.Context, conditionID *ua.NodeID, method uint32, args ...*ua.Variant) error {
	return c.callStatus(ctx, conditionID, ua.NewNumericNodeID(0, method), args...)
}

// Suppress suppresses an alarm (Part 9 §5.8, SuppressedState). The alarm
// must have the optional SuppressedState; a suppressed alarm stays
// suppressed.
func (c *Client) Suppress(ctx context.Context, conditionID *ua.NodeID) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypeSuppress)
}

// Suppress2 is Suppress with a Comment, which becomes the Comment of the
// condition when not empty.
func (c *Client) Suppress2(ctx context.Context, conditionID *ua.NodeID, comment string) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypeSuppress2, c.commentArg(comment))
}

// Unsuppress ends the suppression of an alarm.
func (c *Client) Unsuppress(ctx context.Context, conditionID *ua.NodeID) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypeUnsuppress)
}

// Unsuppress2 is Unsuppress with a Comment.
func (c *Client) Unsuppress2(ctx context.Context, conditionID *ua.NodeID, comment string) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypeUnsuppress2, c.commentArg(comment))
}

// RemoveFromService takes an alarm out of service (OutOfServiceState).
func (c *Client) RemoveFromService(ctx context.Context, conditionID *ua.NodeID) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypeRemoveFromService)
}

// RemoveFromService2 is RemoveFromService with a Comment.
func (c *Client) RemoveFromService2(ctx context.Context, conditionID *ua.NodeID, comment string) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypeRemoveFromService2, c.commentArg(comment))
}

// PlaceInService puts an alarm back in service.
func (c *Client) PlaceInService(ctx context.Context, conditionID *ua.NodeID) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypePlaceInService)
}

// PlaceInService2 is PlaceInService with a Comment.
func (c *Client) PlaceInService2(ctx context.Context, conditionID *ua.NodeID, comment string) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypePlaceInService2, c.commentArg(comment))
}

// Silence silences an alarm (SilenceState) until it becomes active again.
func (c *Client) Silence(ctx context.Context, conditionID *ua.NodeID) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypeSilence)
}

// Reset resets a latched alarm (LatchedState) that is no longer active; the
// server refuses to reset an active alarm (ua.StatusBadInvalidState on a
// go-opcua server).
func (c *Client) Reset(ctx context.Context, conditionID *ua.NodeID) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypeReset)
}

// Reset2 is Reset with a Comment.
func (c *Client) Reset2(ctx context.Context, conditionID *ua.NodeID, comment string) error {
	return c.conditionCall(ctx, conditionID, id.AlarmConditionTypeReset2, c.commentArg(comment))
}

// GetGroupMemberships returns the AlarmGroups an alarm is a member of
// (Part 9 §5.8).
func (c *Client) GetGroupMemberships(ctx context.Context, conditionID *ua.NodeID) ([]*ua.NodeID, error) {
	res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: conditionID, MethodID: ua.NewNumericNodeID(0, id.AlarmConditionTypeGetGroupMemberships)})
	if err != nil {
		return nil, err
	}
	if res.StatusCode != ua.StatusOK {
		return nil, res.StatusCode
	}
	if len(res.OutputArguments) != 1 || res.OutputArguments[0] == nil {
		return nil, fmt.Errorf("opcua: GetGroupMemberships: %d output arguments, want 1", len(res.OutputArguments))
	}
	switch v := res.OutputArguments[0].Value().(type) {
	case []*ua.NodeID:
		return v, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("opcua: GetGroupMemberships: output %T, want []*ua.NodeID", v)
	}
}

// Respond answers a dialog (DialogConditionType, Part 9 §5.6.3) with the
// index of one of its ResponseOptionSet. The error is
// ua.StatusBadDialogNotActive or ua.StatusBadDialogResponseInvalid when the
// server refuses the response.
func (c *Client) Respond(ctx context.Context, conditionID *ua.NodeID, selectedResponse int32) error {
	return c.conditionCall(ctx, conditionID, id.DialogConditionTypeRespond, ua.MustVariant(selectedResponse))
}

// Respond2 is Respond with a Comment (Part 9 §5.6.4).
func (c *Client) Respond2(ctx context.Context, conditionID *ua.NodeID, selectedResponse int32, comment string) error {
	return c.conditionCall(ctx, conditionID, id.DialogConditionTypeRespond2, ua.MustVariant(selectedResponse), c.commentArg(comment))
}

// TimedShelve2 is TimedShelve with a Comment.
func (c *Client) TimedShelve2(ctx context.Context, conditionID *ua.NodeID, d time.Duration, comment string) error {
	ss, err := c.shelvingState(ctx, conditionID)
	if err != nil {
		return err
	}
	return c.callStatus(ctx, ss, ua.NewNumericNodeID(0, id.ShelvedStateMachineTypeTimedShelve2),
		ua.MustVariant(float64(d)/float64(time.Millisecond)), c.commentArg(comment))
}

// OneShotShelve2 is OneShotShelve with a Comment.
func (c *Client) OneShotShelve2(ctx context.Context, conditionID *ua.NodeID, comment string) error {
	ss, err := c.shelvingState(ctx, conditionID)
	if err != nil {
		return err
	}
	return c.callStatus(ctx, ss, ua.NewNumericNodeID(0, id.ShelvedStateMachineTypeOneShotShelve2), c.commentArg(comment))
}

// Unshelve2 is Unshelve with a Comment.
func (c *Client) Unshelve2(ctx context.Context, conditionID *ua.NodeID, comment string) error {
	ss, err := c.shelvingState(ctx, conditionID)
	if err != nil {
		return err
	}
	return c.callStatus(ctx, ss, ua.NewNumericNodeID(0, id.ShelvedStateMachineTypeUnshelve2), c.commentArg(comment))
}

// --- audit events --------------------------------------------------------------

// auditFields are the fields of NewAuditConditionEventFilter, in order.
var auditFields = []conditionField{
	{"EventId", id.BaseEventType}, {"EventType", id.BaseEventType}, {"SourceNode", id.BaseEventType},
	{"SourceName", id.BaseEventType}, {"Time", id.BaseEventType}, {"Message", id.BaseEventType},
	{"ActionTimeStamp", id.AuditEventType}, {"Status", id.AuditEventType}, {"ServerId", id.AuditEventType},
	{"ClientAuditEntryId", id.AuditEventType}, {"ClientUserId", id.AuditEventType},
	{"MethodId", id.AuditUpdateMethodEventType}, {"InputArguments", id.AuditUpdateMethodEventType},
	{"ConditionEventId", id.AuditConditionCommentEventType}, {"Comment", id.AuditConditionCommentEventType},
	{"SelectedResponse", id.AuditConditionRespondEventType}, {"ShelvingTime", id.AuditConditionShelvingEventType},
}

// NewAuditConditionEventFilter returns an EventFilter for the audit events of
// condition methods (AuditConditionEventType and its subtypes, Part 9
// §5.10), for [ParseAuditConditionEvent].
func NewAuditConditionEventFilter() *ua.EventFilter {
	b := ua.NewEventFilter()
	for _, f := range auditFields {
		b.TypeDefinition(ua.NewNumericNodeID(0, f.typeDef)).SelectPaths(f.path)
	}
	b.Where(&ua.ContentFilterElement{
		FilterOperator: ua.FilterOperatorOfType,
		FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(ua.NewNumericNodeID(0, id.AuditConditionEventType))})},
	})
	return b.Build()
}

// AuditConditionEvent is an audit event of a condition method received
// through [NewAuditConditionEventFilter].
type AuditConditionEvent struct {
	EventID   []byte
	EventType *ua.NodeID
	// SourceNode is the ConditionId.
	SourceNode         *ua.NodeID
	SourceName         string
	Time               time.Time
	Message            string
	ActionTimeStamp    time.Time
	Status             bool
	ServerID           string
	ClientAuditEntryID string
	ClientUserID       string
	MethodID           *ua.NodeID
	InputArguments     []*ua.Variant
	// ConditionEventID and Comment are those of AddComment, Acknowledge
	// and Confirm; SelectedResponse of Respond; ShelvingTime of
	// TimedShelve.
	ConditionEventID []byte
	Comment          *ua.LocalizedText
	SelectedResponse *int32
	ShelvingTime     *time.Duration
}

// ParseAuditConditionEvent decodes the fields of an event of an item created
// with [NewAuditConditionEventFilter].
func ParseAuditConditionEvent(ev *ua.EventFieldList) (*AuditConditionEvent, error) {
	if ev == nil {
		return nil, fmt.Errorf("opcua: audit event: nil event")
	}
	if len(ev.EventFields) != len(auditFields) {
		return nil, fmt.Errorf("opcua: audit event: %d fields, want %d", len(ev.EventFields), len(auditFields))
	}
	val := func(i int) any {
		if ev.EventFields[i] == nil {
			return nil
		}
		return ev.EventFields[i].Value()
	}
	e := &AuditConditionEvent{}
	e.EventID, _ = val(0).([]byte)
	e.EventType, _ = val(1).(*ua.NodeID)
	e.SourceNode, _ = val(2).(*ua.NodeID)
	e.SourceName, _ = val(3).(string)
	e.Time, _ = val(4).(time.Time)
	if m, ok := val(5).(*ua.LocalizedText); ok && m != nil {
		e.Message = m.Text
	}
	e.ActionTimeStamp, _ = val(6).(time.Time)
	e.Status, _ = val(7).(bool)
	e.ServerID, _ = val(8).(string)
	e.ClientAuditEntryID, _ = val(9).(string)
	e.ClientUserID, _ = val(10).(string)
	e.MethodID, _ = val(11).(*ua.NodeID)
	e.InputArguments, _ = val(12).([]*ua.Variant)
	e.ConditionEventID, _ = val(13).([]byte)
	e.Comment, _ = val(14).(*ua.LocalizedText)
	if r, ok := val(15).(int32); ok {
		e.SelectedResponse = &r
	}
	if ms, ok := val(16).(float64); ok {
		d := time.Duration(ms * float64(time.Millisecond))
		e.ShelvingTime = &d
	}
	return e, nil
}

// auditEntryKey carries the AuditEntryId of WithAuditEntryID.
type auditEntryKey struct{}

// WithAuditEntryID returns a context whose requests carry auditEntryID as
// the AuditEntryId of their RequestHeader (Part 4 §7.33), unless the request
// sets one itself. A server reports it as the ClientAuditEntryId of the
// audit events of the request.
func WithAuditEntryID(ctx context.Context, auditEntryID string) context.Context {
	return context.WithValue(ctx, auditEntryKey{}, auditEntryID)
}

// applyAuditEntryID sets the AuditEntryId of WithAuditEntryID on req.
func applyAuditEntryID(ctx context.Context, req ua.Request) {
	ae, ok := ctx.Value(auditEntryKey{}).(string)
	if !ok || ae == "" || req == nil {
		return
	}
	hdr := req.Header()
	if hdr == nil {
		req.SetHeader(&ua.RequestHeader{AuditEntryID: ae})
		return
	}
	if hdr.AuditEntryID == "" {
		cp := *hdr
		cp.AuditEntryID = ae
		req.SetHeader(&cp)
	}
}
