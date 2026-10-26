// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// Historical events (Part 11 §5.4, §6.5.2, §6.9.4, §6.9.7).
//
// An Object or View whose EventNotifier attribute has the HistoryRead bit
// (Part 3 §5.4, Part 11 §5.4.4) is a HistoricalEventNode: the server hands
// every event reported on it to the [EventHistoryProvider] of the server,
// the events reported on the Server object and the other notifiers of a
// condition or an audit event included, as the event items of those
// notifiers receive them. Its HistoricalEventFilter Property (Part 11
// §5.4.2) selects what is stored: the events its WhereClause passes, with
// the fields of its SelectClauses. HistoryRead ReadEventDetails reads the
// history, HistoryUpdate UpdateEventDetails and DeleteEventDetails change it
// when the HistoryWrite bit is set too.

// HistoricalEvent is an event in the event history of a notifier. Fields
// holds its fields by their BrowsePath, the names joined with "/"
// ("EventId", "Time", "AckedState/Id"); the key "" holds the ConditionId of
// a condition event (the SelectClause with an empty BrowsePath and
// AttributeId NodeId, Part 9 §5.5.2). A field that is not there is null.
// Providers treat a HistoricalEvent as immutable.
type HistoricalEvent struct {
	Fields map[string]*ua.Variant
}

// historicalConditionIDKey is the key of the ConditionId in
// HistoricalEvent.Fields.
const historicalConditionIDKey = ""

// baseEventFields are the fields of a BaseEvent outside its Fields map.
var baseEventFields = []string{"EventId", "EventType", "SourceNode", "SourceName", "Time", "Message", "Severity"}

// keptEventFields are the fields the server always stores: the history needs
// them to order and to find the events, whatever the HistoricalEventFilter
// selects.
var keptEventFields = []string{"EventId", "EventType", "Time", "ReceiveTime"}

// NewHistoricalEvent returns the fields of ev as a HistoricalEvent, as a
// SelectClause of an event item would see them.
func NewHistoricalEvent(ev *BaseEvent) *HistoricalEvent {
	f := make(map[string]*ua.Variant, len(ev.Fields)+len(baseEventFields)+1)
	for k, v := range ev.Fields {
		if v != nil {
			f[k] = v
		}
	}
	for _, name := range baseEventFields {
		f[name] = resolveBaseEventField(ev, name)
	}
	if ev.conditionID != nil {
		f[historicalConditionIDKey] = ua.MustVariant(ev.conditionID)
	}
	return &HistoricalEvent{Fields: f}
}

// field returns the value of a field, nil if the event has none.
func (e *HistoricalEvent) field(name string) any {
	if e == nil {
		return nil
	}
	if v := e.Fields[name]; v != nil {
		return v.Value()
	}
	return nil
}

// EventID returns the EventId of the event (nil if it has none).
func (e *HistoricalEvent) EventID() []byte {
	b, _ := e.field("EventId").([]byte)
	return b
}

// Time returns the Time of the event (zero if it has none).
func (e *HistoricalEvent) Time() time.Time {
	t, _ := e.field("Time").(time.Time)
	return t
}

// EventType returns the EventType of the event (nil if it has none).
func (e *HistoricalEvent) EventType() *ua.NodeID {
	t, _ := e.field("EventType").(*ua.NodeID)
	return t
}

func (e *HistoricalEvent) eventField(clause *ua.SimpleAttributeOperand) *ua.Variant {
	if clause == nil {
		return ua.MustVariant(nil)
	}
	if v := e.Fields[clauseKey(clause)]; v != nil {
		return v
	}
	return ua.MustVariant(nil)
}

func (e *HistoricalEvent) eventTypeID() *ua.NodeID { return e.EventType() }

// replacing returns e as the replacement of old: the EventId, EventType and
// Time e does not give are those of old.
func (e *HistoricalEvent) replacing(old *HistoricalEvent) *HistoricalEvent {
	f := make(map[string]*ua.Variant, len(e.Fields)+3)
	for k, v := range e.Fields {
		f[k] = v
	}
	for _, name := range []string{"EventId", "EventType", "Time"} {
		if v := old.Fields[name]; f[name] == nil && v != nil {
			f[name] = v
		}
	}
	return &HistoricalEvent{Fields: f}
}

// clauseKey is the HistoricalEvent.Fields key a SelectClause refers to.
func clauseKey(clause *ua.SimpleAttributeOperand) string {
	if len(clause.BrowsePath) == 0 && clause.AttributeID == ua.AttributeIDNodeID {
		return historicalConditionIDKey
	}
	return eventFieldPath(clause.BrowsePath)
}

// EventHistoryOptions configure the event history of a notifier
// ([Server.EnableEventHistory]).
type EventHistoryOptions struct {
	// Writable sets the HistoryWrite bit of the EventNotifier: HistoryUpdate
	// may insert, replace, update and delete the events of the notifier.
	Writable bool
	// Filter is the HistoricalEventFilter Property (Part 11 §5.4.2): its
	// WhereClause selects the events stored, its SelectClauses the fields
	// stored (EventId, EventType, Time and ReceiveTime are always stored).
	// A client that reads a field the filter does not select gets
	// Bad_NoData for it (Part 11 §6.5.2.2). Nil stores whole events; the
	// Property then lists the fields of BaseEventType, as a guideline of
	// what the history holds.
	Filter *ua.EventFilter
}

// EnableEventHistory makes the Object or View notifier a HistoricalEventNode
// (Part 11 §5.4): it sets the SubscribeToEvents and HistoryRead bits of its
// EventNotifier attribute (and HistoryWrite with opts.Writable) and adds
// the HistoricalEventFilter Property. The events reported on the notifier
// from then on go to the [EventHistoryProvider] of the server; the default
// [*Historian] keeps them once EnableEvents was called for the notifier.
func (s *Server) EnableEventHistory(notifier *ua.NodeID, opts EventHistoryOptions) error {
	if notifier == nil {
		return ua.StatusBadNodeIDInvalid
	}
	n := s.Node(notifier)
	if n == nil {
		return ua.StatusBadNodeIDUnknown
	}
	if notifier.Namespace() == 0 {
		// Namespace 0 nodes are shared between servers.
		if own := s.ownNode(notifier.IntID()); own != nil {
			n = own
		}
	}
	if nc := n.NodeClass(); nc != ua.NodeClassObject && nc != ua.NodeClassView {
		return ua.StatusBadNodeClassInvalid
	}
	bits := eventNotifierOf(n) | byte(ua.EventNotifierTypeSubscribeToEvents|ua.EventNotifierTypeHistoryRead)
	if opts.Writable {
		bits |= byte(ua.EventNotifierTypeHistoryWrite)
	} else {
		bits &^= byte(ua.EventNotifierTypeHistoryWrite)
	}
	if err := n.SetAttribute(ua.AttributeIDEventNotifier, DataValueFromValue(bits)); err != nil {
		return err
	}
	s.histEventsAll.Store(notifier.String(), opts.Filter == nil)
	filter := opts.Filter
	if filter == nil {
		filter = ua.NewEventFilter().Select(baseEventFields...).Select("ReceiveTime").Build()
	}
	return s.setHistoricalEventFilter(n, filter)
}

// historicalEventFilterName is the BrowseName of the HistoricalEventFilter
// Property (Part 11 §5.4.2).
const historicalEventFilterName = "HistoricalEventFilter"

// setHistoricalEventFilter sets the HistoricalEventFilter Property of n,
// adding it if n has none.
func (s *Server) setHistoricalEventFilter(n *Node, filter *ua.EventFilter) error {
	val := func() *ua.DataValue { return DataValueFromValue(ua.NewExtensionObject(filter)) }
	if p := s.historicalEventFilterNode(n); p != nil {
		p.mu.Lock()
		p.val = val
		p.mu.Unlock()
		return nil
	}
	ns, err := s.Namespace(int(n.ID().Namespace()))
	if err != nil {
		return err
	}
	// "<id>.HistoricalEventFilter" in the namespace of the notifier, as the
	// other Properties the server generates (childPropertyID).
	pid := childPropertyID(n.ID(), historicalEventFilterName)
	p := NewNode(pid, Attributes{
		ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: historicalEventFilterName}),
		ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(historicalEventFilterName, "")),
		ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.EventFilter)),
		ua.AttributeIDValueRank:       DataValueFromValue(int32(-1)),
		ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
	}, nil, val)
	p = ns.AddNode(p)
	if tn := s.Node(ua.NewNumericNodeID(0, id.PropertyType)); tn != nil {
		p.AddRef(tn, RefType(id.HasTypeDefinition), true)
	}
	linkChild(n, p, id.HasProperty)
	return nil
}

// historicalEventFilterNode returns the HistoricalEventFilter Property of n
// (nil if it has none).
func (s *Server) historicalEventFilterNode(n *Node) *Node {
	for _, r := range n.refsSnapshot() {
		if r == nil || !r.IsForward || r.ReferenceTypeID == nil || r.ReferenceTypeID.IntID() != id.HasProperty ||
			r.BrowseName == nil || r.BrowseName.Name != historicalEventFilterName || r.NodeID == nil {
			continue
		}
		if p := s.Node(r.NodeID.NodeID); p != nil {
			return p
		}
	}
	return nil
}

// storageFilter returns the HistoricalEventFilter that decides what the
// history of notifier n stores; nil stores whole events.
func (s *Server) storageFilter(notifier *ua.NodeID, n *Node) *ua.EventFilter {
	if all, ok := s.histEventsAll.Load(notifier.String()); ok && all.(bool) {
		return nil
	}
	p := s.historicalEventFilterNode(n)
	if p == nil {
		return nil
	}
	dv := p.Value()
	if dv == nil || dv.Value == nil {
		return nil
	}
	eo, ok := dv.Value.Value().(*ua.ExtensionObject)
	if !ok || eo == nil {
		return nil
	}
	switch f := eo.Value.(type) {
	case *ua.EventFilter:
		return f
	case ua.EventFilter:
		return &f
	}
	return nil
}

// storedFields returns the keys of the fields a HistoricalEventFilter
// stores; nil for every field.
func storedFields(filter *ua.EventFilter) map[string]bool {
	if filter == nil {
		return nil
	}
	keys := make(map[string]bool, len(filter.SelectClauses)+len(keptEventFields))
	for _, c := range filter.SelectClauses {
		if c != nil {
			keys[clauseKey(c)] = true
		}
	}
	for _, k := range keptEventFields {
		keys[k] = true
	}
	return keys
}

// eventNotifierOf returns the EventNotifier attribute of n.
func eventNotifierOf(n *Node) byte {
	av, err := n.Attribute(ua.AttributeIDEventNotifier)
	if err != nil || av == nil || av.Value == nil || av.Value.Value == nil {
		return 0
	}
	switch v := av.Value.Value.Value().(type) {
	case byte:
		return v
	case int32:
		return byte(v)
	case uint32:
		return byte(v)
	}
	return 0
}

// recordEventHistory hands an event reported on notifier to the event
// history provider when notifier is a HistoricalEventNode. The
// HistoricalEventFilter decides whether, and with which fields, the event is
// stored. The history needs an EventId and a Time: an event without one
// gets them, and ReceiveTime is the time the event reached the history.
func (s *Server) recordEventHistory(notifier *ua.NodeID, event *BaseEvent) {
	h, _ := s.history()
	p, ok := h.(EventHistoryProvider)
	if !ok || notifier == nil || event == nil {
		return
	}
	n := s.Node(notifier)
	if n == nil || eventNotifierOf(n)&byte(ua.EventNotifierTypeHistoryRead) == 0 {
		return
	}
	filter := s.storageFilter(notifier, n)
	if filter != nil && filter.WhereClause != nil && len(filter.WhereClause.Elements) > 0 && !s.evalEventFilter(event, filter.WhereClause) {
		return
	}
	he := NewHistoricalEvent(event)
	if keys := storedFields(filter); keys != nil {
		for k := range he.Fields {
			if !keys[k] {
				delete(he.Fields, k)
			}
		}
	}
	now := time.Now()
	if len(he.EventID()) == 0 {
		he.Fields["EventId"] = ua.MustVariant(newEventID())
	}
	if he.Time().IsZero() {
		he.Fields["Time"] = ua.MustVariant(now)
	}
	if _, ok := he.field("ReceiveTime").(time.Time); !ok {
		he.Fields["ReceiveTime"] = ua.MustVariant(now)
	}
	p.RecordEvent(notifier, he)
}

// eventReadDetails returns the ReadEventDetails of HistoryRead details:
// ReadEventDetails, or ReadEventDetails2 without ReadModified (Part 11
// §6.5.2.3). supported is false for the event details the server does not
// serve (ReadModified, ReadEventDetailsSorted); ok is false for other
// details.
func eventReadDetails(details any) (d *ua.ReadEventDetails, supported, ok bool) {
	switch v := details.(type) {
	case *ua.ReadEventDetails:
		return v, v != nil, true
	case ua.ReadEventDetails:
		return &v, true, true
	case *ua.ReadEventDetails2:
		if v == nil || v.ReadModified {
			return nil, false, true
		}
		return &ua.ReadEventDetails{NumValuesPerNode: v.NumValuesPerNode, StartTime: v.StartTime, EndTime: v.EndTime, Filter: v.Filter}, true, true
	case ua.ReadEventDetails2:
		return eventReadDetails(&v)
	case *ua.ReadEventDetailsSorted, ua.ReadEventDetailsSorted:
		// No SortByEventFields are offered (Part 11 §5.4.3, §6.5.2.5).
		return nil, false, true
	}
	return nil, false, false
}

// checkReadEventDetails checks the parameters of a ReadEventDetails that
// hold for every node of the request (Part 11 §6.5.2.1 Table 29): at least
// two of NumValuesPerNode, StartTime and EndTime, and a Filter with at least
// one SelectClause. The answers are service results (Part 4 §5.10.3 Table
// 51).
func checkReadEventDetails(d *ua.ReadEventDetails) ua.StatusCode {
	given := 0
	for _, ok := range []bool{d.NumValuesPerNode > 0, !d.StartTime.IsZero(), !d.EndTime.IsZero()} {
		if ok {
			given++
		}
	}
	if given < 2 {
		return ua.StatusBadHistoryOperationInvalid
	}
	if d.Filter == nil || len(d.Filter.SelectClauses) == 0 {
		return ua.StatusBadEventFilterInvalid
	}
	return ua.StatusOK
}

// eventHistoryNode returns the node of an event history operation: a
// HistoricalEventNode the session may read (or, with write, write) whose
// history it may change. The status of a refusal is the result of the
// operation.
func (s *Server) eventHistoryNode(ctx context.Context, sc *uasc.SecureChannel, sess *session, nodeID *ua.NodeID, write bool) (*Node, ua.StatusCode) {
	if nodeID == nil {
		return nil, ua.StatusBadNodeIDInvalid
	}
	n := s.Node(nodeID)
	if n == nil {
		return nil, ua.StatusBadNodeIDUnknown
	}
	check := s.checkRead
	if write {
		check = s.checkWrite
	}
	if st := check(ctx, sess, nodeID); st != ua.StatusOK {
		return nil, st
	}
	if st := checkAccessRestrictions(sc, n); st != ua.StatusOK {
		return nil, st
	}
	bits := eventNotifierOf(n)
	switch {
	case write && bits&byte(ua.EventNotifierTypeHistoryWrite) != 0:
		return n, ua.StatusOK
	case bits&byte(ua.EventNotifierTypeHistoryRead) == 0:
		// Not a HistoricalEventNode (Part 11 §5.4.4).
		return nil, ua.StatusBadHistoryOperationUnsupported
	case write:
		return nil, ua.StatusBadNotWritable
	}
	return n, ua.StatusOK
}

// readEventHistory serves ReadEventDetails (Part 11 §6.5.2) for one node:
// the events of the provider that pass the WhereClause of the filter (and
// that the session may receive, for audit events), with the fields of its
// SelectClauses. A field the HistoricalEventFilter does not store is
// Bad_NoData (Part 11 §6.5.2.2); a field the event does not have is null
// (Part 11 §5.4.1). TimestampsToReturn applies to fields of type DataValue
// only (Part 11 §6.5.2.2); the history holds none, so it is ignored.
func (s *AttributeService) readEventHistory(ctx context.Context, sc *uasc.SecureChannel, sess *session, p EventHistoryProvider, d *ua.ReadEventDetails, nodeID *ua.NodeID, continuationPoint []byte) *ua.HistoryReadResult {
	n, st := s.srv.eventHistoryNode(ctx, sc, sess, nodeID, false)
	if st != ua.StatusOK {
		return &ua.HistoryReadResult{StatusCode: st}
	}
	stored := storedFields(s.srv.storageFilter(nodeID, n))
	where := d.Filter.WhereClause
	match := func(e *HistoricalEvent) bool {
		if where != nil && len(where.Elements) > 0 && !s.srv.evalEventFilter(e, where) {
			return false
		}
		return s.srv.mayReadEvent(ctx, sess, e.EventType())
	}
	events, cp, st := p.ReadEvents(nodeID, d.StartTime, d.EndTime, d.NumValuesPerNode, match, continuationPoint)
	if isBad(st) {
		return &ua.HistoryReadResult{StatusCode: st}
	}
	out := make([]*ua.HistoryEventFieldList, len(events))
	for i, e := range events {
		fields := make([]*ua.Variant, len(d.Filter.SelectClauses))
		for j, c := range d.Filter.SelectClauses {
			if stored != nil && c != nil && !stored[clauseKey(c)] {
				fields[j] = ua.MustVariant(ua.StatusBadNoData)
				continue
			}
			fields[j] = e.eventField(c)
		}
		out[i] = &ua.HistoryEventFieldList{EventFields: fields}
	}
	return &ua.HistoryReadResult{
		StatusCode:        st,
		ContinuationPoint: cp,
		HistoryData:       ua.NewExtensionObject(&ua.HistoryEvent{Events: out}),
	}
}

// mayReadEvent reports whether the session may read an event of eventType
// from the history: audit events go to the sessions an
// EventAccessController allows, as their live events do.
func (s *Server) mayReadEvent(ctx context.Context, sess *session, eventType *ua.NodeID) bool {
	eac, ok := s.cfg.accessController.(EventAccessController)
	if !ok || eventType == nil || !s.isSubtypeOf(eventType, ua.NewNumericNodeID(0, id.AuditEventType)) {
		return true
	}
	if sess == nil {
		return false
	}
	return eac.CheckReceiveEvents(ctx, sess.handle(), eventType) == ua.StatusOK
}

// updateEventHistory serves UpdateEventDetails (Part 11 §6.9.4).
//
// The details are checked as a whole (StatusCode): PerformInsertReplace
// Delete is Bad_InvalidArgument (§6.9.4.1); the filter needs SelectClauses
// and no WhereClause (Bad_EventFilterInvalid) and no IndexRange
// (Bad_IndexRangeInvalid); Insert and Update need EventType and Time
// selected, Replace EventId (Bad_ArgumentsMissing, §6.9.4.2, §6.9.4.3).
// Each event then has its OperationResult: Bad_InvalidArgument for a field
// list of the wrong length or a field of the wrong type,
// Bad_TypeDefinitionInvalid for an unknown EventType,
// Bad_SourceNodeIdInvalid for an unknown SourceNode, Good_DataIgnored when
// the HistoricalEventFilter does not store some of the fields given.
// Events matched by EventId; Insert and Update give an event without one a
// new EventId, and null EventType and Time default to BaseEventType and the
// current time.
func (s *AttributeService) updateEventHistory(ctx context.Context, sc *uasc.SecureChannel, sess *session, h HistoryProvider, d *ua.UpdateEventDetails) *ua.HistoryUpdateResult {
	up, ok := h.(EventHistoryUpdater)
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}
	n, st := s.srv.eventHistoryNode(ctx, sc, sess, d.NodeID, true)
	if st != ua.StatusOK {
		return &ua.HistoryUpdateResult{StatusCode: st}
	}
	perform := d.PerformInsertReplace
	switch perform {
	case ua.PerformUpdateTypeInsert, ua.PerformUpdateTypeReplace, ua.PerformUpdateTypeUpdate:
	default:
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadInvalidArgument}
	}
	f := d.Filter
	if f == nil || len(f.SelectClauses) == 0 || f.WhereClause != nil && len(f.WhereClause.Elements) > 0 {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadEventFilterInvalid}
	}
	keys := make([]string, len(f.SelectClauses))
	selected := map[string]bool{}
	for i, c := range f.SelectClauses {
		if c == nil {
			return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadEventFilterInvalid}
		}
		if c.IndexRange != "" {
			return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadIndexRangeInvalid}
		}
		keys[i] = clauseKey(c)
		selected[keys[i]] = true
	}
	if perform == ua.PerformUpdateTypeReplace && !selected["EventId"] ||
		perform != ua.PerformUpdateTypeReplace && (!selected["EventType"] || !selected["Time"]) {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadArgumentsMissing}
	}

	stored := storedFields(s.srv.storageFilter(d.NodeID, n))
	ops := make([]ua.StatusCode, len(d.EventData))
	var events []*HistoricalEvent
	var index []int
	var ignored []bool
	for i, efl := range d.EventData {
		if efl == nil || len(efl.EventFields) != len(keys) {
			ops[i] = ua.StatusBadInvalidArgument
			continue
		}
		ev, ign, st := s.srv.historicalEventOf(keys, efl.EventFields, perform, stored)
		if st != ua.StatusOK {
			ops[i] = st
			continue
		}
		events = append(events, ev)
		index = append(index, i)
		ignored = append(ignored, ign)
	}
	if len(events) == 0 {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK, OperationResults: ops}
	}
	res := up.UpdateEvents(d.NodeID, perform, events)
	if res == nil {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadInternalError}
	}
	if isBad(res.StatusCode) {
		return &ua.HistoryUpdateResult{StatusCode: res.StatusCode}
	}
	for j, i := range index {
		op := ua.StatusBadInternalError
		if j < len(res.OperationResults) {
			op = res.OperationResults[j]
		}
		if ignored[j] && op.Uint32()&0xC0000000 == 0 {
			op = ua.StatusGoodDataIgnored
		}
		ops[i] = op
	}
	return &ua.HistoryUpdateResult{StatusCode: res.StatusCode, OperationResults: ops}
}

// historicalEventOf builds the event of one HistoryEventFieldList of
// UpdateEventDetails (see updateEventHistory). ignored reports fields the
// history does not store.
func (s *Server) historicalEventOf(keys []string, values []*ua.Variant, perform ua.PerformUpdateType, stored map[string]bool) (ev *HistoricalEvent, ignored bool, st ua.StatusCode) {
	f := make(map[string]*ua.Variant, len(keys)+3)
	for i, k := range keys {
		v := values[i]
		if v == nil || v.Value() == nil {
			// A null field: the history picks the default (§6.9.4.2).
			continue
		}
		switch k {
		case "EventId":
			if b, ok := v.Value().([]byte); !ok || len(b) == 0 {
				return nil, false, ua.StatusBadInvalidArgument
			}
		case "EventType":
			t, ok := v.Value().(*ua.NodeID)
			if !ok {
				return nil, false, ua.StatusBadInvalidArgument
			}
			if !s.isKnownEventType(t) {
				return nil, false, ua.StatusBadTypeDefinitionInvalid
			}
		case "SourceNode":
			n, ok := v.Value().(*ua.NodeID)
			if !ok {
				return nil, false, ua.StatusBadInvalidArgument
			}
			if s.Node(n) == nil {
				return nil, false, ua.StatusBadSourceNodeIDInvalid
			}
		case "Time", "ReceiveTime":
			if _, ok := v.Value().(time.Time); !ok {
				return nil, false, ua.StatusBadInvalidArgument
			}
		case "Severity":
			if _, ok := v.Value().(uint16); !ok {
				return nil, false, ua.StatusBadInvalidArgument
			}
		}
		if stored != nil && !stored[k] {
			ignored = true
			continue
		}
		f[k] = v
	}
	ev = &HistoricalEvent{Fields: f}
	if perform == ua.PerformUpdateTypeReplace {
		if len(ev.EventID()) == 0 {
			// Nothing to replace without an EventId.
			return nil, false, ua.StatusBadNoEntryExists
		}
		return ev, ignored, ua.StatusOK
	}
	now := time.Now()
	if f["EventId"] == nil {
		f["EventId"] = ua.MustVariant(newEventID())
	}
	if f["EventType"] == nil {
		f["EventType"] = ua.MustVariant(ua.NewNumericNodeID(0, id.BaseEventType))
	}
	if f["Time"] == nil {
		f["Time"] = ua.MustVariant(now)
	}
	if f["ReceiveTime"] == nil {
		f["ReceiveTime"] = ua.MustVariant(now)
	}
	return ev, ignored, ua.StatusOK
}

// deleteEventHistory serves DeleteEventDetails (Part 11 §6.9.7).
func (s *AttributeService) deleteEventHistory(ctx context.Context, sc *uasc.SecureChannel, sess *session, h HistoryProvider, d *ua.DeleteEventDetails) *ua.HistoryUpdateResult {
	del, ok := h.(EventHistoryDeleter)
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}
	if _, st := s.srv.eventHistoryNode(ctx, sc, sess, d.NodeID, true); st != ua.StatusOK {
		return &ua.HistoryUpdateResult{StatusCode: st}
	}
	res := del.DeleteEvents(d.NodeID, d.EventIDs)
	if res == nil {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadInternalError}
	}
	return res
}

// historyCapabilities are the HistoryServerCapabilities (Part 11 §5.7.2)
// that depend on the history provider of the server.
var historyCapabilities = []struct {
	nodeID    uint32
	supported func(HistoryProvider) bool
}{
	{id.HistoryServerCapabilitiesAccessHistoryDataCapability, func(h HistoryProvider) bool { return h != nil }},
	{id.HistoryServerCapabilitiesInsertDataCapability, isA[HistoryDataUpdater]},
	{id.HistoryServerCapabilitiesReplaceDataCapability, isA[HistoryDataUpdater]},
	{id.HistoryServerCapabilitiesUpdateDataCapability, isA[HistoryDataUpdater]},
	{id.HistoryServerCapabilitiesDeleteRawCapability, isA[RawHistoryDeleter]},
	{id.HistoryServerCapabilitiesDeleteAtTimeCapability, isA[AtTimeHistoryDeleter]},
	{id.HistoryServerCapabilitiesAccessHistoryEventsCapability, isA[EventHistoryProvider]},
	{id.HistoryServerCapabilitiesInsertEventCapability, isA[EventHistoryUpdater]},
	{id.HistoryServerCapabilitiesReplaceEventCapability, isA[EventHistoryUpdater]},
	{id.HistoryServerCapabilitiesUpdateEventCapability, isA[EventHistoryUpdater]},
	{id.HistoryServerCapabilitiesDeleteEventCapability, isA[EventHistoryDeleter]},
}

func isA[T any](h HistoryProvider) bool {
	_, ok := h.(T)
	return ok
}

// bindHistoryCapabilities makes the HistoryServerCapabilities report what
// the history provider of the server supports.
func (s *Server) bindHistoryCapabilities() {
	for _, c := range historyCapabilities {
		n := s.ownNode(c.nodeID)
		if n == nil {
			continue
		}
		supported := c.supported
		n.mu.Lock()
		n.val = func() *ua.DataValue {
			h, _ := s.history()
			return DataValueFromValue(supported(h))
		}
		n.mu.Unlock()
	}
}

// notifyHistoryCapabilities reports the HistoryServerCapabilities to data
// change monitored items after the history provider changed.
func (s *Server) notifyHistoryCapabilities() {
	for _, c := range historyCapabilities {
		s.ChangeNotification(ua.NewNumericNodeID(0, c.nodeID))
	}
}
