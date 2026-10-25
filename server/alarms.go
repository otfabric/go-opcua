// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// Alarms & Conditions (Part 9).
//
// A condition is created with [Server.AddCondition] as an instance of
// ConditionType or one of its subtypes (AcknowledgeableConditionType,
// AlarmConditionType, OffNormalAlarmType, DiscreteAlarmType, the limit alarms
// and their level variants, or an ObjectType of the application derived from
// them). The server builds the instance with its standard components,
// implements the condition methods (Enable, Disable, AddComment, Acknowledge,
// Confirm, the shelving methods) and ConditionRefresh / ConditionRefresh2, and
// reports every state change as an event of the condition through its source
// node and the Server object.
//
// Not implemented: condition branches (BranchId is always null, Part 9
// §5.5.2), the audit events of the methods (Part 9 §5.10), dialogs, alarm
// groups, and the optional AlarmConditionType state (Latched, Silence,
// OutOfService) with the methods of Part 9 1.05 (Reset, Silence, Suppress,
// the *2 variants of the methods).

// AcknowledgeableConditionTypeNodeID is the well-known ObjectType NodeId for
// AcknowledgeableConditionType (Part 9 §5.7.2).
var AcknowledgeableConditionTypeNodeID = ua.NewNumericNodeID(0, id.AcknowledgeableConditionType)

// AlarmsConditionsSupported reports whether the server implements Alarms &
// Conditions (Part 9): condition instances with their state machines, the
// condition methods and ConditionRefresh. See [Server.AddCondition].
func AlarmsConditionsSupported() bool {
	return true
}

// ShelvingState is the state of the ShelvedStateMachine of an alarm
// (Part 9 §5.8.10).
type ShelvingState int

const (
	Unshelved ShelvingState = iota
	TimedShelved
	OneShotShelved
)

func (s ShelvingState) String() string {
	switch s {
	case TimedShelved:
		return "TimedShelved"
	case OneShotShelved:
		return "OneShotShelved"
	default:
		return "Unshelved"
	}
}

func (s ShelvingState) stateID() uint32 {
	switch s {
	case TimedShelved:
		return id.ShelvedStateMachineTypeTimedShelved
	case OneShotShelved:
		return id.ShelvedStateMachineTypeOneShotShelved
	default:
		return id.ShelvedStateMachineTypeUnshelved
	}
}

// shelvingTransitionID is the Transition of the ShelvedStateMachineType from
// one state to another (Part 9 §5.8.10.1), 0 if there is none.
func shelvingTransitionID(from, to ShelvingState) uint32 {
	switch {
	case from == Unshelved && to == TimedShelved:
		return id.ShelvedStateMachineTypeUnshelvedToTimedShelved
	case from == Unshelved && to == OneShotShelved:
		return id.ShelvedStateMachineTypeUnshelvedToOneShotShelved
	case from == TimedShelved && to == Unshelved:
		return id.ShelvedStateMachineTypeTimedShelvedToUnshelved
	case from == TimedShelved && to == OneShotShelved:
		return id.ShelvedStateMachineTypeTimedShelvedToOneShotShelved
	case from == OneShotShelved && to == Unshelved:
		return id.ShelvedStateMachineTypeOneShotShelvedToUnshelved
	case from == OneShotShelved && to == TimedShelved:
		return id.ShelvedStateMachineTypeOneShotShelvedToTimedShelved
	}
	return 0
}

// LimitState is the active limit of an exclusive limit alarm, the current
// state of its ExclusiveLimitStateMachine (Part 9 §5.8.12.2). LimitNone means
// the alarm is inactive.
type LimitState int

const (
	LimitNone LimitState = iota
	LimitHighHigh
	LimitHigh
	LimitLow
	LimitLowLow
)

func (l LimitState) String() string {
	switch l {
	case LimitHighHigh:
		return "HighHigh"
	case LimitHigh:
		return "High"
	case LimitLow:
		return "Low"
	case LimitLowLow:
		return "LowLow"
	default:
		return ""
	}
}

func (l LimitState) stateID() uint32 {
	switch l {
	case LimitHighHigh:
		return id.ExclusiveLimitStateMachineTypeHighHigh
	case LimitHigh:
		return id.ExclusiveLimitStateMachineTypeHigh
	case LimitLow:
		return id.ExclusiveLimitStateMachineTypeLow
	case LimitLowLow:
		return id.ExclusiveLimitStateMachineTypeLowLow
	default:
		return 0
	}
}

// exclusiveLimitTransitionID is the Transition of the
// ExclusiveLimitStateMachineType between two limit states (Part 9 §5.8.12.2),
// 0 if the state machine has none (a change from or to inactive).
func exclusiveLimitTransitionID(from, to LimitState) uint32 {
	switch {
	case from == LimitLowLow && to == LimitLow:
		return id.ExclusiveLimitStateMachineTypeLowLowToLow
	case from == LimitLow && to == LimitLowLow:
		return id.ExclusiveLimitStateMachineTypeLowToLowLow
	case from == LimitHighHigh && to == LimitHigh:
		return id.ExclusiveLimitStateMachineTypeHighHighToHigh
	case from == LimitHigh && to == LimitHighHigh:
		return id.ExclusiveLimitStateMachineTypeHighToHighHigh
	}
	return 0
}

// AlarmLimits are the limits of a limit alarm (LimitAlarmType, Part 9
// §5.8.11). A nil limit is not configured: its Property and, for a
// non-exclusive alarm, its state variable are absent.
type AlarmLimits struct {
	HighHigh, High, Low, LowLow *float64
}

// NonExclusiveLimits are the states of a non-exclusive limit alarm
// (NonExclusiveLimitAlarmType, Part 9 §5.8.13): any combination may be
// active.
type NonExclusiveLimits struct {
	HighHigh, High, Low, LowLow bool
}

func (l NonExclusiveLimits) any() bool { return l.HighHigh || l.High || l.Low || l.LowLow }

// ConditionConfig describes a condition instance for [Server.AddCondition].
type ConditionConfig struct {
	// Type is the ObjectType of the condition: ConditionType or a subtype
	// of it. Default: AlarmConditionType.
	Type *ua.NodeID
	// NodeID is the NodeId of the condition (the ConditionId). Default: a
	// new numeric NodeId in Namespace.
	NodeID *ua.NodeID
	// Namespace receives the nodes of the condition. Default: the namespace
	// of NodeID, else of Source (which must then be a NodeNameSpace other
	// than namespace 0).
	Namespace *NodeNameSpace
	// Name is the BrowseName and the ConditionName (Part 9 §5.5.2).
	Name string
	// Source is the SourceNode of the condition's events: the object or
	// variable the condition is about. It gets a HasCondition and a
	// HasComponent reference to the condition and becomes an event
	// notifier. Required.
	Source *ua.NodeID
	// SourceName is reported in the events. Default: the BrowseName of
	// Source.
	SourceName string
	// Notifiers are further event notifiers that report the events of the
	// condition, in addition to Source and the Server object.
	Notifiers []*ua.NodeID
	// ConditionClassID / ConditionClassName classify the condition.
	// Default: BaseConditionClassType.
	ConditionClassID   *ua.NodeID
	ConditionClassName string
	// Severity and Message are the initial values (1..1000; 0 means 500).
	Severity uint16
	Message  string
	// Retain is the initial Retain of a ConditionType instance. For the
	// acknowledgeable types the server derives Retain from the state.
	Retain bool
	// Disabled creates the condition in the Disabled state.
	Disabled bool
	// Confirmable adds the optional ConfirmedState and the Confirm method
	// (acknowledgeable types).
	Confirmable bool
	// Suppressible adds the optional SuppressedState (alarm types).
	Suppressible bool
	// Shelving adds the ShelvingState with the TimedShelve, OneShotShelve
	// and Unshelve methods (alarm types). MaxTimeShelved, when set, bounds
	// the shelving time and is exposed as the MaxTimeShelved Property.
	Shelving       bool
	MaxTimeShelved time.Duration
	// InputNode is the InputNode Property of an alarm.
	InputNode *ua.NodeID
	// NormalState is the NormalState Property of an OffNormalAlarmType.
	NormalState *ua.NodeID
	// Limits are the limits of a LimitAlarmType (and subtypes).
	Limits AlarmLimits

	// The hooks are called when a client calls the method, after the
	// checks of the state (a call the state machine refuses does not reach
	// them) and before the change is made; a status other than Good
	// refuses the call with that status. They run without locks held, so
	// they may read or change the condition.
	OnAcknowledge func(ctx context.Context, c *Condition, comment *ua.LocalizedText) ua.StatusCode
	OnConfirm     func(ctx context.Context, c *Condition, comment *ua.LocalizedText) ua.StatusCode
	OnAddComment  func(ctx context.Context, c *Condition, comment *ua.LocalizedText) ua.StatusCode
	OnEnable      func(ctx context.Context, c *Condition, enable bool) ua.StatusCode
	OnShelve      func(ctx context.Context, c *Condition, state ShelvingState, shelvingTime time.Duration) ua.StatusCode
}

// ConditionState is a snapshot of the state of a condition.
type ConditionState struct {
	EventID      []byte // the EventId of the latest event
	Time         time.Time
	Enabled      bool
	Retain       bool
	Severity     uint16
	LastSeverity uint16
	Message      *ua.LocalizedText
	Quality      ua.StatusCode
	Comment      *ua.LocalizedText
	ClientUserID string
	Acked        bool
	Confirmed    bool
	Active       bool
	Suppressed   bool
	Shelving     ShelvingState
	// UnshelveAt is when a shelved alarm unshelves by itself (zero if
	// never).
	UnshelveAt         time.Time
	Limit              LimitState
	NonExclusiveLimits NonExclusiveLimits
}

// ConditionUpdate is a change of the state of a condition made by the
// application, see [Condition.Update]. Nil fields are left unchanged.
type ConditionUpdate struct {
	// Active sets the ActiveState of an alarm. Becoming active makes the
	// alarm unacknowledged and unconfirmed again (Part 9 §5.8.2); becoming
	// inactive ends a OneShotShelved state.
	Active *bool
	// Severity sets the Severity; LastSeverity takes the previous value.
	Severity *uint16
	// Message sets the Message of the event.
	Message *string
	// Quality sets the Quality.
	Quality *ua.StatusCode
	// Retain sets Retain of a ConditionType instance (the acknowledgeable
	// types derive it from their state).
	Retain *bool
	// Acked / Confirmed set the AckedState / ConfirmedState directly, e.g.
	// to require a new acknowledgement of a non-alarm condition.
	Acked     *bool
	Confirmed *bool
	// Suppressed sets the SuppressedState of an alarm.
	Suppressed *bool
	// Limit sets the active limit of an exclusive limit alarm; ActiveState
	// follows (active unless LimitNone).
	Limit *LimitState
	// NonExclusiveLimits sets the limit states of a non-exclusive limit
	// alarm; ActiveState follows (active if any is).
	NonExclusiveLimits *NonExclusiveLimits
}

// Errors of the Condition API.
var (
	ErrConditionRemoved   = errors.New("server: condition removed")
	ErrConditionNotAlarm  = errors.New("server: condition is not an alarm")
	ErrConditionUnsupport = errors.New("server: condition type does not have this state")
)

// conditionState is the mutable state of a condition, guarded by
// Condition.mu.
type conditionState struct {
	eventID     []byte
	time        time.Time
	receiveTime time.Time

	enabled     bool
	enabledTime time.Time
	retain      bool // application Retain of a ConditionType instance

	severity, lastSeverity uint16
	lastSeverityTime       time.Time
	message                *ua.LocalizedText
	quality                ua.StatusCode
	qualityTime            time.Time
	comment                *ua.LocalizedText
	commentTime            time.Time
	clientUserID           string

	acked, confirmed         bool
	ackedTime, confirmedTime time.Time

	active         bool
	activeTime     time.Time
	suppressed     bool
	suppressedTime time.Time

	shelving       ShelvingState
	shelvingFrom   ShelvingState // previous state, for LastTransition
	shelvingTime   time.Time     // time of the last shelving transition
	unshelveAt     time.Time
	shelveTimer    *time.Timer
	shelveTimerGen uint64

	limit        LimitState
	limitFrom    LimitState
	limitTime    time.Time
	nonExclusive NonExclusiveLimits
	nonExclTimes [4]time.Time
	recentIDs    [][]byte // EventIds of the recent events, newest last
	removed      bool
}

// recentEventIDs is how many EventIds of a condition the methods accept:
// a client may act on a notification that a newer one has overtaken.
const recentEventIDs = 32

// Condition is a condition instance in the address space.
type Condition struct {
	srv *Server
	cfg ConditionConfig

	id         *ua.NodeID
	typeID     *ua.NodeID
	sourceName string
	ns         *NodeNameSpace
	classID    *ua.NodeID
	className  *ua.LocalizedText

	isAck, isAlarm, isLimit, isExclusive, isNonExclusive, isOffNormal bool

	// targets are the notifiers whose event items receive the events.
	targets []*ua.NodeID
	// table are the components of the instance.
	table []condField
	// nodes are the nodes of the instance; vars the variables, for change
	// notifications.
	nodes      []*ua.NodeID
	vars       []*ua.NodeID
	shelvingID *ua.NodeID
	methods    [][2]*ua.NodeID
	sourceRefs func() // removes the references of the source

	// emitMu serializes the changes and the events of the condition, so
	// that every notifier sees them in order. It is never taken with mu
	// held, and value functions take only mu.
	emitMu sync.Mutex
	mu     sync.RWMutex
	st     conditionState
}

// alarmManager holds the conditions of a server.
type alarmManager struct {
	mu         sync.Mutex
	conds      map[string]*Condition // by ConditionId
	shelving   map[string]*Condition // by ShelvingState NodeId
	refreshing map[uint32]bool       // subscriptions with a ConditionRefresh running
	closed     bool
}

func newAlarmManager() *alarmManager {
	return &alarmManager{conds: map[string]*Condition{}, shelving: map[string]*Condition{}, refreshing: map[uint32]bool{}}
}

func (m *alarmManager) list() []*Condition {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Condition, 0, len(m.conds))
	for _, c := range m.conds {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b *Condition) int {
		switch {
		case a.id.String() < b.id.String():
			return -1
		case a.id.String() > b.id.String():
			return 1
		}
		return 0
	})
	return out
}

// close stops the shelving timers (Server.Close).
func (m *alarmManager) close() {
	m.mu.Lock()
	m.closed = true
	conds := make([]*Condition, 0, len(m.conds))
	for _, c := range m.conds {
		conds = append(conds, c)
	}
	m.mu.Unlock()
	for _, c := range conds {
		c.mu.Lock()
		c.stopShelveTimerLocked()
		c.mu.Unlock()
	}
}

// registerAlarmMethods registers ConditionRefresh and ConditionRefresh2.
// The ObjectId of the calls is ConditionType (Part 9 §5.5.7); the Server
// object is accepted too, as several clients use it.
func (s *Server) registerAlarmMethods() {
	refresh := ua.NewNumericNodeID(0, id.ConditionTypeConditionRefresh)
	refresh2 := ua.NewNumericNodeID(0, id.ConditionTypeConditionRefresh2)
	for _, obj := range []uint32{id.ConditionType, id.Server} {
		o := ua.NewNumericNodeID(0, obj)
		s.RegisterMethod(o, refresh, s.conditionRefreshMethod)
		s.RegisterMethod(o, refresh2, s.conditionRefresh2Method)
	}
}

// Condition returns the condition with the given ConditionId.
func (s *Server) Condition(conditionID *ua.NodeID) (*Condition, bool) {
	if conditionID == nil {
		return nil, false
	}
	s.alarms.mu.Lock()
	defer s.alarms.mu.Unlock()
	c, ok := s.alarms.conds[conditionID.String()]
	return c, ok
}

// Conditions returns the conditions of the server, ordered by ConditionId.
func (s *Server) Conditions() []*Condition { return s.alarms.list() }

// AddCondition creates a condition instance (Part 9 §5.5) with the
// components of its type and the options of cfg, attaches it to its source
// node and returns it. The condition reports an initial event.
func (s *Server) AddCondition(cfg ConditionConfig) (*Condition, error) {
	if cfg.Source == nil {
		return nil, errors.New("server: AddCondition: Source is required")
	}
	if cfg.Name == "" {
		return nil, errors.New("server: AddCondition: Name is required")
	}
	src := s.Node(cfg.Source)
	if src == nil {
		return nil, fmt.Errorf("server: AddCondition: source %v not found", cfg.Source)
	}
	typeID := cfg.Type
	if typeID == nil {
		typeID = ua.NewNumericNodeID(0, id.AlarmConditionType)
	}
	is := func(t uint32) bool { return s.isSubtypeOf(typeID, ua.NewNumericNodeID(0, t)) }
	if s.Node(typeID) == nil || !is(id.ConditionType) {
		return nil, fmt.Errorf("server: AddCondition: %v is not a subtype of ConditionType", typeID)
	}
	ns := cfg.Namespace
	if ns == nil {
		ref := cfg.Source
		if cfg.NodeID != nil {
			ref = cfg.NodeID
		}
		if x, err := s.Namespace(int(ref.Namespace())); err == nil && ref.Namespace() != 0 {
			ns, _ = x.(*NodeNameSpace)
		}
		if ns == nil {
			return nil, errors.New("server: AddCondition: Namespace is required")
		}
	}
	condID := cfg.NodeID
	if condID == nil {
		condID = ua.NewNumericNodeID(ns.ID(), ns.GetNextNodeID())
	}
	if s.Node(condID) != nil {
		return nil, fmt.Errorf("server: AddCondition: node %v exists", condID)
	}

	c := &Condition{srv: s, cfg: cfg, id: condID, typeID: typeID, ns: ns,
		isAck: is(id.AcknowledgeableConditionType), isAlarm: is(id.AlarmConditionType),
		isLimit: is(id.LimitAlarmType), isExclusive: is(id.ExclusiveLimitAlarmType),
		isNonExclusive: is(id.NonExclusiveLimitAlarmType), isOffNormal: is(id.OffNormalAlarmType)}
	c.sourceName = cfg.SourceName
	if c.sourceName == "" {
		c.sourceName = src.BrowseName().Name
	}
	c.classID = cfg.ConditionClassID
	if c.classID == nil {
		c.classID = ua.NewNumericNodeID(0, id.BaseConditionClassType)
	}
	cn := cfg.ConditionClassName
	if cn == "" {
		cn = "BaseConditionClass"
		if n := s.Node(c.classID); n != nil {
			cn = n.BrowseName().Name
		}
	}
	c.className = ua.NewLocalizedText(cn)
	c.targets = []*ua.NodeID{cfg.Source}
	if !cfg.Source.Equal(ua.NewNumericNodeID(0, id.Server)) {
		c.targets = append(c.targets, ua.NewNumericNodeID(0, id.Server))
	}
	for _, n := range cfg.Notifiers {
		if n != nil && !slices.ContainsFunc(c.targets, n.Equal) {
			c.targets = append(c.targets, n)
		}
	}

	now := time.Now()
	sev := cfg.Severity
	if sev == 0 {
		sev = 500
	}
	c.st = conditionState{
		enabled: !cfg.Disabled, enabledTime: now, retain: cfg.Retain,
		severity: sev, lastSeverity: sev, lastSeverityTime: now,
		message: ua.NewLocalizedText(cfg.Message), quality: ua.StatusOK, qualityTime: now,
		comment: &ua.LocalizedText{}, acked: true, confirmed: true,
	}

	s.alarms.mu.Lock()
	if _, dup := s.alarms.conds[condID.String()]; dup {
		s.alarms.mu.Unlock()
		return nil, fmt.Errorf("server: AddCondition: condition %v exists", condID)
	}
	s.alarms.conds[condID.String()] = c
	s.alarms.mu.Unlock()

	c.build(src)
	if c.shelvingID != nil {
		s.alarms.mu.Lock()
		s.alarms.shelving[c.shelvingID.String()] = c
		s.alarms.mu.Unlock()
	}
	c.registerMethods()

	c.emitMu.Lock()
	c.mu.Lock()
	ev := c.newEventLocked()
	enabled := c.st.enabled
	c.mu.Unlock()
	if enabled {
		c.deliver(ev)
	}
	c.emitMu.Unlock()
	return c, nil
}

// RemoveCondition deletes a condition and its nodes. The condition reports
// no further events (Part 9 §5.5.2: a deleted condition is not refreshed).
func (s *Server) RemoveCondition(conditionID *ua.NodeID) error {
	c, ok := s.Condition(conditionID)
	if !ok {
		return fmt.Errorf("server: condition %v not found", conditionID)
	}
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.mu.Lock()
	c.st.removed = true
	c.stopShelveTimerLocked()
	c.mu.Unlock()

	s.alarms.mu.Lock()
	delete(s.alarms.conds, conditionID.String())
	if c.shelvingID != nil {
		delete(s.alarms.shelving, c.shelvingID.String())
	}
	s.alarms.mu.Unlock()
	for _, m := range c.methods {
		s.unregisterMethod(m[0], m[1])
	}
	if c.sourceRefs != nil {
		c.sourceRefs()
	}
	for _, n := range c.nodes {
		_ = c.ns.DeleteNode(n)
	}
	return nil
}

// NodeID returns the ConditionId.
func (c *Condition) NodeID() *ua.NodeID { return c.id }

// Name returns the ConditionName.
func (c *Condition) Name() string { return c.cfg.Name }

// TypeID returns the ObjectType of the condition.
func (c *Condition) TypeID() *ua.NodeID { return c.typeID }

// Source returns the SourceNode.
func (c *Condition) Source() *ua.NodeID { return c.cfg.Source }

// State returns a snapshot of the state of the condition.
func (c *Condition) State() ConditionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	st := &c.st
	return ConditionState{
		EventID: slices.Clone(st.eventID), Time: st.time, Enabled: st.enabled, Retain: c.retainLocked(),
		Severity: st.severity, LastSeverity: st.lastSeverity, Message: st.message, Quality: st.quality,
		Comment: st.comment, ClientUserID: st.clientUserID, Acked: st.acked, Confirmed: st.confirmed,
		Active: st.active, Suppressed: st.suppressed, Shelving: st.shelving, UnshelveAt: st.unshelveAt,
		Limit: st.limit, NonExclusiveLimits: st.nonExclusive,
	}
}

// retainLocked is the Retain of the condition (Part 9 §5.5.2): false while
// disabled; for the acknowledgeable types true while the condition waits for
// an acknowledgement or confirmation, for alarms also while active.
func (c *Condition) retainLocked() bool {
	st := &c.st
	if !st.enabled {
		return false
	}
	if !c.isAck {
		return st.retain
	}
	r := !st.acked || (c.cfg.Confirmable && !st.confirmed)
	if c.isAlarm && st.active {
		r = true
	}
	return r
}

// Update changes the state of the condition and reports it in one event. A
// disabled condition takes the change but reports no event (Part 9 §5.5.2).
func (c *Condition) Update(u ConditionUpdate) error {
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.mu.Lock()
	if c.st.removed {
		c.mu.Unlock()
		return ErrConditionRemoved
	}
	if err := c.checkUpdateLocked(u); err != nil {
		c.mu.Unlock()
		return err
	}
	now := time.Now()
	c.applyLocked(u, now)
	ev := c.newEventLocked()
	enabled := c.st.enabled
	c.mu.Unlock()
	if enabled {
		c.deliver(ev)
	}
	c.notifyChanges()
	return nil
}

func (c *Condition) checkUpdateLocked(u ConditionUpdate) error {
	if (u.Active != nil || u.Suppressed != nil) && !c.isAlarm {
		return ErrConditionNotAlarm
	}
	if (u.Acked != nil || u.Confirmed != nil) && !c.isAck {
		return ErrConditionUnsupport
	}
	if u.Confirmed != nil && !c.cfg.Confirmable {
		return ErrConditionUnsupport
	}
	if u.Suppressed != nil && !c.cfg.Suppressible {
		return ErrConditionUnsupport
	}
	if u.Retain != nil && c.isAck {
		return ErrConditionUnsupport
	}
	if u.Limit != nil && !c.isExclusive {
		return ErrConditionUnsupport
	}
	if u.NonExclusiveLimits != nil && !c.isNonExclusive {
		return ErrConditionUnsupport
	}
	return nil
}

func (c *Condition) applyLocked(u ConditionUpdate, now time.Time) {
	st := &c.st
	active := u.Active
	if u.Limit != nil {
		a := *u.Limit != LimitNone
		active = &a
		if *u.Limit != st.limit {
			st.limitFrom, st.limit, st.limitTime = st.limit, *u.Limit, now
		}
	}
	if u.NonExclusiveLimits != nil {
		a := u.NonExclusiveLimits.any()
		active = &a
		old := [4]bool{st.nonExclusive.HighHigh, st.nonExclusive.High, st.nonExclusive.Low, st.nonExclusive.LowLow}
		nw := [4]bool{u.NonExclusiveLimits.HighHigh, u.NonExclusiveLimits.High, u.NonExclusiveLimits.Low, u.NonExclusiveLimits.LowLow}
		for i := range old {
			if old[i] != nw[i] {
				st.nonExclTimes[i] = now
			}
		}
		st.nonExclusive = *u.NonExclusiveLimits
	}
	if active != nil && *active != st.active {
		st.active, st.activeTime = *active, now
		if st.active {
			// A new activation needs a new acknowledgement (and
			// confirmation): Part 9 §5.7.2, §5.8.2.
			if c.isAck {
				st.acked, st.ackedTime = false, now
				if c.cfg.Confirmable {
					st.confirmed, st.confirmedTime = false, now
				}
			}
		} else if st.shelving == OneShotShelved {
			// A OneShotShelved alarm unshelves when it becomes inactive
			// (Part 9 §5.8.10.1).
			c.setShelvingLocked(Unshelved, 0, now)
		}
	}
	if u.Severity != nil && *u.Severity != st.severity {
		st.lastSeverity, st.lastSeverityTime = st.severity, now
		st.severity = *u.Severity
	}
	if u.Message != nil {
		st.message = ua.NewLocalizedText(*u.Message)
	}
	if u.Quality != nil && *u.Quality != st.quality {
		st.quality, st.qualityTime = *u.Quality, now
	}
	if u.Retain != nil {
		st.retain = *u.Retain
	}
	if u.Acked != nil && *u.Acked != st.acked {
		st.acked, st.ackedTime = *u.Acked, now
	}
	if u.Confirmed != nil && *u.Confirmed != st.confirmed {
		st.confirmed, st.confirmedTime = *u.Confirmed, now
	}
	if u.Suppressed != nil && *u.Suppressed != st.suppressed {
		st.suppressed, st.suppressedTime = *u.Suppressed, now
	}
}

// Report reports the current state in a new event.
func (c *Condition) Report() error { return c.Update(ConditionUpdate{}) }

// SetActive sets the ActiveState of an alarm.
func (c *Condition) SetActive(active bool) error { return c.Update(ConditionUpdate{Active: &active}) }

// SetSeverity sets the Severity.
func (c *Condition) SetSeverity(severity uint16) error {
	return c.Update(ConditionUpdate{Severity: &severity})
}

// SetMessage sets the Message.
func (c *Condition) SetMessage(msg string) error { return c.Update(ConditionUpdate{Message: &msg}) }

// SetQuality sets the Quality.
func (c *Condition) SetQuality(q ua.StatusCode) error { return c.Update(ConditionUpdate{Quality: &q}) }

// SetRetain sets Retain of a ConditionType instance.
func (c *Condition) SetRetain(retain bool) error { return c.Update(ConditionUpdate{Retain: &retain}) }

// SetSuppressed sets the SuppressedState of an alarm.
func (c *Condition) SetSuppressed(s bool) error { return c.Update(ConditionUpdate{Suppressed: &s}) }

// SetLimitState sets the active limit of an exclusive limit alarm.
func (c *Condition) SetLimitState(l LimitState) error { return c.Update(ConditionUpdate{Limit: &l}) }

// SetNonExclusiveLimits sets the limit states of a non-exclusive limit
// alarm.
func (c *Condition) SetNonExclusiveLimits(l NonExclusiveLimits) error {
	return c.Update(ConditionUpdate{NonExclusiveLimits: &l})
}

// EvaluateLimits compares v with the configured limits of a limit alarm and
// sets its limit states: an exclusive alarm takes the most severe limit
// exceeded, a non-exclusive alarm every limit exceeded. A high limit is
// exceeded when v >= limit, a low limit when v <= limit.
func (c *Condition) EvaluateLimits(v float64) error {
	l := c.cfg.Limits
	hi := func(p *float64) bool { return p != nil && v >= *p }
	lo := func(p *float64) bool { return p != nil && v <= *p }
	switch {
	case c.isExclusive:
		st := LimitNone
		switch {
		case hi(l.HighHigh):
			st = LimitHighHigh
		case hi(l.High):
			st = LimitHigh
		case lo(l.LowLow):
			st = LimitLowLow
		case lo(l.Low):
			st = LimitLow
		}
		return c.SetLimitState(st)
	case c.isNonExclusive:
		return c.SetNonExclusiveLimits(NonExclusiveLimits{HighHigh: hi(l.HighHigh), High: hi(l.High), Low: lo(l.Low), LowLow: lo(l.LowLow)})
	}
	return ErrConditionUnsupport
}

// Enable enables the condition (Part 9 §5.5.4). It returns
// Bad_ConditionAlreadyEnabled when the condition is enabled.
func (c *Condition) Enable() error {
	if sc := c.setEnabled(true); sc != ua.StatusOK {
		return sc
	}
	return nil
}

// Disable disables the condition (Part 9 §5.5.4). It returns
// Bad_ConditionAlreadyDisabled when the condition is disabled.
func (c *Condition) Disable() error {
	if sc := c.setEnabled(false); sc != ua.StatusOK {
		return sc
	}
	return nil
}

func (c *Condition) setEnabled(enable bool) ua.StatusCode {
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.mu.Lock()
	if sc := c.enableCheckLocked(enable); sc != ua.StatusOK {
		c.mu.Unlock()
		return sc
	}
	c.st.enabled, c.st.enabledTime = enable, time.Now()
	// The event of the transition to Disabled reports Retain false and
	// the state as Bad_ConditionDisabled (Part 9 §5.5.2); the enabled
	// condition reports its current state.
	ev := c.newEventLocked()
	c.mu.Unlock()
	c.deliver(ev)
	c.notifyChanges()
	return ua.StatusOK
}

func (c *Condition) enableCheckLocked(enable bool) ua.StatusCode {
	switch {
	case c.st.removed:
		return ua.StatusBadNodeIDUnknown
	case enable && c.st.enabled:
		return ua.StatusBadConditionAlreadyEnabled
	case !enable && !c.st.enabled:
		return ua.StatusBadConditionAlreadyDisabled
	}
	return ua.StatusOK
}

// newEventID returns a new unique EventId.
func newEventID() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

// newEventLocked gives the condition a new EventId and Time and returns its
// event. mu must be held.
func (c *Condition) newEventLocked() *BaseEvent {
	st := &c.st
	now := time.Now()
	if !now.After(st.time) {
		// Time never goes back between the events of a condition.
		now = st.time.Add(time.Microsecond)
	}
	st.eventID, st.time, st.receiveTime = newEventID(), now, now
	st.recentIDs = append(st.recentIDs, st.eventID)
	if len(st.recentIDs) > recentEventIDs {
		st.recentIDs = slices.Delete(st.recentIDs, 0, len(st.recentIDs)-recentEventIDs)
	}
	return c.eventLocked()
}

// knownEventIDLocked reports whether eventID is one of the recent events of
// the condition.
func (c *Condition) knownEventIDLocked(eventID []byte) bool {
	for _, e := range c.st.recentIDs {
		if string(e) == string(eventID) {
			return true
		}
	}
	return false
}

// deliver hands an event of the condition to the event items of its
// notifiers. emitMu must be held, mu not.
func (c *Condition) deliver(ev *BaseEvent) {
	for _, t := range c.targets {
		c.srv.emitEvent(t, ev, true)
	}
}

// notifyChanges reports the new values of the condition's variables to data
// change monitored items.
func (c *Condition) notifyChanges() {
	for _, v := range c.vars {
		c.srv.ChangeNotification(v)
	}
}

// --- shelving ---------------------------------------------------------------

// setShelvingLocked moves the ShelvedStateMachine to state; d is the
// shelving time of TimedShelved. mu must be held.
func (c *Condition) setShelvingLocked(state ShelvingState, d time.Duration, now time.Time) {
	st := &c.st
	c.stopShelveTimerLocked()
	st.shelvingFrom, st.shelving, st.shelvingTime = st.shelving, state, now
	st.unshelveAt = time.Time{}
	if state == OneShotShelved && c.cfg.MaxTimeShelved > 0 {
		d = c.cfg.MaxTimeShelved
	}
	if state != Unshelved && d > 0 {
		st.unshelveAt = now.Add(d)
		st.shelveTimerGen++
		gen := st.shelveTimerGen
		st.shelveTimer = time.AfterFunc(d, func() { c.shelveExpired(gen) })
	}
}

func (c *Condition) stopShelveTimerLocked() {
	if c.st.shelveTimer != nil {
		c.st.shelveTimer.Stop()
		c.st.shelveTimer = nil
	}
	c.st.shelveTimerGen++
}

// shelveExpired unshelves the alarm when its shelving time is over
// (Part 9 §5.8.10.1).
func (c *Condition) shelveExpired(gen uint64) {
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.mu.Lock()
	if c.st.removed || gen != c.st.shelveTimerGen || c.st.shelving == Unshelved {
		c.mu.Unlock()
		return
	}
	c.st.shelveTimer = nil
	c.setShelvingLocked(Unshelved, 0, time.Now())
	ev := c.newEventLocked()
	enabled := c.st.enabled
	c.mu.Unlock()
	if enabled {
		c.deliver(ev)
	}
	c.notifyChanges()
}

// --- caller identity --------------------------------------------------------

// clientUserID is the ClientUserId of a method call (Part 9 §5.5.2): the
// user name, the subject of an X.509 identity, or "Anonymous".
func clientUserID(ctx context.Context) string {
	caller, ok := MethodCallerFromContext(ctx)
	if !ok || caller == nil {
		return ""
	}
	switch t := caller.Identity.(type) {
	case *ua.UserNameIdentityToken:
		return t.UserName
	case *ua.X509IdentityToken:
		if cert, err := x509.ParseCertificate(t.CertificateData); err == nil {
			return cert.Subject.String()
		}
		return "X509"
	case *ua.IssuedIdentityToken:
		return "IssuedToken"
	}
	return "Anonymous"
}
