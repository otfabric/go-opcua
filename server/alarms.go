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
// Part 9 1.05 adds the optional AlarmConditionType states (SuppressedState,
// OutOfServiceState, SilenceState, LatchedState) with their methods
// (Suppress, Unsuppress, RemoveFromService, PlaceInService, Silence, Reset
// and the *2 variants that take a Comment), dialogs (DialogConditionType
// with Respond and Respond2), condition branches ([Condition.CreateBranch],
// [ConditionConfig.Branching]), alarm groups ([Server.AddAlarmGroup]) and
// the audit events of the methods ([WithAuditing]), and the optional
// AlarmConditionType components AudibleEnabled / AudibleSound, OnDelay /
// OffDelay, ReAlarmTime / ReAlarmRepeatCount and FirstInGroupFlag /
// FirstInGroup. [Server.AddAlarmMetrics] adds AlarmMetricsType objects.
// The timers run on the clock of [WithAlarmClock].

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
	// Serviceable adds the optional OutOfServiceState with the
	// RemoveFromService(2) and PlaceInService(2) methods (alarm types).
	Serviceable bool
	// Silenceable adds the optional SilenceState with the Silence method
	// (alarm types). A new activation of the alarm ends the silence.
	Silenceable bool
	// Latching adds the optional LatchedState with the Reset(2) methods
	// (alarm types): the alarm latches when it becomes active and stays
	// latched (and retained) until it is inactive and reset.
	Latching bool
	// Branching keeps the previous occurrence of an alarm that becomes
	// active again before its last activation was acknowledged (and
	// confirmed): the server moves that state to a branch with its own
	// BranchId, which a client acknowledges and confirms with the EventId
	// of the branch (Part 9 §5.5.2, §4.4). Acknowledgeable types.
	Branching bool
	// Dialog makes the condition a dialog (DialogConditionType and its
	// subtypes, Part 9 §5.6); required for those types.
	Dialog *DialogConfig
	// SuppressionGroups are AlarmSuppressionGroups (see
	// [Server.AddAlarmGroup]) whose suppression suppresses the alarm; it
	// needs Suppressible.
	SuppressionGroups []*ua.NodeID
	// AudibleSound adds the AudibleEnabled Property and the AudibleSound
	// variable (AudioVariableType) of an alarm (Part 9 §5.8.2): the sound
	// a console plays for it. AudibleEnabled starts true;
	// ConditionUpdate.AudibleEnabled changes it.
	AudibleSound *AudibleSound
	// OnDelay adds the OnDelay Property of an alarm: an activation is
	// reported only when the alarm stays active for OnDelay; one that ends
	// earlier is never reported. OffDelay adds the OffDelay Property: the
	// alarm stays active for OffDelay after it returns to normal, and an
	// activation within that time continues the alarm without a new
	// occurrence (Part 9 §5.8.2). The delays apply to the changes of
	// ActiveState (Active, Limit and NonExclusiveLimits of an update);
	// the other changes of the update take effect at once.
	OnDelay, OffDelay time.Duration
	// ReAlarmTime adds the ReAlarmTime Property and the ReAlarmRepeatCount
	// variable of an alarm: an alarm that is still active ReAlarmTime after
	// its activation (or its last re-alarm) is reported again as if it had
	// just become active (unacknowledged, unconfirmed, not silenced), and
	// ReAlarmRepeatCount counts the re-alarms of the activation.
	ReAlarmTime time.Duration
	// FirstInGroup is an alarm group (see [Server.AddAlarmGroup]) whose
	// first-out alarm the alarm can be: it adds the FirstInGroupFlag
	// variable and the FirstInGroup object (AlarmGroupType, listing the
	// alarms with the same FirstInGroup) and makes the alarm a member of
	// the group. FirstInGroupFlag is true for the alarm that became active
	// first while none of these alarms was active, until all of them are
	// inactive again.
	FirstInGroup *ua.NodeID
	// InputNode is the InputNode Property of an alarm.
	InputNode *ua.NodeID
	// NormalState is the NormalState Property of an OffNormalAlarmType.
	NormalState *ua.NodeID
	// Limits are the limits of a LimitAlarmType (and subtypes).
	Limits AlarmLimits
	// Properties are further Properties of the condition, such as those
	// of a subtype of the types above (ExpirationDate of
	// CertificateExpirationAlarmType). They are nodes of the instance and
	// fields of its events.
	Properties []ConditionProperty

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
	// The hooks of the Part 9 1.05 methods; comment is nil for the
	// variants without a Comment argument.
	OnSuppress func(ctx context.Context, c *Condition, suppress bool, comment *ua.LocalizedText) ua.StatusCode
	OnService  func(ctx context.Context, c *Condition, inService bool, comment *ua.LocalizedText) ua.StatusCode
	OnSilence  func(ctx context.Context, c *Condition) ua.StatusCode
	OnReset    func(ctx context.Context, c *Condition, comment *ua.LocalizedText) ua.StatusCode
	OnRespond  func(ctx context.Context, c *Condition, selectedResponse int32, comment *ua.LocalizedText) ua.StatusCode
}

// DialogConfig describes a dialog (DialogConditionType, Part 9 §5.6).
type DialogConfig struct {
	// Prompt is the initial Prompt of the dialog.
	Prompt string
	// ResponseOptions are the options a client responds with, by index
	// (ResponseOptionSet). Required.
	ResponseOptions []string
	// DefaultResponse, OkResponse and CancelResponse are indexes into
	// ResponseOptions; nil means none (-1).
	DefaultResponse, OkResponse, CancelResponse *int32
	// Active creates the dialog active (shown to the operator).
	Active bool
}

// AudibleSound is the AudibleSound of an alarm (AudioVariableType, Part 9
// §5.8.2, Part 3 AudioDataType).
type AudibleSound struct {
	// Sound is the audio data (AudioDataType, a ByteString).
	Sound []byte
	// ListID, AgencyID and VersionID identify the sound in a sound list;
	// each adds its optional Property when set.
	ListID, AgencyID, VersionID string
}

// dialogInfo are the static Properties of a dialog.
type dialogInfo struct {
	options                                     []*ua.LocalizedText
	defaultResponse, okResponse, cancelResponse int32
}

// ConditionProperty is a Property of a condition that ConditionConfig adds
// (scalar, with a DataType of namespace 0).
type ConditionProperty struct {
	Name     string
	DataType uint32
	// Value returns the value. It is called with the lock of the
	// condition held: it must not call methods of the Condition.
	Value func() any
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
	// BranchID is the BranchId of a branch, nil for the condition itself.
	BranchID     *ua.NodeID
	OutOfService bool
	Silenced     bool
	Latched      bool
	// DialogActive, Prompt and LastResponse are those of a dialog.
	DialogActive bool
	Prompt       *ua.LocalizedText
	LastResponse int32
	// AudibleEnabled is the AudibleEnabled of an alarm with AudibleSound.
	AudibleEnabled bool
	// ReAlarmRepeatCount counts the re-alarms of the current activation.
	ReAlarmRepeatCount int16
	// FirstInGroup is the FirstInGroupFlag of an alarm with FirstInGroup.
	FirstInGroup bool
	// PendingActive / PendingInactive tell that an activation waits for
	// OnDelay, or a return to normal for OffDelay.
	PendingActive, PendingInactive bool
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
	// OutOfService, Silenced and Latched set the OutOfServiceState,
	// SilenceState and LatchedState of an alarm that has them.
	OutOfService *bool
	Silenced     *bool
	Latched      *bool
	// DialogActive shows (true) or withdraws (false) a dialog; Prompt sets
	// its Prompt.
	DialogActive *bool
	Prompt       *string
	// AudibleEnabled sets the AudibleEnabled of an alarm with AudibleSound.
	AudibleEnabled *bool
}

// Errors of the Condition API.
var (
	ErrConditionRemoved   = errors.New("server: condition removed")
	ErrConditionNotAlarm  = errors.New("server: condition is not an alarm")
	ErrConditionUnsupport = errors.New("server: condition type does not have this state")
	ErrBranchUnknown      = errors.New("server: condition branch not found")
	ErrTooManyBranches    = errors.New("server: too many condition branches")
)

// maxConditionBranches bounds the branches of a condition.
const maxConditionBranches = 256

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
	shelveTimer    timerStop
	shelveTimerGen uint64

	limit        LimitState
	limitFrom    LimitState
	limitTime    time.Time
	nonExclusive NonExclusiveLimits
	nonExclTimes [4]time.Time
	recentIDs    [][]byte // EventIds of the recent events, newest last
	removed      bool

	outOfService     bool
	outOfServiceTime time.Time
	silenced         bool
	silenceTime      time.Time
	latched          bool
	latchedTime      time.Time

	dialogActive bool
	dialogTime   time.Time
	prompt       *ua.LocalizedText
	lastResponse int32

	// branchID is the BranchId of a branch state, nil for the condition.
	branchID *ua.NodeID
	// deleted marks a branch being deleted: its last event has Retain
	// false.
	deleted bool

	audibleEnabled bool
	// reAlarmCount is ReAlarmRepeatCount; reAlarmTimer re-alarms the
	// active alarm.
	reAlarmCount int16
	reAlarmTimer timerStop
	reAlarmGen   uint64
	// delayed is the activation change (Active, Limit, NonExclusiveLimits)
	// that waits for OnDelay (delayOn) or OffDelay.
	delayed    *ConditionUpdate
	delayOn    bool
	delayTimer timerStop
	delayGen   uint64
	// firstInGroup is the FirstInGroupFlag of a branch (the condition
	// reads it from its group).
	firstInGroup bool
}

// suppressedOrShelved is the SuppressedOrShelved of an alarm (Part 9
// §5.8.2): suppressed, shelved or out of service.
func (st *conditionState) suppressedOrShelved() bool {
	return st.suppressed || st.shelving != Unshelved || st.outOfService
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

	isAck, isAlarm, isLimit, isExclusive, isNonExclusive, isOffNormal, isDialog bool
	dialog                                                                      *dialogInfo

	// targets are the notifiers whose event items receive the events.
	targets []*ua.NodeID
	// table are the components of the instance.
	table []condField
	// nodes are the nodes of the instance; vars the variables, for change
	// notifications.
	nodes      []*ua.NodeID
	vars       []*ua.NodeID
	shelvingID *ua.NodeID
	// firstGroup is the FirstInGroup group; firstInGroupID the NodeId of
	// the FirstInGroup object.
	firstGroup     *AlarmGroup
	firstInGroupID *ua.NodeID
	methods        [][2]*ua.NodeID
	sourceRefs     func() // removes the references of the source

	// emitMu serializes the changes and the events of the condition, so
	// that every notifier sees them in order. It is never taken with mu
	// held, and value functions take only mu.
	emitMu sync.Mutex
	mu     sync.RWMutex
	st     conditionState
	// branches are the branches of the condition, oldest first (mu).
	branches []*conditionState
	// metricsTouched are the AlarmMetrics a change counted in, to notify
	// after the change (mu).
	metricsTouched []*AlarmMetrics
}

// alarmManager holds the conditions of a server.
type alarmManager struct {
	mu         sync.Mutex
	conds      map[string]*Condition // by ConditionId
	shelving   map[string]*Condition // by ShelvingState NodeId
	refreshing map[uint32]bool       // subscriptions with a ConditionRefresh running
	closed     bool
	groups     groupState
	metrics    metricsState
}

func newAlarmManager() *alarmManager {
	return &alarmManager{conds: map[string]*Condition{}, shelving: map[string]*Condition{}, refreshing: map[uint32]bool{},
		groups: groupState{groups: map[string]*AlarmGroup{}}, metrics: metricsState{byID: map[string]*AlarmMetrics{}}}
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
		c.stopTimersLocked()
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
		isNonExclusive: is(id.NonExclusiveLimitAlarmType), isOffNormal: is(id.OffNormalAlarmType),
		isDialog: is(id.DialogConditionType)}
	if err := c.checkConfig(); err != nil {
		return nil, err
	}
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

	now := s.now()
	sev := cfg.Severity
	if sev == 0 {
		sev = 500
	}
	c.st = conditionState{
		enabled: !cfg.Disabled, enabledTime: now, retain: cfg.Retain,
		severity: sev, lastSeverity: sev, lastSeverityTime: now,
		message: ua.NewLocalizedText(cfg.Message), quality: ua.StatusOK, qualityTime: now,
		comment: &ua.LocalizedText{}, acked: true, confirmed: true, lastResponse: -1,
		audibleEnabled: cfg.AudibleSound != nil,
	}
	if c.isDialog {
		c.st.prompt = ua.NewLocalizedText(cfg.Dialog.Prompt)
		c.st.dialogActive, c.st.dialogTime = cfg.Dialog.Active, now
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
	s.joinSuppressionGroups(c)
	c.joinFirstInGroup()

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
	// The condition leaves its alarm groups after emitMu is released: a
	// group change holds the groups' lock while it updates conditions.
	defer s.leaveAlarmGroups(c)
	defer c.leaveFirstInGroup()
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.mu.Lock()
	c.st.removed = true
	c.stopTimersLocked()
	c.branches = nil
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
	return c.snapshotLocked(&c.st)
}

func (c *Condition) snapshotLocked(st *conditionState) ConditionState {
	return ConditionState{
		BranchID: st.branchID,
		EventID:  slices.Clone(st.eventID), Time: st.time, Enabled: st.enabled, Retain: c.retainOfLocked(st),
		Severity: st.severity, LastSeverity: st.lastSeverity, Message: st.message, Quality: st.quality,
		Comment: st.comment, ClientUserID: st.clientUserID, Acked: st.acked, Confirmed: st.confirmed,
		Active: st.active, Suppressed: st.suppressed, Shelving: st.shelving, UnshelveAt: st.unshelveAt,
		Limit: st.limit, NonExclusiveLimits: st.nonExclusive,
		OutOfService: st.outOfService, Silenced: st.silenced, Latched: st.latched,
		DialogActive: st.dialogActive, Prompt: st.prompt, LastResponse: st.lastResponse,
		AudibleEnabled: st.audibleEnabled, ReAlarmRepeatCount: st.reAlarmCount, FirstInGroup: c.firstInGroupOfLocked(st),
		PendingActive: st.delayed != nil && st.delayOn, PendingInactive: st.delayed != nil && !st.delayOn,
	}
}

// retainLocked is the Retain of the condition (Part 9 §5.5.2): false while
// disabled; for the acknowledgeable types true while the condition waits for
// an acknowledgement or confirmation, for alarms also while active.
func (c *Condition) retainLocked() bool { return c.retainOfLocked(&c.st) }

// retainOfLocked is the Retain of st, the state of the condition or of a
// branch: a branch is retained while it waits for an acknowledgement or a
// confirmation, a dialog while it is active, an alarm also while it is
// active or latched.
func (c *Condition) retainOfLocked(st *conditionState) bool {
	if !c.st.enabled || st.deleted {
		return false
	}
	if c.isDialog {
		return st.dialogActive
	}
	if !c.isAck {
		return st.retain
	}
	r := !st.acked || (c.cfg.Confirmable && !st.confirmed)
	if st.branchID == nil && c.isAlarm && (st.active || st.latched) {
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
	now := c.srv.now()
	u, delayedOnly := c.delayLocked(u)
	if delayedOnly {
		// Only an activation change that waits for its delay: nothing
		// to report yet.
		c.mu.Unlock()
		return nil
	}
	c.commitLocked(u, now)
	return nil
}

// commitLocked applies u, reports the change in an event and unlocks mu.
// emitMu and mu must be held.
func (c *Condition) commitLocked(u ConditionUpdate, now time.Time) {
	evs, others := c.applyLocked(u, now)
	evs = append(evs, c.newEventLocked())
	enabled := c.st.enabled
	c.mu.Unlock()
	if enabled {
		for _, ev := range evs {
			c.deliver(ev)
		}
	}
	c.notifyChanges()
	for _, o := range others {
		o.notifyChanges()
	}
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
	if (u.OutOfService != nil && !c.cfg.Serviceable) || (u.Silenced != nil && !c.cfg.Silenceable) || (u.Latched != nil && !c.cfg.Latching) {
		return ErrConditionUnsupport
	}
	if (u.DialogActive != nil || u.Prompt != nil) && !c.isDialog {
		return ErrConditionUnsupport
	}
	if u.AudibleEnabled != nil && c.cfg.AudibleSound == nil {
		return ErrConditionUnsupport
	}
	return nil
}

// applyLocked applies u to the state of the condition and returns the
// event of a branch it creates (Branching) and the other conditions whose
// FirstInGroupFlag changed.
func (c *Condition) applyLocked(u ConditionUpdate, now time.Time) ([]*BaseEvent, []*Condition) {
	var evs []*BaseEvent
	var others []*Condition
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
		since := st.activeTime
		st.active, st.activeTime = *active, now
		if c.firstGroup != nil {
			others = c.firstGroup.noteActive(c, st.active)
		}
		if st.active {
			evs = c.annunciateLocked(evs, now)
			st.reAlarmCount = 0
			c.startReAlarmLocked()
			c.metricsLocked(func(m *AlarmMetrics) { m.activated(now) })
		} else {
			c.stopReAlarmLocked()
			c.metricsLocked(func(m *AlarmMetrics) { m.deactivated(now.Sub(since)) })
			if st.shelving == OneShotShelved {
				// A OneShotShelved alarm unshelves when it becomes
				// inactive (Part 9 §5.8.10.1).
				c.setShelvingLocked(Unshelved, 0, now)
			}
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
		c.setAckedLocked(st, *u.Acked, now)
	}
	if u.Confirmed != nil && *u.Confirmed != st.confirmed {
		st.confirmed, st.confirmedTime = *u.Confirmed, now
	}
	if u.Suppressed != nil && *u.Suppressed != st.suppressed {
		st.suppressed, st.suppressedTime = *u.Suppressed, now
	}
	if u.OutOfService != nil && *u.OutOfService != st.outOfService {
		st.outOfService, st.outOfServiceTime = *u.OutOfService, now
	}
	if u.Silenced != nil && *u.Silenced != st.silenced {
		st.silenced, st.silenceTime = *u.Silenced, now
	}
	if u.Latched != nil && *u.Latched != st.latched {
		st.latched, st.latchedTime = *u.Latched, now
	}
	if u.Prompt != nil {
		st.prompt = ua.NewLocalizedText(*u.Prompt)
	}
	if u.DialogActive != nil && *u.DialogActive != st.dialogActive {
		st.dialogActive, st.dialogTime = *u.DialogActive, now
	}
	if u.AudibleEnabled != nil {
		st.audibleEnabled = *u.AudibleEnabled
	}
	return evs, others
}

// annunciateLocked makes the alarm a new occurrence, as on its activation
// (and on a re-alarm): the previous occurrence, if it still waits for an
// acknowledgement or confirmation, moves to a branch (Branching); the alarm
// needs a new acknowledgement and confirmation (Part 9 §5.7.2, §5.8.2), its
// silence ends and a latching alarm latches. mu must be held.
func (c *Condition) annunciateLocked(evs []*BaseEvent, now time.Time) []*BaseEvent {
	st := &c.st
	fresh := false // the previous occurrence moved to a branch
	if c.cfg.Branching && c.isAck && st.enabled && (!st.acked || (c.cfg.Confirmable && !st.confirmed)) &&
		len(c.branches) < maxConditionBranches {
		prev := *st
		prev.active = false
		prev.firstInGroup = c.firstInGroupOfLocked(st)
		evs = append(evs, c.newEventOfLocked(c.newBranchLocked(&prev)))
		fresh = true
	}
	if c.cfg.Silenceable && st.silenced {
		st.silenced, st.silenceTime = false, now
	}
	if c.cfg.Latching && !st.latched {
		st.latched, st.latchedTime = true, now
	}
	// An alarm that is still unacknowledged (or unconfirmed) stays so since
	// its first annunciation, unless that occurrence moved to a branch: the
	// transition time and MaximumUnAck count from there.
	if c.isAck && (st.acked || fresh) {
		st.acked, st.ackedTime = false, now
	}
	if c.isAck && c.cfg.Confirmable && (st.confirmed || fresh) {
		st.confirmed, st.confirmedTime = false, now
	}
	return evs
}

// setAckedLocked sets the AckedState of st; an acknowledgement reports the
// time the alarm was unacknowledged to the alarm metrics.
func (c *Condition) setAckedLocked(st *conditionState, acked bool, now time.Time) {
	if acked && !st.acked && c.isAlarm {
		unacked := now.Sub(st.ackedTime)
		c.metricsLocked(func(m *AlarmMetrics) { m.acknowledged(unacked) })
	}
	st.acked, st.ackedTime = acked, now
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
	c.st.enabled, c.st.enabledTime = enable, c.srv.now()
	// Disabling ends the branches: each reports a last event with Retain
	// false. The event of the transition to Disabled reports Retain false
	// and the state as Bad_ConditionDisabled (Part 9 §5.5.2); the enabled
	// condition reports its current state.
	var evs []*BaseEvent
	if !enable {
		for _, b := range c.branches {
			b.deleted, b.enabled, b.enabledTime = true, false, c.st.enabledTime
			evs = append(evs, c.newEventOfLocked(b))
		}
		c.branches = nil
	}
	evs = append(evs, c.newEventLocked())
	c.mu.Unlock()
	for _, ev := range evs {
		c.deliver(ev)
	}
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
func (c *Condition) newEventLocked() *BaseEvent { return c.newEventOfLocked(&c.st) }

// newEventOfLocked gives st (the condition's state or a branch) a new
// EventId and Time and returns its event. mu must be held.
func (c *Condition) newEventOfLocked(st *conditionState) *BaseEvent {
	now := c.srv.now()
	if !now.After(st.time) {
		// Time never goes back between the events of a condition.
		now = st.time.Add(time.Microsecond)
	}
	st.eventID, st.time, st.receiveTime = newEventID(), now, now
	st.recentIDs = append(st.recentIDs, st.eventID)
	if len(st.recentIDs) > recentEventIDs {
		st.recentIDs = slices.Delete(st.recentIDs, 0, len(st.recentIDs)-recentEventIDs)
	}
	return c.eventOfLocked(st)
}

// knownEventIDLocked reports whether eventID is one of the recent events of
// st.
func knownEventIDLocked(st *conditionState, eventID []byte) bool {
	for _, e := range st.recentIDs {
		if string(e) == string(eventID) {
			return true
		}
	}
	return false
}

// stateOfEventLocked returns the state an EventId refers to: the condition
// or one of its branches; nil if the EventId is unknown.
func (c *Condition) stateOfEventLocked(eventID []byte) *conditionState {
	if knownEventIDLocked(&c.st, eventID) {
		return &c.st
	}
	for _, b := range c.branches {
		if knownEventIDLocked(b, eventID) {
			return b
		}
	}
	return nil
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
	c.mu.Lock()
	touched := c.metricsTouched
	c.metricsTouched = nil
	c.mu.Unlock()
	for _, m := range touched {
		m.notify()
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
		st.shelveTimer = c.srv.alarmClock().AfterFunc(d, func() { c.shelveExpired(gen) })
	}
}

func (c *Condition) stopShelveTimerLocked() {
	if c.st.shelveTimer != nil {
		c.st.shelveTimer()
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
	c.setShelvingLocked(Unshelved, 0, c.srv.now())
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
