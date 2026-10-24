// SPDX-License-Identifier: MIT

package pubsub

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// DiagnosticsCounterID identifies a counter of the PubSub diagnostics
// objects (Part 14 §9.1.11): the state counters every component has
// (PubSubDiagnosticsType, §9.1.11.2) and the counters of the subtypes for
// writer groups, reader groups, writers and readers (§9.1.11.9 to
// §9.1.11.12). Its String is the BrowseName of the counter.
type DiagnosticsCounterID uint8

// Diagnostics counters.
const (
	// CounterStateError counts transitions to Error (§9.1.11.2).
	CounterStateError DiagnosticsCounterID = iota
	// CounterStateOperationalByMethod counts transitions to Operational
	// caused by the Enable method of the component.
	CounterStateOperationalByMethod
	// CounterStateOperationalByParent counts transitions to Operational
	// because the parent became Operational.
	CounterStateOperationalByParent
	// CounterStateOperationalFromError counts transitions from Error to
	// Operational.
	CounterStateOperationalFromError
	// CounterStatePausedByParent counts transitions to Paused because the
	// parent is Paused or Disabled.
	CounterStatePausedByParent
	// CounterStateDisabledByMethod counts transitions to Disabled caused
	// by the Disable method of the component.
	CounterStateDisabledByMethod
	// CounterSentNetworkMessages counts the NetworkMessages a writer group
	// sent (§9.1.11.9).
	CounterSentNetworkMessages
	// CounterFailedTransmissions counts the NetworkMessages of a writer
	// group that could not be encoded or sent.
	CounterFailedTransmissions
	// CounterEncryptionErrors counts the NetworkMessages of a writer group
	// that could not be signed or encrypted.
	CounterEncryptionErrors
	// CounterReceivedNetworkMessages counts the NetworkMessages a reader
	// group received and processed (§9.1.11.10).
	CounterReceivedNetworkMessages
	// CounterReceivedInvalidNetworkMessages counts received NetworkMessages
	// for a reader group that could not be decoded.
	CounterReceivedInvalidNetworkMessages
	// CounterDecryptionErrors counts received NetworkMessages that failed
	// the security checks (signature, decryption, keys, security mode) of
	// a reader group or a reader.
	CounterDecryptionErrors
	// CounterFailedDataSetMessages counts the DataSetMessages of a writer
	// that could not be encoded or sent (§9.1.11.11), and the received
	// DataSetMessages a reader could not process: a MajorVersion that
	// does not match its DataSetMetaData or fields it cannot place
	// (§9.1.11.12).
	CounterFailedDataSetMessages

	numCounters
)

var counterNames = [numCounters]string{
	"StateError", "StateOperationalByMethod", "StateOperationalByParent", "StateOperationalFromError",
	"StatePausedByParent", "StateDisabledByMethod", "SentNetworkMessages", "FailedTransmissions",
	"EncryptionErrors", "ReceivedNetworkMessages", "ReceivedInvalidNetworkMessages", "DecryptionErrors",
	"FailedDataSetMessages",
}

func (c DiagnosticsCounterID) String() string {
	if c < numCounters {
		return counterNames[c]
	}
	return "DiagnosticsCounterID(" + strconv.Itoa(int(c)) + ")"
}

// Classification is the classification of a counter: Error for the counters
// of failures, Information for the others (Part 14 §9.1.11.6).
func (c DiagnosticsCounterID) Classification() ua.PubSubDiagnosticsCounterClassification {
	if c < numCounters && counterErrors[c] {
		return ua.PubSubDiagnosticsCounterClassificationError
	}
	return ua.PubSubDiagnosticsCounterClassificationInformation
}

// Level is the DiagnosticsLevel a counter belongs to (Part 14 §9.1.11.4):
// the counter is active while the DiagnosticsLevel of its object is at
// least this level. The counters of the message security and of invalid
// messages are Advanced, the others Basic.
func (c DiagnosticsCounterID) Level() ua.DiagnosticsLevel {
	if c < numCounters && counterAdvanced[c] {
		return ua.DiagnosticsLevelAdvanced
	}
	return ua.DiagnosticsLevelBasic
}

var (
	counterErrors = [numCounters]bool{
		CounterStateError: true, CounterFailedTransmissions: true, CounterEncryptionErrors: true,
		CounterReceivedInvalidNetworkMessages: true, CounterDecryptionErrors: true, CounterFailedDataSetMessages: true,
	}
	counterAdvanced = [numCounters]bool{
		CounterEncryptionErrors: true, CounterReceivedInvalidNetworkMessages: true, CounterDecryptionErrors: true,
	}
)

var stateCounters = []DiagnosticsCounterID{
	CounterStateError, CounterStateOperationalByMethod, CounterStateOperationalByParent,
	CounterStateOperationalFromError, CounterStatePausedByParent, CounterStateDisabledByMethod,
}

// DiagnosticsCountersOf returns the counters of the diagnostics object of a
// component kind, in the order of the specification. Published data sets
// have no diagnostics object.
func DiagnosticsCountersOf(kind ComponentKind) []DiagnosticsCounterID {
	var extra []DiagnosticsCounterID
	switch kind {
	case KindPubSub, KindConnection:
	case KindWriterGroup:
		extra = []DiagnosticsCounterID{CounterSentNetworkMessages, CounterFailedTransmissions, CounterEncryptionErrors}
	case KindReaderGroup:
		extra = []DiagnosticsCounterID{CounterReceivedNetworkMessages, CounterReceivedInvalidNetworkMessages, CounterDecryptionErrors}
	case KindDataSetWriter:
		extra = []DiagnosticsCounterID{CounterFailedDataSetMessages}
	case KindDataSetReader:
		extra = []DiagnosticsCounterID{CounterFailedDataSetMessages, CounterDecryptionErrors}
	default:
		return nil
	}
	return append(append([]DiagnosticsCounterID(nil), stateCounters...), extra...)
}

// DiagnosticsCounter is the value of a diagnostics counter
// (PubSubDiagnosticsCounterType, Part 14 §9.1.11.5).
type DiagnosticsCounter struct {
	ID DiagnosticsCounterID
	// Value is the count since the last reset; it stops at the largest
	// UInt32.
	Value uint32
	// Active reports whether the counter counts: its Level is within the
	// DiagnosticsLevel of the object. An inactive counter keeps its value
	// and is set to 0 when it becomes active again.
	Active         bool
	Classification ua.PubSubDiagnosticsCounterClassification
	Level          ua.DiagnosticsLevel
	// TimeFirstChange is when the value went from 0 to 1; zero while the
	// value is 0.
	TimeFirstChange time.Time
}

// DiagnosticsLiveValues are the LiveValues of a diagnostics object. Which of
// them a component kind has, and at which DiagnosticsLevel, is defined by
// Part 14 §9.1.11.7 to §9.1.11.12; the others are zero.
type DiagnosticsLiveValues struct {
	// ConfiguredDataSetWriters and OperationalDataSetWriters count the
	// writers of the runtime (PublishSubscribe) or of a writer group, all
	// and those that are Operational.
	ConfiguredDataSetWriters  uint16
	OperationalDataSetWriters uint16
	// ConfiguredDataSetReaders and OperationalDataSetReaders count the
	// readers of the runtime or of a reader group.
	ConfiguredDataSetReaders  uint16
	OperationalDataSetReaders uint16
	// ResolvedAddress is the address of a connection.
	ResolvedAddress string
	// MessageSequenceNumber and StatusCode are those of the last
	// DataSetMessage a writer sent or a reader received.
	MessageSequenceNumber uint16
	StatusCode            ua.StatusCode
	// MajorVersion and MinorVersion are the ConfigurationVersion of the
	// DataSetMetaData of a writer or a reader.
	MajorVersion uint32
	MinorVersion uint32
	// SecurityTokenID is the current token of the SecurityGroup of a
	// secured writer group or reader, TimeToNextTokenID the time until the
	// next one if the key source knows it.
	SecurityTokenID   uint32
	TimeToNextTokenID time.Duration
}

// Diagnostics is the diagnostics object of a component (Part 14 §9.1.11).
type Diagnostics struct {
	ComponentInfo
	// Level is the DiagnosticsLevel of the object.
	Level ua.DiagnosticsLevel
	// TotalInformation and TotalError are the sums of the active counters
	// classified Information and Error; TotalInformationFirstChange and
	// TotalErrorFirstChange the earliest TimeFirstChange among them.
	TotalInformation            uint32
	TotalError                  uint32
	TotalInformationFirstChange time.Time
	TotalErrorFirstChange       time.Time
	// SubError reports whether the diagnostics object of a child (the
	// connections of the runtime, the groups of a connection, the
	// writers or readers of a group) has a TotalError above 0.
	SubError bool
	// Counters are the counters of the component kind, in the order of
	// [DiagnosticsCountersOf].
	Counters   []DiagnosticsCounter
	LiveValues DiagnosticsLiveValues
}

// Counter returns a counter of the object.
func (d *Diagnostics) Counter(id DiagnosticsCounterID) (DiagnosticsCounter, bool) {
	for _, c := range d.Counters {
		if c.ID == id {
			return c, true
		}
	}
	return DiagnosticsCounter{}, false
}

// diagCounter is one counter of a component, guarded by PubSub.mu.
type diagCounter struct {
	v     uint32
	first time.Time
}

// diagState is the diagnostics state of a component, guarded by PubSub.mu.
type diagState struct {
	// level is the DiagnosticsLevel if levelSet, else the default of the
	// runtime.
	level    ua.DiagnosticsLevel
	levelSet bool
	ctr      [numCounters]diagCounter
	// enableReq and disableReq mark a pending Enable or Disable method
	// call, for the counters of the state transitions it causes.
	enableReq  bool
	disableReq bool
	// The last DataSetMessage of a writer or a reader.
	lastSeq    uint16
	lastStatus ua.StatusCode
}

// WithDiagnosticsLevel sets the DiagnosticsLevel the diagnostics objects of
// the components start with. The default is Basic.
func WithDiagnosticsLevel(l ua.DiagnosticsLevel) Option {
	return func(o *options) { o.diagLevel = l }
}

func (p *PubSub) levelOf(b *base) ua.DiagnosticsLevel {
	if b.diag.levelSet {
		return b.diag.level
	}
	return p.opts.diagLevel
}

// count adds n to a counter of a component if it is active. p.mu is held.
func (p *PubSub) count(b *base, c DiagnosticsCounterID, n uint64) {
	if n == 0 || c.Level() > p.levelOf(b) {
		return
	}
	dc := &b.diag.ctr[c]
	if dc.v == 0 {
		dc.first = time.Now()
	}
	if n >= uint64(math.MaxUint32-dc.v) {
		dc.v = math.MaxUint32
	} else {
		dc.v += uint32(n)
	}
}

// countTransition counts a state transition by its cause (Part 14 §9.1.11.2
// Table 311). The transitions of the runtime itself caused by Start and
// stop count as caused by its parent, the application. p.mu is held.
func (p *PubSub) countTransition(b *base, old, s ua.PubSubState) {
	d := &b.diag
	switch s {
	case ua.PubSubStateError:
		p.count(b, CounterStateError, 1)
	case ua.PubSubStateOperational:
		switch {
		case old == ua.PubSubStateError:
			p.count(b, CounterStateOperationalFromError, 1)
		case d.enableReq:
			p.count(b, CounterStateOperationalByMethod, 1)
		default:
			p.count(b, CounterStateOperationalByParent, 1)
		}
		d.enableReq = false
	case ua.PubSubStatePaused:
		p.count(b, CounterStatePausedByParent, 1)
		d.enableReq = false
	case ua.PubSubStateDisabled:
		if d.disableReq {
			p.count(b, CounterStateDisabledByMethod, 1)
		}
		d.enableReq, d.disableReq = false, false
	case ua.PubSubStatePreOperational:
	}
}

// diagBase returns the base of a component with a diagnostics object.
// p.mu is held.
func (p *PubSub) diagBase(id ComponentID) (*base, component, error) {
	if id == Root {
		return &p.root, nil, nil
	}
	c := p.comps[id]
	if c == nil {
		return nil, nil, fmt.Errorf("pubsub: no component with id %d: %w", id, ua.StatusBadNotFound)
	}
	if c.b().kind == KindPublishedDataSet {
		return nil, nil, fmt.Errorf("pubsub: a published data set has no diagnostics: %w", ua.StatusBadNotSupported)
	}
	return c.b(), c, nil
}

// SetDiagnosticsLevel sets the DiagnosticsLevel of the diagnostics object of
// a component (or, with [Root], of the runtime). Counters that become active
// start again at 0 (Part 14 §9.1.11.4).
func (p *PubSub) SetDiagnosticsLevel(id ComponentID, l ua.DiagnosticsLevel) error {
	if l > ua.DiagnosticsLevelDebug {
		return fmt.Errorf("pubsub: DiagnosticsLevel %d: %w", l, ua.StatusBadOutOfRange)
	}
	p.lock()
	defer p.unlock()
	b, _, err := p.diagBase(id)
	if err != nil {
		return err
	}
	old := p.levelOf(b)
	for c := range numCounters {
		if lv := c.Level(); lv > old && lv <= l {
			b.diag.ctr[c] = diagCounter{}
		}
	}
	b.diag.level, b.diag.levelSet = l, true
	return nil
}

// ResetDiagnostics sets the counters of the diagnostics object of a
// component (or, with [Root], of the runtime) back to 0 (the Reset method,
// Part 14 §9.1.11.3). It does not reset the counters of the children, nor
// the [Counters] of [PubSub.Status].
func (p *PubSub) ResetDiagnostics(id ComponentID) error {
	p.lock()
	defer p.unlock()
	b, _, err := p.diagBase(id)
	if err != nil {
		return err
	}
	b.diag.ctr = [numCounters]diagCounter{}
	return nil
}

// Diagnostics returns the diagnostics object of a component (or, with
// [Root], of the runtime): its counters and its LiveValues. Published data
// sets have none (Bad_NotSupported).
func (p *PubSub) Diagnostics(id ComponentID) (Diagnostics, error) {
	p.lock()
	b, c, err := p.diagBase(id)
	if err != nil {
		p.unlock()
		return Diagnostics{}, err
	}
	d := p.diagnosticsLocked(b)
	switch x := c.(type) {
	case nil:
		for _, conn := range p.conns {
			d.SubError = d.SubError || p.totalError(&conn.base) > 0
			for _, g := range conn.wgs {
				for _, w := range g.writers {
					d.LiveValues.ConfiguredDataSetWriters++
					if w.state == ua.PubSubStateOperational {
						d.LiveValues.OperationalDataSetWriters++
					}
				}
			}
			for _, g := range conn.rgs {
				for _, r := range g.readers {
					d.LiveValues.ConfiguredDataSetReaders++
					if r.state == ua.PubSubStateOperational {
						d.LiveValues.OperationalDataSetReaders++
					}
				}
			}
		}
	case *connection:
		for _, g := range x.wgs {
			d.SubError = d.SubError || p.totalError(&g.base) > 0
		}
		for _, g := range x.rgs {
			d.SubError = d.SubError || p.totalError(&g.base) > 0
		}
		d.LiveValues.ResolvedAddress = x.url
	case *writerGroup:
		for _, w := range x.writers {
			d.SubError = d.SubError || p.totalError(&w.base) > 0
			d.LiveValues.ConfiguredDataSetWriters++
			if w.state == ua.PubSubStateOperational {
				d.LiveValues.OperationalDataSetWriters++
			}
		}
	case *readerGroup:
		for _, r := range x.readers {
			d.SubError = d.SubError || p.totalError(&r.base) > 0
			d.LiveValues.ConfiguredDataSetReaders++
			if r.state == ua.PubSubStateOperational {
				d.LiveValues.OperationalDataSetReaders++
			}
		}
	case *dataSetWriter:
		d.LiveValues.MessageSequenceNumber = x.diag.lastSeq
		d.LiveValues.StatusCode = x.diag.lastStatus
		if x.pds != nil {
			d.LiveValues.MajorVersion, d.LiveValues.MinorVersion = versionOf(x.pds.md)
		}
	case *dataSetReader:
		d.LiveValues.MessageSequenceNumber = x.diag.lastSeq
		d.LiveValues.StatusCode = x.diag.lastStatus
		d.LiveValues.MajorVersion, d.LiveValues.MinorVersion = versionOf(x.md)
	}
	var groupID string
	switch x := c.(type) {
	case *writerGroup:
		if x.mode > ua.MessageSecurityModeNone {
			groupID = x.cfg.SecurityGroupID
		}
	case *dataSetReader:
		if x.mode > ua.MessageSecurityModeNone {
			groupID = x.groupID
		}
	}
	p.unlock()
	if groupID != "" {
		d.LiveValues.SecurityTokenID, d.LiveValues.TimeToNextTokenID = tokenOf(p.KeySource(groupID))
	}
	return d, nil
}

func versionOf(md *ua.DataSetMetaDataType) (uint32, uint32) {
	if md == nil || md.ConfigurationVersion == nil {
		return 0, 0
	}
	return md.ConfigurationVersion.MajorVersion, md.ConfigurationVersion.MinorVersion
}

// tokenOf returns the current security token of a key source and, if it
// tells, the time until the next one.
func tokenOf(ks security.KeySource) (uint32, time.Duration) {
	if ks == nil {
		return 0, 0
	}
	var tok uint32
	if k, err := ks.CurrentKeys(); err == nil && k != nil {
		tok = k.TokenID
	}
	var next time.Duration
	switch x := ks.(type) {
	case interface{ TimeToNextKey() time.Duration }:
		next = x.TimeToNextKey()
	case interface{ Ring() *security.KeyRing }:
		if r := x.Ring(); r != nil {
			next = r.TimeToNextKey()
		}
	}
	return tok, next
}

// diagnosticsLocked returns the counters and totals of a component. p.mu
// is held.
func (p *PubSub) diagnosticsLocked(b *base) Diagnostics {
	lvl := p.levelOf(b)
	d := Diagnostics{ComponentInfo: b.info(), Level: lvl}
	for _, id := range DiagnosticsCountersOf(b.kind) {
		dc := b.diag.ctr[id]
		c := DiagnosticsCounter{
			ID: id, Value: dc.v, Active: id.Level() <= lvl,
			Classification: id.Classification(), Level: id.Level(), TimeFirstChange: dc.first,
		}
		d.Counters = append(d.Counters, c)
		if !c.Active || c.Value == 0 {
			continue
		}
		if c.Classification == ua.PubSubDiagnosticsCounterClassificationError {
			d.TotalError = addSat(d.TotalError, c.Value)
			d.TotalErrorFirstChange = earliest(d.TotalErrorFirstChange, c.TimeFirstChange)
		} else {
			d.TotalInformation = addSat(d.TotalInformation, c.Value)
			d.TotalInformationFirstChange = earliest(d.TotalInformationFirstChange, c.TimeFirstChange)
		}
	}
	return d
}

// totalError returns the TotalError of a component. p.mu is held.
func (p *PubSub) totalError(b *base) uint32 {
	lvl := p.levelOf(b)
	var t uint32
	for _, id := range DiagnosticsCountersOf(b.kind) {
		if id.Classification() == ua.PubSubDiagnosticsCounterClassificationError && id.Level() <= lvl {
			t = addSat(t, b.diag.ctr[id].v)
		}
	}
	return t
}

func addSat(a, b uint32) uint32 {
	if b > math.MaxUint32-a {
		return math.MaxUint32
	}
	return a + b
}

func earliest(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// isSecurityError reports whether a codec error is a failure of the message
// security: signing, verification, encryption, decryption, missing keys or
// a security mode that does not satisfy the receiver.
func isSecurityError(err error) bool {
	return errors.Is(err, uadp.ErrSecurityChecksFailed) || errors.Is(err, uadp.ErrSecurityMode) ||
		errors.Is(err, security.ErrNoKeys) || errors.Is(err, security.ErrSignature)
}
