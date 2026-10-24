// SPDX-License-Identifier: MIT

package amqp

import "math"

// Role is the role of a link end (§2.8.1): a boolean on the wire, false
// for the sender.
type Role uint8

// Roles (§2.8.1).
const (
	RoleSender Role = iota
	RoleReceiver
)

func decodeRole(f fieldList, i int) (Role, error) {
	r, err := f.boolAt(i, false)
	if r {
		return RoleReceiver, err
	}
	return RoleSender, err
}

// Sender settle modes (§2.8.2).
const (
	SenderSettleUnsettled uint8 = 0
	SenderSettleSettled   uint8 = 1
	SenderSettleMixed     uint8 = 2
)

// Receiver settle modes (§2.8.3).
const (
	ReceiverSettleFirst  uint8 = 0
	ReceiverSettleSecond uint8 = 1
)

// Open negotiates the connection parameters (§2.7.1).
type Open struct {
	ContainerID string
	Hostname    string
	// MaxFrameSize: 0 means the default (no limit, 4294967295).
	MaxFrameSize uint32
	ChannelMax   uint16
	// IdleTimeout in milliseconds; 0: none.
	IdleTimeout         uint32
	OfferedCapabilities []Symbol
	DesiredCapabilities []Symbol
	Properties          Map
}

func (*Open) descriptor() uint64 { return descOpen }
func (o *Open) fields() []any {
	return []any{o.ContainerID, nilIfEmpty(o.Hostname), nilIfZero(o.MaxFrameSize), o.ChannelMax,
		nilIfZero(o.IdleTimeout), nil, nil, symbolsField(o.OfferedCapabilities), symbolsField(o.DesiredCapabilities), mapField(o.Properties)}
}

func decodeOpen(f fieldList) (*Open, error) {
	if !f.present(0) {
		return nil, protoErr("open without container-id")
	}
	o := &Open{}
	var err error
	if o.ContainerID, err = f.stringAt(0); err != nil {
		return nil, err
	}
	if o.Hostname, err = f.stringAt(1); err != nil {
		return nil, err
	}
	if o.MaxFrameSize, err = f.uint32At(2, math.MaxUint32); err != nil {
		return nil, err
	}
	if o.ChannelMax, err = f.uint16At(3, math.MaxUint16); err != nil {
		return nil, err
	}
	if o.IdleTimeout, err = f.uint32At(4, 0); err != nil {
		return nil, err
	}
	if o.OfferedCapabilities, err = f.symbolsAt(7); err != nil {
		return nil, err
	}
	if o.DesiredCapabilities, err = f.symbolsAt(8); err != nil {
		return nil, err
	}
	if o.Properties, err = f.mapAt(9); err != nil {
		return nil, err
	}
	return o, nil
}

// Begin starts a session (§2.7.2).
type Begin struct {
	RemoteChannel       *uint16
	NextOutgoingID      uint32
	IncomingWindow      uint32
	OutgoingWindow      uint32
	HandleMax           uint32 // 0 is read as the default, 4294967295
	OfferedCapabilities []Symbol
	DesiredCapabilities []Symbol
	Properties          Map
}

func (*Begin) descriptor() uint64 { return descBegin }
func (b *Begin) fields() []any {
	var rc any
	if b.RemoteChannel != nil {
		rc = *b.RemoteChannel
	}
	return []any{rc, b.NextOutgoingID, b.IncomingWindow, b.OutgoingWindow, nilIfZero(b.HandleMax),
		symbolsField(b.OfferedCapabilities), symbolsField(b.DesiredCapabilities), mapField(b.Properties)}
}

func decodeBegin(f fieldList) (*Begin, error) {
	if !f.present(1) || !f.present(2) || !f.present(3) {
		return nil, protoErr("begin without a mandatory field")
	}
	b := &Begin{}
	var err error
	if f.present(0) {
		rc, err := f.uint16At(0, 0)
		if err != nil {
			return nil, err
		}
		b.RemoteChannel = &rc
	}
	if b.NextOutgoingID, err = f.uint32At(1, 0); err != nil {
		return nil, err
	}
	if b.IncomingWindow, err = f.uint32At(2, 0); err != nil {
		return nil, err
	}
	if b.OutgoingWindow, err = f.uint32At(3, 0); err != nil {
		return nil, err
	}
	if b.HandleMax, err = f.uint32At(4, math.MaxUint32); err != nil {
		return nil, err
	}
	if b.OfferedCapabilities, err = f.symbolsAt(5); err != nil {
		return nil, err
	}
	if b.DesiredCapabilities, err = f.symbolsAt(6); err != nil {
		return nil, err
	}
	if b.Properties, err = f.mapAt(7); err != nil {
		return nil, err
	}
	return b, nil
}

// Source is the source terminus of a link (§3.5.3). Only the fields this
// package uses are kept.
type Source struct {
	Address      string
	Durable      uint32
	ExpiryPolicy Symbol
	Timeout      uint32
	Dynamic      bool
	// DistributionMode is "move" (queue semantics) or "copy" (browse).
	DistributionMode Symbol
	Filter           Map
	DefaultOutcome   any
	Outcomes         []Symbol
	Capabilities     []Symbol
}

func (*Source) descriptor() uint64 { return descSource }
func (s *Source) fields() []any {
	return []any{nilIfEmpty(s.Address), nilIfZero(s.Durable), nilIfEmpty(s.ExpiryPolicy), nilIfZero(s.Timeout),
		nilIfZero(s.Dynamic), nil, nilIfEmpty(s.DistributionMode), mapField(s.Filter), s.DefaultOutcome,
		symbolsField(s.Outcomes), symbolsField(s.Capabilities)}
}

func decodeSource(v any) (*Source, error) {
	_, f, err := composite(v, descSource)
	if err != nil || f == nil {
		return nil, err
	}
	s := &Source{}
	if s.Address, err = f.stringAt(0); err != nil {
		return nil, err
	}
	if s.Durable, err = f.uint32At(1, 0); err != nil {
		return nil, err
	}
	if s.ExpiryPolicy, err = f.symbolAt(2); err != nil {
		return nil, err
	}
	if s.Timeout, err = f.uint32At(3, 0); err != nil {
		return nil, err
	}
	if s.Dynamic, err = f.boolAt(4, false); err != nil {
		return nil, err
	}
	if s.DistributionMode, err = f.symbolAt(6); err != nil {
		return nil, err
	}
	if s.Filter, err = f.mapAt(7); err != nil {
		return nil, err
	}
	s.DefaultOutcome = f.at(8)
	if s.Outcomes, err = f.symbolsAt(9); err != nil {
		return nil, err
	}
	if s.Capabilities, err = f.symbolsAt(10); err != nil {
		return nil, err
	}
	return s, nil
}

// Target is the target terminus of a link (§3.5.4).
type Target struct {
	Address      string
	Durable      uint32
	ExpiryPolicy Symbol
	Timeout      uint32
	Dynamic      bool
	Capabilities []Symbol
}

func (*Target) descriptor() uint64 { return descTarget }
func (t *Target) fields() []any {
	return []any{nilIfEmpty(t.Address), nilIfZero(t.Durable), nilIfEmpty(t.ExpiryPolicy), nilIfZero(t.Timeout),
		nilIfZero(t.Dynamic), nil, symbolsField(t.Capabilities)}
}

func decodeTarget(v any) (*Target, error) {
	_, f, err := composite(v, descTarget)
	if err != nil || f == nil {
		return nil, err
	}
	t := &Target{}
	if t.Address, err = f.stringAt(0); err != nil {
		return nil, err
	}
	if t.Durable, err = f.uint32At(1, 0); err != nil {
		return nil, err
	}
	if t.ExpiryPolicy, err = f.symbolAt(2); err != nil {
		return nil, err
	}
	if t.Timeout, err = f.uint32At(3, 0); err != nil {
		return nil, err
	}
	if t.Dynamic, err = f.boolAt(4, false); err != nil {
		return nil, err
	}
	if t.Capabilities, err = f.symbolsAt(6); err != nil {
		return nil, err
	}
	return t, nil
}

// Attach attaches a link (§2.7.3).
type Attach struct {
	Name          string
	Handle        uint32
	Role          Role
	SndSettleMode uint8
	RcvSettleMode uint8
	// Source and Target are nil when absent: a peer refusing a link
	// answers with a null terminus and detaches (§2.6.3).
	Source               *Source
	Target               *Target
	InitialDeliveryCount uint32
	// MaxMessageSize: 0 means no limit.
	MaxMessageSize      uint64
	OfferedCapabilities []Symbol
	DesiredCapabilities []Symbol
	Properties          Map
}

func (*Attach) descriptor() uint64 { return descAttach }
func (a *Attach) fields() []any {
	var idc any
	if a.Role == RoleSender {
		idc = a.InitialDeliveryCount // mandatory for senders
	}
	return []any{a.Name, a.Handle, a.Role == RoleReceiver, a.SndSettleMode, a.RcvSettleMode, nested(a.Source), nested(a.Target),
		nil, nil, idc, nilIfZero(a.MaxMessageSize), symbolsField(a.OfferedCapabilities), symbolsField(a.DesiredCapabilities),
		mapField(a.Properties)}
}

func decodeAttach(f fieldList) (*Attach, error) {
	if !f.present(0) || !f.present(1) || !f.present(2) {
		return nil, protoErr("attach without a mandatory field")
	}
	a := &Attach{}
	var err error
	if a.Name, err = f.stringAt(0); err != nil {
		return nil, err
	}
	if a.Handle, err = f.uint32At(1, 0); err != nil {
		return nil, err
	}
	if a.Role, err = decodeRole(f, 2); err != nil {
		return nil, err
	}
	if a.SndSettleMode, err = f.uint8At(3, SenderSettleMixed); err != nil {
		return nil, err
	}
	if a.RcvSettleMode, err = f.uint8At(4, ReceiverSettleFirst); err != nil {
		return nil, err
	}
	if a.Source, err = decodeSource(f.at(5)); err != nil {
		return nil, err
	}
	if a.Target, err = decodeTarget(f.at(6)); err != nil {
		return nil, err
	}
	if a.InitialDeliveryCount, err = f.uint32At(9, 0); err != nil {
		return nil, err
	}
	if a.MaxMessageSize, err = f.uint64At(10, 0); err != nil {
		return nil, err
	}
	if a.OfferedCapabilities, err = f.symbolsAt(11); err != nil {
		return nil, err
	}
	if a.DesiredCapabilities, err = f.symbolsAt(12); err != nil {
		return nil, err
	}
	if a.Properties, err = f.mapAt(13); err != nil {
		return nil, err
	}
	return a, nil
}

// Flow updates the flow state of a session and, with a Handle, of a link
// (§2.7.4).
type Flow struct {
	NextIncomingID *uint32
	IncomingWindow uint32
	NextOutgoingID uint32
	OutgoingWindow uint32
	Handle         *uint32
	DeliveryCount  *uint32
	LinkCredit     *uint32
	Available      *uint32
	Drain          bool
	Echo           bool
	Properties     Map
}

func (*Flow) descriptor() uint64 { return descFlow }
func (fl *Flow) fields() []any {
	opt := func(p *uint32) any {
		if p == nil {
			return nil
		}
		return *p
	}
	return []any{opt(fl.NextIncomingID), fl.IncomingWindow, fl.NextOutgoingID, fl.OutgoingWindow, opt(fl.Handle),
		opt(fl.DeliveryCount), opt(fl.LinkCredit), opt(fl.Available), nilIfZero(fl.Drain), nilIfZero(fl.Echo), mapField(fl.Properties)}
}

func decodeFlow(f fieldList) (*Flow, error) {
	if !f.present(1) || !f.present(2) || !f.present(3) {
		return nil, protoErr("flow without a mandatory field")
	}
	fl := &Flow{}
	opt := func(i int) (*uint32, error) {
		if !f.present(i) {
			return nil, nil
		}
		n, err := f.uint32At(i, 0)
		return &n, err
	}
	var err error
	if fl.NextIncomingID, err = opt(0); err != nil {
		return nil, err
	}
	if fl.IncomingWindow, err = f.uint32At(1, 0); err != nil {
		return nil, err
	}
	if fl.NextOutgoingID, err = f.uint32At(2, 0); err != nil {
		return nil, err
	}
	if fl.OutgoingWindow, err = f.uint32At(3, 0); err != nil {
		return nil, err
	}
	if fl.Handle, err = opt(4); err != nil {
		return nil, err
	}
	if fl.DeliveryCount, err = opt(5); err != nil {
		return nil, err
	}
	if fl.LinkCredit, err = opt(6); err != nil {
		return nil, err
	}
	if fl.Available, err = opt(7); err != nil {
		return nil, err
	}
	if fl.Drain, err = f.boolAt(8, false); err != nil {
		return nil, err
	}
	if fl.Echo, err = f.boolAt(9, false); err != nil {
		return nil, err
	}
	if fl.Properties, err = f.mapAt(10); err != nil {
		return nil, err
	}
	return fl, nil
}

// Transfer carries (a part of) a message (§2.7.5). The message bytes are
// the frame's Payload.
type Transfer struct {
	Handle uint32
	// DeliveryID and DeliveryTag are set on the first frame of a delivery.
	DeliveryID    *uint32
	DeliveryTag   []byte
	MessageFormat *uint32
	Settled       *bool
	More          bool
	RcvSettleMode *uint8
	State         DeliveryState
	Resume        bool
	Aborted       bool
	Batchable     bool
}

func (*Transfer) descriptor() uint64 { return descTransfer }
func (t *Transfer) fields() []any {
	var id, mf, settled, rsm any
	if t.DeliveryID != nil {
		id = *t.DeliveryID
	}
	if t.MessageFormat != nil {
		mf = *t.MessageFormat
	}
	if t.Settled != nil {
		settled = *t.Settled
	}
	if t.RcvSettleMode != nil {
		rsm = *t.RcvSettleMode
	}
	return []any{t.Handle, id, nilIfEmpty(t.DeliveryTag), mf, settled, nilIfZero(t.More), rsm, stateField(t.State),
		nilIfZero(t.Resume), nilIfZero(t.Aborted), nilIfZero(t.Batchable)}
}

func decodeTransfer(f fieldList) (*Transfer, error) {
	if !f.present(0) {
		return nil, protoErr("transfer without handle")
	}
	t := &Transfer{}
	var err error
	if t.Handle, err = f.uint32At(0, 0); err != nil {
		return nil, err
	}
	if f.present(1) {
		id, err := f.uint32At(1, 0)
		if err != nil {
			return nil, err
		}
		t.DeliveryID = &id
	}
	if t.DeliveryTag, err = f.binaryAt(2); err != nil {
		return nil, err
	}
	if len(t.DeliveryTag) > 32 {
		return nil, protoErr("delivery-tag of %d bytes", len(t.DeliveryTag)) // §2.8.7
	}
	if f.present(3) {
		mf, err := f.uint32At(3, 0)
		if err != nil {
			return nil, err
		}
		t.MessageFormat = &mf
	}
	if f.present(4) {
		s, err := f.boolAt(4, false)
		if err != nil {
			return nil, err
		}
		t.Settled = &s
	}
	if t.More, err = f.boolAt(5, false); err != nil {
		return nil, err
	}
	if f.present(6) {
		m, err := f.uint8At(6, 0)
		if err != nil {
			return nil, err
		}
		t.RcvSettleMode = &m
	}
	if t.State, err = decodeState(f.at(7)); err != nil {
		return nil, err
	}
	if t.Resume, err = f.boolAt(8, false); err != nil {
		return nil, err
	}
	if t.Aborted, err = f.boolAt(9, false); err != nil {
		return nil, err
	}
	if t.Batchable, err = f.boolAt(10, false); err != nil {
		return nil, err
	}
	return t, nil
}

// Disposition informs the peer of delivery state changes (§2.7.6).
type Disposition struct {
	Role    Role
	First   uint32
	Last    *uint32
	Settled bool
	State   DeliveryState
}

func (*Disposition) descriptor() uint64 { return descDisposition }
func (d *Disposition) fields() []any {
	var last any
	if d.Last != nil {
		last = *d.Last
	}
	return []any{d.Role == RoleReceiver, d.First, last, nilIfZero(d.Settled), stateField(d.State)}
}

func decodeDisposition(f fieldList) (*Disposition, error) {
	if !f.present(0) || !f.present(1) {
		return nil, protoErr("disposition without a mandatory field")
	}
	d := &Disposition{}
	var err error
	if d.Role, err = decodeRole(f, 0); err != nil {
		return nil, err
	}
	if d.First, err = f.uint32At(1, 0); err != nil {
		return nil, err
	}
	if f.present(2) {
		last, err := f.uint32At(2, 0)
		if err != nil {
			return nil, err
		}
		d.Last = &last
	}
	if d.Settled, err = f.boolAt(3, false); err != nil {
		return nil, err
	}
	if d.State, err = decodeState(f.at(4)); err != nil {
		return nil, err
	}
	return d, nil
}

// Detach detaches a link (§2.7.7).
type Detach struct {
	Handle uint32
	Closed bool
	Error  *Error
}

func (*Detach) descriptor() uint64 { return descDetach }
func (d *Detach) fields() []any {
	return []any{d.Handle, nilIfZero(d.Closed), nested(d.Error)}
}

func decodeDetach(f fieldList) (*Detach, error) {
	if !f.present(0) {
		return nil, protoErr("detach without handle")
	}
	d := &Detach{}
	var err error
	if d.Handle, err = f.uint32At(0, 0); err != nil {
		return nil, err
	}
	if d.Closed, err = f.boolAt(1, false); err != nil {
		return nil, err
	}
	if d.Error, err = f.errorAt(2); err != nil {
		return nil, err
	}
	return d, nil
}

// End ends a session (§2.7.8).
type End struct{ Error *Error }

func (*End) descriptor() uint64 { return descEnd }
func (e *End) fields() []any    { return []any{nested(e.Error)} }

// Close closes the connection (§2.7.9).
type Close struct{ Error *Error }

func (*Close) descriptor() uint64 { return descClose }
func (c *Close) fields() []any    { return []any{nested(c.Error)} }

// ---------------------------------------------------------------------------
// Delivery states (§3.4)

// DeliveryState is the state of a delivery: one of *Received, *Accepted,
// *Rejected, *Released and *Modified.
type DeliveryState interface {
	descriptor() uint64
	fields() []any
}

// Received is the non-terminal state of a partly received delivery
// (§3.4.1).
type Received struct {
	SectionNumber uint32
	SectionOffset uint64
}

// Accepted is the outcome of a message that was processed (§3.4.2).
type Accepted struct{}

// Rejected is the outcome of an invalid message (§3.4.3).
type Rejected struct{ Error *Error }

// Released is the outcome of a message that was not and will not be acted
// upon (§3.4.4).
type Released struct{}

// Modified is the outcome of a message that was not processed and may be
// delivered again, modified (§3.4.5).
type Modified struct {
	DeliveryFailed     bool
	UndeliverableHere  bool
	MessageAnnotations Map
}

func (*Received) descriptor() uint64 { return descReceived }
func (r *Received) fields() []any    { return []any{r.SectionNumber, r.SectionOffset} }
func (*Accepted) descriptor() uint64 { return descAccepted }
func (*Accepted) fields() []any      { return nil }
func (*Rejected) descriptor() uint64 { return descRejected }
func (r *Rejected) fields() []any    { return []any{nested(r.Error)} }
func (*Released) descriptor() uint64 { return descReleased }
func (*Released) fields() []any      { return nil }
func (*Modified) descriptor() uint64 { return descModified }
func (m *Modified) fields() []any {
	return []any{nilIfZero(m.DeliveryFailed), nilIfZero(m.UndeliverableHere), mapField(m.MessageAnnotations)}
}

func stateField(s DeliveryState) any {
	if s == nil {
		return nil
	}
	return nested(s)
}

func decodeState(v any) (DeliveryState, error) {
	code, f, err := composite(v, descReceived, descAccepted, descRejected, descReleased, descModified)
	if err != nil || v == nil {
		return nil, err
	}
	switch code {
	case descReceived:
		r := &Received{}
		if r.SectionNumber, err = f.uint32At(0, 0); err != nil {
			return nil, err
		}
		if r.SectionOffset, err = f.uint64At(1, 0); err != nil {
			return nil, err
		}
		return r, nil
	case descAccepted:
		return &Accepted{}, nil
	case descRejected:
		e, err := f.errorAt(0)
		if err != nil {
			return nil, err
		}
		return &Rejected{Error: e}, nil
	case descReleased:
		return &Released{}, nil
	}
	m := &Modified{}
	if m.DeliveryFailed, err = f.boolAt(0, false); err != nil {
		return nil, err
	}
	if m.UndeliverableHere, err = f.boolAt(1, false); err != nil {
		return nil, err
	}
	if m.MessageAnnotations, err = f.mapAt(2); err != nil {
		return nil, err
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// SASL frames (Part 5 §5.3.3)

// SASL outcome codes (§5.3.3.6).
const (
	SASLOk      uint8 = 0
	SASLAuth    uint8 = 1
	SASLSys     uint8 = 2
	SASLSysPerm uint8 = 3
	SASLSysTemp uint8 = 4
)

// SASLMechanisms announces the server's mechanisms (§5.3.3.1).
type SASLMechanisms struct{ Mechanisms []Symbol }

// SASLInit selects a mechanism (§5.3.3.2).
type SASLInit struct {
	Mechanism       Symbol
	InitialResponse []byte
	Hostname        string
}

// SASLChallenge is a server challenge (§5.3.3.3).
type SASLChallenge struct{ Challenge []byte }

// SASLResponse answers a challenge (§5.3.3.4).
type SASLResponse struct{ Response []byte }

// SASLOutcome ends the exchange (§5.3.3.5).
type SASLOutcome struct {
	Code           uint8
	AdditionalData []byte
}

func (*SASLMechanisms) descriptor() uint64 { return descSASLMechanisms }
func (m *SASLMechanisms) fields() []any {
	return []any{m.Mechanisms} // mandatory, even if empty
}
func (*SASLInit) descriptor() uint64 { return descSASLInit }
func (i *SASLInit) fields() []any {
	var ir any
	if i.InitialResponse != nil {
		ir = i.InitialResponse
	}
	return []any{i.Mechanism, ir, nilIfEmpty(i.Hostname)}
}
func (*SASLChallenge) descriptor() uint64 { return descSASLChallenge }
func (c *SASLChallenge) fields() []any    { return []any{orEmpty(c.Challenge)} }
func (*SASLResponse) descriptor() uint64  { return descSASLResponse }
func (r *SASLResponse) fields() []any     { return []any{orEmpty(r.Response)} }
func (*SASLOutcome) descriptor() uint64   { return descSASLOutcome }
func (o *SASLOutcome) fields() []any      { return []any{o.Code, nilIfEmpty(o.AdditionalData)} }

func orEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func decodeSASL(code uint64, f fieldList) (Body, error) {
	var err error
	switch code {
	case descSASLMechanisms:
		m := &SASLMechanisms{}
		if m.Mechanisms, err = f.symbolsAt(0); err != nil {
			return nil, err
		}
		return m, nil
	case descSASLInit:
		if !f.present(0) {
			return nil, protoErr("sasl-init without mechanism")
		}
		i := &SASLInit{}
		if i.Mechanism, err = f.symbolAt(0); err != nil {
			return nil, err
		}
		if i.InitialResponse, err = f.binaryAt(1); err != nil {
			return nil, err
		}
		if i.Hostname, err = f.stringAt(2); err != nil {
			return nil, err
		}
		return i, nil
	case descSASLChallenge:
		c := &SASLChallenge{}
		c.Challenge, err = f.binaryAt(0)
		return c, err
	case descSASLResponse:
		r := &SASLResponse{}
		r.Response, err = f.binaryAt(0)
		return r, err
	case descSASLOutcome:
		if !f.present(0) {
			return nil, protoErr("sasl-outcome without code")
		}
		o := &SASLOutcome{}
		if o.Code, err = f.uint8At(0, 0); err != nil {
			return nil, err
		}
		if o.AdditionalData, err = f.binaryAt(1); err != nil {
			return nil, err
		}
		return o, nil
	}
	return nil, protoErr("unknown SASL frame 0x%02x", code)
}
