// SPDX-License-Identifier: MIT

package pubsub

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// PubSub Actions (Part 14 §6.2.11.2 in 1.05): the request and response
// pattern over PubSub.
//
// The Responder is a DataSetWriter of a PublishedDataSet whose
// DataSetSource is a PublishedAction: its targets run the [ActionHandler]s
// registered for them. The requests for the writers of a writer group arrive
// on the address of the connection (datagram transports) or on the QueueName
// of the group (broker transports, Table 85); the responses go to the
// ResponseAddress of the request or, without one, to the connection address
// or the action-response topic that corresponds to the action-request topic
// the request came on (§7.3.4.7.10).
//
// The Requestor calls an Action target with [PubSub.CallAction] on one of its
// connections: it sends an ActionRequest with ActionState Executing, waits
// for the Done response (the RequestId and random CorrelationData identify
// it) and acknowledges it with an Idle request. On a datagram transport it
// resends the request while it hears nothing and the Idle acknowledgement
// until the Responder confirms it, at ActionTarget.ResendInterval (the
// PublishingInterval of the Responder, Tables 83 and 84).
//
// The Responder executes a request once for every combination of
// RequestorId, CorrelationData, RequestId and DataSetWriterId: a repeated
// request is answered with the current state (Executing or the stored Done
// response) and not executed again. It keeps a completed exchange until the
// Idle acknowledgement or the end of the TimeoutHint, sending Executing and
// repeating Done every PublishingInterval of a datagram group. New requests
// are bounded by a token bucket (ActionOptions.Rate, Burst) and by the
// number of exchanges of a connection (MaxConcurrent); requests beyond them
// are dropped without response or answered with Bad_TooManyOperations.
// Messages that cannot be decoded, are not addressed to a known writer and
// target, or lack the required security get no response (§6.2.11.2.2).

// ActionHandler executes an Action target. inputs are the fields of the
// request, in the order of the request DataSetMetaData of the
// PublishedAction (when it has fields, their number and built-in types are
// checked before the handler runs). It returns the output fields, in the
// order of the response DataSetMetaData (the DataSetMetaData of the
// PublishedDataSet), and the result: the outputs of a Bad result are not
// sent.
//
// ctx ends with the TimeoutHint of the request (at most
// ActionOptions.MaxTimeout) and when the runtime stops; a handler must
// return then, since [PubSub.Close] waits for it. [ActionInvocationFrom]
// tells which request it serves. A panic is recovered and answered with
// Bad_InternalError.
type ActionHandler func(ctx context.Context, inputs []*ua.Variant) ([]*ua.Variant, ua.StatusCode)

// actionKey identifies the handler of an Action target.
type actionKey struct {
	dataSet string
	target  uint16
}

// ActionInvocation describes the request an [ActionHandler] serves.
type ActionInvocation struct {
	// Writer is the id of the Action DataSetWriter, DataSetWriterID its
	// DataSetWriterId, DataSet the name of its PublishedDataSet.
	Writer          ComponentID
	DataSetWriterID uint16
	DataSet         string
	ActionTargetID  uint16
	// RequestorID is the PublisherId of the Requestor, if the request
	// carried it.
	RequestorID *message.PublisherID
	RequestID   uint16
}

type invocationKey struct{}

// ActionInvocationFrom returns the request an [ActionHandler] serves from its
// context.
func ActionInvocationFrom(ctx context.Context) (ActionInvocation, bool) {
	inv, ok := ctx.Value(invocationKey{}).(ActionInvocation)
	return inv, ok
}

// ActionOptions bound the PubSub Actions of a runtime. Zero fields select
// the defaults.
type ActionOptions struct {
	// MaxConcurrent bounds the exchanges a connection keeps as Responder:
	// running and completed requests not yet acknowledged (default 64).
	MaxConcurrent int
	// Rate and Burst bound the new requests a connection accepts as
	// Responder, all writers and Requestors together (default 50 per
	// second, bursts of 50).
	Rate  float64
	Burst int
	// MaxTimeout caps the TimeoutHint of a request, and is the timeout of
	// a request without one (default 60 seconds).
	MaxTimeout time.Duration
	// DefaultTimeout is the timeout of [PubSub.CallAction] when neither
	// the ActionTarget nor the context sets one (default 10 seconds).
	DefaultTimeout time.Duration
}

// Defaults of ActionOptions and fixed limits.
const (
	defaultActionMaxConcurrent  = 64
	defaultActionRate           = 50
	defaultActionBurst          = 50
	defaultActionMaxTimeout     = time.Minute
	defaultActionDefaultTimeout = 10 * time.Second
	// actionDuplicateGuard is the least time between two answers to
	// repeated requests of an exchange.
	actionDuplicateGuard = 100 * time.Millisecond
	// maxActionSenders bounds the transports a connection keeps open to
	// datagram ResponseAddresses and RequestAddresses.
	maxActionSenders = 8
	// actionReplyBuffer is the number of responses a call buffers.
	actionReplyBuffer = 16
	// correlationLength is the length of the random CorrelationData of
	// the requests of CallAction.
	correlationLength = 16
)

func (o ActionOptions) normalized() ActionOptions {
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = defaultActionMaxConcurrent
	}
	if o.Rate <= 0 {
		o.Rate = defaultActionRate
	}
	if o.Burst <= 0 {
		o.Burst = defaultActionBurst
	}
	if o.MaxTimeout <= 0 {
		o.MaxTimeout = defaultActionMaxTimeout
	}
	if o.DefaultTimeout <= 0 {
		o.DefaultTimeout = defaultActionDefaultTimeout
	}
	return o
}

// WithActionOptions sets the limits of the PubSub Actions.
func WithActionOptions(o ActionOptions) Option {
	return func(opts *options) { opts.actions = o }
}

// WithActionHandler registers the handler of the Action target
// actionTargetID of the PublishedAction dataSetName (Responder). A target
// without handler is answered with Bad_NotImplemented.
func WithActionHandler(dataSetName string, actionTargetID uint16, h ActionHandler) Option {
	return func(o *options) {
		if o.actionHandlers == nil {
			o.actionHandlers = map[actionKey]ActionHandler{}
		}
		if h == nil {
			delete(o.actionHandlers, actionKey{dataSetName, actionTargetID})
			return
		}
		o.actionHandlers[actionKey{dataSetName, actionTargetID}] = h
	}
}

// SetActionHandler registers (or, with nil, removes) the handler of an
// Action target at run time, like [WithActionHandler]. Running requests keep
// the handler they started with.
func (p *PubSub) SetActionHandler(dataSetName string, actionTargetID uint16, h ActionHandler) {
	p.lock()
	defer p.unlock()
	WithActionHandler(dataSetName, actionTargetID, h)(&p.opts)
}

// isAction reports whether a writer is an Action writer: its
// PublishedDataSet is a PublishedAction.
func (w *dataSetWriter) isAction() bool { return w.pds != nil && w.pds.action != nil }

// completeActionMetaData completes the request DataSetMetaData of a
// PublishedAction like completeMetaData does the others: name, version,
// field names ("Field0", ...) and DataTypes.
func completeActionMetaData(md *ua.DataSetMetaDataType, name string) *ua.DataSetMetaDataType {
	if md == nil {
		md = &ua.DataSetMetaDataType{}
	}
	if md.Name == "" {
		md.Name = name
	}
	if md.Description == nil {
		md.Description = &ua.LocalizedText{}
	}
	if md.DataSetClassID == nil {
		md.DataSetClassID = &ua.GUID{}
	}
	if md.ConfigurationVersion == nil || (md.ConfigurationVersion.MajorVersion == 0 && md.ConfigurationVersion.MinorVersion == 0) {
		v := versionTime(time.Now())
		md.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: v, MinorVersion: v}
	}
	for i, f := range md.Fields {
		if f.Name == "" {
			f.Name = fieldName(i)
		}
		if f.Description == nil {
			f.Description = &ua.LocalizedText{}
		}
		if f.DataType == nil {
			f.DataType = ua.NewNumericNodeID(0, 24)
		}
	}
	return md
}

func fieldName(i int) string { return fmt.Sprintf("Field%d", i) }

// ActionRequestTopic returns the default MQTT topic of the requests for the
// Action writers of a writer group of a Responder (Part 14 §7.3.4.7.9 in
// 1.05): <prefix>/<encoding>/action-request/<responder>/<writerGroup>. It is
// the QueueName of the writer group and the RequestAddress of the
// [ActionTarget].
func ActionRequestTopic(prefix string, mapping MessageMapping, responder, writerGroup string) string {
	return actionTopic(prefix, mapping, "action-request", responder, writerGroup)
}

// ActionResponseTopic returns the default MQTT topic of the responses of a
// Responder (Part 14 §7.3.4.7.10 in 1.05):
// <prefix>/<encoding>/action-response/<responder>/<writerGroup>.
func ActionResponseTopic(prefix string, mapping MessageMapping, responder, writerGroup string) string {
	return actionTopic(prefix, mapping, "action-response", responder, writerGroup)
}

func actionTopic(prefix string, mapping MessageMapping, level, responder, writerGroup string) string {
	enc := "uadp"
	if mapping == MappingJSON {
		enc = "json"
	}
	return prefix + "/" + enc + "/" + level + "/" + responder + "/" + writerGroup
}

// defaultResponseTopic returns the action-response topic that corresponds
// to an action-request topic, empty if topic has no action-request level.
func defaultResponseTopic(topic string) string {
	const req, resp = "/action-request/", "/action-response/"
	if i := strings.LastIndex(topic, req); i >= 0 {
		return topic[:i] + resp + topic[i+len(req):]
	}
	return ""
}

// ActionTarget addresses an Action target of a Responder for
// [PubSub.CallAction].
type ActionTarget struct {
	// Connection is the name of the connection of this runtime the
	// request is sent on. It needs a PublisherId: it is the RequestorId.
	// Its transport profile selects the message mapping.
	Connection string
	// PublisherID (a byte, uint16, uint32, uint64, string or a
	// message.PublisherID), DataSetWriterID and ActionTargetID address the
	// Action target of the Responder.
	PublisherID     any
	DataSetWriterID uint16
	ActionTargetID  uint16
	// RequestAddress is where the request is sent: the QueueName of the
	// Responder's writer group on a broker (required, see
	// [ActionRequestTopic]); on a datagram transport an address such as
	// opc.udp://host:port, empty for the address of the connection.
	RequestAddress string
	// ResponseAddress is where the Responder sends its responses. Empty
	// selects on a broker the action-response topic corresponding to the
	// RequestAddress, on a datagram transport the address of the
	// connection (sent along when RequestAddress is another one). The
	// connection subscribes to it for the call.
	ResponseAddress string
	// SecurityMode and SecurityGroupID secure the UADP messages of the
	// call; the Responder answers with the security of its writer group.
	SecurityMode    ua.MessageSecurityMode
	SecurityGroupID string
	// RequestMetaData names the input fields for the JSON mapping and
	// ResponseMetaData describes the outputs (field order of JSON
	// messages, RawData fields). Without them inputs are named "Field0",
	// "Field1", ... (the default names of the Responder's DataSetMetaData)
	// and outputs are taken in the order received.
	RequestMetaData  *ua.DataSetMetaDataType
	ResponseMetaData *ua.DataSetMetaDataType
	// Timeout is the TimeoutHint of the request and how long CallAction
	// waits for the Done response. Zero uses the deadline of the context
	// or ActionOptions.DefaultTimeout.
	Timeout time.Duration
	// ResendInterval, if positive, is the PublishingInterval of the
	// Responder on a non-reliable (datagram) transport: the request is
	// resent while no response arrives within it, and the Idle
	// acknowledgement until the Responder confirms it (Part 14 Table 83).
	ResendInterval time.Duration
}

// ActionResult is the Done response to a call.
type ActionResult struct {
	// Status is the result of the Action; Outputs are empty for a Bad
	// Status.
	Status  ua.StatusCode
	Outputs []*ua.Variant
	// RequestID is the RequestId of the request.
	RequestID uint16
}

// ErrActionTimeout is wrapped by the error of a call that got no Done
// response within its timeout. It wraps ua.StatusBadTimeout.
var ErrActionTimeout = fmt.Errorf("pubsub: no response to the Action request: %w", ua.StatusBadTimeout)

// actionState is the state of the PubSub Actions of one run of a
// connection. It is guarded by PubSub.mu.
type actionState struct {
	// Responder: the exchanges and the token bucket of new requests.
	exchanges map[exchangeKey]*exchange
	bucket    tokenBucket
	// Requestor: the pending calls and the response topics they listen
	// on ("" for the address of a datagram connection), counted.
	calls  map[callKey]*actionCall
	listen map[string]int
	// senders are open transports to datagram addresses other than the
	// connection's, in the order they were opened.
	senders map[string]transport.Connection
	order   []string
}

func (s *actionState) init() {
	if s.exchanges == nil {
		s.exchanges = map[exchangeKey]*exchange{}
		s.calls = map[callKey]*actionCall{}
		s.listen = map[string]int{}
		s.senders = map[string]transport.Connection{}
	}
}

// stopActions ends the Actions of a stopped connection: running handlers
// are cancelled, calls fail. p.mu is held.
func (p *PubSub) stopActions(c *connection) {
	for _, ex := range c.act.exchanges {
		ex.stop()
	}
	for _, call := range c.act.calls {
		close(call.gone)
	}
	for _, tc := range c.act.senders {
		p.later(func() { _ = tc.Close() })
	}
	c.act = actionState{}
}

// actionTopics adds the subscriptions of the Actions of a connection to
// want: the request queues of its running Action writer groups and the
// response topics of its calls. p.mu is held.
func (p *PubSub) actionTopics(c *connection, want map[string]byte) {
	add := func(topic string, qos byte) {
		if !c.broker {
			topic, qos = "", 0
		}
		if q, ok := want[topic]; !ok || qos > q {
			want[topic] = qos
		}
	}
	for _, g := range c.wgs {
		if g.cancel == nil {
			continue
		}
		for _, w := range g.writers {
			if !w.isAction() {
				continue
			}
			if !c.broker {
				add("", 0)
			} else if g.brokerTS != nil && g.brokerTS.QueueName != "" {
				// Part 14 Table 85: AtLeastOnce or better.
				add(g.brokerTS.QueueName, max(qosOf(g.brokerTS.RequestedDeliveryGuarantee, 1), 1))
			}
			break
		}
	}
	for topic := range c.act.listen {
		add(topic, 1)
	}
}

// tokenBucket bounds the rate of an event: Burst at once, Rate per second
// in the long run.
type tokenBucket struct {
	tokens float64
	at     time.Time
}

func (b *tokenBucket) allow(now time.Time, rate float64, burst int) bool {
	if b.at.IsZero() || now.Before(b.at) {
		b.tokens = float64(burst)
	} else {
		b.tokens = min(float64(burst), b.tokens+now.Sub(b.at).Seconds()*rate)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// isActionMessage tells a received action message from the others: by its
// MQTT 5.0 message type, the ExtendedFlags2 of UADP, or the MessageType of
// a JSON message.
func isActionMessage(enc encoding, m *transport.Message) bool {
	if mt, ok := m.UserProperty(transport.UAMessageTypeProperty); ok {
		return mt == transport.MessageTypeActionRequest || mt == transport.MessageTypeActionResponse
	}
	if enc == encUADP {
		return uadp.PeekAction(m.Payload)
	}
	b := m.Payload
	if len(b) > 512 {
		b = b[:512]
	}
	if !bytes.Contains(b, []byte(`"ua-action-re`)) {
		return false
	}
	t, err := jsonmsg.MessageType(m.Payload)
	return err == nil && (t == jsonmsg.MessageTypeActionRequest || t == jsonmsg.MessageTypeActionResponse)
}

// actionSnap is what the decoding of an action message needs to know of a
// connection, copied for the decoder callbacks that run outside the lock.
type actionSnap struct {
	writers []actionWriterSnap
	calls   []actionCallSnap
}

type actionWriterSnap struct {
	dswid   uint16
	mode    ua.MessageSecurityMode
	groupID string
	md      *ua.DataSetMetaDataType
}

type actionCallSnap struct {
	pub     message.PublisherID
	dswid   uint16
	mode    ua.MessageSecurityMode
	groupID string
	md      *ua.DataSetMetaDataType
}

// actionWriter returns the running Action writer of an Operational group of
// a connection with a DataSetWriterId. p.mu is held.
func actionWriter(c *connection, dswid uint16) *dataSetWriter {
	for _, g := range c.wgs {
		if g.state != ua.PubSubStateOperational {
			continue
		}
		for _, w := range g.writers {
			if w.running && w.isAction() && w.cfg.DataSetWriterID == dswid {
				return w
			}
		}
	}
	return nil
}

func (p *PubSub) snapshotActions(c *connection) actionSnap {
	var s actionSnap
	if c.hasPub {
		for _, g := range c.wgs {
			if g.state != ua.PubSubStateOperational {
				continue
			}
			for _, w := range g.writers {
				if w.running && w.isAction() {
					s.writers = append(s.writers, actionWriterSnap{dswid: w.cfg.DataSetWriterID, mode: g.mode, groupID: g.cfg.SecurityGroupID, md: w.pds.action.RequestDataSetMetaData})
				}
			}
		}
	}
	for _, call := range c.act.calls {
		s.calls = append(s.calls, actionCallSnap{pub: call.pub, dswid: call.dswid, mode: call.mode, groupID: call.groupID, md: call.md})
	}
	return s
}

// receiveAction handles a received ActionRequest or ActionResponse.
func (p *PubSub) receiveAction(c *connection, gen uint64, enc encoding, m *transport.Message) {
	p.lock()
	if c.gen != gen {
		p.unlock()
		return
	}
	c.ctr.NetworkMessagesReceived++
	c.ctr.BytesReceived += uint64(len(m.Payload))
	snap := p.snapshotActions(c)
	ownPub, hasPub := c.pubID, c.hasPub
	p.unlock()
	if len(snap.writers) == 0 && len(snap.calls) == 0 {
		return
	}
	// The MessageType of a JSON message tells requests from responses
	// before the payload is decoded; a UADP message has it in its
	// (possibly encrypted) ActionHeader.
	var kind message.ActionMessageType
	if enc == encJSON {
		if t, _ := jsonmsg.MessageType(m.Payload); t == jsonmsg.MessageTypeActionRequest {
			kind = message.ActionRequest
		} else {
			kind = message.ActionResponse
		}
	}
	forUs := func(h *message.NetworkMessage, consider func(ua.MessageSecurityMode, string)) {
		var ids []uint16
		for _, dsm := range h.Messages {
			ids = append(ids, dsm.DataSetWriterID)
		}
		match := func(id uint16) bool {
			if len(ids) == 0 {
				return true
			}
			for _, x := range ids {
				if x == 0 || x == id {
					return true
				}
			}
			return false
		}
		if kind != message.ActionResponse && hasPub && samePublisher(h.PublisherID, ownPub) {
			for _, w := range snap.writers {
				if match(w.dswid) {
					consider(w.mode, w.groupID)
				}
			}
		}
		if kind != message.ActionRequest {
			for _, call := range snap.calls {
				if samePublisher(h.PublisherID, call.pub) && match(call.dswid) {
					consider(call.mode, call.groupID)
				}
			}
		}
	}
	var keyGroup string
	opts := &decodeOptions{}
	opts.DecodeOptions = uadp.DecodeOptions{
		Accept: func(h *message.NetworkMessage) bool {
			found := false
			forUs(h, func(ua.MessageSecurityMode, string) { found = true })
			return found
		},
		// The least security a writer or call the message may be for
		// requires, verified with the keys of the first secured one;
		// each DataSetMessage is then checked against its own.
		Security: func(h *message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
			mode := ua.MessageSecurityModeInvalid
			var ks security.KeySource
			forUs(h, func(m ua.MessageSecurityMode, groupID string) {
				if mode == ua.MessageSecurityModeInvalid || m < mode {
					mode = m
				}
				if m > ua.MessageSecurityModeNone && ks == nil {
					ks = p.KeySource(groupID)
					keyGroup = groupID
				}
			})
			return max(mode, ua.MessageSecurityModeNone), ks, nil
		},
		MetaData: func(pub message.PublisherID, _ uint16, dswid uint16) *ua.DataSetMetaDataType {
			if kind != message.ActionResponse && hasPub && samePublisher(pub, ownPub) {
				for _, w := range snap.writers {
					if w.dswid == dswid {
						return w.md
					}
				}
			}
			if kind != message.ActionRequest {
				for _, call := range snap.calls {
					if call.dswid == dswid && samePublisher(pub, call.pub) {
						return call.md
					}
				}
			}
			return nil
		},
	}
	var nm *message.NetworkMessage
	var err error
	if p.protect("decode", func() { nm, err = p.codecs(enc).Decode(m.Payload, opts) }) {
		err = errDecodePanic
	}
	if err == nil && nm.Action == nil {
		err = fmt.Errorf("%w: not an action message", uadp.ErrMalformed)
	}
	if err != nil {
		if errors.Is(err, uadp.ErrFiltered) {
			return
		}
		p.lock()
		if c.gen == gen {
			c.ctr.DecodeErrors++
			c.err = err
		}
		p.unlock()
		p.log.Debug("pubsub: action message decode failed", "connection", c.name, "error", err)
		return
	}
	got := securityOf(nm)
	if nm.Action.Type == message.ActionRequest {
		p.actionRequests(c, gen, enc, nm, m, got, keyGroup)
	} else {
		p.actionResponses(c, gen, nm, got, keyGroup)
	}
}

// secured tells whether a message secured with mode by the keys of
// keyGroup satisfies a required security.
func securedFor(want ua.MessageSecurityMode, groupID string, got ua.MessageSecurityMode, keyGroup string) bool {
	if want <= ua.MessageSecurityModeNone {
		return true
	}
	return got >= want && groupID == keyGroup
}

// exchangeKey identifies a request at the Responder (Part 14 §6.2.11.2.2:
// the RequestId is unique within a RequestorId and CorrelationData).
type exchangeKey struct {
	requestor string
	corr      string
	reqID     uint16
	dswid     uint16
}

// replyTo is where and how a Responder answers a request.
type replyTo struct {
	enc       encoding
	topic     string // broker
	dest      string // datagram: "" for the connection address
	corr      []byte
	requestor *message.PublisherID
}

// exchange is a request a Responder executes or executed.
type exchange struct {
	key      exchangeKey
	w        *dataSetWriter
	target   uint16
	reply    replyTo
	deadline time.Time
	state    ua.ActionState
	status   ua.StatusCode
	outputs  []*ua.Variant
	lastSent time.Time
	cancel   context.CancelFunc
	timer    *time.Timer
}

func (ex *exchange) stop() {
	if ex.cancel != nil {
		ex.cancel()
	}
	if ex.timer != nil {
		ex.timer.Stop()
	}
}

// actionSend is a response (or a request) ready to be encoded and sent.
type actionSend struct {
	c   *connection
	gen uint64
	nm  *message.NetworkMessage
	enc encoding
	// mode, groupID and g (for the nonces) secure a UADP message.
	mode    ua.MessageSecurityMode
	groupID string
	g       *writerGroup
	w       *dataSetWriter
	md      *ua.DataSetMetaDataType
	topic   string
	qos     byte
	dest    string
	msgType string
}

// actionRequests handles a received ActionRequest NetworkMessage.
func (p *PubSub) actionRequests(c *connection, gen uint64, enc encoding, nm *message.NetworkMessage, m *transport.Message, got ua.MessageSecurityMode, keyGroup string) {
	now := time.Now()
	var sends []*actionSend
	p.lock()
	if c.gen != gen || !c.hasPub || !samePublisher(nm.PublisherID, c.pubID) {
		p.unlock()
		return
	}
	c.act.init()
	requestor := ""
	if r := nm.Action.RequestorID; r != nil {
		requestor = r.String()
	}
	for _, dsm := range nm.Messages {
		if !dsm.Valid {
			continue
		}
		w := actionWriter(c, dsm.DataSetWriterID)
		if w == nil || !securedFor(w.group.mode, w.group.cfg.SecurityGroupID, got, keyGroup) || !hasActionTarget(w.pds.action, dsm.ActionTargetID) {
			c.ctr.ActionRequestsRejected++
			if w != nil && !securedFor(w.group.mode, w.group.cfg.SecurityGroupID, got, keyGroup) {
				p.count(&w.group.base, CounterDecryptionErrors, 1)
			}
			continue
		}
		w.ctr.ActionRequestsReceived++
		key := exchangeKey{requestor: requestor, corr: string(nm.Action.CorrelationData), reqID: dsm.RequestID, dswid: dsm.DataSetWriterID}
		if s := p.actionRequestLocked(c, gen, enc, w, key, nm, dsm, m, now); s != nil {
			sends = append(sends, s)
		}
	}
	p.unlock()
	for _, s := range sends {
		_ = p.sendAction(s)
	}
}

func hasActionTarget(a *ua.PublishedActionDataType, id uint16) bool {
	for _, t := range a.ActionTargets {
		if t != nil && t.ActionTargetID == id {
			return true
		}
	}
	return false
}

// actionRequestLocked handles one ActionRequest DataSetMessage (Part 14
// Table 84) and returns the response to send now, if any. p.mu is held.
func (p *PubSub) actionRequestLocked(c *connection, gen uint64, enc encoding, w *dataSetWriter, key exchangeKey, nm *message.NetworkMessage, dsm *message.DataSetMessage, m *transport.Message, now time.Time) *actionSend {
	o := &p.opts.actions
	ex := c.act.exchanges[key]
	switch dsm.ActionState {
	case ua.ActionStateExecuting:
		if ex != nil {
			// A repeated request: answered with the current state, not
			// executed again.
			if now.Sub(ex.lastSent) < actionDuplicateGuard {
				return nil
			}
			return p.responseLocked(c, gen, ex, now)
		}
		if !c.act.bucket.allow(now, o.Rate, o.Burst) {
			c.ctr.ActionRequestsRejected++
			return nil
		}
		reply, ok := p.replyAddress(c, enc, nm, m)
		if !ok {
			c.ctr.ActionRequestsRejected++
			return nil
		}
		timeout := duration(nm.Action.TimeoutHint)
		if timeout <= 0 || timeout > o.MaxTimeout {
			timeout = o.MaxTimeout
		}
		ex = &exchange{key: key, w: w, target: dsm.ActionTargetID, reply: reply, deadline: now.Add(timeout), state: ua.ActionStateExecuting}
		if len(c.act.exchanges) >= o.MaxConcurrent {
			// Answered at once and not kept.
			c.ctr.ActionRequestsRejected++
			ex.finish(ua.StatusBadTooManyOperations, nil, nil)
			return p.responseLocked(c, gen, ex, now)
		}
		c.act.exchanges[key] = ex
		inputs, st := actionInputs(w.pds.action.RequestDataSetMetaData, dsm)
		h := p.opts.actionHandlers[actionKey{w.pds.name, dsm.ActionTargetID}]
		switch {
		case !isGood(st):
			ex.finish(st, nil, nil)
		case h == nil:
			ex.finish(ua.StatusBadNotImplemented, nil, nil)
		default:
			p.startAction(c, gen, ex, h, inputs, nm.Action.RequestorID)
		}
		p.armExchange(c, gen, ex, now)
		if ex.state == ua.ActionStateDone {
			return p.responseLocked(c, gen, ex, now)
		}
		return nil
	case ua.ActionStateIdle:
		// The acknowledgement of a Done response: confirmed with Idle.
		if ex != nil {
			if ex.state != ua.ActionStateDone {
				return nil
			}
			delete(c.act.exchanges, key)
			ex.stop()
			ex.state, ex.status, ex.outputs = ua.ActionStateIdle, ua.StatusGood, nil
			return p.responseLocked(c, gen, ex, now)
		}
		if !c.act.bucket.allow(now, o.Rate, o.Burst) {
			return nil
		}
		reply, ok := p.replyAddress(c, enc, nm, m)
		if !ok {
			return nil
		}
		ex = &exchange{key: key, w: w, target: dsm.ActionTargetID, reply: reply, state: ua.ActionStateIdle}
		return p.responseLocked(c, gen, ex, now)
	default:
		// Done is no state of a request.
		return nil
	}
}

// finish completes an exchange with the result of the Action. The outputs
// of a Bad result are dropped, as are outputs that do not match the
// response DataSetMetaData md.
func (ex *exchange) finish(st ua.StatusCode, outputs []*ua.Variant, md *ua.DataSetMetaDataType) {
	ex.state, ex.status, ex.outputs = ua.ActionStateDone, st, nil
	if isBad(st) {
		return
	}
	if md != nil && len(md.Fields) > 0 && len(outputs) != len(md.Fields) {
		ex.status = ua.StatusBadInternalError
		return
	}
	ex.outputs = outputs
}

// actionInputs returns the inputs of a request in the order of the request
// DataSetMetaData, and Bad_ArgumentsMissing, Bad_TooManyArguments or
// Bad_TypeMismatch if they do not match it. Without fields in the metadata
// the inputs are taken as they are.
func actionInputs(md *ua.DataSetMetaDataType, dsm *message.DataSetMessage) ([]*ua.Variant, ua.StatusCode) {
	if md == nil || len(md.Fields) == 0 {
		in := make([]*ua.Variant, len(dsm.Fields))
		for i, f := range dsm.Fields {
			if f.Value != nil {
				in[i] = f.Value.Value
			}
		}
		return in, ua.StatusGood
	}
	n := len(md.Fields)
	if len(dsm.Fields) > n {
		return nil, ua.StatusBadTooManyArguments
	}
	in := make([]*ua.Variant, n)
	for _, f := range dsm.Fields {
		if int(f.Index) >= n {
			return nil, ua.StatusBadTooManyArguments
		}
		if f.Value != nil {
			in[f.Index] = f.Value.Value
		}
	}
	for i, fm := range md.Fields {
		v := in[i]
		if v == nil {
			return nil, ua.StatusBadArgumentsMissing
		}
		bt := ua.TypeID(fm.BuiltInType)
		if bt != 0 && bt != ua.TypeIDVariant && v.Value() != nil && v.Type() != bt {
			return nil, ua.StatusBadTypeMismatch
		}
	}
	return in, ua.StatusGood
}

// replyAddress returns where to answer a request: the ResponseAddress or
// the default of the transport (§7.3.4.7.10: the action-response topic of
// the action-request topic). A datagram ResponseAddress must be the host
// the request came from or a multicast group, so that requests cannot direct
// responses at third parties. p.mu is held.
func (p *PubSub) replyAddress(c *connection, enc encoding, nm *message.NetworkMessage, m *transport.Message) (replyTo, bool) {
	r := replyTo{enc: enc, corr: nm.Action.CorrelationData, requestor: nm.Action.RequestorID}
	addr := nm.Action.ResponseAddress
	if c.broker {
		r.topic = addr
		if r.topic == "" {
			r.topic = defaultResponseTopic(m.Topic)
		}
		if r.topic == "" || strings.ContainsAny(r.topic, "+#") {
			p.log.Debug("pubsub: no address for the response to an Action request", "connection", c.name, "topic", m.Topic)
			return r, false
		}
		return r, true
	}
	if addr == "" || addr == c.url {
		return r, true
	}
	if !replyAllowed(addr, m.Source) {
		p.log.Debug("pubsub: Action ResponseAddress refused", "connection", c.name, "address", addr, "source", m.Source)
		return r, false
	}
	r.dest = addr
	return r, true
}

// replyAllowed tells whether a datagram response may go to addr for a
// request from src: an opc.udp address of the source host or a multicast
// group. Without a known source (transports that do not report it) any
// address of the scheme of the request is allowed.
func replyAllowed(addr string, src net.Addr) bool {
	scheme, err := transport.Scheme(addr)
	if err != nil {
		return false
	}
	if scheme != "opc.udp" {
		return src == nil
	}
	if sharedAddress(addr) {
		return true
	}
	if src == nil {
		return true
	}
	host, _, err := net.SplitHostPort(strings.TrimPrefix(addr, "opc.udp://"))
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ua, ok := src.(*net.UDPAddr)
	if !ok {
		return false
	}
	sa, ok := netip.AddrFromSlice(ua.IP)
	return ok && sa.Unmap() == a.Unmap()
}

// startAction runs the handler of an exchange. p.mu is held.
func (p *PubSub) startAction(c *connection, gen uint64, ex *exchange, h ActionHandler, inputs []*ua.Variant, requestor *message.PublisherID) {
	w := ex.w
	inv := ActionInvocation{Writer: w.id, DataSetWriterID: w.cfg.DataSetWriterID, DataSet: w.pds.name, ActionTargetID: ex.target, RequestorID: requestor, RequestID: ex.key.reqID}
	ctx, cancel := context.WithDeadline(p.ctx, ex.deadline)
	ctx = context.WithValue(ctx, invocationKey{}, inv)
	ex.cancel = cancel
	md := w.pds.md
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer cancel()
		var outputs []*ua.Variant
		st := ua.StatusBadInternalError
		if p.protect("ActionHandler", func() { outputs, st = h(ctx, inputs) }) {
			outputs, st = nil, ua.StatusBadInternalError
		}
		p.lock()
		if c.gen != gen || c.act.exchanges[ex.key] != ex {
			p.unlock()
			return
		}
		ex.finish(st, outputs, md)
		if ex.status != st {
			p.log.Warn("pubsub: Action handler returned outputs that do not match the response DataSetMetaData",
				"data_set", w.pds.name, "target", ex.target, "outputs", len(outputs))
		}
		s := p.responseLocked(c, gen, ex, time.Now())
		p.unlock()
		_ = p.sendAction(s)
	}()
}

// armExchange schedules the next event of an exchange: its expiry at the
// end of the TimeoutHint and, for a group with a PublishingInterval (a
// datagram transport), the repetition of its state. p.mu is held.
func (p *PubSub) armExchange(c *connection, gen uint64, ex *exchange, now time.Time) {
	d := ex.deadline.Sub(now)
	if iv := ex.w.group.interval; iv > 0 && iv < d {
		d = iv
	}
	ex.timer = time.AfterFunc(max(d, 0), func() { p.exchangeTimer(c, gen, ex) })
}

func (p *PubSub) exchangeTimer(c *connection, gen uint64, ex *exchange) {
	p.lock()
	if c.gen != gen || c.act.exchanges[ex.key] != ex {
		p.unlock()
		return
	}
	now := time.Now()
	if !now.Before(ex.deadline) {
		delete(c.act.exchanges, ex.key)
		ex.stop()
		p.unlock()
		return
	}
	var s *actionSend
	if ex.w.group.interval > 0 {
		s = p.responseLocked(c, gen, ex, now)
	}
	p.armExchange(c, gen, ex, now)
	p.unlock()
	if s != nil {
		_ = p.sendAction(s)
	}
}

// responseLocked builds the response of an exchange in its current state:
// Executing (Status Good, no fields), Done (the result) or Idle (the
// confirmation of the acknowledgement). p.mu is held.
func (p *PubSub) responseLocked(c *connection, gen uint64, ex *exchange, now time.Time) *actionSend {
	w := ex.w
	g := w.group
	md := w.pds.md
	ex.lastSent = now
	dsm := &message.DataSetMessage{
		DataSetWriterID: w.cfg.DataSetWriterID,
		Type:            message.DataSetMessageActionResponse,
		Valid:           true,
		// Part 14 Table 85: the Status is always included.
		UADPMask: w.uadpMask&(ua.UADPDataSetMessageContentMaskTimestamp|ua.UADPDataSetMessageContentMaskMajorVersion|
			ua.UADPDataSetMessageContentMaskMinorVersion) | ua.UADPDataSetMessageContentMaskStatus,
		JSONMask: w.jsonMask & (ua.JSONDataSetMessageContentMaskDataSetWriterName | ua.JSONDataSetMessageContentMaskWriterGroupName |
			ua.JSONDataSetMessageContentMaskMetaDataVersion | ua.JSONDataSetMessageContentMaskMinorVersion |
			ua.JSONDataSetMessageContentMaskTimestamp | ua.JSONDataSetMessageContentMaskMessageType),
		Timestamp:         now,
		Status:            ua.StatusGood,
		DataSetWriterName: w.name,
		WriterGroupName:   g.name,
		ActionTargetID:    ex.target,
		RequestID:         ex.key.reqID,
		ActionState:       ex.state,
	}
	if md != nil && md.ConfigurationVersion != nil {
		dsm.MetaDataVersion = *md.ConfigurationVersion
	}
	if w.cfg.DataSetFieldContentMask&ua.DataSetFieldContentMaskRawData != 0 {
		dsm.FieldEncoding = message.FieldEncodingRawData
		dsm.FieldContentMask = ua.DataSetFieldContentMaskRawData
	}
	if ex.state == ua.ActionStateDone {
		dsm.Status = ex.status
		dsm.Fields = namedFields(ex.outputs, md)
	}
	nm := &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		PublisherID: c.pubID,
		Timestamp:   now,
		Messages:    []*message.DataSetMessage{dsm},
		Action:      &message.ActionHeader{Type: message.ActionResponse, CorrelationData: ex.reply.corr, RequestorID: ex.reply.requestor},
	}
	if ex.reply.enc == encUADP {
		nm.UADPMask = ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskPayloadHeader |
			ua.UADPNetworkMessageContentMaskGroupHeader | ua.UADPNetworkMessageContentMaskWriterGroupID
		nm.GroupHeader.WriterGroupID = g.cfg.WriterGroupID
	} else {
		nm.MessageID = uuid.NewString()
	}
	s := &actionSend{c: c, gen: gen, nm: nm, enc: ex.reply.enc, mode: g.mode, groupID: g.cfg.SecurityGroupID, g: g, w: w, md: md,
		topic: ex.reply.topic, dest: ex.reply.dest, msgType: transport.MessageTypeActionResponse, qos: 1}
	if g.brokerTS != nil {
		s.qos = max(qosOf(g.brokerTS.RequestedDeliveryGuarantee, 1), 1)
	}
	return s
}

// namedFields returns the fields of values, named after md (or "Field0",
// ...).
func namedFields(values []*ua.Variant, md *ua.DataSetMetaDataType) []*message.Field {
	var out []*message.Field
	for i, v := range values {
		if v == nil {
			v = ua.MustVariant(nil)
		}
		f := &message.Field{Index: uint16(i), Name: fieldName(i), Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v}}
		if md != nil && i < len(md.Fields) && md.Fields[i] != nil && md.Fields[i].Name != "" {
			f.Name = md.Fields[i].Name
		}
		out = append(out, f)
	}
	return out
}

// actionTransport returns the transport to send an action message on: the
// connection's, or one to another datagram address. p.mu is not held.
func (p *PubSub) actionTransport(c *connection, gen uint64, dest string) (transport.Connection, error) {
	p.lock()
	if c.gen != gen || c.tc == nil {
		p.unlock()
		return nil, fmt.Errorf("pubsub: connection %q is not open: %w", c.name, ua.StatusBadNotConnected)
	}
	if dest == "" {
		tc := c.tc
		p.unlock()
		return tc, nil
	}
	c.act.init()
	if tc := c.act.senders[dest]; tc != nil {
		p.unlock()
		return tc, nil
	}
	cfg := p.transportConfig(c)
	p.unlock()
	cfg.URL, cfg.ListenAddress = dest, ""
	octx, cancel := context.WithTimeout(context.Background(), openTimeout)
	tc, err := transport.Open(octx, cfg)
	cancel()
	if err != nil {
		return nil, err
	}
	var evict []transport.Connection
	p.lock()
	defer func() {
		p.unlock()
		for _, x := range evict {
			_ = x.Close()
		}
	}()
	if c.gen != gen {
		evict = append(evict, tc)
		return nil, fmt.Errorf("pubsub: connection %q stopped: %w", c.name, ua.StatusBadNotConnected)
	}
	if x := c.act.senders[dest]; x != nil {
		evict = append(evict, tc)
		return x, nil
	}
	for len(c.act.order) >= maxActionSenders {
		evict = append(evict, c.act.senders[c.act.order[0]])
		delete(c.act.senders, c.act.order[0])
		c.act.order = c.act.order[1:]
	}
	c.act.senders[dest] = tc
	c.act.order = append(c.act.order, dest)
	return tc, nil
}

// encodeAction encodes an action message, secured for UADP.
func (p *PubSub) encodeAction(s *actionSend) ([]byte, error) {
	opts := &uadp.EncodeOptions{}
	if md := s.md; md != nil {
		opts.MetaData = func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType { return md }
	}
	if s.enc == encUADP && s.mode > ua.MessageSecurityModeNone {
		ks := p.KeySource(s.groupID)
		if ks == nil {
			return nil, fmt.Errorf("pubsub: no keys of SecurityGroup %q: %w", s.groupID, security.ErrNoKeys)
		}
		opts.SecurityMode, opts.Keys = s.mode, ks
		if s.g != nil {
			opts.NextNonceSequence = s.g.nextNonce
		} else {
			opts.NextNonceSequence = p.nextActionNonce
		}
	}
	var b []byte
	var err error
	if p.protect("encode", func() { b, err = p.codecs(s.enc).Encode(s.nm, opts) }) {
		err = errors.New("pubsub: encoding the action message panicked")
	}
	return b, err
}

// nextActionNonce numbers the secured requests of the Requestor.
func (p *PubSub) nextActionNonce() uint32 { return p.actNonce.Add(1) }

// sendAction encodes and sends an action message and counts it.
func (p *PubSub) sendAction(s *actionSend) error {
	b, err := p.encodeAction(s)
	if err == nil {
		var tc transport.Connection
		if tc, err = p.actionTransport(s.c, s.gen, s.dest); err == nil {
			err = tc.Send(context.Background(), b, transport.PublishOptions{Topic: s.topic, QoS: s.qos,
				ContentType: s.enc.contentType(), MessageType: s.msgType})
		}
	}
	p.lock()
	defer p.unlock()
	if s.c.gen != s.gen {
		return err
	}
	resp := s.msgType == transport.MessageTypeActionResponse
	if err != nil {
		p.log.Debug("pubsub: action message not sent", "connection", s.c.name, "type", s.msgType, "error", err)
		if resp {
			s.g.ctr.SendErrors++
			s.g.err = err
			p.count(&s.g.base, CounterFailedTransmissions, 1)
		} else {
			s.c.ctr.SendErrors++
		}
		return err
	}
	if resp {
		s.w.ctr.ActionResponsesSent++
		s.g.ctr.NetworkMessagesSent++
		s.g.ctr.BytesSent += uint64(len(b))
		p.count(&s.g.base, CounterSentNetworkMessages, 1)
	} else {
		s.c.ctr.ActionRequestsSent++
		s.c.ctr.NetworkMessagesSent++
		s.c.ctr.BytesSent += uint64(len(b))
	}
	return nil
}

// callKey identifies a call of the Requestor: its CorrelationData and
// RequestId.
type callKey struct {
	corr  string
	reqID uint16
}

// actionCall is a pending call of the Requestor.
type actionCall struct {
	key     callKey
	pub     message.PublisherID
	dswid   uint16
	target  uint16
	mode    ua.MessageSecurityMode
	groupID string
	md      *ua.DataSetMetaDataType
	// ch receives the responses; gone is closed when the connection
	// stops.
	ch   chan actionReply
	gone chan struct{}
}

// actionReply is a response received for a call.
type actionReply struct {
	state   ua.ActionState
	status  ua.StatusCode
	outputs []*ua.Variant
}

// actionResponses hands the received ActionResponses to their calls.
func (p *PubSub) actionResponses(c *connection, gen uint64, nm *message.NetworkMessage, got ua.MessageSecurityMode, keyGroup string) {
	p.lock()
	defer p.unlock()
	if c.gen != gen {
		return
	}
	if r := nm.Action.RequestorID; r != nil && c.hasPub && !samePublisher(*r, c.pubID) {
		return
	}
	corr := string(nm.Action.CorrelationData)
	for _, dsm := range nm.Messages {
		call := c.act.calls[callKey{corr: corr, reqID: dsm.RequestID}]
		if call == nil || !dsm.Valid || !samePublisher(nm.PublisherID, call.pub) || dsm.ActionTargetID != call.target ||
			(dsm.DataSetWriterID != 0 && dsm.DataSetWriterID != call.dswid) || !securedFor(call.mode, call.groupID, got, keyGroup) {
			continue
		}
		c.ctr.ActionResponsesReceived++
		r := actionReply{state: dsm.ActionState, status: dsm.Status, outputs: actionOutputs(call.md, dsm)}
		select {
		case call.ch <- r:
		default:
		}
	}
}

// actionOutputs returns the output fields of a response: in the order of
// the response DataSetMetaData if known (JSON fields are placed by name),
// else as received.
func actionOutputs(md *ua.DataSetMetaDataType, dsm *message.DataSetMessage) []*ua.Variant {
	if len(dsm.Fields) == 0 {
		return nil
	}
	value := func(f *message.Field) *ua.Variant {
		if f.Value == nil {
			return nil
		}
		return f.Value.Value
	}
	if md != nil && len(md.Fields) > 0 {
		// Fields beyond the metadata are dropped.
		out := make([]*ua.Variant, len(md.Fields))
		for _, f := range dsm.Fields {
			if int(f.Index) < len(out) {
				out[f.Index] = value(f)
			}
		}
		return out
	}
	out := make([]*ua.Variant, len(dsm.Fields))
	for i, f := range dsm.Fields {
		out[i] = value(f)
	}
	return out
}

// CallAction calls an Action target of a Responder (the Requestor of Part 14
// §6.2.11.2 in 1.05): it sends the request with the inputs on the connection
// t.Connection and waits for the Done response, which it acknowledges. It
// returns the result of the Action; an error is returned when the call
// could not be made or completed: an invalid target, a connection that is
// not running, ErrActionTimeout (Bad_Timeout) when no Done response came in
// time, the error of ctx, or Bad_NotConnected when the connection stopped
// meanwhile.
//
// The connection must be running: CallAction waits until its transport is
// open and subscribed to the response address, within the timeout.
func (p *PubSub) CallAction(ctx context.Context, t ActionTarget, inputs []*ua.Variant) (*ActionResult, error) {
	pv, err := PublisherIDVariant(t.PublisherID)
	if err != nil {
		return nil, fmt.Errorf("pubsub: ActionTarget: %w: %w", err, ua.StatusBadInvalidArgument)
	}
	responder, ok, _ := publisherIDOf(pv)
	if !ok {
		return nil, fmt.Errorf("pubsub: ActionTarget needs the PublisherId of the Responder: %w", ua.StatusBadInvalidArgument)
	}
	if t.DataSetWriterID == 0 {
		return nil, fmt.Errorf("pubsub: ActionTarget needs the DataSetWriterId of the Responder: %w", ua.StatusBadInvalidArgument)
	}
	mode := securityMode(t.SecurityMode)
	if mode > ua.MessageSecurityModeSignAndEncrypt || (mode > ua.MessageSecurityModeNone && t.SecurityGroupID == "") {
		return nil, fmt.Errorf("pubsub: ActionTarget: SecurityMode %v needs a SecurityGroupId: %w", t.SecurityMode, ua.StatusBadInvalidArgument)
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = p.opts.actions.DefaultTimeout
		if dl, ok := ctx.Deadline(); ok {
			timeout = time.Until(dl)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	corr := make([]byte, correlationLength)
	_, _ = crand.Read(corr)

	p.lock()
	if p.closed {
		p.unlock()
		return nil, ErrClosed
	}
	var c *connection
	for _, x := range p.conns {
		if x.name == t.Connection {
			c = x
		}
	}
	var setupErr error
	enc := encUADP
	switch {
	case c == nil:
		setupErr = fmt.Errorf("pubsub: no connection %q: %w", t.Connection, ua.StatusBadNotFound)
	case !c.hasPub:
		setupErr = fmt.Errorf("pubsub: connection %q has no PublisherId for the RequestorId: %w", c.name, ua.StatusBadConfigurationError)
	case c.cancel == nil:
		setupErr = fmt.Errorf("pubsub: connection %q is not running: %w", c.name, ua.StatusBadInvalidState)
	case isJSONProfile(c.cfg.TransportProfileURI):
		enc = encJSON
		if mode > ua.MessageSecurityModeNone {
			setupErr = fmt.Errorf("pubsub: the JSON message mapping has no message security: %w", ua.StatusBadInvalidArgument)
		}
	}
	var listen, reqTopic, dest, respAddr string
	if setupErr == nil {
		respAddr = t.ResponseAddress
		if c.broker {
			reqTopic = t.RequestAddress
			if respAddr == "" {
				respAddr = defaultResponseTopic(reqTopic)
			}
			listen = respAddr
			switch {
			case reqTopic == "":
				setupErr = fmt.Errorf("pubsub: ActionTarget needs the RequestAddress (the request queue of the Responder): %w", ua.StatusBadInvalidArgument)
			case respAddr == "":
				setupErr = fmt.Errorf("pubsub: ActionTarget needs a ResponseAddress: %q has no action-request level: %w", reqTopic, ua.StatusBadInvalidArgument)
			}
		} else if t.RequestAddress != "" && t.RequestAddress != c.url {
			dest = t.RequestAddress
			if respAddr == "" {
				respAddr = c.url
			}
		}
	}
	if setupErr != nil {
		p.unlock()
		return nil, setupErr
	}
	p.reqSeq++
	call := &actionCall{
		key: callKey{corr: string(corr), reqID: p.reqSeq}, pub: responder, dswid: t.DataSetWriterID, target: t.ActionTargetID,
		mode: mode, groupID: t.SecurityGroupID, md: t.ResponseMetaData,
		ch: make(chan actionReply, actionReplyBuffer), gone: make(chan struct{}),
	}
	c.act.init()
	c.act.calls[call.key] = call
	c.act.listen[listen]++
	p.updateTopics(c)
	gen, requestor, seq := c.gen, c.pubID, c.topicsSeq
	p.unlock()

	released := false
	release := func() {
		if released {
			return
		}
		released = true
		p.lock()
		defer p.unlock()
		if c.gen != gen {
			return
		}
		delete(c.act.calls, call.key)
		if c.act.listen[listen]--; c.act.listen[listen] <= 0 {
			delete(c.act.listen, listen)
		}
		p.updateTopics(c)
	}
	defer release()

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	fail := func(err error) (*ActionResult, error) {
		select {
		case <-call.gone:
			if p.isClosed() {
				return nil, ErrClosed
			}
			return nil, fmt.Errorf("pubsub: connection %q stopped: %w", c.name, ua.StatusBadNotConnected)
		default:
		}
		if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			p.lock()
			if c.gen == gen {
				c.ctr.ActionTimeouts++
			}
			p.unlock()
			return nil, fmt.Errorf("pubsub: Action target %d of writer %d of %v: %w", t.ActionTargetID, t.DataSetWriterID, responder, ErrActionTimeout)
		}
		return nil, err
	}
	if err := p.waitSubscribed(cctx, c, gen, seq, listen); err != nil {
		return fail(err)
	}

	request := func(state ua.ActionState) *actionSend {
		now := time.Now()
		dsm := &message.DataSetMessage{
			DataSetWriterID: t.DataSetWriterID, Type: message.DataSetMessageActionRequest, Valid: true,
			JSONMask:  ua.JSONDataSetMessageContentMaskTimestamp | ua.JSONDataSetMessageContentMaskMessageType,
			Timestamp: now, ActionTargetID: t.ActionTargetID, RequestID: call.key.reqID, ActionState: state,
		}
		if state == ua.ActionStateExecuting {
			dsm.Fields = namedFields(inputs, t.RequestMetaData)
		}
		nm := &message.NetworkMessage{
			Type: message.NetworkMessageDataSet, PublisherID: responder, Timestamp: now,
			Messages: []*message.DataSetMessage{dsm},
			Action: &message.ActionHeader{Type: message.ActionRequest, ResponseAddress: respAddr, CorrelationData: corr,
				RequestorID: &requestor, TimeoutHint: millis(timeout)},
		}
		if enc == encUADP {
			nm.UADPMask = ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskPayloadHeader
		} else {
			nm.JSONMask = ua.JSONNetworkMessageContentMaskNetworkMessageHeader | ua.JSONNetworkMessageContentMaskDataSetMessageHeader |
				ua.JSONNetworkMessageContentMaskPublisherID
			nm.MessageID = uuid.NewString()
		}
		return &actionSend{c: c, gen: gen, nm: nm, enc: enc, mode: mode, groupID: t.SecurityGroupID,
			topic: reqTopic, qos: 1, dest: dest, msgType: transport.MessageTypeActionRequest}
	}
	if err := p.sendAction(request(ua.ActionStateExecuting)); err != nil {
		return fail(err)
	}
	var tick <-chan time.Time
	if t.ResendInterval > 0 {
		tk := time.NewTicker(t.ResendInterval)
		defer tk.Stop()
		tick = tk.C
	}
	heard := time.Now()
	var res *ActionResult
	for res == nil {
		select {
		case r := <-call.ch:
			heard = time.Now()
			if r.state == ua.ActionStateDone {
				res = &ActionResult{Status: r.status, Outputs: r.outputs, RequestID: call.key.reqID}
			}
		case <-tick:
			// Part 14 Table 83: resent while neither Executing nor Done
			// arrives.
			if time.Since(heard) >= t.ResendInterval {
				_ = p.sendAction(request(ua.ActionStateExecuting))
			}
		case <-call.gone:
			return fail(nil)
		case <-cctx.Done():
			return fail(cctx.Err())
		}
	}
	// Acknowledge the Done response; on a non-reliable transport until the
	// Responder confirms it.
	_ = p.sendAction(request(ua.ActionStateIdle))
	if t.ResendInterval > 0 {
		p.lock()
		if !p.closed && c.gen == gen {
			released = true // the acknowledgement releases the call
			p.wg.Add(1)
			go p.acknowledge(c, gen, call, listen, t.ResendInterval, time.Now().Add(timeout), func() *actionSend { return request(ua.ActionStateIdle) })
		}
		p.unlock()
	}
	return res, nil
}

// acknowledge resends the Idle acknowledgement of a call every interval
// until the Responder confirms it or the deadline passes, then releases the
// call.
func (p *PubSub) acknowledge(c *connection, gen uint64, call *actionCall, listen string, interval time.Duration, deadline time.Time, idle func() *actionSend) {
	defer p.wg.Done()
	defer func() {
		p.lock()
		defer p.unlock()
		if c.gen != gen {
			return
		}
		delete(c.act.calls, call.key)
		if c.act.listen[listen]--; c.act.listen[listen] <= 0 {
			delete(c.act.listen, listen)
		}
		p.updateTopics(c)
	}()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	end := time.NewTimer(time.Until(deadline))
	defer end.Stop()
	for {
		select {
		case r := <-call.ch:
			if r.state == ua.ActionStateIdle {
				return
			}
		case <-tk.C:
			_ = p.sendAction(idle())
		case <-call.gone:
			return
		case <-end.C:
			return
		}
	}
}

func (p *PubSub) isClosed() bool {
	p.lock()
	defer p.unlock()
	return p.closed
}

// waitSubscribed waits until a running connection is subscribed to topic,
// by a subscription update that saw the topics of change seq or later.
func (p *PubSub) waitSubscribed(ctx context.Context, c *connection, gen, seq uint64, topic string) error {
	for {
		p.lock()
		if c.gen != gen || c.subsCh == nil {
			p.unlock()
			return fmt.Errorf("pubsub: connection %q stopped: %w", c.name, ua.StatusBadNotConnected)
		}
		if c.syncedSeq >= seq && c.subscribed[topic] {
			p.unlock()
			return nil
		}
		ch := c.subsCh
		p.unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
