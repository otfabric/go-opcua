// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// pubsubConfig is the PubSub configuration given with WithPubSub.
type pubsubConfig struct {
	cfg  *ua.PubSubConfigurationDataType
	opts []pubsub.Option
}

// pubsubState is the PubSub runtime of a server and its information model.
type pubsubState struct {
	once sync.Once
	rt   *pubsub.PubSub
	err  error

	// mu guards the information model below.
	mu    sync.Mutex
	model *pubsubModel

	evMu   sync.Mutex
	evSubs map[*pubsubEventSub]struct{}
}

// WithPubSub makes the server a PubSub publisher and subscriber (Part 14):
// it runs a PubSub runtime for cfg, started and stopped with the server, and
// publishes the PublishSubscribe information model below the Server object
// (i=14443), with the methods that let clients configure it (AddConnection,
// AddWriterGroup, ...).
//
// cfg may be nil for an empty, enabled runtime that clients configure. The
// runtime reads published variables from the address space and writes the
// target variables of readers to it, and the targets of its
// PublishedActionMethods call the Methods of the address space; opts can
// replace these sources and add handlers and key sources. The runtime is available with [Server.PubSub].
func WithPubSub(cfg *ua.PubSubConfigurationDataType, opts ...pubsub.Option) Option {
	return func(c *serverConfig) error {
		if cfg != nil {
			if err := pubsub.Validate(cfg); err != nil {
				return fmt.Errorf("server: WithPubSub: %w", err)
			}
		}
		c.pubsub = &pubsubConfig{cfg: cfg, opts: opts}
		return nil
	}
}

// PubSubAuthorizer decides whether the caller of a PubSub configuration
// method (AddConnection, RemoveGroup, Enable, ...) may call it. method is
// the BrowseName of the method. It returns Good to allow the call or the
// Bad status to answer it with.
type PubSubAuthorizer func(ctx context.Context, caller *MethodCaller, method string) ua.StatusCode

// WithPubSubAuthorizer restricts the PubSub configuration methods. Without
// it every session may call them, as with open62541.
func WithPubSubAuthorizer(a PubSubAuthorizer) Option {
	return func(c *serverConfig) error {
		c.pubsubAuth = a
		return nil
	}
}

// PubSub returns the PubSub runtime of the server, nil if the server was
// created without [WithPubSub]. Components added to it, before or after
// Start, appear in the information model.
func (s *Server) PubSub() *pubsub.PubSub {
	if s.cfg.pubsub == nil {
		return nil
	}
	s.ps.once.Do(func() {
		opts := []pubsub.Option{
			pubsub.WithLogger(s.cfg.logger),
			pubsub.WithDataSource(serverDataSource{s}),
			pubsub.WithTargetWriter(serverTargetWriter{s}),
			pubsub.WithEventSource(serverEventSource{s}),
			pubsub.WithEventHandler(s.onPubSubEvent),
			pubsub.WithActionMethodCaller(s.callActionMethod),
		}
		s.ps.rt, s.ps.err = pubsub.New(s.cfg.pubsub.cfg, append(opts, s.cfg.pubsub.opts...)...)
	})
	return s.ps.rt
}

// callActionMethod calls a Method of the address space for the target of
// a PublishedActionMethod, like the Call service does but without a
// session: the request was authorized by the security of the writer group.
// The handler finds no MethodCaller in its context;
// pubsub.ActionInvocationFrom tells the request it serves.
func (s *Server) callActionMethod(ctx context.Context, objectID, methodID *ua.NodeID, inputs []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	res := (&MethodService{srv: s}).callMethod(ctx, &ua.CallMethodRequest{ObjectID: objectID, MethodID: methodID, InputArguments: inputs})
	return res.OutputArguments, res.StatusCode
}

// startPubSub builds the information model and starts the runtime.
func (s *Server) startPubSub(ctx context.Context) error {
	if s.cfg.pubsub == nil {
		return nil
	}
	rt := s.PubSub()
	if rt == nil {
		return fmt.Errorf("server: pubsub: %w", s.ps.err)
	}
	if err := s.buildPubSubModel(); err != nil {
		return err
	}
	return rt.Start(ctx)
}

func (s *Server) closePubSub() {
	if s.cfg.pubsub == nil || s.ps.rt == nil {
		return
	}
	_ = s.ps.rt.Close()
}

// serverDataSource reads published variables from the address space.
type serverDataSource struct{ s *Server }

func (d serverDataSource) ReadPublishedData(_ context.Context, vars []*ua.PublishedVariableDataType) []*ua.DataValue {
	out := make([]*ua.DataValue, len(vars))
	for i, v := range vars {
		out[i] = d.s.readPublished(v)
	}
	return out
}

func badValue(sc ua.StatusCode) *ua.DataValue {
	return &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: sc}
}

func (s *Server) readPublished(v *ua.PublishedVariableDataType) *ua.DataValue {
	if v == nil || v.PublishedVariable == nil {
		return badValue(ua.StatusBadNodeIDUnknown)
	}
	ns, err := s.Namespace(int(v.PublishedVariable.Namespace()))
	if err != nil {
		return badValue(ua.StatusBadNodeIDUnknown)
	}
	attr := v.AttributeID
	if attr == 0 {
		attr = ua.AttributeIDValue
	}
	dv := ns.Attribute(v.PublishedVariable, attr)
	if dv == nil {
		return badValue(ua.StatusBadNodeIDUnknown)
	}
	cp := *dv
	if v.IndexRange != "" {
		if attr != ua.AttributeIDValue || cp.Value == nil || cp.Status&0x80000000 != 0 {
			return badValue(ua.StatusBadIndexRangeInvalid)
		}
		sliced, sc := ua.SliceVariantRead(cp.Value, v.IndexRange)
		if sc != ua.StatusOK {
			return badValue(sc)
		}
		cp.Value = sliced
	}
	return &cp
}

// FieldMetaData implements pubsub.FieldMetaDataResolver from the DataType
// and ValueRank of the published variable.
func (d serverDataSource) FieldMetaData(v *ua.PublishedVariableDataType) *ua.FieldMetaData {
	n := d.s.Node(v.PublishedVariable)
	if n == nil || (v.AttributeID != 0 && v.AttributeID != ua.AttributeIDValue) {
		return nil
	}
	f := &ua.FieldMetaData{Name: n.BrowseName().Name, ValueRank: -1, Description: &ua.LocalizedText{}}
	ns, err := d.s.Namespace(int(v.PublishedVariable.Namespace()))
	if err != nil {
		return nil
	}
	if dv := ns.Attribute(v.PublishedVariable, ua.AttributeIDDataType); dv != nil && dv.Value != nil {
		switch x := dv.Value.Value().(type) {
		case *ua.NodeID:
			f.DataType = x
		case *ua.ExpandedNodeID:
			f.DataType = x.NodeID
		}
	}
	if f.DataType == nil {
		f.DataType = ua.NewNumericNodeID(0, id.BaseDataType)
	}
	if dv := ns.Attribute(v.PublishedVariable, ua.AttributeIDValueRank); dv != nil && dv.Value != nil {
		if vr, ok := dv.Value.Value().(int32); ok {
			f.ValueRank = vr
		}
	} else if val := n.Value(); val != nil && val.Value != nil && val.Value.IsArray() {
		f.ValueRank = 1
	}
	if v.IndexRange != "" && f.ValueRank >= 1 {
		// A range of an array is still an array, a single element is not
		// known here: leave the rank of the variable.
		f.ValueRank = 1
	}
	f.BuiltInType = d.s.builtinType(f.DataType)
	return f
}

// builtinType returns the built-in type a DataType is encoded with: itself
// for the built-in types, Int32 for enumerations, ExtensionObject for
// structures, else the built-in type of its supertype.
func (s *Server) builtinType(dt *ua.NodeID) uint8 {
	for range 32 {
		if dt == nil {
			break
		}
		if dt.Namespace() == 0 {
			switch n := dt.IntID(); {
			case n == id.Enumeration:
				return uint8(ua.TypeIDInt32)
			case n >= 1 && n <= 25:
				return uint8(n)
			}
		}
		dt = s.superType(dt)
	}
	return uint8(ua.TypeIDVariant)
}

// superType returns the supertype of a type node (the source of its inverse
// HasSubtype reference).
func (s *Server) superType(t *ua.NodeID) *ua.NodeID {
	n := s.Node(t)
	if n == nil {
		return nil
	}
	for _, r := range n.refsSnapshot() {
		if r != nil && !r.IsForward && r.ReferenceTypeID != nil && r.ReferenceTypeID.IntID() == id.HasSubtype && r.NodeID != nil {
			return r.NodeID.NodeID
		}
	}
	return nil
}

// serverTargetWriter writes received fields to target variables.
type serverTargetWriter struct{ s *Server }

func (w serverTargetWriter) WriteTargets(_ context.Context, writes []pubsub.TargetWrite) []error {
	errs := make([]error, len(writes))
	for i, tw := range writes {
		if sc := w.s.writeTarget(tw.Target, tw.Value); sc != ua.StatusOK {
			errs[i] = fmt.Errorf("server: write %v: %w", tw.Target.TargetNodeID, sc)
		}
	}
	return errs
}

func (s *Server) writeTarget(t *ua.FieldTargetDataType, dv *ua.DataValue) ua.StatusCode {
	if t == nil || t.TargetNodeID == nil || dv == nil {
		return ua.StatusBadNodeIDUnknown
	}
	ns, err := s.Namespace(int(t.TargetNodeID.Namespace()))
	if err != nil {
		return ua.StatusBadNodeIDUnknown
	}
	attr := t.AttributeID
	if attr == 0 {
		attr = ua.AttributeIDValue
	}
	cp := *dv
	if t.WriteIndexRange != "" {
		if attr != ua.AttributeIDValue || cp.Value == nil {
			return ua.StatusBadIndexRangeInvalid
		}
		cur := ns.Attribute(t.TargetNodeID, ua.AttributeIDValue)
		if cur == nil || cur.Value == nil || cur.Status&0x80000000 != 0 {
			return ua.StatusBadIndexRangeInvalid
		}
		merged, sc := ua.MergeVariantWrite(cur.Value, t.WriteIndexRange, cp.Value)
		if sc != ua.StatusOK {
			return sc
		}
		cp.Value = merged
	}
	cp.UpdateMask()
	return ns.SetAttribute(t.TargetNodeID, attr, &cp)
}

// WriteMirror implements pubsub.MirrorWriter: the DataSet is mirrored in
// variables below an object named ParentNodeName in the SubscribedDataSet
// of the reader.
func (w serverTargetWriter) WriteMirror(_ context.Context, m *pubsub.MirrorWrite) error {
	return w.s.writeMirror(m)
}

// pubsubEventSub is a PublishedEvents subscription to the server's events.
type pubsubEventSub struct {
	events  *ua.PublishedEventsDataType
	deliver func([]*ua.Variant)
}

// serverEventSource delivers the events emitted with EmitBaseEvent.
type serverEventSource struct{ s *Server }

func (e serverEventSource) SubscribeEvents(_ context.Context, ev *ua.PublishedEventsDataType, deliver func([]*ua.Variant)) (func(), error) {
	if ev == nil || ev.EventNotifier == nil {
		return nil, errors.New("server: PublishedEvents without EventNotifier")
	}
	sub := &pubsubEventSub{events: ev, deliver: deliver}
	ps := &e.s.ps
	ps.evMu.Lock()
	if ps.evSubs == nil {
		ps.evSubs = map[*pubsubEventSub]struct{}{}
	}
	ps.evSubs[sub] = struct{}{}
	ps.evMu.Unlock()
	return func() {
		ps.evMu.Lock()
		delete(ps.evSubs, sub)
		ps.evMu.Unlock()
	}, nil
}

// forwardPubSubEvent hands an event emitted on a node to the PublishedEvents
// whose EventNotifier is that node and whose filter it passes.
func (s *Server) forwardPubSubEvent(nodeID *ua.NodeID, event *BaseEvent) {
	if nodeID == nil || event == nil {
		return
	}
	s.ps.evMu.Lock()
	var subs []*pubsubEventSub
	for sub := range s.ps.evSubs {
		if sub.events.EventNotifier.Equal(nodeID) {
			subs = append(subs, sub)
		}
	}
	s.ps.evMu.Unlock()
	for _, sub := range subs {
		if f := sub.events.Filter; f != nil && len(f.Elements) > 0 && !s.evalEventFilter(event, f) {
			continue
		}
		sub.deliver(selectEventFields(event, sub.events.SelectedFields))
	}
}
