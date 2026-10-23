// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"log/slog"
	"time"

	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

// DataSource reads the values of PublishedDataItems for the publisher.
//
// ReadPublishedData returns one DataValue per variable, in order. It honours
// the AttributeId and the IndexRange of the PublishedVariableDataType; the
// runtime applies the SubstituteValue to Bad values itself. A missing value
// is reported with a Bad status, not by leaving the slot nil.
type DataSource interface {
	ReadPublishedData(ctx context.Context, vars []*ua.PublishedVariableDataType) []*ua.DataValue
}

// DataSourceFunc adapts a function to a [DataSource].
type DataSourceFunc func(ctx context.Context, vars []*ua.PublishedVariableDataType) []*ua.DataValue

// ReadPublishedData calls f.
func (f DataSourceFunc) ReadPublishedData(ctx context.Context, vars []*ua.PublishedVariableDataType) []*ua.DataValue {
	return f(ctx, vars)
}

// FieldMetaDataResolver is implemented by a [DataSource] that can describe a
// published variable. The runtime uses it to complete the DataSetMetaData of
// PublishedDataItems that were configured without one. The returned
// FieldMetaData needs no name; nil means unknown.
type FieldMetaDataResolver interface {
	FieldMetaData(v *ua.PublishedVariableDataType) *ua.FieldMetaData
}

// EventSource delivers the events of PublishedEvents to the publisher.
//
// SubscribeEvents starts delivering the events of the EventNotifier that pass
// the Filter: deliver is called with the values of the SelectedFields, in
// order, for every event. Cancel stops the delivery; the runtime calls it
// when the DataSetWriter stops.
type EventSource interface {
	SubscribeEvents(ctx context.Context, events *ua.PublishedEventsDataType, deliver func(fields []*ua.Variant)) (cancel func(), err error)
}

// TargetWrite is one write of a received field to a target variable.
type TargetWrite struct {
	// Reader is the id of the DataSetReader the write is for.
	Reader ComponentID
	// Target is the target variable: TargetNodeId, AttributeId and
	// WriteIndexRange. The ReceiverIndexRange is already applied to Value.
	Target *ua.FieldTargetDataType
	// Value is the value to write, with its status and timestamps.
	Value *ua.DataValue
}

// TargetWriter writes the fields of DataSetReaders configured with
// TargetVariables to their target variables. It returns one error (nil for
// success) per write.
type TargetWriter interface {
	WriteTargets(ctx context.Context, writes []TargetWrite) []error
}

// TargetWriterFunc adapts a function to a [TargetWriter].
type TargetWriterFunc func(ctx context.Context, writes []TargetWrite) []error

// WriteTargets calls f.
func (f TargetWriterFunc) WriteTargets(ctx context.Context, writes []TargetWrite) []error {
	return f(ctx, writes)
}

// MirrorWrite is a received DataSet for a DataSetReader configured with a
// SubscribedDataSetMirror.
type MirrorWrite struct {
	Reader     ComponentID
	ReaderName string
	Mirror     *ua.SubscribedDataSetMirrorDataType
	MetaData   *ua.DataSetMetaDataType
	Fields     []ReceivedField
	Changed    []int
}

// MirrorWriter is implemented by a [TargetWriter] that can mirror received
// DataSets in an address space (SubscribedDataSetMirror, Part 14 §6.2.10.3):
// it creates a variable per field below an object named ParentNodeName and
// writes the received values to it.
type MirrorWriter interface {
	WriteMirror(ctx context.Context, m *MirrorWrite) error
}

// DataSetHandler receives the DataSets of all DataSetReaders. It is called
// outside the runtime's lock, in the order the messages were received on a
// connection, and must not block for long. It runs on the receiving
// goroutine of the transport, which [PubSub.Close] waits for: a handler
// must not call Close (it may start it in a goroutine of its own).
type DataSetHandler func(ds *ReceivedDataSet)

// KeySourceLookup returns the keys of a SecurityGroup, nil if unknown.
type KeySourceLookup func(securityGroupID string) security.KeySource

// Option configures a runtime.
type Option func(*options)

type options struct {
	logger          *slog.Logger
	dataSource      DataSource
	eventSource     EventSource
	targetWriter    TargetWriter
	dataSetHandlers []DataSetHandler
	eventHandlers   []func(Event)
	keySources      map[string]security.KeySource
	keyLookups      []KeySourceLookup
	transportConfig []func(conn *ua.PubSubConnectionDataType, cfg *transport.Config)
	retryInterval   time.Duration
	codecs          func(encoding) codec
}

// WithLogger sets the logger. The default discards log output.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithDataSource sets the source of the values of PublishedDataItems.
func WithDataSource(ds DataSource) Option {
	return func(o *options) { o.dataSource = ds }
}

// WithEventSource sets the source of the events of PublishedEvents.
func WithEventSource(es EventSource) Option {
	return func(o *options) { o.eventSource = es }
}

// WithTargetWriter sets the writer of TargetVariables (and, if it implements
// [MirrorWriter], of SubscribedDataSetMirrors).
func WithTargetWriter(tw TargetWriter) Option {
	return func(o *options) { o.targetWriter = tw }
}

// WithDataSetHandler adds a handler for the DataSets received by all
// DataSetReaders.
func WithDataSetHandler(h DataSetHandler) Option {
	return func(o *options) {
		if h != nil {
			o.dataSetHandlers = append(o.dataSetHandlers, h)
		}
	}
}

// WithEventHandler adds a handler for the events of the runtime: components
// added and removed, and state changes.
func WithEventHandler(h func(Event)) Option {
	return func(o *options) {
		if h != nil {
			o.eventHandlers = append(o.eventHandlers, h)
		}
	}
}

// WithKeySource sets the keys of a SecurityGroup: groups with the
// SecurityGroupId secure their messages with them. ks is typically a static
// key ring or a client of a Security Key Service.
func WithKeySource(securityGroupID string, ks security.KeySource) Option {
	return func(o *options) {
		if o.keySources == nil {
			o.keySources = map[string]security.KeySource{}
		}
		o.keySources[securityGroupID] = ks
	}
}

// WithKeySourceLookup adds a lookup for the keys of SecurityGroups that were
// not set with [WithKeySource] or [PubSub.SetKeySource]. Lookups are asked in
// the order they were added.
func WithKeySourceLookup(l KeySourceLookup) Option {
	return func(o *options) {
		if l != nil {
			o.keyLookups = append(o.keyLookups, l)
		}
	}
}

// WithTransportConfig adds a hook that completes the transport configuration
// of a connection before it is opened: MQTT credentials, a TLS
// configuration, multicast settings.
func WithTransportConfig(f func(conn *ua.PubSubConnectionDataType, cfg *transport.Config)) Option {
	return func(o *options) {
		if f != nil {
			o.transportConfig = append(o.transportConfig, f)
		}
	}
}

// WithRetryInterval sets how long a connection whose transport failed to
// open (state Error) waits before it tries again. The default is 5 seconds.
func WithRetryInterval(d time.Duration) Option {
	return func(o *options) { o.retryInterval = d }
}
