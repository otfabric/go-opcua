// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"log/slog"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
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
// must not call Close (it may start it in a goroutine of its own). Nor may
// it wait for [PubSub.CallAction]: the response would arrive on the
// goroutine the handler blocks.
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
	diagLevel       ua.DiagnosticsLevel
	reassembly      *uadp.ReassemblerOptions
	discovery       DiscoveryOptions
	actions         ActionOptions
	actionHandlers  map[actionKey]ActionHandler
	methodCaller    ActionMethodCaller
	inflateLimit    int
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
// added and removed, and state changes. Handlers run on the goroutine that
// made the change, which is a goroutine of the runtime for the state
// changes of a connection and its readers: they must not block for long,
// call [PubSub.Close] or wait for [PubSub.CallAction] (start those in a
// goroutine of their own).
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

// WithJSONDecompressionLimit sets the largest JSON NetworkMessage a
// subscriber decompresses from a gzip compressed message (Part 14
// §7.3.4.9.1); larger ones are decode errors. The default is
// [DefaultJSONDecompressionLimit].
func WithJSONDecompressionLimit(n int) Option {
	return func(o *options) { o.inflateLimit = n }
}

// WithChunkReassembly sets the limits of the reassembly of chunked UADP
// NetworkMessages: the largest message, the memory of the incomplete
// messages of each connection, overall and per PublisherId, and how long an
// incomplete message waits for its chunks. Zero fields keep the defaults of
// [uadp.ReassemblerOptions].
func WithChunkReassembly(o uadp.ReassemblerOptions) Option {
	return func(opts *options) { opts.reassembly = &o }
}

// DiscoveryOptions control the UADP discovery of datagram connections
// (Part 14 §7.2.4.6): the probes a subscriber sends for DataSetMetaData it
// does not have, and the announcements a publisher sends in answer to
// probes. Zero fields select the defaults.
type DiscoveryOptions struct {
	// Disabled turns discovery off: no probes are sent or answered and no
	// cyclic announcements are sent.
	Disabled bool
	// MinInterval is the least time between two announcements of the same
	// kind and writer (default 500 ms, the minimum of Part 14
	// §7.2.4.6.12.2): probes for it in between are ignored.
	MinInterval time.Duration
	// Rate and Burst bound the announcements a connection sends in answer
	// to probes, all kinds and writers together (default 20 per second,
	// bursts of 20): probes cannot make a publisher flood the network.
	Rate  float64
	Burst int
	// MaxProbeInterval bounds the interval between the probes of a
	// subscriber, which doubles from 500 ms while the announcement is
	// missing (default 8 seconds).
	MaxProbeInterval time.Duration
	// Layout is the byte layout of the probes the subscriber sends: the
	// spec's (default) or that of the OPC Foundation .NET stack. Probes
	// are answered in the layout they came in.
	Layout message.DiscoveryLayout
	// Endpoints returns the server endpoints of the publisher for
	// PublisherEndpoints probes; without it they are answered with
	// Bad_NotSupported.
	Endpoints func() []*ua.EndpointDescription
	// Application returns the ApplicationDescription of the publisher, and
	// Capabilities are its capabilities, for FindApplications probes;
	// without it they are answered with the state of the runtime.
	Application  func() *ua.ApplicationDescription
	Capabilities []string
}

// WithDiscovery sets the options of the UADP discovery.
func WithDiscovery(o DiscoveryOptions) Option {
	return func(opts *options) { opts.discovery = o }
}
