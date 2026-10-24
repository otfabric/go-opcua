// SPDX-License-Identifier: MIT

package pubsub

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// ComponentID identifies a component of a PubSub runtime: a connection, a
// group, a writer, a reader or a published data set. Ids are never reused
// within a runtime. [Root] is the runtime itself.
type ComponentID uint32

// Root is the id of the runtime itself (the PublishSubscribe object) for
// [PubSub.Enable], [PubSub.Disable], [PubSub.State] and [PubSub.Status].
const Root ComponentID = 0

// ComponentKind is the kind of a component.
type ComponentKind uint8

// Component kinds.
const (
	KindPubSub ComponentKind = iota
	KindConnection
	KindWriterGroup
	KindReaderGroup
	KindDataSetWriter
	KindDataSetReader
	KindPublishedDataSet
)

func (k ComponentKind) String() string {
	switch k {
	case KindPubSub:
		return "PubSub"
	case KindConnection:
		return "Connection"
	case KindWriterGroup:
		return "WriterGroup"
	case KindReaderGroup:
		return "ReaderGroup"
	case KindDataSetWriter:
		return "DataSetWriter"
	case KindDataSetReader:
		return "DataSetReader"
	case KindPublishedDataSet:
		return "PublishedDataSet"
	}
	return "ComponentKind(" + strconv.Itoa(int(k)) + ")"
}

// ComponentInfo describes a component.
type ComponentInfo struct {
	ID   ComponentID
	Kind ComponentKind
	Name string
	// Parent is the id of the containing component: Root for connections
	// and published data sets, the connection for groups, the group for
	// writers and readers.
	Parent  ComponentID
	Enabled bool
	// State is the state of the component. Published data sets have no
	// state machine and report Operational.
	State ua.PubSubState
}

// EventType is the type of an [Event].
type EventType uint8

// Event types.
const (
	// EventAdded reports a component that was added.
	EventAdded EventType = iota
	// EventRemoved reports a component that was removed.
	EventRemoved
	// EventStateChanged reports a state transition.
	EventStateChanged
)

func (t EventType) String() string {
	switch t {
	case EventAdded:
		return "Added"
	case EventRemoved:
		return "Removed"
	case EventStateChanged:
		return "StateChanged"
	}
	return "EventType(" + strconv.Itoa(int(t)) + ")"
}

// Event reports a change of the runtime: a component that was added or
// removed, or a state transition. Events are delivered in order to the
// handlers given with [WithEventHandler], outside the runtime's lock.
type Event struct {
	Type      EventType
	Component ComponentInfo
	// OldState is the previous state of a state change.
	OldState ua.PubSubState
	// Err is the reason of a transition to Error, if known.
	Err error
}

// Counters are the diagnostic counters of a component. The counters of a
// group include those of its writers or readers, the counters of a
// connection those of its groups.
type Counters struct {
	// NetworkMessagesSent and NetworkMessagesReceived count NetworkMessages,
	// BytesSent and BytesReceived their encoded size.
	NetworkMessagesSent     uint64
	NetworkMessagesReceived uint64
	BytesSent               uint64
	BytesReceived           uint64
	// DataSetMessagesSent and DataSetMessagesReceived count DataSetMessages
	// with data (key frames, delta frames, events); keep-alive messages are
	// counted separately.
	DataSetMessagesSent     uint64
	DataSetMessagesReceived uint64
	KeepAlivesSent          uint64
	KeepAlivesReceived      uint64
	// MetaDataSent and MetaDataReceived count DataSetMetaData messages.
	MetaDataSent     uint64
	MetaDataReceived uint64
	// EncodeErrors, SendErrors and DecodeErrors count failures of the codecs
	// and the transport.
	EncodeErrors uint64
	SendErrors   uint64
	DecodeErrors uint64
	// SequenceDiscards counts DataSetMessages discarded as duplicates or as
	// older than the last one received; SequenceResyncs counts jumps of the
	// sequence number that resynchronised the reader.
	SequenceDiscards uint64
	SequenceResyncs  uint64
	// VersionMismatches counts DataSetMessages discarded because their
	// MetaData version does not match the reader's.
	VersionMismatches uint64
	// Timeouts counts MessageReceiveTimeouts of readers.
	Timeouts uint64
	// TargetWriteErrors counts failed writes to target variables.
	TargetWriteErrors uint64
	// StateChanges counts state transitions.
	StateChanges uint64
	// Panics counts panics the runtime recovered from: in an application
	// callback (DataSetHandler, DataSource, TargetWriter, event handler) or
	// while decoding a received message. They are logged with their stack.
	Panics uint64

	// ChunksSent and ChunksReceived count UADP chunk NetworkMessages
	// (Part 14 §7.2.4.4.4); they are NetworkMessages as well.
	// ChunkedMessagesReceived counts the messages reassembled from them.
	// ChunksDiscarded counts received chunks the reassembly rejected
	// (outside their message, duplicate or overlapping, beyond the memory
	// limits) or dropped with an incomplete message (timeout, eviction).
	ChunksSent              uint64
	ChunksReceived          uint64
	ChunkedMessagesReceived uint64
	ChunksDiscarded         uint64
	// DiscoveryRequestsSent and DiscoveryRequestsReceived count UADP
	// discovery probes (Part 14 §7.2.4.6.12); DiscoveryRequestsIgnored
	// counts received probes that were not answered: not for this
	// publisher, duplicates, or beyond the rate limit.
	// DiscoveryResponsesSent counts the announcements sent in answer to
	// probes or cyclically, DiscoveryResponsesReceived the announcements
	// received.
	DiscoveryRequestsSent      uint64
	DiscoveryRequestsReceived  uint64
	DiscoveryRequestsIgnored   uint64
	DiscoveryResponsesSent     uint64
	DiscoveryResponsesReceived uint64
}

func (c *Counters) add(o *Counters) {
	c.NetworkMessagesSent += o.NetworkMessagesSent
	c.NetworkMessagesReceived += o.NetworkMessagesReceived
	c.BytesSent += o.BytesSent
	c.BytesReceived += o.BytesReceived
	c.DataSetMessagesSent += o.DataSetMessagesSent
	c.DataSetMessagesReceived += o.DataSetMessagesReceived
	c.KeepAlivesSent += o.KeepAlivesSent
	c.KeepAlivesReceived += o.KeepAlivesReceived
	c.MetaDataSent += o.MetaDataSent
	c.MetaDataReceived += o.MetaDataReceived
	c.EncodeErrors += o.EncodeErrors
	c.SendErrors += o.SendErrors
	c.DecodeErrors += o.DecodeErrors
	c.SequenceDiscards += o.SequenceDiscards
	c.SequenceResyncs += o.SequenceResyncs
	c.VersionMismatches += o.VersionMismatches
	c.Timeouts += o.Timeouts
	c.TargetWriteErrors += o.TargetWriteErrors
	c.StateChanges += o.StateChanges
	c.Panics += o.Panics
	c.ChunksSent += o.ChunksSent
	c.ChunksReceived += o.ChunksReceived
	c.ChunkedMessagesReceived += o.ChunkedMessagesReceived
	c.ChunksDiscarded += o.ChunksDiscarded
	c.DiscoveryRequestsSent += o.DiscoveryRequestsSent
	c.DiscoveryRequestsReceived += o.DiscoveryRequestsReceived
	c.DiscoveryRequestsIgnored += o.DiscoveryRequestsIgnored
	c.DiscoveryResponsesSent += o.DiscoveryResponsesSent
	c.DiscoveryResponsesReceived += o.DiscoveryResponsesReceived
}

// Status is the state and the diagnostics of a component.
type Status struct {
	ComponentInfo
	// LastError is the last error of the component (the reason of the
	// Error state, or the last send or decode failure), nil if none.
	LastError error
	// Counters of the component and, aggregated, of its children.
	Counters Counters
}

// ReceivedField is one field of a received DataSet.
type ReceivedField struct {
	// Index is the position of the field in the DataSetMetaData.
	Index int
	// Name is the field name from the DataSetMetaData (or the message).
	Name string
	// Value is the last value received for the field; nil if no value was
	// received yet (delta frames before the first key frame).
	Value *ua.DataValue
}

// ReceivedDataSet is a DataSet received by a DataSetReader, given to the
// [DataSetHandler].
type ReceivedDataSet struct {
	// Reader is the id of the DataSetReader, ReaderName its name.
	Reader     ComponentID
	ReaderName string

	PublisherID     message.PublisherID
	WriterGroupID   uint16
	DataSetWriterID uint16
	// SequenceNumber of the DataSetMessage (0 if the message had none).
	SequenceNumber uint32
	// Timestamp of the DataSetMessage, or of the NetworkMessage if the
	// DataSetMessage had none, or the reception time.
	Timestamp time.Time
	// Status of the DataSetMessage.
	Status ua.StatusCode
	// MessageType is KeyFrame, DeltaFrame or Event.
	MessageType message.DataSetMessageType
	// MetaDataVersion is the ConfigurationVersion of the DataSetMetaData
	// the message was decoded with.
	MetaDataVersion ua.ConfigurationVersionDataType

	// Fields are all fields of the DataSet in DataSetMetaData order. A
	// delta frame is merged onto the last key frame, so Fields always holds
	// the latest value of every field. Events carry their own fields.
	Fields []ReceivedField
	// Changed are the indexes of the fields this message carried.
	Changed []int
	// Complete reports whether every field has a value: a key frame (or an
	// event) was received.
	Complete bool
}

// Field returns the value of the field with the given name, or nil.
func (d *ReceivedDataSet) Field(name string) *ua.DataValue {
	for i := range d.Fields {
		if d.Fields[i].Name == name {
			return d.Fields[i].Value
		}
	}
	return nil
}

// ErrClosed is returned by operations on a closed runtime.
var ErrClosed = errors.New("pubsub: runtime closed")

// ConfigError reports an invalid configuration. It wraps
// ua.StatusBadConfigurationError, so errors.Is(err,
// ua.StatusBadConfigurationError) holds for it.
type ConfigError struct {
	// Path locates the offending setting, for example
	// `connection "c1": writer group "wg1": PublishingInterval`.
	Path string
	Msg  string
}

func (e *ConfigError) Error() string {
	if e.Path == "" {
		return "pubsub: " + e.Msg
	}
	return "pubsub: " + e.Path + ": " + e.Msg
}

// Unwrap returns ua.StatusBadConfigurationError.
func (e *ConfigError) Unwrap() error { return ua.StatusBadConfigurationError }

func configErr(path, format string, args ...any) error {
	return &ConfigError{Path: path, Msg: fmt.Sprintf(format, args...)}
}

func notFound(kind ComponentKind, id ComponentID) error {
	return fmt.Errorf("pubsub: no %s with id %d: %w", kind, id, ua.StatusBadNotFound)
}

// StatusCodeOf maps an error of this package to the StatusCode a server
// returns for it: the wrapped ua.StatusCode, or Bad_InternalError.
func StatusCodeOf(err error) ua.StatusCode {
	if err == nil {
		return ua.StatusGood
	}
	var sc ua.StatusCode
	if errors.As(err, &sc) {
		return sc
	}
	if errors.Is(err, ErrClosed) {
		return ua.StatusBadInvalidState
	}
	return ua.StatusBadInternalError
}
