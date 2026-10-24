// SPDX-License-Identifier: MIT

package pubsub

import (
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

// The helpers of this file build the standard configuration structures for
// the common setups. They return plain ua structures that can be adjusted
// before they are passed to [New] or to the Add methods. Components are
// created enabled.

// MessageMapping selects the UADP or the JSON message mapping.
type MessageMapping uint8

// Message mappings.
const (
	MappingUADP MessageMapping = iota
	MappingJSON
)

// NewConfiguration returns an enabled configuration with the published data
// sets and connections.
func NewConfiguration(pds []*ua.PublishedDataSetDataType, conns ...*ua.PubSubConnectionDataType) *ua.PubSubConfigurationDataType {
	return &ua.PubSubConfigurationDataType{Enabled: true, PublishedDataSets: pds, Connections: conns}
}

func mustPublisherID(v any) *ua.Variant {
	pv, err := PublisherIDVariant(v)
	if err != nil {
		panic(err)
	}
	return pv
}

// AttachWriterGroups appends writer groups to a connection.
func AttachWriterGroups(c *ua.PubSubConnectionDataType, groups ...*ua.WriterGroupDataType) *ua.PubSubConnectionDataType {
	c.WriterGroups = append(c.WriterGroups, groups...)
	return c
}

// AttachReaderGroups appends reader groups to a connection.
func AttachReaderGroups(c *ua.PubSubConnectionDataType, groups ...*ua.ReaderGroupDataType) *ua.PubSubConnectionDataType {
	c.ReaderGroups = append(c.ReaderGroups, groups...)
	return c
}

// UDPConnection returns a connection with the UDP UADP transport profile.
// url is opc.udp://host:port (a multicast group address joins the group);
// publisherID is a byte, uint16, uint32, uint64, string or a non-negative
// int, or nil for a connection that only subscribes. It panics on a
// PublisherId of another type.
func UDPConnection(name, url string, publisherID any) *ua.PubSubConnectionDataType {
	return &ua.PubSubConnectionDataType{
		Name:                name,
		Enabled:             true,
		PublisherID:         mustPublisherID(publisherID),
		TransportProfileURI: transport.ProfileUDPUADP,
		Address:             ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: url}),
	}
}

// EthernetConnection returns a connection with the Ethernet UADP transport
// profile (Part 14 §7.3.3): url is opc.eth://<MAC>[:<VID>[.<PCP>]] (a
// multicast MAC address joins the group, a VID adds an IEEE 802.1Q tag),
// iface the network interface the frames are sent and received on.
// publisherID is as for [UDPConnection].
func EthernetConnection(name, url, iface string, publisherID any) *ua.PubSubConnectionDataType {
	return &ua.PubSubConnectionDataType{
		Name:                name,
		Enabled:             true,
		PublisherID:         mustPublisherID(publisherID),
		TransportProfileURI: transport.ProfileEthUADP,
		Address:             ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: url, NetworkInterface: iface}),
	}
}

// MQTTConnection returns a connection to an MQTT broker (mqtt://host:port or
// mqtts://host:port) with the MQTT UADP or MQTT JSON transport profile.
func MQTTConnection(name, url string, publisherID any, mapping MessageMapping) *ua.PubSubConnectionDataType {
	profile := transport.ProfileMQTTUADP
	if mapping == MappingJSON {
		profile = transport.ProfileMQTTJSON
	}
	return &ua.PubSubConnectionDataType{
		Name:                name,
		Enabled:             true,
		PublisherID:         mustPublisherID(publisherID),
		TransportProfileURI: profile,
		Address:             ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: url}),
	}
}

func millis(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// WriterGroup returns a UADP writer group that publishes every interval with
// the default NetworkMessage content mask
// ([DefaultUADPNetworkMessageContentMask]).
func WriterGroup(name string, writerGroupID uint16, interval time.Duration, writers ...*ua.DataSetWriterDataType) *ua.WriterGroupDataType {
	return &ua.WriterGroupDataType{
		Name:               name,
		Enabled:            true,
		WriterGroupID:      writerGroupID,
		PublishingInterval: millis(interval),
		SecurityMode:       ua.MessageSecurityModeNone,
		MessageSettings: ua.NewExtensionObject(&ua.UADPWriterGroupMessageDataType{
			NetworkMessageContentMask: DefaultUADPNetworkMessageContentMask,
		}),
		DataSetWriters: writers,
	}
}

// JSONWriterGroup returns a JSON writer group for a broker connection that
// publishes every interval to queue.
func JSONWriterGroup(name string, writerGroupID uint16, interval time.Duration, queue string, writers ...*ua.DataSetWriterDataType) *ua.WriterGroupDataType {
	return &ua.WriterGroupDataType{
		Name:               name,
		Enabled:            true,
		WriterGroupID:      writerGroupID,
		PublishingInterval: millis(interval),
		SecurityMode:       ua.MessageSecurityModeNone,
		MessageSettings: ua.NewExtensionObject(&ua.JSONWriterGroupMessageDataType{
			NetworkMessageContentMask: DefaultJSONNetworkMessageContentMask,
		}),
		TransportSettings: ua.NewExtensionObject(&ua.BrokerWriterGroupTransportDataType{
			QueueName:                  queue,
			RequestedDeliveryGuarantee: ua.BrokerTransportQoSAtLeastOnce,
		}),
		DataSetWriters: writers,
	}
}

// Secure sets the message security of a writer or reader group:
// SecurityMode Sign or SignAndEncrypt with the keys of a SecurityGroup.
func Secure[T *ua.WriterGroupDataType | *ua.ReaderGroupDataType](g T, mode ua.MessageSecurityMode, securityGroupID string) T {
	switch x := any(g).(type) {
	case *ua.WriterGroupDataType:
		x.SecurityMode, x.SecurityGroupID = mode, securityGroupID
	case *ua.ReaderGroupDataType:
		x.SecurityMode, x.SecurityGroupID = mode, securityGroupID
	}
	return g
}

// DataSetWriter returns a writer of the published data set dataSetName that
// sends a key frame every message, with the fields Variant encoded. Set
// KeyFrameCount for delta frames and DataSetFieldContentMask for the
// DataValue or RawData encodings. The message settings default to those of
// the group's mapping.
func DataSetWriter(name string, dataSetWriterID uint16, dataSetName string) *ua.DataSetWriterDataType {
	return &ua.DataSetWriterDataType{
		Name:            name,
		Enabled:         true,
		DataSetWriterID: dataSetWriterID,
		DataSetName:     dataSetName,
		KeyFrameCount:   1,
	}
}

// SetWriterQueue gives a writer on a broker connection its own queue and,
// if metaDataQueue is not empty, a queue on which its DataSetMetaData is
// announced (retained).
func SetWriterQueue(w *ua.DataSetWriterDataType, queue, metaDataQueue string) *ua.DataSetWriterDataType {
	w.TransportSettings = ua.NewExtensionObject(&ua.BrokerDataSetWriterTransportDataType{
		QueueName:                  queue,
		MetaDataQueueName:          metaDataQueue,
		RequestedDeliveryGuarantee: ua.BrokerTransportQoSAtLeastOnce,
	})
	return w
}

// Field describes a field of a DataSet.
type Field struct {
	Name string
	// Type is the built-in type of the field; 0 means BaseDataType (any).
	Type ua.TypeID
	// Array makes the field a one-dimensional array.
	Array bool
}

func (f Field) metaData() *ua.FieldMetaData {
	fm := &ua.FieldMetaData{Name: f.Name, ValueRank: -1, Description: &ua.LocalizedText{}}
	if f.Array {
		fm.ValueRank = 1
	}
	if f.Type == 0 {
		fm.BuiltInType = uint8(ua.TypeIDVariant)
		fm.DataType = ua.NewNumericNodeID(0, 24)
	} else {
		fm.BuiltInType = uint8(f.Type)
		fm.DataType = ua.NewNumericNodeID(0, uint32(f.Type))
	}
	return fm
}

// PublishedField is a published variable.
type PublishedField struct {
	Field
	// NodeID is the published variable; its Value attribute is published.
	NodeID *ua.NodeID
	// IndexRange publishes a part of an array value.
	IndexRange string
	// Substitute, if not nil, is published with the status
	// Uncertain_SubstituteValue when the value is Bad.
	Substitute any
}

// Var returns a PublishedField.
func Var(name string, nodeID *ua.NodeID, typ ua.TypeID) PublishedField {
	return PublishedField{Field: Field{Name: name, Type: typ}, NodeID: nodeID}
}

// MetaData returns DataSetMetaData with the given fields.
func MetaData(name string, fields ...Field) *ua.DataSetMetaDataType {
	md := &ua.DataSetMetaDataType{Name: name, Description: &ua.LocalizedText{}, DataSetClassID: &ua.GUID{}}
	for _, f := range fields {
		md.Fields = append(md.Fields, f.metaData())
	}
	return md
}

// PublishedDataItems returns a PublishedDataSet of variables with its
// DataSetMetaData. The ConfigurationVersion is set by the runtime.
func PublishedDataItems(name string, fields ...PublishedField) *ua.PublishedDataSetDataType {
	items := &ua.PublishedDataItemsDataType{}
	md := MetaData(name)
	for _, f := range fields {
		v := &ua.PublishedVariableDataType{
			PublishedVariable: f.NodeID,
			AttributeID:       ua.AttributeIDValue,
			IndexRange:        f.IndexRange,
		}
		if f.Substitute != nil {
			sv, err := ua.NewVariant(f.Substitute)
			if err != nil {
				panic(fmt.Errorf("pubsub: substitute value of %q: %w", f.Name, err))
			}
			v.SubstituteValue = sv
		}
		items.PublishedData = append(items.PublishedData, v)
		md.Fields = append(md.Fields, f.metaData())
	}
	return &ua.PublishedDataSetDataType{
		Name:            name,
		DataSetMetaData: md,
		DataSetSource:   ua.NewExtensionObject(items),
	}
}

// DataSetMetaDataOf returns the DataSetMetaData of a published data set
// built with [PublishedDataItems], for the readers of its writers.
func DataSetMetaDataOf(pds *ua.PublishedDataSetDataType) *ua.DataSetMetaDataType {
	md, _ := clone(pds.DataSetMetaData)
	return md
}

// ReaderGroup returns a reader group.
func ReaderGroup(name string, readers ...*ua.DataSetReaderDataType) *ua.ReaderGroupDataType {
	return &ua.ReaderGroupDataType{
		Name:           name,
		Enabled:        true,
		SecurityMode:   ua.MessageSecurityModeNone,
		DataSetReaders: readers,
	}
}

// DataSetReader returns a reader of the messages of one DataSetWriter of a
// publisher. A nil publisherID or a zero writerGroupID or dataSetWriterID
// does not filter. md describes the fields; without it the reader uses the
// DataSetMetaData it receives (broker transports) or the field positions.
func DataSetReader(name string, publisherID any, writerGroupID, dataSetWriterID uint16, md *ua.DataSetMetaDataType) *ua.DataSetReaderDataType {
	return &ua.DataSetReaderDataType{
		Name:            name,
		Enabled:         true,
		PublisherID:     mustPublisherID(publisherID),
		WriterGroupID:   writerGroupID,
		DataSetWriterID: dataSetWriterID,
		DataSetMetaData: md,
		SecurityMode:    ua.MessageSecurityModeNone,
	}
}

// SetReaderQueue sets the broker queue of a reader and, if metaDataQueue is
// not empty, the queue its DataSetMetaData is announced on.
func SetReaderQueue(r *ua.DataSetReaderDataType, queue, metaDataQueue string) *ua.DataSetReaderDataType {
	r.TransportSettings = ua.NewExtensionObject(&ua.BrokerDataSetReaderTransportDataType{
		QueueName:                  queue,
		MetaDataQueueName:          metaDataQueue,
		RequestedDeliveryGuarantee: ua.BrokerTransportQoSAtLeastOnce,
	})
	return r
}

// Target returns a target variable: the Value attribute of nodeID.
func Target(nodeID *ua.NodeID) *ua.FieldTargetDataType {
	return &ua.FieldTargetDataType{TargetNodeID: nodeID, AttributeID: ua.AttributeIDValue}
}

// SetTargetVariables makes a reader write the fields of the DataSet to
// target variables: the i-th target takes the i-th field (or the field with
// its DataSetFieldId).
func SetTargetVariables(r *ua.DataSetReaderDataType, targets ...*ua.FieldTargetDataType) *ua.DataSetReaderDataType {
	r.SubscribedDataSet = ua.NewExtensionObject(&ua.TargetVariablesDataType{TargetVariables: targets})
	return r
}

// SetMirror makes a reader mirror the DataSet in the address space below an
// object named parentNodeName.
func SetMirror(r *ua.DataSetReaderDataType, parentNodeName string) *ua.DataSetReaderDataType {
	r.SubscribedDataSet = ua.NewExtensionObject(&ua.SubscribedDataSetMirrorDataType{ParentNodeName: parentNodeName})
	return r
}
