// SPDX-License-Identifier: MIT

// Package pubsub is the OPC UA PubSub runtime (Part 14): publishers that
// sample PublishedDataSets and send them as NetworkMessages, and subscribers
// that receive NetworkMessages and hand the DataSets to the application or
// write them to target variables.
//
// # Configuration
//
// The configuration is the standard PubSub configuration model of Part 14
// §6.2, as generated in package ua: a [ua.PubSubConfigurationDataType] holds
// the PublishedDataSets and the PubSubConnections, a connection holds
// WriterGroups and ReaderGroups, and those hold the DataSetWriters and
// DataSetReaders. Message and transport settings are the ExtensionObjects of
// the standard (UADPWriterGroupMessageDataType, BrokerWriterGroupTransportDataType,
// ...). The helpers of this package ([UDPConnection], [WriterGroup],
// [PublishedDataItems], [DataSetReader], ...) fill those structures for the
// common cases; [Validate] checks a configuration and reports what is wrong.
//
// DataSets are dynamic: the fields of a DataSet, their names and types, come
// from its DataSetMetaData and are versioned with its ConfigurationVersion.
//
// # Runtime
//
// [New] creates a runtime for a configuration and [PubSub.Start] starts it.
// Every connection, group, writer, reader and published data set is a
// component with an id ([ComponentID]) and, except the published data sets,
// a state machine (Part 14 §6.2.1): Disabled, Paused, PreOperational,
// Operational and Error. A component that is enabled runs when its parent is
// Operational and is Paused otherwise. Components can be added, removed,
// enabled and disabled while the runtime runs.
//
// Publishers read the values of PublishedDataItems through a [DataSource]
// and the events of PublishedEvents through an [EventSource]. Subscribers
// deliver every received DataSet to a [DataSetHandler] and write the fields
// of DataSetReaders with TargetVariables through a [TargetWriter]. The
// OPC UA server (package server, option WithPubSub) provides all three on
// its address space.
//
// # Message mappings, transports and security
//
// NetworkMessages are encoded with the UADP mapping (package
// [github.com/otfabric/go-opcua/pubsub/uadp]) or the JSON mapping (package
// [github.com/otfabric/go-opcua/pubsub/jsonmsg]), as selected by the message
// settings of the group, and sent over the transport registered for the
// scheme of the connection address (package
// [github.com/otfabric/go-opcua/pubsub/transport]). Secured groups get the
// keys of their SecurityGroup from a [security.KeySource] given with
// [WithKeySource] or [WithKeySourceLookup].
//
// # Actions
//
// PubSub Actions (Part 14 §6.2.11.2 in 1.05) call Action targets over
// PubSub. A Responder is a DataSetWriter of a PublishedAction
// ([PublishedActions]) whose targets run the [ActionHandler]s registered
// with [WithActionHandler] or [PubSub.SetActionHandler]; a Requestor calls
// them with [PubSub.CallAction]. Both work over UDP and over MQTT and AMQP
// brokers, with the UADP (secured or not) and JSON mappings; [ActionOptions]
// bound what a Responder accepts.
package pubsub
