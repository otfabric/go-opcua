// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// UDPUADP is the transport profile of UDP with UADP (Part 14 §7.3.2), the
// default for an opc.udp Address.
const UDPUADP = "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"

// links returns the CommunicationLinks of an endpoint configuration
// (§6.12.2), nil when it has none. Library interpretation: the field is a
// Structure (Table F.5) whose only defined subtype is
// PubSubCommunicationLinkConfigurationDataType; its encoding is recognised
// by its identifier, as the namespace index of its TypeId depends on who
// built the set.
func links(eo *ua.ExtensionObject) (*uafx.PubSubCommunicationLinkConfiguration, error) {
	if eo == nil || eo.EncodingMask == ua.ExtensionObjectEmpty {
		return nil, nil
	}
	if l, ok := eo.Value.(*uafx.PubSubCommunicationLinkConfiguration); ok {
		return l, nil
	}
	if eo.TypeID == nil || eo.TypeID.NodeID == nil || eo.TypeID.NodeID.IntID() != fxdataid.PubSubCommunicationLinkConfigurationDataTypeEncodingDefaultBinary {
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadNotSupported, "CommunicationLinks of a type other than PubSubCommunicationLinkConfigurationDataType")
	}
	cp := *eo
	cp.TypeID = ua.NewNumericExpandedNodeID(cloneNS.Data, fxdataid.PubSubCommunicationLinkConfigurationDataTypeEncodingDefaultBinary)
	s, err := uafx.DecodeStructure(&cp, cloneNS)
	if err != nil {
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadDecodingError, "CommunicationLinks: %v", err)
	}
	l, _ := s.(*uafx.PubSubCommunicationLinkConfiguration)
	return l, nil
}

// modeOf returns the PubSubConnectionEndpointMode of e (§10.41). Library
// interpretation: Part 81 gives the set no Mode field; an endpoint with an
// outbound and an inbound flow is PublisherSubscriber, with one of them
// Publisher or Subscriber (the flows are what Table 208 asks the DataSetWriter
// and DataSetReader references for); without flows its CommunicationLinks
// decide the same way.
func modeOf(e *endpoint, l *uafx.PubSubCommunicationLinkConfiguration) (uafx.PubSubConnectionEndpointMode, bool) {
	pub, sub := e.outbound != nil, e.inbound != nil
	if !pub && !sub && l != nil {
		pub = l.DataSetWriterRef != nil && l.DataSetWriterRef.ConfigurationMask != 0
		sub = l.DataSetReaderRef != nil && l.DataSetReaderRef.ConfigurationMask != 0
	}
	switch {
	case pub && sub:
		return uafx.PubSubPublisherSubscriber, true
	case pub:
		return uafx.PubSubPublisher, true
	case sub:
		return uafx.PubSubSubscriber, true
	}
	return 0, false
}

// relatedEndpoint returns the RelatedEndpoint of e (§10.42): the other
// endpoint of its Connection, its server's Address, the BrowsePath of its
// FunctionalEntity from FxRoot and its Name. Library interpretation: the
// path is the FunctionalEntityNode when it is a RelativePath, with the
// NamespaceUris of its ServerAddress; a FunctionalEntityNode given as a
// NodeId leaves the path empty. A Connection with one endpoint (an
// autonomous publisher or subscriber, §5.5.1) has no other end: the Address
// of the flow names the far side then, as a URL.
func relatedEndpoint(e *endpoint) *uafx.RelatedEndpoint {
	var other *endpoint
	for _, o := range e.conn.endpoints {
		if o != e {
			other = o
		}
	}
	if other == nil {
		r := &uafx.RelatedEndpoint{}
		var f *flow
		switch {
		case e.outbound != nil:
			f = e.outbound
		case e.inbound != nil:
			f = e.inbound.flow
		}
		if f != nil {
			if eo := address(f.conf.Address); eo != nil {
				if a, ok := eo.Value.(*ua.NetworkAddressURLDataType); ok && a != nil {
					r.Address = a.URL
				}
			}
		}
		return r
	}
	r := &uafx.RelatedEndpoint{ConnectionEndpointName: other.conf.Name}
	if other.ac != nil && other.ac.server != nil {
		r.Address = other.ac.server.conf.Address
		if bp := other.conf.FunctionalEntityNode.IdentifierBrowsePath; bp != nil {
			for _, el := range bp.Elements {
				uri, _ := other.ac.server.ns.uri(el.TargetName.NamespaceIndex)
				r.ConnectionEndpointPath = append(r.ConnectionEndpointPath, &ua.PortableQualifiedName{NamespaceURI: uri, Name: el.TargetName.Name})
			}
		}
	}
	return r
}

// commModel is the PubSub configuration of one AutomationComponent of a
// run (§6.16.3): the CommunicationModelConfig of its configuration with the
// NodeIds mapped to the server and the placeholders resolved.
type commModel struct {
	cfg  *ua.PubSubConfiguration2DataType
	refs []*ua.PubSubConfigurationRefDataType
}

// copyPubSub returns a deep copy of cfg.
func copyPubSub(cfg *ua.PubSubConfiguration2DataType) (*ua.PubSubConfiguration2DataType, error) {
	b, err := ua.Encode(cfg)
	if err != nil {
		return nil, err
	}
	out := new(ua.PubSubConfiguration2DataType)
	if _, err := ua.Decode(b, out); err != nil {
		return nil, err
	}
	return out, nil
}

// prepareComm returns the PubSub configuration of the AutomationComponent
// of a, nil when it has none (§6.16.3): the NamespaceIndexes are mapped
// from the Namespaces of its ServerAddress (F.1.2.2) to the server, and the
// NodeIds of the Translation namespace are resolved through the
// TranslationTable, a path from the AutomationComponent. SecurityGroups and
// PubSubKeyPushTargets go to an SKS (E.2.1): a configuration with them is
// not supported (decision D3).
func (x *run) prepareComm(ctx context.Context, a *acRun) (*commModel, error) {
	m, ok := a.ac.conf.CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration)
	if !ok || m == nil || m.PubSubConfiguration == nil {
		return nil, nil
	}
	if len(m.PubSubConfiguration.SecurityGroups) > 0 || len(m.PubSubConfiguration.PubSubKeyPushTargets) > 0 {
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadNotSupported, "the PubSubConfiguration of %s configures an SKS, which the ConnectionManager does not do", a.ac.conf.BrowseName)
	}
	cfg, err := copyPubSub(m.PubSubConfiguration)
	if err != nil {
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadEncodingError, "the PubSubConfiguration of %s: %v", a.ac.conf.BrowseName, err)
	}
	scope := a.ac.server.ns
	trURI := -1
	for i, u := range scope {
		if u == TranslationNamespace {
			trURI = i
		}
	}
	mapID := func(n *ua.NodeID) (*ua.NodeID, error) {
		if n == nil {
			return nil, nil
		}
		if trURI > 0 && int(n.Namespace()) == trURI {
			for _, t := range m.TranslationTable {
				if t != nil && t.NodePlaceholder != nil && t.NodePlaceholder.Equal(n) {
					return a.t.resolvePortable(ctx, t.PortableNode, a.node)
				}
			}
			return nil, failure(uafx.FxErrorResolvingPathsError, ua.StatusBadNoMatch, "the placeholder %v is not in the TranslationTable", n)
		}
		return a.t.mapNodeID(n, scope)
	}
	if err := walkPubSubNodeIDs(cfg, mapID); err != nil {
		return nil, err
	}
	return &commModel{cfg: cfg, refs: m.ConfigurationReferences}, nil
}

// walkPubSubNodeIDs replaces the NodeIds of the variables of cfg with
// what f returns: the PublishedVariables of PublishedDataItems and the
// TargetNodeIds of TargetVariables, in DataSetReaders and
// StandaloneSubscribedDataSets. A DataSetSource or SubscribedDataSet of
// another kind (events, mirrors) is not supported.
func walkPubSubNodeIDs(cfg *ua.PubSubConfiguration2DataType, f func(*ua.NodeID) (*ua.NodeID, error)) error {
	for _, p := range cfg.PublishedDataSets {
		if p == nil || p.DataSetSource == nil || p.DataSetSource.EncodingMask == ua.ExtensionObjectEmpty {
			continue
		}
		items, ok := p.DataSetSource.Value.(*ua.PublishedDataItemsDataType)
		if !ok {
			return failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadNotSupported, "the PublishedDataSet %q has a DataSetSource of %T", p.Name, p.DataSetSource.Value)
		}
		for _, v := range items.PublishedData {
			if v == nil {
				continue
			}
			n, err := f(v.PublishedVariable)
			if err != nil {
				return err
			}
			v.PublishedVariable = n
		}
	}
	subscribed := func(name string, eo *ua.ExtensionObject) error {
		if eo == nil || eo.EncodingMask == ua.ExtensionObjectEmpty {
			return nil
		}
		tv, ok := eo.Value.(*ua.TargetVariablesDataType)
		if !ok {
			return failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadNotSupported, "%q has a SubscribedDataSet of %T", name, eo.Value)
		}
		for _, t := range tv.TargetVariables {
			if t == nil {
				continue
			}
			n, err := f(t.TargetNodeID)
			if err != nil {
				return err
			}
			t.TargetNodeID = n
		}
		return nil
	}
	for _, c := range cfg.Connections {
		if c == nil {
			continue
		}
		for _, g := range c.ReaderGroups {
			if g == nil {
				continue
			}
			for _, rd := range g.DataSetReaders {
				if rd == nil {
					continue
				}
				if err := subscribed(rd.Name, rd.SubscribedDataSet); err != nil {
					return err
				}
			}
		}
	}
	for _, s := range cfg.SubscribedDataSets {
		if s == nil {
			continue
		}
		if err := subscribed(s.Name, s.SubscribedDataSet); err != nil {
			return err
		}
	}
	return nil
}

// isNullID reports whether v, a PublisherId, is null (§6.16.3: the AC
// assigns one).
func isNullID(v *ua.Variant) bool {
	if v == nil || v.Value() == nil {
		return true
	}
	switch x := v.Value().(type) {
	case string:
		return x == ""
	case uint8:
		return x == 0
	case uint16:
		return x == 0
	case uint32:
		return x == 0
	case uint64:
		return x == 0
	}
	return false
}

// reserveNeed returns the WriterGroupIds and DataSetWriterIds the
// configuration leaves 0 (§6.16.3: null identifiers are assigned by the AC
// or reserved), and the transport profile of the first connection that
// publishes.
func (cm *commModel) reserveNeed() (groups, writers uint16, profile string) {
	for _, c := range cm.cfg.Connections {
		if c == nil {
			continue
		}
		for _, g := range c.WriterGroups {
			if g == nil {
				continue
			}
			if profile == "" {
				profile = c.TransportProfileURI
			}
			if g.WriterGroupID == 0 {
				groups++
			}
			for _, w := range g.DataSetWriters {
				if w != nil && w.DataSetWriterID == 0 {
					writers++
				}
			}
		}
	}
	return groups, writers, profile
}

// fillReserved sets the 0 WriterGroupIds and DataSetWriterIds of the
// configuration to the reserved ones, in order (E.2.2.1 step 3).
func (cm *commModel) fillReserved(res *uafx.PubSubReserveCommunicationIDsResult) error {
	gi, wi := 0, 0
	for _, c := range cm.cfg.Connections {
		if c == nil {
			continue
		}
		for _, g := range c.WriterGroups {
			if g == nil {
				continue
			}
			if g.WriterGroupID == 0 {
				if gi >= len(res.WriterGroupIDs) {
					return failure(uafx.FxErrorReserveCommunicationIDsError, ua.StatusBadUnexpectedError, "%d WriterGroupIds reserved", len(res.WriterGroupIDs))
				}
				g.WriterGroupID = res.WriterGroupIDs[gi]
				gi++
			}
			for _, w := range g.DataSetWriters {
				if w == nil || w.DataSetWriterID != 0 {
					continue
				}
				if wi >= len(res.DataSetWriterIDs) {
					return failure(uafx.FxErrorReserveCommunicationIDsError, ua.StatusBadUnexpectedError, "%d DataSetWriterIds reserved", len(res.DataSetWriterIDs))
				}
				w.DataSetWriterID = res.DataSetWriterIDs[wi]
				wi++
			}
		}
	}
	return nil
}

// writerAt and readerAt return the elements a reference names, nil for
// none.
func writerAt(cfg *ua.PubSubConfiguration2DataType, r *ua.PubSubConfigurationRefDataType) (*ua.PubSubConnectionDataType, *ua.WriterGroupDataType, *ua.DataSetWriterDataType) {
	if r == nil || int(r.ConnectionIndex) >= len(cfg.Connections) || cfg.Connections[r.ConnectionIndex] == nil {
		return nil, nil, nil
	}
	c := cfg.Connections[r.ConnectionIndex]
	if int(r.GroupIndex) >= len(c.WriterGroups) || c.WriterGroups[r.GroupIndex] == nil || int(r.ElementIndex) >= len(c.WriterGroups[r.GroupIndex].DataSetWriters) {
		return nil, nil, nil
	}
	g := c.WriterGroups[r.GroupIndex]
	return c, g, g.DataSetWriters[r.ElementIndex]
}

func readerAt(cfg *ua.PubSubConfiguration2DataType, r *ua.PubSubConfigurationRefDataType) *ua.DataSetReaderDataType {
	if r == nil || int(r.ConnectionIndex) >= len(cfg.Connections) || cfg.Connections[r.ConnectionIndex] == nil {
		return nil
	}
	c := cfg.Connections[r.ConnectionIndex]
	if int(r.GroupIndex) >= len(c.ReaderGroups) || c.ReaderGroups[r.GroupIndex] == nil || int(r.ElementIndex) >= len(c.ReaderGroups[r.GroupIndex].DataSetReaders) {
		return nil
	}
	return c.ReaderGroups[r.GroupIndex].DataSetReaders[r.ElementIndex]
}

// publisherIDOf returns the PublisherId a subscriber of the writer of r
// on a expects (§6.16.3): the PublisherId of its PubSubConnection, the
// DefaultPublisherId the reservation returned when that is null.
func (a *acRun) publisherIDOf(conn *ua.PubSubConnectionDataType) *ua.Variant {
	if !isNullID(conn.PublisherID) {
		return conn.PublisherID
	}
	return a.defaultPublisherID
}

// linkFlows fills the DataSetReaders of the subscribers of each flow with
// the PublisherId, WriterGroupId and DataSetWriterId of its publisher
// (E.2.2: the subscriber side is configured with the publisher's ids). A
// reader whose ids are set already keeps them. Library interpretation: the
// publisher and subscribers of a flow are the endpoints that reference it
// (ToOutboundFlow, ToInboundFlow, §6.13.3), their DataSetWriter and
// DataSetReader those of their CommunicationLinks.
func (x *run) linkFlows() {
	type pub struct {
		a    *acRun
		conn *ua.PubSubConnectionDataType
		g    *ua.WriterGroupDataType
		w    *ua.DataSetWriterDataType
	}
	pubs := map[*flow]pub{}
	for _, ep := range x.eps {
		if ep.failed() || ep.e.outbound == nil || ep.links == nil || ep.a.comm == nil {
			continue
		}
		if c, g, w := writerAt(ep.a.comm.cfg, ep.links.DataSetWriterRef); w != nil {
			pubs[ep.e.outbound] = pub{ep.a, c, g, w}
		}
	}
	for _, ep := range x.eps {
		if ep.failed() || ep.e.inbound == nil || ep.links == nil || ep.a.comm == nil {
			continue
		}
		p, ok := pubs[ep.e.inbound.flow]
		if !ok {
			continue
		}
		rd := readerAt(ep.a.comm.cfg, ep.links.DataSetReaderRef)
		if rd == nil {
			continue
		}
		if isNullID(rd.PublisherID) {
			rd.PublisherID = p.a.publisherIDOf(p.conn)
			ep.assumedPublisher = &assumed{a: p.a, conn: p.conn, id: rd.PublisherID}
		}
		if rd.WriterGroupID == 0 {
			rd.WriterGroupID = p.g.WriterGroupID
		}
		if rd.DataSetWriterID == 0 {
			rd.DataSetWriterID = p.w.DataSetWriterID
		}
	}
}

// assumed is the PublisherId a subscriber was configured with before its
// publisher's call returned the one its PubSubConnection has.
type assumed struct {
	a    *acRun
	conn *ua.PubSubConnectionDataType
	id   *ua.Variant
}

// parameter returns the ConnectionEndpointParameter of an endpoint
// (§6.2.4.3.5, Table 79): the parameters of its configuration, the Mode of
// its flows, the RelatedEndpoint of its Connection.
func (ep *epRun) parameter() (*uafx.PubSubConnectionEndpointParameter, error) {
	mode, ok := modeOf(ep.e, ep.links)
	if !ok {
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError, "the endpoint %s has no flow and no CommunicationLinks: its Mode is unknown", ep.e.conf.Name)
	}
	typ, err := ep.a.t.mapNodeID(ep.e.conf.ConnectionEndpointTypeID, ep.a.ac.server.ns)
	if err != nil {
		return nil, err
	}
	return &uafx.PubSubConnectionEndpointParameter{
		Name:                     ep.e.conf.Name,
		ConnectionEndpointTypeID: typ,
		InputVariableIDs:         ep.inputs,
		OutputVariableIDs:        ep.outputs,
		IsPersistent:             ep.e.conf.IsPersistent,
		CleanupTimeout:           ep.e.conf.CleanupTimeout,
		RelatedEndpoint:          relatedEndpoint(ep.e),
		IsPreconfigured:          ep.e.conf.IsPreconfigured,
		Mode:                     mode,
	}, nil
}
