// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"fmt"
	"math"
	"slices"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// The actual communication configuration of an endpoint an establish would
// adopt (design docs/design/uafx-persistent-connections.md §6.6, decision
// C3-D6: "its actual configuration matches ... its communication links").
// The names of its DataSetReader and DataSetWriter prove nothing: another
// configuration mechanism (Part 14 §9.1) may have changed what they
// publish or subscribe to. What the AutomationComponent shows of them in
// its PublishSubscribe Object (Part 14 §9.1.4 to §9.1.8) is compared with
// what the run would configure:
//
//   - the DataSetWriter (DataSetWriterId, DataSetFieldContentMask,
//     KeyFrameCount), its WriterGroup (WriterGroupId, PublishingInterval,
//     KeepAliveTime, Priority, HeaderLayoutUri, SecurityMode,
//     SecurityGroupId), its PubSubConnection (PublisherId,
//     TransportProfileUri, Address Url) and the PublishedData of the
//     PublishedDataSet that feeds it (DataSetToWriter);
//   - the DataSetReader (PublisherId, WriterGroupId, DataSetWriterId,
//     DataSetFieldContentMask, MessageReceiveTimeout, KeyFrameCount,
//     HeaderLayoutUri, SecurityMode, SecurityGroupId), the TargetVariables
//     of its SubscribedDataSet and its PubSubConnection
//     (TransportProfileUri, Address Url).
//
// Identifiers the configuration leaves to be allocated (a WriterGroupId or
// DataSetWriterId of 0, a null PublisherId; §6.2.4.3.4 ReserveCommunicationIds,
// §6.16.3) are not compared with the configuration: the publisher's are
// whatever the AC holds, and a subscriber's must be those of the publisher
// of its flow when the run adopts that publisher too (adoptFlows), or 0 and
// null like the configuration when its publisher is not of the set. The
// enablement is not compared: the action decides it (§6.7.5.3). Library
// interpretation: the PublishedDataSet is compared by its PublishedData, not
// its name, which a run may change when it reuses one (reuseDataSets).

// commActual is the communication configuration of an endpoint as its
// AutomationComponent shows it.
type commActual struct {
	// writer, group and wconn are the Properties of the DataSetWriter, its
	// WriterGroup and its PubSubConnection, by BrowseName; published the
	// PublishedData of its PublishedDataSet.
	writer, group, wconn map[string]*ua.Variant
	published            []*ua.PublishedVariableDataType
	// reader and rconn are those of the DataSetReader and its
	// PubSubConnection; targets the TargetVariables of its
	// SubscribedDataSet.
	reader, rconn map[string]*ua.Variant
	targets       []*ua.FieldTargetDataType
}

// Properties read from each element (Part 14 §9.1.4 to §9.1.8).
var (
	connProps   = []string{"PublisherId", "TransportProfileUri", "Address/Url"}
	groupProps  = []string{"WriterGroupId", "PublishingInterval", "KeepAliveTime", "Priority", "HeaderLayoutUri", "SecurityMode", "SecurityGroupId"}
	writerProps = []string{"DataSetWriterId", "DataSetFieldContentMask", "KeyFrameCount"}
	readerProps = []string{
		"PublisherId", "WriterGroupId", "DataSetWriterId", "DataSetFieldContentMask", "MessageReceiveTimeout",
		"KeyFrameCount", "HeaderLayoutUri", "SecurityMode", "SecurityGroupId",
	}
)

// readComm reads the communication configuration of the endpoint whose
// actual is act, on the server of t.
func readComm(ctx context.Context, t *target, act *actual) (*commActual, error) {
	c := &commActual{}
	var err error
	if act.writer != nil {
		if c.writer, err = readProps(ctx, t, act.writer, writerProps); err != nil {
			return nil, err
		}
		g, err := parentOf(ctx, t, act.writer, id.HasDataSetWriter)
		if err != nil {
			return nil, err
		}
		if c.group, err = readProps(ctx, t, g, groupProps); err != nil {
			return nil, err
		}
		conn, err := parentOf(ctx, t, g, id.HasWriterGroup)
		if err != nil {
			return nil, err
		}
		if c.wconn, err = readProps(ctx, t, conn, connProps); err != nil {
			return nil, err
		}
		pds, err := parentOf(ctx, t, act.writer, id.DataSetToWriter)
		if err != nil {
			return nil, err
		}
		pd, err := readProps(ctx, t, pds, []string{"PublishedData"})
		if err != nil {
			return nil, err
		}
		if eos, ok := valueOf(pd["PublishedData"]).([]*ua.ExtensionObject); ok {
			for _, eo := range eos {
				v, _ := eo.Value.(*ua.PublishedVariableDataType)
				c.published = append(c.published, v)
			}
		}
	}
	if act.reader != nil {
		if c.reader, err = readProps(ctx, t, act.reader, readerProps); err != nil {
			return nil, err
		}
		rg, err := parentOf(ctx, t, act.reader, id.HasDataSetReader)
		if err != nil {
			return nil, err
		}
		conn, err := parentOf(ctx, t, rg, id.HasReaderGroup)
		if err != nil {
			return nil, err
		}
		if c.rconn, err = readProps(ctx, t, conn, connProps); err != nil {
			return nil, err
		}
		tv, err := readProps(ctx, t, act.reader, []string{"SubscribedDataSet/TargetVariables"})
		if err != nil {
			return nil, err
		}
		if eos, ok := valueOf(tv["SubscribedDataSet/TargetVariables"]).([]*ua.ExtensionObject); ok {
			for _, eo := range eos {
				v, _ := eo.Value.(*ua.FieldTargetDataType)
				c.targets = append(c.targets, v)
			}
		}
	}
	return c, nil
}

// readProps reads the values of the children of n named by paths (a
// BrowseName in namespace 0, or two joined by "/") in one Read. A child
// that is missing or a value that cannot be read is an error: a
// configuration that cannot be read is not one that matches.
func readProps(ctx context.Context, t *target, n *ua.NodeID, paths []string) (map[string]*ua.Variant, error) {
	refs, err := t.children(ctx, n)
	if err != nil {
		return nil, err
	}
	read := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	sub := map[string][]*ua.ReferenceDescription{}
	for _, p := range paths {
		parent, name, nested := cutPath(p)
		var node *ua.NodeID
		if !nested {
			node = child(refs, 0, p)
		} else {
			o := child(refs, 0, parent)
			if o == nil {
				return nil, fmt.Errorf("fxcm: %v has no %s", n, parent)
			}
			if sub[parent] == nil {
				if sub[parent], err = t.children(ctx, o); err != nil {
					return nil, err
				}
			}
			node = child(sub[parent], 0, name)
		}
		if node == nil {
			return nil, fmt.Errorf("fxcm: %v has no %s", n, p)
		}
		read.NodesToRead = append(read.NodesToRead, &ua.ReadValueID{NodeID: node, AttributeID: ua.AttributeIDValue})
	}
	res, err := t.sess.Read(ctx, read)
	if err != nil {
		return nil, err
	}
	if len(res.Results) != len(paths) {
		return nil, fmt.Errorf("fxcm: Read: %d results", len(res.Results))
	}
	out := map[string]*ua.Variant{}
	for i, dv := range res.Results {
		if dv == nil || bad(dv.Status) {
			return nil, fmt.Errorf("fxcm: the %s of %v was not read", paths[i], n)
		}
		v := dv.Value
		if v == nil {
			v = &ua.Variant{}
		}
		out[paths[i]] = v
	}
	return out, nil
}

func cutPath(p string) (parent, name string, nested bool) {
	for i := range len(p) {
		if p[i] == '/' {
			return p[:i], p[i+1:], true
		}
	}
	return "", p, false
}

// parentOf returns the source of the one inverse reference of type ref
// (namespace 0) of n: the WriterGroup of a DataSetWriter (HasDataSetWriter),
// the PubSubConnection of a group (HasWriterGroup, HasReaderGroup), the
// PublishedDataSet of a DataSetWriter (DataSetToWriter).
func parentOf(ctx context.Context, t *target, n *ua.NodeID, ref uint32) (*ua.NodeID, error) {
	res, err := t.sess.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: n, BrowseDirection: ua.BrowseDirectionInverse,
		ReferenceTypeID: ua.NewNumericNodeID(0, ref), ResultMask: uint32(ua.BrowseResultMaskAll),
	}}})
	if err != nil {
		return nil, err
	}
	if len(res.Results) != 1 || res.Results[0] == nil {
		return nil, fmt.Errorf("fxcm: Browse of %v: %d results", n, len(res.Results))
	}
	if sc := res.Results[0].StatusCode; sc != ua.StatusOK {
		return nil, sc
	}
	var out *ua.NodeID
	for _, r := range res.Results[0].References {
		if r == nil || r.IsForward || r.NodeID == nil || r.NodeID.NodeID == nil || r.NodeID.ServerIndex != 0 {
			continue
		}
		if out != nil {
			return nil, fmt.Errorf("fxcm: %v has more than one parent by %d", n, ref)
		}
		out = r.NodeID.NodeID
	}
	if out == nil {
		return nil, fmt.Errorf("fxcm: %v has no parent by %d", n, ref)
	}
	return out, nil
}

// sameComm reports whether c, the communication of the endpoint of ep, is
// the one cfg, the configuration of the set mapped to its server
// (prepareComm), gives it; why says what differs.
func sameComm(cfg *ua.PubSubConfiguration2DataType, ep *epRun, c *commActual) (ok bool, why string) {
	_, l := pubsubOf(ep.e)
	return sameCommAt(cfg, l, c)
}

// sameCommAt is sameComm for the CommunicationLinks l of the endpoint.
func sameCommAt(cfg *ua.PubSubConfiguration2DataType, l *uafx.PubSubCommunicationLinkConfiguration, c *commActual) (ok bool, why string) {
	if cfg == nil || l == nil {
		return true, ""
	}
	if c.writer != nil {
		conn, g, w := writerAt(cfg, l.DataSetWriterRef)
		if w == nil {
			return false, "the configuration has no DataSetWriter for it"
		}
		switch {
		case w.DataSetWriterID != 0 && !sameU16(c.writer["DataSetWriterId"], w.DataSetWriterID):
			return false, "its DataSetWriterId"
		case !sameU32(c.writer["DataSetFieldContentMask"], uint32(w.DataSetFieldContentMask)):
			return false, "the DataSetFieldContentMask of its DataSetWriter"
		case !sameU32(c.writer["KeyFrameCount"], w.KeyFrameCount):
			return false, "the KeyFrameCount of its DataSetWriter"
		case g.WriterGroupID != 0 && !sameU16(c.group["WriterGroupId"], g.WriterGroupID):
			return false, "its WriterGroupId"
		case !sameF64(c.group["PublishingInterval"], g.PublishingInterval):
			return false, "the PublishingInterval of its WriterGroup"
		case !sameF64(c.group["KeepAliveTime"], g.KeepAliveTime):
			return false, "the KeepAliveTime of its WriterGroup"
		case !sameU8(c.group["Priority"], g.Priority):
			return false, "the Priority of its WriterGroup"
		case !sameStr(c.group["HeaderLayoutUri"], g.HeaderLayoutURI):
			return false, "the HeaderLayoutUri of its WriterGroup"
		case !sameI32(c.group["SecurityMode"], int32(g.SecurityMode)):
			return false, "the SecurityMode of its WriterGroup"
		case !sameStr(c.group["SecurityGroupId"], g.SecurityGroupID):
			return false, "the SecurityGroupId of its WriterGroup"
		case !isNullID(conn.PublisherID) && !sameVariant(c.wconn["PublisherId"], conn.PublisherID):
			return false, "the PublisherId of its PubSubConnection"
		case !sameConn(c.wconn, conn):
			return false, "the transport of its PubSubConnection"
		case !samePublished(cfg, w.DataSetName, c.published):
			return false, "the PublishedData of its PublishedDataSet"
		}
	}
	if c.reader != nil {
		r := readerAt(cfg, l.DataSetReaderRef)
		if r == nil {
			return false, "the configuration has no DataSetReader for it"
		}
		conn := cfg.Connections[l.DataSetReaderRef.ConnectionIndex]
		switch {
		case !isNullID(r.PublisherID) && !sameVariant(c.reader["PublisherId"], r.PublisherID):
			return false, "the PublisherId of its DataSetReader"
		case r.WriterGroupID != 0 && !sameU16(c.reader["WriterGroupId"], r.WriterGroupID):
			return false, "the WriterGroupId of its DataSetReader"
		case r.DataSetWriterID != 0 && !sameU16(c.reader["DataSetWriterId"], r.DataSetWriterID):
			return false, "the DataSetWriterId of its DataSetReader"
		case !sameU32(c.reader["DataSetFieldContentMask"], uint32(r.DataSetFieldContentMask)):
			return false, "the DataSetFieldContentMask of its DataSetReader"
		case !sameF64(c.reader["MessageReceiveTimeout"], r.MessageReceiveTimeout):
			return false, "the MessageReceiveTimeout of its DataSetReader"
		case !sameU32(c.reader["KeyFrameCount"], r.KeyFrameCount):
			return false, "the KeyFrameCount of its DataSetReader"
		case !sameStr(c.reader["HeaderLayoutUri"], r.HeaderLayoutURI):
			return false, "the HeaderLayoutUri of its DataSetReader"
		case !sameI32(c.reader["SecurityMode"], int32(r.SecurityMode)):
			return false, "the SecurityMode of its DataSetReader"
		case !sameStr(c.reader["SecurityGroupId"], r.SecurityGroupID):
			return false, "the SecurityGroupId of its DataSetReader"
		case !sameConn(c.rconn, conn):
			return false, "the transport of the PubSubConnection of its DataSetReader"
		case !sameTargets(r, c.targets):
			return false, "the TargetVariables of its DataSetReader"
		}
	}
	return true, ""
}

// adoptFlows checks the identifiers the configuration leaves to be
// allocated across the flows of the run: a DataSetReader of an adoptable
// subscriber whose PublisherId, WriterGroupId or DataSetWriterId the
// configuration leaves open names those of the DataSetWriter of the
// publisher of its flow, when the run adopts that publisher (E.2.2: the
// subscriber side is configured with the publisher's ids); when the
// publisher is not an endpoint of the set, they are the configuration's.
// It reports whether a subscriber fails: then the run adopts nothing.
func (x *run) adoptFlows() (rejected bool) {
	pubs := map[*flow]*epRun{}
	for _, ep := range x.eps {
		if ep.adopt != nil && ep.e.outbound != nil && ep.comm != nil && ep.comm.writer != nil {
			pubs[ep.e.outbound] = ep
		}
	}
	for _, ep := range x.eps {
		if ep.adopt == nil || ep.e.inbound == nil || ep.comm == nil || ep.comm.reader == nil {
			continue
		}
		_, l := pubsubOf(ep.e)
		if ep.a.adoptCfg == nil || l == nil {
			continue
		}
		r := readerAt(ep.a.adoptCfg, l.DataSetReaderRef)
		if r == nil {
			continue
		}
		f := ep.e.inbound.flow
		p := pubs[f]
		inSet := slices.ContainsFunc(x.cfg.endpointsOf(f), func(e *endpoint) bool { return e.outbound == f })
		why := ""
		switch {
		case p != nil:
			switch {
			case isNullID(r.PublisherID) && !sameVariant(ep.comm.reader["PublisherId"], p.comm.wconn["PublisherId"]):
				why = "its PublisherId is not its publisher's"
			case r.WriterGroupID == 0 && !sameVariant(ep.comm.reader["WriterGroupId"], p.comm.group["WriterGroupId"]):
				why = "its WriterGroupId is not its publisher's"
			case r.DataSetWriterID == 0 && !sameVariant(ep.comm.reader["DataSetWriterId"], p.comm.writer["DataSetWriterId"]):
				why = "its DataSetWriterId is not its publisher's"
			}
		case inSet:
			why = "its publisher is not adopted"
		default:
			switch {
			case isNullID(r.PublisherID) && !isNullID(ep.comm.reader["PublisherId"]):
				why = "its PublisherId is not the configuration's"
			case r.WriterGroupID == 0 && !sameU16(ep.comm.reader["WriterGroupId"], 0):
				why = "its WriterGroupId is not the configuration's"
			case r.DataSetWriterID == 0 && !sameU16(ep.comm.reader["DataSetWriterId"], 0):
				why = "its DataSetWriterId is not the configuration's"
			}
		}
		if why != "" {
			x.m.log.Debug("fxcm: an endpoint was not adopted", "set", x.r.key.String(), "run", x.r.id, "endpoint", ep.e.conf.Name, "why", why)
			rejected = true
		}
	}
	return rejected
}

func sameConn(have map[string]*ua.Variant, want *ua.PubSubConnectionDataType) bool {
	if want == nil {
		return false
	}
	url := ""
	if want.Address != nil {
		if a, ok := want.Address.Value.(*ua.NetworkAddressURLDataType); ok {
			url = a.URL
		}
	}
	return sameStr(have["TransportProfileUri"], want.TransportProfileURI) && sameStr(have["Address/Url"], url)
}

// samePublished reports whether have is the PublishedData of the
// PublishedDataSet name of cfg.
func samePublished(cfg *ua.PubSubConfiguration2DataType, name string, have []*ua.PublishedVariableDataType) bool {
	for _, p := range cfg.PublishedDataSets {
		if p == nil || p.Name != name || p.DataSetSource == nil {
			continue
		}
		items, ok := p.DataSetSource.Value.(*ua.PublishedDataItemsDataType)
		return ok && samePublishedData(have, items.PublishedData)
	}
	return false
}

// sameTargets reports whether have are the TargetVariables of r.
func sameTargets(r *ua.DataSetReaderDataType, have []*ua.FieldTargetDataType) bool {
	var want []*ua.FieldTargetDataType
	if r.SubscribedDataSet != nil {
		if tv, ok := r.SubscribedDataSet.Value.(*ua.TargetVariablesDataType); ok {
			want = tv.TargetVariables
		}
	}
	if len(have) != len(want) {
		return false
	}
	for i, w := range want {
		h := have[i]
		if h == nil || w == nil {
			if h != w {
				return false
			}
			continue
		}
		if !h.TargetNodeID.Equal(w.TargetNodeID) || h.AttributeID != w.AttributeID || h.WriteIndexRange != w.WriteIndexRange ||
			h.ReceiverIndexRange != w.ReceiverIndexRange || !sameGUID(h.DataSetFieldID, w.DataSetFieldID) ||
			h.OverrideValueHandling != w.OverrideValueHandling || !sameValue(h.OverrideValue, w.OverrideValue) {
			return false
		}
	}
	return true
}

// sameGUID compares two GUIDs of which either may be absent: absent and
// the null GUID are the same.
func sameGUID(a, b *ua.GUID) bool {
	switch {
	case nullGUID(a) || nullGUID(b):
		return nullGUID(a) && nullGUID(b)
	}
	return a.String() == b.String()
}

// valueOf is the value of v; an absent Property (an optional one the AC
// does not have) has none.
func valueOf(v *ua.Variant) any {
	if v == nil {
		return nil
	}
	return v.Value()
}

func sameU8(v *ua.Variant, want uint8) bool {
	x, ok := valueOf(v).(uint8)
	return ok && x == want
}

func sameU16(v *ua.Variant, want uint16) bool {
	x, ok := valueOf(v).(uint16)
	return ok && x == want
}

func sameU32(v *ua.Variant, want uint32) bool {
	x, ok := valueOf(v).(uint32)
	return ok && x == want
}

func sameI32(v *ua.Variant, want int32) bool {
	x, ok := valueOf(v).(int32)
	return ok && x == want
}

func sameF64(v *ua.Variant, want float64) bool {
	x, ok := valueOf(v).(float64)
	return ok && (x == want || math.IsNaN(x) && math.IsNaN(want))
}

func sameStr(v *ua.Variant, want string) bool {
	x, ok := valueOf(v).(string)
	return ok && x == want || valueOf(v) == nil && want == ""
}
