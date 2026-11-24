// SPDX-License-Identifier: MIT

package fxcm

import (
	"bytes"
	"fmt"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// reflectFlows applies the CommunicationFlowConfiguration Variables an edit
// changed to the PubSubConfigurations of next, the Config a CommitUpdates
// makes from base: "After a ConnectionConfigurationSet is edited … the
// ConnectionManager shall update the PubSubConfiguration" (§6.16.3), and the
// ConnectionManager reflects a client's changes in the
// CommunicationModelConfiguration (§6.13.1).
//
// Library interpretation (CS-19), as Part 81 gives no mapping of the flow
// Variables onto the PubSubConfiguration: a changed Variable of a flow is
// written to what the CommunicationLinks of its endpoints reference.
//
//   - Publisher (the endpoint whose outbound flow it is, DataSetWriterRef):
//     PublishingInterval, HeaderLayoutUri, SecurityMode and SecurityGroupId
//     to the WriterGroup; TransportProfileUri and Address to the
//     PubSubConnection.
//   - Subscriber (an endpoint with the flow inbound, DataSetReaderRef):
//     HeaderLayoutUri, SecurityMode and SecurityGroupId to the
//     DataSetReader, MessageReceiveTimeout of its SubscriberConfiguration
//     to the DataSetReader; TransportProfileUri to the PubSubConnection, and
//     the Address of the SubscriberConfiguration, else the Address of the
//     flow when it is multicast, to the PubSubConnection.
//
// Qos and ReceiveQos are not reflected. Only a Variable that is present in
// both Versions and whose value changed is reflected; an unchanged Variable
// leaves what the PubSubConfiguration says. Two different values reflected
// onto the same field, as when two flows share a WriterGroup, are a
// Finding.
func reflectFlows(base, next *Config) []Finding {
	r := reflector{set: map[string]string{}}
	old := map[string]*flow{}
	for _, f := range base.flows {
		old[f.conf.BrowseName] = f
	}
	for _, f := range next.flows {
		o := old[f.conf.BrowseName]
		if o == nil {
			continue
		}
		path := fmt.Sprintf("CommunicationFlows[%d]", f.index)
		for _, e := range next.endpointsOf(f) {
			if e.outbound == f {
				r.publisher(path, e, o.conf, f.conf)
			}
			if e.inbound != nil && e.inbound.flow == f {
				r.subscriber(path, e, o, f)
			}
		}
	}
	return r.findings
}

// endpointsOf returns the endpoints of c with f as their outbound or
// inbound flow.
func (c *Config) endpointsOf(f *flow) []*endpoint {
	var out []*endpoint
	for _, cn := range c.conns {
		for _, e := range cn.endpoints {
			if e.outbound == f || (e.inbound != nil && e.inbound.flow == f) {
				out = append(out, e)
			}
		}
	}
	return out
}

type reflector struct {
	set      map[string]string // a field reflected onto: the value written
	findings []Finding
}

// pubsubOf returns the PubSubConfiguration of the AC of e and the decoded
// CommunicationLinks of e, nil when either is absent.
func pubsubOf(e *endpoint) (*ua.PubSubConfiguration2DataType, *uafx.PubSubCommunicationLinkConfiguration) {
	if e.ac == nil {
		return nil, nil
	}
	m, ok := e.ac.conf.CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration)
	if !ok || m == nil || m.PubSubConfiguration == nil {
		return nil, nil
	}
	l, err := links(e.conf.CommunicationLinks)
	if err != nil || l == nil {
		return nil, nil
	}
	return m.PubSubConfiguration, l
}

func (r *reflector) publisher(path string, e *endpoint, o, n *uafx.PubSubCommunicationFlowConfigurationConf) {
	cfg, l := pubsubOf(e)
	if cfg == nil || l.DataSetWriterRef == nil {
		return
	}
	conn, g, _ := writerAt(cfg, l.DataSetWriterRef)
	if g == nil {
		return
	}
	at := fmt.Sprintf("%s/%s", e.ac.conf.BrowseName, connName(conn))
	gat := at + "/" + g.Name
	if v, ok := changed(o.PublishingInterval, n.PublishingInterval); ok {
		r.put(path+".PublishingInterval", gat+".PublishingInterval", v, func() { g.PublishingInterval = v })
	}
	if v, ok := changed(o.HeaderLayoutURI, n.HeaderLayoutURI); ok {
		r.put(path+".HeaderLayoutUri", gat+".HeaderLayoutUri", v, func() { g.HeaderLayoutURI = v })
	}
	if v, ok := changed(o.SecurityMode, n.SecurityMode); ok {
		r.put(path+".SecurityMode", gat+".SecurityMode", v, func() { g.SecurityMode = v })
	}
	if v, ok := changed(o.SecurityGroupID, n.SecurityGroupID); ok {
		r.put(path+".SecurityGroupId", gat+".SecurityGroupId", v, func() { g.SecurityGroupID = v })
	}
	if v, ok := changed(o.TransportProfileURI, n.TransportProfileURI); ok {
		r.put(path+".TransportProfileUri", at+".TransportProfileUri", v, func() { conn.TransportProfileURI = v })
	}
	if a, ok := changedAddress(o.Address, n.Address); ok {
		r.putAddress(path+".Address", at+".Address", a, conn)
	}
}

func (r *reflector) subscriber(path string, e *endpoint, of, nf *flow) {
	cfg, l := pubsubOf(e)
	if cfg == nil || l.DataSetReaderRef == nil {
		return
	}
	rd := readerAt(cfg, l.DataSetReaderRef)
	if rd == nil {
		return
	}
	conn := cfg.Connections[l.DataSetReaderRef.ConnectionIndex]
	at := fmt.Sprintf("%s/%s", e.ac.conf.BrowseName, connName(conn))
	rat := at + "/" + rd.Name
	o, n := of.conf, nf.conf
	if v, ok := changed(o.HeaderLayoutURI, n.HeaderLayoutURI); ok {
		r.put(path+".HeaderLayoutUri", rat+".HeaderLayoutUri", v, func() { rd.HeaderLayoutURI = v })
	}
	if v, ok := changed(o.SecurityMode, n.SecurityMode); ok {
		r.put(path+".SecurityMode", rat+".SecurityMode", v, func() { rd.SecurityMode = v })
	}
	if v, ok := changed(o.SecurityGroupID, n.SecurityGroupID); ok {
		r.put(path+".SecurityGroupId", rat+".SecurityGroupId", v, func() { rd.SecurityGroupID = v })
	}
	if v, ok := changed(o.TransportProfileURI, n.TransportProfileURI); ok {
		r.put(path+".TransportProfileUri", at+".TransportProfileUri", v, func() { conn.TransportProfileURI = v })
	}
	ns := nf.conf.SubscriberConfigurations
	var os *uafx.SubscriberConfigurationConf
	if idx := e.inbound.index; idx < len(of.conf.SubscriberConfigurations) {
		os = of.conf.SubscriberConfigurations[idx]
	}
	sub := e.inbound.subscriber
	if sub != nil && os != nil && os.BrowseName == sub.BrowseName && e.inbound.index < len(ns) {
		if sub.MessageReceiveTimeout != os.MessageReceiveTimeout {
			v := sub.MessageReceiveTimeout
			r.put(fmt.Sprintf("%s.SubscriberConfigurations[%d].MessageReceiveTimeout", path, e.inbound.index), rat+".MessageReceiveTimeout", v, func() { rd.MessageReceiveTimeout = v })
		}
		if address(sub.Address) != nil || address(os.Address) != nil {
			if a, ok := changedAddress(os.Address, sub.Address); ok {
				r.putAddress(fmt.Sprintf("%s.SubscriberConfigurations[%d].Address", path, e.inbound.index), at+".Address", a, conn)
			}
			return
		}
	}
	if nf.multicast != nil && *nf.multicast {
		if a, ok := changedAddress(o.Address, n.Address); ok {
			r.putAddress(path+".Address", at+".Address", a, conn)
		}
	}
}

// put writes v with apply unless another flow wrote a different value to
// the same target.
func (r *reflector) put(path, target string, v any, apply func()) {
	s := fmt.Sprint(v)
	if prev, ok := r.set[target]; ok {
		if prev != s {
			r.findings = append(r.findings, Finding{Path: path, Clause: libInterp + ": §6.16.3", Problem: fmt.Sprintf("the edit reflects %s onto %s, which another flow sets to %s", s, target, prev)})
		}
		return
	}
	r.set[target] = s
	apply()
}

func (r *reflector) putAddress(path, target string, a *ua.ExtensionObject, conn *ua.PubSubConnectionDataType) {
	b, err := ua.Encode(a)
	if err != nil {
		r.findings = append(r.findings, Finding{Path: path, Clause: "§6.13.3", Problem: fmt.Sprintf("the Address cannot be encoded: %v", err)})
		return
	}
	show := fmt.Sprintf("%x", b)
	if u, ok := a.Value.(*ua.NetworkAddressURLDataType); ok && u != nil {
		show = u.URL
	}
	r.put(path, target, show, func() { conn.Address = a })
}

// changed returns the new value when both are present and differ.
func changed[T comparable](o, n *T) (T, bool) {
	var zero T
	if o == nil || n == nil || *o == *n {
		return zero, false
	}
	return *n, true
}

// changedAddress returns the new Address when both are present and their
// encodings differ.
func changedAddress(o, n *uafx.AddressSelection) (*ua.ExtensionObject, bool) {
	oa, na := address(o), address(n)
	if oa == nil || na == nil {
		return nil, false
	}
	ob, err1 := ua.Encode(oa)
	nb, err2 := ua.Encode(na)
	if err1 == nil && err2 == nil && bytes.Equal(ob, nb) {
		return nil, false
	}
	return na, true
}

func connName(c *ua.PubSubConnectionDataType) string {
	if c == nil {
		return ""
	}
	return c.Name
}
