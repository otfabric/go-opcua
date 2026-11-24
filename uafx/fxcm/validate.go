// SPDX-License-Identifier: MIT

package fxcm

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
)

// libInterp is the Clause of a Finding where the library decides.
const libInterp = "library interpretation"

// checker collects the findings of a set.
type checker struct{ fs []Finding }

func (k *checker) add(path, clause, format string, args ...any) {
	k.fs = append(k.fs, Finding{Path: path, Clause: clause, Problem: fmt.Sprintf(format, args...)})
}

// build validates c.conf and resolves its indexes (F.1.2.1) into the
// graph of c. It returns the findings; c is usable only without any.
//
// c.conf went through the binary encoding (cloneConf): a structure that is
// not an ExtensionObject, such as an element of Connections or Endpoint1,
// has no null (Part 6 §5.2.6); a nil one is encoded as the default
// structure and validated as one.
func (c *Config) build() []Finding {
	k := &checker{}
	conf := c.conf

	if conf.BrowseName == "" {
		k.add("BrowseName", libInterp, "empty: a set is found by its BrowseName (§6.7.2, F.3.3.2)")
	}
	for i, f := range conf.ConnectionConfigurationSetFolder {
		if f == "" {
			k.add(fmt.Sprintf("ConnectionConfigurationSetFolder[%d]", i), libInterp, "an empty Folder name")
		}
	}
	for _, a := range []struct {
		name string
		n    int
	}{
		{"Connections", len(conf.Connections)},
		{"CommunicationFlows", len(conf.CommunicationFlows)},
		{"ServerAddresses", len(conf.ServerAddresses)},
		{"AutomationComponentConfigurations", len(conf.AutomationComponentConfigurations)},
	} {
		if a.n == 0 {
			k.add(a.name, "§6.8.2 Table 89", "empty: a set has one or more of them (MandatoryPlaceholder)")
		}
	}

	c.servers = c.buildServers(k)
	c.acs = c.buildACs(k)
	c.flows = c.buildFlows(k)
	c.conns = c.buildConnections(k)
	c.checkEndpointNames(k)
	c.checkFlowUse(k)
	c.checkSKS(k)
	return k.fs
}

// unique adds a finding for every name that is empty or used before.
func unique(k *checker, seen map[string]string, path, name, clause string) {
	if name == "" {
		k.add(path+".BrowseName", libInterp, "empty: the element is a Node with this BrowseName in the set (§6.8.2)")
		return
	}
	if first, ok := seen[name]; ok {
		k.add(path+".BrowseName", clause, "%q is also the BrowseName of %s", name, first)
		return
	}
	seen[name] = path
}

// siblingClause is the Clause of a duplicated BrowseName of the elements
// of a set other than its Connections.
const siblingClause = libInterp + ": siblings of the set in the AddressSpace (§6.8.2)"

func (c *Config) buildServers(k *checker) []*serverAddress {
	out := make([]*serverAddress, len(c.conf.ServerAddresses))
	seen := map[string]string{}
	for i, sa := range c.conf.ServerAddresses {
		p := fmt.Sprintf("ServerAddresses[%d]", i)
		unique(k, seen, p, sa.BrowseName, siblingClause)
		if sa.Address == "" {
			k.add(p+".Address", "§9.2", "empty: the DiscoveryUrl of the server")
		}
		if sa.SecurityMode < ua.MessageSecurityModeNone || sa.SecurityMode > ua.MessageSecurityModeSignAndEncrypt {
			k.add(p+".SecurityMode", "§9.2", "%v is not a MessageSecurityMode a secure channel can use", sa.SecurityMode)
		}
		if len(sa.Namespaces) > 0 && sa.Namespaces[0] != uaNamespace {
			k.add(p+".Namespaces[0]", libInterp+": F.1.2.2, index 0 of a NamespaceArray", "%q is not the OPC UA namespace", sa.Namespaces[0])
		}
		for j, u := range sa.Namespaces {
			if j > 0 && u == "" {
				k.add(fmt.Sprintf("%s.Namespaces[%d]", p, j), "F.1.2.2", "an empty NamespaceUri")
			}
		}
		selection(k, p+".Address", sa.Address, sa.AddressSelection, flag(sa.AddressModify))
		selection(k, p+".SecurityMode", sa.SecurityMode, sa.SecurityModeSelection, flag(sa.SecurityModeModify))
		selection(k, p+".SecurityPolicyUri", sa.SecurityPolicyURI, sa.SecurityPolicyURISelection, flag(sa.SecurityPolicyURIModify))
		selection(k, p+".ServerUri", sa.ServerURI, sa.ServerURISelection, flag(sa.ServerURIModify))
		out[i] = &serverAddress{index: i, conf: sa, ns: namespaceScope(sa.Namespaces)}
	}
	return out
}

func (c *Config) buildACs(k *checker) []*automationComponent {
	out := make([]*automationComponent, len(c.conf.AutomationComponentConfigurations))
	seen := map[string]string{}
	for i, ac := range c.conf.AutomationComponentConfigurations {
		p := fmt.Sprintf("AutomationComponentConfigurations[%d]", i)
		unique(k, seen, p, ac.BrowseName, siblingClause)
		a := &automationComponent{index: i, conf: ac}
		switch idx := ac.ServerAddressIndex; {
		case idx < 0:
			k.add(p+".ServerAddressIndex", "§6.8.2 Table 90, F.1.2.1", "%d: no ServerAddress, the AutomationComponent cannot be reached", idx)
		case int(idx) >= len(c.servers):
			k.add(p+".ServerAddressIndex", "F.1.2.1", "%d is not an index of ServerAddresses (%d)", idx, len(c.servers))
		default:
			a.server = c.servers[idx]
		}
		var ns namespaceScope
		scoped := a.server != nil
		if scoped {
			ns = a.server.ns
		}
		identifier(k, p+".AutomationComponentNode", "§6.14", ac.AutomationComponentNode, ns, scoped)
		if len(ac.AutomationComponentNodeSelection) > 0 && !ac.AutomationComponentNodeModify &&
			!slices.ContainsFunc(ac.AutomationComponentNodeSelection, func(n *uafx.NodeIdentifier) bool { return sameStructure(n, ac.AutomationComponentNode) }) {
			k.add(p+".AutomationComponentNode", libInterp+": F.1.2.3", "not one of the AutomationComponentNodeSelection and AutomationComponentNodeModify is FALSE")
		}
		for j, av := range ac.AssetVerification {
			q := fmt.Sprintf("%s.AssetVerification[%d]", p, j)
			identifier(k, q+".AssetToVerify", "§6.15", av.AssetToVerify, ns, scoped)
			pairs(k, q+".ExpectedVerificationVariables", "§6.15", av.ExpectedVerificationVariables, ns, scoped)
			pairs(k, q+".ExpectedAdditionalVerificationVariables", "§6.15", av.ExpectedAdditionalVerificationVariables, ns, scoped)
		}
		out[i] = a
	}
	return out
}

func (c *Config) buildFlows(k *checker) []*flow {
	out := make([]*flow, len(c.conf.CommunicationFlows))
	seen := map[string]string{}
	for i, cf := range c.conf.CommunicationFlows {
		p := fmt.Sprintf("CommunicationFlows[%d]", i)
		fc, ok := cf.(*uafx.PubSubCommunicationFlowConfigurationConf)
		if !ok || fc == nil {
			k.add(p, "§6.13, F.1.3", "null: a flow is a PubSubCommunicationFlowConfigurationConf")
			continue
		}
		unique(k, seen, p, fc.BrowseName, siblingClause)
		f := &flow{index: i, conf: fc}
		flowAddr := address(fc.Address)
		if flowAddr != nil {
			f.multicast = multicastAddress(flowAddr)
		}
		if fc.Address != nil {
			addressSelection(k, p+".Address", fc.Address)
		}
		optSelection(k, p+".TransportProfileUri", fc.TransportProfileURI, fc.TransportProfileURISelection, flag(fc.TransportProfileURIModify))
		optSelection(k, p+".HeaderLayoutUri", fc.HeaderLayoutURI, fc.HeaderLayoutURISelection, flag(fc.HeaderLayoutURIModify))
		optSelection(k, p+".PublishingInterval", fc.PublishingInterval, fc.PublishingIntervalSelection, flag(fc.PublishingIntervalModify))
		optSelection(k, p+".SecurityMode", fc.SecurityMode, fc.SecurityModeSelection, flag(fc.SecurityModeModify))
		optSelection(k, p+".SecurityGroupId", fc.SecurityGroupID, fc.SecurityGroupIDSelection, flag(fc.SecurityGroupIDModify))
		if fc.Qos != nil && len(fc.QosSelection) > 0 && !flag(fc.QosModify) &&
			!slices.ContainsFunc(fc.QosSelection, func(q *uafx.CommunicationFlowQos) bool { return sameStructure(q, fc.Qos) }) {
			k.add(p+".Qos", libInterp+": F.1.2.3", "not one of the QosSelection and QosModify is not TRUE")
		}
		subs := map[string]string{}
		for j, sc := range fc.SubscriberConfigurations {
			q := fmt.Sprintf("%s.SubscriberConfigurations[%d]", p, j)
			unique(k, subs, q, sc.BrowseName, siblingClause)
			if flowAddr == nil && address(sc.Address) == nil {
				k.add(q+".Address", "§6.13.3", "absent here and in the flow: the configuration is invalid")
			}
			if sc.Address != nil {
				addressSelection(k, q+".Address", sc.Address)
			}
			if sc.ReceiveQos != nil && fc.Qos == nil {
				k.add(q+".ReceiveQos", "§6.13.3", "present while the flow has no Qos")
			}
			optSelection(k, q+".MessageReceiveTimeout", &sc.MessageReceiveTimeout, sc.MessageReceiveTimeoutSelection, flag(sc.MessageReceiveTimeoutModify))
		}
		out[i] = f
	}
	return out
}

func (c *Config) buildConnections(k *checker) []*connection {
	out := make([]*connection, 0, len(c.conf.Connections))
	seen := map[string]string{}
	for i, cc := range c.conf.Connections {
		p := fmt.Sprintf("Connections[%d]", i)
		if cc.BrowseName == "" {
			k.add(p+".BrowseName", libInterp, "empty: the ConnectionsDiagnostics name a Connection by it (§6.8.2)")
		} else if first, ok := seen[cc.BrowseName]; ok {
			k.add(p+".BrowseName", "§6.8.2", "%q is also the name of %s: ConnectionsDiagnostics are linked to their Connection by name", cc.BrowseName, first)
		} else {
			seen[cc.BrowseName] = p
		}
		cn := &connection{index: i, name: cc.BrowseName}
		for n, ep := range []*uafx.ConnectionEndpointConfigurationConf{cc.Endpoint1, cc.Endpoint2} {
			if ep == nil { // Endpoint2 is optional (§6.10 Table 94)
				continue
			}
			cn.endpoints = append(cn.endpoints, c.buildEndpoint(k, fmt.Sprintf("%s.Endpoint%d", p, n+1), cn, n+1, ep))
		}
		out = append(out, cn)
	}
	return out
}

func (c *Config) buildEndpoint(k *checker, p string, cn *connection, number int, ep *uafx.ConnectionEndpointConfigurationConf) *endpoint {
	e := &endpoint{conn: cn, number: number, conf: ep}
	switch idx := ep.AutomationComponentIndex; {
	case idx < 0 || int(idx) >= len(c.acs):
		k.add(p+".AutomationComponentIndex", "§6.8.2 Table 90, F.1.2.1", "%d is not an index of AutomationComponentConfigurations (%d)", idx, len(c.acs))
	default:
		e.ac = c.acs[idx]
	}
	var ns namespaceScope
	scoped := e.ac != nil && e.ac.server != nil
	if scoped {
		ns = e.ac.server.ns
	}
	identifier(k, p+".FunctionalEntityNode", "§6.11 Table 95, F.1.5", ep.FunctionalEntityNode, ns, scoped)
	if len(ep.FunctionalEntityNodeSelection) > 0 && !flag(ep.FunctionalEntityNodeModify) &&
		!slices.ContainsFunc(ep.FunctionalEntityNodeSelection, func(n *uafx.NodeIdentifier) bool { return sameStructure(n, ep.FunctionalEntityNode) }) {
		k.add(p+".FunctionalEntityNode", libInterp+": F.1.2.3", "not one of the FunctionalEntityNodeSelection and FunctionalEntityNodeModify is not TRUE")
	}
	if ep.Name == "" {
		k.add(p+".Name", "§6.12", "empty: the BrowseName of the ConnectionEndpoint to create")
	}
	selection(k, p+".Name", ep.Name, ep.NameSelection, flag(ep.NameModify))
	if ep.ConnectionEndpointTypeID == nil {
		k.add(p+".ConnectionEndpointTypeId", "§6.12, F.1.5", "absent")
	} else if scoped {
		nodeID(k, p+".ConnectionEndpointTypeId", "F.1.2.2", ep.ConnectionEndpointTypeID, ns)
	}
	if len(ep.InputVariableIDs) == 0 && len(ep.OutputVariableIDs) == 0 {
		k.add(p, "§6.12", "neither InputVariableIds nor OutputVariableIds: a ConnectionEndpointParameter has at least one of them")
	}
	for j, id := range ep.InputVariableIDs {
		identifier(k, fmt.Sprintf("%s.InputVariableIds[%d]", p, j), "§6.12, F.1.5", id, ns, scoped)
	}
	for j, id := range ep.OutputVariableIDs {
		identifier(k, fmt.Sprintf("%s.OutputVariableIds[%d]", p, j), "§6.12, F.1.5", id, ns, scoped)
	}
	if (ep.PreconfiguredPublishedDataSet != nil || ep.PreconfiguredSubscribedDataSet != nil) && scoped && !maybePubSubEndpoint(ep.ConnectionEndpointTypeID, ns) {
		k.add(p+".ConnectionEndpointTypeId", "§6.12", "a preconfigured DataSet is configured but the type is not PubSubConnectionEndpointType")
	}
	pairs(k, p+".ExpectedVerificationVariables", "§6.11, F.1.5", ep.ExpectedVerificationVariables, ns, scoped)
	for j, id := range ep.ControlGroups {
		identifier(k, fmt.Sprintf("%s.ControlGroups[%d]", p, j), "§6.11, F.1.5", id, ns, scoped)
	}
	pairs(k, p+".ConfigurationData", "§6.11, F.1.5", ep.ConfigurationData, ns, scoped)

	if ep.OutboundFlowIndex != nil && *ep.OutboundFlowIndex >= 0 {
		if idx := *ep.OutboundFlowIndex; int(idx) >= len(c.flows) {
			k.add(p+".OutboundFlowIndex", "F.1.2.1", "%d is not an index of CommunicationFlows (%d)", idx, len(c.flows))
		} else {
			e.outbound = c.flows[idx]
		}
	}
	switch in := ep.InboundFlowIndex; {
	case len(in) == 0:
	case len(in) != 2:
		k.add(p+".InboundFlowIndex", "F.1.5 Table F.5", "%d elements: the flow and its SubscriberConfiguration", len(in))
	case in[0] < 0:
		if in[1] >= 0 {
			k.add(p+".InboundFlowIndex", "F.1.2.1", "a SubscriberConfiguration %d without a flow", in[1])
		}
	case int(in[0]) >= len(c.flows):
		k.add(p+".InboundFlowIndex[0]", "F.1.2.1", "%d is not an index of CommunicationFlows (%d)", in[0], len(c.flows))
	case c.flows[in[0]] == nil:
		// The flow has its finding.
	default:
		f := c.flows[in[0]]
		if in[1] < 0 || int(in[1]) >= len(f.conf.SubscriberConfigurations) {
			k.add(p+".InboundFlowIndex[1]", "§6.13.3, F.1.2.1", "%d is not an index of the SubscriberConfigurations of %s (%d)", in[1], f.conf.BrowseName, len(f.conf.SubscriberConfigurations))
		} else {
			e.inbound = &inbound{flow: f, index: int(in[1]), subscriber: f.conf.SubscriberConfigurations[in[1]]}
		}
	}
	return e
}

// checkEndpointNames checks that no two endpoints of the set would be
// created under the same Name in the same FunctionalEntity (§6.12: the
// Name is unique within the ConnectionEndpoints Folder). Library
// interpretation: before resolution, the same AutomationComponentIndex and
// the same FunctionalEntityNode identifier stand for the same
// FunctionalEntity; C2.2 checks the resolved nodes again.
func (c *Config) checkEndpointNames(k *checker) {
	type place struct {
		ac int
		fe string
	}
	seen := map[place]map[string]string{}
	for _, cn := range c.conns {
		for _, e := range cn.endpoints {
			if e.ac == nil || e.conf.Name == "" {
				continue
			}
			fe, err := encoded(e.conf.FunctionalEntityNode)
			if err != nil {
				continue // identifier has its finding
			}
			pl := place{e.ac.index, string(fe)}
			if seen[pl] == nil {
				seen[pl] = map[string]string{}
			}
			p := fmt.Sprintf("Connections[%d].Endpoint%d", cn.index, e.number)
			if first, ok := seen[pl][e.conf.Name]; ok {
				k.add(p+".Name", "§6.12", "%q is also the Name of %s in the same FunctionalEntity", e.conf.Name, first)
				continue
			}
			seen[pl][e.conf.Name] = p
		}
	}
}

// checkFlowUse checks how the endpoints use the flows (§6.13.3): one
// publisher per flow (library interpretation: a flow is the information
// flow of one Publisher, §6.13.3 "the Publisher of the information
// flow"), and a unicast flow has one SubscriberConfiguration and one
// subscriber.
func (c *Config) checkFlowUse(k *checker) {
	pubs := map[*flow][]string{}
	subs := map[*flow][]string{}
	for _, cn := range c.conns {
		for _, e := range cn.endpoints {
			p := fmt.Sprintf("Connections[%d].Endpoint%d", cn.index, e.number)
			if e.outbound != nil {
				pubs[e.outbound] = append(pubs[e.outbound], p)
			}
			if e.inbound != nil {
				subs[e.inbound.flow] = append(subs[e.inbound.flow], p)
			}
		}
	}
	for _, f := range c.flows {
		if f == nil {
			continue
		}
		p := fmt.Sprintf("CommunicationFlows[%d]", f.index)
		if ps := pubs[f]; len(ps) > 1 {
			k.add(p, libInterp+": §6.13.3", "published by %d endpoints (%v): a flow has one Publisher", len(ps), ps)
		}
		if f.multicast != nil && !*f.multicast {
			if n := len(f.conf.SubscriberConfigurations); n > 1 {
				k.add(p+".SubscriberConfigurations", "§6.13.3", "%d SubscriberConfigurations for a unicast Address: a unicast flow has a single one", n)
			}
			if ss := subs[f]; len(ss) > 1 {
				k.add(p, "§6.13.3", "%d subscribers (%v) of a unicast Address", len(ss), ss)
			}
		}
	}
}

func (c *Config) checkSKS(k *checker) {
	s := c.conf.SecurityKeyServer
	if nullSKS(s) {
		return
	}
	if s.Address == "" {
		k.add("SecurityKeyServer.Address", "§9.3", "empty")
	}
	selection(k, "SecurityKeyServer.Address", s.Address, s.AddressSelection, flag(s.AddressModify))
	selection(k, "SecurityKeyServer.SecurityPolicyUri", s.SecurityPolicyURI, s.SecurityPolicyURISelection, flag(s.SecurityPolicyURIModify))
	selection(k, "SecurityKeyServer.ServerUri", s.ServerURI, s.ServerURISelection, flag(s.ServerURIModify))
}

// nullSKS reports whether s is the null SecurityKeyServer of a set without
// SKS configuration (Table F.1). Library interpretation: the field is a
// structure, not an ExtensionObject, and Part 6 §5.2.6 has no null
// structure; the null one is its default value.
func nullSKS(s *uafx.SecurityKeyServerAddressConf) bool {
	return s == nil || s.Address == "" && s.AddressSelection == nil && s.AddressModify == nil &&
		s.SecurityPolicyURI == "" && s.SecurityPolicyURISelection == nil && s.SecurityPolicyURIModify == nil &&
		s.ServerURI == "" && s.ServerURISelection == nil && s.ServerURIModify == nil && !s.UsePushModel &&
		s.SecurityGroups == nil && s.PubSubKeyPushTargets == nil && s.SksProperties == nil
}

// flag returns the value of an optional Modify field: an absent one means
// RestrictToList TRUE (F.1.2.3).
func flag(b *bool) bool { return b != nil && *b }

// selection checks a SelectionList (F.1.2.3). Library interpretation: the
// Selection holds the values a client may choose, the current one among
// them ("the list can contain only the current value"); so with
// RestrictToList TRUE (Modify absent or FALSE) the current value is one of
// a non-empty Selection.
func selection[T comparable](k *checker, path string, cur T, sel []T, modify bool) {
	if len(sel) > 0 && !modify && !slices.Contains(sel, cur) {
		k.add(path, libInterp+": F.1.2.3", "%v is not one of the Selection %v and Modify is not TRUE", cur, sel)
	}
}

// optSelection is selection for an optional field: an absent value is not
// checked.
func optSelection[T comparable](k *checker, path string, cur *T, sel []T, modify bool) {
	if cur != nil {
		selection(k, path, *cur, sel, modify)
	}
}

// address returns the Address of an AddressSelection, nil when absent.
func address(a *uafx.AddressSelection) *ua.ExtensionObject {
	if a == nil || a.Address == nil || a.Address.EncodingMask == ua.ExtensionObjectEmpty {
		return nil
	}
	return a.Address
}

// addressSelection checks the SelectionList of an Address (F.1.2.3).
func addressSelection(k *checker, path string, a *uafx.AddressSelection) {
	cur := address(a)
	if cur == nil || len(a.AddressSelection) == 0 || a.AddressModify {
		return
	}
	want, err := ua.Encode(cur)
	if err != nil {
		k.add(path, "§6.13.3", "the Address cannot be encoded: %v", err)
		return
	}
	for _, s := range a.AddressSelection {
		if b, err := ua.Encode(s); err == nil && bytes.Equal(b, want) {
			return
		}
	}
	k.add(path, libInterp+": F.1.2.3", "not one of the AddressSelection and AddressModify is FALSE")
}

// identifier checks a NodeIdentifier: one of its choices (F.1.15), with
// the namespace indexes in the scope of its server when scoped (F.1.2.2).
func identifier(k *checker, path, clause string, id *uafx.NodeIdentifier, ns namespaceScope, scoped bool) {
	switch {
	case id == nil || id.Node == nil && id.Alias == nil && id.IdentifierBrowsePath == nil:
		k.add(path, clause, "absent or the null NodeIdentifier")
	case id.Node != nil:
		if scoped {
			nodeID(k, path+".Node", "F.1.2.2", id.Node, ns)
		}
	case id.Alias != nil:
		if *id.Alias == "" {
			k.add(path+".Alias", clause, "an empty AliasName")
		}
	default:
		rp := id.IdentifierBrowsePath
		if len(rp.Elements) == 0 {
			k.add(path+".IdentifierBrowsePath", clause, "a RelativePath without elements")
		}
		for j, el := range rp.Elements {
			q := fmt.Sprintf("%s.IdentifierBrowsePath[%d]", path, j)
			if el == nil || el.TargetName == nil || el.TargetName.Name == "" {
				k.add(q, "F.1.15", "an element without a TargetName")
				continue
			}
			if !scoped {
				continue
			}
			if el.ReferenceTypeID != nil {
				nodeID(k, q+".ReferenceTypeId", "F.1.2.2", el.ReferenceTypeID, ns)
			}
			if _, ok := ns.uri(el.TargetName.NamespaceIndex); !ok {
				k.add(q+".TargetName", "F.1.2.2", "the namespace index %d is not in the Namespaces of the ServerAddress", el.TargetName.NamespaceIndex)
			}
		}
	}
}

// nodeID checks that the namespace index of id is in the scope ns.
func nodeID(k *checker, path, clause string, id *ua.NodeID, ns namespaceScope) {
	if _, ok := ns.uri(id.Namespace()); !ok {
		k.add(path, clause, "the namespace index %d is not in the Namespaces of the ServerAddress", id.Namespace())
	}
}

// pairs checks the Keys of NodeIdentifierValuePairs (F.1.16).
func pairs(k *checker, path, clause string, ps []*uafx.NodeIdentifierValuePair, ns namespaceScope, scoped bool) {
	for j, p := range ps {
		q := fmt.Sprintf("%s[%d]", path, j)
		identifier(k, q+".Key", clause, p.Key, ns, scoped)
	}
}

// maybePubSubEndpoint reports whether id may be PubSubConnectionEndpointType
// or a subtype of it: false only for a type of the OPC UA namespace or
// another type of the UAFX AC namespace; a vendor type cannot be told
// before the type hierarchy of the server is read.
func maybePubSubEndpoint(id *ua.NodeID, ns namespaceScope) bool {
	if id == nil {
		return true
	}
	u, ok := ns.uri(id.Namespace())
	switch {
	case !ok:
		return true // has its finding
	case u == uaNamespace:
		return false
	case u == fxacid.NamespaceURI:
		return id.Type() != ua.NodeIDTypeString && id.Type() != ua.NodeIDTypeGUID && id.Type() != ua.NodeIDTypeByteString && id.IntID() == fxacid.PubSubConnectionEndpointType
	}
	return true
}

// sameStructure reports whether a and b, UAFX structures, encode to the
// same bytes.
func sameStructure[T uafx.Structure](a, b T) bool {
	x, err := encoded(a)
	if err != nil {
		return false
	}
	y, err := encoded(b)
	return err == nil && bytes.Equal(x, y)
}

func encoded(v uafx.Structure) ([]byte, error) {
	eo, err := uafx.EncodeStructure(v, cloneNS)
	if err != nil {
		return nil, err
	}
	return eo.Value.([]byte), nil
}
