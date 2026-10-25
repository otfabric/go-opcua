// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// buildPushModel serves the ServerConfiguration object of namespace 0
// (Part 12 §7.10.3) with its methods, the TransactionDiagnostics and the
// certificate groups with their trust lists and alarms.
func (s *Server) buildPushModel() error {
	m := s.push
	if m == nil || s.Node(ua.NewNumericNodeID(0, id.ServerConfiguration)) == nil {
		return nil
	}
	set := func(nid uint32, v ValueFunc, dynamic *[]*ua.NodeID) {
		if n := s.ownNode(nid); n != nil {
			n.mu.Lock()
			n.val = v
			n.mu.Unlock()
			if dynamic != nil {
				*dynamic = append(*dynamic, n.ID())
			}
		}
	}
	set(id.ServerConfigurationServerCapabilities, static([]string{"NA"}), nil)
	set(id.ServerConfigurationSupportedPrivateKeyFormats, static([]string{"PEM", "PFX"}), nil)
	set(id.ServerConfigurationMaxTrustListSize, static(m.cfg.MaxTrustListSize), nil)
	set(id.ServerConfigurationMulticastDNSEnabled, static(s.cfg.multicast.enabled), nil)
	set(id.ServerConfigurationApplicationURI, func() *ua.DataValue { return DataValueFromValue(s.cfg.applicationURI) }, nil)
	set(id.ServerConfigurationProductURI, func() *ua.DataValue { return DataValueFromValue(s.applicationDescription().ProductURI) }, nil)
	set(id.ServerConfigurationApplicationType, func() *ua.DataValue {
		return DataValueFromValue(int32(s.applicationDescription().ApplicationType))
	}, nil)
	set(id.ServerConfigurationHasSecureElement, static(false), nil)
	set(id.ServerConfigurationInApplicationSetup, static(false), nil)
	for nid, v := range m.diagnosticsValues() {
		set(nid, v, &m.nodes)
	}

	for _, g := range m.groups {
		d := g.def
		set(d.certTypes, func() *ua.DataValue { return DataValueFromValue(m.groupTypes(g)) }, &g.nodes)
		set(d.size, func() *ua.DataValue { return DataValueFromValue(uint64(g.trust.Load().size)) }, &g.nodes)
		set(d.openCount, func() *ua.DataValue { return DataValueFromValue(uint16(g.openCount.Load())) }, &g.nodes)
		set(d.lastUpdate, func() *ua.DataValue {
			return DataValueFromValue(time.Unix(0, g.lastUpdate.Load()).UTC())
		}, &g.nodes)
		set(d.writable, static(true), nil)
		set(d.userWritable, static(true), nil)
		if f := m.cfg.TrustListUpdateFrequency; f > 0 {
			s.addPushProperty(d.trustList, d.updateFrequency, "UpdateFrequency", id.Duration, static(float64(f)/float64(time.Millisecond)))
		}
	}
	set(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListMaxByteStringLength, static(uint32(maxTrustListRead)), nil)

	type method struct {
		name   string
		method uint32
		h      func(context.Context, *MethodCaller, []*ua.Variant) ([]*ua.Variant, ua.StatusCode)
	}
	register := func(obj uint32, ms []method) {
		for _, x := range ms {
			s.RegisterMethod(ua.NewNumericNodeID(0, obj), ua.NewNumericNodeID(0, x.method), m.method(x.name, x.h))
		}
	}
	// GetCertificates and CreateSelfSignedCertificate are optional and not
	// in the standard node set's ServerConfiguration.
	s.addPushMethod(id.ServerConfigurationGetCertificates, "GetCertificates", id.ServerConfigurationTypeGetCertificates)
	s.addPushMethod(id.ServerConfigurationCreateSelfSignedCertificate, "CreateSelfSignedCertificate", id.ServerConfigurationTypeCreateSelfSignedCertificate)
	register(id.ServerConfiguration, []method{
		{"UpdateCertificate", id.ServerConfigurationUpdateCertificate, m.updateCertificate},
		{"CreateSigningRequest", id.ServerConfigurationCreateSigningRequest, m.createSigningRequest},
		{"CreateSelfSignedCertificate", id.ServerConfigurationCreateSelfSignedCertificate, m.createSelfSignedCertificate},
		{"GetCertificates", id.ServerConfigurationGetCertificates, m.getCertificates},
		{"GetRejectedList", id.ServerConfigurationGetRejectedList, m.getRejectedList},
		{"ApplyChanges", id.ServerConfigurationApplyChanges, m.applyChanges},
		{"CancelChanges", id.ServerConfigurationCancelChanges, m.cancelChanges},
		{"ResetToServerDefaults", id.ServerConfigurationResetToServerDefaults, m.resetToServerDefaults},
	})
	for _, g := range m.groups {
		d := g.def
		gm := func(f func(context.Context, *MethodCaller, *certGroup, []*ua.Variant) ([]*ua.Variant, ua.StatusCode)) func(context.Context, *MethodCaller, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			return func(ctx context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
				return f(ctx, c, g, args)
			}
		}
		register(d.trustList, []method{
			{"Open", d.open, gm(m.fileOpen)},
			{"OpenWithMasks", d.openWithMasks, gm(m.fileOpenWithMasks)},
			{"Close", d.close, gm(m.fileClose)},
			{"Read", d.read, gm(m.fileRead)},
			{"Write", d.write, gm(m.fileWrite)},
			{"GetPosition", d.getPosition, gm(m.fileGetPosition)},
			{"SetPosition", d.setPosition, gm(m.fileSetPosition)},
			{"CloseAndUpdate", d.closeAndUpdate, gm(m.fileCloseAndUpdate)},
			{"AddCertificate", d.addCertificate, gm(m.addCertificate)},
			{"RemoveCertificate", d.removeCertificate, gm(m.removeCertificate)},
		})
	}
	if m.cfg.Alarms != nil {
		if err := m.buildAlarms(); err != nil {
			return fmt.Errorf("server: certificate alarms: %w", err)
		}
	}
	return nil
}

// addPushProperty adds a Property with a standard NodeId to a node of
// ServerConfiguration that the standard node set does not have.
func (s *Server) addPushProperty(parent, nid uint32, name string, dataType uint32, v ValueFunc) {
	p := s.ownNode(parent)
	if p == nil || s.Node(ua.NewNumericNodeID(0, nid)) != nil {
		return
	}
	n := NewNode(ua.NewNumericNodeID(0, nid), Attributes{
		ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: name}),
		ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, dataType)),
		ua.AttributeIDValueRank:       DataValueFromValue(int32(-1)),
		ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
	}, nil, v)
	s.ns0().AddNode(n)
	if t := s.Node(ua.NewNumericNodeID(0, id.PropertyType)); t != nil {
		n.AddRef(t, RefType(id.HasTypeDefinition), true)
	}
	linkChild(p, n, id.HasProperty)
}

// addPushMethod adds a method of ServerConfigurationType to the
// ServerConfiguration object, with the standard NodeId of the instance and
// the arguments of the type's method.
func (s *Server) addPushMethod(nid uint32, name string, decl uint32) {
	obj := s.ownNode(id.ServerConfiguration)
	if obj == nil || s.Node(ua.NewNumericNodeID(0, nid)) != nil {
		return
	}
	mn := NewNode(ua.NewNumericNodeID(0, nid), Attributes{
		ua.AttributeIDNodeClass:      DataValueFromValue(uint32(ua.NodeClassMethod)),
		ua.AttributeIDBrowseName:     DataValueFromValue(&ua.QualifiedName{Name: name}),
		ua.AttributeIDDisplayName:    DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:    DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDExecutable:     DataValueFromValue(true),
		ua.AttributeIDUserExecutable: DataValueFromValue(true),
	}, nil, nil)
	s.ns0().AddNode(mn)
	linkChild(obj, mn, id.HasComponent)
	// The InputArguments and OutputArguments of the instance are those of
	// the declaration, with the NodeIds that follow the method's.
	dn := s.Node(ua.NewNumericNodeID(0, decl))
	if dn == nil {
		return
	}
	next := nid
	for _, name := range []string{"InputArguments", "OutputArguments"} {
		var arg *Node
		for _, r := range dn.refsSnapshot() {
			if r != nil && r.IsForward && r.BrowseName != nil && r.BrowseName.Name == name && r.NodeID != nil {
				arg = s.Node(r.NodeID.NodeID)
			}
		}
		if arg == nil {
			continue
		}
		next++
		dv := arg.Value()
		if dv == nil || dv.Value == nil {
			continue
		}
		s.addArgumentsProperty(mn, next, name, dv.Value)
	}
}

// addArgumentsProperty adds an InputArguments or OutputArguments Property
// to a method node.
func (s *Server) addArgumentsProperty(method *Node, nid uint32, name string, v *ua.Variant) {
	n := NewNode(ua.NewNumericNodeID(0, nid), Attributes{
		ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: name}),
		ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
		ua.AttributeIDValueRank:       DataValueFromValue(int32(1)),
		ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
	}, nil, func() *ua.DataValue { return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v} })
	s.ns0().AddNode(n)
	if t := s.Node(ua.NewNumericNodeID(0, id.PropertyType)); t != nil {
		n.AddRef(t, RefType(id.HasTypeDefinition), true)
	}
	linkChild(method, n, id.HasProperty)
}
