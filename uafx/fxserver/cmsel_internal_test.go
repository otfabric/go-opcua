// SPDX-License-Identifier: MIT

package fxserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

func ptr[T any](v T) *T { return &v }

// TestScalarSel: a mandatory field is written only within RestrictToList
// (OPC 10000-5 §7.18, Part 81 §6.8.1), any value when <Var>Modify is TRUE.
func TestScalarSel(t *testing.T) {
	var v string
	var sels []string
	var modify *bool
	s := strSel(func(*conf) (*string, []string, *bool) { return &v, sels, modify })

	v = "a"
	val, got, m := s.get(nil)
	assert.Equal(t, "a", val)
	assert.Equal(t, []string{"a"}, got, "a fixed value is its own Selection")
	assert.False(t, m)
	assert.Equal(t, ua.StatusBadTypeMismatch, s.write(nil, ua.MustVariant(int32(1))))
	assert.Equal(t, ua.StatusBadOutOfRange, s.write(nil, ua.MustVariant("b")))
	assert.Equal(t, ua.StatusGood, s.write(nil, ua.MustVariant("a")))

	sels = []string{"a", "b"}
	assert.Equal(t, ua.StatusGood, s.write(nil, ua.MustVariant("b")))
	assert.Equal(t, "b", v)
	assert.Equal(t, ua.StatusBadOutOfRange, s.write(nil, ua.MustVariant("c")))

	sels, modify = nil, ptr(true)
	val, got, m = s.get(nil)
	assert.Equal(t, "b", val)
	assert.Equal(t, []string{}, got)
	assert.True(t, m)
	assert.Equal(t, ua.StatusGood, s.write(nil, ua.MustVariant("anything")))
	assert.Equal(t, "anything", v)
}

// TestOptSel: an optional field is null until written; RestrictToList as
// for a mandatory one.
func TestOptSel(t *testing.T) {
	var v *float64
	var sels []float64
	var modify *bool
	s := optFloatSel(func(*conf) (**float64, []float64, *bool) { return &v, sels, modify })

	val, got, _ := s.get(nil)
	assert.Nil(t, val)
	assert.Equal(t, []float64{}, got)
	assert.Equal(t, ua.StatusBadOutOfRange, s.write(nil, ua.MustVariant(1.0)), "no value, no Selection")
	assert.Equal(t, ua.StatusBadTypeMismatch, s.write(nil, ua.MustVariant("x")))

	sels = []float64{1, 2}
	assert.Equal(t, ua.StatusGood, s.write(nil, ua.MustVariant(2.0)))
	require.NotNil(t, v)
	assert.InDelta(t, 2.0, *v, 0)
	val, got, _ = s.get(nil)
	assert.Equal(t, 2.0, val)
	assert.Equal(t, []float64{1, 2}, got)

	sels = nil
	_, got, _ = s.get(nil)
	assert.Equal(t, []float64{2}, got)
	modify = ptr(true)
	_, got, _ = s.get(nil)
	assert.Equal(t, []float64{}, got)

	var str *string
	os := optStrSel(func(*conf) (**string, []string, *bool) { return &str, nil, ptr(true) })
	assert.Equal(t, ua.StatusGood, os.write(nil, ua.MustVariant("x")))
	assert.Equal(t, "x", *str)
}

// TestModeSel: a MessageSecurityMode is shown as Int32 (Part 6 §5.2.4) and
// written as Int32 or as the enumeration.
func TestModeSel(t *testing.T) {
	v := ua.MessageSecurityModeSign
	sels := []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt}
	s := modeSel(func(*conf) (*ua.MessageSecurityMode, []ua.MessageSecurityMode, *bool) { return &v, sels, nil })
	val, got, _ := s.get(nil)
	assert.Equal(t, int32(ua.MessageSecurityModeSign), val)
	assert.Equal(t, []int32{int32(ua.MessageSecurityModeSign), int32(ua.MessageSecurityModeSignAndEncrypt)}, got)
	assert.Equal(t, ua.StatusGood, s.write(nil, ua.MustVariant(int32(ua.MessageSecurityModeSignAndEncrypt))))
	assert.Equal(t, ua.MessageSecurityModeSignAndEncrypt, v)
	assert.Equal(t, ua.StatusBadOutOfRange, s.write(nil, ua.MustVariant(int32(ua.MessageSecurityModeNone))))
	assert.Equal(t, ua.StatusBadTypeMismatch, s.write(nil, ua.MustVariant("x")))

	m, ok := asMode(ua.MessageSecurityModeNone)
	assert.True(t, ok)
	assert.Equal(t, ua.MessageSecurityModeNone, m)

	var o *ua.MessageSecurityMode
	os := optModeSel(func(*conf) (**ua.MessageSecurityMode, []ua.MessageSecurityMode, *bool) { return &o, sels, nil })
	val, got, _ = os.get(nil)
	assert.Nil(t, val)
	assert.Equal(t, []int32{}, got, "a null optional mode has no Selections")
	assert.Equal(t, ua.StatusGood, os.write(nil, ua.MustVariant(int32(ua.MessageSecurityModeSign))))
	val, _, _ = os.get(nil)
	assert.Equal(t, int32(ua.MessageSecurityModeSign), val)
}

// TestFixedSel: a fixed value is read-only, its only Selection itself.
func TestFixedSel(t *testing.T) {
	s := fixedSel(func(*conf) bool { return true }, asBool)
	assert.Nil(t, s.write)
	val, got, m := s.get(nil)
	assert.Equal(t, true, val)
	assert.Equal(t, []bool{true}, got)
	assert.False(t, m)
	_, ok := asBool("x")
	assert.False(t, ok)
}

func urlEO(u string) *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.NetworkAddressURLDataType{NetworkInterface: "eth0", URL: u})
}

// TestAddrSel: an Address is a NetworkAddressUrlDataType within the
// AddressSelection, any one when AddressModify is TRUE.
func TestAddrSel(t *testing.T) {
	var a *uafx.AddressSelection
	s := addrSel(func(*conf) *uafx.AddressSelection { return a })

	val, got, m := s.get(nil)
	assert.Nil(t, val)
	assert.Equal(t, []*ua.ExtensionObject{}, got)
	assert.False(t, m)
	assert.Equal(t, ua.StatusBadNotWritable, s.write(nil, ua.MustVariant(urlEO("opc.udp://239.0.0.1:4840"))))
	assert.Equal(t, ua.StatusBadTypeMismatch, s.write(nil, ua.MustVariant("x")))
	assert.Equal(t, ua.StatusBadTypeMismatch, s.write(nil, ua.MustVariant(ua.NewExtensionObject(&ua.NetworkAddressDataType{NetworkInterface: "eth0"}))))

	a = &uafx.AddressSelection{Address: urlEO("opc.udp://239.0.0.1:4840")}
	_, got, _ = s.get(nil)
	assert.Len(t, got, 1, "a fixed Address is its own Selection")
	assert.Equal(t, ua.StatusBadOutOfRange, s.write(nil, ua.MustVariant(urlEO("opc.udp://239.0.0.2:4840"))))
	assert.Equal(t, ua.StatusGood, s.write(nil, ua.MustVariant(urlEO("opc.udp://239.0.0.1:4840"))))

	a.AddressSelection = []*ua.ExtensionObject{urlEO("opc.udp://239.0.0.1:4840"), urlEO("opc.udp://239.0.0.2:4840")}
	assert.Equal(t, ua.StatusGood, s.write(nil, ua.MustVariant(urlEO("opc.udp://239.0.0.2:4840"))))
	assert.True(t, sameEO(a.Address, urlEO("opc.udp://239.0.0.2:4840")))

	a.AddressSelection, a.AddressModify = nil, true
	_, got, m = s.get(nil)
	assert.Empty(t, got)
	assert.True(t, m)
	assert.Equal(t, ua.StatusGood, s.write(nil, ua.MustVariant(urlEO("opc.udp://239.0.0.9:4840"))))

	assert.False(t, sameEO(&ua.ExtensionObject{EncodingMask: 0xff}, &ua.ExtensionObject{EncodingMask: 0xff}))
}

func testProjector() *projector {
	return &projector{c: &ConnectionManager{ns: Namespaces{Data: 2, AC: 3, CM: 4}}}
}

// TestIdentSel: a NodeIdentifier is shown and written as a
// PortableNodeIdentifier mapped through the Namespaces of the ServerAddress
// (F.1.2.2).
func TestIdentSel(t *testing.T) {
	p := testProjector()
	idx := p.c.idx()
	ns := []string{"http://opcfoundation.org/UA/", "urn:ac"}
	cur := &uafx.NodeIdentifier{Node: ua.NewNumericNodeID(1, 7)}
	var sels []*uafx.NodeIdentifier
	var modify *bool
	s := p.identSel(func(*conf) (**uafx.NodeIdentifier, []*uafx.NodeIdentifier, *bool, []string) {
		return &cur, sels, modify, ns
	})
	enc := func(pn *uafx.PortableNodeIdentifier) *ua.Variant {
		eo, err := uafx.EncodeStructure(pn, idx)
		require.NoError(t, err)
		return ua.MustVariant(eo)
	}
	node := func(uri string, n uint32) *uafx.PortableNodeIdentifier {
		return &uafx.PortableNodeIdentifier{Node: &ua.PortableNodeID{NamespaceURI: uri, Identifier: ua.NewNumericNodeID(0, n)}}
	}

	val, got, m := s.get(nil)
	eo, ok := val.(*ua.ExtensionObject)
	require.True(t, ok)
	dec, err := uafx.DecodeStructure(eo, idx)
	require.NoError(t, err)
	assert.Equal(t, "urn:ac", dec.(*uafx.PortableNodeIdentifier).Node.NamespaceURI)
	assert.Len(t, got, 1)
	assert.False(t, m)

	assert.Equal(t, ua.StatusBadTypeMismatch, s.write(nil, ua.MustVariant("x")))
	assert.Equal(t, ua.StatusBadTypeMismatch, s.write(nil, ua.MustVariant(urlEO("opc.udp://x"))))
	assert.Equal(t, ua.StatusBadInvalidArgument, s.write(nil, enc(node("urn:other", 7))))
	assert.Equal(t, ua.StatusBadOutOfRange, s.write(nil, enc(node("urn:ac", 8))))
	assert.Equal(t, ua.StatusGood, s.write(nil, enc(node("urn:ac", 7))))

	sels = []*uafx.NodeIdentifier{cur, {Alias: ptr("pump")}}
	_, got, _ = s.get(nil)
	assert.Len(t, got, 2)
	assert.Equal(t, ua.StatusGood, s.write(nil, enc(&uafx.PortableNodeIdentifier{Alias: ptr("pump")})))
	assert.Equal(t, "pump", *cur.Alias)

	modify = ptr(true)
	assert.Equal(t, ua.StatusGood, s.write(nil, enc(node("http://opcfoundation.org/UA/", 85))))
	assert.Equal(t, ua.NewNumericNodeID(0, 85).String(), cur.Node.String())

	cur = nil
	val, _, _ = s.get(nil)
	assert.Nil(t, val.(*ua.ExtensionObject))
}

// TestPortable: the mapping of NodeIdentifier to PortableNodeIdentifier
// and back keeps every union member.
func TestPortable(t *testing.T) {
	ns := []string{"", "urn:ac", "urn:types"}
	bp := &uafx.NodeIdentifier{IdentifierBrowsePath: &ua.RelativePath{Elements: []*ua.RelativePathElement{
		{ReferenceTypeID: ua.NewNumericNodeID(0, 47), IncludeSubtypes: true, TargetName: &ua.QualifiedName{NamespaceIndex: 1, Name: "Pump"}},
		{ReferenceTypeID: ua.NewNumericNodeID(2, 5001), IsInverse: true, TargetName: &ua.QualifiedName{NamespaceIndex: 2, Name: "Speed"}},
		{},
	}}}
	for _, n := range []*uafx.NodeIdentifier{
		{Node: ua.NewStringNodeID(1, "x")},
		{Node: ua.NewNumericNodeID(0, 85)},
		{Alias: ptr("pump")},
		bp,
	} {
		p := toPortable(n, ns)
		back, ok := fromPortable(p, ns)
		require.True(t, ok)
		assert.Equal(t, n, back)
	}
	pbp := toPortable(bp, ns).IdentifierBrowsePath
	assert.Equal(t, "urn:types", pbp.Elements[1].ReferenceTypeID.NamespaceURI)
	assert.Equal(t, "urn:ac", pbp.Elements[0].TargetName.NamespaceURI)

	assert.Equal(t, &uafx.PortableNodeIdentifier{}, toPortable(&uafx.NodeIdentifier{}, ns))
	assert.Empty(t, nsURI(ns, 9))

	for name, p := range map[string]*uafx.PortableNodeIdentifier{
		"null":            {},
		"no identifier":   {Node: &ua.PortableNodeID{NamespaceURI: "urn:ac"}},
		"unknown node ns": {Node: &ua.PortableNodeID{NamespaceURI: "urn:x", Identifier: ua.NewNumericNodeID(0, 1)}},
		"unknown ref ns": {IdentifierBrowsePath: &uafx.PortableRelativePath{Elements: []*uafx.PortableRelativePathElement{
			{ReferenceTypeID: &ua.PortableNodeID{NamespaceURI: "urn:x", Identifier: ua.NewNumericNodeID(0, 1)}}}}},
		"unknown name ns": {IdentifierBrowsePath: &uafx.PortableRelativePath{Elements: []*uafx.PortableRelativePathElement{
			{TargetName: &ua.PortableQualifiedName{NamespaceURI: "urn:x", Name: "y"}}}}},
	} {
		_, ok := fromPortable(p, ns)
		assert.False(t, ok, name)
	}
}

// TestNamespacesOf: the Namespaces of the ServerAddress of an AC, nil for
// an index out of range.
func TestNamespacesOf(t *testing.T) {
	c := &conf{
		ServerAddresses: []*uafx.ServerAddressConf{{Namespaces: []string{"", "urn:a"}}},
		AutomationComponentConfigurations: []*uafx.AutomationComponentConfigurationConf{
			{ServerAddressIndex: 0}, {ServerAddressIndex: 5},
		},
	}
	assert.Equal(t, []string{"", "urn:a"}, namespacesOf(c, 0))
	assert.Nil(t, namespacesOf(c, 1))
	assert.Nil(t, namespacesOf(c, -1))
	assert.Nil(t, namespacesOf(c, 2))
}
