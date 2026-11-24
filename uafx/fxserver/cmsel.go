// SPDX-License-Identifier: MIT

package fxserver

import (
	"bytes"
	"slices"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// The SelectionListType Variables of a set (OPC 10000-5 §7.18, Part 81
// §6.8.1): the value, its Selections and RestrictToList. A field of the
// set with <Var>Selection and <Var>Modify (F.1.2.3) is shown as it is:
// RestrictToList is TRUE unless <Var>Modify is TRUE. A fixed value, a field
// without Selection, has itself as the only Selection with RestrictToList
// TRUE (§6.8.1). A client may write a value that RestrictToList allows
// while it holds the Lock of the set in edit.

type conf = uafx.ConnectionConfigurationSetConf

// selection is the value of one SelectionList Variable, from a conf.
type selection struct {
	get   func(c *conf) (val, sels any, modify bool)
	write func(c *conf, v *ua.Variant) ua.StatusCode
}

// allowed reports whether v may be written (§6.8.1): any value when
// Modify is TRUE, else one of the Selections, else the value itself.
func allowed[T any](v T, cur *T, sels []T, modify bool, eq func(a, b T) bool) bool {
	if modify {
		return true
	}
	if len(sels) == 0 {
		return cur != nil && eq(v, *cur)
	}
	return slices.ContainsFunc(sels, func(s T) bool { return eq(v, s) })
}

func isTrue(b *bool) bool { return b != nil && *b }

func eqOf[T comparable](a, b T) bool { return a == b }

// scalarSel is a SelectionList of a mandatory field.
func scalarSel[T comparable](get func(c *conf) (*T, []T, *bool), conv func(any) (T, bool)) selection {
	return selection{
		get: func(c *conf) (any, any, bool) {
			p, sels, m := get(c)
			if len(sels) == 0 && !isTrue(m) {
				sels = []T{*p}
			}
			if sels == nil {
				sels = []T{}
			}
			return *p, sels, isTrue(m)
		},
		write: func(c *conf, v *ua.Variant) ua.StatusCode {
			x, ok := conv(v.Value())
			if !ok {
				return ua.StatusBadTypeMismatch
			}
			p, sels, m := get(c)
			if !allowed(x, p, sels, isTrue(m), eqOf[T]) {
				return ua.StatusBadOutOfRange
			}
			*p = x
			return ua.StatusGood
		},
	}
}

// optSel is a SelectionList of an optional field.
func optSel[T comparable](get func(c *conf) (**T, []T, *bool), conv func(any) (T, bool)) selection {
	return selection{
		get: func(c *conf) (any, any, bool) {
			pp, sels, m := get(c)
			if *pp == nil {
				return nil, []T{}, isTrue(m)
			}
			if len(sels) == 0 && !isTrue(m) {
				sels = []T{**pp}
			}
			if sels == nil {
				sels = []T{}
			}
			return **pp, sels, isTrue(m)
		},
		write: func(c *conf, v *ua.Variant) ua.StatusCode {
			x, ok := conv(v.Value())
			if !ok {
				return ua.StatusBadTypeMismatch
			}
			pp, sels, m := get(c)
			if !allowed(x, *pp, sels, isTrue(m), eqOf[T]) {
				return ua.StatusBadOutOfRange
			}
			*pp = &x
			return ua.StatusGood
		},
	}
}

func asString(v any) (string, bool)   { s, ok := v.(string); return s, ok }
func asFloat(v any) (float64, bool)   { f, ok := v.(float64); return f, ok }
func asBool(v any) (bool, bool)       { b, ok := v.(bool); return b, ok }
func asMode(v any) (ua.MessageSecurityMode, bool) {
	switch x := v.(type) {
	case int32:
		return ua.MessageSecurityMode(x), true
	case ua.MessageSecurityMode:
		return x, true
	}
	return 0, false
}

func strSel(get func(c *conf) (*string, []string, *bool)) selection { return scalarSel(get, asString) }
func floatSel(get func(c *conf) (*float64, []float64, *bool)) selection {
	return scalarSel(get, asFloat)
}
func modeSel(get func(c *conf) (*ua.MessageSecurityMode, []ua.MessageSecurityMode, *bool)) selection {
	s := scalarSel(get, asMode)
	return modeValues(s)
}
func optStrSel(get func(c *conf) (**string, []string, *bool)) selection { return optSel(get, asString) }
func optFloatSel(get func(c *conf) (**float64, []float64, *bool)) selection {
	return optSel(get, asFloat)
}
func optModeSel(get func(c *conf) (**ua.MessageSecurityMode, []ua.MessageSecurityMode, *bool)) selection {
	return modeValues(optSel(get, asMode))
}

// modeValues shows MessageSecurityMode values as Int32, the encoding of an
// enumeration (Part 6 §5.2.4).
func modeValues(s selection) selection {
	get := s.get
	s.get = func(c *conf) (any, any, bool) {
		v, sels, m := get(c)
		if x, ok := v.(ua.MessageSecurityMode); ok {
			v = int32(x)
		}
		if xs, ok := sels.([]ua.MessageSecurityMode); ok {
			out := make([]int32, len(xs))
			for i, x := range xs {
				out[i] = int32(x)
			}
			sels = out
		}
		return v, sels, m
	}
	return s
}

// fixedSel is a field the set has no Selection for and that clients do not
// change: its value is its only Selection, RestrictToList TRUE (§6.8.1).
func fixedSel[T comparable](get func(c *conf) T, conv func(any) (T, bool)) selection {
	s := scalarSel(func(c *conf) (*T, []T, *bool) {
		v := get(c)
		return &v, nil, nil
	}, conv)
	s.write = nil
	return s
}

// encoded returns the binary encoding of an ExtensionObject, nil when it
// cannot be encoded.
func encoded(eo *ua.ExtensionObject) []byte {
	b, err := ua.Encode(eo)
	if err != nil {
		return nil
	}
	return b
}

func sameEO(a, b *ua.ExtensionObject) bool {
	x, y := encoded(a), encoded(b)
	return x != nil && bytes.Equal(x, y)
}

// addrSel is the SelectionList of an Address (NetworkAddressDataType).
func addrSel(get func(c *conf) *uafx.AddressSelection) selection {
	return selection{
		get: func(c *conf) (any, any, bool) {
			a := get(c)
			if a == nil {
				return nil, []*ua.ExtensionObject{}, false
			}
			sels := a.AddressSelection
			if len(sels) == 0 && !a.AddressModify && a.Address != nil {
				sels = []*ua.ExtensionObject{a.Address}
			}
			if sels == nil {
				sels = []*ua.ExtensionObject{}
			}
			return a.Address, sels, a.AddressModify
		},
		write: func(c *conf, v *ua.Variant) ua.StatusCode {
			eo, ok := v.Value().(*ua.ExtensionObject)
			if !ok || eo == nil {
				return ua.StatusBadTypeMismatch
			}
			if _, ok := eo.Value.(*ua.NetworkAddressURLDataType); !ok {
				return ua.StatusBadTypeMismatch
			}
			a := get(c)
			if a == nil {
				return ua.StatusBadNotWritable
			}
			if !allowed(eo, &a.Address, a.AddressSelection, a.AddressModify, sameEO) {
				return ua.StatusBadOutOfRange
			}
			a.Address = eo
			return ua.StatusGood
		},
	}
}

// identSel is the SelectionList of a NodeIdentifier field, shown as the
// PortableNodeIdentifier the NodeSet gives the Variable (DataType 3012):
// the NamespaceIndexes of the set are mapped to the NamespaceUris of the
// Namespaces of its ServerAddress (F.1.2.2).
func (p *projector) identSel(get func(c *conf) (**uafx.NodeIdentifier, []*uafx.NodeIdentifier, *bool, []string)) selection {
	idx := p.c.idx()
	enc := func(n *uafx.NodeIdentifier, ns []string) *ua.ExtensionObject {
		if n == nil {
			return nil
		}
		eo, err := uafx.EncodeStructure(toPortable(n, ns), idx)
		if err != nil {
			return nil
		}
		return eo
	}
	same := func(a, b *uafx.NodeIdentifier) bool {
		x, err1 := uafx.EncodeStructure(a, idx)
		y, err2 := uafx.EncodeStructure(b, idx)
		return err1 == nil && err2 == nil && sameEO(x, y)
	}
	return selection{
		get: func(c *conf) (any, any, bool) {
			pp, sels, m, ns := get(c)
			out := []*ua.ExtensionObject{}
			for _, s := range sels {
				out = append(out, enc(s, ns))
			}
			if len(sels) == 0 && !isTrue(m) && *pp != nil {
				out = append(out, enc(*pp, ns))
			}
			return enc(*pp, ns), out, isTrue(m)
		},
		write: func(c *conf, v *ua.Variant) ua.StatusCode {
			eo, ok := v.Value().(*ua.ExtensionObject)
			if !ok || eo == nil {
				return ua.StatusBadTypeMismatch
			}
			s, err := uafx.DecodeStructure(eo, idx)
			pn, ok := s.(*uafx.PortableNodeIdentifier)
			if err != nil || !ok || pn == nil {
				return ua.StatusBadTypeMismatch
			}
			pp, sels, m, ns := get(c)
			n, ok := fromPortable(pn, ns)
			if !ok {
				return ua.StatusBadInvalidArgument
			}
			if !allowed(n, pp, sels, isTrue(m), same) {
				return ua.StatusBadOutOfRange
			}
			*pp = n
			return ua.StatusGood
		},
	}
}

// nsURI is the NamespaceUri of idx in the Namespaces of a ServerAddress:
// index 0 is the OPC UA namespace, also when the array leaves it out
// (library interpretation, as fxcm resolves it).
func nsURI(ns []string, idx uint16) string {
	if idx == 0 {
		return "http://opcfoundation.org/UA/"
	}
	if int(idx) < len(ns) {
		return ns[idx]
	}
	return ""
}

func nsIndex(ns []string, uri string) (uint16, bool) {
	if uri == "http://opcfoundation.org/UA/" || uri == "" {
		return 0, true
	}
	for i, u := range ns {
		if i > 0 && u == uri {
			return uint16(i), true
		}
	}
	return 0, false
}

// toPortable maps a NodeIdentifier of a set to a PortableNodeIdentifier.
func toPortable(n *uafx.NodeIdentifier, ns []string) *uafx.PortableNodeIdentifier {
	switch {
	case n.Node != nil:
		cp := *n.Node
		id := &cp
		_ = id.SetNamespace(0)
		return &uafx.PortableNodeIdentifier{Node: &ua.PortableNodeID{NamespaceURI: nsURI(ns, n.Node.Namespace()), Identifier: id}}
	case n.Alias != nil:
		a := *n.Alias
		return &uafx.PortableNodeIdentifier{Alias: &a}
	case n.IdentifierBrowsePath != nil:
		p := &uafx.PortableRelativePath{}
		for _, e := range n.IdentifierBrowsePath.Elements {
			pe := &uafx.PortableRelativePathElement{IsInverse: e.IsInverse, IncludeSubtypes: e.IncludeSubtypes}
			if e.ReferenceTypeID != nil {
				cp := *e.ReferenceTypeID
				_ = cp.SetNamespace(0)
				pe.ReferenceTypeID = &ua.PortableNodeID{NamespaceURI: nsURI(ns, e.ReferenceTypeID.Namespace()), Identifier: &cp}
			}
			if e.TargetName != nil {
				pe.TargetName = &ua.PortableQualifiedName{NamespaceURI: nsURI(ns, e.TargetName.NamespaceIndex), Name: e.TargetName.Name}
			}
			p.Elements = append(p.Elements, pe)
		}
		return &uafx.PortableNodeIdentifier{IdentifierBrowsePath: p}
	}
	return &uafx.PortableNodeIdentifier{}
}

// fromPortable maps a PortableNodeIdentifier back with the Namespaces of a
// ServerAddress; false when it names a namespace they do not have.
func fromPortable(p *uafx.PortableNodeIdentifier, ns []string) (*uafx.NodeIdentifier, bool) {
	switch {
	case p.Node != nil:
		if p.Node.Identifier == nil {
			return nil, false
		}
		i, ok := nsIndex(ns, p.Node.NamespaceURI)
		if !ok {
			return nil, false
		}
		cp := *p.Node.Identifier
		_ = cp.SetNamespace(i)
		return &uafx.NodeIdentifier{Node: &cp}, true
	case p.Alias != nil:
		a := *p.Alias
		return &uafx.NodeIdentifier{Alias: &a}, true
	case p.IdentifierBrowsePath != nil:
		rp := &ua.RelativePath{}
		for _, e := range p.IdentifierBrowsePath.Elements {
			re := &ua.RelativePathElement{IsInverse: e.IsInverse, IncludeSubtypes: e.IncludeSubtypes}
			if e.ReferenceTypeID != nil && e.ReferenceTypeID.Identifier != nil {
				i, ok := nsIndex(ns, e.ReferenceTypeID.NamespaceURI)
				if !ok {
					return nil, false
				}
				cp := *e.ReferenceTypeID.Identifier
				_ = cp.SetNamespace(i)
				re.ReferenceTypeID = &cp
			}
			if e.TargetName != nil {
				i, ok := nsIndex(ns, e.TargetName.NamespaceURI)
				if !ok {
					return nil, false
				}
				re.TargetName = &ua.QualifiedName{NamespaceIndex: i, Name: e.TargetName.Name}
			}
			rp.Elements = append(rp.Elements, re)
		}
		return &uafx.NodeIdentifier{IdentifierBrowsePath: rp}, true
	}
	return nil, false
}

// namespacesOf is the Namespaces of the ServerAddress of the
// AutomationComponentConfiguration ac of c, nil when there is none.
func namespacesOf(c *conf, ac int32) []string {
	if ac < 0 || int(ac) >= len(c.AutomationComponentConfigurations) {
		return nil
	}
	si := c.AutomationComponentConfigurations[ac].ServerAddressIndex
	if si < 0 || int(si) >= len(c.ServerAddresses) {
		return nil
	}
	return c.ServerAddresses[si].Namespaces
}
