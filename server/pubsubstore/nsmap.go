// SPDX-License-Identifier: MIT

package pubsubstore

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// ErrNamespace reports a stored NodeId in a namespace the server does not
// have: the configuration cannot be restored as it was written.
var ErrNamespace = errors.New("pubsubstore: a namespace of the stored configuration is not in the server")

// nsMap maps the namespace indexes of a record written with one
// NamespaceArray to those of another.
type nsMap struct {
	from []string
	m    map[uint16]uint16
}

func newNSMap(from, to []string) *nsMap {
	r := &nsMap{from: from, m: map[uint16]uint16{}}
	idx := map[string]int{}
	for i, u := range to {
		if _, ok := idx[u]; !ok {
			idx[u] = i
		}
	}
	for i, u := range from {
		if j, ok := idx[u]; ok && i <= math.MaxUint16 && j <= math.MaxUint16 {
			r.m[uint16(i)] = uint16(j)
		}
	}
	return r
}

var (
	nodeIDType   = reflect.TypeFor[ua.NodeID]()
	expandedType = reflect.TypeFor[ua.ExpandedNodeID]()
	variantType  = reflect.TypeFor[ua.Variant]()
	timeType     = reflect.TypeFor[time.Time]()
)

// maxDepth bounds the nesting the walk follows.
const maxDepth = 64

// remap rewrites, in place, the namespace index of every NodeId reachable
// from v: in structures, slices, ExtensionObjects and Variants. An
// ExpandedNodeId with a NamespaceUri or a ServerIndex is left alone. It
// fails with
// ErrNamespace for an index whose URI the target does not have.
func (r *nsMap) remap(v any) error {
	var walk func(rv reflect.Value, depth int) error
	walk = func(rv reflect.Value, depth int) error {
		if depth > maxDepth {
			return corrupt("nested too deeply")
		}
		switch rv.Kind() {
		case reflect.Pointer:
			if rv.IsNil() {
				return nil
			}
			switch rv.Type().Elem() {
			case nodeIDType:
				return r.node(rv)
			case expandedType:
				e := rv.Interface().(*ua.ExpandedNodeID)
				if e.NamespaceURI != "" || e.ServerIndex != 0 {
					return nil
				}
				return walk(rv.Elem().FieldByName("NodeID"), depth+1)
			case variantType:
				if x := rv.Interface().(*ua.Variant).Value(); x != nil {
					return walk(reflect.ValueOf(x), depth+1)
				}
				return nil
			}
			return walk(rv.Elem(), depth+1)
		case reflect.Interface:
			if rv.IsNil() {
				return nil
			}
			return walk(rv.Elem(), depth+1)
		case reflect.Struct:
			if rv.Type() == timeType {
				return nil
			}
			t := rv.Type()
			for i := range rv.NumField() {
				if !t.Field(i).IsExported() {
					continue
				}
				if err := walk(rv.Field(i), depth+1); err != nil {
					return err
				}
			}
		case reflect.Slice:
			if rv.Type().Elem().Kind() == reflect.Uint8 {
				return nil
			}
			for i := range rv.Len() {
				if err := walk(rv.Index(i), depth+1); err != nil {
					return err
				}
			}
		default:
		}
		return nil
	}
	return walk(reflect.ValueOf(v), 0)
}

// node remaps the NodeId rv points to. A TwoByte or FourByte NodeId that
// cannot hold the new index is replaced by a Numeric one when rv can be
// set.
func (r *nsMap) node(rv reflect.Value) error {
	n := rv.Interface().(*ua.NodeID)
	ns := n.Namespace()
	to, ok := r.m[ns]
	switch {
	case !ok && int(ns) < len(r.from):
		return fmt.Errorf("%w: %q", ErrNamespace, r.from[ns])
	case !ok:
		return corrupt("a NodeId in namespace %d, which its record does not have", ns)
	case to == ns:
		return nil
	}
	if err := n.SetNamespace(to); err == nil {
		return nil
	}
	if !rv.CanSet() {
		return fmt.Errorf("pubsubstore: the NodeId %v cannot take the namespace index %d", n, to)
	}
	rv.Set(reflect.ValueOf(ua.NewNumericNodeID(to, n.IntID())))
	return nil
}
