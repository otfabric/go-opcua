// SPDX-License-Identifier: MIT

package fxserver

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// The records of the persistent ConnectionEndpoints in the "ac" namespace of
// the store (design §4.2). Keys:
//
//	ep/<ac>/<endpoint>  a persistent endpoint
//	pc/<component>      a PubSub component a persistent endpoint references
//	q/<ac>/<endpoint>   a quarantined endpoint record
//
// <ac>, <endpoint> and <component> are hex SHA-256 prefixes of the
// URI-qualified NodeIds and component paths, so that a key never depends on
// a namespace index. The values carry the NamespaceArray they were written
// with; their NodeIds are remapped to the current one at load (design
// §4.8).

// recordSchema is the schema of the records (fxstore.DomainOptions.Schema).
const recordSchema = 1

// Endpoint states in a record (design §4.4).
const (
	stateActive        uint8 = 1
	stateRemovePending uint8 = 2
)

// Provenance of a component (design §4.2).
const (
	provCreated       uint8 = 1 // an EstablishConnections call added it
	provPreconfigured uint8 = 2 // it existed before, configured by the application
	provAdopted       uint8 = 3 // it existed before, from another mechanism
)

// epIdentity is the identity header of an endpoint record: what a
// quarantine must reserve. It decodes on its own, with its own checksum, so
// that a corrupt body still tells the identities (design §4.7).
type epIdentity struct {
	Namespaces       []string
	AC               *ua.NodeID
	Endpoint         *ua.NodeID
	FunctionalEntity *ua.NodeID
	Name             string
	// Nodes are the nodes created for the endpoint, the endpoint first.
	Nodes            []*ua.NodeID
	WriterGroupIDs   []uint16
	DataSetWriterIDs []uint16
	// Components are the keys of the component records it references.
	Components []string
	// Paths are the paths of those components ("kind/conn/group/name").
	Paths []string
}

// epBody is the rest of an endpoint record.
type epBody struct {
	State         uint8
	Enabled       bool
	Preconfigured bool
	Folder        *ua.NodeID
	Mode          int32
	Inputs        []*ua.NodeID
	Outputs       []*ua.NodeID
	// Related is the RelatedEndpoint as encoded in its Variable.
	Related              []byte
	CleanupTimeout       float64
	ConnectionManagerURI string
	CreationTime         time.Time
	ModificationTime     time.Time
	// ControlGroups are the ControlGroups the endpoint controls.
	ControlGroups []*ua.NodeID
	// Reader and Writer are the component keys of its DataSetReader and
	// DataSetWriter, "" for none.
	Reader, Writer string
	// OwnReader and OwnWriter are kept for the record format; a restore
	// takes the ownership from the Provenance of the component record,
	// which every endpoint that references it shares.
	OwnReader, OwnWriter bool
}

// compRecord is the record of a PubSub component.
type compRecord struct {
	Namespaces []string
	Kind       uint8
	// Path is the names from the PubSubConnection down (a
	// PublishedDataSet: its Name).
	Path []string
	// Config is the configuration of the component without its children,
	// Enabled cleared: enablement follows the endpoints.
	Config     *ua.ExtensionObject
	Provenance uint8
	// Refs are the keys of the endpoint records that reference it.
	Refs []string
	// Removed: another configuration mechanism removed it; it is not
	// re-created (design §4.5).
	Removed bool
}

const recordFormat = 1

var crcTable = crc32.MakeTable(crc32.Castagnoli)

var errRecord = errors.New("fxserver: corrupt record")

// appendPart appends a length-prefixed, checksummed part.
func appendPart(b, part []byte) []byte {
	if uint64(len(part)) > math.MaxUint32 {
		panic("fxserver: record part too large")
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(part)))
	b = append(b, part...)
	return binary.LittleEndian.AppendUint32(b, crc32.Checksum(part, crcTable))
}

// readPart reads a part appended by appendPart.
func readPart(b []byte) (part, rest []byte, err error) {
	if len(b) < 8 {
		return nil, nil, fmt.Errorf("%w: truncated", errRecord)
	}
	n := binary.LittleEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-8) {
		return nil, nil, fmt.Errorf("%w: truncated", errRecord)
	}
	part, rest = b[4:4+n], b[4+n:]
	if crc32.Checksum(part, crcTable) != binary.LittleEndian.Uint32(rest) {
		return nil, nil, fmt.Errorf("%w: checksum", errRecord)
	}
	return part, rest[4:], nil
}

func encodeEndpoint(id *epIdentity, body *epBody) ([]byte, error) {
	ib, err := ua.Encode(id)
	if err != nil {
		return nil, err
	}
	bb, err := ua.Encode(body)
	if err != nil {
		return nil, err
	}
	return appendPart(appendPart([]byte{recordFormat}, ib), bb), nil
}

// decodeIdentity decodes the identity header of an endpoint record.
func decodeIdentity(v []byte) (*epIdentity, []byte, error) {
	if len(v) < 1 || v[0] != recordFormat {
		return nil, nil, fmt.Errorf("%w: format", errRecord)
	}
	ib, rest, err := readPart(v[1:])
	if err != nil {
		return nil, nil, err
	}
	id := new(epIdentity)
	if err := decodeExact(ib, id); err != nil {
		return nil, nil, err
	}
	return id, rest, nil
}

// decodeEndpoint decodes an endpoint record; id is set when the identity
// header decodes, whatever the body.
func decodeEndpoint(v []byte) (id *epIdentity, body *epBody, err error) {
	id, rest, err := decodeIdentity(v)
	if err != nil {
		return nil, nil, err
	}
	bb, rest, err := readPart(rest)
	if err != nil {
		return id, nil, err
	}
	if len(rest) != 0 {
		return id, nil, fmt.Errorf("%w: trailing data", errRecord)
	}
	body = new(epBody)
	if err := decodeExact(bb, body); err != nil {
		return id, nil, err
	}
	return id, body, nil
}

func encodeComponent(r *compRecord) ([]byte, error) {
	b, err := ua.Encode(r)
	if err != nil {
		return nil, err
	}
	return appendPart([]byte{recordFormat}, b), nil
}

func decodeComponent(v []byte) (*compRecord, error) {
	if len(v) < 1 || v[0] != recordFormat {
		return nil, fmt.Errorf("%w: format", errRecord)
	}
	b, rest, err := readPart(v[1:])
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing data", errRecord)
	}
	r := new(compRecord)
	if err := decodeExact(b, r); err != nil {
		return nil, err
	}
	return r, nil
}

// decodeExact decodes b into v and fails unless it takes all of b.
func decodeExact(b []byte, v any) (err error) {
	defer func() {
		// The reflective decoder must not take the server down on a
		// hostile record.
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", errRecord, r)
		}
	}()
	n, err := ua.Decode(b, v)
	if err != nil {
		return fmt.Errorf("%w: %w", errRecord, err)
	}
	if n != len(b) {
		return fmt.Errorf("%w: %d bytes left", errRecord, len(b)-n)
	}
	return nil
}

// --- keys -----------------------------------------------------------------

// qualified returns n with its namespace URI instead of its index, "" when
// the index has no URI in namespaces.
func qualified(n *ua.NodeID, namespaces []string) string {
	if n == nil {
		return ""
	}
	ns := int(n.Namespace())
	if ns >= len(namespaces) {
		return ""
	}
	s := n.String()
	if strings.HasPrefix(s, "ns=") {
		if i := strings.IndexByte(s, ';'); i >= 0 {
			s = s[i+1:]
		}
	}
	return namespaces[ns] + "|" + s
}

func hashKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = fmt.Fprintf(h, "%d:%s", len(p), p) // a hash.Hash never fails a write
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// endpointKey is the key of the record of endpoint ep of the
// AutomationComponent ac, without its "ep/" or "q/" prefix.
func endpointKey(ac, ep *ua.NodeID, namespaces []string) string {
	return hashKey(qualified(ac, namespaces)) + "/" + hashKey(qualified(ep, namespaces))
}

// acOfKey returns the AutomationComponent part of an endpoint key.
func acOfKey(k string) string {
	if i := strings.IndexByte(k, '/'); i > 0 {
		return k[:i]
	}
	return ""
}

// componentPath is the path of a component: its kind and names.
func componentPath(kind pubsub.ComponentKind, names ...string) string {
	return kind.String() + "/" + strings.Join(names, "/")
}

func componentKey(path string) string { return hashKey(path) }

// --- namespaces -----------------------------------------------------------

// errNamespace reports a record that uses a namespace the server no longer
// has.
var errNamespace = errors.New("fxserver: a namespace of the record is not in the server")

// remapper maps the namespace indexes of a record written with the
// NamespaceArray from to the server's NamespaceArray to.
type remapper struct {
	m    map[uint16]uint16
	miss map[uint16]bool
	// used, when set, collects the missing indexes the NodeIds use
	// instead of failing.
	used map[uint16]bool
}

func newRemapper(from, to []string) *remapper {
	r := &remapper{m: map[uint16]uint16{}, miss: map[uint16]bool{}}
	idx := map[string]int{}
	for i, u := range to {
		if _, ok := idx[u]; !ok {
			idx[u] = i
		}
	}
	for i, u := range from {
		if i > math.MaxUint16 {
			break
		}
		if j, ok := idx[u]; ok && j <= math.MaxUint16 {
			r.m[uint16(i)] = uint16(j)
		} else {
			r.miss[uint16(i)] = true
		}
	}
	return r
}

// identity reports whether the remap changes nothing.
func (r *remapper) identity() bool {
	for k, v := range r.m {
		if k != v {
			return false
		}
	}
	return len(r.miss) == 0
}

var (
	nodeIDType   = reflect.TypeFor[ua.NodeID]()
	expandedType = reflect.TypeFor[ua.ExpandedNodeID]()
	variantType  = reflect.TypeFor[ua.Variant]()
	timeType     = reflect.TypeFor[time.Time]()
)

// remap rewrites, in place, the namespace index of every NodeId reachable
// from v: in structures, slices, ExtensionObjects and Variants, the
// NodeIds nested in PubSub configurations included. An ExpandedNodeId with
// a NamespaceUri or a ServerIndex is left alone. It fails with errNamespace
// when a NodeId uses an index whose URI the server does not have.
func (r *remapper) remap(v any) error {
	seen := map[uintptr]bool{}
	var walk func(rv reflect.Value, depth int) error
	walk = func(rv reflect.Value, depth int) error {
		if depth > 64 {
			return fmt.Errorf("%w: nested too deeply", errRecord)
		}
		switch rv.Kind() {
		case reflect.Pointer:
			if rv.IsNil() {
				return nil
			}
			if seen[rv.Pointer()] {
				return nil
			}
			seen[rv.Pointer()] = true
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
			if rv.Type() == timeType || rv.Type() == nodeIDType {
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
		case reflect.Slice, reflect.Array:
			if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8 {
				return nil
			}
			for i := range rv.Len() {
				if err := walk(rv.Index(i), depth+1); err != nil {
					return err
				}
			}
		case reflect.Map:
			it := rv.MapRange()
			for it.Next() {
				if err := walk(it.Value(), depth+1); err != nil {
					return err
				}
			}
		default:
		}
		return nil
	}
	return walk(reflect.ValueOf(v), 0)
}

// node remaps the NodeId rv points to; a NodeId whose encoding cannot hold
// the new index is replaced when rv can be set.
func (r *remapper) node(rv reflect.Value) error {
	n := rv.Interface().(*ua.NodeID)
	ns := n.Namespace()
	to, ok := r.m[ns]
	if r.miss[ns] || !ok {
		if r.used != nil {
			r.used[ns] = true
			return nil
		}
		return fmt.Errorf("%w: index %d", errNamespace, ns)
	}
	if to == ns {
		return nil
	}
	if err := n.SetNamespace(to); err == nil {
		return nil
	}
	m := withNamespace(n, to)
	if m == nil || !rv.CanSet() {
		return fmt.Errorf("%w: NodeId %v cannot take namespace %d", errRecord, n, to)
	}
	rv.Set(reflect.ValueOf(m))
	return nil
}

// usedMissing returns the URIs of the namespaces of from, the
// NamespaceArray the values vs were written with, that the NodeIds of vs
// use and to does not have. It changes vs.
func usedMissing(from, to []string, vs ...any) []string {
	r := newRemapper(from, to)
	r.used = map[uint16]bool{}
	for _, v := range vs {
		_ = r.remap(v)
	}
	var out []string
	for i, u := range from {
		if i <= math.MaxUint16 && r.used[uint16(i)] {
			out = append(out, u)
		}
	}
	return out
}

// withNamespace returns n in the namespace ns, in an encoding that holds it.
func withNamespace(n *ua.NodeID, ns uint16) *ua.NodeID {
	switch n.Type() {
	case ua.NodeIDTypeTwoByte, ua.NodeIDTypeFourByte, ua.NodeIDTypeNumeric:
		return ua.NewNumericNodeID(ns, n.IntID())
	case ua.NodeIDTypeString:
		return ua.NewStringNodeID(ns, n.StringID())
	case ua.NodeIDTypeGUID:
		return ua.NewGUIDNodeID(ns, n.StringID())
	case ua.NodeIDTypeByteString:
		return ua.NewByteStringNodeID(ns, []byte(n.StringID()))
	}
	return nil
}

// relatedOf decodes a RelatedEndpoint as encoded in an endpoint record.
func relatedOf(b []byte) (*uafx.RelatedEndpoint, error) {
	r := new(uafx.RelatedEndpoint)
	if err := decodeExact(b, r); err != nil {
		return nil, err
	}
	return r, nil
}
