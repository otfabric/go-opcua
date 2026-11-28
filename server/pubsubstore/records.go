// SPDX-License-Identifier: MIT

package pubsubstore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// encode is ua.Encode, replaced by the tests to inject a failure.
var encode = ua.Encode

// recordFormat is the format byte of the records.
const recordFormat = 1

// Record keys.
const (
	rootKey    = "root"
	pdsPrefix  = "pds/"
	connPrefix = "conn/"
)

// nameKey returns the key of the record of the PublishedDataSet or
// PubSubConnection named name: prefix and the first 16 bytes of the
// SHA-256 of the name in hexadecimal, so that a key has a fixed length
// whatever the name (the record holds the name).
func nameKey(prefix, name string) string {
	h := sha256.Sum256([]byte(name))
	return prefix + hex.EncodeToString(h[:16])
}

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: pubsubstore: %s", fxstore.ErrCorrupt, fmt.Sprintf(format, args...))
}

// root is the root record: the Enabled of PublishSubscribe and the names of
// the PublishedDataSets and PubSubConnections in their order.
type root struct {
	enabled bool
	pds     []string
	conns   []string
}

func appendString(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func appendStrings(b []byte, ss []string) []byte {
	b = binary.AppendUvarint(b, uint64(len(ss)))
	for _, s := range ss {
		b = appendString(b, s)
	}
	return b
}

// reader reads the fields of an untrusted record.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) uvarint() uint64 {
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.bad = true
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *reader) string() string {
	n := r.uvarint()
	if r.bad || n > uint64(len(r.b)) {
		r.bad = true
		return ""
	}
	s := string(r.b[:n])
	r.b = r.b[n:]
	return s
}

// strings reads a count and as many strings. Each takes a byte at least,
// so the count is bounded by what is left before anything is allocated.
func (r *reader) strings() []string {
	n := r.uvarint()
	if r.bad || n > uint64(len(r.b)) {
		r.bad = true
		return nil
	}
	out := make([]string, 0, n)
	for range n {
		out = append(out, r.string())
	}
	return out
}

func (x root) encode() []byte {
	b := []byte{recordFormat, 0}
	if x.enabled {
		b[1] = 1
	}
	b = appendStrings(b, x.pds)
	return appendStrings(b, x.conns)
}

func decodeRoot(b []byte) (root, error) {
	var x root
	if len(b) < 2 || b[0] != recordFormat || b[1] > 1 {
		return x, corrupt("the root record")
	}
	x.enabled = b[1] == 1
	r := &reader{b: b[2:]}
	x.pds, x.conns = r.strings(), r.strings()
	if r.bad || len(r.b) != 0 {
		return root{}, corrupt("the root record")
	}
	return x, nil
}

// encodeComponent returns the record of a PublishedDataSet or a
// PubSubConnection: the format byte, the NamespaceArray its NodeIds are in
// and the component in the OPC UA Binary encoding (Part 6 §5.2).
func encodeComponent(v any, namespaces []string) ([]byte, error) {
	body, err := encode(v)
	if err != nil {
		return nil, err
	}
	b := appendStrings([]byte{recordFormat}, namespaces)
	return append(b, body...), nil
}

// decodeComponent decodes the record of a PublishedDataSet or a
// PubSubConnection into v, exactly, and returns its NamespaceArray. The
// record is untrusted: the bytes of a file.
func decodeComponent(b []byte, v any) ([]string, error) {
	if len(b) < 1 || b[0] != recordFormat {
		return nil, corrupt("a component record")
	}
	r := &reader{b: b[1:]}
	ns := r.strings()
	if r.bad {
		return nil, corrupt("a component record")
	}
	n, err := ua.Decode(r.b, v)
	if err != nil || n != len(r.b) {
		return nil, corrupt("a component record")
	}
	return ns, nil
}

// stored is the decoded state of the domain: the components with the
// NamespaceArray of their record.
type stored struct {
	root  root
	pds   []*ua.PublishedDataSetDataType
	pdsNS [][]string
	conns []*ua.PubSubConnectionDataType
	cnNS  [][]string
}

// decodeState decodes the records of the domain. A store without records
// holds no configuration (nil). Records without the root record, a record
// the root does not name or a name without its record, a record under a
// key that is not its name's, and a configuration that is not valid
// (pubsub.Validate) are corrupt.
func decodeState(state map[string][]byte) (*stored, error) {
	if len(state) == 0 {
		return nil, nil
	}
	rv, ok := state[rootKey]
	if !ok {
		return nil, corrupt("records without the root record")
	}
	rt, err := decodeRoot(rv)
	if err != nil {
		return nil, err
	}
	st := &stored{root: rt}
	seen := map[string]bool{rootKey: true}
	for _, name := range rt.pds {
		k := nameKey(pdsPrefix, name)
		d := new(ua.PublishedDataSetDataType)
		ns, err := decodeNamed(state, seen, k, d)
		if err != nil {
			return nil, err
		}
		if d.Name != name {
			return nil, corrupt("the record %q holds %q, not %q", k, d.Name, name)
		}
		st.pds, st.pdsNS = append(st.pds, d), append(st.pdsNS, ns)
	}
	for _, name := range rt.conns {
		k := nameKey(connPrefix, name)
		c := new(ua.PubSubConnectionDataType)
		ns, err := decodeNamed(state, seen, k, c)
		if err != nil {
			return nil, err
		}
		if c.Name != name {
			return nil, corrupt("the record %q holds %q, not %q", k, c.Name, name)
		}
		st.conns, st.cnNS = append(st.conns, c), append(st.cnNS, ns)
	}
	if len(seen) != len(state) {
		for _, k := range slices.Sorted(maps.Keys(state)) {
			if !seen[k] {
				return nil, corrupt("the record %q is not in the root record", k)
			}
		}
	}
	if err := pubsub.Validate(st.config()); err != nil {
		return nil, corrupt("the stored configuration: %v", err)
	}
	return st, nil
}

// decodeNamed decodes the record of key k, once.
func decodeNamed(state map[string][]byte, seen map[string]bool, k string, v any) ([]string, error) {
	b, ok := state[k]
	if !ok || seen[k] {
		return nil, corrupt("the root record names %q twice or without its record", k)
	}
	seen[k] = true
	ns, err := decodeComponent(b, v)
	if err != nil {
		return nil, fmt.Errorf("%w: record %q", err, k)
	}
	return ns, nil
}

// config returns the configuration of st, its NodeIds as stored.
func (st *stored) config() *ua.PubSubConfigurationDataType {
	return &ua.PubSubConfigurationDataType{Enabled: st.root.enabled, PublishedDataSets: st.pds, Connections: st.conns}
}

// records returns the records of cfg, its NodeIds in namespaces.
func records(cfg *ua.PubSubConfigurationDataType, namespaces []string) (map[string][]byte, error) {
	out := map[string][]byte{}
	rt := root{enabled: cfg.Enabled}
	for _, d := range cfg.PublishedDataSets {
		v, err := encodeComponent(d, namespaces)
		if err != nil {
			return nil, fmt.Errorf("pubsubstore: encode the PublishedDataSet %q: %w", d.Name, err)
		}
		out[nameKey(pdsPrefix, d.Name)] = v
		rt.pds = append(rt.pds, d.Name)
	}
	for _, c := range cfg.Connections {
		v, err := encodeComponent(c, namespaces)
		if err != nil {
			return nil, fmt.Errorf("pubsubstore: encode the PubSubConnection %q: %w", c.Name, err)
		}
		out[nameKey(connPrefix, c.Name)] = v
		rt.conns = append(rt.conns, c.Name)
	}
	out[rootKey] = rt.encode()
	return out, nil
}
