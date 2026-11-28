// SPDX-License-Identifier: MIT

package rolestore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// ErrNamespace reports a stored role in a namespace the server does not
// have: the role cannot be restored as it was written.
var ErrNamespace = errors.New("rolestore: a namespace of the stored roles is not in the server")

// encode is ua.Encode, replaced by the tests to inject a failure.
var encode = ua.Encode

// recordFormat is the format byte of the records.
const recordFormat = 1

// Record keys.
const (
	rootKey    = "root"
	rolePrefix = "role/"
)

// The flags of a role record.
const (
	flagRemovable = 1 << iota
	flagAppsExclude
	flagEndpointsExclude
	flagsAll = flagRemovable | flagAppsExclude | flagEndpointsExclude
)

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: rolestore: %s", fxstore.ErrCorrupt, fmt.Sprintf(format, args...))
}

// body is the part of a role record in the OPC UA Binary encoding: the
// NodeId and BrowseName in namespace 0 (their namespaces are URIs before
// it) and the configuration.
type body struct {
	NodeID       *ua.NodeID
	BrowseName   string
	Identities   []*ua.IdentityMappingRuleType
	Applications []string
	Endpoints    []*ua.EndpointType
}

// record is a decoded role record.
type record struct {
	flags  byte
	nodeNS string // the namespace URI of the NodeId
	nameNS string // the namespace URI of the BrowseName
	b      body
}

// roleKey returns the key of the record of the role with the NodeId nid,
// in namespace 0, of the namespace uri: the first 16 bytes of the SHA-256
// of the URI and the NodeId, in hexadecimal, so that a key has a fixed
// length and does not depend on the namespace index.
func roleKey(uri string, nid *ua.NodeID) string {
	h := sha256.Sum256([]byte(uri + "\n" + nid.String()))
	return rolePrefix + hex.EncodeToString(h[:16])
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

// encodeRoot returns the root record: the format byte and the keys of the
// role records in the order of the roles.
func encodeRoot(keys []string) []byte {
	return appendStrings([]byte{recordFormat}, keys)
}

func decodeRoot(b []byte) ([]string, error) {
	if len(b) < 1 || b[0] != recordFormat {
		return nil, corrupt("the root record")
	}
	r := &reader{b: b[1:]}
	keys := r.strings()
	if r.bad || len(r.b) != 0 {
		return nil, corrupt("the root record")
	}
	return keys, nil
}

func (x *record) encode() ([]byte, error) {
	v, err := encode(&x.b)
	if err != nil {
		return nil, err
	}
	b := []byte{recordFormat, x.flags}
	b = appendString(b, x.nodeNS)
	b = appendString(b, x.nameNS)
	return append(b, v...), nil
}

// decodeRecord decodes a role record, exactly. The record is untrusted:
// the bytes of a file.
func decodeRecord(b []byte) (*record, error) {
	if len(b) < 2 || b[0] != recordFormat || b[1]&^flagsAll != 0 {
		return nil, corrupt("a role record")
	}
	x := &record{flags: b[1]}
	r := &reader{b: b[2:]}
	x.nodeNS, x.nameNS = r.string(), r.string()
	if r.bad {
		return nil, corrupt("a role record")
	}
	n, err := ua.Decode(r.b, &x.b)
	if err != nil || n != len(r.b) || x.b.NodeID.Namespace() != 0 || x.b.BrowseName == "" {
		return nil, corrupt("a role record")
	}
	return x, nil
}

// decodeState decodes the records of the domain into the role records in
// their order. A store without records holds no roles (nil). Records
// without the root record, a record the root does not name or a key it
// names without its record or twice, and a record under a key that is not
// that of its role are corrupt.
func decodeState(state map[string][]byte) ([]*record, error) {
	if len(state) == 0 {
		return nil, nil
	}
	rv, ok := state[rootKey]
	if !ok {
		return nil, corrupt("records without the root record")
	}
	keys, err := decodeRoot(rv)
	if err != nil {
		return nil, err
	}
	out := make([]*record, 0, len(keys))
	seen := map[string]bool{rootKey: true}
	for _, k := range keys {
		b, ok := state[k]
		if !ok || seen[k] {
			return nil, corrupt("the root record names %q twice or without its record", k)
		}
		seen[k] = true
		x, err := decodeRecord(b)
		if err != nil {
			return nil, fmt.Errorf("%w: record %q", err, k)
		}
		if roleKey(x.nodeNS, x.b.NodeID) != k {
			return nil, corrupt("the record %q holds the role %v of %q", k, x.b.NodeID, x.nodeNS)
		}
		out = append(out, x)
	}
	if len(seen) != len(state) {
		for _, k := range slices.Sorted(maps.Keys(state)) {
			if !seen[k] {
				return nil, corrupt("the record %q is not in the root record", k)
			}
		}
	}
	return out, nil
}

// uriOf returns the namespace URI of the index ns of namespaces.
func uriOf(namespaces []string, ns uint16, what string) (string, error) {
	if int(ns) >= len(namespaces) {
		return "", fmt.Errorf("rolestore: the %s is in namespace %d, which the NamespaceArray does not have", what, ns)
	}
	return namespaces[ns], nil
}

// records returns the records of roles, their NodeIds and BrowseNames in
// namespaces.
func records(roles []server.Role, namespaces []string) (map[string][]byte, error) {
	out := map[string][]byte{}
	keys := make([]string, 0, len(roles))
	for _, r := range roles {
		if r.NodeID == nil || r.BrowseName == nil || r.BrowseName.Name == "" {
			return nil, errors.New("rolestore: a role without NodeId or BrowseName")
		}
		nodeNS, err := uriOf(namespaces, r.NodeID.Namespace(), "NodeId of a role")
		if err != nil {
			return nil, err
		}
		nameNS, err := uriOf(namespaces, r.BrowseName.NamespaceIndex, "BrowseName of a role")
		if err != nil {
			return nil, err
		}
		x := &record{nodeNS: nodeNS, nameNS: nameNS, b: body{
			NodeID: withNamespace(r.NodeID, 0), BrowseName: r.BrowseName.Name,
			Identities: r.Identities, Applications: r.Applications, Endpoints: r.Endpoints,
		}}
		if r.Removable {
			x.flags |= flagRemovable
		}
		if r.ApplicationsExclude {
			x.flags |= flagAppsExclude
		}
		if r.EndpointsExclude {
			x.flags |= flagEndpointsExclude
		}
		k := roleKey(nodeNS, x.b.NodeID)
		if _, ok := out[k]; ok {
			return nil, fmt.Errorf("rolestore: the role %v twice", r.NodeID)
		}
		v, err := x.encode()
		if err != nil {
			return nil, fmt.Errorf("rolestore: encode the role %v: %w", r.NodeID, err)
		}
		out[k] = v
		keys = append(keys, k)
	}
	out[rootKey] = encodeRoot(keys)
	return out, nil
}

// role returns the role of the record x with its NodeId and BrowseName in
// namespaces: ErrNamespace when namespaces does not have one of its URIs.
func (x *record) role(namespaces []string) (server.Role, error) {
	nodeNS, ok := indexOf(namespaces, x.nodeNS)
	if !ok {
		return server.Role{}, fmt.Errorf("%w: %q", ErrNamespace, x.nodeNS)
	}
	nameNS, ok := indexOf(namespaces, x.nameNS)
	if !ok {
		return server.Role{}, fmt.Errorf("%w: %q", ErrNamespace, x.nameNS)
	}
	return server.Role{
		NodeID:              withNamespace(x.b.NodeID, nodeNS),
		BrowseName:          &ua.QualifiedName{NamespaceIndex: nameNS, Name: x.b.BrowseName},
		Identities:          x.b.Identities,
		Applications:        x.b.Applications,
		ApplicationsExclude: x.flags&flagAppsExclude != 0,
		Endpoints:           x.b.Endpoints,
		EndpointsExclude:    x.flags&flagEndpointsExclude != 0,
		Removable:           x.flags&flagRemovable != 0,
	}, nil
}

// indexOf returns the first index of uri in namespaces.
func indexOf(namespaces []string, uri string) (uint16, bool) {
	i := slices.Index(namespaces, uri)
	if i < 0 || i > 0xffff {
		return 0, false
	}
	return uint16(i), true
}

// withNamespace returns a copy of n in the namespace ns. A numeric NodeId
// is a Numeric one whatever its encoding, so that the records of a role do
// not depend on the index of its namespace.
func withNamespace(n *ua.NodeID, ns uint16) *ua.NodeID {
	if t := n.Type(); t == ua.NodeIDTypeTwoByte || t == ua.NodeIDTypeFourByte || t == ua.NodeIDTypeNumeric {
		return ua.NewNumericNodeID(ns, n.IntID())
	}
	c := *n
	_ = c.SetNamespace(ns) // a String, Guid or ByteString NodeId takes any index
	return &c
}
