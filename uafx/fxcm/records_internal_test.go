// SPDX-License-Identifier: MIT

package fxcm

import (
	"encoding/binary"
	"hash/crc32"
	"maps"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// TestRecordsRoundTrip: every record decodes to what was encoded, and a
// changed byte fails the checksum.
func TestRecordsRoundTrip(t *testing.T) {
	t.Parallel()
	for _, v := range []any{
		&countersRecord{Generation: 7, RunID: 9},
		&setRecord{Folder: []string{"a"}, Name: "s", Version: 3, Generation: 4, Fingerprint: []byte{1, 2}, Conf: []byte{3}},
		&epStored{Folder: []string{"f"}, SetName: "s", Connection: "c", Endpoint: 1, Address: "opc.tcp://x", Namespaces: []string{"http://opcfoundation.org/UA/", "urn:x"},
			ServerURIConf: "urn:x", Server: serverEvidence{ApplicationURI: "urn:x", Secured: true, Thumbprint: []byte{9}},
			ACNode: &qualifiedID{NamespaceURI: "urn:x", ID: "i=5"}, FunctionalEntity: &qualifiedID{NamespaceURI: "urn:x", ID: "s=fe"}, Name: "n", NodeID: &qualifiedID{NamespaceURI: "urn:x", ID: "i=6"},
			CreationTime: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC), CMApplicationURI: "urn:cm", CMObserved: true,
			Class: int64(KnownOwned), Run: 2, Version: 1, Generation: 4, Fingerprint: []byte{1}, EndpointFingerprint: []byte{2}},
		&runRecord{Run: 2, SetName: "s", Generation: 4, Action: 1, RollbackOnError: true, Phase: phaseExecuting, Endpoints: []string{"ep/x"}},
		&txRecord{Run: 2, Ops: []txOp{{Op: 4, Name: "s", Version: 1, Old: 3, New: 5, Fingerprint: []byte{1}, Conf: []byte{2}}}},
		&callRecord{Run: 2, Kind: callEstablish, ACNode: &qualifiedID{NamespaceURI: "urn:x", ID: "i=5"}, Names: []string{"n"}, FunctionalEntities: []*qualifiedID{{NamespaceURI: "urn:x", ID: "s=fe"}},
			EndpointFingerprints: [][]byte{{1}}, Request: []byte{1}, AbsentBefore: []bool{true}, Preconfigured: []*qualifiedID{{}}},
	} {
		b, err := encodeRecord(v)
		require.NoError(t, err)
		out := newLike(v)
		require.NoError(t, decodeRecord(b, out))
		require.Equal(t, v, out)
		b[len(b)/2] ^= 0xff
		require.ErrorIs(t, decodeRecord(b, newLike(v)), errRecord)
	}
	require.Nil(t, orNil(ua.NewTwoByteNodeID(0)))
	require.NotNil(t, orNil(ua.NewTwoByteNodeID(1)))
	require.ErrorIs(t, decodeRecord(nil, new(setRecord)), errRecord)
	require.ErrorIs(t, decodeRecord([]byte{9, 0, 0, 0, 0, 0, 0, 0, 0}, new(setRecord)), errRecord)
	require.ErrorIs(t, decodeRecord([]byte{1, 5, 0, 0, 0, 0, 0, 0, 0}, new(setRecord)), errRecord)
}

func newLike(v any) any {
	switch v.(type) {
	case *countersRecord:
		return new(countersRecord)
	case *setRecord:
		return new(setRecord)
	case *epStored:
		return new(epStored)
	case *runRecord:
		return new(runRecord)
	case *callRecord:
		return new(callRecord)
	case *txRecord:
		return new(txRecord)
	}
	panic("unknown record")
}

// frame is part as a record of the store: the format, the length, part and
// its checksum, so that a fuzzed part reaches the decoder.
func frame(part []byte) []byte {
	val := make([]byte, 0, 9+len(part))
	val = append(val, recordFormat)
	val = binary.LittleEndian.AppendUint32(val, uint32(len(part)))
	val = append(val, part...)
	return binary.LittleEndian.AppendUint32(val, crc32.Checksum(part, crcTable))
}

// keyOf is the store key a record r would have, for its semantic check.
func keyOf(r any) string {
	switch r := r.(type) {
	case *setRecord:
		return setStoreKey(SetKey{Folder: r.Folder, Name: r.Name})
	case *epStored:
		addr := ServerAddress{Address: r.Address, SecurityMode: ua.MessageSecurityMode(r.SecurityMode), SecurityPolicyURI: r.SecurityPolicyURI, ServerURI: r.ServerURIConf}
		return epStoreKey(SetKey{Folder: r.Folder, Name: r.SetName}, addr, r.FunctionalEntity, r.Name)
	case *runRecord:
		return runStoreKey(RunID(r.Run))
	case *txRecord:
		return txStoreKey(RunID(r.Run))
	case *callRecord:
		return callStoreKey(RunID(r.Run), 1)
	}
	return "counters"
}

// FuzzDecodeRecord: a record from the store, which a restarted Manager
// reads, never panics the decoder or its semantic check (check, against
// its own key and the highest counters), and one that decodes encodes back
// to a record that decodes to the same value. The checksum is fixed up so
// that the input reaches the decoder.
func FuzzDecodeRecord(f *testing.F) {
	conf, _, err := encodeConf(named("s"))
	require.NoError(f, err)
	for _, v := range []any{
		&countersRecord{Generation: 7, RunID: 9},
		&setRecord{Folder: []string{"a"}, Name: "s", Version: 3, Generation: 4, Fingerprint: []byte{1, 2}, Conf: conf},
		&epStored{SetName: "s", Connection: "c", Namespaces: []string{"urn:x"}, ACNode: &qualifiedID{NamespaceURI: "urn:x", ID: "i=5"}, Class: int64(KnownOwned)},
		&epStored{SetName: "s", Connection: "c", Namespaces: []string{"urn:x"}, ACNode: &qualifiedID{NamespaceURI: "urn:x", ID: "i=5"}, Class: int64(KnownOwned),
			Param: storedParam{Set: true, Mode: 3, Inputs: []*qualifiedID{{NamespaceURI: "urn:x", ID: "i=7"}}, Outputs: []*qualifiedID{{NamespaceURI: "urn:x", ID: "i=8"}}, IsPersistent: true, CleanupTimeout: -1, Related: []byte{0, 0}}},
		&runRecord{Run: 2, SetName: "s", Phase: phaseExecuting, Endpoints: []string{"ep/x"}},
		&txRecord{Run: 2, Ops: []txOp{{Op: 1, Name: "s", Version: 1, New: 5, Conf: conf}}},
		&callRecord{Run: 2, Kind: callEstablish, Names: []string{"n"}, AbsentBefore: []bool{true}, Preconfigured: []*qualifiedID{{ID: "i=0"}}},
	} {
		b, err := ua.Encode(v)
		require.NoError(f, err)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, part []byte) {
		if uint64(len(part)) > math.MaxUint32 {
			return
		}
		val := frame(part)
		for _, v := range []func() any{
			func() any { return new(countersRecord) }, func() any { return new(setRecord) }, func() any { return new(epStored) },
			func() any { return new(runRecord) }, func() any { return new(callRecord) }, func() any { return new(txRecord) },
		} {
			out := v()
			if decodeRecord(val, out) != nil {
				continue
			}
			again, err := encodeRecord(out)
			require.NoError(t, err)
			back := v()
			require.NoError(t, decodeRecord(again, back))
			require.Equal(t, out, back)
			if s, ok := out.(*setRecord); ok {
				_, _ = decodeConf(s.Conf)
			}
			if c, ok := out.(interface {
				check(k string, c countersRecord) error
			}); ok {
				_ = c.check(keyOf(out), countersRecord{Generation: math.MaxUint64, RunID: math.MaxUint64})
			}
		}
	})
}

// TestRecordsErrors: a Conf that is not an ExtensionObject, not a UAFX
// structure or not a set fails to decode, and the kinds of owed work have
// names.
func TestRecordsErrors(t *testing.T) {
	t.Parallel()
	_, err := decodeConf([]byte{1, 2, 3})
	require.ErrorIs(t, err, errRecord)
	eo, err := ua.Encode(ua.NewExtensionObject(&ua.Argument{Name: "x"}))
	require.NoError(t, err)
	_, err = decodeConf(eo)
	require.ErrorIs(t, err, errRecord)
	for k, want := range map[OwedKind]string{OwedReconcile: "Reconcile", OwedRollback: "Rollback", OwedSetChange: "SetChange", OwedCall: "Call", 9: "OwedKind(9)"} {
		require.Equal(t, want, k.String())
	}
}

// FuzzLoadState: a store whose records a restarted Manager loads
// (decodeState, design §3.2) never panics it, whatever one record of a
// valid journal is replaced with; every record is either decoded or
// failed, never both or neither.
func FuzzLoadState(f *testing.F) {
	base := map[string][]byte{}
	for k, v := range semanticState(f) {
		b, err := encodeRecord(v)
		require.NoError(f, err)
		base[k] = b
	}
	keys := sortedKeys(base)
	for i, k := range keys {
		b, err := ua.Encode(semanticState(f)[k])
		require.NoError(f, err)
		f.Add(uint8(i), b, false)
	}
	f.Add(uint8(0), []byte{1, 2, 3}, true)
	f.Fuzz(func(t *testing.T, at uint8, part []byte, rekey bool) {
		if uint64(len(part)) > math.MaxUint32 {
			return
		}
		st := maps.Clone(base)
		k := keys[int(at)%len(keys)]
		val := frame(part)
		if rekey {
			// The record under the key it names, so that its check
			// against its key passes and the others are reached.
			for _, v := range []any{new(setRecord), new(epStored), new(runRecord), new(txRecord), new(callRecord)} {
				if decodeRecord(val, v) == nil && strings.HasPrefix(keyOf(v), strings.SplitN(k, "/", 2)[0]+"/") {
					delete(st, k)
					k = keyOf(v)
					break
				}
			}
		}
		st[k] = val
		l := decodeState(st)
		for key := range st {
			_, failed := l.failed[key]
			n := 0
			for _, has := range []bool{l.sets[key] != nil, l.eps[key] != nil, l.runs[key] != nil, l.txs[key] != nil, l.calls[key] != nil, key == "counters"} {
				if has {
					n++
				}
			}
			if key == "counters" {
				continue
			}
			require.True(t, failed != (n == 1), "%s: failed %v, decoded %d", key, failed, n)
		}
	})
}
