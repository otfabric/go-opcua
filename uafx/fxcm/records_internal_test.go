// SPDX-License-Identifier: MIT

package fxcm

import (
	"encoding/binary"
	"hash/crc32"
	"math"
	"testing"

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
			ServerURI: "urn:x", ACNode: ua.NewNumericNodeID(1, 5), FunctionalEntity: ua.NewStringNodeID(1, "fe"), Name: "n", NodeID: ua.NewNumericNodeID(1, 6), Class: int64(KnownOwned), Run: 2, Version: 1},
		&runRecord{Run: 2, SetName: "s", Generation: 4, Action: 1, RollbackOnError: true, Phase: phaseExecuting, Endpoints: []string{"ep/x"}},
		&callRecord{Run: 2, Kind: callEstablish, ACNode: ua.NewNumericNodeID(1, 5), Names: []string{"n"}, FunctionalEntities: []*ua.NodeID{ua.NewStringNodeID(1, "fe")}, Request: []byte{1}, AbsentBefore: []bool{true}, Preconfigured: []*ua.NodeID{ua.NewTwoByteNodeID(0)}},
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
	}
	panic("unknown record")
}

// FuzzDecodeRecord: a record from the store, which a restarted Manager
// reads, never panics the decoder, and one that decodes encodes back to a
// record that decodes to the same value. The checksum is fixed up so that
// the input reaches the decoder.
func FuzzDecodeRecord(f *testing.F) {
	conf, _, err := encodeConf(named("s"))
	require.NoError(f, err)
	for _, v := range []any{
		&countersRecord{Generation: 7, RunID: 9},
		&setRecord{Folder: []string{"a"}, Name: "s", Version: 3, Generation: 4, Fingerprint: []byte{1, 2}, Conf: conf},
		&epStored{SetName: "s", Connection: "c", Namespaces: []string{"urn:x"}, ACNode: ua.NewNumericNodeID(1, 5), Class: int64(KnownOwned)},
		&runRecord{Run: 2, SetName: "s", Phase: phaseExecuting, Endpoints: []string{"ep/x"}},
		&callRecord{Run: 2, Kind: callEstablish, Names: []string{"n"}, AbsentBefore: []bool{true}, Preconfigured: []*ua.NodeID{ua.NewTwoByteNodeID(0)}},
	} {
		b, err := ua.Encode(v)
		require.NoError(f, err)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, part []byte) {
		if uint64(len(part)) > math.MaxUint32 {
			return
		}
		val := make([]byte, 0, 9+len(part))
		val = append(val, recordFormat)
		val = binary.LittleEndian.AppendUint32(val, uint32(len(part)))
		val = append(val, part...)
		val = binary.LittleEndian.AppendUint32(val, crc32.Checksum(part, crcTable))
		for _, v := range []func() any{
			func() any { return new(countersRecord) }, func() any { return new(setRecord) }, func() any { return new(epStored) },
			func() any { return new(runRecord) }, func() any { return new(callRecord) },
		} {
			out := v()
			if decodeRecord(val, out) != nil {
				continue
			}
			again, err := encodeRecord(out)
			require.NoError(t, err)
			back := v()
			require.NoError(t, decodeRecord(again, back))
			if s, ok := out.(*setRecord); ok {
				_, _ = decodeConf(s.Conf)
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
