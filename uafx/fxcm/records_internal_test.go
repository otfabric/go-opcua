// SPDX-License-Identifier: MIT

package fxcm

import (
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
