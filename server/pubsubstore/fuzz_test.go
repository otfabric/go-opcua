// SPDX-License-Identifier: MIT

package pubsubstore

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

// FuzzRecords decodes a root record, a PubSubConnection record and a
// PublishedDataSet record, alone and as a state, as Open does with the
// bytes of a file: nothing panics, and a state that decodes encodes again
// to records that decode to the same configuration.
func FuzzRecords(f *testing.F) {
	recs, err := records(config("A"), nsA)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(recs[rootKey], recs[nameKey(connPrefix, "A")], recs[nameKey(pdsPrefix, "Data")])
	f.Add(root{conns: []string{"A"}}.encode(), recs[nameKey(connPrefix, "A")], []byte(nil))
	f.Add([]byte{1, 1, 0, 0}, []byte{1, 0}, []byte{})
	f.Fuzz(func(t *testing.T, rootRec, connRec, pdsRec []byte) {
		_, _ = decodeComponent(connRec, new(ua.PubSubConnectionDataType))
		_, _ = decodeComponent(pdsRec, new(ua.PublishedDataSetDataType))
		state := map[string][]byte{rootKey: rootRec}
		if r, err := decodeRoot(rootRec); err == nil {
			for _, n := range r.conns {
				state[nameKey(connPrefix, n)] = connRec
			}
			for _, n := range r.pds {
				state[nameKey(pdsPrefix, n)] = pdsRec
			}
		}
		st, err := decodeState(state)
		if err != nil || st == nil {
			return
		}
		again, err := records(st.config(), nsA)
		if err != nil {
			t.Fatalf("a decoded state does not encode: %v", err)
		}
		st2, err := decodeState(again)
		if err != nil {
			t.Fatalf("the records of a decoded state do not decode: %v", err)
		}
		a, _ := ua.Encode(st.config())
		b, _ := ua.Encode(st2.config())
		if !bytes.Equal(a, b) {
			t.Fatal("the configuration changed in a round trip")
		}
	})
}
