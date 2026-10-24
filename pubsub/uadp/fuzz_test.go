// SPDX-License-Identifier: MIT

package uadp

import (
	"testing"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// FuzzDecode feeds arbitrary bytes to Decode, with the DataSetMetaData of the
// RawData golden vector and the keys of the open62541 vector, and encodes
// whatever it accepts again. Neither may panic.
func FuzzDecode(f *testing.F) {
	var md *ua.DataSetMetaDataType
	for _, g := range goldenVectors() {
		f.Add(h(f, g.hex))
		if g.md != nil {
			md = g.md
		}
	}
	f.Add(unhex(f, o6Header+o6PayloadEnc+o6Sig))
	f.Add(unhex(f, o6HeaderNoSec+o6PayloadDec))
	f.Add([]byte{0x41, 0x02, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x91, 0x80, 0x08, 0x01, 0x02, 0x05, 0x00, 0x0a, 0x00})
	// ActionMetaData and ActionResponder announcements.
	for _, d := range []*message.Discovery{
		{Type: message.DiscoveryActionMetaData, DataSetWriterID: 100, ActionTargets: []*ua.ActionTargetDataType{{ActionTargetID: 1, Name: "Add"}},
			RequestMetaData: &ua.DataSetMetaDataType{Name: "Calc"}, MetaData: &ua.DataSetMetaDataType{Name: "Calc"},
			ActionMethods: []*ua.ActionMethodDataType{{ObjectID: ua.NewStringNodeID(1, "o"), MethodID: ua.NewStringNodeID(1, "m")}}},
		{Type: message.DiscoveryActionResponder, Connections: []*ua.PubSubConnectionDataType{{Name: "c", WriterGroups: []*ua.WriterGroupDataType{{Name: "g"}}}}},
	} {
		b, err := Encode(discoveryNM(d), nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}

	ks := zeroKeys(testPolicy{})
	opts := &DecodeOptions{
		MetaData: metaLookup(md),
		Security: requireSecurity(ua.MessageSecurityModeNone, ks),
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		nm, err := Decode(b, opts)
		if err != nil {
			return
		}
		_, _ = Encode(nm, &EncodeOptions{MetaData: metaLookup(md)})
		for _, m := range nm.Messages {
			if m.FieldEncoding == message.FieldEncodingRawData && len(m.Fields) > len(md.Fields) {
				t.Fatalf("%d RawData fields for %d in the metadata", len(m.Fields), len(md.Fields))
			}
		}
	})
}
