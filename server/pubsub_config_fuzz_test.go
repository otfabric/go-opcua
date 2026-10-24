// SPDX-License-Identifier: MIT

package server

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

func fuzzBaseConfig() *ua.PubSubConfigurationDataType {
	action := pubsub.PublishedActions("Calc", []pubsub.Field{{Name: "A", Type: ua.TypeIDInt32}}, nil, pubsub.ActionTargetOf(1, "Run"))
	return pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{action},
		pubsub.AttachReaderGroups(pubsub.AttachWriterGroups(pubsub.UDPConnection("Base", "opc.udp://127.0.0.1:4840", uint16(1)),
			pubsub.WriterGroup("Actions", 1, time.Second, pubsub.DataSetWriter("CalcWriter", 1, "Calc"))),
			pubsub.ReaderGroup("Readers", pubsub.DataSetReader("R", uint16(2), 1, 1, pubsub.MetaData("m")))))
}

func fuzzFile(cfg *ua.PubSubConfiguration2DataType) []byte {
	b, err := ua.Encode(&ua.UABinaryFileDataType{Body: ua.MustVariant(ua.NewExtensionObject(cfg))})
	if err != nil {
		panic(err)
	}
	return b
}

// FuzzPubSubConfigUpdate: CloseAndUpdate on any file and any references
// never panics and leaves a valid configuration.
func FuzzPubSubConfigUpdate(f *testing.F) {
	base := fuzzBaseConfig()
	same := fuzzFile(&ua.PubSubConfiguration2DataType{PublishedDataSets: base.PublishedDataSets, Connections: base.Connections})
	other := pubsub.UDPConnection("", "opc.udp://127.0.0.1:4841", nil)
	other.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("", 0, time.Second, pubsub.DataSetWriter("", 0, "Calc"))}
	other.ReaderGroups = []*ua.ReaderGroupDataType{pubsub.ReaderGroup("", pubsub.DataSetReader("", uint16(3), 1, 1, pubsub.MetaData("n")))}
	added := fuzzFile(&ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{other}})
	ref := func(mask ua.PubSubConfigurationRefMask, c, g, e uint16) []byte {
		b := binary.LittleEndian.AppendUint16(nil, uint16(mask))
		return append(b, byte(c), byte(g), byte(e))
	}
	cat := func(xs ...[]byte) []byte {
		var out []byte
		for _, x := range xs {
			out = append(out, x...)
		}
		return out
	}
	add, match, mod, rm := ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskElementMatch, ua.PubSubConfigurationRefMaskElementModify, ua.PubSubConfigurationRefMaskElementRemove
	conn, wg, rg, w, r, pds := ua.PubSubConfigurationRefMaskReferenceConnection, ua.PubSubConfigurationRefMaskReferenceWriterGroup,
		ua.PubSubConfigurationRefMaskReferenceReaderGroup, ua.PubSubConfigurationRefMaskReferenceWriter, ua.PubSubConfigurationRefMaskReferenceReader, ua.PubSubConfigurationRefMaskReferencePubDataset
	f.Add(same, cat(ref(rm|pds, 0, 0, 0), ref(mod|wg, 0, 0, 0), ref(rm|r, 0, 0, 0)))
	f.Add(same, cat(ref(add|match|conn, 0, 0, 0), ref(match|rg, 0, 0, 0), ref(mod|w, 0, 0, 0)))
	f.Add(added, cat(ref(add|conn, 0, 0, 0), ref(add|wg, 0, 0, 0), ref(add|w, 0, 0, 0), ref(add|rg, 0, 0, 0), ref(add|r, 0, 0, 0)))
	f.Add(added, cat(ref(add|w, 0, 0, 0), ref(rm|conn, 0, 0, 0), ref(0xffff, 9, 9, 9)))
	f.Add([]byte("garbage"), ref(add|conn, 0, 0, 0))
	f.Fuzz(func(t *testing.T, file, refBytes []byte) {
		cfg, sc := decodeConfigFile(file)
		if sc != ua.StatusOK {
			return
		}
		var refs []*ua.PubSubConfigurationRefDataType
		for len(refBytes) >= 5 && len(refs) < 32 {
			refs = append(refs, &ua.PubSubConfigurationRefDataType{
				ConfigurationMask: ua.PubSubConfigurationRefMask(binary.LittleEndian.Uint16(refBytes)),
				ConnectionIndex:   uint16(refBytes[2] % 4), GroupIndex: uint16(refBytes[3] % 4), ElementIndex: uint16(refBytes[4] % 4),
			})
			refBytes = refBytes[5:]
		}
		u := newConfigUpdate(cfg, fuzzBaseConfig(), ua.MustVariant(uint16(9)), map[uint16]bool{}, map[uint16]bool{})
		results := u.run(refs)
		if len(results) != len(refs) {
			t.Fatalf("%d results for %d references", len(results), len(refs))
		}
		if err := pubsub.Validate(u.cfg); err != nil {
			t.Fatalf("invalid configuration after %v: %v", results, err)
		}
	})
}
