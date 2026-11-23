// SPDX-License-Identifier: MIT

package uafx

import (
	"encoding/xml"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/schema"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/internal/model"
)

// mandatoryOf returns the browse names, without prefix, of the members of
// the type typeID of the NodeSet doc with the ModellingRule Mandatory
// (i=78), sorted.
func mandatoryOf(t *testing.T, doc []byte, typeID uint32) []string {
	t.Helper()
	var ns schema.UANodeSet
	require.NoError(t, xml.Unmarshal(doc, &ns))
	type member struct {
		browseName string
		refs       []*schema.Reference
	}
	nodes := map[string]member{}
	add := func(id, bn string, refs *schema.ListOfReferences) {
		if refs != nil {
			nodes[id] = member{bn, refs.Reference}
		}
	}
	for _, n := range ns.UAObject {
		add(n.NodeIDAttr, n.BrowseNameAttr, n.References)
	}
	for _, n := range ns.UAVariable {
		add(n.NodeIDAttr, n.BrowseNameAttr, n.References)
	}
	for _, n := range ns.UAMethod {
		add(n.NodeIDAttr, n.BrowseNameAttr, n.References)
	}
	for _, n := range ns.UAObjectType {
		add(n.NodeIDAttr, n.BrowseNameAttr, n.References)
	}
	typ, ok := nodes["ns=1;i="+strconv.FormatUint(uint64(typeID), 10)]
	require.True(t, ok, "type %d", typeID)
	var out []string
	for _, r := range typ.refs {
		if r.IsForwardAttr != nil && !*r.IsForwardAttr {
			continue
		}
		m, ok := nodes[r.Value]
		if !ok {
			continue
		}
		for _, mr := range m.refs {
			if mr.ReferenceTypeAttr == "HasModellingRule" && mr.Value == "i=78" {
				_, name, _ := strings.Cut(m.browseName, ":")
				out = append(out, name)
			}
		}
	}
	slices.Sort(out)
	return out
}

// TestMandatoryMatchesModel checks the mandatory members Inspect looks for
// against the ModellingRules of the embedded NodeSets.
func TestMandatoryMatchesModel(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  []byte
		typ  uint32
		want []string
	}{
		{"AutomationComponentType", model.AC, fxacid.AutomationComponentType, mandatoryAC},
		{"ConnectionEndpointType", model.AC, fxacid.ConnectionEndpointType, mandatoryEndpoint},
		{"PubSubConnectionEndpointType", model.AC, fxacid.PubSubConnectionEndpointType, mandatoryPubSubEndpoint},
		{"ConnectionManagerType", model.CM, fxcmid.ConnectionManagerType, mandatoryCM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := slices.Sorted(slices.Values(tc.want))
			assert.Equal(t, mandatoryOf(t, tc.doc, tc.typ), want)
		})
	}
}

func eo(ac uint16, enc uint32, mask uint8, body any) *ua.Variant {
	return ua.MustVariant(&ua.ExtensionObject{TypeID: ua.NewNumericExpandedNodeID(ac, enc), EncodingMask: mask, Value: body})
}

func TestDecodeAggregatedHealth(t *testing.T) {
	const ac = 7
	enc := uint32(fxacid.AggregatedHealthDataTypeEncodingDefaultBinary)
	h, err := decodeAggregatedHealth(eo(ac, enc, ua.ExtensionObjectBinary, []byte{0x09, 0, 0, 0, 0x0a, 0}), ac)
	require.NoError(t, err)
	assert.Equal(t, DeviceFailure|DeviceOffSpec, h.AggregatedDeviceHealth)
	assert.Equal(t, OperationalError|SubOperationalError, h.AggregatedOperationalHealth)

	// The body the client keeps of a structure it does not know.
	raw := &ua.ExtensionObject{TypeID: ua.NewNumericExpandedNodeID(ac, enc), EncodingMask: ua.ExtensionObjectBinary, RawBody: []byte{1, 0, 0, 0, 0, 0}}
	h, err = decodeAggregatedHealth(ua.MustVariant(raw), ac)
	require.NoError(t, err)
	assert.Equal(t, DeviceFailure, h.AggregatedDeviceHealth)

	for name, v := range map[string]*ua.Variant{
		"nil":            nil,
		"not a struct":   ua.MustVariant(uint32(1)),
		"xml":            eo(ac, enc, ua.ExtensionObjectXML, []byte("<x/>")),
		"other encoding": eo(ac, uint32(fxacid.FxVersionEncodingDefaultBinary), ua.ExtensionObjectBinary, []byte{0, 0, 0, 0, 0, 0}),
		"other ns":       eo(ac+1, enc, ua.ExtensionObjectBinary, []byte{0, 0, 0, 0, 0, 0}),
		"short":          eo(ac, enc, ua.ExtensionObjectBinary, []byte{0, 0, 0}),
		"long":           eo(ac, enc, ua.ExtensionObjectBinary, []byte{0, 0, 0, 0, 0, 0, 0}),
		"decoded":        ua.MustVariant(&ua.ExtensionObject{TypeID: ua.NewNumericExpandedNodeID(ac, enc), EncodingMask: ua.ExtensionObjectBinary, Value: &FxVersion{}}),
		"no type id":     ua.MustVariant(&ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, Value: []byte{}}),
	} {
		_, err := decodeAggregatedHealth(v, ac)
		assert.Error(t, err, name)
	}
}

func TestDecodeFxVersion(t *testing.T) {
	const ac = 3
	enc := uint32(fxacid.FxVersionEncodingDefaultBinary)
	v, err := decodeFxVersion(eo(ac, enc, ua.ExtensionObjectBinary, []byte{1, 0, 0, 1, 0xff, 0xff, 0, 0}), ac)
	require.NoError(t, err)
	assert.Equal(t, FxVersion{Major: 1, Minor: 256, Build: 65535}, *v)
	assert.Equal(t, "1.256.65535.0", v.String())
	_, err = decodeFxVersion(eo(ac, enc, ua.ExtensionObjectBinary, []byte{1}), ac)
	assert.Error(t, err)
	_, err = decodeFxVersion(ua.MustVariant("x"), ac)
	assert.Error(t, err)
}

// FuzzDecodeStructures feeds arbitrary bodies, which come from the server,
// to the decoders of the structures Inspect reads.
func FuzzDecodeStructures(f *testing.F) {
	f.Add([]byte{0x04, 0, 0, 0, 1, 0})
	f.Add([]byte{1, 0, 2, 0, 3, 0, 4, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		const ac = 2
		h, err := decodeAggregatedHealth(eo(ac, fxacid.AggregatedHealthDataTypeEncodingDefaultBinary, ua.ExtensionObjectBinary, body), ac)
		if err == nil && len(body) != 6 {
			t.Fatalf("decoded %d bytes as AggregatedHealthDataType: %+v", len(body), h)
		}
		v, err := decodeFxVersion(eo(ac, fxacid.FxVersionEncodingDefaultBinary, ua.ExtensionObjectBinary, body), ac)
		if err == nil && len(body) != 8 {
			t.Fatalf("decoded %d bytes as FxVersion: %+v", len(body), v)
		}
	})
}

func TestStrings(t *testing.T) {
	assert.Equal(t, "Operational", ConnectionEndpointOperational.String())
	assert.Equal(t, "Initial", ConnectionEndpointInitial.String())
	assert.Equal(t, "ConnectionEndpointStatus(9)", ConnectionEndpointStatus(9).String())
	assert.Equal(t, "ConnectionEndpointStatus(-1)", ConnectionEndpointStatus(-1).String())
	assert.Equal(t, "OK", DeviceHealth(0).String())
	assert.Equal(t, "DeviceFailure|DeviceMaintenanceRequired", (DeviceFailure | DeviceMaintenanceRequired).String())
	assert.Equal(t, "DeviceCheckFunction|0x100", (DeviceCheckFunction | 0x100).String())
	assert.Equal(t, "OK", OperationalHealth(0).String())
	assert.Equal(t, "OperationalWarning|SubOperationalError|0x1", (OperationalWarning | SubOperationalError | 1).String())
	assert.Equal(t, "the server is odd (Part 81 §1)", Finding{Clause: "1", Text: "the server is odd"}.String())
	assert.Equal(t, "A/B: x (Part 81 §2)", Finding{Path: "A/B", Clause: "2", Text: "x"}.String())
}

func TestDurationOf(t *testing.T) {
	assert.Equal(t, 1500*time.Millisecond, durationOf(1500))
	assert.Equal(t, time.Duration(0), durationOf(-1))
	assert.Equal(t, time.Duration(0), durationOf(math.NaN()))
	assert.Equal(t, time.Duration(math.MaxInt64), durationOf(math.Inf(1)))
	assert.Equal(t, time.Duration(math.MaxInt64), durationOf(1e300))
}

func TestText(t *testing.T) {
	assert.Equal(t, "", text(nil))
	assert.Equal(t, "a", text(ua.MustVariant("a")))
	assert.Equal(t, "b", text(ua.MustVariant(ua.NewLocalizedText("b"))))
	assert.Equal(t, "", text(ua.MustVariant(int32(1))))
	assert.Equal(t, "", text(ua.MustVariant((*ua.LocalizedText)(nil))))
}

func TestLimitsDefaults(t *testing.T) {
	l := Limits{}.withDefaults()
	assert.Equal(t, Limits{MaxComponents: 256, MaxChildren: 1024, MaxDepth: 8, MaxNodes: 10000}, l)
	assert.Equal(t, Limits{MaxComponents: 1, MaxChildren: 2, MaxDepth: 3, MaxNodes: 4}, Limits{1, 2, 3, 4}.withDefaults())
}

func TestIndexAndNodeOf(t *testing.T) {
	refs := []*ua.ReferenceDescription{
		{BrowseName: &ua.QualifiedName{Name: "A"}, NodeID: ua.NewNumericExpandedNodeID(1, 1)},
		{BrowseName: &ua.QualifiedName{Name: "A"}, NodeID: ua.NewNumericExpandedNodeID(1, 2)},
		{BrowseName: nil, NodeID: ua.NewNumericExpandedNodeID(1, 3)},
		{BrowseName: &ua.QualifiedName{Name: "B"}},
	}
	m := index(refs)
	require.Len(t, m, 1)
	assert.Equal(t, uint32(1), m["A"].NodeID.NodeID.IntID())
	n := nodeOf(&ua.ReferenceDescription{NodeID: ua.NewNumericExpandedNodeID(1, 5)})
	assert.NotNil(t, n.BrowseName)
	assert.Equal(t, "", n.DisplayName)
	assert.Nil(t, n.TypeDefinition)
}
