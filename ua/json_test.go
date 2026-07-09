// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVariantMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		v    *Variant
		want string
	}{
		{"null", MustVariant(nil), `{"type":"Null","value":null}`},
		{"int32", MustVariant(int32(42)), `{"type":"Int32","value":42}`},
		{"bool", MustVariant(true), `{"type":"Boolean","value":true}`},
		{"float64", MustVariant(float64(3.14)), `{"type":"Double","value":3.14}`},
		{"string", MustVariant("hello"), `{"type":"String","value":"hello"}`},
		{"status good", MustVariant(StatusGood), `{"type":"StatusCode","value":"StatusGood"}`},
		{"int32 array", MustVariant([]int32{1, 2, 3}), `{"type":"Int32[]","value":[1,2,3]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.v)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if got := string(b); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDataValueMarshalJSON(t *testing.T) {
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	t.Run("value only", func(t *testing.T) {
		dv := &DataValue{
			EncodingMask: DataValueValue,
			Value:        MustVariant(int32(42)),
		}
		b, err := json.Marshal(dv)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m["value"] == nil {
			t.Error("expected value field")
		}
		if _, ok := m["sourceTimestamp"]; ok {
			t.Error("sourceTimestamp should be omitted")
		}
	})

	t.Run("with timestamps", func(t *testing.T) {
		dv := &DataValue{
			EncodingMask:    DataValueValue | DataValueSourceTimestamp | DataValueServerTimestamp,
			Value:           MustVariant(float32(3.14)),
			SourceTimestamp: ts,
			ServerTimestamp: ts,
		}
		b, err := json.Marshal(dv)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m["sourceTimestamp"] == nil {
			t.Error("expected sourceTimestamp")
		}
		if m["serverTimestamp"] == nil {
			t.Error("expected serverTimestamp")
		}
	})
}

func TestQualifiedNameMarshalJSON(t *testing.T) {
	q := &QualifiedName{NamespaceIndex: 2, Name: "Temperature"}
	b, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"namespaceIndex":2,"name":"Temperature"}`
	if got := string(b); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestLocalizedTextMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		lt   *LocalizedText
		want string
	}{
		{"text only", &LocalizedText{Text: "Hello"}, `{"text":"Hello"}`},
		{"with locale", &LocalizedText{Locale: "en", Text: "Hello"}, `{"locale":"en","text":"Hello"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.lt)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(b); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestStatusCodeMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		sc   StatusCode
		code uint32
		text string
	}{
		{"good", StatusGood, 0, "StatusGood"},
		{"bad", StatusBadUnexpectedError, 0x80010000, "StatusBadUnexpectedError"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.sc)
			if err != nil {
				t.Fatal(err)
			}
			var m struct {
				Code uint32 `json:"code"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			if m.Code != tt.code {
				t.Errorf("code: got %d, want %d", m.Code, tt.code)
			}
			if m.Name != tt.text {
				t.Errorf("name: got %q, want %q", m.Name, tt.text)
			}
		})
	}
}

func TestReferenceDescriptionString(t *testing.T) {
	ref := &ReferenceDescription{
		ReferenceTypeID: NewNumericNodeID(0, 35),
		IsForward:       true,
		NodeID: &ExpandedNodeID{
			NodeID: NewNumericNodeID(0, 85),
		},
		BrowseName:  &QualifiedName{NamespaceIndex: 0, Name: "Objects"},
		DisplayName: &LocalizedText{Text: "Objects"},
		NodeClass:   NodeClassObject,
		TypeDefinition: &ExpandedNodeID{
			NodeID: NewNumericNodeID(0, 61),
		},
	}

	got := ref.String()
	if got == "" {
		t.Error("String() returned empty")
	}
	// Should contain the node id and display name
	if !containsStr(got, "i=85") {
		t.Errorf("expected i=85 in %q", got)
	}
	if !containsStr(got, "Objects") {
		t.Errorf("expected Objects in %q", got)
	}
	if !containsStr(got, "→") {
		t.Errorf("expected → for forward ref in %q", got)
	}

	// Test backward reference
	ref.IsForward = false
	got = ref.String()
	if !containsStr(got, "←") {
		t.Errorf("expected ← for backward ref in %q", got)
	}
}

func TestReferenceDescriptionMarshalJSON(t *testing.T) {
	ref := &ReferenceDescription{
		ReferenceTypeID: NewNumericNodeID(0, 35),
		IsForward:       true,
		NodeID: &ExpandedNodeID{
			NodeID: NewNumericNodeID(0, 85),
		},
		BrowseName:  &QualifiedName{NamespaceIndex: 0, Name: "Objects"},
		DisplayName: &LocalizedText{Text: "Objects"},
		NodeClass:   NodeClassObject,
		TypeDefinition: &ExpandedNodeID{
			NodeID: NewNumericNodeID(0, 61),
		},
	}
	b, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["nodeId"] != "i=85" {
		t.Errorf("nodeId: got %q, want i=85", m["nodeId"])
	}
	if m["displayName"] != "Objects" {
		t.Errorf("displayName: got %q, want Objects", m["displayName"])
	}
	if m["isForward"] != true {
		t.Errorf("isForward: got %v, want true", m["isForward"])
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestStatusCodeMarshalJSON_Unknown(t *testing.T) {
	// unknown status code exercises the fallback branch
	unknown := StatusCode(0xDEADBEEF)
	b, err := unknown.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON unknown: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("MarshalJSON returned empty bytes")
	}
}

func TestNodeClassName(t *testing.T) {
	classes := []NodeClass{
		NodeClassObject, NodeClassVariable, NodeClassMethod,
		NodeClassObjectType, NodeClassVariableType, NodeClassReferenceType,
		NodeClassDataType, NodeClassView, NodeClass(99),
	}
	for _, nc := range classes {
		s := nodeClassName(nc)
		if s == "" {
			t.Errorf("nodeClassName(%v) returned empty string", nc)
		}
	}
}
