package ua

import (
	"encoding/json"
	"fmt"
)

// MarshalJSON implements json.Marshaler for Variant.
// Scalars are encoded as {"type":"Int32","value":42}.
// Arrays are encoded as {"type":"Int32[]","value":[1,2,3]}.
// Null variants are encoded as {"type":"Null","value":null}.
func (m *Variant) MarshalJSON() ([]byte, error) {
	typeName := typeIDDisplayName(m.Type())
	if m.Has(VariantArrayValues) {
		typeName += "[]"
	}
	return json.Marshal(struct {
		Type  string      `json:"type"`
		Value interface{} `json:"value"`
	}{
		Type:  typeName,
		Value: m.jsonValue(),
	})
}

// typeIDDisplayName returns a clean type name suitable for JSON.
func typeIDDisplayName(t TypeID) string {
	s := t.String()
	// The generated stringer produces "TypeIDBoolean" etc.
	if len(s) > 6 && s[:6] == "TypeID" {
		return s[6:]
	}
	return s
}

func (m *Variant) jsonValue() interface{} {
	if m.value == nil || m.Type() == TypeIDNull {
		return nil
	}
	// StatusCode as string
	if sc, ok := m.value.(StatusCode); ok {
		if d, ok := StatusCodes[sc]; ok {
			return d.Name
		}
		return fmt.Sprintf("0x%08X", uint32(sc))
	}
	return m.value
}

// MarshalJSON implements json.Marshaler for DataValue.
func (d *DataValue) MarshalJSON() ([]byte, error) {
	out := struct {
		Value             *Variant   `json:"value,omitempty"`
		Status            StatusCode `json:"status,omitempty"`
		SourceTimestamp   string     `json:"sourceTimestamp,omitempty"`
		ServerTimestamp   string     `json:"serverTimestamp,omitempty"`
		SourcePicoseconds uint16     `json:"sourcePicoseconds,omitempty"`
		ServerPicoseconds uint16     `json:"serverPicoseconds,omitempty"`
	}{}

	if d.Has(DataValueValue) {
		out.Value = d.Value
	}
	if d.Has(DataValueStatusCode) {
		out.Status = d.Status
	}
	if d.Has(DataValueSourceTimestamp) {
		out.SourceTimestamp = d.SourceTimestamp.UTC().Format("2006-01-02T15:04:05.999999999Z")
	}
	if d.Has(DataValueServerTimestamp) {
		out.ServerTimestamp = d.ServerTimestamp.UTC().Format("2006-01-02T15:04:05.999999999Z")
	}
	if d.Has(DataValueSourcePicoseconds) {
		out.SourcePicoseconds = d.SourcePicoseconds
	}
	if d.Has(DataValueServerPicoseconds) {
		out.ServerPicoseconds = d.ServerPicoseconds
	}

	return json.Marshal(out)
}

// MarshalJSON implements json.Marshaler for QualifiedName.
func (q *QualifiedName) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		NamespaceIndex uint16 `json:"namespaceIndex"`
		Name           string `json:"name"`
	}{
		NamespaceIndex: q.NamespaceIndex,
		Name:           q.Name,
	})
}

// MarshalJSON implements json.Marshaler for LocalizedText.
func (l *LocalizedText) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Locale string `json:"locale,omitempty"`
		Text   string `json:"text"`
	}{
		Locale: l.Locale,
		Text:   l.Text,
	})
}

// MarshalJSON implements json.Marshaler for ReferenceDescription.
func (r *ReferenceDescription) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ReferenceTypeID string    `json:"referenceTypeId"`
		IsForward       bool      `json:"isForward"`
		NodeID          string    `json:"nodeId"`
		BrowseName      string    `json:"browseName"`
		DisplayName     string    `json:"displayName"`
		NodeClass       NodeClass `json:"nodeClass"`
		TypeDefinition  string    `json:"typeDefinition"`
	}{
		ReferenceTypeID: r.ReferenceTypeID.String(),
		IsForward:       r.IsForward,
		NodeID:          r.NodeID.NodeID.String(),
		BrowseName:      fmt.Sprintf("%d:%s", r.BrowseName.NamespaceIndex, r.BrowseName.Name),
		DisplayName:     r.DisplayName.Text,
		NodeClass:       r.NodeClass,
		TypeDefinition:  r.TypeDefinition.NodeID.String(),
	})
}

// MarshalJSON implements json.Marshaler for StatusCode.
func (s StatusCode) MarshalJSON() ([]byte, error) {
	if d, ok := StatusCodes[s]; ok {
		return json.Marshal(struct {
			Code uint32 `json:"code"`
			Name string `json:"name"`
		}{
			Code: uint32(s),
			Name: d.Name,
		})
	}
	return json.Marshal(struct {
		Code uint32 `json:"code"`
		Name string `json:"name"`
	}{
		Code: uint32(s),
		Name: fmt.Sprintf("0x%08X", uint32(s)),
	})
}

// String returns a human-readable representation of a ReferenceDescription.
func (r *ReferenceDescription) String() string {
	dir := "→"
	if !r.IsForward {
		dir = "←"
	}
	return fmt.Sprintf("%s %s %s (%s)", dir, r.NodeID.NodeID, r.DisplayName.Text, nodeClassName(r.NodeClass))
}

func nodeClassName(nc NodeClass) string {
	switch nc {
	case NodeClassObject:
		return "Object"
	case NodeClassVariable:
		return "Variable"
	case NodeClassMethod:
		return "Method"
	case NodeClassObjectType:
		return "ObjectType"
	case NodeClassVariableType:
		return "VariableType"
	case NodeClassReferenceType:
		return "ReferenceType"
	case NodeClassDataType:
		return "DataType"
	case NodeClassView:
		return "View"
	default:
		return fmt.Sprintf("NodeClass(%d)", nc)
	}
}
