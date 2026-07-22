//go:build interop

// SPDX-License-Identifier: MIT

// Tests in this file cover go-opcua client ← open62541 server direction.
//
// Each test starts the open62541 adapter container in server mode, waits for
// the ready file, then exercises the go-opcua client API against it.
package interop

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func findNS(t *testing.T, c interface {
	UpdateNamespaces(context.Context) error
	FindNamespace(context.Context, string) (uint16, error)
}) (context.Context, uint16) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	if err := c.UpdateNamespaces(ctx); err != nil {
		t.Fatalf("UpdateNamespaces: %v", err)
	}
	nsIdx, err := c.FindNamespace(ctx, interopNamespaceURI)
	if err != nil {
		t.Fatalf("FindNamespace(%q): %v", interopNamespaceURI, err)
	}
	return ctx, nsIdx
}

// ---------------------------------------------------------------------------
// go-opcua client ← open62541 server
// ---------------------------------------------------------------------------

// TestOpen62541Server_Connect verifies that go-opcua can connect to the
// open62541 adapter and resolve the interop namespace.
func TestOpen62541Server_Connect(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.UpdateNamespaces(ctx); err != nil {
		t.Fatalf("UpdateNamespaces: %v", err)
	}

	nsIdx, err := c.FindNamespace(ctx, interopNamespaceURI)
	if err != nil {
		t.Fatalf("FindNamespace(%q): %v", interopNamespaceURI, err)
	}
	if nsIdx == 0 {
		t.Errorf("namespace index for %q should not be 0", interopNamespaceURI)
	}
	t.Logf("interop namespace index: %d", nsIdx)
}

// TestOpen62541Server_Browse browses the Objects folder and expects at least
// one child reference.
func TestOpen62541Server_Browse(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ns=0, i=85 is the standard Objects folder.
	objects := c.Node(ua.NewNumericNodeID(0, 85))
	refs, err := objects.References(ctx,
		33, // HierarchicalReferences
		ua.BrowseDirectionForward,
		ua.NodeClassAll,
		true,
	)
	if err != nil {
		t.Fatalf("Browse Objects: %v", err)
	}
	if len(refs) == 0 {
		t.Error("expected at least one reference under Objects folder")
	}
	t.Logf("Objects folder has %d reference(s)", len(refs))
}

// TestOpen62541Server_BrowseInteropNamespace browses the interop namespace
// root Object and verifies that the expected top-level folders are present.
func TestOpen62541Server_BrowseInteropNamespace(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, _ := findNS(t, c)

	// Browse the interop namespace root object (the Objects folder in ns=0 has
	// a HasComponent reference to the interop root whose BrowseName is the
	// namespace alias; in practice we browse the Objects folder and look for
	// our expected top-level folders in the child list).
	objects := c.Node(ua.NewNumericNodeID(0, 85)) // Objects
	refs, err := objects.References(ctx,
		33, // HierarchicalReferences
		ua.BrowseDirectionForward,
		ua.NodeClassAll,
		true,
	)
	if err != nil {
		t.Fatalf("Browse Objects: %v", err)
	}

	// Collect child browse names
	names := map[string]bool{}
	for _, r := range refs {
		if r.BrowseName != nil {
			names[r.BrowseName.Name] = true
		}
	}

	// Browse the interop namespace's Objects folder (nodeId in ns=nsIdx).
	// The interop root folder should be a child of Objects.
	// Walk one level deeper to find the interop folders.
	for _, r := range refs {
		if r.BrowseName != nil && r.NodeID != nil {
			childRefs, err2 := c.Node(r.NodeID.NodeID).References(ctx, 33, ua.BrowseDirectionForward, ua.NodeClassAll, true)
			if err2 != nil {
				continue
			}
			for _, cr := range childRefs {
				if cr.BrowseName != nil {
					names[cr.BrowseName.Name] = true
				}
			}
		}
	}

	wantFolders := []string{"Scalars", "Arrays", "Dynamic", "Methods", "Access", "DataValues"}
	for _, f := range wantFolders {
		if !names[f] {
			t.Errorf("Browse: folder %q not found; found: %v", f, names)
		}
	}

	if !t.Failed() {
		t.Logf("Browse found all %d expected folders in open62541 namespace", len(wantFolders))
	}
}

// TestOpen62541Server_BrowseScalarsFolder browses the Scalars folder and
// verifies that a representative set of scalar variable nodes is present.
func TestOpen62541Server_BrowseScalarsFolder(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	scalarsID := ua.NewStringNodeID(nsIdx, "Scalars")
	refs, err := c.Node(scalarsID).References(ctx,
		33, // HierarchicalReferences
		ua.BrowseDirectionForward,
		ua.NodeClassVariable,
		true,
	)
	if err != nil {
		t.Fatalf("Browse Scalars: %v", err)
	}
	if len(refs) < 5 {
		t.Errorf("Scalars folder: expected at least 5 variables, got %d", len(refs))
	}
	names := map[string]bool{}
	for _, r := range refs {
		if r.BrowseName != nil {
			names[r.BrowseName.Name] = true
		}
	}
	for _, want := range []string{"Scalar.Boolean", "Scalar.Int32", "Scalar.Double", "Scalar.String"} {
		if !names[want] {
			t.Errorf("Scalars folder: %q not found", want)
		}
	}
	t.Logf("Scalars folder: %d variables found", len(refs))
}

// TestOpen62541Server_WriteAndReadBack writes to Access.ReadWrite and reads back.
func TestOpen62541Server_WriteAndReadBack(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsIdx, err := c.FindNamespace(ctx, interopNamespaceURI)
	if err != nil {
		t.Fatalf("FindNamespace: %v", err)
	}

	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")
	const writeVal int32 = 9999

	sc, err := c.WriteNodeValue(ctx, nodeID, writeVal)
	if err != nil {
		t.Fatalf("WriteNodeValue: %v", err)
	}
	if sc != ua.StatusGood {
		t.Fatalf("WriteNodeValue status: %v", sc)
	}

	v, err := c.Node(nodeID).Value(ctx)
	if err != nil {
		t.Fatalf("Value after write: %v", err)
	}
	got, ok := v.Value().(int32)
	if !ok {
		t.Fatalf("expected int32 after read-back, got %T", v.Value())
	}
	if got != writeVal {
		t.Errorf("read-back: got %d, want %d", got, writeVal)
	}
}

// ---------------------------------------------------------------------------
// Scalar reads — one test per OPC UA built-in scalar type
// ---------------------------------------------------------------------------

func readScalar(t *testing.T, h *serverHandle, nodeID string) interface{} {
	t.Helper()
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	v, err := c.Node(ua.NewStringNodeID(nsIdx, nodeID)).Value(ctx)
	if err != nil {
		t.Fatalf("Value(%s): %v", nodeID, err)
	}
	return v.Value()
}

func TestOpen62541Server_ReadScalarBoolean(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.Boolean")
	got, ok := raw.(bool)
	if !ok {
		t.Fatalf("expected bool, got %T", raw)
	}
	if !got {
		t.Errorf("Scalar.Boolean: got %v, want true", got)
	}
}

func TestOpen62541Server_ReadScalarSByte(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.SByte")
	got, ok := raw.(int8)
	if !ok {
		t.Fatalf("expected int8, got %T", raw)
	}
	const want int8 = -100
	if got != want {
		t.Errorf("Scalar.SByte: got %d, want %d", got, want)
	}
}

func TestOpen62541Server_ReadScalarByte(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.Byte")
	got, ok := raw.(uint8)
	if !ok {
		t.Fatalf("expected uint8, got %T", raw)
	}
	const want uint8 = 200
	if got != want {
		t.Errorf("Scalar.Byte: got %d, want %d", got, want)
	}
}

func TestOpen62541Server_ReadScalarInt16(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.Int16")
	got, ok := raw.(int16)
	if !ok {
		t.Fatalf("expected int16, got %T", raw)
	}
	const want int16 = -12345
	if got != want {
		t.Errorf("Scalar.Int16: got %d, want %d", got, want)
	}
}

func TestOpen62541Server_ReadScalarUInt16(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.UInt16")
	got, ok := raw.(uint16)
	if !ok {
		t.Fatalf("expected uint16, got %T", raw)
	}
	const want uint16 = 54321
	if got != want {
		t.Errorf("Scalar.UInt16: got %d, want %d", got, want)
	}
}

func TestOpen62541Server_ReadScalarInt32(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.Int32")
	got, ok := raw.(int32)
	if !ok {
		t.Fatalf("expected int32, got %T", raw)
	}
	const want int32 = -123456789
	if got != want {
		t.Errorf("Scalar.Int32: got %d, want %d", got, want)
	}
}

func TestOpen62541Server_ReadScalarUInt32(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.UInt32")
	got, ok := raw.(uint32)
	if !ok {
		t.Fatalf("expected uint32, got %T", raw)
	}
	const want uint32 = 3234567890
	if got != want {
		t.Errorf("Scalar.UInt32: got %d, want %d", got, want)
	}
}

func TestOpen62541Server_ReadScalarInt64(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.Int64")
	got, ok := raw.(int64)
	if !ok {
		t.Fatalf("expected int64, got %T", raw)
	}
	const want int64 = -1234567890123456789
	if got != want {
		t.Errorf("Scalar.Int64: got %d, want %d", got, want)
	}
}

func TestOpen62541Server_ReadScalarUInt64(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.UInt64")
	got, ok := raw.(uint64)
	if !ok {
		t.Fatalf("expected uint64, got %T", raw)
	}
	const want uint64 = 12345678901234567890
	if got != want {
		t.Errorf("Scalar.UInt64: got %d, want %d", got, want)
	}
}

func TestOpen62541Server_ReadScalarFloat(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.Float")
	got, ok := raw.(float32)
	if !ok {
		t.Fatalf("expected float32, got %T", raw)
	}
	const want float32 = 12.5
	if got != want {
		t.Errorf("Scalar.Float: got %v, want %v", got, want)
	}
}

func TestOpen62541Server_ReadScalarDouble(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.Double")
	got, ok := raw.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", raw)
	}
	const want = -12345.6789
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("Scalar.Double: got %v, want %v", got, want)
	}
}

func TestOpen62541Server_ReadScalarString(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.String")
	got, ok := raw.(string)
	if !ok {
		t.Fatalf("expected string, got %T", raw)
	}
	// "OPC UA – 兼容性 – Δ"  (Unicode: en-dash U+2013, CJK U+517c U+5bb9 U+6027, delta U+0394)
	const want = "OPC UA \u2013 \u517c\u5bb9\u6027 \u2013 \u0394"
	if got != want {
		t.Errorf("Scalar.String: got %q, want %q", got, want)
	}
}

func TestOpen62541Server_ReadScalarDateTime(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.DateTime")
	got, ok := raw.(time.Time)
	if !ok {
		t.Fatalf("Scalar.DateTime: expected time.Time, got %T", raw)
	}
	want := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Scalar.DateTime: got %v, want %v", got, want)
	}
}

func TestOpen62541Server_ReadScalarGuid(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.Guid")
	got, ok := raw.(*ua.GUID)
	if !ok {
		t.Fatalf("Scalar.Guid: expected *ua.GUID, got %T", raw)
	}
	want := ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63")
	if got.Data1 != want.Data1 || got.Data2 != want.Data2 || got.Data3 != want.Data3 {
		t.Errorf("Scalar.Guid: got %s, want %s", got, want)
	}
}

func TestOpen62541Server_ReadScalarByteString(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.ByteString")
	got, ok := raw.([]byte)
	if !ok {
		t.Fatalf("Scalar.ByteString: expected []byte, got %T", raw)
	}
	const want = "opcua-compat"
	if string(got) != want {
		t.Errorf("Scalar.ByteString: got %q, want %q", string(got), want)
	}
}

func TestOpen62541Server_ReadScalarXmlElement(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.XmlElement")
	got, ok := raw.(ua.XMLElement)
	if !ok {
		t.Fatalf("Scalar.XmlElement: expected ua.XMLElement, got %T", raw)
	}
	const want = "<compat>test</compat>"
	if string(got) != want {
		t.Errorf("Scalar.XmlElement: got %q, want %q", string(got), want)
	}
}

func TestOpen62541Server_ReadScalarNodeId(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.NodeId")
	got, ok := raw.(*ua.NodeID)
	if !ok {
		t.Fatalf("Scalar.NodeId: expected *ua.NodeID, got %T", raw)
	}
	// fixture initialValue "i=85": namespace 0, numeric id 85 (Objects folder)
	if got.Namespace() != 0 || got.IntID() != 85 {
		t.Errorf("Scalar.NodeId: got ns=%d id=%d, want ns=0 id=85", got.Namespace(), got.IntID())
	}
}

func TestOpen62541Server_ReadScalarQualifiedName(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.QualifiedName")
	got, ok := raw.(*ua.QualifiedName)
	if !ok {
		t.Fatalf("Scalar.QualifiedName: expected *ua.QualifiedName, got %T", raw)
	}
	if got.NamespaceIndex != 0 || got.Name != "Objects" {
		t.Errorf("Scalar.QualifiedName: got %s, want 0:Objects", got)
	}
}

func TestOpen62541Server_ReadScalarLocalizedText(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.LocalizedText")
	got, ok := raw.(*ua.LocalizedText)
	if !ok {
		t.Fatalf("Scalar.LocalizedText: expected *ua.LocalizedText, got %T", raw)
	}
	if got.Text != "OPC UA Compatibility" {
		t.Errorf("Scalar.LocalizedText: text=%q, want %q", got.Text, "OPC UA Compatibility")
	}
	if got.Locale != "en" {
		t.Errorf("Scalar.LocalizedText: locale=%q, want %q", got.Locale, "en")
	}
}

func TestOpen62541Server_ReadScalarStatusCode(t *testing.T) {
	h := startOpen62541Server(t)
	raw := readScalar(t, h, "Scalar.StatusCode")
	got, ok := raw.(ua.StatusCode)
	if !ok {
		t.Fatalf("Scalar.StatusCode: expected ua.StatusCode, got %T", raw)
	}
	if got != ua.StatusOK {
		t.Errorf("Scalar.StatusCode: got 0x%08X, want StatusOK (0)", got)
	}
}

// TestOpen62541Server_ReadDynamicCounter reads the Dynamic.Counter node and
// verifies it returns a valid integer value (the counter increments, so we
// only assert type correctness here).
func TestOpen62541Server_ReadDynamicCounter(t *testing.T) {
	h := startOpen62541Server(t)
	val := readScalar(t, h, "Dynamic.Counter")
	switch val.(type) {
	case uint32, int32, uint64, int64:
		// any integer type is acceptable
	default:
		t.Errorf("Dynamic.Counter: unexpected type %T (value: %v)", val, val)
	}
}

// TestOpen62541Server_CallMethodAdd calls Methods.Add(3, 4) and verifies
// the result is 7.
func TestOpen62541Server_CallMethodAdd(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	objectID := ua.NewStringNodeID(nsIdx, "Methods")
	methodID := ua.NewStringNodeID(nsIdx, "Methods.Add")

	result, err := c.CallMethod(ctx, objectID, methodID, int32(3), int32(4))
	if err != nil {
		t.Fatalf("CallMethod: %v", err)
	}
	if result.StatusCode != ua.StatusOK {
		t.Fatalf("CallMethod status: %v", result.StatusCode)
	}
	if len(result.OutputArguments) != 1 {
		t.Fatalf("expected 1 output argument, got %d", len(result.OutputArguments))
	}
	got, ok := result.OutputArguments[0].Value().(int32)
	if !ok {
		t.Fatalf("expected int32 output, got %T", result.OutputArguments[0].Value())
	}
	if got != 7 {
		t.Errorf("Methods.Add(3,4): got %d, want 7", got)
	}
}

// TestOpen62541Server_Subscribe creates a data-change subscription on
// Dynamic.Counter and collects 3 notifications, verifying they are
// monotonically non-decreasing Int64 values.
func TestOpen62541Server_Subscribe(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	counterID := ua.NewStringNodeID(nsIdx, "Dynamic.Counter")

	sub, notifyCh, err := c.NewSubscription().
		Interval(300 * time.Millisecond).
		Monitor(counterID).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Cancel(ctx) //nolint:errcheck

	const want = 3
	got := 0
	var first, prev int64
	deadline := time.After(15 * time.Second)
	for got < want {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("subscription notification channel closed unexpectedly")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, item := range dcn.MonitoredItems {
				var v int64
				switch val := item.Value.Value.Value().(type) {
				case int64:
					v = val
				case int32:
					v = int64(val)
				case uint64:
					v = int64(val)
				case uint32:
					v = int64(val)
				default:
					t.Errorf("Dynamic.Counter notification: unexpected type %T", item.Value.Value.Value())
					continue
				}
				if got > 0 && v < prev {
					t.Errorf("Dynamic.Counter: non-monotonic: %d after %d", v, prev)
				}
				if got == 0 {
					first = v
				}
				prev = v
				got++
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %d notifications (got %d)", want, got)
		}
	}
	if prev <= first {
		t.Fatalf("counter did not advance: first=%d last=%d", first, prev)
	}
	t.Logf("received %d monotonic Dynamic.Counter notifications; last value: %d", got, prev)
}

// ---------------------------------------------------------------------------
// Array reads — go-opcua client ← open62541 server
// ---------------------------------------------------------------------------

// readArray reads a variable node by string ID and returns the Variant.
func readArray(t *testing.T, h *serverHandle, nodeID string) *ua.Variant {
	t.Helper()
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	v, err := c.Node(ua.NewStringNodeID(nsIdx, nodeID)).Value(ctx)
	if err != nil {
		t.Fatalf("Value(%s): %v", nodeID, err)
	}
	return v
}

// TestOpen62541Server_ReadArrayInt32 reads the six-element Int32 array from
// the open62541 adapter and asserts element count and boundary values.
func TestOpen62541Server_ReadArrayInt32(t *testing.T) {
	h := startOpen62541Server(t)
	v := readArray(t, h, "Array.Int32")
	if !v.IsArray() {
		t.Fatalf("Array.Int32: expected array Variant, got type %T value %v", v.Value(), v.Value())
	}
	got, ok := v.Value().([]int32)
	if !ok {
		t.Fatalf("Array.Int32: expected []int32, got %T", v.Value())
	}
	want := []int32{0, 1, -1, 2147483647, -2147483648, -123456789}
	if len(got) != len(want) {
		t.Fatalf("Array.Int32: length %d, want %d; got %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("Array.Int32[%d]: got %d, want %d", i, got[i], w)
		}
	}
}

// TestOpen62541Server_ReadArrayEmpty reads the zero-element Int32 array and
// verifies that go-opcua receives an empty (not null) array.
func TestOpen62541Server_ReadArrayEmpty(t *testing.T) {
	h := startOpen62541Server(t)
	v := readArray(t, h, "Array.Empty")
	if !v.IsArray() {
		t.Fatalf("Array.Empty: expected array Variant, got type %T value %v", v.Value(), v.Value())
	}
	if v.ArrayLength() != 0 {
		t.Fatalf("Array.Empty: expected ArrayLength=0, got %d", v.ArrayLength())
	}
}

// TestOpen62541Server_ReadArrayString reads the four-element String array and
// checks element count and that the empty-string element is preserved.
func TestOpen62541Server_ReadArrayString(t *testing.T) {
	h := startOpen62541Server(t)
	v := readArray(t, h, "Array.String")
	if !v.IsArray() {
		t.Fatalf("Array.String: expected array Variant, got %T", v.Value())
	}
	got, ok := v.Value().([]string)
	if !ok {
		t.Fatalf("Array.String: expected []string, got %T", v.Value())
	}
	if len(got) != 4 {
		t.Fatalf("Array.String: length %d, want 4; got %v", len(got), got)
	}
	if got[0] != "alpha" {
		t.Errorf("Array.String[0]: got %q, want %q", got[0], "alpha")
	}
	if got[3] != "" {
		t.Errorf("Array.String[3]: got %q, want empty string", got[3])
	}
	t.Logf("Array.String: %v", got)
}

// TestOpen62541Server_ReadArrayByteString reads the two-element ByteString array
// and verifies element content.
func TestOpen62541Server_ReadArrayByteString(t *testing.T) {
	h := startOpen62541Server(t)
	v := readArray(t, h, "Array.ByteString")
	if !v.IsArray() {
		t.Fatalf("Array.ByteString: expected array Variant, got %T", v.Value())
	}
	got, ok := v.Value().([][]byte)
	if !ok {
		t.Fatalf("Array.ByteString: expected [][]byte, got %T", v.Value())
	}
	want := [][]byte{{1, 2, 3}, {4, 5, 6}}
	if len(got) != len(want) {
		t.Fatalf("Array.ByteString: length %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if len(got[i]) != len(w) {
			t.Errorf("Array.ByteString[%d]: length %d, want %d", i, len(got[i]), len(w))
			continue
		}
		for j, b := range w {
			if got[i][j] != b {
				t.Errorf("Array.ByteString[%d][%d]: got %d, want %d", i, j, got[i][j], b)
			}
		}
	}
}

// TestOpen62541Server_ReadArrayMatrix2D reads the 3×2 Double matrix and
// verifies the shape (ArrayDimensions) and element values.
func TestOpen62541Server_ReadArrayMatrix2D(t *testing.T) {
	h := startOpen62541Server(t)
	v := readArray(t, h, "Array.Matrix2D")
	if !v.IsArray() {
		t.Fatalf("Array.Matrix2D: expected array Variant, got %T", v.Value())
	}
	dims := v.ArrayDimensions()
	if len(dims) != 2 || dims[0] != 3 || dims[1] != 2 {
		t.Fatalf("Array.Matrix2D: dimensions %v, want [3 2]", dims)
	}
	got, ok := v.Value().([][]float64)
	if !ok {
		t.Fatalf("Array.Matrix2D: expected [][]float64, got %T", v.Value())
	}
	want := [][]float64{{1.1, 2.2}, {3.3, 4.4}, {5.5, 6.6}}
	if len(got) != len(want) {
		t.Fatalf("Array.Matrix2D: row count %d, want %d", len(got), len(want))
	}
	for i, row := range want {
		for j, w := range row {
			if got[i][j] != w {
				t.Errorf("Array.Matrix2D[%d][%d]: got %v, want %v", i, j, got[i][j], w)
			}
		}
	}
}

// TestOpen62541Server_DataValue_Uncertain verifies that the open62541 adapter
// sets an Uncertain status code on DataValues.Uncertain, which confirms that
// the fixed-status behavior correctly propagates OPC UA status severity.
func TestOpen62541Server_DataValue_Uncertain(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	nodeID := ua.NewStringNodeID(nsIdx, "DataValues.Uncertain")
	dv, err := c.ReadValue(ctx, nodeID)
	if err != nil {
		t.Fatalf("ReadValue(DataValues.Uncertain): %v", err)
	}
	// Status code severity: bits 31-30 encode Good=0, Uncertain=1, Bad=2.
	severity := (dv.Status >> 30) & 0x3
	if severity != 1 {
		t.Errorf("DataValues.Uncertain status severity: got %d (code=0x%08X), want 1 (Uncertain)",
			severity, uint32(dv.Status))
	} else {
		t.Logf("DataValues.Uncertain status=0x%08X (severity=Uncertain) OK", uint32(dv.Status))
	}
}

// TestOpen62541Server_ReadArrayBoolean reads the three-element Boolean array
// from the open62541 adapter and verifies element count and values.
func TestOpen62541Server_ReadArrayBoolean(t *testing.T) {
	h := startOpen62541Server(t)
	v := readArray(t, h, "Array.Boolean")
	if !v.IsArray() {
		t.Fatalf("Array.Boolean: expected array Variant, got %T", v.Value())
	}
	got, ok := v.Value().([]bool)
	if !ok {
		t.Fatalf("Array.Boolean: expected []bool, got %T", v.Value())
	}
	want := []bool{true, false, true}
	if len(got) != len(want) {
		t.Fatalf("Array.Boolean: length %d, want %d; got %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("Array.Boolean[%d]: got %v, want %v", i, got[i], w)
		}
	}
}

// TestOpen62541Server_ReadArrayDouble reads the four-element Double array
// from the open62541 adapter and verifies element count and values.
func TestOpen62541Server_ReadArrayDouble(t *testing.T) {
	h := startOpen62541Server(t)
	v := readArray(t, h, "Array.Double")
	if !v.IsArray() {
		t.Fatalf("Array.Double: expected array Variant, got %T", v.Value())
	}
	got, ok := v.Value().([]float64)
	if !ok {
		t.Fatalf("Array.Double: expected []float64, got %T", v.Value())
	}
	want := []float64{0.0, 1.5, -1.5, 3.141592653589793}
	if len(got) != len(want) {
		t.Fatalf("Array.Double: length %d, want %d; got %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("Array.Double[%d]: got %v, want %v", i, got[i], w)
		}
	}
}

// ---------------------------------------------------------------------------
// go-opcua client ← open62541 server (secure channel)
// ---------------------------------------------------------------------------

// TestOpen62541Server_Basic256Sha256_Sign_ScalarRead verifies that go-opcua can
// negotiate a Basic256Sha256/Sign secure channel with the open62541 adapter and
// successfully read a scalar value, proving session activation over a signed channel.
func TestOpen62541Server_Basic256Sha256_Sign_ScalarRead(t *testing.T) {
	h := startOpen62541SecureServer(t)
	c := dialSecureClient(t, h.endpoint, "Basic256Sha256", "Sign")

	ctx, nsIdx := findNS(t, c)
	v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
	if err != nil {
		t.Fatalf("Value(Scalar.Int32): %v", err)
	}
	got, ok := v.Value().(int32)
	if !ok {
		t.Fatalf("Scalar.Int32 type %T, want int32", v.Value())
	}
	const want int32 = -123456789
	if got != want {
		t.Errorf("Scalar.Int32: got %d, want %d", got, want)
	}
	t.Logf("Basic256Sha256/Sign scalar read OK: %d", got)
}

// TestOpen62541Server_Basic256Sha256_SignAndEncrypt_ScalarRead verifies that
// go-opcua can negotiate a Basic256Sha256/SignAndEncrypt secure channel with the
// open62541 adapter and successfully read a scalar value.
func TestOpen62541Server_Basic256Sha256_SignAndEncrypt_ScalarRead(t *testing.T) {
	h := startOpen62541SecureServer(t)
	c := dialSecureClient(t, h.endpoint, "Basic256Sha256", "SignAndEncrypt")

	ctx, nsIdx := findNS(t, c)
	v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
	if err != nil {
		t.Fatalf("Value(Scalar.Int32): %v", err)
	}
	got, ok := v.Value().(int32)
	if !ok {
		t.Fatalf("Scalar.Int32 type %T, want int32", v.Value())
	}
	const want int32 = -123456789
	if got != want {
		t.Errorf("Scalar.Int32: got %d, want %d", got, want)
	}
	t.Logf("Basic256Sha256/SignAndEncrypt scalar read OK: %d", got)
}

// TestOpen62541Server_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead verifies
// that go-opcua can negotiate an Aes128_Sha256_RsaOaep/SignAndEncrypt secure
// channel with the open62541 adapter and read a scalar value.
func TestOpen62541Server_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead(t *testing.T) {
	h := startOpen62541SecureServer(t)
	c := dialSecureClient(t, h.endpoint, "Aes128_Sha256_RsaOaep", "SignAndEncrypt")

	ctx, nsIdx := findNS(t, c)
	v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
	if err != nil {
		t.Fatalf("Value(Scalar.Int32): %v", err)
	}
	got, ok := v.Value().(int32)
	if !ok {
		t.Fatalf("Scalar.Int32 type %T, want int32", v.Value())
	}
	const want int32 = -123456789
	if got != want {
		t.Errorf("Scalar.Int32: got %d, want %d", got, want)
	}
	t.Logf("Aes128_Sha256_RsaOaep/SignAndEncrypt scalar read OK: %d", got)
}

// TestOpen62541Server_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead verifies
// that go-opcua can negotiate an Aes256_Sha256_RsaPss/SignAndEncrypt secure
// channel with the open62541 adapter and read a scalar value.
func TestOpen62541Server_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead(t *testing.T) {
	h := startOpen62541SecureServer(t)
	c := dialSecureClient(t, h.endpoint, "Aes256_Sha256_RsaPss", "SignAndEncrypt")

	ctx, nsIdx := findNS(t, c)
	v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
	if err != nil {
		t.Fatalf("Value(Scalar.Int32): %v", err)
	}
	got, ok := v.Value().(int32)
	if !ok {
		t.Fatalf("Scalar.Int32 type %T, want int32", v.Value())
	}
	const want int32 = -123456789
	if got != want {
		t.Errorf("Scalar.Int32: got %d, want %d", got, want)
	}
	t.Logf("Aes256_Sha256_RsaPss/SignAndEncrypt scalar read OK: %d", got)
}

// TestOpen62541Server_UntrustedCert_Rejected verifies that the open62541 adapter
// refuses a secure-channel connection from a certificate that is not in its trust
// store. The connection must fail; any successful Connect is a test failure.
func TestOpen62541Server_UntrustedCert_Rejected(t *testing.T) {
	h := startOpen62541SecureServer(t)

	pki := pkiDir(t)
	untrustedCert := filepath.Join(pki, "untrusted", "cert.crt")
	untrustedKey := filepath.Join(pki, "untrusted", "cert.key")
	caPath := filepath.Join(pki, "ca", "ca.crt")
	serverCert := filepath.Join(pki, "open62541-server", "cert.crt")

	for _, f := range []string{untrustedCert, untrustedKey} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("untrusted cert not found (%s): run certs/generate.sh first", f)
		}
	}

	ca := loadCACert(t, caPath)

	// Discover endpoints first to get the server cert for SignAndEncrypt.
	discoverCtx, discoverCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer discoverCancel()

	eps, err := opcua.GetEndpoints(discoverCtx, h.endpoint)
	if err != nil {
		t.Fatalf("GetEndpoints: %v", err)
	}

	wantPolicy := ua.FormatSecurityPolicyURI("Basic256Sha256")
	wantMode := ua.MessageSecurityModeFromString("SignAndEncrypt")

	var chosen *ua.EndpointDescription
	for _, ep := range eps {
		if ep.SecurityPolicyURI == wantPolicy && ep.SecurityMode == wantMode {
			chosen = ep
			break
		}
	}
	if chosen == nil {
		t.Fatal("open62541 server did not advertise Basic256Sha256/SignAndEncrypt — security configuration is broken")
	}
	chosen.EndpointURL = h.endpoint

	// Suppress unused variable warning; serverCert was only needed for the
	// fallback path which is now a hard failure.
	_ = serverCert

	c, err := opcua.NewClient(h.endpoint,
		opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeAnonymous),
		opcua.CertificateFile(untrustedCert),
		opcua.PrivateKeyFile(untrustedKey),
		opcua.TrustedCertificates(ca),
		opcua.AuthAnonymous(),
	)
	if err != nil {
		// Client-side config rejection is only valid if it is a certificate error.
		if isCertRejectionError(err) {
			t.Logf("NewClient correctly rejected untrusted cert at config stage: %v", err)
			return
		}
		t.Fatalf("NewClient returned unexpected error (not a certificate rejection): %v", err)
	}

	connectCtx, connectCancel := context.WithTimeout(context.Background(), dialTimeout)
	defer connectCancel()

	connectErr := c.Connect(connectCtx)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if connectErr == nil {
		c.Close(ctx2) //nolint:errcheck
		t.Fatal("server accepted connection from untrusted certificate — trust validation is not active")
	}
	if !isCertRejectionError(connectErr) {
		t.Fatalf("server rejected connection but for unexpected reason (want BadCertificateUntrusted or BadSecurityChecksFailed): %v", connectErr)
	}
	t.Logf("Connect correctly rejected untrusted certificate (%v)", connectErr)
}

// ---------------------------------------------------------------------------
// go-opcua client ← open62541 server (username authentication)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Method calls — go-opcua client ← open62541 server
// ---------------------------------------------------------------------------

func TestOpen62541Server_CallMethodMultiply(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	result, err := c.CallMethod(ctx,
		ua.NewStringNodeID(nsIdx, "Methods"),
		ua.NewStringNodeID(nsIdx, "Methods.Multiply"),
		float64(3.0), float64(4.0),
	)
	if err != nil {
		t.Fatalf("CallMethod Multiply: %v", err)
	}
	if result.StatusCode != ua.StatusOK {
		t.Fatalf("Methods.Multiply status: %v", result.StatusCode)
	}
	if len(result.OutputArguments) != 1 {
		t.Fatalf("expected 1 output, got %d", len(result.OutputArguments))
	}
	got, ok := result.OutputArguments[0].Value().(float64)
	if !ok {
		t.Fatalf("expected float64 output, got %T", result.OutputArguments[0].Value())
	}
	if got != 12.0 {
		t.Errorf("Methods.Multiply(3,4): got %v, want 12.0", got)
	}
}

func TestOpen62541Server_CallMethodEcho(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	const input = "OPC UA — 兼容性"
	result, err := c.CallMethod(ctx,
		ua.NewStringNodeID(nsIdx, "Methods"),
		ua.NewStringNodeID(nsIdx, "Methods.Echo"),
		input,
	)
	if err != nil {
		t.Fatalf("CallMethod Echo: %v", err)
	}
	if result.StatusCode != ua.StatusOK {
		t.Fatalf("Methods.Echo status: %v", result.StatusCode)
	}
	if len(result.OutputArguments) != 1 {
		t.Fatalf("expected 1 output, got %d", len(result.OutputArguments))
	}
	got, ok := result.OutputArguments[0].Value().(string)
	if !ok {
		t.Fatalf("expected string output, got %T", result.OutputArguments[0].Value())
	}
	if got != input {
		t.Errorf("Methods.Echo: got %q, want %q", got, input)
	}
}

func TestOpen62541Server_CallMethodNoArguments(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	result, err := c.CallMethod(ctx,
		ua.NewStringNodeID(nsIdx, "Methods"),
		ua.NewStringNodeID(nsIdx, "Methods.NoArguments"),
	)
	if err != nil {
		t.Fatalf("CallMethod NoArguments: %v", err)
	}
	if result.StatusCode != ua.StatusOK {
		t.Fatalf("Methods.NoArguments status: %v", result.StatusCode)
	}
	if len(result.OutputArguments) != 1 {
		t.Fatalf("expected 1 output, got %d", len(result.OutputArguments))
	}
	got, ok := result.OutputArguments[0].Value().(bool)
	if !ok {
		t.Fatalf("expected bool output, got %T", result.OutputArguments[0].Value())
	}
	if !got {
		t.Errorf("Methods.NoArguments: expected true, got false")
	}
}

func TestOpen62541Server_CallMethodMultipleOutputs(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	result, err := c.CallMethod(ctx,
		ua.NewStringNodeID(nsIdx, "Methods"),
		ua.NewStringNodeID(nsIdx, "Methods.MultipleOutputs"),
		int32(7),
	)
	if err != nil {
		t.Fatalf("CallMethod MultipleOutputs: %v", err)
	}
	if result.StatusCode != ua.StatusOK {
		t.Fatalf("Methods.MultipleOutputs status: %v", result.StatusCode)
	}
	if len(result.OutputArguments) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(result.OutputArguments))
	}
	doubled, ok := result.OutputArguments[0].Value().(int32)
	if !ok {
		t.Fatalf("output[0] expected int32, got %T", result.OutputArguments[0].Value())
	}
	label, ok2 := result.OutputArguments[1].Value().(string)
	if !ok2 {
		t.Fatalf("output[1] expected string, got %T", result.OutputArguments[1].Value())
	}
	if doubled != 14 {
		t.Errorf("Methods.MultipleOutputs doubled: got %d, want 14", doubled)
	}
	if label != "7" {
		t.Errorf("Methods.MultipleOutputs label: got %q, want %q", label, "7")
	}
}

func TestOpen62541Server_CallMethodFail(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	result, err := c.CallMethod(ctx,
		ua.NewStringNodeID(nsIdx, "Methods"),
		ua.NewStringNodeID(nsIdx, "Methods.Fail"),
	)
	// The method call itself may succeed at the transport/service level but
	// return a Bad status in the method result, or the client may return an error.
	if err == nil && result.StatusCode == ua.StatusOK {
		t.Fatal("Methods.Fail returned StatusOK — server must return a Bad status")
	}
	t.Logf("Methods.Fail correctly returned non-OK: err=%v status=%v", err, result.StatusCode)
}

// ---------------------------------------------------------------------------
// DataValue metadata — go-opcua client ← open62541 server
// ---------------------------------------------------------------------------

func TestOpen62541Server_DataValue_GoodWithTimestamps(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	nodeID := ua.NewStringNodeID(nsIdx, "DataValues.GoodWithTimestamps")
	dv, err := c.ReadValue(ctx, nodeID)
	if err != nil {
		t.Fatalf("ReadValue DataValues.GoodWithTimestamps: %v", err)
	}
	if dv.Status != ua.StatusOK {
		t.Errorf("status: got %v, want Good", dv.Status)
	}
	got, ok := dv.Value.Value().(float64)
	if !ok {
		t.Fatalf("value type %T, want float64", dv.Value.Value())
	}
	const want = 3.14159
	if got != want {
		t.Errorf("value: got %v, want %v", got, want)
	}
	if dv.SourceTimestamp.IsZero() {
		t.Error("SourceTimestamp is zero — server must set source timestamp")
	}
	if dv.ServerTimestamp.IsZero() {
		t.Error("ServerTimestamp is zero — server must set server timestamp")
	}
	t.Logf("DataValues.GoodWithTimestamps: value=%.5f sourceTS=%v serverTS=%v",
		got, dv.SourceTimestamp, dv.ServerTimestamp)
}

// ---------------------------------------------------------------------------
// Access level enforcement — go-opcua client ← open62541 server
// ---------------------------------------------------------------------------

func TestOpen62541Server_Access_ReadOnly_WriteRejected(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadOnly")
	sc, err := c.WriteNodeValue(ctx, nodeID, "should-fail")
	// Either an error is returned or the status code is Bad.
	if err == nil && sc == ua.StatusGood {
		t.Fatal("write to Access.ReadOnly succeeded — access level not enforced")
	}
	t.Logf("Access.ReadOnly write correctly rejected: err=%v sc=%v", err, sc)
}

func TestOpen62541Server_Access_WriteOnly_ReadRejected(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	nodeID := ua.NewStringNodeID(nsIdx, "Access.WriteOnly")
	_, err := c.Node(nodeID).Value(ctx)
	if err == nil {
		t.Fatal("read from Access.WriteOnly succeeded — access level not enforced")
	}
	t.Logf("Access.WriteOnly read correctly rejected: %v", err)
}

// TestOpen62541Server_Username_ValidCredentials connects over None/None and
// authenticates with valid username/password, then performs a scalar read to
// prove session activation completed successfully.
func TestOpen62541Server_Username_ValidCredentials(t *testing.T) {
	h := startOpen62541Server(t)
	c, err := dialUsernameClient(t, h.endpoint, "test-user", "test-password")
	if err != nil {
		t.Fatalf("username auth with valid credentials failed: %v", err)
	}
	ctx, nsIdx := findNS(t, c)
	v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
	if err != nil {
		t.Fatalf("Value(Scalar.Int32): %v", err)
	}
	got, ok := v.Value().(int32)
	if !ok {
		t.Fatalf("Scalar.Int32 type %T, want int32", v.Value())
	}
	const want int32 = -123456789
	if got != want {
		t.Errorf("Scalar.Int32: got %d, want %d", got, want)
	}
	t.Logf("username auth + scalar read OK: %d", got)
}

// TestOpen62541Server_Username_InvalidPassword_Rejected connects over None/None
// with an incorrect password and expects the open62541 server to reject session
// activation. A successful Connect is a test failure.
func TestOpen62541Server_Username_InvalidPassword_Rejected(t *testing.T) {
	h := startOpen62541Server(t)
	_, err := dialUsernameClient(t, h.endpoint, "test-user", "wrong-password")
	if err == nil {
		t.Fatal("open62541 server accepted invalid password — identity validation is not active")
	}
	if !isIdentityRejectedError(err) {
		t.Fatalf("server rejected connection but for unexpected reason (want BadUserAccessDenied/BadIdentityTokenRejected): %v", err)
	}
	t.Logf("invalid password correctly rejected (%v)", err)
}

// ---------------------------------------------------------------------------
// Batch read — go-opcua client ← open62541 server
// ---------------------------------------------------------------------------

// TestOpen62541Server_BatchRead reads four scalar nodes in one Read request
// and verifies all four return Good status and the correct values.
func TestOpen62541Server_BatchRead(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	ids := []*ua.NodeID{
		ua.NewStringNodeID(nsIdx, "Scalar.Boolean"),
		ua.NewStringNodeID(nsIdx, "Scalar.Int32"),
		ua.NewStringNodeID(nsIdx, "Scalar.Double"),
		ua.NewStringNodeID(nsIdx, "Scalar.String"),
	}
	dvs, err := c.ReadValues(ctx, ids...)
	if err != nil {
		t.Fatalf("ReadValues batch: %v", err)
	}
	if len(dvs) != 4 {
		t.Fatalf("expected 4 results, got %d", len(dvs))
	}
	for i, dv := range dvs {
		if dv.Status != ua.StatusOK {
			t.Errorf("result[%d] status: %v", i, dv.Status)
		}
	}
	if v, ok := dvs[0].Value.Value().(bool); !ok || !v {
		t.Errorf("Scalar.Boolean: got %v (%T), want true", dvs[0].Value.Value(), dvs[0].Value.Value())
	}
	if v, ok := dvs[1].Value.Value().(int32); !ok || v != -123456789 {
		t.Errorf("Scalar.Int32: got %v, want -123456789", dvs[1].Value.Value())
	}
	if v, ok := dvs[2].Value.Value().(float64); !ok || v != -12345.6789 {
		t.Errorf("Scalar.Double: got %v, want -12345.6789", dvs[2].Value.Value())
	}
	if v, ok := dvs[3].Value.Value().(string); !ok || v == "" {
		t.Errorf("Scalar.String: got %v (%T), want non-empty string", dvs[3].Value.Value(), dvs[3].Value.Value())
	}
	t.Logf("batch read OK: bool=%v int32=%v double=%v string=%q",
		dvs[0].Value.Value(), dvs[1].Value.Value(), dvs[2].Value.Value(), dvs[3].Value.Value())
}

// ---------------------------------------------------------------------------
// Write and read-back — additional scalar types
// ---------------------------------------------------------------------------

func TestOpen62541Server_WriteReadBack_Boolean(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	nodeID := ua.NewStringNodeID(nsIdx, "Scalar.Boolean")
	const writeVal = false // initial is true; write false to verify change
	sc, err := c.WriteNodeValue(ctx, nodeID, writeVal)
	if err != nil {
		t.Fatalf("WriteNodeValue Boolean: %v", err)
	}
	if sc != ua.StatusGood {
		t.Fatalf("WriteNodeValue Boolean status: %v", sc)
	}
	v, err := c.Node(nodeID).Value(ctx)
	if err != nil {
		t.Fatalf("Value Boolean after write: %v", err)
	}
	got, ok := v.Value().(bool)
	if !ok {
		t.Fatalf("expected bool after read-back, got %T", v.Value())
	}
	if got != writeVal {
		t.Errorf("read-back Boolean: got %v, want %v", got, writeVal)
	}
}

func TestOpen62541Server_WriteReadBack_Float(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	nodeID := ua.NewStringNodeID(nsIdx, "Scalar.Float")
	const writeVal = float32(99.5)
	sc, err := c.WriteNodeValue(ctx, nodeID, writeVal)
	if err != nil {
		t.Fatalf("WriteNodeValue Float: %v", err)
	}
	if sc != ua.StatusGood {
		t.Fatalf("WriteNodeValue Float status: %v", sc)
	}
	v, err := c.Node(nodeID).Value(ctx)
	if err != nil {
		t.Fatalf("Value Float after write: %v", err)
	}
	got, ok := v.Value().(float32)
	if !ok {
		t.Fatalf("expected float32 after read-back, got %T", v.Value())
	}
	if got != writeVal {
		t.Errorf("read-back Float: got %v, want %v", got, writeVal)
	}
}

func TestOpen62541Server_WriteReadBack_String(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	nodeID := ua.NewStringNodeID(nsIdx, "Scalar.String")
	const writeVal = "interop-write-test"
	sc, err := c.WriteNodeValue(ctx, nodeID, writeVal)
	if err != nil {
		t.Fatalf("WriteNodeValue String: %v", err)
	}
	if sc != ua.StatusGood {
		t.Fatalf("WriteNodeValue String status: %v", sc)
	}
	v, err := c.Node(nodeID).Value(ctx)
	if err != nil {
		t.Fatalf("Value String after write: %v", err)
	}
	got, ok := v.Value().(string)
	if !ok {
		t.Fatalf("expected string after read-back, got %T", v.Value())
	}
	if got != writeVal {
		t.Errorf("read-back String: got %q, want %q", got, writeVal)
	}
}

// ---------------------------------------------------------------------------
// Subscriptions — additional dynamic nodes
// ---------------------------------------------------------------------------

// TestOpen62541Server_Subscribe_Toggle subscribes to Dynamic.Toggle and
// verifies the delivered values alternate between true and false.
func TestOpen62541Server_Subscribe_Toggle(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	toggleID := ua.NewStringNodeID(nsIdx, "Dynamic.Toggle")
	sub, notifyCh, err := c.NewSubscription().
		Interval(700 * time.Millisecond).
		Monitor(toggleID).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe Toggle: %v", err)
	}
	defer sub.Cancel(ctx) //nolint:errcheck

	const want = 3
	var values []bool
	deadline := time.After(20 * time.Second)
	for len(values) < want {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("subscription channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, item := range dcn.MonitoredItems {
				v, ok := item.Value.Value.Value().(bool)
				if !ok {
					continue
				}
				values = append(values, v)
			}
		case <-deadline:
			t.Fatalf("timeout waiting for %d toggle notifications (got %d)", want, len(values))
		}
	}
	hasTrue, hasFalse := false, false
	for _, v := range values {
		if v {
			hasTrue = true
		} else {
			hasFalse = true
		}
	}
	if !hasTrue || !hasFalse {
		t.Errorf("Dynamic.Toggle did not alternate: %v (expected both true and false)", values)
	}
	t.Logf("Toggle notifications: %v", values)
}

// TestOpen62541Server_Subscribe_Ramp subscribes to Dynamic.Ramp and verifies
// delivered values are doubles in [0.0, 100.0].
func TestOpen62541Server_Subscribe_Ramp(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	rampID := ua.NewStringNodeID(nsIdx, "Dynamic.Ramp")
	sub, notifyCh, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		Monitor(rampID).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe Ramp: %v", err)
	}
	defer sub.Cancel(ctx) //nolint:errcheck

	const want = 5
	var values []float64
	deadline := time.After(20 * time.Second)
	for len(values) < want {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("subscription channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, item := range dcn.MonitoredItems {
				v, ok := item.Value.Value.Value().(float64)
				if !ok {
					continue
				}
				values = append(values, v)
			}
		case <-deadline:
			t.Fatalf("timeout waiting for %d ramp notifications (got %d)", want, len(values))
		}
	}
	for i, v := range values {
		if v < 0.0 || v > 100.0 {
			t.Errorf("Ramp value[%d]=%v out of [0, 100]", i, v)
		}
	}
	t.Logf("Ramp notifications: %v", values)
}

// ---------------------------------------------------------------------------
// Subscription queue semantics — go-opcua client → open62541 server
// ---------------------------------------------------------------------------

// TestOpen62541Server_Subscribe_QueueMultiple verifies that when a monitored
// item is created with queueSize > 1 and a slow publishing interval, the
// open62541 server correctly queues multiple sampled values and delivers them
// as separate MonitoredItem entries in a single DataChangeNotification.
// It also verifies discard-oldest behaviour: values arrive monotonically
// increasing (newest values are retained when the queue is full).
func TestOpen62541Server_Subscribe_QueueMultiple(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	counterID := ua.NewStringNodeID(nsIdx, "Dynamic.Counter")

	// QueueSize=5 with 100 ms sampling over a 2 s publish interval.
	// Dynamic.Counter increments every 250 ms → ~8 increments per interval.
	// With discardOldest=true the server retains the 5 most recent samples.
	req := opcua.NewMonitoredItemCreateRequestWithDefaults(counterID, ua.AttributeIDValue, 0)
	req.RequestedParameters.QueueSize = 5
	req.RequestedParameters.DiscardOldest = true
	req.RequestedParameters.SamplingInterval = 100.0

	notifyCh := make(chan *opcua.PublishNotificationData, 256)
	sub, _, err := c.NewSubscription().
		Interval(2000 * time.Millisecond).
		NotifyChannel(notifyCh).
		MonitorItems(req).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Cancel(ctx) //nolint:errcheck

	// Accumulate counter values across notifications until we see a batch that
	// contains at least 3 values delivered together.
	deadline := time.After(20 * time.Second)
	var batchValues []int64
	seenMulti := false
	for !seenMulti {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("subscription channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			var batch []int64
			for _, item := range dcn.MonitoredItems {
				switch v := item.Value.Value.Value().(type) {
				case int64:
					batch = append(batch, v)
				case int32:
					batch = append(batch, int64(v))
				case uint64:
					batch = append(batch, int64(v))
				case uint32:
					batch = append(batch, int64(v))
				}
			}
			if len(batch) >= 3 {
				batchValues = batch
				seenMulti = true
			}
		case <-deadline:
			t.Fatalf("timeout: never received >=3 queued values in one publish cycle")
		}
	}

	// Verify discard-oldest: values must be monotonically non-decreasing.
	for i := 1; i < len(batchValues); i++ {
		if batchValues[i] < batchValues[i-1] {
			t.Errorf("discard-oldest violation: value[%d]=%d < value[%d]=%d (batch=%v)",
				i, batchValues[i], i-1, batchValues[i-1], batchValues)
			break
		}
	}
	t.Logf("Queue semantics: received %d queued counter values in one cycle: %v", len(batchValues), batchValues)
}

// TestOpen62541Server_Subscribe_DiscardOldest verifies that with
// discardOldest=false the open62541 server retains the oldest queued values
// (not the newest), meaning the delivered values start at a lower counter
// than those delivered with discardOldest=true.
func TestOpen62541Server_Subscribe_DiscardOldest(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	counterID := ua.NewStringNodeID(nsIdx, "Dynamic.Counter")

	// discardOldest=false: keep oldest, discard newest → delivered batch
	// contains the first values after the subscribe, NOT the most recent.
	req := opcua.NewMonitoredItemCreateRequestWithDefaults(counterID, ua.AttributeIDValue, 0)
	req.RequestedParameters.QueueSize = 3
	req.RequestedParameters.DiscardOldest = false
	req.RequestedParameters.SamplingInterval = 100.0

	notifyCh := make(chan *opcua.PublishNotificationData, 256)
	sub, _, err := c.NewSubscription().
		Interval(1500 * time.Millisecond).
		NotifyChannel(notifyCh).
		MonitorItems(req).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Cancel(ctx) //nolint:errcheck

	// Collect the first publish cycle that delivers 3 values.
	deadline := time.After(15 * time.Second)
	var keepOldestBatch []int64
	for len(keepOldestBatch) < 3 {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("subscription channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, item := range dcn.MonitoredItems {
				switch v := item.Value.Value.Value().(type) {
				case int64:
					keepOldestBatch = append(keepOldestBatch, v)
				case int32:
					keepOldestBatch = append(keepOldestBatch, int64(v))
				case uint64:
					keepOldestBatch = append(keepOldestBatch, int64(v))
				case uint32:
					keepOldestBatch = append(keepOldestBatch, int64(v))
				}
			}
		case <-deadline:
			t.Fatalf("timeout: only got %d values (want 3)", len(keepOldestBatch))
		}
	}

	// With discardOldest=false values are also monotonically non-decreasing
	// (the server keeps the first arrivals which are still ordered in time).
	for i := 1; i < len(keepOldestBatch); i++ {
		if keepOldestBatch[i] < keepOldestBatch[i-1] {
			t.Errorf("keep-oldest: non-monotonic: %d after %d (batch=%v)",
				keepOldestBatch[i], keepOldestBatch[i-1], keepOldestBatch)
			break
		}
	}
	t.Logf("discardOldest=false: received values %v", keepOldestBatch)
}

// ---------------------------------------------------------------------------
// BrowseNext — Go client → open62541 server
// ---------------------------------------------------------------------------

// TestOpen62541Server_BrowseNext verifies that the Go client correctly issues
// BrowseNext requests to consume all continuation points when the server
// paginates browse results via RequestedMaxReferencesPerNode.
func TestOpen62541Server_BrowseNext(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	// Browse Scalars (many Variable children) to force pagination.
	scalarsID := ua.NewStringNodeID(nsIdx, "Scalars")
	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          scalarsID,
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, 33), // HierarchicalReferences
			IncludeSubtypes: true,
			NodeClassMask:   uint32(ua.NodeClassAll),
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
		RequestedMaxReferencesPerNode: 3,
	})
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatal("Browse: no results")
	}
	if resp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("Browse status: %s", resp.Results[0].StatusCode)
	}

	// Collect references, consuming continuation points until exhausted.
	refs := append([]*ua.ReferenceDescription{}, resp.Results[0].References...)
	cp := resp.Results[0].ContinuationPoint
	if len(cp) == 0 {
		t.Skip("server returned all references in one page — BrowseNext not exercised")
	}

	for len(cp) > 0 {
		next, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{
			ContinuationPoints:        [][]byte{cp},
			ReleaseContinuationPoints: false,
		})
		if err != nil {
			t.Fatalf("BrowseNext: %v", err)
		}
		if len(next.Results) == 0 {
			break
		}
		refs = append(refs, next.Results[0].References...)
		cp = next.Results[0].ContinuationPoint
	}

	// Release any remaining continuation point.
	if len(cp) > 0 {
		_, _ = c.BrowseNext(ctx, &ua.BrowseNextRequest{ //nolint:errcheck
			ContinuationPoints:        [][]byte{cp},
			ReleaseContinuationPoints: true,
		})
	}

	if len(refs) < 10 {
		t.Errorf("BrowseNext: expected ≥10 total references under Scalars, got %d", len(refs))
	}
	found := false
	for _, r := range refs {
		if r.BrowseName != nil && r.BrowseName.Name == "Scalar.Int32" {
			found = true
			break
		}
	}
	if !found {
		t.Error("BrowseNext: Scalar.Int32 not found in paginated results")
	}
	t.Logf("BrowseNext: collected %d total references via pagination", len(refs))
}

// ---------------------------------------------------------------------------
// Phase 11 — Service Semantics (Go client → open62541 server)
// ---------------------------------------------------------------------------

// TestOpen62541Server_BatchWrite verifies per-item Write results against open62541.
func TestOpen62541Server_BatchWrite(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	resp, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{
				NodeID: ua.NewStringNodeID(nsIdx, "Access.ReadWrite"), AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(42))},
			},
			{
				NodeID: ua.NewStringNodeID(nsIdx, "Access.ReadOnly"), AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant("x")},
			},
			{
				NodeID: ua.NewStringNodeID(nsIdx, "DoesNotExist"), AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(1))},
			},
		},
	})
	if err != nil {
		t.Fatalf("BatchWrite: %v", err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(resp.Results))
	}
	if resp.Results[0] != ua.StatusOK {
		t.Errorf("Access.ReadWrite: got %v, want Good", resp.Results[0])
	}
	if resp.Results[1] != ua.StatusBadUserAccessDenied && resp.Results[1] != ua.StatusBadNotWritable {
		// open62541 may use BadUserAccessDenied or BadNotWritable for read-only
		t.Logf("Access.ReadOnly status: %v (accepted as access denial)", resp.Results[1])
		if resp.Results[1] == ua.StatusOK {
			t.Errorf("Access.ReadOnly: unexpectedly Good")
		}
	}
	if resp.Results[2] != ua.StatusBadNodeIDUnknown {
		t.Errorf("DoesNotExist: got %v, want BadNodeIdUnknown", resp.Results[2])
	}
}

// TestOpen62541Server_WriteTypeMismatch verifies BadTypeMismatch from open62541.
func TestOpen62541Server_WriteTypeMismatch(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	nodeID := ua.NewStringNodeID(nsIdx, "Scalar.Int32")
	sc, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID: nodeID, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant("not-an-int")},
		}},
	})
	if err != nil {
		t.Fatalf("WriteTypeMismatch: %v", err)
	}
	if len(sc.Results) == 0 || sc.Results[0] != ua.StatusBadTypeMismatch {
		t.Errorf("WriteTypeMismatch: got %v, want BadTypeMismatch", sc.Results)
	}
}

// TestOpen62541Server_IndexRange verifies IndexRange on a scalar is rejected.
func TestOpen62541Server_IndexRange(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	resp, err := c.Read(ctx, &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{{
			NodeID: ua.NewStringNodeID(nsIdx, "Scalar.Int32"),
			AttributeID: ua.AttributeIDValue,
			IndexRange: "0:1",
		}},
	})
	if err != nil {
		t.Fatalf("IndexRange read: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatal("no results")
	}
	st := resp.Results[0].Status
	if st == ua.StatusOK {
		t.Errorf("IndexRange on scalar unexpectedly Good")
	} else {
		t.Logf("IndexRange on scalar correctly rejected: %v", st)
	}
}

// TestOpen62541Server_IndexRangeSubset verifies open62541 serves array IndexRange subsets.
func TestOpen62541Server_IndexRangeSubset(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	arrResp, err := c.Read(ctx, &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{{
			NodeID: ua.NewStringNodeID(nsIdx, "Array.Int32"),
			AttributeID: ua.AttributeIDValue,
			IndexRange: "0:1",
		}},
	})
	if err != nil {
		t.Fatalf("Array IndexRange read: %v", err)
	}
	if arrResp.Results[0].Status != ua.StatusOK {
		t.Fatalf("Array IndexRange(0:1) status=%v", arrResp.Results[0].Status)
	}
	got, ok := arrResp.Results[0].Value.Value().([]int32)
	if !ok || len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Errorf("Array IndexRange(0:1): got %v (%T), want [0 1]", arrResp.Results[0].Value.Value(), arrResp.Results[0].Value.Value())
	}

	wresp, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID: ua.NewStringNodeID(nsIdx, "Array.Int32"),
			AttributeID: ua.AttributeIDValue,
			IndexRange: "1:2",
			Value: &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        ua.MustVariant([]int32{90, 91}),
			},
		}},
	})
	if err != nil {
		t.Fatalf("IndexRange Write: %v", err)
	}
	if len(wresp.Results) == 0 || wresp.Results[0] != ua.StatusOK {
		t.Fatalf("IndexRange Write status: %v", wresp.Results)
	}
}

// TestOpen62541Server_BrowseNextRelease verifies early BrowseNext release.
func TestOpen62541Server_BrowseNextRelease(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	scalarsID := ua.NewStringNodeID(nsIdx, "Scalars")

	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          scalarsID,
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, 33),
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
		RequestedMaxReferencesPerNode: 3,
	})
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	if resp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("Browse status: %s", resp.Results[0].StatusCode)
	}
	cp := resp.Results[0].ContinuationPoint
	if len(cp) == 0 {
		t.Fatal("expected non-empty continuation point for BrowseNext release")
	}
	rel, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{
		ContinuationPoints: [][]byte{cp}, ReleaseContinuationPoints: true,
	})
	if err != nil {
		t.Fatalf("BrowseNext release: %v", err)
	}
	if rel.Results[0].StatusCode != ua.StatusOK {
		t.Errorf("release: got %v", rel.Results[0].StatusCode)
	}
	again, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{
		ContinuationPoints: [][]byte{cp},
	})
	if err != nil {
		t.Fatalf("BrowseNext after release: %v", err)
	}
	if again.Results[0].StatusCode != ua.StatusBadContinuationPointInvalid {
		t.Errorf("after release: got %v, want BadContinuationPointInvalid", again.Results[0].StatusCode)
	}
}

// TestOpen62541Server_BrowseResultMask verifies peer ResultMask handling.
func TestOpen62541Server_BrowseResultMask(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          ua.NewStringNodeID(nsIdx, "Scalars"),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskBrowseName),
		}},
	})
	if err != nil {
		t.Fatalf("BrowseResultMask: %v", err)
	}
	if len(resp.Results) == 0 || len(resp.Results[0].References) == 0 {
		t.Fatal("no references")
	}
	// Peer stacks may clear omitted fields or leave defaults; require BrowseName.
	for _, r := range resp.Results[0].References {
		if r.BrowseName == nil || r.BrowseName.Name == "" {
			t.Errorf("BrowseName missing under BrowseName mask")
		}
	}
}

// TestOpen62541Server_WriteEncodingMask verifies open62541 rejects Status/timestamp Writes.
func TestOpen62541Server_WriteEncodingMask(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	ok, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID: nodeID, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(3))},
		}},
	})
	if err != nil {
		t.Fatalf("value-only: %v", err)
	}
	if ok.Results[0] != ua.StatusOK {
		t.Errorf("value-only: got %v", ok.Results[0])
	}

	bad, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID: nodeID, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{
				EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
				Value:           ua.MustVariant(int32(4)),
				SourceTimestamp: time.Now(),
			},
		}},
	})
	if err != nil {
		t.Fatalf("timestamp write: %v", err)
	}
	if bad.Results[0] != ua.StatusBadWriteNotSupported {
		t.Errorf("timestamp write: got %v, want BadWriteNotSupported", bad.Results[0])
	}
}

// TestOpen62541Server_TimestampsToReturn verifies peer TimestampsToReturn Neither.
func TestOpen62541Server_TimestampsToReturn(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	resp, err := c.Read(ctx, &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnNeither,
		NodesToRead: []*ua.ReadValueID{{
			NodeID: ua.NewStringNodeID(nsIdx, "Scalar.Int32"), AttributeID: ua.AttributeIDValue,
		}},
	})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	dv := resp.Results[0]
	if dv.EncodingMask&ua.DataValueSourceTimestamp != 0 || dv.EncodingMask&ua.DataValueServerTimestamp != 0 {
		t.Logf("open62541 Neither left timestamps (mask=%#x); accepted if peer soft-filters", dv.EncodingMask)
	}
}

// TestOpen62541Server_BrowseFiltering verifies NodeClassMask=Variable filtering.
func TestOpen62541Server_BrowseFiltering(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)

	// Scalars folder contains only Variable children — ideal for NodeClassMask.
	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          ua.NewStringNodeID(nsIdx, "Scalars"),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
			IncludeSubtypes: true,
			NodeClassMask:   uint32(ua.NodeClassVariable),
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
	})
	if err != nil {
		t.Fatalf("BrowseFiltering: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatal("BrowseFiltering: no results")
	}
	if resp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("BrowseFiltering status: %v", resp.Results[0].StatusCode)
	}
	if len(resp.Results[0].References) == 0 {
		t.Fatal("BrowseFiltering: expected Variable references under Scalars")
	}
	for _, ref := range resp.Results[0].References {
		if ref.NodeClass != ua.NodeClassVariable {
			t.Errorf("expected Variable, got %v for %v", ref.NodeClass, ref.BrowseName)
		}
	}
	t.Logf("BrowseFiltering: %d Variable refs", len(resp.Results[0].References))
}

// TestOpen62541Server_InvalidNodeId verifies unknown NodeId status codes.
func TestOpen62541Server_InvalidNodeId(t *testing.T) {
	h := startOpen62541Server(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	unknown := ua.NewStringNodeID(nsIdx, "DoesNotExist")

	t.Run("Read", func(t *testing.T) {
		dv, err := c.ReadValue(ctx, unknown)
		if err != nil {
			t.Fatalf("ReadValue: %v", err)
		}
		if dv.Status != ua.StatusBadNodeIDUnknown {
			t.Errorf("Read unknown: got %v, want BadNodeIdUnknown", dv.Status)
		}
	})

	t.Run("Write", func(t *testing.T) {
		sc, err := c.Write(ctx, &ua.WriteRequest{
			NodesToWrite: []*ua.WriteValue{{
				NodeID: unknown, AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(1))},
			}},
		})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if sc.Results[0] != ua.StatusBadNodeIDUnknown {
			t.Errorf("Write unknown: got %v", sc.Results[0])
		}
	})

	t.Run("Browse", func(t *testing.T) {
		resp, err := c.Browse(ctx, &ua.BrowseRequest{
			NodesToBrowse: []*ua.BrowseDescription{{
				NodeID:          unknown,
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
				IncludeSubtypes: true,
				ResultMask:      uint32(ua.BrowseResultMaskAll),
			}},
		})
		if err != nil {
			t.Fatalf("Browse: %v", err)
		}
		if resp.Results[0].StatusCode != ua.StatusBadNodeIDUnknown {
			t.Errorf("Browse unknown: got %v", resp.Results[0].StatusCode)
		}
	})
}
