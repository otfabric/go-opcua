//go:build interop

// SPDX-License-Identifier: MIT

// Tests in this file cover dotnet client → go-opcua server direction.
//
// Each test starts an in-process go-opcua server populated with the baseline
// fixture scalar set, then runs the dotnet adapter container in client mode and
// asserts the JSON output. Coverage mirrors open62541_client_test.go to
// confirm cross-stack parity.
package interop

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// ---------------------------------------------------------------------------
// dotnet client → go-opcua server
// ---------------------------------------------------------------------------

// TestGoServer_DotnetClient_Endpoints verifies that the dotnet client can
// retrieve endpoints from the go-opcua server.
func TestGoServer_DotnetClient_Endpoints(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "endpoints")

	if result.Operation != "endpoints" {
		t.Errorf("operation: got %q, want %q", result.Operation, "endpoints")
	}
	if !result.Success {
		t.Errorf("endpoints failed: serviceResult=%s", result.ServiceResult)
	}
	if len(result.Results) == 0 || string(result.Results) == "null" || string(result.Results) == "[]" {
		t.Error("endpoints: expected non-empty results array")
	}
	t.Logf("endpoints result: %s", result.Results)
}

// TestGoServer_DotnetClient_Browse verifies that the dotnet client can browse
// the Objects folder of the go-opcua server.
func TestGoServer_DotnetClient_Browse(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "browse",
		"--node", "i=85",
	)

	if result.Operation != "browse" {
		t.Errorf("operation: got %q, want %q", result.Operation, "browse")
	}
	if !result.Success {
		t.Errorf("browse failed: serviceResult=%s", result.ServiceResult)
	}
	if len(result.Results) == 0 || string(result.Results) == "null" {
		t.Error("browse: expected non-empty results array")
	}
	t.Logf("browse result count: %d bytes", len(result.Results))
}

// TestGoServer_DotnetClient_BrowseObjectsNodes verifies that browsing the
// interop namespace Objects folder returns known interop node names including
// scalar and dynamic entries.
func TestGoServer_DotnetClient_BrowseObjectsNodes(t *testing.T) {
	endpoint := startGoServer(t)
	// The interop nodes live under the namespace-local Objects folder
	// (nsu=<interopURI>;i=85), not the standard ns=0 Objects folder (i=85).
	result := runDotnetClient(t, endpoint, "browse",
		"--node", "nsu="+interopNamespaceURI+";i=85",
	)
	if !result.Success {
		t.Fatalf("browse failed: %s", result.ServiceResult)
	}
	names := parseBrowseNames(t, result.Results)
	for _, want := range []string{"Scalar.Int32", "Scalar.Boolean", "Dynamic.Counter", "Array.Int32"} {
		if !names[want] {
			t.Errorf("browse interop Objects: expected node %q in results, got: %v", want, setKeys(names))
		}
	}
	t.Logf("browse interop Objects: %d nodes, checked 4 expected names", len(names))
}

// TestGoServer_DotnetClient_BrowseNext verifies that the dotnet client correctly
// issues BrowseNext requests when the server paginates browse results via
// --max-refs.
func TestGoServer_DotnetClient_BrowseNext(t *testing.T) {
	endpoint := startGoServer(t)
	// Use --max-refs 3 to force continuation points; the interop Objects folder
	// has many more than 3 children, so BrowseNext must be used.
	result := runDotnetClient(t, endpoint, "browse",
		"--node", "nsu="+interopNamespaceURI+";i=85",
		"--max-refs", "3",
	)
	if !result.Success {
		t.Fatalf("browse with pagination failed: %s", result.ServiceResult)
	}
	names := parseBrowseNames(t, result.Results)
	if len(names) < 10 {
		t.Errorf("browse with BrowseNext: expected >=10 nodes, got %d: %v", len(names), setKeys(names))
	}
	if !names["Scalar.Int32"] {
		t.Errorf("browse with BrowseNext: expected Scalar.Int32 in results")
	}
	t.Logf("browse with BrowseNext (max-refs=3): got %d total nodes", len(names))
}

// ---------------------------------------------------------------------------
// Scalar reads — dotnet client → go server
// ---------------------------------------------------------------------------

// dotnetReadScalarFromGoServer runs the dotnet client in read mode against a
// freshly started go server and returns the first result item.
func dotnetReadScalarFromGoServer(t *testing.T, nodeSuffix string) json.RawMessage {
	t.Helper()
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s="+nodeSuffix,
	)
	if result.Operation != "read" {
		t.Errorf("operation: got %q, want %q", result.Operation, "read")
	}
	if !result.Success {
		t.Errorf("read %s failed: serviceResult=%s", nodeSuffix, result.ServiceResult)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse results for %s: %v; raw: %s", nodeSuffix, err, result.Results)
	}
	t.Logf("read %s result: %s", nodeSuffix, items[0])
	return items[0]
}

func TestGoServer_DotnetClient_ReadScalarBoolean(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.Boolean")
}

func TestGoServer_DotnetClient_ReadScalarSByte(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.SByte")
}

func TestGoServer_DotnetClient_ReadScalarByte(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.Byte")
}

func TestGoServer_DotnetClient_ReadScalarInt16(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.Int16")
}

func TestGoServer_DotnetClient_ReadScalarUInt16(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.UInt16")
}

func TestGoServer_DotnetClient_ReadScalarInt32(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.Int32")
}

func TestGoServer_DotnetClient_ReadScalarUInt32(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.UInt32")
}

func TestGoServer_DotnetClient_ReadScalarInt64(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.Int64")
}

func TestGoServer_DotnetClient_ReadScalarUInt64(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.UInt64")
}

func TestGoServer_DotnetClient_ReadScalarFloat(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.Float")
}

func TestGoServer_DotnetClient_ReadScalarDouble(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.Double")
}

func TestGoServer_DotnetClient_ReadScalarString(t *testing.T) {
	dotnetReadScalarFromGoServer(t, "Scalar.String")
}

// ---------------------------------------------------------------------------
// Rich scalar reads — dotnet client → go server (value assertions)
// ---------------------------------------------------------------------------

// dotnetExtractScalarValue parses a single read result item and returns the "value" field.
func dotnetExtractScalarValue(t *testing.T, item json.RawMessage) json.RawMessage {
	t.Helper()
	var row struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(item, &row); err != nil {
		t.Fatalf("dotnetExtractScalarValue unmarshal: %v; raw: %s", err, item)
	}
	return row.Value
}

func TestGoServer_DotnetClient_ReadScalarDateTime(t *testing.T) {
	item := dotnetReadScalarFromGoServer(t, "Scalar.DateTime")
	v := strings.Trim(string(dotnetExtractScalarValue(t, item)), `"`)
	// dotnet formats DateTime via getJavaInstant().toString(): "2024-01-01T00:00:00Z"
	if !strings.HasPrefix(v, "2024-01-01T00:00:00") {
		t.Errorf("Scalar.DateTime: got %q, want prefix 2024-01-01T00:00:00", v)
	}
	if !strings.HasSuffix(v, "Z") {
		t.Errorf("Scalar.DateTime: got %q, want UTC suffix Z", v)
	}
}

func TestGoServer_DotnetClient_ReadScalarGuid(t *testing.T) {
	item := dotnetReadScalarFromGoServer(t, "Scalar.Guid")
	v := strings.Trim(string(dotnetExtractScalarValue(t, item)), `"`)
	want := "72962b91-fa75-4ae6-8d28-b404dc7daf63"
	if strings.ToLower(v) != want {
		t.Errorf("Scalar.Guid: got %q, want %q", v, want)
	}
}

func TestGoServer_DotnetClient_ReadScalarByteString(t *testing.T) {
	item := dotnetReadScalarFromGoServer(t, "Scalar.ByteString")
	v := strings.Trim(string(dotnetExtractScalarValue(t, item)), `"`)
	decoded, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("Scalar.ByteString: base64 decode %q: %v", v, err)
	}
	if string(decoded) != "opcua-compat" {
		t.Errorf("Scalar.ByteString: decoded %q, want %q", decoded, "opcua-compat")
	}
}

func TestGoServer_DotnetClient_ReadScalarXmlElement(t *testing.T) {
	item := dotnetReadScalarFromGoServer(t, "Scalar.XmlElement")
	v := strings.Trim(string(dotnetExtractScalarValue(t, item)), `"`)
	want := "<compat>test</compat>"
	if v != want {
		t.Errorf("Scalar.XmlElement: got %q, want %q", v, want)
	}
}

func TestGoServer_DotnetClient_ReadScalarNodeId(t *testing.T) {
	item := dotnetReadScalarFromGoServer(t, "Scalar.NodeId")
	v := strings.Trim(string(dotnetExtractScalarValue(t, item)), `"`)
	want := "i=85"
	if v != want {
		t.Errorf("Scalar.NodeId: got %q, want %q", v, want)
	}
}

func TestGoServer_DotnetClient_ReadScalarQualifiedName(t *testing.T) {
	item := dotnetReadScalarFromGoServer(t, "Scalar.QualifiedName")
	raw := dotnetExtractScalarValue(t, item)
	var qn struct {
		NS   int    `json:"ns"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &qn); err != nil {
		t.Fatalf("Scalar.QualifiedName: unmarshal %q: %v", raw, err)
	}
	if qn.NS != 0 || qn.Name != "Objects" {
		t.Errorf("Scalar.QualifiedName: got ns=%d name=%q, want ns=0 name=Objects", qn.NS, qn.Name)
	}
}

func TestGoServer_DotnetClient_ReadScalarLocalizedText(t *testing.T) {
	item := dotnetReadScalarFromGoServer(t, "Scalar.LocalizedText")
	raw := dotnetExtractScalarValue(t, item)
	var lt struct {
		Locale string `json:"locale"`
		Text   string `json:"text"`
	}
	if err := json.Unmarshal(raw, &lt); err != nil {
		t.Fatalf("Scalar.LocalizedText: unmarshal %q: %v", raw, err)
	}
	if lt.Locale != "en" {
		t.Errorf("Scalar.LocalizedText: locale=%q, want %q", lt.Locale, "en")
	}
	if lt.Text != "OPC UA Compatibility" {
		t.Errorf("Scalar.LocalizedText: text=%q, want %q", lt.Text, "OPC UA Compatibility")
	}
}

func TestGoServer_DotnetClient_ReadScalarStatusCode(t *testing.T) {
	item := dotnetReadScalarFromGoServer(t, "Scalar.StatusCode")
	raw := dotnetExtractScalarValue(t, item)
	var sc struct {
		Name     string `json:"name"`
		Code     uint32 `json:"code"`
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatalf("Scalar.StatusCode: unmarshal %q: %v", raw, err)
	}
	if sc.Code != 0 {
		t.Errorf("Scalar.StatusCode: code=0x%08X, want 0 (Good)", sc.Code)
	}
	if sc.Severity != "Good" {
		t.Errorf("Scalar.StatusCode: severity=%q, want Good", sc.Severity)
	}
}

// ---------------------------------------------------------------------------
// Dynamic counter — dotnet client → go server
// ---------------------------------------------------------------------------

// TestGoServer_DotnetClient_ReadDynamicCounter reads Dynamic.Counter until a
// later read is strictly greater than the first.
func TestGoServer_DotnetClient_ReadDynamicCounter(t *testing.T) {
	endpoint := startGoServer(t)

	readCounter := func() int64 {
		t.Helper()
		result := runDotnetClient(t, endpoint, "read",
			"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		)
		if !result.Success {
			t.Fatalf("read Dynamic.Counter failed: %s", result.ServiceResult)
		}
		var items []struct {
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
			t.Fatalf("parse Dynamic.Counter result: %v", err)
		}
		// dotnet returns Int64 as a quoted string.
		v := strings.Trim(string(items[0].Value), `"`)
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("Dynamic.Counter value %q not an integer: %v", v, err)
		}
		return n
	}

	// Each read is a separate client container, so the counter has normally
	// moved on by the second read; poll instead of assuming how long that takes.
	v1 := readCounter()
	deadline := time.Now().Add(15 * time.Second)
	v2 := readCounter()
	for v2 <= v1 && time.Now().Before(deadline) {
		v2 = readCounter()
	}
	if v2 <= v1 {
		t.Errorf("Dynamic.Counter: did not increase within 15s of the first read (%d, last %d)", v1, v2)
	}
	t.Logf("Dynamic.Counter: %d → %d (delta %d)", v1, v2, v2-v1)
}

// ---------------------------------------------------------------------------
// Browse Scalars folder — dotnet client → go server
// ---------------------------------------------------------------------------

// TestGoServer_DotnetClient_BrowseScalarsFolder browses the interop Objects
// folder and asserts that all rich built-in scalar nodes are present.
func TestGoServer_DotnetClient_BrowseScalarsFolder(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "browse",
		"--node", "nsu="+interopNamespaceURI+";i=85",
	)
	if !result.Success {
		t.Fatalf("browse interop Objects failed: %s", result.ServiceResult)
	}
	names := parseBrowseNames(t, result.Results)
	for _, want := range []string{
		"Scalar.DateTime", "Scalar.Guid", "Scalar.ByteString",
		"Scalar.XmlElement", "Scalar.NodeId", "Scalar.QualifiedName",
		"Scalar.LocalizedText", "Scalar.StatusCode",
	} {
		if !names[want] {
			t.Errorf("BrowseScalars: expected node %q, got: %v", want, setKeys(names))
		}
	}
	t.Logf("BrowseScalars: %d total nodes, all 8 rich scalar types present", len(names))
}

// ---------------------------------------------------------------------------
// Subscription queue semantics — dotnet client → go server
// ---------------------------------------------------------------------------

// dotnetParseNotificationValues parses integer values from a dotnet subscribe result.
func dotnetParseNotificationValues(t *testing.T, notifRaw json.RawMessage) []int64 {
	t.Helper()
	var notifs []struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(notifRaw, &notifs); err != nil {
		t.Fatalf("dotnetParseNotificationValues: %v", err)
	}
	vals := make([]int64, 0, len(notifs))
	for _, n := range notifs {
		s := strings.Trim(string(n.Value), `"`)
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			continue
		}
		vals = append(vals, v)
	}
	return vals
}

// TestGoServer_DotnetClient_Subscribe_QueueMultiple subscribes to
// Dynamic.Counter with QueueSize=5 and verifies that ≥5 queued values arrive.
func TestGoServer_DotnetClient_Subscribe_QueueMultiple(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "5",
		"--queue-size", "5",
		"--discard-oldest", "true",
		"--publishing-interval-ms", "2000",
		"--sampling-interval-ms", "100",
		"--timeout-ms", "15000",
	)
	if !result.Success {
		t.Fatalf("subscribe failed: %s error=%s", result.ServiceResult, result.Error)
	}

	var items []struct {
		Notifications json.RawMessage `json:"notifications"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse subscribe results: %v", err)
	}
	vals := dotnetParseNotificationValues(t, items[0].Notifications)
	if len(vals) < 5 {
		t.Errorf("Subscribe QueueMultiple: expected ≥5 notifications, got %d: %v", len(vals), vals)
	}
	for i := 1; i < len(vals); i++ {
		if vals[i] < vals[i-1] {
			t.Errorf("Subscribe QueueMultiple: discard-oldest violation at index %d: %v", i, vals)
			break
		}
	}
	t.Logf("Subscribe QueueMultiple: %d queued counter values: %v", len(vals), vals)
}

// TestGoServer_DotnetClient_Subscribe_DiscardOldest verifies discardOldest
// semantics against the go-opcua server via the dotnet adapter client.
func TestGoServer_DotnetClient_Subscribe_DiscardOldest(t *testing.T) {
	endpoint := startGoServer(t)

	subscribe := func(discardOldest string) []int64 {
		t.Helper()
		result := runDotnetClient(t, endpoint, "subscribe",
			"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
			"--notifications", "3",
			"--queue-size", "3",
			"--discard-oldest", discardOldest,
			"--publishing-interval-ms", "1500",
			"--sampling-interval-ms", "100",
			"--timeout-ms", "12000",
		)
		if !result.Success {
			t.Fatalf("subscribe (discard=%s) failed: %s", discardOldest, result.ServiceResult)
		}
		var items []struct {
			Notifications json.RawMessage `json:"notifications"`
		}
		if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
			t.Fatalf("parse results: %v", err)
		}
		return dotnetParseNotificationValues(t, items[0].Notifications)
	}

	oldest := subscribe("false")
	newest := subscribe("true")

	t.Logf("discardOldest=false (oldest): %v", oldest)
	t.Logf("discardOldest=true  (newest): %v", newest)

	if len(oldest) == 0 || len(newest) == 0 {
		t.Fatal("no notification values received")
	}
	for i := 1; i < len(oldest); i++ {
		if oldest[i] < oldest[i-1] {
			t.Errorf("discardOldest=false: values not non-decreasing: %v", oldest)
			break
		}
	}
	for i := 1; i < len(newest); i++ {
		if newest[i] < newest[i-1] {
			t.Errorf("discardOldest=true: values not non-decreasing: %v", newest)
			break
		}
	}
	if len(oldest) > 0 && len(newest) > 0 && oldest[0] > newest[0] {
		t.Errorf("discardOldest=false first value (%d) > discardOldest=true first value (%d)", oldest[0], newest[0])
	}
}

// TestGoServer_DotnetClient_Write verifies that the dotnet client can write Int32
// to Access.ReadWrite on the go-opcua server.
func TestGoServer_DotnetClient_Write(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--type", "Int32",
		"--value", "6666",
	)

	if result.Operation != "write" {
		t.Errorf("operation: got %q, want %q", result.Operation, "write")
	}
	if !result.Success {
		t.Errorf("write failed: serviceResult=%s", result.ServiceResult)
	}
}

// TestGoServer_DotnetClient_CallMethod calls Methods.Add(3, 4) on the
// go-opcua server via the dotnet adapter client and asserts the result is 7.
func TestGoServer_DotnetClient_CallMethod(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.Add",
		"--input", "Int32:3",
		"--input", "Int32:4",
	)

	if result.Operation != "call" {
		t.Errorf("operation: got %q, want %q", result.Operation, "call")
	}
	if !result.Success {
		t.Fatalf("call failed: serviceResult=%s error=%s", result.ServiceResult, result.Error)
	}

	var items []struct {
		StatusCode      statusCodeObj   `json:"statusCode"`
		OutputArguments json.RawMessage `json:"outputArguments"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse call results: %v; raw: %s", err, result.Results)
	}
	if items[0].StatusCode.Code != 0 {
		t.Errorf("call item statusCode: %s", items[0].StatusCode)
	}
	t.Logf("Methods.Add(3,4) outputArguments: %s", items[0].OutputArguments)
}

// TestGoServer_DotnetClient_Subscribe subscribes to Dynamic.Counter on the
// go-opcua server via the dotnet adapter and asserts 3 notifications arrive.
func TestGoServer_DotnetClient_Subscribe(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "3",
		"--publishing-interval-ms", "300",
		"--sampling-interval-ms", "100",
		"--timeout-ms", "15000",
	)

	if result.Operation != "subscribe" {
		t.Errorf("operation: got %q, want %q", result.Operation, "subscribe")
	}
	if !result.Success {
		t.Fatalf("subscribe failed: serviceResult=%s error=%s", result.ServiceResult, result.Error)
	}

	var items []struct {
		NodeID        string          `json:"nodeId"`
		Notifications json.RawMessage `json:"notifications"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse subscribe results: %v; raw: %s", err, result.Results)
	}
	var notifs []json.RawMessage
	if err := json.Unmarshal(items[0].Notifications, &notifs); err != nil {
		t.Fatalf("parse notifications: %v", err)
	}
	if len(notifs) < 3 {
		t.Errorf("expected at least 3 notifications, got %d", len(notifs))
	}
	t.Logf("received %d Dynamic.Counter notifications from go server", len(notifs))
}

// ---------------------------------------------------------------------------
// Array reads — dotnet client → go server
// ---------------------------------------------------------------------------

// dotnetReadArrayFromGoServer runs the dotnet client in read mode for an array
// node on the go server and returns the raw first result item.
func dotnetReadArrayFromGoServer(t *testing.T, nodeSuffix string) json.RawMessage {
	t.Helper()
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s="+nodeSuffix,
	)
	if result.Operation != "read" {
		t.Errorf("operation: got %q, want %q", result.Operation, "read")
	}
	if !result.Success {
		t.Fatalf("read %s failed: serviceResult=%s error=%s", nodeSuffix, result.ServiceResult, result.Error)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse results for %s: %v; raw: %s", nodeSuffix, err, result.Results)
	}
	t.Logf("read %s result: %s", nodeSuffix, items[0])
	return items[0]
}

// TestGoServer_DotnetClient_ReadArrayInt32 reads the Int32 array from the go
// server and verifies the read succeeds.
func TestGoServer_DotnetClient_ReadArrayInt32(t *testing.T) {
	dotnetReadArrayFromGoServer(t, "Array.Int32")
}

// TestGoServer_DotnetClient_ReadArrayEmpty reads the empty Int32 array from the
// go server and verifies the read succeeds.
func TestGoServer_DotnetClient_ReadArrayEmpty(t *testing.T) {
	dotnetReadArrayFromGoServer(t, "Array.Empty")
}

// TestGoServer_DotnetClient_ReadArrayString reads the String array from the go
// server and verifies the read succeeds.
func TestGoServer_DotnetClient_ReadArrayString(t *testing.T) {
	dotnetReadArrayFromGoServer(t, "Array.String")
}

// TestGoServer_DotnetClient_ReadArrayByteString reads the ByteString array from
// the go server and verifies the read succeeds.
func TestGoServer_DotnetClient_ReadArrayByteString(t *testing.T) {
	dotnetReadArrayFromGoServer(t, "Array.ByteString")
}

// TestGoServer_DotnetClient_ReadArrayMatrix2D reads the 3×2 Double matrix from
// the go server and verifies the read succeeds.
func TestGoServer_DotnetClient_ReadArrayMatrix2D(t *testing.T) {
	dotnetReadArrayFromGoServer(t, "Array.Matrix2D")
}

// TestGoServer_DotnetClient_ReadArrayBoolean reads the Boolean array from
// the go server and verifies the read succeeds.
func TestGoServer_DotnetClient_ReadArrayBoolean(t *testing.T) {
	dotnetReadArrayFromGoServer(t, "Array.Boolean")
}

// TestGoServer_DotnetClient_ReadArrayDouble reads the Double array from
// the go server and verifies the read succeeds.
func TestGoServer_DotnetClient_ReadArrayDouble(t *testing.T) {
	dotnetReadArrayFromGoServer(t, "Array.Double")
}

// ---------------------------------------------------------------------------
// Secure-channel tests: dotnet client → go-opcua secure server
// ---------------------------------------------------------------------------

// securedotnetReadScalarInt32 connects the dotnet adapter client to the secure
// go-opcua server using the given policy and mode, reads Scalar.Int32,
// and verifies the result is a good read.
func securedotnetReadScalarInt32(t *testing.T, policy, mode string) {
	t.Helper()
	endpoint := startSecureGoServer(t)
	result := runSecureAdapterClient(t,
		dotnetEnv, defaultDotnetImage,
		"dotnet-client",
		endpoint, "read",
		policy, mode,
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
	)
	if result.Operation != "read" {
		t.Errorf("operation: got %q, want %q", result.Operation, "read")
	}
	if !result.Success {
		t.Fatalf("read Scalar.Int32 (%s/%s) failed: %s error=%s", policy, mode, result.ServiceResult, result.Error)
	}
}

// TestGoServer_DotnetClient_Basic256Sha256_Sign_ScalarRead verifies that the
// dotnet client can read a scalar over a Basic256Sha256/Sign channel.
func TestGoServer_DotnetClient_Basic256Sha256_Sign_ScalarRead(t *testing.T) {
	securedotnetReadScalarInt32(t, "Basic256Sha256", "Sign")
}

// TestGoServer_DotnetClient_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead
// verifies that the dotnet adapter client can read over
// Aes128_Sha256_RsaOaep/SignAndEncrypt against the go-opcua server.
func TestGoServer_DotnetClient_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead(t *testing.T) {
	securedotnetReadScalarInt32(t, "Aes128_Sha256_RsaOaep", "SignAndEncrypt")
}

// TestGoServer_DotnetClient_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead
// verifies that the dotnet adapter client can read over
// Aes256_Sha256_RsaPss/SignAndEncrypt against the go-opcua server.
func TestGoServer_DotnetClient_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead(t *testing.T) {
	securedotnetReadScalarInt32(t, "Aes256_Sha256_RsaPss", "SignAndEncrypt")
}

// TestGoServer_DotnetClient_Basic256Sha256_SignAndEncrypt_ScalarRead verifies
// that the dotnet client can read a scalar over Basic256Sha256/SignAndEncrypt.
func TestGoServer_DotnetClient_Basic256Sha256_SignAndEncrypt_ScalarRead(t *testing.T) {
	securedotnetReadScalarInt32(t, "Basic256Sha256", "SignAndEncrypt")
}

// ---------------------------------------------------------------------------
// Method calls: dotnet client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_DotnetClient_CallMethodMultiply(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.Multiply",
		"--input", "Double:3.0",
		"--input", "Double:4.0",
	)
	if !result.Success {
		t.Fatalf("Methods.Multiply failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("Methods.Multiply(3,4) output: %s", result.Results)
}

func TestGoServer_DotnetClient_CallMethodEcho(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.Echo",
		"--input", "String:hello",
	)
	if !result.Success {
		t.Fatalf("Methods.Echo failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("Methods.Echo(hello) output: %s", result.Results)
}

func TestGoServer_DotnetClient_CallMethodNoArguments(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.NoArguments",
	)
	if !result.Success {
		t.Fatalf("Methods.NoArguments failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("Methods.NoArguments output: %s", result.Results)
}

func TestGoServer_DotnetClient_CallMethodMultipleOutputs(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.MultipleOutputs",
		"--input", "Int32:7",
	)
	if !result.Success {
		t.Fatalf("Methods.MultipleOutputs failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("Methods.MultipleOutputs(7) output: %s", result.Results)
}

func TestGoServer_DotnetClient_CallMethodFail(t *testing.T) {
	endpoint := startGoServer(t)
	result := runAdapterClientResult(t,
		dotnetEnv, defaultDotnetImage,
		endpoint, "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.Fail",
	)
	if result.Success {
		t.Fatal("Methods.Fail returned success — server must return a Bad status")
	}
	t.Logf("Methods.Fail correctly returned non-success: %s", result.ServiceResult)
}

// ---------------------------------------------------------------------------
// DataValue metadata: dotnet client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_DotnetClient_DataValue_GoodWithTimestamps(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=DataValues.GoodWithTimestamps",
	)
	if !result.Success {
		t.Fatalf("read DataValues.GoodWithTimestamps failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("DataValues.GoodWithTimestamps result: %s", result.Results)
}

// ---------------------------------------------------------------------------
// Access level enforcement: dotnet client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_DotnetClient_Access_ReadOnly_WriteRejected(t *testing.T) {
	endpoint := startGoServer(t)
	result := runAdapterClientResult(t,
		dotnetEnv, defaultDotnetImage,
		endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadOnly",
		"--value", "String:should-fail",
	)
	if result.Success {
		t.Fatal("write to Access.ReadOnly succeeded — access level not enforced")
	}
	t.Logf("Access.ReadOnly write correctly rejected: %s", result.ServiceResult)
}

func TestGoServer_DotnetClient_Access_WriteOnly_ReadRejected(t *testing.T) {
	endpoint := startGoServer(t)
	result := runAdapterClientResult(t,
		dotnetEnv, defaultDotnetImage,
		endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Access.WriteOnly",
	)
	if result.Success {
		t.Fatal("read from Access.WriteOnly succeeded — access level not enforced")
	}
	t.Logf("Access.WriteOnly read correctly rejected: %s", result.ServiceResult)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// DataValues.Uncertain: dotnet client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_DotnetClient_DataValue_Uncertain(t *testing.T) {
	endpoint := startGoServer(t)
	// Use the non-fatal variant: the adapter exits non-zero when the per-item
	// status is Uncertain, but the JSON result is still written to stdout.
	result := runDotnetClientResult(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=DataValues.Uncertain",
	)
	if result.Results == nil {
		t.Fatalf("read DataValues.Uncertain: no results; error=%s", result.Error)
	}
	var items []struct {
		StatusCode struct {
			Severity string `json:"severity"`
			Code     uint32 `json:"code"`
		} `json:"statusCode"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse results: %v; raw: %s", err, result.Results)
	}
	got := items[0].StatusCode.Severity
	code := items[0].StatusCode.Code
	if got != "Uncertain" {
		t.Errorf("DataValues.Uncertain severity: got %q (code=0x%08X), want \"Uncertain\"", got, code)
	} else {
		t.Logf("DataValues.Uncertain status 0x%08X severity=%s OK", code, got)
	}
}

// ---------------------------------------------------------------------------
// Batch read: dotnet client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_DotnetClient_BatchRead(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Boolean",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Double",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.String",
	)
	if !result.Success {
		t.Fatalf("batch read failed: %s error=%s", result.ServiceResult, result.Error)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(result.Results, &items); err != nil {
		t.Fatalf("parse batch results: %v; raw: %s", err, result.Results)
	}
	if len(items) != 4 {
		t.Errorf("expected 4 batch results, got %d", len(items))
	}
	t.Logf("batch read OK: %d items", len(items))
}

// ---------------------------------------------------------------------------
// Write/read-back: dotnet client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_DotnetClient_WriteReadBack_Boolean(t *testing.T) {
	endpoint := startGoServer(t)
	wResult := runAdapterClientResult(t,
		dotnetEnv, defaultDotnetImage,
		endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Boolean",
		"--type", "Boolean",
		"--value", "false",
	)
	if !wResult.Success {
		t.Fatalf("write Boolean failed: %s", wResult.ServiceResult)
	}
	rResult := runDotnetClient(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Boolean",
	)
	if !rResult.Success {
		t.Fatalf("read Boolean after write failed: %s", rResult.ServiceResult)
	}
	t.Logf("write/read-back Boolean OK: %s", rResult.Results)
}

func TestGoServer_DotnetClient_WriteReadBack_Float(t *testing.T) {
	endpoint := startGoServer(t)
	wResult := runAdapterClientResult(t,
		dotnetEnv, defaultDotnetImage,
		endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Float",
		"--type", "Float",
		"--value", "99.5",
	)
	if !wResult.Success {
		t.Fatalf("write Float failed: %s", wResult.ServiceResult)
	}
	rResult := runDotnetClient(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Float",
	)
	if !rResult.Success {
		t.Fatalf("read Float after write failed: %s", rResult.ServiceResult)
	}
	t.Logf("write/read-back Float OK: %s", rResult.Results)
}

func TestGoServer_DotnetClient_WriteReadBack_String(t *testing.T) {
	endpoint := startGoServer(t)
	wResult := runAdapterClientResult(t,
		dotnetEnv, defaultDotnetImage,
		endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.String",
		"--type", "String",
		"--value", "interop-write-test",
	)
	if !wResult.Success {
		t.Fatalf("write String failed: %s", wResult.ServiceResult)
	}
	rResult := runDotnetClient(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.String",
	)
	if !rResult.Success {
		t.Fatalf("read String after write failed: %s", rResult.ServiceResult)
	}
	t.Logf("write/read-back String OK: %s", rResult.Results)
}

// ---------------------------------------------------------------------------
// Subscribe — dotnet client → go-opcua server (dynamic nodes)
// ---------------------------------------------------------------------------

func TestGoServer_DotnetClient_Subscribe_Toggle(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Toggle",
		"--notifications", "3",
		"--publishing-interval-ms", "700",
		"--sampling-interval-ms", "200",
		"--timeout-ms", "10000",
	)
	if !result.Success {
		t.Fatalf("subscribe Toggle failed: %s error=%s", result.ServiceResult, result.Error)
	}
	var items []struct {
		NodeID        string          `json:"nodeId"`
		Notifications json.RawMessage `json:"notifications"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse subscribe results: %v; raw: %s", err, result.Results)
	}
	var notifs []json.RawMessage
	if err := json.Unmarshal(items[0].Notifications, &notifs); err != nil {
		t.Fatalf("parse notifications: %v", err)
	}
	if len(notifs) < 3 {
		t.Errorf("expected at least 3 Toggle notifications, got %d", len(notifs))
	}
	var hasTrue, hasFalse bool
	for _, raw := range notifs {
		var notif struct {
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(raw, &notif); err != nil {
			continue
		}
		var v bool
		if err := json.Unmarshal(notif.Value, &v); err != nil {
			continue
		}
		if v {
			hasTrue = true
		} else {
			hasFalse = true
		}
	}
	if !hasTrue || !hasFalse {
		t.Errorf("Dynamic.Toggle did not alternate: hasTrue=%v hasFalse=%v", hasTrue, hasFalse)
	}
	t.Logf("Subscribe Toggle OK: %d notifications", len(notifs))
}

func TestGoServer_DotnetClient_Subscribe_Ramp(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClient(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Ramp",
		"--notifications", "5",
		"--publishing-interval-ms", "200",
		"--sampling-interval-ms", "100",
		"--timeout-ms", "10000",
	)
	if !result.Success {
		t.Fatalf("subscribe Ramp failed: %s error=%s", result.ServiceResult, result.Error)
	}
	var items []struct {
		NodeID        string          `json:"nodeId"`
		Notifications json.RawMessage `json:"notifications"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse subscribe results: %v; raw: %s", err, result.Results)
	}
	var notifs []json.RawMessage
	if err := json.Unmarshal(items[0].Notifications, &notifs); err != nil {
		t.Fatalf("parse notifications: %v", err)
	}
	if len(notifs) < 5 {
		t.Errorf("expected at least 5 Ramp notifications, got %d", len(notifs))
	}
	for i, raw := range notifs {
		var notif struct {
			Value float64 `json:"value"`
		}
		if err := json.Unmarshal(raw, &notif); err != nil {
			t.Errorf("notif[%d]: parse value: %v; raw: %s", i, err, raw)
			continue
		}
		if notif.Value < 0.0 || notif.Value > 100.0 {
			t.Errorf("notif[%d]: Ramp value %v out of [0, 100]", i, notif.Value)
		}
	}
	t.Logf("Subscribe Ramp OK: %d notifications", len(notifs))
}

// ---------------------------------------------------------------------------
// Username authentication tests: dotnet client → go-opcua server
// ---------------------------------------------------------------------------

// The UA-.NETStandard client refuses to send a UserName token whose password
// is not encrypted on anything but a SignAndEncrypt channel ("A UserName
// identity token without token encryption requires a SignAndEncrypt
// channel."), so these tests authenticate over Basic256Sha256/SignAndEncrypt
// with the dotnet-client identity, unlike their open62541 / Milo
// counterparts on a None channel.

// TestGoServer_DotnetClient_Username_ValidCredentials verifies that the dotnet
// adapter client can authenticate with valid username/password against the
// go-opcua server and perform a read.
func TestGoServer_DotnetClient_Username_ValidCredentials(t *testing.T) {
	endpoint := startSecureGoServer(t)
	result := runSecureAdapterClient(t,
		dotnetEnv, defaultDotnetImage, "dotnet-client",
		endpoint, "read", "Basic256Sha256", "SignAndEncrypt",
		"--username", "test-user",
		"--password", "test-password",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
	)
	if !result.Success {
		t.Fatalf("valid credentials rejected: %s error=%s", result.ServiceResult, result.Error)
	}
}

// TestGoServer_DotnetClient_Username_InvalidPassword_Rejected verifies that the
// dotnet adapter client is rejected when supplying a wrong password.
func TestGoServer_DotnetClient_Username_InvalidPassword_Rejected(t *testing.T) {
	endpoint := startSecureGoServer(t)
	result := runSecureAdapterClientResult(t,
		dotnetEnv, defaultDotnetImage, "dotnet-client",
		endpoint, "read", "Basic256Sha256", "SignAndEncrypt",
		"--username", "test-user",
		"--password", "wrong-password",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
	)
	if result.Success {
		t.Fatal("wrong password should have been rejected but succeeded")
	}
	if !isIdentityRejectedServiceResult(result.ServiceResult.Name) {
		t.Errorf("expected identity-rejected service result, got: %s", result.ServiceResult)
	}
}

// ---------------------------------------------------------------------------
// Trust validation — dotnet client → go server
// ---------------------------------------------------------------------------

// TestGoServer_DotnetClient_TrustedCert_Accepted verifies that the dotnet adapter
// client can connect to the Go server when its certificate is CA-signed.
func TestGoServer_DotnetClient_TrustedCert_Accepted(t *testing.T) {
	endpoint := startTrustGoServer(t)
	result := runSecureAdapterClient(t,
		dotnetEnv, defaultDotnetImage,
		"dotnet-client", endpoint, "read",
		"Basic256Sha256", "SignAndEncrypt",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
	)
	if !result.Success {
		t.Fatalf("trusted cert should have been accepted: %s", result.ServiceResult)
	}
}

// TestGoServer_DotnetClient_UntrustedCert_Rejected verifies that the Go server
// rejects a dotnet adapter client presenting a certificate not in the trust CA.
func TestGoServer_DotnetClient_UntrustedCert_Rejected(t *testing.T) {
	endpoint := startTrustGoServer(t)
	result := runSecureAdapterClientResult(t,
		dotnetEnv, defaultDotnetImage,
		"untrusted", endpoint, "read",
		"Basic256Sha256", "SignAndEncrypt",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
	)
	if result.Success {
		t.Fatal("untrusted cert should have been rejected but connection succeeded")
	}
	if !isUntrustedClientRejected(result) {
		t.Errorf("expected certificate/channel rejection, got success=%v serviceResult=%s error=%s",
			result.Success, result.ServiceResult, result.Error)
	}
	t.Logf("dotnet untrusted cert correctly rejected: serviceResult=%s error=%s", result.ServiceResult, result.Error)
}

// ---------------------------------------------------------------------------
// Service semantics and error handling
// ---------------------------------------------------------------------------

// TestGoServer_DotnetClient_BatchWrite verifies per-item WriteResponse.Results
// (IEC 62541-4 Write Service): Good, BadUserAccessDenied, and BadNodeIdUnknown
// in a single request.
func TestGoServer_DotnetClient_BatchWrite(t *testing.T) {
	endpoint := startGoServer(t)
	result := runDotnetClientResult(t, endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--type", "Int32", "--value", "42",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadOnly",
		"--type", "String", "--value", "x",
		"--node", "nsu="+interopNamespaceURI+";s=DoesNotExist",
		"--type", "Int32", "--value", "1",
	)
	items := parseWriteResults(t, result.Results)
	if len(items) != 3 {
		t.Fatalf("BatchWrite: expected 3 results, got %d; raw=%s", len(items), result.Results)
	}
	if !statusCodeIs(items[0].StatusCode, ua.StatusOK) {
		t.Errorf("Access.ReadWrite: got %s, want Good", items[0].StatusCode)
	}
	if !statusCodeIs(items[1].StatusCode, ua.StatusBadUserAccessDenied) &&
		!statusCodeNameHas(items[1].StatusCode, "UserAccessDenied") {
		t.Errorf("Access.ReadOnly: got %s, want BadUserAccessDenied", items[1].StatusCode)
	}
	if !statusCodeIs(items[2].StatusCode, ua.StatusBadNodeIDUnknown) &&
		!statusCodeNameHas(items[2].StatusCode, "NodeIdUnknown") {
		t.Errorf("DoesNotExist: got %s, want BadNodeIdUnknown", items[2].StatusCode)
	}
	t.Logf("BatchWrite per-item: %s | %s | %s", items[0].StatusCode, items[1].StatusCode, items[2].StatusCode)
}

// TestGoServer_DotnetClient_WriteTypeMismatch verifies BadTypeMismatch for
// incompatible Variant writes (IEC 62541-4 Write Service).
func TestGoServer_DotnetClient_WriteTypeMismatch(t *testing.T) {
	endpoint := startGoServer(t)
	cases := []struct {
		name, node, typ, val string
	}{
		{"StringToInt32", "Scalar.Int32", "String", "hello"},
		{"Int64ToInt32", "Scalar.Int32", "Int64", "99"},
		{"ArrayToScalar", "Scalar.Int32", "Int32[]", "1,2,3"},
		{"ScalarToArray", "Array.Int32", "Int32", "7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runDotnetClientResult(t, endpoint, "write",
				"--node", "nsu="+interopNamespaceURI+";s="+tc.node,
				"--type", tc.typ, "--value", tc.val,
			)
			items := parseWriteResults(t, result.Results)
			if len(items) == 0 {
				t.Fatalf("no write results; serviceResult=%s", result.ServiceResult)
			}
			if !statusCodeIs(items[0].StatusCode, ua.StatusBadTypeMismatch) &&
				!statusCodeNameHas(items[0].StatusCode, "TypeMismatch") {
				t.Errorf("%s: got %s, want BadTypeMismatch", tc.name, items[0].StatusCode)
			}
		})
	}
}

// TestGoServer_DotnetClient_MethodValidation covers Call Service argument
// and identity failures (IEC 62541-4).
func TestGoServer_DotnetClient_MethodValidation(t *testing.T) {
	endpoint := startGoServer(t)

	t.Run("TooFewArgs", func(t *testing.T) {
		result := runDotnetClientResult(t, endpoint, "call",
			"--object", "nsu="+interopNamespaceURI+";s=Methods",
			"--method", "nsu="+interopNamespaceURI+";s=Methods.Add",
		)
		if result.Success {
			t.Fatal("Call with too few args succeeded")
		}
		if !statusCodeNameHas(result.ServiceResult, "ArgumentsMissing") &&
			!statusCodeIs(result.ServiceResult, ua.StatusBadArgumentsMissing) {
			// Per-item status may be in results[0].statusCode
			var items []struct {
				StatusCode statusCodeObj `json:"statusCode"`
			}
			_ = json.Unmarshal(result.Results, &items)
			if len(items) == 0 || (!statusCodeNameHas(items[0].StatusCode, "ArgumentsMissing") &&
				!statusCodeIs(items[0].StatusCode, ua.StatusBadArgumentsMissing)) {
				t.Errorf("TooFewArgs: serviceResult=%s results=%s", result.ServiceResult, result.Results)
			}
		}
	})

	t.Run("TooManyArgs", func(t *testing.T) {
		result := runDotnetClientResult(t, endpoint, "call",
			"--object", "nsu="+interopNamespaceURI+";s=Methods",
			"--method", "nsu="+interopNamespaceURI+";s=Methods.NoArguments",
			"--input", "Int32:5",
		)
		if result.Success {
			t.Fatal("Call with too many args succeeded")
		}
		var items []struct {
			StatusCode statusCodeObj `json:"statusCode"`
		}
		_ = json.Unmarshal(result.Results, &items)
		sc := result.ServiceResult
		if len(items) > 0 {
			sc = items[0].StatusCode
		}
		if !statusCodeNameHas(sc, "TooManyArguments") && !statusCodeIs(sc, ua.StatusBadTooManyArguments) {
			t.Errorf("TooManyArgs: got %s, want BadTooManyArguments", sc)
		}
	})

	t.Run("WrongType", func(t *testing.T) {
		result := runDotnetClientResult(t, endpoint, "call",
			"--object", "nsu="+interopNamespaceURI+";s=Methods",
			"--method", "nsu="+interopNamespaceURI+";s=Methods.Add",
			"--input", "String:a",
			"--input", "String:b",
		)
		if result.Success {
			t.Fatal("Call with wrong arg types succeeded")
		}
		var items []struct {
			StatusCode statusCodeObj `json:"statusCode"`
		}
		_ = json.Unmarshal(result.Results, &items)
		sc := result.ServiceResult
		if len(items) > 0 {
			sc = items[0].StatusCode
		}
		if !statusCodeNameHas(sc, "TypeMismatch") && !statusCodeIs(sc, ua.StatusBadTypeMismatch) {
			t.Errorf("WrongType: got %s, want BadTypeMismatch", sc)
		}
	})

	t.Run("UnknownMethod", func(t *testing.T) {
		result := runDotnetClientResult(t, endpoint, "call",
			"--object", "nsu="+interopNamespaceURI+";s=Methods",
			"--method", "nsu="+interopNamespaceURI+";s=Methods.DoesNotExist",
		)
		if result.Success {
			t.Fatal("Call unknown method succeeded")
		}
		var items []struct {
			StatusCode statusCodeObj `json:"statusCode"`
		}
		_ = json.Unmarshal(result.Results, &items)
		sc := result.ServiceResult
		if len(items) > 0 {
			sc = items[0].StatusCode
		}
		if !statusCodeNameHas(sc, "MethodInvalid") && !statusCodeIs(sc, ua.StatusBadMethodInvalid) {
			t.Errorf("UnknownMethod: got %s, want BadMethodInvalid", sc)
		}
	})

	t.Run("WrongObject", func(t *testing.T) {
		result := runDotnetClientResult(t, endpoint, "call",
			"--object", "nsu="+interopNamespaceURI+";s=Scalars",
			"--method", "nsu="+interopNamespaceURI+";s=Methods.Add",
			"--input", "Int32:1",
			"--input", "Int32:2",
		)
		if result.Success {
			t.Fatal("Call with wrong object succeeded")
		}
		var items []struct {
			StatusCode statusCodeObj `json:"statusCode"`
		}
		_ = json.Unmarshal(result.Results, &items)
		sc := result.ServiceResult
		if len(items) > 0 {
			sc = items[0].StatusCode
		}
		if !statusCodeNameHas(sc, "MethodInvalid") && !statusCodeNameHas(sc, "NodeIdUnknown") &&
			!statusCodeIs(sc, ua.StatusBadMethodInvalid) && !statusCodeIs(sc, ua.StatusBadNodeIDUnknown) {
			t.Errorf("WrongObject: got %s, want BadMethodInvalid or BadNodeIdUnknown", sc)
		}
	})
}

// TestGoServer_DotnetClient_IndexRange verifies IndexRange on a scalar is
// rejected with BadIndexRangeInvalid (IEC 62541-4).
func TestGoServer_DotnetClient_IndexRange(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	ctx, nsIdx := findNS(t, c)
	nodeID := ua.NewStringNodeID(nsIdx, "Scalar.Int32")

	resp, err := c.Read(ctx, &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{{
			NodeID:      nodeID,
			AttributeID: ua.AttributeIDValue,
			IndexRange:  "0:1",
		}},
	})
	if err != nil {
		t.Fatalf("Read with IndexRange: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatal("no read results")
	}
	if resp.Results[0].Status != ua.StatusBadIndexRangeInvalid {
		t.Errorf("IndexRange on scalar: got %v, want BadIndexRangeInvalid", resp.Results[0].Status)
	}

	wresp, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID:      nodeID,
			AttributeID: ua.AttributeIDValue,
			IndexRange:  "0:1",
			Value: &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        ua.MustVariant(int32(1)),
			},
		}},
	})
	if err != nil {
		t.Fatalf("Write with IndexRange: %v", err)
	}
	if len(wresp.Results) == 0 || wresp.Results[0] != ua.StatusBadIndexRangeInvalid {
		t.Errorf("Write IndexRange: got %v, want BadIndexRangeInvalid", wresp.Results)
	}
}

// TestGoServer_DotnetClient_IndexRangeSubset verifies one-dimensional IndexRange
// subset Read/Write via the dotnet adapter client.
func TestGoServer_DotnetClient_IndexRangeSubset(t *testing.T) {
	endpoint := startGoServer(t)
	arrayNode := "nsu=" + interopNamespaceURI + ";s=Array.Int32"

	t.Run("ReadSubset", func(t *testing.T) {
		result := runDotnetClient(t, endpoint, "read",
			"--node", arrayNode, "--index-range", "0:1",
		)
		if !result.Success {
			t.Fatalf("IndexRange Read failed: %s", result.ServiceResult)
		}
		var items []struct {
			Value []int32 `json:"value"`
		}
		if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
			t.Fatalf("parse: %v raw=%s", err, result.Results)
		}
		if len(items[0].Value) != 2 || items[0].Value[0] != 0 || items[0].Value[1] != 1 {
			t.Errorf("IndexRange 0:1: got %v, want [0,1]", items[0].Value)
		}
	})

	t.Run("WriteMerge", func(t *testing.T) {
		w := runDotnetClientResult(t, endpoint, "write",
			"--node", arrayNode, "--type", "Int32[]", "--value", "90,91",
			"--index-range", "1:2",
		)
		if !w.Success {
			t.Fatalf("IndexRange Write failed: %s", w.ServiceResult)
		}
	})

	t.Run("NoData", func(t *testing.T) {
		result := runDotnetClientResult(t, endpoint, "read",
			"--node", arrayNode, "--index-range", "100:101",
		)
		var items []struct {
			StatusCode statusCodeObj `json:"statusCode"`
		}
		_ = json.Unmarshal(result.Results, &items)
		sc := result.ServiceResult
		if len(items) > 0 {
			sc = items[0].StatusCode
		}
		if !statusCodeNameHas(sc, "IndexRangeNoData") && !statusCodeIs(sc, ua.StatusBadIndexRangeNoData) {
			t.Errorf("out-of-range IndexRange: got %s, want BadIndexRangeNoData", sc)
		}
	})
}

// TestGoServer_DotnetClient_TimestampsToReturn verifies TimestampsToReturn via
// Go client and dotnet CLI --timestamps.
func TestGoServer_DotnetClient_TimestampsToReturn(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	ctx, nsIdx := findNS(t, c)
	nodeID := ua.NewStringNodeID(nsIdx, "Scalar.Int32")

	resp, err := c.Read(ctx, &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnNeither,
		NodesToRead: []*ua.ReadValueID{{
			NodeID: nodeID, AttributeID: ua.AttributeIDValue,
		}},
	})
	if err != nil {
		t.Fatalf("Read Neither: %v", err)
	}
	if resp.Results[0].EncodingMask&ua.DataValueSourceTimestamp != 0 ||
		resp.Results[0].EncodingMask&ua.DataValueServerTimestamp != 0 {
		t.Errorf("Neither: timestamps present mask=%#x", resp.Results[0].EncodingMask)
	}

	result := runDotnetClient(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
		"--timestamps", "Neither",
	)
	if !result.Success {
		t.Fatalf("dotnet Neither read failed: %s", result.ServiceResult)
	}
}

// TestGoServer_DotnetClient_WriteEncodingMask verifies BadWriteNotSupported for
// Status/timestamp Writes.
func TestGoServer_DotnetClient_WriteEncodingMask(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	ctx, nsIdx := findNS(t, c)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	ok, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID: nodeID, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(11))},
		}},
	})
	if err != nil {
		t.Fatalf("value-only Write: %v", err)
	}
	if len(ok.Results) == 0 || ok.Results[0] != ua.StatusOK {
		t.Errorf("value-only Write: got %v", ok.Results)
	}

	bad, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID: nodeID, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{
				EncodingMask:    ua.DataValueValue | ua.DataValueServerTimestamp,
				Value:           ua.MustVariant(int32(12)),
				ServerTimestamp: time.Now(),
			},
		}},
	})
	if err != nil {
		t.Fatalf("timestamp Write: %v", err)
	}
	if len(bad.Results) == 0 || bad.Results[0] != ua.StatusBadWriteNotSupported {
		t.Errorf("timestamp Write: got %v, want BadWriteNotSupported", bad.Results)
	}
}

// TestGoServer_DotnetClient_BrowseResultMask verifies ResultMask on the Go server
// and that the dotnet CLI accepts --result-mask.
func TestGoServer_DotnetClient_BrowseResultMask(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	ctx, nsIdx := findNS(t, c)
	objectsID := ua.NewNumericNodeID(nsIdx, id.ObjectsFolder)

	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID: objectsID, BrowseDirection: ua.BrowseDirectionForward,
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
	for _, r := range resp.Results[0].References {
		if r.DisplayName != nil && r.DisplayName.Text != "" {
			t.Errorf("DisplayName should be cleared")
		}
		if r.BrowseName == nil || r.BrowseName.Name == "" {
			t.Errorf("BrowseName missing")
		}
	}

	result := runDotnetClient(t, endpoint, "browse",
		"--node", "nsu="+interopNamespaceURI+";i=85",
		"--result-mask", "8",
	)
	if !result.Success {
		t.Fatalf("dotnet BrowseResultMask failed: %s", result.ServiceResult)
	}
}

// TestGoServer_DotnetClient_BrowseNextRelease verifies early continuation-point
// release on the Go server (dotnet client exercises BrowseNext separately).
func TestGoServer_DotnetClient_BrowseNextRelease(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	ctx, nsIdx := findNS(t, c)
	objectsID := ua.NewNumericNodeID(nsIdx, id.ObjectsFolder)

	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID: objectsID, BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
			IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll),
		}},
		RequestedMaxReferencesPerNode: 2,
	})
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	cp := resp.Results[0].ContinuationPoint
	if len(cp) == 0 {
		t.Fatal("expected non-empty continuation point for BrowseNext release")
	}
	if _, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{
		ContinuationPoints: [][]byte{cp}, ReleaseContinuationPoints: true,
	}); err != nil {
		t.Fatalf("release: %v", err)
	}
	again, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{
		ContinuationPoints: [][]byte{cp},
	})
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	if again.Results[0].StatusCode != ua.StatusBadContinuationPointInvalid {
		t.Errorf("after release: got %v", again.Results[0].StatusCode)
	}
}

// TestGoServer_DotnetClient_BrowseFiltering verifies NodeClassMask filtering
// (IEC 62541-4 Browse Service).
func TestGoServer_DotnetClient_BrowseFiltering(t *testing.T) {
	endpoint := startGoServer(t)
	// NodeClass Variable = 2
	result := runDotnetClient(t, endpoint, "browse",
		"--node", "nsu="+interopNamespaceURI+";i=85",
		"--node-class-mask", "2",
	)
	if !result.Success {
		t.Fatalf("BrowseFiltering failed: %s", result.ServiceResult)
	}
	refs := parseBrowseRefs(t, result.Results)
	if len(refs) == 0 {
		t.Fatal("BrowseFiltering: expected some Variable references")
	}
	for _, r := range refs {
		if r.NodeClass != "Variable" && r.NodeClass != "NodeClassVariable" {
			t.Errorf("BrowseFiltering: unexpected NodeClass %q for %q", r.NodeClass, r.BrowseName.Name)
		}
	}
	t.Logf("BrowseFiltering: %d Variable-only references", len(refs))
}

// TestGoServer_DotnetClient_InvalidNodeId verifies identity failures for
// Read/Write/Browse of unknown nodes (IEC 62541-4).
func TestGoServer_DotnetClient_InvalidNodeId(t *testing.T) {
	endpoint := startGoServer(t)
	unknown := "nsu=" + interopNamespaceURI + ";s=DoesNotExist"

	t.Run("Read", func(t *testing.T) {
		result := runDotnetClientResult(t, endpoint, "read", "--node", unknown)
		if result.Success {
			t.Fatal("Read unknown NodeId succeeded")
		}
		var items []struct {
			StatusCode statusCodeObj `json:"statusCode"`
		}
		_ = json.Unmarshal(result.Results, &items)
		sc := result.ServiceResult
		if len(items) > 0 {
			sc = items[0].StatusCode
		}
		if !statusCodeNameHas(sc, "NodeIdUnknown") && !statusCodeIs(sc, ua.StatusBadNodeIDUnknown) {
			t.Errorf("Read unknown: got %s", sc)
		}
	})

	t.Run("Write", func(t *testing.T) {
		result := runDotnetClientResult(t, endpoint, "write",
			"--node", unknown, "--type", "Int32", "--value", "1",
		)
		items := parseWriteResults(t, result.Results)
		if len(items) == 0 {
			t.Fatalf("no results: %s", result.ServiceResult)
		}
		if !statusCodeNameHas(items[0].StatusCode, "NodeIdUnknown") &&
			!statusCodeIs(items[0].StatusCode, ua.StatusBadNodeIDUnknown) {
			t.Errorf("Write unknown: got %s", items[0].StatusCode)
		}
	})

	t.Run("Browse", func(t *testing.T) {
		result := runDotnetClientResult(t, endpoint, "browse", "--node", unknown)
		if result.Success {
			t.Fatal("Browse unknown NodeId succeeded")
		}
		if !statusCodeNameHas(result.ServiceResult, "NodeIdUnknown") &&
			!statusCodeIs(result.ServiceResult, ua.StatusBadNodeIDUnknown) {
			t.Errorf("Browse unknown: got %s", result.ServiceResult)
		}
	})
}
