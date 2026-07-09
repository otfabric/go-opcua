//go:build interop

// SPDX-License-Identifier: MIT

// Tests in this file cover open62541 client → go-opcua server direction.
//
// Each test starts an in-process go-opcua server populated with the baseline
// fixture node set, then runs the open62541 adapter container in client mode
// and asserts the JSON output.
package interop

import (
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// open62541 client → go-opcua server
// ---------------------------------------------------------------------------

// TestGoServer_Open62541Client_Endpoints verifies that the open62541 client
// can retrieve endpoints from the go-opcua server.
func TestGoServer_Open62541Client_Endpoints(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "endpoints")

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

// TestGoServer_Open62541Client_Browse verifies that the open62541 client can
// browse the Objects folder of the go-opcua server.
func TestGoServer_Open62541Client_Browse(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "browse",
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

// TestGoServer_Open62541Client_BrowseObjectsNodes verifies that browsing the
// interop namespace Objects folder returns known interop node names including
// scalar and dynamic entries.
func TestGoServer_Open62541Client_BrowseObjectsNodes(t *testing.T) {
	endpoint := startGoServer(t)
	// The interop nodes live under the namespace-local Objects folder
	// (nsu=<interopURI>;i=85), not the standard ns=0 Objects folder (i=85).
	result := runOpen62541Client(t, endpoint, "browse",
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

// TestGoServer_Open62541Client_BrowseNext verifies that the open62541 client
// correctly issues BrowseNext requests when the server paginates browse
// results via --max-refs.
func TestGoServer_Open62541Client_BrowseNext(t *testing.T) {
	endpoint := startGoServer(t)
	// Use --max-refs 3 to force continuation points; the interop Objects folder
	// has many more than 3 children, so BrowseNext must be used.
	result := runOpen62541Client(t, endpoint, "browse",
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
// Scalar reads — open62541 client → go server
// ---------------------------------------------------------------------------

// readScalarFromGoServer is a shared helper: runs the open62541 client in
// read mode against a freshly started go server and returns the first result.
func readScalarFromGoServer(t *testing.T, nodeSuffix string) json.RawMessage {
	t.Helper()
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "read",
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

func TestGoServer_Open62541Client_ReadScalarBoolean(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.Boolean")
}

func TestGoServer_Open62541Client_ReadScalarSByte(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.SByte")
}

func TestGoServer_Open62541Client_ReadScalarByte(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.Byte")
}

func TestGoServer_Open62541Client_ReadScalarInt16(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.Int16")
}

func TestGoServer_Open62541Client_ReadScalarUInt16(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.UInt16")
}

func TestGoServer_Open62541Client_ReadScalarInt32(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.Int32")
}

func TestGoServer_Open62541Client_ReadScalarUInt32(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.UInt32")
}

func TestGoServer_Open62541Client_ReadScalarInt64(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.Int64")
}

func TestGoServer_Open62541Client_ReadScalarUInt64(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.UInt64")
}

func TestGoServer_Open62541Client_ReadScalarFloat(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.Float")
}

func TestGoServer_Open62541Client_ReadScalarDouble(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.Double")
}

func TestGoServer_Open62541Client_ReadScalarString(t *testing.T) {
	readScalarFromGoServer(t, "Scalar.String")
}

// TestGoServer_Open62541Client_Write verifies that the open62541 client can
// write Int32 to Access.ReadWrite on the go-opcua server.
func TestGoServer_Open62541Client_Write(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--type", "Int32",
		"--value", "7777",
	)

	if result.Operation != "write" {
		t.Errorf("operation: got %q, want %q", result.Operation, "write")
	}
	if !result.Success {
		t.Errorf("write failed: serviceResult=%s", result.ServiceResult)
	}
}

// TestGoServer_Open62541Client_CallMethod calls Methods.Add(3, 4) on the
// go-opcua server via the open62541 adapter client and asserts the result is 7.
func TestGoServer_Open62541Client_CallMethod(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "call",
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

	// results[0].outputArguments should contain [7]
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

// TestGoServer_Open62541Client_Subscribe subscribes to Dynamic.Counter on the
// go-opcua server via the open62541 adapter and asserts 3 notifications arrive.
func TestGoServer_Open62541Client_Subscribe(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "subscribe",
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
// Array reads — open62541 client → go server
// ---------------------------------------------------------------------------

// readArrayFromGoServer runs the open62541 client in read mode for an array
// node on the go server and returns the raw first result item.
func readArrayFromGoServer(t *testing.T, nodeSuffix string) json.RawMessage {
	t.Helper()
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "read",
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

// TestGoServer_Open62541Client_ReadArrayInt32 reads the Int32 array from the
// go server and verifies the read succeeds.
func TestGoServer_Open62541Client_ReadArrayInt32(t *testing.T) {
	readArrayFromGoServer(t, "Array.Int32")
}

// TestGoServer_Open62541Client_ReadArrayEmpty reads the empty Int32 array
// from the go server and verifies the read succeeds.
func TestGoServer_Open62541Client_ReadArrayEmpty(t *testing.T) {
	readArrayFromGoServer(t, "Array.Empty")
}

// TestGoServer_Open62541Client_ReadArrayString reads the String array from
// the go server and verifies the read succeeds.
func TestGoServer_Open62541Client_ReadArrayString(t *testing.T) {
	readArrayFromGoServer(t, "Array.String")
}

// TestGoServer_Open62541Client_ReadArrayByteString reads the ByteString array
// from the go server and verifies the read succeeds.
func TestGoServer_Open62541Client_ReadArrayByteString(t *testing.T) {
	readArrayFromGoServer(t, "Array.ByteString")
}

// TestGoServer_Open62541Client_ReadArrayMatrix2D reads the 3×2 Double matrix
// from the go server and verifies the read succeeds.
func TestGoServer_Open62541Client_ReadArrayMatrix2D(t *testing.T) {
	readArrayFromGoServer(t, "Array.Matrix2D")
}

// TestGoServer_Open62541Client_ReadArrayBoolean reads the Boolean array from
// the go server and verifies the read succeeds.
func TestGoServer_Open62541Client_ReadArrayBoolean(t *testing.T) {
	readArrayFromGoServer(t, "Array.Boolean")
}

// TestGoServer_Open62541Client_ReadArrayDouble reads the Double array from
// the go server and verifies the read succeeds.
func TestGoServer_Open62541Client_ReadArrayDouble(t *testing.T) {
	readArrayFromGoServer(t, "Array.Double")
}

// ---------------------------------------------------------------------------
// Secure-channel tests: open62541 client → go-opcua secure server
// ---------------------------------------------------------------------------

// secureOpen62541ReadScalarInt32 connects the open62541 adapter client to the
// secure go-opcua server using the given policy and mode, reads Scalar.Int32,
// and verifies the result is a good read.
func secureOpen62541ReadScalarInt32(t *testing.T, policy, mode string) {
	t.Helper()
	endpoint := startSecureGoServer(t)
	result := runSecureAdapterClient(t,
		"OPEN62541_IMAGE", defaultOpen62541Image,
		"open62541-client",
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

// TestGoServer_Open62541Client_Basic256Sha256_Sign_ScalarRead verifies that
// the open62541 client can read a scalar over a Basic256Sha256/Sign channel.
func TestGoServer_Open62541Client_Basic256Sha256_Sign_ScalarRead(t *testing.T) {
	secureOpen62541ReadScalarInt32(t, "Basic256Sha256", "Sign")
}

// TestGoServer_Open62541Client_Basic256Sha256_SignAndEncrypt_ScalarRead verifies
// that the open62541 client can read a scalar over Basic256Sha256/SignAndEncrypt.
func TestGoServer_Open62541Client_Basic256Sha256_SignAndEncrypt_ScalarRead(t *testing.T) {
	secureOpen62541ReadScalarInt32(t, "Basic256Sha256", "SignAndEncrypt")
}

// TestGoServer_Open62541Client_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead
// verifies that the open62541 adapter client can read over
// Aes128_Sha256_RsaOaep/SignAndEncrypt against the go-opcua server.
func TestGoServer_Open62541Client_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead(t *testing.T) {
	secureOpen62541ReadScalarInt32(t, "Aes128_Sha256_RsaOaep", "SignAndEncrypt")
}

// TestGoServer_Open62541Client_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead
// verifies that the open62541 adapter client can read over
// Aes256_Sha256_RsaPss/SignAndEncrypt against the go-opcua server.
func TestGoServer_Open62541Client_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead(t *testing.T) {
	secureOpen62541ReadScalarInt32(t, "Aes256_Sha256_RsaPss", "SignAndEncrypt")
}

// ---------------------------------------------------------------------------
// Method calls: open62541 client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_Open62541Client_CallMethodMultiply(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "call",
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

func TestGoServer_Open62541Client_CallMethodEcho(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.Echo",
		"--input", "String:hello",
	)
	if !result.Success {
		t.Fatalf("Methods.Echo failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("Methods.Echo(hello) output: %s", result.Results)
}

func TestGoServer_Open62541Client_CallMethodNoArguments(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.NoArguments",
	)
	if !result.Success {
		t.Fatalf("Methods.NoArguments failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("Methods.NoArguments output: %s", result.Results)
}

func TestGoServer_Open62541Client_CallMethodMultipleOutputs(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.MultipleOutputs",
		"--input", "Int32:7",
	)
	if !result.Success {
		t.Fatalf("Methods.MultipleOutputs failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("Methods.MultipleOutputs(7) output: %s", result.Results)
}

func TestGoServer_Open62541Client_CallMethodFail(t *testing.T) {
	endpoint := startGoServer(t)
	result := runAdapterClientResult(t,
		"OPEN62541_IMAGE", defaultOpen62541Image,
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
// DataValue metadata: open62541 client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_Open62541Client_DataValue_GoodWithTimestamps(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=DataValues.GoodWithTimestamps",
	)
	if !result.Success {
		t.Fatalf("read DataValues.GoodWithTimestamps failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("DataValues.GoodWithTimestamps result: %s", result.Results)
}

// ---------------------------------------------------------------------------
// Access level enforcement: open62541 client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_Open62541Client_Access_ReadOnly_WriteRejected(t *testing.T) {
	endpoint := startGoServer(t)
	result := runAdapterClientResult(t,
		"OPEN62541_IMAGE", defaultOpen62541Image,
		endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadOnly",
		"--value", "String:should-fail",
	)
	if result.Success {
		t.Fatal("write to Access.ReadOnly succeeded — access level not enforced")
	}
	t.Logf("Access.ReadOnly write correctly rejected: %s", result.ServiceResult)
}

func TestGoServer_Open62541Client_Access_WriteOnly_ReadRejected(t *testing.T) {
	endpoint := startGoServer(t)
	result := runAdapterClientResult(t,
		"OPEN62541_IMAGE", defaultOpen62541Image,
		endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Access.WriteOnly",
	)
	if result.Success {
		t.Fatal("read from Access.WriteOnly succeeded — access level not enforced")
	}
	t.Logf("Access.WriteOnly read correctly rejected: %s", result.ServiceResult)
}

// ---------------------------------------------------------------------------
// DataValues.Uncertain: open62541 client → go-opcua server
// ---------------------------------------------------------------------------

// TestGoServer_Open62541Client_DataValue_Uncertain reads DataValues.Uncertain
// from the go-opcua server and verifies the adapter reports Uncertain severity.
func TestGoServer_Open62541Client_DataValue_Uncertain(t *testing.T) {
	endpoint := startGoServer(t)
	// Use the non-fatal variant: the adapter exits non-zero when the per-item
	// status is Uncertain, but the JSON result is still written to stdout.
	result := runOpen62541ClientResult(t, endpoint, "read",
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
// Batch read: open62541 client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_Open62541Client_BatchRead(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "read",
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
// Write/read-back: open62541 client → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_Open62541Client_WriteReadBack_Boolean(t *testing.T) {
	endpoint := startGoServer(t)
	// Write false (initial is true)
	wResult := runAdapterClientResult(t,
		"OPEN62541_IMAGE", defaultOpen62541Image,
		endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Boolean",
		"--type", "Boolean",
		"--value", "false",
	)
	if !wResult.Success {
		t.Fatalf("write Boolean failed: %s", wResult.ServiceResult)
	}
	// Read back
	rResult := runOpen62541Client(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Boolean",
	)
	if !rResult.Success {
		t.Fatalf("read Boolean after write failed: %s", rResult.ServiceResult)
	}
	t.Logf("write/read-back Boolean OK: %s", rResult.Results)
}

func TestGoServer_Open62541Client_WriteReadBack_Float(t *testing.T) {
	endpoint := startGoServer(t)
	wResult := runAdapterClientResult(t,
		"OPEN62541_IMAGE", defaultOpen62541Image,
		endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Float",
		"--type", "Float",
		"--value", "99.5",
	)
	if !wResult.Success {
		t.Fatalf("write Float failed: %s", wResult.ServiceResult)
	}
	rResult := runOpen62541Client(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Float",
	)
	if !rResult.Success {
		t.Fatalf("read Float after write failed: %s", rResult.ServiceResult)
	}
	t.Logf("write/read-back Float OK: %s", rResult.Results)
}

func TestGoServer_Open62541Client_WriteReadBack_String(t *testing.T) {
	endpoint := startGoServer(t)
	wResult := runAdapterClientResult(t,
		"OPEN62541_IMAGE", defaultOpen62541Image,
		endpoint, "write",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.String",
		"--type", "String",
		"--value", "interop-write-test",
	)
	if !wResult.Success {
		t.Fatalf("write String failed: %s", wResult.ServiceResult)
	}
	rResult := runOpen62541Client(t, endpoint, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.String",
	)
	if !rResult.Success {
		t.Fatalf("read String after write failed: %s", rResult.ServiceResult)
	}
	t.Logf("write/read-back String OK: %s", rResult.Results)
}

// ---------------------------------------------------------------------------
// Subscribe — open62541 client → go-opcua server (dynamic nodes)
// ---------------------------------------------------------------------------

// TestGoServer_Open62541Client_Subscribe_Toggle subscribes to Dynamic.Toggle
// on the go-opcua server and verifies that boolean values are delivered.
func TestGoServer_Open62541Client_Subscribe_Toggle(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "subscribe",
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
	// Parse notification values and verify at least one true and one false appear.
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
		t.Errorf("Dynamic.Toggle did not alternate: hasTrue=%v hasFalse=%v notifs=%s", hasTrue, hasFalse, result.Results)
	}
	t.Logf("Subscribe Toggle OK: %d notifications", len(notifs))
}

// TestGoServer_Open62541Client_Subscribe_Ramp subscribes to Dynamic.Ramp on
// the go-opcua server and verifies that float64 values in [0, 100] are delivered.
func TestGoServer_Open62541Client_Subscribe_Ramp(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541Client(t, endpoint, "subscribe",
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
// Username authentication tests: open62541 client → go-opcua server
// ---------------------------------------------------------------------------

// TestGoServer_Open62541Client_Username_ValidCredentials verifies that the
// open62541 adapter client can authenticate with valid username/password
// against the go-opcua server and perform a read.
func TestGoServer_Open62541Client_Username_ValidCredentials(t *testing.T) {
	endpoint := startSecureGoServer(t)
	result := runAdapterClient(t,
		"OPEN62541_IMAGE", defaultOpen62541Image,
		endpoint, "read",
		"--username", "test-user",
		"--password", "test-password",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
	)
	if !result.Success {
		t.Fatalf("valid credentials rejected: %s error=%s", result.ServiceResult, result.Error)
	}
}

// TestGoServer_Open62541Client_Username_InvalidPassword_Rejected verifies that
// the open62541 adapter client is rejected when supplying a wrong password.
func TestGoServer_Open62541Client_Username_InvalidPassword_Rejected(t *testing.T) {
	endpoint := startSecureGoServer(t)
	result := runAdapterClientResult(t,
		"OPEN62541_IMAGE", defaultOpen62541Image,
		endpoint, "read",
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
