//go:build interop

// SPDX-License-Identifier: MIT

// Peer subscription lifecycle tests (O→S / M→S).
// COVERAGE.md: subscriptions / subscription.lifecycle.revise, subscription.lifecycle.delete

package interop

import (
	"encoding/json"
	"testing"
)

type lifecycleReviseResult struct {
	SubscriptionID              uint32  `json:"subscriptionId"`
	RequestedPublishingInterval float64 `json:"requestedPublishingInterval"`
	RequestedLifetimeCount      uint32  `json:"requestedLifetimeCount"`
	RequestedMaxKeepAliveCount  uint32  `json:"requestedMaxKeepAliveCount"`
	RevisedPublishingInterval   float64 `json:"revisedPublishingInterval"`
	RevisedLifetimeCount        uint32  `json:"revisedLifetimeCount"`
	RevisedMaxKeepAliveCount    uint32  `json:"revisedMaxKeepAliveCount"`
}

type subscribeRevisedResult struct {
	NodeID                    string  `json:"nodeId"`
	SubscriptionID            uint32  `json:"subscriptionId"`
	RevisedPublishingInterval float64 `json:"revisedPublishingInterval"`
	RevisedLifetimeCount      uint32  `json:"revisedLifetimeCount"`
	RevisedMaxKeepAliveCount  uint32  `json:"revisedMaxKeepAliveCount"`
}

func assertReviseLifecycle(t *testing.T, result adapterResult) {
	t.Helper()
	if result.Operation != "subscription-lifecycle" {
		t.Fatalf("operation: got %q, want subscription-lifecycle", result.Operation)
	}
	if !result.Success {
		t.Fatalf("lifecycle revise failed: serviceResult=%s error=%s raw=%s",
			result.ServiceResult, result.Error, result.Results)
	}
	var items []lifecycleReviseResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse revise results: %v; raw: %s", err, result.Results)
	}
	got := items[0]
	if got.SubscriptionID == 0 {
		t.Errorf("subscriptionId must be non-zero")
	}
	if got.RevisedPublishingInterval < 10 {
		t.Errorf("revisedPublishingInterval=%v, want >=10", got.RevisedPublishingInterval)
	}
	if got.RevisedLifetimeCount < got.RevisedMaxKeepAliveCount*3 {
		t.Errorf("revisedLifetimeCount=%d < 3× keepalive=%d",
			got.RevisedLifetimeCount, got.RevisedMaxKeepAliveCount)
	}
}

func assertSubscribeRevisedFields(t *testing.T, result adapterResult) {
	t.Helper()
	if !result.Success {
		t.Fatalf("subscribe failed: serviceResult=%s error=%s", result.ServiceResult, result.Error)
	}
	var items []subscribeRevisedResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse subscribe results: %v; raw: %s", err, result.Results)
	}
	got := items[0]
	if got.SubscriptionID == 0 {
		t.Errorf("subscriptionId must be non-zero")
	}
	if got.RevisedPublishingInterval <= 0 {
		t.Errorf("revisedPublishingInterval=%v, want >0", got.RevisedPublishingInterval)
	}
	if got.RevisedLifetimeCount == 0 || got.RevisedMaxKeepAliveCount == 0 {
		t.Errorf("revised counts zero: lifetime=%d keepalive=%d",
			got.RevisedLifetimeCount, got.RevisedMaxKeepAliveCount)
	}
}

// TestGoServer_Open62541Client_SubscribeRevisedFields verifies subscribe JSON
// includes CreateSubscription revised parameters.
func TestGoServer_Open62541Client_SubscribeRevisedFields(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541ClientResult(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "1",
		"--publishing-interval-ms", "200",
		"--timeout-ms", "15000",
	)
	assertSubscribeRevisedFields(t, result)
}

// TestGoServer_MiloClient_SubscribeRevisedFields verifies Milo subscribe JSON
// includes CreateSubscription revised parameters.
func TestGoServer_MiloClient_SubscribeRevisedFields(t *testing.T) {
	endpoint := startGoServer(t)
	result := runMiloClientResult(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "1",
		"--publishing-interval-ms", "200",
		"--timeout-ms", "15000",
	)
	assertSubscribeRevisedFields(t, result)
}

// TestGoServer_Open62541Client_SubscriptionLifecycle_Revise exercises the
// subscription-lifecycle revise scenario against the Go server.
func TestGoServer_Open62541Client_SubscriptionLifecycle_Revise(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541ClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "revise",
		"--timeout-ms", "15000",
	)
	assertReviseLifecycle(t, result)
}

// TestGoServer_MiloClient_SubscriptionLifecycle_Revise exercises the Milo
// subscription-lifecycle revise scenario against the Go server.
func TestGoServer_MiloClient_SubscriptionLifecycle_Revise(t *testing.T) {
	endpoint := startGoServer(t)
	result := runMiloClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "revise",
		"--timeout-ms", "15000",
	)
	assertReviseLifecycle(t, result)
}

// TestGoServer_Open62541Client_SubscriptionLifecycle_Delete verifies second
// delete returns Bad*Invalid statuses.
func TestGoServer_Open62541Client_SubscriptionLifecycle_Delete(t *testing.T) {
	endpoint := startGoServer(t)
	result := runOpen62541ClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "delete",
		"--timeout-ms", "15000",
	)
	if result.Operation != "subscription-lifecycle" {
		t.Fatalf("operation: got %q", result.Operation)
	}
	if !result.Success {
		t.Fatalf("lifecycle delete failed: serviceResult=%s error=%s raw=%s",
			result.ServiceResult, result.Error, result.Results)
	}
}

// TestGoServer_MiloClient_SubscriptionLifecycle_Delete verifies Milo delete
// scenario against the Go server.
func TestGoServer_MiloClient_SubscriptionLifecycle_Delete(t *testing.T) {
	endpoint := startGoServer(t)
	result := runMiloClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "delete",
		"--timeout-ms", "15000",
	)
	if !result.Success {
		t.Fatalf("lifecycle delete failed: serviceResult=%s error=%s raw=%s",
			result.ServiceResult, result.Error, result.Results)
	}
}
