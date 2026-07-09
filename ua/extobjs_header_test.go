// SPDX-License-Identifier: MIT

package ua

import "testing"

// TestRequestHeaderAccessors exercises Header() and SetHeader() on all
// generated Request/Response types to drive branch coverage.
func TestRequestHeaderAccessors(t *testing.T) {
	t.Run("FindServersRequest", func(t *testing.T) {
		v := &FindServersRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("FindServersRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("FindServersOnNetworkRequest", func(t *testing.T) {
		v := &FindServersOnNetworkRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("FindServersOnNetworkRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("GetEndpointsRequest", func(t *testing.T) {
		v := &GetEndpointsRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("GetEndpointsRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("RegisterServerRequest", func(t *testing.T) {
		v := &RegisterServerRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("RegisterServerRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("RegisterServer2Request", func(t *testing.T) {
		v := &RegisterServer2Request{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("RegisterServer2Request.Header() = %v, want handle 42", got)
		}
	})
	t.Run("OpenSecureChannelRequest", func(t *testing.T) {
		v := &OpenSecureChannelRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("OpenSecureChannelRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("CloseSecureChannelRequest", func(t *testing.T) {
		v := &CloseSecureChannelRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("CloseSecureChannelRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("CreateSessionRequest", func(t *testing.T) {
		v := &CreateSessionRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("CreateSessionRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("ActivateSessionRequest", func(t *testing.T) {
		v := &ActivateSessionRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("ActivateSessionRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("CloseSessionRequest", func(t *testing.T) {
		v := &CloseSessionRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("CloseSessionRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("CancelRequest", func(t *testing.T) {
		v := &CancelRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("CancelRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("AddNodesRequest", func(t *testing.T) {
		v := &AddNodesRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("AddNodesRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("AddReferencesRequest", func(t *testing.T) {
		v := &AddReferencesRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("AddReferencesRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("DeleteNodesRequest", func(t *testing.T) {
		v := &DeleteNodesRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("DeleteNodesRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("DeleteReferencesRequest", func(t *testing.T) {
		v := &DeleteReferencesRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("DeleteReferencesRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("BrowseRequest", func(t *testing.T) {
		v := &BrowseRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("BrowseRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("BrowseNextRequest", func(t *testing.T) {
		v := &BrowseNextRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("BrowseNextRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("TranslateBrowsePathsToNodeIDsRequest", func(t *testing.T) {
		v := &TranslateBrowsePathsToNodeIDsRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("TranslateBrowsePathsToNodeIDsRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("RegisterNodesRequest", func(t *testing.T) {
		v := &RegisterNodesRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("RegisterNodesRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("UnregisterNodesRequest", func(t *testing.T) {
		v := &UnregisterNodesRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("UnregisterNodesRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("QueryFirstRequest", func(t *testing.T) {
		v := &QueryFirstRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("QueryFirstRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("QueryNextRequest", func(t *testing.T) {
		v := &QueryNextRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("QueryNextRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("ReadRequest", func(t *testing.T) {
		v := &ReadRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("ReadRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("HistoryReadRequest", func(t *testing.T) {
		v := &HistoryReadRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("HistoryReadRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("WriteRequest", func(t *testing.T) {
		v := &WriteRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("WriteRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("HistoryUpdateRequest", func(t *testing.T) {
		v := &HistoryUpdateRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("HistoryUpdateRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("CallRequest", func(t *testing.T) {
		v := &CallRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("CallRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("CreateMonitoredItemsRequest", func(t *testing.T) {
		v := &CreateMonitoredItemsRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("CreateMonitoredItemsRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("ModifyMonitoredItemsRequest", func(t *testing.T) {
		v := &ModifyMonitoredItemsRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("ModifyMonitoredItemsRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("SetMonitoringModeRequest", func(t *testing.T) {
		v := &SetMonitoringModeRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("SetMonitoringModeRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("SetTriggeringRequest", func(t *testing.T) {
		v := &SetTriggeringRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("SetTriggeringRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("DeleteMonitoredItemsRequest", func(t *testing.T) {
		v := &DeleteMonitoredItemsRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("DeleteMonitoredItemsRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("CreateSubscriptionRequest", func(t *testing.T) {
		v := &CreateSubscriptionRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("CreateSubscriptionRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("ModifySubscriptionRequest", func(t *testing.T) {
		v := &ModifySubscriptionRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("ModifySubscriptionRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("SetPublishingModeRequest", func(t *testing.T) {
		v := &SetPublishingModeRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("SetPublishingModeRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("PublishRequest", func(t *testing.T) {
		v := &PublishRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("PublishRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("RepublishRequest", func(t *testing.T) {
		v := &RepublishRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("RepublishRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("TransferSubscriptionsRequest", func(t *testing.T) {
		v := &TransferSubscriptionsRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("TransferSubscriptionsRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("DeleteSubscriptionsRequest", func(t *testing.T) {
		v := &DeleteSubscriptionsRequest{}
		h := &RequestHeader{RequestHandle: 42}
		v.SetHeader(h)
		if got := v.Header(); got == nil || got.RequestHandle != 42 {
			t.Errorf("DeleteSubscriptionsRequest.Header() = %v, want handle 42", got)
		}
	})
	t.Run("ServiceFault", func(t *testing.T) {
		v := &ServiceFault{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("ServiceFault.Header() returned nil")
		}
	})
	t.Run("FindServersResponse", func(t *testing.T) {
		v := &FindServersResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("FindServersResponse.Header() returned nil")
		}
	})
	t.Run("FindServersOnNetworkResponse", func(t *testing.T) {
		v := &FindServersOnNetworkResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("FindServersOnNetworkResponse.Header() returned nil")
		}
	})
	t.Run("GetEndpointsResponse", func(t *testing.T) {
		v := &GetEndpointsResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("GetEndpointsResponse.Header() returned nil")
		}
	})
	t.Run("RegisterServerResponse", func(t *testing.T) {
		v := &RegisterServerResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("RegisterServerResponse.Header() returned nil")
		}
	})
	t.Run("RegisterServer2Response", func(t *testing.T) {
		v := &RegisterServer2Response{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("RegisterServer2Response.Header() returned nil")
		}
	})
	t.Run("OpenSecureChannelResponse", func(t *testing.T) {
		v := &OpenSecureChannelResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("OpenSecureChannelResponse.Header() returned nil")
		}
	})
	t.Run("CloseSecureChannelResponse", func(t *testing.T) {
		v := &CloseSecureChannelResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("CloseSecureChannelResponse.Header() returned nil")
		}
	})
	t.Run("CreateSessionResponse", func(t *testing.T) {
		v := &CreateSessionResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("CreateSessionResponse.Header() returned nil")
		}
	})
	t.Run("ActivateSessionResponse", func(t *testing.T) {
		v := &ActivateSessionResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("ActivateSessionResponse.Header() returned nil")
		}
	})
	t.Run("CloseSessionResponse", func(t *testing.T) {
		v := &CloseSessionResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("CloseSessionResponse.Header() returned nil")
		}
	})
	t.Run("CancelResponse", func(t *testing.T) {
		v := &CancelResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("CancelResponse.Header() returned nil")
		}
	})
	t.Run("AddNodesResponse", func(t *testing.T) {
		v := &AddNodesResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("AddNodesResponse.Header() returned nil")
		}
	})
	t.Run("AddReferencesResponse", func(t *testing.T) {
		v := &AddReferencesResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("AddReferencesResponse.Header() returned nil")
		}
	})
	t.Run("DeleteNodesResponse", func(t *testing.T) {
		v := &DeleteNodesResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("DeleteNodesResponse.Header() returned nil")
		}
	})
	t.Run("DeleteReferencesResponse", func(t *testing.T) {
		v := &DeleteReferencesResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("DeleteReferencesResponse.Header() returned nil")
		}
	})
	t.Run("BrowseResponse", func(t *testing.T) {
		v := &BrowseResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("BrowseResponse.Header() returned nil")
		}
	})
	t.Run("BrowseNextResponse", func(t *testing.T) {
		v := &BrowseNextResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("BrowseNextResponse.Header() returned nil")
		}
	})
	t.Run("TranslateBrowsePathsToNodeIDsResponse", func(t *testing.T) {
		v := &TranslateBrowsePathsToNodeIDsResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("TranslateBrowsePathsToNodeIDsResponse.Header() returned nil")
		}
	})
	t.Run("RegisterNodesResponse", func(t *testing.T) {
		v := &RegisterNodesResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("RegisterNodesResponse.Header() returned nil")
		}
	})
	t.Run("UnregisterNodesResponse", func(t *testing.T) {
		v := &UnregisterNodesResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("UnregisterNodesResponse.Header() returned nil")
		}
	})
	t.Run("QueryFirstResponse", func(t *testing.T) {
		v := &QueryFirstResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("QueryFirstResponse.Header() returned nil")
		}
	})
	t.Run("QueryNextResponse", func(t *testing.T) {
		v := &QueryNextResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("QueryNextResponse.Header() returned nil")
		}
	})
	t.Run("ReadResponse", func(t *testing.T) {
		v := &ReadResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("ReadResponse.Header() returned nil")
		}
	})
	t.Run("HistoryReadResponse", func(t *testing.T) {
		v := &HistoryReadResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("HistoryReadResponse.Header() returned nil")
		}
	})
	t.Run("WriteResponse", func(t *testing.T) {
		v := &WriteResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("WriteResponse.Header() returned nil")
		}
	})
	t.Run("HistoryUpdateResponse", func(t *testing.T) {
		v := &HistoryUpdateResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("HistoryUpdateResponse.Header() returned nil")
		}
	})
	t.Run("CallResponse", func(t *testing.T) {
		v := &CallResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("CallResponse.Header() returned nil")
		}
	})
	t.Run("CreateMonitoredItemsResponse", func(t *testing.T) {
		v := &CreateMonitoredItemsResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("CreateMonitoredItemsResponse.Header() returned nil")
		}
	})
	t.Run("ModifyMonitoredItemsResponse", func(t *testing.T) {
		v := &ModifyMonitoredItemsResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("ModifyMonitoredItemsResponse.Header() returned nil")
		}
	})
	t.Run("SetMonitoringModeResponse", func(t *testing.T) {
		v := &SetMonitoringModeResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("SetMonitoringModeResponse.Header() returned nil")
		}
	})
	t.Run("SetTriggeringResponse", func(t *testing.T) {
		v := &SetTriggeringResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("SetTriggeringResponse.Header() returned nil")
		}
	})
	t.Run("DeleteMonitoredItemsResponse", func(t *testing.T) {
		v := &DeleteMonitoredItemsResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("DeleteMonitoredItemsResponse.Header() returned nil")
		}
	})
	t.Run("CreateSubscriptionResponse", func(t *testing.T) {
		v := &CreateSubscriptionResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("CreateSubscriptionResponse.Header() returned nil")
		}
	})
	t.Run("ModifySubscriptionResponse", func(t *testing.T) {
		v := &ModifySubscriptionResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("ModifySubscriptionResponse.Header() returned nil")
		}
	})
	t.Run("SetPublishingModeResponse", func(t *testing.T) {
		v := &SetPublishingModeResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("SetPublishingModeResponse.Header() returned nil")
		}
	})
	t.Run("PublishResponse", func(t *testing.T) {
		v := &PublishResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("PublishResponse.Header() returned nil")
		}
	})
	t.Run("RepublishResponse", func(t *testing.T) {
		v := &RepublishResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("RepublishResponse.Header() returned nil")
		}
	})
	t.Run("TransferSubscriptionsResponse", func(t *testing.T) {
		v := &TransferSubscriptionsResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("TransferSubscriptionsResponse.Header() returned nil")
		}
	})
	t.Run("DeleteSubscriptionsResponse", func(t *testing.T) {
		v := &DeleteSubscriptionsResponse{}
		h := &ResponseHeader{ServiceResult: StatusGood}
		v.SetHeader(h)
		if got := v.Header(); got == nil {
			t.Errorf("DeleteSubscriptionsResponse.Header() returned nil")
		}
	})
}
