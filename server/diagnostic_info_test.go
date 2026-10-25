// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// diagCase is a request with one good and one failed operation, its
// response, and how to get the operation DiagnosticInfos of the response.
type diagCase struct {
	name  string
	req   ua.Request
	resp  ua.Response
	infos func() []*ua.DiagnosticInfo
	// info is a substring of the AdditionalInfo of the failed operation.
	info string
}

func diagCases() []diagCase {
	bad := ua.StatusBadNodeIDUnknown
	n := ua.NewStringNodeID(1, "x")
	var cases []diagCase
	add := func(name string, req ua.Request, resp ua.Response, infos func() []*ua.DiagnosticInfo, info string) {
		cases = append(cases, diagCase{name, req, resp, infos, info})
	}
	{
		r := &ua.ReadResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.DataValue{{}, {Status: bad}}}
		add("Read", &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: n}, {NodeID: n, AttributeID: ua.AttributeIDValue}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "ns=1;s=x, attribute Value")
	}
	{
		r := &ua.WriteResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []ua.StatusCode{ua.StatusOK, bad}}
		add("Write", &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{NodeID: n}, {NodeID: n, AttributeID: ua.AttributeIDDisplayName}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "attribute DisplayName")
	}
	{
		r := &ua.HistoryReadResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.HistoryReadResult{{}, {StatusCode: bad}}}
		add("HistoryRead", &ua.HistoryReadRequest{NodesToRead: []*ua.HistoryReadValueID{{NodeID: n}, {NodeID: n}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "ns=1;s=x")
	}
	{
		r := &ua.HistoryUpdateResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.HistoryUpdateResult{nil, {StatusCode: bad}}}
		add("HistoryUpdate", &ua.HistoryUpdateRequest{}, r, func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "")
	}
	{
		r := &ua.BrowseResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.BrowseResult{{}, {StatusCode: bad}}}
		add("Browse", &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{NodeID: n}, {NodeID: n}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "ns=1;s=x")
	}
	{
		r := &ua.BrowseNextResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.BrowseResult{nil, {StatusCode: ua.StatusBadContinuationPointInvalid}}}
		add("BrowseNext", &ua.BrowseNextRequest{}, r, func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "continuation point 1")
	}
	{
		r := &ua.TranslateBrowsePathsToNodeIDsResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.BrowsePathResult{{}, {StatusCode: ua.StatusBadNoMatch}}}
		add("TranslateBrowsePaths", &ua.TranslateBrowsePathsToNodeIDsRequest{BrowsePaths: []*ua.BrowsePath{{}, {StartingNode: n}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "browse path from ns=1;s=x")
	}
	{
		r := &ua.AddNodesResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.AddNodesResult{{}, {StatusCode: ua.StatusBadNodeIDExists}}}
		add("AddNodes", &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{{}, {BrowseName: &ua.QualifiedName{Name: "Pump"}}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "node Pump")
	}
	{
		r := &ua.AddReferencesResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []ua.StatusCode{ua.StatusOK, bad}}
		add("AddReferences", &ua.AddReferencesRequest{ReferencesToAdd: []*ua.AddReferencesItem{{}, {SourceNodeID: n}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "reference from ns=1;s=x")
	}
	{
		r := &ua.DeleteNodesResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []ua.StatusCode{ua.StatusOK, bad}}
		add("DeleteNodes", &ua.DeleteNodesRequest{NodesToDelete: []*ua.DeleteNodesItem{{}, {NodeID: n}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "ns=1;s=x")
	}
	{
		r := &ua.DeleteReferencesResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []ua.StatusCode{ua.StatusOK, bad}}
		add("DeleteReferences", &ua.DeleteReferencesRequest{ReferencesToDelete: []*ua.DeleteReferencesItem{{}, {SourceNodeID: n}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "reference from ns=1;s=x")
	}
	{
		r := &ua.CreateMonitoredItemsResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.MonitoredItemCreateResult{{}, {StatusCode: bad}}}
		add("CreateMonitoredItems", &ua.CreateMonitoredItemsRequest{ItemsToCreate: []*ua.MonitoredItemCreateRequest{{}, {ItemToMonitor: &ua.ReadValueID{NodeID: n, AttributeID: ua.AttributeIDValue}}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "ns=1;s=x, attribute Value")
	}
	{
		r := &ua.ModifyMonitoredItemsResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.MonitoredItemModifyResult{{}, {StatusCode: ua.StatusBadMonitoredItemIDInvalid}}}
		add("ModifyMonitoredItems", &ua.ModifyMonitoredItemsRequest{ItemsToModify: []*ua.MonitoredItemModifyRequest{{}, {MonitoredItemID: 7}}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "monitored item 7")
	}
	{
		r := &ua.SetMonitoringModeResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []ua.StatusCode{ua.StatusOK, ua.StatusBadMonitoredItemIDInvalid}}
		add("SetMonitoringMode", &ua.SetMonitoringModeRequest{MonitoredItemIDs: []uint32{1, 8}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "monitored item 8")
	}
	{
		r := &ua.DeleteMonitoredItemsResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []ua.StatusCode{ua.StatusOK, ua.StatusBadMonitoredItemIDInvalid}}
		add("DeleteMonitoredItems", &ua.DeleteMonitoredItemsRequest{MonitoredItemIDs: []uint32{1, 9}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "monitored item 9")
	}
	{
		r := &ua.SetTriggeringResponse{ResponseHeader: &ua.ResponseHeader{}, AddResults: []ua.StatusCode{ua.StatusOK, ua.StatusBadMonitoredItemIDInvalid}, RemoveResults: []ua.StatusCode{ua.StatusOK}}
		add("SetTriggering", &ua.SetTriggeringRequest{LinksToAdd: []uint32{1, 10}}, r,
			func() []*ua.DiagnosticInfo {
				if len(r.RemoveDiagnosticInfos) != 0 {
					return nil // fails the test: the removes were good
				}
				return r.AddDiagnosticInfos
			}, "link to monitored item 10")
	}
	{
		r := &ua.SetPublishingModeResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []ua.StatusCode{ua.StatusOK, ua.StatusBadSubscriptionIDInvalid}}
		add("SetPublishingMode", &ua.SetPublishingModeRequest{SubscriptionIDs: []uint32{1, 11}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "subscription 11")
	}
	{
		r := &ua.DeleteSubscriptionsResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []ua.StatusCode{ua.StatusOK, ua.StatusBadSubscriptionIDInvalid}}
		add("DeleteSubscriptions", &ua.DeleteSubscriptionsRequest{SubscriptionIDs: []uint32{1, 12}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "subscription 12")
	}
	{
		r := &ua.TransferSubscriptionsResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.TransferResult{{}, {StatusCode: ua.StatusBadSubscriptionIDInvalid}}}
		add("TransferSubscriptions", &ua.TransferSubscriptionsRequest{SubscriptionIDs: []uint32{1, 13}}, r,
			func() []*ua.DiagnosticInfo { return r.DiagnosticInfos }, "subscription 13")
	}
	return cases
}

// TestAddDiagnostics_Operations verifies the operation DiagnosticInfos of
// every service: one per operation once one of them failed, the failed one
// with its symbolic id and the operation in terms of the request.
func TestAddDiagnostics_Operations(t *testing.T) {
	for _, tc := range diagCases() {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.SetHeader(&ua.RequestHeader{ReturnDiagnostics: ua.OperationLevelAll})
			addDiagnostics(tc.req, tc.resp)
			infos := tc.infos()
			require.Len(t, infos, 2)
			hdr := tc.resp.Header()
			require.Nil(t, hdr.Diagnostic(infos[0]))
			d := hdr.Diagnostic(infos[1])
			require.NotNil(t, d)
			require.NotEmpty(t, d.SymbolicID)
			require.Equal(t, uaNamespaceURI, d.NamespaceURI)
			require.NotEmpty(t, d.LocalizedText)
			require.Equal(t, "en", d.Locale)
			require.Contains(t, d.AdditionalInfo, tc.info)
			require.Nil(t, hdr.ServiceDiagnostics)
		})
	}
}

// TestAddDiagnostics_NoRequest verifies operation diagnostics of a response
// whose request is not of the expected type: no AdditionalInfo.
func TestAddDiagnostics_NoRequest(t *testing.T) {
	for _, tc := range diagCases() {
		t.Run(tc.name, func(t *testing.T) {
			other := &ua.CloseSessionRequest{RequestHeader: &ua.RequestHeader{ReturnDiagnostics: ua.OperationLevelSymbolicID}}
			addDiagnostics(other, tc.resp)
			infos := tc.infos()
			require.Len(t, infos, 2)
			d := tc.resp.Header().Diagnostic(infos[1])
			require.NotEmpty(t, d.SymbolicID)
			require.Empty(t, d.AdditionalInfo)
		})
	}
}

// TestAddDiagnostics_Bits verifies that only the requested fields are
// filled, and that nothing is returned without the mask.
func TestAddDiagnostics_Bits(t *testing.T) {
	mk := func(mask uint32) *ua.ReadResponse {
		req := &ua.ReadRequest{RequestHeader: &ua.RequestHeader{ReturnDiagnostics: mask}, NodesToRead: []*ua.ReadValueID{{}}}
		resp := &ua.ReadResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.DataValue{{Status: ua.StatusBadNodeIDUnknown}}}
		addDiagnostics(req, resp)
		return resp
	}
	r := mk(0)
	require.Nil(t, r.DiagnosticInfos)
	require.Nil(t, r.ResponseHeader.StringTable)

	r = mk(ua.ServiceLevelAll) // service bits only: the service was good
	require.Nil(t, r.ResponseHeader.ServiceDiagnostics)
	require.Nil(t, r.DiagnosticInfos)

	r = mk(ua.OperationLevelLocalizedText)
	d := r.ResponseHeader.Diagnostic(r.DiagnosticInfos[0])
	require.Empty(t, d.SymbolicID)
	require.NotEmpty(t, d.LocalizedText)

	r = mk(ua.OperationLevelAdditionalInfo)
	d = r.ResponseHeader.Diagnostic(r.DiagnosticInfos[0])
	require.Equal(t, "null NodeId, attribute Invalid", d.AdditionalInfo)
	require.Empty(t, r.ResponseHeader.StringTable, "AdditionalInfo is not in the string table")

	// Only good operations: an empty array.
	req := &ua.ReadRequest{RequestHeader: &ua.RequestHeader{ReturnDiagnostics: ua.ReturnDiagnosticsAll}, NodesToRead: []*ua.ReadValueID{{}}}
	resp := &ua.ReadResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.DataValue{nil}}
	addDiagnostics(req, resp)
	require.NotNil(t, resp.DiagnosticInfos)
	require.Empty(t, resp.DiagnosticInfos)

	// No header, no response: nothing happens.
	addDiagnostics(nil, resp)
	addDiagnostics(req, nil)
	addDiagnostics(&ua.ReadRequest{}, resp)
}

// TestAddDiagnostics_Service verifies the service diagnostics of a failed
// service, and that a failed service has no operation diagnostics.
func TestAddDiagnostics_Service(t *testing.T) {
	for _, tc := range []struct {
		req  ua.Request
		st   ua.StatusCode
		info string
	}{
		{&ua.ReadRequest{}, ua.StatusBadSessionIDInvalid, "no session"},
		{&ua.ReadRequest{}, ua.StatusBadSessionNotActivated, "not been activated"},
		{&ua.QueryFirstRequest{}, ua.StatusBadServiceUnsupported, "does not implement QueryFirst"},
		{&ua.ReadRequest{NodesToRead: make([]*ua.ReadValueID, 3)}, ua.StatusBadTooManyOperations, "Read with 3 operations"},
		{&ua.WriteRequest{}, ua.StatusBadNothingToDo, "Write without operations"},
		{&ua.BrowseRequest{}, ua.StatusBadTimeout, ""},
	} {
		tc.req.SetHeader(&ua.RequestHeader{ReturnDiagnostics: ua.ReturnDiagnosticsAll})
		resp := &ua.ServiceFault{ResponseHeader: &ua.ResponseHeader{ServiceResult: tc.st}}
		addDiagnostics(tc.req, resp)
		d := resp.ResponseHeader.ServiceDiagnostic()
		require.NotNil(t, d, tc.st.Error())
		require.NotEmpty(t, d.SymbolicID)
		require.Contains(t, d.AdditionalInfo, tc.info)
	}

	// Operation counts of the requests the operation limits apply to.
	for _, req := range []ua.Request{
		&ua.ReadRequest{NodesToRead: make([]*ua.ReadValueID, 2)},
		&ua.WriteRequest{NodesToWrite: make([]*ua.WriteValue, 2)},
		&ua.BrowseRequest{NodesToBrowse: make([]*ua.BrowseDescription, 2)},
		&ua.CallRequest{MethodsToCall: make([]*ua.CallMethodRequest, 2)},
		&ua.HistoryReadRequest{NodesToRead: make([]*ua.HistoryReadValueID, 2)},
		&ua.TranslateBrowsePathsToNodeIDsRequest{BrowsePaths: make([]*ua.BrowsePath, 2)},
		&ua.CreateMonitoredItemsRequest{ItemsToCreate: make([]*ua.MonitoredItemCreateRequest, 2)},
		&ua.RegisterNodesRequest{NodesToRegister: make([]*ua.NodeID, 2)},
		&ua.AddNodesRequest{NodesToAdd: make([]*ua.AddNodesItem, 2)},
		&ua.DeleteNodesRequest{NodesToDelete: make([]*ua.DeleteNodesItem, 2)},
	} {
		require.Equal(t, 2, operationCount(req), "%T", req)
	}
	require.Zero(t, operationCount(&ua.PublishRequest{}))
}

// TestAddDiagnostics_Call verifies the diagnostics of a method call: the
// first failed input argument is the inner status of the call, and every
// failed argument has a DiagnosticInfo of its own.
func TestAddDiagnostics_Call(t *testing.T) {
	obj, m := ua.NewNumericNodeID(1, 1), ua.NewNumericNodeID(1, 2)
	req := &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{ReturnDiagnostics: ua.ReturnDiagnosticsAll},
		MethodsToCall: []*ua.CallMethodRequest{{ObjectID: obj, MethodID: m}, {ObjectID: obj, MethodID: m}},
	}
	resp := &ua.CallResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.CallMethodResult{
		{StatusCode: ua.StatusOK, InputArgumentResults: []ua.StatusCode{ua.StatusOK}},
		{StatusCode: ua.StatusBadInvalidArgument, InputArgumentResults: []ua.StatusCode{ua.StatusOK, ua.StatusBadTypeMismatch, ua.StatusBadOutOfRange}},
	}}
	addDiagnostics(req, resp)
	require.Len(t, resp.DiagnosticInfos, 2)
	d := resp.ResponseHeader.Diagnostic(resp.DiagnosticInfos[1])
	require.Equal(t, "BadInvalidArgument", d.SymbolicID)
	require.Equal(t, ua.StatusBadTypeMismatch, d.InnerStatusCode)
	require.NotNil(t, d.Inner)
	require.Equal(t, "BadTypeMismatch", d.Inner.SymbolicID)
	require.Equal(t, "method ns=1;i=2 of object ns=1;i=1", d.AdditionalInfo)
	require.Contains(t, d.String(), "inner")

	require.Empty(t, resp.Results[0].InputArgumentDiagnosticInfos)
	args := resp.Results[1].InputArgumentDiagnosticInfos
	require.Len(t, args, 3)
	require.Nil(t, resp.ResponseHeader.Diagnostic(args[0]))
	require.Equal(t, "BadOutOfRange", resp.ResponseHeader.Diagnostic(args[2]).SymbolicID)
	require.Equal(t, "input argument 2", resp.ResponseHeader.Diagnostic(args[2]).AdditionalInfo)

	// The string table holds every string once.
	seen := map[string]bool{}
	for _, s := range resp.ResponseHeader.StringTable {
		require.False(t, seen[s], s)
		seen[s] = true
	}

	// A nil result.
	resp = &ua.CallResponse{ResponseHeader: &ua.ResponseHeader{}, Results: []*ua.CallMethodResult{nil}}
	addDiagnostics(req, resp)
	require.Empty(t, resp.DiagnosticInfos)
}

// TestDiagBuilder_Info verifies the corner cases of building a
// DiagnosticInfo.
func TestDiagBuilder_Info(t *testing.T) {
	b := &diagBuilder{}
	require.Nil(t, b.info(diagLevelBits, ua.StatusOK, "x", 0), "nothing to tell about a good status")
	require.Nil(t, b.info(0, ua.StatusBadInternalError, "x", 0), "no bits")
	// An unknown status has no symbolic id or text, only the AdditionalInfo.
	d := b.info(diagLevelBits, ua.StatusCode(0x80FF0000), "x", 0)
	require.NotNil(t, d)
	require.Equal(t, byte(ua.DiagnosticInfoAdditionalInfo), d.EncodingMask)
	require.Nil(t, b.info(diagSymbolicID, ua.StatusCode(0x80FF0000), "", 0))
	// Inner status without inner diagnostics.
	d = b.info(diagInnerStatusCode, ua.StatusBadInvalidArgument, "", ua.StatusBadTypeMismatch)
	require.Equal(t, byte(ua.DiagnosticInfoInnerStatusCode), d.EncodingMask)
	require.Nil(t, d.InnerDiagnosticInfo)
	require.Equal(t, "i=1", nodeInfo(ua.NewNumericNodeID(0, 1)))
	require.Equal(t, ua.StatusOK, dataValueStatus(nil))
	require.Empty(t, subscriptionInfo(nil, 0))
	require.Empty(t, subscriptionInfo(&ua.SetPublishingModeRequest{}, 3))
}

// FuzzAddDiagnostics builds the diagnostics of a Call with arbitrary
// statuses and masks: every DiagnosticInfo must refer to the string table,
// and there is either none or one per operation.
func FuzzAddDiagnostics(f *testing.F) {
	f.Add(uint32(ua.ReturnDiagnosticsAll), uint32(ua.StatusBadNodeIDUnknown), uint32(ua.StatusOK), uint32(ua.StatusBadTypeMismatch), uint32(0))
	f.Add(uint32(ua.OperationLevelSymbolicID), uint32(0x80FF0000), uint32(ua.StatusUncertain), uint32(0), uint32(ua.StatusBadTimeout))
	f.Fuzz(func(t *testing.T, mask, st1, st2, arg, svc uint32) {
		req := &ua.CallRequest{
			RequestHeader: &ua.RequestHeader{ReturnDiagnostics: mask},
			MethodsToCall: []*ua.CallMethodRequest{{}, nil},
		}
		resp := &ua.CallResponse{ResponseHeader: &ua.ResponseHeader{ServiceResult: ua.StatusCode(svc)}, Results: []*ua.CallMethodResult{
			{StatusCode: ua.StatusCode(st1), InputArgumentResults: []ua.StatusCode{ua.StatusCode(arg)}},
			{StatusCode: ua.StatusCode(st2)},
		}}
		addDiagnostics(req, resp)
		table := resp.ResponseHeader.StringTable
		check := func(d *ua.DiagnosticInfo) {
			for ; d != nil; d = d.InnerDiagnosticInfo {
				for _, ix := range []struct {
					flag byte
					i    int32
				}{{ua.DiagnosticInfoSymbolicID, d.SymbolicID}, {ua.DiagnosticInfoNamespaceURI, d.NamespaceURI},
					{ua.DiagnosticInfoLocalizedText, d.LocalizedText}, {ua.DiagnosticInfoLocale, d.Locale}} {
					if d.Has(ix.flag) && (ix.i < 0 || int(ix.i) >= len(table)) {
						t.Fatalf("index %d outside the string table of %d", ix.i, len(table))
					}
				}
			}
		}
		check(resp.ResponseHeader.ServiceDiagnostics)
		if n := len(resp.DiagnosticInfos); n != 0 && n != len(resp.Results) {
			t.Fatalf("%d DiagnosticInfos for %d operations", n, len(resp.Results))
		}
		for _, d := range resp.DiagnosticInfos {
			check(d)
		}
		for _, r := range resp.Results {
			for _, d := range r.InputArgumentDiagnosticInfos {
				check(d)
			}
		}
	})
}
