// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// fakeLog answers the Browse of a LogObject with its GetRecords and the
// calls with results, one per call.
type fakeLog struct {
	fakeMethods
	results []*ua.CallMethodResult
	reqs    []*ua.CallMethodRequest
}

func (f *fakeLog) Call(_ context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	f.reqs = append(f.reqs, req)
	if f.callErr != nil {
		return nil, f.callErr
	}
	r := f.results[0]
	f.results = f.results[1:]
	return r, nil
}

var (
	fakeLogNode    = ua.NewStringNodeID(5, "log")
	fakeGetRecords = ua.NewStringNodeID(5, "log.GetRecords")
)

func browseOf(refs ...*ua.ReferenceDescription) *ua.BrowseResponse {
	return &ua.BrowseResponse{Results: []*ua.BrowseResult{{StatusCode: ua.StatusOK, References: refs}}}
}

func refTo(n *ua.NodeID, bn *ua.QualifiedName) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{NodeID: ua.NewExpandedNodeID(n, "", 0), BrowseName: bn}
}

func recordsResult(cp any, msgs ...string) *ua.CallMethodResult {
	recs := &ua.LogRecordsDataType{}
	for _, m := range msgs {
		recs.LogRecordArray = append(recs.LogRecordArray, &ua.LogRecord{Severity: 100, Message: ua.NewLocalizedText(m)})
	}
	return &ua.CallMethodResult{OutputArguments: []*ua.Variant{ua.MustVariant(ua.NewExtensionObject(recs)), ua.MustVariant(cp)}}
}

func newFakeLog(results ...*ua.CallMethodResult) *fakeLog {
	return &fakeLog{
		fakeMethods: fakeMethods{browse: browseOf(
			refTo(ua.NewStringNodeID(5, "other"), &ua.QualifiedName{Name: "Other"}),
			refTo(fakeGetRecords, &ua.QualifiedName{Name: "GetRecords"}),
		)},
		results: results,
	}
}

// TestGetRecordsArguments: the six arguments of OPC 10000-26 §5.3 Table 2,
// with the defaults for a zero EndTime and MinimumSeverity.
func TestGetRecordsArguments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFakeLog(recordsResult([]byte{}, "a"), recordsResult(nil))
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	res, err := getRecords(ctx, f, fakeLogNode, GetRecordsRequest{StartTime: start, MaxReturnRecords: 7, RequestMask: ua.LogRecordMaskSourceName})
	require.NoError(t, err)
	require.Len(t, res.Records, 1)
	assert.Nil(t, res.ContinuationPoint, "an empty ByteString is none")
	req := f.reqs[0]
	assert.True(t, req.ObjectID.Equal(fakeLogNode))
	assert.True(t, req.MethodID.Equal(fakeGetRecords))
	in := req.InputArguments
	require.Len(t, in, 6)
	assert.Equal(t, start, in[0].Value())
	assert.Equal(t, MaxLogTime, in[1].Value())
	assert.Equal(t, uint32(7), in[2].Value())
	assert.Equal(t, uint16(1), in[3].Value())
	assert.Equal(t, uint32(ua.LogRecordMaskSourceName), in[4].Value())

	end := start.Add(time.Hour)
	res, err = getRecords(ctx, f, fakeLogNode, GetRecordsRequest{EndTime: end, MinimumSeverity: 300, ContinuationPoint: []byte{1}})
	require.NoError(t, err)
	assert.Empty(t, res.Records)
	in = f.reqs[1].InputArguments
	assert.Equal(t, end, in[1].Value())
	assert.Equal(t, uint16(300), in[3].Value())
	assert.Equal(t, []byte{1}, in[5].Value())
}

// TestReadLog follows the continuation points until there is none.
func TestReadLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFakeLog(recordsResult([]byte{1}, "a", "b"), recordsResult([]byte{2}, "c"), recordsResult(nil, "d"))
	recs, err := readLog(ctx, f, fakeLogNode, GetRecordsRequest{})
	require.NoError(t, err)
	var msgs []string
	for _, r := range recs {
		msgs = append(msgs, r.Message.Text)
	}
	assert.Equal(t, []string{"a", "b", "c", "d"}, msgs)
	require.Len(t, f.reqs, 3)
	assert.Nil(t, f.reqs[0].InputArguments[5].Value())
	assert.Equal(t, []byte{1}, f.reqs[1].InputArguments[5].Value())
	assert.Equal(t, []byte{2}, f.reqs[2].InputArguments[5].Value())

	// An error ends it with what it has.
	f = newFakeLog(recordsResult([]byte{1}, "a"), &ua.CallMethodResult{StatusCode: ua.StatusBadContinuationPointInvalid})
	recs, err = readLog(ctx, f, fakeLogNode, GetRecordsRequest{})
	require.ErrorIs(t, err, ua.StatusBadContinuationPointInvalid)
	require.ErrorIs(t, err, ErrCall)
	assert.Len(t, recs, 1)
}

// TestGetRecordsErrors: what the client refuses.
func TestGetRecordsErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	recs := ua.MustVariant(ua.NewExtensionObject(&ua.LogRecordsDataType{}))
	for name, res := range map[string]*ua.CallMethodResult{
		"one output":     {OutputArguments: []*ua.Variant{recs}},
		"nil output":     {OutputArguments: []*ua.Variant{recs, nil}},
		"no structure":   {OutputArguments: []*ua.Variant{ua.MustVariant(int32(1)), ua.MustVariant([]byte{})}},
		"other struct":   {OutputArguments: []*ua.Variant{ua.MustVariant(ua.NewExtensionObject(&ua.RolePermissionType{})), ua.MustVariant([]byte{})}},
		"cp not a bytes": {OutputArguments: []*ua.Variant{recs, ua.MustVariant("x")}},
	} {
		_, err := getRecords(ctx, newFakeLog(res), fakeLogNode, GetRecordsRequest{})
		assert.ErrorIs(t, err, ErrCall, name)
	}

	f := newFakeLog()
	f.callErr = errFake
	_, err := getRecords(ctx, f, fakeLogNode, GetRecordsRequest{})
	assert.ErrorIs(t, err, errFake)

	f = newFakeLog()
	f.browse = browseOf()
	_, err = getRecords(ctx, f, fakeLogNode, GetRecordsRequest{})
	assert.ErrorIs(t, err, ErrCall, "no GetRecords")
	assert.Empty(t, f.reqs)
}

// TestComponentLog: the AutomationComponentLog and the
// ConnectionManagerLog by their BrowseName in the namespace of their
// model, and the errors on the way.
func TestComponentLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	acLog := ua.NewStringNodeID(5, "aclog")
	f := &fakeMethods{nsa: []string{"http://opcfoundation.org/UA/", fxacid.NamespaceURI, fxcmid.NamespaceURI},
		browse: browseOf(
			refTo(ua.NewStringNodeID(5, "wrongns"), &ua.QualifiedName{NamespaceIndex: 2, Name: "AutomationComponentLog"}),
			&ua.ReferenceDescription{NodeID: &ua.ExpandedNodeID{NodeID: acLog, NamespaceURI: "urn:remote"}, BrowseName: &ua.QualifiedName{NamespaceIndex: 1, Name: "AutomationComponentLog"}},
			nil,
			&ua.ReferenceDescription{NodeID: ua.NewExpandedNodeID(acLog, "", 0)},
			refTo(acLog, &ua.QualifiedName{NamespaceIndex: 1, Name: "AutomationComponentLog"}),
			refTo(ua.NewStringNodeID(5, "cmlog"), &ua.QualifiedName{NamespaceIndex: 2, Name: "ConnectionManagerLog"}),
		)}
	n, err := componentLog(ctx, f, fakeAC, fxacid.NamespaceURI, "AutomationComponentLog")
	require.NoError(t, err)
	assert.True(t, n.Equal(acLog))
	n, err = connectionManagerLog(ctx, f)
	require.NoError(t, err)
	assert.Equal(t, "ns=5;s=cmlog", n.String())

	_, err = componentLog(ctx, f, nil, fxacid.NamespaceURI, "AutomationComponentLog")
	require.ErrorIs(t, err, ErrCall)
	_, err = componentLog(ctx, f, fakeAC, "urn:none", "AutomationComponentLog")
	require.ErrorIs(t, err, ErrCall)
	_, err = componentLog(ctx, f, fakeAC, fxacid.NamespaceURI, "Missing")
	require.ErrorIs(t, err, ErrCall)

	for name, b := range map[string]*fakeMethods{
		"namespaces": {nsaErr: errFake},
		"browse":     {nsa: f.nsa, browseErr: errFake},
		"results":    {nsa: f.nsa, browse: &ua.BrowseResponse{}},
		"nil result": {nsa: f.nsa, browse: &ua.BrowseResponse{Results: []*ua.BrowseResult{nil}}},
		"status":     {nsa: f.nsa, browse: &ua.BrowseResponse{Results: []*ua.BrowseResult{{StatusCode: ua.StatusBadNodeIDUnknown}}}},
	} {
		_, err := componentLog(ctx, b, fakeAC, fxacid.NamespaceURI, "AutomationComponentLog")
		assert.ErrorIs(t, err, ErrCall, name)
	}
	_, err = connectionManagerLog(ctx, &fakeMethods{nsa: []string{"http://opcfoundation.org/UA/"}})
	require.ErrorIs(t, err, ErrCall, "no CM namespace")
	_, err = childOf(ctx, f, nil, ua.NodeClassMethod, &ua.QualifiedName{Name: "GetRecords"})
	require.ErrorIs(t, err, ErrCall)
}
