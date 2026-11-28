// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

var annT0 = time.Date(2026, 4, 1, 8, 0, 0, 0, time.UTC)

func annT(s int) time.Time { return annT0.Add(time.Duration(s) * time.Second) }

// annotationClient connects to a server whose Variable "annotated" has
// history in the built-in Historian and the Annotations Property, and whose
// Variable "plain" has history without it.
func annotationClient(t *testing.T, handlers map[uint16]server.Handler) (*opcua.Client, *ua.NodeID, *ua.NodeID) {
	t.Helper()
	srv, url := newScriptedServer(t, handlers)
	ns := server.NewNodeNameSpace(srv, "urn:annotations")
	v := ns.AddNewVariableStringNode("annotated", 1.0)
	plain := ns.AddNewVariableStringNode("plain", 1.0)
	h := server.NewHistorian()
	h.EnableNode(v.ID(), 0)
	h.EnableNode(plain.ID(), 0)
	srv.SetHistorian(h)
	require.NoError(t, srv.EnableAnnotations(v.ID()))
	return connectCovClient(t, url, opcua.SkipNamespaceUpdate()), v.ID(), plain.ID()
}

// TestClientAnnotations: UpdateAnnotations and ReadAnnotations against the
// server (Part 11 §6.5.6, §6.9.3).
func TestClientAnnotations(t *testing.T) {
	c, node, plain := annotationClient(t, nil)
	ctx := context.Background()
	note := func(s int, msg string) opcua.HistoryAnnotation {
		return opcua.HistoryAnnotation{Time: annT(s), Annotation: &ua.Annotation{Message: msg, UserName: "op", AnnotationTime: annT(100)}}
	}

	ops, err := c.UpdateAnnotations(ctx, node, ua.PerformUpdateTypeInsert, note(1, "one"), note(2, "two"))
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted, ua.StatusGoodEntryInserted}, ops)
	ops, err = c.UpdateAnnotations(ctx, node, ua.PerformUpdateTypeInsert, note(1, "again"))
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusBadEntryExists}, ops)
	ops, err = c.UpdateAnnotations(ctx, node, ua.PerformUpdateTypeReplace, note(2, "dos"))
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced}, ops)

	got, err := c.ReadAnnotations(ctx, node, annT(2), annT(3), annT(1))
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, "dos", got[0].Annotation.Message)
	require.Equal(t, annT(2), got[0].Time)
	require.Equal(t, ua.StatusOK, got[0].Status)
	require.Nil(t, got[1].Annotation)
	require.Equal(t, ua.StatusBadNoData, got[1].Status)
	require.Equal(t, "one", got[2].Annotation.Message)
	require.Equal(t, "op", got[2].Annotation.UserName)
	require.Equal(t, annT(100), got[2].Annotation.AnnotationTime)

	ops, err = c.UpdateAnnotations(ctx, node, ua.PerformUpdateTypeRemove, opcua.HistoryAnnotation{Time: annT(1)})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, ops)
	got, err = c.ReadAnnotations(ctx, node, annT(1))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNoData, got[0].Status)

	// A node without the Annotations Property.
	_, err = c.ReadAnnotations(ctx, plain, annT(1))
	require.ErrorIs(t, err, ua.StatusBadHistoryOperationUnsupported)
	_, err = c.UpdateAnnotations(ctx, plain, ua.PerformUpdateTypeInsert, note(1, "x"))
	require.ErrorIs(t, err, ua.StatusBadHistoryOperationUnsupported)
}

// TestClientAnnotationsMalformed: responses the helpers reject.
func TestClientAnnotationsMalformed(t *testing.T) {
	var readResp func(*ua.HistoryReadRequest) *ua.HistoryReadResponse
	var updateResp func(*ua.HistoryUpdateRequest) ua.Response
	c, node, _ := annotationClient(t, map[uint16]server.Handler{
		id.HistoryReadRequestEncodingDefaultBinary: func(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
			req := r.(*ua.HistoryReadRequest)
			resp := readResp(req)
			resp.ResponseHeader = okHeader(req)
			return resp, nil
		},
		id.HistoryUpdateRequestEncodingDefaultBinary: func(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
			return updateResp(r.(*ua.HistoryUpdateRequest)), nil
		},
	})
	ctx := context.Background()
	data := func(dvs ...*ua.DataValue) *ua.HistoryReadResponse {
		return &ua.HistoryReadResponse{Results: []*ua.HistoryReadResult{{
			HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: dvs}),
		}}}
	}

	// A value that is no Annotation, a null value: no Annotation.
	readResp = func(*ua.HistoryReadRequest) *ua.HistoryReadResponse {
		return data(&ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(1.0)},
			&ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(ua.NewExtensionObject(&ua.Range{}))},
			&ua.DataValue{})
	}
	got, err := c.ReadAnnotations(ctx, node, annT(1), annT(2), annT(3))
	require.NoError(t, err)
	require.Len(t, got, 3)
	for _, a := range got {
		require.Nil(t, a.Annotation)
	}
	// No HistoryData: no Annotations.
	readResp = func(*ua.HistoryReadRequest) *ua.HistoryReadResponse {
		return &ua.HistoryReadResponse{Results: []*ua.HistoryReadResult{{StatusCode: ua.StatusGoodNoData}}}
	}
	got, err = c.ReadAnnotations(ctx, node, annT(1))
	require.NoError(t, err)
	require.Empty(t, got)
	// Another HistoryData.
	readResp = func(*ua.HistoryReadRequest) *ua.HistoryReadResponse {
		return &ua.HistoryReadResponse{Results: []*ua.HistoryReadResult{{HistoryData: ua.NewExtensionObject(&ua.HistoryEvent{})}}}
	}
	_, err = c.ReadAnnotations(ctx, node, annT(1))
	require.ErrorContains(t, err, "HistoryData")

	// Update: no result, a service fault.
	updateResp = func(req *ua.HistoryUpdateRequest) ua.Response {
		require.Len(t, req.HistoryUpdateDetails, 1)
		require.Equal(t, uint32(id.UpdateStructureDataDetailsEncodingDefaultBinary), req.HistoryUpdateDetails[0].TypeID.NodeID.IntID())
		return &ua.HistoryUpdateResponse{ResponseHeader: okHeader(req)}
	}
	_, err = c.UpdateAnnotations(ctx, node, ua.PerformUpdateTypeInsert, opcua.HistoryAnnotation{Time: annT(1)})
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)
	updateResp = func(req *ua.HistoryUpdateRequest) ua.Response {
		h := okHeader(req)
		h.ServiceResult = ua.StatusBadTooManyOperations
		return &ua.ServiceFault{ResponseHeader: h}
	}
	_, err = c.UpdateAnnotations(ctx, node, ua.PerformUpdateTypeInsert, opcua.HistoryAnnotation{Time: annT(1)})
	require.ErrorIs(t, err, ua.StatusBadTooManyOperations)
}
