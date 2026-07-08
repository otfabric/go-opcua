// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttributeService_Read(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	svc := &AttributeService{srv: srv}

	t.Run("read existing variable", func(t *testing.T) {
		req := &ua.ReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead: []*ua.ReadValueID{
				{
					NodeID:      ua.NewStringNodeID(ns.ID(), "rw_int32"),
					AttributeID: ua.AttributeIDValue,
				},
			},
		}
		resp, err := svc.Read(context.Background(), nil, req, 1)
		require.NoError(t, err)

		readResp, ok := resp.(*ua.ReadResponse)
		require.True(t, ok)
		require.Len(t, readResp.Results, 1)
		assert.Equal(t, int32(42), readResp.Results[0].Value.Value())
	})

	t.Run("read multiple nodes", func(t *testing.T) {
		req := &ua.ReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead: []*ua.ReadValueID{
				{NodeID: ua.NewStringNodeID(ns.ID(), "rw_int32"), AttributeID: ua.AttributeIDValue},
				{NodeID: ua.NewStringNodeID(ns.ID(), "rw_float64"), AttributeID: ua.AttributeIDValue},
			},
		}
		resp, err := svc.Read(context.Background(), nil, req, 1)
		require.NoError(t, err)

		readResp := resp.(*ua.ReadResponse)
		require.Len(t, readResp.Results, 2)
		assert.Equal(t, int32(42), readResp.Results[0].Value.Value())
		assert.Equal(t, float64(3.14), readResp.Results[1].Value.Value())
	})

	t.Run("read node in unknown namespace", func(t *testing.T) {
		req := &ua.ReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead: []*ua.ReadValueID{
				{NodeID: ua.NewStringNodeID(99, "nonexistent"), AttributeID: ua.AttributeIDValue},
			},
		}
		resp, err := svc.Read(context.Background(), nil, req, 1)
		require.NoError(t, err)

		readResp := resp.(*ua.ReadResponse)
		require.Len(t, readResp.Results, 1)
		assert.Equal(t, ua.StatusBad, readResp.Results[0].Status)
	})

	t.Run("read unknown node", func(t *testing.T) {
		req := &ua.ReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead: []*ua.ReadValueID{
				{NodeID: ua.NewStringNodeID(ns.ID(), "does_not_exist"), AttributeID: ua.AttributeIDValue},
			},
		}
		resp, err := svc.Read(context.Background(), nil, req, 1)
		require.NoError(t, err)

		readResp := resp.(*ua.ReadResponse)
		require.Len(t, readResp.Results, 1)
		assert.Equal(t, ua.StatusBadNodeIDUnknown, readResp.Results[0].Status)
	})

	t.Run("read no-access node", func(t *testing.T) {
		req := &ua.ReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead: []*ua.ReadValueID{
				{NodeID: ua.NewStringNodeID(ns.ID(), "no_access"), AttributeID: ua.AttributeIDValue},
			},
		}
		resp, err := svc.Read(context.Background(), nil, req, 1)
		require.NoError(t, err)

		readResp := resp.(*ua.ReadResponse)
		require.Len(t, readResp.Results, 1)
		assert.Equal(t, ua.StatusBadUserAccessDenied, readResp.Results[0].Status)
	})

	t.Run("read browse name attribute", func(t *testing.T) {
		req := &ua.ReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead: []*ua.ReadValueID{
				{NodeID: ua.NewStringNodeID(ns.ID(), "rw_int32"), AttributeID: ua.AttributeIDBrowseName},
			},
		}
		resp, err := svc.Read(context.Background(), nil, req, 1)
		require.NoError(t, err)

		readResp := resp.(*ua.ReadResponse)
		require.Len(t, readResp.Results, 1)
		qn, ok := readResp.Results[0].Value.Value().(*ua.QualifiedName)
		require.True(t, ok)
		assert.Equal(t, "rw_int32", qn.Name)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.Read(context.Background(), nil, &ua.WriteRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestAttributeService_Write(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	svc := &AttributeService{srv: srv}

	t.Run("write to writable node", func(t *testing.T) {
		req := &ua.WriteRequest{
			RequestHeader: reqHeader(),
			NodesToWrite: []*ua.WriteValue{
				{
					NodeID:      ua.NewStringNodeID(ns.ID(), "rw_int32"),
					AttributeID: ua.AttributeIDValue,
					Value: &ua.DataValue{
						EncodingMask: ua.DataValueValue,
						Value:        ua.MustVariant(int32(100)),
					},
				},
			},
		}
		resp, err := svc.Write(context.Background(), nil, req, 1)
		require.NoError(t, err)

		writeResp := resp.(*ua.WriteResponse)
		require.Len(t, writeResp.Results, 1)
		assert.Equal(t, ua.StatusOK, writeResp.Results[0])

		// Verify the write took effect
		readReq := &ua.ReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead: []*ua.ReadValueID{
				{NodeID: ua.NewStringNodeID(ns.ID(), "rw_int32"), AttributeID: ua.AttributeIDValue},
			},
		}
		readResp, err := svc.Read(context.Background(), nil, readReq, 2)
		require.NoError(t, err)
		rr := readResp.(*ua.ReadResponse)
		assert.Equal(t, int32(100), rr.Results[0].Value.Value())
	})

	t.Run("write to read-only node", func(t *testing.T) {
		req := &ua.WriteRequest{
			RequestHeader: reqHeader(),
			NodesToWrite: []*ua.WriteValue{
				{
					NodeID:      ua.NewStringNodeID(ns.ID(), "ro_bool"),
					AttributeID: ua.AttributeIDValue,
					Value: &ua.DataValue{
						EncodingMask: ua.DataValueValue,
						Value:        ua.MustVariant(false),
					},
				},
			},
		}
		resp, err := svc.Write(context.Background(), nil, req, 1)
		require.NoError(t, err)

		writeResp := resp.(*ua.WriteResponse)
		require.Len(t, writeResp.Results, 1)
		assert.Equal(t, ua.StatusBadUserAccessDenied, writeResp.Results[0])
	})

	t.Run("write to unknown namespace", func(t *testing.T) {
		req := &ua.WriteRequest{
			RequestHeader: reqHeader(),
			NodesToWrite: []*ua.WriteValue{
				{
					NodeID:      ua.NewStringNodeID(99, "x"),
					AttributeID: ua.AttributeIDValue,
					Value: &ua.DataValue{
						EncodingMask: ua.DataValueValue,
						Value:        ua.MustVariant(int32(1)),
					},
				},
			},
		}
		resp, err := svc.Write(context.Background(), nil, req, 1)
		require.NoError(t, err)

		writeResp := resp.(*ua.WriteResponse)
		require.Len(t, writeResp.Results, 1)
		assert.Equal(t, ua.StatusBadNodeNotInView, writeResp.Results[0])
	})

	t.Run("write to no-access node", func(t *testing.T) {
		req := &ua.WriteRequest{
			RequestHeader: reqHeader(),
			NodesToWrite: []*ua.WriteValue{
				{
					NodeID:      ua.NewStringNodeID(ns.ID(), "no_access"),
					AttributeID: ua.AttributeIDValue,
					Value: &ua.DataValue{
						EncodingMask: ua.DataValueValue,
						Value:        ua.MustVariant(int32(0)),
					},
				},
			},
		}
		resp, err := svc.Write(context.Background(), nil, req, 1)
		require.NoError(t, err)

		writeResp := resp.(*ua.WriteResponse)
		require.Len(t, writeResp.Results, 1)
		assert.Equal(t, ua.StatusBadUserAccessDenied, writeResp.Results[0])
	})
}

func TestAttributeService_HistoryRead(t *testing.T) {
	srv := newTestServer()
	svc := &AttributeService{srv: srv}

	t.Run("returns unsupported for each node", func(t *testing.T) {
		req := &ua.HistoryReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead: []*ua.HistoryReadValueID{
				{NodeID: ua.NewStringNodeID(2, "rw_int32")},
				{NodeID: ua.NewStringNodeID(2, "rw_float64")},
			},
		}
		resp, err := svc.HistoryRead(context.Background(), nil, req, 1)
		require.NoError(t, err)

		histResp := resp.(*ua.HistoryReadResponse)
		assert.Equal(t, ua.StatusOK, histResp.ResponseHeader.ServiceResult)
		require.Len(t, histResp.Results, 2)
		assert.Equal(t, ua.StatusBadHistoryOperationUnsupported, histResp.Results[0].StatusCode)
		assert.Equal(t, ua.StatusBadHistoryOperationUnsupported, histResp.Results[1].StatusCode)
	})

	t.Run("empty request", func(t *testing.T) {
		req := &ua.HistoryReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead:   []*ua.HistoryReadValueID{},
		}
		resp, err := svc.HistoryRead(context.Background(), nil, req, 2)
		require.NoError(t, err)

		histResp := resp.(*ua.HistoryReadResponse)
		assert.Equal(t, ua.StatusOK, histResp.ResponseHeader.ServiceResult)
		assert.Empty(t, histResp.Results)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.HistoryRead(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestAttributeService_HistoryUpdate(t *testing.T) {
	srv := newTestServer()
	svc := &AttributeService{srv: srv}

	t.Run("returns unsupported for each detail", func(t *testing.T) {
		req := &ua.HistoryUpdateRequest{
			RequestHeader:        reqHeader(),
			HistoryUpdateDetails: []*ua.ExtensionObject{ua.NewExtensionObject(nil)},
		}
		resp, err := svc.HistoryUpdate(context.Background(), nil, req, 1)
		require.NoError(t, err)

		histResp := resp.(*ua.HistoryUpdateResponse)
		assert.Equal(t, ua.StatusOK, histResp.ResponseHeader.ServiceResult)
		require.Len(t, histResp.Results, 1)
		assert.Equal(t, ua.StatusBadHistoryOperationUnsupported, histResp.Results[0].StatusCode)
	})

	t.Run("empty request", func(t *testing.T) {
		req := &ua.HistoryUpdateRequest{
			RequestHeader:        reqHeader(),
			HistoryUpdateDetails: []*ua.ExtensionObject{},
		}
		resp, err := svc.HistoryUpdate(context.Background(), nil, req, 2)
		require.NoError(t, err)

		histResp := resp.(*ua.HistoryUpdateResponse)
		assert.Equal(t, ua.StatusOK, histResp.ResponseHeader.ServiceResult)
		assert.Empty(t, histResp.Results)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.HistoryUpdate(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}
