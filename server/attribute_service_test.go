// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
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

func TestAttributeService_HistoryWithHistorian(t *testing.T) {
	srv := newTestServer()
	svc := &AttributeService{srv: srv}
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Hist.Svc")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		h.RecordValue(nodeID, &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	srv.SetHistorian(h)

	t.Run("read raw", func(t *testing.T) {
		req := &ua.HistoryReadRequest{
			RequestHeader: reqHeader(),
			HistoryReadDetails: ua.NewExtensionObject(&ua.ReadRawModifiedDetails{
				StartTime:        base,
				EndTime:          base.Add(10 * time.Second),
				NumValuesPerNode: 10,
			}),
			NodesToRead: []*ua.HistoryReadValueID{{NodeID: nodeID}},
		}
		resp, err := svc.HistoryRead(context.Background(), nil, req, 1)
		require.NoError(t, err)
		hist := resp.(*ua.HistoryReadResponse)
		require.Len(t, hist.Results, 1)
		assert.Equal(t, ua.StatusOK, hist.Results[0].StatusCode)
	})

	t.Run("read modified", func(t *testing.T) {
		_ = h.UpdateData(nodeID, ua.PerformUpdateTypeReplace, []*ua.DataValue{{
			EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(float64(99)), SourceTimestamp: base,
		}})
		req := &ua.HistoryReadRequest{
			RequestHeader: reqHeader(),
			HistoryReadDetails: ua.NewExtensionObject(&ua.ReadRawModifiedDetails{
				IsReadModified: true,
				StartTime:      base,
				EndTime:        base.Add(time.Second),
			}),
			NodesToRead: []*ua.HistoryReadValueID{{NodeID: nodeID}},
		}
		resp, err := svc.HistoryRead(context.Background(), nil, req, 2)
		require.NoError(t, err)
		assert.Equal(t, ua.StatusOK, resp.(*ua.HistoryReadResponse).Results[0].StatusCode)
	})

	t.Run("read at time", func(t *testing.T) {
		req := &ua.HistoryReadRequest{
			RequestHeader: reqHeader(),
			HistoryReadDetails: ua.NewExtensionObject(&ua.ReadAtTimeDetails{
				ReqTimes: []time.Time{base.Add(1500 * time.Millisecond)},
			}),
			NodesToRead: []*ua.HistoryReadValueID{{NodeID: nodeID}},
		}
		resp, err := svc.HistoryRead(context.Background(), nil, req, 3)
		require.NoError(t, err)
		assert.Equal(t, ua.StatusOK, resp.(*ua.HistoryReadResponse).Results[0].StatusCode)
	})

	t.Run("read processed", func(t *testing.T) {
		req := &ua.HistoryReadRequest{
			RequestHeader: reqHeader(),
			HistoryReadDetails: ua.NewExtensionObject(&ua.ReadProcessedDetails{
				StartTime:          base,
				EndTime:            base.Add(4 * time.Second),
				ProcessingInterval: 2000,
				AggregateType:      []*ua.NodeID{ua.NewNumericNodeID(0, id.AggregateFunctionAverage)},
			}),
			NodesToRead: []*ua.HistoryReadValueID{{NodeID: nodeID}},
		}
		resp, err := svc.HistoryRead(context.Background(), nil, req, 4)
		require.NoError(t, err)
		assert.Equal(t, ua.StatusOK, resp.(*ua.HistoryReadResponse).Results[0].StatusCode)
	})

	t.Run("release continuation points", func(t *testing.T) {
		req := &ua.HistoryReadRequest{
			RequestHeader:             reqHeader(),
			ReleaseContinuationPoints: true,
			NodesToRead: []*ua.HistoryReadValueID{
				{NodeID: nodeID, ContinuationPoint: []byte("unused")},
			},
		}
		resp, err := svc.HistoryRead(context.Background(), nil, req, 5)
		require.NoError(t, err)
		assert.Equal(t, ua.StatusOK, resp.(*ua.HistoryReadResponse).Results[0].StatusCode)
	})

	t.Run("update data / delete raw / delete at time", func(t *testing.T) {
		req := &ua.HistoryUpdateRequest{
			RequestHeader: reqHeader(),
			HistoryUpdateDetails: []*ua.ExtensionObject{
				ua.NewExtensionObject(&ua.UpdateDataDetails{
					NodeID:               nodeID,
					PerformInsertReplace: ua.PerformUpdateTypeUpdate,
					UpdateValues: []*ua.DataValue{{
						EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
						Value:           ua.MustVariant(float64(7)),
						SourceTimestamp: base.Add(10 * time.Second),
					}},
				}),
				ua.NewExtensionObject(&ua.DeleteRawModifiedDetails{
					NodeID:    nodeID,
					StartTime: base.Add(10 * time.Second),
					EndTime:   base.Add(10 * time.Second),
				}),
				ua.NewExtensionObject(&ua.DeleteAtTimeDetails{
					NodeID:   nodeID,
					ReqTimes: []time.Time{base},
				}),
			},
		}
		resp, err := svc.HistoryUpdate(context.Background(), nil, req, 6)
		require.NoError(t, err)
		hist := resp.(*ua.HistoryUpdateResponse)
		require.Len(t, hist.Results, 3)
		for i, r := range hist.Results {
			assert.Equal(t, ua.StatusOK, r.StatusCode, "result %d", i)
		}
	})

	t.Run("unsupported details type", func(t *testing.T) {
		req := &ua.HistoryReadRequest{
			RequestHeader:      reqHeader(),
			HistoryReadDetails: ua.NewExtensionObject(&ua.ReadEventDetails{}),
			NodesToRead:        []*ua.HistoryReadValueID{{NodeID: nodeID}},
		}
		resp, err := svc.HistoryRead(context.Background(), nil, req, 7)
		require.NoError(t, err)
		assert.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.(*ua.HistoryReadResponse).Results[0].StatusCode)
	})
}
