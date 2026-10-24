// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// Every convenience wrapper of a closed client fails with
// BadServerNotConnected.
func TestClientCovWrappersClosed(t *testing.T) {
	c, f, ctx := setupFixture(t)
	require.NoError(t, c.Close(ctx))
	n := f.Int32
	now := time.Now()

	calls := map[string]func() error{
		"NamespaceArray":   func() error { _, err := c.NamespaceArray(ctx); return err },
		"FindNamespace":    func() error { _, err := c.FindNamespace(ctx, "x"); return err },
		"UpdateNamespaces": func() error { return c.UpdateNamespaces(ctx) },
		"NamespaceURI":     func() error { _, err := c.NamespaceURI(ctx, 0); return err },
		"ReadValue":        func() error { _, err := c.ReadValue(ctx, n); return err },
		"ReadValues":       func() error { _, err := c.ReadValues(ctx, n, n); return err },
		"ReadMulti":        func() error { _, err := c.ReadMulti(ctx, []opcua.ReadItem{{NodeID: n}}); return err },
		"WriteValue":       func() error { _, err := c.WriteValue(ctx, n, valueDV(int32(1))); return err },
		"WriteValues":      func() error { _, err := c.WriteValues(ctx, &ua.WriteValue{NodeID: n}); return err },
		"WriteAttribute":   func() error { _, err := c.WriteAttribute(ctx, n, ua.AttributeIDValue, valueDV(int32(1))); return err },
		"BrowseAll":        func() error { _, err := c.BrowseAll(ctx, f.Plant); return err },
		"CallMethod":       func() error { _, err := c.CallMethod(ctx, f.MethodObject, f.SquareMethod, int32(2)); return err },
		"ServerStatus":     func() error { _, err := c.ServerStatus(ctx); return err },
		"MethodArguments":  func() error { _, _, err := c.MethodArguments(ctx, f.MethodObject, f.SquareMethod); return err },
		"ReadHistory":      func() error { _, err := c.ReadHistory(ctx, n, now.Add(-time.Hour), now, 0); return err },
		"ReadHistoryAll": func() error {
			var last error
			for _, err := range c.ReadHistoryAll(ctx, n, now.Add(-time.Hour), now) {
				last = err
			}
			return last
		},
		"NodeFromPath":            func() error { _, err := c.NodeFromPath(ctx, "Server"); return err },
		"NodeFromPathInNamespace": func() error { _, err := c.NodeFromPathInNamespace(ctx, 0, "Server"); return err },
		"NodeFromQualifiedPath":   func() error { _, err := c.NodeFromQualifiedPath(ctx, "0:Server"); return err },
		"HistoryReadEvent": func() error {
			_, err := c.HistoryReadEvent(ctx, []*ua.HistoryReadValueID{{NodeID: n}}, &ua.ReadEventDetails{})
			return err
		},
		"HistoryReadProcessed": func() error {
			_, err := c.HistoryReadProcessed(ctx, []*ua.HistoryReadValueID{{NodeID: n}}, &ua.ReadProcessedDetails{})
			return err
		},
		"HistoryReadAtTime": func() error {
			_, err := c.HistoryReadAtTime(ctx, []*ua.HistoryReadValueID{{NodeID: n}}, &ua.ReadAtTimeDetails{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, call(), ua.StatusBadServerNotConnected)
		})
	}
}

func TestClientCovWrappers(t *testing.T) {
	c, f, ctx := setupFixture(t)

	// NamespaceURI and FindNamespace
	nsURI, err := c.NamespaceURI(ctx, f.NSIndex)
	require.NoError(t, err)
	require.Equal(t, "http://otfabric.com/conformance", nsURI)
	_, err = c.NamespaceURI(ctx, 999)
	require.ErrorContains(t, err, "namespace index 999 out of range")
	_, err = c.FindNamespace(ctx, "urn:not-there")
	require.ErrorIs(t, err, errors.ErrNamespaceNotFound)

	// ReadMulti in chunks of two keeps the order of the items
	items := []opcua.ReadItem{
		{NodeID: f.Int32},
		{NodeID: f.String},
		{NodeID: f.Bool, AttributeID: ua.AttributeIDValue},
		{NodeID: f.Int32Array, IndexRange: "1:2"},
		{NodeID: ua.NewStringNodeID(f.NSIndex, "missing")},
	}
	res, err := c.ReadMulti(ctx, items, opcua.ReadMultiWithChunkSize(2))
	require.NoError(t, err)
	require.Len(t, res, 5)
	require.Equal(t, int32(42), res[0].DataValue.Value.Value())
	require.Equal(t, "hello", res[1].DataValue.Value.Value())
	require.Equal(t, true, res[2].DataValue.Value.Value())
	require.Equal(t, []int32{2, 3}, res[3].DataValue.Value.Value())
	require.Equal(t, ua.StatusBadNodeIDUnknown, res[4].StatusCode)
	empty, err := c.ReadMulti(ctx, nil)
	require.NoError(t, err)
	require.Nil(t, empty)

	// WriteValues, WriteAttribute and WriteNodeValue
	sts, err := c.WriteValues(ctx,
		&ua.WriteValue{NodeID: f.Writable, AttributeID: ua.AttributeIDValue, Value: valueDV(int32(11))},
		&ua.WriteValue{NodeID: f.ReadOnly, AttributeID: ua.AttributeIDValue, Value: valueDV(int32(12))},
	)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sts[0])
	require.Equal(t, ua.StatusBadUserAccessDenied, sts[1])
	st, err := c.WriteAttribute(ctx, f.Writable, ua.AttributeIDValue, valueDV(int32(13)))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	dv, err := c.ReadValue(ctx, f.Writable)
	require.NoError(t, err)
	require.Equal(t, int32(13), dv.Value.Value())
	st, err = c.WriteNodeValue(ctx, f.Writable, struct{}{})
	require.ErrorIs(t, err, errors.ErrUnsupportedType)
	require.Equal(t, ua.StatusBad, st)

	// CallMethod rejects arguments that are no OPC UA values
	_, err = c.CallMethod(ctx, f.MethodObject, f.SquareMethod, struct{}{})
	require.ErrorContains(t, err, "call method arg 0")
	require.ErrorIs(t, err, errors.ErrUnsupportedType)

	// ServerStatus of the real server
	ss, err := c.ServerStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.ServerStateRunning, ss.State)

	// path helpers
	_, err = c.NodeFromPath(ctx, "Server.NoSuchNode")
	require.ErrorIs(t, err, ua.StatusBadNoMatch)
	_, err = c.NodeFromPathInNamespace(ctx, 0, "Server.NoSuchNode")
	require.ErrorIs(t, err, ua.StatusBadNoMatch)
	_, err = c.NodeFromQualifiedPath(ctx, "0:Server.0:NoSuchNode")
	require.ErrorIs(t, err, ua.StatusBadNoMatch)
	_, err = c.NodeFromQualifiedPath(ctx, "Server")
	require.ErrorContains(t, err, "missing namespace prefix")
	_, err = c.NodeFromQualifiedPath(ctx, "   ")
	require.ErrorContains(t, err, "qualified path is empty")
	_, err = c.NodeFromQualifiedPath(ctx, "0:")
	require.ErrorContains(t, err, "empty name")
	_, err = c.NodeFromQualifiedPath(ctx, "x:Server")
	require.ErrorContains(t, err, "namespace \"x\"")
	n, err := c.NodeFromQualifiedPath(ctx, " 0:Server . 0:ServerStatus ")
	require.NoError(t, err)
	require.Equal(t, ua.NewNumericNodeID(0, id.ServerServerStatus), n.ID)
}

// The history read wrappers send the right details to the server: the
// built-in historian answers raw reads; the other kinds are rejected per node.
func TestClientCovHistory(t *testing.T) {
	h := server.NewHistorian()
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	base := time.Date(2024, 1, 2, 3, 0, 0, 0, time.UTC)
	h.EnableNode(f.HistoryVar, 0)
	for i := range 5 {
		h.RecordValue(f.HistoryVar, &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: base.Add(time.Duration(i) * time.Second),
			ServerTimestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	srv.SetHistorian(h)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()
	start, end := base.Add(-time.Second), base.Add(time.Minute)

	dvs, err := c.ReadHistory(ctx, f.HistoryVar, start, end, 3)
	require.NoError(t, err)
	require.Len(t, dvs, 3)
	require.Equal(t, float64(0), dvs[0].Value.Value())

	var all []float64
	for dv, err := range c.ReadHistoryAll(ctx, f.HistoryVar, start, end) {
		require.NoError(t, err)
		all = append(all, dv.Value.Value().(float64))
	}
	require.Equal(t, []float64{0, 1, 2, 3, 4}, all)

	// a node without history
	_, err = c.ReadHistory(ctx, f.NoHistoryVar, start, end, 0)
	require.Error(t, err)
	var last error
	for _, err := range c.ReadHistoryAll(ctx, f.NoHistoryVar, start, end) {
		last = err
	}
	require.Error(t, last)
	require.Equal(t, err, last, "both report the status of the node")

	nodes := []*ua.HistoryReadValueID{{NodeID: f.HistoryVar}}
	resps := map[string]func() (*ua.HistoryReadResponse, error){
		"event": func() (*ua.HistoryReadResponse, error) {
			return c.HistoryReadEvent(ctx, nodes, &ua.ReadEventDetails{StartTime: start, EndTime: end, Filter: &ua.EventFilter{}})
		},
		"processed": func() (*ua.HistoryReadResponse, error) {
			return c.HistoryReadProcessed(ctx, nodes, &ua.ReadProcessedDetails{StartTime: start, EndTime: end, ProcessingInterval: 1000})
		},
		"at time": func() (*ua.HistoryReadResponse, error) {
			return c.HistoryReadAtTime(ctx, nodes, &ua.ReadAtTimeDetails{ReqTimes: []time.Time{base}})
		},
	}
	for name, read := range resps {
		t.Run(name, func(t *testing.T) {
			res, err := read()
			require.NoError(t, err)
			require.Len(t, res.Results, 1)
			require.NotEqual(t, ua.StatusCode(0xFFFFFFFF), res.Results[0].StatusCode)
		})
	}
}

// malformedServer starts a server whose Read, Write, Call, Browse and
// HistoryRead services answer as set up in the returned table: for each
// node id string the DataValue (Read), the per-node status list (Write) or
// HistoryReadResult (HistoryRead) to return.
type malformedServer struct {
	mu      sync.Mutex
	reads   map[string]*ua.DataValue
	history map[string]func(cp []byte) (*ua.HistoryReadResult, error)
	url     string
}

func (m *malformedServer) setRead(nodeID *ua.NodeID, dv *ua.DataValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads[nodeID.String()] = dv
}

func newMalformedServer(t *testing.T) *malformedServer {
	t.Helper()
	m := &malformedServer{
		reads:   map[string]*ua.DataValue{},
		history: map[string]func([]byte) (*ua.HistoryReadResult, error){},
	}
	read := func(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
		req := r.(*ua.ReadRequest)
		key := req.NodesToRead[0].NodeID.String()
		switch key {
		case "ns=1;s=wrong-response":
			return &ua.WriteResponse{ResponseHeader: okHeader(r)}, nil
		case "ns=1;s=two-results":
			return &ua.ReadResponse{ResponseHeader: okHeader(r), Results: []*ua.DataValue{valueDV(int32(1)), valueDV(int32(2))}}, nil
		}
		res := &ua.ReadResponse{ResponseHeader: okHeader(r)}
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, rv := range req.NodesToRead {
			dv, ok := m.reads[rv.NodeID.String()]
			if !ok {
				dv = &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadNodeIDUnknown}
			}
			res.Results = append(res.Results, dv)
		}
		return res, nil
	}
	write := respond(func(r ua.Request) ua.Response {
		return &ua.WriteResponse{ResponseHeader: okHeader(r), Results: []ua.StatusCode{ua.StatusOK, ua.StatusOK}}
	})
	call := respond(func(r ua.Request) ua.Response {
		return &ua.CallResponse{ResponseHeader: okHeader(r)}
	})
	history := func(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
		req := r.(*ua.HistoryReadRequest)
		m.mu.Lock()
		fn := m.history[req.NodesToRead[0].NodeID.String()]
		m.mu.Unlock()
		if fn == nil {
			return &ua.HistoryReadResponse{ResponseHeader: okHeader(r)}, nil
		}
		hr, err := fn(req.NodesToRead[0].ContinuationPoint)
		if err != nil {
			return nil, err
		}
		return &ua.HistoryReadResponse{ResponseHeader: okHeader(r), Results: []*ua.HistoryReadResult{hr}}, nil
	}
	_, m.url = newScriptedServer(t, map[uint16]server.Handler{
		id.ReadRequestEncodingDefaultBinary:        read,
		id.WriteRequestEncodingDefaultBinary:       write,
		id.CallRequestEncodingDefaultBinary:        call,
		id.HistoryReadRequestEncodingDefaultBinary: history,
		id.BrowseRequestEncodingDefaultBinary: browseHandler(func(*ua.BrowseDescription) *ua.BrowseResult {
			prop := func(name, nodeName string) *ua.ReferenceDescription {
				r := refTo(nodeName)
				r.BrowseName = &ua.QualifiedName{Name: name}
				r.NodeClass = ua.NodeClassVariable
				return r
			}
			return &ua.BrowseResult{References: []*ua.ReferenceDescription{
				prop("EngineeringUnits", "m-other"),
				prop("InputArguments", "m-in"),
				prop("OutputArguments", "m-out"),
			}}
		}),
	})
	return m
}

func historyData(values ...float64) *ua.ExtensionObject {
	hd := &ua.HistoryData{}
	for _, v := range values {
		hd.DataValues = append(hd.DataValues, valueDV(v))
	}
	return ua.NewExtensionObject(hd)
}

func argsValue(args ...any) *ua.DataValue {
	var eos []*ua.ExtensionObject
	for _, a := range args {
		eos = append(eos, ua.NewExtensionObject(a))
	}
	return valueDV(eos)
}

func TestClientCovMalformedResponses(t *testing.T) {
	ctx := context.Background()
	m := newMalformedServer(t)
	c := connectCovClient(t, m.url, opcua.SkipNamespaceUpdate())

	// a response of the wrong type
	_, err := c.ReadValue(ctx, ua.NewStringNodeID(1, "wrong-response"))
	require.ErrorIs(t, err, errors.ErrInvalidResponseType)
	var irt *opcua.InvalidResponseTypeError
	require.ErrorAs(t, err, &irt)
	require.Equal(t, "*ua.WriteResponse", irt.Got)
	require.Equal(t, "*ua.ReadResponse", irt.Want)
	require.Contains(t, irt.Error(), "got *ua.WriteResponse want *ua.ReadResponse")

	// too many results
	_, err = c.ReadValue(ctx, ua.NewStringNodeID(1, "two-results"))
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)
	_, err = c.WriteValue(ctx, ua.NewStringNodeID(1, "x"), valueDV(int32(1)))
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)
	_, err = c.WriteAttribute(ctx, ua.NewStringNodeID(1, "x"), ua.AttributeIDValue, valueDV(int32(1)))
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)
	// no result
	_, err = c.CallMethod(ctx, ua.NewStringNodeID(1, "o"), ua.NewStringNodeID(1, "m"))
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)

	// an extension object of a type the client does not know is reported as
	// such, a DataValue without a value keeps its status
	unknown := ua.NewStringNodeID(1, "eo-unknown")
	m.setRead(unknown, valueDV(&ua.ExtensionObject{
		TypeID:       ua.NewFourByteExpandedNodeID(1, 4711),
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        []byte{1, 2, 3},
	}))
	m.setRead(ua.NewStringNodeID(1, "no-value"), &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusUncertain})
	dvs, err := c.ReadValues(ctx, unknown, ua.NewStringNodeID(1, "no-value"))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadDataTypeIDUnknown, dvs[0].Status)
	require.Equal(t, ua.StatusUncertain, dvs[1].Status)
	require.Nil(t, dvs[1].Value.Value())

	// namespace array of the wrong type
	nsArray := ua.NewNumericNodeID(0, id.ServerNamespaceArray)
	m.setRead(nsArray, valueDV(int32(3)))
	_, err = c.NamespaceArray(ctx)
	require.ErrorIs(t, err, errors.ErrInvalidNamespaceType)
	require.ErrorIs(t, c.UpdateNamespaces(ctx), errors.ErrInvalidNamespaceType)
	_, err = c.FindNamespace(ctx, "x")
	require.ErrorIs(t, err, errors.ErrInvalidNamespaceType)
	_, err = c.NamespaceURI(ctx, 0)
	require.ErrorIs(t, err, errors.ErrInvalidNamespaceType)

	// server status of the wrong type
	status := ua.NewNumericNodeID(0, id.ServerServerStatus)
	m.setRead(status, valueDV("running"))
	_, err = c.ServerStatus(ctx)
	require.ErrorContains(t, err, "expected ExtensionObject, got string")
	m.setRead(status, valueDV(ua.NewExtensionObject(&ua.Argument{Name: "x"})))
	_, err = c.ServerStatus(ctx)
	require.ErrorContains(t, err, "expected *ServerStatusDataType, got *ua.Argument")
	m.setRead(status, valueDV(ua.NewExtensionObject(&ua.ServerStatusDataType{State: ua.ServerStateSuspended})))
	ss, err := c.ServerStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.ServerStateSuspended, ss.State)
}

func TestClientCovMethodArguments(t *testing.T) {
	ctx := context.Background()
	m := newMalformedServer(t)
	c := connectCovClient(t, m.url, opcua.SkipNamespaceUpdate())
	obj, meth := ua.NewStringNodeID(1, "o"), ua.NewStringNodeID(1, "m")
	in := &ua.Argument{Name: "in", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1, Description: ua.NewLocalizedText("")}
	out := &ua.Argument{Name: "out", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1, Description: ua.NewLocalizedText("")}
	m.setRead(ua.NewStringNodeID(1, "m-in"), argsValue(in))

	// properties other than the argument lists are not read
	m.setRead(ua.NewStringNodeID(1, "m-out"), argsValue(out))
	inputs, outputs, err := c.MethodArguments(ctx, obj, meth)
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	require.Equal(t, "in", inputs[0].Name)
	require.Len(t, outputs, 1)
	require.Equal(t, "out", outputs[0].Name)

	// an argument list without a value means no arguments
	m.setRead(ua.NewStringNodeID(1, "m-out"), valueDV(nil))
	inputs, outputs, err = c.MethodArguments(ctx, obj, meth)
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	require.Nil(t, outputs)

	m.setRead(ua.NewStringNodeID(1, "m-out"), &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadUserAccessDenied})
	_, _, err = c.MethodArguments(ctx, obj, meth)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	require.ErrorContains(t, err, "read OutputArguments")

	m.setRead(ua.NewStringNodeID(1, "m-out"), valueDV("not a list"))
	_, _, err = c.MethodArguments(ctx, obj, meth)
	require.ErrorContains(t, err, "decode OutputArguments")
	require.ErrorContains(t, err, "expected []*ExtensionObject, got string")

	m.setRead(ua.NewStringNodeID(1, "m-out"), argsValue(&ua.ServerStatusDataType{}))
	_, _, err = c.MethodArguments(ctx, obj, meth)
	require.ErrorContains(t, err, "expected *Argument, got *ua.ServerStatusDataType")
}

func TestClientCovHistoryMalformed(t *testing.T) {
	ctx := context.Background()
	m := newMalformedServer(t)
	c := connectCovClient(t, m.url, opcua.SkipNamespaceUpdate())
	now := time.Now()
	start := now.Add(-time.Hour)

	set := func(name string, fn func(cp []byte) (*ua.HistoryReadResult, error)) *ua.NodeID {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.history["ns=1;s="+name] = fn
		return ua.NewStringNodeID(1, name)
	}
	readAll := func(n *ua.NodeID, stopAfter int) ([]float64, error) {
		var got []float64
		for dv, err := range c.ReadHistoryAll(ctx, n, start, now) {
			if err != nil {
				return got, err
			}
			got = append(got, dv.Value.Value().(float64))
			if len(got) == stopAfter {
				break
			}
		}
		return got, nil
	}

	// paged: values 1, 2 and a continuation point, then 3
	paged := set("paged", func(cp []byte) (*ua.HistoryReadResult, error) {
		if len(cp) == 0 {
			return &ua.HistoryReadResult{StatusCode: ua.StatusOK, ContinuationPoint: []byte("p2"), HistoryData: historyData(1, 2)}, nil
		}
		return &ua.HistoryReadResult{StatusCode: ua.StatusOK, HistoryData: historyData(3)}, nil
	})
	dvs, err := c.ReadHistory(ctx, paged, start, now, 0)
	require.NoError(t, err)
	require.Len(t, dvs, 2, "ReadHistory returns the first page")
	got, err := readAll(paged, 0)
	require.NoError(t, err)
	require.Equal(t, []float64{1, 2, 3}, got)
	got, err = readAll(paged, 1)
	require.NoError(t, err)
	require.Equal(t, []float64{1}, got, "stopping early stops the iteration")

	// the second page fails
	pageFault := set("page-fault", func(cp []byte) (*ua.HistoryReadResult, error) {
		if len(cp) == 0 {
			return &ua.HistoryReadResult{StatusCode: ua.StatusOK, ContinuationPoint: []byte("p2"), HistoryData: historyData(1)}, nil
		}
		return nil, ua.StatusBadContinuationPointInvalid
	})
	got, err = readAll(pageFault, 0)
	require.ErrorIs(t, err, ua.StatusBadContinuationPointInvalid)
	require.Equal(t, []float64{1}, got)

	// no result
	none := ua.NewStringNodeID(1, "none")
	_, err = c.ReadHistory(ctx, none, start, now, 0)
	require.ErrorIs(t, err, ua.StatusBadUnexpectedError)
	_, err = readAll(none, 0)
	require.ErrorIs(t, err, ua.StatusBadUnexpectedError)

	// bad status of the node
	bad := set("bad", func([]byte) (*ua.HistoryReadResult, error) {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	})
	_, err = c.ReadHistory(ctx, bad, start, now, 0)
	require.ErrorIs(t, err, ua.StatusBadHistoryOperationUnsupported)
	_, err = readAll(bad, 0)
	require.ErrorIs(t, err, ua.StatusBadHistoryOperationUnsupported)

	// history of the wrong kind
	wrong := set("wrong", func([]byte) (*ua.HistoryReadResult, error) {
		return &ua.HistoryReadResult{StatusCode: ua.StatusOK, HistoryData: ua.NewExtensionObject(&ua.HistoryEvent{})}, nil
	})
	_, err = c.ReadHistory(ctx, wrong, start, now, 0)
	require.ErrorContains(t, err, "expected *HistoryData, got *ua.HistoryEvent")
	_, err = readAll(wrong, 0)
	require.ErrorContains(t, err, "expected *HistoryData, got *ua.HistoryEvent")

	// the service fails
	failing := set("fail", func([]byte) (*ua.HistoryReadResult, error) {
		return nil, ua.StatusBadHistoryOperationInvalid
	})
	_, err = c.ReadHistory(ctx, failing, start, now, 0)
	require.ErrorIs(t, err, ua.StatusBadHistoryOperationInvalid)
}
