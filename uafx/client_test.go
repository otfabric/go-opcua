// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// fakeMethods answers the calls of the client API.
type fakeMethods struct {
	nsa       []string
	nsaErr    error
	browse    *ua.BrowseResponse
	browseErr error
	call      *ua.CallMethodResult
	callErr   error
	req       *ua.CallMethodRequest
}

func (f *fakeMethods) NamespaceArray(context.Context) ([]string, error) { return f.nsa, f.nsaErr }

func (f *fakeMethods) Browse(context.Context, *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	return f.browse, f.browseErr
}

func (f *fakeMethods) Call(_ context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	f.req = req
	return f.call, f.callErr
}

var (
	fakeAC     = ua.NewNumericNodeID(5, 1000)
	fakeMethod = ua.NewNumericNodeID(5, 1006)
	errFake    = errors.New("fake")
)

// newFake returns a server with Data at testData, AC at 3 and the Method
// name on fakeAC.
func newFake(name string) *fakeMethods {
	nsa := make([]string, testData+1)
	nsa[3], nsa[testData] = fxacid.NamespaceURI, fxdataid.NamespaceURI
	return &fakeMethods{nsa: nsa, browse: &ua.BrowseResponse{Results: []*ua.BrowseResult{{References: []*ua.ReferenceDescription{
		{BrowseName: &ua.QualifiedName{NamespaceIndex: 3, Name: "Other"}, NodeID: ua.NewExpandedNodeID(ua.NewNumericNodeID(5, 1), "", 0)},
		{BrowseName: &ua.QualifiedName{NamespaceIndex: 1, Name: name}, NodeID: ua.NewExpandedNodeID(ua.NewNumericNodeID(5, 2), "", 0)},
		{BrowseName: &ua.QualifiedName{NamespaceIndex: 3, Name: name}, NodeID: ua.NewExpandedNodeID(fakeMethod, "", 0)},
	}}}}}
}

func TestClientEstablish(t *testing.T) {
	ctx := context.Background()
	f := newFake("EstablishConnections")
	out, err := EncodeEstablishConnectionsResult(fullResult(), testData)
	require.NoError(t, err)
	f.call = &ua.CallMethodResult{StatusCode: ua.StatusUncertain, OutputArguments: wire(t, out)}
	res, err := establishConnections(ctx, f, fakeAC, fullRequest())
	require.NoError(t, err)
	assert.Equal(t, ua.StatusUncertain, res.Status)
	assert.Equal(t, fakeMethod, f.req.MethodID)
	assert.Equal(t, fakeAC, f.req.ObjectID)
	assert.Len(t, f.req.InputArguments, 5)

	f.call.OutputArguments = f.call.OutputArguments[:2]
	_, err = establishConnections(ctx, f, fakeAC, fullRequest())
	assert.ErrorIs(t, err, ErrCall)
	_, err = establishConnections(ctx, f, fakeAC, nil)
	assert.ErrorIs(t, err, ErrCall)
	_, err = establishConnections(ctx, f, fakeAC, &EstablishConnectionsRequest{ConnectionEndpointConfigurations: []*ConnectionEndpointConfiguration{nil}})
	assert.ErrorIs(t, err, ErrCodec)
}

func TestClientClose(t *testing.T) {
	ctx := context.Background()
	f := newFake("CloseConnections")
	f.call = &ua.CallMethodResult{StatusCode: ua.StatusUncertain, OutputArguments: []*ua.Variant{ua.MustVariant([]ua.StatusCode{ua.StatusBadNodeIDUnknown})}}
	sc, res, err := closeConnections(ctx, f, fakeAC, []*ua.NodeID{fakeAC}, true)
	require.NoError(t, err)
	assert.Equal(t, ua.StatusUncertain, sc)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadNodeIDUnknown}, res)
	assert.Equal(t, []*ua.NodeID{fakeAC}, f.req.InputArguments[0].Value())
	assert.Equal(t, true, f.req.InputArguments[1].Value())

	for name, out := range map[string][]*ua.Variant{
		"none":   nil,
		"nil":    {nil},
		"type":   {ua.MustVariant("x")},
		"length": {ua.MustVariant([]ua.StatusCode{})},
	} {
		f.call.OutputArguments = out
		_, _, err := closeConnections(ctx, f, fakeAC, []*ua.NodeID{fakeAC}, false)
		assert.ErrorIs(t, err, ErrCall, name)
	}
	f.call.OutputArguments = []*ua.Variant{ua.MustVariant([]ua.StatusCode(nil))}
	sc, res, err = closeConnections(ctx, f, fakeAC, nil, false)
	require.NoError(t, err)
	assert.Equal(t, ua.StatusUncertain, sc)
	assert.Empty(t, res)
	assert.Equal(t, []*ua.NodeID{}, f.req.InputArguments[0].Value())
}

// TestClientErrors: the calls fail with ErrCall, and with the status of a
// Bad call in the chain.
func TestClientErrors(t *testing.T) {
	ctx := context.Background()
	for name, mod := range map[string]func(f *fakeMethods){
		"namespace array": func(f *fakeMethods) { f.nsaErr = errFake },
		"no namespaces":   func(f *fakeMethods) { f.nsa = []string{"x"} },
		"browse":          func(f *fakeMethods) { f.browseErr = errFake },
		"browse results":  func(f *fakeMethods) { f.browse = &ua.BrowseResponse{} },
		"browse status":   func(f *fakeMethods) { f.browse.Results[0].StatusCode = ua.StatusBadNodeIDUnknown },
		"no method":       func(f *fakeMethods) { f.browse.Results[0].References = nil },
		"call":            func(f *fakeMethods) { f.callErr = errFake },
		"no result":       func(f *fakeMethods) { f.call = nil },
		"bad call": func(f *fakeMethods) {
			f.call = &ua.CallMethodResult{StatusCode: ua.StatusBadInvalidArgument}
		},
	} {
		f := newFake("CloseConnections")
		f.call = &ua.CallMethodResult{OutputArguments: []*ua.Variant{ua.MustVariant([]ua.StatusCode{})}}
		mod(f)
		_, _, err := closeConnections(ctx, f, fakeAC, nil, false)
		require.ErrorIs(t, err, ErrCall, name)
		if name == "bad call" {
			var sc ua.StatusCode
			require.True(t, errors.As(err, &sc))
			assert.Equal(t, ua.StatusBadInvalidArgument, sc)
		}
	}
	_, _, err := closeConnections(ctx, newFake("CloseConnections"), nil, nil, false)
	assert.ErrorIs(t, err, ErrCall)
	_, err = establishConnections(ctx, &fakeMethods{nsaErr: errFake}, fakeAC, fullRequest())
	assert.ErrorIs(t, err, ErrCall)
}

// argsWire is the binary encoding of the arguments of a call, as they come
// over the wire.
type argsWire struct{ Args []*ua.Variant }

// FuzzDecodeEstablishConnections feeds arbitrary arguments to the decoders
// of the arguments a server receives (the request) and a client receives
// (the result): they return an error or a value that encodes again.
func FuzzDecodeEstablishConnections(f *testing.F) {
	in, err := EncodeEstablishConnectionsRequest(fullRequest(), testData)
	if err != nil {
		f.Fatal(err)
	}
	out, err := EncodeEstablishConnectionsResult(fullResult(), testData)
	if err != nil {
		f.Fatal(err)
	}
	for _, args := range [][]*ua.Variant{in, out, {}} {
		b, err := ua.Encode(&argsWire{Args: args})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var w argsWire
		if _, err := ua.Decode(b, &w); err != nil {
			return
		}
		if r, err := DecodeEstablishConnectionsRequest(w.Args, testData); err == nil {
			if _, err := EncodeEstablishConnectionsRequest(r, testData); err != nil {
				t.Fatalf("a decoded request does not encode: %v", err)
			}
		}
		if r, err := DecodeEstablishConnectionsResult(w.Args, testData); err == nil {
			if _, err := EncodeEstablishConnectionsResult(r, testData); err != nil {
				t.Fatalf("a decoded result does not encode: %v", err)
			}
		}
	})
}
