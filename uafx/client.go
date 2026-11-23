// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// ErrCall reports that a call of EstablishConnections or CloseConnections
// failed: the server has no UAFX namespaces, the AutomationComponent no such
// Method, or the call returned a Bad status or a result that does not
// decode. A Bad status of the call is in the chain: errors.As with a
// ua.StatusCode finds it.
var ErrCall = errors.New("uafx: call")

// methodClient is what the calls use of an opcua.Client.
type methodClient interface {
	NamespaceArray(ctx context.Context) ([]string, error)
	Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error)
	Call(ctx context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error)
}

var _ methodClient = (*opcua.Client)(nil)

// EstablishConnections calls the EstablishConnections Method of the
// AutomationComponent ac (Part 81 §6.2.4). It resolves the index of the UAFX
// Data namespace from the NamespaceArray of the server. A call the server
// aborted returns a result with Status Uncertain and the per-command results
// that tell what failed (§6.2.4.3.11); a Bad status of the call (Table 9) is
// an error.
func EstablishConnections(ctx context.Context, c *opcua.Client, ac *ua.NodeID, req *EstablishConnectionsRequest) (*EstablishConnectionsResult, error) {
	return establishConnections(ctx, c, ac, req)
}

func establishConnections(ctx context.Context, c methodClient, ac *ua.NodeID, req *EstablishConnectionsRequest) (*EstablishConnectionsResult, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: no request", ErrCall)
	}
	data, method, err := resolveMethod(ctx, c, ac, "EstablishConnections")
	if err != nil {
		return nil, err
	}
	args, err := EncodeEstablishConnectionsRequest(req, data)
	if err != nil {
		return nil, err
	}
	res, err := call(ctx, c, ac, method, args)
	if err != nil {
		return nil, err
	}
	out, err := DecodeEstablishConnectionsResult(res.OutputArguments, data)
	if err != nil {
		return nil, fmt.Errorf("%w: EstablishConnections: %w", ErrCall, err)
	}
	out.Status = res.StatusCode
	return out, nil
}

// CloseConnections calls the CloseConnections Method of the
// AutomationComponent ac (Part 81 §6.2.5) for the ConnectionEndpoints
// endpoints, with remove to remove what EstablishConnections created for
// them. It returns the status of the call, Good or Uncertain (Table 23),
// and one result per endpoint (Table 24).
func CloseConnections(ctx context.Context, c *opcua.Client, ac *ua.NodeID, endpoints []*ua.NodeID, remove bool) (ua.StatusCode, []ua.StatusCode, error) {
	return closeConnections(ctx, c, ac, endpoints, remove)
}

func closeConnections(ctx context.Context, c methodClient, ac *ua.NodeID, endpoints []*ua.NodeID, remove bool) (ua.StatusCode, []ua.StatusCode, error) {
	_, method, err := resolveMethod(ctx, c, ac, "CloseConnections")
	if err != nil {
		return 0, nil, err
	}
	if endpoints == nil {
		endpoints = []*ua.NodeID{}
	}
	res, err := call(ctx, c, ac, method, []*ua.Variant{ua.MustVariant(endpoints), ua.MustVariant(remove)})
	if err != nil {
		return 0, nil, err
	}
	if len(res.OutputArguments) != 1 || res.OutputArguments[0] == nil {
		return 0, nil, fmt.Errorf("%w: CloseConnections: %d output arguments", ErrCall, len(res.OutputArguments))
	}
	var results []ua.StatusCode
	switch v := res.OutputArguments[0].Value().(type) {
	case []ua.StatusCode:
		results = v
	case nil:
	default:
		return 0, nil, fmt.Errorf("%w: CloseConnections: Results is %T", ErrCall, v)
	}
	if len(results) != len(endpoints) {
		return 0, nil, fmt.Errorf("%w: CloseConnections: %d results for %d endpoints", ErrCall, len(results), len(endpoints))
	}
	return res.StatusCode, results, nil
}

// resolveMethod returns the index of the UAFX Data namespace and the
// Method name (in the AC namespace) of ac.
func resolveMethod(ctx context.Context, c methodClient, ac *ua.NodeID, name string) (uint16, *ua.NodeID, error) {
	if ac == nil {
		return 0, nil, fmt.Errorf("%w: no AutomationComponent", ErrCall)
	}
	nsa, err := c.NamespaceArray(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: NamespaceArray: %w", ErrCall, err)
	}
	data, acNS := -1, -1
	for i, u := range nsa {
		switch u {
		case fxdataid.NamespaceURI:
			data = i
		case fxacid.NamespaceURI:
			acNS = i
		}
	}
	if data < 0 || acNS < 0 || data > 0xffff || acNS > 0xffff {
		return 0, nil, fmt.Errorf("%w: the server has no UAFX Data and AC namespaces", ErrCall)
	}
	res, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID: ac, BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent), IncludeSubtypes: true,
			NodeClassMask: uint32(ua.NodeClassMethod), ResultMask: uint32(ua.BrowseResultMaskBrowseName),
		}},
	})
	if err != nil {
		return 0, nil, fmt.Errorf("%w: Browse: %w", ErrCall, err)
	}
	if len(res.Results) != 1 || res.Results[0] == nil {
		return 0, nil, fmt.Errorf("%w: Browse: %d results", ErrCall, len(res.Results))
	}
	if sc := res.Results[0].StatusCode; sc != ua.StatusOK {
		return 0, nil, fmt.Errorf("%w: Browse of %v: %w", ErrCall, ac, sc)
	}
	for _, r := range res.Results[0].References {
		if r != nil && r.BrowseName != nil && r.BrowseName.Name == name && int(r.BrowseName.NamespaceIndex) == acNS &&
			r.NodeID != nil && r.NodeID.NodeID != nil && r.NodeID.NamespaceURI == "" && r.NodeID.ServerIndex == 0 {
			return uint16(data), r.NodeID.NodeID, nil
		}
	}
	return 0, nil, fmt.Errorf("%w: %v has no %s Method", ErrCall, ac, name)
}

// call calls method on obj and returns its result unless its status is Bad.
func call(ctx context.Context, c methodClient, obj, method *ua.NodeID, args []*ua.Variant) (*ua.CallMethodResult, error) {
	res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: obj, MethodID: method, InputArguments: args})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCall, err)
	}
	if res == nil {
		return nil, fmt.Errorf("%w: no result", ErrCall)
	}
	if res.StatusCode.Uint32()&0x80000000 != 0 {
		return nil, fmt.Errorf("%w: %w", ErrCall, res.StatusCode)
	}
	return res, nil
}
