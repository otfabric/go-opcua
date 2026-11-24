// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"fmt"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// EditConnectionConfigurationSets calls EditConnectionConfigurationSets of
// the ConnectionManager of the server (Part 81 §6.7.4, §12.3) with action
// for the ConnectionConfigurationSet Objects sets. It returns the status of
// the call, Good, Uncertain or Bad_UserAccessDenied (Table 81), and one
// result per set (Table 82).
func EditConnectionConfigurationSets(ctx context.Context, c *opcua.Client, action FxEdit, sets []*ua.NodeID) (ua.StatusCode, []ua.StatusCode, error) {
	return cmCall(ctx, c, "EditConnectionConfigurationSets", fxcmid.FxRootConnectionManagerEditConnectionConfigurationSets, int32(action), sets)
}

// ProcessConnectionConfigurationSets calls ProcessConnectionConfigurationSets
// of the ConnectionManager of the server (Part 81 §6.7.5, §12.3) with
// action for the ConnectionConfigurationSet Objects sets. The Method
// returns once the processing started; the ConnectionConfigurationSet
// events (§8.7 to §8.9) and the state machines of the sets tell the
// outcome. It returns the status of the call (Table 85) and one result per
// set (Table 86).
func ProcessConnectionConfigurationSets(ctx context.Context, c *opcua.Client, action FxProcess, sets []*ua.NodeID) (ua.StatusCode, []ua.StatusCode, error) {
	return cmCall(ctx, c, "ProcessConnectionConfigurationSets", fxcmid.FxRootConnectionManagerProcessConnectionConfigurationSets, int32(action), sets)
}

// ConnectionManagerNode returns the NodeId of FxRoot.ConnectionManager
// (Part 81 §12.3) on the server.
func ConnectionManagerNode(ctx context.Context, c *opcua.Client) (*ua.NodeID, error) {
	ns, err := cmNamespace(ctx, c)
	if err != nil {
		return nil, err
	}
	return ua.NewNumericNodeID(ns, fxcmid.FxRootConnectionManager), nil
}

func cmNamespace(ctx context.Context, c methodClient) (uint16, error) {
	nsa, err := c.NamespaceArray(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: NamespaceArray: %w", ErrCall, err)
	}
	for i, u := range nsa {
		if u == fxcmid.NamespaceURI && i <= 0xffff {
			return uint16(i), nil
		}
	}
	return 0, fmt.Errorf("%w: the server has no UAFX CM namespace", ErrCall)
}

func cmCall(ctx context.Context, c methodClient, name string, method uint32, action int32, sets []*ua.NodeID) (ua.StatusCode, []ua.StatusCode, error) {
	ns, err := cmNamespace(ctx, c)
	if err != nil {
		return 0, nil, err
	}
	if sets == nil {
		sets = []*ua.NodeID{}
	}
	res, err := call(ctx, c, ua.NewNumericNodeID(ns, fxcmid.FxRootConnectionManager), ua.NewNumericNodeID(ns, method),
		[]*ua.Variant{ua.MustVariant(action), ua.MustVariant(sets)})
	if err != nil {
		return 0, nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(res.OutputArguments) != 1 || res.OutputArguments[0] == nil {
		return 0, nil, fmt.Errorf("%w: %s: %d output arguments", ErrCall, name, len(res.OutputArguments))
	}
	var results []ua.StatusCode
	switch v := res.OutputArguments[0].Value().(type) {
	case []ua.StatusCode:
		results = v
	case nil:
	default:
		return 0, nil, fmt.Errorf("%w: %s: Results is %T", ErrCall, name, v)
	}
	if len(results) != len(sets) {
		return 0, nil, fmt.Errorf("%w: %s: %d results for %d sets", ErrCall, name, len(results), len(sets))
	}
	return res.StatusCode, results, nil
}
