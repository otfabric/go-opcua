// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// TestCMCall: the ConnectionManager Methods are called on FxRoot's
// ConnectionManager of the CM namespace (§12.3) and their results checked.
func TestCMCall(t *testing.T) {
	ctx := context.Background()
	set := ua.NewStringNodeID(3, "set")
	f := &fakeMethods{nsa: []string{"http://opcfoundation.org/UA/", "urn:x", fxcmid.NamespaceURI},
		call: &ua.CallMethodResult{StatusCode: ua.StatusUncertain, OutputArguments: []*ua.Variant{ua.MustVariant([]ua.StatusCode{ua.StatusBadInvalidState})}}}
	sc, rs, err := cmCall(ctx, f, "Edit", fxcmid.FxRootConnectionManagerEditConnectionConfigurationSets, int32(StartEditing), []*ua.NodeID{set})
	require.NoError(t, err)
	assert.Equal(t, ua.StatusUncertain, sc)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadInvalidState}, rs)
	assert.Equal(t, ua.NewNumericNodeID(2, fxcmid.FxRootConnectionManager).String(), f.req.ObjectID.String())
	assert.Equal(t, ua.NewNumericNodeID(2, fxcmid.FxRootConnectionManagerEditConnectionConfigurationSets).String(), f.req.MethodID.String())

	for _, tc := range []struct {
		name string
		f    *fakeMethods
		sets []*ua.NodeID
	}{
		{"no namespace", &fakeMethods{nsa: []string{"x"}}, nil},
		{"NamespaceArray", &fakeMethods{nsaErr: errFake}, nil},
		{"call", &fakeMethods{nsa: f.nsa, callErr: errFake}, nil},
		{"outputs", &fakeMethods{nsa: f.nsa, call: &ua.CallMethodResult{}}, nil},
		{"type", &fakeMethods{nsa: f.nsa, call: &ua.CallMethodResult{OutputArguments: []*ua.Variant{ua.MustVariant("x")}}}, nil},
		{"length", &fakeMethods{nsa: f.nsa, call: &ua.CallMethodResult{OutputArguments: []*ua.Variant{ua.MustVariant([]ua.StatusCode{})}}}, []*ua.NodeID{set}},
	} {
		_, _, err := cmCall(ctx, tc.f, "Process", fxcmid.FxRootConnectionManagerProcessConnectionConfigurationSets, 0, tc.sets)
		assert.ErrorIs(t, err, ErrCall, tc.name)
	}
	// A null Results with no sets is no result for no set.
	_, rs, err = cmCall(ctx, &fakeMethods{nsa: f.nsa, call: &ua.CallMethodResult{OutputArguments: []*ua.Variant{{}}}}, "Process", 1, 0, nil)
	require.NoError(t, err)
	assert.Empty(t, rs)
}
