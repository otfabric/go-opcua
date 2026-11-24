// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/otfabric/go-opcua/ua"
)

// TestCMFileArguments: the Methods of ConnectionManagerConfiguration check
// their InputArguments (OPC 10000-20 §4.2) before they touch a handle.
func TestCMFileArguments(t *testing.T) {
	ctx := context.Background()
	f := &cmFile{handles: map[uint32]*fileHandle{}}
	c := &ConnectionManager{}
	v := ua.MustVariant
	h := v(uint32(1))
	type m = func(context.Context, []*ua.Variant) ([]*ua.Variant, ua.StatusCode)
	for _, tc := range []struct {
		name string
		m    m
		args []*ua.Variant
		want ua.StatusCode
	}{
		{"Open args", f.open(c), nil, ua.StatusBadArgumentsMissing},
		{"Open mode", f.open(c), []*ua.Variant{v("x")}, ua.StatusBadTypeMismatch},
		{"Close args", f.close, nil, ua.StatusBadArgumentsMissing},
		{"Close handle type", f.close, []*ua.Variant{v("x")}, ua.StatusBadTypeMismatch},
		{"Close unknown", f.close, []*ua.Variant{h}, ua.StatusBadInvalidArgument},
		{"Read args", f.read, nil, ua.StatusBadArgumentsMissing},
		{"Read length", f.read, []*ua.Variant{h, v("x")}, ua.StatusBadTypeMismatch},
		{"Read unknown", f.read, []*ua.Variant{h, v(int32(1))}, ua.StatusBadInvalidArgument},
		{"Write args", f.writeData, nil, ua.StatusBadArgumentsMissing},
		{"Write data", f.writeData, []*ua.Variant{h, v("x")}, ua.StatusBadTypeMismatch},
		{"Write unknown", f.writeData, []*ua.Variant{h, v([]byte{1})}, ua.StatusBadInvalidArgument},
		{"GetPosition args", f.getPosition, nil, ua.StatusBadArgumentsMissing},
		{"GetPosition unknown", f.getPosition, []*ua.Variant{h}, ua.StatusBadInvalidArgument},
		{"SetPosition args", f.setPosition, nil, ua.StatusBadArgumentsMissing},
		{"SetPosition position", f.setPosition, []*ua.Variant{h, v("x")}, ua.StatusBadTypeMismatch},
		{"SetPosition unknown", f.setPosition, []*ua.Variant{h, v(uint64(0))}, ua.StatusBadInvalidArgument},
		{"CloseAndUpdate args", f.closeAndUpdate(c), nil, ua.StatusBadArgumentsMissing},
		{"CloseAndUpdate require", f.closeAndUpdate(c), []*ua.Variant{h, v("x"), v([]byte{})}, ua.StatusBadTypeMismatch},
		{"CloseAndUpdate ops", f.closeAndUpdate(c), []*ua.Variant{h, v(true), v("x")}, ua.StatusBadTypeMismatch},
		{"CloseAndUpdate unknown", f.closeAndUpdate(c), []*ua.Variant{h, v(true), {}}, ua.StatusBadInvalidArgument},
	} {
		_, sc := tc.m(ctx, tc.args)
		assert.Equal(t, tc.want, sc, tc.name)
	}

	// A write past the bound of the file, a read with a negative length, a
	// write that grows the file from a position, a bad file body.
	f.handles[1] = &fileHandle{write: true}
	_, sc := f.writeData(ctx, []*ua.Variant{h, v(make([]byte, maxFileSize+1))})
	assert.Equal(t, ua.StatusBadOutOfRange, sc)
	_, sc = f.writeData(ctx, []*ua.Variant{h, v([]byte{1, 2, 3})})
	assert.Equal(t, ua.StatusGood, sc)
	_, sc = f.setPosition(ctx, []*ua.Variant{h, v(uint64(99))})
	assert.Equal(t, ua.StatusGood, sc)
	out, _ := f.getPosition(ctx, []*ua.Variant{h})
	assert.Equal(t, uint64(3), out[0].Value(), "SetPosition stops at the end")
	_, sc = f.writeData(ctx, []*ua.Variant{h, {}})
	assert.Equal(t, ua.StatusGood, sc, "a null ByteString writes nothing")
	_, sc = f.closeAndUpdate(c)(ctx, []*ua.Variant{h, v(true), v([]byte{})})
	assert.Equal(t, ua.StatusBadTypeMismatch, sc, "not a file body")
	f.handles[2] = &fileHandle{}
	_, sc = f.read(ctx, []*ua.Variant{v(uint32(2)), v(int32(-1))})
	assert.Equal(t, ua.StatusBadInvalidState, sc)
}
