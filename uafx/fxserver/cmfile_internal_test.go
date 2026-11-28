// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestCMFileArguments: CloseAndUpdate of ConnectionManagerConfiguration
// checks its InputArguments (F.3.3, Table F.39) before it touches a handle;
// the Methods of FileType are those of server.FileObject, whose arguments
// are checked against the declarations of namespace 0.
func TestCMFileArguments(t *testing.T) {
	ctx := context.Background()
	srv, err := server.New(server.EndPoint("localhost", 0), server.InsecureNoSecurity())
	require.NoError(t, err)
	file, err := srv.NewFile(server.FileConfig{Backend: server.NewMemoryFile(nil)})
	require.NoError(t, err)
	f := &cmFile{id: ua.NewStringNodeID(1, "cm.File"), file: file}
	c := &ConnectionManager{opts: ConnectionManagerOptions{Authorizer: func(context.Context, CMRequest) ua.StatusCode { return ua.StatusOK }}}
	v := ua.MustVariant
	h := v(uint32(1))
	for _, tc := range []struct {
		name string
		args []*ua.Variant
		want ua.StatusCode
	}{
		{"args", nil, ua.StatusBadArgumentsMissing},
		{"require", []*ua.Variant{h, v("x"), v([]byte{})}, ua.StatusBadTypeMismatch},
		{"ops", []*ua.Variant{h, v(true), v("x")}, ua.StatusBadTypeMismatch},
		{"handle type", []*ua.Variant{v("x"), v(true), {}}, ua.StatusBadTypeMismatch},
		{"unknown", []*ua.Variant{h, v(true), {}}, ua.StatusBadInvalidArgument},
		{"ByteString ops", []*ua.Variant{h, v(true), v([]byte{1})}, ua.StatusBadInvalidArgument},
	} {
		_, sc := f.closeAndUpdate(c)(ctx, tc.args)
		assert.Equal(t, tc.want, sc, tc.name)
	}
	_, sc := f.method("Open")(ctx, []*ua.Variant{v(uint8(1))})
	assert.Equal(t, ua.StatusBadSessionIDInvalid, sc, "a call without a session")
}
