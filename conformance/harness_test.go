// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
)

// setup stands up a server with the rich fixture and a connected client. All
// resources are torn down via t.Cleanup.
func setup(t *testing.T) (*opcua.Client, *testutil.Fixture, context.Context) {
	t.Helper()
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	return c, f, context.Background()
}
