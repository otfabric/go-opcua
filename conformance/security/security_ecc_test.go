// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// eccMatrixValue hands every TestECC_PolicyModeMatrix subtest a distinct value.
var eccMatrixValue atomic.Int32

// TestECC_PolicyModeMatrix connects with every ECC security policy in both
// Sign and SignAndEncrypt mode and performs signed/encrypted reads, writes, a
// multi-chunk read, a method call and a subscription over the channel.
func TestECC_PolicyModeMatrix(t *testing.T) {
	f, url := mixedServer(t)
	ctx := context.Background()

	for _, pol := range eccPolicies {
		for _, mode := range secureModes {
			t.Run(shortPolicy(pol.uri)+"/"+mode.String(), func(t *testing.T) {
				ep := endpointFor(t, url, pol.uri, mode)
				require.Equal(t, pki(t).ecc.server[pol.curve].cert, ep.ServerCertificate,
					"an ECC endpoint advertises the ECC certificate of its curve")
				require.Equal(t, serverAppURI, ep.Server.ApplicationURI)

				c := newClient(t, url, eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous)...)
				require.Equal(t, pol.uri, c.SecurityPolicy())
				require.Equal(t, mode, c.SecurityMode())

				want := "ecc-" + shortPolicy(pol.uri) + "-" + mode.String()
				st, err := c.WriteNodeValue(ctx, f.String, want)
				require.NoError(t, err)
				require.Equal(t, ua.StatusOK, st)

				dv, err := c.ReadValue(ctx, f.String)
				require.NoError(t, err)
				require.Equal(t, want, dv.Value.Value())

				// A request large enough to span several secured chunks in both
				// directions.
				ids := make([]*ua.NodeID, 600)
				for i := range ids {
					ids[i] = f.Int32Array
				}
				dvs, err := c.ReadValues(ctx, ids...)
				require.NoError(t, err)
				require.Len(t, dvs, len(ids))
				for _, dv := range dvs {
					require.Equal(t, []int32{1, 2, 3, 4, 5}, dv.Value.Value())
				}

				res, err := c.CallMethod(ctx, f.MethodObject, f.SquareMethod, int32(12))
				require.NoError(t, err)
				require.Equal(t, ua.StatusOK, res.StatusCode)
				require.Equal(t, int32(144), res.OutputArguments[0].Value())

				// The asynchronous Publish path.
				sub, ch, err := c.NewSubscription().
					Interval(fastInterval).
					Monitor(f.Writable).
					Start(ctx)
				require.NoError(t, err)
				t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
				nextDataChanges(t, ch) // initial value
				// The subtests share one server: each must write a value the
				// previous one did not leave behind, or nothing changes.
				changed := 4242 + eccMatrixValue.Add(1)
				writeInt32(t, c, f.Writable, changed)
				awaitInt32Change(t, ch, changed)
			})
		}
	}
}

// awaitInt32Change waits until the subscription behind ch reports want.
func awaitInt32Change(t *testing.T, ch <-chan *opcua.PublishNotificationData, want int32) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		for _, dc := range nextDataChanges(t, ch) {
			if dc.DV != nil && dc.DV.Value != nil && dc.DV.Value.Value() == want {
				return
			}
		}
	}
	t.Fatalf("no data change with value %d", want)
}
