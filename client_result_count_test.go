// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// countServer starts a server whose Read and Write handlers answer with the
// number of results results returns for the number of operations of the
// request, and returns a connected client.
func countServer(t *testing.T, results func(ops int) int) *opcua.Client {
	t.Helper()
	read := respond(func(r ua.Request) ua.Response {
		req := r.(*ua.ReadRequest)
		res := &ua.ReadResponse{ResponseHeader: okHeader(req)}
		for i := range results(len(req.NodesToRead)) {
			res.Results = append(res.Results, valueDV(int32(i)))
		}
		return res
	})
	write := respond(func(r ua.Request) ua.Response {
		req := r.(*ua.WriteRequest)
		res := &ua.WriteResponse{ResponseHeader: okHeader(req)}
		for range results(len(req.NodesToWrite)) {
			res.Results = append(res.Results, ua.StatusOK)
		}
		return res
	})
	_, url := newScriptedServer(t, map[uint16]server.Handler{
		id.ReadRequestEncodingDefaultBinary:  read,
		id.WriteRequestEncodingDefaultBinary: write,
	})
	return connectCovClient(t, url, opcua.SkipNamespaceUpdate())
}

// TestBatchHelpersCheckResultCount: ReadMulti, ReadValues, WriteValues and
// Node.Attributes (and Node.Summary through it) take a response only when it
// holds one result per operation of the request, and fail with
// Bad_UnknownResponse otherwise, in every chunk of a ReadMulti.
func TestBatchHelpersCheckResultCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tt := range []struct {
		name    string
		results func(ops int) int
		ok      bool
	}{
		{"one per operation", func(ops int) int { return ops }, true},
		{"one more", func(ops int) int { return ops + 1 }, false},
		{"one fewer", func(ops int) int { return ops - 1 }, false},
		{"none", func(int) int { return 0 }, false},
		{"twice as many", func(ops int) int { return 2 * ops }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := countServer(t, tt.results)
			// assert, not require: every helper is checked in one run.
			check := func(what string, err error) {
				t.Helper()
				if tt.ok {
					assert.NoError(t, err, what)
					return
				}
				assert.ErrorIs(t, err, ua.StatusBadUnknownResponse, what)
			}

			n := func(i int) *ua.NodeID { return ua.NewStringNodeID(1, fmt.Sprintf("v%d", i)) }
			// Three items in chunks of 1 to 4: full chunks, a shorter last
			// chunk and a single chunk.
			items := []opcua.ReadItem{{NodeID: n(0)}, {NodeID: n(1)}, {NodeID: n(2)}}
			for _, size := range []uint32{1, 2, 3, 4} {
				res, err := c.ReadMulti(ctx, items, opcua.ReadMultiWithChunkSize(size))
				check(fmt.Sprintf("ReadMulti in chunks of %d", size), err)
				if tt.ok {
					assert.Len(t, res, len(items))
				} else {
					assert.Nil(t, res)
				}
			}

			dvs, err := c.ReadValues(ctx, n(0), n(1))
			check("ReadValues", err)
			if !tt.ok {
				assert.Nil(t, dvs)
			}

			sts, err := c.WriteValues(ctx,
				&ua.WriteValue{NodeID: n(0), AttributeID: ua.AttributeIDValue, Value: valueDV(int32(1))},
				&ua.WriteValue{NodeID: n(1), AttributeID: ua.AttributeIDValue, Value: valueDV(int32(2))},
			)
			check("WriteValues", err)
			if tt.ok {
				assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, sts)
			} else {
				assert.Nil(t, sts)
			}

			attrs, err := c.Node(n(0)).Attributes(ctx, ua.AttributeIDValue, ua.AttributeIDDisplayName)
			check("Node.Attributes", err)
			if !tt.ok {
				assert.Nil(t, attrs)
			}

			// Summary reads eight attributes in one request and then browses
			// the type definition, which the scripted server answers.
			_, err = c.Node(n(0)).Summary(ctx)
			check("Node.Summary", err)
		})
	}
}
