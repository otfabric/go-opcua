// SPDX-License-Identifier: MIT

package conformkit

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// Setup stands up a server with the rich fixture and a connected client. All
// resources are torn down via t.Cleanup.
func Setup(t *testing.T) (*opcua.Client, *testutil.Fixture, context.Context) {
	t.Helper()
	srv, url := NewServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	return c, f, context.Background()
}

// AckDialer returns a Dialer option that advertises the given UACP limits in
// the client's HELLO.
func AckDialer(ack *uacp.Acknowledge) opcua.Option {
	return opcua.Dialer(&uacp.Dialer{Dialer: &net.Dialer{}, ClientACK: ack})
}

// --- raw service requests ---------------------------------------------------

// SendRaw sends req and returns the typed response.
func SendRaw[T any](t *testing.T, c *opcua.Client, req ua.Request) (*T, error) {
	t.Helper()
	var out *T
	err := c.Send(context.Background(), req, func(r ua.Response) error {
		// A ServiceFault is reported through the returned error.
		if v, ok := any(r).(*T); ok {
			out = v
		}
		return nil
	})
	return out, err
}

// MustSendRaw sends req, requires that it succeeds and returns the typed
// response.
func MustSendRaw[T any](t *testing.T, c *opcua.Client, req ua.Request) *T {
	t.Helper()
	out, err := SendRaw[T](t, c, req)
	require.NoError(t, err)
	return out
}

// --- data-change samples ----------------------------------------------------

// DataChange is one flattened data-change sample.
type DataChange struct {
	Handle uint32
	DV     *ua.DataValue
}

// NextDataChanges blocks until the next publish that carries at least one
// data-change sample and returns its samples in wire order.
func NextDataChanges(t *testing.T, ch <-chan *opcua.PublishNotificationData) []DataChange {
	t.Helper()
	deadline := time.After(WaitTimeout)
	for {
		select {
		case msg := <-ch:
			require.NoError(t, msg.Error)
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok || len(dcn.MonitoredItems) == 0 {
				continue
			}
			out := make([]DataChange, len(dcn.MonitoredItems))
			for i, it := range dcn.MonitoredItems {
				out[i] = DataChange{Handle: it.ClientHandle, DV: it.Value}
			}
			return out
		case <-deadline:
			t.Fatal("timed out waiting for a data-change notification")
			return nil
		}
	}
}

// --- content filter operands ------------------------------------------------

// ElementOperand refers to another element of a content filter.
func ElementOperand(index uint32) *ua.ExtensionObject {
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(0, id.ElementOperandEncodingDefaultBinary),
		Value:        ua.ElementOperand{Index: index},
	}
}

// LiteralOperand is a literal value operand of a content filter.
func LiteralOperand(v *ua.Variant) *ua.ExtensionObject {
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(0, id.LiteralOperandEncodingDefaultBinary),
		Value:        ua.LiteralOperand{Value: v},
	}
}

// Lit is LiteralOperand for a Go value.
func Lit(v any) *ua.ExtensionObject { return LiteralOperand(ua.MustVariant(v)) }

// Element builds a content filter element.
func Element(op ua.FilterOperator, operands ...*ua.ExtensionObject) *ua.ContentFilterElement {
	return &ua.ContentFilterElement{FilterOperator: op, FilterOperands: operands}
}

// --- connection state and logs ----------------------------------------------

// StateRecorder collects connection states in order: pass its Record to
// opcua.WithConnStateHandler.
type StateRecorder struct {
	mu     sync.Mutex
	states []opcua.ConnState
}

// Record records s.
func (r *StateRecorder) Record(s opcua.ConnState) {
	r.mu.Lock()
	r.states = append(r.states, s)
	r.mu.Unlock()
}

// States returns the states recorded so far.
func (r *StateRecorder) States() []opcua.ConnState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.states)
}

// Seen reports whether s was recorded.
func (r *StateRecorder) Seen(s opcua.ConnState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.states {
		if x == s {
			return true
		}
	}
	return false
}

// SeenAfter reports whether state b was recorded after the first a.
func (r *StateRecorder) SeenAfter(a, b opcua.ConnState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	foundA := false
	for _, x := range r.states {
		if x == a {
			foundA = true
		} else if foundA && x == b {
			return true
		}
	}
	return false
}

// LogCounter is an slog.Handler that counts records by message.
type LogCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

// Enabled implements slog.Handler.
func (l *LogCounter) Enabled(context.Context, slog.Level) bool { return true }

// Handle implements slog.Handler.
func (l *LogCounter) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	if l.counts == nil {
		l.counts = map[string]int{}
	}
	l.counts[r.Message]++
	l.mu.Unlock()
	return nil
}

// WithAttrs implements slog.Handler.
func (l *LogCounter) WithAttrs([]slog.Attr) slog.Handler { return l }

// WithGroup implements slog.Handler.
func (l *LogCounter) WithGroup(string) slog.Handler { return l }

// Count returns the number of records with message msg.
func (l *LogCounter) Count(msg string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[msg]
}

// --- reverse connect --------------------------------------------------------

// FastReverseRetry makes a server retry a failed reverse connection quickly,
// so that the tests do not wait for the production back-off.
var FastReverseRetry = server.ReverseConnectRetryInterval(20*time.Millisecond, 200*time.Millisecond)

// ReverseListener opens a reverse connect listener on an OS-assigned loopback
// port and returns it with the URL servers have to connect to. It is closed on
// test cleanup, after the clients and servers created later.
func ReverseListener(t *testing.T, cfg *uacp.ReverseListenerConfig) (*uacp.ReverseListener, string) {
	t.Helper()
	l, err := uacp.ListenReverse(context.Background(), "127.0.0.1:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l, "opc.tcp://" + l.Addr().String()
}
