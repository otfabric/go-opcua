//go:build interop

// SPDX-License-Identifier: MIT

// go-opcua client against every peer server (C→P) for services and
// transport properties the baseline did not reach:
//
//	transport.chunking.secure            multi-chunk requests and responses
//	                                     on Basic256Sha256 / Aes256_Sha256_RsaPss
//	                                     SignAndEncrypt channels
//	monitoreditem.set-triggering         SetTriggering, linked item in Sampling
//	subscription.client.transfer.anonymous
//	subscription.client.transfer.other-identity
//	                                     TransferSubscriptions identity rules
//	nodemgmt.add-references / .delete-references
//	diagnostics.server-summary           ServerDiagnosticsSummary,
//	                                     SessionDiagnosticsArray
//	diagnostics.return-diagnostics       Read with ReturnDiagnostics,
//	                                     DiagnosticInfo decoded
//
// The assertions are shared; each peer's Test function (here for open62541
// and Milo, in the peer's *_peer_test.go for the other peers) names the
// ledger row in its subtest and says what the peer was observed to decide
// where the specification leaves room or the peer deviates from it.

package interop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// serviceStatus returns the StatusCode a service call failed with.
func serviceStatus(err error) (ua.StatusCode, bool) {
	var sc ua.StatusCode
	if errors.As(err, &sc) {
		return sc, true
	}
	return 0, false
}

// isServiceUnsupported reports whether sc says that the server does not
// implement a service (or the operation of the service).
func isServiceUnsupported(sc ua.StatusCode) bool {
	return sc == ua.StatusBadServiceUnsupported || sc == ua.StatusBadNotSupported || sc == ua.StatusBadNotImplemented
}

// ---------------------------------------------------------------------------
// transport.chunking.secure
// ---------------------------------------------------------------------------

// chunkingValueSize is the ByteString written and read back: about three
// times the largest send / receive buffer go-opcua ever negotiates (its Hello
// offers 0xffff and a server can only lower it, Part 6 §7.1.2.4), so the
// request and the response cannot fit into one chunk.
const chunkingValueSize = 200 * 1024

// chunkRecorder is a slog handler that records the secure channel's chunk
// log of a client: the chunks it sent per request type and request id, the
// MSG chunks it received per request id, and the Acknowledge of the server.
type chunkRecorder struct {
	mu   sync.Mutex
	sent map[string]map[string]int // request type -> request id -> chunks
	recv map[string]int            // request id -> MSG chunks
	ack  map[string]uint64         // Acknowledge field -> value
}

func newChunkRecorder() *chunkRecorder {
	return &chunkRecorder{sent: map[string]map[string]int{}, recv: map[string]int{}}
}

var ackField = regexp.MustCompile(`(\w+):0x([0-9a-f]+)`)

func (r *chunkRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *chunkRecorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *chunkRecorder) WithGroup(string) slog.Handler            { return r }

func (r *chunkRecorder) Handle(_ context.Context, rec slog.Record) error {
	attrs := map[string]string{}
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	switch rec.Message {
	case "send":
		typ, reqID := attrs["type"], attrs["request_id"]
		if r.sent[typ] == nil {
			r.sent[typ] = map[string]int{}
		}
		r.sent[typ][reqID]++
	case "recv":
		if attrs["message_type"] == "MSG" {
			r.recv[attrs["request_id"]]++
		}
	case "received ACK":
		r.ack = map[string]uint64{}
		for _, m := range ackField.FindAllStringSubmatch(attrs["ack"], -1) {
			if v, err := strconv.ParseUint(m[2], 16, 64); err == nil {
				r.ack[m[1]] = v
			}
		}
	}
	return nil
}

// reset forgets the chunks logged so far.
func (r *chunkRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent, r.recv = map[string]map[string]int{}, map[string]int{}
}

// chunks returns the number of chunks of the only request of type typ sent
// since reset, and the number of MSG chunks of its response.
func (r *chunkRecorder) chunks(t *testing.T, typ string) (sent, received int) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sent[typ]) != 1 {
		t.Fatalf("%d %s requests were logged, want 1: %v", len(r.sent[typ]), typ, r.sent[typ])
	}
	for reqID, n := range r.sent[typ] {
		sent, received = n, r.recv[reqID]
	}
	return sent, received
}

func (r *chunkRecorder) acknowledge() map[string]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ack
}

// chunkingValue returns size bytes that no two lengths share a prefix of.
func chunkingValue(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

// assertPeerChunkedSecure writes a ByteString of chunkingValueSize bytes to
// Scalar.ByteString over Basic256Sha256 and Aes256_Sha256_RsaPss
// SignAndEncrypt, reads it back and compares. The message is reduced to what
// the server accepts (the MaxMessageSize of its Acknowledge and the
// MaxRequestMessageSize of CreateSession); a server with a shorter
// MaxByteStringLength gets several shorter values written to (and read
// from) the node in one request. It has to stay more than twice the
// negotiated buffer: the client's chunk log must show the request and the
// response in several chunks.
func assertPeerChunkedSecure(t *testing.T, endpoint string) {
	t.Helper()
	for _, policy := range []string{"Basic256Sha256", "Aes256_Sha256_RsaPss"} {
		t.Run(policy, func(t *testing.T) {
			rec := newChunkRecorder()
			c, err := connectSecureClient(t, endpoint, policy, "SignAndEncrypt", ua.UserTokenTypeAnonymous,
				opcua.AuthAnonymous(), opcua.WithLogger(slog.New(rec)))
			if err != nil {
				t.Fatalf("connect %s/SignAndEncrypt: %v", policy, err)
			}
			if got := c.SecurityPolicy(); got != ua.FormatSecurityPolicyURI(policy) {
				t.Fatalf("connected with %s, want %s", got, policy)
			}
			_, nsIdx := findNS(t, c)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			ack := rec.acknowledge()
			if ack == nil {
				t.Fatal("the client logged no Acknowledge: the negotiated limits are unknown")
			}
			buf := max(ack["SendBufSize"], ack["ReceiveBufSize"])
			if buf == 0 || buf > 0xffff {
				t.Fatalf("negotiated buffers %v: want 0 < size <= 0xffff", ack)
			}

			// What the server accepts: in one message, and in one ByteString.
			msgLimits := map[string]uint64{"Acknowledge.MaxMessageSize": ack["MaxMessageSize"]}
			if s := c.Session(); s != nil {
				msgLimits["CreateSession.MaxRequestMessageSize"] = uint64(s.MaxRequestMessageSize())
			}
			var maxByteString uint64
			if dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerCapabilitiesMaxByteStringLength)); err == nil && dv.Status == ua.StatusOK && dv.Value != nil {
				if n, ok := dv.Value.Value().(uint32); ok {
					maxByteString = uint64(n)
				}
			}
			const overhead = 4096 // request header, NodeIds, sequence and security headers, padding, signature
			total := uint64(chunkingValueSize)
			for name, l := range msgLimits {
				if l != 0 && total+overhead > l {
					t.Logf("%s is %d: the message is reduced", name, l)
					total = l - overhead
				}
			}
			// A server whose ByteStrings are shorter than the message gets the
			// value several times in one request: n operations on the node.
			size, n := total, uint64(1)
			if maxByteString != 0 && size > maxByteString-64 {
				size = maxByteString - 64
				n = total / size
				t.Logf("MaxByteStringLength is %d: %d operations of %d bytes each", maxByteString, n, size)
			}
			if n*size <= 2*buf {
				t.Skipf("the server accepts no message larger than %d bytes (limits %v, MaxByteStringLength %d), which fits into %d chunks of %d bytes: "+
					"no multi-chunk message can be provoked", n*size, msgLimits, maxByteString, n*size/buf+1, buf)
			}
			t.Logf("negotiated %v, limits %v, MaxByteStringLength %d: %d × %d bytes", ack, msgLimits, maxByteString, n, size)

			value := chunkingValue(int(size))
			node := ua.NewStringNodeID(nsIdx, "Scalar.ByteString")
			writes := make([]*ua.WriteValue, n)
			reads := make([]*ua.ReadValueID, n)
			for i := range writes {
				writes[i] = &ua.WriteValue{
					NodeID: node, AttributeID: ua.AttributeIDValue,
					Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(value)},
				}
				reads[i] = &ua.ReadValueID{NodeID: node, AttributeID: ua.AttributeIDValue}
			}
			rec.reset()
			wr, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: writes})
			if err != nil {
				t.Fatalf("Write of %d × %d bytes: %v", n, size, err)
			}
			if uint64(len(wr.Results)) != n {
				t.Fatalf("Write of %d × %d bytes: %d results", n, size, len(wr.Results))
			}
			for i, r := range wr.Results {
				if r != ua.StatusOK {
					t.Fatalf("Write of %d bytes, operation %d: %v", size, i, r)
				}
			}
			sent, _ := rec.chunks(t, "*ua.WriteRequest")

			rec.reset()
			rr, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: reads, TimestampsToReturn: ua.TimestampsToReturnNeither})
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			_, received := rec.chunks(t, "*ua.ReadRequest")
			if uint64(len(rr.Results)) != n {
				t.Fatalf("Read: %d results for %d operations", len(rr.Results), n)
			}
			for i, dv := range rr.Results {
				if dv.Status != ua.StatusOK || dv.Value == nil {
					t.Fatalf("Read operation %d: status %v value %v", i, dv.Status, dv.Value)
				}
				got, ok := dv.Value.Value().([]byte)
				if !ok {
					t.Fatalf("Read operation %d returned %T, want a ByteString", i, dv.Value.Value())
				}
				if !bytes.Equal(got, value) {
					t.Fatalf("Read operation %d: %d bytes that differ from the %d written", i, len(got), len(value))
				}
			}

			minChunks := int(n*size/buf) + 1
			if sent < minChunks || received < minChunks {
				t.Fatalf("WriteRequest went in %d chunks, ReadResponse came in %d: want at least %d each for %d bytes in buffers of %d",
					sent, received, minChunks, n*size, buf)
			}
			t.Logf("%d × %d bytes: WriteRequest in %d chunks, ReadResponse in %d chunks", n, size, sent, received)
		})
	}
}

func TestOpen62541Server_ChunkedSecureMessages(t *testing.T) {
	t.Run("coverage/transport.chunking.secure/go-client-to-open62541-server", func(t *testing.T) {
		assertPeerChunkedSecure(t, startOpen62541SecureServer(t).endpoint)
	})
}

func TestMiloServer_ChunkedSecureMessages(t *testing.T) {
	t.Run("coverage/transport.chunking.secure/go-client-to-milo-server", func(t *testing.T) {
		assertPeerChunkedSecure(t, startMiloSecureServer(t).endpoint)
	})
}

// ---------------------------------------------------------------------------
// monitoreditem.set-triggering
// ---------------------------------------------------------------------------

const (
	trigHandleTrigger = 1 // Scalar.Double, Reporting
	trigHandleLinked  = 2 // Scalar.Int32, Sampling
	trigHandleWitness = 3 // Scalar.Float, Reporting, never linked
)

// trigWatch follows the notifications of the SetTriggering subscription.
type trigWatch struct {
	t  *testing.T
	ch <-chan *opcua.PublishNotificationData
	n  int // notification messages seen
	// seen: handle -> value -> index of the first notification message
	// that carried it
	seen map[uint32]map[string]int
}

func (w *trigWatch) key(v any) string { return fmt.Sprintf("%T:%v", v, v) }

// await consumes notifications until the item with handle reports value.
func (w *trigWatch) await(handle uint32, value any, timeout time.Duration) int {
	w.t.Helper()
	k := w.key(value)
	deadline := time.After(timeout)
	for {
		if i, ok := w.seen[handle][k]; ok {
			return i
		}
		select {
		case msg, ok := <-w.ch:
			if !ok {
				w.t.Fatal("notification channel closed")
			}
			if msg.Error != nil {
				w.t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok || dcn == nil {
				continue
			}
			w.n++
			for _, mi := range dcn.MonitoredItems {
				if mi.Value == nil || mi.Value.Value == nil {
					continue
				}
				if w.seen[mi.ClientHandle] == nil {
					w.seen[mi.ClientHandle] = map[string]int{}
				}
				vk := w.key(mi.Value.Value.Value())
				if _, dup := w.seen[mi.ClientHandle][vk]; !dup {
					w.seen[mi.ClientHandle][vk] = w.n
				}
			}
		case <-deadline:
			w.t.Fatalf("handle %d did not report %v within %v (seen %v)", handle, value, timeout, w.seen)
		}
	}
}

func (w *trigWatch) reported(handle uint32, value any) (int, bool) {
	i, ok := w.seen[handle][w.key(value)]
	return i, ok
}

// assertPeerSetTriggering: the linked item samples but does not report on
// its own; after SetTriggering a value written to it is reported only once
// the triggering item reports, and after RemoveLinks not at all.
//
// Whether a value has had its chance to be reported is decided by the
// witness item: two values written to it after the linked item's value, and
// reported, mean that the server sampled and published since then.
//
// It returns the status of SetTriggering when the server refuses the
// service, and Good when the assertions ran.
func assertPeerSetTriggering(t *testing.T, endpoint string) ua.StatusCode {
	t.Helper()
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)

	sub, ch, err := c.NewSubscription().Interval(100 * time.Millisecond).Start(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	item := func(name string, handle uint32, mode ua.MonitoringMode) *ua.MonitoredItemCreateRequest {
		r := opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewStringNodeID(nsIdx, name), ua.AttributeIDValue, handle)
		r.MonitoringMode = mode
		r.RequestedParameters.SamplingInterval = 50
		return r
	}
	mon, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		item("Scalar.Double", trigHandleTrigger, ua.MonitoringModeReporting),
		item("Scalar.Int32", trigHandleLinked, ua.MonitoringModeSampling),
		item("Scalar.Float", trigHandleWitness, ua.MonitoringModeReporting),
	)
	if err != nil {
		t.Fatalf("CreateMonitoredItems: %v", err)
	}
	if len(mon.Results) != 3 {
		t.Fatalf("CreateMonitoredItems: %d results, want 3", len(mon.Results))
	}
	for i, r := range mon.Results {
		if r.StatusCode != ua.StatusOK {
			t.Fatalf("CreateMonitoredItems item %d: %v", i, r.StatusCode)
		}
	}
	triggerID, linkedID := mon.Results[0].MonitoredItemID, mon.Results[1].MonitoredItemID

	write := func(name string, v any) {
		t.Helper()
		resp, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
			NodeID: ua.NewStringNodeID(nsIdx, name), AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
		}}})
		if err != nil || len(resp.Results) != 1 || resp.Results[0] != ua.StatusOK {
			t.Fatalf("Write %s=%v: %v %+v", name, v, err, resp)
		}
	}
	w := &trigWatch{t: t, ch: ch, seen: map[uint32]map[string]int{}}
	const wait = 20 * time.Second
	// settle writes witness values and waits for them: the server has
	// sampled and published at least once after everything written before.
	witness := float32(0)
	settle := func() {
		t.Helper()
		for range 2 {
			witness++
			write("Scalar.Float", witness)
			w.await(trigHandleWitness, witness, wait)
		}
	}

	settle()
	if vals := w.seen[trigHandleLinked]; len(vals) > 0 {
		t.Fatalf("the linked item reported %v in Sampling mode without a trigger", vals)
	}

	st, err := sub.SetTriggering(ctx, triggerID, []uint32{linkedID}, nil)
	if err != nil {
		if sc, ok := serviceStatus(err); ok {
			return sc
		}
		t.Fatalf("SetTriggering (add): %v", err)
	}
	if len(st.AddResults) != 1 || st.AddResults[0] != ua.StatusOK {
		t.Fatalf("SetTriggering AddResults %v, want [Good]", st.AddResults)
	}

	// A value written to the linked item waits for the trigger.
	write("Scalar.Int32", int32(7001))
	settle()
	if i, ok := w.reported(trigHandleLinked, int32(7001)); ok {
		t.Fatalf("the linked item reported 7001 in notification %d before the triggering item reported", i)
	}
	write("Scalar.Double", 1.5)
	trig := w.await(trigHandleTrigger, 1.5, wait)
	linked := w.await(trigHandleLinked, int32(7001), wait)
	if linked < trig {
		t.Fatalf("the linked value came in notification %d, before the trigger's in %d", linked, trig)
	}
	t.Logf("trigger reported in notification %d, the linked value in %d", trig, linked)
	// open62541 reports the samples of a linked item for one publishing
	// interval after its trigger reported (MonitoredItem.triggeredUntil),
	// also once the link is gone: let that window pass first.
	settle()

	// RemoveLinks: the linked item stays in Sampling mode and reports nothing,
	// not even when the former trigger reports.
	st, err = sub.SetTriggering(ctx, triggerID, nil, []uint32{linkedID})
	if err != nil {
		t.Fatalf("SetTriggering (remove): %v", err)
	}
	if len(st.RemoveResults) != 1 || st.RemoveResults[0] != ua.StatusOK {
		t.Fatalf("SetTriggering RemoveResults %v, want [Good]", st.RemoveResults)
	}
	write("Scalar.Int32", int32(7002))
	write("Scalar.Double", 2.5)
	w.await(trigHandleTrigger, 2.5, wait)
	settle()
	if i, ok := w.reported(trigHandleLinked, int32(7002)); ok {
		t.Fatalf("the unlinked item reported 7002 in notification %d", i)
	}
	return ua.StatusOK
}

// requireSetTriggering runs assertPeerSetTriggering against a peer that
// implements the service.
func requireSetTriggering(t *testing.T, endpoint string) {
	t.Helper()
	if sc := assertPeerSetTriggering(t, endpoint); sc != ua.StatusOK {
		t.Fatalf("SetTriggering refused: %v", sc)
	}
}

func TestOpen62541Server_SetTriggering(t *testing.T) {
	t.Run("coverage/monitoreditem.set-triggering/go-client-to-open62541-server", func(t *testing.T) {
		requireSetTriggering(t, startOpen62541Server(t).endpoint)
	})
}

func TestMiloServer_SetTriggering(t *testing.T) {
	t.Run("coverage/monitoreditem.set-triggering/go-client-to-milo-server", func(t *testing.T) {
		requireSetTriggering(t, startMiloServer(t).endpoint)
	})
}

// ---------------------------------------------------------------------------
// subscription.client.transfer.anonymous / .other-identity
// ---------------------------------------------------------------------------

// transferBetween creates a subscription in c1's session and transfers it to
// c2's session; it returns the result for the subscription.
func transferBetween(t *testing.T, c1, c2 *opcua.Client) ua.StatusCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	notifyCh := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c1.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 200 * time.Millisecond}, notifyCh)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	resp, err := c2.TransferSubscriptions(ctx, []uint32{sub.SubscriptionID}, false)
	if err != nil {
		if sc, ok := serviceStatus(err); ok {
			t.Logf("TransferSubscriptions(%d): service result %v", sub.SubscriptionID, sc)
			return sc
		}
		t.Fatalf("TransferSubscriptions: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("TransferSubscriptions: %d results, want 1", len(resp.Results))
	}
	t.Logf("TransferSubscriptions(%d): %v", sub.SubscriptionID, resp.Results[0].StatusCode)
	return resp.Results[0].StatusCode
}

// dialSecureAnonymous and dialSecureUser open a session over Basic256Sha256
// SignAndEncrypt with the consumer application certificate.
func dialSecureAnonymous(t *testing.T, endpoint string) *opcua.Client {
	t.Helper()
	return dialSecureClient(t, endpoint, "Basic256Sha256", "SignAndEncrypt")
}

func dialSecureUser(t *testing.T, endpoint, user, password string) *opcua.Client {
	t.Helper()
	c, err := connectSecureClient(t, endpoint, "Basic256Sha256", "SignAndEncrypt", ua.UserTokenTypeUserName,
		opcua.AuthUsername(user, password))
	if err != nil {
		t.Fatalf("connect as %s: %v", user, err)
	}
	return c
}

// assertPeerTransferAnonymous: two anonymous sessions of the same client
// application (same certificate, Basic256Sha256 SignAndEncrypt). Part 4
// §5.14.7 asks the server to check that the client operates on behalf of the
// same user; for anonymous sessions only the application is there to compare.
// want is the peer's decision as observed.
func assertPeerTransferAnonymous(t *testing.T, endpoint string, want ua.StatusCode) {
	t.Helper()
	got := transferBetween(t, dialSecureAnonymous(t, endpoint), dialSecureAnonymous(t, endpoint))
	if got != want {
		t.Fatalf("anonymous → anonymous, same application certificate: %v, want %v", got, want)
	}
}

// assertPeerTransferOtherIdentity: a subscription of the fixture user
// test-user transferred to an anonymous session of the same application.
// The fixture has a single user, so the other identity is the anonymous one;
// Part 4 §5.14.7 requires Bad_UserAccessDenied for a different user.
func assertPeerTransferOtherIdentity(t *testing.T, endpoint string, want ua.StatusCode) {
	t.Helper()
	got := transferBetween(t, dialSecureUser(t, endpoint, "test-user", "test-password"), dialSecureAnonymous(t, endpoint))
	if got != want {
		t.Fatalf("test-user → anonymous: %v, want %v", got, want)
	}
}

func TestOpen62541Server_TransferSubscriptionsIdentity(t *testing.T) {
	t.Run("coverage/subscription.client.transfer.anonymous/go-client-to-open62541-server", func(t *testing.T) {
		assertPeerTransferAnonymous(t, startOpen62541SecureServer(t).endpoint, ua.StatusOK)
	})
	t.Run("coverage/subscription.client.transfer.other-identity/go-client-to-open62541-server", func(t *testing.T) {
		assertPeerTransferOtherIdentity(t, startOpen62541SecureServer(t).endpoint, ua.StatusBadUserAccessDenied)
	})
}

func TestMiloServer_TransferSubscriptionsIdentity(t *testing.T) {
	t.Run("coverage/subscription.client.transfer.anonymous/go-client-to-milo-server", func(t *testing.T) {
		assertPeerTransferAnonymous(t, startMiloSecureServer(t).endpoint, ua.StatusOK)
	})
	t.Run("coverage/subscription.client.transfer.other-identity/go-client-to-milo-server", func(t *testing.T) {
		assertPeerTransferOtherIdentity(t, startMiloSecureServer(t).endpoint, ua.StatusBadUserAccessDenied)
	})
}

// ---------------------------------------------------------------------------
// nodemgmt.add-references / .delete-references
// ---------------------------------------------------------------------------

// referencesProbe is the reference the tests add and delete: an Organizes
// reference from the fixture folder Dynamic to the variable Scalar.Int32,
// which the fixture does not have.
func referencesProbe(nsIdx uint16) (source, target *ua.NodeID, refType *ua.NodeID) {
	return ua.NewStringNodeID(nsIdx, "Dynamic"), ua.NewStringNodeID(nsIdx, "Scalar.Int32"), ua.NewNumericNodeID(0, id.Organizes)
}

func browseHasTarget(t *testing.T, c *opcua.Client, source, target *ua.NodeID) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: source, BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes), IncludeSubtypes: true,
		ResultMask: uint32(ua.BrowseResultMaskAll),
	}}})
	if err != nil || len(resp.Results) != 1 || resp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("Browse %v: %v %+v", source, err, resp)
	}
	for _, r := range resp.Results[0].References {
		if r.NodeID != nil && r.NodeID.NodeID != nil && r.NodeID.NodeID.String() == target.String() {
			return true
		}
	}
	return false
}

func addReferenceRequest(source, target, refType *ua.NodeID) *ua.AddReferencesRequest {
	return &ua.AddReferencesRequest{ReferencesToAdd: []*ua.AddReferencesItem{{
		SourceNodeID: source, ReferenceTypeID: refType, IsForward: true,
		TargetNodeID: ua.NewExpandedNodeID(target, "", 0), TargetNodeClass: ua.NodeClassVariable,
	}}}
}

// assertPeerAddDeleteReferences adds the probe reference, sees it in a
// Browse, deletes it and sees it gone.
func assertPeerAddDeleteReferences(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	source, target, refType := referencesProbe(nsIdx)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if browseHasTarget(t, c, source, target) {
		t.Fatalf("%v already organizes %v: the probe needs a reference the fixture does not have", source, target)
	}
	add, err := c.AddReferences(ctx, addReferenceRequest(source, target, refType))
	if err != nil {
		t.Fatalf("AddReferences: %v", err)
	}
	if len(add.Results) != 1 || add.Results[0] != ua.StatusOK {
		t.Fatalf("AddReferences results %v, want [Good]", add.Results)
	}
	if !browseHasTarget(t, c, source, target) {
		t.Fatalf("Browse of %v does not show the added reference to %v", source, target)
	}

	del, err := c.DeleteReferences(ctx, &ua.DeleteReferencesRequest{ReferencesToDelete: []*ua.DeleteReferencesItem{{
		SourceNodeID: source, ReferenceTypeID: refType, IsForward: true,
		TargetNodeID: ua.NewExpandedNodeID(target, "", 0), DeleteBidirectional: true,
	}}})
	if err != nil {
		t.Fatalf("DeleteReferences: %v", err)
	}
	if len(del.Results) != 1 || del.Results[0] != ua.StatusOK {
		t.Fatalf("DeleteReferences results %v, want [Good]", del.Results)
	}
	if browseHasTarget(t, c, source, target) {
		t.Fatalf("Browse of %v still shows the deleted reference to %v", source, target)
	}
	// The variable itself is untouched.
	if dv, err := c.ReadValue(ctx, target); err != nil || dv.Status != ua.StatusOK {
		t.Fatalf("read %v after DeleteReferences: %v %v", target, err, dv)
	}
}

// assertPeerReferencesRefused pins the refusal of AddReferences and
// DeleteReferences by a server without NodeManagement: either service
// answers a service fault or an operation result that says it is not
// supported, and the address space is unchanged.
func assertPeerReferencesRefused(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	source, target, refType := referencesProbe(nsIdx)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	refused := func(what string, err error, results []ua.StatusCode) {
		t.Helper()
		if err != nil {
			sc, ok := serviceStatus(err)
			if !ok || !isServiceUnsupported(sc) {
				t.Fatalf("%s: %v, want BadServiceUnsupported / BadNotSupported / BadNotImplemented", what, err)
			}
			t.Logf("%s: %v", what, sc)
			return
		}
		if len(results) != 1 || !isServiceUnsupported(results[0]) {
			t.Fatalf("%s accepted (%v): the peer implements it, promote the row to a verified test", what, results)
		}
		t.Logf("%s: operation result %v", what, results[0])
	}
	add, err := c.AddReferences(ctx, addReferenceRequest(source, target, refType))
	var addResults []ua.StatusCode
	if add != nil {
		addResults = add.Results
	}
	refused("AddReferences", err, addResults)
	if browseHasTarget(t, c, source, target) {
		t.Fatalf("the refused AddReferences changed the address space")
	}
	del, err := c.DeleteReferences(ctx, &ua.DeleteReferencesRequest{ReferencesToDelete: []*ua.DeleteReferencesItem{{
		SourceNodeID: ua.NewStringNodeID(nsIdx, "Scalars"), ReferenceTypeID: refType, IsForward: true,
		TargetNodeID: ua.NewExpandedNodeID(target, "", 0), DeleteBidirectional: true,
	}}})
	var delResults []ua.StatusCode
	if del != nil {
		delResults = del.Results
	}
	refused("DeleteReferences", err, delResults)
	if !browseHasTarget(t, c, ua.NewStringNodeID(nsIdx, "Scalars"), target) {
		t.Fatalf("the refused DeleteReferences removed Scalars → Scalar.Int32")
	}
}

func TestOpen62541Server_AddDeleteReferences(t *testing.T) {
	h := startOpen62541Server(t)
	t.Run("coverage/nodemgmt.add-references/go-client-to-open62541-server", func(t *testing.T) {
		assertPeerAddDeleteReferences(t, h.endpoint)
	})
	t.Run("coverage/nodemgmt.delete-references/go-client-to-open62541-server", func(t *testing.T) {
		assertPeerAddDeleteReferences(t, h.endpoint)
	})
}

// TestMiloServer_ReferencesUnsupported pins why nodemgmt.*-references C→M
// are unsupported: the Milo reference server has no NodeManagement.
func TestMiloServer_ReferencesUnsupported(t *testing.T) {
	assertPeerReferencesRefused(t, startMiloServer(t).endpoint)
}

// ---------------------------------------------------------------------------
// diagnostics.server-summary / diagnostics.return-diagnostics
// ---------------------------------------------------------------------------

// readServerSummary reads ServerDiagnosticsSummary.
func readServerSummary(t *testing.T, ctx context.Context, c *opcua.Client) *ua.ServerDiagnosticsSummaryDataType {
	t.Helper()
	dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsServerDiagnosticsSummary))
	if err != nil {
		t.Fatalf("read ServerDiagnosticsSummary: %v", err)
	}
	if dv.Status != ua.StatusOK || dv.Value == nil {
		t.Skipf("ServerDiagnosticsSummary: status %v: the server has no server diagnostics", dv.Status)
	}
	eo, ok := dv.Value.Value().(*ua.ExtensionObject)
	if !ok || eo == nil {
		t.Fatalf("ServerDiagnosticsSummary is %T, want an ExtensionObject", dv.Value.Value())
	}
	sum, ok := eo.Value.(*ua.ServerDiagnosticsSummaryDataType)
	if !ok || sum == nil {
		t.Fatalf("ServerDiagnosticsSummary decoded to %T, want *ua.ServerDiagnosticsSummaryDataType", eo.Value)
	}
	return sum
}

// diagnosticsEnabled reads Server.ServerDiagnostics.EnabledFlag; a server
// without it or with diagnostics off has no diagnostics to claim.
func diagnosticsEnabled(t *testing.T, ctx context.Context, c *opcua.Client) (bool, string) {
	t.Helper()
	dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsEnabledFlag))
	if err != nil {
		t.Fatalf("read EnabledFlag: %v", err)
	}
	if dv.Status != ua.StatusOK || dv.Value == nil {
		return false, fmt.Sprintf("EnabledFlag: status %v", dv.Status)
	}
	on, ok := dv.Value.Value().(bool)
	if !ok {
		// async-opcua 0.19 has the node, with a null value
		return false, fmt.Sprintf("EnabledFlag has no Boolean value (%T %v)", dv.Value.Value(), dv.Value.Value())
	}
	return on, fmt.Sprintf("EnabledFlag = %v", on)
}

// assertPeerServerDiagnostics reads ServerDiagnosticsSummary, checks that it
// counts the test's own sessions (a second session raises the cumulated
// count) and finds the session in the SessionDiagnosticsArray where the
// server exposes it to the client.
func assertPeerServerDiagnostics(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if on, why := diagnosticsEnabled(t, ctx, c); !on {
		t.Skipf("the server has no diagnostics (%s)", why)
	}
	first := readServerSummary(t, ctx, c)
	t.Logf("ServerDiagnosticsSummary: %+v", *first)
	if first.CurrentSessionCount < 1 || first.CumulatedSessionCount < first.CurrentSessionCount {
		t.Fatalf("summary counts %d current / %d cumulated sessions with this one open",
			first.CurrentSessionCount, first.CumulatedSessionCount)
	}
	if first.CumulatedSubscriptionCount < first.CurrentSubscriptionCount {
		t.Fatalf("summary: %d cumulated < %d current subscriptions", first.CumulatedSubscriptionCount, first.CurrentSubscriptionCount)
	}

	// Another session: the summary follows (servers refresh it periodically,
	// so poll until the deadline).
	dialClient(t, endpoint)
	deadline := time.Now().Add(30 * time.Second)
	for {
		s := readServerSummary(t, ctx, c)
		if s.CumulatedSessionCount > first.CumulatedSessionCount && s.CurrentSessionCount >= 2 {
			t.Logf("after a second session: %d current / %d cumulated", s.CurrentSessionCount, s.CumulatedSessionCount)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a second session left the summary at %d current / %d cumulated (before: %d / %d)",
				s.CurrentSessionCount, s.CumulatedSessionCount, first.CurrentSessionCount, first.CumulatedSessionCount)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}

	t.Run("SessionDiagnosticsArray", func(t *testing.T) {
		dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSessionsDiagnosticsSummarySessionDiagnosticsArray))
		if err != nil {
			t.Fatalf("read SessionDiagnosticsArray: %v", err)
		}
		if dv.Status != ua.StatusOK || dv.Value == nil {
			t.Skipf("SessionDiagnosticsArray: status %v: not exposed to an anonymous client", dv.Status)
		}
		eos, ok := dv.Value.Value().([]*ua.ExtensionObject)
		if !ok {
			t.Fatalf("SessionDiagnosticsArray is %T, want []ExtensionObject", dv.Value.Value())
		}
		own := c.Session().SessionID()
		var ids []string
		for _, eo := range eos {
			sd, ok := eo.Value.(*ua.SessionDiagnosticsDataType)
			if !ok || sd == nil {
				t.Fatalf("SessionDiagnosticsArray element decoded to %T", eo.Value)
			}
			ids = append(ids, sd.SessionID.String())
			if sd.SessionID != nil && own != nil && sd.SessionID.String() == own.String() {
				if sd.ActualSessionTimeout <= 0 {
					t.Errorf("own session: ActualSessionTimeout %v", sd.ActualSessionTimeout)
				}
				t.Logf("own session %s: %q, timeout %v ms, %d reads", own, sd.SessionName, sd.ActualSessionTimeout, readCount(sd))
				return
			}
		}
		t.Fatalf("own session %v not among the %d sessions %v", own, len(eos), ids)
	})
}

func readCount(sd *ua.SessionDiagnosticsDataType) uint32 {
	if sd.ReadCount == nil {
		return 0
	}
	return sd.ReadCount.TotalCount
}

// assertDiagnosticInfo checks one DiagnosticInfo against the response's
// string table and returns a printable form.
func assertDiagnosticInfo(t *testing.T, d *ua.DiagnosticInfo, table []string, depth int) string {
	t.Helper()
	if d == nil {
		return "<nil>"
	}
	if depth > 5 {
		t.Fatalf("DiagnosticInfo nested deeper than 5")
	}
	str := func(flag byte, idx int32, name string) string {
		if !d.Has(flag) {
			return ""
		}
		if idx < 0 || int(idx) >= len(table) {
			t.Fatalf("DiagnosticInfo %s index %d outside the string table of %d entries", name, idx, len(table))
		}
		return fmt.Sprintf(" %s=%q", name, table[idx])
	}
	out := fmt.Sprintf("{mask=%#x", d.EncodingMask) +
		str(ua.DiagnosticInfoSymbolicID, d.SymbolicID, "SymbolicId") +
		str(ua.DiagnosticInfoNamespaceURI, d.NamespaceURI, "NamespaceUri") +
		str(ua.DiagnosticInfoLocalizedText, d.LocalizedText, "LocalizedText") +
		str(ua.DiagnosticInfoLocale, d.Locale, "Locale")
	if d.Has(ua.DiagnosticInfoAdditionalInfo) {
		out += fmt.Sprintf(" AdditionalInfo=%q", d.AdditionalInfo)
	}
	if d.Has(ua.DiagnosticInfoInnerStatusCode) {
		out += fmt.Sprintf(" InnerStatusCode=%v", d.InnerStatusCode)
	}
	if d.Has(ua.DiagnosticInfoInnerDiagnosticInfo) {
		out += " Inner=" + assertDiagnosticInfo(t, d.InnerDiagnosticInfo, table, depth+1)
	}
	return out + "}"
}

// assertPeerReturnDiagnostics reads a fixture variable and an unknown node,
// once without and once with ReturnDiagnostics. Without the mask a server
// returns no DiagnosticInfos (Part 4 §7.33); with it, one per operation or
// none, and every DiagnosticInfo that comes back must decode against the
// string table. A server that returns none for the failed operation has no
// operation diagnostics to claim.
func assertPeerReturnDiagnostics(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	read := func(mask uint32) *ua.ReadResponse {
		t.Helper()
		resp, err := c.Read(ctx, &ua.ReadRequest{
			RequestHeader: &ua.RequestHeader{ReturnDiagnostics: mask},
			NodesToRead: []*ua.ReadValueID{
				{NodeID: ua.NewStringNodeID(nsIdx, "Scalar.Int32")},
				{NodeID: ua.NewStringNodeID(nsIdx, "Interop.NoSuchNode")},
			},
			TimestampsToReturn: ua.TimestampsToReturnNeither,
		})
		if err != nil {
			t.Fatalf("Read (ReturnDiagnostics %#x): %v", mask, err)
		}
		if len(resp.Results) != 2 || resp.Results[0].Status != ua.StatusOK || resp.Results[1].Status != ua.StatusBadNodeIDUnknown {
			t.Fatalf("Read (ReturnDiagnostics %#x): results %+v, want Good and BadNodeIdUnknown", mask, resp.Results)
		}
		return resp
	}

	plain := read(0)
	if len(plain.DiagnosticInfos) != 0 {
		t.Fatalf("without ReturnDiagnostics the server returned %d DiagnosticInfos", len(plain.DiagnosticInfos))
	}

	resp := read(ua.ReturnDiagnosticsAll)
	table := resp.ResponseHeader.StringTable
	if sd := resp.ResponseHeader.ServiceDiagnostics; sd != nil && sd.EncodingMask != 0 {
		t.Logf("service diagnostics: %s", assertDiagnosticInfo(t, sd, table, 0))
	}
	switch len(resp.DiagnosticInfos) {
	case 0:
		t.Skipf("with ReturnDiagnostics %#x the server returned no DiagnosticInfos for a BadNodeIdUnknown operation (string table %q)",
			uint32(ua.ReturnDiagnosticsAll), table)
	case 2:
	default:
		t.Fatalf("%d DiagnosticInfos for 2 operations", len(resp.DiagnosticInfos))
	}
	failed := resp.DiagnosticInfos[1]
	t.Logf("DiagnosticInfos: ok=%s failed=%s, string table %q",
		assertDiagnosticInfo(t, resp.DiagnosticInfos[0], table, 0), assertDiagnosticInfo(t, failed, table, 0), table)
	if failed == nil || failed.EncodingMask == 0 {
		t.Skip("the DiagnosticInfo of the failed operation is empty: the server has no operation diagnostics")
	}
}

func TestOpen62541Server_Diagnostics(t *testing.T) {
	h := startOpen62541Server(t)
	t.Run("coverage/diagnostics.server-summary/go-client-to-open62541-server", func(t *testing.T) {
		assertPeerServerDiagnostics(t, h.endpoint)
	})
	t.Run("coverage/diagnostics.return-diagnostics/go-client-to-open62541-server", func(t *testing.T) {
		assertPeerReturnDiagnostics(t, h.endpoint)
	})
}

func TestMiloServer_Diagnostics(t *testing.T) {
	h := startMiloServer(t)
	t.Run("coverage/diagnostics.server-summary/go-client-to-milo-server", func(t *testing.T) {
		assertPeerServerDiagnostics(t, h.endpoint)
	})
	t.Run("coverage/diagnostics.return-diagnostics/go-client-to-milo-server", func(t *testing.T) {
		assertPeerReturnDiagnostics(t, h.endpoint)
	})
}
