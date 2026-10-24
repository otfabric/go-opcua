// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// checkDiagnostics verifies the invariants of one diagnostics snapshot
// (Part 14 §9.1.11): a counter is active exactly when its level is within
// the level of the object, its TimeFirstChange is set exactly when it is
// not 0, and the totals are the saturated sums of the active counters of
// their classification.
func checkDiagnostics(sink *chaoskit.ErrSink, d *pubsub.Diagnostics) {
	var info, errs uint64
	for _, c := range d.Counters {
		if c.Active != (c.Level <= d.Level) {
			sink.Addf("%v %q: counter %v active=%v with level %v in an object of level %v", d.Kind, d.Name, c.ID, c.Active, c.Level, d.Level)
		}
		if (c.Value == 0) != c.TimeFirstChange.IsZero() {
			sink.Addf("%v %q: counter %v is %d with TimeFirstChange %v", d.Kind, d.Name, c.ID, c.Value, c.TimeFirstChange)
		}
		if !c.Active {
			continue
		}
		if c.Classification == ua.PubSubDiagnosticsCounterClassificationError {
			errs += uint64(c.Value)
		} else {
			info += uint64(c.Value)
		}
	}
	if want := uint32(min(info, math.MaxUint32)); d.TotalInformation != want {
		sink.Addf("%v %q: TotalInformation %d, the active counters sum to %d", d.Kind, d.Name, d.TotalInformation, want)
	}
	if want := uint32(min(errs, math.MaxUint32)); d.TotalError != want {
		sink.Addf("%v %q: TotalError %d, the active counters sum to %d", d.Kind, d.Name, d.TotalError, want)
	}
}

// diagWorker reads, resets and changes the level of the diagnostics of
// random components of the runtime through the Go API.
func (c *churn) diagWorker(rng *rand.Rand, stop <-chan struct{}, reads *atomic.Int64) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		comps := c.rt.Components()
		cid := pubsub.Root
		if x, ok := pick(rng, comps); ok && rng.Intn(5) > 0 {
			cid = x.ID
		}
		_ = c.wd.Do("diagnostics", func() error {
			switch rng.Intn(6) {
			case 0:
				c.check("ResetDiagnostics", c.rt.ResetDiagnostics(cid))
			case 1:
				c.check("SetDiagnosticsLevel", c.rt.SetDiagnosticsLevel(cid, ua.DiagnosticsLevel(rng.Intn(5))))
			default:
				d, err := c.rt.Diagnostics(cid)
				c.check("Diagnostics", err)
				if err == nil {
					reads.Add(1)
					checkDiagnostics(c.sink, &d)
				}
			}
			return nil
		})
	}
}

// diagNode is the diagnostics object of a component in the address space,
// with the nodes the remote workers read.
type diagNode struct {
	cid   pubsub.ComponentID
	diag  *ua.NodeID
	nodes []*ua.NodeID
}

// childNode browses one level below n for a BrowseName.
func childNode(ctx context.Context, cl *opcua.Client, n *ua.NodeID, name string) (*ua.NodeID, error) {
	refs, err := cl.Node(n).References(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	if err != nil {
		return nil, err
	}
	for _, r := range refs {
		if r.BrowseName.Name == name {
			return r.NodeID.NodeID, nil
		}
	}
	return nil, ua.StatusBadNotFound
}

// remoteDiagWorker browses the diagnostics objects of random components
// through an OPC UA client, reads their counters and calls their Reset
// method, while the components come and go. A read of a removed object
// must fail with Bad_NodeIdUnknown, never return stale values.
func (c *churn) remoteDiagWorker(rng *rand.Rand, cl *opcua.Client, stop <-chan struct{}, seen *sync.Map, reads *atomic.Int64) {
	ctx := context.Background()
	for {
		select {
		case <-stop:
			return
		default:
		}
		comps := c.rt.Components()
		x, ok := pick(rng, comps)
		if !ok || x.Kind == pubsub.KindPublishedDataSet {
			continue
		}
		node, ok := c.srv.PubSubNodeID(x.ID)
		if !ok {
			continue
		}
		_ = c.wd.Do("remote diagnostics", func() error {
			diag, err := childNode(ctx, cl, node, "Diagnostics")
			if err != nil {
				return nil // removed in between
			}
			ctrs, err := childNode(ctx, cl, diag, "Counters")
			if err != nil {
				return nil
			}
			se, err1 := childNode(ctx, cl, ctrs, "StateError")
			lvl, err2 := childNode(ctx, cl, diag, "DiagnosticsLevel")
			te, err3 := childNode(ctx, cl, diag, "TotalError")
			if err1 != nil || err2 != nil || err3 != nil {
				return nil
			}
			dn := &diagNode{cid: x.ID, diag: diag, nodes: []*ua.NodeID{se, lvl, te}}
			seen.Store(diag.String(), dn)
			if rng.Intn(4) == 0 {
				res, err := cl.Call(ctx, &ua.CallMethodRequest{ObjectID: diag, MethodID: ua.NewNumericNodeID(0, id.PubSubDiagnosticsTypeReset)})
				if err == nil {
					switch res.StatusCode {
					case ua.StatusOK, ua.StatusBadNodeIDUnknown, ua.StatusBadNotFound:
					default:
						c.sink.Addf("Reset of %v: %v", diag, res.StatusCode)
					}
				}
				return nil
			}
			var rv []*ua.ReadValueID
			for _, n := range dn.nodes {
				rv = append(rv, &ua.ReadValueID{NodeID: n, AttributeID: ua.AttributeIDValue})
			}
			res, err := cl.Read(ctx, &ua.ReadRequest{NodesToRead: rv})
			if err != nil {
				return nil
			}
			reads.Add(1)
			for i, r := range res.Results {
				switch r.Status {
				case ua.StatusOK:
					if i == 1 {
						if l, ok := r.Value.Value().(int32); !ok || l < 0 || l > int32(ua.DiagnosticsLevelDebug) {
							c.sink.Addf("DiagnosticsLevel of %v reads %v", diag, r.Value.Value())
						}
					}
				case ua.StatusBadNodeIDUnknown, ua.StatusBadOutOfService:
				default:
					c.sink.Addf("read %v: %v", dn.nodes[i], r.Status)
				}
			}
			return nil
		})
	}
}

// TestChaosDiagnostics resets the diagnostics objects (Part 14 §9.1.11),
// changes their DiagnosticsLevel and reads them, through the Go API and
// through OPC UA clients (Read, Browse, the Reset method), while other
// workers add, remove, enable and disable components and the base stream
// flows. Every snapshot must be consistent, every operation must return in
// time with an expected status, the diagnostics objects of removed
// components must disappear from the address space, and every remaining
// component must have exactly one.
func TestChaosDiagnostics(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	c := newChurn(t)
	clients := []*opcua.Client{testutil.NewTestClient(t, c.url), testutil.NewTestClient(t, c.url)}
	var apiReads, remoteReads atomic.Int64
	var seen sync.Map
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c.apiWorker(rand.New(rand.NewSource(seed+int64(i))), stop)
		}()
		go func() {
			defer wg.Done()
			c.diagWorker(rand.New(rand.NewSource(seed+10+int64(i))), stop, &apiReads)
		}()
	}
	for i, cl := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.remoteDiagWorker(rand.New(rand.NewSource(seed+20+int64(i))), cl, stop, &seen, &remoteReads)
		}()
	}
	time.Sleep(chaoskit.Duration(t, defaultDuration))
	close(stop)
	c.wd.Wait("diagnostics workers", &wg)
	t.Logf("%d operations, %d API snapshots, %d remote reads", c.ops.Load(), apiReads.Load(), remoteReads.Load())
	if apiReads.Load() == 0 || remoteReads.Load() == 0 {
		t.Error("no diagnostics were read")
	}

	// The base stream still flows.
	c.chk.waitGrowth(t, 10, "base")

	// The diagnostics objects of removed components are gone; those of
	// the others are there, once each.
	ctx := context.Background()
	cl := clients[0]
	present := map[pubsub.ComponentID]bool{}
	for _, x := range c.rt.Components() {
		present[x.ID] = true
	}
	var gone, kept int
	seen.Range(func(_, v any) bool {
		dn := v.(*diagNode)
		if present[dn.cid] {
			kept++
			return true
		}
		gone++
		res, err := cl.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: dn.nodes[0], AttributeID: ua.AttributeIDValue}}})
		if err != nil {
			t.Errorf("read: %v", err)
			return true
		}
		if s := res.Results[0].Status; s != ua.StatusBadNodeIDUnknown {
			t.Errorf("the StateError counter %v of removed component %d reads %v", dn.nodes[0], dn.cid, s)
		}
		return true
	})
	t.Logf("%d diagnostics objects of removed components, %d of present ones", gone, kept)
	for _, x := range c.rt.Components() {
		if x.Kind == pubsub.KindPublishedDataSet {
			continue
		}
		node, ok := c.srv.PubSubNodeID(x.ID)
		if !ok {
			continue
		}
		refs, err := cl.Node(node).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassObject, true)
		if err != nil {
			if errors.Is(err, ua.StatusBadNodeIDUnknown) {
				continue
			}
			t.Fatal(err)
		}
		n := 0
		for _, r := range refs {
			if r.BrowseName.Name == "Diagnostics" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%v %q has %d Diagnostics objects", x.Kind, x.Name, n)
		}
		d, err := c.rt.Diagnostics(x.ID)
		if err == nil {
			checkDiagnostics(c.sink, &d)
		}
	}
	c.sink.Report(t)
}
