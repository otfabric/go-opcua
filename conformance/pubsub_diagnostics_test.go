// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// The PubSub diagnostics objects (Part 14 §9.1.11) read, browsed and reset
// through OPC UA clients, against what the runtimes report.

// psChild browses one level below n for a BrowseName.
func psChild(ctx context.Context, c *opcua.Client, n *ua.NodeID, name string) (*ua.NodeID, error) {
	refs, err := c.Node(n).References(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	if err != nil {
		return nil, err
	}
	for _, r := range refs {
		if r.BrowseName != nil && r.BrowseName.Name == name {
			return r.NodeID.NodeID, nil
		}
	}
	return nil, fmt.Errorf("no %q below %v", name, n)
}

func psChildren(ctx context.Context, c *opcua.Client, n *ua.NodeID) (map[string]*ua.NodeID, error) {
	refs, err := c.Node(n).References(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	if err != nil {
		return nil, err
	}
	out := map[string]*ua.NodeID{}
	for _, r := range refs {
		if r.BrowseName != nil {
			out[r.BrowseName.Name] = r.NodeID.NodeID
		}
	}
	return out, nil
}

// psDiagObject is the diagnostics object of a component in the address
// space: the NodeIds of its variables by path ("TotalError",
// "Counters/StateError", "Counters/StateError/TimeFirstChange",
// "LiveValues/ResolvedAddress", ...).
type psDiagObject struct {
	cid   pubsub.ComponentID
	name  string
	node  *ua.NodeID
	paths []string
	nodes []*ua.NodeID
}

// psDiagObjects browses the diagnostics objects of the runtime of a server
// and of all its components but the published data sets.
func psDiagObjects(t *testing.T, srv *server.Server, c *opcua.Client) []*psDiagObject {
	t.Helper()
	ctx := context.Background()
	var out []*psDiagObject
	rt := srv.PubSub()
	comps := append([]pubsub.ComponentInfo{{ID: pubsub.Root, Kind: pubsub.KindPubSub, Name: "PublishSubscribe"}}, rt.Components()...)
	for _, ci := range comps {
		if ci.Kind == pubsub.KindPublishedDataSet {
			continue
		}
		o := &psDiagObject{cid: ci.ID, name: fmt.Sprintf("%v %s", ci.Kind, ci.Name)}
		if ci.ID == pubsub.Root {
			o.node = ua.NewNumericNodeID(0, id.PublishSubscribeDiagnostics)
		} else {
			n, ok := srv.PubSubNodeID(ci.ID)
			require.True(t, ok, o.name)
			var err error
			o.node, err = psChild(ctx, c, n, "Diagnostics")
			require.NoError(t, err, o.name)
		}
		top, err := psChildren(ctx, c, o.node)
		require.NoError(t, err)
		add := func(path string, n *ua.NodeID) {
			o.paths = append(o.paths, path)
			o.nodes = append(o.nodes, n)
		}
		for _, p := range []string{"DiagnosticsLevel", "TotalError", "TotalInformation", "SubError"} {
			require.Contains(t, top, p, o.name)
			add(p, top[p])
		}
		for _, folder := range []string{"Counters", "LiveValues"} {
			require.Contains(t, top, folder, o.name)
			vars, err := psChildren(ctx, c, top[folder])
			require.NoError(t, err)
			for name, n := range vars {
				add(folder+"/"+name, n)
				if folder != "Counters" {
					continue
				}
				props, err := psChildren(ctx, c, n)
				require.NoError(t, err)
				for _, p := range []string{"Active", "TimeFirstChange"} {
					require.Contains(t, props, p, "%s %s", o.name, name)
					add(folder+"/"+name+"/"+p, props[p])
				}
			}
		}
		out = append(out, o)
	}
	return out
}

// psLiveValueLevel is the DiagnosticsLevel of a LiveValue (Part 14
// §9.1.11.7 to §9.1.11.12).
func psLiveValueLevel(name string) ua.DiagnosticsLevel {
	switch name {
	case "ConfiguredDataSetWriters", "ConfiguredDataSetReaders", "OperationalDataSetWriters", "OperationalDataSetReaders", "ResolvedAddress":
		return ua.DiagnosticsLevelBasic
	}
	return ua.DiagnosticsLevelInfo
}

func psSameTime(got any, want time.Time) bool {
	g, ok := got.(time.Time)
	if !ok {
		return false
	}
	if want.IsZero() {
		return g.IsZero() || g.Year() <= 1601
	}
	d := g.Sub(want)
	return d > -time.Microsecond && d < time.Microsecond
}

// psCompareDiag compares the diagnostics object o as the client reads it
// with d; it returns the differences.
func psCompareDiag(o *psDiagObject, d *pubsub.Diagnostics, res []*ua.DataValue) []string {
	var diffs []string
	bad := func(path string, got *ua.DataValue, want any) {
		var v any
		if got.Value != nil {
			v = got.Value.Value()
		}
		diffs = append(diffs, fmt.Sprintf("%s %s: read %v (%v), runtime %v", o.name, path, v, got.Status, want))
	}
	for i, path := range o.paths {
		r := res[i]
		var v any
		if r.Status == ua.StatusOK && r.Value != nil {
			v = r.Value.Value()
		}
		parts := strings.Split(path, "/")
		switch {
		case path == "DiagnosticsLevel":
			if v != int32(d.Level) {
				bad(path, r, d.Level)
			}
		case path == "TotalError":
			if v != d.TotalError {
				bad(path, r, d.TotalError)
			}
		case path == "TotalInformation":
			if v != d.TotalInformation {
				bad(path, r, d.TotalInformation)
			}
		case path == "SubError":
			if v != d.SubError {
				bad(path, r, d.SubError)
			}
		case parts[0] == "Counters":
			var c *pubsub.DiagnosticsCounter
			for j := range d.Counters {
				if d.Counters[j].ID.String() == parts[1] {
					c = &d.Counters[j]
				}
			}
			if c == nil {
				diffs = append(diffs, fmt.Sprintf("%s: counter %s in the address space, not in the runtime", o.name, parts[1]))
				continue
			}
			switch {
			case len(parts) == 2 && c.Active:
				if v != c.Value {
					bad(path, r, c.Value)
				}
			case len(parts) == 2:
				if r.Status != ua.StatusBadOutOfService {
					bad(path, r, "Bad_OutOfService")
				}
			case parts[2] == "Active":
				if v != c.Active {
					bad(path, r, c.Active)
				}
			case parts[2] == "TimeFirstChange":
				if !psSameTime(v, c.TimeFirstChange) {
					bad(path, r, c.TimeFirstChange)
				}
			}
		case parts[0] == "LiveValues":
			if parts[1] == "TimeToNextTokenID" {
				continue // changes with the time
			}
			if psLiveValueLevel(parts[1]) > d.Level {
				if r.Status != ua.StatusBadOutOfService {
					bad(path, r, "Bad_OutOfService")
				}
				continue
			}
			f := reflect.ValueOf(d.LiveValues).FieldByName(parts[1])
			if !f.IsValid() {
				diffs = append(diffs, fmt.Sprintf("%s: LiveValue %s unknown to the runtime", o.name, parts[1]))
				continue
			}
			if want := f.Interface(); !reflect.DeepEqual(v, want) {
				bad(path, r, want)
			}
		}
	}
	return diffs
}

// psCheckDiagnostics reads all diagnostics objects of a server through the
// client until they match what the runtime reports between two identical
// snapshots, and returns the objects and the snapshots.
func psCheckDiagnostics(t *testing.T, srv *server.Server, c *opcua.Client) map[pubsub.ComponentID]pubsub.Diagnostics {
	t.Helper()
	ctx := context.Background()
	objs := psDiagObjects(t, srv, c)
	rt := srv.PubSub()
	var last []string
	var snap map[pubsub.ComponentID]pubsub.Diagnostics
	ok := func() bool {
		last = nil
		before := map[pubsub.ComponentID]pubsub.Diagnostics{}
		for _, o := range objs {
			d, err := rt.Diagnostics(o.cid)
			if err != nil {
				last = []string{err.Error()}
				return false
			}
			d.LiveValues.TimeToNextTokenID = 0 // changes with the time
			before[o.cid] = d
		}
		results := make([][]*ua.DataValue, len(objs))
		for i, o := range objs {
			var rv []*ua.ReadValueID
			for _, n := range o.nodes {
				rv = append(rv, &ua.ReadValueID{NodeID: n, AttributeID: ua.AttributeIDValue})
			}
			res, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: rv})
			if err != nil {
				last = []string{err.Error()}
				return false
			}
			results[i] = res.Results
		}
		for _, o := range objs {
			d, err := rt.Diagnostics(o.cid)
			d.LiveValues.TimeToNextTokenID = 0
			if err != nil || !reflect.DeepEqual(d, before[o.cid]) {
				last = []string{"the runtime's diagnostics changed during the read: " + o.name}
				return false
			}
		}
		for i, o := range objs {
			d := before[o.cid]
			last = append(last, psCompareDiag(o, &d, results[i])...)
		}
		snap = before
		return len(last) == 0
	}
	deadline := time.Now().Add(waitTimeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("the diagnostics read through the client do not match the runtime's:\n%s", strings.Join(last, "\n"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	return snap
}

// TestPubSub_DiagnosticsThroughClient runs a publishing server and two
// subscribing servers, one with the keys of the publisher and one with
// other keys, over one segment, with DiagnosticsLevels set per component.
// Every diagnostics object read through an OPC UA client (Browse, Read)
// must show what pubsub.Diagnostics reports: levels, counters, Active,
// TimeFirstChange, Bad_OutOfService for inactive counters and LiveValues,
// totals, SubError. The decryption errors of the subscriber with the
// wrong keys show as errors up to its PublishSubscribe object. The Reset
// methods called through the client clear the counters of their object,
// and only those.
func TestPubSub_DiagnosticsThroughClient(t *testing.T) {
	parallel(t)
	ringA, ringB := psRing(t, "sg"), psRing(t, "sg")
	pubSrv, pubURL := newServer(t, server.WithPubSub(nil, pubsub.WithKeySource("sg", ringA)))
	subSrv, subURL := newServer(t, server.WithPubSub(nil, pubsub.WithKeySource("sg", ringA)))
	badSrv, badURL := newServer(t, server.WithPubSub(nil, pubsub.WithKeySource("sg", ringB), pubsub.WithDiagnosticsLevel(ua.DiagnosticsLevelDebug)))
	ns := server.NewNodeNameSpace(pubSrv, "urn:pubsub:diagnostics:pub")
	pub, sub, bad := pubSrv.PubSub(), subSrv.PubSub(), badSrv.PubSub()
	seg := psMemURL(t)
	ctx := context.Background()

	v := ns.AddNewVariableStringNode("v", int32(3))
	pds := pubsub.PublishedDataItems("pds", pubsub.Var("v", v.ID(), ua.TypeIDInt32))
	_, err := pub.AddPublishedDataSet(pds)
	require.NoError(t, err)
	pc, err := pub.AddConnection(pubsub.UDPConnection("pub", seg, uint16(31)))
	require.NoError(t, err)
	plainWG, err := pub.AddWriterGroup(pc, pubsub.WriterGroup("plain", 1, psInterval, pubsub.DataSetWriter("w", 1, "pds")))
	require.NoError(t, err)
	secureWG, err := pub.AddWriterGroup(pc, pubsub.Secure(pubsub.WriterGroup("secure", 2, psInterval, pubsub.DataSetWriter("w", 2, "pds")), ua.MessageSecurityModeSignAndEncrypt, "sg"))
	require.NoError(t, err)
	readers := map[*pubsub.PubSub]map[string]pubsub.ComponentID{}
	for _, rt := range []*pubsub.PubSub{sub, bad} {
		cid, err := rt.AddConnection(pubsub.UDPConnection("sub", seg, nil))
		require.NoError(t, err)
		readers[rt] = map[string]pubsub.ComponentID{}
		for _, g := range []struct {
			name string
			gid  uint16
			mode ua.MessageSecurityMode
		}{{"plain", 1, ua.MessageSecurityModeNone}, {"secure", 2, ua.MessageSecurityModeSignAndEncrypt}} {
			rg := pubsub.ReaderGroup(g.name, pubsub.DataSetReader("r", uint16(31), g.gid, g.gid, pubsub.DataSetMetaDataOf(pds)))
			if g.mode != ua.MessageSecurityModeNone {
				pubsub.Secure(rg, g.mode, "sg")
			}
			gid, err := rt.AddReaderGroup(cid, rg)
			require.NoError(t, err)
			readers[rt][g.name] = gid
			rid, ok := rt.Lookup(pubsub.KindDataSetReader, gid, "r")
			require.True(t, ok)
			readers[rt][g.name+"/r"] = rid
		}
	}
	// Levels per object: Debug for the secured reader of the subscriber,
	// Info for the secured writer group and the plain reader group;
	// everything else stays Basic (the bad subscriber: Debug).
	require.NoError(t, sub.SetDiagnosticsLevel(readers[sub]["secure/r"], ua.DiagnosticsLevelDebug))
	require.NoError(t, sub.SetDiagnosticsLevel(readers[sub]["plain"], ua.DiagnosticsLevelInfo))
	require.NoError(t, pub.SetDiagnosticsLevel(secureWG, ua.DiagnosticsLevelInfo))

	// Traffic, then a quiet publisher: its writer groups are disabled
	// through the Disable method.
	eventually(t, func() bool {
		for _, r := range []string{"plain/r", "secure/r"} {
			st, err := sub.Status(readers[sub][r])
			if err != nil || st.Counters.DataSetMessagesReceived < 5 {
				return false
			}
		}
		d, err := bad.Diagnostics(readers[bad]["secure/r"])
		if err != nil {
			return false
		}
		c, _ := d.Counter(pubsub.CounterDecryptionErrors)
		return c.Value >= 5
	}, "data reaches the subscriber, and the bad subscriber fails to decrypt it")
	pcl := newClient(t, pubURL)
	rc := remote.New(pcl)
	for _, wg := range []pubsub.ComponentID{plainWG, secureWG} {
		n, ok := pubSrv.PubSubNodeID(wg)
		require.True(t, ok)
		require.NoError(t, rc.Disable(ctx, n))
	}

	clients := map[*server.Server]*opcua.Client{pubSrv: pcl, subSrv: newClient(t, subURL), badSrv: newClient(t, badURL)}
	for _, srv := range []*server.Server{pubSrv, subSrv, badSrv} {
		snap := psCheckDiagnostics(t, srv, clients[srv])
		// Some counters are inactive at the levels below Debug.
		inactive := 0
		for _, d := range snap {
			for _, c := range d.Counters {
				if !c.Active {
					inactive++
				}
			}
		}
		if srv != badSrv {
			require.NotZero(t, inactive)
		}
	}

	// The writer groups were disabled by method.
	for _, wg := range []pubsub.ComponentID{plainWG, secureWG} {
		d, err := pub.Diagnostics(wg)
		require.NoError(t, err)
		c, _ := d.Counter(pubsub.CounterStateDisabledByMethod)
		require.Equal(t, uint32(1), c.Value)
	}
	// The wrong keys: errors of the secured reader and its group, SubError
	// up to PublishSubscribe.
	bc := clients[badSrv]
	for _, cid := range []pubsub.ComponentID{readers[bad]["secure/r"], readers[bad]["secure"]} {
		d, err := bad.Diagnostics(cid)
		require.NoError(t, err)
		c, _ := d.Counter(pubsub.CounterDecryptionErrors)
		require.NotZero(t, c.Value)
		require.NotZero(t, d.TotalError)
	}
	// SubError: the connection has a group with errors. (It looks at the
	// TotalError of the direct children only, so PublishSubscribe, whose
	// connection has no errors of its own, does not show it.)
	badConn := psComponent(t, bad, pubsub.KindConnection, "sub")
	cd, err := bad.Diagnostics(badConn)
	require.NoError(t, err)
	require.True(t, cd.SubError)
	require.Zero(t, cd.TotalError)

	// Reset of the secured reader of the subscriber through its method.
	sc := clients[subSrv]
	rn, ok := subSrv.PubSubNodeID(readers[sub]["secure/r"])
	require.True(t, ok)
	diag, err := psChild(ctx, sc, rn, "Diagnostics")
	require.NoError(t, err)
	before, err := sub.Diagnostics(readers[sub]["secure/r"])
	require.NoError(t, err)
	require.NotZero(t, before.TotalInformation)
	res, err := sc.Call(ctx, &ua.CallMethodRequest{ObjectID: diag, MethodID: ua.NewNumericNodeID(0, id.PubSubDiagnosticsTypeReset)})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	after, err := sub.Diagnostics(readers[sub]["secure/r"])
	require.NoError(t, err)
	require.Zero(t, after.TotalInformation)
	require.Zero(t, after.TotalError)
	for _, c := range after.Counters {
		require.Zero(t, c.Value, c.ID)
		require.True(t, c.TimeFirstChange.IsZero(), c.ID)
	}
	// Not the counters of the parent, nor those of Status.
	pd, err := sub.Diagnostics(readers[sub]["secure"])
	require.NoError(t, err)
	require.NotZero(t, pd.TotalInformation)
	st, err := sub.Status(readers[sub]["secure/r"])
	require.NoError(t, err)
	require.NotZero(t, st.Counters.DataSetMessagesReceived)

	// Reset of the bad subscriber's PublishSubscribe object (the standard
	// node, i=17421).
	res, err = bc.Call(ctx, &ua.CallMethodRequest{ObjectID: ua.NewNumericNodeID(0, id.PublishSubscribeDiagnostics), MethodID: ua.NewNumericNodeID(0, id.PublishSubscribeDiagnosticsReset)})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	root, err := bad.Diagnostics(pubsub.Root)
	require.NoError(t, err)
	require.Zero(t, root.TotalError)
	require.Zero(t, root.TotalInformation)
	cd, err = bad.Diagnostics(badConn)
	require.NoError(t, err)
	require.True(t, cd.SubError, "the children keep their errors")

	// A level raised through the Go API: the counters that become active
	// start at 0, and the client sees it.
	require.NoError(t, sub.SetDiagnosticsLevel(readers[sub]["plain/r"], ua.DiagnosticsLevelDebug))
	for _, srv := range []*server.Server{subSrv, badSrv} {
		psCheckDiagnostics(t, srv, clients[srv])
	}
	// A component removed through the client takes its diagnostics object
	// along.
	src := remote.New(sc)
	gn, ok := subSrv.PubSubNodeID(readers[sub]["plain"])
	require.True(t, ok)
	rdiag, err := psChild(ctx, sc, mustNode(t, subSrv, readers[sub]["plain/r"]), "Diagnostics")
	require.NoError(t, err)
	cn, ok := subSrv.PubSubNodeID(psComponent(t, sub, pubsub.KindConnection, "sub"))
	require.True(t, ok)
	require.NoError(t, src.RemoveGroup(ctx, cn, gn))
	eventually(t, func() bool {
		dvs, err := sc.Node(rdiag).Attributes(ctx, ua.AttributeIDBrowseName)
		return err == nil && len(dvs) == 1 && dvs[0].Status == ua.StatusBadNodeIDUnknown
	}, "the diagnostics object of a removed reader leaves the address space")
	psCheckDiagnostics(t, subSrv, sc)
}

func mustNode(t *testing.T, srv *server.Server, cid pubsub.ComponentID) *ua.NodeID {
	t.Helper()
	n, ok := srv.PubSubNodeID(cid)
	require.True(t, ok)
	return n
}
