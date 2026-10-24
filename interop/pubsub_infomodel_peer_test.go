//go:build interop

// SPDX-License-Identifier: MIT

// The PublishSubscribe information model (Part 14 §9) between go-opcua and
// open62541: configuration methods and browsing.
// COVERAGE.md: pubsub / pubsub.infomodel.methods, pubsub.infomodel.browse
//
//   - go-opcua client (pubsub/remote) → open62541 server: AddPublishedDataItems,
//     AddConnection with a WriterGroup and DataSetWriter, AddReaderGroup,
//     AddDataSetReader, Enable / Disable, the Remove methods, and the listing
//     of the components. The components built this way publish to and
//     receive from go-opcua.
//   - open62541 client (adapter "call", "browse", "read") → go-opcua server
//     with WithPubSub: AddConnection, Enable / Disable on the Status object,
//     RemoveConnection, browsing the PublishSubscribe tree; the connection
//     built this way publishes to go-opcua.
//
// Method argument conventions of open62541 1.5.9: opcua-interop
// docs/CLIENT_CONTRACT.md §14.6.

package interop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

func componentNames(cs []remote.Component) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func findComponent(t *testing.T, cs []remote.Component, name string) *ua.NodeID {
	t.Helper()
	for _, c := range cs {
		if c.Name == name {
			return c.NodeID
		}
	}
	t.Fatalf("no component %q in %v", name, componentNames(cs))
	return nil
}

// TestPubSubInfoModel_GoClient_Open62541: pubsub/remote configures an
// open62541 server through its PublishSubscribe methods.
func TestPubSubInfoModel_GoClient_Open62541(t *testing.T) {
	requirePubSubServer(t)
	hostPort, ch := psListenUDP(t) // open62541 publishes to the host
	readerPort := freeUDPPort(t)   // go-opcua publishes to open62541
	srv := startPubSubServer(t, pubsubServerOpts{
		config:   jobj{"configuration": jobj{"PublishedDataSets": []jobj{}, "Connections": []jobj{}, "Enabled": true}},
		udpPorts: []int{readerPort},
	})
	c := dialClient(t, srv.endpoint)
	ctx, ns := findNS(t, c)
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	r := remote.New(c)

	// AddPublishedDataItems (on PublishSubscribe.PublishedDataSets).
	vars := []psVar{{"Int32", 6, -1}, {"String", 12, -1}, {"Double", 11, -1}}
	var pvs []*ua.PublishedVariableDataType
	var aliases []string
	for _, v := range vars {
		pvs = append(pvs, &ua.PublishedVariableDataType{PublishedVariable: ua.NewStringNodeID(ns, "PubSub."+v.name), AttributeID: ua.AttributeIDValue})
		aliases = append(aliases, v.name)
	}
	pdi, err := r.AddPublishedDataItems(ctx, "RemoteDataSet", aliases, make([]ua.DataSetFieldFlags, len(vars)), pvs)
	if err != nil {
		t.Fatalf("AddPublishedDataItems: %v", err)
	}
	if pdi.DataSetNodeID == nil {
		t.Fatal("AddPublishedDataItems returned no DataSetNodeId")
	}

	// AddConnection with a WriterGroup (unicast destination: the host) and
	// a DataSetWriter of RemoteDataSet.
	wg := pubsub.WriterGroup("RemoteWG", 300, 100*time.Millisecond, pubsub.DataSetWriter("RemoteWriter", 3, "RemoteDataSet"))
	wg.TransportSettings = ua.NewExtensionObject(&ua.DatagramWriterGroupTransport2DataType{
		Address: ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: fmt.Sprintf("opc.udp://host.docker.internal:%d", hostPort)}),
	})
	conn, err := r.AddConnection(ctx, pubsub.AttachWriterGroups(
		pubsub.UDPConnection("RemoteConn", fmt.Sprintf("opc.udp://localhost:%d", readerPort), uint16(77)), wg))
	if err != nil {
		t.Fatalf("AddConnection: %v", err)
	}

	// Browse: the components are listed.
	conns := mustOK[[]remote.Component](t)(r.Connections(ctx))
	if got := findComponent(t, conns, "RemoteConn"); !got.Equal(conn) {
		t.Errorf("Connections lists RemoteConn as %v, AddConnection returned %v", got, conn)
	}
	if !slices.Contains(componentNames(mustOK[[]remote.Component](t)(r.PublishedDataSets(ctx))), "RemoteDataSet") {
		t.Error("PublishedDataSets does not list RemoteDataSet")
	}
	wgNode := findComponent(t, mustOK[[]remote.Component](t)(r.WriterGroups(ctx, conn)), "RemoteWG")
	writer := findComponent(t, mustOK[[]remote.Component](t)(r.DataSetWriters(ctx, wgNode)), "RemoteWriter")

	// open62541 creates the connection and the writer disabled.
	if st := mustOK[ua.PubSubState](t)(r.State(ctx, conn)); st != ua.PubSubStateDisabled {
		t.Errorf("new connection: %v, want Disabled (open62541 1.5.9)", st)
	}
	for _, n := range []*ua.NodeID{conn, writer} {
		if err := r.Enable(ctx, n); err != nil {
			t.Fatalf("Enable %v: %v", n, err)
		}
	}
	for name, n := range map[string]*ua.NodeID{"connection": conn, "writer group": wgNode, "writer": writer} {
		waitState(t, name, ua.PubSubStateOperational, 10*time.Second, func() ua.PubSubState { return mustOK[ua.PubSubState](t)(r.State(ctx, n)) })
	}

	// The writer built through the methods publishes RemoteDataSet.
	values := psValues(vars, psFresh())
	writePubSubVars(t, srv.endpoint, vars, values)
	c2 := psLiveCase{vars: vars}
	nm := psReceive(t, ch, psDecodeUADP(c2, nil), values, psReceiveTimeout)
	if !nm.PublisherID.Equal(message.NewPublisherID(message.PublisherIDUInt16, 77)) || nm.GroupHeader.WriterGroupID != 300 || nm.Messages[0].DataSetWriterID != 3 {
		t.Errorf("message from %v/%d/%d, want UInt16 77/300/3", nm.PublisherID, nm.GroupHeader.WriterGroupID, nm.Messages[0].DataSetWriterID)
	}

	// Disable stops the WriterGroup.
	if err := r.Disable(ctx, wgNode); err != nil {
		t.Fatalf("Disable the WriterGroup: %v", err)
	}
	if st := mustOK[ua.PubSubState](t)(r.State(ctx, wgNode)); st != ua.PubSubStateDisabled {
		t.Errorf("disabled WriterGroup: %v", st)
	}

	// AddReaderGroup / AddDataSetReader: a reader of go-opcua messages with
	// a TargetVariable. open62541 1.5.9 adds every TargetNodeId as a new
	// Variable (BrowseName = field name) below a folder named after the
	// DataSetMetaData and writes to it; an existing node (a fixture
	// variable) cannot be the target: the add fails and every write fails
	// with BadNodeIdUnknown (contrary to opcua-interop
	// docs/CLIENT_CONTRACT.md §14.6). So the target is a new node.
	rg, err := r.AddReaderGroup(ctx, conn, pubsub.ReaderGroup("RemoteRG"))
	if err != nil {
		t.Fatalf("AddReaderGroup: %v", err)
	}
	readerVars := []psVar{{"Double", 11, -1}}
	rd := pubsub.DataSetReader("RemoteReader", uint16(psPubID), psWriterGroupID, psWriterID, psMetaData(readerVars, 0))
	pubsub.SetTargetVariables(rd, pubsub.Target(ua.NewStringNodeID(ns, "PubSub.ViaMethod")))
	reader, err := r.AddDataSetReader(ctx, rg, rd)
	if err != nil {
		t.Fatalf("AddDataSetReader: %v", err)
	}
	findComponent(t, mustOK[[]remote.Component](t)(r.ReaderGroups(ctx, conn)), "RemoteRG")
	if got := findComponent(t, mustOK[[]remote.Component](t)(r.DataSetReaders(ctx, rg)), "RemoteReader"); !got.Equal(reader) {
		t.Errorf("DataSetReaders lists %v, AddDataSetReader returned %v", got, reader)
	}
	for _, n := range []*ua.NodeID{rg, reader} {
		if st := mustOK[ua.PubSubState](t)(r.State(ctx, n)); st == ua.PubSubStateDisabled {
			if err := r.Enable(ctx, n); err != nil {
				t.Fatalf("Enable %v: %v", n, err)
			}
		}
	}
	// open62541 1.5.9 opens the receive socket of a connection when the
	// connection is enabled and it has a ReaderGroup: a ReaderGroup added to
	// a running connection receives nothing until the connection is
	// disabled and enabled again.
	if err := r.Disable(ctx, conn); err != nil {
		t.Fatalf("Disable the connection: %v", err)
	}
	if err := r.Enable(ctx, conn); err != nil {
		t.Fatalf("Enable the connection: %v", err)
	}
	readerValues := psValues(readerVars, psFresh())
	send := psDial(t, transport.Config{ProfileURI: psProfileUDP, URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", srv.udpPort(t, readerPort))})
	psSendLoop(t, send, transport.PublishOptions{}, psUADPEncoder(t, psLiveCase{vars: readerVars}, readerValues))
	waitPubSubVars(t, srv.endpoint, []psVar{{"ViaMethod", 11, -1}}, readerValues, psReceiveTimeout)

	// The Remove methods.
	steps := []struct {
		name string
		do   func() error
	}{
		// open62541 1.5.9 removes a DataSetReader only from a disabled
		// ReaderGroup (else Bad_InternalError, "Removal of the
		// DataSetReader not possible while the ReaderGroup is enabled").
		{"Disable (reader group)", func() error { return r.Disable(ctx, rg) }},
		{"RemoveDataSetReader", func() error { return r.RemoveDataSetReader(ctx, rg, reader) }},
		{"RemoveGroup (reader group)", func() error { return r.RemoveGroup(ctx, conn, rg) }},
		{"RemoveDataSetWriter", func() error { return r.RemoveDataSetWriter(ctx, wgNode, writer) }},
		{"RemoveGroup (writer group)", func() error { return r.RemoveGroup(ctx, conn, wgNode) }},
		{"RemoveConnection", func() error { return r.RemoveConnection(ctx, conn) }},
		{"RemovePublishedDataSet", func() error { return r.RemovePublishedDataSet(ctx, pdi.DataSetNodeID) }},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
	}
	if names := componentNames(mustOK[[]remote.Component](t)(r.Connections(ctx))); slices.Contains(names, "RemoteConn") {
		t.Errorf("RemoteConn still listed after RemoveConnection: %v", names)
	}
	if names := componentNames(mustOK[[]remote.Component](t)(r.PublishedDataSets(ctx))); slices.Contains(names, "RemoteDataSet") {
		t.Errorf("RemoteDataSet still listed after RemovePublishedDataSet: %v", names)
	}
}

// adapterBrowse lists the references of a node with the open62541 adapter.
func adapterBrowse(t *testing.T, endpoint, node string) map[string]string {
	t.Helper()
	r := runOpen62541Client(t, endpoint, "browse", "--node", node)
	if !r.Success {
		t.Fatalf("browse %s: %s %s", node, r.ServiceResult, r.Error)
	}
	var items []struct {
		NodeID     string `json:"nodeId"`
		BrowseName struct {
			Name string `json:"name"`
		} `json:"browseName"`
	}
	if err := json.Unmarshal(r.Results, &items); err != nil {
		t.Fatalf("browse %s: %v", node, err)
	}
	out := map[string]string{}
	for _, it := range items {
		out[it.BrowseName.Name] = it.NodeID
	}
	return out
}

type adapterCallResult struct {
	StatusCode      statusCodeObj     `json:"statusCode"`
	OutputArguments []json.RawMessage `json:"outputArguments"`
}

// adapterCall calls a method with the open62541 adapter over None.
func adapterCall(t *testing.T, endpoint, object, method string, inputs ...string) adapterCallResult {
	t.Helper()
	args := []string{"--object", object, "--method", method}
	for _, in := range inputs {
		args = append(args, "--input", in)
	}
	r := runOpen62541ClientResult(t, endpoint, "call", args...)
	var items []adapterCallResult
	if err := json.Unmarshal(r.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("call %s on %s: %v; result %+v", method, object, err, r)
	}
	return items[0]
}

// adapterReadState reads a PubSubState variable with the open62541 adapter.
func adapterReadState(t *testing.T, endpoint, node string) ua.PubSubState {
	t.Helper()
	r := runOpen62541Client(t, endpoint, "read", "--node", node)
	var items []struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(r.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("read %s: %v %s", node, err, r.Results)
	}
	var v int32
	if err := json.Unmarshal(items[0].Value, &v); err != nil {
		t.Fatalf("read %s: value %s", node, items[0].Value)
	}
	return ua.PubSubState(v)
}

// TestPubSubInfoModel_Open62541Client_GoServer: the open62541 adapter client
// configures a go-opcua server with WithPubSub through the PublishSubscribe
// methods and browses its tree.
func TestPubSubInfoModel_Open62541Client_GoServer(t *testing.T) {
	requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "call")
	requirePubSubServer(t)
	port, ch := psListenUDP(t)
	vars := psVars
	srv := startGoPubSubServer(t, goPubSubOpts{}, func(p *pubsub.PubSub, ns uint16) {
		mustOK[pubsub.ComponentID](t)(p.AddPublishedDataSet(psRuntimeDataSet(vars, ns, 0)))
	})

	// AddConnection (i=17366 on PublishSubscribe i=14443) with a binary
	// PubSubConnectionDataType (DefaultBinary i=15694).
	cfg := pubsub.AttachWriterGroups(pubsub.UDPConnection("AdapterConn", fmt.Sprintf("opc.udp://127.0.0.1:%d", port), uint16(88)),
		pubsub.WriterGroup("AdapterWG", 400, 100*time.Millisecond, pubsub.DataSetWriter("AdapterWriter", 4, "InteropDataSet")))
	body, err := ua.Encode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res := adapterCall(t, srv.endpoint, "i=14443", "i=17366", "ExtensionObject:i=15694|"+base64.StdEncoding.EncodeToString(body))
	if res.StatusCode.Code != 0 || len(res.OutputArguments) != 1 {
		t.Fatalf("AddConnection: %s %s", res.StatusCode, res.OutputArguments)
	}
	var connNode string
	if err := json.Unmarshal(res.OutputArguments[0], &connNode); err != nil {
		t.Fatalf("ConnectionId %s: %v", res.OutputArguments[0], err)
	}
	connID, ok := srv.srv.PubSub().Lookup(pubsub.KindConnection, pubsub.Root, "AdapterConn")
	if !ok {
		t.Fatal("the go-opcua runtime has no connection AdapterConn")
	}

	// Browse: PublishSubscribe → connection → WriterGroup → DataSetWriter,
	// and the Status object of the connection.
	if got := adapterBrowse(t, srv.endpoint, "i=14443")["AdapterConn"]; got != connNode {
		t.Errorf("browse PublishSubscribe: AdapterConn is %q, AddConnection returned %q", got, connNode)
	}
	children := adapterBrowse(t, srv.endpoint, connNode)
	wgNode, ok := children["AdapterWG"]
	if !ok {
		t.Fatalf("browse %s: no AdapterWG in %v", connNode, children)
	}
	if _, ok := adapterBrowse(t, srv.endpoint, wgNode)["AdapterWriter"]; !ok {
		t.Errorf("browse %s: no AdapterWriter", wgNode)
	}
	status, ok := children["Status"]
	if !ok {
		t.Fatalf("browse %s: no Status in %v", connNode, children)
	}
	state := adapterBrowse(t, srv.endpoint, status)["State"]
	if state == "" {
		t.Fatalf("browse %s: no State", status)
	}

	// Enable (if the server created it disabled), then the connection
	// publishes.
	if adapterReadState(t, srv.endpoint, state) == ua.PubSubStateDisabled {
		if r := adapterCall(t, srv.endpoint, status, "i=14645"); r.StatusCode.Code != 0 {
			t.Fatalf("Enable: %s", r.StatusCode)
		}
	}
	values := psValues(vars, psFresh())
	writePubSubVars(t, srv.endpoint, vars, values)
	nm := psReceive(t, ch, psDecodeUADP(psLiveCase{vars: vars}, nil), values, psReceiveTimeout)
	if !nm.PublisherID.Equal(message.NewPublisherID(message.PublisherIDUInt16, 88)) || nm.GroupHeader.WriterGroupID != 400 || nm.Messages[0].DataSetWriterID != 4 {
		t.Errorf("message from %v/%d/%d, want UInt16 88/400/4", nm.PublisherID, nm.GroupHeader.WriterGroupID, nm.Messages[0].DataSetWriterID)
	}
	if got := adapterReadState(t, srv.endpoint, state); got != ua.PubSubStateOperational {
		t.Errorf("State read by open62541: %v, want Operational", got)
	}

	// Disable through the Status object.
	if r := adapterCall(t, srv.endpoint, status, "i=14646"); r.StatusCode.Code != 0 {
		t.Fatalf("Disable: %s", r.StatusCode)
	}
	if got := adapterReadState(t, srv.endpoint, state); got != ua.PubSubStateDisabled {
		t.Errorf("State after Disable: %v", got)
	}
	if st := mustOK[ua.PubSubState](t)(srv.srv.PubSub().State(connID)); st != ua.PubSubStateDisabled {
		t.Errorf("runtime state after Disable: %v", st)
	}
	if r := adapterCall(t, srv.endpoint, status, "i=14646"); r.StatusCode.Code != uint32(ua.StatusBadInvalidState) {
		t.Errorf("Disable of a disabled connection: %s, want BadInvalidState", r.StatusCode)
	}

	// RemoveConnection.
	if r := adapterCall(t, srv.endpoint, "i=14443", "i=17369", "NodeId:"+connNode); r.StatusCode.Code != 0 {
		t.Fatalf("RemoveConnection: %s", r.StatusCode)
	}
	if _, ok := srv.srv.PubSub().Lookup(pubsub.KindConnection, pubsub.Root, "AdapterConn"); ok {
		t.Error("the connection is still in the runtime")
	}
	if _, ok := adapterBrowse(t, srv.endpoint, "i=14443")["AdapterConn"]; ok {
		t.Error("the connection is still in the address space")
	}
	if r := adapterCall(t, srv.endpoint, "i=14443", "i=17369", "NodeId:"+connNode); r.StatusCode.Code == 0 {
		t.Error("RemoveConnection of a removed connection succeeded")
	}
}
