// SPDX-License-Identifier: MIT

package codec

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/schema"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// golden is the expected value of a variable of a NodeSet: its NodeId and the
// binary encoding of the Variant, decoded by this test from the <Value>
// element - independently of whatever the server keeps.
type golden struct {
	id  *ua.NodeID
	bin []byte
	// mutable: the value is an array or a structure, i.e. something that
	// hands out memory which a caller could write to.
	mutable bool
}

// decode returns a new copy of the value. The binary decoder does not copy a
// ByteString out of its input, so the copy is decoded from a copy of the
// encoding: what the caller does to the value must not reach g.bin.
func (g *golden) decode() (*ua.Variant, error) {
	v := new(ua.Variant)
	_, err := ua.Decode(bytes.Clone(g.bin), v)
	return v, err
}

var (
	builtinGoldenOnce sync.Once
	builtinGolden     []golden
	builtinGoldenErr  error
)

// goldenValues decodes the <Value> elements of the variables of a NodeSet2
// document. It cuts them out of the text instead of unmarshalling the
// document: under the race detector encoding/xml needs seconds for the
// standard NodeSet.
func goldenValues(doc []byte) ([]golden, error) {
	const (
		open, closing     = "<UAVariable ", "</UAVariable>"
		valOpen, valClose = "<Value>", "</Value>"
		idAttr            = `NodeId="`
	)
	var out []golden
	for {
		i := bytes.Index(doc, []byte(open))
		if i < 0 {
			break
		}
		doc = doc[i:]
		end := bytes.Index(doc, []byte(closing))
		if tagEnd := bytes.IndexByte(doc, '>'); tagEnd > 0 && doc[tagEnd-1] == '/' {
			doc = doc[tagEnd:] // an element without content
			continue
		}
		if end < 0 {
			return nil, fmt.Errorf("unterminated UAVariable")
		}
		block := doc[:end]
		doc = doc[end:]

		a := bytes.Index(block, []byte(idAttr))
		if a < 0 {
			return nil, fmt.Errorf("UAVariable without NodeId")
		}
		a += len(idAttr)
		id, err := ua.ParseNodeID(string(block[a : a+bytes.IndexByte(block[a:], '"')]))
		if err != nil {
			return nil, err
		}
		// The first <Value> is the one of the variable; structures in it
		// may have Value members of their own, so the last </Value> ends
		// it.
		from, to := bytes.Index(block, []byte(valOpen)), bytes.LastIndex(block, []byte(valClose))
		if from < 0 || to < from {
			continue
		}
		val := new(ua.Variant)
		if err := ua.DecodeXML(block[from:to+len(valClose)], val); err != nil || val.Type() == ua.TypeIDNull {
			continue
		}
		bin, err := ua.Encode(val)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		kind := reflect.ValueOf(val.Value()).Kind()
		out = append(out, golden{id: id, bin: bin, mutable: kind == reflect.Slice || kind == reflect.Pointer})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id.String() < out[j].id.String() })
	return out, nil
}

// builtinGoldenValues returns the values of the namespace-0 variables that a
// new server serves from the built-in NodeSet. Variables the server replaces
// with live ones (ServerStatus, capabilities) are left out: ref is a server
// that nobody has touched yet.
func builtinGoldenValues(t *testing.T, ref *server.Server) []golden {
	t.Helper()
	builtinGoldenOnce.Do(func() {
		all, err := goldenValues(schema.OpcUaNodeSet2)
		if err != nil {
			builtinGoldenErr = err
			return
		}
		for _, g := range all {
			// The type dictionaries (ByteStrings of several hundred
			// kilobytes) are left out: reading them from every server
			// in every phase is most of the run time and adds nothing.
			if len(g.bin) > 16<<10 {
				continue
			}
			if got, err := apiValue(ref, g.id); err == nil && bytes.Equal(got, g.bin) {
				builtinGolden = append(builtinGolden, g)
			}
		}
	})
	if builtinGoldenErr != nil {
		t.Fatal(builtinGoldenErr)
	}
	if len(builtinGolden) < 500 {
		t.Fatalf("only %d variables of the built-in NodeSet have a value", len(builtinGolden))
	}
	return builtinGolden
}

// apiValue reads the Value attribute through the server API and returns the
// binary encoding of the Variant.
func apiValue(srv *server.Server, id *ua.NodeID) ([]byte, error) {
	n := srv.Node(id)
	if n == nil {
		return nil, fmt.Errorf("%s: no such node", id)
	}
	av, err := n.Attribute(ua.AttributeIDValue)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	if av.Value == nil || av.Value.Value == nil {
		return nil, fmt.Errorf("%s: no value", id)
	}
	return ua.Encode(av.Value.Value)
}

// station is a started server with a connected client.
type station struct {
	name string
	srv  *server.Server
	c    *opcua.Client
}

func newStation(name string) (*station, error) {
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: server.New: %w", name, err)
	}
	return startStation(name, srv)
}

func startStation(name string, srv *server.Server) (*station, error) {
	if err := srv.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("%s: Start: %w", name, err)
	}
	c, err := opcua.NewClient(fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()),
		opcua.InsecureNoSecurity(),
		opcua.DialTimeout(30*time.Second),
		opcua.RequestTimeout(60*time.Second),
		opcua.AutoReconnect(false),
	)
	if err == nil {
		ctx, cancel := chaoskit.OpCtx()
		err = c.Connect(ctx)
		cancel()
	}
	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("%s: client: %w", name, err)
	}
	return &station{name: name, srv: srv, c: c}, nil
}

func (s *station) close() {
	if s == nil {
		return
	}
	chaoskit.CloseClient(s.c, nil)
	_ = s.srv.Close()
}

// clientValues reads the Value attribute of the nodes through the client and
// returns the binary encodings of the Variants, nil for a variable the
// session is not allowed to read.
func (s *station) clientValues(ids []*ua.NodeID) ([][]byte, error) {
	out := make([][]byte, 0, len(ids))
	for len(ids) > 0 {
		n := min(len(ids), 200)
		req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
		for _, id := range ids[:n] {
			req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{NodeID: id, AttributeID: ua.AttributeIDValue})
		}
		ctx, cancel := chaoskit.OpCtx()
		resp, err := s.c.Read(ctx, req)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("%s: Read: %w", s.name, err)
		}
		if len(resp.Results) != n {
			return nil, fmt.Errorf("%s: Read returned %d results for %d nodes", s.name, len(resp.Results), n)
		}
		for i, r := range resp.Results {
			switch r.Status {
			case ua.StatusOK:
			case ua.StatusBadSecurityModeInsufficient, ua.StatusBadUserAccessDenied, ua.StatusBadNotReadable:
				// Some variables of namespace 0 are not for an
				// anonymous session on an unsecured channel.
				out = append(out, nil)
				continue
			default:
				return nil, fmt.Errorf("%s: Read %s: %v", s.name, ids[i], r.Status)
			}
			if r.Value == nil {
				return nil, fmt.Errorf("%s: Read %s: no value", s.name, ids[i])
			}
			bin, err := ua.Encode(r.Value)
			if err != nil {
				return nil, err
			}
			out = append(out, bin)
		}
		ids = ids[n:]
	}
	return out, nil
}

// verify checks that the station serves the golden values, through the
// server API and through the client. skip names nodes that were changed on
// this station on purpose.
func (s *station) verify(want []golden, skip map[string]bool) error {
	var ids []*ua.NodeID
	var expect [][]byte
	for _, g := range want {
		if skip[g.id.String()] {
			continue
		}
		got, err := apiValue(s.srv, g.id)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		if !bytes.Equal(got, g.bin) {
			return fmt.Errorf("%s: %s: the server API serves a value that is not the one of the NodeSet\n want: %x\n got:  %x", s.name, g.id, clipBytes(g.bin), clipBytes(got))
		}
		ids = append(ids, g.id)
		expect = append(expect, g.bin)
	}
	got, err := s.clientValues(ids)
	if err != nil {
		return err
	}
	denied := 0
	for i := range ids {
		if got[i] == nil {
			denied++
			continue
		}
		if !bytes.Equal(got[i], expect[i]) {
			return fmt.Errorf("%s: %s: a client reads a value that is not the one of the NodeSet\n want: %x\n got:  %x", s.name, ids[i], clipBytes(expect[i]), clipBytes(got[i]))
		}
	}
	if denied > len(ids)/4 {
		return fmt.Errorf("%s: the client was denied %d of %d values", s.name, denied, len(ids))
	}
	return nil
}

// scramble overwrites everything it can reach through v: the elements of
// slices, what pointers point to, the exported fields of structures and the
// bodies of ExtensionObjects. It is what a careless application does with a
// value it got from the server. It reports whether it wrote anything.
func scramble(v reflect.Value, depth int) bool {
	if depth > 6 || !v.IsValid() {
		return false
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return false
		}
		return scramble(v.Elem(), depth+1)
	case reflect.Slice:
		wrote := false
		for i := 0; i < v.Len(); i++ {
			if scramble(v.Index(i), depth+1) {
				wrote = true
			}
		}
		return wrote
	case reflect.Struct:
		wrote := false
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			// The masks and type ids stay: the value must remain
			// something the mutating server itself can still encode.
			if name := v.Type().Field(i).Name; !f.CanSet() || name == "EncodingMask" || name == "TypeID" {
				continue
			}
			if scramble(f, depth+1) {
				wrote = true
			}
		}
		return wrote
	default:
	}
	if !v.CanSet() {
		return false
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString("HACKED")
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(v.Int() ^ 0x55)
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() ^ 0x55)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(v.Float() + 12345)
	default:
		return false
	}
	return true
}

// TestNodeSet_ServersInParallel creates servers concurrently and reads the
// values of the namespace-0 variables that come from the built-in NodeSet,
// through the server API and through clients. The NodeSet is parsed and its
// values are decoded once per process; this test is about what the servers
// share as a result.
//
// One server then scrambles in place every array and structure value its API
// hands out, a second one replaces values with Node.SetAttribute, a third one
// is written to by its client, a fourth one's client scrambles what it read -
// while the remaining servers keep serving reads.
//
// Invariants: no data race, no panic, no deadlock, no goroutine leak (the
// package's TestMain checks); every server serves exactly the values of the
// NodeSet for every variable that was not changed on that very server - the
// servers running next to the mutated ones as well as a server created
// afterwards.
func TestNodeSet_ServersInParallel(t *testing.T) {
	t.Parallel()
	_ = chaoskit.Seed(t)
	wd := chaoskit.NewWatchdog(t)

	began := time.Now()
	const numStations = 5
	var (
		stations = make([]*station, numStations)
		errs     = make([]error, numStations)
		wg       sync.WaitGroup
		start    = make(chan struct{})
	)
	t.Cleanup(func() {
		for _, s := range stations {
			s.close()
		}
	})
	for i := range stations {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = wd.Do("server.New + Start + Connect", func() error {
				var err error
				stations[i], err = newStation(fmt.Sprintf("server %d", i))
				return err
			})
		}(i)
	}
	close(start)
	wd.Wait("starting the servers", &wg)
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	// The reference: an untouched server, compared with what this test
	// decodes from the NodeSet itself.
	ref, err := server.New(server.EndPoint("localhost", 0))
	if err != nil {
		t.Fatal(err)
	}
	want := builtinGoldenValues(t, ref)
	var mutable []golden
	for _, g := range want {
		if g.mutable {
			mutable = append(mutable, g)
		}
	}
	if len(mutable) < 100 {
		t.Fatalf("only %d array or structure values in the built-in NodeSet", len(mutable))
	}

	// Phase 1: all servers serve the NodeSet values, concurrently.
	parallelDo := func(what string, fn func(i int, s *station) error) {
		t.Helper()
		var wg sync.WaitGroup
		errs := make([]error, len(stations))
		for i, s := range stations {
			wg.Add(1)
			go func(i int, s *station) {
				defer wg.Done()
				errs[i] = wd.Do(what, func() error { return fn(i, s) })
			}(i, s)
		}
		wd.Wait(what, &wg)
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("%d servers started: %v", numStations, time.Since(began).Round(time.Millisecond))
	parallelDo("first read", func(_ int, s *station) error { return s.verify(want, nil) })
	t.Logf("first read: %v", time.Since(began).Round(time.Millisecond))

	// Phase 2: four servers are mutated, each in its own way, while the
	// others are read.
	changed := make([]map[string]bool, numStations)
	var wrote [numStations]int
	parallelDo("mutation", func(i int, s *station) error {
		changed[i] = map[string]bool{}
		switch i {
		case 0: // scramble in place what the server API hands out
			for _, g := range mutable {
				av, err := s.srv.Node(g.id).Attribute(ua.AttributeIDValue)
				if err != nil {
					return err
				}
				if scramble(reflect.ValueOf(av.Value.Value.Value()), 0) {
					wrote[i]++
				}
				changed[i][g.id.String()] = true
			}
		case 1: // replace the value on the server side
			for k, g := range mutable {
				if k%3 != 0 {
					continue
				}
				cur, err := g.decode()
				if err != nil {
					return err
				}
				scramble(reflect.ValueOf(cur.Value()), 0)
				dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: cur}
				if err := s.srv.Node(g.id).SetAttribute(ua.AttributeIDValue, dv); err == nil {
					wrote[i]++
				}
				changed[i][g.id.String()] = true
			}
		case 2: // write through the client
			req := &ua.WriteRequest{}
			for k, g := range mutable {
				if k%3 != 1 {
					continue
				}
				cur, err := g.decode()
				if err != nil {
					return err
				}
				scramble(reflect.ValueOf(cur.Value()), 0)
				req.NodesToWrite = append(req.NodesToWrite, &ua.WriteValue{
					NodeID:      g.id,
					AttributeID: ua.AttributeIDValue,
					Value:       &ua.DataValue{EncodingMask: ua.DataValueValue, Value: cur},
				})
				changed[i][g.id.String()] = true
			}
			ctx, cancel := chaoskit.OpCtx()
			defer cancel()
			resp, err := s.c.Write(ctx, req)
			if err != nil {
				return fmt.Errorf("%s: Write: %w", s.name, err)
			}
			for _, st := range resp.Results {
				if st == ua.StatusOK {
					wrote[i]++
				}
			}
		case 3: // scramble what a client read
			for k, g := range mutable {
				if k%10 != 0 {
					continue
				}
				ctx, cancel := chaoskit.OpCtx()
				dv, err := s.c.Node(g.id).Value(ctx)
				cancel()
				if stderrors.Is(err, ua.StatusBadSecurityModeInsufficient) || stderrors.Is(err, ua.StatusBadUserAccessDenied) {
					continue // not for an anonymous session
				}
				if err != nil {
					return fmt.Errorf("%s: read %s: %w", s.name, g.id, err)
				}
				if scramble(reflect.ValueOf(dv.Value()), 0) {
					wrote[i]++
				}
			}
		default: // keep reading
			return s.verify(want, nil)
		}
		return nil
	})
	t.Logf("%d NodeSet values (%d arrays or structures); scrambled in place: %d, SetAttribute: %d, client writes accepted: %d, scrambled client copies: %d",
		len(want), len(mutable), wrote[0], wrote[1], wrote[2], wrote[3])
	if wrote[0] == 0 || wrote[1] == 0 {
		t.Fatalf("the mutations did not happen: %v", wrote)
	}

	// Phase 3: nothing leaked from one server into another, or into the
	// values a new server starts with.
	t.Logf("mutations: %v", time.Since(began).Round(time.Millisecond))
	parallelDo("read after the mutations", func(i int, s *station) error { return s.verify(want, changed[i]) })
	t.Logf("read after the mutations: %v", time.Since(began).Round(time.Millisecond))

	late, err := newStation("server created after the mutations")
	if err != nil {
		t.Fatal(err)
	}
	defer late.close()
	if err := late.verify(want, nil); err != nil {
		t.Error(err)
	}
	// The untouched reference server from the beginning as well.
	for _, g := range want {
		if got, err := apiValue(ref, g.id); err != nil || !bytes.Equal(got, g.bin) {
			t.Fatalf("reference server: %s changed: %v", g.id, err)
		}
	}
}

// importNodeSet is a NodeSet2 document with values of every shape: scalar,
// array, matrix, LocalizedText array and structures.
const importNodeSet = `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <NamespaceUris><Uri>urn:chaos:codec</Uri></NamespaceUris>
  <Aliases>
    <Alias Alias="Int32">i=6</Alias>
    <Alias Alias="Double">i=11</Alias>
    <Alias Alias="String">i=12</Alias>
    <Alias Alias="LocalizedText">i=21</Alias>
    <Alias Alias="Argument">i=296</Alias>
    <Alias Alias="Range">i=884</Alias>
  </Aliases>
  <UAVariable NodeId="ns=1;i=6001" BrowseName="1:Scalar" DataType="Int32">
    <DisplayName>Scalar</DisplayName>
    <Value><uax:Int32>42</uax:Int32></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6002" BrowseName="1:Array" DataType="Double" ValueRank="1" ArrayDimensions="3">
    <DisplayName>Array</DisplayName>
    <Value><uax:ListOfDouble><uax:Double>1.5</uax:Double><uax:Double>2.5</uax:Double><uax:Double>3.5</uax:Double></uax:ListOfDouble></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6003" BrowseName="1:Arguments" DataType="Argument" ValueRank="1" ArrayDimensions="2">
    <DisplayName>Arguments</DisplayName>
    <Value>
      <uax:ListOfExtensionObject>
        <uax:ExtensionObject>
          <uax:TypeId><uax:Identifier>i=297</uax:Identifier></uax:TypeId>
          <uax:Body><uax:Argument>
            <uax:Name>Speed</uax:Name>
            <uax:DataType><uax:Identifier>i=11</uax:Identifier></uax:DataType>
            <uax:ValueRank>-1</uax:ValueRank>
            <uax:ArrayDimensions />
            <uax:Description><uax:Text>target speed</uax:Text></uax:Description>
          </uax:Argument></uax:Body>
        </uax:ExtensionObject>
        <uax:ExtensionObject>
          <uax:TypeId><uax:Identifier>i=297</uax:Identifier></uax:TypeId>
          <uax:Body><uax:Argument>
            <uax:Name>Ramp</uax:Name>
            <uax:DataType><uax:Identifier>i=6</uax:Identifier></uax:DataType>
            <uax:ValueRank>1</uax:ValueRank>
            <uax:ArrayDimensions><uax:UInt32>4</uax:UInt32></uax:ArrayDimensions>
            <uax:Description><uax:Locale>en</uax:Locale><uax:Text>ramp</uax:Text></uax:Description>
          </uax:Argument></uax:Body>
        </uax:ExtensionObject>
      </uax:ListOfExtensionObject>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6004" BrowseName="1:Matrix" DataType="Int32" ValueRank="2" ArrayDimensions="2,2">
    <DisplayName>Matrix</DisplayName>
    <Value><uax:Matrix>
      <uax:Dimensions><uax:Int32>2</uax:Int32><uax:Int32>2</uax:Int32></uax:Dimensions>
      <uax:Elements><uax:Int32>1</uax:Int32><uax:Int32>2</uax:Int32><uax:Int32>3</uax:Int32><uax:Int32>4</uax:Int32></uax:Elements>
    </uax:Matrix></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6005" BrowseName="1:Texts" DataType="LocalizedText" ValueRank="1">
    <DisplayName>Texts</DisplayName>
    <Value><uax:ListOfLocalizedText>
      <uax:LocalizedText><uax:Locale>en</uax:Locale><uax:Text>Off</uax:Text></uax:LocalizedText>
      <uax:LocalizedText><uax:Text>On</uax:Text></uax:LocalizedText>
    </uax:ListOfLocalizedText></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6006" BrowseName="1:Range" DataType="Range">
    <DisplayName>Range</DisplayName>
    <Value><uax:ExtensionObject>
      <uax:TypeId><uax:Identifier>i=885</uax:Identifier></uax:TypeId>
      <uax:Body><uax:Range><uax:Low>-1.5</uax:Low><uax:High>99</uax:High></uax:Range></uax:Body>
    </uax:ExtensionObject></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=6007" BrowseName="1:Strings" DataType="String" ValueRank="1">
    <DisplayName>Strings</DisplayName>
    <Value><uax:ListOfString><uax:String>a</uax:String><uax:String>b</uax:String></uax:ListOfString></Value>
  </UAVariable>
</UANodeSet>`

// TestNodeSet_ConcurrentImport imports the same NodeSet2 document - the very
// same byte slice - into several servers at once, then mutates the imported
// values on some of them, in place and through the API.
//
// Invariants: no data race, no panic; the document is not modified; every
// server serves the values of the document, through its API and to clients;
// what is changed on one server stays on that server, also for a server that
// imports the document afterwards.
func TestNodeSet_ConcurrentImport(t *testing.T) {
	t.Parallel()
	_ = chaoskit.Seed(t)
	wd := chaoskit.NewWatchdog(t)

	doc := []byte(importNodeSet)
	pristine := bytes.Clone(doc)
	want, err := goldenValues(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 7 {
		t.Fatalf("the document has %d values, want 7", len(want))
	}

	const numStations = 5
	var (
		stations = make([]*station, numStations)
		errs     = make([]error, numStations)
		wg       sync.WaitGroup
		start    = make(chan struct{})
	)
	t.Cleanup(func() {
		for _, s := range stations {
			s.close()
		}
	})
	importInto := func(name string) (*station, error) {
		srv, err := server.New(
			server.EndPoint("localhost", 0),
			server.EnableSecurity("None", ua.MessageSecurityModeNone),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		)
		if err != nil {
			return nil, err
		}
		if err := srv.ImportNodeSetXML(doc); err != nil {
			return nil, fmt.Errorf("%s: ImportNodeSetXML: %w", name, err)
		}
		return startStation(name, srv)
	}
	for i := range stations {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = wd.Do("server.New + ImportNodeSetXML + Start", func() error {
				var err error
				stations[i], err = importInto(fmt.Sprintf("server %d", i))
				if err != nil {
					return err
				}
				return stations[i].verify(want, nil)
			})
		}(i)
	}
	close(start)
	wd.Wait("importing", &wg)
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	// Mutate on servers 0 and 1 while the others are read.
	wg = sync.WaitGroup{}
	for i, s := range stations {
		wg.Add(1)
		go func(i int, s *station) {
			defer wg.Done()
			errs[i] = wd.Do("mutation", func() error {
				for _, g := range want {
					switch i {
					case 0:
						av, err := s.srv.Node(g.id).Attribute(ua.AttributeIDValue)
						if err != nil {
							return err
						}
						scramble(reflect.ValueOf(av.Value.Value.Value()), 0)
					case 1:
						cur, err := g.decode()
						if err != nil {
							return err
						}
						if !scramble(reflect.ValueOf(cur.Value()), 0) {
							continue
						}
						if err := s.srv.Node(g.id).SetAttribute(ua.AttributeIDValue, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: cur}); err != nil {
							return fmt.Errorf("%s: SetAttribute %s: %w", s.name, g.id, err)
						}
					default:
						return s.verify(want, nil)
					}
				}
				return nil
			})
		}(i, s)
	}
	wd.Wait("mutating", &wg)
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, s := range stations[2:] {
		if err := s.verify(want, nil); err != nil {
			t.Error(err)
		}
	}
	late, err := importInto("server importing after the mutations")
	if err != nil {
		t.Fatal(err)
	}
	defer late.close()
	if err := late.verify(want, nil); err != nil {
		t.Error(err)
	}
	if !bytes.Equal(doc, pristine) {
		t.Error("ImportNodeSetXML modified the document it was given")
	}
}
