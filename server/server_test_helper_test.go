// SPDX-License-Identifier: MIT

package server

import (
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// ns0Cache holds a pre-built snapshot of the OPC UA base namespace so that
// newTestServer does not re-parse and re-import the XML nodeset for every test.
// The snapshot is built once on first use and reused by all tests.
var (
	ns0CacheOnce  sync.Once
	ns0CacheNodes []*Node
	ns0CacheMap   map[string]*Node
	ns0CacheSeq   uint32
)

func warmNS0Cache() {
	ns0CacheOnce.Do(func() {
		s, err := New(EndPoint("localhost", 4840))
		if err != nil {
			panic("server: warmNS0Cache: " + err.Error())
		}
		ns0 := s.namespaces[0].(*NodeNameSpace)
		ns0.mu.RLock()
		ns0CacheNodes = make([]*Node, len(ns0.nodes))
		copy(ns0CacheNodes, ns0.nodes)
		ns0CacheMap = make(map[string]*Node, len(ns0.m))
		for k, v := range ns0.m {
			ns0CacheMap[k] = v
		}
		ns0CacheSeq = ns0.nodeidSequence
		ns0.mu.RUnlock()
	})
}

// newTestServer creates a Server suitable for unit tests, without starting
// a network listener.  On the first call the OPC UA base nodeset is imported
// and cached; subsequent calls copy the cached node references into a fresh
// NodeNameSpace, making each call roughly 100× faster than a cold New().
//
// Tests MUST NOT mutate ns-0 nodes (the OPC UA base nodeset); they should
// add their own namespace via addTestNamespace.  Write-service tests that
// go through the server handler already do this.
func newTestServer() *Server {
	warmNS0Cache()

	// Build a fresh server with no namespaces yet.
	s, err := newServerNoNS()
	if err != nil {
		panic("server: newTestServer: " + err.Error())
	}

	// Build a per-test NodeNameSpace for ns-0, pre-populated from the cache.
	// Each test gets its own NodeNameSpace instance (own srv pointer, own
	// nodes/m slices) so concurrent tests do not share mutable struct fields.
	ns0 := &NodeNameSpace{
		srv:            s,
		name:           "http://opcfoundation.org/UA/",
		nodes:          make([]*Node, len(ns0CacheNodes)),
		m:              make(map[string]*Node, len(ns0CacheMap)),
		nodeidSequence: ns0CacheSeq,
	}
	copy(ns0.nodes, ns0CacheNodes)
	for k, v := range ns0CacheMap {
		ns0.m[k] = v
	}
	s.namespaces = []NameSpace{ns0}

	// initHandlers is normally called by Start().
	// We need SubscriptionService and MonitoredItemService
	// to be set so that ChangeNotification doesn't panic.
	s.SubscriptionService = &SubscriptionService{
		srv:  s,
		Subs: make(map[uint32]*Subscription),
	}
	s.MonitoredItemService = &MonitoredItemService{
		SubService: s.SubscriptionService,
		Items:      make(map[uint32]*MonitoredItem),
		Nodes:      make(map[string][]*MonitoredItem),
		Subs:       make(map[uint32][]*MonitoredItem),
	}
	return s
}

// addTestNamespace creates a NodeNameSpace with some test nodes and adds it
// to the server. Returns the namespace and its Objects node.
func addTestNamespace(s *Server) (*NodeNameSpace, *Node) {
	ns := NewNodeNameSpace(s, "TestNamespace")
	obj := ns.Objects()

	// Read-only bool variable
	n := ns.AddNewVariableStringNode("ro_bool", true)
	_ = n.SetAttribute(ua.AttributeIDUserAccessLevel, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(uint32(ua.AccessLevelTypeCurrentRead)),
	})
	obj.AddRef(n, id.HasComponent, true)

	// Read-write int32 variable
	n = ns.AddNewVariableStringNode("rw_int32", int32(42))
	obj.AddRef(n, id.HasComponent, true)

	// Read-write float64 variable
	n = ns.AddNewVariableStringNode("rw_float64", float64(3.14))
	obj.AddRef(n, id.HasComponent, true)

	// No access variable
	noAccess := NewNode(
		ua.NewStringNodeID(ns.ID(), "no_access"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeNone)),
			ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeNone)),
			ua.AttributeIDBrowseName:      DataValueFromValue(attrs.BrowseName("no_access")),
			ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return DataValueFromValue(int32(999)) },
	)
	ns.AddNode(noAccess)
	obj.AddRef(noAccess, id.HasComponent, true)

	return ns, obj
}

func reqHeader() *ua.RequestHeader {
	return &ua.RequestHeader{RequestHandle: 1}
}
