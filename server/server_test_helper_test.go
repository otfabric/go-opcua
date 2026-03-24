package server

import (
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// newTestServer creates a Server suitable for unit tests, without starting
// a network listener. It initialises namespace 0 (the OPC-UA base nodeset)
// and a MonitoredItemService so that write-side tests don't panic.
func newTestServer() *Server {
	s, _ := New(EndPoint("localhost", 4840))

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
