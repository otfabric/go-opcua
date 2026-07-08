// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func TestBrowse(t *testing.T) {
	ctx := context.Background()

	srv, url := testutil.NewTestServer(t)
	populateServer(srv)

	c := testutil.NewTestClient(t, url)

	// browse the nodes (depth 7 for faster test)
	nodeList, err := browseWithWalkLimit(ctx, c, c.Node(ua.MustParseNodeID("i=84")), 7)
	if err != nil {
		t.Fatal(err)
	}

	// ensure that the TestVar1 node was found
	found := false
	for _, n := range nodeList {
		if n.BrowseName == "TestVar1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("TestVar1 not found in nodeList: %v", nodeList)
	}
}

func populateServer(s *server.Server) {
	// When the server is created, it will automatically create namespace 0 and populate it with
	// the core opc ua nodes.

	// add the namespaces to the server, and add a reference to them (otherwise browsing will not find it).
	// here we are choosing to add the namespaces to the root/object folder
	// to do this we first need to get the root namespace object folder so we
	// get the object node
	rootNs, _ := s.Namespace(0)
	rootObjNode := rootNs.Objects()

	// Now we'll add a node namespace.
	nodeNS := server.NewNodeNameSpace(s, "NodeNamespace")
	log.Printf("Node Namespace added at index %d", nodeNS.ID())

	// add the reference for this namespace's root object folder to the server's root object folder
	// but you can add a reference to whatever node(s) you need
	nnsObj := nodeNS.Objects()
	rootObjNode.AddRef(nnsObj, id.HasComponent, true)

	// Create some nodes for it.  Here we are usin gthe AddNewVariableNode utility function to create a new variable node
	// with an integer node ID that is automatically assigned. (ns=<namespace id>,s=<auto assigned>)
	// be sure to add the reference to the node somewhere if desired, or clients won't be able to browse it.
	var1 := nodeNS.AddNewVariableNode("TestVar1", float32(123.45))
	nnsObj.AddRef(var1, id.HasComponent, true)
}
