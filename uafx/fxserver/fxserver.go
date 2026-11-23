// SPDX-License-Identifier: MIT

// Package fxserver adds the information model of OPC UA FX (UAFX,
// OPC 10000-81 version 1.00.04) to a server.Server: the types of the UAFX
// Data, AutomationComponent (AC) and ConnectionManager (CM) namespaces, the
// Devices (DI) model of OPC 10000-100 they build on, the FxRoot object
// (Part 81 §12.2) and the NamespaceMetadata objects of the three UAFX
// namespaces (§14.1).
//
// A server becomes an AutomationComponent with the instances an
// application imports with ImportNodeSet. EnableConnections serves the
// EstablishConnections and CloseConnections Methods of its
// AutomationComponents (§6.2.4, §6.2.5) with PubSub. The other Methods of
// the model (Verify and VerifyAsset called on their own, and the Methods
// of the ConnectionManager) have no implementation: the server answers a
// call with Bad_MethodInvalid, as for any Method without a handler.
//
//	srv := server.New(opts...)
//	ns, err := fxserver.AddModel(srv)
//	...
//	err = fxserver.ImportNodeSet(srv, myAutomationComponentNodeSet)
//	conns, err := fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{})
//
// Import the model and enable the connections before the server starts.
package fxserver

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/internal/nodeset"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/internal/model"
)

// Model selects a part of the UAFX model for AddModel.
type Model uint8

const (
	// ModelAC is the AutomationComponent model (namespace
	// http://opcfoundation.org/UA/FX/AC/), with DI.
	ModelAC Model = 1 << iota
	// ModelCM is the ConnectionManager model (namespace
	// http://opcfoundation.org/UA/FX/CM/), with DI.
	ModelCM
)

// Namespaces are the namespace indexes of the UAFX model on a server. An
// index of 0 is a namespace the server does not have.
type Namespaces struct {
	DI   uint16 // http://opcfoundation.org/UA/DI/
	Data uint16 // http://opcfoundation.org/UA/FX/Data/
	AC   uint16 // http://opcfoundation.org/UA/FX/AC/
	CM   uint16 // http://opcfoundation.org/UA/FX/CM/
}

// ErrModel reports that the UAFX model cannot be added to the server.
var ErrModel = errors.New("fxserver: UAFX model")

// AddModel imports the UAFX model into srv: the Data namespace, which a UAFX
// server must have, and the AC and CM models selected by models, both when
// models is empty (Part 81 §14.2: a UAFX server has at least one of them).
//
// Namespace index 1 is the namespace of the local server (Part 81 §14.2,
// Table 260), whose URI is the ApplicationUri of the server (Part 5
// §6.3.1). A server that has no namespace besides namespace 0 gets it
// before the model, named by its ApplicationUri ([server.ApplicationURI]
// or the URI of its certificate). A server without an ApplicationUri, or
// whose namespace 1 has another URI, is an error.
//
// DI is imported unless the server has the DI namespace already, for
// example from an application that imported it before. The DI nodes the
// UAFX model refers to must then be on the server with the NodeClass the DI
// NodeSet gives them, or AddModel fails without importing anything. A UAFX
// namespace the server has already is an error.
func AddModel(srv *server.Server, models ...Model) (Namespaces, error) {
	var want Model
	for _, m := range models {
		want |= m
	}
	if want == 0 {
		want = ModelAC | ModelCM
	}
	var ns Namespaces
	if want&^(ModelAC|ModelCM) != 0 {
		return ns, fmt.Errorf("%w: unknown model %#x", ErrModel, uint8(want))
	}
	for _, uri := range []string{fxdataid.NamespaceURI, fxacid.NamespaceURI, fxcmid.NamespaceURI} {
		if _, ok := lookup(srv, uri); ok {
			return ns, fmt.Errorf("%w: the server has the namespace %s already", ErrModel, uri)
		}
	}

	type part struct {
		uri  string
		data []byte
		idx  *uint16
	}
	parts := []part{{fxdataid.NamespaceURI, model.Data, &ns.Data}}
	if want&ModelAC != 0 {
		parts = append(parts, part{fxacid.NamespaceURI, model.AC, &ns.AC})
	}
	if want&ModelCM != 0 {
		parts = append(parts, part{fxcmid.NamespaceURI, model.CM, &ns.CM})
	}
	di, haveDI := lookup(srv, diid.NamespaceURI)
	if haveDI {
		if err := checkDI(srv, di, want); err != nil {
			return ns, err
		}
		ns.DI = di
	} else {
		parts = append([]part{{diid.NamespaceURI, model.DI, &ns.DI}}, parts...)
	}
	if err := localNamespace(srv); err != nil {
		return ns, err
	}
	for _, p := range parts {
		if err := ImportNodeSet(srv, p.data); err != nil {
			return ns, fmt.Errorf("%w: %s: %w", ErrModel, p.uri, err)
		}
		*p.idx, _ = lookup(srv, p.uri)
	}
	return ns, nil
}

// localNamespace makes sure namespace 1 of srv is the namespace of the
// local server (Part 81 §14.2): the ApplicationUri of the server, which
// Part 5 §6.3.1 requires NamespaceArray[1] to be.
func localNamespace(srv *server.Server) error {
	uri := srv.ApplicationURI()
	if uri == "" {
		return fmt.Errorf("%w: the server has no ApplicationUri to name namespace 1, the namespace of the local server (Part 81 §14.2, Part 5 §6.3.1): set server.ApplicationURI", ErrModel)
	}
	nss := srv.Namespaces()
	if len(nss) > 1 {
		if got := nss[1].Name(); got != uri {
			return fmt.Errorf("%w: namespace 1 of the server is %s, not its ApplicationUri %s (Part 81 §14.2, Part 5 §6.3.1)", ErrModel, got, uri)
		}
		return nil
	}
	// The server has namespace 0 only: the new namespace gets index 1.
	server.NewNodeNameSpace(srv, uri)
	return nil
}

// diNode is a node of the DI model that the UAFX model refers to.
type diNode struct {
	id    uint32
	class ua.NodeClass
}

// diNeeds lists the DI nodes the Data, AC and CM models refer to, by the
// NodeSets embedded in package model.
var diNeeds = sync.OnceValues(func() (map[Model][]diNode, error) {
	classes, err := nodeset.Nodes(model.DI)
	if err != nil {
		return nil, err
	}
	out := map[Model][]diNode{}
	for m, doc := range map[Model][]byte{0: model.Data, ModelAC: model.AC, ModelCM: model.CM} {
		uris, err := nodeset.URIs(doc)
		if err != nil {
			return nil, err
		}
		idx := slices.Index(uris, diid.NamespaceURI) + 1
		if idx == 0 {
			continue
		}
		ids, err := nodeset.NodeIDs(doc)
		if err != nil {
			return nil, err
		}
		for _, s := range ids {
			n, err := ua.ParseNodeID(s)
			if err != nil || int(n.Namespace()) != idx || n.Type() != ua.NodeIDTypeNumeric && n.Type() != ua.NodeIDTypeFourByte && n.Type() != ua.NodeIDTypeTwoByte {
				continue
			}
			el := classes[fmt.Sprintf("ns=1;i=%d", n.IntID())]
			if el == "" {
				return nil, fmt.Errorf("fxserver: the DI NodeSet has no node i=%d", n.IntID())
			}
			out[m] = append(out[m], diNode{n.IntID(), nodeClasses[el]})
		}
	}
	return out, nil
})

// nodeClasses maps the elements of a NodeSet to the NodeClass of the node
// they define (Part 6 §F.1).
var nodeClasses = map[string]ua.NodeClass{
	"UAObject": ua.NodeClassObject, "UAVariable": ua.NodeClassVariable, "UAMethod": ua.NodeClassMethod,
	"UAView": ua.NodeClassView, "UAObjectType": ua.NodeClassObjectType, "UAVariableType": ua.NodeClassVariableType,
	"UAReferenceType": ua.NodeClassReferenceType, "UADataType": ua.NodeClassDataType,
}

// checkDI reports an ErrModel unless the DI namespace di of srv has the DI
// nodes the models of want refer to.
func checkDI(srv *server.Server, di uint16, want Model) error {
	needs, err := diNeeds()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrModel, err)
	}
	var missing []string
	for _, m := range []Model{0, ModelAC, ModelCM} {
		if m != 0 && want&m == 0 {
			continue
		}
		for _, n := range needs[m] {
			node := srv.Node(ua.NewNumericNodeID(di, n.id))
			switch {
			case node == nil:
				missing = append(missing, fmt.Sprintf("i=%d", n.id))
			case node.NodeClass() != n.class:
				missing = append(missing, fmt.Sprintf("i=%d (a %v, not a %v)", n.id, node.NodeClass(), n.class))
			}
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		missing = slices.Compact(missing)
		return fmt.Errorf("%w: the DI namespace of the server lacks nodes the UAFX model refers to: %s", ErrModel, strings.Join(missing, ", "))
	}
	return nil
}

// ImportNodeSet imports the NodeSet2 document data into srv with the
// namespace indexes of the server: each namespace of the NamespaceUris of
// the document gets the index the server has for it, or a new namespace on
// the server (Part 6 §F.2). Use it for the instances of an
// AutomationComponent, which a NodeSet describes in a namespace of its own
// with references to the UAFX types.
func ImportNodeSet(srv *server.Server, data []byte) error {
	out, err := nodeset.Remap(data, func(uri string) (uint16, error) {
		if idx, ok := lookup(srv, uri); ok {
			return idx, nil
		}
		ns := server.NewNodeNameSpace(srv, uri)
		if idx, ok := lookup(srv, uri); ok && ns.ID() == idx {
			return idx, nil
		}
		return 0, fmt.Errorf("the server has no namespace index left")
	})
	if err != nil {
		return err
	}
	return srv.ImportNodeSetXML(out)
}

// lookup returns the index of the namespace uri on srv.
func lookup(srv *server.Server, uri string) (uint16, bool) {
	var idx uint16 // a server has at most 65536 namespaces
	for _, ns := range srv.Namespaces() {
		if ns.Name() == uri {
			return idx, true
		}
		idx++
	}
	return 0, false
}
