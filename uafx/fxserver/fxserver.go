// SPDX-License-Identifier: MIT

// Package fxserver adds the information model of OPC UA FX (UAFX,
// OPC 10000-81 version 1.00.04) to a server.Server: the types of the UAFX
// Data, AutomationComponent (AC) and ConnectionManager (CM) namespaces, the
// Devices (DI) model of OPC 10000-100 they build on, the FxRoot object
// (Part 81 §12.2) and the NamespaceMetadata objects of the three UAFX
// namespaces (§14.1).
//
// The model is the address space only. The Methods of the model
// (EstablishConnections, CloseConnections, Verify, VerifyAsset and the
// Methods of the ConnectionManager) have no implementation: the server
// answers a call with Bad_MethodInvalid, as for any Method without a handler. A server becomes an AutomationComponent with the
// instances an application imports with ImportNodeSet.
//
//	srv := server.New(opts...)
//	ns, err := fxserver.AddModel(srv)
//	...
//	err = fxserver.ImportNodeSet(srv, myAutomationComponentNodeSet)
//
// Import the model before the server starts.
package fxserver

import (
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/internal/nodeset"
	"github.com/otfabric/go-opcua/server"
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
// DI is imported unless the server has the DI namespace already, for
// example from an application that imported it before. A UAFX namespace the
// server has already is an error.
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
	di, haveDI := lookup(srv, diid.NamespaceURI)
	if !haveDI {
		parts = append([]part{{diid.NamespaceURI, model.DI, &ns.DI}}, parts...)
	} else {
		ns.DI = di
	}
	if want&ModelAC != 0 {
		parts = append(parts, part{fxacid.NamespaceURI, model.AC, &ns.AC})
	}
	if want&ModelCM != 0 {
		parts = append(parts, part{fxcmid.NamespaceURI, model.CM, &ns.CM})
	}
	for _, p := range parts {
		if err := ImportNodeSet(srv, p.data); err != nil {
			return ns, fmt.Errorf("%w: %s: %w", ErrModel, p.uri, err)
		}
		*p.idx, _ = lookup(srv, p.uri)
	}
	return ns, nil
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
