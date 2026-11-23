// SPDX-License-Identifier: MIT

// Package fxtest holds the OPC UA FX test address space shared by the tests
// of uafx, conformance/uafx and chaos/uafx: automation_component.xml, a
// NodeSet with AutomationComponents that conform to Part 81 (Controller),
// break it (Broken, Bare) or are not of AutomationComponentType (Other),
// plus the values of the UAFX structures that a NodeSet cannot hold.
package fxtest

import (
	_ "embed"
	"fmt"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// NS is the namespace of automation_component.xml.
const NS = "urn:go-opcua:uafx:test"

// AppNS is the application namespace Prepare adds before the UAFX
// namespaces, so that their indexes differ from those of the NodeSet
// documents.
const AppNS = "urn:go-opcua:uafx:application"

// NodeIds, in NS, of the nodes whose values Prepare sets.
const (
	AggregatedHealthID      = 1004 // Controller/AggregatedHealth
	AuthorAssignedVersionID = 1203 // Controller/Motion/AuthorAssignedVersion
)

// Values of AggregatedHealth and AuthorAssignedVersion set by Prepare, as
// their binary encoding: DeviceMaintenanceRequired with OperationalWarning,
// and FxVersion 1.2.3.4.
var (
	AggregatedHealth      = []byte{0x04, 0x00, 0x00, 0x00, 0x01, 0x00}
	AuthorAssignedVersion = []byte{1, 0, 2, 0, 3, 0, 4, 0}
)

//go:embed automation_component.xml
var nodeSet []byte

// NodeSet returns automation_component.xml.
func NodeSet() []byte { return append([]byte(nil), nodeSet...) }

// Prepare adds the UAFX model of models to srv, which must not be started
// yet, and unless bare the test AutomationComponents with their structure
// values.
func Prepare(srv *server.Server, bare bool, models ...fxserver.Model) (fxserver.Namespaces, error) {
	if _, ok := Index(srv, AppNS); !ok {
		server.NewNodeNameSpace(srv, AppNS)
	}
	ns, err := fxserver.AddModel(srv, models...)
	if err != nil || bare {
		return ns, err
	}
	if err := fxserver.ImportNodeSet(srv, nodeSet); err != nil {
		return ns, err
	}
	test, ok := Index(srv, NS)
	if !ok {
		return ns, fmt.Errorf("fxtest: no namespace %s", NS)
	}
	if err := SetStructure(srv, ua.NewNumericNodeID(test, AggregatedHealthID), ns.AC,
		fxacid.AggregatedHealthDataTypeEncodingDefaultBinary, AggregatedHealth); err != nil {
		return ns, err
	}
	return ns, SetStructure(srv, ua.NewNumericNodeID(test, AuthorAssignedVersionID), ns.AC,
		fxacid.FxVersionEncodingDefaultBinary, AuthorAssignedVersion)
}

// SetStructure sets the Value of the node nid of srv to a UAFX structure:
// an ExtensionObject with the binary encoding NodeId enc of the AC
// namespace ac and the encoded body.
func SetStructure(srv *server.Server, nid *ua.NodeID, ac uint16, enc uint32, body []byte) error {
	return SetValue(srv, nid, &ua.ExtensionObject{
		TypeID:       ua.NewNumericExpandedNodeID(ac, enc),
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        body,
	})
}

// SetValue sets the Value of the node nid of srv to v and notifies the
// monitored items of the node.
func SetValue(srv *server.Server, nid *ua.NodeID, v any) error {
	n := srv.Node(nid)
	if n == nil {
		return fmt.Errorf("fxtest: no node %v", nid)
	}
	if err := n.SetAttribute(ua.AttributeIDValue, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}); err != nil {
		return err
	}
	srv.ChangeNotification(nid)
	return nil
}

// Index returns the index of the namespace uri on srv.
func Index(srv *server.Server, uri string) (uint16, bool) {
	var idx uint16
	for _, ns := range srv.Namespaces() {
		if ns.Name() == uri {
			return idx, true
		}
		idx++
	}
	return 0, false
}
