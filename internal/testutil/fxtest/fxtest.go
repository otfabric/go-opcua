// SPDX-License-Identifier: MIT

// Package fxtest holds the OPC UA FX test address spaces shared by the
// tests of uafx, uafx/fxserver, conformance/uafx and chaos/uafx:
// connections.xml (see ConnectionsNodeSet) and automation_component.xml, a
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

// AppNS is an ApplicationUri for test servers. AddModel names namespace 1
// after the ApplicationUri, so the UAFX namespaces follow it and their
// indexes differ from those of the NodeSet documents.
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

// ConnNS is the namespace of connections.xml.
const ConnNS = "urn:go-opcua:fxserver:connections"

//go:embed connections.xml
var connectionsNodeSet []byte

// ConnectionsNodeSet returns connections.xml: AutomationComponents for the
// tests of EstablishConnections and CloseConnections (fxserver
// EnableConnections). Ctl has the FunctionalEntity Motion with InputData,
// OutputData, ConfigurationData, ControlGroups, a SubFunctionalEntity Axis
// and a preconfigured PubSubConnectionEndpoint Preset; Peer is a second
// AutomationComponent. The constants Conn* are its NodeIds.
func ConnectionsNodeSet() []byte { return append([]byte(nil), connectionsNodeSet...) }

// NodeIds, in ConnNS, of connections.xml.
const (
	ConnCtl       = 1000 // the AutomationComponent Ctl
	ConnCtlHealth = 1004 // Ctl/AggregatedHealth
	ConnPump      = 1010 // Ctl/Assets/Pump
	ConnMotion    = 1200 // Ctl/FunctionalEntities/Motion
	ConnMotionOH  = 1204 // Motion/OperationalHealth
	ConnAppID     = 1206 // Motion/ApplicationIdentifier, ApplicationIdentifierDataType[], no value
	ConnSetpoint  = 1221 // Motion/InputData/Setpoint, Double
	ConnLimit     = 1222 // Motion/InputData/Limit, Double
	ConnActual    = 1231 // Motion/OutputData/Actual, Double 42.5
	ConnGain      = 1241 // Motion/ConfigurationData/Gain, Double 1, writable
	ConnFixed     = 1242 // Motion/ConfigurationData/Fixed, Double 7, read-only
	ConnTable     = 1243 // Motion/ConfigurationData/Table, Double[] {1, 2, 3}
	ConnLabel     = 1244 // Motion/ConfigurationData/Label, String "  pump-1 ", read-only
	ConnLabels    = 1245 // Motion/ConfigurationData/Labels, String[] {" a ", "b"}, read-only
	ConnGroup     = 1251 // Motion/ControlGroups/Group, a ControlGroup
	ConnNotAGroup = 1252 // Motion/ControlGroups/NotAGroup
	// ConnControl is Motion/ControlGroups/Control of control_groups.xml
	// (PrepareControlGroups), a ControlGroup that
	// blocks Table and restricts Gain and ConnReset; ConnMonitor blocks
	// Limit and restricts Gain, with a MaxInactiveLockTime of 300 ms on
	// its ListToRestrict. Each has ListToBlock at +1 (its Lock at +2, the
	// Lock's Properties Locked, LockingClient, LockingUser,
	// RemainingLockTime at +3 to +6 and Methods InitLock, RenewLock,
	// ExitLock, BreakLock at +7 to +10), ListToRestrict at +11 (Lock at
	// +12, ...), IsControlled at +23 and the Methods EstablishControl,
	// ReleaseControl, ReassignControl at +24 to +26.
	ConnControl = 1400
	ConnMonitor = 1440
	ConnReset   = 1297 // Motion/Reset, a Method of control_groups.xml
	ConnAxis    = 1260 // Motion/Axis, a SubFunctionalEntity
	ConnAxisIn  = 1262 // Axis/InputData/AxisIn, Double
	ConnPreset  = 1300 // Motion/ConnectionEndpoints/Preset, Subscriber of Setpoint
	ConnPeer    = 3000 // the AutomationComponent Peer
	ConnRemote  = 3200 // Peer/FunctionalEntities/Remote
)

//go:embed control_groups.xml
var controlGroupsNodeSet []byte

// PrepareControlGroups is PrepareConnections with control_groups.xml: the
// ControlGroups ConnControl and ConnMonitor of Motion and the Method
// ConnReset. Call it before fxserver.EnableConnections.
func PrepareControlGroups(srv *server.Server) (fxserver.Namespaces, uint16, error) {
	ns, idx, err := PrepareConnections(srv)
	if err != nil {
		return ns, idx, err
	}
	return ns, idx, fxserver.ImportNodeSet(srv, controlGroupsNodeSet)
}

// PrepareConnections adds the AC model and connections.xml to srv, which
// must not be started yet, have an ApplicationUri and PubSub, and sets the
// InputVariables and OutputVariables of Preset, which a NodeSet cannot
// hold here: InputVariables is Setpoint.
func PrepareConnections(srv *server.Server) (fxserver.Namespaces, uint16, error) {
	ns, err := fxserver.AddModel(srv, fxserver.ModelAC)
	if err != nil {
		return ns, 0, err
	}
	if err := fxserver.ImportNodeSet(srv, connectionsNodeSet); err != nil {
		return ns, 0, err
	}
	idx, ok := Index(srv, ConnNS)
	if !ok {
		return ns, 0, fmt.Errorf("fxtest: no namespace %s", ConnNS)
	}
	if err := SetValue(srv, ua.NewNumericNodeID(idx, ConnPreset+6), []*ua.NodeID{ua.NewNumericNodeID(idx, ConnSetpoint)}); err != nil {
		return ns, 0, err
	}
	return ns, idx, SetValue(srv, ua.NewNumericNodeID(idx, ConnPreset+7), []*ua.NodeID{})
}

// Prepare adds the UAFX model of models to srv, which must not be started
// yet and must have an ApplicationUri, and unless bare the test AutomationComponents with their structure
// values.
func Prepare(srv *server.Server, bare bool, models ...fxserver.Model) (fxserver.Namespaces, error) {
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
