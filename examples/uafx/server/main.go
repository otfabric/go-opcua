// SPDX-License-Identifier: MIT

// Example uafx/server runs an OPC UA server with the OPC UA FX information
// model (OPC 10000-81) and one AutomationComponent: a controller with a
// drive as its Asset and a Motion FunctionalEntity with input, output and
// configuration data and a preconfigured PubSub ConnectionEndpoint
// (controller.xml). Every few seconds the drive reports another health,
// which the AggregatedHealth of the controller shows.
//
// The controller serves EstablishConnections and CloseConnections
// (fxserver.EnableConnections): a client (uafx.EstablishConnections) can
// connect Motion over PubSub. The other Methods of Part 81 answer
// Bad_MethodInvalid.
//
// Usage:
//
//	go run ./examples/uafx/server -port 4855
//	go run ./examples/uafx/inspect -endpoint opc.tcp://localhost:4855
package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

//go:embed controller.xml
var controller []byte

// applicationURI is the ApplicationUri of the server, and the name of
// namespace 1, the namespace of the local server (Part 81 §14.2).
const applicationURI = "urn:example:uafx:server"

// controllerNS is the namespace of controller.xml.
const controllerNS = "urn:example:uafx:controller"

// NodeIds in controllerNS: the AggregatedHealth of the controller and the
// AuthorAssignedVersion and OperationalHealth of its Motion
// FunctionalEntity.
const (
	aggregatedHealthID        = 1004
	authorAssignedVersionID   = 1203
	motionOperationalHealthID = 1204
)

func main() {
	host := flag.String("host", "localhost", "host name of the endpoint")
	port := flag.Int("port", 4855, "port of the endpoint (0: any)")
	interval := flag.Duration("interval", 5*time.Second, "how often the drive reports another health")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	a, err := newApp(*host, *port)
	if err != nil {
		log.Fatal(err)
	}
	if err := a.srv.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer a.close()
	log.Printf("UAFX server on opc.tcp://%s:%d", *host, a.srv.Port())

	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := a.setHealth(healthSequence[i%len(healthSequence)]); err != nil {
				log.Print(err)
			}
		}
	}
}

// app is the server and the connections of its controller.
type app struct {
	srv   *server.Server
	conns *fxserver.Connections
}

func (a *app) close() {
	_ = a.conns.Close()
	_ = a.srv.Close()
}

// newApp returns a server, not started, with the UAFX model, PubSub, the
// controller with its connection Methods and its initial health.
func newApp(host string, port int) (*app, error) {
	srv, err := server.New(
		server.EndPoint(host, port),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI(applicationURI),
		// The connections configure PubSub through the PubSub information
		// model (Part 14 §9.1.3, CloseAndUpdate §9.1.3.7.6).
		server.WithPubSub(nil),
	)
	if err != nil {
		return nil, err
	}
	ns, err := fxserver.AddModel(srv)
	if err != nil {
		return nil, err
	}
	if err := fxserver.ImportNodeSet(srv, controller); err != nil {
		return nil, fmt.Errorf("import controller.xml: %w", err)
	}
	// FxVersion (Part 81 §10.28): Major, Minor, Build, SubBuild.
	if err := setStructure(srv, authorAssignedVersionID, fxacid.FxVersionEncodingDefaultBinary,
		&struct{ Major, Minor, Build, SubBuild uint16 }{1, 2, 0, 0}); err != nil {
		return nil, err
	}
	conns, err := fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{})
	if err != nil {
		return nil, err
	}
	a := &app{srv: srv, conns: conns}
	if err := a.setHealth(healthSequence[0]); err != nil {
		_ = conns.Close()
		return nil, err
	}
	return a, nil
}

// health is an AggregatedHealthDataType value (Part 81 §10.1):
// DeviceHealthOptionSet (UInt16) and OperationalHealthOptionSet (UInt32).
type health struct {
	Device      uint16
	Operational uint32
}

var healthSequence = []health{
	{0, 0},       // all well
	{1 << 2, 0},  // DeviceMaintenanceRequired
	{0, 1 << 16}, // OperationalWarning
	{1 << 0, 0},  // DeviceFailure
}

// setHealth reports h: the device health in the AggregatedHealth of the
// controller, the operational health in the vendor bits (16 to 31) of the
// OperationalHealth of Motion. The connections own bits 0 to 15, the
// health of its ConnectionEndpoints, and aggregate the OperationalHealth
// of the FunctionalEntities (Part 81 §9.1.2, §10.34).
func (a *app) setHealth(h health) error {
	if err := setStructure(a.srv, aggregatedHealthID, fxacid.AggregatedHealthDataTypeEncodingDefaultBinary, &health{Device: h.Device}); err != nil {
		return err
	}
	ctl, _ := index(a.srv, controllerNS)
	n := a.srv.Node(ua.NewNumericNodeID(ctl, motionOperationalHealthID))
	if n == nil {
		return fmt.Errorf("no OperationalHealth of Motion")
	}
	cur, _ := n.Value().Value.Value().(uint32)
	if err := n.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(cur&0xffff|h.Operational&^0xffff)); err != nil {
		return err
	}
	a.srv.ChangeNotification(n.ID())
	a.conns.RefreshHealth()
	return nil
}

// setStructure writes v, a UAFX structure, to the variable node of
// controllerNS. The structure is encoded here: its encoding NodeId (enc) is
// in the AC namespace, whose index is that of this server, so package ua
// has no type registered for it.
func setStructure(srv *server.Server, node, enc uint32, v any) error {
	ac, ok := index(srv, fxacid.NamespaceURI)
	ctl, ok2 := index(srv, controllerNS)
	if !ok || !ok2 {
		return fmt.Errorf("the server has no namespace %s or %s", fxacid.NamespaceURI, controllerNS)
	}
	body, err := ua.Encode(v)
	if err != nil {
		return err
	}
	n := srv.Node(ua.NewNumericNodeID(ctl, node))
	if n == nil {
		return fmt.Errorf("no node ns=%d;i=%d", ctl, node)
	}
	eo := &ua.ExtensionObject{
		TypeID:       ua.NewNumericExpandedNodeID(ac, enc),
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        body,
	}
	if err := n.SetAttribute(ua.AttributeIDValue, &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(eo),
		SourceTimestamp: time.Now(),
	}); err != nil {
		return err
	}
	srv.ChangeNotification(n.ID())
	return nil
}

func index(srv *server.Server, uri string) (uint16, bool) {
	var i uint16
	for _, ns := range srv.Namespaces() {
		if ns.Name() == uri {
			return i, true
		}
		i++
	}
	return 0, false
}
