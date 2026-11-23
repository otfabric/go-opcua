// SPDX-License-Identifier: MIT

// Example uafx/server runs an OPC UA server with the OPC UA FX information
// model (OPC 10000-81) and one AutomationComponent: a controller with a
// drive as its Asset and a Motion FunctionalEntity with a PubSub
// ConnectionEndpoint (controller.xml). Every few seconds the drive reports
// another health, which the AggregatedHealth of the controller shows.
//
// The server serves the model only: the Methods of Part 81
// (EstablishConnections, CloseConnections, ...) answer Bad_MethodInvalid.
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

// controllerNS is the namespace of controller.xml.
const controllerNS = "urn:example:uafx:controller"

// NodeIds in controllerNS: the AggregatedHealth of the controller and the
// AuthorAssignedVersion of its Motion FunctionalEntity.
const (
	aggregatedHealthID      = 1004
	authorAssignedVersionID = 1203
)

func main() {
	host := flag.String("host", "localhost", "host name of the endpoint")
	port := flag.Int("port", 4855, "port of the endpoint (0: any)")
	interval := flag.Duration("interval", 5*time.Second, "how often the drive reports another health")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv, err := newServer(*host, *port)
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	log.Printf("UAFX server on opc.tcp://%s:%d", *host, srv.Port())

	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := setHealth(srv, healthSequence[i%len(healthSequence)]); err != nil {
				log.Print(err)
			}
		}
	}
}

// newServer returns a server, not started, with the UAFX model, the
// controller and its initial health.
func newServer(host string, port int) (*server.Server, error) {
	srv, err := server.New(
		server.EndPoint(host, port),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	if err != nil {
		return nil, err
	}
	if _, err := fxserver.AddModel(srv); err != nil {
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
	if err := setHealth(srv, healthSequence[0]); err != nil {
		return nil, err
	}
	return srv, nil
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

// setHealth writes h to the AggregatedHealth of the controller.
func setHealth(srv *server.Server, h health) error {
	return setStructure(srv, aggregatedHealthID, fxacid.AggregatedHealthDataTypeEncodingDefaultBinary, &h)
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
