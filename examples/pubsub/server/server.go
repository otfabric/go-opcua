// SPDX-License-Identifier: MIT

// Command server runs an OPC UA server that publishes one of its variables
// with PubSub (UADP over UDP) and subscribes to it again, writing the
// received value to a second variable. Clients see the configuration below
// Objects/Server/PublishSubscribe and can change it with the PubSub methods
// (see package pubsub/remote).
//
//	go run ./examples/pubsub/server -endpoint opc.tcp://localhost:4840
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	port := flag.Int("port", 4840, "OPC UA port")
	url := flag.String("pubsub", "opc.udp://224.0.0.22:4841", "PubSub UDP address")
	flag.Parse()

	// Variables live in the namespace the server creates first, so their
	// NodeIds are known before the server exists.
	const nsURI = "urn:example:pubsub"
	temperature := ua.NewStringNodeID(1, "Temperature")
	received := ua.NewStringNodeID(1, "ReceivedTemperature")

	pds := pubsub.PublishedDataItems("Plant", pubsub.Var("Temperature", temperature, ua.TypeIDDouble))
	md := pubsub.DataSetMetaDataOf(pds)
	conn := pubsub.UDPConnection("UDP", *url, uint16(1))
	pubsub.AttachWriterGroups(conn, pubsub.WriterGroup("Publisher", 1, 500*time.Millisecond, pubsub.DataSetWriter("Plant", 1, "Plant")))
	pubsub.AttachReaderGroups(conn, pubsub.ReaderGroup("Subscriber",
		pubsub.SetTargetVariables(pubsub.DataSetReader("Plant", uint16(1), 1, 1, md), pubsub.Target(received))))
	cfg := pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pds}, conn)

	srv, err := server.New(
		server.EndPoint("localhost", *port),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.WithPubSub(cfg),
	)
	if err != nil {
		log.Fatal(err)
	}
	ns := server.NewNodeNameSpace(srv, nsURI)
	root, _ := srv.Namespace(0)
	root.Objects().AddRef(ns.Objects(), id.HasComponent, true)
	temp := ns.AddNewVariableStringNode("Temperature", 20.0)
	ns.Objects().AddRef(temp, id.HasComponent, true)
	rcv := ns.AddNewVariableStringNode("ReceivedTemperature", 0.0)
	ns.Objects().AddRef(rcv, id.HasComponent, true)
	if !temp.ID().Equal(temperature) || !rcv.ID().Equal(received) {
		log.Fatalf("unexpected NodeIds %v %v", temp.ID(), rcv.ID())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := srv.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	log.Printf("OPC UA server on port %d, PubSub on %s", srv.Port(), *url)

	t := time.NewTicker(time.Second)
	defer t.Stop()
	for v := 20.0; ; v += 0.5 {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = ns.SetAttribute(temperature, ua.AttributeIDValue, server.DataValueFromValue(v))
			if dv := rcv.Value(); dv != nil && dv.Value != nil {
				log.Printf("published %.1f, received %v", v, dv.Value.Value())
			}
		}
	}
}
