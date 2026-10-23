// SPDX-License-Identifier: MIT

// Command subscriber receives the DataSets of the publisher example (UADP
// over UDP) and prints them.
//
//	go run ./examples/pubsub/subscriber -url opc.udp://224.0.0.22:4840
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	url := flag.String("url", "opc.udp://224.0.0.22:4840", "UDP address to receive on")
	publisherID := flag.Uint("publisher", 2234, "PublisherId to accept (UInt16)")
	timeout := flag.Duration("timeout", 2*time.Second, "MessageReceiveTimeout")
	flag.Parse()

	// The reader needs the DataSetMetaData of the writer: UADP carries
	// neither field names nor, for RawData, types.
	md := pubsub.MetaData("Measurements",
		pubsub.Field{Name: "Counter", Type: ua.TypeIDUint32},
		pubsub.Field{Name: "Sine", Type: ua.TypeIDDouble},
	)
	reader := pubsub.DataSetReader("Reader", uint16(*publisherID), 100, 62541, md)
	reader.MessageReceiveTimeout = float64(*timeout / time.Millisecond)
	cfg := pubsub.NewConfiguration(nil,
		pubsub.AttachReaderGroups(pubsub.UDPConnection("UDP", *url, nil), pubsub.ReaderGroup("Group", reader)))

	ps, err := pubsub.New(cfg,
		pubsub.WithDataSetHandler(func(ds *pubsub.ReceivedDataSet) {
			var b strings.Builder
			for _, f := range ds.Fields {
				if f.Value != nil && f.Value.Value != nil {
					b.WriteString(" " + f.Name + "=" + f.Value.Value.String())
				}
			}
			log.Printf("%v #%d from %v:%s", ds.MessageType, ds.SequenceNumber, ds.PublisherID, b.String())
		}),
		pubsub.WithEventHandler(func(ev pubsub.Event) {
			if ev.Type == pubsub.EventStateChanged && ev.Component.Kind == pubsub.KindDataSetReader {
				log.Printf("reader %q: %v (%v)", ev.Component.Name, ev.Component.State, ev.Err)
			}
		}))
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := ps.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = ps.Close() }()
	log.Printf("listening on %s", *url)
	<-ctx.Done()
}
