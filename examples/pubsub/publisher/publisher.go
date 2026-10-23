// SPDX-License-Identifier: MIT

// Command publisher publishes a counter and a sine wave as UADP
// NetworkMessages over UDP (multicast by default), without an OPC UA server.
//
//	go run ./examples/pubsub/publisher -url opc.udp://224.0.0.22:4840
//
// The subscriber example (or open62541's tutorial_pubsub_subscribe with
// PublisherId 2234, WriterGroupId 100, DataSetWriterId 62541) receives it.
package main

import (
	"context"
	"flag"
	"log"
	"math"
	"os"
	"os/signal"
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	url := flag.String("url", "opc.udp://224.0.0.22:4840", "UDP address to publish to")
	interval := flag.Duration("interval", 100*time.Millisecond, "publishing interval")
	publisherID := flag.Uint("publisher", 2234, "PublisherId (UInt16)")
	flag.Parse()

	counter := ua.NewStringNodeID(1, "counter")
	sine := ua.NewStringNodeID(1, "sine")
	values := pubsub.NewMemoryDataSource()

	pds := pubsub.PublishedDataItems("Measurements",
		pubsub.Var("Counter", counter, ua.TypeIDUint32),
		pubsub.Var("Sine", sine, ua.TypeIDDouble),
	)
	writer := pubsub.DataSetWriter("Writer", 62541, "Measurements")
	writer.KeyFrameCount = 10 // delta frames in between
	writer.DataSetFieldContentMask = ua.DataSetFieldContentMaskStatusCode | ua.DataSetFieldContentMaskSourceTimestamp
	group := pubsub.WriterGroup("Group", 100, *interval, writer)
	group.KeepAliveTime = float64(5 * *interval / time.Millisecond)
	cfg := pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		pubsub.AttachWriterGroups(pubsub.UDPConnection("UDP", *url, uint16(*publisherID)), group))

	ps, err := pubsub.New(cfg, pubsub.WithDataSource(values), pubsub.WithEventHandler(func(ev pubsub.Event) {
		if ev.Type == pubsub.EventStateChanged {
			log.Printf("%s %q: %v", ev.Component.Kind, ev.Component.Name, ev.Component.State)
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
	log.Printf("publishing to %s every %v", *url, *interval)

	t := time.NewTicker(*interval)
	defer t.Stop()
	var n uint32
	for {
		select {
		case <-ctx.Done():
			st, _ := ps.Status(pubsub.Root)
			log.Printf("sent %d NetworkMessages", st.Counters.NetworkMessagesSent)
			return
		case now := <-t.C:
			n++
			_ = values.Set(counter, n)
			_ = values.Set(sine, math.Sin(float64(now.UnixMilli())/1000))
		}
	}
}
