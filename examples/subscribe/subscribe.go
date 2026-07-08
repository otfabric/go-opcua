// SPDX-License-Identifier: MIT

// Example subscribe demonstrates creating an OPC-UA subscription that monitors
// a node for data changes or events.
//
// It uses the high-level SubscriptionBuilder to create the subscription and
// monitored items, and the EventFilterBuilder to construct an event filter.
//
// Usage:
//
//	# Subscribe to data changes
//	go run subscribe.go -endpoint opc.tcp://localhost:4840 -node "ns=2;s=Temperature"
//
//	# Subscribe to events
//	go run subscribe.go -endpoint opc.tcp://localhost:4840 -node "ns=0;i=2253" -event
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// eventFieldNames are the event fields selected by the event filter, in order.
// The EventNotificationList delivers EventFields in the same order.
var eventFieldNames = []string{"EventId", "EventType", "Severity", "Time", "Message"}

func main() {
	var (
		endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
		policy   = flag.String("policy", "", "Security policy: None, Basic128Rsa15, Basic256, Basic256Sha256. Default: auto")
		mode     = flag.String("mode", "", "Security mode: None, Sign, SignAndEncrypt. Default: auto")
		certFile = flag.String("cert", "", "Path to cert.pem. Required for security mode/policy != None")
		keyFile  = flag.String("key", "", "Path to private key.pem. Required for security mode/policy != None")
		nodeID   = flag.String("node", "", "node id to subscribe to")
		event    = flag.Bool("event", false, "subscribe to node event changes (Default: node value changes)")
		interval = flag.Duration("interval", opcua.DefaultSubscriptionInterval, "subscription interval")
	)
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")

	flag.Parse()
	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	log.SetFlags(0)

	// add an arbitrary timeout to demonstrate how to stop a subscription
	// with a context.
	d := 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	log.Printf("Subscription will stop after %s for demonstration purposes", d)

	endpoints, err := opcua.GetEndpoints(ctx, *endpoint)
	if err != nil {
		log.Fatal(err)
	}
	ep, err := ua.SelectEndpoint(endpoints, *policy, ua.MessageSecurityModeFromString(*mode))
	if err != nil {
		log.Fatal(err)
	}
	ep.EndpointURL = *endpoint

	fmt.Println("*", ep.SecurityPolicyURI, ep.SecurityMode)

	opts := []opcua.Option{
		opcua.SecurityPolicy(*policy),
		opcua.SecurityModeString(*mode),
		opcua.CertificateFile(*certFile),
		opcua.PrivateKeyFile(*keyFile),
		opcua.AuthAnonymous(),
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
	}

	c, err := opcua.NewClient(ep.EndpointURL, opts...)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()

	id, err := ua.ParseNodeID(*nodeID)
	if err != nil {
		log.Fatal(err)
	}

	// Build the subscription with the fluent SubscriptionBuilder. Start creates
	// the subscription and the monitored item(s) in one call, and returns the
	// notification channel to read from.
	builder := c.NewSubscription().Interval(*interval)
	if *event {
		// Construct an event filter with the EventFilterBuilder: select the
		// fields to report and only deliver events with Severity >= 0.
		filter := ua.NewEventFilter().
			Select(eventFieldNames...).
			Where(ua.Field("Severity").GreaterThanOrEqual(uint16(0))).
			Build()
		builder = builder.MonitorEvents(filter, id)
	} else {
		builder = builder.Monitor(id)
	}

	sub, notifyCh, err := builder.Start(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = sub.Cancel(ctx) }()
	log.Printf("Created subscription with id %v", sub.SubscriptionID)

	// read from subscription's notification channel until ctx is cancelled
	for {
		select {
		case <-ctx.Done():
			return
		case res := <-notifyCh:
			if res.Error != nil {
				log.Print(res.Error)
				continue
			}

			switch x := res.Value.(type) {
			case *ua.DataChangeNotification:
				for _, item := range x.MonitoredItems {
					data := item.Value.Value.Value()
					log.Printf("MonitoredItem with client handle %v = %v", item.ClientHandle, data)
				}

			case *ua.EventNotificationList:
				for _, item := range x.Events {
					log.Printf("Event for client handle: %v\n", item.ClientHandle)
					for i, field := range item.EventFields {
						log.Printf("%v: %v of Type: %T", eventFieldNames[i], field.Value(), field.Value())
					}
					log.Println()
				}

			default:
				log.Printf("what's this publish result? %T", res.Value)
			}
		}
	}
}
