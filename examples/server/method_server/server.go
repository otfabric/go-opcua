// SPDX-License-Identifier: MIT

// Example method_server demonstrates server-side methods end to end:
// registering a method handler with server.RegisterMethod and calling it from
// a client with Client.CallMethod / Client.MethodArguments.
//
// The example builds a "Calculator" object with a "square" method that returns
// n*n, and exposes the method's InputArguments/OutputArguments so that
// MethodArguments can report the signature.
//
// Usage:
//
//	# Run the server and a client against it in one process (default)
//	go run server.go
//
//	# Run only the server (Ctrl-C to stop)
//	go run server.go -mode server
//
//	# Run only the client against an already-running server
//	go run server.go -mode client -endpoint opc.tcp://localhost:4840
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	var (
		mode     = flag.String("mode", "both", "server, client, or both")
		endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL (client mode)")
		host     = flag.String("host", "localhost", "server listen host")
		port     = flag.Int("port", 4840, "server listen port")
	)
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")
	flag.Parse()
	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	log.SetFlags(0)

	switch *mode {
	case "server":
		s := newServer(*host, *port)
		if err := s.Start(context.Background()); err != nil {
			log.Fatalf("start server: %v", err)
		}
		defer func() { _ = s.Close() }()
		log.Printf("server listening on opc.tcp://%s:%d — press Ctrl-C to exit", *host, *port)
		sigch := make(chan os.Signal, 1)
		signal.Notify(sigch, os.Interrupt)
		<-sigch

	case "client":
		runClient(*endpoint)

	case "both":
		s := newServer(*host, *port)
		if err := s.Start(context.Background()); err != nil {
			log.Fatalf("start server: %v", err)
		}
		defer func() { _ = s.Close() }()
		// Give the listener a moment to accept connections.
		time.Sleep(500 * time.Millisecond)
		runClient(fmt.Sprintf("opc.tcp://%s:%d", *host, *port))

	default:
		log.Fatalf("unknown -mode %q (want server, client, or both)", *mode)
	}
}

// objectID and methodID identify the Calculator object and its square method.
// They live in the custom namespace created by newServer (index reported at
// startup); string identifiers keep them stable and easy to reference.
var (
	nsURI    = "http://example.com/method-server"
	objectID *ua.NodeID
	methodID *ua.NodeID
)

func newServer(host string, port int) *server.Server {
	s, err := server.New(
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EndPoint(host, port),
		server.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))),
	)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	rootNs, _ := s.Namespace(0)
	rootObj := rootNs.Objects()

	ns := server.NewNodeNameSpace(s, nsURI)
	nsIdx := ns.ID()
	log.Printf("custom namespace at index %d", nsIdx)
	rootObj.AddRef(ns.Objects(), id.HasComponent, true)

	objectID = ua.NewStringNodeID(nsIdx, "Calculator")
	methodID = ua.NewStringNodeID(nsIdx, "square")

	// The Calculator object owns the method.
	objNode := server.NewFolderNode(objectID, "Calculator")
	ns.AddNode(objNode)
	ns.Objects().AddRef(objNode, id.HasComponent, true)

	// The method node. Its NodeClass must be Method.
	methodNode := server.NewFolderNode(methodID, "square")
	methodNode.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(methodNode)
	objNode.AddRef(methodNode, id.HasComponent, true)

	// Expose the method signature via InputArguments/OutputArguments properties
	// so that Client.MethodArguments can report it.
	addArgumentsProperty(ns, methodNode, nsIdx, "InputArguments", &ua.Argument{
		Name:        "n",
		DataType:    ua.NewNumericNodeID(0, id.Int64),
		ValueRank:   -1,
		Description: ua.NewLocalizedText("value to square"),
	})
	addArgumentsProperty(ns, methodNode, nsIdx, "OutputArguments", &ua.Argument{
		Name:        "result",
		DataType:    ua.NewNumericNodeID(0, id.Int64),
		ValueRank:   -1,
		Description: ua.NewLocalizedText("n squared"),
	})

	// Register the handler: square returns n*n.
	s.RegisterMethod(objectID, methodID,
		func(ctx context.Context, oID, mID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) < 1 || args[0] == nil {
				return nil, ua.StatusBadArgumentsMissing
			}
			n := args[0].Int()
			return []*ua.Variant{ua.MustVariant(n * n)}, ua.StatusOK
		})

	return s
}

// addArgumentsProperty adds an InputArguments/OutputArguments property node
// (a Variable holding an array of Argument) referenced from the method node.
func addArgumentsProperty(ns *server.NodeNameSpace, methodNode *server.Node, nsIdx uint16, name string, args ...*ua.Argument) {
	eos := make([]*ua.ExtensionObject, len(args))
	for i, a := range args {
		eos[i] = ua.NewExtensionObject(a)
	}
	value := &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(eos),
	}
	node := server.NewNode(
		ua.NewStringNodeID(nsIdx, "square."+name),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName(name)),
			ua.AttributeIDDataType:   server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
		},
		nil,
		func() *ua.DataValue { return value },
	)
	ns.AddNode(node)
	methodNode.AddRef(node, id.HasProperty, true)
}

func runClient(endpoint string) {
	ctx := context.Background()

	c, err := opcua.NewClient(endpoint, opcua.SecurityMode(ua.MessageSecurityModeNone))
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	if err := c.Connect(ctx); err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer func() { _ = c.Close(ctx) }()

	// Resolve the object and method NodeIDs from the server's namespace URI so
	// the client does not depend on a hard-coded namespace index.
	nsIdx, err := c.FindNamespace(ctx, nsURI)
	if err != nil {
		log.Fatalf("find namespace %q: %v", nsURI, err)
	}
	objID := ua.NewStringNodeID(nsIdx, "Calculator")
	methID := ua.NewStringNodeID(nsIdx, "square")

	// Report the declared signature.
	inputs, outputs, err := c.MethodArguments(ctx, objID, methID)
	if err != nil {
		log.Printf("MethodArguments unavailable: %v", err)
	}
	for _, a := range inputs {
		log.Printf("input  arg: %s", a.Name)
	}
	for _, a := range outputs {
		log.Printf("output arg: %s", a.Name)
	}

	// Call the method: square(7) => 49.
	in := int64(7)
	result, err := c.CallMethod(ctx, objID, methID, in)
	if err != nil {
		log.Fatalf("call method: %v", err)
	}
	if result.StatusCode != ua.StatusOK {
		log.Fatalf("call status: %v", result.StatusCode)
	}
	log.Printf("square(%d) = %v", in, result.OutputArguments[0].Value())
}
