// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Example browse uses Node.WalkLimit to traverse the OPC-UA address space
// up to a configurable depth and outputs all discovered variable nodes as CSV.
//
// Usage:
//
//	go run browse.go -endpoint opc.tcp://localhost:4840
//	go run browse.go -endpoint opc.tcp://localhost:4840 -depth 5
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

type NodeDef struct {
	NodeID      *ua.NodeID
	NodeClass   ua.NodeClass
	BrowseName  string
	Description string
	AccessLevel ua.AccessLevelType
	Path        string
	DataType    string
	Writable    bool
	Unit        string
	Scale       string
	Min         string
	Max         string
}

func (n NodeDef) Records() []string {
	return []string{n.BrowseName, n.DataType, n.NodeID.String(), n.Unit, n.Scale, n.Min, n.Max, strconv.FormatBool(n.Writable), n.Description}
}

// nodeDefFromAttrs fetches attributes for the node and builds a NodeDef. Returns (nil, nil) to skip (e.g. access denied).
func nodeDefFromAttrs(ctx context.Context, node *opcua.Node, path string) (*NodeDef, error) {
	attrs, err := node.Attributes(ctx, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName, ua.AttributeIDDescription, ua.AttributeIDAccessLevel, ua.AttributeIDDataType)
	if err != nil {
		return nil, err
	}

	def := &NodeDef{NodeID: node.ID, Path: path}

	switch attrs[0].Status {
	case ua.StatusOK:
		def.NodeClass = ua.NodeClass(attrs[0].Value.Int())
	case ua.StatusBadSecurityModeInsufficient, ua.StatusBadUserAccessDenied:
		return nil, nil
	default:
		return nil, attrs[0].Status
	}

	switch attrs[1].Status {
	case ua.StatusOK:
		def.BrowseName = attrs[1].Value.String()
	default:
		return nil, attrs[1].Status
	}

	switch attrs[2].Status {
	case ua.StatusOK:
		def.Description = attrs[2].Value.String()
	case ua.StatusBadAttributeIDInvalid:
		// ignore
	default:
		return nil, attrs[2].Status
	}

	switch attrs[3].Status {
	case ua.StatusOK:
		def.AccessLevel = ua.AccessLevelType(attrs[3].Value.Int())
		def.Writable = def.AccessLevel&ua.AccessLevelTypeCurrentWrite == ua.AccessLevelTypeCurrentWrite
	case ua.StatusBadAttributeIDInvalid:
		// ignore
	default:
		return nil, attrs[3].Status
	}

	switch attrs[4].Status {
	case ua.StatusOK:
		switch v := attrs[4].Value.NodeID().IntID(); v {
		case id.DateTime:
			def.DataType = "time.Time"
		case id.Boolean:
			def.DataType = "bool"
		case id.SByte:
			def.DataType = "int8"
		case id.Int16:
			def.DataType = "int16"
		case id.Int32:
			def.DataType = "int32"
		case id.Byte:
			def.DataType = "byte"
		case id.UInt16:
			def.DataType = "uint16"
		case id.UInt32:
			def.DataType = "uint32"
		case id.UtcTime:
			def.DataType = "time.Time"
		case id.String:
			def.DataType = "string"
		case id.Float:
			def.DataType = "float32"
		case id.Double:
			def.DataType = "float64"
		default:
			def.DataType = attrs[4].Value.NodeID().String()
		}
	case ua.StatusBadAttributeIDInvalid:
		// ignore
	default:
		return nil, attrs[4].Status
	}

	return def, nil
}

func browseWithWalkLimit(ctx context.Context, c *opcua.Client, root *opcua.Node, maxDepth int) ([]NodeDef, error) {
	var nodeList []NodeDef
	var pathStack []string

	for wr, err := range root.WalkLimit(ctx, maxDepth) {
		if err != nil {
			return nil, err
		}
		ref := wr.Ref
		if ref == nil || ref.NodeID.NodeID == nil {
			continue
		}
		// Update path stack: depth 0 = first level of refs, so path has (depth+1) segments
		if wr.Depth < len(pathStack) {
			pathStack = pathStack[:wr.Depth]
		}
		name := ""
		if ref.BrowseName != nil {
			name = ref.BrowseName.Name
		}
		pathStack = append(pathStack, name)
		path := strings.Join(pathStack, ".")

		node := c.NodeFromExpandedNodeID(ref.NodeID)
		def, err := nodeDefFromAttrs(ctx, node, path)
		if err != nil {
			return nil, err
		}
		if def == nil {
			continue
		}
		if def.NodeClass == ua.NodeClassVariable {
			nodeList = append(nodeList, *def)
		}
	}

	return nodeList, nil
}

func main() {
	endpoint := flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
	nodeID := flag.String("node", "i=84", "node id for the root node") // i=84 is the standard root node
	depth := flag.Int("depth", 10, "maximum walk depth (0 = root only)")
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")

	flag.Parse()
	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	log.SetFlags(0)

	ctx := context.Background()

	c, err := opcua.NewClient(*endpoint)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()

	id, err := ua.ParseNodeID(*nodeID)
	if err != nil {
		log.Fatalf("invalid node id: %s", err)
	}

	nodeList, err := browseWithWalkLimit(ctx, c, c.Node(id), *depth)
	if err != nil {
		log.Fatal(err)
	}

	w := csv.NewWriter(os.Stdout)
	w.Comma = ';'
	hdr := []string{"Name", "Type", "Addr", "Unit (SI)", "Scale", "Min", "Max", "Writable", "Description"}
	_ = w.Write(hdr)
	for _, s := range nodeList {
		_ = w.Write(s.Records())
	}
	w.Flush()
}
