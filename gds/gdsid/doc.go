// SPDX-License-Identifier: MIT

// Package gdsid holds the numeric identifiers of the nodes of the Global
// Discovery Server information model of OPC UA Part 12 (the
// Opc.Ua.Gds.NodeSet2 of the OPC Foundation), generated from
// schema/Opc.Ua.Gds.NodeIds.csv by go generate (internal/cmd/gen).
//
// The identifiers belong to the namespace NamespaceURI. Its namespace index
// differs from server to server: resolve it with the NamespaceArray of the
// server, for example ua.NewNumericNodeID(ns, gdsid.Directory).
package gdsid

// NamespaceURI is the namespace of the GDS information model.
const NamespaceURI = "http://opcfoundation.org/UA/GDS/"
