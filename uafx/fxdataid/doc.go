// SPDX-License-Identifier: MIT

// Package fxdataid holds the numeric identifiers of the nodes of the
// UAFX Data information model of OPC 10000-81 (opc.ua.fx.data.nodeset2 of the
// OPC Foundation), generated from schema/opc.ua.fx.data.nodeset2.csv by go generate (internal/cmd/gen).
//
// The identifiers belong to the namespace NamespaceURI. Its namespace index
// differs from server to server: resolve it with the NamespaceArray of the
// server, for example ua.NewNumericNodeID(ns, fxdataid.FxRoot).
package fxdataid

// NamespaceURI is the namespace of the UAFX Data information model.
const NamespaceURI = "http://opcfoundation.org/UA/FX/Data/"
