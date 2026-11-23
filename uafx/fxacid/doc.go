// SPDX-License-Identifier: MIT

// Package fxacid holds the numeric identifiers of the nodes of the
// UAFX AutomationComponent information model of OPC 10000-81
// (opc.ua.fx.ac.nodeset2 of the OPC Foundation), generated from
// schema/opc.ua.fx.ac.nodeset2.csv by go generate (internal/cmd/gen).
//
// The identifiers belong to the namespace NamespaceURI. Its namespace index
// differs from server to server: resolve it with the NamespaceArray of the
// server, for example ua.NewNumericNodeID(ns, fxacid.AutomationComponentType).
package fxacid

// NamespaceURI is the namespace of the UAFX AutomationComponent information model.
const NamespaceURI = "http://opcfoundation.org/UA/FX/AC/"
