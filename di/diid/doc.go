// SPDX-License-Identifier: MIT

// Package diid holds the numeric identifiers of the nodes of the
// Devices (DI) information model of OPC 10000-100 (the Opc.Ua.Di.NodeSet2 of the OPC Foundation), generated from
// schema/Opc.Ua.Di.NodeIds.csv by go generate (internal/cmd/gen).
//
// The identifiers belong to the namespace NamespaceURI. Its namespace index
// differs from server to server: resolve it with the NamespaceArray of the
// server, for example ua.NewNumericNodeID(ns, diid.DeviceSet).
package diid

// NamespaceURI is the namespace of the DI information model.
const NamespaceURI = "http://opcfoundation.org/UA/DI/"
