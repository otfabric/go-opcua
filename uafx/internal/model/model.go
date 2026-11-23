// SPDX-License-Identifier: MIT

// Package model embeds the NodeSets of the OPC UA FX information model of
// OPC 10000-81 version 1.00.04 and of the Devices (DI) model of OPC 10000-100
// it builds on, as published by the OPC Foundation in the UA-Nodeset
// repository (MIT license). schema/update-schema.sh downloads them.
package model

import _ "embed"

// DI is the NodeSet of the DI information model,
// namespace http://opcfoundation.org/UA/DI/.
//
//go:embed Opc.Ua.Di.NodeSet2.xml
var DI []byte

// Data is the NodeSet of the UAFX Data model,
// namespace http://opcfoundation.org/UA/FX/Data/.
//
//go:embed opc.ua.fx.data.nodeset2.xml
var Data []byte

// AC is the NodeSet of the UAFX AutomationComponent model,
// namespace http://opcfoundation.org/UA/FX/AC/. It requires DI and Data.
//
//go:embed opc.ua.fx.ac.nodeset2.xml
var AC []byte

// CM is the NodeSet of the UAFX ConnectionManager model,
// namespace http://opcfoundation.org/UA/FX/CM/. It requires DI and Data.
//
//go:embed opc.ua.fx.cm.nodeset2.xml
var CM []byte
