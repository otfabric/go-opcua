// SPDX-License-Identifier: MIT

// Package uafx reads the OPC UA FX (UAFX) information model of a server:
// OPC 10000-81 version 1.00.04, Connecting Devices and Information Model.
//
// Inspect reports the UAFX namespaces of a server with their versions, the
// FxRoot object (Part 81 §12.2), the AutomationComponents FxRoot organizes
// with their Assets, FunctionalEntities, ConnectionEndpoints, health and
// descriptors, and the ConnectionManager (§12.3). Deviations from Part 81
// that it can see in the address space, such as a missing mandatory member
// or a missing namespace, are Findings of the report.
//
//	r, err := uafx.Inspect(ctx, client, uafx.Limits{})
//	if err != nil { ... }
//	for _, ac := range r.AutomationComponents {
//		fmt.Println(ac.BrowseName.Name, ac.AggregatedHealth)
//	}
//
// EstablishConnections and CloseConnections call the Methods of an
// AutomationComponent that establish and close connections (§6.2.4,
// §6.2.5); package fxserver serves them. The structures of their arguments
// and the codecs that encode them with the namespace index of the server
// are in this package. Verify, VerifyAsset and the Methods of the
// ConnectionManager have no client functions.
//
// The NodeIds of the UAFX namespaces are in packages fxdataid, fxacid and
// fxcmid, those of the DI model (OPC 10000-100) the UAFX model builds on in
// package di/diid. Package fxserver adds the UAFX model to a server.
package uafx
