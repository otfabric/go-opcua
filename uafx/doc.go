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
// Inspect only reads: it does not establish, verify or close connections.
// The Methods of Part 81 (EstablishConnections, CloseConnections, Verify,
// VerifyAsset and those of the ConnectionManager) are not implemented by
// this package or by package fxserver.
//
// The NodeIds of the UAFX namespaces are in packages fxdataid, fxacid and
// fxcmid, those of the DI model (OPC 10000-100) the UAFX model builds on in
// package di/diid. Package fxserver adds the UAFX model to a server.
package uafx
