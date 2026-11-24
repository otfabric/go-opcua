// SPDX-License-Identifier: MIT

// Package fxcm is a UAFX ConnectionManager: OPC 10000-81 version 1.00.04,
// §6.7 to §6.16, §13 and Annex F.
//
// A ConnectionConfigurationSet comes in as the Annex F structure
// uafx.ConnectionConfigurationSetConf, from a file (DecodeFile, F.2) or
// built in Go. NewConfig validates it and turns it into an immutable Config,
// one per Version of the set (§6.8.2). An Edit is the transactional edit of
// §6.7.4: a working copy that CommitUpdates turns into the next Version.
//
// State is the state machine of a set (§6.9), with the transitions an
// action may start and the event each one has. The ownership classes of the
// ConnectionEndpoints a ConnectionManager finds (Ownership) and the
// decisions over them (what a run may close, when a lost response proves an
// endpoint ours, when a set may be processed again by itself) are pure
// functions, as are the diagnostics of §10.19 and the ConnectionState of
// §10.20.
//
// A Manager holds sets and processes them against the AutomationComponents
// (§6.7.3, §6.7.5): it dials their servers through a Dialer, resolves the
// identifiers of a set (§13.3), and calls EstablishConnections and
// CloseConnections (§6.2.4, §6.2.5). Process starts a Run per set and
// returns at once; Status, the Observer and the Counters report what the
// runs do. An endpoint whose ownership a run cannot prove is Unresolved and
// never closed until Settle decides it.
//
// The design of the ConnectionManager, which the comments cite as
// "design §n", is docs/design/uafx-connection-manager.md (go-opcua pull
// request 44).
package fxcm
