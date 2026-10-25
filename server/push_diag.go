// SPDX-License-Identifier: MIT

package server

import (
	"slices"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// txDiagnostics is the TransactionDiagnostics object of ServerConfiguration
// (TransactionDiagnosticsType, Part 12 §7.10.11): the last transaction, or
// the one in progress.
type txDiagnostics struct {
	start, end time.Time
	result     ua.StatusCode
	trustLists []*ua.NodeID
	groups     []*ua.NodeID
	errs       []*ua.TransactionErrorType
}

// maxTransactionErrors bounds the Errors of TransactionDiagnostics.
const maxTransactionErrors = 32

// startDiagnostics starts the diagnostics of a new transaction.
func (m *pushManager) startDiagnostics() {
	m.diagMu.Lock()
	defer m.diagMu.Unlock()
	m.diag = txDiagnostics{start: m.now(), result: ua.StatusOK}
}

// endDiagnostics records the end of the transaction with its result:
// Good when ApplyChanges applied it, Bad_RequestCancelledByClient when
// CancelChanges or ResetToServerDefaults dropped it, Bad_SessionClosed when
// its session was gone.
func (m *pushManager) endDiagnostics(result ua.StatusCode) {
	m.diagMu.Lock()
	defer m.diagMu.Unlock()
	m.diag.end = m.now()
	m.diag.result = result
}

// setDiagnosticsResult records a failure of ApplyChanges; the transaction
// stays pending.
func (m *pushManager) setDiagnosticsResult(result ua.StatusCode) {
	m.diagMu.Lock()
	defer m.diagMu.Unlock()
	m.diag.result = result
}

// affected records a trust list or a certificate group the transaction
// changes.
func (m *pushManager) affected(trustList, group *ua.NodeID) {
	m.diagMu.Lock()
	defer m.diagMu.Unlock()
	if trustList != nil && !slices.ContainsFunc(m.diag.trustLists, trustList.Equal) {
		m.diag.trustLists = append(m.diag.trustLists, trustList)
	}
	if group != nil && !slices.ContainsFunc(m.diag.groups, group.Equal) {
		m.diag.groups = append(m.diag.groups, group)
	}
}

// recordError adds an error of the transaction.
func (m *pushManager) recordError(target *ua.NodeID, sc ua.StatusCode, msg string) {
	m.diagMu.Lock()
	defer m.diagMu.Unlock()
	if len(m.diag.errs) >= maxTransactionErrors {
		m.diag.errs = slices.Delete(m.diag.errs, 0, 1)
	}
	m.diag.errs = append(m.diag.errs, &ua.TransactionErrorType{TargetID: target, Error: sc, Message: ua.NewLocalizedText(msg)})
}

func (m *pushManager) diagnostics() txDiagnostics {
	m.diagMu.Lock()
	defer m.diagMu.Unlock()
	d := m.diag
	d.trustLists = slices.Clone(d.trustLists)
	d.groups = slices.Clone(d.groups)
	d.errs = slices.Clone(d.errs)
	return d
}

// isTransactionDiagnostics reports whether nid is TransactionDiagnostics or
// one of its properties, which only SecurityAdmin may read (Part 12
// §7.10.11).
func isTransactionDiagnostics(nid *ua.NodeID) bool {
	if nid == nil || nid.Namespace() != 0 || !isNumericNodeID(nid) {
		return false
	}
	n := nid.IntID()
	return n >= id.ServerConfigurationTransactionDiagnostics && n <= id.ServerConfigurationTransactionDiagnosticsErrors
}

// checkRead refuses reads of the TransactionDiagnostics to all but
// SecurityAdmin.
func (m *pushManager) checkRead(sess *session, nid *ua.NodeID) ua.StatusCode {
	if m == nil || !isTransactionDiagnostics(nid) || isSecurityAdmin(sess) {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

// diagnosticsValues are the value functions of the TransactionDiagnostics
// properties.
func (m *pushManager) diagnosticsValues() map[uint32]ValueFunc {
	get := func(f func(d txDiagnostics) any) ValueFunc {
		return func() *ua.DataValue { return DataValueFromValue(f(m.diagnostics())) }
	}
	return map[uint32]ValueFunc{
		id.ServerConfigurationTransactionDiagnosticsStartTime: get(func(d txDiagnostics) any { return d.start.UTC() }),
		id.ServerConfigurationTransactionDiagnosticsEndTime:   get(func(d txDiagnostics) any { return d.end.UTC() }),
		id.ServerConfigurationTransactionDiagnosticsResult:    get(func(d txDiagnostics) any { return d.result }),
		id.ServerConfigurationTransactionDiagnosticsAffectedTrustLists: get(func(d txDiagnostics) any {
			return nonNilNodeIDs(d.trustLists)
		}),
		id.ServerConfigurationTransactionDiagnosticsAffectedCertificateGroups: get(func(d txDiagnostics) any {
			return nonNilNodeIDs(d.groups)
		}),
		id.ServerConfigurationTransactionDiagnosticsErrors: get(func(d txDiagnostics) any { return eos(d.errs) }),
	}
}

func nonNilNodeIDs(xs []*ua.NodeID) []*ua.NodeID {
	if xs == nil {
		return []*ua.NodeID{}
	}
	return xs
}
