// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"strings"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// Access to the diagnostics. Session diagnostics describe the clients of the
// server: their applications, users, certificates and what they do. The
// standard node set grants Anonymous read access to the summary and the
// SessionDiagnosticsArray, and only SecurityAdmin to the
// SessionSecurityDiagnosticsArray (which is also restricted to encrypted
// channels by its AccessRestrictions); EnabledFlag can be written by
// SecurityAdmin and ConfigureAdmin. The diagnostics object of a session can be
// browsed and read by the session itself and by those administrators, its
// SessionSecurityDiagnostics by the session and SecurityAdmin, as
// UA-.NETStandard does. These rules apply in addition to the
// AccessController of the server.

// hasRole reports whether the session was granted one of the roles.
func hasRole(sess *session, roles ...ua.WellKnownRole) bool {
	if sess == nil {
		return false
	}
	for _, r := range sess.roles {
		if r == nil || r.Namespace() != 0 {
			continue
		}
		for _, want := range roles {
			if r.IntID() == uint32(want) {
				return true
			}
		}
	}
	return false
}

// isDiagnosticsAdmin reports whether the session may see the diagnostics of
// other sessions and change EnabledFlag.
func isDiagnosticsAdmin(sess *session) bool {
	return hasRole(sess, ua.RoleSecurityAdmin, ua.RoleConfigureAdmin)
}

// isSecurityAdmin reports whether the session may see the security
// diagnostics of other sessions.
func isSecurityAdmin(sess *session) bool {
	return hasRole(sess, ua.RoleSecurityAdmin)
}

// diagnosticsNamespace returns the index of the diagnostics namespace, or -1
// before it exists.
func (d *serverDiagnostics) diagnosticsNamespace() int {
	return int(d.nsIndex.Load())
}

// checkSessionNode checks the access of sess to a node of the diagnostics
// namespace.
func (d *serverDiagnostics) checkSessionNode(sess *session, nid *ua.NodeID) ua.StatusCode {
	owner := diagnosticsOwner(nid)
	if owner == "" {
		return ua.StatusOK
	}
	if sess != nil && sess.ID != nil && strings.EqualFold(sess.ID.StringID(), owner) {
		return ua.StatusOK
	}
	if nid.Type() == ua.NodeIDTypeString && strings.Contains(nid.StringID(), ".SessionSecurityDiagnostics") {
		if isSecurityAdmin(sess) {
			return ua.StatusOK
		}
		return ua.StatusBadUserAccessDenied
	}
	if isDiagnosticsAdmin(sess) {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

// checkRead checks a Read (or a monitored item) of a diagnostics node.
func (d *serverDiagnostics) checkRead(sess *session, nid *ua.NodeID) ua.StatusCode {
	if d == nil || nid == nil {
		return ua.StatusOK
	}
	switch ns := int(nid.Namespace()); {
	case ns == 0:
		if nid.IntID() == id.ServerServerDiagnosticsSessionsDiagnosticsSummarySessionSecurityDiagnosticsArray && nid.Type() != ua.NodeIDTypeString {
			if !isSecurityAdmin(sess) {
				return ua.StatusBadUserAccessDenied
			}
		}
		return ua.StatusOK
	case ns == d.diagnosticsNamespace():
		return d.checkSessionNode(sess, nid)
	}
	return ua.StatusOK
}

// checkWrite checks a Write of a diagnostics node.
func (d *serverDiagnostics) checkWrite(sess *session, nid *ua.NodeID) ua.StatusCode {
	if nid != nil && nid.Namespace() == 0 && nid.IntID() == id.ServerServerDiagnosticsEnabledFlag && !isDiagnosticsAdmin(sess) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

// isEnabledFlag reports whether a Write targets the Value of EnabledFlag.
func isEnabledFlag(wv *ua.WriteValue) bool {
	return wv != nil && wv.NodeID != nil && wv.NodeID.Namespace() == 0 &&
		wv.NodeID.Type() != ua.NodeIDTypeString && wv.NodeID.IntID() == id.ServerServerDiagnosticsEnabledFlag &&
		wv.AttributeID == ua.AttributeIDValue
}

// writeEnabledFlag applies a Write of EnabledFlag.
func (d *serverDiagnostics) writeEnabledFlag(wv *ua.WriteValue) ua.StatusCode {
	if wv.IndexRange != "" {
		return ua.StatusBadIndexRangeInvalid
	}
	if wv.Value == nil || wv.Value.Value == nil {
		return ua.StatusBadTypeMismatch
	}
	on, ok := wv.Value.Value.Value().(bool)
	if !ok {
		return ua.StatusBadTypeMismatch
	}
	d.setEnabled(on)
	d.s.ChangeNotification(wv.NodeID)
	return ua.StatusOK
}

// filterBrowse removes the diagnostics objects of other sessions from the
// result of browsing SessionsDiagnosticsSummary, unless sess may see them.
func (d *serverDiagnostics) filterBrowse(sess *session, nodeID *ua.NodeID, res *ua.BrowseResult) {
	if res == nil || nodeID == nil || nodeID.Namespace() != 0 ||
		nodeID.IntID() != id.ServerServerDiagnosticsSessionsDiagnosticsSummary || isDiagnosticsAdmin(sess) {
		return
	}
	ns := d.diagnosticsNamespace()
	if ns < 0 {
		return
	}
	kept := make([]*ua.ReferenceDescription, 0, len(res.References))
	for _, r := range res.References {
		if r != nil && r.NodeID != nil && r.NodeID.NodeID != nil && int(r.NodeID.NodeID.Namespace()) == ns &&
			d.checkSessionNode(sess, r.NodeID.NodeID) != ua.StatusOK {
			continue
		}
		kept = append(kept, r)
	}
	res.References = kept
}

// checkRead runs the diagnostics access rules and the AccessController of
// the server for reading a node.
func (s *Server) checkRead(ctx context.Context, sess *session, nid *ua.NodeID) ua.StatusCode {
	if st := s.diag.checkRead(sess, nid); st != ua.StatusOK {
		return st
	}
	if st := s.push.checkRead(sess, nid); st != ua.StatusOK {
		return st
	}
	return s.cfg.accessController.CheckRead(ctx, sess.handle(), nid)
}

// checkWrite is checkRead for writing a node.
func (s *Server) checkWrite(ctx context.Context, sess *session, nid *ua.NodeID) ua.StatusCode {
	if st := s.diag.checkWrite(sess, nid); st != ua.StatusOK {
		return st
	}
	return s.cfg.accessController.CheckWrite(ctx, sess.handle(), nid)
}

// checkBrowse is checkRead for browsing a node.
func (s *Server) checkBrowse(ctx context.Context, sess *session, nid *ua.NodeID) ua.StatusCode {
	if nid != nil && int(nid.Namespace()) == s.diag.diagnosticsNamespace() {
		if st := s.diag.checkSessionNode(sess, nid); st != ua.StatusOK {
			return st
		}
	}
	return s.cfg.accessController.CheckBrowse(ctx, sess.handle(), nid)
}
