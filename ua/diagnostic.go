// SPDX-License-Identifier: MIT

package ua

import (
	"strconv"
	"strings"
)

// Diagnostic is a DiagnosticInfo with the strings it refers to resolved
// against the string table of its response (Part 4 §7.12): the members of a
// DiagnosticInfo are indexes into ResponseHeader.StringTable.
type Diagnostic struct {
	// SymbolicID is the symbolic id of the status, e.g. "BadNodeIdUnknown",
	// in the namespace NamespaceURI.
	SymbolicID   string
	NamespaceURI string
	// LocalizedText is a human readable description in the locale Locale.
	LocalizedText string
	Locale        string
	// AdditionalInfo is vendor specific text, e.g. the operation the status
	// belongs to.
	AdditionalInfo string
	// InnerStatusCode is the status of the inner operation that caused the
	// status, Inner its diagnostics.
	InnerStatusCode StatusCode
	Inner           *Diagnostic
}

// maxDiagnosticDepth bounds the InnerDiagnosticInfo chain Resolve follows.
const maxDiagnosticDepth = 32

// Resolve resolves the DiagnosticInfo against the string table of its
// response. It returns nil for a nil or empty DiagnosticInfo. An index
// outside the table resolves to the empty string.
func (d *DiagnosticInfo) Resolve(table []string) *Diagnostic {
	return d.resolve(table, 0)
}

func (d *DiagnosticInfo) resolve(table []string, depth int) *Diagnostic {
	if d == nil || d.EncodingMask == 0 || depth >= maxDiagnosticDepth {
		return nil
	}
	str := func(flag byte, idx int32) string {
		if !d.Has(flag) || idx < 0 || int(idx) >= len(table) {
			return ""
		}
		return table[idx]
	}
	out := &Diagnostic{
		SymbolicID:    str(DiagnosticInfoSymbolicID, d.SymbolicID),
		NamespaceURI:  str(DiagnosticInfoNamespaceURI, d.NamespaceURI),
		LocalizedText: str(DiagnosticInfoLocalizedText, d.LocalizedText),
		Locale:        str(DiagnosticInfoLocale, d.Locale),
	}
	if d.Has(DiagnosticInfoAdditionalInfo) {
		out.AdditionalInfo = d.AdditionalInfo
	}
	if d.Has(DiagnosticInfoInnerStatusCode) {
		out.InnerStatusCode = d.InnerStatusCode
	}
	if d.Has(DiagnosticInfoInnerDiagnosticInfo) {
		out.Inner = d.InnerDiagnosticInfo.resolve(table, depth+1)
	}
	return out
}

// String returns the diagnostic in one line.
func (d *Diagnostic) String() string {
	if d == nil {
		return ""
	}
	var parts []string
	add := func(s string) {
		if s != "" {
			parts = append(parts, s)
		}
	}
	add(d.SymbolicID)
	if d.LocalizedText != "" {
		add(strconv.Quote(d.LocalizedText))
	}
	add(d.AdditionalInfo)
	if d.InnerStatusCode != 0 {
		add("inner " + d.InnerStatusCode.Error())
	}
	if d.Inner != nil {
		add("(" + d.Inner.String() + ")")
	}
	return strings.Join(parts, " ")
}

// ServiceDiagnostic returns the resolved service diagnostics of the
// response, nil if there are none.
func (h *ResponseHeader) ServiceDiagnostic() *Diagnostic {
	if h == nil {
		return nil
	}
	return h.ServiceDiagnostics.Resolve(h.StringTable)
}

// Diagnostic resolves a DiagnosticInfo of the response (an element of its
// DiagnosticInfos) against the string table of the header.
func (h *ResponseHeader) Diagnostic(d *DiagnosticInfo) *Diagnostic {
	if h == nil {
		return d.Resolve(nil)
	}
	return d.Resolve(h.StringTable)
}
