// SPDX-License-Identifier: MIT

package nodeset

import "bytes"

// The scanners here match what Remap rewrites. They used to be regular
// expressions, which the race detector made the most expensive part of an
// import (the backtracker state of package regexp is pooled, and the
// detector drops pooled items). scan_test.go keeps the expressions and
// checks the scanners against them (FuzzScanners).

func isSpace(c byte) bool  { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }
func isDigit(c byte) bool  { return '0' <= c && c <= '9' }
func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isWord(c byte) bool   { return isLetter(c) || isDigit(c) || c == '_' }

// replaceNodeIDIndexes replaces each namespace index of a NodeId in the
// string form of Part 6 §5.3.1.10 ("ns=1;i=5") in s with f(index): the
// matches of `(^|[^A-Za-z])ns=(\d+);`, left to right and not overlapping.
// The character before "ns" must not be a letter, so that "nsu=" is left
// alone. It returns s when nothing matches.
func replaceNodeIDIndexes(s []byte, f func(index []byte) []byte) []byte {
	var out []byte
	last := 0 // end of the previous match
	for i := 0; i < len(s); {
		j := bytes.Index(s[i:], []byte("ns="))
		if j < 0 {
			break
		}
		p := i + j
		// The match starts at p (at the start of s) or at the non-letter
		// before p, which a previous match must not have taken.
		ok := p == 0 || p-1 >= last && !isLetter(s[p-1])
		k := p + 3
		for k < len(s) && isDigit(s[k]) {
			k++
		}
		if !ok || k == p+3 || k >= len(s) || s[k] != ';' {
			i = p + 1
			continue
		}
		out = append(out, s[last:p]...)
		out = append(out, "ns="...)
		out = append(out, f(s[p+3:k])...)
		out = append(out, ';')
		last, i = k+1, k+1
	}
	if out == nil {
		return s
	}
	return append(out, s[last:]...)
}

// replaceAttrs replaces each attribute of the start tag raw with
// f(match, space, name, eq, value): the matches of
// `(\s)([A-Za-z_][\w.:-]*)(\s*=\s*)("[^"]*"|'[^']*')`, left to right and
// not overlapping; value keeps its quotes. It returns raw when nothing
// matches.
func replaceAttrs(raw []byte, f func(m, space, name, eq, value []byte) []byte) []byte {
	var out []byte
	last := 0
	for s := 0; s < len(raw); s++ {
		if !isSpace(raw[s]) {
			continue
		}
		n := s + 1
		if n >= len(raw) || !isLetter(raw[n]) && raw[n] != '_' {
			continue
		}
		e := n + 1
		for e < len(raw) && (isWord(raw[e]) || raw[e] == '.' || raw[e] == ':' || raw[e] == '-') {
			e++
		}
		q := e
		for q < len(raw) && isSpace(raw[q]) {
			q++
		}
		if q >= len(raw) || raw[q] != '=' {
			continue
		}
		q++
		for q < len(raw) && isSpace(raw[q]) {
			q++
		}
		if q >= len(raw) || raw[q] != '"' && raw[q] != '\'' {
			continue
		}
		c := bytes.IndexByte(raw[q+1:], raw[q])
		if c < 0 {
			continue
		}
		end := q + 1 + c + 1
		out = append(out, raw[last:s]...)
		out = append(out, f(raw[s:end], raw[s:n], raw[n:e], raw[e:q], raw[q:end])...)
		last, s = end, end-1
	}
	if out == nil {
		return raw
	}
	return append(out, raw[last:]...)
}

// qualifiedPrefix returns the namespace index of the QualifiedName v
// ("1:Name", `^(\d+):`) and the length of the prefix with its colon.
func qualifiedPrefix(v []byte) (index []byte, n int, ok bool) {
	k := 0
	for k < len(v) && isDigit(v[k]) {
		k++
	}
	if k == 0 || k >= len(v) || v[k] != ':' {
		return nil, 0, false
	}
	return v[:k], k + 1, true
}

// numberParts splits the NamespaceIndex v of a QualifiedName value,
// `^(\s*)(\d+)(\s*)$`, into its white space and digits.
func numberParts(v []byte) (lead, digits, trail []byte, ok bool) {
	a := 0
	for a < len(v) && isSpace(v[a]) {
		a++
	}
	b := a
	for b < len(v) && isDigit(v[b]) {
		b++
	}
	c := b
	for c < len(v) && isSpace(v[c]) {
		c++
	}
	if b == a || c != len(v) {
		return nil, nil, nil, false
	}
	return v[:a], v[a:b], v[b:], true
}
