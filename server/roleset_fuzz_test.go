// SPDX-License-Identifier: MIT

package server

import (
	"encoding/asn1"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// FuzzRoleSetSubjectCriteria: the X509Subject criteria of an
// IdentityMappingRuleType a client sends to AddIdentity (OPC 10000-18
// §4.4.3). A criteria taken is a list of name="value" in the order of
// Table 10.
func FuzzRoleSetSubjectCriteria(f *testing.F) {
	for _, s := range []string{`CN="a"`, `CN="a"/O="b"/OU="c"/OU="d"/DC="e"/L="f"/S="g"/C="h"/dnQualifier="i"/serialNumber="j"`,
		`O="a"/CN="b"`, `CN="a`, `CN="a"/`, `=`, `CN=""`, "CN=\"\x00\""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !validSubjectCriteria(s) {
			return
		}
		// The pairs tile the criteria, separated by '/', in order.
		order, end := -1, 0
		for _, m := range subjectPair.FindAllStringSubmatchIndex(s, -1) {
			if m[0] != end {
				t.Fatalf("%q taken: no pair at %d", s, end)
			}
			name := s[m[2]:m[3]]
			i := slices.IndexFunc(subjectNames, func(x struct {
				name string
				oid  asn1.ObjectIdentifier
			}) bool {
				return x.name == name
			})
			if i < order {
				t.Fatalf("%q taken: %s out of order", s, name)
			}
			order, end = i, m[1]
			if end < len(s) && s[end] == '/' {
				end++
			}
		}
		if end != len(s) || strings.HasSuffix(s, "/") {
			t.Fatalf("%q taken: trailing %q", s, s[end:])
		}
	})
}

var subjectPair = regexp.MustCompile(`(CN|OU|O|DC|L|S|C|dnQualifier|serialNumber)="[^"]*"`)

// FuzzRoleSetJWTClaims: the claims of the JWT of an IssuedIdentityToken a
// client activates a session with (Part 6 §6.5.2.3).
func FuzzRoleSetJWTClaims(f *testing.F) {
	for _, s := range [][]byte{testJWT(`{"iss":"idp","roles":["r"],"groups":["g"]}`), testJWT(`{}`), testJWT(`[]`),
		[]byte("a.b.c"), []byte("..."), nil} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, ok := parseJWTClaims(data)
		if !ok {
			return
		}
		roles, groups := c.qualified()
		if len(roles) != len(c.Roles) || len(groups) != len(c.Groups) {
			t.Fatalf("qualified changed the number of claims: %v %v", roles, groups)
		}
		for _, r := range roles {
			if c.Iss != "" && !strings.HasPrefix(r, c.Iss+"/") {
				t.Fatalf("role %q not qualified by %q", r, c.Iss)
			}
		}
	})
}
