// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Package goname provides a shared naming formatter for all OPC UA code
// generators. It converts OPC UA spec identifiers into idiomatic Go names
// by removing underscores, applying CamelCase, and normalizing Go
// initialisms.
package goname

import (
	"go/token"
	"strings"
	"unicode"
)

var (
	idents = strings.NewReplacer(
		"Dns", "DNS",
		"Guid", "GUID",
		"Https", "HTTPS",
		"Http", "HTTP",
		"Id", "ID",
		"Json", "JSON",
		"QualityOfService", "QoS",
		"Tcp", "TCP",
		"Tls", "TLS",
		"Uadp", "UADP",
		"Uri", "URI",
		"Url", "URL",
		"Xml", "XML",
	)

	fixes = strings.NewReplacer(
		"IDentity", "Identity",
		"IDentifier", "Identifier",
		"IDle", "Idle",
	)
)

// Format converts an OPC UA spec token into an idiomatic exported Go
// identifier.
//
// Rules applied in order:
//  1. Split on underscores.
//  2. Drop empty segments.
//  3. Capitalize the first rune of each segment.
//  4. Join segments.
//  5. Normalize known Go initialisms (ID, URI, XML, …).
//  6. Fix over-eager initialism replacements (IDentity → Identity, …).
func Format(s string) string {
	parts := strings.Split(s, "_")
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		runes := []rune(p)
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes))
	}
	result := idents.Replace(b.String())
	return fixes.Replace(result)
}

// IsValidIdent reports whether s is a valid, non-keyword Go identifier.
func IsValidIdent(s string) bool {
	if s == "" {
		return false
	}
	if token.IsKeyword(s) {
		return false
	}
	for i, r := range s {
		if i == 0 && !unicode.IsLetter(r) && r != '_' {
			return false
		}
		if i > 0 && !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}
