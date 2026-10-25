// SPDX-License-Identifier: MIT

package gdsserver

import (
	"errors"
	"regexp"
	"strings"

	"github.com/otfabric/go-opcua/ua"
)

// likePattern is a pattern of the Like operator (Part 4 §7.7.3), with
// which QueryApplications and QueryServers filter: % matches any string,
// _ any character, [list] and [^list] a character of a list or range, and
// \ escapes the next character. A nil pattern matches everything.
type likePattern struct{ re *regexp.Regexp }

var errLike = errors.New("gdsserver: invalid pattern")

// compileLike compiles a Like pattern.
func compileLike(pattern string) (*likePattern, error) {
	var b strings.Builder
	b.WriteString(`^(?s:`)
	r := []rune(pattern)
	for i := 0; i < len(r); i++ {
		switch c := r[i]; c {
		case '%':
			b.WriteString(`.*`)
		case '_':
			b.WriteString(`.`)
		case '\\':
			if i+1 < len(r) {
				i++
			}
			b.WriteString(regexp.QuoteMeta(string(r[i])))
		case '[':
			j := i + 1
			b.WriteString(`[`)
			if j < len(r) && r[j] == '^' {
				b.WriteString(`^`)
				j++
			}
			start := j
			for ; j < len(r) && r[j] != ']'; j++ {
				switch {
				case r[j] == '\\' && j+1 < len(r):
					j++
					b.WriteString(regexp.QuoteMeta(string(r[j])))
				case r[j] == '-' && j > start && j+1 < len(r) && r[j+1] != ']':
					b.WriteString(`-`)
				default:
					b.WriteString(regexp.QuoteMeta(string(r[j])))
				}
			}
			if j >= len(r) || j == start {
				return nil, errLike
			}
			b.WriteString(`]`)
			i = j
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`)$`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, errLike
	}
	return &likePattern{re: re}, nil
}

func (p *likePattern) match(s string) bool { return p == nil || p.re.MatchString(s) }

// cloneLT copies a LocalizedText.
func cloneLT(l *ua.LocalizedText) *ua.LocalizedText {
	if l == nil {
		return nil
	}
	c := *l
	return &c
}
