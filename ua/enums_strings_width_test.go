// SPDX-License-Identifier: MIT

package ua

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestEnumStrings_UnsignedFullRange checks that the String method of an
// enumeration with an unsigned type gives a name or "Type(n)" for every
// value, also where int has 32 bits: the table has the low end, the values
// on both sides of 1<<31 and the largest value of the type.
func TestEnumStrings_UnsignedFullRange(t *testing.T) {
	values := []uint64{0, 1, 1<<31 - 2, 1<<31 - 1, 1 << 31, 1<<31 + 1, 1<<32 - 2, 1<<32 - 1}
	for name, conv := range enumStringers() {
		kind := reflect.TypeOf(conv(0)).Kind()
		var width uint
		switch kind {
		case reflect.Uint8:
			width = 8
		case reflect.Uint16:
			width = 16
		case reflect.Uint32:
			width = 32
		default:
			continue
		}
		for _, v := range values {
			n := v & (1<<width - 1)
			s := conv(int64(v)).String()
			if s == "" {
				t.Errorf("%s(%d).String() is empty", name, n)
				continue
			}
			// No enumeration defines a value of 1<<31 or more.
			if n >= 1<<31 {
				if want := fmt.Sprintf("%s(%d)", name, n); s != want {
					t.Errorf("%s(%d).String() = %q, want %q", name, n, s, want)
				}
				continue
			}
			if strings.HasPrefix(s, name+"(") && s != fmt.Sprintf("%s(%d)", name, n) {
				t.Errorf("%s(%d).String() = %q, want the name or %s(%d)", name, n, s, name, n)
			}
		}
	}
}
