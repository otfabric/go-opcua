// SPDX-License-Identifier: MIT

package gdsserver

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// allocatedBytes returns the number of bytes fn allocates.
func allocatedBytes(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// likeCompileBudget is the allocation budget of compiling a Like pattern of
// n bytes: a fixed part and a part per byte of the pattern.
func likeCompileBudget(n int) uint64 { return 64<<10 + 2048*uint64(n) }

// TestQueryPatternLengthIsCheckedBeforeCompiling: the patterns of
// QueryApplications and QueryServers have the length limit of a string
// argument. A longer pattern is refused with Bad_InvalidArgument without
// being compiled, so refusing it costs the same whatever its length. It
// runs alone (not in parallel): it measures allocations.
func TestQueryPatternLengthIsCheckedBeforeCompiling(t *testing.T) {
	const refusalBudget = 64 << 10
	for _, tt := range []struct {
		name    string
		pattern string
		want    ua.StatusCode
	}{
		{"empty", "", ua.StatusOK},
		{"one wildcard", "%", ua.StatusOK},
		{"limit minus one", strings.Repeat("%", maxStringLen-1), ua.StatusOK},
		{"limit", strings.Repeat("%", maxStringLen), ua.StatusOK},
		{"limit, literals", strings.Repeat("a", maxStringLen), ua.StatusOK},
		{"limit, wildcards and literals", strings.Repeat("%_", maxStringLen/2), ua.StatusOK},
		{"limit plus one", strings.Repeat("%", maxStringLen+1), ua.StatusBadInvalidArgument},
		{"limit plus one, literals", strings.Repeat("a", maxStringLen+1), ua.StatusBadInvalidArgument},
		{"64 KiB", strings.Repeat("%", 64<<10), ua.StatusBadInvalidArgument},
		{"1 MiB", strings.Repeat("%", 1<<20), ua.StatusBadInvalidArgument},
		{"1 MiB, wildcards and literals", strings.Repeat("%a", 1<<19), ua.StatusBadInvalidArgument},
		{"not UTF-8", "a\xffb", ua.StatusBadInvalidArgument},
		{"unterminated list", "[abc", ua.StatusBadInvalidArgument},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The pattern in each of the three arguments that take one.
			for i := range 3 {
				args := [3]string{}
				args[i] = tt.pattern
				var q *query
				var sc ua.StatusCode
				n := allocatedBytes(func() { q, sc = newQuery(args[0], args[1], args[2], nil) })
				require.Equal(t, tt.want, sc, "argument %d", i)
				if sc != ua.StatusOK {
					require.Nil(t, q)
					require.Less(t, n, uint64(refusalBudget), "bytes allocated to refuse a pattern of %d bytes", len(tt.pattern))
					continue
				}
				require.NotNil(t, q)
				require.Less(t, n, likeCompileBudget(len(tt.pattern)), "bytes allocated to compile a pattern of %d bytes", len(tt.pattern))
			}
		})
	}
}

// TestLikeRepeatedWildcards: consecutive % are compiled as one. The pattern
// then is the pattern with a single %, and matches what it matched as
// written. An escaped % and a % in a list are characters, not wildcards,
// and stay.
func TestLikeRepeatedWildcards(t *testing.T) {
	t.Parallel()
	subjects := []string{
		"", "a", "b", "ab", "ba", "aXb", "aXXb", "abab", "a%b", "a%%b", "%", "%%", "%%%",
		"a%", "a%X", `a\`, `a\b`, "a\nb", "aé☃b", "xa", "axbxc", "abc", "a_b", "[%%]", "-", "a]b",
	}
	for _, tt := range []struct {
		repeated, single string
	}{
		{"%%", "%"},
		{"%%%%%%%%", "%"},
		{"a%%", "a%"},
		{"%%a", "%a"},
		{"a%%b", "a%b"},
		{"a%%%b", "a%b"},
		{"%%a%%b%%", "%a%b%"},
		{"a%%_%%b", "a%_%b"},
		{"_%%", "_%"},
		{"%%_", "%_"},
		{`a\%%%`, `a\%%`},      // an escaped %, then wildcards
		{`a\%%%b`, `a\%%b`},    //
		{`\%%%\%`, `\%%\%`},    //
		{`a\\%%b`, `a\\%b`},    // an escaped backslash, then wildcards
		{"[%]%%", "[%]%"},      // a list of %, then wildcards
		{"%%[^%]%%", "%[^%]%"}, //
		{"[a-c]%%[a-c]", "[a-c]%[a-c]"},
		{strings.Repeat("%", maxStringLen), "%"},
		{strings.Repeat("%", maxStringLen/2) + "b", "%b"},
	} {
		rp, err := compileLike(tt.repeated)
		require.NoError(t, err, tt.repeated)
		sp, err := compileLike(tt.single)
		require.NoError(t, err, tt.single)
		name := tt.repeated
		if len(name) > 32 {
			name = name[:32] + "..."
		}
		require.Equal(t, sp.re.String(), rp.re.String(), "%q compiles to what %q compiles to", name, tt.single)
		for _, s := range subjects {
			require.Equal(t, sp.match(s), rp.match(s), "%q and %q on %q", name, tt.single, s)
		}
	}

	// What a repeated % matches, spelled out.
	for _, tt := range []struct {
		pattern, s string
		match      bool
	}{
		{"a%%b", "ab", true},
		{"a%%b", "aXXb", true},
		{"a%%b", "a\nb", true},
		{"a%%b", "aXbX", false},
		{"%%", "", true},
		{"%%", "anything", true},
		{`a\%%%`, "a%", true},
		{`a\%%%`, "a%XYZ", true},
		{`a\%%%`, "aXYZ", false},
		{"[%%]", "%", true}, // a list with % twice: one character
		{"[%%]", "%%", false},
		{"[%%]", "a", false},
		{`\%\%`, "%%", true}, // two escaped %: two characters
		{`\%\%`, "%", false},
		{`\%\%`, "%X%", false},
	} {
		p, err := compileLike(tt.pattern)
		require.NoError(t, err, tt.pattern)
		require.Equal(t, tt.match, p.match(tt.s), "%q ~ %q", tt.pattern, tt.s)
	}
}

// FuzzCompileLike: a pattern within the length limit of a string argument
// compiles within an allocation budget that depends on its length only,
// repeating its wildcards does not change what it compiles to, and a
// pattern beyond the limit is refused by the query without being compiled.
func FuzzCompileLike(f *testing.F) {
	for _, s := range []string{
		"", "%", "%%", "a%b", "a_c", `a\%`, `a\`, "[a-c]x", "[^a-c]x", "[-a]x", `[\]]x`, "[", "[]", "a[bc",
		"%\n%", "é%☃", "a\xffb",
		strings.Repeat("%", maxStringLen), strings.Repeat("%", maxStringLen+1),
		strings.Repeat("%a", maxStringLen/2), strings.Repeat("_", maxStringLen),
		strings.Repeat("[a-z]", maxStringLen/5), strings.Repeat("a", maxStringLen),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		if !validString(pattern) {
			var sc ua.StatusCode
			n := allocatedBytes(func() { _, sc = newQuery(pattern, "", "", nil) })
			if sc != ua.StatusBadInvalidArgument {
				t.Fatalf("a pattern of %d bytes is not refused: %v", len(pattern), sc)
			}
			if n > 64<<10 {
				t.Fatalf("%d bytes allocated to refuse a pattern of %d bytes", n, len(pattern))
			}
			return
		}
		var p *likePattern
		var err error
		n := allocatedBytes(func() { p, err = compileLike(pattern) })
		if budget := likeCompileBudget(len(pattern)); n > budget {
			t.Fatalf("%d bytes allocated to compile a pattern of %d bytes, the budget is %d", n, len(pattern), budget)
		}
		if err != nil {
			return
		}
		p.match("")
		p.match("a%_[x]")
		// A % after the pattern is a wildcard unless the pattern ends in an
		// escape character; a second one after it changes nothing.
		one, err1 := compileLike(pattern + "x%")
		two, err2 := compileLike(pattern + "x%%")
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("%q: one %% after it: %v, two: %v", pattern, err1, err2)
		}
		if err1 == nil && one.re.String() != two.re.String() {
			t.Fatalf("%q: a repeated %% compiles to %q, a single one to %q", pattern, two.re, one.re)
		}
	})
}
