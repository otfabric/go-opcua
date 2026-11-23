// SPDX-License-Identifier: MIT

package nodeset

import (
	"bytes"
	"os"
	"regexp"
	"testing"
)

// The regular expressions the scanners of scan.go replace: the oracle of
// FuzzScanners.
var (
	nodeIDIndexRE = regexp.MustCompile(`(^|[^A-Za-z])ns=(\d+);`)
	attrRE        = regexp.MustCompile(`(\s)([A-Za-z_][\w.:-]*)(\s*=\s*)("[^"]*"|'[^']*')`)
	prefixRE      = regexp.MustCompile(`^(\d+):`)
	numberRE      = regexp.MustCompile(`^(\s*)(\d+)(\s*)$`)
)

// checkScanners compares each scanner with its regular expression on in.
func checkScanners(t *testing.T, in []byte) {
	t.Helper()
	mark := func(idx []byte) []byte { return append(append([]byte("<"), idx...), '>') }

	want := nodeIDIndexRE.ReplaceAllFunc(in, func(m []byte) []byte {
		sub := nodeIDIndexRE.FindSubmatch(m)
		return concat(sub[1], []byte("ns="), mark(sub[2]), []byte(";"))
	})
	if got := replaceNodeIDIndexes(in, mark); !bytes.Equal(got, want) {
		t.Fatalf("replaceNodeIDIndexes(%q) = %q, want %q", in, got, want)
	}

	want = attrRE.ReplaceAllFunc(in, func(m []byte) []byte {
		sub := attrRE.FindSubmatch(m)
		return concat([]byte("["), sub[1], []byte("|"), sub[2], []byte("|"), sub[3], []byte("|"), sub[4], []byte("]"))
	})
	got := replaceAttrs(in, func(m, space, name, eq, value []byte) []byte {
		if !bytes.Equal(m, concat(space, name, eq, value)) {
			t.Fatalf("replaceAttrs(%q): match %q is not its parts", in, m)
		}
		return concat([]byte("["), space, []byte("|"), name, []byte("|"), eq, []byte("|"), value, []byte("]"))
	})
	if !bytes.Equal(got, want) {
		t.Fatalf("replaceAttrs(%q) = %q, want %q", in, got, want)
	}

	idx, n, ok := qualifiedPrefix(in)
	if p := prefixRE.FindSubmatch(in); (p != nil) != ok || ok && (!bytes.Equal(p[1], idx) || len(p[0]) != n) {
		t.Fatalf("qualifiedPrefix(%q) = %q, %d, %v, want %q", in, idx, n, ok, p)
	}

	lead, digits, trail, ok := numberParts(in)
	if m := numberRE.FindSubmatch(in); (m != nil) != ok || ok && (!bytes.Equal(m[1], lead) || !bytes.Equal(m[2], digits) || !bytes.Equal(m[3], trail)) {
		t.Fatalf("numberParts(%q) = %q, %q, %q, %v, want %q", in, lead, digits, trail, ok, m)
	}
}

func TestScanners(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"", "ns=1;i=5", "ns=1;ns=2;", " ns=12;s=x", "nsu=urn:x;i=1", "xns=1;", "-ns=1;", "ns=;", "ns=1", "éns=3;i=1", "\xffns=3;",
		`<UAVariable NodeId="ns=1;i=5" BrowseName='1:X' a = "b" _c.d:e-f="g">`, `<a x="unterminated>`, `<a  x="1"y="2">`,
		"<a\tb\n=\r'q'>", "<a 1x=\"y\">", "1:Name", "12:", ":x", "x:1", "  42 ", "4 2", " ", "7",
	} {
		checkScanners(t, []byte(in))
	}
	// The embedded models.
	for _, f := range []string{"Opc.Ua.Di.NodeSet2.xml", "opc.ua.fx.ac.nodeset2.xml"} {
		doc, err := os.ReadFile("../../uafx/internal/model/" + f)
		if err != nil {
			t.Fatal(err)
		}
		checkScanners(t, doc)
	}
}

// FuzzScanners checks the scanners of scan.go against the regular
// expressions they replace.
func FuzzScanners(f *testing.F) {
	for _, s := range []string{"ns=1;i=5", `<a b="ns=2;i=1" c='1:x'>`, " 3 ", "4:y", "nsu=u;ns=1;"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) { checkScanners(t, in) })
}

func BenchmarkRemapModels(b *testing.B) {
	var docs [][]byte
	for _, f := range []string{"Opc.Ua.Di.NodeSet2.xml", "opc.ua.fx.data.nodeset2.xml", "opc.ua.fx.ac.nodeset2.xml", "opc.ua.fx.cm.nodeset2.xml"} {
		d, err := os.ReadFile("../../uafx/internal/model/" + f)
		if err != nil {
			b.Fatal(err)
		}
		docs = append(docs, d)
	}
	resolve := func(string) (uint16, error) { return 5, nil }
	b.ReportAllocs()
	for b.Loop() {
		for _, d := range docs {
			if _, err := Remap(d, resolve); err != nil {
				b.Fatal(err)
			}
		}
	}
}
