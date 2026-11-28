// SPDX-License-Identifier: MIT

package profiles

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const moduleRoot = "../.."

// TestInventory checks the inventory against the pinned profile set and the
// module: every ConformanceUnit of a target has an entry, every test,
// ledger row and document of an entry exists, and docs/profiles.md and
// server/server_profiles_gen.go are those the inventory gives. A renamed
// test fails it.
func TestInventory(t *testing.T) {
	files, err := Generate(moduleRoot)
	require.NoError(t, err)
	require.Len(t, files, 2)
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(moduleRoot, name))
		require.NoError(t, err)
		require.Equal(t, string(want), string(got), "%s is out of date: run make gen", name)
	}
}

// TestPinnedTargets: the target Profiles expand, through the Profiles they
// include, to the ConformanceUnits of the pinned profile database export.
func TestPinnedTargets(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(moduleRoot, "internal/profiles/testdata/ProfileSet_UACore_1.05.xml"))
	require.NoError(t, err)
	ps, err := ParseProfileSet(data)
	require.NoError(t, err)
	require.Equal(t, "UACore 1.05", ps.Group)

	count := func(reqs []Requirement) (mandatory, optional int) {
		for _, r := range reqs {
			if r.Optional {
				optional++
			} else {
				mandatory++
			}
		}
		return mandatory, optional
	}
	p, reqs, err := ps.Requirements("http://opcfoundation.org/UA-Profile/Server/MicroEmbeddedDevice2025")
	require.NoError(t, err)
	require.Equal(t, "Micro Embedded Device 2025 Server Profile", p.Name)
	require.False(t, p.Deprecated)
	m, o := count(reqs)
	require.Equal(t, [2]int{30, 32}, [2]int{m, o})
	var names []string
	for _, inc := range ps.Included(p) {
		names = append(names, inc.Name)
	}
	require.Equal(t, []string{
		"Nano Embedded Device 2025 Server Profile",
		"Core 2022 Server Facet",
		"Security Time Synchronization",
		"UA-TCP UA-SC UA-Binary",
		"Embedded DataChange Subscription 2022 Server Facet",
	}, names)

	_, reqs, err = ps.Requirements("http://opcfoundation.org/UA-Profile/Client/Standard2025")
	require.NoError(t, err)
	m, o = count(reqs)
	require.Equal(t, [2]int{48, 55}, [2]int{m, o})

	old, _, err := ps.Requirements("http://opcfoundation.org/UA-Profile/Server/MicroEmbeddedDevice2022")
	require.NoError(t, err)
	require.True(t, old.Deprecated)
}

const testSet = "\xef\xbb\xbf" + `<?xml version="1.0" encoding="utf-8"?>
<UAProfileSet xmlns="http://opcfoundation.org/UA/schema/UAProfileSet.xsd">
  <ProfileGroups><ProfileGroup Index="1" FullName="G" /></ProfileGroups>
  <Profiles>
    <Profile Name="Root" Id="r"><ProfileUri>urn:root</ProfileUri>
      <Profiles><ProfileId>f</ProfileId><ProfileId>f2</ProfileId></Profiles>
      <ConformanceUnits><IncludedConformanceUnit Id="a" /><IncludedConformanceUnit Id="b" IsOptional="true" /></ConformanceUnits>
    </Profile>
    <Profile Name="Facet" Id="f"><ProfileUri>urn:facet</ProfileUri>
      <Profiles><ProfileId>f2</ProfileId></Profiles>
      <ConformanceUnits><IncludedConformanceUnit Id="b" /><IncludedConformanceUnit Id="c" IsOptional="true" /></ConformanceUnits>
    </Profile>
    <Profile Name="Facet2" Id="f2"><ProfileUri>urn:facet2</ProfileUri></Profile>
    <Profile Name="Client" Id="cl"><ProfileUri>urn:client</ProfileUri>
      <ConformanceUnits><IncludedConformanceUnit Id="a" /></ConformanceUnits>
    </Profile>
    <Profile Name="Old" Id="o" ReleaseStatus="Deprecated"><ProfileUri>urn:old</ProfileUri></Profile>
    <Profile Name="BadUnit" Id="bu"><ProfileUri>urn:badunit</ProfileUri>
      <ConformanceUnits><IncludedConformanceUnit Id="zz" /></ConformanceUnits>
    </Profile>
    <Profile Name="BadInclude" Id="bi"><ProfileUri>urn:badinclude</ProfileUri>
      <Profiles><ProfileId>zz</ProfileId></Profiles>
    </Profile>
    <Profile Name="BadDeep" Id="bd"><ProfileUri>urn:baddeep</ProfileUri>
      <Profiles><ProfileId>bi</ProfileId></Profiles>
    </Profile>
  </Profiles>
  <ConformanceUnits>
    <ConformanceUnit Name=" A" Id="a" />
    <ConformanceUnit Name="B" Id="b" />
    <ConformanceUnit Name="C" Id="c" />
  </ConformanceUnits>
</UAProfileSet>
`

func testProfileSet(t *testing.T) *ProfileSet {
	t.Helper()
	ps, err := ParseProfileSet([]byte(testSet))
	require.NoError(t, err)
	return ps
}

func TestParseProfileSet(t *testing.T) {
	ps := testProfileSet(t)
	require.Equal(t, "G", ps.Group)
	require.Len(t, ps.Profiles, 8)
	require.Equal(t, "A", ps.Units["a"].Name, "the name is trimmed")

	_, err := ParseProfileSet([]byte("<UAProfileSet>"))
	require.ErrorContains(t, err, "profile set")
	_, err = ParseProfileSet([]byte("<UAProfileSet />"))
	require.ErrorContains(t, err, "0 profile groups")
}

func TestRequirements(t *testing.T) {
	ps := testProfileSet(t)
	p, reqs, err := ps.Requirements("urn:root")
	require.NoError(t, err)
	require.Equal(t, "Root", p.Name)
	require.Equal(t, []Requirement{
		{Unit: Unit{ID: "a", Name: "A"}, From: []string{"Root"}},
		{Unit: Unit{ID: "b", Name: "B"}, From: []string{"Root", "Facet"}},
		{Unit: Unit{ID: "c", Name: "C"}, Optional: true, From: []string{"Facet"}},
	}, reqs, "a unit is mandatory when any Profile lists it so")

	_, _, err = ps.Requirements("urn:none")
	require.ErrorContains(t, err, "no profile urn:none in G")
	_, _, err = ps.Requirements("urn:badunit")
	require.ErrorContains(t, err, "BadUnit lists unknown conformance unit zz")
	_, _, err = ps.Requirements("urn:baddeep")
	require.ErrorContains(t, err, "BadInclude includes unknown profile zz")
}

func TestIncluded(t *testing.T) {
	ps := testProfileSet(t)
	names := func(uri string) []string {
		var out []string
		for _, p := range ps.Included(ps.byURI[uri]) {
			out = append(out, p.Name)
		}
		return out
	}
	require.Equal(t, []string{"Facet", "Facet2"}, names("urn:root"), "each once")
	require.Empty(t, names("urn:badinclude"), "an unknown Profile is skipped")
}

func TestParseInventory(t *testing.T) {
	inv, err := ParseInventory([]byte(`{"targets": [{"uri": "urn:root", "role": "server"}],
		"units": [{"role": "server", "unit": "A", "status": "evidenced", "tests": [".:TestA"], "note": "n"}]}`))
	require.NoError(t, err)
	require.Equal(t, []Target{{URI: "urn:root", Role: RoleServer}}, inv.Targets)

	_, err = ParseInventory([]byte(`{"other": 1}`))
	require.ErrorContains(t, err, "unknown field")

	_, err = ParseInventory([]byte(`{"targets": [{"uri": "urn:root", "role": "peer"}], "units": [
		{"role": "peer", "unit": "A", "status": "missing", "note": "n"},
		{"role": "server", "unit": "B", "status": "missing", "note": "n"},
		{"role": "server", "unit": "B", "status": "missing", "note": "n"},
		{"role": "server", "unit": "C", "status": "done", "note": "n"},
		{"role": "server", "unit": "D", "status": "partial"},
		{"role": "client", "unit": "E", "status": "evidenced", "note": "n"}]}`))
	for _, want := range []string{
		`target urn:root: role "peer"`,
		`"A": role "peer"`,
		`server "B": more than one entry`,
		`server "C": status "done"`,
		`server "D": no note`,
		`client "E": evidenced without a test`,
	} {
		require.ErrorContains(t, err, want)
	}
}

func evaluate(t *testing.T, inventory string) (*Report, error) {
	t.Helper()
	inv, err := ParseInventory([]byte(inventory))
	require.NoError(t, err)
	return Evaluate(testProfileSet(t), inv)
}

func TestEvaluate(t *testing.T) {
	rep, err := evaluate(t, `{"targets": [{"uri": "urn:root", "role": "server"}, {"uri": "urn:client", "role": "client"}], "units": [
		{"role": "server", "unit": "C", "status": "missing", "note": "n"},
		{"role": "server", "unit": "B", "status": "partial", "tests": [".:TestB"], "note": "n"},
		{"role": "server", "unit": "A", "status": "evidenced", "tests": [".:TestA"], "note": "n"},
		{"role": "client", "unit": "A", "status": "evidenced", "tests": [".:TestA"], "note": "n"}]}`)
	require.NoError(t, err)
	require.Len(t, rep.Targets, 2)
	srv := &rep.Targets[0]
	require.False(t, srv.Claimed, "B is partial")
	require.Equal(t, []string{"A", "B", "C"}, []string{srv.Rows[0].Unit.Name, srv.Rows[1].Unit.Name, srv.Rows[2].Unit.Name})
	require.Equal(t, 1, srv.Count(false, StatusEvidenced))
	require.Equal(t, 1, srv.Count(false, StatusPartial))
	require.Equal(t, 1, srv.Count(true, StatusMissing))
	require.True(t, rep.Targets[1].Claimed)
	require.Equal(t, []string{}, rep.ServerProfiles(), "a client Profile is no server Profile")

	rep, err = evaluate(t, `{"targets": [{"uri": "urn:root", "role": "server"}], "units": [
		{"role": "server", "unit": "C", "status": "missing", "note": "n"},
		{"role": "server", "unit": "B", "status": "evidenced", "tests": [".:TestB"], "note": "n"},
		{"role": "server", "unit": "A", "status": "evidenced", "tests": [".:TestA"], "note": "n"}]}`)
	require.NoError(t, err)
	require.True(t, rep.Targets[0].Claimed, "an optional unit may be missing")
	require.Equal(t, []string{"urn:root"}, rep.ServerProfiles())
}

func TestEvaluateErrors(t *testing.T) {
	_, err := evaluate(t, `{"targets": [{"uri": "urn:none", "role": "server"}, {"uri": "urn:old", "role": "server"},
		{"uri": "urn:root", "role": "server"}], "units": [
		{"role": "server", "unit": "A", "status": "missing", "note": "n"},
		{"role": "server", "unit": "Z", "status": "missing", "note": "n"}]}`)
	for _, want := range []string{
		"no profile urn:none",
		"target Old is deprecated",
		`Root: no server entry for "B"`,
		`server entry "Z" is for no unit of a target`,
	} {
		require.ErrorContains(t, err, want)
	}
}

// writeFiles writes files, by slash path, under a new directory.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
	return root
}

const testLedger = `{"interopVersion": "v9", "entries": [
	{"capability": "read", "direction": "a-client-to-go-server", "status": "verified"},
	{"capability": "write", "direction": "a-client-to-go-server", "status": "deferred"}]}`

const testDoc = "# Guide\n\n## Limits (server)\n\n```\n# not a heading\n```\n\n## Limits (server)\n\n#nospace\n text\n"

func TestReadLedger(t *testing.T) {
	root := writeFiles(t, map[string]string{"l.json": testLedger, "bad.json": "{"})
	l, err := ReadLedger(filepath.Join(root, "l.json"))
	require.NoError(t, err)
	require.Equal(t, "v9", l.InteropVersion)
	require.Equal(t, map[string]bool{"read|a-client-to-go-server": true}, l.Verified)

	_, err = ReadLedger(filepath.Join(root, "none.json"))
	require.Error(t, err)
	_, err = ReadLedger(filepath.Join(root, "bad.json"))
	require.ErrorContains(t, err, "bad.json")
}

func TestCheckEvidence(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"pkg/a_test.go":    "package pkg\n\nfunc TestA(t *testing.T) {}\n\nfunc (s) TestMethod() {}\n",
		"pkg/b_test.go":    "//go:build interop\n\npackage pkg\n\nfunc TestB(t *testing.T) {}\n",
		"broken/a_test.go": "package broken\n\nfunc {\n",
		"empty/a.go":       "package empty\n",
		"docs/guide.md":    testDoc,
	})
	ledger := &Ledger{Verified: map[string]bool{"read|a-client-to-go-server": true}}
	check := func(e Entry) error {
		e.Role, e.Name = RoleServer, "U"
		return CheckEvidence(root, &Inventory{Units: []Entry{e}}, ledger)
	}

	require.NoError(t, check(Entry{
		Tests:  []string{"pkg:TestA", "pkg:TestB"},
		Ledger: []string{"read|a-client-to-go-server"},
		Docs:   []string{"docs/guide.md", "docs/guide.md#guide", "docs/guide.md#limits-server", "docs/guide.md#limits-server-1"},
	}))

	for ref, want := range map[string]string{
		"pkg/TestA":         `test "pkg/TestA" is not dir:TestName`,
		"pkg:Example":       `test "pkg:Example" is not dir:TestName`,
		"pkg:TestMethod":    "no func TestMethod in pkg",
		"pkg:TestC":         "no func TestC in pkg",
		"empty:TestA":       "no test files in",
		"none[:TestA":       "syntax error in pattern",
		"broken:TestBroken": "expected",
	} {
		require.ErrorContains(t, check(Entry{Tests: []string{ref}}), want, ref)
	}
	require.ErrorContains(t, check(Entry{Ledger: []string{"write|a-client-to-go-server"}}), "write|a-client-to-go-server is no verified row")
	require.ErrorContains(t, check(Entry{Docs: []string{"docs/none.md"}}), "document docs/none.md")
	require.ErrorContains(t, check(Entry{Docs: []string{"docs/guide.md#not-a-heading"}}), `no heading with anchor "not-a-heading"`)
	require.ErrorContains(t, check(Entry{Docs: []string{"docs/guide.md#nospace"}}), `no heading with anchor "nospace"`)
}

func TestSlugify(t *testing.T) {
	require.Equal(t, "session-and-subscription-limits-server", slugify(" Session and subscription limits (server) "))
	require.Equal(t, "per_call-limits-ü", slugify("Per_call limits: Ü!"))
}

// testModule writes a module with a profile set, its source, an inventory
// and a ledger, with the given changes; a nil value leaves a file out.
func testModule(t *testing.T, change map[string]*string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(testSet))
	files := map[string]string{
		"internal/profiles/testdata/set.xml": testSet,
		SourcePath: `{"file": "set.xml", "url": "https://example.com/x", "page": "https://example.com/",
			"profileGroup": "G", "releaseStatus": "Released", "retrieved": "2026-11-28", "servedAs": "x.xml",
			"sha256": "` + hex.EncodeToString(sum[:]) + `"}`,
		InventoryPath: `{"targets": [{"uri": "urn:root", "role": "server"}], "units": [
			{"role": "server", "unit": "A", "status": "evidenced", "tests": ["pkg:TestA"], "note": "n"},
			{"role": "server", "unit": "B", "status": "evidenced", "tests": ["pkg:TestA"], "ledger": ["read|a-client-to-go-server"], "docs": ["docs/guide.md#guide"], "note": "a|b"},
			{"role": "server", "unit": "C", "status": "missing", "note": "n"}]}`,
		LedgerPath:      testLedger,
		"pkg/a_test.go": "package pkg\n\nfunc TestA(t *testing.T) {}\n",
		"docs/guide.md": testDoc,
	}
	for name, data := range change {
		if data == nil {
			delete(files, name)
		} else {
			files[name] = *data
		}
	}
	return writeFiles(t, files)
}

func ptr(s string) *string { return &s }

func TestGenerate(t *testing.T) {
	files, err := Generate(testModule(t, nil))
	require.NoError(t, err)
	gen := string(files[ServerGenPath])
	require.Contains(t, gen, "var evidencedServerProfiles = []string{\n\t\"urn:root\",\n}\n")
	md := string(files[ReportPath])
	for _, want := range []string{
		"| Root | server | 2 / 0 / 0 | 0 / 0 / 1 | yes |",
		"The default ServerProfileArray is `urn:root`.",
		"- Facet, `urn:facet`",
		"Every mandatory ConformanceUnit is evidenced.",
		"| B | mandatory | evidenced | `pkg:TestA`<br>ledger `read\\|a-client-to-go-server`<br>`docs/guide.md#guide` | a\\|b |",
		"| C | optional | missing |  | n |",
		"opcua-interop v9",
	} {
		require.Contains(t, md, want)
	}
}

func TestGenerateErrors(t *testing.T) {
	badSum := `{"file": "set.xml", "sha256": "00", "profileGroup": "G"}`
	sum := sha256.Sum256([]byte("<x"))
	badSet := `{"file": "set.xml", "sha256": "` + hex.EncodeToString(sum[:]) + `", "profileGroup": "G"}`
	sum = sha256.Sum256([]byte(testSet))
	otherGroup := `{"file": "set.xml", "sha256": "` + hex.EncodeToString(sum[:]) + `", "profileGroup": "H"}`
	for name, tc := range map[string]struct {
		change map[string]*string
		want   string
	}{
		"no source":     {map[string]*string{SourcePath: nil}, "ProfileSet_UACore_1.05.source.json"},
		"bad source":    {map[string]*string{SourcePath: ptr("{")}, SourcePath},
		"no set":        {map[string]*string{"internal/profiles/testdata/set.xml": nil}, "set.xml"},
		"sha mismatch":  {map[string]*string{SourcePath: &badSum}, "the source pins 00"},
		"bad set":       {map[string]*string{SourcePath: &badSet, "internal/profiles/testdata/set.xml": ptr("<x")}, "profile set"},
		"other group":   {map[string]*string{SourcePath: &otherGroup}, `is profile group "G", the source says "H"`},
		"no inventory":  {map[string]*string{InventoryPath: nil}, "inventory.json"},
		"bad inventory": {map[string]*string{InventoryPath: ptr("{")}, "inventory"},
		"no entry":      {map[string]*string{InventoryPath: ptr(`{"targets": [{"uri": "urn:root", "role": "server"}]}`)}, `no server entry for "A"`},
		"no ledger":     {map[string]*string{LedgerPath: nil}, "coverage.json"},
		"renamed test":  {map[string]*string{"pkg/a_test.go": ptr("package pkg\n\nfunc TestRenamed(t *testing.T) {}\n")}, "no func TestA in pkg"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Generate(testModule(t, tc.change))
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestServerGoEmpty(t *testing.T) {
	got := string(ServerGo(&Report{}))
	require.True(t, strings.HasSuffix(got, "// No target Profile is yet.\nvar evidencedServerProfiles = []string{}\n"), got)
	require.Contains(t, got, "// Code generated by internal/cmd/profiles. DO NOT EDIT.")
}
