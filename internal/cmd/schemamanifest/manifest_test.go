// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
)

const repoRoot = "../../.."

// TestVendoredInputs: the vendored inputs are those of schema/manifest.json
// and the RequiredModels of the vendored NodeSets are satisfied.
func TestVendoredInputs(t *testing.T) {
	m, err := readManifest(filepath.Join(repoRoot, manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(repoRoot, m); err != nil {
		t.Fatal(err)
	}
	// One commit for every input.
	for _, e := range m.Inputs {
		if e.Commit != m.Commit {
			t.Errorf("%s is pinned to %s, the manifest to %s", e.Path, e.Commit, m.Commit)
		}
	}
	// The NodeSets the generators and the server read.
	want := map[string]bool{
		"http://opcfoundation.org/UA/":         true,
		"http://opcfoundation.org/UA/GDS/":     true,
		"http://opcfoundation.org/UA/DI/":      true,
		"http://opcfoundation.org/UA/FX/Data/": true,
		"http://opcfoundation.org/UA/FX/AC/":   true,
		"http://opcfoundation.org/UA/FX/CM/":   true,
	}
	for _, e := range m.Inputs {
		for _, mod := range e.Models {
			delete(want, mod.ModelURI)
		}
	}
	if len(want) != 0 {
		t.Errorf("models not in the manifest: %v", want)
	}
}

func TestCompareModels(t *testing.T) {
	ua := func(mv, date string) Model {
		return Model{ModelURI: "http://opcfoundation.org/UA/", ModelVersion: mv, PublicationDate: date}
	}
	for _, tc := range []struct {
		name string
		a, b Model
		want int
	}{
		// The vendored UA 1.05.07 against the requirements of UAFX and GDS.
		{"later ModelVersion", ua("1.5.7", "2026-07-30T00:00:00Z"), ua("1.5.6", "2025-11-08T00:00:00Z"), 1},
		{"equal ModelVersion, later date", ua("1.5.7", "2026-07-30T00:00:00Z"), ua("1.5.7", "2026-05-01T00:00:00Z"), 1},
		{"equal", ua("1.5.0", "2025-11-15T00:00:00Z"), ua("1.5.0", "2025-11-15T00:00:00Z"), 0},
		{"earlier ModelVersion, later date", ua("1.5.4", "2027-01-01T00:00:00Z"), ua("1.5.6", "2025-11-08T00:00:00Z"), -1},
		{"numeric, not lexical", ua("1.10.0", ""), ua("1.9.0", ""), 1},
		{"only a has ModelVersion", ua("1.0.0", "2020-01-01T00:00:00Z"), ua("", "2026-01-01T00:00:00Z"), 1},
		{"only b has ModelVersion", ua("", "2026-01-01T00:00:00Z"), ua("1.0.0", "2020-01-01T00:00:00Z"), -1},
		{"no ModelVersion, dates", ua("", "2026-07-22T18:52:04Z"), ua("", "2026-07-22T18:52:04Z"), 0},
		{"no ModelVersion, earlier date", ua("", "2026-07-22T18:52:03Z"), ua("", "2026-07-22T18:52:04Z"), -1},
		{"requirement without date", ua("", "2026-07-22T18:52:03Z"), ua("", ""), 1},
		{"pre-release precedes release", ua("1.5.7-rc.1", ""), ua("1.5.7", ""), -1},
		{"release follows pre-release", ua("1.5.7", ""), ua("1.5.7-rc.1", ""), 1},
		{"numeric pre-release identifiers", ua("1.5.7-rc.10", ""), ua("1.5.7-rc.9", ""), 1},
		{"numeric before alphanumeric", ua("1.5.7-1", ""), ua("1.5.7-a", ""), -1},
		{"alphanumeric after numeric", ua("1.5.7-a", ""), ua("1.5.7-1", ""), 1},
		{"alphanumeric", ua("1.5.7-alpha", ""), ua("1.5.7-beta", ""), -1},
		{"more pre-release identifiers", ua("1.5.7-rc.1.1", ""), ua("1.5.7-rc.1", ""), 1},
		{"build metadata ignored", ua("1.5.7+abc", ""), ua("1.5.7", ""), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := compareModels(tc.a, tc.b)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("compareModels = %d, want %d", got, tc.want)
			}
		})
	}
	for _, tc := range [][2]Model{
		{ua("1.05.07", ""), ua("1.5.6", "")},
		{ua("1.5.6", ""), ua("1.05", "")},
		{ua("", "yesterday"), ua("", "2026-07-22T18:52:04Z")},
		{ua("", "2026-07-22T18:52:04Z"), ua("", "2026-07-22")},
		{ua("1.5.6", "2026"), ua("1.5.6", "2026-07-22T18:52:04Z")},
	} {
		if _, err := compareModels(tc[0], tc[1]); err == nil {
			t.Errorf("compareModels(%+v, %+v) passed", tc[0], tc[1])
		}
	}
}

func TestRequiredModels(t *testing.T) {
	base := Model{ModelURI: "urn:base", ModelVersion: "1.5.7", PublicationDate: "2026-07-30T00:00:00Z"}
	need := func(req Model) []Input {
		return []Input{
			{Path: "base.xml", Models: []Model{base}},
			{Path: "dep.xml", Models: []Model{{ModelURI: "urn:dep", RequiredModels: []Model{req}}}},
		}
	}
	if errs := requiredModels(need(Model{ModelURI: "urn:base", ModelVersion: "1.5.6", PublicationDate: "2025-11-08T00:00:00Z"})); len(errs) != 0 {
		t.Errorf("an older requirement is not satisfied: %v", errs)
	}
	for name, req := range map[string]Model{
		"newer":        {ModelURI: "urn:base", ModelVersion: "1.6.0"},
		"not vendored": {ModelURI: "urn:other"},
		"bad version":  {ModelURI: "urn:base", ModelVersion: "one"},
	} {
		if errs := requiredModels(need(req)); len(errs) != 1 {
			t.Errorf("%s: %d errors: %v", name, len(errs), errs)
		}
	}
}

func TestReadModels(t *testing.T) {
	ms, err := readModels([]byte(`<UANodeSet><NamespaceUris><Uri>urn:a</Uri></NamespaceUris><Models>
<Model ModelUri="urn:a" Version="1.00" ModelVersion="1.0.0" PublicationDate="2026-01-01T00:00:00Z">
<RequiredModel ModelUri="http://opcfoundation.org/UA/" Version="1.05.06" ModelVersion="1.5.6"/></Model>
<Model ModelUri="urn:b"/></Models><UAObject NodeId="i=1"/></UANodeSet>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].ModelURI != "urn:a" || ms[0].Version != "1.00" || ms[0].ModelVersion != "1.0.0" ||
		ms[0].PublicationDate != "2026-01-01T00:00:00Z" || len(ms[0].RequiredModels) != 1 ||
		ms[0].RequiredModels[0].ModelVersion != "1.5.6" || ms[1].ModelURI != "urn:b" {
		t.Errorf("readModels = %+v", ms)
	}
	for _, doc := range []string{
		`<UANodeSet></UANodeSet>`,
		`<UANodeSet><Models></Models></UANodeSet>`,
		`<UANodeSet><Models><Model Version="1"/></Models></UANodeSet>`,
		`<UANodeSet><Models><Model ModelUri="urn:a"></Models></UANodeSet>`,
		`<UANodeSet><`,
	} {
		if _, err := readModels([]byte(doc)); err == nil {
			t.Errorf("readModels(%s) passed", doc)
		}
	}
}

// fakeInputs replaces the inputs with two small files for one test.
func fakeInputs(t *testing.T) {
	t.Helper()
	saved := inputs
	inputs = []input{
		{"schema/a.csv", "Schema/a.csv"},
		{"model/b.xml", "B/b.xml"},
	}
	cleanup.Register(t, func() { inputs = saved })
}

const fakeCommit = "0123456789abcdef0123456789abcdef01234567"

var fakeFiles = map[string]string{
	"Schema/a.csv": "Boolean,1,DataType\n",
	"B/b.xml": `<UANodeSet><Models><Model ModelUri="urn:b" ModelVersion="1.0.0" PublicationDate="2026-01-01T00:00:00Z">` +
		`<RequiredModel ModelUri="urn:b" ModelVersion="1.0.0"/></Model></Models></UANodeSet>`,
}

// fakeUpstream serves the GitHub API and the raw files for fakeFiles.
func fakeUpstream(t *testing.T, files map[string]string) upstream {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+upstreamRepo+"/commits/", func(w http.ResponseWriter, r *http.Request) {
		ref := strings.TrimPrefix(r.URL.Path, "/repos/"+upstreamRepo+"/commits/")
		switch ref {
		case "latest", fakeCommit:
			if r.Header.Get("Authorization") != "Bearer secret" {
				http.Error(w, "no token", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"sha":"` + fakeCommit + `","commit":{"committer":{"date":"2026-11-18T08:20:55Z"}}}`))
		case "garbage":
			_, _ = w.Write([]byte(`{`))
		case "short":
			_, _ = w.Write([]byte(`{"sha":"abc"}`))
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/"+upstreamRepo+"/"+fakeCommit+"/", func(w http.ResponseWriter, r *http.Request) {
		data, ok := files[strings.TrimPrefix(r.URL.Path, "/"+upstreamRepo+"/"+fakeCommit+"/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(data))
	})
	srv := httptest.NewServer(mux)
	cleanup.Register(t, srv.Close)
	return upstream{api: srv.URL, raw: srv.URL, token: "secret", client: srv.Client()}
}

func TestUpdateAndVerify(t *testing.T) {
	fakeInputs(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "schema"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := fakeUpstream(t, fakeFiles)
	var out bytes.Buffer
	if err := update(root, "latest", u, &out); err != nil {
		t.Fatalf("update: %v\n%s", err, out.String())
	}
	m, err := readManifest(filepath.Join(root, manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if m.Commit != fakeCommit || m.CommitDate != "2026-11-18T08:20:55Z" || len(m.Inputs) != 2 ||
		m.Inputs[0].Models != nil || len(m.Inputs[1].Models) != 1 || m.Inputs[1].Models[0].ModelURI != "urn:b" {
		t.Errorf("manifest = %+v", m)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "model", "b.xml")); string(got) != fakeFiles["B/b.xml"] {
		t.Errorf("b.xml = %q", got)
	}

	// Without a ref, update downloads the commit of the manifest again.
	if err := update(root, "", u, &out); err != nil {
		t.Fatal(err)
	}
	again, _ := readManifest(filepath.Join(root, manifestPath))
	if string(again.encode()) != string(m.encode()) {
		t.Error("updating to the pinned commit changes the manifest")
	}

	// verify notices every kind of difference.
	mutate := func(name string, f func(m *Manifest), file func()) {
		t.Helper()
		c, _ := readManifest(filepath.Join(root, manifestPath))
		f(c)
		if file != nil {
			file()
		}
		if err := verify(root, c); err == nil {
			t.Errorf("%s: verify passed", name)
		}
	}
	mutate("repository", func(m *Manifest) { m.Repository = "someone/else" }, nil)
	mutate("commit", func(m *Manifest) { m.Commit = "latest" }, nil)
	mutate("input commit", func(m *Manifest) { m.Inputs[0].Commit = "latest" }, nil)
	mutate("missing input", func(m *Manifest) { m.Inputs = m.Inputs[:1] }, nil)
	mutate("other path", func(m *Manifest) { m.Inputs[0].Path = "schema/c.csv" }, nil)
	mutate("sha256", func(m *Manifest) { m.Inputs[0].SHA256 = strings.Repeat("0", 64) }, nil)
	mutate("models", func(m *Manifest) { m.Inputs[1].Models[0].Version = "2" }, nil)
	mutate("bad NodeSet", func(m *Manifest) {}, func() {
		if err := os.WriteFile(filepath.Join(root, "model", "b.xml"), []byte("<UANodeSet/>"), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	mutate("missing file", func(m *Manifest) {}, func() {
		if err := os.Remove(filepath.Join(root, "schema", "a.csv")); err != nil {
			t.Fatal(err)
		}
	})
}

func TestUpdateFails(t *testing.T) {
	fakeInputs(t)
	u := fakeUpstream(t, fakeFiles)
	var out bytes.Buffer
	for _, ref := range []string{"missing", "garbage", "short"} {
		if err := update(t.TempDir(), ref, u, &out); err == nil {
			t.Errorf("ref %s: update passed", ref)
		}
	}
	// No ref and no manifest.
	if err := update(t.TempDir(), "", u, &out); err == nil {
		t.Error("update without ref or manifest passed")
	}
	// A file is missing upstream: nothing is written.
	root := t.TempDir()
	if err := update(root, "latest", fakeUpstream(t, map[string]string{"Schema/a.csv": "x"}), &out); err == nil {
		t.Error("update with a missing upstream file passed")
	}
	if _, err := os.Stat(filepath.Join(root, "schema", "a.csv")); !os.IsNotExist(err) {
		t.Error("update wrote a file although a download failed")
	}
	// A NodeSet without Models.
	if err := update(t.TempDir(), "latest", fakeUpstream(t, map[string]string{"Schema/a.csv": "x", "B/b.xml": "<UANodeSet/>"}), &out); err == nil {
		t.Error("update with a NodeSet without Models passed")
	}
	// An unsatisfied requirement is reported after the files are written.
	bad := map[string]string{"Schema/a.csv": "x", "B/b.xml": `<UANodeSet><Models><Model ModelUri="urn:b"><RequiredModel ModelUri="urn:c"/></Model></Models></UANodeSet>`}
	root = t.TempDir()
	if err := update(root, "latest", fakeUpstream(t, bad), &out); err == nil || !strings.Contains(err.Error(), "urn:c") {
		t.Errorf("update with an unsatisfied requirement: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, manifestPath)); err != nil {
		t.Error("update did not write the manifest it reports on")
	}
	// The root cannot be written.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := update(file, "latest", u, &out); err == nil {
		t.Error("update into a file passed")
	}
	// No host.
	if _, err := (upstream{client: http.DefaultClient}).download(fakeCommit, "x"); err == nil {
		t.Error("download without a host passed")
	}
}

func TestDownloadLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, maxInput+1))
	}))
	defer srv.Close()
	u := upstream{raw: srv.URL, client: srv.Client()}
	if _, err := u.download(fakeCommit, "big"); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("download of a too large file: %v", err)
	}
}

func TestDiff(t *testing.T) {
	old := &Manifest{Commit: fakeCommit, CommitDate: "2026-11-18T08:20:55Z", Inputs: []Input{
		{Path: "schema/a.csv", Upstream: "Schema/a.csv", SHA256: "aaaaaaaaaaaaaaaa"},
		{Path: "model/b.xml", Upstream: "B/b.xml", SHA256: "bbbbbbbbbbbbbbbb", Models: []Model{{ModelURI: "urn:b", Version: "1.05.07", ModelVersion: "1.5.7"}}},
		{Path: "model/c.xml", Upstream: "C/c.xml", SHA256: "cccc", Models: []Model{{ModelURI: "urn:c"}}},
	}}
	if got := diff(old, old); !strings.Contains(got, "No input differs.") {
		t.Errorf("diff of a manifest with itself:\n%s", got)
	}

	cur := &Manifest{Commit: strings.Repeat("f", 40), CommitDate: "2026-12-01T00:00:00Z", Inputs: []Input{
		{Path: "schema/a.csv", Upstream: "Schema/a.csv", SHA256: "aaaaaaaaaaaaaaaa"},
		{Path: "model/b.xml", Upstream: "B/b.xml", SHA256: "cbbbbbbbbbbbbbbb", Models: []Model{{
			ModelURI: "urn:b", Version: "1.05.08", ModelVersion: "1.5.8",
			RequiredModels: []Model{{ModelURI: "urn:c", ModelVersion: "1.0.0"}},
		}}},
		{Path: "model/d.xml", Upstream: "D/d.xml", SHA256: "dddd", Models: []Model{{ModelURI: "urn:d"}}},
	}}
	got := diff(old, cur)
	for _, want := range []string{
		"| Commit | `0123456789ab` (2026-11-18T08:20:55Z) | `ffffffffffff` (2026-12-01T00:00:00Z) |",
		"| `model/b.xml` | `B/b.xml` | `bbbbbbbbbbbb` → `cbbbbbbbbbbb` |",
		"| `model/c.xml` | `C/c.xml` | removed |",
		"| `model/d.xml` | `D/d.xml` | new input |",
		"| `urn:b` | 1.05.07 (1.5.7)  | 1.05.08 (1.5.8) <br>requires `urn:c`  (1.0.0)  |",
		"| `urn:c` |  ()  | removed |",
		"| `urn:d` | |  ()  |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diff lacks\n%s\nin\n%s", want, got)
		}
	}
	if strings.Contains(got, "schema/a.csv") {
		t.Errorf("diff reports an unchanged input:\n%s", got)
	}

	// A changed CSV alone changes no model.
	csv := *old
	csv.Inputs = append([]Input{{Path: "schema/a.csv", Upstream: "Schema/a.csv", SHA256: "aaaaaaaaaaaaaaab"}}, old.Inputs[1:]...)
	if got := diff(old, &csv); !strings.Contains(got, "No model version, publication date or required model changed.") {
		t.Errorf("diff of a changed CSV:\n%s", got)
	}
}

func TestRun(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{nil, {"what"}, {"diff", "one"}, {"diff", "missing", "missing"}, {"update", "-unknown"}} {
		if err := run(args, &out); err == nil {
			t.Errorf("run(%q) passed", args)
		}
	}
	dir := t.TempDir()
	m := &Manifest{Repository: upstreamRepo, Commit: fakeCommit}
	path := filepath.Join(dir, "m.json")
	if err := os.WriteFile(path, m.encode(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"diff", path, filepath.Join(dir, "missing")}, &out); err == nil {
		t.Error("run diff with a missing manifest passed")
	}
	out.Reset()
	if err := run([]string{"diff", path, path}, &out); err != nil || !strings.Contains(out.String(), "No input differs.") {
		t.Errorf("run diff: %v\n%s", err, out.String())
	}
	// An unknown field is an error, so a typo in the manifest is noticed.
	var raw map[string]any
	if err := json.Unmarshal(m.encode(), &raw); err != nil {
		t.Fatal(err)
	}
	raw["comit"] = "x"
	data, _ := json.Marshal(raw)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(path); err == nil {
		t.Error("a manifest with an unknown field passed")
	}
}

// TestRunVerify runs the verify command from the module root, as the gen
// driver does.
func TestRunVerify(t *testing.T) {
	t.Chdir(repoRoot)
	var out bytes.Buffer
	if err := run([]string{"verify"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Vendored schema matches") {
		t.Errorf("verify printed %q", out.String())
	}
}

func TestShort(t *testing.T) {
	if short("abc") != "abc" || short(fakeCommit) != "0123456789ab" {
		t.Error("short")
	}
}
