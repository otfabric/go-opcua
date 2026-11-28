// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxInput bounds the size of one downloaded input; the largest, the
// NodeSet of namespace 0, is below 20 MB.
const maxInput = 64 << 20

// upstream is where update resolves refs and downloads files.
type upstream struct {
	api    string // the GitHub REST API
	raw    string // the raw file host
	token  string // optional, raises the API rate limit
	client *http.Client
}

func defaultUpstream() upstream {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	return upstream{
		api:    "https://api.github.com",
		raw:    "https://raw.githubusercontent.com",
		token:  token,
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

// resolve returns the commit a ref names and its committer date.
func (u upstream) resolve(ref string) (commit, date string, err error) {
	req, err := http.NewRequest(http.MethodGet, u.api+"/repos/"+upstreamRepo+"/commits/"+url.PathEscape(ref), nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if u.token != "" {
		req.Header.Set("Authorization", "Bearer "+u.token)
	}
	body, err := u.get(req)
	if err != nil {
		return "", "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	var c struct {
		SHA    string `json:"sha"`
		Commit struct {
			Committer struct {
				Date string `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return "", "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	if !commitRE.MatchString(c.SHA) {
		return "", "", fmt.Errorf("resolve %s: commit %q", ref, c.SHA)
	}
	return c.SHA, c.Commit.Committer.Date, nil
}

// download returns a file of the upstream repository at a commit.
func (u upstream) download(commit, path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, u.raw+"/"+upstreamRepo+"/"+commit+"/"+path, nil)
	if err != nil {
		return nil, err
	}
	body, err := u.get(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", path, err)
	}
	return body, nil
}

func (u upstream) get(req *http.Request) ([]byte, error) {
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", req.URL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInput+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxInput {
		return nil, fmt.Errorf("%s: larger than %d bytes", req.URL, maxInput)
	}
	return body, nil
}

// update downloads every input at ref (the commit of the manifest when
// ref is empty) into root and rewrites the manifest. Nothing is written
// unless every download succeeds and every NodeSet has a Models element.
func update(root, ref string, u upstream, stdout io.Writer) error {
	if ref == "" {
		m, err := readManifest(filepath.Join(root, manifestPath))
		if err != nil {
			return fmt.Errorf("no ref and no manifest: %w", err)
		}
		ref = m.Commit
	}
	commit, date, err := u.resolve(ref)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "UA-Nodeset %s is commit %s (%s)\n", ref, commit, date)
	m := &Manifest{Repository: upstreamRepo, Commit: commit, CommitDate: date}
	files := make([][]byte, len(inputs))
	for i, in := range inputs {
		_, _ = fmt.Fprintf(stdout, "Downloading %s\n", in.upstream)
		data, err := u.download(commit, in.upstream)
		if err != nil {
			return err
		}
		e, err := describe(in, commit, data)
		if err != nil {
			return err
		}
		files[i] = data
		m.Inputs = append(m.Inputs, e)
	}
	for i, in := range inputs {
		path := filepath.Join(root, filepath.FromSlash(in.path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, files[i], 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(root, manifestPath), m.encode(), 0o644); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Wrote %s\n", manifestPath)
	return verify(root, m)
}

// diff reports, in Markdown, how the inputs and models of cur differ from
// those of old: the commits, the inputs whose content changed, and the
// Version, ModelVersion, PublicationDate and RequiredModels of each model.
func diff(old, cur *Manifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "| | Pinned | Upstream |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| Commit | `%s` (%s) | `%s` (%s) |\n\n", short(old.Commit), old.CommitDate, short(cur.Commit), cur.CommitDate)

	oldIn := map[string]Input{}
	for _, e := range old.Inputs {
		oldIn[e.Path] = e
	}
	var rows []string
	for _, e := range cur.Inputs {
		o, ok := oldIn[e.Path]
		switch {
		case !ok:
			rows = append(rows, fmt.Sprintf("| `%s` | `%s` | new input |", e.Path, e.Upstream))
		case o.SHA256 != e.SHA256:
			rows = append(rows, fmt.Sprintf("| `%s` | `%s` | `%s` → `%s` |", e.Path, e.Upstream, o.SHA256[:min(12, len(o.SHA256))], e.SHA256[:min(12, len(e.SHA256))]))
		}
		delete(oldIn, e.Path)
	}
	for _, o := range oldIn {
		rows = append(rows, fmt.Sprintf("| `%s` | `%s` | removed |", o.Path, o.Upstream))
	}
	if len(rows) == 0 {
		b.WriteString("No input differs.\n")
		return b.String()
	}
	sort.Strings(rows)
	b.WriteString("| Input | Upstream path | SHA-256 |\n|---|---|---|\n")
	b.WriteString(strings.Join(rows, "\n"))
	b.WriteString("\n\n")

	models := func(m *Manifest) map[string]Model {
		out := map[string]Model{}
		for _, e := range m.Inputs {
			for _, mod := range e.Models {
				out[mod.ModelURI] = mod
			}
		}
		return out
	}
	om, cm := models(old), models(cur)
	rows = rows[:0]
	for uri, c := range cm {
		o, ok := om[uri]
		if !ok {
			rows = append(rows, fmt.Sprintf("| `%s` | | %s |", uri, modelCell(c)))
			continue
		}
		if !modelEqual(o, c) {
			rows = append(rows, fmt.Sprintf("| `%s` | %s | %s |", uri, modelCell(o), modelCell(c)))
		}
	}
	for uri, o := range om {
		if _, ok := cm[uri]; !ok {
			rows = append(rows, fmt.Sprintf("| `%s` | %s | removed |", uri, modelCell(o)))
		}
	}
	if len(rows) == 0 {
		b.WriteString("No model version, publication date or required model changed.\n")
		return b.String()
	}
	sort.Strings(rows)
	b.WriteString("| Model | Pinned | Upstream |\n|---|---|---|\n")
	b.WriteString(strings.Join(rows, "\n"))
	b.WriteString("\n")
	return b.String()
}

func modelEqual(a, b Model) bool { return modelCell(a) == modelCell(b) }

// modelCell describes a model in a table cell: its versions, publication
// date and the versions it requires.
func modelCell(m Model) string {
	s := fmt.Sprintf("%s (%s) %s", m.Version, m.ModelVersion, m.PublicationDate)
	for _, r := range m.RequiredModels {
		s += fmt.Sprintf("<br>requires `%s` %s (%s) %s", r.ModelURI, r.Version, r.ModelVersion, r.PublicationDate)
	}
	return s
}
