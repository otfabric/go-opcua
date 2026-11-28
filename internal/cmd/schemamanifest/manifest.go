// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// upstreamRepo is the GitHub repository the inputs come from.
const upstreamRepo = "OPCFoundation/UA-Nodeset"

// manifestPath is the manifest, relative to the module root.
const manifestPath = "schema/manifest.json"

// input is a vendored input of the code generators, of the runtime or of
// the tests: the path in this repository and the path in the upstream
// repository.
type input struct{ path, upstream string }

// inputs lists every file schema/update-schema.sh downloads, in the order
// of the manifest. A file ending in .xml is a NodeSet2 file (OPC 10000-6
// Annex F).
var inputs = []input{
	{"schema/NodeIds.csv", "Schema/NodeIds.csv"},
	{"schema/StatusCode.csv", "Schema/StatusCode.csv"},
	{"schema/AttributeIds.csv", "Schema/AttributeIds.csv"},
	{"schema/ServerCapabilities.csv", "Schema/ServerCapabilities.csv"},
	{"schema/Opc.Ua.NodeIds.permissions.csv", "Schema/Opc.Ua.NodeIds.permissions.csv"},
	{"schema/Opc.Ua.Types.bsd", "Schema/Opc.Ua.Types.bsd"},
	{"internal/schema/Opc.Ua.NodeSet2.xml", "Schema/Opc.Ua.NodeSet2.xml"},
	{"schema/Opc.Ua.Gds.NodeIds.csv", "GDS/Opc.Ua.Gds.NodeIds.csv"},
	{"internal/schema/Opc.Ua.Gds.NodeSet2.xml", "GDS/Opc.Ua.Gds.NodeSet2.xml"},
	{"schema/Opc.Ua.Di.NodeIds.csv", "DI/Opc.Ua.Di.NodeIds.csv"},
	{"uafx/internal/model/Opc.Ua.Di.NodeSet2.xml", "DI/Opc.Ua.Di.NodeSet2.xml"},
	{"schema/opc.ua.fx.data.nodeset2.csv", "UAFX/opc.ua.fx.data.nodeset2.csv"},
	{"uafx/internal/model/opc.ua.fx.data.nodeset2.xml", "UAFX/opc.ua.fx.data.nodeset2.xml"},
	{"schema/opc.ua.fx.data.nodeset2.bsd", "UAFX/opc.ua.fx.data.nodeset2.bsd"},
	{"schema/opc.ua.fx.ac.nodeset2.csv", "UAFX/opc.ua.fx.ac.nodeset2.csv"},
	{"uafx/internal/model/opc.ua.fx.ac.nodeset2.xml", "UAFX/opc.ua.fx.ac.nodeset2.xml"},
	{"schema/opc.ua.fx.ac.nodeset2.bsd", "UAFX/opc.ua.fx.ac.nodeset2.bsd"},
	{"schema/opc.ua.fx.cm.nodeset2.csv", "UAFX/opc.ua.fx.cm.nodeset2.csv"},
	{"uafx/internal/model/opc.ua.fx.cm.nodeset2.xml", "UAFX/opc.ua.fx.cm.nodeset2.xml"},
	{"schema/opc.ua.fx.cm.nodeset2.bsd", "UAFX/opc.ua.fx.cm.nodeset2.bsd"},
	// The examples of Part 13 Annex A, the evidence of server/aggregate.
	{"server/aggregate/testdata/AggregateExamples.csv", "Schema/AggregateExamples.csv"},
}

func (in input) isNodeSet() bool { return strings.HasSuffix(strings.ToLower(in.path), ".xml") }

// Manifest is schema/manifest.json.
type Manifest struct {
	// Repository is the upstream repository, OPCFoundation/UA-Nodeset.
	Repository string `json:"repository"`
	// Commit is the upstream commit update downloaded the inputs from,
	// CommitDate its committer date.
	Commit     string  `json:"commit"`
	CommitDate string  `json:"commitDate"`
	Inputs     []Input `json:"inputs"`
}

// Input is one vendored file.
type Input struct {
	Path     string `json:"path"`
	Upstream string `json:"upstream"`
	Commit   string `json:"commit"`
	SHA256   string `json:"sha256"`
	// Models are the Models a NodeSet defines (its Models element).
	Models []Model `json:"models,omitempty"`
}

// Model is a ModelTableEntry of a UANodeSet (OPC 10000-6 §F.2, Table F.1).
// The values are those of the file, unparsed.
type Model struct {
	ModelURI        string  `json:"modelUri"`
	Version         string  `json:"version,omitempty"`
	ModelVersion    string  `json:"modelVersion,omitempty"`
	PublicationDate string  `json:"publicationDate,omitempty"`
	RequiredModels  []Model `json:"requiredModels,omitempty"`
}

func readManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	m := &Manifest{}
	if err := dec.Decode(m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

func (m *Manifest) encode() []byte {
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(err) // a Manifest has no values JSON cannot encode
	}
	return append(out, '\n')
}

// describe returns the manifest entry of a file.
func describe(in input, commit string, data []byte) (Input, error) {
	sum := sha256.Sum256(data)
	e := Input{Path: in.path, Upstream: in.upstream, Commit: commit, SHA256: hex.EncodeToString(sum[:])}
	if in.isNodeSet() {
		models, err := readModels(data)
		if err != nil {
			return Input{}, fmt.Errorf("%s: %w", in.path, err)
		}
		e.Models = models
	}
	return e, nil
}

// readModels reads the Models element of a UANodeSet, which precedes the
// Aliases and the nodes (OPC 10000-6 §F.2), so the rest is not decoded.
func readModels(data []byte) ([]Model, error) {
	type xmlModel struct {
		ModelURI        string     `xml:"ModelUri,attr"`
		Version         string     `xml:"Version,attr"`
		ModelVersion    string     `xml:"ModelVersion,attr"`
		PublicationDate string     `xml:"PublicationDate,attr"`
		RequiredModels  []xmlModel `xml:"RequiredModel"`
	}
	var conv func(xmlModel) Model
	conv = func(x xmlModel) Model {
		m := Model{ModelURI: x.ModelURI, Version: x.Version, ModelVersion: x.ModelVersion, PublicationDate: x.PublicationDate}
		for _, r := range x.RequiredModels {
			m.RequiredModels = append(m.RequiredModels, conv(r))
		}
		return m
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, errors.New("no Models element")
		}
		if err != nil {
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Models" {
			continue
		}
		var x struct {
			Models []xmlModel `xml:"Model"`
		}
		if err := dec.DecodeElement(&x, &se); err != nil {
			return nil, err
		}
		if len(x.Models) == 0 {
			return nil, errors.New("the Models element has no Model")
		}
		out := make([]Model, 0, len(x.Models))
		for _, xm := range x.Models {
			if xm.ModelURI == "" {
				return nil, errors.New("a Model has no ModelUri")
			}
			out = append(out, conv(xm))
		}
		return out, nil
	}
}

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// verify checks the vendored inputs under root against the manifest: the
// list of inputs, their SHA-256, the Models of each NodeSet, and that the
// RequiredModels of every vendored model are satisfied by a vendored model.
func verify(root string, m *Manifest) error {
	var errs []error
	if m.Repository != upstreamRepo {
		errs = append(errs, fmt.Errorf("repository %q, want %q", m.Repository, upstreamRepo))
	}
	if !commitRE.MatchString(m.Commit) {
		errs = append(errs, fmt.Errorf("commit %q is not a full commit hash", m.Commit))
	}
	if len(m.Inputs) != len(inputs) {
		errs = append(errs, fmt.Errorf("the manifest has %d inputs, schemamanifest knows %d: run schema/update-schema.sh", len(m.Inputs), len(inputs)))
	}
	for i, in := range inputs {
		if i >= len(m.Inputs) {
			break
		}
		e := m.Inputs[i]
		if e.Path != in.path || e.Upstream != in.upstream {
			errs = append(errs, fmt.Errorf("input %d is %s from %s, want %s from %s", i, e.Path, e.Upstream, in.path, in.upstream))
			continue
		}
		if !commitRE.MatchString(e.Commit) {
			errs = append(errs, fmt.Errorf("%s: commit %q is not a full commit hash", e.Path, e.Commit))
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(e.Path)))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		got, err := describe(in, e.Commit, data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if got.SHA256 != e.SHA256 {
			errs = append(errs, fmt.Errorf("%s: SHA-256 %s, the manifest records %s (UA-Nodeset %s:%s)", e.Path, got.SHA256, e.SHA256, short(e.Commit), e.Upstream))
			continue
		}
		if !reflect.DeepEqual(got.Models, e.Models) {
			errs = append(errs, fmt.Errorf("%s: the Models of the file differ from the manifest", e.Path))
		}
	}
	if len(errs) == 0 {
		errs = append(errs, requiredModels(m.Inputs)...)
	}
	return errors.Join(errs...)
}

// requiredModels checks that every RequiredModel of a vendored model is
// satisfied by a vendored model with the same ModelUri.
//
// OPC 10000-6 §F.2, Table F.1, RequiredModels: "Tools which attempt to
// resolve these dependencies may accept any model with the same or later
// ModelVersion"; which of two models is the later follows the rules of
// the ModelVersion row (see compareModels). Version is "not intended for
// programmatic comparisons" and is not compared.
func requiredModels(in []Input) []error {
	have := map[string]Model{}
	for _, e := range in {
		for _, m := range e.Models {
			have[m.ModelURI] = m
		}
	}
	var errs []error
	for _, e := range in {
		for _, m := range e.Models {
			for _, req := range m.RequiredModels {
				got, ok := have[req.ModelURI]
				if !ok {
					errs = append(errs, fmt.Errorf("%s: %s requires %s, which is not vendored", e.Path, m.ModelURI, req.ModelURI))
					continue
				}
				c, err := compareModels(got, req)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %s requires %s: %w", e.Path, m.ModelURI, req.ModelURI, err))
					continue
				}
				if c < 0 {
					errs = append(errs, fmt.Errorf("%s: %s requires %s %s, the vendored model is %s", e.Path, m.ModelURI, req.ModelURI, versionString(req), versionString(got)))
				}
			}
		}
	}
	return errs
}

func versionString(m Model) string {
	return fmt.Sprintf("ModelVersion %q PublicationDate %q (Version %q)", m.ModelVersion, m.PublicationDate, m.Version)
}

// compareModels compares two versions of a model, -1 when a precedes b,
// by the rules of OPC 10000-6 §F.2, Table F.1, ModelVersion: when both
// have a ModelVersion it is compared (SemVer precedence), and an equal
// ModelVersion is decided by the PublicationDate; when only one has a
// ModelVersion it is the later; when neither has one the PublicationDate
// is compared. A missing PublicationDate precedes every date, so a
// requirement without one is satisfied by any model with its ModelUri.
func compareModels(a, b Model) (int, error) {
	switch {
	case a.ModelVersion != "" && b.ModelVersion != "":
		c, err := compareSemVer(a.ModelVersion, b.ModelVersion)
		if err != nil || c != 0 {
			return c, err
		}
		return compareDates(a.PublicationDate, b.PublicationDate)
	case a.ModelVersion != "":
		return 1, nil
	case b.ModelVersion != "":
		return -1, nil
	}
	return compareDates(a.PublicationDate, b.PublicationDate)
}

func compareDates(a, b string) (int, error) {
	if a == "" || b == "" {
		return cmpBool(a != "", b != ""), nil
	}
	ta, err := time.Parse(time.RFC3339, a)
	if err != nil {
		return 0, fmt.Errorf("PublicationDate: %w", err)
	}
	tb, err := time.Parse(time.RFC3339, b)
	if err != nil {
		return 0, fmt.Errorf("PublicationDate: %w", err)
	}
	return ta.Compare(tb), nil
}

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

// compareSemVer compares two versions by the precedence of SemVer 2.0.0
// §11, which ModelVersion follows (OPC 10000-6 §F.2, Table F.1).
func compareSemVer(a, b string) (int, error) {
	pa := semverRE.FindStringSubmatch(a)
	if pa == nil {
		return 0, fmt.Errorf("ModelVersion %q is not a SemVer version", a)
	}
	pb := semverRE.FindStringSubmatch(b)
	if pb == nil {
		return 0, fmt.Errorf("ModelVersion %q is not a SemVer version", b)
	}
	for i := 1; i <= 3; i++ {
		if c := compareNumeric(pa[i], pb[i]); c != 0 {
			return c, nil
		}
	}
	// A version with a pre-release precedes the same version without one.
	switch {
	case pa[4] == pb[4]:
		return 0, nil
	case pa[4] == "":
		return 1, nil
	case pb[4] == "":
		return -1, nil
	}
	ia, ib := strings.Split(pa[4], "."), strings.Split(pb[4], ".")
	for i := 0; i < len(ia) && i < len(ib); i++ {
		na, ea := strconv.ParseUint(ia[i], 10, 64)
		nb, eb := strconv.ParseUint(ib[i], 10, 64)
		var c int
		switch {
		case ea == nil && eb == nil:
			c = cmpUint(na, nb)
		case ea == nil: // numeric identifiers precede alphanumeric ones
			c = -1
		case eb == nil:
			c = 1
		default:
			c = strings.Compare(ia[i], ib[i])
		}
		if c != 0 {
			return c, nil
		}
	}
	return cmpUint(uint64(len(ia)), uint64(len(ib))), nil
}

// compareNumeric compares two decimal numbers without leading zeros.
func compareNumeric(a, b string) int {
	if len(a) != len(b) {
		return cmpUint(uint64(len(a)), uint64(len(b)))
	}
	return strings.Compare(a, b)
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
