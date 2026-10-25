// SPDX-License-Identifier: MIT

package interop_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nodeOpcuaLedgerDirections are the row directions of
// testdata/ledger-node-opcua.json. As in coverage.json, LDS evidence sits in
// the node-opcua→go row of its capability and its case names the finer
// direction (node-opcua-server-to-go-lds, node-opcua-client-to-go-lds; see
// nodeopcua_harness_test.go).
var nodeOpcuaLedgerDirections = map[string]bool{
	"go-client-to-node-opcua-server": true,
	"node-opcua-client-to-go-server": true,
}

// nodeOpcuaDirectionConst names the constants (nodeopcua_harness_test.go)
// that shared peer tests turn into coverage/<capability>/<direction>
// subtests.
var nodeOpcuaDirectionConst = map[string]string{
	"node-opcua-client-to-go-server": "dirNodeOpcuaClientToGoServer",
}

// nodeOpcuaUnverifiedReasons are the controlled reasons of an unverified row
// (as in TestCoverageManifestValid).
var nodeOpcuaUnverifiedReasons = map[string]bool{
	"test-missing":            true,
	"adapter-command-missing": true,
	"adapter-unreleased":      true,
	"adapter-fixture-missing": true,
	"fault-harness-missing":   true,
	"consumer-demand-missing": true,
	"peer-capability-unknown": true,
}

// TestNodeOpcuaLedgerValid checks testdata/ledger-node-opcua.json without
// Docker: the release it is written against, known capabilities and
// directions, one row per capability and direction (for every capability),
// evidence tests that exist, subtest cases that the evidence test declares,
// and a row for every coverage/<capability>/<direction> subtest of the
// nodeopcua_*_test.go files.
func TestNodeOpcuaLedgerValid(t *testing.T) {
	root := findModuleRoot(t)
	dir := filepath.Join(root, "interop")

	caps := mustReadJSON[struct {
		Capabilities []struct {
			ID string `json:"id"`
		} `json:"capabilities"`
	}](t, filepath.Join(dir, "capabilities.json"))
	capIDs := map[string]bool{}
	for _, c := range caps.Capabilities {
		capIDs[c.ID] = true
	}

	ledger := mustReadJSON[struct {
		InteropVersion string `json:"interopVersion"`
		Peer           struct {
			Stack   string `json:"stack"`
			Version string `json:"version"`
		} `json:"peer"`
		Entries []struct {
			Capability string `json:"capability"`
			Direction  string `json:"direction"`
			Status     string `json:"status"`
			Test       string `json:"test"`
			Case       string `json:"case"`
			Reason     string `json:"reason"`
			Issue      string `json:"issue"`
			NextAction string `json:"nextAction"`
		} `json:"entries"`
	}](t, filepath.Join(dir, "testdata", "ledger-node-opcua.json"))

	// Keep in step with interopVersion (harness_test.go).
	if ledger.InteropVersion != "v0.15.0" {
		t.Errorf("interopVersion = %q, want v0.15.0", ledger.InteropVersion)
	}
	if ledger.Peer.Stack != "node-opcua" || ledger.Peer.Version == "" {
		t.Errorf("peer = %+v, want stack node-opcua with a version", ledger.Peer)
	}
	if len(ledger.Entries) == 0 {
		t.Fatal("no entries")
	}

	tests := listInteropTestFuncs(t, dir)
	sources := nodeOpcuaTestSources(t, dir)

	seen := map[string]bool{}
	cased := map[string]bool{}
	for _, e := range ledger.Entries {
		key := e.Capability + "/" + e.Direction
		if seen[key] {
			t.Errorf("%s: duplicate row", key)
		}
		seen[key] = true
		if !capIDs[e.Capability] {
			t.Errorf("%s: unknown capability", key)
		}
		if !nodeOpcuaLedgerDirections[e.Direction] {
			t.Errorf("%s: unknown direction %q", key, e.Direction)
		}
		if e.Test != "" && !tests[e.Test] {
			t.Errorf("%s: test %q not found in the interop package", key, e.Test)
		}
		switch e.Status {
		case "verified", "blocked":
			if e.Test == "" {
				t.Errorf("%s: %s without a test", key, e.Status)
			}
			if e.Status == "blocked" && (e.Issue == "" || e.Reason == "") {
				t.Errorf("%s: blocked requires issue and reason", key)
			}
		case "unsupported":
			// What the stack lacks is said in nextAction; a test (if any)
			// pins the refusal or skips with the reason.
			if e.NextAction == "" {
				t.Errorf("%s: unsupported requires nextAction", key)
			}
		case "unverified":
			if !nodeOpcuaUnverifiedReasons[e.Reason] {
				t.Errorf("%s: unverified needs a controlled reason, not %q", key, e.Reason)
			}
		case "deferred", "not-applicable":
		default:
			t.Errorf("%s: invalid status %q", key, e.Status)
		}
		if e.Case != "" {
			if !strings.HasPrefix(e.Case, "coverage/"+e.Capability+"/") {
				t.Errorf("%s: case %q is not a coverage subtest of the capability", key, e.Case)
			}
			// The case is a literal of the test, or a shared test helper
			// (following the test in its file) builds it from the direction
			// constant.
			body, ok := sources[e.Test]
			dirConst, built := nodeOpcuaDirectionConst[e.Direction]
			fromConst := built && e.Case == "coverage/"+key && strings.Contains(body, dirConst)
			if !ok || (!strings.Contains(body, `"`+e.Case+`"`) && !fromConst) {
				t.Errorf("%s: test %s has no subtest %q", key, e.Test, e.Case)
			}
			cased[e.Case] = true
		}
	}

	for id := range capIDs {
		for d := range nodeOpcuaLedgerDirections {
			if !seen[id+"/"+d] {
				t.Errorf("%s/%s: no row", id, d)
			}
		}
	}

	// Every coverage subtest of the node-opcua files is the case of a row.
	re := regexp.MustCompile(`"(coverage/[a-z0-9.-]+/[a-z0-9-]*node-opcua[a-z0-9-]*(?:/[^"]*)?)"`)
	for name, body := range sources {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if !cased[m[1]] {
				t.Errorf("%s: subtest %s is no ledger case", name, m[1])
			}
		}
	}
}

// nodeOpcuaTestSources returns the source of every Test function in the
// nodeopcua_*_test.go files, by name.
func nodeOpcuaTestSources(t *testing.T, dir string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "nodeopcua_*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	head := regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\) \{$`)
	out := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		idx := head.FindAllStringSubmatchIndex(src, -1)
		for i, m := range idx {
			end := len(src)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			name := src[m[2]:m[3]]
			if _, dup := out[name]; dup {
				t.Fatalf("%s declared twice", name)
			}
			out[name] = src[m[0]:end]
		}
	}
	return out
}
