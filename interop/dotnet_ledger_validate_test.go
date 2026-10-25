// SPDX-License-Identifier: MIT

package interop_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// dotnetLedgerDirections are the row directions of testdata/ledger-dotnet.json.
// As in coverage.json, LDS evidence sits in the →S row of its capability and
// its case names the finer direction (dotnet-server-to-go-lds,
// dotnet-client-to-go-lds; see dotnet_harness_test.go).
var dotnetLedgerDirections = map[string]bool{
	"go-client-to-dotnet-server": true,
	"dotnet-client-to-go-server": true,
}

// dotnetDirectionConst names the constants (dotnet_harness_test.go) that
// shared peer assertions turn into coverage/<capability>/<direction> subtests.
var dotnetDirectionConst = map[string]string{
	"go-client-to-dotnet-server": "dirGoClientToDotnetServer",
	"dotnet-client-to-go-server": "dirDotnetClientToGoServer",
}

// dotnetUnverifiedReasons are the controlled reasons of an unverified row
// (as in TestCoverageManifestValid).
var dotnetUnverifiedReasons = map[string]bool{
	"test-missing":            true,
	"adapter-command-missing": true,
	"adapter-unreleased":      true,
	"adapter-fixture-missing": true,
	"fault-harness-missing":   true,
	"consumer-demand-missing": true,
	"peer-capability-unknown": true,
}

// TestDotnetLedgerValid checks testdata/ledger-dotnet.json without Docker:
// the release it is written against, known capabilities and directions, one
// row per capability and direction (for every capability), evidence tests
// that exist, subtest cases that the evidence test declares, and a row for
// every coverage/<capability>/<direction> subtest of the dotnet test files.
func TestDotnetLedgerValid(t *testing.T) {
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
	}](t, filepath.Join(dir, "testdata", "ledger-dotnet.json"))

	// Keep in step with interopVersion (harness_test.go).
	if ledger.InteropVersion != "v0.16.0" {
		t.Errorf("interopVersion = %q, want v0.16.0", ledger.InteropVersion)
	}
	if ledger.Peer.Stack != "opcfoundation-uanetstandard" || ledger.Peer.Version == "" {
		t.Errorf("peer = %+v, want stack opcfoundation-uanetstandard with a version", ledger.Peer)
	}
	if len(ledger.Entries) == 0 {
		t.Fatal("no entries")
	}

	tests := listInteropTestFuncs(t, dir)
	sources := testSources(t, dir, "dotnet_*_test.go")
	allSources := testSources(t, dir, "*_test.go")

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
		if !dotnetLedgerDirections[e.Direction] {
			t.Errorf("%s: unknown direction %q", key, e.Direction)
		}
		// The status rules of coverage.json (TestCoverageManifestValid); an
		// unsupported row explains itself in nextAction, its test (if any)
		// pins the refusal.
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
			if e.NextAction == "" {
				t.Errorf("%s: unsupported requires nextAction", key)
			}
		case "unverified":
			if !dotnetUnverifiedReasons[e.Reason] {
				t.Errorf("%s: unverified needs a controlled reason, not %q", key, e.Reason)
			}
		case "deferred", "not-applicable":
		default:
			t.Errorf("%s: invalid status %q", key, e.Status)
		}
		if strings.HasPrefix(e.Case, "coverage/") {
			cased[e.Case] = true
			// The case is a literal of the test, a shared assertion builds it
			// from the direction constant the test passes, or a shared test
			// builds it from the name of each peer it runs, dotnet among them
			// (TestMulticast_GoAndPeers).
			body := allSources[e.Test]
			dirConst, built := dotnetDirectionConst[e.Direction]
			literal := strings.Contains(body, `"`+e.Case+`"`)
			fromConst := built && e.Case == "coverage/"+key && strings.Contains(body, dirConst)
			fromPeer := strings.HasPrefix(e.Case, "coverage/"+e.Capability+"/dotnet-") &&
				strings.Contains(body, `"coverage/`+e.Capability+`/"+`) && strings.Contains(body, `{"dotnet", dotnetEnv, defaultDotnetImage}`)
			if !literal && !fromConst && !fromPeer {
				t.Errorf("%s: test %s has no subtest %q", key, e.Test, e.Case)
			}
		}
	}

	for id := range capIDs {
		for d := range dotnetLedgerDirections {
			if !seen[id+"/"+d] {
				t.Errorf("%s/%s: no row", id, d)
			}
		}
	}

	// Every coverage subtest of the dotnet files is the case of a row, or
	// names a row by capability and direction.
	re := regexp.MustCompile(`"(coverage/([a-z0-9.-]+)/([a-z0-9-]*dotnet[a-z0-9-]*))"`)
	for name, body := range sources {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if !cased[m[1]] && !seen[m[2]+"/"+m[3]] {
				t.Errorf("%s: subtest %s is no ledger row or case", name, m[1])
			}
		}
	}
}

// testSources returns the source of every Test function in the files of dir
// that match pattern, by name.
func testSources(t *testing.T, dir, pattern string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, pattern))
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
