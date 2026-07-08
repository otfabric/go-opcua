// SPDX-License-Identifier: MIT

package conformance

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/stretchr/testify/require"
)

// implicitlyCovered lists exported *Client methods that are not asserted by a
// dedicated test because they are connection/session lifecycle primitives
// exercised by every test through the shared harness (Connect/Close) or via the
// internal/testutil package rather than the conformance package itself.
var implicitlyCovered = map[string]string{
	"Connect":         "established for every test by the shared harness",
	"Dial":            "low-level transport primitive used by Connect",
	"Close":           "torn down for every test by the shared harness",
	"CreateSession":   "performed as part of Connect",
	"ActivateSession": "performed as part of Connect",
	"CloseSession":    "performed as part of Close",
	"DetachSession":   "session lifecycle primitive; not part of the data plane",
}

// TestMatrix_ClientAPICoverage fails if any exported method of *opcua.Client is
// neither referenced by a test in this package nor explicitly listed as
// implicitly covered. This keeps the back-to-back suite honest as the API grows.
func TestMatrix_ClientAPICoverage(t *testing.T) {
	src := readPackageTestSource(t)

	ct := reflect.TypeOf((*opcua.Client)(nil))
	var missing []string
	for i := 0; i < ct.NumMethod(); i++ {
		name := ct.Method(i).Name
		if _, ok := implicitlyCovered[name]; ok {
			continue
		}
		if strings.Contains(src, "."+name+"(") {
			continue
		}
		missing = append(missing, name)
	}

	require.Empty(t, missing,
		"these exported *opcua.Client methods are not covered by any conformance test "+
			"(add a test or, for lifecycle primitives, add them to implicitlyCovered): %v", missing)
}

// readPackageTestSource concatenates the source of every _test.go file in this
// directory so coverage can be detected by simple reference scanning.
func readPackageTestSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(".", e.Name()))
		require.NoError(t, err)
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}
