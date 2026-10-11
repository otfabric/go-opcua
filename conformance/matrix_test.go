// SPDX-License-Identifier: MIT

package conformance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/monitor"
	"github.com/stretchr/testify/require"
)

// The matrix tests keep the back-to-back suite honest as the API grows: a new
// exported method or option fails them until a conformance test exercises it.
//
// Two levels of evidence are used:
//
//   - *opcua.Client methods and the client/server Option constructors must be
//     referenced somewhere in this package's tests.
//   - *opcua.Node, *opcua.Subscription, *opcua.SubscriptionBuilder and the
//     monitor package's types have many methods with generic names (Value,
//     String, Monitor, ...), for which a package-wide text scan proves little.
//     Each of their methods is therefore tied to a named test, and the matrix
//     verifies that this test exists and really calls a method of that name.

// notCovered lists exported *Client methods that are deliberately not required
// to be referenced. It is empty: every client method has a conformance test.
var notCovered = map[string]string{}

// TestMatrix_ClientAPICoverage fails if any exported method of *opcua.Client is
// not referenced by a test in this package.
func TestMatrix_ClientAPICoverage(t *testing.T) {
	src := readPackageTestSource(t)

	ct := reflect.TypeOf((*opcua.Client)(nil))
	var missing []string
	for i := 0; i < ct.NumMethod(); i++ {
		name := ct.Method(i).Name
		if _, ok := notCovered[name]; ok {
			continue
		}
		if strings.Contains(src, "."+name+"(") {
			continue
		}
		missing = append(missing, name)
	}

	require.Empty(t, missing,
		"these exported *opcua.Client methods are not covered by any conformance test: %v", missing)
}

// nodeCoverage names, for every exported *opcua.Node method, the conformance
// test that asserts its behaviour.
var nodeCoverage = map[string]string{
	"String":                                 "TestNode_ReferenceHelpers",
	"Walk":                                   "TestNode_WalkVariants",
	"WalkLimit":                              "TestNode_WalkVariants",
	"WalkLimitDedup":                         "TestNode_WalkVariants",
	"BrowseWithDepth":                        "TestNode_BrowseWithDepth",
	"NodeClass":                              "TestNode_AttributeHelpers",
	"BrowseName":                             "TestNode_AttributeHelpers",
	"Description":                            "TestNode_AttributeHelpers",
	"DisplayName":                            "TestNode_AttributeHelpers",
	"AccessLevel":                            "TestNode_AttributeHelpers",
	"HasAccessLevel":                         "TestNode_AttributeHelpers",
	"UserAccessLevel":                        "TestNode_AttributeHelpers",
	"HasUserAccessLevel":                     "TestNode_AttributeHelpers",
	"Value":                                  "TestNode_AttributeHelpers",
	"DataType":                               "TestNode_AttributeHelpers",
	"Attribute":                              "TestNode_AttributeHelpers",
	"Attributes":                             "TestNode_AttributeHelpers",
	"TypeDefinition":                         "TestNode_ReferenceHelpers",
	"Children":                               "TestNode_ReferenceHelpers",
	"ReferencedNodes":                        "TestNode_ReferenceHelpers",
	"References":                             "TestNode_ReferenceHelpers",
	"BrowseAll":                              "TestNode_ReferenceHelpers",
	"Summary":                                "TestNode_Summary",
	"TranslateBrowsePathsToNodeIDs":          "TestView_TranslateBrowsePaths",
	"TranslateBrowsePathInNamespaceToNodeID": "TestView_TranslateBrowsePaths",
}

// subscriptionCoverage does the same for *opcua.Subscription.
var subscriptionCoverage = map[string]string{
	"Cancel":               "TestSubscription_HighLevelItemLifecycle",
	"ModifySubscription":   "TestSubscription_ParameterRevision",
	"Monitor":              "TestSubscription_HighLevelItemLifecycle",
	"Unmonitor":            "TestSubscription_HighLevelItemLifecycle",
	"ModifyMonitoredItems": "TestSubscription_HighLevelItemLifecycle",
	"SetMonitoringMode":    "TestSubscription_HighLevelItemLifecycle",
	"SetTriggering":        "TestSubscription_HighLevelItemLifecycle",
	"SetPublishingMode":    "TestSubscription_HighLevelItemLifecycle",
	"Stats":                "TestSubscription_Stats",
}

// builderCoverage does the same for *opcua.SubscriptionBuilder.
var builderCoverage = map[string]string{
	"Interval":                   "TestSubscription_BuilderOptions",
	"LifetimeCount":              "TestSubscription_BuilderOptions",
	"MaxKeepAliveCount":          "TestSubscription_BuilderOptions",
	"MaxNotificationsPerPublish": "TestSubscription_BuilderOptions",
	"Priority":                   "TestSubscription_BuilderOptions",
	"Timestamps":                 "TestSubscription_BuilderOptions",
	"SamplingInterval":           "TestSubscription_BuilderOptions",
	"NotifyChannel":              "TestSubscription_BuilderOptions",
	"Monitor":                    "TestSubscription_BuilderOptions",
	"MonitorItems":               "TestSubscription_BuilderOptions",
	"MonitorEvents":              "TestEvents_BuilderAndHighLevelAPI",
	"Start":                      "TestSubscription_BuilderOptions",
}

// sessionCoverage does the same for *opcua.Session.
var sessionCoverage = map[string]string{
	"RevisedTimeout":        "TestSession_Properties",
	"SessionID":             "TestSession_Properties",
	"ServerEndpoints":       "TestSession_Properties",
	"MaxRequestMessageSize": "TestSession_Properties",
}

// monitorSubscriptionCoverage does the same for *monitor.Subscription.
var monitorSubscriptionCoverage = map[string]string{
	"Modify":                      "TestMonitor_ChannelSubscription",
	"Unsubscribe":                 "TestMonitor_ChannelSubscription",
	"Subscribed":                  "TestMonitor_ChannelSubscription",
	"SubscriptionID":              "TestMonitor_ChannelSubscription",
	"Delivered":                   "TestMonitor_ChannelSubscription",
	"Dropped":                     "TestMonitor_SlowConsumerIsReported",
	"AddNodes":                    "TestMonitor_ChannelSubscription",
	"AddNodeIDs":                  "TestMonitor_ChannelSubscription",
	"AddMonitorItems":             "TestMonitor_ChannelSubscription",
	"RemoveNodes":                 "TestMonitor_ChannelSubscription",
	"RemoveNodeIDs":               "TestMonitor_ChannelSubscription",
	"RemoveMonitorItems":          "TestMonitor_ChannelSubscription",
	"ModifyMonitorItems":          "TestMonitor_ChannelSubscription",
	"SetMonitoringModeForNodes":   "TestMonitor_ChannelSubscription",
	"SetMonitoringModeForNodeIDs": "TestMonitor_ChannelSubscription",
	"SetMonitoringMode":           "TestMonitor_ChannelSubscription",
	"Stats":                       "TestSubscription_Stats",
}

// nodeMonitorCoverage does the same for *monitor.NodeMonitor.
var nodeMonitorCoverage = map[string]string{
	"SetErrorHandler": "TestMonitor_SlowConsumerIsReported",
	"Subscribe":       "TestMonitor_CallbackSubscription",
	"ChanSubscribe":   "TestMonitor_ChannelSubscription",
}

// TestMatrix_TypeAPICoverage verifies the per-type coverage tables above are
// complete and truthful.
func TestMatrix_TypeAPICoverage(t *testing.T) {
	calls := testFunctionCalls(t)

	for _, tc := range []struct {
		typ      reflect.Type
		coverage map[string]string
	}{
		{reflect.TypeOf((*opcua.Node)(nil)), nodeCoverage},
		{reflect.TypeOf((*opcua.Subscription)(nil)), subscriptionCoverage},
		{reflect.TypeOf((*opcua.SubscriptionBuilder)(nil)), builderCoverage},
		{reflect.TypeOf((*opcua.Session)(nil)), sessionCoverage},
		{reflect.TypeOf((*monitor.Subscription)(nil)), monitorSubscriptionCoverage},
		{reflect.TypeOf((*monitor.NodeMonitor)(nil)), nodeMonitorCoverage},
	} {
		t.Run(tc.typ.Elem().String(), func(t *testing.T) {
			exported := map[string]bool{}
			for i := 0; i < tc.typ.NumMethod(); i++ {
				name := tc.typ.Method(i).Name
				exported[name] = true

				test, ok := tc.coverage[name]
				require.True(t, ok, "exported method %s.%s has no conformance test: add one and list it in the coverage table",
					tc.typ.Elem(), name)
				called, exists := calls[test]
				require.True(t, exists, "%s.%s is mapped to %s, which does not exist", tc.typ.Elem(), name, test)
				require.True(t, called[name], "%s.%s is mapped to %s, but that test never calls a method named %s",
					tc.typ.Elem(), name, test, name)
			}
			for name := range tc.coverage {
				require.True(t, exported[name], "coverage table lists %s.%s, which is not an exported method (stale entry)",
					tc.typ.Elem(), name)
			}
		})
	}
}

// optionsNotCovered lists Option constructors that are deliberately not
// required to be referenced by the conformance suite, with the reason.
var optionsNotCovered = map[string]map[string]string{
	"opcua": {},
	"server": {
		"ListenOn":                 "binds a separate (wildcard) listen address; exercised by server/bound_port_test.go to keep this suite on loopback",
		"WithResponseWriteTimeout": "only observable with a peer that stops reading its socket; exercised by chaos/robustness_test.go",
	},
}

// TestMatrix_OptionCoverage fails if a client or server Option constructor is
// not used by any conformance test.
func TestMatrix_OptionCoverage(t *testing.T) {
	src := readPackageTestSource(t)

	for _, pkg := range []struct {
		name, dir string
	}{
		{"opcua", ".."},
		{"server", filepath.Join("..", "server")},
	} {
		t.Run(pkg.name, func(t *testing.T) {
			options := optionConstructors(t, pkg.dir)
			require.NotEmpty(t, options, "no Option constructors found in %s: the scan is broken", pkg.dir)

			var missing []string
			for _, name := range options {
				if _, ok := optionsNotCovered[pkg.name][name]; ok {
					continue
				}
				if !strings.Contains(src, pkg.name+"."+name+"(") && !strings.Contains(src, pkg.name+"."+name+",") {
					missing = append(missing, name)
				}
			}
			require.Empty(t, missing, "these %s options are not used by any conformance test: %v", pkg.name, missing)

			for name := range optionsNotCovered[pkg.name] {
				require.Contains(t, options, name, "optionsNotCovered lists %s.%s, which is not an Option constructor (stale entry)", pkg.name, name)
			}
		})
	}
}

// optionConstructors returns the names of the exported top-level functions in
// the non-test Go files of dir whose only result is of type Option.
func optionConstructors(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
				continue
			}
			if id, ok := fn.Type.Results.List[0].Type.(*ast.Ident); ok && id.Name == "Option" {
				out = append(out, fn.Name.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// testFunctionCalls parses the test files of this package and returns, for
// every top-level Test function, the set of method names it calls (anywhere in
// its body, including subtests and closures).
func testFunctionCalls(t *testing.T) map[string]map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	out := map[string]map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			called := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						called[sel.Sel.Name] = true
					}
				}
				return true
			})
			out[fn.Name.Name] = called
		}
	}
	return out
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
