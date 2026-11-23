// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

func TestRun(t *testing.T) {
	ctx := context.Background()
	srv, url := testutil.NewTestServer(t)
	if _, err := fxserver.AddModel(srv); err != nil {
		t.Fatal(err)
	}
	xml, err := os.ReadFile("../server/controller.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err := fxserver.ImportNodeSet(srv, xml); err != nil {
		t.Fatal(err)
	}

	var text bytes.Buffer
	if err := run(ctx, url, false, &text); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"UAFX server: true",
		"AutomationComponent Controller",
		"asset Drive:",
		"functional entity Motion",
		"functional entity Axis",
		"endpoint ToLine:",
		"ConnectionManager",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("output has no %q:\n%s", want, text.String())
		}
	}
	if strings.Contains(text.String(), "Findings") {
		t.Errorf("findings for the example controller:\n%s", text.String())
	}

	var js bytes.Buffer
	if err := run(ctx, url, true, &js); err != nil {
		t.Fatal(err)
	}
	var r uafx.Report
	if err := json.Unmarshal(js.Bytes(), &r); err != nil {
		t.Fatalf("%v:\n%s", err, js.String())
	}
	if len(r.AutomationComponents) != 1 {
		t.Errorf("JSON report has %d components", len(r.AutomationComponents))
	}
}

func TestRunNoServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, "opc.tcp://localhost:1", false, &bytes.Buffer{}); err == nil {
		t.Fatal("no error without a server")
	}
}

func TestPrintTruncated(t *testing.T) {
	var b bytes.Buffer
	err := print(&b, &uafx.Report{
		Namespaces: []uafx.Namespace{{URI: "urn:x"}},
		Findings:   []uafx.Finding{{Path: "X", Clause: "6.2.2", Text: "broken"}},
		Truncated:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"(absent)", "Findings", "incomplete"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("output has no %q:\n%s", want, b.String())
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestPrintWriteError(t *testing.T) {
	if err := print(failingWriter{}, &uafx.Report{}); err == nil || err.Error() != "disk full" {
		t.Fatalf("error %v, want disk full", err)
	}
}
