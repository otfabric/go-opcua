// SPDX-License-Identifier: MIT

package fxcm

import (
	"errors"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

func TestConfigErrorText(t *testing.T) {
	e := &ConfigError{Key: SetKey{Name: "S"}, Findings: []Finding{{"a", "c", "p"}, {"b", "c", "p"}, {"c", "c", "p"}, {"d", "c", "p"}, {"e", "c", "p"}}}
	s := e.Error()
	if !strings.Contains(s, "S is not valid; a: p (c)") || !strings.HasSuffix(s, "; and 2 more") {
		t.Errorf("%q", s)
	}
}

func TestStatusOf(t *testing.T) {
	if StatusOf(nil) != ua.StatusGood || StatusOf(errors.New("x")) != ua.StatusBad {
		t.Error("StatusOf")
	}
	err := managerError(ua.StatusBadInvalidState, "x %d", 1)
	var se interface{ Status() ua.StatusCode }
	if !errors.As(err, &se) || se.Status() != ua.StatusBadInvalidState || err.Error() != "fxcm: manager: x 1" {
		t.Errorf("%v", err)
	}
}

func TestSetKey(t *testing.T) {
	if k := KeyOf(nil); k.Name != "" || k.Folder != nil {
		t.Errorf("KeyOf(nil) %v", k)
	}
	if k := KeyOf(&uafx.ConnectionConfigurationSetConf{BrowseName: "S", ConnectionConfigurationSetFolder: []string{}}); k.Folder != nil {
		t.Error("an empty Folder is a null Folder (Table F.1)")
	}
	a := SetKey{Folder: []string{"A", "B"}, Name: "S"}
	if !a.Equal(SetKey{Folder: []string{"A", "B"}, Name: "S"}) || a.Equal(SetKey{Folder: []string{"A"}, Name: "S"}) || a.Equal(SetKey{Folder: []string{"A", "B"}, Name: "T"}) {
		t.Error("Equal")
	}
	for k, want := range map[*SetKey]string{
		&a:                                  "A/B/S",
		{Name: "S"}:                         "S",
		{Folder: []string{"a/b"}, Name: ""}: `"a/b"/""`,
		{Name: `x"y`}:                       `"x\"y"`,
	} {
		if got := k.String(); got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
}
