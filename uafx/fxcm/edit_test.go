// SPDX-License-Identifier: MIT

package fxcm

import (
	"errors"
	"reflect"
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

func mustConfig(t *testing.T, c *conf) *Config {
	t.Helper()
	cfg, err := NewConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestEdit follows §6.7.4 (ED-1 to ED-6).
func TestEdit(t *testing.T) {
	base := mustConfig(t, validConf())
	var s EditSlot

	// Commit and Discard of a set not in edit are ignored (ED-6).
	if cfg, ok, err := s.Commit("a"); cfg != nil || ok || err != nil {
		t.Errorf("Commit outside edit: %v %v %v", cfg, ok, err)
	}
	if ok, err := s.Discard("a"); ok || err != nil {
		t.Errorf("Discard outside edit: %v %v", ok, err)
	}
	if s.LockLost() {
		t.Error("LockLost outside edit")
	}
	if _, err := s.Start(base, ""); StatusOf(err) != ua.StatusBadInvalidArgument {
		t.Errorf("Start without owner: %v", err)
	}

	e, err := s.Start(base, "a")
	if err != nil || e.Owner() != "a" || e.Base() != base || s.Editing() != e {
		t.Fatalf("Start: %v %v", e, err)
	}
	// StartEditing again by the owner: no action (ED-3).
	if e2, err := s.Start(base, "a"); err != nil || e2 != e || e2.Conf() != e.Conf() {
		t.Errorf("Start again: %v", err)
	}
	// Another client: Bad_InvalidState (Table 82).
	if _, err := s.Start(base, "b"); StatusOf(err) != ua.StatusBadInvalidState {
		t.Errorf("Start by b: %v", err)
	}
	if _, _, err := s.Commit("b"); StatusOf(err) != ua.StatusBadInvalidState || !errors.Is(err, ErrManager) {
		t.Errorf("Commit by b: %v", err)
	}
	if _, err := s.Discard("b"); StatusOf(err) != ua.StatusBadInvalidState {
		t.Errorf("Discard by b: %v", err)
	}

	// An invalid working copy: the edit stays, with the Lock (library
	// interpretation).
	e.Conf().Connections[0].Endpoint1.Name = "NotSelectable"
	if _, _, err := s.Commit("a"); !errors.Is(err, ErrConfig) || s.Editing() != e {
		t.Errorf("Commit invalid: %v, editing %v", err, s.Editing())
	}
	// A rename is a Replace.
	e.Conf().Connections[0].Endpoint1.Name = "ToAC2"
	e.Conf().BrowseName = "Line2"
	var ce *ConfigError
	if _, _, err := s.Commit("a"); !errors.As(err, &ce) || ce.Findings[0].Path != "BrowseName" {
		t.Errorf("Commit rename: %v", err)
	}
	e.Conf().BrowseName = "Line1"

	// The input of the base is not changed by the edit.
	if base.Conf().Connections[1].Endpoint2.Name != "FromAC2" {
		t.Fatal("the base changed")
	}
	e.Conf().Connections[1].Endpoint2.Name = "FromAC2b"
	cfg, ok, err := s.Commit("a")
	if err != nil || !ok || cfg.Version() != base.Version()+1 || s.Editing() != nil {
		t.Fatalf("Commit: %v %v %v", cfg, ok, err)
	}
	if base.Conf().Connections[1].Endpoint2.Name != "FromAC2" || cfg.Conf().Connections[1].Endpoint2.Name != "FromAC2b" {
		t.Error("commit did not make a new snapshot")
	}
	if got := Renamed(base, cfg); !reflect.DeepEqual(got, []EndpointRef{{"C2", 2}}) {
		t.Errorf("Renamed %v", got)
	}

	// Version is incremented on every commit, also without a change
	// (§6.7.4).
	if _, err := s.Start(cfg, "b"); err != nil {
		t.Fatal(err)
	}
	cfg2, ok, err := s.Commit("b")
	if err != nil || !ok || cfg2.Version() != 3 || len(Renamed(cfg, cfg2)) != 0 {
		t.Errorf("empty commit: %v %v %v", cfg2, ok, err)
	}

	// Discard and a lost Lock end the edit (ED-2, ED-5).
	if _, err := s.Start(cfg2, "c"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Discard("c"); !ok || err != nil || s.Editing() != nil {
		t.Errorf("Discard: %v %v", ok, err)
	}
	if _, err := s.Start(cfg2, "d"); err != nil {
		t.Fatal(err)
	}
	if !s.LockLost() || s.Editing() != nil {
		t.Error("LockLost")
	}
}

func TestRenamedRemovedConnection(t *testing.T) {
	old := mustConfig(t, validConf())
	c := validConf()
	c.Connections = c.Connections[:1]
	c.Connections[0].Endpoint2 = nil
	pubsubFlow(c, 0).SubscriberConfigurations = nil
	next := mustConfig(t, c)
	if got := Renamed(old, next); len(got) != 0 {
		t.Errorf("Renamed %v: a removed endpoint is not a rename", got)
	}
}
