// SPDX-License-Identifier: MIT

package fxserver

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

func safeFixture() *ua.PubSubConfigurationDataType {
	return &ua.PubSubConfigurationDataType{
		PublishedDataSets: []*ua.PublishedDataSetDataType{{Name: "P"}, nil},
		Connections: []*ua.PubSubConnectionDataType{nil, {
			Name: "C", Enabled: true,
			WriterGroups: []*ua.WriterGroupDataType{nil, {Name: "WG", Enabled: true, WriterGroupID: 1,
				DataSetWriters: []*ua.DataSetWriterDataType{nil, {Name: "W", Enabled: true, DataSetWriterID: 2}}}},
			ReaderGroups: []*ua.ReaderGroupDataType{nil, {Name: "RG", Enabled: true,
				DataSetReaders: []*ua.DataSetReaderDataType{nil, {Name: "R", Enabled: true}}}},
		}},
	}
}

// TestSafeDirection: a change is in the safe direction when it only
// removes components or turns Enabled off; an addition, an enable or any
// other modification is not.
func TestSafeDirection(t *testing.T) {
	t.Parallel()
	conn := func(c *ua.PubSubConfigurationDataType) *ua.PubSubConnectionDataType { return c.Connections[1] }
	for name, c := range map[string]struct {
		mod  func(c *ua.PubSubConfigurationDataType)
		safe bool
	}{
		"unchanged":                {func(*ua.PubSubConfigurationDataType) {}, true},
		"PublishedDataSet removed": {func(c *ua.PubSubConfigurationDataType) { c.PublishedDataSets = nil }, true},
		"PublishedDataSet added": {func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets = append(c.PublishedDataSets, &ua.PublishedDataSetDataType{Name: "Q"})
		}, false},
		"PublishedDataSet modified": {func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0] = &ua.PublishedDataSetDataType{Name: "P", DataSetFolder: []string{"x"}}
		}, false},
		"connection removed": {func(c *ua.PubSubConfigurationDataType) { c.Connections = nil }, true},
		"connection added": {func(c *ua.PubSubConfigurationDataType) {
			c.Connections = append(c.Connections, &ua.PubSubConnectionDataType{Name: "D"})
		}, false},
		"connection disabled":  {func(c *ua.PubSubConfigurationDataType) { conn(c).Enabled = false }, true},
		"connection modified":  {func(c *ua.PubSubConfigurationDataType) { conn(c).TransportProfileURI = "x" }, false},
		"writer group removed": {func(c *ua.PubSubConfigurationDataType) { conn(c).WriterGroups = nil }, true},
		"writer group added": {func(c *ua.PubSubConfigurationDataType) {
			conn(c).WriterGroups = append(conn(c).WriterGroups, &ua.WriterGroupDataType{Name: "X"})
		}, false},
		"writer group disabled":   {func(c *ua.PubSubConfigurationDataType) { conn(c).WriterGroups[1].Enabled = false }, true},
		"writer group id changed": {func(c *ua.PubSubConfigurationDataType) { conn(c).WriterGroups[1].WriterGroupID = 9 }, false},
		"writer removed":          {func(c *ua.PubSubConfigurationDataType) { conn(c).WriterGroups[1].DataSetWriters = nil }, true},
		"writer added": {func(c *ua.PubSubConfigurationDataType) {
			g := conn(c).WriterGroups[1]
			g.DataSetWriters = append(g.DataSetWriters, &ua.DataSetWriterDataType{Name: "X"})
		}, false},
		"writer disabled":      {func(c *ua.PubSubConfigurationDataType) { conn(c).WriterGroups[1].DataSetWriters[1].Enabled = false }, true},
		"writer id changed":    {func(c *ua.PubSubConfigurationDataType) { conn(c).WriterGroups[1].DataSetWriters[1].DataSetWriterID = 9 }, false},
		"reader group removed": {func(c *ua.PubSubConfigurationDataType) { conn(c).ReaderGroups = nil }, true},
		"reader group added": {func(c *ua.PubSubConfigurationDataType) {
			conn(c).ReaderGroups = append(conn(c).ReaderGroups, &ua.ReaderGroupDataType{Name: "X"})
		}, false},
		"reader group disabled": {func(c *ua.PubSubConfigurationDataType) { conn(c).ReaderGroups[1].Enabled = false }, true},
		"reader group modified": {func(c *ua.PubSubConfigurationDataType) { conn(c).ReaderGroups[1].MaxNetworkMessageSize = 9 }, false},
		"reader removed":        {func(c *ua.PubSubConfigurationDataType) { conn(c).ReaderGroups[1].DataSetReaders = nil }, true},
		"reader added": {func(c *ua.PubSubConfigurationDataType) {
			g := conn(c).ReaderGroups[1]
			g.DataSetReaders = append(g.DataSetReaders, &ua.DataSetReaderDataType{Name: "X"})
		}, false},
		"reader disabled": {func(c *ua.PubSubConfigurationDataType) { conn(c).ReaderGroups[1].DataSetReaders[1].Enabled = false }, true},
		"reader modified": {func(c *ua.PubSubConfigurationDataType) { conn(c).ReaderGroups[1].DataSetReaders[1].WriterGroupID = 9 }, false},
	} {
		after := safeFixture()
		c.mod(after)
		if got := safeDirection(safeFixture(), after); got != c.safe {
			t.Errorf("%s: safeDirection = %v; want %v", name, got, c.safe)
		}
	}
	// Enabling is not safe, at every level.
	before := safeFixture()
	before.Connections[1].Enabled = false
	if safeDirection(before, safeFixture()) {
		t.Error("enabling a connection is safe")
	}
	if !safeDirection(safeFixture(), nil) {
		t.Error("no configuration after is not safe")
	}
	if safeDirection(nil, safeFixture()) {
		t.Error("adding to nothing is safe")
	}
	if !safeDirection(nil, &ua.PubSubConfigurationDataType{}) {
		t.Error("nothing after nothing is not safe")
	}
}

// TestCheckPersistedReadError: the persisted check of a persistent
// endpoint, or of any endpoint with StrictNotPersisted, fails with
// Bad_InvalidState when the configuration of the reader or writer, its
// group or its connection cannot be read (Part 81 §6.2.4.3.9.2, Table
// 16); without a check to run it passes.
func TestCheckPersistedReadError(t *testing.T) {
	t.Parallel()
	srv, err := server.New(server.EndPoint("localhost", 0), server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous), server.WithPubSub(nil))
	require.NoError(t, err)
	for _, tc := range []struct {
		name       string
		persistent bool
		strict     bool
		want       ua.StatusCode
	}{
		{"persistent", true, false, ua.StatusBadInvalidState},
		{"strict", false, true, ua.StatusBadInvalidState},
		{"no check", false, false, ua.StatusOK},
	} {
		c := &Connections{srv: srv, log: slog.New(slog.DiscardHandler),
			opts: ConnectionOptions{Store: &fxstore.MemoryStore{}, StrictNotPersisted: tc.strict}}
		x := &call{c: c}
		e := &endpoint{persistent: tc.persistent}
		for _, reader := range []bool{true, false} {
			require.Equal(t, tc.want, x.checkPersisted(e, reader, 9001, 9002, 9003), "%s reader=%v", tc.name, reader)
		}
	}
}
