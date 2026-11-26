// SPDX-License-Identifier: MIT

package fxcm

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

func notPersistedKV(v bool) *ua.KeyValuePair {
	return &ua.KeyValuePair{Key: &ua.QualifiedName{Name: "NotPersisted"}, Value: ua.MustVariant(v)}
}

// persistedFixture is one PubSubConnection with a writer group of two
// writers and a reader group of one reader.
func persistedFixture() *ua.PubSubConfiguration2DataType {
	return &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{{
		Name:         "C",
		WriterGroups: []*ua.WriterGroupDataType{{Name: "WG", DataSetWriters: []*ua.DataSetWriterDataType{{Name: "W0"}, {Name: "W1"}}}},
		ReaderGroups: []*ua.ReaderGroupDataType{{Name: "RG", DataSetReaders: []*ua.DataSetReaderDataType{{Name: "R0"}}}},
	}}}
}

func writerRef(ei uint16) *ua.PubSubConfigurationRefDataType {
	return &ua.PubSubConfigurationRefDataType{ElementIndex: ei}
}

// persistedRun returns a run whose AutomationComponent has cfg and an
// endpoint per persistent flag, endpoint i linked to writer refs[i].
func persistedRun(cfg *ua.PubSubConfiguration2DataType, persistent []bool, writers []uint16, reader bool) (*run, *acRun) {
	x := &run{}
	a := &acRun{comm: &commModel{cfg: cfg}}
	for i, p := range persistent {
		ep := &epRun{x: x, a: a, e: &endpoint{conf: &uafx.ConnectionEndpointConfigurationConf{IsPersistent: p}, conn: &connection{name: "c"}, number: i + 1}}
		ep.links = &uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: writerRef(writers[i])}
		if reader && i == 0 {
			ep.links.DataSetReaderRef = &ua.PubSubConfigurationRefDataType{}
		}
		a.eps = append(a.eps, ep)
		x.eps = append(x.eps, ep)
	}
	return x, a
}

// TestFillNotPersisted: the ConnectionManager fills a missing NotPersisted
// from IsPersistent (design §6.7, decision C3-D2), on the parents of a
// persistent endpoint's reader or writer too, keeps a consistent explicit
// value, and fails the endpoints of a contradicting one or of a reader or
// writer shared by a persistent and a non-persistent endpoint (G14); a
// shared parent is no conflict.
func TestFillNotPersisted(t *testing.T) {
	t.Parallel()
	get := func(props []*ua.KeyValuePair) any {
		v, ok := notPersistedOf(props)
		if !ok {
			return nil
		}
		return v
	}

	// Persistent on W0 and R0, non-persistent on W1: the group and the
	// connection are shared and persisted.
	cfg := persistedFixture()
	x, a := persistedRun(cfg, []bool{true, false}, []uint16{0, 1}, true)
	x.fillNotPersisted(a)
	require.False(t, x.anyFailed())
	c := cfg.Connections[0]
	assert.Equal(t, false, get(c.ConnectionProperties))
	assert.Equal(t, false, get(c.WriterGroups[0].GroupProperties))
	assert.Equal(t, false, get(c.ReaderGroups[0].GroupProperties))
	assert.Equal(t, false, get(c.WriterGroups[0].DataSetWriters[0].DataSetWriterProperties))
	assert.Equal(t, true, get(c.WriterGroups[0].DataSetWriters[1].DataSetWriterProperties))
	assert.Equal(t, false, get(c.ReaderGroups[0].DataSetReaders[0].DataSetReaderProperties))

	// Only non-persistent: the parents are left as they are.
	cfg = persistedFixture()
	x, a = persistedRun(cfg, []bool{false}, []uint16{0}, false)
	x.fillNotPersisted(a)
	require.False(t, x.anyFailed())
	assert.Nil(t, get(cfg.Connections[0].ConnectionProperties))
	assert.Equal(t, true, get(cfg.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetWriterProperties))

	// A consistent explicit value is kept, not doubled.
	cfg = persistedFixture()
	cfg.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetWriterProperties = []*ua.KeyValuePair{notPersistedKV(false)}
	x, a = persistedRun(cfg, []bool{true}, []uint16{0}, false)
	x.fillNotPersisted(a)
	require.False(t, x.anyFailed())
	assert.Len(t, cfg.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetWriterProperties, 1)

	for name, tc := range map[string]struct {
		mutate     func(*ua.PubSubConfiguration2DataType)
		persistent []bool
		writers    []uint16
	}{
		"persistent writer NotPersisted TRUE": {func(c *ua.PubSubConfiguration2DataType) {
			c.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetWriterProperties = []*ua.KeyValuePair{notPersistedKV(true)}
		}, []bool{true}, []uint16{0}},
		"non-persistent writer NotPersisted FALSE": {func(c *ua.PubSubConfiguration2DataType) {
			c.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetWriterProperties = []*ua.KeyValuePair{notPersistedKV(false)}
		}, []bool{false}, []uint16{0}},
		"parent of a persistent writer NotPersisted TRUE": {func(c *ua.PubSubConfiguration2DataType) {
			c.Connections[0].ConnectionProperties = []*ua.KeyValuePair{notPersistedKV(true)}
		}, []bool{true}, []uint16{0}},
		"writer shared by a persistent and a non-persistent endpoint": {func(*ua.PubSubConfiguration2DataType) {}, []bool{true, false}, []uint16{0, 0}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := persistedFixture()
			tc.mutate(cfg)
			x, a := persistedRun(cfg, tc.persistent, tc.writers, false)
			x.fillNotPersisted(a)
			for _, ep := range a.eps {
				require.NotNil(t, ep.outcome)
				assert.Equal(t, Failed, ep.outcome.Kind)
				assert.Equal(t, ua.StatusBadConfigurationError, ep.outcome.Status)
			}
		})
	}

	// Out-of-range references are skipped; no comm model is nothing.
	cfg = persistedFixture()
	x, a = persistedRun(cfg, []bool{true}, []uint16{9}, false)
	x.fillNotPersisted(a)
	require.False(t, x.anyFailed())
	assert.Nil(t, get(cfg.Connections[0].ConnectionProperties))
	x.fillNotPersisted(&acRun{})
	for _, r := range []propsRef{{kind: 1, ci: 3}, {kind: 2, gi: 3}, {kind: 2, gi: 3, reader: true}, {kind: 3, ei: 3, reader: true}} {
		assert.Nil(t, propsAt(persistedFixture(), r))
	}
	assert.Nil(t, propsAt(nil, propsRef{}))
}

// TestValidatePersistentCleanupTimeout: IsPersistent TRUE needs a negative,
// finite CleanupTimeout; anything else is a ConfigError, never normalized
// (decision C3-D4).
func TestValidatePersistentCleanupTimeout(t *testing.T) {
	t.Parallel()
	for _, v := range []float64{0, 1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		c := validConf()
		c.Connections[0].Endpoint1.IsPersistent = true
		c.Connections[0].Endpoint1.CleanupTimeout = v
		_, err := NewConfig(c)
		var ce *ConfigError
		require.ErrorAs(t, err, &ce, "%v", v)
		assert.Contains(t, ce.Error(), "CleanupTimeout")
	}
	c := validConf()
	c.Connections[0].Endpoint1.IsPersistent = true
	c.Connections[0].Endpoint1.CleanupTimeout = -1
	_, err := NewConfig(c)
	require.NoError(t, err)
}
