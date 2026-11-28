// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// reflectConf is validConf with a PubSubConfiguration on both ACs and
// CommunicationLinks on every endpoint: AC1 publishes Flow1 and subscribes
// Flow2 on its one PubSubConnection, AC2 the other way round.
func reflectConf() *uafx.ConnectionConfigurationSetConf {
	c := validConf()
	model := func() *uafx.PubSubCommunicationModelConfiguration {
		return &uafx.PubSubCommunicationModelConfiguration{PubSubConfiguration: &ua.PubSubConfiguration2DataType{
			Connections: []*ua.PubSubConnectionDataType{{
				Name:                "Conn",
				TransportProfileURI: UDPUADP,
				Address:             urlAddress("opc.udp://239.0.0.1:4840"),
				WriterGroups:        []*ua.WriterGroupDataType{{Name: "WG", PublishingInterval: 10, DataSetWriters: []*ua.DataSetWriterDataType{{Name: "W"}}}},
				ReaderGroups:        []*ua.ReaderGroupDataType{{Name: "RG", DataSetReaders: []*ua.DataSetReaderDataType{{Name: "R", MessageReceiveTimeout: 100}}}},
			}},
		}}
	}
	c.AutomationComponentConfigurations[0].CommunicationModelConfig = model()
	c.AutomationComponentConfigurations[1].CommunicationModelConfig = model()
	ref := &ua.PubSubConfigurationRefDataType{ConfigurationMask: 1}
	enc := func(l *uafx.PubSubCommunicationLinkConfiguration) *ua.ExtensionObject {
		eo, err := uafx.EncodeStructure(l, cloneNS)
		if err != nil {
			panic(err)
		}
		return eo
	}
	pub := enc(&uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: ref})
	sub := enc(&uafx.PubSubCommunicationLinkConfiguration{DataSetReaderRef: ref})
	for _, cn := range c.Connections {
		cn.Endpoint1.CommunicationLinks = pub
		cn.Endpoint2.CommunicationLinks = sub
	}
	for _, f := range c.CommunicationFlows {
		f.(*uafx.PubSubCommunicationFlowConfigurationConf).TransportProfileURI = ptr(UDPUADP)
	}
	f2 := c.CommunicationFlows[1].(*uafx.PubSubCommunicationFlowConfigurationConf)
	f2.SecurityMode = ptr(ua.MessageSecurityModeSign)
	f2.SecurityGroupID = ptr("G1")
	f2.HeaderLayoutURI = ptr("urn:h1")
	return c
}

func flowOf(c *uafx.ConnectionConfigurationSetConf, i int) *uafx.PubSubCommunicationFlowConfigurationConf {
	return c.CommunicationFlows[i].(*uafx.PubSubCommunicationFlowConfigurationConf)
}

func pubsubConn(c *Config, ac int) *ua.PubSubConnectionDataType {
	return c.conf.AutomationComponentConfigurations[ac].CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration).PubSubConfiguration.Connections[0]
}

// TestReflectFlows: a committed edit of the flow Variables reaches the
// writer and reader groups and connections the CommunicationLinks name
// (§6.13.1, §6.16.3; library interpretation CS-19).
func TestReflectFlows(t *testing.T) {
	base := mustConfig(t, reflectConf())
	var s EditSlot
	e, err := s.Start(base, "a")
	require.NoError(t, err)
	w := e.Conf()
	f1, f2 := flowOf(w, 0), flowOf(w, 1)
	f1.PublishingInterval = ptr(20.0)
	f1.Address.Address = urlAddress("opc.udp://239.0.0.2:4840")
	f1.SubscriberConfigurations[0].MessageReceiveTimeout = 250
	f2.SecurityMode = ptr(ua.MessageSecurityModeSignAndEncrypt)
	f2.SecurityGroupID = ptr("G2")
	f2.HeaderLayoutURI = ptr("urn:h2")
	next, ok, err := s.Commit("a")
	require.NoError(t, err)
	require.True(t, ok)

	ac1, ac2 := pubsubConn(next, 0), pubsubConn(next, 1)
	// AC1 publishes Flow1: group and connection.
	assert.Equal(t, 20.0, ac1.WriterGroups[0].PublishingInterval)
	assert.Equal(t, urlAddress("opc.udp://239.0.0.2:4840"), ac1.Address)
	// AC2 subscribes Flow1: the multicast Address and the timeout.
	assert.Equal(t, urlAddress("opc.udp://239.0.0.2:4840"), ac2.Address)
	assert.Equal(t, 250.0, ac2.ReaderGroups[0].DataSetReaders[0].MessageReceiveTimeout)
	// AC2 publishes Flow2.
	g := ac2.WriterGroups[0]
	assert.Equal(t, ua.MessageSecurityModeSignAndEncrypt, g.SecurityMode)
	assert.Equal(t, "G2", g.SecurityGroupID)
	assert.Equal(t, "urn:h2", g.HeaderLayoutURI)
	// AC1 subscribes Flow2.
	r := ac1.ReaderGroups[0].DataSetReaders[0]
	assert.Equal(t, ua.MessageSecurityModeSignAndEncrypt, r.SecurityMode)
	assert.Equal(t, "G2", r.SecurityGroupID)
	assert.Equal(t, "urn:h2", r.HeaderLayoutURI)
	// The base Config is untouched.
	assert.Equal(t, 10.0, pubsubConn(base, 0).WriterGroups[0].PublishingInterval)
}

// TestReflectFlowsConflict: two flows reflected onto one connection with
// different values are a ConfigError, and the set stays in edit.
func TestReflectFlowsConflict(t *testing.T) {
	base := mustConfig(t, reflectConf())
	var s EditSlot
	e, err := s.Start(base, "a")
	require.NoError(t, err)
	flowOf(e.Conf(), 0).TransportProfileURI = ptr("urn:a")
	flowOf(e.Conf(), 1).TransportProfileURI = ptr("urn:b")
	_, ok, err := s.Commit("a")
	require.False(t, ok)
	var ce *ConfigError
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Findings[0].Problem, "another flow sets")
	assert.NotNil(t, s.Editing())

	// AC2's one PubSubConnection publishes Flow2 and subscribes the
	// multicast Flow1: two new Addresses for it conflict too.
	flowOf(e.Conf(), 0).TransportProfileURI = ptr(UDPUADP)
	flowOf(e.Conf(), 1).TransportProfileURI = ptr(UDPUADP)
	flowOf(e.Conf(), 0).Address.Address = urlAddress("opc.udp://239.0.0.2:4840")
	flowOf(e.Conf(), 1).Address.Address = urlAddress("opc.udp://10.0.0.2:4840")
	_, _, err = s.Commit("a")
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Findings[0].Problem, "opc.udp://")
}

// TestReflectFlowsUnchanged: a commit without flow changes leaves the
// PubSubConfigurations as they are, also where they disagree with the
// flow Variables.
func TestReflectFlowsUnchanged(t *testing.T) {
	c := reflectConf()
	c.AutomationComponentConfigurations[0].CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration).PubSubConfiguration.Connections[0].WriterGroups[0].PublishingInterval = 50
	base := mustConfig(t, c)
	var s EditSlot
	_, err := s.Start(base, "a")
	require.NoError(t, err)
	next, ok, err := s.Commit("a")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 50.0, pubsubConn(next, 0).WriterGroups[0].PublishingInterval)
}

func TestReflectHelpers(t *testing.T) {
	_, ok := changed[int](nil, ptr(1))
	assert.False(t, ok)
	_, ok = changed(ptr(1), ptr(1))
	assert.False(t, ok)
	v, ok := changed(ptr(1), ptr(2))
	assert.True(t, ok)
	assert.Equal(t, 2, v)
	a := &uafx.AddressSelection{Address: urlAddress("x")}
	_, ok = changedAddress(a, nil)
	assert.False(t, ok)
	_, ok = changedAddress(a, &uafx.AddressSelection{Address: urlAddress("x")})
	assert.False(t, ok)
	assert.Equal(t, "", connName(nil))
	cfg, l := pubsubOf(&endpoint{})
	assert.Nil(t, cfg)
	assert.Nil(t, l)
	cfg, _ = pubsubOf(&endpoint{ac: &automationComponent{conf: &uafx.AutomationComponentConfigurationConf{}}})
	assert.Nil(t, cfg)
	// Endpoints without a PubSubConfiguration or a matching element are
	// skipped.
	r := reflector{set: map[string]string{}}
	f := &uafx.PubSubCommunicationFlowConfigurationConf{PublishingInterval: ptr(1.0)}
	r.publisher("p", &endpoint{}, f, f)
	r.subscriber("p", &endpoint{}, &flow{conf: f}, &flow{conf: f})
	model := &uafx.PubSubCommunicationModelConfiguration{PubSubConfiguration: &ua.PubSubConfiguration2DataType{}}
	ep := &endpoint{
		ac: &automationComponent{conf: &uafx.AutomationComponentConfigurationConf{CommunicationModelConfig: model}},
		conf: &uafx.ConnectionEndpointConfigurationConf{CommunicationLinks: ua.NewExtensionObject(&uafx.PubSubCommunicationLinkConfiguration{ // decoded already
			DataSetWriterRef: &ua.PubSubConfigurationRefDataType{}, DataSetReaderRef: &ua.PubSubConfigurationRefDataType{},
		})},
	}
	r.publisher("p", ep, f, f)
	r.subscriber("p", ep, &flow{conf: f}, &flow{conf: f})
	assert.Empty(t, r.findings)
}

// TestCloneKeepsLinks: CommunicationLinks that a decode left as a RawBody
// survive a second clone, as an edit makes one from Config.Conf and
// commits another.
func TestCloneKeepsLinks(t *testing.T) {
	base := mustConfig(t, reflectConf())
	raw := base.conf.Connections[0].Endpoint1.CommunicationLinks
	require.Nil(t, raw.Value)
	require.NotEmpty(t, raw.RawBody)
	again, err := newConfig(base.Conf(), 2)
	require.NoError(t, err)
	l, err := links(again.conf.Connections[0].Endpoint1.CommunicationLinks)
	require.NoError(t, err)
	require.NotNil(t, l)
	assert.Equal(t, ua.PubSubConfigurationRefMask(1), l.DataSetWriterRef.ConfigurationMask)
	assert.Nil(t, raw.Value, "the source is not changed")
	// A set without RawBody links is used as it is.
	c := validConf()
	assert.Same(t, c, withRawLinks(c))
	c.Connections = append(c.Connections, nil)
	assert.Same(t, c, withRawLinks(c))
	c.Connections[0].Endpoint1.CommunicationLinks = raw
	cp := withRawLinks(c)
	assert.NotSame(t, c, cp)
	assert.Nil(t, cp.Connections[2])
}

// TestManagerObservers: AddObserver sees the set and edit events with the
// Version, and stops seeing them once removed.
func TestManagerObservers(t *testing.T) {
	t.Parallel()
	m, err := New(Options{Dialer: offline{}, ApplicationURI: cmURI})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = m.Close() })
	var mu sync.Mutex
	var got []Event
	remove := m.AddObserver(ObserverFunc(func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		if e.Kind >= EventSetAdded {
			got = append(got, e)
		}
	}))
	c := reflectConf()
	key := KeyOf(c)
	_, err = m.Add(c)
	require.NoError(t, err)
	e, err := m.StartEdit(key, "a")
	require.NoError(t, err)
	_, err = m.StartEdit(key, "a") // the same owner: no second event
	require.NoError(t, err)
	flowOf(e.Conf(), 0).PublishingInterval = ptr(20.0)
	_, ok, err := m.CommitEdit(key, "a")
	require.NoError(t, err)
	require.True(t, ok)
	cfg, _ := m.Config(key)
	assert.Equal(t, 20.0, pubsubConn(cfg, 0).WriterGroups[0].PublishingInterval)
	_, err = m.StartEdit(key, "a")
	require.NoError(t, err)
	ok, err = m.DiscardEdit(key, "a")
	require.NoError(t, err)
	require.True(t, ok)
	_, err = m.StartEdit(key, "a")
	require.NoError(t, err)
	require.True(t, m.EditLockLost(key))
	_, err = m.Replace(context.Background(), reflectConf())
	require.NoError(t, err)
	require.NoError(t, m.Remove(context.Background(), key))
	remove()
	_, err = m.Add(reflectConf())
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	kinds := make([]EventKind, len(got))
	for i, e := range got {
		kinds[i] = e.Kind
		assert.True(t, e.Set.Equal(key))
	}
	assert.Equal(t, []EventKind{
		EventSetAdded, EventEditStarted, EventCommitted, EventEditStarted, EventEditEnded,
		EventEditStarted, EventEditEnded, EventSetReplaced, EventSetRemoved,
	}, kinds)
	assert.Equal(t, uint32(1), got[0].Version)
	assert.Equal(t, uint32(2), got[2].Version)
	assert.Equal(t, uint32(1), got[7].Version)
	cfg, ok = m.Config(key)
	require.True(t, ok)
	assert.Equal(t, 10.0, pubsubConn(cfg, 0).WriterGroups[0].PublishingInterval, "the re-added set")
}
