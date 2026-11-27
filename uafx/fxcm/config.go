// SPDX-License-Identifier: MIT

package fxcm

import (
	"fmt"
	"net"
	"net/url"
	"slices"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// Config is one Version of a ConnectionConfigurationSet: validated and
// immutable. A run processes the Config it started with; an edit makes a
// new one (§6.7.4: only committed updates are processed).
type Config struct {
	key     SetKey
	version uint32
	conf    *uafx.ConnectionConfigurationSetConf // a private copy

	servers []*serverAddress
	acs     []*automationComponent
	flows   []*flow
	conns   []*connection
}

// NewConfig validates conf and returns it as the first Version of the set:
// Version is 1 when a set is added or replaced (§6.8.2), whatever the
// Version field of conf says. conf is copied; the caller may change it
// afterwards. An invalid set is a *ConfigError.
func NewConfig(conf *uafx.ConnectionConfigurationSetConf) (*Config, error) {
	return newConfig(conf, 1)
}

func newConfig(conf *uafx.ConnectionConfigurationSetConf, version uint32) (*Config, error) {
	if conf == nil {
		return nil, &ConfigError{Findings: []Finding{{Path: "", Clause: "F.1.3", Problem: "no ConnectionConfigurationSet"}}}
	}
	cp, err := cloneConf(conf)
	if err != nil {
		return nil, &ConfigError{Key: KeyOf(conf), Findings: []Finding{{Path: "", Clause: "F.2", Problem: err.Error()}}}
	}
	cp.Version = version
	c := &Config{key: KeyOf(cp), version: version, conf: cp}
	if fs := c.build(); len(fs) > 0 {
		return nil, &ConfigError{Key: c.key, Findings: fs}
	}
	return c, nil
}

// cloneNS are the namespace indexes cloneConf encodes with: any distinct
// indexes do, the bytes do not leave the package.
var cloneNS = uafx.NamespaceIndexes{Data: 2, AC: 3, CM: 4}

// cloneConf returns a deep copy of conf, through its binary encoding.
func cloneConf(conf *uafx.ConnectionConfigurationSetConf) (*uafx.ConnectionConfigurationSetConf, error) {
	eo, err := uafx.EncodeStructure(withRawLinks(conf), cloneNS)
	if err != nil {
		return nil, err
	}
	b, err := ua.Encode(eo)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", uafx.ErrCodec, err)
	}
	out := new(ua.ExtensionObject)
	if _, err := ua.Decode(b, out); err != nil {
		return nil, fmt.Errorf("%w: %w", uafx.ErrCodec, err)
	}
	s, err := uafx.DecodeStructure(out, cloneNS)
	if err != nil {
		return nil, err
	}
	return s.(*uafx.ConnectionConfigurationSetConf), nil
}

// withRawLinks returns conf, or a shallow copy of it, in which every
// CommunicationLinks that ua.Decode left as a RawBody, its type not being
// registered (as after a clone, or a set decoded from a file), carries the
// body as its Value, so that it is encoded again: Encode ignores RawBody.
// conf is not changed.
func withRawLinks(conf *uafx.ConnectionConfigurationSetConf) *uafx.ConnectionConfigurationSetConf {
	raw := func(e *uafx.ConnectionEndpointConfigurationConf) bool {
		return e != nil && e.CommunicationLinks != nil && e.CommunicationLinks.Value == nil && len(e.CommunicationLinks.RawBody) > 0
	}
	fix := func(e *uafx.ConnectionEndpointConfigurationConf) *uafx.ConnectionEndpointConfigurationConf {
		if !raw(e) {
			return e
		}
		ec, eo := *e, *e.CommunicationLinks
		eo.Value, eo.RawBody = eo.RawBody, nil
		ec.CommunicationLinks = &eo
		return &ec
	}
	need := false
	for _, cn := range conf.Connections {
		need = need || (cn != nil && (raw(cn.Endpoint1) || raw(cn.Endpoint2)))
	}
	if !need {
		return conf
	}
	cp := *conf
	cp.Connections = make([]*uafx.ConnectionConfigurationConf, len(conf.Connections))
	for i, cn := range conf.Connections {
		if cn == nil {
			continue
		}
		cc := *cn
		cc.Endpoint1, cc.Endpoint2 = fix(cn.Endpoint1), fix(cn.Endpoint2)
		cp.Connections[i] = &cc
	}
	return &cp
}

// Key returns the identity of the set.
func (c *Config) Key() SetKey {
	return SetKey{Folder: slices.Clone(c.key.Folder), Name: c.key.Name}
}

// Version returns the Version of the set (§6.8.2).
func (c *Config) Version() uint32 { return c.version }

// Conf returns a copy of the set, with Version set to the Version of c.
func (c *Config) Conf() *uafx.ConnectionConfigurationSetConf {
	cp, err := cloneConf(c.conf)
	if err != nil {
		// c.conf was encoded and decoded by newConfig.
		panic("fxcm: copy of a valid set: " + err.Error())
	}
	return cp
}

// RollbackOnError reports whether an error during establishment closes all
// established Connections of the set (§6.8.2, F.1.3).
func (c *Config) RollbackOnError() bool { return c.conf.RollbackOnError }

// Connections returns the names of the Connections of the set, in the
// order of the set. A ConnectionsDiagnostics element is linked to its
// Connection by this name (§6.8.2).
func (c *Config) Connections() []string {
	names := make([]string, len(c.conns))
	for i, cn := range c.conns {
		names[i] = cn.name
	}
	return names
}

// The resolved form of a set: the indexes of F.1.2.1 as pointers.

type serverAddress struct {
	index int
	conf  *uafx.ServerAddressConf
	ns    namespaceScope
}

type automationComponent struct {
	index  int
	conf   *uafx.AutomationComponentConfigurationConf
	server *serverAddress
}

type flow struct {
	index int
	conf  *uafx.PubSubCommunicationFlowConfigurationConf
	// multicast is the kind of the Address of the flow: true for a
	// multicast IP address, false for a unicast one, nil when the Address
	// is absent or its kind cannot be told without resolving a host name.
	multicast *bool
}

type connection struct {
	index     int
	name      string
	endpoints []*endpoint // Endpoint1 and, when present, Endpoint2
}

type endpoint struct {
	conn     *connection
	number   int // 1 or 2
	conf     *uafx.ConnectionEndpointConfigurationConf
	ac       *automationComponent
	outbound *flow
	inbound  *inbound
}

type inbound struct {
	flow       *flow
	index      int
	subscriber *uafx.SubscriberConfigurationConf
}

// namespaceScope is the Namespaces table of a ServerAddressConf: the scope
// of the NodeIds and RelativePaths of the configurations of its
// AutomationComponents (F.1.2.2).
type namespaceScope []string

// uaNamespace is the namespace with index 0 of every server (Part 3 §8.2.2).
const uaNamespace = "http://opcfoundation.org/UA/"

// uri returns the NamespaceUri of the index idx. Library interpretation:
// F.1.2.2 says the NamespaceIndex is an index into the Namespaces array, so
// the array mirrors a NamespaceArray of a server (Part 5 §6.3.1): index 0 is
// the OPC UA namespace, also when the array leaves it out.
func (s namespaceScope) uri(idx uint16) (string, bool) {
	switch {
	case idx == 0:
		return uaNamespace, true
	case int(idx) < len(s) && s[idx] != "":
		return s[idx], true
	}
	return "", false
}

// multicastAddress reports whether eo, the Address of a flow, is a
// NetworkAddressUrl whose host is an IP multicast address, nil when that
// cannot be told without resolving a host name. Library interpretation:
// §6.13.3 tells unicast from multicast flows by their Address; the kind of
// an IP address is that of its range.
func multicastAddress(eo *ua.ExtensionObject) *bool {
	if eo == nil {
		return nil
	}
	a, ok := eo.Value.(*ua.NetworkAddressURLDataType)
	if !ok || a == nil {
		return nil
	}
	u, err := url.Parse(a.URL)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil {
		return nil
	}
	m := ip.IsMulticast()
	return &m
}

// endpointNamed returns the endpoint configuration of c whose Name is name.
func (c *Config) endpointNamed(name string) (EndpointRef, bool) {
	for _, cn := range c.conns {
		for _, e := range cn.endpoints {
			if e.conf.Name == name {
				return EndpointRef{Connection: cn.name, Endpoint: e.number}, true
			}
		}
	}
	return EndpointRef{}, false
}
