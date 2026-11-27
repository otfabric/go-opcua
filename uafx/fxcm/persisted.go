// SPDX-License-Identifier: MIT

package fxcm

import (
	"slices"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// notPersistedKey is the configuration property 0:NotPersisted of a PubSub
// component (OPC 10000-14 §6.2.2 Table 4: absent is FALSE).
var notPersistedKey = ua.QualifiedName{NamespaceIndex: 0, Name: "NotPersisted"}

// notPersistedOf returns the value of 0:NotPersisted in props and whether
// it is there.
func notPersistedOf(props []*ua.KeyValuePair) (value, ok bool) {
	for _, kv := range props {
		if kv != nil && kv.Key != nil && kv.Key.NamespaceIndex == 0 && kv.Key.Name == notPersistedKey.Name {
			if kv.Value != nil {
				value, _ = kv.Value.Value().(bool)
			}
			return value, true
		}
	}
	return false, false
}

// propsRef points at the configuration properties of one component of a
// PubSubConfiguration2DataType.
type propsRef struct {
	kind       uint8 // 1 connection, 2 group, 3 reader or writer
	ci, gi, ei uint16
	reader     bool
}

// fillNotPersisted applies design §6.7 (decision C3-D2) to the PubSub
// configuration of a, before it is sent: where the configuration does not
// state 0:NotPersisted for the DataSetReader or DataSetWriter of an
// endpoint, the ConnectionManager sets it from IsPersistent (FALSE for a
// persistent endpoint, TRUE for another), and for a persistent endpoint
// sets FALSE on the group and the PubSubConnection above it, so that the
// persisted check of SetCommunicationConfigurationCmd (Part 81
// §6.2.4.3.9.2) holds. An explicit value that contradicts IsPersistent is
// never overwritten: the endpoints fail with ConnectionConfigurationSetInvalid
// and Bad_ConfigurationError. So do the endpoints of a reader or writer
// shared by a persistent and a non-persistent endpoint (G14); a parent
// shared by both is persisted and no conflict.
func (x *run) fillNotPersisted(a *acRun) {
	if a.comm == nil {
		return
	}
	cfg := a.comm.cfg
	type use struct{ persistent, transient []*epRun }
	uses := map[propsRef]*use{}
	var order []propsRef
	at := func(r propsRef, ep *epRun, persistent bool) {
		u := uses[r]
		if u == nil {
			u = &use{}
			uses[r] = u
			order = append(order, r)
		}
		if persistent {
			u.persistent = append(u.persistent, ep)
		} else {
			u.transient = append(u.transient, ep)
		}
	}
	for _, ep := range a.eps {
		if ep.links == nil || ep.failed() {
			continue
		}
		persistent := ep.e.conf.IsPersistent
		for _, ref := range []struct {
			r      *ua.PubSubConfigurationRefDataType
			reader bool
		}{{ep.links.DataSetReaderRef, true}, {ep.links.DataSetWriterRef, false}} {
			if ref.r == nil || propsAt(cfg, propsRef{kind: 3, ci: ref.r.ConnectionIndex, gi: ref.r.GroupIndex, ei: ref.r.ElementIndex, reader: ref.reader}) == nil {
				continue
			}
			at(propsRef{kind: 3, ci: ref.r.ConnectionIndex, gi: ref.r.GroupIndex, ei: ref.r.ElementIndex, reader: ref.reader}, ep, persistent)
			if persistent {
				at(propsRef{kind: 2, ci: ref.r.ConnectionIndex, gi: ref.r.GroupIndex, reader: ref.reader}, ep, true)
				at(propsRef{kind: 1, ci: ref.r.ConnectionIndex}, ep, true)
			}
		}
	}
	fail := func(eps ...[]*epRun) {
		for _, l := range eps {
			for _, ep := range l {
				x.fail(ep, Failure{FxError: uafx.FxErrorConnectionConfigurationSetInvalid, Status: ua.StatusBadConfigurationError})
			}
		}
	}
	for _, r := range order {
		u := uses[r]
		props := propsAt(cfg, r)
		if props == nil {
			continue
		}
		v, explicit := notPersistedOf(*props)
		switch {
		case r.kind == 3 && len(u.persistent) > 0 && len(u.transient) > 0:
			fail(u.persistent, u.transient)
		case r.kind == 3:
			want := len(u.persistent) == 0
			if explicit && v != want {
				fail(u.persistent, u.transient)
				continue
			}
			if !explicit {
				*props = append(slices.Clone(*props), &ua.KeyValuePair{Key: &ua.QualifiedName{Name: notPersistedKey.Name}, Value: ua.MustVariant(want)})
			}
		default:
			// A parent of a persistent endpoint's reader or writer.
			if explicit && v {
				fail(u.persistent)
				continue
			}
			if !explicit {
				*props = append(slices.Clone(*props), &ua.KeyValuePair{Key: &ua.QualifiedName{Name: notPersistedKey.Name}, Value: ua.MustVariant(false)})
			}
		}
	}
}

// propsAt returns the configuration properties of r in cfg, nil when cfg
// has no such component.
func propsAt(cfg *ua.PubSubConfiguration2DataType, r propsRef) *[]*ua.KeyValuePair {
	if cfg == nil || int(r.ci) >= len(cfg.Connections) || cfg.Connections[r.ci] == nil {
		return nil
	}
	c := cfg.Connections[r.ci]
	if r.kind == 1 {
		return &c.ConnectionProperties
	}
	if r.reader {
		if int(r.gi) >= len(c.ReaderGroups) || c.ReaderGroups[r.gi] == nil {
			return nil
		}
		g := c.ReaderGroups[r.gi]
		if r.kind == 2 {
			return &g.GroupProperties
		}
		if int(r.ei) >= len(g.DataSetReaders) || g.DataSetReaders[r.ei] == nil {
			return nil
		}
		return &g.DataSetReaders[r.ei].DataSetReaderProperties
	}
	if int(r.gi) >= len(c.WriterGroups) || c.WriterGroups[r.gi] == nil {
		return nil
	}
	g := c.WriterGroups[r.gi]
	if r.kind == 2 {
		return &g.GroupProperties
	}
	if int(r.ei) >= len(g.DataSetWriters) || g.DataSetWriters[r.ei] == nil {
		return nil
	}
	return &g.DataSetWriters[r.ei].DataSetWriterProperties
}
