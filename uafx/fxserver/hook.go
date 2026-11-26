// SPDX-License-Identifier: MIT

package fxserver

import (
	"reflect"
	"slices"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The hook of the PubSub transaction of the server (design §4.5): it keeps
// the component records of the persistent endpoints in line with the
// configuration, whatever changes it (CloseAndUpdate, the PubSub Methods,
// UpdatePubSubConfiguration, ChangePubSubConfiguration), and holds the
// PubSub identifiers the quarantined records reserve (§4.7).

var _ server.PubSubConfigurationRestorer = (*persistence)(nil)

// PubSubConfigurationChanged checks the change ch and writes the component
// records it changes. A change of an EstablishConnections call itself is
// written at the call's commit point. A Revert, and a change of this
// package's own that only removes or disables components, is never refused
// for a record that is not committed: its record is owed. Such a change
// comes after its durable state: the removal intent (RemovePending) or the
// disabled record of a CloseConnections, or the rollback of what was not
// committed (design §4.4). The same change made by another mechanism (a
// PubSub Method, CloseAndUpdate) has no such intent and is refused.
func (p *persistence) PubSubConfigurationChanged(ch *server.PubSubChange) error {
	added := addedComponents(ch.Before, ch.After)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !ch.Revert {
		if sc := p.checkAdditionsLocked(added); sc != ua.StatusOK {
			return sc
		}
		if sc := p.checkNotPersistedLocked(ch.After); sc != ua.StatusOK {
			return sc
		}
	}
	if ownCall(ch.Context) {
		return nil
	}
	s := p.begin()
	s.refresh()
	b, err := s.batch()
	if err != nil {
		return ua.StatusBadInternalError
	}
	if b.Empty() {
		return nil
	}
	ctx, cancel := p.ctx()
	defer cancel()
	o, err := p.d.Apply(ctx, b)
	switch {
	case o == fxstore.Committed:
		p.reload()
		return nil
	case o == fxstore.NotCommitted && !ch.Revert && (!p.own || !safeDirection(ch.Before, ch.After)):
		// The store and the runtime must agree: the change is refused
		// (library interpretation, design §4.5).
		p.c.log.Warn("uafx: a PubSub change to a persisted component is refused: its record was not committed", "error", err)
		return ua.StatusBadResourceUnavailable
	default:
		// Unknown, a Revert, or a change of this package's own in the
		// safe direction (it only removes or disables components, as
		// CloseConnections does after its intent, also while the store is
		// fenced by that intent; design §4.4): the change stands and the
		// store follows.
		_, _ = p.d.Require(ctx, b)
		p.c.log.Warn("uafx: the record of a changed PubSub component is owed; the store is fenced until it is written", "error", err)
		return nil
	}
}

// HeldPubSubIDs returns the WriterGroupIds and DataSetWriterIds the
// quarantined records reserve. It refuses every reservation while a record
// whose identities cannot be read is quarantined (they may be any), or
// while the store is fenced (a write with an unknown outcome may hold
// some).
func (p *persistence) HeldPubSubIDs() (groups, writers []uint16, refuse bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, q := range p.quar {
		if q.id != nil {
			groups = append(groups, q.id.WriterGroupIDs...)
			writers = append(writers, q.id.DataSetWriterIDs...)
		}
	}
	return groups, writers, p.allocFencedLocked() || p.fenced()
}

// allocFencedLocked reports whether a quarantined record hides the PubSub
// identifiers it reserves: no new WriterGroup or DataSetWriter id may be
// used anywhere in the server (design §4.7: the identifiers are shared by
// all AutomationComponents).
func (p *persistence) allocFencedLocked() bool {
	for _, q := range p.quar {
		if q.id == nil && !q.component {
			return true
		}
	}
	return false
}

// added is a component a change adds.
type added struct {
	path   string
	group  uint16 // WriterGroupId of a WriterGroup
	writer uint16 // DataSetWriterId of a DataSetWriter
	ids    bool   // a WriterGroup or a DataSetWriter
}

// addedComponents returns the components in after that are not in
// before, and the WriterGroups and DataSetWriters whose WriterGroupId or
// DataSetWriterId changed: a new id on an existing component is an
// allocation too (a modify of Part 14 §9.1.3.7.4, or a replacement by
// UpdatePubSubConfiguration).
func addedComponents(before, after *ua.PubSubConfigurationDataType) []added {
	have := map[string]added{}
	for _, a := range componentsIn(before) {
		have[a.path] = a
	}
	var out []added
	for _, a := range componentsIn(after) {
		if b, ok := have[a.path]; !ok || a.group != b.group || a.writer != b.writer {
			out = append(out, a)
		}
	}
	return out
}

func componentsIn(cfg *ua.PubSubConfigurationDataType) []added {
	if cfg == nil {
		return nil
	}
	var out []added
	for _, pds := range cfg.PublishedDataSets {
		if pds != nil {
			out = append(out, added{path: componentPath(pubsub.KindPublishedDataSet, pds.Name)})
		}
	}
	for _, conn := range cfg.Connections {
		if conn == nil {
			continue
		}
		out = append(out, added{path: componentPath(pubsub.KindConnection, conn.Name)})
		for _, g := range conn.WriterGroups {
			if g == nil {
				continue
			}
			out = append(out, added{path: componentPath(pubsub.KindWriterGroup, conn.Name, g.Name), group: g.WriterGroupID, ids: true})
			for _, w := range g.DataSetWriters {
				if w != nil {
					out = append(out, added{path: componentPath(pubsub.KindDataSetWriter, conn.Name, g.Name, w.Name), writer: w.DataSetWriterID, ids: true})
				}
			}
		}
		for _, g := range conn.ReaderGroups {
			if g == nil {
				continue
			}
			out = append(out, added{path: componentPath(pubsub.KindReaderGroup, conn.Name, g.Name)})
			for _, r := range g.DataSetReaders {
				if r != nil {
					out = append(out, added{path: componentPath(pubsub.KindDataSetReader, conn.Name, g.Name, r.Name)})
				}
			}
		}
	}
	return out
}

// checkAdditionsLocked refuses additions that could take what a
// quarantined record or a write with an unknown outcome reserves: its
// component paths, its WriterGroupIds and DataSetWriterIds, or any of them
// when they cannot be told (design §3.5, §4.7). Bad_ResourceUnavailable.
func (p *persistence) checkAdditionsLocked(add []added) ua.StatusCode {
	if len(add) == 0 {
		return ua.StatusOK
	}
	fence := p.allocFencedLocked() || p.fenced()
	var paths []string
	var groups, writers []uint16
	for _, q := range p.quar {
		if q.id != nil {
			paths = append(paths, q.id.Paths...)
			groups = append(groups, q.id.WriterGroupIDs...)
			writers = append(writers, q.id.DataSetWriterIDs...)
		}
	}
	for _, a := range add {
		switch {
		case a.ids && fence,
			slices.Contains(paths, a.path),
			a.group != 0 && slices.Contains(groups, a.group),
			a.writer != 0 && slices.Contains(writers, a.writer):
			p.c.log.Warn("uafx: a PubSub component is refused: a quarantined persistent record or an unsettled store reserves it", "component", a.path)
			return ua.StatusBadResourceUnavailable
		}
	}
	return ua.StatusOK
}

// checkNotPersistedLocked refuses NotPersisted TRUE on a component a
// persistent endpoint references (design §4.5; Part 81 §6.2.4.3.9.2,
// Part 14 §6.2.2 Table 4). Bad_InvalidState.
func (p *persistence) checkNotPersistedLocked(after *ua.PubSubConfigurationDataType) ua.StatusCode {
	if after == nil {
		return ua.StatusOK
	}
	persisted := map[string]bool{}
	s := &staged{eps: p.eps}
	for _, cr := range p.comps {
		if !cr.Removed && s.active(cr) {
			persisted[componentPath(pubsub.ComponentKind(cr.Kind), cr.Path...)] = true
		}
	}
	if len(persisted) == 0 {
		return ua.StatusOK
	}
	for _, path := range notPersistedIn(after) {
		if persisted[path] {
			p.c.log.Warn("uafx: NotPersisted TRUE on a component of a persistent ConnectionEndpoint is refused", "component", path)
			return ua.StatusBadInvalidState
		}
	}
	return ua.StatusOK
}

// notPersistedIn returns the paths of the components of cfg with
// NotPersisted TRUE.
func notPersistedIn(cfg *ua.PubSubConfigurationDataType) []string {
	var out []string
	for _, conn := range cfg.Connections {
		if conn == nil {
			continue
		}
		if notPersisted(conn.ConnectionProperties) {
			out = append(out, componentPath(pubsub.KindConnection, conn.Name))
		}
		for _, g := range conn.WriterGroups {
			if g == nil {
				continue
			}
			if notPersisted(g.GroupProperties) {
				out = append(out, componentPath(pubsub.KindWriterGroup, conn.Name, g.Name))
			}
			for _, w := range g.DataSetWriters {
				if w != nil && notPersisted(w.DataSetWriterProperties) {
					out = append(out, componentPath(pubsub.KindDataSetWriter, conn.Name, g.Name, w.Name))
				}
			}
		}
		for _, g := range conn.ReaderGroups {
			if g == nil {
				continue
			}
			if notPersisted(g.GroupProperties) {
				out = append(out, componentPath(pubsub.KindReaderGroup, conn.Name, g.Name))
			}
			for _, r := range g.DataSetReaders {
				if r != nil && notPersisted(r.DataSetReaderProperties) {
					out = append(out, componentPath(pubsub.KindDataSetReader, conn.Name, g.Name, r.Name))
				}
			}
		}
	}
	return out
}

// notPersisted reports whether the configuration properties props have
// 0:NotPersisted TRUE (Part 14 §6.2.2 Table 4: absent is FALSE).
func notPersisted(props []*ua.KeyValuePair) bool {
	for _, kv := range props {
		if kv != nil && kv.Key != nil && kv.Key.NamespaceIndex == 0 && kv.Key.Name == "NotPersisted" {
			b, _ := val(kv.Value).(bool)
			return b
		}
	}
	return false
}

// safeDirection reports whether after only removes or disables components
// of before: every component of after is in before, the same but for an
// Enabled that went from TRUE to FALSE.
func safeDirection(before, after *ua.PubSubConfigurationDataType) bool {
	if after == nil {
		return true
	}
	if before == nil {
		return len(after.Connections) == 0 && len(after.PublishedDataSets) == 0
	}
	for _, a := range after.PublishedDataSets {
		if a == nil {
			continue
		}
		i := slices.IndexFunc(before.PublishedDataSets, func(b *ua.PublishedDataSetDataType) bool { return b != nil && b.Name == a.Name })
		if i < 0 || !reflect.DeepEqual(a, before.PublishedDataSets[i]) {
			return false
		}
	}
	for _, a := range after.Connections {
		if a == nil {
			continue
		}
		i := slices.IndexFunc(before.Connections, func(b *ua.PubSubConnectionDataType) bool { return b != nil && b.Name == a.Name })
		if i < 0 || !safeConnection(before.Connections[i], a) {
			return false
		}
	}
	return true
}

func safeConnection(b, a *ua.PubSubConnectionDataType) bool {
	bc, ac := *b, *a
	bc.WriterGroups, bc.ReaderGroups, ac.WriterGroups, ac.ReaderGroups = nil, nil, nil, nil
	if !offOnly(&bc.Enabled, &ac.Enabled) || !reflect.DeepEqual(bc, ac) {
		return false
	}
	for _, x := range a.WriterGroups {
		if x == nil {
			continue
		}
		i := slices.IndexFunc(b.WriterGroups, func(y *ua.WriterGroupDataType) bool { return y != nil && y.Name == x.Name })
		if i < 0 {
			return false
		}
		bg, ag := *b.WriterGroups[i], *x
		bg.DataSetWriters, ag.DataSetWriters = nil, nil
		if !offOnly(&bg.Enabled, &ag.Enabled) || !reflect.DeepEqual(bg, ag) {
			return false
		}
		for _, w := range x.DataSetWriters {
			if w == nil {
				continue
			}
			j := slices.IndexFunc(b.WriterGroups[i].DataSetWriters, func(y *ua.DataSetWriterDataType) bool { return y != nil && y.Name == w.Name })
			if j < 0 {
				return false
			}
			bw, aw := *b.WriterGroups[i].DataSetWriters[j], *w
			if !offOnly(&bw.Enabled, &aw.Enabled) || !reflect.DeepEqual(bw, aw) {
				return false
			}
		}
	}
	for _, x := range a.ReaderGroups {
		if x == nil {
			continue
		}
		i := slices.IndexFunc(b.ReaderGroups, func(y *ua.ReaderGroupDataType) bool { return y != nil && y.Name == x.Name })
		if i < 0 {
			return false
		}
		bg, ag := *b.ReaderGroups[i], *x
		bg.DataSetReaders, ag.DataSetReaders = nil, nil
		if !offOnly(&bg.Enabled, &ag.Enabled) || !reflect.DeepEqual(bg, ag) {
			return false
		}
		for _, r := range x.DataSetReaders {
			if r == nil {
				continue
			}
			j := slices.IndexFunc(b.ReaderGroups[i].DataSetReaders, func(y *ua.DataSetReaderDataType) bool { return y != nil && y.Name == r.Name })
			if j < 0 {
				return false
			}
			br, ar := *b.ReaderGroups[i].DataSetReaders[j], *r
			if !offOnly(&br.Enabled, &ar.Enabled) || !reflect.DeepEqual(br, ar) {
				return false
			}
		}
	}
	return true
}

// offOnly reports whether Enabled stayed or went from TRUE to FALSE, and
// then makes the two equal for the comparison of the rest.
func offOnly(before, after *bool) bool {
	if *after && !*before {
		return false
	}
	*after = *before
	return true
}
