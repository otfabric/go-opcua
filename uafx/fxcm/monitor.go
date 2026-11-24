// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// monitor reads the Status of the established endpoints every Interval
// (§10.20: ConnectionState from the ConnectionEndpoint Status; §6.7.3.2
// leaves supervision to the CM). Library interpretation: the monitor polls
// with Read; it does not subscribe.
func (m *Manager) monitor() {
	defer m.wg.Done()
	iv := m.opts.Monitor.Interval
	if iv <= 0 {
		iv = time.Second
	}
	tk := time.NewTicker(iv)
	defer tk.Stop()
	for {
		select {
		case <-m.monitorStop:
			return
		case <-tk.C:
			m.monitorOnce(m.ctx)
		}
	}
}

// monitorOnce reads the Status of every closable endpoint once.
func (m *Manager) monitorOnce(ctx context.Context) {
	m.mu.Lock()
	sets := make([]*set, 0, len(m.sets))
	for _, s := range m.sets {
		sets = append(sets, s)
	}
	m.mu.Unlock()
	for _, s := range sets {
		m.monitorSet(ctx, s)
	}
}

func (m *Manager) monitorSet(ctx context.Context, s *set) {
	s.mu.Lock()
	if s.current != nil || s.removed {
		s.mu.Unlock()
		return
	}
	var recs []*record
	for _, r := range s.records {
		if r.Class.MayClose() && r.NodeID != nil {
			recs = append(recs, r)
		}
	}
	s.mu.Unlock()
	gone := false
	for _, r := range recs {
		st, ok, err := m.readStatus(ctx, r)
		if err != nil {
			continue // not reachable: keep the last Status
		}
		cp := r.EndpointRecord
		s.mu.Lock()
		k := recordKey(r.addr, r.FunctionalEntity, r.Name)
		if s.records[k] != r {
			s.mu.Unlock()
			continue
		}
		if !ok {
			delete(s.records, k)
			gone = true
		} else {
			r.state, r.monitored = st, true
		}
		key := cp.Set
		s.mu.Unlock()
		ev := Event{Kind: EventMonitor, Set: key, Record: &cp, Status: ua.StatusGood}
		if !ok {
			ev.Status, ev.Err, ev.Closed = ua.StatusBadNodeIDUnknown, ua.StatusBadNodeIDUnknown, true
		}
		m.observe(ev)
	}
	if !gone {
		return
	}
	s.mu.Lock()
	var action *uafx.FxProcess
	if m.opts.Monitor.Reestablish && s.lastEstablish != nil && s.state != StateProcessing {
		a := *s.lastEstablish
		action = &a
	}
	key := SetKey{}
	if s.cfg != nil {
		key = s.cfg.Key()
	}
	s.mu.Unlock()
	if action != nil {
		m.start(key, *action, true)
	}
}

// readStatus reads the Status of the endpoint of r; ok is false when the
// endpoint no longer exists.
func (m *Manager) readStatus(ctx context.Context, r *record) (st uafx.ConnectionEndpointStatus, ok bool, err error) {
	cctx, cancel := context.WithTimeout(ctx, m.opts.CallTimeout)
	defer cancel()
	sess, err := m.pool.get(cctx, r.addr)
	if err != nil {
		return 0, false, err
	}
	t := &target{addr: r.addr, sess: sess, cache: m.res.of(r.addr)}
	if err := t.open(cctx); err != nil {
		m.pool.drop(cctx, r.addr, sess)
		return 0, false, err
	}
	acNS, err := t.acNamespace()
	if err != nil {
		return 0, false, err
	}
	refs, err := t.children(cctx, r.NodeID)
	if err != nil {
		if StatusOf(err) == ua.StatusBadNodeIDUnknown {
			return 0, false, nil
		}
		return 0, false, err
	}
	n := child(refs, acNS, "Status")
	if n == nil {
		return 0, false, nil
	}
	res, err := sess.Read(cctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: n, AttributeID: ua.AttributeIDValue}}})
	if err != nil {
		return 0, false, err
	}
	if len(res.Results) != 1 || res.Results[0] == nil {
		return 0, false, ua.StatusBadUnexpectedError
	}
	if res.Results[0].Status == ua.StatusBadNodeIDUnknown {
		return 0, false, nil
	}
	switch v := dvValue(res.Results[0]).(type) {
	case int32:
		return uafx.ConnectionEndpointStatus(v), true, nil
	case uafx.ConnectionEndpointStatus:
		return v, true, nil
	}
	return 0, false, ua.StatusBadTypeMismatch
}
