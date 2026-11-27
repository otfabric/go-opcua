// SPDX-License-Identifier: MIT

package fxcm

import (
	"bytes"
	"context"
	"slices"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// Keep-in-place adoption (design docs/design/uafx-persistent-connections.md
// §6.6, decision C3-D6). An establish run of a Manager with a Store keeps an
// endpoint its step 0 finds instead of closing and creating it again when
// all of these hold:
//   - its record is KnownOwned: made by this Manager, or proven by the
//     verification of §6.5 after a restart; never Unverified or Unresolved;
//   - the record has the generation and fingerprint of the configuration
//     the run processes (§6.1);
//   - its actual configuration is the one the run would create: the
//     parameter (Mode, InputVariables, OutputVariables, IsPersistent,
//     CleanupTimeout, RelatedEndpoint; §6.6.2 Table 73), the communication
//     links (a DataSetReader and DataSetWriter as its Mode needs, of the
//     configured Names), the ControlGroups it controls (Controls, §6.5.2).
//
// Library interpretation: adoption is all or nothing for the run. When an
// endpoint of the run is not adoptable, the run follows the rules of C2 for
// every endpoint (close first and create again), so that the PubSub
// configuration of every AutomationComponent is built and sent as one
// (§6.16.3) and the PublisherIds of the flows between them stay consistent.
// What the adopted endpoints get follows the action (§6.7.5.3): enabled
// (EnableCommunicationCmd, §6.2.4.3.10.2) for ActionEstablishConnectionsEnabled,
// disabled (CloseConnections with Remove FALSE, §6.2.5.2) for
// ActionEstablishConnectionsDisabled, and for ActionEstablishConnections the
// enablement its DataSetWriter or DataSetReader has in the configuration.
// An adopted endpoint belongs to the run: with RollbackOnError TRUE an abort
// closes it too (CR-4).

// adoptable reports whether the endpoint obs, found by step 0 under the
// Name of ep and recorded as rec, may be kept in place by the run.
func (x *run) adoptable(ctx context.Context, a *acRun, ep *epRun, rec *record, obs *Observed) bool {
	switch x.r.action {
	case uafx.ActionEstablishConnectionsEnabled, uafx.ActionEstablishConnectionsDisabled, uafx.ActionEstablishConnections:
	default:
		return false
	}
	if x.store() == nil || x.gen == 0 || ep.param == nil {
		return false
	}
	x.s.mu.Lock()
	ok := rec.Class == KnownOwned && rec.gen == x.gen && bytes.Equal(rec.fp, x.fp) && rec.NodeID.Equal(obs.NodeID)
	x.s.mu.Unlock()
	if !ok {
		return false
	}
	act, err := readActual(ctx, a.t, obs.NodeID)
	if err != nil {
		x.m.log.Debug("fxcm: an endpoint was not adopted: its configuration was not read", "set", x.r.key.String(), "run", x.r.id, "endpoint", ep.e.conf.Name, "error", err)
		return false
	}
	why := ""
	switch {
	case !sameParam(act.param, paramOf(ep.param, a.t.nsa)):
		why = "its parameter is not the configured one"
	case !x.sameLinks(ep, act):
		why = "its DataSetReader or DataSetWriter is not the configured one"
	case !sameNodes(act.controls, ep.controls):
		why = "it does not control the configured ControlGroups"
	}
	if why == "" && a.adoptCfg == nil {
		// The configuration of the set on this server: its NodeIds
		// mapped as the run would send them (prepareComm).
		cm, err := x.prepareComm(ctx, a)
		if err != nil {
			x.m.log.Debug("fxcm: an endpoint was not adopted: its configuration does not map to the server", "set", x.r.key.String(), "run", x.r.id, "endpoint", ep.e.conf.Name, "error", err)
			return false
		}
		if cm != nil {
			a.adoptCfg = cm.cfg
		}
	}
	if why == "" {
		c, err := readComm(ctx, a.t, act)
		if err != nil {
			x.m.log.Debug("fxcm: an endpoint was not adopted: its communication configuration was not read", "set", x.r.key.String(), "run", x.r.id, "endpoint", ep.e.conf.Name, "error", err)
			return false
		}
		if ok, what := sameComm(a.adoptCfg, ep, c); !ok {
			why = what + " is not the configured one"
		}
		ep.comm = c
	}
	if why != "" {
		x.m.log.Debug("fxcm: an endpoint was not adopted", "set", x.r.key.String(), "run", x.r.id, "endpoint", ep.e.conf.Name, "why", why)
		return false
	}
	return true
}

// sameLinks reports whether the DataSetReader and DataSetWriter of the
// endpoint act are the ones ep needs: one of each its Mode subscribes or
// publishes with, none it does not, and of the Names the configuration of
// the set gives them.
func (x *run) sameLinks(ep *epRun, act *actual) bool {
	mode := ep.param.Mode
	if mode.Subscribes() != (act.reader != nil) || mode.Publishes() != (act.writer != nil) {
		return false
	}
	cfg, l := pubsubOf(ep.e)
	if cfg == nil || l == nil {
		return true
	}
	if _, _, w := writerAt(cfg, l.DataSetWriterRef); w != nil && w.Name != "" && act.writer != nil && w.Name != act.writerName {
		return false
	}
	if r := readerAt(cfg, l.DataSetReaderRef); r != nil && r.Name != "" && act.reader != nil && r.Name != act.readerName {
		return false
	}
	return true
}

// sameNodes reports whether a and b hold the same NodeIds, in any order.
func sameNodes(a, b []*ua.NodeID) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]int{}
	for _, n := range a {
		set[n.String()]++
	}
	for _, n := range b {
		set[n.String()]--
	}
	for _, c := range set {
		if c != 0 {
			return false
		}
	}
	return true
}

// configuredEnabled reports whether the configuration of the set enables
// the DataSetWriter or DataSetReader of ep (ActionEstablishConnections
// applies the configuration as it is, §6.7.5.3.1).
func configuredEnabled(ep *epRun) bool {
	cfg, l := pubsubOf(ep.e)
	if cfg == nil || l == nil {
		return true
	}
	if _, _, w := writerAt(cfg, l.DataSetWriterRef); w != nil && !w.Enabled {
		return false
	}
	if r := readerAt(cfg, l.DataSetReaderRef); r != nil && !r.Enabled {
		return false
	}
	return true
}

// adopt decides, after step 0, whether the run keeps the endpoints it
// found adoptable: when every endpoint of the run is adoptable, they are
// kept in place (keepInPlace) and it returns true: the run makes no further
// step. When step 0 failed an endpoint, the run stops there and the
// adoptable ones are left as they are, neither adopted nor closed: closing
// them would interrupt Connections the run cannot make again. Otherwise the
// adoptable ones are closed first, as step 0 closes a KnownOwned survivor
// (design §5.2), and the run goes on.
func (x *run) adopt(ctx context.Context) bool {
	var adopted, rest []*epRun
	for _, ep := range x.eps {
		switch {
		case ep.adopt != nil:
			adopted = append(adopted, ep)
		default:
			rest = append(rest, ep)
		}
	}
	if len(adopted) == 0 {
		return false
	}
	// The identifiers allocated across the flows (adopt_comm.go): a
	// subscriber that fails them is not adoptable, so neither is the run;
	// it is closed first like the other adoptable ones.
	rejected := x.adoptFlows()
	if x.anyFailed() {
		for _, ep := range adopted {
			ep.adopt = nil
		}
		return false
	}
	if len(rest) == 0 && !rejected {
		x.keepInPlace(ctx, adopted)
		return true
	}
	var recs []*record
	for _, ep := range adopted {
		recs = append(recs, ep.adopt)
	}
	errs := x.closeRecords(ctx, recs, true)
	for _, ep := range adopted {
		rec := ep.adopt
		ep.adopt = nil
		if err := errs[rec]; err != nil {
			x.failErr(ep, err, uafx.FxErrorCloseConnectionError)
			continue
		}
		ep.obs = nil // absent before the create of this run
	}
	return false
}

// keepInPlace keeps the endpoints eps: their records become the run's, and
// their enablement follows the action of the run.
func (x *run) keepInPlace(ctx context.Context, eps []*epRun) {
	var enable, disable []*record
	for _, ep := range eps {
		rec := ep.adopt
		x.s.mu.Lock()
		rec.Run, rec.Version = x.r.id, x.r.version
		cp := rec.EndpointRecord
		x.s.mu.Unlock()
		x.touchAC(ep.a, recordKey(ep.a.addr, ep.fe, ep.e.conf.Name), rec)
		x.mu.Lock()
		x.res.Adopted = append(x.res.Adopted, cp)
		x.mu.Unlock()
		x.m.observe(Event{Kind: EventEndpoint, Set: x.r.key, Run: x.r.id, Record: &cp})
		on := x.r.action == uafx.ActionEstablishConnectionsEnabled || x.r.action == uafx.ActionEstablishConnections && configuredEnabled(ep)
		if on {
			enable = append(enable, rec)
		} else {
			disable = append(disable, rec)
		}
	}
	x.m.log.Info("fxcm: endpoints kept in place", "set", x.r.key.String(), "run", x.r.id, "adopted", len(eps))
	x.crashPoint("adopt.before-enablement")
	if len(enable) > 0 {
		x.enableRecords(ctx, enable)
	}
	if len(disable) > 0 {
		errs := x.closeRecords(ctx, disable, false)
		for _, r := range disable {
			if err := errs[r]; err != nil {
				if ep := x.epOf(r.Endpoint); ep != nil {
					x.failErr(ep, err, uafx.FxErrorCloseConnectionError)
				}
			}
		}
	}
	if x.anyFailed() {
		x.stop(ctx)
	}
}

// enableRecords sends EnableCommunicationCmd for recs, one call per
// AutomationComponent (enableOn).
func (x *run) enableRecords(ctx context.Context, recs []*record) {
	type group struct {
		addr ServerAddress
		ac   *ua.NodeID
		recs []*record
	}
	var groups []*group
	for _, r := range recs {
		i := slices.IndexFunc(groups, func(g *group) bool { return g.addr == r.addr && g.ac.Equal(r.acNode) })
		if i < 0 {
			groups = append(groups, &group{addr: r.addr, ac: r.acNode})
			i = len(groups) - 1
		}
		groups[i].recs = append(groups[i].recs, r)
	}
	for _, g := range groups {
		x.enableOn(ctx, g.addr, g.ac, g.recs)
	}
}
