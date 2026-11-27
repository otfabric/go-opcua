// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// run is the work of one Run.
type run struct {
	m   *Manager
	s   *set
	r   *Run
	cfg *Config
	// gen and fp are the generation and fingerprint of cfg, the committed
	// configuration the run processes, as the run started (design §6.1):
	// the evidence of its intents and records, whatever is committed
	// meanwhile.
	gen uint64
	fp  []byte

	acs []*acRun
	eps []*epRun
	// blocked are the server addresses on which an intent of the set is
	// unresolved (recover): no call of the run is sent there.
	blocked map[string]bool

	mu      sync.Mutex
	stopped bool
	res     RunResult
	// j is the journal of the run, with a Store (journal.go).
	j journal
}

// acRun is an AutomationComponent of a run.
type acRun struct {
	ac   *automationComponent
	addr ServerAddress
	t    *target
	eps  []*epRun

	node      *ua.NodeID // the AutomationComponent
	establish *ua.NodeID // its Methods
	close     *ua.NodeID
	data      uint16 // the UAFX Data namespace
	// maxPerCall and bundle are the capabilities of §6.2.6, bundle also
	// CommandBundleRequired of the set (§6.14, decision D13).
	maxPerCall uint32
	bundle     bool
	assets     []*uafx.AssetVerification
	comm       *commModel
	// defaultPublisherID is the DefaultPublisherId of the reservation.
	defaultPublisherID *ua.Variant
	// adoptCfg is the PubSub configuration of the set mapped to the
	// server, for the adoption of its endpoints (adopt_comm.go); set by
	// the scan of a.
	adoptCfg *ua.PubSubConfiguration2DataType
	// values are the ConfigurationValues the calls returned (§6.16.3).
	values []*ua.PubSubConfigurationValueDataType
	// configured is set when the configure step of the AC returned, so
	// its PubSubConnections have their PublisherIds (resolvePublishers).
	configured bool
	// intents are the keys of the intents of the calls on the AC whose
	// results the step has not synced yet, lastIntent that of the last
	// call, touched the records the step changed (journal.go).
	intents    []string
	lastIntent string
	touched    touched
}

// takeIntents returns the intents and the touched records of a and forgets
// them.
func (a *acRun) takeIntents() ([]string, touched) {
	ks, t := a.intents, a.touched
	a.intents, a.touched = nil, touched{}
	return ks, t
}

// syncStep completes the intents of the step of a (journal.go).
func (x *run) syncStep(a *acRun) {
	ks, t := a.takeIntents()
	x.sync(ks, t, false)
}

// epRun is an endpoint configuration of a run.
type epRun struct {
	x *run
	e *endpoint
	a *acRun

	fe       *ua.NodeID
	inputs   []*ua.NodeID
	outputs  []*ua.NodeID
	controls []*ua.NodeID
	verify   []*uafx.NodeIDValuePair
	config   []*uafx.NodeIDValuePair
	links    *uafx.PubSubCommunicationLinkConfiguration
	param    *uafx.PubSubConnectionEndpointParameter

	// obs is what step 0 found under the Name, nil for nothing.
	obs              *Observed
	assumedPublisher *assumed

	outcome *Outcome
	// sent is the SHA-256 of the ConnectionEndpointConfiguration the run
	// sent for the endpoint (design §6.1), with a Store.
	sent []byte
	// adopt is the record of the endpoint step 0 found adoptable (adopt.go),
	// comm its communication configuration as read (adopt_comm.go).
	adopt *record
	comm  *commActual
}

func (ep *epRun) ref() EndpointRef { return EndpointRef{ep.e.conn.name, ep.e.number} }

func (ep *epRun) failed() bool {
	ep.x.mu.Lock()
	defer ep.x.mu.Unlock()
	return ep.outcome != nil && ep.outcome.Kind == Failed
}

// fail sets the outcome of ep to a failure, unless it failed already.
func (x *run) fail(ep *epRun, f Failure) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if ep.outcome != nil && ep.outcome.Kind == Failed {
		return
	}
	o := FailedWith(f.FxError, f.Status)
	ep.outcome = &o
}

func (x *run) failErr(ep *epRun, err error, fx uafx.FxError) {
	x.m.log.Warn("fxcm: operation failed", "set", x.r.key.String(), "run", x.r.id, "connection", ep.e.conn.name, "endpoint", ep.e.number, "error", err)
	x.fail(ep, failureOf(err, fx))
}

func (x *run) setOutcome(ep *epRun, k OutcomeKind) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if ep.outcome != nil && ep.outcome.Kind == Failed {
		return
	}
	ep.outcome = &Outcome{Kind: k}
}

// remoteEffectLocked reports whether the run changed a server, or may
// have: a close succeeded, a call's outcome is unknown (its intent is
// retained), or a failure has an ambiguous status (decision C3-D13). The
// caller holds x.mu.
func (x *run) remoteEffectLocked() bool {
	if len(x.res.Closed) > 0 || len(x.j.retained) > 0 {
		return true
	}
	for _, f := range x.res.Failures {
		if ambiguousStatus(f.Status) {
			return true
		}
	}
	for _, ep := range x.eps {
		if ep.outcome != nil && ep.outcome.Kind == Failed && ambiguousStatus(ep.outcome.Status) {
			return true
		}
	}
	return false
}

func (x *run) anyFailed() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, ep := range x.eps {
		if ep.outcome != nil && ep.outcome.Kind == Failed {
			return true
		}
	}
	return false
}

// execute runs r on s, which the caller put in Processing from prev, and
// takes the transition at its end.
func (m *Manager) execute(ctx context.Context, s *set, r *Run, prev State) *RunResult {
	s.mu.Lock()
	cfg, gen, fp := s.cfg, s.gen, s.fp
	s.mu.Unlock()
	x := &run{m: m, s: s, r: r, cfg: cfg, gen: gen, fp: fp}
	for _, cn := range cfg.conns {
		for _, e := range cn.endpoints {
			x.eps = append(x.eps, &epRun{x: x, e: e})
		}
	}
	// EC-12: the AuditEntryId of the calls of the run.
	ctx = opcua.WithAuditEntryID(ctx, fmt.Sprintf("fxcm:%s:run:%d", r.key, r.id))
	x.j.tx = r.tx
	if err := x.startJournal(); err != nil {
		// No run record, no call (design §6.3).
		x.extraFailure(failureOf(err, uafx.FxErrorRuntimeError))
		return x.finish()
	}
	// The owed work of the set first (recover.go): unless it is done, the
	// action does not run.
	ok := x.recover(ctx)
	switch {
	case !ok:
	case r.action == uafx.ActionEstablishConnectionsEnabled, r.action == uafx.ActionEstablishConnectionsDisabled, r.action == uafx.ActionEstablishConnections:
		if x.failBlocked() {
			// Its Connections on a blocked server fail, which stops the
			// run before any call (EC-10), with the rollback of C2.
			x.stop(ctx)
			break
		}
		x.establishRun(ctx)
	case r.action == uafx.ActionRemoveConnections, r.action == ActionRemoveSet:
		x.closeRun(ctx, true)
	case r.action == uafx.ActionDisableConnections:
		x.closeRun(ctx, false)
	case r.action == uafx.ActionEnableConnections:
		x.enableRun(ctx)
	case r.action == ActionReconcile:
		x.reconcileRun(ctx, prev)
		x.completeSetChange()
	}
	if p := x.store(); p != nil {
		if owed := p.owedOfSet(x.r.key); len(owed) > 0 {
			// The run leaves owed work: the set stays in Error, as it
			// starts after a restart (design §6.4).
			x.m.log.Warn("fxcm: the set still owes work", "set", x.r.key.String(), "run", x.r.id, "kind", owed[0].Kind.String(), "of", owed[0].Run)
			x.extraFailure(Failure{FxError: uafx.FxErrorRuntimeError, Status: ua.StatusBadInvalidState})
		}
	}
	return x.finish()
}

// parallel runs f for each AutomationComponent of the run, at most
// Parallelism at a time (§6.7.3.2: calls to several ACs in parallel).
func (x *run) parallel(ctx context.Context, acs []*acRun, f func(context.Context, *acRun)) {
	sem := make(chan struct{}, x.m.opts.Parallelism)
	var wg sync.WaitGroup
	for _, a := range acs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				x.failAC(a, failure(uafx.FxErrorProcessingStopped, ua.StatusBadTimeout, "%v", ctx.Err()))
				return
			}
			defer func() { <-sem }()
			f(ctx, a)
		}()
	}
	wg.Wait()
}

// live returns the AutomationComponents of the run with an endpoint that
// did not fail.
func (x *run) live() []*acRun {
	var out []*acRun
	for _, a := range x.acs {
		if slices.ContainsFunc(a.eps, func(ep *epRun) bool { return !ep.failed() }) {
			out = append(out, a)
		}
	}
	return out
}

func (x *run) failAC(a *acRun, err error) {
	for _, ep := range a.eps {
		x.failErr(ep, err, uafx.FxErrorTargetServerConnectionError)
	}
}

// --- establish ------------------------------------------------------------

// establishRun establishes the Connections of the set (§6.7.3.2, design
// §5.2): connect and resolve, scan and reconcile (step 0), reserve,
// configure; on a failure no new step starts and, with RollbackOnError,
// every closable endpoint of the set is closed (§6.8.2, F.1.3).
func (x *run) establishRun(ctx context.Context) {
	byAC := map[*automationComponent]*acRun{}
	for _, ep := range x.eps {
		a := byAC[ep.e.ac]
		if a == nil {
			a = &acRun{ac: ep.e.ac, addr: x.cfg.serverAddress(ep.e.ac.server), bundle: ep.e.ac.conf.CommandBundleRequired}
			byAC[ep.e.ac] = a
			x.acs = append(x.acs, a)
		}
		a.eps = append(a.eps, ep)
		ep.a = a
	}
	if x.step(ctx, x.acs, x.setup) {
		return
	}
	x.checkNames()
	if x.anyFailed() {
		x.stop(ctx)
		return
	}
	var places []string
	for _, ep := range x.eps {
		places = append(places, ep.a.addr.Address+"\x00"+ep.fe.String())
	}
	release, err := x.m.places.lock(ctx, places)
	defer release()
	if err != nil {
		for _, ep := range x.eps {
			x.failErr(ep, err, uafx.FxErrorProcessingStopped)
		}
		x.stop(ctx)
		return
	}
	if x.step(ctx, x.live(), x.scan) {
		return
	}
	if x.adopt(ctx) {
		return
	}
	if x.anyFailed() {
		x.stop(ctx)
		return
	}
	for _, f := range []func(context.Context, *acRun){x.prepare, x.reserve} {
		if x.step(ctx, x.live(), f) {
			return
		}
	}
	x.linkFlows()
	for _, wave := range x.configureWaves(x.live()) {
		x.resolvePublishers(wave)
		if x.step(ctx, wave, x.configure) {
			return
		}
	}
	x.adaptSubscribers(ctx)
	if x.anyFailed() {
		x.stop(ctx)
	}
}

// step runs f on acs and reports whether the run stopped after it.
func (x *run) step(ctx context.Context, acs []*acRun, f func(context.Context, *acRun)) bool {
	x.parallel(ctx, acs, f)
	if x.anyFailed() {
		x.stop(ctx)
		return true
	}
	return false
}

// stop ends a failed establish run: no new step starts (EC-10); with
// RollbackOnError the endpoints of the set are closed (EC-11).
func (x *run) stop(ctx context.Context) {
	x.mu.Lock()
	x.stopped = true
	x.mu.Unlock()
	if x.cfg.RollbackOnError() {
		x.rollback(ctx)
	}
}

// openTarget opens a target on the session the pool holds for addr and
// reads its NamespaceArray. When that session was dialed by an earlier run
// and the read fails, its server may have restarted while it was idle: the
// read, before any call, is made once more on a new session (design §5.1;
// a read changes nothing, Part 4 §5.11.2). A failure is a
// TargetServerConnectionError, or the failure of the read.
func (x *run) openTarget(ctx context.Context, addr ServerAddress) (*target, error) {
	sess, reused, err := x.m.pool.reuse(ctx, addr)
	if err != nil {
		return nil, failure(uafx.FxErrorTargetServerConnectionError, failureOf(err, uafx.FxErrorTargetServerConnectionError).Status, "%v", err)
	}
	t := &target{addr: addr, sess: sess, cache: x.m.res.of(addr)}
	err = t.open(ctx)
	if err != nil && reused {
		x.m.pool.drop(ctx, addr, sess)
		if sess, err = x.m.pool.get(ctx, addr); err != nil {
			return nil, failure(uafx.FxErrorTargetServerConnectionError, failureOf(err, uafx.FxErrorTargetServerConnectionError).Status, "%v", err)
		}
		t = &target{addr: addr, sess: sess, cache: x.m.res.of(addr)}
		err = t.open(ctx)
	}
	if err != nil {
		x.m.pool.drop(ctx, addr, sess)
		return nil, err
	}
	return t, nil
}

// setup opens the session of a, resolves the AutomationComponent, its
// Methods and capabilities, and the identifiers of its endpoints (step 1).
func (x *run) setup(ctx context.Context, a *acRun) {
	t, err := x.openTarget(ctx, a.addr)
	if err != nil {
		x.failAC(a, err)
		return
	}
	a.t = t
	x.identify(ctx, a.t)
	root, err := a.t.fxRoot()
	if err != nil {
		x.failAC(a, err)
		return
	}
	scope := a.ac.server.ns
	if a.node, err = a.t.resolve(ctx, a.ac.conf.AutomationComponentNode, scope, root); err != nil {
		x.failAC(a, err)
		return
	}
	if err := x.methods(ctx, a); err != nil {
		x.failAC(a, err)
		return
	}
	x.capabilities(ctx, a)
	for _, av := range a.ac.conf.AssetVerification {
		v, err := x.asset(ctx, a, av)
		if err != nil {
			x.failAC(a, err)
			return
		}
		a.assets = append(a.assets, v)
	}
	for _, ep := range a.eps {
		if err := x.resolveEndpoint(ctx, ep, root); err != nil {
			x.failErr(ep, err, uafx.FxErrorResolvingPathsError)
		}
	}
}

// methods finds EstablishConnections and CloseConnections of a.
func (x *run) methods(ctx context.Context, a *acRun) error {
	var err error
	a.establish, a.close, a.data, err = methodsOf(ctx, a.t, a.node)
	return err
}

func methodsOf(ctx context.Context, t *target, ac *ua.NodeID) (establish, closeM *ua.NodeID, data uint16, err error) {
	acNS, err := t.acNamespace()
	if err != nil {
		return nil, nil, 0, err
	}
	d, ok := t.ns(fxdataid.NamespaceURI)
	if !ok {
		return nil, nil, 0, failure(uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch, "%s has no UAFX Data namespace", t.addr.Address)
	}
	res, err := t.sess.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: ac, BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent), IncludeSubtypes: true,
		NodeClassMask: uint32(ua.NodeClassMethod), ResultMask: uint32(ua.BrowseResultMaskAll),
	}}})
	if err != nil {
		f := failureOf(err, uafx.FxErrorTargetServerConnectionError)
		return nil, nil, 0, failure(f.FxError, f.Status, "Browse of %v: %v", ac, err)
	}
	if len(res.Results) != 1 || res.Results[0] == nil || res.Results[0].StatusCode != ua.StatusOK {
		return nil, nil, 0, failure(uafx.FxErrorResolvingPathsError, ua.StatusBadNodeIDUnknown, "the AutomationComponent %v cannot be browsed", ac)
	}
	establish = child(res.Results[0].References, acNS, "EstablishConnections")
	closeM = child(res.Results[0].References, acNS, "CloseConnections")
	if establish == nil || closeM == nil {
		return nil, nil, 0, failure(uafx.FxErrorResolvingPathsError, ua.StatusBadMethodInvalid, "%v is not an AutomationComponent with EstablishConnections and CloseConnections", ac)
	}
	return establish, closeM, d, nil
}

// capabilities reads MaxConnectionsPerCall and CommandBundleRequired of a
// (§6.2.6). A capability that cannot be read is absent.
func (x *run) capabilities(ctx context.Context, a *acRun) {
	acNS, _ := a.t.acNamespace()
	refs, err := a.t.children(ctx, a.node)
	if err != nil {
		return
	}
	capsNode := child(refs, acNS, "ComponentCapabilities")
	if capsNode == nil {
		return
	}
	caps, err := a.t.children(ctx, capsNode)
	if err != nil {
		return
	}
	max, bundle := child(caps, acNS, "MaxConnectionsPerCall"), child(caps, acNS, "CommandBundleRequired")
	var nodes []*ua.ReadValueID
	for _, n := range []*ua.NodeID{max, bundle} {
		if n == nil {
			n = ua.NewNumericNodeID(0, 0)
		}
		nodes = append(nodes, &ua.ReadValueID{NodeID: n, AttributeID: ua.AttributeIDValue})
	}
	res, err := a.t.sess.Read(ctx, &ua.ReadRequest{NodesToRead: nodes, TimestampsToReturn: ua.TimestampsToReturnNeither})
	if err != nil || len(res.Results) != 2 {
		return
	}
	if v, ok := dvValue(res.Results[0]).(uint32); ok {
		a.maxPerCall = v
	}
	if v, ok := dvValue(res.Results[1]).(bool); ok && v {
		a.bundle = true
	}
}

// asset returns the AssetVerification of av (Table 79): AssetToVerify from
// the AutomationComponent, ExpectedVerificationVariables as BrowseNames of
// Variables of the Asset (§6.15, §10.4: KeyValuePairs whose Key is the
// BrowseName), the additional ones as NodeIds from the Asset.
func (x *run) asset(ctx context.Context, a *acRun, av *uafx.AssetVerificationConf) (*uafx.AssetVerification, error) {
	scope := a.ac.server.ns
	n, err := a.t.resolve(ctx, av.AssetToVerify, scope, a.node)
	if err != nil {
		return nil, err
	}
	out := &uafx.AssetVerification{AssetToVerify: n, VerificationMode: av.VerificationMode, ExpectedVerificationResult: av.ExpectedVerificationResult}
	for _, p := range av.ExpectedVerificationVariables {
		qn, err := x.browseName(ctx, a, p.Key, n)
		if err != nil {
			return nil, err
		}
		out.ExpectedVerificationVariables = append(out.ExpectedVerificationVariables, &ua.KeyValuePair{Key: qn, Value: p.Value})
	}
	pairs, err := x.pairs(ctx, a, av.ExpectedAdditionalVerificationVariables, n)
	if err != nil {
		return nil, err
	}
	out.ExpectedAdditionalVerificationVariables = pairs
	return out, nil
}

// browseName returns the BrowseName of the Variable key names: the
// TargetName of a one-element RelativePath, else the BrowseName of the
// resolved node.
func (x *run) browseName(ctx context.Context, a *acRun, key *uafx.NodeIdentifier, start *ua.NodeID) (*ua.QualifiedName, error) {
	if key != nil && key.IdentifierBrowsePath != nil && len(key.IdentifierBrowsePath.Elements) == 1 {
		tn := key.IdentifierBrowsePath.Elements[0].TargetName
		uri, ok := a.ac.server.ns.uri(tn.NamespaceIndex)
		if !ok {
			return nil, failure(uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch, "the namespace index %d is not in the Namespaces of the ServerAddress", tn.NamespaceIndex)
		}
		return a.t.qualifiedName(uri, tn.Name)
	}
	n, err := a.t.resolve(ctx, key, a.ac.server.ns, start)
	if err != nil {
		return nil, err
	}
	res, err := a.t.sess.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: n, AttributeID: ua.AttributeIDBrowseName}}})
	if err != nil {
		f := failureOf(err, uafx.FxErrorResolvingPathsError)
		return nil, failure(f.FxError, f.Status, "the BrowseName of %v: %v", n, err)
	}
	if len(res.Results) == 1 {
		if qn, ok := dvValue(res.Results[0]).(*ua.QualifiedName); ok {
			return qn, nil
		}
	}
	return nil, failure(uafx.FxErrorResolvingPathsError, ua.StatusBadNodeIDUnknown, "no BrowseName of %v", n)
}

func (x *run) pairs(ctx context.Context, a *acRun, ps []*uafx.NodeIdentifierValuePair, start *ua.NodeID) ([]*uafx.NodeIDValuePair, error) {
	var out []*uafx.NodeIDValuePair
	for _, p := range ps {
		n, err := a.t.resolve(ctx, p.Key, a.ac.server.ns, start)
		if err != nil {
			return nil, err
		}
		out = append(out, &uafx.NodeIDValuePair{Key: &uafx.NodeIDArray{Node: n, ArrayIndex: p.ArrayIndex}, Value: p.Value})
	}
	return out, nil
}

func (x *run) nodes(ctx context.Context, a *acRun, ids []*uafx.NodeIdentifier, start *ua.NodeID) ([]*ua.NodeID, error) {
	var out []*ua.NodeID
	for _, i := range ids {
		n, err := a.t.resolve(ctx, i, a.ac.server.ns, start)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// resolveEndpoint resolves the identifiers of an endpoint configuration
// (EC-8): FunctionalEntityNode from FxRoot (§6.11), the variables,
// ControlGroups and the keys of ExpectedVerificationVariables and
// ConfigurationData from the FunctionalEntity (§6.12).
func (x *run) resolveEndpoint(ctx context.Context, ep *epRun, root *ua.NodeID) error {
	a, conf := ep.a, ep.e.conf
	var err error
	if ep.fe, err = a.t.resolve(ctx, conf.FunctionalEntityNode, a.ac.server.ns, root); err != nil {
		return err
	}
	if ep.inputs, err = x.nodes(ctx, a, conf.InputVariableIDs, ep.fe); err != nil {
		return err
	}
	if ep.outputs, err = x.nodes(ctx, a, conf.OutputVariableIDs, ep.fe); err != nil {
		return err
	}
	if ep.controls, err = x.nodes(ctx, a, conf.ControlGroups, ep.fe); err != nil {
		return err
	}
	if ep.verify, err = x.pairs(ctx, a, conf.ExpectedVerificationVariables, ep.fe); err != nil {
		return err
	}
	if ep.config, err = x.pairs(ctx, a, conf.ConfigurationData, ep.fe); err != nil {
		return err
	}
	if ep.links, err = links(conf.CommunicationLinks); err != nil {
		return err
	}
	ep.param, err = ep.parameter()
	return err
}

// checkNames fails the endpoints that would be created under the same Name
// in the same resolved FunctionalEntity (§6.12).
func (x *run) checkNames() {
	seen := map[string]*epRun{}
	for _, ep := range x.eps {
		if ep.failed() || ep.fe == nil {
			continue
		}
		k := recordKey(ep.a.addr, ep.fe, ep.e.conf.Name)
		if o := seen[k]; o != nil {
			f := Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadBrowseNameDuplicated}
			x.fail(ep, f)
			x.fail(o, f)
			continue
		}
		seen[k] = ep
	}
}

// --- step 0: scan and reconcile ------------------------------------------

// observeName returns the endpoints under name in the ConnectionEndpoints
// Folder of fe (§6.4.2), with what classifies them (§6.6.2).
func observeName(ctx context.Context, t *target, fe *ua.NodeID, name string, ours *uafx.RelatedEndpoint) ([]Observed, error) {
	acNS, err := t.acNamespace()
	if err != nil {
		return nil, err
	}
	refs, err := t.children(ctx, fe)
	if err != nil {
		return nil, err
	}
	folder := child(refs, acNS, "ConnectionEndpoints")
	if folder == nil {
		return nil, nil
	}
	eps, err := t.children(ctx, folder)
	if err != nil {
		return nil, err
	}
	var out []Observed
	for _, r := range eps {
		if r == nil || r.BrowseName == nil || r.BrowseName.Name != name || r.NodeID == nil || r.NodeID.NodeID == nil || r.NodeClass != ua.NodeClassObject {
			continue
		}
		o, err := observeEndpoint(ctx, t, r.NodeID.NodeID, acNS, ours)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// observeEndpoint reads ConnectionManagerApplicationUri, IsPreconfigured
// and RelatedEndpoint of the endpoint n. Library interpretation: an
// endpoint without IsPreconfigured is preconfigured when it has no
// ConnectionManagerApplicationUri, which EstablishConnections sets for the
// endpoints it creates (§6.6.2); it is in use when its RelatedEndpoint
// names another end than ours (Table 12).
func observeEndpoint(ctx context.Context, t *target, n *ua.NodeID, acNS uint16, ours *uafx.RelatedEndpoint) (Observed, error) {
	o := Observed{NodeID: n}
	props, err := t.children(ctx, n)
	if err != nil {
		return o, err
	}
	names := []string{"ConnectionManagerApplicationUri", "IsPreconfigured", "RelatedEndpoint"}
	read := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for _, nm := range names {
		c := child(props, acNS, nm)
		if c == nil {
			c = ua.NewNumericNodeID(0, 0)
		}
		read.NodesToRead = append(read.NodesToRead, &ua.ReadValueID{NodeID: c, AttributeID: ua.AttributeIDValue})
	}
	res, err := t.sess.Read(ctx, read)
	if err != nil {
		return o, err
	}
	if len(res.Results) != len(names) {
		return o, fmt.Errorf("fxcm: Read: %d results", len(res.Results))
	}
	if s, ok := dvValue(res.Results[0]).(string); ok && s != "" {
		o.CMApplicationURI = &s
	}
	if b, ok := dvValue(res.Results[1]).(bool); ok {
		o.IsPreconfigured = b
	} else {
		o.IsPreconfigured = o.CMApplicationURI == nil
	}
	if eo := dvStructure(res.Results[2]); eo != nil {
		rel := relatedOf(t, eo)
		o.InUse = rel != nil && !nullRelated(rel) && !sameRelated(rel, ours)
	}
	return o, nil
}

// relatedOf decodes the RelatedEndpoint value eo read from t, a structure
// of the AC namespace (§10.42) whose encoding NodeId has the namespace
// index of t.
func relatedOf(t *target, eo *ua.ExtensionObject) *uafx.RelatedEndpoint {
	if eo == nil {
		return nil
	}
	if r, ok := eo.Value.(*uafx.RelatedEndpoint); ok {
		return r
	}
	ns := uafx.NamespaceIndexes{}
	ns.Data, _ = t.ns(fxdataid.NamespaceURI)
	ns.AC, _ = t.ns(fxacid.NamespaceURI)
	s, err := uafx.DecodeStructure(eo, ns)
	if err != nil {
		return nil
	}
	r, _ := s.(*uafx.RelatedEndpoint)
	return r
}

func nullRelated(r *uafx.RelatedEndpoint) bool {
	return r.Address == "" && r.ConnectionEndpointName == "" && len(r.ConnectionEndpointPath) == 0
}

func sameRelated(a, b *uafx.RelatedEndpoint) bool {
	if a == nil || b == nil {
		return false
	}
	x, err1 := ua.Encode(a)
	y, err2 := ua.Encode(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// scan is step 0 (design §5.2): classify what exists under each Name;
// close known-owned survivors; fail a Connection whose Name is taken.
func (x *run) scan(ctx context.Context, a *acRun) {
	var closeFirst []*record
	var closeEps []*epRun
	for _, ep := range a.eps {
		if ep.failed() {
			continue
		}
		found, err := observeName(ctx, a.t, ep.fe, ep.e.conf.Name, ep.param.RelatedEndpoint)
		if err != nil {
			x.failErr(ep, err, uafx.FxErrorResolvingPathsError)
			continue
		}
		k := recordKey(a.addr, ep.fe, ep.e.conf.Name)
		x.s.mu.Lock()
		rec := x.s.records[k]
		var recCopy *EndpointRecord
		if rec != nil {
			c := rec.EndpointRecord
			recCopy = &c
		}
		x.s.mu.Unlock()
		if recCopy != nil && (recCopy.Class == Unverified || recCopy.Class == Unresolved && x.heldName(a.addr, recCopy.Name)) {
			// A record loaded at the start and not verified since, or
			// the Name of a call whose outcome is unknown, holds the
			// Name: the Connection fails, the record stays as it is
			// (design §6.3, §6.4: never closed, adopted, changed or
			// forgotten, and absence proves nothing).
			x.mu.Lock()
			x.res.Unresolved = append(x.res.Unresolved, *recCopy)
			x.mu.Unlock()
			x.fail(ep, Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadInvalidState})
			continue
		}
		if len(found) > 1 {
			x.fail(ep, Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadBrowseNameDuplicated})
			continue
		}
		var obs *Observed
		if len(found) == 1 {
			obs = &found[0]
		}
		if obs == nil && rec != nil {
			// The endpoint is gone (cleanup, a restarted AC): forget it.
			x.forget(a, k)
		}
		class, verdict := Scan(recCopy, obs, x.m.opts.ApplicationURI, ep.e.conf.IsPreconfigured)
		ep.obs = obs
		if verdict == ScanCloseFirst && rec != nil {
			// Ownership before adoption (§6.5): an endpoint that is not
			// the incarnation its record was made with is neither adopted
			// nor closed, by this step or a rollback.
			if held, why := x.incarnation(ctx, a.t, rec); held != 0 {
				x.hold(rec, k, a, held, why)
				x.fail(ep, Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadInvalidState})
				continue
			}
		}
		switch verdict {
		case ScanCloseFirst:
			if class == KnownOwned && x.adoptable(ctx, a, ep, rec, obs) {
				// Kept in place if every endpoint of the run is (adopt).
				ep.adopt = rec
				continue
			}
			closeFirst = append(closeFirst, rec)
			closeEps = append(closeEps, ep)
		case ScanBlocked:
			if class == Unresolved && rec == nil {
				x.remember(a, ep, obs.NodeID, Unresolved)
			}
			x.fail(ep, Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadBrowseNameDuplicated})
		case ScanCreate, ScanTake:
		}
	}
	if len(closeFirst) == 0 {
		return
	}
	errs := x.closeRecords(ctx, closeFirst, true)
	for i, rec := range closeFirst {
		if err := errs[rec]; err != nil {
			x.failErr(closeEps[i], err, uafx.FxErrorCloseConnectionError)
			continue
		}
		if !rec.IsPreconfiguredClass() {
			closeEps[i].obs = nil // absent before the create of this run
		}
	}
}

// heldName reports whether an owed intent of the set holds name on addr.
func (x *run) heldName(addr ServerAddress, name string) bool {
	p := x.store()
	return p != nil && p.heldName(x.r.key, addr, name)
}

// IsPreconfiguredClass reports whether the record is of an endpoint the
// AC keeps after a close.
func (r *record) IsPreconfiguredClass() bool { return r.Class == TakenPreconfigured }

// remember records an endpoint of ep with class, as the run found or
// made it.
// incarnation re-proves, before a state-changing step, that the endpoint
// of rec on t is the one rec was made with (§6.5, §6.6.2 Table 74): its
// Diagnostics CreationTime is the recorded one and its
// ConnectionManagerApplicationUri not another's. It returns 0 when it is,
// or when the endpoint is gone (a close of it changes nothing); Unresolved
// when it is another, Unverified when that cannot be read now. A record
// without a CreationTime is not checked here: the scan and the re-proof
// decide it by its ConnectionManagerApplicationUri.
func (x *run) incarnation(ctx context.Context, t *target, rec *record) (Ownership, string) {
	x.s.mu.Lock()
	created, n := rec.created, rec.NodeID
	x.s.mu.Unlock()
	if created.IsZero() || n == nil || t == nil {
		return 0, ""
	}
	cm, cmOK, now, err := endpointEvidence(ctx, t, n)
	switch {
	case errors.Is(err, ua.StatusBadNodeIDUnknown):
		return 0, ""
	case err != nil:
		return Unverified, fmt.Sprintf("its evidence was not read: %v", err)
	case now.IsZero():
		return Unresolved, "it shows no CreationTime"
	case !now.Equal(created):
		return Unresolved, "it is another incarnation: its CreationTime is not the recorded one"
	case cmOK && cm != x.m.opts.ApplicationURI:
		return Unresolved, "its ConnectionManagerApplicationUri is another"
	}
	return 0, ""
}

// hold sets the record rec, of map key rk, to class (Unresolved or
// Unverified) after incarnation, reports it and has the step of a write
// it: it is never closed, adopted or changed until it is proven or
// settled.
func (x *run) hold(rec *record, rk string, a *acRun, class Ownership, why string) {
	x.s.mu.Lock()
	if x.s.records[rk] != rec {
		x.s.mu.Unlock()
		return
	}
	rec.Class, rec.ClosePending = class, false
	cp := rec.EndpointRecord
	x.s.mu.Unlock()
	x.touchAC(a, rk, rec)
	x.m.log.Warn("fxcm: an endpoint is not the one recorded: it is not touched", "set", x.r.key.String(), "run", x.r.id, "endpoint", cp.Name, "node", cp.NodeID, "class", class, "why", why)
	x.mu.Lock()
	x.res.Unresolved = append(x.res.Unresolved, cp)
	x.mu.Unlock()
}

func (x *run) remember(a *acRun, ep *epRun, n *ua.NodeID, class Ownership) {
	rec := &record{EndpointRecord: EndpointRecord{
		Set: x.r.key, Endpoint: ep.ref(), ServerURI: a.addr.ServerURI, FunctionalEntity: ep.fe, Name: ep.e.conf.Name,
		NodeID: n, Class: class, Run: x.r.id, Version: x.r.version,
	}, addr: a.addr, acNode: a.node, gen: x.gen, fp: x.fp, epfp: ep.sent}
	if a.t != nil {
		rec.nsa, rec.server = a.t.nsa, a.t.evidenceNow()
		if n != nil {
			rec.param = paramOf(ep.param, a.t.nsa)
		}
	}
	if ep.obs != nil && n != nil && ep.obs.NodeID.Equal(n) && ep.obs.CMApplicationURI != nil {
		rec.cmURI, rec.cmObserved = *ep.obs.CMApplicationURI, true
	}
	rk := recordKey(a.addr, ep.fe, ep.e.conf.Name)
	x.s.mu.Lock()
	x.s.records[rk] = rec
	x.s.mu.Unlock()
	x.touchAC(a, rk, rec)
	cp := rec.EndpointRecord
	x.mu.Lock()
	switch class {
	case Unresolved, Unverified:
		x.res.Unresolved = append(x.res.Unresolved, cp)
	case KnownOwned, TakenPreconfigured:
		x.res.Created = append(x.res.Created, cp)
	case Foreign:
	}
	x.mu.Unlock()
	x.m.observe(Event{Kind: EventEndpoint, Set: x.r.key, Run: x.r.id, Record: &cp})
}

func (x *run) forget(a *acRun, k string) {
	x.s.mu.Lock()
	rec := x.s.records[k]
	delete(x.s.records, k)
	x.s.mu.Unlock()
	x.touchAC(a, k, rec)
	if rec != nil {
		cp := rec.EndpointRecord
		x.m.observe(Event{Kind: EventEndpoint, Set: x.r.key, Run: x.r.id, Record: &cp, Closed: true})
	}
}

// --- steps 2 and 3: reserve, configure ------------------------------------

// prepare builds the PubSub configuration of a (§6.16.3) and the
// parameters of its endpoints.
func (x *run) prepare(ctx context.Context, a *acRun) {
	cm, err := x.prepareComm(ctx, a)
	if err != nil {
		x.failAC(a, err)
		return
	}
	a.comm = cm
	if cm != nil {
		if err := x.reuseDataSets(ctx, a); err != nil {
			x.failAC(a, err)
			return
		}
		x.fillNotPersisted(a)
	}
	if cm == nil {
		for _, ep := range a.eps {
			if ep.links != nil {
				x.fail(ep, Failure{FxError: uafx.FxErrorConnectionConfigurationSetInvalid, Status: ua.StatusBadNotSupported})
			}
		}
		return
	}
	switch x.r.action {
	case uafx.ActionEstablishConnectionsEnabled, uafx.ActionEstablishConnectionsDisabled:
		disabledModel(cm.cfg)
	default:
	}
}

// reuseDataSets drops the ElementAdd of each PublishedDataSet of a's
// configuration that the AC has already under the same Name and with the
// same content. Library interpretation: CloseConnections removes the
// DataSetWriters and DataSetReaders an endpoint used, not the
// PublishedDataSets, which other Connections may publish (§6.2.5.2);
// ElementMatch is defined for PubSubConnections and groups only (§6.16.3,
// OPC 10000-14 Table 241), so establishing a set again reuses the
// PublishedDataSet of the same Name, found in
// PublishSubscribe.PublishedDataSets (OPC 10000-14 §9.1.4.2). It is reused
// only when its PublishedData and the Fields of its DataSetMetaData are
// those of the set (sameDataSet); a PublishedDataSet of that Name with
// other content fails the AutomationComponent with
// SetCommunicationConfigurationError and Bad_BrowseNameDuplicated. A
// reused PublishedDataSet is shared, not owned: the ConnectionManager
// neither changes nor removes it.
func (x *run) reuseDataSets(ctx context.Context, a *acRun) error {
	cfg := a.comm.cfg
	adds := map[string]*ua.PublishedDataSetDataType{}
	for _, r := range a.comm.refs {
		if r != nil && r.ConfigurationMask&ua.PubSubConfigurationRefMaskReferencePubDataset != 0 && r.ConfigurationMask&ua.PubSubConfigurationRefMaskElementAdd != 0 &&
			int(r.ElementIndex) < len(cfg.PublishedDataSets) && cfg.PublishedDataSets[r.ElementIndex] != nil && cfg.PublishedDataSets[r.ElementIndex].Name != "" {
			p := cfg.PublishedDataSets[r.ElementIndex]
			adds[p.Name] = p
		}
	}
	if len(adds) == 0 {
		return nil
	}
	// A server without the PubSub model has no folder (OPC 10000-14
	// §9.1.3.2): nothing to reuse, and the call adds them.
	refs, _ := a.t.children(ctx, ua.NewNumericNodeID(0, id.PublishSubscribePublishedDataSets))
	reuse := map[string]bool{}
	for _, r := range refs {
		if r == nil || r.BrowseName == nil || r.NodeID == nil || r.NodeID.NodeID == nil {
			continue
		}
		want := adds[r.BrowseName.Name]
		if want == nil {
			continue
		}
		same, err := x.sameDataSet(ctx, a, r.NodeID.NodeID, want)
		if err != nil {
			return err
		}
		if !same {
			return failure(uafx.FxErrorSetCommunicationConfigurationError, ua.StatusBadBrowseNameDuplicated,
				"%s has a PublishedDataSet %q with other PublishedData or DataSetMetaData than the set", a.addr.Address, want.Name)
		}
		reuse[want.Name] = true
	}
	kept := a.comm.refs[:0:0]
	for _, r := range a.comm.refs {
		if r != nil && r.ConfigurationMask&ua.PubSubConfigurationRefMaskReferencePubDataset != 0 && r.ConfigurationMask&ua.PubSubConfigurationRefMaskElementAdd != 0 &&
			int(r.ElementIndex) < len(cfg.PublishedDataSets) && cfg.PublishedDataSets[r.ElementIndex] != nil &&
			reuse[cfg.PublishedDataSets[r.ElementIndex].Name] {
			continue
		}
		kept = append(kept, r)
	}
	a.comm.refs = kept
	return nil
}

// sameDataSet reads the PublishedData and DataSetMetaData Properties of the
// PublishedDataItemsType Object n (OPC 10000-14 §9.1.4) and reports
// whether they publish what want does: the same Variables, Attributes,
// IndexRanges, deadbands, SubstituteValues (sent for a Bad value,
// OPC 10000-14 §6.2.3.7.1) and MetaDataProperties in the same order, and
// Fields (FieldMetaData,
// OPC 10000-14 §6.2.3.2.4) of the same Names, FieldFlags, BuiltInTypes,
// DataTypes, ValueRanks, ArrayDimensions, MaxStringLengths, Properties and
// DataSetFieldIds, and the same DataSetClassId (a set without
// DataSetMetaData leaves the Fields to the publisher). Library
// interpretation: SamplingIntervalHint is a hint, Descriptions are text
// for people, and the ConfigurationVersion is the publisher's own
// (ConfigurationVersionDataType), so none of them is compared.
func (x *run) sameDataSet(ctx context.Context, a *acRun, n *ua.NodeID, want *ua.PublishedDataSetDataType) (bool, error) {
	if want.DataSetSource == nil {
		return false, nil
	}
	items, ok := want.DataSetSource.Value.(*ua.PublishedDataItemsDataType)
	if !ok {
		return false, nil
	}
	props, err := a.t.children(ctx, n)
	if err != nil {
		f := failureOf(err, uafx.FxErrorSetCommunicationConfigurationError)
		return false, failure(f.FxError, f.Status, "the PublishedDataSet %q on %s: %v", want.Name, a.addr.Address, err)
	}
	pd, md := child(props, 0, "PublishedData"), child(props, 0, "DataSetMetaData")
	if pd == nil || md == nil {
		return false, nil
	}
	res, err := a.t.sess.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: pd, AttributeID: ua.AttributeIDValue}, {NodeID: md, AttributeID: ua.AttributeIDValue},
	}})
	if err == nil && len(res.Results) != 2 {
		err = ua.StatusBadUnexpectedError
	}
	if err != nil {
		f := failureOf(err, uafx.FxErrorSetCommunicationConfigurationError)
		return false, failure(f.FxError, f.Status, "the PublishedDataSet %q on %s: %v", want.Name, a.addr.Address, err)
	}
	var have []*ua.PublishedVariableDataType
	if eos, ok := dvValue(res.Results[0]).([]*ua.ExtensionObject); ok {
		for _, eo := range eos {
			v, _ := eo.Value.(*ua.PublishedVariableDataType)
			have = append(have, v)
		}
	}
	var haveMD *ua.DataSetMetaDataType
	if eo, ok := dvValue(res.Results[1]).(*ua.ExtensionObject); ok {
		haveMD, _ = eo.Value.(*ua.DataSetMetaDataType)
	}
	return samePublishedData(have, items.PublishedData) && sameFields(haveMD, want.DataSetMetaData), nil
}

func samePublishedData(have, want []*ua.PublishedVariableDataType) bool {
	if len(have) != len(want) {
		return false
	}
	for i, w := range want {
		h := have[i]
		if h == nil || w == nil {
			if h != w {
				return false
			}
			continue
		}
		if !h.PublishedVariable.Equal(w.PublishedVariable) || h.AttributeID != w.AttributeID || h.IndexRange != w.IndexRange ||
			h.DeadbandType != w.DeadbandType || h.DeadbandValue != w.DeadbandValue ||
			!sameValue(h.SubstituteValue, w.SubstituteValue) || !sameNames(h.MetaDataProperties, w.MetaDataProperties) {
			return false
		}
	}
	return true
}

// sameValue compares two Variants of which either may be absent: a nil
// Variant and one without a value are the same (no SubstituteValue).
func sameValue(have, want *ua.Variant) bool {
	if have == nil || have.Value() == nil || want == nil || want.Value() == nil {
		return (have == nil || have.Value() == nil) == (want == nil || want.Value() == nil)
	}
	return sameVariant(have, want)
}

func sameNames(have, want []*ua.QualifiedName) bool {
	return slices.EqualFunc(have, want, func(h, w *ua.QualifiedName) bool {
		if h == nil || w == nil {
			return h == w
		}
		return h.NamespaceIndex == w.NamespaceIndex && h.Name == w.Name
	})
}

func sameFields(have, want *ua.DataSetMetaDataType) bool {
	switch {
	case want == nil:
		return true
	case have == nil:
		return false
	}
	if len(have.Fields) != len(want.Fields) {
		return false
	}
	for i, w := range want.Fields {
		h := have.Fields[i]
		if h == nil || w == nil {
			if h != w {
				return false
			}
			continue
		}
		if h.Name != w.Name || h.FieldFlags != w.FieldFlags || h.BuiltInType != w.BuiltInType || h.ValueRank != w.ValueRank ||
			!slices.Equal(h.ArrayDimensions, w.ArrayDimensions) || h.MaxStringLength != w.MaxStringLength ||
			!sameAssigned(h.DataSetFieldID, w.DataSetFieldID) || !sameProperties(h.Properties, w.Properties) {
			return false
		}
		if (h.DataType != nil || w.DataType != nil) && !h.DataType.Equal(w.DataType) {
			return false
		}
	}
	return sameAssigned(have.DataSetClassID, want.DataSetClassID)
}

// sameAssigned compares a Guid the set may leave null. A DataSetFieldId is
// generated when the field is added (OPC 10000-14 §6.2.3.2.4) and a
// DataSetClassId is null for a DataSet not created from a class
// (§6.2.3.2.3, §6.2.3.3). Library interpretation: a null want leaves the
// Guid to the publisher and matches any; one the set names must be the
// publisher's, since a subscriber maps received fields by DataSetFieldId
// (FieldTargetDataType, §6.2.10.2.3).
func sameAssigned(have, want *ua.GUID) bool {
	if nullGUID(want) {
		return true
	}
	return !nullGUID(have) && have.String() == want.String()
}

func nullGUID(g *ua.GUID) bool {
	if g == nil {
		return true
	}
	return g.Data1 == 0 && g.Data2 == 0 && g.Data3 == 0 && !slices.ContainsFunc(g.Data4, func(b byte) bool { return b != 0 })
}

// sameProperties compares the Properties of two fields (FieldMetaData,
// OPC 10000-14 §6.2.3.2.4) in order: their Keys and Values.
func sameProperties(have, want []*ua.KeyValuePair) bool {
	if len(have) != len(want) {
		return false
	}
	for i, w := range want {
		h := have[i]
		if h == nil || w == nil {
			if h != w {
				return false
			}
			continue
		}
		if (h.Key == nil) != (w.Key == nil) || h.Key != nil && (h.Key.NamespaceIndex != w.Key.NamespaceIndex || h.Key.Name != w.Key.Name) || !sameVariant(h.Value, w.Value) {
			return false
		}
	}
	return true
}

// disabledModel sets the DataSetReaders and DataSetWriters of cfg to
// Enabled FALSE and everything else to TRUE (§6.7.5.3.1: a disabled
// communication model).
func disabledModel(cfg *ua.PubSubConfiguration2DataType) {
	cfg.Enabled = true
	for _, c := range cfg.Connections {
		if c == nil {
			continue
		}
		c.Enabled = true
		for _, g := range c.WriterGroups {
			if g == nil {
				continue
			}
			g.Enabled = true
			for _, w := range g.DataSetWriters {
				if w != nil {
					w.Enabled = false
				}
			}
		}
		for _, g := range c.ReaderGroups {
			if g == nil {
				continue
			}
			g.Enabled = true
			for _, r := range g.DataSetReaders {
				if r != nil {
					r.Enabled = false
				}
			}
		}
	}
}

// reserve is step 2 (E.2.2.1 step 1): ReserveCommunicationIdsCmd for the
// WriterGroupIds and DataSetWriterIds a's configuration leaves 0 and for
// the DefaultPublisherId, with VerifyAssetCmd.
func (x *run) reserve(ctx context.Context, a *acRun) {
	defer x.syncStep(a)
	if a.comm == nil {
		return
	}
	groups, writers, profile := a.comm.reserveNeed()
	nullPub := false
	for _, c := range a.comm.cfg.Connections {
		if c != nil && len(c.WriterGroups) > 0 && isNullID(c.PublisherID) {
			nullPub = true
		}
	}
	if groups == 0 && writers == 0 && !nullPub {
		return
	}
	if profile == "" {
		profile = UDPUADP
	}
	req := &uafx.EstablishConnectionsRequest{
		CommandMask: uafx.ReserveCommunicationIDsCmd,
		ReserveCommunicationIDs: []*uafx.PubSubReserveCommunicationIDs{{
			TransportProfileURI: profile, NumReqWriterGroupIDs: groups, NumReqDataSetWriterIDs: writers,
		}},
	}
	if len(a.assets) > 0 {
		req.CommandMask |= uafx.VerifyAssetCmd
		req.AssetVerifications = a.assets
		a.assets = nil
	}
	res, err, unknown := x.call(ctx, a, req)
	switch {
	case unknown:
		// Ids are released with the session (CL-2); nothing was created,
		// so the intent owes nothing, unless the call had a command with
		// durable effects (second C3.2 review).
		if !sessionScoped(req.CommandMask) {
			x.retain(a.lastIntent)
		}
		x.failAC(a, failure(uafx.FxErrorReserveCommunicationIDsError, failureOf(err, uafx.FxErrorReserveCommunicationIDsError).Status, "%v", err))
		return
	case err != nil:
		x.failAC(a, failure(fxOfMask(req.CommandMask), StatusOf(err), "%v", err))
		return
	}
	if f, ok := assetFailure(res); ok {
		x.failAC(a, failure(f.FxError, f.Status, "VerifyAsset"))
		return
	}
	if len(res.ReserveCommunicationIDsResults) != 1 || res.ReserveCommunicationIDsResults[0] == nil || bad(res.ReserveCommunicationIDsResults[0].Result) || res.Status != ua.StatusGood {
		st := res.Status
		if len(res.ReserveCommunicationIDsResults) == 1 && res.ReserveCommunicationIDsResults[0] != nil && bad(res.ReserveCommunicationIDsResults[0].Result) {
			st = res.ReserveCommunicationIDsResults[0].Result
		}
		x.failAC(a, failure(uafx.FxErrorReserveCommunicationIDsError, st, "ReserveCommunicationIds"))
		return
	}
	rr := res.ReserveCommunicationIDsResults[0]
	if err := a.comm.fillReserved(rr); err != nil {
		x.failAC(a, err)
		return
	}
	a.defaultPublisherID = rr.DefaultPublisherID
}

// sessionScoped reports whether the commands of mask change nothing that
// outlives the session: ReserveCommunicationIdsCmd (released with the
// session, CL-2) and the verifications (§6.2.4.3.2, §6.2.4.3.3). A call of
// only those owes no recovery when its outcome is unknown.
func sessionScoped(mask uafx.FxCommandMask) bool {
	return mask != 0 && mask&^(uafx.ReserveCommunicationIDsCmd|uafx.VerifyAssetCmd|uafx.VerifyFunctionalEntityCmd) == 0
}

// bad reports whether st is a Bad StatusCode (OPC 10000-4 §7.39).
func bad(st ua.StatusCode) bool { return st.Uint32()&0x80000000 != 0 }

func assetFailure(res *uafx.EstablishConnectionsResult) (Failure, bool) {
	for _, r := range res.AssetVerificationResults {
		if r == nil {
			continue
		}
		if bad(r.VerificationStatus) {
			return Failure{FxError: uafx.FxErrorVerifyAssetError, Status: r.VerificationStatus}, true
		}
		if r.VerificationResult == uafx.AssetVerificationMismatch {
			return Failure{FxError: uafx.FxErrorVerifyAssetError, Status: ua.StatusBadNoMatch}, true
		}
	}
	return Failure{}, false
}

// fxOfMask returns the FxError of the first command of mask in the order
// of §6.2.4.3.1 (design §5.7).
func fxOfMask(mask uafx.FxCommandMask) uafx.FxError {
	if o := mask.Order(); len(o) > 0 {
		return fxOfCommand(o[0])
	}
	return uafx.FxErrorUnknownStatus
}

func fxOfCommand(c uafx.FxCommandMask) uafx.FxError {
	switch c {
	case uafx.VerifyAssetCmd:
		return uafx.FxErrorVerifyAssetError
	case uafx.VerifyFunctionalEntityCmd:
		return uafx.FxErrorVerifyFunctionalEntityError
	case uafx.CreateConnectionEndpointCmd:
		return uafx.FxErrorCreateConnectionEndpointError
	case uafx.EstablishControlCmd:
		return uafx.FxErrorEstablishControlError
	case uafx.SetConfigurationDataCmd:
		return uafx.FxErrorSetConfigurationDataError
	case uafx.ReassignControlCmd:
		return uafx.FxErrorReassignControlError
	case uafx.ReserveCommunicationIDsCmd:
		return uafx.FxErrorReserveCommunicationIDsError
	case uafx.SetCommunicationConfigurationCmd:
		return uafx.FxErrorSetCommunicationConfigurationError
	case uafx.EnableCommunicationCmd:
		return uafx.FxErrorEnableCommunicationError
	default:
		return uafx.FxErrorUnknownStatus
	}
}

// errAmbiguous marks a response that does not prove the outcome of a
// state-changing call (decision C3-D13).
var errAmbiguous = errors.New("fxcm: the result does not prove the outcome of the call (decision C3-D13)")

// ambiguousStatus reports whether st, the result of a state-changing call
// or of one of its operations, proves neither that the call failed nor
// that nothing changed remotely (design §6.7, decision C3-D13; library
// interpretation of the set: an internal or unexpected error of the
// server, an exhausted resource, a timeout, a closed or failed channel, a
// shutdown, a response that did not decode).
// Bad_ResourceUnavailable is not among them: from an AutomationComponent
// with a store it means the store definitely did not commit and the call
// was undone.
func ambiguousStatus(st ua.StatusCode) bool {
	switch st {
	case ua.StatusBadInternalError, ua.StatusBadUnexpectedError, ua.StatusBadOutOfMemory, ua.StatusBadTimeout,
		ua.StatusBadRequestTimeout, ua.StatusBadCommunicationError, ua.StatusBadConnectionClosed, ua.StatusBadSecureChannelClosed,
		ua.StatusBadServerHalted, ua.StatusBadShutdown, ua.StatusBadDecodingError:
		return true
	default:
		return false
	}
}

// call calls EstablishConnections on a. unknown is set when no response
// came (a communication error, a timeout), or the method result is
// ambiguous (decision C3-D13, err wraps errAmbiguous): the outcome is
// unknown (design §5.4). Otherwise err is a Bad status of the call (Table
// 9), and res the result of a call that returned Good or Uncertain.
func (x *run) call(ctx context.Context, a *acRun, req *uafx.EstablishConnectionsRequest) (res *uafx.EstablishConnectionsResult, err error, unknown bool) {
	args, err := uafx.EncodeEstablishConnectionsRequest(req, a.data)
	if err != nil {
		return nil, failure(uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadEncodingError, "%v", err), false
	}
	// The intent first: without it nothing is sent (design §6.3).
	if x.store() != nil {
		// The fingerprint of what each endpoint was established with
		// (design §6.5: the configuration evidence).
		for _, cec := range req.ConnectionEndpointConfigurations {
			d := cec.ConnectionEndpoint
			if d == nil || d.Parameter == nil {
				continue
			}
			for _, ep := range a.eps {
				if ep.fe.Equal(cec.FunctionalEntityNode) && ep.e.conf.Name == d.Parameter.Name {
					ep.sent = fingerprint(cec)
				}
			}
		}
	}
	k, err := x.intend(x.establishIntent(a, req, args))
	if err != nil {
		return nil, err, false
	}
	a.lastIntent = k
	if k != "" {
		a.intents = append(a.intents, k)
	}
	cctx, cancel := context.WithTimeout(ctx, x.m.opts.CallTimeout)
	defer cancel()
	x.m.counters.establish.Add(1)
	out, err := a.t.sess.Call(cctx, &ua.CallMethodRequest{ObjectID: a.node, MethodID: a.establish, InputArguments: args})
	x.crashPoint("call.after-send")
	ev := Event{Kind: EventCall, Set: x.r.key, Run: x.r.id, Method: "EstablishConnections", Address: a.addr.Address}
	defer func() { x.m.observe(ev) }()
	if err != nil {
		x.m.counters.establishFailed.Add(1)
		if errors.Is(err, context.DeadlineExceeded) {
			err = fmt.Errorf("%w: %w", ua.StatusBadTimeout, err)
		}
		ev.Err = err
		return nil, err, true
	}
	ev.Status = out.StatusCode
	if out.StatusCode != ua.StatusGood {
		x.m.counters.establishFailed.Add(1)
	}
	if bad(out.StatusCode) {
		if ambiguousStatus(out.StatusCode) {
			// Decision C3-D13: no proof that nothing changed.
			return nil, fmt.Errorf("%w: %w", out.StatusCode, errAmbiguous), true
		}
		return nil, out.StatusCode, false
	}
	res, err = uafx.DecodeEstablishConnectionsResult(out.OutputArguments, a.data)
	if err != nil {
		ev.Err = err
		return nil, fmt.Errorf("%w: %w: %w", ua.StatusBadDecodingError, errAmbiguous, err), true
	}
	res.Status = out.StatusCode
	return res, nil, false
}

// configure is step 3 (E.2.2.2): one call per AutomationComponent with the
// bundle of each endpoint (CreateConnectionEndpoint, EstablishControl,
// SetConfigurationData, ReassignControl, SetCommunicationConfiguration with
// the ids of step 2, EnableCommunication for an enabled establish), split at
// MaxConnectionsPerCall without separating the commands of one endpoint
// (EC-4, EC-5).
func (x *run) configure(ctx context.Context, a *acRun) {
	defer x.syncStep(a)
	var eps []*epRun
	for _, ep := range a.eps {
		if !ep.failed() {
			eps = append(eps, ep)
		}
	}
	size := len(eps)
	if a.maxPerCall > 0 && int(a.maxPerCall) < size {
		size = int(a.maxPerCall)
	}
	var chunks [][]*epRun
	for i := 0; i < len(eps); i += size {
		chunks = append(chunks, eps[i:min(i+size, len(eps))])
	}
	for ci, chunk := range chunks {
		refs := chunkRefs(a, chunks, ci)
		withComm := a.comm != nil && (len(refs) > 0 || slices.ContainsFunc(chunk, func(ep *epRun) bool { return ep.links != nil }))
		req := x.configureRequest(a, chunk, withComm, refs)
		res, err, unknown := x.call(ctx, a, req)
		if !unknown && err == nil {
			if why := inconclusive(res, len(chunk), withComm, true); why != nil {
				unknown, err = true, why
			}
		}
		switch {
		case unknown:
			x.lostResponse(ctx, a, chunk, req.CommandMask, err)
			x.stopRest(chunks[ci+1:])
			return
		case err != nil:
			for _, ep := range chunk {
				x.fail(ep, Failure{FxError: fxOfMask(req.CommandMask), Status: StatusOf(err)})
			}
			x.stopRest(chunks[ci+1:])
			return
		}
		ok := x.configured(a, chunk, req, res)
		x.evidence(ctx, a.t, a, chunk)
		if !ok && x.store() != nil {
			// A partial outcome (decision C3-D13 as reviewed): a
			// definite failure of one operation does not prove that the
			// others had no effect. The Names of the call without an
			// endpoint record of this run are browsed again; the intent
			// stays unless each is proven.
			var unproven []*epRun
			for _, ep := range chunk {
				x.s.mu.Lock()
				rec := x.s.records[recordKey(a.addr, ep.fe, ep.e.conf.Name)]
				mine := rec != nil && rec.Run == x.r.id
				x.s.mu.Unlock()
				if !mine {
					unproven = append(unproven, ep)
				}
			}
			if !x.reprove(ctx, a.t, a, unproven, func(*epRun) bool { return false }) {
				x.retain(a.lastIntent)
			}
		}
		if !ok {
			x.stopRest(chunks[ci+1:])
			return
		}
		if withComm && len(res.CommunicationConfigurationResults) == 1 && res.CommunicationConfigurationResults[0] != nil {
			a.values = append(a.values, res.CommunicationConfigurationResults[0].ConfigurationValues...)
			applyValues(a.comm.cfg, res.CommunicationConfigurationResults[0].ConfigurationValues)
		}
	}
	a.configured = true
}

// linkedBy reports whether the CommunicationLinks l name the reader or
// writer of the reference r.
func linkedBy(l *uafx.PubSubCommunicationLinkConfiguration, r *ua.PubSubConfigurationRefDataType) bool {
	same := func(x *ua.PubSubConfigurationRefDataType, kind ua.PubSubConfigurationRefMask) bool {
		return x != nil && x.ConfigurationMask&kind != 0 && r.ConfigurationMask&kind != 0 &&
			x.ConnectionIndex == r.ConnectionIndex && x.GroupIndex == r.GroupIndex && x.ElementIndex == r.ElementIndex
	}
	return l != nil && (same(l.DataSetWriterRef, ua.PubSubConfigurationRefMaskReferenceWriter) || same(l.DataSetReaderRef, ua.PubSubConfigurationRefMaskReferenceReader))
}

// chunkRefs returns the ConfigurationReferences of call ci of a split
// configure step (EC-5). The first call adds the PublishedDataSets,
// PubSubConnections and groups, the removals, and the readers and writers
// that no endpoint of a later call links to; a later call adds the readers
// and writers its endpoints link to, inside the parents the first call
// added, which the server finds by the Names it assigned (§6.16.3,
// applyValues). Library interpretation: ElementMatch is defined for
// PubSubConnections and groups only (OPC 10000-14 §9.1.3.7.2), so no
// element is sent twice. A later call whose readers and writers were all
// added before matches the PubSubConnection of its first link, as the
// command needs a reference.
func chunkRefs(a *acRun, chunks [][]*epRun, ci int) []*ua.PubSubConfigurationRefDataType {
	if a.comm == nil {
		return nil
	}
	owner := func(r *ua.PubSubConfigurationRefDataType) int {
		if r.ConfigurationMask&(ua.PubSubConfigurationRefMaskReferenceWriter|ua.PubSubConfigurationRefMaskReferenceReader) == 0 ||
			r.ConfigurationMask&ua.PubSubConfigurationRefMaskElementAdd == 0 {
			return 0
		}
		for k, c := range chunks {
			for _, ep := range c {
				if linkedBy(ep.links, r) {
					return k
				}
			}
		}
		return 0
	}
	var out []*ua.PubSubConfigurationRefDataType
	for _, r := range a.comm.refs {
		if r != nil && owner(r) == ci {
			out = append(out, r)
		}
	}
	if len(out) > 0 || ci == 0 {
		return out
	}
	for _, ep := range chunks[ci] {
		if ep.links == nil {
			continue
		}
		for _, l := range []*ua.PubSubConfigurationRefDataType{ep.links.DataSetWriterRef, ep.links.DataSetReaderRef} {
			if l != nil && l.ConfigurationMask != 0 {
				return []*ua.PubSubConfigurationRefDataType{{
					ConfigurationMask: ua.PubSubConfigurationRefMaskElementMatch | ua.PubSubConfigurationRefMaskReferenceConnection,
					ConnectionIndex:   l.ConnectionIndex,
				}}
			}
		}
	}
	return nil
}

// stopRest gives the endpoints of chunks that were not called the outcome
// Stopped (§10.19: skipped because of an unrelated failure).
func (x *run) stopRest(chunks [][]*epRun) {
	for _, c := range chunks {
		for _, ep := range c {
			x.setOutcome(ep, Stopped)
		}
	}
}

func (x *run) configureRequest(a *acRun, chunk []*epRun, withComm bool, refs []*ua.PubSubConfigurationRefDataType) *uafx.EstablishConnectionsRequest {
	req := &uafx.EstablishConnectionsRequest{CommandMask: uafx.CreateConnectionEndpointCmd}
	if len(a.assets) > 0 {
		req.CommandMask |= uafx.VerifyAssetCmd
		req.AssetVerifications = a.assets
		a.assets = nil
	}
	for _, ep := range chunk {
		el := &uafx.ConnectionEndpointConfiguration{
			FunctionalEntityNode:          ep.fe,
			ConnectionEndpoint:            &uafx.ConnectionEndpointDefinition{Parameter: ep.param},
			ExpectedVerificationVariables: ep.verify,
			ControlGroups:                 ep.controls,
			ConfigurationData:             ep.config,
		}
		if withComm {
			el.CommunicationLinks = ep.links
		}
		if len(ep.verify) > 0 {
			req.CommandMask |= uafx.VerifyFunctionalEntityCmd
		}
		if len(ep.controls) > 0 {
			req.CommandMask |= uafx.EstablishControlCmd | uafx.ReassignControlCmd
		}
		if len(ep.config) > 0 {
			req.CommandMask |= uafx.SetConfigurationDataCmd
		}
		req.ConnectionEndpointConfigurations = append(req.ConnectionEndpointConfigurations, el)
	}
	if withComm {
		req.CommandMask |= uafx.SetCommunicationConfigurationCmd
		req.CommunicationConfigurations = []*uafx.PubSubCommunicationConfiguration{{
			PubSubConfiguration: a.comm.cfg, RequireCompleteUpdate: true, ConfigurationReferences: refs,
		}}
	}
	if x.r.action == uafx.ActionEstablishConnectionsEnabled && (withComm || a.comm == nil) {
		req.CommandMask |= uafx.EnableCommunicationCmd
	}
	return req
}

// applyValues writes the names and ids an AC assigned (ConfigurationValues,
// §6.16.3) into cfg, so that a later call can match the elements.
func applyValues(cfg *ua.PubSubConfiguration2DataType, values []*ua.PubSubConfigurationValueDataType) {
	for _, v := range values {
		if v == nil || v.ConfigurationElement == nil {
			continue
		}
		r := v.ConfigurationElement
		m := r.ConfigurationMask
		switch {
		case m&ua.PubSubConfigurationRefMaskReferencePubDataset != 0:
			if int(r.ElementIndex) < len(cfg.PublishedDataSets) && cfg.PublishedDataSets[r.ElementIndex] != nil && v.Name != "" {
				old := cfg.PublishedDataSets[r.ElementIndex].Name
				cfg.PublishedDataSets[r.ElementIndex].Name = v.Name
				renameDataSet(cfg, old, v.Name)
			}
		case m&ua.PubSubConfigurationRefMaskReferenceWriter != 0:
			if _, _, w := writerAt(cfg, r); w != nil {
				setName(&w.Name, v.Name)
				if id, ok := v.Identifier.Value().(uint16); ok && w.DataSetWriterID == 0 {
					w.DataSetWriterID = id
				}
			}
		case m&ua.PubSubConfigurationRefMaskReferenceReader != 0:
			if rd := readerAt(cfg, r); rd != nil {
				setName(&rd.Name, v.Name)
			}
		case m&ua.PubSubConfigurationRefMaskReferenceWriterGroup != 0:
			if c := connAt(cfg, r); c != nil && int(r.GroupIndex) < len(c.WriterGroups) && c.WriterGroups[r.GroupIndex] != nil {
				g := c.WriterGroups[r.GroupIndex]
				setName(&g.Name, v.Name)
				if id, ok := v.Identifier.Value().(uint16); ok && g.WriterGroupID == 0 {
					g.WriterGroupID = id
				}
			}
		case m&ua.PubSubConfigurationRefMaskReferenceReaderGroup != 0:
			if c := connAt(cfg, r); c != nil && int(r.GroupIndex) < len(c.ReaderGroups) && c.ReaderGroups[r.GroupIndex] != nil {
				setName(&c.ReaderGroups[r.GroupIndex].Name, v.Name)
			}
		case m&ua.PubSubConfigurationRefMaskReferenceConnection != 0:
			if c := connAt(cfg, r); c != nil {
				setName(&c.Name, v.Name)
				// The PublisherId the PubSubConnection has: the one of the
				// connection it matched, or the one it was added with
				// (§6.16.3).
				if !isNullID(v.Identifier) {
					c.PublisherID = v.Identifier
				}
			}
		}
	}
}

func setName(dst *string, name string) {
	if *dst == "" && name != "" {
		*dst = name
	}
}

func connAt(cfg *ua.PubSubConfiguration2DataType, r *ua.PubSubConfigurationRefDataType) *ua.PubSubConnectionDataType {
	if int(r.ConnectionIndex) < len(cfg.Connections) {
		return cfg.Connections[r.ConnectionIndex]
	}
	return nil
}

func renameDataSet(cfg *ua.PubSubConfiguration2DataType, old, name string) {
	if old == "" || old == name {
		return
	}
	for _, c := range cfg.Connections {
		if c == nil {
			continue
		}
		for _, g := range c.WriterGroups {
			if g == nil {
				continue
			}
			for _, w := range g.DataSetWriters {
				if w != nil && w.DataSetName == old {
					w.DataSetName = name
				}
			}
		}
	}
}

// configured processes the result of a configure call and reports whether
// the run goes on (§6.2.4.3.11: an Uncertain call was aborted and undone by
// the AC, its results say which command failed).
func (x *run) configured(a *acRun, chunk []*epRun, req *uafx.EstablishConnectionsRequest, res *uafx.EstablishConnectionsResult) bool {
	if x.m.log.Enabled(context.Background(), slog.LevelDebug) {
		var eps, comm []string
		for _, r := range res.ConnectionEndpointConfigurationResults {
			if r != nil {
				eps = append(eps, fmt.Sprintf("%+v", *r))
			}
		}
		for _, r := range res.CommunicationConfigurationResults {
			if r != nil {
				comm = append(comm, fmt.Sprintf("result %v references %v", r.Result, r.ReferenceResults))
			}
		}
		x.m.log.Debug("fxcm: EstablishConnections result", "set", x.r.key.String(), "run", x.r.id, "address", a.addr.Address,
			"status", res.Status, "endpoints", eps, "communication", comm)
	}
	failed := false
	if f, ok := assetFailure(res); ok {
		for _, ep := range chunk {
			x.fail(ep, f)
		}
		failed = true
	}
	// The commands that failed are reported; those the AC skipped after
	// them return Bad_NothingToDo (§6.2.4.3.11) and are reported only when
	// nothing else failed.
	results := res.ConnectionEndpointConfigurationResults
	resultOf := func(i int) *uafx.ConnectionEndpointConfigurationResult {
		if i < len(results) {
			return results[i]
		}
		return nil
	}
	var commResult ua.StatusCode
	if len(res.CommunicationConfigurationResults) == 1 && res.CommunicationConfigurationResults[0] != nil {
		commResult = res.CommunicationConfigurationResults[0].Result
	}
	failComm := func() {
		for _, ep := range chunk {
			if ep.links != nil || len(chunk) == 1 {
				x.fail(ep, Failure{FxError: uafx.FxErrorSetCommunicationConfigurationError, Status: commResult})
			}
		}
		failed = true
	}
	for _, skip := range []bool{true, false} {
		for i, ep := range chunk {
			if r := resultOf(i); r != nil {
				if f, ok := elementFailureSkipping(r, skip); ok {
					x.fail(ep, f)
					failed = true
				}
			}
		}
		if bad(commResult) && (!skip || commResult != ua.StatusBadNothingToDo) {
			failComm()
		}
		if failed {
			break
		}
	}
	if res.Status != ua.StatusGood {
		// The AC aborted the call and undid it (§6.2.4.3.11, Table 21).
		if !failed {
			for _, ep := range chunk {
				x.fail(ep, Failure{FxError: uafx.FxErrorUnknownStatus, Status: res.Status})
			}
		}
		for _, ep := range chunk {
			x.setOutcome(ep, Stopped)
		}
		return false
	}
	for i, ep := range chunk {
		// A null NodeId is no NodeId: the encoding has no absent one
		// (Part 6 §5.2.2.9).
		if i >= len(results) || results[i] == nil || orNil(results[i].ConnectionEndpointID) == nil {
			x.fail(ep, Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBadUnexpectedError})
			failed = true
			continue
		}
		class := KnownOwned
		if ep.e.conf.IsPreconfigured {
			class = TakenPreconfigured
		}
		x.remember(a, ep, results[i].ConnectionEndpointID, class)
		x.setOutcome(ep, Succeeded)
	}
	return !failed
}

// elementFailure returns the failure of the first command of an element
// that failed, in the order of §6.2.4.3.1.
func elementFailure(r *uafx.ConnectionEndpointConfigurationResult) (Failure, bool) {
	if f, ok := elementFailureSkipping(r, true); ok {
		return f, true
	}
	return elementFailureSkipping(r, false)
}

// elementFailureSkipping is elementFailure; with skip a Bad_NothingToDo,
// a command the AC skipped after another failed, is not a failure.
func elementFailureSkipping(r *uafx.ConnectionEndpointConfigurationResult, skip bool) (Failure, bool) {
	bad := func(s ua.StatusCode) bool { return bad(s) && (!skip || s != ua.StatusBadNothingToDo) }
	firstBad := func(sts []ua.StatusCode) (ua.StatusCode, bool) {
		for _, s := range sts {
			if bad(s) {
				return s, true
			}
		}
		return 0, false
	}
	switch {
	case bad(r.FunctionalEntityNodeResult):
		return Failure{uafx.FxErrorVerifyFunctionalEntityError, r.FunctionalEntityNodeResult}, true
	case bad(r.VerificationStatus):
		return Failure{uafx.FxErrorVerifyFunctionalEntityError, r.VerificationStatus}, true
	case r.VerificationResult == uafx.FunctionalEntityVerificationMismatch:
		return Failure{uafx.FxErrorVerifyFunctionalEntityError, ua.StatusBadNoMatch}, true
	case bad(r.ConnectionEndpointResult):
		return Failure{uafx.FxErrorCreateConnectionEndpointError, r.ConnectionEndpointResult}, true
	}
	if st, ok := firstBad(r.EstablishControlResult); ok {
		return Failure{uafx.FxErrorEstablishControlError, st}, true
	}
	if st, ok := firstBad(r.ConfigurationDataResult); ok {
		return Failure{uafx.FxErrorSetConfigurationDataError, st}, true
	}
	if st, ok := firstBad(r.ReassignControlResult); ok {
		return Failure{uafx.FxErrorReassignControlError, st}, true
	}
	switch {
	case bad(r.CommunicationLinksResult):
		return Failure{uafx.FxErrorSetCommunicationConfigurationError, r.CommunicationLinksResult}, true
	case bad(r.EnableCommunicationResult):
		return Failure{uafx.FxErrorEnableCommunicationError, r.EnableCommunicationResult}, true
	}
	return Failure{}, false
}

// lostResponse handles a configure call without a response (design §5.4):
// the step fails; on a new session each FunctionalEntity is browsed for the
// Names the call meant to create, and what is found is classified by
// ResolveLostResponse. The call is never sent again.
func (x *run) lostResponse(ctx context.Context, a *acRun, chunk []*epRun, mask uafx.FxCommandMask, err error) {
	ambiguous := errors.Is(err, errAmbiguous)
	f := failureOf(err, fxOfMask(mask))
	if !ambiguous && f.Status != ua.StatusBadTimeout {
		f.Status = ua.StatusBadCommunicationError
	}
	proven := !ambiguous
	defer func() {
		if !proven {
			// The intent stays: the outcome is not proven (decision
			// C3-D13), its Names are re-proved, never resent.
			x.retain(a.lastIntent)
		}
	}()
	for _, ep := range chunk {
		x.fail(ep, f)
	}
	x.m.pool.drop(ctx, a.addr, a.t.sess)
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), x.m.opts.CallTimeout)
	defer cancel()
	sess, derr := x.m.pool.get(cctx, a.addr)
	var t *target
	if derr == nil {
		t = &target{addr: a.addr, sess: sess, cache: x.m.res.of(a.addr)}
		derr = t.open(cctx)
	}
	if derr != nil {
		// Not checked: unresolved until a Reconcile or a run checks it.
		for _, ep := range chunk {
			x.remember(a, ep, nil, Unresolved)
		}
		proven = false
		return
	}
	x.identify(cctx, t)
	// Absent proves nothing after an ambiguous result: an
	// AutomationComponent whose store had an unknown outcome may restore
	// the endpoint (C3-D13); library interpretation: nor after a lost
	// response, for a persistent endpoint.
	if !x.reprove(cctx, t, a, chunk, func(ep *epRun) bool { return ambiguous || ep.e.conf.IsPersistent }) {
		proven = false
	}
}

// reprove browses the FunctionalEntities of t for the Names of eps, whose
// calls did not prove what they did, and records what it finds as
// ResolveLostResponse classifies it. A Name that is not found is proven
// absent unless holdAbsent says absence proves nothing for it: then it is
// held, Unresolved. It reports whether every Name was proven: found and
// classified other than Unresolved, or proven absent.
func (x *run) reprove(ctx context.Context, t *target, a *acRun, eps []*epRun, holdAbsent func(*epRun) bool) bool {
	proven := true
	for _, ep := range eps {
		found, err := observeName(ctx, t, ep.fe, ep.e.conf.Name, ep.param.RelatedEndpoint)
		if err != nil {
			x.remember(a, ep, nil, Unresolved)
			proven = false
			continue
		}
		lr := LostResponse{AbsentBefore: ep.obs == nil, Serialized: true, Preconfigured: ep.e.conf.IsPreconfigured, Found: found}
		if ep.e.conf.IsPreconfigured && len(found) == 1 {
			lr.RelatedEndpointOurs = x.relatedIsOurs(ctx, t, found[0].NodeID, ep.param.RelatedEndpoint)
		}
		class, absent := ResolveLostResponse(lr, x.m.opts.ApplicationURI, x.m.opts.ExclusiveApplicationURI)
		switch {
		case absent && holdAbsent(ep):
			x.remember(a, ep, nil, Unresolved)
			proven = false
			continue
		case absent:
			continue
		case class == Unresolved:
			proven = false
		}
		x.remember(a, ep, found[0].NodeID, class)
	}
	x.evidence(ctx, t, a, eps)
	return proven
}

// inconclusive returns an error wrapping errAmbiguous when the result res
// of an EstablishConnections of n endpoint configurations does not prove
// its outcome (decision C3-D13): an ambiguous status of the call or of one
// of its operations, or a result that does not have what the call asked
// for (one result per configuration, one communication result with comm,
// with create an endpoint for each configuration that did not fail).
func inconclusive(res *uafx.EstablishConnectionsResult, n int, comm, create bool) error {
	why := func(st ua.StatusCode, format string, args ...any) error {
		return fmt.Errorf("%w: %w: %s", st, errAmbiguous, fmt.Sprintf(format, args...))
	}
	if ambiguousStatus(res.Status) {
		return why(res.Status, "the status of the call")
	}
	if len(res.ConnectionEndpointConfigurationResults) != n {
		return why(ua.StatusBadUnexpectedError, "%d results for %d endpoint configurations", len(res.ConnectionEndpointConfigurationResults), n)
	}
	if comm && (len(res.CommunicationConfigurationResults) != 1 || res.CommunicationConfigurationResults[0] == nil) {
		return why(ua.StatusBadUnexpectedError, "%d communication results for one configuration", len(res.CommunicationConfigurationResults))
	}
	for _, c := range res.CommunicationConfigurationResults {
		if c == nil {
			continue
		}
		if ambiguousStatus(c.Result) {
			return why(c.Result, "the communication result")
		}
		for _, r := range c.ReferenceResults {
			if ambiguousStatus(r) {
				return why(r, "a reference result")
			}
		}
	}
	failed := false
	for _, r := range res.ConnectionEndpointConfigurationResults {
		if r == nil {
			return why(ua.StatusBadUnexpectedError, "a missing endpoint result")
		}
		sts := []ua.StatusCode{r.FunctionalEntityNodeResult, r.VerificationStatus, r.ConnectionEndpointResult, r.CommunicationLinksResult, r.EnableCommunicationResult}
		sts = append(append(append(sts, r.EstablishControlResult...), r.ConfigurationDataResult...), r.ReassignControlResult...)
		for _, st := range sts {
			if ambiguousStatus(st) {
				return why(st, "an endpoint result")
			}
			failed = failed || bad(st)
		}
	}
	if create && res.Status == ua.StatusGood && !failed {
		for _, r := range res.ConnectionEndpointConfigurationResults {
			if orNil(r.ConnectionEndpointID) == nil {
				return why(ua.StatusBadUnexpectedError, "a created endpoint without its NodeId")
			}
		}
	}
	return nil
}

// identify reads the identity of the server of t when the Manager keeps
// records (design §6.5).
func (x *run) identify(ctx context.Context, t *target) {
	if x.store() != nil {
		t.identify(ctx)
	}
}

// evidence reads, with a Store, the ConnectionManagerApplicationUri and
// the Diagnostics CreationTime (§6.6.2 Table 74) of the endpoints of eps
// the run remembered with a NodeId, the evidence of design §6.5 that a
// restart cannot read back. What the AutomationComponent does not expose,
// or a read that fails, stays empty in the record: it is evidence absent,
// never evidence of absence.
func (x *run) evidence(ctx context.Context, t *target, a *acRun, eps []*epRun) {
	if x.store() == nil || t == nil {
		return
	}
	for _, ep := range eps {
		rk := recordKey(a.addr, ep.fe, ep.e.conf.Name)
		x.s.mu.Lock()
		rec := x.s.records[rk]
		var n *ua.NodeID
		if rec != nil && rec.Run == x.r.id {
			n = rec.NodeID
		}
		x.s.mu.Unlock()
		if n == nil {
			continue
		}
		cm, cmOK, created, err := endpointEvidence(ctx, t, n)
		if err != nil {
			x.m.log.Debug("fxcm: the evidence of an endpoint was not read", "set", x.r.key.String(), "run", x.r.id, "endpoint", ep.e.conf.Name, "error", err)
			continue
		}
		x.s.mu.Lock()
		if x.s.records[rk] == rec {
			rec.cmURI, rec.cmObserved, rec.created = cm, cmOK, created
		}
		x.s.mu.Unlock()
		x.touchAC(a, rk, rec)
	}
}

// endpointEvidence reads the ConnectionManagerApplicationUri and the
// Diagnostics CreationTime of the endpoint n (§6.6.2 Table 74); cmOK says
// the first was read, a zero created that the second is not exposed.
func endpointEvidence(ctx context.Context, t *target, n *ua.NodeID) (cm string, cmOK bool, created time.Time, err error) {
	acNS, err := t.acNamespace()
	if err != nil {
		return "", false, time.Time{}, err
	}
	props, err := t.children(ctx, n)
	if err != nil {
		return "", false, time.Time{}, err
	}
	read := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	cmNode := child(props, acNS, "ConnectionManagerApplicationUri")
	if cmNode != nil {
		read.NodesToRead = append(read.NodesToRead, &ua.ReadValueID{NodeID: cmNode, AttributeID: ua.AttributeIDValue})
	}
	var ctNode *ua.NodeID
	// The Diagnostics has the BrowseName of its InstanceDeclaration, in
	// the DI namespace (OPC 10000-81 §6.6.2 Table 74); its CreationTime is
	// in the AutomationComponent's.
	var d *ua.NodeID
	if di := slices.Index(t.nsa, diid.NamespaceURI); di > 0 && di <= math.MaxUint16 {
		d = child(props, uint16(di), "Diagnostics")
	}
	if d != nil {
		dprops, err := t.children(ctx, d)
		if err != nil {
			return "", false, time.Time{}, err
		}
		ctNode = child(dprops, acNS, "CreationTime")
		if ctNode != nil {
			read.NodesToRead = append(read.NodesToRead, &ua.ReadValueID{NodeID: ctNode, AttributeID: ua.AttributeIDValue})
		}
	}
	if len(read.NodesToRead) == 0 {
		return "", false, time.Time{}, nil
	}
	res, err := t.sess.Read(ctx, read)
	if err != nil {
		return "", false, time.Time{}, err
	}
	if len(res.Results) != len(read.NodesToRead) {
		return "", false, time.Time{}, fmt.Errorf("fxcm: Read: %d results", len(res.Results))
	}
	i := 0
	if cmNode != nil {
		cm, cmOK = dvValue(res.Results[0]).(string)
		i++
	}
	if ctNode != nil {
		created, _ = dvValue(res.Results[i]).(time.Time)
	}
	return cm, cmOK, created, nil
}

func (x *run) relatedIsOurs(ctx context.Context, t *target, n *ua.NodeID, ours *uafx.RelatedEndpoint) bool {
	acNS, err := t.acNamespace()
	if err != nil {
		return false
	}
	props, err := t.children(ctx, n)
	if err != nil {
		return false
	}
	c := child(props, acNS, "RelatedEndpoint")
	if c == nil {
		return false
	}
	res, err := t.sess.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: c, AttributeID: ua.AttributeIDValue}}})
	if err != nil || len(res.Results) != 1 {
		return false
	}
	return sameRelated(relatedOf(t, dvStructure(res.Results[0])), ours)
}

// configureWaves orders the configure step (§6.16.3, §6.2.6). An AC with
// CommandBundleRequired cannot take the call that adapts its subscribers
// to the PublisherId a matched PubSubConnection has (adaptSubscribers), so
// it is configured after the ACs whose flows it subscribes to, with the
// PublisherIds their calls returned (resolvePublishers). Every other AC is
// configured in the first wave, in parallel. Bundled ACs that subscribe to
// each other in a cycle cannot wait for each other: when no other AC can
// go, the members of the cycles go together in one wave, and a mismatch
// among them fails as in adaptOn; the ACs that wait on a cycle still go
// after it. A bundled AC that subscribes to itself does not wait for
// itself.
func (x *run) configureWaves(acs []*acRun) [][]*acRun {
	pending := map[*acRun]bool{}
	for _, a := range acs {
		pending[a] = true
	}
	// deps are the pending ACs a bundled AC subscribes to, but itself.
	deps := func(a *acRun) []*acRun {
		if !a.bundle {
			return nil
		}
		var ds []*acRun
		for _, ep := range a.eps {
			if as := ep.assumedPublisher; as != nil && as.a != a && pending[as.a] && !slices.Contains(ds, as.a) {
				ds = append(ds, as.a)
			}
		}
		return ds
	}
	// inCycle reports whether a reaches itself over deps.
	inCycle := func(a *acRun) bool {
		seen := map[*acRun]bool{}
		next := deps(a)
		for len(next) > 0 {
			d := next[len(next)-1]
			next = next[:len(next)-1]
			if d == a {
				return true
			}
			if !seen[d] {
				seen[d] = true
				next = append(next, deps(d)...)
			}
		}
		return false
	}
	var waves [][]*acRun
	for len(pending) > 0 {
		var wave []*acRun
		for _, a := range acs {
			if pending[a] && len(deps(a)) == 0 {
				wave = append(wave, a)
			}
		}
		if len(wave) == 0 {
			for _, a := range acs {
				if pending[a] && inCycle(a) {
					wave = append(wave, a)
				}
			}
		}
		for _, a := range wave {
			delete(pending, a)
		}
		waves = append(waves, wave)
	}
	return waves
}

// resolvePublishers sets the DataSetReaders of the bundled ACs of a wave
// to the PublisherIds their publishers' PubSubConnections have after an
// earlier wave (§6.16.3), before their single call (configureWaves).
func (x *run) resolvePublishers(wave []*acRun) {
	for _, a := range wave {
		if !a.bundle {
			continue
		}
		for _, ep := range a.eps {
			as := ep.assumedPublisher
			if as == nil || as.a == a || ep.failed() || !as.a.configured {
				continue
			}
			actual := as.conn.PublisherID
			if isNullID(actual) || sameVariant(actual, as.id) {
				continue
			}
			if rd := readerAt(a.comm.cfg, ep.links.DataSetReaderRef); rd != nil {
				rd.PublisherID, as.id = actual, actual
			}
		}
	}
}

// adaptSubscribers adapts the subscribers to the PublisherIds their
// publishers' PubSubConnections have after the configure step (§6.16.3: a
// PubSubConnection that matched an existing one has that one's
// PublisherId, and the ConnectionManager adapts the subscribers'
// configuration to the PublisherIds returned). A DataSetReader that was
// configured with another PublisherId is modified on its AC in one more
// EstablishConnections call, per AC, with SetCommunicationConfigurationCmd
// for the endpoints created before (ConnectionEndpointDefinition Node,
// Table 79) and ElementModify of the readers (OPC 10000-14 Table 241), and
// EnableCommunicationCmd for an enabled establish. An AC with
// CommandBundleRequired takes SetCommunicationConfigurationCmd only with
// CreateConnectionEndpointCmd (§6.2.6): it is configured after its
// publishers with their PublisherIds (configureWaves), and only a
// subscriber that could not wait (in a cycle of bundled ACs, or on its own
// flow) is left to adapt here: its Connection fails with
// SetCommunicationConfigurationError and Bad_ConfigurationError.
func (x *run) adaptSubscribers(ctx context.Context) {
	byAC := map[*acRun][]*epRun{}
	var acs []*acRun
	for _, ep := range x.eps {
		as := ep.assumedPublisher
		if as == nil || ep.failed() {
			continue
		}
		actual := as.conn.PublisherID
		if isNullID(actual) || sameVariant(actual, as.id) {
			continue
		}
		rd := readerAt(ep.a.comm.cfg, ep.links.DataSetReaderRef)
		if rd == nil {
			continue
		}
		rd.PublisherID, as.id = actual, actual
		if byAC[ep.a] == nil {
			acs = append(acs, ep.a)
		}
		byAC[ep.a] = append(byAC[ep.a], ep)
	}
	x.parallel(ctx, acs, func(ctx context.Context, a *acRun) {
		x.adaptOn(ctx, a, byAC[a])
	})
}

// adaptOn modifies the DataSetReaders of eps on a (adaptSubscribers).
func (x *run) adaptOn(ctx context.Context, a *acRun, eps []*epRun) {
	defer x.syncStep(a)
	failAll := func(st ua.StatusCode) {
		for _, ep := range eps {
			x.fail(ep, Failure{FxError: uafx.FxErrorSetCommunicationConfigurationError, Status: st})
		}
	}
	if a.bundle {
		failAll(ua.StatusBadConfigurationError)
		return
	}
	req := &uafx.EstablishConnectionsRequest{CommandMask: uafx.SetCommunicationConfigurationCmd}
	var refs []*ua.PubSubConfigurationRefDataType
	for _, ep := range eps {
		x.s.mu.Lock()
		rec := x.s.records[recordKey(a.addr, ep.fe, ep.e.conf.Name)]
		x.s.mu.Unlock()
		if rec == nil || rec.NodeID == nil {
			failAll(ua.StatusBadInvalidState)
			return
		}
		r := *ep.links.DataSetReaderRef
		r.ConfigurationMask = ua.PubSubConfigurationRefMaskReferenceReader | ua.PubSubConfigurationRefMaskElementModify
		refs = append(refs, &r)
		req.ConnectionEndpointConfigurations = append(req.ConnectionEndpointConfigurations, &uafx.ConnectionEndpointConfiguration{
			FunctionalEntityNode: ep.fe,
			ConnectionEndpoint:   &uafx.ConnectionEndpointDefinition{Node: rec.NodeID},
			// The links of the endpoint as created (§10.13.3, Table 16:
			// they name the reader and writer its Mode needs).
			CommunicationLinks: ep.links,
		})
	}
	req.CommunicationConfigurations = []*uafx.PubSubCommunicationConfiguration{{
		PubSubConfiguration: a.comm.cfg, RequireCompleteUpdate: true, ConfigurationReferences: refs,
	}}
	if x.r.action == uafx.ActionEstablishConnectionsEnabled {
		req.CommandMask |= uafx.EnableCommunicationCmd
	}
	res, err, unknown := x.call(ctx, a, req)
	if !unknown && err == nil {
		if why := inconclusive(res, len(eps), true, false); why != nil {
			unknown, err = true, why
		}
	}
	if unknown {
		// Decision C3-D13: the intent stays, the outcome is not proven.
		x.retain(a.lastIntent)
	}
	switch {
	case err != nil:
		failAll(StatusOf(err))
	case res.Status != ua.StatusGood:
		failAll(res.Status)
	default:
		x.adapted(eps, res)
	}
}

// adapted checks the nested results of a Good adaptation call (Table 21):
// the PubSubCommunicationConfigurationResult of the one configuration, its
// ReferenceResult for the reader of each endpoint (one reference per
// endpoint, in order, as CloseAndUpdate returns them, OPC 10000-14
// §9.1.3.7.4), and the result of each endpoint. A result that is missing
// is Bad_UnexpectedError.
func (x *run) adapted(eps []*epRun, res *uafx.EstablishConnectionsResult) {
	failEp := func(ep *epRun, fx uafx.FxError, st ua.StatusCode) {
		x.fail(ep, Failure{FxError: fx, Status: st})
	}
	var comm *uafx.PubSubCommunicationConfigurationResult
	if len(res.CommunicationConfigurationResults) == 1 {
		comm = res.CommunicationConfigurationResults[0]
	}
	for i, ep := range eps {
		switch {
		case comm == nil:
			failEp(ep, uafx.FxErrorSetCommunicationConfigurationError, ua.StatusBadUnexpectedError)
		case bad(comm.Result):
			failEp(ep, uafx.FxErrorSetCommunicationConfigurationError, comm.Result)
		case i >= len(comm.ReferenceResults):
			failEp(ep, uafx.FxErrorSetCommunicationConfigurationError, ua.StatusBadUnexpectedError)
		case bad(comm.ReferenceResults[i]):
			failEp(ep, uafx.FxErrorSetCommunicationConfigurationError, comm.ReferenceResults[i])
		}
		if i >= len(res.ConnectionEndpointConfigurationResults) || res.ConnectionEndpointConfigurationResults[i] == nil {
			failEp(ep, uafx.FxErrorSetCommunicationConfigurationError, ua.StatusBadUnexpectedError)
		} else if f, ok := elementFailure(res.ConnectionEndpointConfigurationResults[i]); ok {
			x.fail(ep, f)
		}
	}
}

func sameVariant(a, b *ua.Variant) bool {
	x, err1 := ua.Encode(a)
	y, err2 := ua.Encode(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// --- closing ---------------------------------------------------------------

// closeRecords closes recs with CloseConnections (§6.2.5), one call per
// AutomationComponent, in parallel. It returns the error of each record
// that was not closed. A closed record of a removed endpoint is forgotten; a
// record that was not closed gets ClosePending.
func (x *run) closeRecords(ctx context.Context, recs []*record, remove bool) map[*record]error {
	type group struct {
		addr ServerAddress
		ac   *ua.NodeID
		recs []*record
	}
	var groups []*group
	for _, r := range recs {
		var g *group
		for _, o := range groups {
			if o.addr == r.addr && o.ac.Equal(r.acNode) {
				g = o
			}
		}
		if g == nil {
			g = &group{addr: r.addr, ac: r.acNode}
			groups = append(groups, g)
		}
		g.recs = append(g.recs, r)
	}
	errs := map[*record]error{}
	closedGone := map[*record]bool{}
	// unknown are the records whose close has an unknown outcome: their
	// intent stays, and they are Unresolved until the outcome is proven
	// (decision C3-D13), so that no later step closes them again.
	unknown := map[*record]bool{}
	// held are the records incarnation did not prove: not sent, and held
	// as Unresolved or Unverified instead of ClosePending.
	held := map[*record]heldRecord{}
	var intents []string
	recsTouched := touched{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, x.m.opts.Parallelism)
	for _, g := range groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if x.blocked[g.addr.Address] {
				mu.Lock()
				defer mu.Unlock()
				for _, r := range g.recs {
					errs[r] = blockedFailure(uafx.FxErrorCloseConnectionError, g.addr)
				}
				return
			}
			results, k, notSent, err := x.closeOn(ctx, g.addr, g.ac, g.recs, remove)
			mu.Lock()
			defer mu.Unlock()
			if k != "" {
				intents = append(intents, k)
			}
			retained := x.retained(k)
			for i, r := range g.recs {
				if h, ok := notSent[i]; ok {
					held[r] = h
					errs[r] = failure(uafx.FxErrorCloseConnectionError, ua.StatusBadInvalidState, "%v is not the endpoint recorded: %s", r.NodeID, h.why)
					continue
				}
				if retained && (err != nil || ambiguousStatus(results[i])) {
					unknown[r] = true
				}
				e := err
				// Bad_NodeIdUnknown: the endpoint does not exist (Table 24),
				// as after a close whose response was lost or a cleanup:
				// it is closed.
				if e == nil && bad(results[i]) && results[i] != ua.StatusBadNodeIDUnknown {
					e = failure(uafx.FxErrorCloseConnectionError, results[i], "CloseConnections of %v", r.NodeID)
				}
				if e != nil {
					errs[r] = e
				} else if err == nil && results[i] == ua.StatusBadNodeIDUnknown {
					closedGone[r] = true
				}
			}
		}()
	}
	wg.Wait()
	for _, r := range recs {
		x.s.mu.Lock()
		k := recordKey(r.addr, r.FunctionalEntity, r.Name)
		cur := x.s.records[k]
		x.touch(recsTouched, k, r)
		if h, ok := held[r]; ok {
			x.s.mu.Unlock()
			x.hold(r, k, nil, h.class, h.why)
			continue
		}
		if errs[r] != nil {
			if cur != nil {
				cur.ClosePending = true
				if unknown[r] && cur == r {
					cur.Class = Unresolved
				}
			}
		} else if (remove || closedGone[r]) && cur == r {
			delete(x.s.records, k)
		} else if cur != nil {
			cur.ClosePending = false
		}
		cp := r.EndpointRecord
		x.s.mu.Unlock()
		if errs[r] == nil {
			x.mu.Lock()
			x.res.Closed = append(x.res.Closed, cp)
			x.mu.Unlock()
			x.m.observe(Event{Kind: EventEndpoint, Set: x.r.key, Run: x.r.id, Record: &cp, Closed: true})
		}
	}
	x.sync(intents, recsTouched, false)
	return errs
}

// heldRecord is a record closeOn did not send: incarnation's verdict.
type heldRecord struct {
	class Ownership
	why   string
}

// closeOn calls CloseConnections on the AutomationComponent ac of addr for
// the records of recs whose endpoints are proven to be the ones recorded
// (incarnation); the others are in held, by index, and not sent. The
// results are by index of recs.
func (x *run) closeOn(ctx context.Context, addr ServerAddress, ac *ua.NodeID, recs []*record, remove bool) ([]ua.StatusCode, string, map[int]heldRecord, error) {
	t, err := x.openTarget(ctx, addr)
	if err != nil {
		f := failureOf(err, uafx.FxErrorCloseConnectionError)
		return nil, "", nil, failure(uafx.FxErrorCloseConnectionError, f.Status, "%v", err)
	}
	x.identify(ctx, t)
	var held map[int]heldRecord
	var send []int
	for i, r := range recs {
		if class, why := x.incarnation(ctx, t, r); class != 0 {
			if held == nil {
				held = map[int]heldRecord{}
			}
			held[i] = heldRecord{class: class, why: why}
			continue
		}
		send = append(send, i)
	}
	if len(send) == 0 {
		return make([]ua.StatusCode, len(recs)), "", held, nil
	}
	results, k, err := x.closeSent(ctx, t, ac, recs, send, remove)
	return results, k, held, err
}

// closeSent calls CloseConnections for the records send of recs; the
// results are by index of recs.
func (x *run) closeSent(ctx context.Context, t *target, ac *ua.NodeID, recs []*record, send []int, remove bool) ([]ua.StatusCode, string, error) {
	addr, sess := t.addr, t.sess
	_, closeM, _, err := methodsOf(ctx, t, ac)
	if err != nil {
		f := failureOf(err, uafx.FxErrorCloseConnectionError)
		return nil, "", failure(uafx.FxErrorCloseConnectionError, f.Status, "%v", err)
	}
	nodes := make([]*ua.NodeID, len(send))
	prior := make([]Ownership, len(send))
	x.s.mu.Lock()
	for j, i := range send {
		nodes[j], prior[j] = recs[i].NodeID, recs[i].Class
	}
	x.s.mu.Unlock()
	// The intent first: without it nothing is sent (design §6.3).
	k, err := x.intend(closeIntent(t, ac, nodes, prior, remove))
	if err != nil {
		return nil, "", err
	}
	// Decision C3-D13: a lost response, an ambiguous status or a result
	// that does not answer the call proves nothing; the intent stays.
	proven := false
	defer func() {
		if !proven {
			x.retain(k)
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, x.m.opts.CallTimeout)
	defer cancel()
	x.m.counters.close.Add(1)
	ev := Event{Kind: EventCall, Set: x.r.key, Run: x.r.id, Method: "CloseConnections", Address: addr.Address}
	defer func() { x.m.observe(ev) }()
	out, err := sess.Call(cctx, &ua.CallMethodRequest{ObjectID: ac, MethodID: closeM, InputArguments: []*ua.Variant{ua.MustVariant(nodes), ua.MustVariant(remove)}})
	if err != nil {
		x.m.counters.closeFailed.Add(1)
		ev.Err = err
		f := failureOf(err, uafx.FxErrorCloseConnectionError)
		if errors.Is(err, context.DeadlineExceeded) {
			f.Status = ua.StatusBadTimeout
		}
		return nil, k, failure(uafx.FxErrorCloseConnectionError, f.Status, "CloseConnections: %v", err)
	}
	ev.Status = out.StatusCode
	if out.StatusCode != ua.StatusGood {
		x.m.counters.closeFailed.Add(1)
	}
	if bad(out.StatusCode) {
		proven = !ambiguousStatus(out.StatusCode)
		return nil, k, failure(uafx.FxErrorCloseConnectionError, out.StatusCode, "CloseConnections")
	}
	var results []ua.StatusCode
	if len(out.OutputArguments) == 1 && out.OutputArguments[0] != nil {
		results, _ = out.OutputArguments[0].Value().([]ua.StatusCode)
	}
	if len(results) != len(send) {
		return nil, k, failure(uafx.FxErrorCloseConnectionError, ua.StatusBadUnexpectedError, "CloseConnections: %d results for %d endpoints", len(results), len(send))
	}
	proven = !slices.ContainsFunc(results, ambiguousStatus)
	byRec := make([]ua.StatusCode, len(recs))
	for j, i := range send {
		byRec[i] = results[j]
	}
	return byRec, k, nil
}

// closable returns the records of the set that may be closed and the
// Unresolved ones.
func (x *run) closable() (closable, unresolved []*record) {
	x.s.mu.Lock()
	defer x.s.mu.Unlock()
	for _, r := range x.s.records {
		switch {
		case r.Class.MayClose() && r.NodeID != nil:
			closable = append(closable, r)
		case r.Class == Unresolved, r.Class == Unverified:
			unresolved = append(unresolved, r)
		}
	}
	sortRecords(closable)
	sortRecords(unresolved)
	return closable, unresolved
}

func sortRecords(rs []*record) {
	slices.SortFunc(rs, func(a, b *record) int {
		switch {
		case a.Endpoint.Connection != b.Endpoint.Connection:
			if a.Endpoint.Connection < b.Endpoint.Connection {
				return -1
			}
			return 1
		case a.Endpoint.Endpoint != b.Endpoint.Endpoint:
			return a.Endpoint.Endpoint - b.Endpoint.Endpoint
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
}

func (x *run) epOf(ref EndpointRef) *epRun {
	for _, ep := range x.eps {
		if ep.ref() == ref {
			return ep
		}
	}
	return nil
}

// rollback closes every closable endpoint of the set with Remove TRUE
// (§6.8.2, F.1.3, EC-11), within RollbackTimeout. Unresolved endpoints are
// reported, never closed (design §5.5).
func (x *run) rollback(ctx context.Context) {
	if err := x.setPhase(phaseRollbackRequired); err != nil {
		// No rollback close without the durable obligation (design
		// §6.3): the endpoints stay as they are, the rollback owed.
		x.mu.Lock()
		x.j.rollbackOwed = true
		x.res.RolledBack = true
		x.mu.Unlock()
		x.extraFailure(failureOf(err, uafx.FxErrorRuntimeError))
		return
	}
	x.crashPoint("rollback.started")
	recs, unresolved := x.closable()
	x.mu.Lock()
	for _, r := range unresolved {
		if !slices.ContainsFunc(x.res.Unresolved, func(e EndpointRecord) bool { return e.Endpoint == r.Endpoint && e.Name == r.Name }) {
			x.res.Unresolved = append(x.res.Unresolved, r.EndpointRecord)
		}
	}
	if slices.ContainsFunc(unresolved, func(r *record) bool { return r.Run == x.r.id }) {
		// An endpoint of this run that may exist is not closed: the
		// rollback stays owed (design §6.3). Records of earlier runs
		// are not this rollback's.
		x.j.rollbackOwed = true
	}
	x.mu.Unlock()
	if len(recs) == 0 {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), x.m.opts.RollbackTimeout)
	defer cancel()
	errs := x.closeRecords(rctx, recs, true)
	x.mu.Lock()
	x.res.RolledBack = true
	x.res.RollbackComplete = len(errs) == 0
	if len(errs) > 0 {
		x.j.rollbackOwed = true
	}
	x.mu.Unlock()
	for _, r := range recs {
		ep := x.epOf(r.Endpoint)
		if ep == nil {
			continue
		}
		if err := errs[r]; err != nil {
			x.failErr(ep, err, uafx.FxErrorCloseConnectionError)
			continue
		}
		x.setOutcome(ep, RolledBack)
	}
}

// closeRun is a Remove (remove) or Disable run (§6.7.5.3.2, §6.7.5.3.4):
// CloseConnections for every closable endpoint of the set; a failure does
// not stop the others (EC-15). An Unresolved endpoint is not closed; in a
// remove run its Connection fails with CloseConnectionError and
// Bad_InvalidState, so that the set is not removed while it may have
// Connections (design §5.4).
func (x *run) closeRun(ctx context.Context, remove bool) {
	recs, unresolved := x.closable()
	for _, r := range unresolved {
		x.mu.Lock()
		x.res.Unresolved = append(x.res.Unresolved, r.EndpointRecord)
		x.mu.Unlock()
		if remove {
			if ep := x.epOf(r.Endpoint); ep != nil {
				x.fail(ep, Failure{FxError: uafx.FxErrorCloseConnectionError, Status: ua.StatusBadInvalidState})
			} else {
				x.extraFailure(Failure{FxError: uafx.FxErrorCloseConnectionError, Status: ua.StatusBadInvalidState})
			}
		}
	}
	if len(recs) == 0 {
		return
	}
	errs := x.closeRecords(ctx, recs, remove)
	for _, r := range recs {
		err := errs[r]
		ep := x.epOf(r.Endpoint)
		switch {
		case err != nil && ep != nil:
			x.failErr(ep, err, uafx.FxErrorCloseConnectionError)
		case err != nil:
			x.extraFailure(failureOf(err, uafx.FxErrorCloseConnectionError))
		}
	}
}

// extraFailure records a failure of an endpoint that the current Config no
// longer has (an earlier Version's): the run fails without a Connection to
// report it on.
func (x *run) extraFailure(f Failure) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.res.Failures = append(x.res.Failures, f)
}

// enableRun is an Enable run (§6.7.5.3.3): EstablishConnections with
// EnableCommunicationCmd for the closable endpoints of the set, one call
// per AutomationComponent.
func (x *run) enableRun(ctx context.Context) {
	recs, unresolved := x.closable()
	x.mu.Lock()
	for _, r := range unresolved {
		x.res.Unresolved = append(x.res.Unresolved, r.EndpointRecord)
	}
	x.mu.Unlock()
	type group struct {
		addr ServerAddress
		ac   *ua.NodeID
		recs []*record
	}
	var groups []*group
	for _, r := range recs {
		var g *group
		for _, o := range groups {
			if o.addr == r.addr && o.ac.Equal(r.acNode) {
				g = o
			}
		}
		if g == nil {
			g = &group{addr: r.addr, ac: r.acNode}
			groups = append(groups, g)
		}
		g.recs = append(g.recs, r)
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, x.m.opts.Parallelism)
	for _, g := range groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			x.enableOn(ctx, g.addr, g.ac, g.recs)
		}()
	}
	wg.Wait()
}

func (x *run) enableOn(ctx context.Context, addr ServerAddress, ac *ua.NodeID, recs []*record) {
	failAll := func(f Failure) {
		for _, r := range recs {
			if ep := x.epOf(r.Endpoint); ep != nil {
				x.fail(ep, f)
			} else {
				x.extraFailure(f)
			}
		}
	}
	if x.blocked[addr.Address] {
		failAll(failureOf(blockedFailure(uafx.FxErrorEnableCommunicationError, addr), uafx.FxErrorEnableCommunicationError))
		return
	}
	t, err := x.openTarget(ctx, addr)
	if err != nil {
		failAll(failureOf(err, uafx.FxErrorTargetServerConnectionError))
		return
	}
	a := &acRun{addr: addr, node: ac, t: t}
	x.identify(ctx, a.t)
	if err := x.methods(ctx, a); err != nil {
		failAll(failureOf(err, uafx.FxErrorEnableCommunicationError))
		return
	}
	defer x.syncStep(a)
	// Only the endpoints proven to be the ones recorded are enabled
	// (incarnation, §6.5); the others are held and not sent.
	sent := recs[:0:0]
	for _, r := range recs {
		class, why := x.incarnation(ctx, a.t, r)
		if class == 0 {
			sent = append(sent, r)
			continue
		}
		x.hold(r, recordKey(r.addr, r.FunctionalEntity, r.Name), a, class, why)
		f := Failure{FxError: uafx.FxErrorEnableCommunicationError, Status: ua.StatusBadInvalidState}
		if ep := x.epOf(r.Endpoint); ep != nil {
			x.fail(ep, f)
		} else {
			x.extraFailure(f)
		}
	}
	if recs = sent; len(recs) == 0 {
		return
	}
	req := &uafx.EstablishConnectionsRequest{CommandMask: uafx.EnableCommunicationCmd}
	for _, r := range recs {
		req.ConnectionEndpointConfigurations = append(req.ConnectionEndpointConfigurations, &uafx.ConnectionEndpointConfiguration{
			FunctionalEntityNode: r.FunctionalEntity,
			ConnectionEndpoint:   &uafx.ConnectionEndpointDefinition{Node: r.NodeID},
		})
	}
	res, err, unknown := x.call(ctx, a, req)
	if !unknown && err == nil {
		if why := inconclusive(res, len(recs), false, false); why != nil {
			unknown, err = true, why
		}
	}
	switch {
	case unknown:
		// Decision C3-D13: the intent stays, the outcome is not proven;
		// with a Store the records are Unresolved until the re-proof of
		// the outcome (proveOutcome) or Settle decides them, so that no
		// later step enables them again or builds on them.
		x.retain(a.lastIntent)
		if a.lastIntent != "" {
			x.s.mu.Lock()
			for _, r := range recs {
				if cur := x.s.records[recordKey(r.addr, r.FunctionalEntity, r.Name)]; cur == r {
					r.Class = Unresolved
				}
			}
			x.s.mu.Unlock()
			for _, r := range recs {
				x.touchAC(a, recordKey(r.addr, r.FunctionalEntity, r.Name), r)
			}
		}
		f := failureOf(err, uafx.FxErrorEnableCommunicationError)
		if !errors.Is(err, errAmbiguous) && f.Status != ua.StatusBadTimeout {
			f.Status = ua.StatusBadCommunicationError
		}
		failAll(Failure{FxError: uafx.FxErrorEnableCommunicationError, Status: f.Status})
		return
	case err != nil:
		failAll(Failure{FxError: uafx.FxErrorEnableCommunicationError, Status: StatusOf(err)})
		return
	}
	for i, r := range recs {
		ep := x.epOf(r.Endpoint)
		var f Failure
		ok := false
		if i < len(res.ConnectionEndpointConfigurationResults) && res.ConnectionEndpointConfigurationResults[i] != nil {
			f, ok = elementFailure(res.ConnectionEndpointConfigurationResults[i])
		}
		if !ok && res.Status != ua.StatusGood {
			f, ok = Failure{FxError: uafx.FxErrorEnableCommunicationError, Status: res.Status}, true
		}
		switch {
		case ok && ep != nil:
			x.fail(ep, f)
		case ok:
			x.extraFailure(f)
		}
	}
}

// reconcileRun is a Reconcile run: it closes the closable endpoints the
// committed Config does not need (another Version's, a close pending, the
// survivors of a failed run), and checks the Unresolved ones again: one
// that disappeared is forgotten.
func (x *run) reconcileRun(ctx context.Context, prev State) {
	if err := x.setPhase(phaseReconciling); err != nil {
		// No close without the run's record of it (design §6.3).
		x.extraFailure(failureOf(err, uafx.FxErrorRuntimeError))
		return
	}
	recs, unresolved := x.closable()
	var toClose []*record
	for _, r := range recs {
		needed := x.epOf(r.Endpoint) != nil && x.epOf(r.Endpoint).e.conf.Name == r.Name
		if !needed || r.ClosePending || prev == StateError {
			toClose = append(toClose, r)
		}
	}
	if len(toClose) > 0 {
		errs := x.closeRecords(ctx, toClose, true)
		for _, r := range toClose {
			if err := errs[r]; err != nil {
				if ep := x.epOf(r.Endpoint); ep != nil {
					x.failErr(ep, err, uafx.FxErrorCloseConnectionError)
				} else {
					x.extraFailure(failureOf(err, uafx.FxErrorCloseConnectionError))
				}
			}
		}
	}
	for _, r := range unresolved {
		if r.Class == Unverified {
			// Reported, not rechecked: its verification is the
			// re-proof of design §6.5.
			x.mu.Lock()
			x.res.Unresolved = append(x.res.Unresolved, r.EndpointRecord)
			x.mu.Unlock()
			continue
		}
		gone, err := x.recheck(ctx, r)
		if p := x.store(); gone && err == nil && p != nil && p.heldName(x.r.key, r.addr, r.Name) {
			// An intent whose outcome is not proven holds the Name:
			// absent now proves nothing (decision C3-D13).
			gone = false
		}
		switch {
		case err != nil || !gone:
			x.mu.Lock()
			x.res.Unresolved = append(x.res.Unresolved, r.EndpointRecord)
			x.mu.Unlock()
		default:
			x.forget(nil, recordKey(r.addr, r.FunctionalEntity, r.Name))
		}
	}
}

// recheck reports whether the endpoint of an Unresolved record is gone; a
// record without NodeId gets the one found.
func (x *run) recheck(ctx context.Context, r *record) (gone bool, err error) {
	sess, err := x.m.pool.get(ctx, r.addr)
	if err != nil {
		return false, err
	}
	t := &target{addr: r.addr, sess: sess, cache: x.m.res.of(r.addr)}
	if err := t.open(ctx); err != nil {
		x.m.pool.drop(ctx, r.addr, sess)
		return false, err
	}
	found, err := observeName(ctx, t, r.FunctionalEntity, r.Name, nil)
	if err != nil {
		return false, err
	}
	if len(found) == 0 {
		return true, nil
	}
	x.s.mu.Lock()
	if r.NodeID == nil {
		r.NodeID = found[0].NodeID
	}
	x.s.mu.Unlock()
	return false, nil
}

// --- the end of a run -----------------------------------------------------

// finish takes the transition at the end of the run (§6.9.2), updates the
// diagnostics (§10.19) and the counters, and schedules a retry.
func (x *run) finish() *RunResult {
	if x.store() != nil {
		// A Replace or Remove whose closes succeeded keeps its run
		// record until the switch is written (design §6.2). One whose
		// closes failed after some had a remote effect (a close that
		// succeeded, or one whose outcome is unknown) keeps it too,
		// with its set change, as owed work: what it closed cannot be
		// undone (Table 24), so the transaction is not abandoned.
		// Only one that failed before any remote effect is.
		removeSet := x.r.action == ActionRemoveSet
		failed := x.anyFailed()
		x.mu.Lock()
		failed = failed || len(x.res.Failures) > 0
		switching := removeSet && !failed
		x.j.keep = switching || removeSet && x.remoteEffectLocked()
		x.mu.Unlock()
		x.sync(nil, nil, true)
		if !switching {
			// What the run leaves in the store is owed work now; a
			// RemoveSet record whose closes all succeeded stays the
			// Manager's until it writes the switch.
			p := x.store()
			p.activate(x.r.id, false)
			unlock := p.lockJournal(x.s)
			p.refreshOwed()
			unlock()
		}
	}
	x.mu.Lock()
	stopped := x.stopped
	for _, ep := range x.eps {
		if ep.outcome == nil {
			k := Succeeded
			if stopped {
				k = Stopped
			}
			ep.outcome = &Outcome{Kind: k}
		}
		if ep.outcome.Kind == Failed {
			x.res.Failures = append(x.res.Failures, Failure{FxError: ep.outcome.FxError, Status: ep.outcome.Status})
		}
	}
	failed := len(x.res.Failures) > 0
	x.mu.Unlock()

	monitored := x.m.opts.Monitor != nil
	s := x.s
	s.mu.Lock()
	tr, _ := Finish(StateProcessing, failed)
	s.state = tr.To()
	action := x.r.action
	if action == ActionRemoveSet {
		action = uafx.ActionRemoveConnections
	}
	if Activity(action) != 0 && s.cfg == x.cfg {
		for i, cn := range x.cfg.conns {
			eps := x.connectionEps(cn)
			var ep2 *Outcome
			if len(eps) > 1 {
				ep2 = eps[1].outcome
			}
			s.diags[i] = Diagnose(&ua.QualifiedName{Name: cn.name}, action, uafx.ConnectionNotMonitored, *eps[0].outcome, ep2)
		}
	}
	switch x.r.action {
	case uafx.ActionEstablishConnectionsEnabled, uafx.ActionEstablishConnectionsDisabled, uafx.ActionEstablishConnections:
		a := x.r.action
		s.lastEstablish = &a
	case uafx.ActionRemoveConnections:
		s.lastEstablish = nil
	default:
	}
	unresolved := 0
	for _, r := range s.records {
		if r.Class == Unresolved || r.Class == Unverified {
			unresolved++
		}
	}
	x.res.State, x.res.Transition = s.state, tr
	s.transition = tr
	x.res.Diagnostics = s.diagnostics(monitored)
	s.current = nil
	s.last = x.r
	res := x.res
	x.r.result = &res
	retry := x.scheduleRetryLocked(failed, unresolved)
	s.mu.Unlock()
	close(x.r.done)
	x.m.observe(Event{Kind: EventTransition, Set: x.r.key, Run: x.r.id, Transition: tr, Action: x.r.action})
	if retry > 0 {
		x.m.observe(Event{Kind: EventRetry, Set: x.r.key, Run: x.r.id, Attempt: s.retries})
	}
	return &res
}

func (x *run) connectionEps(cn *connection) []*epRun {
	var out []*epRun
	for _, ep := range x.eps {
		if ep.e.conn == cn {
			out = append(out, ep)
		}
	}
	return out
}

// scheduleRetryLocked schedules the next attempt of a failed establish run
// when the RetryPolicy and RetryAllowed allow it, and returns its delay.
func (x *run) scheduleRetryLocked(failed bool, unresolved int) time.Duration {
	p, s := x.m.opts.Retry, x.s
	switch x.r.action {
	case uafx.ActionEstablishConnectionsEnabled, uafx.ActionEstablishConnectionsDisabled, uafx.ActionEstablishConnections:
	default:
		return 0
	}
	if p == nil || !failed || s.removed || !RetryAllowed(x.res.Failures, unresolved) || s.retries >= p.Attempts {
		return 0
	}
	d := p.Initial << s.retries
	if d > p.Max || d <= 0 {
		d = p.Max
	}
	d += time.Duration(rand.Int64N(int64(d)/5 + 1))
	s.retries++
	key, action := x.r.key, x.r.action
	m := x.m
	s.retry = time.AfterFunc(d, func() { m.start(key, action, true) })
	return d
}
