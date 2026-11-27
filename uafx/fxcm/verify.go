// SPDX-License-Identifier: MIT

package fxcm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The verification of the records a Manager with a Store loaded (design
// docs/design/uafx-persistent-connections.md §6.4, §6.5, decision C3-D5):
// read-only on the AutomationComponents, bounded per server by a deadline
// and in concurrency, retried with a bounded backoff while a server cannot
// be reached, and cancelled by Close. Every verdict is durable before it is
// the record's (§6.2). A record is KnownOwned or TakenPreconfigured again
// only on the evidence of §6.5; a failed Browse or Read leaves it
// Unverified, never absent.

// Defaults of VerifyOptions (design §6.4).
const (
	DefaultVerifyTimeout      = 30 * time.Second
	DefaultVerifyRetryInitial = time.Second
	DefaultVerifyRetryMax     = time.Minute
)

// VerifyOptions configure the verification of the endpoint records a
// Manager with a Store loads (design §6.4).
type VerifyOptions struct {
	// Timeout bounds one attempt on one server. 0: DefaultVerifyTimeout.
	Timeout time.Duration
	// Parallelism bounds the servers verified at the same time. 0:
	// Options.Parallelism.
	Parallelism int
	// RetryInitial and RetryMax bound the backoff between the attempts on
	// a server that could not be verified: doubled after each attempt up
	// to RetryMax. 0: DefaultVerifyRetryInitial, DefaultVerifyRetryMax.
	RetryInitial time.Duration
	RetryMax     time.Duration
	// Manual: no verification in the background; the records of a set are
	// verified by the first step of a run on it (Process, Reconcile).
	Manual bool
}

// proof is the verdict of the re-proof of one record.
type proof struct {
	// class is the class the evidence proves; Unverified when the
	// evidence could not be read (err).
	class Ownership
	// drop: the endpoint is verifiably absent, or Foreign: the record
	// goes, nothing is closed.
	drop bool
	// node is the endpoint the browse found, nil for none.
	node *ua.NodeID
	// The evidence read from it (endpointEvidence) and its parameter.
	cm      string
	cmOK    bool
	created time.Time
	param   storedParam
	read    bool
	why     string
	err     error
}

func (p proof) String() string {
	switch {
	case p.err != nil:
		return "Unverified: " + p.err.Error()
	case p.drop:
		return "dropped: " + p.why
	case p.why != "":
		return p.class.String() + ": " + p.why
	}
	return p.class.String()
}

// actual is what an AutomationComponent shows of an endpoint: its
// parameter (§6.6.2 Table 73, §6.6.3), its DataSetReader and DataSetWriter
// (ToDataSetReader, ToDataSetWriter) and the ControlGroups it controls
// (Controls, §6.5.2).
type actual struct {
	param          storedParam
	related        *uafx.RelatedEndpoint
	reader, writer *ua.NodeID
	// readerName and writerName are the BrowseNames of reader and writer.
	readerName, writerName string
	controls               []*ua.NodeID
}

// readActual reads the endpoint n of t (§6.6.2 Table 73: Mode,
// InputVariables, OutputVariables, IsPersistent, CleanupTimeout,
// RelatedEndpoint as Properties in the AC namespace; the References
// ToDataSetReader, ToDataSetWriter and Controls). A Variable the endpoint
// does not have is an error: a configuration that cannot be read is not a
// configuration that matches.
func readActual(ctx context.Context, t *target, n *ua.NodeID) (*actual, error) {
	acNS, err := t.acNamespace()
	if err != nil {
		return nil, err
	}
	res, err := t.sess.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: n, BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.References), IncludeSubtypes: true,
		ResultMask: uint32(ua.BrowseResultMaskAll),
	}}})
	if err != nil {
		return nil, err
	}
	if len(res.Results) != 1 || res.Results[0] == nil {
		return nil, fmt.Errorf("fxcm: Browse of %v: %d results", n, len(res.Results))
	}
	if sc := res.Results[0].StatusCode; sc != ua.StatusOK {
		return nil, sc
	}
	refs := res.Results[0].References
	a := &actual{}
	isRef := func(r *ua.ReferenceDescription, ns uint16, i uint32) bool {
		return r.ReferenceTypeID != nil && r.ReferenceTypeID.Namespace() == ns && r.ReferenceTypeID.IntID() == i && r.ReferenceTypeID.Type() != ua.NodeIDTypeString
	}
	for _, r := range refs {
		if r == nil || r.NodeID == nil || r.NodeID.NodeID == nil || !r.IsForward {
			continue
		}
		name := ""
		if r.BrowseName != nil {
			name = r.BrowseName.Name
		}
		switch {
		case isRef(r, acNS, fxacid.ToDataSetReader):
			a.reader, a.readerName = r.NodeID.NodeID, name
		case isRef(r, acNS, fxacid.ToDataSetWriter):
			a.writer, a.writerName = r.NodeID.NodeID, name
		case isRef(r, 0, id.Controls):
			a.controls = append(a.controls, r.NodeID.NodeID)
		}
	}
	names := []string{"Mode", "InputVariables", "OutputVariables", "IsPersistent", "CleanupTimeout", "RelatedEndpoint"}
	read := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for _, nm := range names {
		c := child(refs, acNS, nm)
		if c == nil {
			return nil, fmt.Errorf("fxcm: the endpoint %v has no %s", n, nm)
		}
		read.NodesToRead = append(read.NodesToRead, &ua.ReadValueID{NodeID: c, AttributeID: ua.AttributeIDValue})
	}
	rr, err := t.sess.Read(ctx, read)
	if err != nil {
		return nil, err
	}
	if len(rr.Results) != len(names) {
		return nil, fmt.Errorf("fxcm: Read: %d results", len(rr.Results))
	}
	for i, dv := range rr.Results {
		// A RelatedEndpoint the session cannot decode comes with
		// Bad_DataTypeIdUnknown and its body; relatedOf decodes it.
		if dv == nil || bad(dv.Status) && (i != 5 || dv.Status != ua.StatusBadDataTypeIDUnknown) {
			return nil, fmt.Errorf("fxcm: the %s of the endpoint %v was not read", names[i], n)
		}
	}
	p := storedParam{Set: true}
	ok := true
	switch v := dvValue(rr.Results[0]).(type) {
	case int32:
		p.Mode = v
	default:
		ok = false
	}
	ins, ok1 := dvValue(rr.Results[1]).([]*ua.NodeID)
	outs, ok2 := dvValue(rr.Results[2]).([]*ua.NodeID)
	persistent, ok4 := dvValue(rr.Results[3]).(bool)
	p.IsPersistent = persistent
	ct, ok3 := dvValue(rr.Results[4]).(float64)
	if !ok || !ok4 || !ok1 && dvValue(rr.Results[1]) != nil || !ok2 && dvValue(rr.Results[2]) != nil || !ok3 {
		return nil, fmt.Errorf("fxcm: the parameter of the endpoint %v has values of other types", n)
	}
	p.CleanupTimeout = ct
	for _, x := range ins {
		p.Inputs = append(p.Inputs, qualify(x, t.nsa))
	}
	for _, x := range outs {
		p.Outputs = append(p.Outputs, qualify(x, t.nsa))
	}
	if eo := dvStructure(rr.Results[5]); eo != nil {
		a.related = relatedOf(t, eo)
		if a.related == nil {
			return nil, fmt.Errorf("fxcm: the RelatedEndpoint of the endpoint %v does not decode", n)
		}
		if !nullRelated(a.related) {
			if b, err := ua.Encode(a.related); err == nil {
				p.Related = b
			}
		}
	}
	a.param = p
	return a, nil
}

// sameParam reports whether the parameters a and b are equal: the
// Variables by their namespace-qualified NodeIds (§6.1), a RelatedEndpoint
// that is null like none.
func sameParam(a, b storedParam) bool {
	if !a.Set || !b.Set || a.Mode != b.Mode || a.IsPersistent != b.IsPersistent || !sameDuration(a.CleanupTimeout, b.CleanupTimeout) {
		return false
	}
	same := func(x, y []*qualifiedID) bool {
		return slices.EqualFunc(x, y, func(p, q *qualifiedID) bool { return p.String() == q.String() })
	}
	if !same(a.Inputs, b.Inputs) || !same(a.Outputs, b.Outputs) {
		return false
	}
	ra, err1 := a.related()
	rb, err2 := b.related()
	switch {
	case err1 != nil || err2 != nil:
		return false
	case ra == nil || nullRelated(ra):
		return rb == nil || nullRelated(rb)
	case rb == nil:
		return false
	}
	return sameRelated(ra, rb)
}

// sameDuration compares two CleanupTimeouts: every negative value means
// that the cleanup is disabled (§6.6.2).
func sameDuration(a, b float64) bool {
	if a < 0 && b < 0 {
		return true
	}
	return a == b || math.IsInf(a, 1) && math.IsInf(b, 1)
}

// sameServer compares the identity cur of the server of a session with
// the identity rec a record was made with (design §6.5): the same
// ApplicationUri, and the same certificate thumbprint when the record was
// authenticated. Evidence is compared like for like: a reported identity is
// never taken for an authenticated one. retry is set when the session
// cannot show the evidence the record has (no authenticated channel now):
// the record stays Unverified. A record made over a secured channel without
// authenticated evidence is never re-proved by the ApplicationUri the
// server reports (design §6.5: the thumbprint when the record was made
// over a secured channel): the evidence it lacks cannot be read back.
func sameServer(rec, cur serverEvidence) (ok, retry bool, why string) {
	switch {
	case rec.Source == identityUnavailable || rec.ApplicationURI == "":
		return false, false, "the record has no identity of its server"
	case rec.Secured && rec.Source != identityAuthenticated:
		return false, false, "the record was made over a secured channel without an authenticated identity"
	case cur.ApplicationURI == "":
		return false, true, "the session shows no identity of its server"
	case cur.ApplicationURI != rec.ApplicationURI:
		return false, false, fmt.Sprintf("the server is %q, the record's %q", cur.ApplicationURI, rec.ApplicationURI)
	case rec.Source == identityAuthenticated && cur.Source != identityAuthenticated:
		return false, true, "the record was made over an authenticated channel, the session is not authenticated"
	case rec.Source == identityAuthenticated && !bytes.Equal(rec.Thumbprint, cur.Thumbprint):
		return false, false, "the certificate of the server is another"
	}
	return true, false, ""
}

// current returns the NodeId q on the server of t.
func current(q *qualifiedID, t *target) (*ua.NodeID, error) { return unqualify(q, t.nsa) }

// proveRecord re-proves the loaded record rec, stored as KnownOwned or
// TakenPreconfigured, against the server of t (design §6.5): the server's
// identity, the endpoint of its Name under its FunctionalEntity at its
// NodeId, a ConnectionManagerApplicationUri that does not contradict ours,
// the incarnation (CreationTime, or ExclusiveApplicationURI without it),
// and the configuration (the parameter the record was made with). A
// preconfigured endpoint must also still be preconfigured, free and
// related to the end the record set (Classify).
func (m *Manager) proveRecord(ctx context.Context, t *target, rec *record) proof {
	ok, retry, why := sameServer(rec.server, t.evidenceNow())
	switch {
	case retry:
		return proof{class: Unverified, err: errors.New(why)}
	case !ok:
		return proof{class: Unresolved, why: why}
	}
	fe, err := current(qualify(rec.FunctionalEntity, rec.nsa), t)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	want, err := current(qualify(rec.NodeID, rec.nsa), t)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	ours, _ := rec.param.related()
	found, err := observeName(ctx, t, fe, rec.Name, ours)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	switch {
	case len(found) == 0:
		return proof{drop: true, why: "no endpoint of its Name"}
	case len(found) > 1:
		return proof{class: Unresolved, why: "more than one endpoint of its Name"}
	}
	obs := found[0]
	if !obs.NodeID.Equal(want) {
		// Another endpoint has the Name: not the record's (§6.5).
		if Classify(nil, &obs, m.opts.ApplicationURI) == Unresolved {
			return proof{class: Unresolved, node: obs.NodeID, why: "another endpoint with our ConnectionManagerApplicationUri has its Name"}
		}
		return proof{drop: true, why: "a Foreign endpoint has its Name"}
	}
	if obs.CMApplicationURI != nil && !obs.ours(m.opts.ApplicationURI) {
		// A contradiction wins (§6.5).
		return proof{drop: true, why: "its ConnectionManagerApplicationUri is another"}
	}
	pr := proof{node: obs.NodeID}
	pr.cm, pr.cmOK, pr.created, err = endpointEvidence(ctx, t, obs.NodeID)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	if pr.cmOK && pr.cm != m.opts.ApplicationURI {
		// The later read contradicts ours: it wins over the browse (§6.5).
		return proof{drop: true, why: "its ConnectionManagerApplicationUri is another"}
	}
	act, err := readActual(ctx, t, obs.NodeID)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	pr.param, pr.read = act.param, true
	unresolved := func(why string) proof {
		pr.class, pr.why = Unresolved, why
		return pr
	}
	switch {
	case !rec.created.IsZero() && !pr.created.Equal(rec.created):
		return unresolved("its CreationTime is another")
	case rec.created.IsZero() && !pr.created.IsZero():
		return unresolved("the record has no CreationTime to compare")
	case rec.created.IsZero() && (!m.opts.ExclusiveApplicationURI || !pr.cmOK || pr.cm != m.opts.ApplicationURI):
		return unresolved("no CreationTime, and no ExclusiveApplicationURI with our ConnectionManagerApplicationUri")
	case !sameParam(act.param, rec.param):
		return unresolved("its configuration is not the record's")
	}
	if rec.stored == TakenPreconfigured {
		if !obs.IsPreconfigured || obs.InUse {
			return unresolved("no longer a free preconfigured endpoint")
		}
		pr.class = TakenPreconfigured
		return pr
	}
	pr.class = KnownOwned
	return pr
}

// intentName is a Name of an unended establish intent.
type intentName struct {
	key string
	c   *callRecord
	i   int
}

// proveIntentName decides the Name n of an unended establish intent on the
// server of t (design §6.3, §6.4): the outcome of the call is unknown, so
// it is re-proved as a lost response (ResolveLostResponse, C2 §5.4) with
// the evidence of the intent, never resent. The (AC, FunctionalEntity) was
// serialized for the call, and the fence of the owed call kept every other
// run of this Manager off its server since. Absent proves nothing for a
// persistent endpoint, whose AutomationComponent may restore it (C3-D13),
// nor when the configuration of the call is not the set's any more.
func (m *Manager) proveIntentName(ctx context.Context, t *target, cfg *Config, gen uint64, n intentName) proof {
	c := n.c
	name := c.Names[n.i]
	// The server the call was sent to, by the evidence of the intent: a
	// server replaced at the address proves nothing about the call (§6.5).
	ok, retry, why := sameServer(c.Server, t.evidenceNow())
	switch {
	case retry:
		return proof{class: Unverified, err: errors.New(why)}
	case !ok:
		return proof{class: Unresolved, why: why}
	}
	fe, err := current(c.FunctionalEntities[n.i], t)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	var conf *uafx.ConnectionEndpointConfigurationConf
	var related *uafx.RelatedEndpoint
	if gen == c.Generation {
		for _, cn := range cfg.conns {
			for _, e := range cn.endpoints {
				if e.conf.Name == name {
					conf, related = e.conf, relatedEndpoint(e)
				}
			}
		}
	}
	found, err := observeName(ctx, t, fe, name, related)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	pre, err := current(c.Preconfigured[n.i], t)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	lr := LostResponse{AbsentBefore: c.AbsentBefore[n.i], Serialized: true, Preconfigured: pre != nil, Found: found}
	var act *actual
	if len(found) == 1 {
		if act, err = readActual(ctx, t, found[0].NodeID); err != nil {
			return proof{class: Unverified, err: err}
		}
		lr.RelatedEndpointOurs = related != nil && act.related != nil && sameRelated(act.related, related)
	}
	class, absent := ResolveLostResponse(lr, m.opts.ApplicationURI, m.opts.ExclusiveApplicationURI)
	switch {
	case absent && (conf == nil || conf.IsPersistent):
		return proof{class: Unresolved, why: "absent, which proves nothing for a persistent endpoint or another configuration"}
	case absent:
		return proof{drop: true, why: "the call created nothing"}
	case len(found) != 1:
		return proof{class: Unresolved, why: "more than one endpoint of its Name"}
	}
	pr := proof{class: class, node: found[0].NodeID, param: act.param, read: true}
	switch {
	case class == Unresolved:
		pr.why = "the lost response is not proven"
	case pre != nil && !found[0].NodeID.Equal(pre):
		// The call took the preconfigured endpoint pre: another one with
		// the Name is not its outcome.
		pr.class, pr.why = Unresolved, "not the preconfigured endpoint the call took"
	case n.i < len(c.Params) && c.Params[n.i].Set && !sameParam(act.param, c.Params[n.i]):
		// What the call sent is the intended configuration (§6.5).
		pr.class, pr.why = Unresolved, "its configuration is not the one the call sent"
	}
	if pr.cm, pr.cmOK, pr.created, err = endpointEvidence(ctx, t, found[0].NodeID); err != nil {
		return proof{class: Unverified, err: err}
	}
	if pr.cmOK && pr.cm != m.opts.ApplicationURI && pr.class != Unresolved {
		pr.class, pr.why = Unresolved, "its ConnectionManagerApplicationUri is another"
	}
	return pr
}

// proveOutcome decides the record r, an endpoint the unended close or
// enablement n addressed, by the postcondition of that call (decision
// C3-D13): ownership is re-proved from the class the record had before the
// call (proveRecord, §6.5), on the server the intent names; then a
// CloseConnections with Remove TRUE (§6.2.5.2) is done only when the
// endpoint is verifiably absent, one with Remove FALSE only when its
// DataSetReader and DataSetWriter are disabled, an EnableCommunicationCmd
// (§6.2.4.3.10.2) only when they are not (their Status State, Part 14
// §9.1.10). An endpoint in place whose postcondition does not hold keeps
// the intent and stays Unresolved: nothing sends the call again; Settle
// decides it.
func (m *Manager) proveOutcome(ctx context.Context, t *target, r *record, n intentName) proof {
	c := n.c
	ok, retry, why := sameServer(c.Server, t.evidenceNow())
	switch {
	case retry:
		return proof{class: Unverified, err: errors.New(why)}
	case !ok:
		return proof{class: Unresolved, why: why}
	case n.i >= len(c.Prior) || !Ownership(c.Prior[n.i]).MayClose():
		return proof{class: Unresolved, why: "the intent shows no ownership of the endpoint before the call"}
	}
	if c.Kind == callClose && c.Remove && Ownership(c.Prior[n.i]) == TakenPreconfigured {
		return proveReleased(ctx, t, r)
	}
	cp := *r
	cp.stored = Ownership(c.Prior[n.i])
	pr := m.proveRecord(ctx, t, &cp)
	if pr.err != nil || pr.drop || pr.class == Unresolved {
		// Unverified, verifiably absent (a removal done, nothing left to
		// disable or enable), or not proven.
		return pr
	}
	if c.Kind == callClose && c.Remove {
		pr.class, pr.why = Unresolved, "a CloseConnections of unknown outcome left it in place"
		return pr
	}
	want := commDisabled
	if c.Kind == callEnable {
		want = commEnabled
	}
	st, err := commStateOf(ctx, t, pr.node)
	switch {
	case err != nil:
		return proof{class: Unverified, err: err}
	case st == want:
	case st == commUnknown || st == commNone:
		// No positive evidence: an unreadable State proves neither.
		pr.class, pr.why = Unresolved, "its communication state cannot be read"
	case want == commEnabled:
		pr.class, pr.why = Unresolved, "an EnableCommunicationCmd of unknown outcome left its communication "+st.String()
	default:
		pr.class, pr.why = Unresolved, "a CloseConnections of unknown outcome left its communication "+st.String()
	}
	return pr
}

// proveReleased decides the record r of a preconfigured endpoint that an
// unended CloseConnections with Remove TRUE addressed: such an endpoint is
// not deleted (§6.2.5.2), it is released: its RelatedEndpoint goes and its
// communication is disabled. Released, or absent, the record goes;
// otherwise it stays Unresolved.
func proveReleased(ctx context.Context, t *target, r *record) proof {
	fe, err := current(qualify(r.FunctionalEntity, r.nsa), t)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	want, err := current(qualify(r.NodeID, r.nsa), t)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	found, err := observeName(ctx, t, fe, r.Name, nil)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	if !slices.ContainsFunc(found, func(o Observed) bool { return o.NodeID.Equal(want) }) {
		return proof{drop: true, why: "no endpoint of its Name at its NodeId"}
	}
	act, err := readActual(ctx, t, want)
	if err != nil {
		return proof{class: Unverified, err: err}
	}
	st, err := commStateOf(ctx, t, want)
	switch {
	case err != nil:
		return proof{class: Unverified, err: err}
	case act.related != nil && !nullRelated(act.related):
		return proof{class: Unresolved, node: want, why: "a CloseConnections of unknown outcome left the preconfigured endpoint related"}
	case st == commUnknown:
		return proof{class: Unresolved, node: want, why: "the communication state of the preconfigured endpoint cannot be read"}
	case st != commDisabled && st != commNone:
		return proof{class: Unresolved, node: want, why: "a CloseConnections of unknown outcome left the communication of the preconfigured endpoint " + st.String()}
	}
	return proof{drop: true, why: "the preconfigured endpoint is released"}
}

// commState is what the State of the Status (Part 14 §9.1.10) of the
// DataSetReader and DataSetWriter of an endpoint shows: each of them is
// enabled when its State is not Disabled. Only commEnabled proves an
// enablement and only commDisabled a disablement; the others prove
// neither.
type commState uint8

const (
	commUnknown  commState = iota // a State that cannot be read
	commNone                      // neither a DataSetReader nor a DataSetWriter
	commEnabled                   // every one enabled
	commDisabled                  // every one disabled
	commMixed                     // some enabled, some disabled
)

func (s commState) String() string {
	switch s {
	case commNone:
		return "absent"
	case commEnabled:
		return "enabled"
	case commDisabled:
		return "disabled"
	case commMixed:
		return "partly enabled"
	case commUnknown:
	}
	return "unknown"
}

// commOf is the commState of the States read: nil for one that could not
// be read.
func commOf(states []*ua.PubSubState) commState {
	if len(states) == 0 {
		return commNone
	}
	on, off := 0, 0
	for _, st := range states {
		switch {
		case st == nil:
			return commUnknown
		case *st == ua.PubSubStateDisabled:
			off++
		default:
			on++
		}
	}
	switch {
	case off == 0:
		return commEnabled
	case on == 0:
		return commDisabled
	}
	return commMixed
}

// commStateOf reads the commState of the endpoint n of t.
func commStateOf(ctx context.Context, t *target, n *ua.NodeID) (commState, error) {
	act, err := readActual(ctx, t, n)
	if err != nil {
		return commUnknown, err
	}
	read := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for _, c := range []*ua.NodeID{act.reader, act.writer} {
		if c == nil {
			continue
		}
		props, err := t.children(ctx, c)
		if err != nil {
			return commUnknown, err
		}
		st := child(props, 0, "Status")
		if st == nil {
			return commUnknown, nil
		}
		sprops, err := t.children(ctx, st)
		if err != nil {
			return commUnknown, err
		}
		v := child(sprops, 0, "State")
		if v == nil {
			return commUnknown, nil
		}
		read.NodesToRead = append(read.NodesToRead, &ua.ReadValueID{NodeID: v, AttributeID: ua.AttributeIDValue})
	}
	if len(read.NodesToRead) == 0 {
		return commNone, nil
	}
	res, err := t.sess.Read(ctx, read)
	if err != nil {
		return commUnknown, err
	}
	if len(res.Results) != len(read.NodesToRead) {
		return commUnknown, fmt.Errorf("fxcm: Read: %d results", len(res.Results))
	}
	states := make([]*ua.PubSubState, len(res.Results))
	for i, dv := range res.Results {
		if dv == nil || bad(dv.Status) {
			continue
		}
		if v, ok := dvValue(dv).(int32); ok {
			st := ua.PubSubState(v)
			states[i] = &st
		}
	}
	return commOf(states), nil
}

// heldBy returns the place of an intent of intents that the record r
// holds, nil for none: a Name of an establish (by its server,
// FunctionalEntity and Name), an endpoint of a close or an enablement (by
// its server and NodeId).
func heldBy(r *record, intents map[string]*callRecord) *intentName {
	for _, k := range slices.Sorted(maps.Keys(intents)) {
		c := intents[k]
		if !c.sameAddress(r.addr) {
			continue
		}
		switch c.Kind {
		case callEstablish:
			for i, name := range c.Names {
				if r.Name == name && qualify(r.FunctionalEntity, r.nsa).String() == c.FunctionalEntities[i].String() {
					return &intentName{key: k, c: c, i: i}
				}
			}
		case callClose, callEnable:
			nodes := c.Nodes
			if c.Kind == callEnable {
				nodes = c.Targets
			}
			for i, q := range nodes {
				if r.NodeID != nil && qualify(r.NodeID, r.nsa).String() == q.String() {
					return &intentName{key: k, c: c, i: i}
				}
			}
		}
	}
	return nil
}

// verdict is the proof of one record of a set, to apply.
type verdict struct {
	rk  string
	rec *record
	p   proof
	// in is the Name of an intent the record holds, when it was decided
	// from the intent.
	in *intentName
}

// work is what the verification of one server has to do for one set.
type work struct {
	s       *set
	cfg     *Config
	gen     uint64
	recs    map[string]*record
	intents map[string]*callRecord
	// absent are the targets of close and enable intents (by intent key
	// and index) that no record of the set holds and that the server
	// shows no node at: nothing is left there for the call to change.
	absent map[string]map[int]bool
}

// sameAddress reports whether the intent c was sent to addr.
func (r *callRecord) sameAddress(addr ServerAddress) bool {
	return r.Address == addr.Address && ua.MessageSecurityMode(r.SecurityMode) == addr.SecurityMode && r.SecurityPolicyURI == addr.SecurityPolicyURI && r.ServerURIConf == addr.ServerURI
}

// collect returns the work of the verification of addr: the Unverified
// records of the sets on addr and the unended intents of runs that are not
// active, of every set (owner nil: the background pass, which skips a set
// that is processed or held and reports it busy) or of owner only (the
// first step of its run).
func (m *Manager) collect(addr ServerAddress, owner *set) (ws []*work, busy bool) {
	p := m.p
	m.mu.Lock()
	sets := slices.Collect(maps.Values(m.sets))
	m.mu.Unlock()
	l := decodeState(p.d.State())
	p.owedMu.Lock()
	active := maps.Clone(p.active)
	p.owedMu.Unlock()
	for _, s := range sets {
		if owner != nil && s != owner {
			continue
		}
		w := &work{s: s, recs: map[string]*record{}, intents: map[string]*callRecord{}}
		ks := keyString(s.cfg.key)
		for k, c := range l.calls {
			if keyString(SetKey{Folder: c.Folder, Name: c.SetName}) == ks && !active[RunID(c.Run)] && c.sameAddress(addr) {
				w.intents[k] = c
			}
		}
		s.mu.Lock()
		skip := owner == nil && (s.current != nil || s.held)
		w.cfg, w.gen = s.cfg, s.gen
		for rk, r := range s.records {
			if r.addr != addr {
				continue
			}
			// A record an unended close or enablement targets is decided
			// by the outcome of that call, whatever its class: a trusted
			// owner proves nothing about the call (decision C3-D13).
			in := heldBy(r, w.intents)
			if r.Class == Unverified || in != nil && (r.Class == Unresolved || in.c.Kind != callEstablish) {
				w.recs[rk] = r
			}
		}
		s.mu.Unlock()
		if len(w.recs) == 0 && len(w.intents) == 0 {
			continue
		}
		if skip {
			busy = true
			continue
		}
		ws = append(ws, w)
	}
	return ws, busy
}

// errBusy is the attempt on a server that skipped a set being processed or
// held: its run verifies its records.
var errBusy = errors.New("fxcm: a set on the server is being processed")

// verifyServer verifies, within ctx, the records and intents of addr of the
// sets collect returns, and applies the verdicts. It returns an error when
// a record stays Unverified or a verdict was not written, and busy when a
// set was skipped because a run or a claim holds it.
func (m *Manager) verifyServer(ctx context.Context, addr ServerAddress, owner *set) (busy bool, err error) {
	ws, busy := m.collect(addr, owner)
	if len(ws) == 0 {
		return busy, nil
	}
	sess, err := m.pool.get(ctx, addr)
	if err != nil {
		return busy, err
	}
	t := &target{addr: addr, sess: sess, cache: m.res.of(addr)}
	if err := t.open(ctx); err != nil {
		m.pool.drop(ctx, addr, sess)
		return busy, err
	}
	t.identify(ctx)
	// The places the work proves, locked as an establish locks them
	// (scan to its end): no run changes the endpoints under them between
	// the evidence and its verdict.
	var places []string
	for _, w := range ws {
		for _, r := range w.recs {
			if fe, err := current(qualify(r.FunctionalEntity, r.nsa), t); err == nil && fe != nil {
				places = append(places, addr.Address+"\x00"+fe.String())
			}
		}
		for _, c := range w.intents {
			for _, q := range c.FunctionalEntities {
				if fe, err := current(q, t); err == nil && fe != nil {
					places = append(places, addr.Address+"\x00"+fe.String())
				}
			}
		}
	}
	release, err := m.places.lock(ctx, places)
	defer release()
	if err != nil {
		return busy, err
	}
	var errs []error
	for _, w := range ws {
		if err := w.findAbsent(ctx, t); err != nil {
			errs = append(errs, err)
		}
		var vs []verdict
		for _, rk := range slices.Sorted(maps.Keys(w.recs)) {
			r := w.recs[rk]
			v := verdict{rk: rk, rec: r}
			in := heldBy(r, w.intents)
			switch {
			case in != nil && in.c.Kind != callEstablish:
				// An endpoint of an unended close or enablement: the
				// postcondition of the call decides it.
				v.in = in
				v.p = m.proveOutcome(ctx, t, r, *in)
			case in != nil && (r.Class == Unresolved || r.stored == Unresolved):
				// A Name of an unended establish: the intent decides it.
				v.in = in
				v.p = m.proveIntentName(ctx, t, w.cfg, w.gen, *in)
			case r.stored == KnownOwned || r.stored == TakenPreconfigured:
				v.p = m.proveRecord(ctx, t, r)
			default:
				// An Unresolved record stays Unresolved: only new evidence
				// of §6.5 or Settle decides it, not a reload.
				v.p = proof{class: Unresolved, why: "stored Unresolved"}
			}
			if v.p.err != nil {
				errs = append(errs, fmt.Errorf("%s %q: %w", w.cfg.key, r.Name, v.p.err))
			}
			vs = append(vs, v)
		}
		switch err := m.applyVerdicts(w, t, vs, owner); {
		case errors.Is(err, errBusy):
			busy = true
		case err != nil:
			errs = append(errs, err)
		}
	}
	m.p.noteVerified(m, addr)
	return busy, errors.Join(errs...)
}

// applyVerdicts writes the verdicts vs on the records of w.s and completes
// the intents of w whose places are all decided, in one write, and then
// applies them in memory (design §6.2: durable before visible). A record
// that changed since it was collected keeps its state.
func (m *Manager) applyVerdicts(w *work, t *target, vs []verdict, owner *set) error {
	p := m.p
	s := w.s
	var events []Event
	defer func() {
		for _, e := range events {
			m.observe(e)
		}
	}()
	unlock := p.lockJournal(s)
	defer unlock()
	if owner == nil && (s.current != nil || s.held) {
		return errBusy
	}
	st := p.d.State()
	b := fxstore.Batch{Puts: map[string][]byte{}}
	type change struct {
		v    verdict
		next *record
	}
	var cs []change
	decided := map[*record]bool{}
	for _, v := range vs {
		outcome := v.in != nil && v.in.c.Kind != callEstablish
		if v.p.class == Unverified && !v.p.drop || s.records[v.rk] != v.rec || v.rec.Class != Unverified && !outcome && (v.in == nil || v.rec.Class != Unresolved) {
			continue
		}
		k := epKeyOf(s.cfg.key, v.rec)
		if v.p.drop {
			if _, ok := st[k]; ok {
				b.Deletes = append(b.Deletes, k)
			}
			cs = append(cs, change{v: v})
			decided[v.rec] = true
			continue
		}
		next := v.rec.proven(v, t, s.cfg)
		val, err := encodeRecord(storedOf(next))
		if err != nil {
			continue
		}
		if nk := epKeyOf(s.cfg.key, next); !bytes.Equal(st[nk], val) {
			b.Puts[nk] = val
		}
		cs = append(cs, change{v: v, next: next})
		decided[v.rec] = next.Class != Unresolved
	}
	// The intents whose places no undecided record holds any more.
	undecided := func(r *record) bool {
		if d, ok := decided[r]; ok {
			return !d
		}
		return r.Class == Unverified || r.Class == Unresolved
	}
	var done []string
	for _, k := range slices.Sorted(maps.Keys(w.intents)) {
		c := w.intents[k]
		if c.Kind != callEstablish {
			// Complete only when every target has an outcome proven in
			// this pass (or nothing left to change at it), never by the
			// ownership of what is recorded there.
			if !w.outcomesProven(k, c, vs, decided) {
				continue
			}
		} else if p.intentOpen(s, c, undecided) {
			continue
		}
		done = append(done, k)
		b.Deletes = append(b.Deletes, k)
	}
	if len(cs) == 0 && len(done) == 0 {
		return nil
	}
	m.crashPoint("verify.before-write")
	if o, err := p.apply(b, 0); o != fxstore.Committed {
		err = storeError(o, err)
		m.log.Warn("fxcm: the verdicts of a verification were not written to the store; the records stay Unverified", "set", s.cfg.key.String(), "error", err)
		return err
	}
	m.crashPoint("verify.after-write")
	for _, c := range cs {
		delete(s.records, c.v.rk)
		var rec EndpointRecord
		if c.next != nil {
			s.records[recordKey(c.next.addr, c.next.FunctionalEntity, c.next.Name)] = c.next
			rec = c.next.EndpointRecord
		} else {
			rec = c.v.rec.EndpointRecord
		}
		m.log.Info("fxcm: a loaded record was verified", "set", s.cfg.key.String(), "endpoint", rec.Name, "verdict", c.v.p.String())
		events = append(events, Event{Kind: EventVerified, Set: s.cfg.key, Record: &rec, Closed: c.next == nil, Address: t.addr.Address})
	}
	return nil
}

// targetsOf returns the endpoints the close or enable intent c targets.
func targetsOf(c *callRecord) []*qualifiedID {
	if c.Kind == callEnable {
		return c.Targets
	}
	return c.Nodes
}

// findAbsent fills w.absent: the targets of the close and enable intents
// of w that no collected record holds, with no node at them on t (Browse
// answers Bad_NodeIdUnknown). A read that fails proves nothing.
func (w *work) findAbsent(ctx context.Context, t *target) error {
	held := map[string]map[int]bool{}
	for _, r := range w.recs {
		if in := heldBy(r, w.intents); in != nil {
			if held[in.key] == nil {
				held[in.key] = map[int]bool{}
			}
			held[in.key][in.i] = true
		}
	}
	var errs []error
	for _, k := range slices.Sorted(maps.Keys(w.intents)) {
		c := w.intents[k]
		if c.Kind == callEstablish {
			continue
		}
		for i, q := range targetsOf(c) {
			if held[k][i] {
				continue
			}
			n, err := current(q, t)
			if err != nil || n == nil {
				continue
			}
			if _, err := t.children(ctx, n); errors.Is(err, ua.StatusBadNodeIDUnknown) {
				if w.absent == nil {
					w.absent = map[string]map[int]bool{}
				}
				if w.absent[k] == nil {
					w.absent[k] = map[int]bool{}
				}
				w.absent[k][i] = true
			} else if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// outcomesProven reports whether every target of the close or enable
// intent c, of key k, has its outcome proven: a verdict of this pass on a
// record at it that is decided (dropped, or proven other than Unresolved or
// Unverified), or no node left at it (findAbsent).
func (w *work) outcomesProven(k string, c *callRecord, vs []verdict, decided map[*record]bool) bool {
	for i := range targetsOf(c) {
		if w.absent[k][i] {
			continue
		}
		ok := false
		for _, v := range vs {
			if v.in != nil && v.in.key == k && v.in.i == i && v.p.err == nil && decided[v.rec] {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// proven returns the record r as the verdict v decided it, on the server of
// t: its class, the endpoint found, the evidence read, and its NodeIds on
// the server's NamespaceArray now (design §4.8 for the CM: a reordered
// NamespaceArray maps the record, it does not lose it).
func (r *record) proven(v verdict, t *target, cfg *Config) *record {
	cp := *r
	cp.Class = v.p.class
	cp.stored = v.p.class
	fe, _ := current(qualify(r.FunctionalEntity, r.nsa), t)
	ac, _ := current(qualify(r.acNode, r.nsa), t)
	cp.FunctionalEntity, cp.acNode = fe, ac
	if v.p.node != nil {
		cp.NodeID = v.p.node
	} else {
		cp.NodeID, _ = current(qualify(r.NodeID, r.nsa), t)
	}
	cp.nsa = t.nsa
	est := v.in != nil && v.in.c.Kind == callEstablish
	if v.p.read {
		cp.cmURI, cp.cmObserved, cp.created = v.p.cm, v.p.cmOK, v.p.created
		if est || !cp.param.Set {
			// A Name the intent decided: the parameter is the one found.
			// A stored parameter is URI-qualified: it needs no mapping.
			cp.param = v.p.param
		}
	}
	if v.in != nil && v.in.c.Kind == callClose && cp.Class != Unresolved {
		// A disablement proven done: no close is pending.
		cp.ClosePending = false
	}
	if est {
		c := v.in.c
		// The identity the call was made with, which the proof compared:
		// never rebaselined on what the session shows now.
		cp.server = c.Server
		cp.epfp = c.EndpointFingerprints[v.in.i]
		if cfg.version != 0 && r.gen == c.Generation {
			cp.Version = cfg.version
		}
	}
	return &cp
}

// intentOpen reports whether a place of the intent c of the set s is held
// by a record undecided says is undecided: a Name of an establish (by
// FunctionalEntity and Name on its server), an endpoint of a close (by its
// NodeId). The caller holds s.mu.
func (p *persistence) intentOpen(s *set, c *callRecord, undecided func(*record) bool) bool {
	for _, r := range s.records {
		if !c.sameAddress(r.addr) || !undecided(r) {
			continue
		}
		switch c.Kind {
		case callEstablish:
			for i, name := range c.Names {
				if r.Name == name && qualify(r.FunctionalEntity, r.nsa).String() == c.FunctionalEntities[i].String() {
					return true
				}
			}
		case callClose, callEnable:
			nodes := c.Nodes
			if c.Kind == callEnable {
				nodes = c.Targets
			}
			for _, q := range nodes {
				if r.NodeID != nil && qualify(r.NodeID, r.nsa).String() == q.String() {
					return true
				}
			}
		}
	}
	return false
}

// unverifiedAddrs returns the servers with Unverified records, or unended
// intents of runs that are not active, of the sets of m.
func (m *Manager) unverifiedAddrs() []ServerAddress {
	m.mu.Lock()
	sets := slices.Collect(maps.Values(m.sets))
	m.mu.Unlock()
	seen := map[ServerAddress]bool{}
	for _, s := range sets {
		s.mu.Lock()
		for _, r := range s.records {
			if r.Class == Unverified {
				seen[r.addr] = true
			}
		}
		s.mu.Unlock()
	}
	out := slices.Collect(maps.Keys(seen))
	slices.SortFunc(out, func(a, b ServerAddress) int {
		return compareStrings(recordKey(a, nil, ""), recordKey(b, nil, ""))
	})
	return out
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// startVerify starts the background verification (design §6.4) unless it
// runs or VerifyOptions.Manual is set.
func (m *Manager) startVerify() {
	p := m.p
	if p == nil || m.opts.Verify.Manual {
		return
	}
	p.verifyMu.Lock()
	defer p.verifyMu.Unlock()
	if p.verifying {
		p.verifyAgain = true
		return
	}
	m.mu.Lock()
	closed := m.closed
	if !closed {
		m.wg.Add(1)
	}
	m.mu.Unlock()
	if closed {
		return
	}
	p.verifying = true
	go func() {
		defer m.wg.Done()
		m.verifyLoop()
	}()
}

// verifyLoop verifies the servers of unverifiedAddrs, at most
// VerifyOptions.Parallelism at a time, each attempt within Timeout, and
// tries a server that failed again after a backoff that doubles up to
// RetryMax, until no record is Unverified or the Manager closes.
func (m *Manager) verifyLoop() {
	p := m.p
	o := m.opts.Verify
	next := map[ServerAddress]time.Time{}
	wait := map[ServerAddress]time.Duration{}
	for {
		addrs := m.unverifiedAddrs()
		p.verifyMu.Lock()
		again := p.verifyAgain
		p.verifyAgain = false
		if len(addrs) == 0 && !again {
			p.verifying = false
			p.verifyMu.Unlock()
			return
		}
		p.verifyMu.Unlock()
		now := time.Now()
		var due []ServerAddress
		for _, a := range addrs {
			if !next[a].After(now) {
				due = append(due, a)
			}
		}
		sem := make(chan struct{}, o.Parallelism)
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, a := range due {
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-m.ctx.Done():
					return
				}
				defer func() { <-sem }()
				ctx, cancel := context.WithTimeout(m.ctx, o.Timeout)
				_, err := m.verifyServer(ctx, a, nil)
				cancel()
				mu.Lock()
				defer mu.Unlock()
				p.noteAttempt(a, err)
				if err == nil {
					// Done, unless a run held a set (it verifies that set
					// itself) or a record changed meanwhile: then the
					// server is tried again after RetryInitial.
					delete(wait, a)
					next[a] = time.Now().Add(o.RetryInitial)
					return
				}
				d := wait[a]
				if d == 0 {
					d = o.RetryInitial
				} else {
					d = min(2*d, o.RetryMax)
				}
				wait[a], next[a] = d, time.Now().Add(d)
				m.log.Warn("fxcm: a server was not verified", "address", a.Address, "error", err, "retry", d)
				m.observe(Event{Kind: EventVerified, Address: a.Address, Err: err})
			}()
		}
		wg.Wait()
		if m.ctx.Err() != nil {
			p.verifyMu.Lock()
			p.verifying = false
			p.verifyMu.Unlock()
			return
		}
		earliest := time.Duration(0)
		for _, a := range m.unverifiedAddrs() {
			d := time.Until(next[a])
			if earliest == 0 || d < earliest {
				earliest = d
			}
		}
		if earliest <= 0 {
			earliest = time.Millisecond
		}
		if !p.sleep(earliest) {
			p.verifyMu.Lock()
			p.verifying = false
			p.verifyMu.Unlock()
			return
		}
	}
}

// verifyRun is the first step of a run with a Store (design §6.4): it
// verifies the Unverified records of the set and resolves the intents of
// its runs that ended without their outcome, on each of its servers within
// VerifyOptions.Timeout, at most Parallelism at a time. What stays
// Unverified is treated as Unresolved for the rest of the run.
func (x *run) verifyRun(ctx context.Context) {
	m := x.m
	seen := map[ServerAddress]bool{}
	x.s.mu.Lock()
	for _, r := range x.s.records {
		if r.Class == Unverified {
			seen[r.addr] = true
		}
	}
	x.s.mu.Unlock()
	for _, c := range decodeState(m.p.d.State()).calls {
		if keyString(SetKey{Folder: c.Folder, Name: c.SetName}) == keyString(x.r.key) && RunID(c.Run) != x.r.id {
			seen[ServerAddress{Address: c.Address, SecurityMode: ua.MessageSecurityMode(c.SecurityMode), SecurityPolicyURI: c.SecurityPolicyURI, ServerURI: c.ServerURIConf}] = true
		}
	}
	if len(seen) == 0 {
		return
	}
	o := m.opts.Verify
	sem := make(chan struct{}, o.Parallelism)
	var wg sync.WaitGroup
	for a := range seen {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			vctx, cancel := context.WithTimeout(ctx, o.Timeout)
			defer cancel()
			_, err := m.verifyServer(vctx, a, x.s)
			m.p.noteAttempt(a, err)
			if err != nil {
				m.log.Warn("fxcm: the records of the set were not all verified", "set", x.r.key.String(), "run", x.r.id, "address", a.Address, "error", err)
			}
		}()
	}
	wg.Wait()
}

// noteVerified clears addr from the unverified servers once no record of
// any set on it is Unverified, and computes the fence again (fencedOf).
func (p *persistence) noteVerified(m *Manager, addr ServerAddress) {
	m.mu.Lock()
	sets := slices.Collect(maps.Values(m.sets))
	m.mu.Unlock()
	for _, s := range sets {
		s.mu.Lock()
		left := slices.ContainsFunc(slices.Collect(maps.Values(s.records)), func(r *record) bool {
			return r.Class == Unverified && r.addr.Address == addr.Address
		})
		s.mu.Unlock()
		if left {
			return
		}
	}
	p.owedMu.Lock()
	was := p.unverified[addr.Address]
	delete(p.unverified, addr.Address)
	p.owedMu.Unlock()
	if was {
		p.mu.Lock()
		p.refreshOwed()
		p.mu.Unlock()
	}
}

// noteAttempt records the outcome of a verification attempt on addr.
func (p *persistence) noteAttempt(addr ServerAddress, err error) {
	p.owedMu.Lock()
	defer p.owedMu.Unlock()
	if err == nil {
		delete(p.verifyErr, addr.Address)
		return
	}
	p.verifyErr[addr.Address] = err.Error()
}
