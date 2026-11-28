// SPDX-License-Identifier: MIT

package fxserver

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// The defaults of LogOptions.
const (
	// DefaultLogMaxRecords is the capacity of a log: the MaxRecords
	// Property (OPC 10000-26 §5.2).
	DefaultLogMaxRecords = 1000
	// DefaultLogMaxReturnRecords is the most records one GetRecords call
	// returns (§5.3: "The Server can also impose a limit").
	DefaultLogMaxReturnRecords = 100
)

// The Severities of the LogRecords the library makes, in the ranges of OPC
// 10000-26 §5.5 Table 9.
const (
	// SeverityInformation is a Good outcome: Information (51 to 100).
	SeverityInformation uint16 = 100
	// SeverityWarning is an Uncertain one: Warning (151 to 200).
	SeverityWarning uint16 = 200
	// SeverityError is a Bad one: Error (201 to 250).
	SeverityError uint16 = 250
)

// ErrLog reports LogOptions that cannot be served.
var ErrLog = errors.New("fxserver: log")

// LogOptions configure a LogObject of OPC 10000-26 (§5): the
// AutomationComponentLog of the AutomationComponents (Part 81 §6.2.2) or
// the ConnectionManagerLog (§6.7.2). The records are kept in memory: a
// restart of the process loses them.
type LogOptions struct {
	// MaxRecords is the capacity of the log, its MaxRecords Property
	// (§5.2): when the log holds MaxRecords records, a new record deletes
	// the oldest one. 0: DefaultLogMaxRecords.
	MaxRecords uint32
	// MinimumSeverity is the MinimumSeverity Property (§5.2): a record with
	// a lower Severity is not kept. 0: no restriction and no Property;
	// otherwise 1 to 1000.
	MinimumSeverity uint16
	// MaxReturnRecords is the most records one GetRecords call returns,
	// whatever the MaxReturnRecords of the call (§5.3); the rest comes with
	// a continuation point. 0: DefaultLogMaxReturnRecords.
	MaxReturnRecords uint32
}

func (o *LogOptions) check() error {
	if o.MinimumSeverity > 1000 {
		return fmt.Errorf("%w: MinimumSeverity %d is not 1 to 1000 (OPC 10000-26 §5.2)", ErrLog, o.MinimumSeverity)
	}
	return nil
}

// Log is a LogObject (OPC 10000-26 §5): the records of a log, oldest first,
// and its GetRecords Method. It is safe for concurrent use.
type Log struct {
	node     *ua.NodeID
	max      int
	minSev   uint16
	page     int
	instance uint64 // identifies the continuation points of the log

	mu   sync.Mutex
	recs []logEntry // by (time, seq)
	seq  uint64
	// gone is the greatest key a deleted record had; valid with lost.
	gone logKey
	lost bool

	spans atomic.Uint64
	now   func() time.Time // time.Now; tests replace it
}

type logKey struct {
	t   time.Time
	seq uint64
}

func (k logKey) compare(o logKey) int {
	if c := k.t.Compare(o.t); c != 0 {
		return c
	}
	return cmp.Compare(k.seq, o.seq)
}

type logEntry struct {
	key logKey
	rec ua.LogRecord
}

func newLog(o LogOptions) *Log {
	l := &Log{max: int(o.MaxRecords), minSev: o.MinimumSeverity, page: int(o.MaxReturnRecords), now: time.Now}
	if l.max <= 0 {
		l.max = DefaultLogMaxRecords
	}
	if l.page <= 0 {
		l.page = DefaultLogMaxReturnRecords
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	l.instance = binary.LittleEndian.Uint64(b[:8])
	// SpanIds are unique within the log and never 0 (§5.6.2, C.2: an
	// increasing UInt64).
	l.spans.Store(binary.LittleEndian.Uint64(b[8:]) >> 1)
	return l
}

// Node returns the NodeId of the LogObject.
func (l *Log) Node() *ua.NodeID { return l.node }

// Add adds r to the log, unless its Severity is below the MinimumSeverity
// (§5.2). A zero Time is the time of the call; the time is kept in UTC with
// the 100 ns resolution of a DateTime (OPC 10000-6 §5.2.2.5), and a
// Severity outside 1 to 1000 is moved into that range (§5.5 Table 8). When
// the log is full, the oldest record is deleted (MaxRecords, §5.2). The log
// keeps r: the caller must not change it, or what it points to, afterwards.
func (l *Log) Add(r ua.LogRecord) {
	if r.Time.IsZero() {
		r.Time = l.now()
	}
	r.Time = r.Time.UTC().Truncate(100 * time.Nanosecond)
	r.Severity = min(max(r.Severity, 1), 1000)
	if r.Severity < l.minSev {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e := logEntry{key: logKey{r.Time, l.seq}, rec: r}
	i := len(l.recs)
	if i > 0 && l.recs[i-1].key.compare(e.key) > 0 {
		// A record older than the newest one: it goes in its place, so
		// that GetRecords returns them in chronological order (§5.3).
		i, _ = slices.BinarySearchFunc(l.recs, e.key, func(a logEntry, k logKey) int { return a.key.compare(k) })
	}
	l.recs = slices.Insert(l.recs, i, e)
	if len(l.recs) > l.max {
		if !l.lost || l.recs[0].key.compare(l.gone) > 0 {
			l.gone = l.recs[0].key
		}
		l.lost = true
		l.recs[0] = logEntry{}
		l.recs = l.recs[1:]
	}
}

// Records returns the records of the log, oldest first. They must not be
// changed.
func (l *Log) Records() []*ua.LogRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*ua.LogRecord, len(l.recs))
	for i := range l.recs {
		r := l.recs[i].rec
		out[i] = &r
	}
	return out
}

// span returns a new SpanId of the log.
func (l *Log) span() uint64 {
	for {
		if s := l.spans.Add(1); s != 0 {
			return s
		}
	}
}

// traceOf returns the TraceContext of a record of a Method call: a new span
// whose parent is the span of the client when the call carried a
// SpanContext (OPC 10000-26 §5.6.3, §5.6.4: the SpanId of the request
// becomes the ParentSpanId, the ParentIdentifier the ApplicationUri of the
// client), nil otherwise.
func (l *Log) traceOf(mc *server.MethodCaller) *ua.TraceContextDataType {
	if mc == nil || mc.SpanContext == nil {
		return nil
	}
	return &ua.TraceContextDataType{TraceID: mc.SpanContext.TraceID, SpanID: l.span(),
		ParentSpanID: mc.SpanContext.SpanID, ParentIdentifier: mc.ClientApplicationURI}
}

// severityOf is the Severity of a record of an outcome sc.
func severityOf(sc ua.StatusCode) uint16 {
	switch {
	case sc.Uint32()&0x80000000 != 0:
		return SeverityError
	case sc.Uint32()&0x40000000 != 0:
		return SeverityWarning
	}
	return SeverityInformation
}

// nv is a NameValuePair of AdditionalData.
func nv(name string, v any) *ua.NameValuePair {
	return &ua.NameValuePair{Name: name, Value: ua.MustVariant(v)}
}

// --- GetRecords -------------------------------------------------------------

// The continuation point of GetRecords: version, instance of the log, the
// key of the next record, a digest of the other arguments.
const (
	cpVersion = 1
	cpLen     = 1 + 8 + 8 + 8 + 8
)

// getRecords is the GetRecords Method (OPC 10000-26 §5.3, Tables 2 and 3).
func (l *Log) getRecords(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 6 {
		return nil, ua.StatusBadArgumentsMissing
	}
	for _, a := range args {
		if a == nil {
			return nil, ua.StatusBadInvalidArgument
		}
	}
	start, ok1 := args[0].Value().(time.Time)
	end, ok2 := args[1].Value().(time.Time)
	maxRet, ok3 := args[2].Value().(uint32)
	minSev, ok4 := args[3].Value().(uint16)
	mask, ok5 := args[4].Value().(uint32)
	cp, ok6 := args[5].Value().([]byte)
	if args[5].Value() == nil {
		cp, ok6 = nil, true
	}
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return nil, ua.StatusBadTypeMismatch
	}
	// "If EndTime is earlier than StartTime, then the error
	// Bad_InvalidArgument shall be returned"; "MinimumSeverity is a number
	// between 1 and 1000 inclusive, a number outside of this range shall
	// result in the error Bad_InvalidArgument" (§5.3; Table 3 names
	// Bad_OutOfRange for it, the text of the clause is followed).
	if end.Before(start) || minSev < 1 || minSev > 1000 {
		return nil, ua.StatusBadInvalidArgument
	}
	digest := cpDigest(start, end, maxRet, minSev, mask)
	limit := l.page
	if maxRet > 0 && int64(maxRet) < int64(limit) {
		limit = int(maxRet)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	var i int
	if len(cp) == 0 {
		i, _ = slices.BinarySearchFunc(l.recs, start, func(e logEntry, t time.Time) int {
			if e.key.t.Before(t) {
				return -1
			}
			return 1
		})
	} else {
		k, sc := l.decodeCP(cp, digest)
		if sc != ua.StatusGood {
			return nil, sc
		}
		i, _ = slices.BinarySearchFunc(l.recs, k, func(e logEntry, k logKey) int { return e.key.compare(k) })
	}
	out := []*ua.LogRecord{}
	var next []byte
	for ; i < len(l.recs) && !l.recs[i].key.t.After(end); i++ {
		e := &l.recs[i]
		if e.rec.Severity < minSev {
			continue
		}
		if len(out) == limit {
			next = encodeCP(l.instance, e.key, digest)
			break
		}
		out = append(out, masked(&e.rec, ua.LogRecordMask(mask)))
	}
	return []*ua.Variant{
		ua.MustVariant(ua.NewExtensionObject(&ua.LogRecordsDataType{LogRecordArray: out})),
		ua.MustVariant(next),
	}, ua.StatusGood
}

// decodeCP returns the key a continuation point of l resumes at:
// Bad_ContinuationPointInvalid for one that is not of l or whose record
// was deleted since (§5.3), Bad_InvalidArgument for one of a call with
// other arguments (§5.3: the Server "can detect any changes to the
// parameters and report an error").
func (l *Log) decodeCP(cp []byte, digest uint64) (logKey, ua.StatusCode) {
	if len(cp) != cpLen || cp[0] != cpVersion || binary.LittleEndian.Uint64(cp[1:]) != l.instance {
		return logKey{}, ua.StatusBadContinuationPointInvalid
	}
	k := logKey{time.Unix(0, int64(binary.LittleEndian.Uint64(cp[9:]))).UTC(), binary.LittleEndian.Uint64(cp[17:])}
	if binary.LittleEndian.Uint64(cp[25:]) != digest {
		return logKey{}, ua.StatusBadInvalidArgument
	}
	if l.lost && k.compare(l.gone) <= 0 {
		return logKey{}, ua.StatusBadContinuationPointInvalid
	}
	return k, ua.StatusGood
}

func encodeCP(instance uint64, k logKey, digest uint64) []byte {
	b := make([]byte, 0, cpLen)
	b = append(b, cpVersion)
	b = binary.LittleEndian.AppendUint64(b, instance)
	b = binary.LittleEndian.AppendUint64(b, uint64(k.t.UnixNano()))
	b = binary.LittleEndian.AppendUint64(b, k.seq)
	return binary.LittleEndian.AppendUint64(b, digest)
}

func cpDigest(start, end time.Time, maxRet uint32, minSev uint16, mask uint32) uint64 {
	h := fnv.New64a()
	var b []byte
	b = binary.LittleEndian.AppendUint64(b, uint64(start.UnixNano()))
	b = binary.LittleEndian.AppendUint64(b, uint64(end.UnixNano()))
	b = binary.LittleEndian.AppendUint32(b, maxRet)
	b = binary.LittleEndian.AppendUint16(b, minSev)
	b = binary.LittleEndian.AppendUint32(b, mask)
	_, _ = h.Write(b)
	return h.Sum64()
}

// masked returns a copy of r with the optional fields RequestMask does not
// ask for left out (§5.3, §5.8 Table 17): Time, Severity and Message are
// always returned.
func masked(r *ua.LogRecord, m ua.LogRecordMask) *ua.LogRecord {
	out := &ua.LogRecord{Time: r.Time, Severity: r.Severity, Message: r.Message}
	if m&ua.LogRecordMaskEventType != 0 {
		out.EventType = r.EventType
	}
	if m&ua.LogRecordMaskSourceNode != 0 {
		out.SourceNode = r.SourceNode
	}
	if m&ua.LogRecordMaskSourceName != 0 {
		out.SourceName = r.SourceName
	}
	if m&ua.LogRecordMaskTraceContext != 0 {
		out.TraceContext = r.TraceContext
	}
	if m&ua.LogRecordMaskAdditionalData != 0 {
		out.AdditionalData = r.AdditionalData
	}
	return out
}

// --- the address space --------------------------------------------------------

// logNodes adds, or completes, the LogObject of a log as the component bn
// of parent (OPC 10000-26 §5.2 Table 1): an Object of LogObjectType with
// the GetRecords Method and the MaxRecords and, when set, MinimumSeverity
// Properties, organized by the Logs Object (§7.3) when the server has it.
// Members the parent has already, from a NodeSet, are taken. The new nodes
// get string NodeIds in the namespace of parent that start with prefix. It
// registers GetRecords and returns the NodeIds it added, in their order,
// with an error too, so that the caller can remove them.
func logNodes(srv *server.Server, parent *ua.NodeID, bn *ua.QualifiedName, prefix string, l *Log) ([]*ua.NodeID, error) {
	pn := srv.Node(parent)
	ns, err := srv.Namespace(int(parent.Namespace()))
	if pn == nil || err != nil {
		return nil, fmt.Errorf("%w: no node %v", ErrLog, parent)
	}
	var added []*ua.NodeID
	newID := func(suffix string) (*ua.NodeID, error) {
		n := ua.NewStringNodeID(parent.Namespace(), prefix+suffix)
		if srv.Node(n) != nil {
			return nil, fmt.Errorf("%w: the NodeId %v is taken", ErrLog, n)
		}
		return n, nil
	}
	add := func(n *server.Node) {
		ns.AddNode(n)
		added = append(added, n.ID())
	}
	obj := childNode(srv, parent, bn)
	if obj == nil {
		oid, err := newID("")
		if err != nil {
			return added, err
		}
		obj = server.NewFolderNode(oid, bn.Name)
		_ = obj.SetAttribute(ua.AttributeIDBrowseName, server.DataValueFromValue(bn))
		add(obj)
		obj.AddReference(srv.Node(ua.NewNumericNodeID(0, id.LogObjectType)), ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
		pn.AddRef(obj, server.RefTypeIDHasComponent, true)
	}
	method := childNode(srv, obj.ID(), &ua.QualifiedName{Name: "GetRecords"})
	if method == nil {
		mid, err := newID(".GetRecords")
		if err != nil {
			return added, err
		}
		method = server.NewNode(mid, server.Attributes{
			ua.AttributeIDNodeClass:      server.DataValueFromValue(uint32(ua.NodeClassMethod)),
			ua.AttributeIDBrowseName:     server.DataValueFromValue(&ua.QualifiedName{Name: "GetRecords"}),
			ua.AttributeIDDisplayName:    server.DataValueFromValue(ua.NewLocalizedText("GetRecords")),
			ua.AttributeIDDescription:    server.DataValueFromValue(&ua.LocalizedText{}),
			ua.AttributeIDExecutable:     server.DataValueFromValue(true),
			ua.AttributeIDUserExecutable: server.DataValueFromValue(true),
		}, []*ua.ReferenceDescription{}, nil)
		add(method)
		obj.AddRef(method, server.RefTypeIDHasComponent, true)
	}
	// InputArguments and OutputArguments of the declaration (Table 4) when
	// the Method has none.
	for _, name := range []string{"InputArguments", "OutputArguments"} {
		if childNode(srv, method.ID(), &ua.QualifiedName{Name: name}) != nil {
			continue
		}
		decl := childNode(srv, ua.NewNumericNodeID(0, id.LogObjectTypeGetRecords), &ua.QualifiedName{Name: name})
		pid, err := newID(".GetRecords." + name)
		if err != nil {
			return added, err
		}
		add(property(srv, method, pid, name, id.Argument, 1, decl.Value()))
	}
	props := []struct {
		name string
		dt   uint32
		v    any
	}{{"MaxRecords", id.UInt32, uint32(l.max)}}
	if l.minSev > 0 {
		props = append(props, struct {
			name string
			dt   uint32
			v    any
		}{"MinimumSeverity", id.UInt16, l.minSev})
	}
	for _, p := range props {
		dv := server.DataValueFromValue(p.v)
		if n := childNode(srv, obj.ID(), &ua.QualifiedName{Name: p.name}); n != nil {
			_ = n.SetAttribute(ua.AttributeIDValue, dv)
			continue
		}
		pid, err := newID("." + p.name)
		if err != nil {
			return added, err
		}
		add(property(srv, obj, pid, p.name, p.dt, -1, dv))
	}
	if logs := srv.Node(ua.NewNumericNodeID(0, id.Logs)); logs != nil {
		logs.AddRef(obj, server.RefTypeIDOrganizes, true)
	}
	l.node = obj.ID()
	srv.RegisterMethod(obj.ID(), method.ID(), l.getRecords)
	return added, nil
}

// property returns a new Property nid of parent with a constant value.
func property(srv *server.Server, parent *server.Node, nid *ua.NodeID, name string, dt uint32, rank int32, dv *ua.DataValue) *server.Node {
	n := server.NewNode(nid, server.Attributes{
		ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:      server.DataValueFromValue(&ua.QualifiedName{Name: name}),
		ua.AttributeIDDisplayName:     server.DataValueFromValue(ua.NewLocalizedText(name)),
		ua.AttributeIDDescription:     server.DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:        server.DataValueFromValue(ua.NewNumericNodeID(0, dt)),
		ua.AttributeIDValueRank:       server.DataValueFromValue(rank),
		ua.AttributeIDAccessLevel:     server.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel: server.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
	}, []*ua.ReferenceDescription{}, func() *ua.DataValue { return dv })
	parent.AddReference(n, ua.NewNumericNodeID(0, id.HasProperty), true)
	n.AddReference(srv.Node(ua.NewNumericNodeID(0, id.PropertyType)), ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
	return n
}

// childNode returns the hierarchical child of n with the BrowseName bn, nil
// when n has none.
func childNode(srv *server.Server, n *ua.NodeID, bn *ua.QualifiedName) *server.Node {
	ns, err := srv.Namespace(int(n.Namespace()))
	if err != nil {
		return nil
	}
	res := ns.Browse(&ua.BrowseDescription{NodeID: n, BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true,
		ResultMask: uint32(ua.BrowseResultMaskAll)})
	if res == nil || res.StatusCode != ua.StatusOK {
		return nil
	}
	for _, r := range res.References {
		if r.BrowseName != nil && r.BrowseName.Name == bn.Name && r.BrowseName.NamespaceIndex == bn.NamespaceIndex &&
			r.NodeID != nil && r.NodeID.NamespaceURI == "" && r.NodeID.ServerIndex == 0 {
			return srv.Node(r.NodeID.NodeID)
		}
	}
	return nil
}
