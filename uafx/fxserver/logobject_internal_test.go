// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

var logT0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// logArgs are the arguments of GetRecords.
func logArgs(start, end time.Time, maxRet uint32, minSev uint16, mask ua.LogRecordMask, cp []byte) []*ua.Variant {
	return []*ua.Variant{ua.MustVariant(start), ua.MustVariant(end), ua.MustVariant(maxRet), ua.MustVariant(minSev),
		ua.MustVariant(uint32(mask)), ua.MustVariant(cp)}
}

// page calls GetRecords and returns the Messages and the continuation
// point.
func page(t *testing.T, l *Log, args []*ua.Variant) ([]string, []byte, ua.StatusCode) {
	t.Helper()
	out, sc := l.getRecords(context.Background(), nil, nil, args)
	if sc != ua.StatusGood {
		return nil, nil, sc
	}
	require.Len(t, out, 2)
	recs := out[0].Value().(*ua.ExtensionObject).Value.(*ua.LogRecordsDataType)
	var msgs []string
	for _, r := range recs.LogRecordArray {
		msgs = append(msgs, r.Message.Text)
	}
	cp, _ := out[1].Value().([]byte)
	return msgs, cp, sc
}

func addAt(l *Log, at time.Duration, sev uint16, msg string) {
	l.Add(ua.LogRecord{Time: logT0.Add(at), Severity: sev, Message: ua.NewLocalizedText(msg)})
}

// TestLogAdd: the records are kept in chronological order, with the
// resolution of a DateTime; a zero Time is now; the Severity is moved
// into 1 to 1000; below MinimumSeverity a record is dropped; a full log
// deletes its oldest record (OPC 10000-26 §5.2, §5.3, §5.5).
func TestLogAdd(t *testing.T) {
	t.Parallel()
	l := newLog(LogOptions{MaxRecords: 3, MinimumSeverity: 2})
	l.now = func() time.Time { return logT0.Add(5 * time.Second) }
	assert.Equal(t, 3, l.max)
	assert.Equal(t, DefaultLogMaxReturnRecords, l.page)
	addAt(l, 2*time.Second, 100, "b")
	addAt(l, time.Second+123, 2000, "a") // before b, Severity 1000
	l.Add(ua.LogRecord{Severity: 0, Message: ua.NewLocalizedText("dropped")})
	l.Add(ua.LogRecord{Severity: 50, Message: ua.NewLocalizedText("now")})
	recs := l.Records()
	require.Len(t, recs, 3)
	assert.Equal(t, []string{"a", "b", "now"}, []string{recs[0].Message.Text, recs[1].Message.Text, recs[2].Message.Text})
	assert.Equal(t, uint16(1000), recs[0].Severity)
	assert.Equal(t, logT0.Add(time.Second+100), recs[0].Time, "100 ns resolution")
	assert.Equal(t, logT0.Add(5*time.Second), recs[2].Time)
	addAt(l, 3*time.Second, 100, "c")
	recs = l.Records()
	assert.Equal(t, "b", recs[0].Message.Text, "the oldest was deleted")
	// A record older than all is deleted at once, and the greatest
	// deleted key does not go back.
	addAt(l, 0, 100, "old")
	assert.Equal(t, "b", l.Records()[0].Message.Text)
	assert.Equal(t, logT0.Add(time.Second+100), l.gone.t)

	d := newLog(LogOptions{})
	assert.Equal(t, DefaultLogMaxRecords, d.max)
	assert.NotZero(t, d.span())
	assert.Nil(t, d.traceOf(nil))
	assert.Nil(t, d.traceOf(&server.MethodCaller{}))
	assert.Equal(t, &ua.Variant{}, valueOf(nil))
	assert.Equal(t, &ua.Variant{}, valueOf(&ua.DataValue{}))
	require.NoError(t, (&LogOptions{MinimumSeverity: 1000}).check())
	require.ErrorIs(t, (&LogOptions{MinimumSeverity: 1001}).check(), ErrLog)
}

// TestGetRecordsPaging: the records between StartTime and EndTime with
// MinimumSeverity, oldest first, in pages of MaxReturnRecords or the
// limit of the log, with a continuation point for the rest (§5.3).
func TestGetRecordsPaging(t *testing.T) {
	t.Parallel()
	l := newLog(LogOptions{MaxReturnRecords: 2})
	for i, m := range []string{"r0", "r1", "r2", "r3", "r4", "r5"} {
		sev := uint16(100)
		if i == 3 {
			sev = 10
		}
		addAt(l, time.Duration(i)*time.Second, sev, m)
	}
	end := logT0.Add(time.Hour)
	msgs, cp, _ := page(t, l, logArgs(logT0.Add(time.Second), end, 0, 50, 0, nil))
	assert.Equal(t, []string{"r1", "r2"}, msgs)
	require.Len(t, cp, cpLen)
	msgs, cp, _ = page(t, l, logArgs(logT0.Add(time.Second), end, 0, 50, 0, cp))
	assert.Equal(t, []string{"r4", "r5"}, msgs, "r3 is below the MinimumSeverity")
	assert.Nil(t, cp, "no more")

	// MaxReturnRecords below the limit of the log; EndTime inclusive.
	msgs, cp, _ = page(t, l, logArgs(logT0, logT0.Add(4*time.Second), 1, 1, 0, nil))
	assert.Equal(t, []string{"r0"}, msgs)
	var all []string
	for cp != nil {
		msgs, cp, _ = page(t, l, logArgs(logT0, logT0.Add(4*time.Second), 1, 1, 0, cp))
		all = append(all, msgs...)
	}
	assert.Equal(t, []string{"r1", "r2", "r3", "r4"}, all)

	// A continuation point with other arguments is an error; one of
	// another log, of another version or with the wrong length is
	// invalid (§5.3).
	_, cp, _ = page(t, l, logArgs(logT0, end, 0, 1, 0, nil))
	require.NotNil(t, cp)
	_, _, sc := page(t, l, logArgs(logT0, end, 0, 2, 0, cp))
	assert.Equal(t, ua.StatusBadInvalidArgument, sc)
	other := newLog(LogOptions{})
	_, _, sc = page(t, other, logArgs(logT0, end, 0, 1, 0, cp))
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, sc)
	bad := append([]byte{}, cp...)
	bad[0] = 9
	_, _, sc = page(t, l, logArgs(logT0, end, 0, 1, 0, bad))
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, sc)
	_, _, sc = page(t, l, logArgs(logT0, end, 0, 1, 0, cp[:5]))
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, sc)

	// The record a continuation point resumes at was deleted: invalid.
	s := newLog(LogOptions{MaxRecords: 3, MaxReturnRecords: 1})
	for i := range 3 {
		addAt(s, time.Duration(i)*time.Second, 100, "s")
	}
	_, cp, _ = page(t, s, logArgs(logT0, end, 0, 1, 0, nil))
	require.NotNil(t, cp)
	addAt(s, 10*time.Second, 100, "t")
	addAt(s, 11*time.Second, 100, "u")
	_, _, sc = page(t, s, logArgs(logT0, end, 0, 1, 0, cp))
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, sc)
}

// TestGetRecordsMask: the RequestMask selects the optional fields (§5.8).
func TestGetRecordsMask(t *testing.T) {
	t.Parallel()
	l := newLog(LogOptions{})
	tc := &ua.TraceContextDataType{TraceID: ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63"), SpanID: 3}
	l.Add(ua.LogRecord{Time: logT0, Severity: 100, Message: ua.NewLocalizedText("m"), EventType: ua.NewNumericNodeID(0, 1),
		SourceNode: ua.NewNumericNodeID(0, 2), SourceName: "s", TraceContext: tc, AdditionalData: []*ua.NameValuePair{nv("x", 1.0)}})
	get := func(m ua.LogRecordMask) *ua.LogRecord {
		out, sc := l.getRecords(context.Background(), nil, nil, logArgs(logT0, logT0, 0, 1, m, nil))
		require.Equal(t, ua.StatusGood, sc)
		return out[0].Value().(*ua.ExtensionObject).Value.(*ua.LogRecordsDataType).LogRecordArray[0]
	}
	r := get(0)
	assert.Equal(t, &ua.LogRecord{Time: logT0, Severity: 100, Message: ua.NewLocalizedText("m")}, r)
	r = get(ua.LogRecordMaskEventType | ua.LogRecordMaskSourceNode | ua.LogRecordMaskSourceName | ua.LogRecordMaskTraceContext | ua.LogRecordMaskAdditionalData)
	assert.Equal(t, "s", r.SourceName)
	assert.Same(t, tc, r.TraceContext)
	assert.Len(t, r.AdditionalData, 1)
	assert.NotNil(t, r.EventType)
	assert.NotNil(t, r.SourceNode)
}

// TestGetRecordsArgumentErrors: Table 3 of §5.3.
func TestGetRecordsArgumentErrors(t *testing.T) {
	t.Parallel()
	l := newLog(LogOptions{})
	end := logT0.Add(time.Hour)
	ok := logArgs(logT0, end, 0, 1, 0, nil)
	with := func(i int, v *ua.Variant) []*ua.Variant {
		a := append([]*ua.Variant{}, ok...)
		a[i] = v
		return a
	}
	for name, c := range map[string]struct {
		args []*ua.Variant
		want ua.StatusCode
	}{
		"five arguments":       {ok[:5], ua.StatusBadArgumentsMissing},
		"a nil argument":       {with(0, nil), ua.StatusBadInvalidArgument},
		"StartTime":            {with(0, ua.MustVariant("x")), ua.StatusBadTypeMismatch},
		"EndTime":              {with(1, ua.MustVariant("x")), ua.StatusBadTypeMismatch},
		"MaxReturnRecords":     {with(2, ua.MustVariant(int32(1))), ua.StatusBadTypeMismatch},
		"MinimumSeverity":      {with(3, ua.MustVariant(uint32(1))), ua.StatusBadTypeMismatch},
		"RequestMask":          {with(4, ua.MustVariant(int32(1))), ua.StatusBadTypeMismatch},
		"ContinuationPointIn":  {with(5, ua.MustVariant("x")), ua.StatusBadTypeMismatch},
		"EndTime < StartTime":  {logArgs(end, logT0, 0, 1, 0, nil), ua.StatusBadInvalidArgument},
		"MinimumSeverity 0":    {logArgs(logT0, end, 0, 0, 0, nil), ua.StatusBadInvalidArgument},
		"MinimumSeverity 1001": {logArgs(logT0, end, 0, 1001, 0, nil), ua.StatusBadInvalidArgument},
	} {
		_, sc := l.getRecords(context.Background(), nil, nil, c.args)
		assert.Equal(t, c.want, sc, name)
	}
	_, sc := l.getRecords(context.Background(), nil, nil, with(5, &ua.Variant{}))
	assert.Equal(t, ua.StatusGood, sc, "a null ContinuationPointIn is none")
}

// TestLogNodesErrors: logNodes needs the parent; the NodeIds it would add
// must be free.
func TestLogNodesErrors(t *testing.T) {
	t.Parallel()
	srv, err := server.New(server.EndPoint("localhost", 0), server.InsecureNoSecurity())
	require.NoError(t, err)
	bn := &ua.QualifiedName{Name: "Log"}
	_, err = logNodes(srv, ua.NewNumericNodeID(0, 99999999), bn, "x", newLog(LogOptions{}))
	require.ErrorIs(t, err, ErrLog)
	_, err = logNodes(srv, ua.NewNumericNodeID(77, 1), bn, "x", newLog(LogOptions{}))
	require.ErrorIs(t, err, ErrLog)
	assert.Nil(t, childNode(srv, ua.NewNumericNodeID(77, 1), bn))
	assert.Nil(t, childNode(srv, ua.NewNumericNodeID(0, 99999999), bn))

	parent := ua.NewNumericNodeID(0, id.ObjectsFolder)
	nsp, _ := srv.Namespace(0)
	for i, suffix := range []string{".GetRecords", ".GetRecords.InputArguments", ".GetRecords.OutputArguments", ".MaxRecords", ".MinimumSeverity"} {
		prefix := "t" + string(rune('a'+i))
		nsp.AddNode(server.NewVariableNode(ua.NewStringNodeID(0, prefix+suffix), "x", 1))
		added, err := logNodes(srv, parent, &ua.QualifiedName{Name: prefix}, prefix, newLog(LogOptions{MinimumSeverity: 5}))
		require.ErrorIs(t, err, ErrLog, suffix)
		assert.NotEmpty(t, added, suffix)
	}
	added, err := logNodes(srv, parent, &ua.QualifiedName{Name: "ok"}, "ok", newLog(LogOptions{MinimumSeverity: 5}))
	require.NoError(t, err)
	assert.Len(t, added, 6)
	// Again: everything is there, nothing is added.
	added, err = logNodes(srv, parent, &ua.QualifiedName{Name: "ok"}, "ok", newLog(LogOptions{}))
	require.NoError(t, err)
	assert.Empty(t, added)
}
