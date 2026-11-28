// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

func TestSpanContextOf(t *testing.T) {
	sc := &ua.SpanContextDataType{TraceID: ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63"), SpanID: 3}
	hdr := func(ps ...*ua.KeyValuePair) *ua.RequestHeader {
		return &ua.RequestHeader{AdditionalHeader: ua.NewExtensionObject(&ua.AdditionalParametersType{Parameters: ps})}
	}
	param := func(ns uint16, v any) *ua.KeyValuePair {
		return &ua.KeyValuePair{Key: &ua.QualifiedName{NamespaceIndex: ns, Name: spanContextName}, Value: ua.MustVariant(v)}
	}
	got := spanContextOf(hdr(nil, &ua.KeyValuePair{}, param(1, ua.NewExtensionObject(sc)),
		&ua.KeyValuePair{Key: &ua.QualifiedName{Name: spanContextName}}, param(0, ua.NewExtensionObject(sc))))
	require.NotNil(t, got)
	require.Equal(t, uint64(3), got.SpanID)
	require.NotSame(t, sc, got)

	for name, h := range map[string]*ua.RequestHeader{
		"no header":            nil,
		"no AdditionalHeader":  {},
		"another structure":    {AdditionalHeader: ua.NewExtensionObject(sc)},
		"not a structure":      hdr(param(0, "x")),
		"another structure in": hdr(param(0, ua.NewExtensionObject(&ua.AdditionalParametersType{}))),
		"SpanId 0":             hdr(param(0, ua.NewExtensionObject(&ua.SpanContextDataType{}))),
		"none":                 hdr(),
	} {
		require.Nil(t, spanContextOf(h), name)
	}
}
