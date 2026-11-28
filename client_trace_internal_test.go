// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

func TestApplySpanContext(t *testing.T) {
	sc := &ua.SpanContextDataType{TraceID: ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63"), SpanID: 9}
	ctx := WithSpanContext(context.Background(), sc)
	params := func(r ua.Request) []*ua.KeyValuePair {
		return r.Header().AdditionalHeader.Value.(*ua.AdditionalParametersType).Parameters
	}

	// A request without a header gets one.
	r := &ua.CallRequest{}
	applySpanContext(ctx, r)
	require.Len(t, params(r), 1)
	got := params(r)[0].Value.Value().(*ua.ExtensionObject).Value.(*ua.SpanContextDataType)
	require.Equal(t, uint64(9), got.SpanID)
	require.NotSame(t, sc, got)

	// Other parameters stay, before it; an empty AdditionalHeader is none.
	other := &ua.KeyValuePair{Key: &ua.QualifiedName{Name: "ECDHPolicyUri"}, Value: ua.MustVariant("x")}
	r = &ua.CallRequest{RequestHeader: &ua.RequestHeader{AuditEntryID: "a",
		AdditionalHeader: ua.NewExtensionObject(&ua.AdditionalParametersType{Parameters: []*ua.KeyValuePair{nil, other}})}}
	applySpanContext(ctx, r)
	require.Len(t, params(r), 3)
	require.Same(t, other, params(r)[1])
	require.Equal(t, "a", r.Header().AuditEntryID)
	r = &ua.CallRequest{RequestHeader: &ua.RequestHeader{AdditionalHeader: ua.NewExtensionObject(nil)}}
	applySpanContext(ctx, r)
	require.Len(t, params(r), 1)

	// A SpanContext the request has already is kept.
	mine := &ua.KeyValuePair{Key: &ua.QualifiedName{Name: spanContextName}, Value: ua.MustVariant(ua.NewExtensionObject(&ua.SpanContextDataType{SpanID: 1}))}
	r = &ua.CallRequest{RequestHeader: &ua.RequestHeader{AdditionalHeader: ua.NewExtensionObject(&ua.AdditionalParametersType{Parameters: []*ua.KeyValuePair{mine}})}}
	applySpanContext(ctx, r)
	require.Equal(t, []*ua.KeyValuePair{mine}, params(r))

	// A parameter of that name in another namespace is not it.
	r = &ua.CallRequest{RequestHeader: &ua.RequestHeader{AdditionalHeader: ua.NewExtensionObject(&ua.AdditionalParametersType{Parameters: []*ua.KeyValuePair{
		{Key: &ua.QualifiedName{NamespaceIndex: 1, Name: spanContextName}}}})}}
	applySpanContext(ctx, r)
	require.Len(t, params(r), 2)

	// Another structure in the AdditionalHeader is left alone.
	eo := ua.NewExtensionObject(&ua.SpanContextDataType{SpanID: 2})
	r = &ua.CallRequest{RequestHeader: &ua.RequestHeader{AdditionalHeader: eo}}
	applySpanContext(ctx, r)
	require.Same(t, eo, r.Header().AdditionalHeader)

	// Without a SpanContext, with SpanId 0, or without a request: nothing.
	r = &ua.CallRequest{}
	applySpanContext(context.Background(), r)
	require.Nil(t, r.RequestHeader)
	applySpanContext(WithSpanContext(context.Background(), &ua.SpanContextDataType{}), r)
	require.Nil(t, r.RequestHeader)
	applySpanContext(ctx, nil)
}
