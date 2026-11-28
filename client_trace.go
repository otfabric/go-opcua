// SPDX-License-Identifier: MIT

package opcua

import (
	"context"

	"github.com/otfabric/go-opcua/ua"
)

// spanContextName is the name of the AdditionalHeader parameter that
// carries a SpanContextDataType (OPC 10000-26 §5.6.4), in namespace 0.
const spanContextName = "SpanContext"

// spanContextKey carries the SpanContext of WithSpanContext.
type spanContextKey struct{}

// WithSpanContext returns a context whose requests carry sc in the
// AdditionalHeader of their RequestHeader (OPC 10000-4 §7.32): an
// AdditionalParametersType (§7.1) with the parameter "SpanContext", as OPC
// 10000-26 §5.6.4 passes the trace of a Client to a Server. A request whose
// AdditionalHeader has a SpanContext already keeps it; other parameters of
// the header are kept. A nil sc, or one with SpanId 0 (an invalid SpanId,
// §5.6.2), adds nothing.
func WithSpanContext(ctx context.Context, sc *ua.SpanContextDataType) context.Context {
	return context.WithValue(ctx, spanContextKey{}, sc)
}

// applySpanContext adds the SpanContext of WithSpanContext to req.
func applySpanContext(ctx context.Context, req ua.Request) {
	sc, ok := ctx.Value(spanContextKey{}).(*ua.SpanContextDataType)
	if !ok || sc == nil || sc.SpanID == 0 || req == nil {
		return
	}
	var hdr ua.RequestHeader
	if h := req.Header(); h != nil {
		hdr = *h
	}
	var params []*ua.KeyValuePair
	if hdr.AdditionalHeader != nil {
		ap, ok := hdr.AdditionalHeader.Value.(*ua.AdditionalParametersType)
		if !ok && hdr.AdditionalHeader.Value != nil {
			// Another structure is not ours to replace.
			return
		}
		if ap != nil {
			for _, p := range ap.Parameters {
				if p != nil && p.Key != nil && p.Key.NamespaceIndex == 0 && p.Key.Name == spanContextName {
					return
				}
			}
			params = append(params, ap.Parameters...)
		}
	}
	cp := *sc
	params = append(params, &ua.KeyValuePair{
		Key:   &ua.QualifiedName{Name: spanContextName},
		Value: ua.MustVariant(ua.NewExtensionObject(&cp)),
	})
	hdr.AdditionalHeader = ua.NewExtensionObject(&ua.AdditionalParametersType{Parameters: params})
	req.SetHeader(&hdr)
}
