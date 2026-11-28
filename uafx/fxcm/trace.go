// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"crypto/rand"
	"encoding/binary"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// RunFailure is a failure of a run (Event.Failures): of the endpoint
// Endpoint, or, with a zero Endpoint, of the run without a Connection to
// report it on (Part 81 §8.10: SourceName "ConnectionManager").
type RunFailure struct {
	Endpoint EndpointRef
	Failure
}

// newTraceID returns the TraceId of a run: a random Guid (OPC 10000-26
// §5.6.2: a Guid that identifies the trace).
func newTraceID() *ua.GUID {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return &ua.GUID{Data1: binary.BigEndian.Uint32(b[:4]), Data2: binary.BigEndian.Uint16(b[4:6]),
		Data3: binary.BigEndian.Uint16(b[6:8]), Data4: b[8:]}
}

// span returns a new SpanId of the Manager: unique among its calls and
// never 0 (OPC 10000-26 §5.6.2).
func (m *Manager) span() uint64 {
	for {
		if s := m.spans.Add(1); s != 0 {
			return s
		}
	}
}

// traced returns ctx with the SpanContext of a new span of the run, which
// the request of the call carries (Part 81 §6.7.2: "the ConnectionManager
// shall provide the SpanContextDataType as part of the EstablishConnection
// Method Call to each AutomationComponent"; OPC 10000-26 §5.6.4), and the
// TraceContext of the call for its Event; ctx and nil without
// Options.TraceCalls.
func (x *run) traced(ctx context.Context) (context.Context, *ua.TraceContextDataType) {
	if !x.m.opts.TraceCalls {
		return ctx, nil
	}
	s := x.m.span()
	return opcua.WithSpanContext(ctx, &ua.SpanContextDataType{TraceID: x.trace, SpanID: s}),
		&ua.TraceContextDataType{TraceID: x.trace, SpanID: s}
}

// callConnections returns the Connections of the endpoints of req, each
// once, in the order of req.
func callConnections(a *acRun, req *uafx.EstablishConnectionsRequest) []string {
	var out []string
	for _, cec := range req.ConnectionEndpointConfigurations {
		d := cec.ConnectionEndpoint
		if d == nil || d.Parameter == nil {
			continue
		}
		for _, ep := range a.eps {
			if ep.fe.Equal(cec.FunctionalEntityNode) && ep.e.conf.Name == d.Parameter.Name {
				out = appendOnce(out, ep.e.conn.name)
			}
		}
	}
	return out
}

// recordConnections returns the Connections of the records send of recs,
// each once.
func recordConnections(recs []*record, send []int) []string {
	var out []string
	for _, i := range send {
		out = appendOnce(out, recs[i].Endpoint.Connection)
	}
	return out
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
