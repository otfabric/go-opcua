// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// ReturnDiagnostics sets the ReturnDiagnostics mask of the RequestHeader of
// every request the client sends (Part 4 §7.33), e.g.
// ua.ReturnDiagnosticsAll. A request that sets a mask of its own keeps it.
//
// The server then returns DiagnosticInfos: the operation diagnostics are in
// the DiagnosticInfos of the response (resolve them with
// ResponseHeader.Diagnostic), and a request the server rejects fails with a
// *ServiceError that carries the service diagnostics and unwraps to the
// StatusCode.
func ReturnDiagnostics(mask uint32) Option {
	return func(cfg *Config) error {
		cfg.returnDiagnostics = mask & ua.ReturnDiagnosticsAll
		return nil
	}
}

// ServiceError is the error of a request that the server rejected with
// service diagnostics (Part 4 §7.12): the ServiceResult and its resolved
// DiagnosticInfo. errors.Is(err, status) and errors.As(err, &status) see the
// StatusCode.
type ServiceError struct {
	StatusCode ua.StatusCode
	Diagnostic *ua.Diagnostic
}

func (e *ServiceError) Error() string {
	if s := e.Diagnostic.String(); s != "" {
		return e.StatusCode.Error() + " (" + s + ")"
	}
	return e.StatusCode.Error()
}

// Unwrap returns the StatusCode.
func (e *ServiceError) Unwrap() error { return e.StatusCode }

// wantsDiagnostics reports whether the request asks for diagnostics, by the
// ReturnDiagnostics option or its own header.
func (c *Client) wantsDiagnostics(req ua.Request) bool {
	if c.cfg.returnDiagnostics != 0 {
		return true
	}
	if req == nil {
		return false
	}
	hdr := req.Header()
	return hdr != nil && hdr.ReturnDiagnostics != 0
}

// prepareDiagnostics applies the ReturnDiagnostics option to a request and
// returns the handler that records the header of the response.
func (c *Client) prepareDiagnostics(req ua.Request, h func(ua.Response) error) (func(ua.Response) error, *ua.ResponseHeader) {
	if m := c.cfg.returnDiagnostics; m != 0 && req != nil {
		if hdr := req.Header(); hdr == nil {
			req.SetHeader(&ua.RequestHeader{ReturnDiagnostics: m})
		} else if hdr.ReturnDiagnostics == 0 {
			cp := *hdr
			cp.ReturnDiagnostics = m
			req.SetHeader(&cp)
		}
	}
	rh := new(ua.ResponseHeader)
	return func(r ua.Response) error {
		if r != nil {
			if hdr := r.Header(); hdr != nil {
				*rh = *hdr
			}
		}
		if h == nil {
			return nil
		}
		return h(r)
	}, rh
}

// serviceError turns the StatusCode of a rejected request into a
// *ServiceError when the response carried service diagnostics.
func serviceError(err error, rh *ua.ResponseHeader) error {
	var st ua.StatusCode
	if err == nil || rh == nil || !errors.As(err, &st) || rh.ServiceResult != st {
		return err
	}
	if _, ok := err.(ua.StatusCode); !ok {
		return err
	}
	d := rh.ServiceDiagnostic()
	if d == nil {
		return err
	}
	return &ServiceError{StatusCode: st, Diagnostic: d}
}

// ServerDiagnosticsSummary reads Server.ServerDiagnostics.ServerDiagnosticsSummary
// (i=2275, Part 5 §6.3.3).
func (c *Client) ServerDiagnosticsSummary(ctx context.Context) (*ua.ServerDiagnosticsSummaryDataType, error) {
	return readStruct[ua.ServerDiagnosticsSummaryDataType](ctx, c, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsServerDiagnosticsSummary))
}

// ServerDiagnosticsEnabled reads Server.ServerDiagnostics.EnabledFlag
// (i=2294): whether the server collects diagnostics.
func (c *Client) ServerDiagnosticsEnabled(ctx context.Context) (bool, error) {
	dv, err := c.readValueOK(ctx, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsEnabledFlag))
	if err != nil {
		return false, err
	}
	on, ok := dv.Value.Value().(bool)
	if !ok {
		return false, fmt.Errorf("opcua: EnabledFlag: expected Boolean, got %T", dv.Value.Value())
	}
	return on, nil
}

// SetServerDiagnosticsEnabled writes Server.ServerDiagnostics.EnabledFlag.
// Enabling resets the diagnostics of the server (Part 5 §6.3.3). Servers
// usually allow it to administrators only.
func (c *Client) SetServerDiagnosticsEnabled(ctx context.Context, on bool) error {
	st, err := c.WriteValue(ctx, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsEnabledFlag), &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(on),
	})
	if err != nil {
		return err
	}
	if st != ua.StatusOK {
		return st
	}
	return nil
}

// SessionDiagnostics reads
// Server.ServerDiagnostics.SessionsDiagnosticsSummary.SessionDiagnosticsArray
// (i=3707): the diagnostics of the sessions of the server.
func (c *Client) SessionDiagnostics(ctx context.Context) ([]*ua.SessionDiagnosticsDataType, error) {
	return readStructs[ua.SessionDiagnosticsDataType](ctx, c, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSessionsDiagnosticsSummarySessionDiagnosticsArray))
}

// SessionSecurityDiagnostics reads SessionSecurityDiagnosticsArray (i=3708).
// Servers restrict it to administrators over encrypted channels.
func (c *Client) SessionSecurityDiagnostics(ctx context.Context) ([]*ua.SessionSecurityDiagnosticsDataType, error) {
	return readStructs[ua.SessionSecurityDiagnosticsDataType](ctx, c, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSessionsDiagnosticsSummarySessionSecurityDiagnosticsArray))
}

// SubscriptionDiagnostics reads Server.ServerDiagnostics.SubscriptionDiagnosticsArray
// (i=2290).
func (c *Client) SubscriptionDiagnostics(ctx context.Context) ([]*ua.SubscriptionDiagnosticsDataType, error) {
	return readStructs[ua.SubscriptionDiagnosticsDataType](ctx, c, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSubscriptionDiagnosticsArray))
}

// SamplingIntervalDiagnostics reads
// Server.ServerDiagnostics.SamplingIntervalDiagnosticsArray (i=2289).
func (c *Client) SamplingIntervalDiagnostics(ctx context.Context) ([]*ua.SamplingIntervalDiagnosticsDataType, error) {
	return readStructs[ua.SamplingIntervalDiagnosticsDataType](ctx, c, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSamplingIntervalDiagnosticsArray))
}

// SessionDiagnosticsOf reads the SessionDiagnostics variable of the
// diagnostics object of a session (Part 5 §6.3.5), whose NodeId is the
// SessionId. A nil sessionID is the session of the client.
func (c *Client) SessionDiagnosticsOf(ctx context.Context, sessionID *ua.NodeID) (*ua.SessionDiagnosticsDataType, error) {
	nid, err := c.sessionDiagnosticsNode(ctx, sessionID, "SessionDiagnostics")
	if err != nil {
		return nil, err
	}
	return readStruct[ua.SessionDiagnosticsDataType](ctx, c, nid)
}

// SessionSecurityDiagnosticsOf reads the SessionSecurityDiagnostics
// variable of the diagnostics object of a session. A nil sessionID is the
// session of the client.
func (c *Client) SessionSecurityDiagnosticsOf(ctx context.Context, sessionID *ua.NodeID) (*ua.SessionSecurityDiagnosticsDataType, error) {
	nid, err := c.sessionDiagnosticsNode(ctx, sessionID, "SessionSecurityDiagnostics")
	if err != nil {
		return nil, err
	}
	return readStruct[ua.SessionSecurityDiagnosticsDataType](ctx, c, nid)
}

// sessionDiagnosticsNode returns the NodeId of a component of the
// diagnostics object of a session.
func (c *Client) sessionDiagnosticsNode(ctx context.Context, sessionID *ua.NodeID, name string) (*ua.NodeID, error) {
	if sessionID == nil {
		s := c.Session()
		if s == nil {
			return nil, ua.StatusBadSessionIDInvalid
		}
		sessionID = s.SessionID()
	}
	resp, err := send[ua.TranslateBrowsePathsToNodeIDsResponse](ctx, c, &ua.TranslateBrowsePathsToNodeIDsRequest{
		BrowsePaths: []*ua.BrowsePath{{
			StartingNode: sessionID,
			RelativePath: &ua.RelativePath{Elements: []*ua.RelativePathElement{{
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
				TargetName:      &ua.QualifiedName{Name: name},
			}}},
		}},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != 1 || resp.Results[0] == nil {
		return nil, ua.StatusBadUnknownResponse
	}
	r := resp.Results[0]
	if r.StatusCode != ua.StatusOK {
		return nil, r.StatusCode
	}
	if len(r.Targets) == 0 || r.Targets[0] == nil || r.Targets[0].TargetID == nil {
		return nil, ua.StatusBadNoMatch
	}
	return r.Targets[0].TargetID.NodeID, nil
}

// readValueOK reads the value of a node and fails with its status if it is
// not Good.
func (c *Client) readValueOK(ctx context.Context, nid *ua.NodeID) (*ua.DataValue, error) {
	dv, err := c.ReadValue(ctx, nid)
	if err != nil {
		return nil, err
	}
	if dv.Status != ua.StatusOK {
		return nil, dv.Status
	}
	if dv.Value == nil {
		return nil, ua.StatusBadNoData
	}
	return dv, nil
}

// readStruct reads a variable whose value is a structure of type T.
func readStruct[T any](ctx context.Context, c *Client, nid *ua.NodeID) (*T, error) {
	dv, err := c.readValueOK(ctx, nid)
	if err != nil {
		return nil, err
	}
	eo, ok := dv.Value.Value().(*ua.ExtensionObject)
	if !ok || eo == nil {
		return nil, fmt.Errorf("opcua: %s: expected ExtensionObject, got %T", nid, dv.Value.Value())
	}
	v, ok := eo.Value.(*T)
	if !ok {
		return nil, fmt.Errorf("opcua: %s: expected %T, got %T", nid, (*T)(nil), eo.Value)
	}
	return v, nil
}

// readStructs reads a variable whose value is an array of structures of
// type T.
func readStructs[T any](ctx context.Context, c *Client, nid *ua.NodeID) ([]*T, error) {
	dv, err := c.readValueOK(ctx, nid)
	if err != nil {
		return nil, err
	}
	var eos []*ua.ExtensionObject
	switch v := dv.Value.Value().(type) {
	case []*ua.ExtensionObject:
		eos = v
	case nil:
	default:
		return nil, fmt.Errorf("opcua: %s: expected ExtensionObject[], got %T", nid, v)
	}
	out := make([]*T, 0, len(eos))
	for _, eo := range eos {
		if eo == nil {
			continue
		}
		v, ok := eo.Value.(*T)
		if !ok {
			return nil, fmt.Errorf("opcua: %s: expected %T, got %T", nid, (*T)(nil), eo.Value)
		}
		out = append(out, v)
	}
	return out, nil
}
