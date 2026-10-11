// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"log/slog"
	mrand "math/rand"
	"runtime/debug"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// Handler processes a service request. ctx is derived from the request and can be used
// for cancellation and timeouts; handlers should use it for downstream calls where applicable.
type Handler func(ctx context.Context, sc *uasc.SecureChannel, req ua.Request, reqID uint32) (ua.Response, error)

func (s *Server) initHandlers() {
	// s.registerHandlerFunc(id.ServiceFaultEncodingDefaultBinary, handleServiceFault)

	discovery := &DiscoveryService{s}
	s.RegisterHandler(id.FindServersRequestEncodingDefaultBinary, discovery.FindServers)
	s.RegisterHandler(id.FindServersOnNetworkRequestEncodingDefaultBinary, discovery.FindServersOnNetwork)
	s.RegisterHandler(id.GetEndpointsRequestEncodingDefaultBinary, discovery.GetEndpoints)
	s.RegisterHandler(id.RegisterServerRequestEncodingDefaultBinary, discovery.RegisterServer)
	s.RegisterHandler(id.RegisterServer2RequestEncodingDefaultBinary, discovery.RegisterServer2)

	// SecureChannel service (handled in the uasc stack)
	// s.registerHandlerFunc(id.OpenSecureChannelRequestEncodingDefaultBinary, handleOpenSecureChannel)
	// s.registerHandlerFunc(id.CloseSecureChannelRequestEncodingDefaultBinary, handleCloseSecureChannel)

	session := &SessionService{s}
	s.RegisterHandler(id.CreateSessionRequestEncodingDefaultBinary, session.CreateSession)
	s.RegisterHandler(id.ActivateSessionRequestEncodingDefaultBinary, session.ActivateSession)
	s.RegisterHandler(id.CloseSessionRequestEncodingDefaultBinary, session.CloseSession)
	s.RegisterHandler(id.CancelRequestEncodingDefaultBinary, session.Cancel)

	node := &NodeManagementService{s}
	s.RegisterHandler(id.AddNodesRequestEncodingDefaultBinary, node.AddNodes)
	s.RegisterHandler(id.AddReferencesRequestEncodingDefaultBinary, node.AddReferences)
	s.RegisterHandler(id.DeleteNodesRequestEncodingDefaultBinary, node.DeleteNodes)
	s.RegisterHandler(id.DeleteReferencesRequestEncodingDefaultBinary, node.DeleteReferences)

	view := &ViewService{srv: s, cps: make(map[string]*continuationPoint)}
	s.RegisterHandler(id.BrowseRequestEncodingDefaultBinary, view.Browse)
	s.RegisterHandler(id.BrowseNextRequestEncodingDefaultBinary, view.BrowseNext)
	s.RegisterHandler(id.TranslateBrowsePathsToNodeIDsRequestEncodingDefaultBinary, view.TranslateBrowsePathsToNodeIDs)
	s.RegisterHandler(id.RegisterNodesRequestEncodingDefaultBinary, view.RegisterNodes)
	s.RegisterHandler(id.UnregisterNodesRequestEncodingDefaultBinary, view.UnregisterNodes)

	query := &QueryService{srv: s, cps: make(map[string]*queryContinuation)}
	s.RegisterHandler(id.QueryFirstRequestEncodingDefaultBinary, query.QueryFirst)
	s.RegisterHandler(id.QueryNextRequestEncodingDefaultBinary, query.QueryNext)

	attr := &AttributeService{s}
	s.RegisterHandler(id.ReadRequestEncodingDefaultBinary, attr.Read)
	s.RegisterHandler(id.HistoryReadRequestEncodingDefaultBinary, attr.HistoryRead)
	s.RegisterHandler(id.WriteRequestEncodingDefaultBinary, attr.Write)
	s.RegisterHandler(id.HistoryUpdateRequestEncodingDefaultBinary, attr.HistoryUpdate)

	method := &MethodService{s}
	// CallRequest is the correct service-level handler per Part 4 §5.11.2.
	// CallMethodRequest is the per-method detail within a CallRequest, not a service message.
	s.RegisterHandler(id.CallRequestEncodingDefaultBinary, method.Call)

	sub := &SubscriptionService{
		srv:  s,
		Subs: make(map[uint32]*Subscription),
		// Start the subscription ids at a value that is unlikely to repeat
		// after a restart. A client that reconnects to a restarted server
		// asks for its old subscriptions by id (TransferSubscriptions,
		// Republish); if the new instance handed out the same small numbers
		// again, it would be given a subscription that another client has
		// just created.
		lastID: mrand.Uint32() >> 1,
	}
	s.SubscriptionService = sub
	s.RegisterHandler(id.CreateSubscriptionRequestEncodingDefaultBinary, sub.CreateSubscription)
	s.RegisterHandler(id.ModifySubscriptionRequestEncodingDefaultBinary, sub.ModifySubscription)
	s.RegisterHandler(id.SetPublishingModeRequestEncodingDefaultBinary, sub.SetPublishingMode)
	s.RegisterHandler(id.PublishRequestEncodingDefaultBinary, sub.Publish)
	s.RegisterHandler(id.RepublishRequestEncodingDefaultBinary, sub.Republish)
	s.RegisterHandler(id.TransferSubscriptionsRequestEncodingDefaultBinary, sub.TransferSubscriptions)
	s.RegisterHandler(id.DeleteSubscriptionsRequestEncodingDefaultBinary, sub.DeleteSubscriptions)

	item := &MonitoredItemService{
		SubService: sub,
		Items:      make(map[uint32]*MonitoredItem),
		Nodes:      make(map[string][]*MonitoredItem),
		Subs:       make(map[uint32][]*MonitoredItem),
	}
	s.MonitoredItemService = item
	// s.registerHandler(id.MonitoredItemCreateRequestEncodingDefaultBinary, item.MonitoredItemCreate)
	s.RegisterHandler(id.CreateMonitoredItemsRequestEncodingDefaultBinary, item.CreateMonitoredItems)
	//s.RegisterHandler(id.CreateMonitoredItemsRequestEncodingDefaultBinary, s.CreateMonitoredItems)
	// s.registerHandler(id.MonitoredItemModifyRequestEncodingDefaultBinary, item.MonitoredItemModify)
	s.RegisterHandler(id.ModifyMonitoredItemsRequestEncodingDefaultBinary, item.ModifyMonitoredItems)
	s.RegisterHandler(id.SetMonitoringModeRequestEncodingDefaultBinary, item.SetMonitoringMode)
	s.RegisterHandler(id.SetTriggeringRequestEncodingDefaultBinary, item.SetTriggering)
	s.RegisterHandler(id.DeleteMonitoredItemsRequestEncodingDefaultBinary, item.DeleteMonitoredItems)
}

// RegisterHandler allows you to overwrite a handler before you call start.
func (s *Server) RegisterHandler(typeID uint16, h Handler) {
	_, ok := s.handlers[typeID]
	if !ok {
		s.handlers[typeID] = h
	}
}

func (s *Server) handleService(ctx context.Context, sc *uasc.SecureChannel, reqID uint32, req ua.Request) {
	resp := s.serve(ctx, sc, reqID, req)
	if resp == nil {
		return
	}
	s.respond(sc, reqID, resp)
}

// serve runs the handler of a request and returns the response to send, or
// nil if the request is answered later (Publish). It never panics: a panic
// in a handler, or in application code a handler calls (method handlers,
// value functions, access controllers, validators), fails that one request
// with BadInternalError.
func (s *Server) serve(ctx context.Context, sc *uasc.SecureChannel, reqID uint32, req ua.Request) (resp ua.Response) {
	s.cfg.logger.Debug("handleService", "type", fmt.Sprintf("%T", req))

	m := s.cfg.metrics
	var svc string
	var start time.Time
	if m != nil {
		svc = serviceName(req)
		m.OnRequest(svc)
		start = time.Now()
	}

	var err error

	defer func() {
		if r := recover(); r != nil {
			logPanic(s.cfg.logger, "handling a request", r, "type", fmt.Sprintf("%T", req), "request_id", reqID)
			if m != nil {
				m.OnError(svc, time.Since(start), ua.StatusBadInternalError)
			}
			resp = &ua.ServiceFault{ResponseHeader: responseHeader(requestHandle(req), ua.StatusBadInternalError)}
		}
	}()

	typeID := ua.ServiceTypeID(req)
	h, ok := s.handlers[typeID]
	if status := s.checkSession(req); ok && status != ua.StatusOK {
		// The service needs an activated session and the request has none.
		err = status
	} else if ok {
		resp, err = h(ctx, sc, req, reqID)
	} else {
		if typeID == 0 {
			s.cfg.logger.Warn("unknown service", "type", fmt.Sprintf("%T", req))
		}
		err = ua.StatusBadServiceUnsupported
	}

	if m != nil {
		d := time.Since(start)
		if err != nil {
			m.OnError(svc, d, err)
		} else {
			m.OnResponse(svc, d)
		}
	}

	if err != nil {
		if statusCode, ok := err.(ua.StatusCode); ok {
			resp = &ua.ServiceFault{ResponseHeader: responseHeader(0, statusCode)}
		} else {
			resp = &ua.ServiceFault{ResponseHeader: responseHeader(0, ua.StatusBadUnexpectedError)}
		}
	}

	return resp
}

// requestHandle returns the handle of a request, or 0 if it has no header.
func requestHandle(req ua.Request) uint32 {
	if req == nil {
		return 0
	}
	if hdr := req.Header(); hdr != nil {
		return hdr.RequestHandle
	}
	return 0
}

// respond sends a response on sc. A channel that is served by the server has
// a writer, which takes the response without blocking; see channelWriter.
// Otherwise (a channel driven directly, as tests do) it is written in place,
// bounded by the response write timeout.
func (s *Server) respond(sc *uasc.SecureChannel, reqID uint32, resp ua.Response) {
	if w := s.channelWriter(sc); w != nil {
		if !w.acquire(context.Background()) {
			return
		}
		if err := w.send(reqID, resp); err != nil {
			s.cfg.logger.Debug("response dropped", "error", err)
		}
		return
	}
	if err := s.writeDirect(sc, reqID, resp); err != nil {
		s.cfg.logger.Warn("error sending response", "error", err)
		// The response could not be sent, most likely because it could not
		// be encoded. Never leave the request unanswered: the client would
		// block until its timeout. If the connection itself is broken this
		// second send fails as well, which is harmless.
		if _, isFault := resp.(*ua.ServiceFault); !isFault {
			fault := &ua.ServiceFault{ResponseHeader: responseHeader(0, ua.StatusBadEncodingError)}
			if ferr := s.writeDirect(sc, reqID, fault); ferr != nil {
				s.cfg.logger.Warn("error sending service fault", "error", ferr)
			}
		}
	}
}

// channelWriter returns the writer of a channel registered with the server.
func (s *Server) channelWriter(sc *uasc.SecureChannel) *channelWriter {
	if s.cb == nil || sc == nil {
		return nil
	}
	return s.cb.writer(sc)
}

// writeDirect writes a response on the calling goroutine with the response
// write timeout as deadline.
func (s *Server) writeDirect(sc *uasc.SecureChannel, reqID uint32, resp ua.Response) error {
	timeout := s.cfg.responseWriteTimeout
	if timeout <= 0 {
		timeout = defaultResponseWriteTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return sc.SendResponseWithContext(ctx, reqID, resp)
}

// sendPublishResponse sends a Publish response from a subscription. The
// request it answers was parked and holds no in-flight slot, so the response
// goes into the channel's (bounded) Publish backlog. An error means that the
// client does not get the message now; the subscription keeps it in its
// retransmission queue.
func (s *Server) sendPublishResponse(sc *uasc.SecureChannel, reqID uint32, resp ua.Response) error {
	if sc == nil {
		return errChannelGone
	}
	if w := s.channelWriter(sc); w != nil {
		return w.sendUnslotted(reqID, resp)
	}
	return s.writeDirect(sc, reqID, resp)
}

// superviseMonitor keeps the request handling goroutine alive. serve
// recovers from panics in handlers; this covers everything around it.
func (s *Server) superviseMonitor(ctx context.Context) {
	for ctx.Err() == nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logPanic(s.cfg.logger, "dispatching requests", r)
				}
			}()
			s.monitorConnections(ctx)
		}()
	}
}

// logPanic logs a recovered panic with its stack at Error level.
func logPanic(l *slog.Logger, what string, r any, args ...any) {
	if l == nil {
		return
	}
	args = append([]any{"panic", fmt.Sprint(r), "stack", string(debug.Stack())}, args...)
	l.Error("recovered from panic while "+what, args...)
}

// goSafe runs fn in a new goroutine. A panic in it (typically in application
// supplied code such as a value function) is logged instead of ending the
// process.
func (s *Server) goSafe(what string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logPanic(s.cfg.logger, what, r)
			}
		}()
		fn()
	}()
}

// checkSession enforces the session state machine of Part 4 §5.6: apart from
// the Discovery services and the services that establish a session, every
// service is only available within a session that has been activated.
//
// Without this check a client can use the address space without ever
// authenticating (CreateSession without ActivateSession, or no session at
// all), and a request carrying the token of a session that was closed or
// has timed out keeps being served.
func (s *Server) checkSession(req ua.Request) ua.StatusCode {
	switch req.(type) {
	case *ua.FindServersRequest, *ua.FindServersOnNetworkRequest, *ua.GetEndpointsRequest,
		*ua.RegisterServerRequest, *ua.RegisterServer2Request,
		*ua.CreateSessionRequest, *ua.ActivateSessionRequest, *ua.CloseSessionRequest:
		// CloseSession is allowed for a session that was never activated;
		// its handler validates the token.
		return ua.StatusOK
	}

	hdr := req.Header()
	if hdr == nil || hdr.AuthenticationToken == nil {
		return ua.StatusBadSessionIDInvalid
	}
	sess := s.sb.Session(hdr.AuthenticationToken)
	if sess == nil {
		return ua.StatusBadSessionIDInvalid
	}
	if !sess.activated.Load() {
		return ua.StatusBadSessionNotActivated
	}
	return ua.StatusOK
}

func responseHeader(reqID uint32, statusCode ua.StatusCode) *ua.ResponseHeader {
	return &ua.ResponseHeader{
		Timestamp:          time.Now(),
		RequestHandle:      reqID,
		ServiceResult:      statusCode,
		ServiceDiagnostics: &ua.DiagnosticInfo{},
		StringTable:        []string{},
		AdditionalHeader:   ua.NewExtensionObject(nil),
	}
}

func serviceUnsupported(hdr *ua.RequestHeader) ua.Response {
	return &ua.ServiceFault{
		ResponseHeader: responseHeader(hdr.RequestHandle, ua.StatusBadServiceUnsupported),
	}
}

func safeReq[T ua.Request](r ua.Request) (T, error) {
	var t T
	req, ok := r.(T)
	if !ok {
		//debug.Printf("expected %T, got %T", t, r)
		return t, ua.StatusBadRequestTypeInvalid
	}
	return req, nil
}

// func handleServiceFault(s *Server, sc *uasc.SecureChannel, r ua.Request) (ua.Response, error) {
// 	debug.Printf("Handling %T", r)

// 	req, ok := r.(*ua.ServiceFault)
// 	if !ok {
// 		debug.Printf("handleServiceFault: Expected *ua.ServiceFault, got %T", r)
// 		return nil, ua.StatusBadRequestTypeInvalid
// 	}
// 	debug.Printf("Got ServiceFault: %s", req.ResponseHeader.ServiceResult)

// 	// No response required
// 	return nil, nil
// }
