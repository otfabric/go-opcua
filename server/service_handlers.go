// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"context"
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

	query := &QueryService{s}
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
	s.cfg.logger.Debugf("handleService type=%T", req)

	m := s.cfg.metrics
	var svc string
	var start time.Time
	if m != nil {
		svc = serviceName(req)
		m.OnRequest(svc)
		start = time.Now()
	}

	var resp ua.Response
	var err error

	typeID := ua.ServiceTypeID(req)
	h, ok := s.handlers[typeID]
	if ok {
		resp, err = h(ctx, sc, req, reqID)
	} else {
		if typeID == 0 {
			s.cfg.logger.Warnf("unknown service type=%T", req)
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

	if resp == nil {
		return
	}

	err = sc.SendResponseWithContext(ctx, reqID, resp)
	if err != nil {
		s.cfg.logger.Warnf("error sending response error=%v", err)
	}
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
