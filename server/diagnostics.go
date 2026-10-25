// SPDX-License-Identifier: MIT

package server

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

// Server diagnostics (Part 5 §6.3.3 ServerDiagnosticsType, §6.3.4
// SessionsDiagnosticsSummaryType, §6.3.5 SessionDiagnosticsObjectType and the
// data types of Part 5 §12.9-§12.16).
//
// The counters are atomics that the request dispatcher (Server.serve) bumps
// on the way out of a request; nothing on the hot path takes a lock. The
// values of the diagnostics variables are computed when they are read. Each
// session gets a SessionDiagnosticsObject below SessionsDiagnosticsSummary
// while it exists, in the diagnostics namespace (DiagnosticsNamespaceURI),
// with the SessionId as its NodeId.
//
// Locks: d.mu (the session objects) is taken before namespace and node locks.
// The value functions of the diagnostics variables run under the lock of
// their node and, when the variable is monitored, under the lock of the
// monitored item service: they take the session broker and subscription
// service locks and the leaf locks below, never d.mu or the monitored item
// service lock.

// DiagnosticsNamespaceURI is the namespace of the session diagnostics objects
// and of the SessionIds of the server. It is added to the namespace array
// when the first session is created, after the namespaces the application
// added before.
const DiagnosticsNamespaceURI = "urn:otfabric:go-opcua:diagnostics"

// WithServerDiagnostics sets whether the server collects diagnostics from the
// start: the initial value of Server.ServerDiagnostics.EnabledFlag (Part 5
// §6.3.3). The default is true. A client with the SecurityAdmin or
// ConfigureAdmin role can change it at runtime by writing EnabledFlag.
func WithServerDiagnostics(enabled bool) Option {
	return func(c *serverConfig) error {
		c.diagnosticsOff = !enabled
		return nil
	}
}

// ServerDiagnosticsEnabled reports whether the server collects diagnostics
// (the value of Server.ServerDiagnostics.EnabledFlag).
func (s *Server) ServerDiagnosticsEnabled() bool {
	return s.diag.enabled.Load()
}

// SetServerDiagnosticsEnabled enables or disables the collection of
// diagnostics, as a write of Server.ServerDiagnostics.EnabledFlag does
// (Part 5 §6.3.3): enabling resets the diagnostics, disabling keeps them as
// they are. While disabled ServerDiagnosticsSummary keeps the values it had,
// the diagnostics arrays are empty and the sessions have no diagnostics
// objects.
func (s *Server) SetServerDiagnosticsEnabled(on bool) {
	s.diag.setEnabled(on)
}

// ServerDiagnosticsSummary returns the current value of
// Server.ServerDiagnostics.ServerDiagnosticsSummary.
func (s *Server) ServerDiagnosticsSummary() *ua.ServerDiagnosticsSummaryDataType {
	return s.diag.summary()
}

// serverDiagnostics is the diagnostics state of a server.
type serverDiagnostics struct {
	s       *Server
	enabled atomic.Bool
	// frozen is the summary at the moment diagnostics were disabled.
	frozen atomic.Pointer[ua.ServerDiagnosticsSummaryDataType]

	cumulatedSessions        atomic.Uint32
	securityRejectedSessions atomic.Uint32
	rejectedSessions         atomic.Uint32
	sessionTimeouts          atomic.Uint32
	sessionAborts            atomic.Uint32
	cumulatedSubscriptions   atomic.Uint32
	securityRejectedRequests atomic.Uint32
	rejectedRequests         atomic.Uint32

	// mu guards ns, summaryObj and sessions. nsIndex is the index of ns,
	// -1 before it exists.
	mu         sync.Mutex
	ns         *NodeNameSpace
	nsIndex    atomic.Int32
	summaryObj *Node // SessionsDiagnosticsSummary (i=3706) of this server
	sessions   map[*session]*sessionNodes

	// subsMu is a leaf lock that guards subs.
	subsMu sync.Mutex
	subs   map[uint32]*subscriptionCounters

	// itemsMu is a leaf lock that guards the monitored item index. The
	// monitored item service updates the index under its own lock.
	itemsMu   sync.Mutex
	items     map[*MonitoredItem]itemInfo
	intervals map[float64]*intervalStat
	subItems  map[uint32]*itemCount
}

func newServerDiagnostics(s *Server, enabled bool) *serverDiagnostics {
	d := &serverDiagnostics{
		s:         s,
		sessions:  make(map[*session]*sessionNodes),
		subs:      make(map[uint32]*subscriptionCounters),
		items:     make(map[*MonitoredItem]itemInfo),
		intervals: make(map[float64]*intervalStat),
		subItems:  make(map[uint32]*itemCount),
	}
	d.enabled.Store(enabled)
	d.nsIndex.Store(-1)
	if !enabled {
		d.frozen.Store(&ua.ServerDiagnosticsSummaryDataType{})
	}
	return d
}

// serviceCounter is a ServiceCounterDataType (Part 5 §12.13).
type serviceCounter struct {
	total  atomic.Uint32
	errors atomic.Uint32
}

func (c *serviceCounter) add(failed bool) {
	c.total.Add(1)
	if failed {
		c.errors.Add(1)
	}
}

func (c *serviceCounter) value() *ua.ServiceCounterDataType {
	return &ua.ServiceCounterDataType{TotalCount: c.total.Load(), ErrorCount: c.errors.Load()}
}

func (c *serviceCounter) reset() {
	c.total.Store(0)
	c.errors.Store(0)
}

// The services counted in SessionDiagnosticsDataType, in the order of its
// fields (Part 5 §12.11).
const (
	svcRead = iota
	svcHistoryRead
	svcWrite
	svcHistoryUpdate
	svcCall
	svcCreateMonitoredItems
	svcModifyMonitoredItems
	svcSetMonitoringMode
	svcSetTriggering
	svcDeleteMonitoredItems
	svcCreateSubscription
	svcModifySubscription
	svcSetPublishingMode
	svcPublish
	svcRepublish
	svcTransferSubscriptions
	svcDeleteSubscriptions
	svcAddNodes
	svcAddReferences
	svcDeleteNodes
	svcDeleteReferences
	svcBrowse
	svcBrowseNext
	svcTranslateBrowsePaths
	svcQueryFirst
	svcQueryNext
	svcRegisterNodes
	svcUnregisterNodes
	numServiceCounters
)

// serviceCounterIndex returns the counter of a request type, or -1.
func serviceCounterIndex(typeID uint16) int {
	switch typeID {
	case id.ReadRequestEncodingDefaultBinary:
		return svcRead
	case id.HistoryReadRequestEncodingDefaultBinary:
		return svcHistoryRead
	case id.WriteRequestEncodingDefaultBinary:
		return svcWrite
	case id.HistoryUpdateRequestEncodingDefaultBinary:
		return svcHistoryUpdate
	case id.CallRequestEncodingDefaultBinary:
		return svcCall
	case id.CreateMonitoredItemsRequestEncodingDefaultBinary:
		return svcCreateMonitoredItems
	case id.ModifyMonitoredItemsRequestEncodingDefaultBinary:
		return svcModifyMonitoredItems
	case id.SetMonitoringModeRequestEncodingDefaultBinary:
		return svcSetMonitoringMode
	case id.SetTriggeringRequestEncodingDefaultBinary:
		return svcSetTriggering
	case id.DeleteMonitoredItemsRequestEncodingDefaultBinary:
		return svcDeleteMonitoredItems
	case id.CreateSubscriptionRequestEncodingDefaultBinary:
		return svcCreateSubscription
	case id.ModifySubscriptionRequestEncodingDefaultBinary:
		return svcModifySubscription
	case id.SetPublishingModeRequestEncodingDefaultBinary:
		return svcSetPublishingMode
	case id.PublishRequestEncodingDefaultBinary:
		return svcPublish
	case id.RepublishRequestEncodingDefaultBinary:
		return svcRepublish
	case id.TransferSubscriptionsRequestEncodingDefaultBinary:
		return svcTransferSubscriptions
	case id.DeleteSubscriptionsRequestEncodingDefaultBinary:
		return svcDeleteSubscriptions
	case id.AddNodesRequestEncodingDefaultBinary:
		return svcAddNodes
	case id.AddReferencesRequestEncodingDefaultBinary:
		return svcAddReferences
	case id.DeleteNodesRequestEncodingDefaultBinary:
		return svcDeleteNodes
	case id.DeleteReferencesRequestEncodingDefaultBinary:
		return svcDeleteReferences
	case id.BrowseRequestEncodingDefaultBinary:
		return svcBrowse
	case id.BrowseNextRequestEncodingDefaultBinary:
		return svcBrowseNext
	case id.TranslateBrowsePathsToNodeIDsRequestEncodingDefaultBinary:
		return svcTranslateBrowsePaths
	case id.QueryFirstRequestEncodingDefaultBinary:
		return svcQueryFirst
	case id.QueryNextRequestEncodingDefaultBinary:
		return svcQueryNext
	case id.RegisterNodesRequestEncodingDefaultBinary:
		return svcRegisterNodes
	case id.UnregisterNodesRequestEncodingDefaultBinary:
		return svcUnregisterNodes
	}
	return -1
}

// sessionDiag is the diagnostics state of a session.
type sessionDiag struct {
	created time.Time

	total        serviceCounter
	unauthorized atomic.Uint32
	services     [numServiceCounters]serviceCounter

	// mu guards the description of the session. It is a leaf lock.
	mu          sync.Mutex
	name        string
	client      *ua.ApplicationDescription
	serverURI   string
	endpointURL string
	locales     []string
	maxResponse uint32
	userID      string
	userHistory []string
	authMech    string
	secMode     ua.MessageSecurityMode
	secPolicy   string
	transport   string
	encoding    string
	clientCert  []byte
	roles       []*ua.NodeID
}

func (sd *sessionDiag) reset() {
	sd.total.reset()
	sd.unauthorized.Store(0)
	for i := range sd.services {
		sd.services[i].reset()
	}
}

// subscriptionCounters are the counters of SubscriptionDiagnosticsDataType
// (Part 5 §12.15) that the subscription itself does not hold.
type subscriptionCounters struct {
	modify, enable, disable                       atomic.Uint32
	republishRequests, republishMessageRequests   atomic.Uint32
	republishMessages                             atomic.Uint32
	transferRequests, transferredAlt, transferred atomic.Uint32
	publishRequests                               atomic.Uint32
	dataChanges, events, notifications            atomic.Uint32
	nextSeq                                       atomic.Uint32
}

func (c *subscriptionCounters) reset() {
	for _, v := range []*atomic.Uint32{&c.modify, &c.enable, &c.disable, &c.republishRequests,
		&c.republishMessageRequests, &c.republishMessages, &c.transferRequests, &c.transferredAlt,
		&c.transferred, &c.publishRequests, &c.dataChanges, &c.events, &c.notifications} {
		v.Store(0)
	}
}

// subCounters returns the counters of a subscription, creating them.
func (d *serverDiagnostics) subCounters(subID uint32) *subscriptionCounters {
	d.subsMu.Lock()
	defer d.subsMu.Unlock()
	c := d.subs[subID]
	if c == nil {
		c = &subscriptionCounters{}
		d.subs[subID] = c
	}
	return c
}

// peekSubCounters returns the counters of a subscription or nil.
func (d *serverDiagnostics) peekSubCounters(subID uint32) *subscriptionCounters {
	d.subsMu.Lock()
	defer d.subsMu.Unlock()
	return d.subs[subID]
}

// pruneSubCounters drops the counters of subscriptions that no longer exist.
func (d *serverDiagnostics) pruneSubCounters(live map[uint32]bool) {
	d.subsMu.Lock()
	defer d.subsMu.Unlock()
	for k := range d.subs {
		if !live[k] {
			delete(d.subs, k)
		}
	}
}

// itemInfo is what the monitored item index knows about an item.
type itemInfo struct {
	sub      uint32
	interval float64 // ms
	sampled  bool    // a data item (event items are not sampled)
	disabled bool
}

type intervalStat struct {
	count, disabled, max uint32
}

type itemCount struct {
	count, disabled uint32
}

// diagnostics returns the diagnostics of the server of the service, or nil.
func (s *MonitoredItemService) diagnostics() *serverDiagnostics {
	if s == nil || s.SubService == nil || s.SubService.srv == nil {
		return nil
	}
	return s.SubService.srv.diag
}

// trackItem adds a monitored item to the index or updates it after its mode
// or sampling interval changed. The monitored item service calls it with its
// lock held.
func (d *serverDiagnostics) trackItem(item *MonitoredItem) {
	if d == nil || item == nil || item.Sub == nil {
		return
	}
	info := itemInfo{
		sub:      item.Sub.ID,
		interval: float64(item.samplingInterval) / float64(time.Millisecond),
		sampled:  !item.isEvent,
		disabled: item.Mode == ua.MonitoringModeDisabled,
	}
	d.itemsMu.Lock()
	defer d.itemsMu.Unlock()
	if old, ok := d.items[item]; ok {
		if old == info {
			return
		}
		d.unindexLocked(old)
	}
	d.items[item] = info
	sc := d.subItems[info.sub]
	if sc == nil {
		sc = &itemCount{}
		d.subItems[info.sub] = sc
	}
	sc.count++
	if info.disabled {
		sc.disabled++
	}
	if info.sampled {
		st := d.intervals[info.interval]
		if st == nil {
			st = &intervalStat{}
			d.intervals[info.interval] = st
		}
		st.count++
		if info.disabled {
			st.disabled++
		}
		st.max = max(st.max, st.count)
	}
}

// untrackItem removes a deleted monitored item from the index.
func (d *serverDiagnostics) untrackItem(item *MonitoredItem) {
	if d == nil || item == nil {
		return
	}
	d.itemsMu.Lock()
	defer d.itemsMu.Unlock()
	if old, ok := d.items[item]; ok {
		delete(d.items, item)
		d.unindexLocked(old)
	}
}

func (d *serverDiagnostics) unindexLocked(info itemInfo) {
	if sc := d.subItems[info.sub]; sc != nil {
		sc.count--
		if info.disabled {
			sc.disabled--
		}
		if sc.count == 0 {
			delete(d.subItems, info.sub)
		}
	}
	if !info.sampled {
		return
	}
	if st := d.intervals[info.interval]; st != nil {
		st.count--
		if info.disabled {
			st.disabled--
		}
		if st.count == 0 {
			delete(d.intervals, info.interval)
		}
	}
}

// itemsOf returns the number of monitored items and of disabled ones of a
// subscription.
func (d *serverDiagnostics) itemsOf(subID uint32) (count, disabled uint32) {
	d.itemsMu.Lock()
	defer d.itemsMu.Unlock()
	if sc := d.subItems[subID]; sc != nil {
		return sc.count, sc.disabled
	}
	return 0, 0
}

// ---------------------------------------------------------------------------
// counting
// ---------------------------------------------------------------------------

// isSecurityStatus reports whether a request was rejected for a reason of
// security: authentication, authorisation, certificates, signatures and
// security policies.
func isSecurityStatus(st ua.StatusCode) bool {
	switch st &^ 0xFFFF {
	case ua.StatusBadCertificateInvalid, ua.StatusBadSecurityChecksFailed, ua.StatusBadCertificatePolicyCheckFailed,
		ua.StatusBadCertificateTimeInvalid, ua.StatusBadCertificateIssuerTimeInvalid, ua.StatusBadCertificateHostNameInvalid,
		ua.StatusBadCertificateURIInvalid, ua.StatusBadCertificateUseNotAllowed, ua.StatusBadCertificateIssuerUseNotAllowed,
		ua.StatusBadCertificateUntrusted, ua.StatusBadCertificateRevocationUnknown, ua.StatusBadCertificateIssuerRevocationUnknown,
		ua.StatusBadCertificateRevoked, ua.StatusBadCertificateIssuerRevoked, ua.StatusBadCertificateChainIncomplete,
		ua.StatusBadUserAccessDenied, ua.StatusBadIdentityTokenInvalid, ua.StatusBadIdentityTokenRejected,
		ua.StatusBadNonceInvalid, ua.StatusBadSessionIDInvalid, ua.StatusBadSessionNotActivated,
		ua.StatusBadSecurityModeRejected, ua.StatusBadSecurityPolicyRejected, ua.StatusBadUserSignatureInvalid,
		ua.StatusBadApplicationSignatureInvalid, ua.StatusBadNoValidCertificates, ua.StatusBadSecurityModeInsufficient,
		ua.StatusBadRequestNotAllowed:
		return true
	default:
		return false
	}
}

// isAuthorizationStatus reports whether a request was refused to the user of
// the session (UnauthorizedRequestCount, Part 5 §12.11).
func isAuthorizationStatus(st ua.StatusCode) bool {
	switch st &^ 0xFFFF {
	case ua.StatusBadUserAccessDenied, ua.StatusBadSecurityModeInsufficient, ua.StatusBadRequestNotAllowed:
		return true
	default:
		return false
	}
}

// statusOfResult returns the service result of a request: the status code
// of the error or of the response header.
func statusOfResult(resp ua.Response, err error) ua.StatusCode {
	if err != nil {
		if st, ok := err.(ua.StatusCode); ok {
			return st
		}
		return ua.StatusBadUnexpectedError
	}
	if resp != nil {
		if h := resp.Header(); h != nil {
			return h.ServiceResult
		}
	}
	return ua.StatusOK
}

func isBad(st ua.StatusCode) bool { return st&0x80000000 != 0 }

// beforeRequest is called by the dispatcher before the handler of a request
// runs. It returns what afterRequest needs to know about the state before.
func (d *serverDiagnostics) beforeRequest(req ua.Request) any {
	if !d.enabled.Load() {
		return nil
	}
	if tr, ok := req.(*ua.TransferSubscriptionsRequest); ok {
		return d.ownersOf(tr.SubscriptionIDs)
	}
	return nil
}

// ownersOf returns the sessions that own the given subscriptions.
func (d *serverDiagnostics) ownersOf(ids []uint32) map[uint32]*session {
	ss := d.s.SubscriptionService
	if ss == nil {
		return nil
	}
	out := make(map[uint32]*session, len(ids))
	ss.Mu.Lock()
	defer ss.Mu.Unlock()
	for _, id := range ids {
		if sub := ss.Subs[id]; sub != nil {
			own, _ := sub.sessionChannel()
			out[id] = own
		}
	}
	return out
}

// afterRequest counts a request once its handler returned. sess is the
// activated session of the request, nil for the session services and for a
// request that was refused for want of a session.
func (d *serverDiagnostics) afterRequest(sc *uasc.SecureChannel, typeID uint16, req ua.Request, sess *session, resp ua.Response, err error, before any) {
	if !d.enabled.Load() {
		return
	}
	st := statusOfResult(resp, err)
	bad := isBad(st)
	if bad {
		d.rejectedRequests.Add(1)
		if isSecurityStatus(st) || (err != nil && !isStatus(err)) {
			d.securityRejectedRequests.Add(1)
		}
	}

	switch r := req.(type) {
	case *ua.CreateSessionRequest:
		if bad {
			d.rejectedSessions.Add(1)
			if isSecurityStatus(st) || !isStatus(err) {
				d.securityRejectedSessions.Add(1)
			}
			return
		}
		if cr, ok := resp.(*ua.CreateSessionResponse); ok {
			d.cumulatedSessions.Add(1)
			if created := d.s.sb.peek(cr.AuthenticationToken); created != nil {
				d.describeSession(created, r, cr)
				d.addSession(created)
			}
		}
		return
	case *ua.ActivateSessionRequest:
		if bad {
			d.rejectedSessions.Add(1)
			if isSecurityStatus(st) {
				d.securityRejectedSessions.Add(1)
			}
		}
		if hdr := r.RequestHeader; hdr != nil && hdr.AuthenticationToken != nil {
			if as := d.s.sb.peek(hdr.AuthenticationToken); as != nil {
				as.diag.total.add(bad)
				if !bad {
					d.activated(sc, as, r)
				}
			}
		}
		return
	case *ua.CloseSessionRequest:
		return
	}

	if sess == nil {
		return
	}
	sess.diag.total.add(bad)
	if isAuthorizationStatus(st) {
		sess.diag.unauthorized.Add(1)
	}
	if i := serviceCounterIndex(typeID); i >= 0 {
		sess.diag.services[i].add(bad)
	}
	if bad {
		return
	}
	d.countSubscriptionRequest(req, resp, sess, before)
}

func isStatus(err error) bool {
	if err == nil {
		return true
	}
	_, ok := err.(ua.StatusCode)
	return ok
}

// countSubscriptionRequest updates the subscription counters after a
// successful request of the Subscription Service Set.
func (d *serverDiagnostics) countSubscriptionRequest(req ua.Request, resp ua.Response, sess *session, before any) {
	switch r := req.(type) {
	case *ua.CreateSubscriptionRequest:
		if cr, ok := resp.(*ua.CreateSubscriptionResponse); ok {
			d.cumulatedSubscriptions.Add(1)
			d.subCounters(cr.SubscriptionID)
			d.maybePruneSubCounters()
		}
	case *ua.ModifySubscriptionRequest:
		if c := d.peekSubCounters(r.SubscriptionID); c != nil {
			c.modify.Add(1)
		}
	case *ua.SetPublishingModeRequest:
		res, _ := resp.(*ua.SetPublishingModeResponse)
		for i, subID := range r.SubscriptionIDs {
			if res == nil || i >= len(res.Results) || res.Results[i] != ua.StatusOK {
				continue
			}
			if c := d.peekSubCounters(subID); c != nil {
				if r.PublishingEnabled {
					c.enable.Add(1)
				} else {
					c.disable.Add(1)
				}
			}
		}
	case *ua.RepublishRequest:
		if c := d.peekSubCounters(r.SubscriptionID); c != nil {
			c.republishRequests.Add(1)
			c.republishMessageRequests.Add(1)
			if rr, ok := resp.(*ua.RepublishResponse); ok && rr.ResponseHeader != nil && rr.ResponseHeader.ServiceResult == ua.StatusOK {
				c.republishMessages.Add(1)
			}
		}
	case *ua.TransferSubscriptionsRequest:
		owners, _ := before.(map[uint32]*session)
		res, _ := resp.(*ua.TransferSubscriptionsResponse)
		for i, subID := range r.SubscriptionIDs {
			c := d.peekSubCounters(subID)
			if c == nil {
				continue
			}
			c.transferRequests.Add(1)
			if res == nil || i >= len(res.Results) || res.Results[i] == nil || res.Results[i].StatusCode != ua.StatusOK {
				continue
			}
			from := owners[subID]
			if from == nil || from == sess {
				continue
			}
			if sameClient(from, sess) {
				c.transferred.Add(1)
			} else {
				c.transferredAlt.Add(1)
			}
		}
	case *ua.DeleteSubscriptionsRequest:
		res, _ := resp.(*ua.DeleteSubscriptionsResponse)
		d.subsMu.Lock()
		for i, subID := range r.SubscriptionIDs {
			if res != nil && i < len(res.Results) && res.Results[i] == ua.StatusOK {
				delete(d.subs, subID)
			}
		}
		d.subsMu.Unlock()
	}
}

// sameClient reports whether two sessions belong to the same client
// application (TransferredToSameClientCount, Part 5 §12.15).
func sameClient(a, b *session) bool {
	uriOf := func(s *session) string {
		s.diag.mu.Lock()
		defer s.diag.mu.Unlock()
		if s.diag.client == nil {
			return ""
		}
		return s.diag.client.ApplicationURI
	}
	x, y := uriOf(a), uriOf(b)
	return x != "" && x == y
}

// maybePruneSubCounters drops the counters of subscriptions that ended
// without DeleteSubscriptions (lifetime expiry, CloseSession) once they
// outnumber the subscriptions that exist.
func (d *serverDiagnostics) maybePruneSubCounters() {
	ss := d.s.SubscriptionService
	if ss == nil {
		return
	}
	d.subsMu.Lock()
	n := len(d.subs)
	d.subsMu.Unlock()
	ss.Mu.Lock()
	live := len(ss.Subs)
	if n <= 2*live+64 {
		ss.Mu.Unlock()
		return
	}
	ids := make(map[uint32]bool, live)
	for k := range ss.Subs {
		ids[k] = true
	}
	ss.Mu.Unlock()
	d.pruneSubCounters(ids)
}

// publishResponse counts a Publish response sent for a subscription.
func (d *serverDiagnostics) publishResponse(resp ua.Response) {
	if d == nil || !d.enabled.Load() {
		return
	}
	pr, ok := resp.(*ua.PublishResponse)
	if !ok || pr == nil {
		return
	}
	c := d.peekSubCounters(pr.SubscriptionID)
	if c == nil {
		return
	}
	c.publishRequests.Add(1)
	msg := pr.NotificationMessage
	if msg == nil {
		return
	}
	if len(msg.NotificationData) == 0 {
		// a keep-alive carries the next sequence number (Part 4 §5.13.1.1)
		c.nextSeq.Store(msg.SequenceNumber)
		return
	}
	c.nextSeq.Store(msg.SequenceNumber + 1)
	for _, eo := range msg.NotificationData {
		if eo == nil {
			continue
		}
		switch n := eo.Value.(type) {
		case *ua.DataChangeNotification:
			c.dataChanges.Add(1)
			c.notifications.Add(uint32(len(n.MonitoredItems)))
		case *ua.EventNotificationList:
			c.events.Add(1)
			c.notifications.Add(uint32(len(n.Events)))
		}
	}
}

// describeSession records the description of a new session.
func (d *serverDiagnostics) describeSession(sess *session, req *ua.CreateSessionRequest, resp *ua.CreateSessionResponse) {
	sd := &sess.diag
	sd.mu.Lock()
	defer sd.mu.Unlock()
	sd.name = req.SessionName
	sd.client = req.ClientDescription
	sd.serverURI = req.ServerURI
	sd.endpointURL = req.EndpointURL
	sd.maxResponse = req.MaxResponseMessageSize
	sd.clientCert = slices.Clone(req.ClientCertificate)
	sd.transport = transportProfileOf(req.EndpointURL)
	sd.encoding = "UA Binary"
	_ = resp
}

// transportProfileOf returns the transport profile of an endpoint URL.
func transportProfileOf(url string) string {
	switch {
	case len(url) >= 8 && url[:8] == "opc.wss:":
		return "http://opcfoundation.org/UA-Profile/Transport/wss-uasc-uabinary"
	case len(url) >= 6 && url[:6] == "https:":
		return "http://opcfoundation.org/UA-Profile/Transport/https-uabinary"
	}
	return "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
}

// activated records the identity of a session after a successful
// ActivateSession.
func (d *serverDiagnostics) activated(sc *uasc.SecureChannel, sess *session, req *ua.ActivateSessionRequest) {
	user, mech := userOf(sess.identityToken)
	sd := &sess.diag
	sd.mu.Lock()
	defer sd.mu.Unlock()
	if user != sd.userID || len(sd.userHistory) == 0 {
		sd.userHistory = append(sd.userHistory, user)
		if len(sd.userHistory) > 16 {
			sd.userHistory = sd.userHistory[len(sd.userHistory)-16:]
		}
	}
	sd.userID = user
	sd.authMech = mech
	sd.locales = slices.Clone(req.LocaleIDs)
	sd.roles = slices.Clone(sess.roles)
	if sc != nil {
		sd.secMode = sc.SecurityMode()
		sd.secPolicy = sc.SecurityPolicyURI()
	}
}

// userOf returns the user id of an identity token (ClientUserIdOfSession,
// Part 5 §12.12) and the name of its UserTokenType (AuthenticationMechanism).
// Secrets (passwords, token data) are never part of it.
func userOf(tok ua.IdentityToken) (user, mechanism string) {
	switch t := tok.(type) {
	case *ua.UserNameIdentityToken:
		return t.UserName, "UserName"
	case *ua.X509IdentityToken:
		if cert, err := uapolicy.ParseCertificate(t.CertificateData); err == nil {
			return cert.Subject.String(), "Certificate"
		}
		return "", "Certificate"
	case *ua.IssuedIdentityToken:
		return "", "IssuedToken"
	}
	return "", "Anonymous"
}

// ---------------------------------------------------------------------------
// enabling and resetting
// ---------------------------------------------------------------------------

// setEnabled enables or disables the collection of diagnostics (EnabledFlag,
// Part 5 §6.3.3). Setting it to true resets the diagnostics, also when it
// was true before; setting it to false keeps them.
func (d *serverDiagnostics) setEnabled(on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !on {
		if !d.enabled.Load() {
			return
		}
		d.frozen.Store(d.summary())
		d.enabled.Store(false)
		for sess, sn := range d.sessions {
			d.dropNodesLocked(sn)
			delete(d.sessions, sess)
		}
		return
	}

	// Reset. The cumulated counts start at the sessions and subscriptions
	// that exist, so that they never fall below the current counts.
	sessions := d.s.sb.all()
	d.cumulatedSessions.Store(uint32(len(sessions)))
	d.cumulatedSubscriptions.Store(d.currentSubscriptions())
	for _, c := range []*atomic.Uint32{&d.securityRejectedSessions, &d.rejectedSessions, &d.sessionTimeouts,
		&d.sessionAborts, &d.securityRejectedRequests, &d.rejectedRequests} {
		c.Store(0)
	}
	for _, sess := range sessions {
		sess.diag.reset()
	}
	d.subsMu.Lock()
	for _, c := range d.subs {
		c.reset()
	}
	d.subsMu.Unlock()
	d.itemsMu.Lock()
	for _, st := range d.intervals {
		st.max = st.count
	}
	d.itemsMu.Unlock()
	d.enabled.Store(true)
	d.frozen.Store(nil)
	for _, sess := range sessions {
		d.addSessionLocked(sess)
	}
}

// sessionRemoved is called by the session broker after a session was
// removed, for whatever reason.
func (d *serverDiagnostics) sessionRemoved(sess *session, timedOut bool) {
	if timedOut && d.enabled.Load() {
		d.sessionTimeouts.Add(1)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if sn := d.sessions[sess]; sn != nil {
		d.dropNodesLocked(sn)
		delete(d.sessions, sess)
	}
}

// sessionNamespace returns the namespace of the SessionIds and of the
// session diagnostics objects, creating it.
func (d *serverDiagnostics) sessionNamespace() uint16 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.namespaceLocked().ID()
}

func (d *serverDiagnostics) namespaceLocked() *NodeNameSpace {
	if d.ns != nil {
		return d.ns
	}
	for _, x := range d.s.Namespaces() {
		if nns, ok := x.(*NodeNameSpace); ok && x.Name() == DiagnosticsNamespaceURI {
			d.ns = nns
		}
	}
	if d.ns == nil {
		d.ns = NewNodeNameSpace(d.s, DiagnosticsNamespaceURI)
	}
	d.nsIndex.Store(int32(d.ns.ID()))
	return d.ns
}

// ---------------------------------------------------------------------------
// values
// ---------------------------------------------------------------------------

// currentSubscriptions returns the number of subscriptions.
func (d *serverDiagnostics) currentSubscriptions() uint32 {
	ss := d.s.SubscriptionService
	if ss == nil {
		return 0
	}
	ss.Mu.Lock()
	defer ss.Mu.Unlock()
	return uint32(len(ss.Subs))
}

// summary returns ServerDiagnosticsSummary (Part 5 §12.9).
func (d *serverDiagnostics) summary() *ua.ServerDiagnosticsSummaryDataType {
	if !d.enabled.Load() {
		if f := d.frozen.Load(); f != nil {
			cp := *f
			return &cp
		}
	}
	sum := &ua.ServerDiagnosticsSummaryDataType{
		ServerViewCount:               0, // the server has no Views
		CurrentSessionCount:           uint32(d.s.sb.count()),
		CumulatedSessionCount:         d.cumulatedSessions.Load(),
		SecurityRejectedSessionCount:  d.securityRejectedSessions.Load(),
		RejectedSessionCount:          d.rejectedSessions.Load(),
		SessionTimeoutCount:           d.sessionTimeouts.Load(),
		SessionAbortCount:             d.sessionAborts.Load(),
		CumulatedSubscriptionCount:    d.cumulatedSubscriptions.Load(),
		SecurityRejectedRequestsCount: d.securityRejectedRequests.Load(),
		RejectedRequestsCount:         d.rejectedRequests.Load(),
	}
	if ss := d.s.SubscriptionService; ss != nil {
		intervals := map[float64]bool{}
		ss.Mu.Lock()
		subs := make([]*Subscription, 0, len(ss.Subs))
		for _, sub := range ss.Subs {
			subs = append(subs, sub)
		}
		ss.Mu.Unlock()
		for _, sub := range subs {
			sub.Mu.Lock()
			intervals[sub.RevisedPublishingInterval] = true
			sub.Mu.Unlock()
		}
		sum.CurrentSubscriptionCount = uint32(len(subs))
		sum.PublishingIntervalCount = uint32(len(intervals))
	}
	// A request can be counted between the reads above; the cumulated
	// counts never fall below the current ones.
	sum.CumulatedSessionCount = max(sum.CumulatedSessionCount, sum.CurrentSessionCount)
	sum.CumulatedSubscriptionCount = max(sum.CumulatedSubscriptionCount, sum.CurrentSubscriptionCount)
	return sum
}

// subscriptionsBySession returns the subscriptions of every session.
func (d *serverDiagnostics) subscriptionsBySession() map[*session][]*Subscription {
	out := map[*session][]*Subscription{}
	ss := d.s.SubscriptionService
	if ss == nil {
		return out
	}
	ss.Mu.Lock()
	defer ss.Mu.Unlock()
	for _, sub := range ss.Subs {
		own, _ := sub.sessionChannel()
		out[own] = append(out[own], sub)
	}
	return out
}

// sessionDiagnostics returns SessionDiagnosticsDataType of a session (Part 5
// §12.11). subs are the subscriptions of the session.
func (d *serverDiagnostics) sessionDiagnostics(sess *session, subs []*Subscription) *ua.SessionDiagnosticsDataType {
	sd := &sess.diag
	var items uint32
	for _, sub := range subs {
		n, _ := d.itemsOf(sub.ID)
		items += n
	}
	out := &ua.SessionDiagnosticsDataType{
		SessionID:                     sess.ID,
		ActualSessionTimeout:          float64(time.Duration(sess.timeout.Load())) / float64(time.Millisecond),
		ClientConnectionTime:          sd.created,
		ClientLastContactTime:         lastContact(sess),
		CurrentSubscriptionsCount:     uint32(len(subs)),
		CurrentMonitoredItemsCount:    items,
		CurrentPublishRequestsInQueue: uint32(len(sess.PublishRequests)),
		TotalRequestCount:             sd.total.value(),
		UnauthorizedRequestCount:      sd.unauthorized.Load(),
	}
	sd.mu.Lock()
	out.SessionName = sd.name
	out.ClientDescription = sd.client
	out.ServerURI = sd.serverURI
	out.EndpointURL = sd.endpointURL
	out.LocaleIDs = slices.Clone(sd.locales)
	out.MaxResponseMessageSize = sd.maxResponse
	sd.mu.Unlock()
	if out.ClientDescription == nil {
		out.ClientDescription = &ua.ApplicationDescription{ApplicationName: &ua.LocalizedText{}}
	}
	if out.LocaleIDs == nil {
		out.LocaleIDs = []string{}
	}
	c := func(i int) *ua.ServiceCounterDataType { return sd.services[i].value() }
	out.ReadCount = c(svcRead)
	out.HistoryReadCount = c(svcHistoryRead)
	out.WriteCount = c(svcWrite)
	out.HistoryUpdateCount = c(svcHistoryUpdate)
	out.CallCount = c(svcCall)
	out.CreateMonitoredItemsCount = c(svcCreateMonitoredItems)
	out.ModifyMonitoredItemsCount = c(svcModifyMonitoredItems)
	out.SetMonitoringModeCount = c(svcSetMonitoringMode)
	out.SetTriggeringCount = c(svcSetTriggering)
	out.DeleteMonitoredItemsCount = c(svcDeleteMonitoredItems)
	out.CreateSubscriptionCount = c(svcCreateSubscription)
	out.ModifySubscriptionCount = c(svcModifySubscription)
	out.SetPublishingModeCount = c(svcSetPublishingMode)
	out.PublishCount = c(svcPublish)
	out.RepublishCount = c(svcRepublish)
	out.TransferSubscriptionsCount = c(svcTransferSubscriptions)
	out.DeleteSubscriptionsCount = c(svcDeleteSubscriptions)
	out.AddNodesCount = c(svcAddNodes)
	out.AddReferencesCount = c(svcAddReferences)
	out.DeleteNodesCount = c(svcDeleteNodes)
	out.DeleteReferencesCount = c(svcDeleteReferences)
	out.BrowseCount = c(svcBrowse)
	out.BrowseNextCount = c(svcBrowseNext)
	out.TranslateBrowsePathsToNodeIDsCount = c(svcTranslateBrowsePaths)
	out.QueryFirstCount = c(svcQueryFirst)
	out.QueryNextCount = c(svcQueryNext)
	out.RegisterNodesCount = c(svcRegisterNodes)
	out.UnregisterNodesCount = c(svcUnregisterNodes)
	return out
}

// sessionSecurityDiagnostics returns SessionSecurityDiagnosticsDataType of a
// session (Part 5 §12.12).
func (d *serverDiagnostics) sessionSecurityDiagnostics(sess *session) *ua.SessionSecurityDiagnosticsDataType {
	sd := &sess.diag
	sd.mu.Lock()
	defer sd.mu.Unlock()
	mech := sd.authMech
	if mech == "" {
		mech = "Anonymous"
	}
	return &ua.SessionSecurityDiagnosticsDataType{
		SessionID:               sess.ID,
		ClientUserIDOfSession:   sd.userID,
		ClientUserIDHistory:     append([]string{}, sd.userHistory...),
		AuthenticationMechanism: mech,
		Encoding:                sd.encoding,
		TransportProtocol:       sd.transport,
		SecurityMode:            sd.secMode,
		SecurityPolicyURI:       sd.secPolicy,
		ClientCertificate:       slices.Clone(sd.clientCert),
	}
}

// subscriptionDiagnostics returns SubscriptionDiagnosticsDataType of a
// subscription (Part 5 §12.15).
func (d *serverDiagnostics) subscriptionDiagnostics(sub *Subscription) *ua.SubscriptionDiagnosticsDataType {
	sub.Mu.Lock()
	out := &ua.SubscriptionDiagnosticsDataType{
		SubscriptionID:             sub.ID,
		Priority:                   sub.Priority,
		PublishingInterval:         sub.RevisedPublishingInterval,
		MaxKeepAliveCount:          sub.RevisedMaxKeepAliveCount,
		MaxLifetimeCount:           sub.RevisedLifetimeCount,
		MaxNotificationsPerPublish: sub.MaxNotificationsPerPublish,
		PublishingEnabled:          sub.publishingEnabled,
		UnacknowledgedMessageCount: uint32(len(sub.sentMessages)),
	}
	if sub.Session != nil {
		out.SessionID = sub.Session.ID
	}
	sub.Mu.Unlock()
	if out.SessionID == nil {
		out.SessionID = ua.NewTwoByteNodeID(0)
	}
	out.MonitoredItemCount, out.DisabledMonitoredItemCount = d.itemsOf(out.SubscriptionID)
	out.NextSequenceNumber = 1
	if c := d.peekSubCounters(out.SubscriptionID); c != nil {
		out.ModifyCount = c.modify.Load()
		out.EnableCount = c.enable.Load()
		out.DisableCount = c.disable.Load()
		out.RepublishRequestCount = c.republishRequests.Load()
		out.RepublishMessageRequestCount = c.republishMessageRequests.Load()
		out.RepublishMessageCount = c.republishMessages.Load()
		out.TransferRequestCount = c.transferRequests.Load()
		out.TransferredToAltClientCount = c.transferredAlt.Load()
		out.TransferredToSameClientCount = c.transferred.Load()
		out.PublishRequestCount = c.publishRequests.Load()
		out.DataChangeNotificationsCount = c.dataChanges.Load()
		out.EventNotificationsCount = c.events.Load()
		out.NotificationsCount = c.notifications.Load()
		if n := c.nextSeq.Load(); n != 0 {
			out.NextSequenceNumber = n
		}
	}
	return out
}

// sessionDiagnosticsArray returns SessionDiagnosticsArray (Part 5 §6.3.4):
// empty while diagnostics are disabled.
func (d *serverDiagnostics) sessionDiagnosticsArray() []*ua.ExtensionObject {
	out := []*ua.ExtensionObject{}
	if !d.enabled.Load() {
		return out
	}
	subs := d.subscriptionsBySession()
	for _, sess := range d.s.sb.all() {
		out = append(out, ua.NewExtensionObject(d.sessionDiagnostics(sess, subs[sess])))
	}
	return out
}

// sessionSecurityDiagnosticsArray returns SessionSecurityDiagnosticsArray.
func (d *serverDiagnostics) sessionSecurityDiagnosticsArray() []*ua.ExtensionObject {
	out := []*ua.ExtensionObject{}
	if !d.enabled.Load() {
		return out
	}
	for _, sess := range d.s.sb.all() {
		out = append(out, ua.NewExtensionObject(d.sessionSecurityDiagnostics(sess)))
	}
	return out
}

// subscriptionDiagnosticsArray returns the SubscriptionDiagnosticsArray of
// the server, or of one session if sess is not nil.
func (d *serverDiagnostics) subscriptionDiagnosticsArray(sess *session) []*ua.ExtensionObject {
	out := []*ua.ExtensionObject{}
	if !d.enabled.Load() {
		return out
	}
	var subs []*Subscription
	if sess != nil {
		subs = d.subscriptionsBySession()[sess]
	} else {
		for _, ss := range d.subscriptionsBySession() {
			subs = append(subs, ss...)
		}
	}
	slices.SortFunc(subs, func(a, b *Subscription) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})
	for _, sub := range subs {
		out = append(out, ua.NewExtensionObject(d.subscriptionDiagnostics(sub)))
	}
	return out
}

// samplingIntervalDiagnosticsArray returns SamplingIntervalDiagnosticsArray
// (Part 5 §12.14): one entry per sampling interval in use.
func (d *serverDiagnostics) samplingIntervalDiagnosticsArray() []*ua.ExtensionObject {
	out := []*ua.ExtensionObject{}
	if !d.enabled.Load() {
		return out
	}
	d.itemsMu.Lock()
	keys := make([]float64, 0, len(d.intervals))
	for k, st := range d.intervals {
		if st.count > 0 {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		st := d.intervals[k]
		out = append(out, ua.NewExtensionObject(&ua.SamplingIntervalDiagnosticsDataType{
			SamplingInterval:           k,
			MonitoredItemCount:         st.count,
			MaxMonitoredItemCount:      st.max,
			DisabledMonitoredItemCount: st.disabled,
		}))
	}
	d.itemsMu.Unlock()
	return out
}
