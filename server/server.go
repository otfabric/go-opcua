// SPDX-License-Identifier: MIT

// Package server implements an OPC UA server with configurable namespaces, security, and services.
package server

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/xml"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/schema"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

const defaultListenAddr = "opc.tcp://localhost:0"

var (
	builtinNodeSetOnce sync.Once
	builtinNodeSet     schema.UANodeSet
	// builtinNodeSetValues holds the decoded <Value> of the variables of
	// the built-in node set (nil if it cannot be decoded). It is written
	// once, under builtinNodeSetOnce. The Variants are prototypes: they
	// tell which values decode and are never handed to a server, see
	// importVariableValue.
	builtinNodeSetValues map[*schema.Value]*ua.Variant
	builtinNodeSetErr    error
)

// Server is a high-level OPC-UA server.
//
// It manages the full server lifecycle: listening for TCP connections,
// establishing secure channels, creating sessions, dispatching service
// requests to handlers, and managing subscriptions.
//
// The server automatically populates namespace 0 with the standard OPC-UA
// address space. Custom namespaces can be added with [Server.AddNamespace]
// or by creating a [NodeNameSpace] or [MapNamespace].
//
// Create a Server with [New], configure it with [Option] functions, and
// start it with [Server.Start]. Call [Server.Close] to shut down.
type Server struct {
	url string

	cfg *serverConfig

	mu         sync.Mutex
	status     *ua.ServerStatusDataType
	endpoints  []*ua.EndpointDescription
	namespaces []NameSpace

	l  *uacp.Listener
	wl *uacp.Listener // opc.wss, nil without WebSocket endpoints
	hs *httpsServer   // opc.https, nil without HTTPS endpoints
	cb *channelBroker
	sb *sessionBroker

	// nextSecureChannelID uint32

	// Service Handlers are methods called to respond to service requests from clients
	// All services should have a method here.
	handlers map[uint16]Handler

	// methods stores registered server-side method handlers keyed by "objectID\x00methodID".
	methods map[string]MethodHandler

	cancelMonitor context.CancelFunc

	SubscriptionService  *SubscriptionService
	MonitoredItemService *MonitoredItemService

	// eventItems tracks event-monitored-item filter state.
	eventItems *eventItemRegistry

	// alarms holds the conditions (Part 9).
	alarms *alarmManager

	// historian provides optional HistoryRead support (nil = unsupported).
	historian HistoryProvider

	// historyCPs binds opaque HistoryRead continuation points to sessions.
	historyCPs *historyCPRegistry

	// rcMu guards the reverse connect targets. rcCtx is the context of the
	// running server (nil before Start) and rcClosed is set by Close.
	rcMu            sync.Mutex
	reverseConnects []*ReverseConnect
	rcCtx           context.Context
	rcClosed        bool
	// disc holds the discovery state: registered servers, the mDNS node and
	// the registration loops towards other discovery servers.
	disc *discoveryManager

	// ps is the PubSub runtime and its information model (pubsub.go).
	ps pubsubState
}

type serverConfig struct {
	privateKey     *rsa.PrivateKey
	certificate    []byte
	applicationURI string
	// applicationURISet tells that applicationURI was set with the
	// ApplicationURI option and is not to be replaced by the certificate's.
	applicationURISet bool

	// reverseConnects are the targets configured with WithReverseConnect.
	reverseConnects []reverseConnectSpec

	// identities are the application instance certificates added with
	// ApplicationIdentity, in the order they were given.
	identities []applicationIdentity

	endpoints  []string
	listenAddr string // overrides endpoints[0] for TCP bind

	applicationName  string
	manufacturerName string
	productName      string
	softwareVersion  string

	enabledSec  []security
	enabledAuth []authMode

	cap ServerCapabilities

	accessController           AccessController
	roleMapper                 RoleMapper
	usernameValidator          UsernameValidator
	x509UserValidator          X509UserValidator
	issuedTokenValidator       IssuedTokenValidator
	clientCertificateValidator ClientCertificateValidator
	allowUsernameOnNone        bool
	metrics                    ServerMetrics

	// lds, multicast and registrations configure the discovery roles of the
	// server (discovery_lds.go, discovery_mdns.go, discovery_register.go).
	lds           ldsConfig
	multicast     multicastConfig
	registrations []*registrationConfig

	// responseWriteTimeout and maxPendingResponses configure the per-channel
	// response writers. Zero selects the default.
	responseWriteTimeout time.Duration
	maxPendingResponses  int

	logger *slog.Logger

	// wss and https are the WebSocket and HTTPS transports (transport.go).
	wss   transportConfig
	https transportConfig
	// tlsConfig is the TLS configuration of both; nil means the RSA
	// application instance certificate is the TLS certificate.
	tlsConfig *tls.Config

	// pubsub is the PubSub configuration of WithPubSub (nil: no PubSub).
	pubsub *pubsubConfig
	// pubsubAuth authorises the PubSub configuration methods.
	pubsubAuth PubSubAuthorizer
}

var capabilities = ServerCapabilities{
	OperationalLimits: OperationalLimits{
		MaxNodesPerRead:                          32,
		MaxNodesPerWrite:                         32,
		MaxNodesPerBrowse:                        32,
		MaxNodesPerMethodCall:                    32,
		MaxNodesPerRegisterNodes:                 32,
		MaxNodesPerTranslateBrowsePathsToNodeIDs: 32,
		MaxNodesPerNodeManagement:                32,
		MaxMonitoredItemsPerCall:                 32,
		MaxNodesPerHistoryReadData:               32,
		MaxNodesPerHistoryReadEvents:             32,
		MaxNodesPerHistoryUpdateData:             32,
		MaxNodesPerHistoryUpdateEvents:           32,
	},
}

type ServerCapabilities struct {
	OperationalLimits OperationalLimits
}

type OperationalLimits struct {
	MaxNodesPerRead                          uint32
	MaxNodesPerWrite                         uint32
	MaxNodesPerBrowse                        uint32
	MaxNodesPerMethodCall                    uint32
	MaxNodesPerRegisterNodes                 uint32
	MaxNodesPerTranslateBrowsePathsToNodeIDs uint32
	MaxNodesPerNodeManagement                uint32
	MaxMonitoredItemsPerCall                 uint32
	MaxNodesPerHistoryReadData               uint32
	MaxNodesPerHistoryReadEvents             uint32
	MaxNodesPerHistoryUpdateData             uint32
	MaxNodesPerHistoryUpdateEvents           uint32
}

type authMode struct {
	tokenType ua.UserTokenType
}

type security struct {
	secPolicy string
	secMode   ua.MessageSecurityMode
}

// New creates and initializes a new OPC-UA server.
//
// The server is configured with the given options. Namespace 0 is
// automatically populated with the standard OPC-UA node set, including
// Server status, capabilities, and current time nodes.
//
// Call [Server.Start] to begin accepting connections.
func New(opts ...Option) (*Server, error) {
	cfg := &serverConfig{
		cap:              capabilities,
		applicationName:  "GOPCUA",                 // override with the ServerName option
		manufacturerName: "otfabric",               // override with the ManufacturerName option
		productName:      "otfabric OPC/UA Server", // override with the ProductName option
		softwareVersion:  "0.0.0-dev",              // override with the SoftwareVersion option
		logger:           silentLogger(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.accessController == nil {
		cfg.accessController = DefaultAccessController{}
	}
	cfg.warnUnvalidatedAuthModes()
	// listenAddr controls where the server binds (TCP).  It defaults to the
	// first endpoint URL, but can be overridden with ListenOn() so that the
	// server can listen on 0.0.0.0 without advertising that address.
	listenURL := ""
	if cfg.listenAddr != "" {
		listenURL = cfg.listenAddr
	} else if len(cfg.endpoints) != 0 {
		listenURL = cfg.endpoints[0]
	}

	s := &Server{
		url:        listenURL,
		cfg:        cfg,
		cb:         newChannelBroker(cfg.logger, listenURL, cfg.clientCertificateValidator),
		sb:         newSessionBroker(cfg.logger),
		handlers:   make(map[uint16]Handler),
		methods:    make(map[string]MethodHandler),
		eventItems: newEventItemRegistry(),
		alarms:     newAlarmManager(),
		historyCPs: newHistoryCPRegistry(nil),
		namespaces: []NameSpace{
			NewNameSpace("http://opcfoundation.org/UA/"), // ns:0
		},
		status: &ua.ServerStatusDataType{
			StartTime:   time.Now(),
			CurrentTime: time.Now(),
			State:       ua.ServerStateSuspended,
			BuildInfo: &ua.BuildInfo{
				ProductURI:       "https://github.com/otfabric/go-opcua",
				ManufacturerName: cfg.manufacturerName,
				ProductName:      cfg.productName,
				SoftwareVersion:  cfg.softwareVersion, // honour the SoftwareVersion option
				BuildNumber:      "",
				BuildDate:        time.Time{},
			},
			SecondsTillShutdown: 0,
			ShutdownReason:      &ua.LocalizedText{},
		},
	}

	s.disc = newDiscoveryManager(s)
	s.registerAlarmMethods()

	builtinNodeSetOnce.Do(func() {
		builtinNodeSetErr = xml.Unmarshal(schema.OpcUaNodeSet2, &builtinNodeSet)
		// The values of the standard node set are decoded once, to know
		// which of them a server can serve. A server does not get these
		// Variants themselves: importVariableValue gives every node a
		// copy of its own.
		builtinNodeSetValues = make(map[*schema.Value]*ua.Variant)
		for _, v := range builtinNodeSet.UAVariable {
			if v.Value != nil {
				builtinNodeSetValues[v.Value] = decodeNodeSetValue(v.Value)
			}
		}
	})
	if builtinNodeSetErr != nil {
		return nil, fmt.Errorf("server: unmarshal built-in node set: %w", builtinNodeSetErr)
	}

	n0, ok := s.namespaces[0].(*NodeNameSpace)
	if !ok {
		return nil, fmt.Errorf("server: namespace 0 is not a NodeNameSpace")
	}
	n0.srv = s

	// An RBACAccessController needs the server whose address space it guards,
	// but options are evaluated before the server exists. Bind a controller
	// that was created without one, so that
	//
	//	server.New(server.WithAccessController(server.NewRBACAccessController(nil)), ...)
	//
	// works; before, RBAC could not be enabled through the public API at all.
	if rbac, ok := cfg.accessController.(*RBACAccessController); ok && rbac != nil && rbac.srv == nil {
		rbac.srv = s
	}
	if err := s.importNodeSet(&builtinNodeSet); err != nil {
		return nil, fmt.Errorf("server: import built-in node set: %w", err)
	}

	s.namespaces[0].AddNode(CurrentTimeNode())
	s.namespaces[0].AddNode(NamespacesNode(s))
	for _, n := range ServerStatusNodes(s, s.namespaces[0].Node(ua.NewNumericNodeID(0, id.Server))) {
		s.namespaces[0].AddNode(n)
	}
	for _, n := range ServerCapabilitiesNodes(s) {
		s.namespaces[0].AddNode(n)
	}

	return s, nil
}

// newServerNoNS creates a Server with all cfg/cb/sb fields initialized but with
// an empty namespaces slice.  It is used by the test helper to avoid re-running
// the expensive nodeset import for every test; the caller is responsible for
// installing a pre-populated ns-0 NodeNameSpace.
func newServerNoNS(opts ...Option) (*Server, error) {
	cfg := &serverConfig{
		cap:              capabilities,
		applicationName:  "GOPCUA",
		manufacturerName: "otfabric",
		productName:      "otfabric OPC/UA Server",
		softwareVersion:  "0.0.0-dev",
		logger:           silentLogger(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.accessController == nil {
		cfg.accessController = DefaultAccessController{}
	}
	listenURL := ""
	if cfg.listenAddr != "" {
		listenURL = cfg.listenAddr
	} else if len(cfg.endpoints) != 0 {
		listenURL = cfg.endpoints[0]
	}

	s := &Server{
		url:        listenURL,
		cfg:        cfg,
		cb:         newChannelBroker(cfg.logger, listenURL, cfg.clientCertificateValidator),
		sb:         newSessionBroker(cfg.logger),
		handlers:   make(map[uint16]Handler),
		methods:    make(map[string]MethodHandler),
		eventItems: newEventItemRegistry(),
		alarms:     newAlarmManager(),
		historyCPs: newHistoryCPRegistry(nil),
		namespaces: nil, // caller fills this in
		status: &ua.ServerStatusDataType{
			StartTime:      time.Now(),
			CurrentTime:    time.Now(),
			State:          ua.ServerStateSuspended,
			ShutdownReason: &ua.LocalizedText{},
		},
	}
	s.disc = newDiscoveryManager(s)
	s.registerAlarmMethods()
	return s, nil
}

func (s *Server) Session(hdr *ua.RequestHeader) *session {
	return s.sb.Session(hdr.AuthenticationToken)
}

func (s *Server) Namespace(id int) (NameSpace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id < len(s.namespaces) {
		return s.namespaces[id], nil
	}
	return nil, fmt.Errorf("opcua: namespace %d not found", id)
}

func (s *Server) Namespaces() []NameSpace {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.namespaces
}

func (s *Server) ChangeNotification(n *ua.NodeID) {
	if s.MonitoredItemService == nil {
		// Service not yet initialized (called before Start()).
		return
	}
	s.MonitoredItemService.ChangeNotification(n)
}

// RegisterMethod registers a handler for a server-side method call.
// The handler is invoked when a client calls the specified method on the given object.
func (s *Server) RegisterMethod(objectID, methodID *ua.NodeID, handler MethodHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.methods[methodKey(objectID, methodID)] = handler
}

func methodKey(objectID, methodID *ua.NodeID) string {
	return objectID.String() + "\x00" + methodID.String()
}

// AddNamespace registers a namespace with the server and assigns it a namespace index.
//
// If the namespace is already registered, its existing index is returned.
// Use [NewNodeNameSpace] or [NewMapNamespace] which call this automatically.
func (s *Server) AddNamespace(ns NameSpace) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx := slices.Index(s.namespaces, ns); idx >= 0 {
		return idx
	}
	ns.SetID(uint16(len(s.namespaces)))
	s.namespaces = append(s.namespaces, ns)

	// Give NodeNameSpace instances their server back-reference so that
	// Browse, ChangeNotification and SetAttribute can call s.cfg.logger,
	// s.Node, etc. without panicking.
	if nns, ok := ns.(*NodeNameSpace); ok && nns.srv == nil {
		nns.srv = s
	}

	if ns.ID() == 0 {
		return 0
	}

	return len(s.namespaces) - 1
}

func (s *Server) Endpoints() []*ua.EndpointDescription {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.endpoints)
}

// Status returns the current server status.
func (s *Server) Status() *ua.ServerStatusDataType {
	status := new(ua.ServerStatusDataType)
	s.mu.Lock()
	*status = *s.status
	s.mu.Unlock()
	status.CurrentTime = time.Now()
	return status
}

// URLs returns opc endpoint that the server is listening on.
//
// The opc.tcp endpoints come first, then the opc.wss and the opc.https ones.
func (s *Server) URLs() []string {
	if len(s.cfg.wss.endpoints) == 0 && len(s.cfg.https.endpoints) == 0 {
		return s.cfg.endpoints
	}
	urls := slices.Clone(s.cfg.endpoints)
	urls = append(urls, s.cfg.wss.endpoints...)
	return append(urls, s.cfg.https.endpoints...)
}

// Port returns the TCP port the server is bound to after [Server.Start], or 0
// if the server is not listening. Useful when ListenOn used port 0.
func (s *Server) Port() int {
	if s == nil || s.l == nil {
		return 0
	}
	tcp, ok := s.l.Addr().(*net.TCPAddr)
	if !ok || tcp == nil {
		return 0
	}
	return tcp.Port
}

// applyBoundPort rewrites listen and endpoint URLs that used port 0 (or were
// missing a port) to the concrete OS-assigned port.
func (s *Server) applyBoundPort(port int) {
	if port <= 0 {
		return
	}
	s.url = rewriteOPCURLPort(s.url, port)
	if s.cfg.listenAddr != "" {
		s.cfg.listenAddr = rewriteOPCURLPort(s.cfg.listenAddr, port)
	}
	for i, ep := range s.cfg.endpoints {
		s.cfg.endpoints[i] = rewriteOPCURLPort(ep, port)
	}
}

func rewriteOPCURLPort(raw string, port int) string {
	if raw == "" || port <= 0 {
		return raw
	}
	prefix := ""
	rest := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		prefix = raw[:i+3]
		rest = raw[i+3:]
	}
	path := ""
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		path = rest[j:]
		rest = rest[:j]
	}
	h, p, err := net.SplitHostPort(rest)
	if err != nil {
		// No port present (e.g. "opc.tcp://localhost").
		return prefix + net.JoinHostPort(rest, strconv.Itoa(port)) + path
	}
	if p != "0" && p != "" {
		return raw // already concrete
	}
	return prefix + net.JoinHostPort(h, strconv.Itoa(port)) + path
}

// Start initializes and starts a Server listening on addr
// If s was not initialized with NewServer(), addr defaults
// to localhost:0 to let the OS select a random port.
func (s *Server) Start(ctx context.Context) error {
	var err error

	if len(s.cfg.endpoints) == 0 {
		return fmt.Errorf("opcua: cannot start server: no endpoints defined")
	}
	if err := s.checkRegistrations(); err != nil {
		return err
	}

	// An ECC endpoint without an ECC certificate cannot work, and unlike an
	// RSA endpoint it cannot fall back on the server's RSA certificate.
	for _, sec := range s.cfg.enabledSec {
		if !uapolicy.IsECC(sec.secPolicy) {
			continue
		}
		if _, _, ok := s.cfg.identityFor(sec.secPolicy); !ok {
			return fmt.Errorf("opcua: cannot start server: security policy %s needs an ECC application instance certificate (see ApplicationIdentity)", sec.secPolicy)
		}
	}

	// Register all service handlers
	s.initHandlers()

	if s.url == "" {
		s.url = defaultListenAddr
	}
	s.l, err = uacp.Listen(ctx, s.url, nil)
	if err != nil {
		return err
	}
	// When ListenOn/EndPoint used port 0, rewrite advertised URLs with the OS-assigned port
	// before building EndpointDescriptions (avoids freePort TOCTOU races in tests).
	if tcp, ok := s.l.Addr().(*net.TCPAddr); ok {
		s.applyBoundPort(tcp.Port)
	}
	// The opc.wss and opc.https listeners, next to opc.tcp.
	if err := s.listenTransports(ctx); err != nil {
		_ = s.l.Close()
		return err
	}
	s.cfg.logger.Info("started listening", "urls", s.URLs())

	s.initEndpoints()
	s.setServerState(ua.ServerStateRunning)

	if s.cb == nil {
		s.cb = newChannelBroker(s.cfg.logger, s.url, s.cfg.clientCertificateValidator)
	} else {
		s.cb.endpointURL = s.url
	}
	s.cb.localIdentity = s.cfg.localIdentity
	s.cb.onRequest = func(hdr *ua.RequestHeader) { s.sb.touchToken(hdr.AuthenticationToken) }
	s.cb.writeTimeout = s.cfg.responseWriteTimeout
	s.cb.maxPending = s.cfg.maxPendingResponses

	// Discovery: the mDNS responder, the cleanup of registered servers and
	// the registration with other discovery servers. Only the multicast
	// sockets can fail here; a discovery server that is down cannot.
	if err := s.disc.start(ctx); err != nil {
		_ = s.l.Close()
		s.closeTransports()
		s.setServerState(ua.ServerStateFailed)
		return err
	}

	s.sb.reopen()
	if s.SubscriptionService != nil {
		s.SubscriptionService.reopen()
	}

	mctx, cancel := context.WithCancel(ctx)
	s.cancelMonitor = cancel

	go s.acceptAndRegister(mctx, s.l)
	s.serveTransports(mctx)
	go s.superviseMonitor(mctx)
	go s.reapSessions(mctx)

	if err := s.startPubSub(mctx); err != nil {
		cancel()
		_ = s.l.Close()
		s.closeTransports()
		s.setServerState(ua.ServerStateFailed)
		return err
	}

	return s.startReverseConnects(mctx)
}

func (s *Server) setServerState(state ua.ServerState) {
	s.mu.Lock()
	s.status.State = state
	s.mu.Unlock()
}

// Close gracefully shuts the server down by closing all open connections,
// and stops listening on all endpoints.
func (s *Server) Close() error {
	s.setServerState(ua.ServerStateShutdown)

	// Leave the discovery servers and the network first, while the server
	// can still be reached: unregister (IsOnline false) and say goodbye on
	// mDNS.
	s.disc.stop()

	// Stop publishing and subscribing before the address space goes away.
	s.closePubSub()
	s.alarms.close()

	if s.cancelMonitor != nil {
		s.cancelMonitor()
	}

	// Close the listener, preventing new sessions from starting
	if s.l != nil {
		_ = s.l.Close()
	}
	// The same for opc.wss; HTTPS requests in flight are ended here.
	s.closeTransports()

	// Shut down all secure channels and UACP connections
	err := s.cb.Close(context.Background())

	// Stop connecting to reverse connect clients and wait for what was
	// started for them.
	s.closeReverseConnects()

	// Nothing can reach the subscriptions and sessions any more. Stop the
	// subscription goroutines (they would otherwise keep ticking until their
	// lifetime expires) and drop the sessions. A request the dispatcher is
	// still handling can no longer add one: both refuse from here on.
	if s.SubscriptionService != nil {
		s.SubscriptionService.deleteAll()
	}
	s.sb.closeAll()

	return err
}

// sessionReapInterval is how often the server looks for timed-out sessions.
const sessionReapInterval = 250 * time.Millisecond

// reapSessions closes sessions whose timeout has elapsed until ctx is done.
//
// The subscriptions of a timed-out session are not deleted with it: Part 4
// §5.13.1.1 keeps them alive until their own lifetime expires so that the
// client can still transfer them to a new session.
func (s *Server) reapSessions(ctx context.Context) {
	t := time.NewTicker(sessionReapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, sess := range s.sb.reapExpired(now) {
				s.cfg.logger.Info("session timed out", "session_id", sess.ID)
				if s.historyCPs != nil && sess.AuthTokenID != nil {
					s.historyCPs.releaseSession(sess.AuthTokenID.String())
				}
			}
		}
	}
}

func (s *Server) acceptAndRegister(ctx context.Context, l *uacp.Listener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c, err := l.Accept(ctx)
			if err != nil {
				// Only a closed listener (or a cancelled context) ends the
				// accept loop. Everything else is the failure of a single
				// connection, typically a peer that reset the connection or
				// sent garbage during the HEL/ACK handshake. Such an error
				// can be a *net.OpError too, so the error's type says nothing
				// about the listener: treating it as "listener closed" let
				// one misbehaving peer stop the server from accepting
				// connections for good.
				if ctx.Err() != nil || stderrors.Is(err, net.ErrClosed) {
					s.cfg.logger.Debug("listener closed", "error", err)
					return
				}
				s.cfg.logger.Warn("error accepting connection", "error", err)
				continue
			}

			go s.serveConn(ctx, c)
			s.cfg.logger.Info("registered connection", "remote_addr", c.RemoteAddr())
		}
	}
}

// serveConn serves a connection that completed the HEL/ACK handshake until
// it ends. Accepted and reverse connections are served alike.
func (s *Server) serveConn(ctx context.Context, c *uacp.Conn) {
	// Last line of defence for this connection's goroutine: the connection
	// is lost, the server is not.
	defer func() {
		if r := recover(); r != nil {
			logPanic(s.cfg.logger, "serving a connection", r)
			_ = c.Close()
		}
	}()
	_ = s.cb.RegisterConn(ctx, c, s.cfg.certificate, s.cfg.privateKey)
}

// monitorConnections reads messages off the secure channel connection and
// sends the message to the service handler.
func (s *Server) monitorConnections(ctx context.Context) {
	for ctx.Err() == nil {
		in, ok := s.cb.ReadMessage(ctx)
		if !ok {
			continue // ctx is likely done, ctx.Err will be non-nil
		}
		s.cfg.logger.Debug("monitorConnections: received message", "type", fmt.Sprintf("%T", in.req))

		// Requests are handled one at a time: the services rely on it (a
		// Write and the data change it triggers, for example, are applied
		// in request order). What must not happen here is waiting for a
		// client, so the response is only queued on the channel's writer.
		resp := s.serve(ctx, in.sc, in.reqID, in.req)
		if resp == nil {
			// answered later (Publish): the request is no longer in flight
			in.w.release()
			continue
		}
		if err := in.w.send(in.reqID, resp); err != nil {
			s.cfg.logger.Debug("response dropped", "error", err)
		}
	}
}

// initEndpoints builds the endpoint list from the server's configuration.
func (s *Server) initEndpoints() {
	var endpoints []*ua.EndpointDescription
	// The opc.tcp endpoints first, then those of opc.wss and opc.https.
	httpsModes := s.httpsModes()
	for _, t := range s.transportEndpoints() {
		isHTTPS := t.profile == ua.TransportProfileHTTPS
		for _, sec := range s.cfg.enabledSec {
			// HTTPS offers a security policy once, with the strongest
			// mode enabled for it, and only a policy that needs no secure
			// conversation (Part 6 §7.4.1).
			if isHTTPS && (!uasc.HTTPSPolicySupported(sec.secPolicy) || httpsModes[sec.secPolicy] != sec.secMode) {
				continue
			}
			for _, url := range t.urls {
				endpoints = append(endpoints, s.endpointDescription(url, t.profile, sec))
			}
		}
	}

	s.mu.Lock()
	s.endpoints = endpoints
	s.mu.Unlock()
}

// endpointDescription describes the endpoint at url with transport profile
// profile and security sec.
func (s *Server) endpointDescription(url, profile string, sec security) *ua.EndpointDescription {
	secLevel := uapolicy.SecurityLevel(sec.secPolicy, sec.secMode)

	ep := &ua.EndpointDescription{
		EndpointURL:         url,
		SecurityLevel:       secLevel,
		Server:              s.applicationDescription(),
		ServerCertificate:   s.cfg.certificateFor(sec.secPolicy),
		SecurityMode:        sec.secMode,
		SecurityPolicyURI:   sec.secPolicy,
		TransportProfileURI: profile,
	}

	for _, auth := range s.cfg.enabledAuth {
		// Each endpoint's UserIdentityToken policies are scoped to the
		// endpoint's own security level.  Advertising cross-policy token
		// policies (e.g. username_basic256sha256 on a None/None endpoint)
		// confuses clients that try to encrypt the password using the
		// "wrong" key material for that channel.
		//
		// Anonymous always uses SecurityPolicyURI=None.
		// Non-anonymous tokens use the endpoint's security policy, with
		// a special exemption: AllowUsernameOnNone lets UserName appear on
		// None endpoints (password sent plaintext over the unencrypted channel).
		authSecPolicy := sec.secPolicy
		if auth.tokenType == ua.UserTokenTypeAnonymous {
			authSecPolicy = "http://opcfoundation.org/UA/SecurityPolicy#None"
		}

		// Over HTTPS TLS encrypts the token whatever the policy.
		if auth.tokenType != ua.UserTokenTypeAnonymous &&
			authSecPolicy == "http://opcfoundation.org/UA/SecurityPolicy#None" &&
			!s.cfg.allowUsernameOnNone && profile != ua.TransportProfileHTTPS {
			continue
		}

		policyID := strings.ToLower(
			strings.TrimPrefix(auth.tokenType.String(), "UserTokenType") +
				"_" +
				strings.TrimPrefix(authSecPolicy, "http://opcfoundation.org/UA/SecurityPolicy#"),
		)

		var dup bool
		for _, uit := range ep.UserIdentityTokens {
			if uit.PolicyID == policyID {
				dup = true
				break
			}
		}

		if dup {
			continue
		}
		// Per OPC UA Part 4 §7.36.1: SecurityPolicyURI in the token
		// policy specifies how the credential is encrypted.  An empty
		// string means "inherit from the SecureChannel's policy",
		// which is the most interoperable choice.  Using the explicit
		// None URI here can confuse some clients (e.g. open62541 v1.5)
		// that treat the explicit None differently from the empty string.
		tok := &ua.UserTokenPolicy{
			PolicyID:          policyID,
			TokenType:         auth.tokenType,
			IssuedTokenType:   "",
			IssuerEndpointURL: "",
			SecurityPolicyURI: "",
		}

		ep.UserIdentityTokens = append(ep.UserIdentityTokens, tok)
	}
	return ep
}

func (s *Server) Node(nid *ua.NodeID) *Node {
	ns := int(nid.Namespace())
	if ns < len(s.namespaces) {
		return s.namespaces[ns].Node(nid)
	}
	return nil
}
