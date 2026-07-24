// SPDX-License-Identifier: MIT

// Package server implements an OPC UA server with configurable namespaces, security, and services.
package server

import (
	"context"
	"crypto/rsa"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/schema"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
)

const defaultListenAddr = "opc.tcp://localhost:0"

var (
	builtinNodeSetOnce sync.Once
	builtinNodeSet     schema.UANodeSet
	builtinNodeSetErr  error
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

	// historian provides optional HistoryRead support (nil = unsupported).
	historian HistoryProvider

	// historyCPs binds opaque HistoryRead continuation points to sessions.
	historyCPs *historyCPRegistry
}

type serverConfig struct {
	privateKey     *rsa.PrivateKey
	certificate    []byte
	applicationURI string

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
	clientCertificateValidator ClientCertificateValidator
	allowUsernameOnNone        bool
	metrics                    ServerMetrics

	logger *slog.Logger
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
		logger:           slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.accessController == nil {
		cfg.accessController = DefaultAccessController{}
	}
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
				SoftwareVersion:  "0.0.0-dev",
				BuildNumber:      "",
				BuildDate:        time.Time{},
			},
			SecondsTillShutdown: 0,
			ShutdownReason:      &ua.LocalizedText{},
		},
	}

	builtinNodeSetOnce.Do(func() {
		builtinNodeSetErr = xml.Unmarshal(schema.OpcUaNodeSet2, &builtinNodeSet)
	})
	if builtinNodeSetErr != nil {
		return nil, fmt.Errorf("server: unmarshal built-in node set: %w", builtinNodeSetErr)
	}

	n0, ok := s.namespaces[0].(*NodeNameSpace)
	if !ok {
		return nil, fmt.Errorf("server: namespace 0 is not a NodeNameSpace")
	}
	n0.srv = s
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
		logger:           slog.Default(),
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

	return &Server{
		url:        listenURL,
		cfg:        cfg,
		cb:         newChannelBroker(cfg.logger, listenURL, cfg.clientCertificateValidator),
		sb:         newSessionBroker(cfg.logger),
		handlers:   make(map[uint16]Handler),
		methods:    make(map[string]MethodHandler),
		eventItems: newEventItemRegistry(),
		historyCPs: newHistoryCPRegistry(nil),
		namespaces: nil, // caller fills this in
		status: &ua.ServerStatusDataType{
			StartTime:      time.Now(),
			CurrentTime:    time.Now(),
			State:          ua.ServerStateSuspended,
			ShutdownReason: &ua.LocalizedText{},
		},
	}, nil
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
func (s *Server) URLs() []string {
	return s.cfg.endpoints
}

// Start initializes and starts a Server listening on addr
// If s was not initialized with NewServer(), addr defaults
// to localhost:0 to let the OS select a random port.
func (s *Server) Start(ctx context.Context) error {
	var err error

	if len(s.cfg.endpoints) == 0 {
		return fmt.Errorf("opcua: cannot start server: no endpoints defined")
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
	s.cfg.logger.Info("started listening", "urls", s.URLs())

	s.initEndpoints()
	s.setServerState(ua.ServerStateRunning)

	if s.cb == nil {
		s.cb = newChannelBroker(s.cfg.logger, s.url, s.cfg.clientCertificateValidator)
	}

	mctx, cancel := context.WithCancel(ctx)
	s.cancelMonitor = cancel

	go s.acceptAndRegister(mctx, s.l)
	go s.monitorConnections(mctx)

	return nil
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

	if s.cancelMonitor != nil {
		s.cancelMonitor()
	}

	// Close the listener, preventing new sessions from starting
	if s.l != nil {
		_ = s.l.Close()
	}

	// Shut down all secure channels and UACP connections
	return s.cb.Close(context.Background())
}

type temporary interface {
	Temporary() bool
}

func (s *Server) acceptAndRegister(ctx context.Context, l *uacp.Listener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c, err := l.Accept(ctx)
			if err != nil {
				switch x := err.(type) {
				case *net.OpError:
					// Listener was closed (normal during shutdown).
					s.cfg.logger.Debug("listener closed", "error", err)
					return
				case temporary:
					if x.Temporary() {
						continue
					}
				default:
					s.cfg.logger.Error("error accepting connection", "error", err)
					continue
				}
			}

			go func() { _ = s.cb.RegisterConn(ctx, c, s.cfg.certificate, s.cfg.privateKey) }()
			s.cfg.logger.Info("registered connection", "remote_addr", c.RemoteAddr())
		}
	}
}

// monitorConnections reads messages off the secure channel connection and
// sends the message to the service handler.
func (s *Server) monitorConnections(ctx context.Context) {
	for ctx.Err() == nil {
		msg := s.cb.ReadMessage(ctx)
		if msg == nil {
			continue // ctx is likely done, ctx.Err will be non-nil
		}
		if msg.Err != nil {
			s.cfg.logger.Error("monitorConnections: error received", "error", msg.Err)
			// Closing the SC here is risky: the channel may recover from transient errors.
			// The channel broker already handles fatal errors by breaking its read loop.
			continue
		}
		if resp := msg.Response(); resp != nil {
			s.cfg.logger.Error("monitorConnections: server received response", "type", fmt.Sprintf("%T", resp))
			// A server should never receive a response. This is a protocol violation
			// but closing the channel could disrupt active sessions on the same channel.
			continue
		}
		s.cfg.logger.Debug("monitorConnections: received message", "type", fmt.Sprintf("%T", msg.Request()))
		s.cb.mu.RLock()
		sc, ok := s.cb.s[msg.SecureChannelID]
		s.cb.mu.RUnlock()
		if !ok {
			// if the secure channel ID is 0, this is probably a open secure channel request.
			if msg.SecureChannelID != 0 {
				s.cfg.logger.Error("monitorConnections: unknown secure channel", "secure_channel_id", msg.SecureChannelID)
			}
			continue
		}

		// handleService is synchronous; long-running handlers would block
		// message processing. If this becomes a bottleneck, wrap in a goroutine.
		s.handleService(ctx, sc, msg.RequestID, msg.Request())
	}
}

// initEndpoints builds the endpoint list from the server's configuration.
func (s *Server) initEndpoints() {
	var endpoints []*ua.EndpointDescription
	for _, sec := range s.cfg.enabledSec {
		for _, url := range s.cfg.endpoints {
			secLevel := uapolicy.SecurityLevel(sec.secPolicy, sec.secMode)

			ep := &ua.EndpointDescription{
				EndpointURL:   url, // todo: be able to listen on multiple adapters
				SecurityLevel: secLevel,
				Server: &ua.ApplicationDescription{
					ApplicationURI: s.cfg.applicationURI,
					ProductURI:     "urn:github.com:otfabric:opcua:server",
					ApplicationName: &ua.LocalizedText{
						EncodingMask: ua.LocalizedTextText,
						Text:         s.cfg.applicationName,
					},
					ApplicationType:     ua.ApplicationTypeServer,
					GatewayServerURI:    "",
					DiscoveryProfileURI: "",
					DiscoveryURLs:       s.URLs(),
				},
				ServerCertificate:   s.cfg.certificate,
				SecurityMode:        sec.secMode,
				SecurityPolicyURI:   sec.secPolicy,
				TransportProfileURI: "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
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

				if auth.tokenType != ua.UserTokenTypeAnonymous &&
					authSecPolicy == "http://opcfoundation.org/UA/SecurityPolicy#None" &&
					!s.cfg.allowUsernameOnNone {
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
			endpoints = append(endpoints, ep)
		}
	}

	s.mu.Lock()
	s.endpoints = endpoints
	s.mu.Unlock()
}

func (s *Server) Node(nid *ua.NodeID) *Node {
	ns := int(nid.Namespace())
	if ns < len(s.namespaces) {
		return s.namespaces[ns].Node(nid)
	}
	return nil
}
