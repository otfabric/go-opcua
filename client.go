// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package opcua

import (
	"context"
	"crypto/rand"
	"expvar"
	"fmt"
	"io"
	"iter"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/otfabric/opcua/errors"
	"github.com/otfabric/opcua/id"
	"github.com/otfabric/opcua/stats"
	"github.com/otfabric/opcua/ua"
	"github.com/otfabric/opcua/uacp"
	"github.com/otfabric/opcua/uapolicy"
	"github.com/otfabric/opcua/uasc"
)

// FindServers returns the servers known to a server or discovery server.
func FindServers(ctx context.Context, endpoint string, opts ...Option) ([]*ua.ApplicationDescription, error) {
	opts = append(opts, AutoReconnect(false))
	c, err := NewClient(endpoint, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Dial(ctx); err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	res, err := c.FindServers(ctx)
	if err != nil {
		return nil, err
	}
	return res.Servers, nil
}

// FindServersOnNetwork returns the servers known to a server or discovery server. Unlike FindServers, this service is only implemented by discovery servers.
func FindServersOnNetwork(ctx context.Context, endpoint string, opts ...Option) ([]*ua.ServerOnNetwork, error) {
	opts = append(opts, AutoReconnect(false))
	c, err := NewClient(endpoint, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Dial(ctx); err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	res, err := c.FindServersOnNetwork(ctx)
	if err != nil {
		return nil, err
	}
	return res.Servers, nil
}

// GetEndpoints returns the available endpoint descriptions for the server.
func GetEndpoints(ctx context.Context, endpoint string, opts ...Option) ([]*ua.EndpointDescription, error) {
	opts = append(opts, AutoReconnect(false))
	c, err := NewClient(endpoint, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Dial(ctx); err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	res, err := c.GetEndpoints(ctx)
	if err != nil {
		return nil, err
	}
	return res.Endpoints, nil
}

// SelectEndpoint returns the endpoint with the highest security level which matches
// security policy and security mode. policy and mode can be omitted so that
// only one of them has to match.
func SelectEndpoint(endpoints []*ua.EndpointDescription, policy string, mode ua.MessageSecurityMode) (*ua.EndpointDescription, error) {
	if len(endpoints) == 0 {
		return nil, errors.ErrNoEndpoints
	}

	sort.Sort(sort.Reverse(bySecurityLevel(endpoints)))
	policy = ua.FormatSecurityPolicyURI(policy)

	// don't care -> return highest security level
	if policy == "" && mode == ua.MessageSecurityModeInvalid {
		return endpoints[0], nil
	}

	for _, p := range endpoints {
		// match only security mode
		if policy == "" && p.SecurityMode == mode {
			return p, nil
		}

		// match only security policy
		if p.SecurityPolicyURI == policy && mode == ua.MessageSecurityModeInvalid {
			return p, nil
		}

		// match both
		if p.SecurityPolicyURI == policy && p.SecurityMode == mode {
			return p, nil
		}
	}
	return nil, fmt.Errorf("%w: policy=%s mode=%s", errors.ErrNoMatchingEndpoint, policy, mode)
}

type bySecurityLevel []*ua.EndpointDescription

func (a bySecurityLevel) Len() int           { return len(a) }
func (a bySecurityLevel) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a bySecurityLevel) Less(i, j int) bool { return a[i].SecurityLevel < a[j].SecurityLevel }

// Client is a high-level client for an OPC-UA server.
//
// It manages the full connection lifecycle: establishing a TCP connection
// via UACP, opening a secure channel (UASC) with encryption and signing,
// creating and activating a session, and managing subscriptions.
//
// The Client supports automatic reconnection when AutoReconnect is enabled.
// On connection loss it will attempt progressive recovery: recreating the
// secure channel, restoring or recreating the session, and transferring
// subscriptions.
//
// Create a Client with [NewClient] and connect with [Client.Connect].
// Always call [Client.Close] when done to release resources.
//
// The Client is safe for concurrent use from multiple goroutines.
type Client struct {
	// endpointURL is the endpoint URL the client connects to.
	endpointURL string

	// cfg is the configuration for the client.
	cfg *Config

	// conn is the open connection
	connMu sync.Mutex
	conn   *uacp.Conn

	// sechan is the open secure channel.
	atomicSechan atomic.Value // *uasc.SecureChannel
	sechanErr    chan error

	// atomicSession is the active atomicSession.
	atomicSession atomic.Value // *Session

	// subMux guards subs and pendingAcks.
	subMux sync.RWMutex

	// subs is the set of active subscriptions by id.
	subs map[uint32]*Subscription

	// pendingAcks contains the pending subscription acknowledgements
	// for all active subscriptions.
	pendingAcks []*ua.SubscriptionAcknowledgement

	// pausech pauses the subscription publish loop
	pausech chan struct{}

	// resumech resumes subscription publish loop
	resumech chan struct{}

	// mcancel stops subscription publish loop
	mcancel func()

	// timeout for sending PublishRequests
	atomicPublishTimeout atomic.Value // time.Duration

	// atomicState of the client
	atomicState atomic.Value // ConnState

	// stateCh is an optional channel for connection state changes. May be nil.
	stateCh chan<- ConnState

	// stateFunc is an optional func for connection state changes. May be nil.
	stateFunc func(ConnState)

	// list of cached atomicNamespaces on the server
	atomicNamespaces atomic.Value // []string

	// monitorOnce ensures only one connection monitor is running
	monitorOnce sync.Once
}

// NewClient creates a new Client.
//
// When no options are provided the new client is created from
// DefaultClientConfig() and DefaultSessionConfig(). If no authentication method
// is configured, a UserIdentityToken for anonymous authentication will be set.
// See #Client.CreateSession for details.
//
// To modify configuration you can provide any number of Options as opts. See
// #Option for details.
//
// https://godoc.org/github.com/otfabric/opcua#Option
func NewClient(endpoint string, opts ...Option) (*Client, error) {
	cfg, err := ApplyConfig(opts...)
	if err != nil {
		return nil, err
	}
	// Propagate logger to sub-components.
	cfg.dialer.Logger = cfg.logger
	cfg.sechan.Logger = cfg.logger

	c := Client{
		endpointURL: endpoint,
		cfg:         cfg,
		sechanErr:   make(chan error, 1),
		subs:        make(map[uint32]*Subscription),
		pendingAcks: make([]*ua.SubscriptionAcknowledgement, 0),
		pausech:     make(chan struct{}, 2),
		resumech:    make(chan struct{}, 2),
		stateCh:     cfg.stateCh,
		stateFunc:   cfg.stateFunc,
	}
	c.pauseSubscriptions(context.Background())
	c.setPublishTimeout(uasc.MaxTimeout)
	// cannot use setState here since it would trigger the stateCh
	c.atomicState.Store(Closed)
	c.setSecureChannel(nil)
	c.setSession(nil)
	c.setNamespaces([]string{})
	return &c, nil
}

// reconnectAction is a list of actions for the client reconnection logic.
type reconnectAction uint8

const (
	none reconnectAction = iota // no reconnection action

	createSecureChannel   // recreate secure channel action
	restoreSession        // ask the server to repair session
	recreateSession       // ask the client to repair session
	restoreSubscriptions  // republish or recreate subscriptions
	transferSubscriptions // move subscriptions from one session to another
	abortReconnect        // the reconnecting is not possible
)

// Connect establishes a secure channel and creates a new session.
//
// It performs the full OPC-UA connection sequence:
//  1. Opens a TCP connection to the server (UACP)
//  2. Opens a secure channel with the configured security policy
//  3. Creates a session with the configured parameters
//  4. Activates the session with the configured authentication
//
// If AutoReconnect is enabled, Connect also starts a background goroutine
// that monitors the connection and attempts recovery on failure.
//
// Connect must be called exactly once. Call [Client.Close] to disconnect.
func (c *Client) Connect(ctx context.Context) error {
	// During reconnection the secure channel is temporarily nil. This check
	// is safe because Connect is only called by the user (never by the
	// reconnect loop), so SecureChannel being nil here means first connect.
	if c.SecureChannel() != nil {
		return errors.ErrAlreadyConnected
	}

	c.setState(ctx, Connecting)
	if err := c.Dial(ctx); err != nil {
		stats.RecordError(err)

		return err
	}

	s, err := c.CreateSession(ctx, c.cfg.session)
	if err != nil {
		c.Close(ctx)
		stats.RecordError(err)

		return err
	}

	if err := c.ActivateSession(ctx, s); err != nil {
		c.Close(ctx)
		stats.RecordError(err)

		return err
	}
	c.setState(ctx, Connected)

	mctx, mcancel := context.WithCancel(context.Background())
	c.mcancel = mcancel
	c.monitorOnce.Do(func() {
		go c.monitor(mctx)
		go c.monitorSubscriptions(mctx)
	})

	// Update the client's namespace table from the server.
	// See https://github.com/otfabric/opcua/pull/512 for discussion.
	if !c.cfg.skipNamespaceUpdate {
		if err := c.UpdateNamespaces(ctx); err != nil {
			c.Close(ctx)
			stats.RecordError(err)

			return err
		}
	}

	return nil
}

// monitor manages connection alteration
func (c *Client) monitor(ctx context.Context) {
	c.cfg.logger.Debugf("monitor: start")
	defer c.cfg.logger.Debugf("monitor: done")

	defer c.mcancel()
	defer c.setState(ctx, Closed)

	action := none
	for {
		select {
		case <-ctx.Done():
			return

		case err, ok := <-c.sechanErr:
			stats.RecordError(err)

			// return if channel or connection is closed
			if !ok || err == io.EOF && c.State() == Closed {
				c.cfg.logger.Debugf("monitor: closed")
				return
			}

			// the subscriptions don't exist for session.
			// skip this error and continue monitor loop
			if errors.Is(err, ua.StatusBadNoSubscription) {
				continue
			}

			// tell the handler the connection is disconnected
			c.setState(ctx, Disconnected)
			c.cfg.logger.Debugf("monitor: disconnected")

			if !c.cfg.sechan.AutoReconnect {
				// the connection is closed and should not be restored
				action = abortReconnect
				c.cfg.logger.Debugf("monitor: auto-reconnect disabled")
				return
			}

			c.cfg.logger.Debugf("monitor: auto-reconnecting")

			switch {
			case errors.Is(err, io.EOF):
				// the connection has been closed
				action = createSecureChannel

			case errors.Is(err, syscall.ECONNREFUSED):
				// the connection has been refused by the server
				action = abortReconnect

			case errors.Is(err, ua.StatusBadSecureChannelIDInvalid):
				// the secure channel has been rejected by the server
				action = createSecureChannel

			case errors.Is(err, ua.StatusBadSessionIDInvalid):
				// the session has been rejected by the server
				action = recreateSession

			case errors.Is(err, ua.StatusBadSubscriptionIDInvalid):
				// the subscription has been rejected by the server
				action = transferSubscriptions

			case errors.Is(err, ua.StatusBadCertificateInvalid):
				// The server certificate may have been rotated. Re-fetch
				// endpoints to obtain the current certificate before
				// reconnecting.
				if eps, epErr := GetEndpoints(ctx, c.endpointURL); epErr == nil {
					for _, ep := range eps {
						if ep.SecurityPolicyURI == c.cfg.sechan.SecurityPolicyURI &&
							ep.SecurityMode == c.cfg.sechan.SecurityMode {
							c.cfg.sechan.RemoteCertificate = ep.ServerCertificate
							c.cfg.sechan.Thumbprint = uapolicy.Thumbprint(ep.ServerCertificate)
							break
						}
					}
				}
				action = createSecureChannel

			default:
				// unknown error has occured
				action = createSecureChannel
			}

			c.pauseSubscriptions(ctx)

			var (
				subsToRepublish []uint32            // subscription ids for which to send republish requests
				subsToRecreate  []uint32            // subscription ids which need to be recreated as new subscriptions
				availableSeqs   map[uint32][]uint32 // available sequence numbers per subscription
				activeSubs      int                 // number of active subscriptions to resume/recreate
			)

			for action != none {

				select {
				case <-ctx.Done():
					return

				default:
					switch action {

					case createSecureChannel:
						c.cfg.logger.Debugf("monitor: action: createSecureChannel")

						// recreate a secure channel by brute forcing
						// a reconnection to the server

						// Close the previous secure channel. The secure channel owns
						// the underlying UACP connection so closing it is sufficient.
						// Only close the raw connection as a fallback when no secure
						// channel exists.
						if sc := c.SecureChannel(); sc != nil {
							sc.Close()
							c.setSecureChannel(nil)
						} else {
							c.connMu.Lock()
							if c.conn != nil {
								c.conn.Close()
							}
							c.connMu.Unlock()
						}

						c.setState(ctx, Reconnecting)

						c.cfg.logger.Debugf("monitor: trying to recreate secure channel")
						for {
							if err := c.Dial(ctx); err != nil {
								select {
								case <-ctx.Done():
									return
								case <-time.After(c.cfg.sechan.ReconnectInterval):
									c.cfg.logger.Debugf("monitor: trying to recreate secure channel")
									continue
								}
							}
							break
						}
						c.cfg.logger.Debugf("monitor: secure channel recreated")
						action = restoreSession

					case restoreSession:
						c.cfg.logger.Debugf("monitor: action: restoreSession")

						// try to reactivate the session,
						// This only works if the session is still open on the server
						// otherwise recreate it

						c.setState(ctx, Reconnecting)

						s := c.Session()
						if s == nil {
							c.cfg.logger.Debugf("monitor: no session to restore")
							action = recreateSession
							continue
						}

						c.cfg.logger.Debugf("monitor: trying to restore session")
						if err := c.ActivateSession(ctx, s); err != nil {
							c.cfg.logger.Debugf("monitor: restore session failed error=%v", err)
							action = recreateSession
							continue
						}
						c.cfg.logger.Debugf("monitor: session restored")

						// todo(fs): see comment about guarding this with an option in Connect()
						c.cfg.logger.Debugf("monitor: trying to update namespaces")
						if !c.cfg.skipNamespaceUpdate {
							if err := c.UpdateNamespaces(ctx); err != nil {
								c.cfg.logger.Debugf("monitor: updating namespaces failed error=%v", err)
								action = createSecureChannel
								continue
							}
						}
						c.cfg.logger.Debugf("monitor: namespaces updated")

						action = restoreSubscriptions

					case recreateSession:
						c.cfg.logger.Debugf("monitor: action: recreateSession")

						c.setState(ctx, Reconnecting)
						// create a new session to replace the previous one

						// clear any previous session as we know the server has closed it
						// this also prevents any unnecessary calls to CloseSession
						c.setSession(nil)

						c.cfg.logger.Debugf("monitor: trying to recreate session")
						s, err := c.CreateSession(ctx, c.cfg.session)
						if err != nil {
							c.cfg.logger.Debugf("monitor: recreate session failed error=%v", err)
							action = createSecureChannel
							continue
						}
						if err := c.ActivateSession(ctx, s); err != nil {
							c.cfg.logger.Debugf("monitor: reactivate session failed error=%v", err)
							action = createSecureChannel
							continue
						}
						c.cfg.logger.Debugf("monitor: session recreated")

						// todo(fs): see comment about guarding this with an option in Connect()
						c.cfg.logger.Debugf("monitor: trying to update namespaces")
						if !c.cfg.skipNamespaceUpdate {
							if err := c.UpdateNamespaces(ctx); err != nil {
								c.cfg.logger.Debugf("monitor: updating namespaces failed error=%v", err)
								action = createSecureChannel
								continue
							}
						}
						c.cfg.logger.Debugf("monitor: namespaces updated")

						action = transferSubscriptions

					case transferSubscriptions:
						c.cfg.logger.Debugf("monitor: action: transferSubscriptions")

						// transfer subscriptions from the old to the new session
						// and try to republish the subscriptions.
						// Restore the subscriptions where republishing fails.

						subIDs := c.SubscriptionIDs()

						availableSeqs = map[uint32][]uint32{}
						subsToRecreate = nil
						subsToRepublish = nil

						// try to transfer all subscriptions to the new session and
						// recreate them all if that fails.
						res, err := c.transferSubscriptions(ctx, subIDs)
						switch {

						case errors.Is(err, ua.StatusBadServiceUnsupported):
							c.cfg.logger.Debugf("monitor: transfer subscriptions not supported, recreating all subscriptions error=%v", err)
							subsToRepublish = nil
							subsToRecreate = subIDs

						case err != nil:
							c.cfg.logger.Debugf("monitor: transfer subscriptions failed, recreating all subscriptions error=%v", err)
							subsToRepublish = nil
							subsToRecreate = subIDs

						default:
							// otherwise, try a republish for the subscriptions that were transferred
							// and recreate the rest.
							for i := range res.Results {
								transferResult := res.Results[i]
								switch transferResult.StatusCode {
								case ua.StatusBadSubscriptionIDInvalid:
									c.cfg.logger.Debugf("monitor: transfer subscription failed sub_id=%v", subIDs[i])
									subsToRecreate = append(subsToRecreate, subIDs[i])

								default:
									subsToRepublish = append(subsToRepublish, subIDs[i])
									availableSeqs[subIDs[i]] = transferResult.AvailableSequenceNumbers
								}
							}
						}

						action = restoreSubscriptions

					case restoreSubscriptions:
						c.cfg.logger.Debugf("monitor: action: restoreSubscriptions")

						// try to republish the previous subscriptions from the server
						// otherwise restore them.
						// Assume that subsToRecreate and subsToRepublish have been
						// populated in the previous step.

						activeSubs = 0
						for _, subID := range subsToRepublish {
							if err := c.republishSubscription(ctx, subID, availableSeqs[subID]); err != nil {
								c.cfg.logger.Debugf("monitor: republish of subscription failed sub_id=%v", subID)
								subsToRecreate = append(subsToRecreate, subID)
							}
							activeSubs++
						}

						for _, subID := range subsToRecreate {
							if err := c.recreateSubscription(ctx, subID); err != nil {
								c.cfg.logger.Debugf("monitor: recreate subscriptions failed error=%v", err)
								action = recreateSession
								continue
							}
							activeSubs++
						}

						c.setState(ctx, Connected)
						action = none

					case abortReconnect:
						c.cfg.logger.Debugf("monitor: action: abortReconnect")

						// Non-recoverable disconnection — stop the client.
						// The error is already surfaced via the state callback;
						// callers should monitor state changes to detect this.
						c.cfg.logger.Warnf("monitor: reconnection not recoverable")
						return
					}
				}
			}

			// clear sechan errors from reconnection
			for len(c.sechanErr) > 0 {
				<-c.sechanErr
			}

			switch {
			case activeSubs > 0:
				c.cfg.logger.Debugf("monitor: resuming subscriptions count=%v", activeSubs)
				c.resumeSubscriptions(ctx)
				c.cfg.logger.Debugf("monitor: resumed subscriptions count=%v", activeSubs)
			default:
				c.cfg.logger.Debugf("monitor: no subscriptions to resume")
			}
		}
	}
}

// Dial establishes a secure channel.
func (c *Client) Dial(ctx context.Context) error {
	stats.Client().Add("Dial", 1)

	if c.SecureChannel() != nil {
		return errors.ErrAlreadyConnected
	}

	var err error
	c.connMu.Lock()
	c.conn, err = c.cfg.dialer.Dial(ctx, c.endpointURL)
	c.connMu.Unlock()
	if err != nil {
		return err
	}

	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	sc, err := uasc.NewSecureChannel(c.endpointURL, conn, c.cfg.sechan, c.sechanErr)
	if err != nil {
		conn.Close()
		return err
	}

	if err := sc.Open(ctx); err != nil {
		conn.Close()
		return err
	}
	c.setSecureChannel(sc)

	// Validate the server certificate configured via SecurityFromEndpoint
	// or RemoteCertificate before proceeding.
	if err := c.cfg.validateServerCertificate(c.cfg.sechan.RemoteCertificate, c.cfg.sechan.SecurityMode); err != nil {
		sc.Close()
		conn.Close()
		c.setSecureChannel(nil)
		return err
	}

	return nil
}

// Close closes the session, secure channel, and underlying TCP connection.
//
// It attempts to gracefully close the session on the server, then closes the
// secure channel and connection. Errors during session close are ignored to
// ensure cleanup completes.
//
// Close is safe to call multiple times. After Close returns, the Client
// cannot be reused.
func (c *Client) Close(ctx context.Context) error {
	stats.Client().Add("Close", 1)

	// try to close the session but ignore any error
	// so that we close the underlying channel and connection.
	c.CloseSession(ctx)
	c.setState(ctx, Closed)

	if c.mcancel != nil {
		c.mcancel()
	}
	if sc := c.SecureChannel(); sc != nil {
		sc.Close()
		c.setSecureChannel(nil)
	}

	// https://github.com/otfabric/opcua/pull/462
	//
	// do not close the c.sechanErr channel since it leads to
	// race conditions and it gets garbage collected anyway.
	// There is nothing we can do with this error while
	// shutting down the client so I think it is safe to ignore
	// them.

	// close the connection but ignore the error since there isn't
	// anything we can do about it anyway
	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.connMu.Unlock()

	return nil
}

// State returns the current connection state.
func (c *Client) State() ConnState {
	return c.atomicState.Load().(ConnState)
}

func (c *Client) setState(ctx context.Context, s ConnState) {
	c.atomicState.Store(s)
	if c.stateCh != nil {
		select {
		case <-ctx.Done():
		case c.stateCh <- s:
		}
	}
	if c.stateFunc != nil {
		c.stateFunc(s)
	}
	n := new(expvar.Int)
	n.Set(int64(s))
	stats.Client().Set("State", n)
}

// Namespaces returns the currently cached list of namespaces.
func (c *Client) Namespaces() []string {
	return c.atomicNamespaces.Load().([]string)
}

func (c *Client) setNamespaces(ns []string) {
	c.atomicNamespaces.Store(ns)
}

func (c *Client) publishTimeout() time.Duration {
	return c.atomicPublishTimeout.Load().(time.Duration)
}

func (c *Client) setPublishTimeout(d time.Duration) {
	c.atomicPublishTimeout.Store(d)
}

// SecureChannel returns the active secure channel.
// During reconnect this value can change.
// Make sure to capture the value in a method before using it.
func (c *Client) SecureChannel() *uasc.SecureChannel {
	s, ok := c.atomicSechan.Load().(*uasc.SecureChannel)
	if !ok {
		return nil
	}
	return s
}

func (c *Client) setSecureChannel(sc *uasc.SecureChannel) {
	c.atomicSechan.Store(sc)
	stats.Client().Add("SecureChannel", 1)
}

// Session returns the active session.
// During reconnect this value can change.
// Make sure to capture the value in a method before using it.
func (c *Client) Session() *Session {
	s, ok := c.atomicSession.Load().(*Session)
	if !ok {
		return nil
	}
	return s
}

func (c *Client) setSession(s *Session) {
	c.atomicSession.Store(s)
	stats.Client().Add("Session", 1)
}

// Session is a OPC/UA session as described in Part 4, 5.6.
type Session struct {
	cfg *uasc.SessionConfig

	// resp is the response to the CreateSession request which contains all
	// necessary parameters to activate the session.
	resp *ua.CreateSessionResponse

	// serverCertificate is the certificate used to generate the signatures for
	// the ActivateSessionRequest methods
	serverCertificate []byte

	// serverNonce is the secret nonce received from the server during Create and Activate
	// Session response. Used to generate the signatures for the ActivateSessionRequest
	// and User Authorization
	serverNonce []byte

	// revisedTimeout is the actual maximum time that a Session shall remain open without activity.
	revisedTimeout time.Duration
}

// RevisedTimeout return actual maximum time that a Session shall remain open without activity.
// This value is provided by the server in response to CreateSession.
func (s *Session) RevisedTimeout() time.Duration {
	return s.revisedTimeout
}

// SessionID returns the server-assigned session identifier.
func (s *Session) SessionID() *ua.NodeID {
	if s.resp == nil {
		return nil
	}
	return s.resp.SessionID
}

// ServerEndpoints returns the endpoints provided by the server during
// session creation.
func (s *Session) ServerEndpoints() []*ua.EndpointDescription {
	if s.resp == nil {
		return nil
	}
	return s.resp.ServerEndpoints
}

// MaxRequestMessageSize returns the maximum request message size negotiated
// during session creation.
func (s *Session) MaxRequestMessageSize() uint32 {
	if s.resp == nil {
		return 0
	}
	return s.resp.MaxRequestMessageSize
}

// CreateSession creates a new session which is not yet activated and not
// associated with the client. Call ActivateSession to both activate and
// associate the session with the client.
//
// If no UserIdentityToken is given explicitly before calling CreateSesion,
// it automatically sets anonymous identity token with the same PolicyID
// that the server sent in Create Session Response. The default PolicyID
// "Anonymous" wii be set if it's missing in response.
//
// See Part 4, 5.6.2
func (c *Client) CreateSession(ctx context.Context, cfg *uasc.SessionConfig) (*Session, error) {
	sc := c.SecureChannel()
	if sc == nil {
		return nil, ua.StatusBadServerNotConnected
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	name := cfg.SessionName
	if name == "" {
		name = fmt.Sprintf("otfabric-opcua-%d", time.Now().UnixNano())
	}

	req := &ua.CreateSessionRequest{
		ClientDescription:       cfg.ClientDescription,
		EndpointURL:             c.endpointURL,
		SessionName:             name,
		ClientNonce:             nonce,
		ClientCertificate:       c.cfg.sechan.Certificate,
		RequestedSessionTimeout: float64(cfg.SessionTimeout / time.Millisecond),
	}

	var s *Session
	// for the CreateSessionRequest the authToken is always nil.
	// use sc.SendRequest() to enforce this.
	err := sc.SendRequest(ctx, req, nil, func(v ua.Response) error {
		var res *ua.CreateSessionResponse
		if err := assign(v, &res); err != nil {
			return err
		}

		err := sc.VerifySessionSignature(res.ServerCertificate, nonce, res.ServerSignature.Signature)
		if err != nil {
			return fmt.Errorf("opcua: verify session signature: %w", err)
		}

		// Validate the server certificate from the CreateSession response.
		if err := c.cfg.validateServerCertificate(res.ServerCertificate, c.cfg.sechan.SecurityMode); err != nil {
			return err
		}

		// Ensure we have a valid identity token that the server will accept before trying to activate a session
		if c.cfg.session.UserIdentityToken == nil {
			opt := AuthAnonymous()
			_ = opt(c.cfg) // cannot fail for AuthAnonymous
		}

		// For anonymous tokens without a PolicyID, look up the correct one
		// from the server's advertised user token policies. This handles
		// the common case where AuthAnonymous() was called explicitly
		// (e.g. via CLI --auth anonymous) which creates the token before
		// the server's endpoints are known.
		if tok, ok := c.cfg.session.UserIdentityToken.(*ua.AnonymousIdentityToken); ok && tok.PolicyID == "" {
			p := anonymousPolicyID(res.ServerEndpoints)
			tok.PolicyID = p
		}

		s = &Session{
			cfg:               cfg,
			resp:              res,
			serverNonce:       res.ServerNonce,
			serverCertificate: res.ServerCertificate,
			revisedTimeout:    time.Duration(res.RevisedSessionTimeout) * time.Millisecond,
		}

		return nil
	})
	return s, err
}

const defaultAnonymousPolicyID = "Anonymous"

func anonymousPolicyID(endpoints []*ua.EndpointDescription) string {
	for _, e := range endpoints {
		if e.SecurityMode != ua.MessageSecurityModeNone || e.SecurityPolicyURI != ua.SecurityPolicyURINone {
			continue
		}

		for _, t := range e.UserIdentityTokens {
			if t.TokenType == ua.UserTokenTypeAnonymous {
				return t.PolicyID
			}
		}
	}

	return defaultAnonymousPolicyID
}

// ActivateSession activates the session and associates it with the client. If
// the client already has a session it will be closed. To retain the current
// session call DetachSession.
//
// See Part 4, 5.6.3
func (c *Client) ActivateSession(ctx context.Context, s *Session) error {
	sc := c.SecureChannel()
	if sc == nil {
		return ua.StatusBadServerNotConnected
	}
	stats.Client().Add("ActivateSession", 1)
	sig, sigAlg, err := sc.NewSessionSignature(s.serverCertificate, s.serverNonce)
	if err != nil {
		return fmt.Errorf("opcua: create session signature: %w", err)
	}

	switch tok := s.cfg.UserIdentityToken.(type) {
	case *ua.AnonymousIdentityToken:
		// nothing to do

	case *ua.UserNameIdentityToken:
		pass, passAlg, err := sc.EncryptUserPassword(s.cfg.AuthPolicyURI, s.cfg.AuthPassword, s.serverCertificate, s.serverNonce)
		if err != nil {
			c.cfg.logger.Warnf("error encrypting user password error=%v", err)
			return err
		}
		tok.Password = pass
		tok.EncryptionAlgorithm = passAlg

	case *ua.X509IdentityToken:
		tokSig, tokSigAlg, err := sc.NewUserTokenSignature(s.cfg.AuthPolicyURI, s.serverCertificate, s.serverNonce)
		if err != nil {
			c.cfg.logger.Warnf("error creating session signature error=%v", err)
			return err
		}
		s.cfg.UserTokenSignature = &ua.SignatureData{
			Algorithm: tokSigAlg,
			Signature: tokSig,
		}

	case *ua.IssuedIdentityToken:
		tok.EncryptionAlgorithm = ""
	}

	req := &ua.ActivateSessionRequest{
		ClientSignature: &ua.SignatureData{
			Algorithm: sigAlg,
			Signature: sig,
		},
		ClientSoftwareCertificates: nil,
		LocaleIDs:                  s.cfg.LocaleIDs,
		UserIdentityToken:          ua.NewExtensionObject(s.cfg.UserIdentityToken),
		UserTokenSignature:         s.cfg.UserTokenSignature,
	}
	return sc.SendRequest(ctx, req, s.resp.AuthenticationToken, func(v ua.Response) error {
		var res *ua.ActivateSessionResponse
		if err := assign(v, &res); err != nil {
			return err
		}

		// save the nonce for the next request
		s.serverNonce = res.ServerNonce

		// close the previous session
		//
		// https://github.com/otfabric/opcua/issues/474
		//
		// We decided not to check the error of CloseSession() since we
		// can't do much about it anyway and it creates a race in the
		// re-connection logic.
		c.CloseSession(ctx)

		c.setSession(s)
		return nil
	})
}

// CloseSession closes the current session.
//
// See Part 4, 5.6.4
func (c *Client) CloseSession(ctx context.Context) error {
	stats.Client().Add("CloseSession", 1)
	if err := c.closeSession(ctx, c.Session()); err != nil {
		return err
	}
	c.setSession(nil)
	return nil
}

// closeSession closes the given session.
func (c *Client) closeSession(ctx context.Context, s *Session) error {
	if s == nil {
		return nil
	}
	req := &ua.CloseSessionRequest{DeleteSubscriptions: true}
	_, err := send[ua.CloseSessionResponse](ctx, c, req)
	return err
}

// DetachSession removes the session from the client without closing it. The
// caller is responsible to close or re-activate the session. If the client
// does not have an active session the function returns no error.
func (c *Client) DetachSession(ctx context.Context) (*Session, error) {
	stats.Client().Add("DetachSession", 1)
	s := c.Session()
	c.setSession(nil)
	return s, nil
}

// Send sends the request via the secure channel and registers a handler for
// the response. If the client has an active session it injects the
// authentication token.
//
// When a [RetryPolicy] is configured via [WithRetryPolicy], failed requests
// are retried according to the policy. Between retries the method sleeps for
// the policy-specified delay while respecting context cancellation.
func (c *Client) Send(ctx context.Context, req ua.Request, h func(ua.Response) error) error {
	stats.Client().Add("Send", 1)

	err := c.doSend(ctx, req, h)
	if err == nil {
		return nil
	}

	p := c.cfg.retryPolicy
	if p == nil {
		return err
	}

	for attempt := 0; ; attempt++ {
		retry, delay := p.ShouldRetry(attempt, err)
		if !retry {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}

		err = c.doSend(ctx, req, h)
		if err == nil {
			return nil
		}
	}
}

// doSend performs a single send attempt with metrics instrumentation.
func (c *Client) doSend(ctx context.Context, req ua.Request, h func(ua.Response) error) error {
	m := c.cfg.metrics
	if m != nil {
		svc := serviceName(req)
		m.OnRequest(svc)
		start := time.Now()
		err := c.sendWithTimeout(ctx, req, c.cfg.sechan.RequestTimeout, h)
		stats.RecordError(err)
		d := time.Since(start)
		if err != nil {
			if err == ua.StatusBadTimeout {
				m.OnTimeout(svc, d)
			} else {
				m.OnError(svc, d, err)
			}
		} else {
			m.OnResponse(svc, d)
		}
		return err
	}

	err := c.sendWithTimeout(ctx, req, c.cfg.sechan.RequestTimeout, h)
	stats.RecordError(err)
	return err
}

// sendWithTimeout sends the request via the secure channel with a custom timeout and registers a handler for
// the response. If the client has an active session it injects the
// authentication token.
func (c *Client) sendWithTimeout(ctx context.Context, req ua.Request, timeout time.Duration, h uasc.ResponseHandler) error {
	sc := c.SecureChannel()
	if sc == nil {
		return ua.StatusBadServerNotConnected
	}
	var authToken *ua.NodeID
	if s := c.Session(); s != nil {
		authToken = s.resp.AuthenticationToken
	}
	return sc.SendRequestWithTimeout(ctx, req, authToken, timeout, h)
}

// Node returns a node object which accesses its attributes
// through this client connection.
func (c *Client) Node(id *ua.NodeID) *Node {
	return &Node{ID: id, c: c}
}

// NodeFromExpandedNodeID returns a node object which accesses its attributes
// through this client connection. This is usually needed when working with node ids returned
// from browse responses by the server.
func (c *Client) NodeFromExpandedNodeID(id *ua.ExpandedNodeID) *Node {
	return &Node{ID: ua.NewNodeIDFromExpandedNodeID(id), c: c}
}

// NodeFromPath resolves a dot-separated browse path to a Node.
//
// Start node: server's Objects folder (i=85).
// Namespace: all path segments are interpreted in namespace 0.
// Path format: dot-separated browse names (e.g. "Server.ServerStatus").
// Error behavior: returns (nil, err) if the path does not resolve, the TranslateBrowsePathsToNodeIDs
// service fails, or the client is not connected. Use NodeFromPathInNamespace for a different namespace;
// use Node().TranslateBrowsePathInNamespaceToNodeID when starting from a custom node.
//
// Example: NodeFromPath(ctx, "Server.ServerStatus") returns the ServerStatus node.
func (c *Client) NodeFromPath(ctx context.Context, path string) (*Node, error) {
	root := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder))
	nodeID, err := root.TranslateBrowsePathInNamespaceToNodeID(ctx, 0, path)
	if err != nil {
		return nil, err
	}
	return c.Node(nodeID), nil
}

// NodeFromPathInNamespace resolves a dot-separated browse path to a Node using a single namespace for all segments.
//
// Start node: server's Objects folder (i=85).
// Namespace: all path segments use the given namespace index ns.
// Path format: dot-separated browse names (e.g. "MyFolder.Sensor1.Temperature").
// Error behavior: returns (nil, err) if the path does not resolve, the service fails, or the client is not connected.
// For paths in namespace 0 from Objects folder, NodeFromPath is equivalent. For a custom start node, use
// Node().TranslateBrowsePathInNamespaceToNodeID.
//
// Example: NodeFromPathInNamespace(ctx, 1, "Objects.IntVar") for a custom namespace 1.
func (c *Client) NodeFromPathInNamespace(ctx context.Context, ns uint16, path string) (*Node, error) {
	root := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder))
	nodeID, err := root.TranslateBrowsePathInNamespaceToNodeID(ctx, ns, path)
	if err != nil {
		return nil, err
	}
	return c.Node(nodeID), nil
}

// NodeFromQualifiedPath resolves a namespace-qualified path to a Node.
//
// Path format: dot-separated segments, each of the form "ns:name" where ns is a decimal
// namespace index (0-65535) and name is the browse name (e.g. "0:Server.0:ServerStatus" or
// "2:DeviceSet.4:PLC_Name"). Parsing is protocol-level and uses TranslateBrowsePathsToNodeIDs
// with per-segment namespace indices.
//
// Start node: server's Objects folder (i=85).
// Namespace: each segment specifies its own namespace via the "ns:" prefix.
// Error behavior: returns (nil, err) if the path is invalid (e.g. segment missing "ns:" or ns not numeric),
// the path does not resolve, the service fails, or the client is not connected.
func (c *Client) NodeFromQualifiedPath(ctx context.Context, path string) (*Node, error) {
	pathNames, err := parseQualifiedPath(path)
	if err != nil {
		return nil, err
	}
	if len(pathNames) == 0 {
		return nil, fmt.Errorf("opcua: qualified path has no segments: %q", path)
	}
	root := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder))
	nodeID, err := root.TranslateBrowsePathsToNodeIDs(ctx, pathNames)
	if err != nil {
		return nil, err
	}
	return c.Node(nodeID), nil
}

// parseQualifiedPath parses "ns1:name1.ns2:name2" into a slice of QualifiedName.
// Each segment must contain at least one ":"; the part before the first ":" is the namespace index (decimal).
func parseQualifiedPath(path string) ([]*ua.QualifiedName, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("opcua: qualified path is empty")
	}
	var out []*ua.QualifiedName
	for i, seg := range strings.Split(path, ".") {
		seg = strings.TrimSpace(seg)
		colon := strings.Index(seg, ":")
		if colon < 0 {
			return nil, fmt.Errorf("opcua: qualified path segment %d %q missing namespace prefix (expected ns:name)", i+1, seg)
		}
		nsStr, name := seg[:colon], strings.TrimSpace(seg[colon+1:])
		if name == "" {
			return nil, fmt.Errorf("opcua: qualified path segment %d has empty name after namespace", i+1)
		}
		ns64, err := strconv.ParseUint(strings.TrimSpace(nsStr), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("opcua: qualified path segment %d namespace %q: %w", i+1, nsStr, err)
		}
		out = append(out, &ua.QualifiedName{NamespaceIndex: uint16(ns64), Name: name})
	}
	return out, nil
}

// FindServers finds the servers available at an endpoint
func (c *Client) FindServers(ctx context.Context) (*ua.FindServersResponse, error) {
	stats.Client().Add("FindServers", 1)

	req := &ua.FindServersRequest{
		EndpointURL: c.endpointURL,
	}
	return send[ua.FindServersResponse](ctx, c, req)
}

// FindServersOnNetwork finds the servers available at an endpoint
func (c *Client) FindServersOnNetwork(ctx context.Context) (*ua.FindServersOnNetworkResponse, error) {
	stats.Client().Add("FindServersOnNetwork", 1)

	req := &ua.FindServersOnNetworkRequest{}
	return send[ua.FindServersOnNetworkResponse](ctx, c, req)
}

// GetEndpoints returns the list of available endpoints of the server.
func (c *Client) GetEndpoints(ctx context.Context) (*ua.GetEndpointsResponse, error) {
	stats.Client().Add("GetEndpoints", 1)

	req := &ua.GetEndpointsRequest{
		EndpointURL: c.endpointURL,
	}
	return send[ua.GetEndpointsResponse](ctx, c, req)
}

func cloneReadRequest(req *ua.ReadRequest) *ua.ReadRequest {
	rvs := make([]*ua.ReadValueID, len(req.NodesToRead))
	for i, rv := range req.NodesToRead {
		rc := &ua.ReadValueID{}
		*rc = *rv
		if rc.AttributeID == 0 {
			rc.AttributeID = ua.AttributeIDValue
		}
		if rc.DataEncoding == nil {
			rc.DataEncoding = &ua.QualifiedName{}
		}
		rvs[i] = rc
	}
	return &ua.ReadRequest{
		MaxAge:             req.MaxAge,
		TimestampsToReturn: req.TimestampsToReturn,
		NodesToRead:        rvs,
	}
}

// Read executes a synchronous read request.
//
// By default, the function requests the value of the nodes
// in the default encoding of the server.
func (c *Client) Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	stats.Client().Add("Read", 1)
	stats.Client().Add("NodesToRead", int64(len(req.NodesToRead)))

	// clone the request and the ReadValueIDs to set defaults without
	// manipulating them in-place.
	req = cloneReadRequest(req)

	var res *ua.ReadResponse
	err := c.Send(ctx, req, func(v ua.Response) error {
		if err := assign(v, &res); err != nil {
			return err
		}

		// If the client cannot decode an extension object then its
		// value will be nil. However, since the EO was known to the
		// server the StatusCode for that data value will be OK. We
		// therefore check for extension objects with nil values and set
		// the status code to StatusBadDataTypeIDUnknown.
		for _, dv := range res.Results {
			if dv.Value == nil {
				continue
			}
			val := dv.Value.Value()
			if eo, ok := val.(*ua.ExtensionObject); ok && eo.Value == nil {
				dv.Status = ua.StatusBadDataTypeIDUnknown
			}
		}
		return nil
	})
	return res, err
}

// Write executes a synchronous write request.
func (c *Client) Write(ctx context.Context, req *ua.WriteRequest) (*ua.WriteResponse, error) {
	stats.Client().Add("Write", 1)
	stats.Client().Add("NodesToWrite", int64(len(req.NodesToWrite)))

	return send[ua.WriteResponse](ctx, c, req)
}

func cloneBrowseRequest(req *ua.BrowseRequest) *ua.BrowseRequest {
	descs := make([]*ua.BrowseDescription, len(req.NodesToBrowse))
	for i, d := range req.NodesToBrowse {
		dc := &ua.BrowseDescription{}
		*dc = *d
		if dc.ReferenceTypeID == nil {
			dc.ReferenceTypeID = ua.NewNumericNodeID(0, id.References)
		}
		descs[i] = dc
	}
	reqc := &ua.BrowseRequest{
		View:                          req.View,
		RequestedMaxReferencesPerNode: req.RequestedMaxReferencesPerNode,
		NodesToBrowse:                 descs,
	}
	if reqc.View == nil {
		reqc.View = &ua.ViewDescription{}
	}
	if reqc.View.ViewID == nil {
		reqc.View.ViewID = ua.NewTwoByteNodeID(0)
	}
	return reqc
}

// Browse executes a synchronous browse request.
func (c *Client) Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	stats.Client().Add("Browse", 1)
	stats.Client().Add("NodesToBrowse", int64(len(req.NodesToBrowse)))

	// clone the request and the NodesToBrowse to set defaults without
	// manipulating them in-place.
	req = cloneBrowseRequest(req)

	return send[ua.BrowseResponse](ctx, c, req)
}

// Call executes a synchronous call request for a single method.
func (c *Client) Call(ctx context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	stats.Client().Add("Call", 1)

	creq := &ua.CallRequest{
		MethodsToCall: []*ua.CallMethodRequest{req},
	}
	res, err := send[ua.CallResponse](ctx, c, creq)
	if err != nil {
		return nil, err
	}
	if len(res.Results) != 1 {
		return nil, ua.StatusBadUnknownResponse
	}
	return res.Results[0], nil
}

// BrowseNext executes a synchronous browse request.
func (c *Client) BrowseNext(ctx context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error) {
	stats.Client().Add("BrowseNext", 1)

	return send[ua.BrowseNextResponse](ctx, c, req)
}

// RegisterNodes registers node ids for more efficient reads.
//
// Part 4, Section 5.8.5
func (c *Client) RegisterNodes(ctx context.Context, req *ua.RegisterNodesRequest) (*ua.RegisterNodesResponse, error) {
	stats.Client().Add("RegisterNodes", 1)
	stats.Client().Add("NodesToRegister", int64(len(req.NodesToRegister)))

	return send[ua.RegisterNodesResponse](ctx, c, req)
}

// UnregisterNodes unregisters node ids previously registered with RegisterNodes.
//
// Part 4, Section 5.8.6
func (c *Client) UnregisterNodes(ctx context.Context, req *ua.UnregisterNodesRequest) (*ua.UnregisterNodesResponse, error) {
	stats.Client().Add("UnregisterNodes", 1)
	stats.Client().Add("NodesToUnregister", int64(len(req.NodesToUnregister)))

	return send[ua.UnregisterNodesResponse](ctx, c, req)
}

// SetPublishingMode enables or disables publishing of notification messages
// for one or more subscriptions.
//
// Part 4, Section 5.13.4
func (c *Client) SetPublishingMode(ctx context.Context, publishingEnabled bool, subscriptionIDs ...uint32) (*ua.SetPublishingModeResponse, error) {
	stats.Client().Add("SetPublishingMode", 1)

	req := &ua.SetPublishingModeRequest{
		PublishingEnabled: publishingEnabled,
		SubscriptionIDs:   subscriptionIDs,
	}

	return send[ua.SetPublishingModeResponse](ctx, c, req)
}

// AddNodes adds one or more nodes to the server address space.
//
// Part 4, Section 5.7.2
func (c *Client) AddNodes(ctx context.Context, req *ua.AddNodesRequest) (*ua.AddNodesResponse, error) {
	stats.Client().Add("AddNodes", 1)
	stats.Client().Add("NodesToAdd", int64(len(req.NodesToAdd)))

	return send[ua.AddNodesResponse](ctx, c, req)
}

// DeleteNodes deletes one or more nodes from the server address space.
//
// Part 4, Section 5.7.3
func (c *Client) DeleteNodes(ctx context.Context, req *ua.DeleteNodesRequest) (*ua.DeleteNodesResponse, error) {
	stats.Client().Add("DeleteNodes", 1)
	stats.Client().Add("NodesToDelete", int64(len(req.NodesToDelete)))

	return send[ua.DeleteNodesResponse](ctx, c, req)
}

// AddReferences adds one or more references to one or more nodes.
//
// Part 4, Section 5.7.4
func (c *Client) AddReferences(ctx context.Context, req *ua.AddReferencesRequest) (*ua.AddReferencesResponse, error) {
	stats.Client().Add("AddReferences", 1)
	stats.Client().Add("ReferencesToAdd", int64(len(req.ReferencesToAdd)))

	return send[ua.AddReferencesResponse](ctx, c, req)
}

// DeleteReferences deletes one or more references from one or more nodes.
//
// Part 4, Section 5.7.5
func (c *Client) DeleteReferences(ctx context.Context, req *ua.DeleteReferencesRequest) (*ua.DeleteReferencesResponse, error) {
	stats.Client().Add("DeleteReferences", 1)
	stats.Client().Add("ReferencesToDelete", int64(len(req.ReferencesToDelete)))

	return send[ua.DeleteReferencesResponse](ctx, c, req)
}

func (c *Client) HistoryReadEvent(ctx context.Context, nodes []*ua.HistoryReadValueID, details *ua.ReadEventDetails) (*ua.HistoryReadResponse, error) {
	stats.Client().Add("HistoryReadEvent", 1)
	stats.Client().Add("HistoryReadValueID", int64(len(nodes)))

	// Part 4, 5.10.3 HistoryRead
	req := &ua.HistoryReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        nodes,
		// Part 11, 6.4 HistoryReadDetails parameters
		HistoryReadDetails: &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadEventDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        details,
		},
	}

	return send[ua.HistoryReadResponse](ctx, c, req)
}

func (c *Client) HistoryReadRawModified(ctx context.Context, nodes []*ua.HistoryReadValueID, details *ua.ReadRawModifiedDetails) (*ua.HistoryReadResponse, error) {
	stats.Client().Add("HistoryReadRawModified", 1)
	stats.Client().Add("HistoryReadValueID", int64(len(nodes)))

	// Part 4, 5.10.3 HistoryRead
	req := &ua.HistoryReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        nodes,
		// Part 11, 6.4 HistoryReadDetails parameters
		HistoryReadDetails: &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadRawModifiedDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        details,
		},
	}

	return send[ua.HistoryReadResponse](ctx, c, req)
}

func (c *Client) HistoryReadProcessed(ctx context.Context, nodes []*ua.HistoryReadValueID, details *ua.ReadProcessedDetails) (*ua.HistoryReadResponse, error) {
	stats.Client().Add("HistoryReadProcessed", 1)
	stats.Client().Add("HistoryReadValueID", int64(len(nodes)))

	// Part 4, 5.10.3 HistoryRead
	req := &ua.HistoryReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        nodes,
		// Part 11, 6.4 HistoryReadDetails parameters
		HistoryReadDetails: &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadProcessedDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        details,
		},
	}

	return send[ua.HistoryReadResponse](ctx, c, req)
}

func (c *Client) HistoryReadAtTime(ctx context.Context, nodes []*ua.HistoryReadValueID, details *ua.ReadAtTimeDetails) (*ua.HistoryReadResponse, error) {
	stats.Client().Add("HistoryReadAtTime", 1)
	stats.Client().Add("HistoryReadValueID", int64(len(nodes)))

	// Part 4, 5.10.3 HistoryRead
	req := &ua.HistoryReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        nodes,
		//Part 11, 6.4.5 ReadAtTimeDetails parameters
		HistoryReadDetails: &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadAtTimeDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        details,
		},
	}

	return send[ua.HistoryReadResponse](ctx, c, req)
}

// HistoryUpdateData updates historical data values for one or more nodes.
//
// Part 4, Section 5.10.5 / Part 11, Section 6.8.2
func (c *Client) HistoryUpdateData(ctx context.Context, details ...*ua.UpdateDataDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryUpdateData", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.UpdateDataDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        d,
		}
	}

	req := &ua.HistoryUpdateRequest{
		HistoryUpdateDetails: eos,
	}

	return send[ua.HistoryUpdateResponse](ctx, c, req)
}

// HistoryUpdateEvents updates historical events for one or more nodes.
//
// Part 4, Section 5.10.5 / Part 11, Section 6.8.4
func (c *Client) HistoryUpdateEvents(ctx context.Context, details ...*ua.UpdateEventDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryUpdateEvents", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.UpdateEventDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        d,
		}
	}

	req := &ua.HistoryUpdateRequest{
		HistoryUpdateDetails: eos,
	}

	return send[ua.HistoryUpdateResponse](ctx, c, req)
}

// HistoryDeleteRawModified deletes raw or modified historical data within a time range.
//
// Part 4, Section 5.10.5 / Part 11, Section 6.8.5
func (c *Client) HistoryDeleteRawModified(ctx context.Context, details ...*ua.DeleteRawModifiedDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryDeleteRawModified", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.DeleteRawModifiedDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        d,
		}
	}

	req := &ua.HistoryUpdateRequest{
		HistoryUpdateDetails: eos,
	}

	return send[ua.HistoryUpdateResponse](ctx, c, req)
}

// HistoryDeleteAtTime deletes historical data values at specific timestamps.
//
// Part 4, Section 5.10.5 / Part 11, Section 6.8.6
func (c *Client) HistoryDeleteAtTime(ctx context.Context, details ...*ua.DeleteAtTimeDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryDeleteAtTime", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.DeleteAtTimeDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        d,
		}
	}

	req := &ua.HistoryUpdateRequest{
		HistoryUpdateDetails: eos,
	}

	return send[ua.HistoryUpdateResponse](ctx, c, req)
}

// HistoryDeleteEvents deletes historical events matching specific event IDs.
//
// Part 4, Section 5.10.5 / Part 11, Section 6.8.7
func (c *Client) HistoryDeleteEvents(ctx context.Context, details ...*ua.DeleteEventDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryDeleteEvents", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.DeleteEventDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        d,
		}
	}

	req := &ua.HistoryUpdateRequest{
		HistoryUpdateDetails: eos,
	}

	return send[ua.HistoryUpdateResponse](ctx, c, req)
}

// NamespaceArray returns the list of namespaces registered on the server.
func (c *Client) NamespaceArray(ctx context.Context) ([]string, error) {
	stats.Client().Add("NamespaceArray", 1)
	node := c.Node(ua.NewNumericNodeID(0, id.Server_NamespaceArray))
	v, err := node.Value(ctx)
	if err != nil {
		return nil, err
	}

	ns, ok := v.Value().([]string)
	if !ok {
		return nil, fmt.Errorf("%w: id=%d type=%T", errors.ErrInvalidNamespaceType, v.Type(), v.Value())
	}
	return ns, nil
}

// FindNamespace returns the id of the namespace with the given name.
func (c *Client) FindNamespace(ctx context.Context, name string) (uint16, error) {
	stats.Client().Add("FindNamespace", 1)
	nsa, err := c.NamespaceArray(ctx)
	if err != nil {
		return 0, err
	}
	for i, ns := range nsa {
		if ns == name {
			return uint16(i), nil
		}
	}
	return 0, fmt.Errorf("%w: name=%s", errors.ErrNamespaceNotFound, name)
}

// UpdateNamespaces updates the list of cached namespaces from the server.
func (c *Client) UpdateNamespaces(ctx context.Context) error {
	stats.Client().Add("UpdateNamespaces", 1)
	ns, err := c.NamespaceArray(ctx)
	if err != nil {
		return err
	}
	c.setNamespaces(ns)
	return nil
}

// assign performs a type-safe assignment from a ua.Response to a typed pointer
// using generics instead of reflection.
func assign[T any](v ua.Response, res **T) error {
	r, ok := any(v).(*T)
	if !ok {
		return &InvalidResponseTypeError{Got: fmt.Sprintf("%T", v), Want: fmt.Sprintf("%T", (*T)(nil))}
	}
	*res = r
	return nil
}

// send sends a request and returns the typed response.
func send[T any](ctx context.Context, c *Client, req ua.Request) (*T, error) {
	var res *T
	err := c.Send(ctx, req, func(v ua.Response) error {
		return assign(v, &res)
	})
	return res, err
}

type InvalidResponseTypeError struct {
	Got  string
	Want string
}

func (e *InvalidResponseTypeError) Error() string {
	return fmt.Sprintf("opcua: invalid response: got %s want %s", e.Got, e.Want)
}

func (e *InvalidResponseTypeError) Is(target error) bool {
	return target == errors.ErrInvalidResponseType
}

// ReadValue reads the Value attribute of a single node.
//
// This is a convenience wrapper around [Client.Read] for the common case
// of reading one node's value. It returns timestamps from both source and server.
//
// For reading multiple nodes in one round-trip, use [Client.ReadValues].
// For reading attributes other than Value, use [Client.Read] directly.
func (c *Client) ReadValue(ctx context.Context, nodeID *ua.NodeID) (*ua.DataValue, error) {
	resp, err := c.Read(ctx, &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{NodeID: nodeID, AttributeID: ua.AttributeIDValue},
		},
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	})
	if err != nil {
		return nil, err
	}
	return resp.Results[0], nil
}

// ReadValues reads the Value attribute of multiple nodes in a single request.
//
// This is more efficient than calling [Client.ReadValue] in a loop because
// all nodes are read in a single OPC-UA Read service call.
// Results are returned in the same order as the input node IDs.
func (c *Client) ReadValues(ctx context.Context, nodeIDs ...*ua.NodeID) ([]*ua.DataValue, error) {
	items := make([]*ua.ReadValueID, len(nodeIDs))
	for i, nid := range nodeIDs {
		items[i] = &ua.ReadValueID{NodeID: nid, AttributeID: ua.AttributeIDValue}
	}
	resp, err := c.Read(ctx, &ua.ReadRequest{
		NodesToRead:        items,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	})
	if err != nil {
		return nil, err
	}
	return resp.Results, nil
}

// ReadItem specifies one node/attribute to read in a batch.
type ReadItem struct {
	NodeID      *ua.NodeID
	AttributeID ua.AttributeID
	IndexRange  string // optional; empty means entire value
}

// ReadResult holds the result of one read in a batch. StatusCode is the
// per-item status from the server; DataValue may be nil if the read failed.
type ReadResult struct {
	DataValue  *ua.DataValue
	StatusCode ua.StatusCode
}

// DefaultReadMultiChunkSize is the default max items per Read request when
// using ReadMulti, to stay under typical server MaxNodesPerRead limits.
const DefaultReadMultiChunkSize = 32

// ReadMulti performs a batch read of N nodes × attributes in one or more
// OPC UA Read calls, chunking by DefaultReadMultiChunkSize (or chunkSize if
// provided via [ReadMultiWithChunkSize]). Results are in the same order as
// items. Each result's StatusCode reflects the server's status for that
// item; a failed overall request returns (nil, err).
func (c *Client) ReadMulti(ctx context.Context, items []ReadItem, opts ...ReadMultiOption) ([]ReadResult, error) {
	if len(items) == 0 {
		return nil, nil
	}
	chunkSize := int(DefaultReadMultiChunkSize)
	for _, o := range opts {
		if o.chunkSize > 0 {
			chunkSize = int(o.chunkSize)
		}
	}
	results := make([]ReadResult, len(items))
	for i := 0; i < len(items); i += chunkSize {
		end := i + chunkSize
		if end > len(items) {
			end = len(items)
		}
		chunk := items[i:end]
		rvs := make([]*ua.ReadValueID, len(chunk))
		for j, it := range chunk {
			attrID := it.AttributeID
			if attrID == 0 {
				attrID = ua.AttributeIDValue
			}
			rvs[j] = &ua.ReadValueID{
				NodeID:      it.NodeID,
				AttributeID: attrID,
				IndexRange:  it.IndexRange,
			}
		}
		req := &ua.ReadRequest{
			NodesToRead:        rvs,
			TimestampsToReturn: ua.TimestampsToReturnBoth,
		}
		resp, err := c.Read(ctx, req)
		if err != nil {
			return nil, err
		}
		for k, dv := range resp.Results {
			idx := i + k
			results[idx] = ReadResult{DataValue: dv, StatusCode: dv.Status}
		}
	}
	return results, nil
}

// ReadMultiOption configures [Client.ReadMulti].
type ReadMultiOption struct{ chunkSize uint32 }

// ReadMultiWithChunkSize sets the max number of items per Read request.
// If 0 or unset, [DefaultReadMultiChunkSize] is used.
func ReadMultiWithChunkSize(n uint32) ReadMultiOption {
	return ReadMultiOption{chunkSize: n}
}

// WriteValue writes a DataValue to a single node's Value attribute.
//
// Returns the status code from the server indicating success or failure.
// For writing multiple nodes in one round-trip, use [Client.WriteValues].
func (c *Client) WriteValue(ctx context.Context, nodeID *ua.NodeID, value *ua.DataValue) (ua.StatusCode, error) {
	resp, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
				Value:       value,
			},
		},
	})
	if err != nil {
		return ua.StatusBad, err
	}
	return resp.Results[0], nil
}

// WriteValues writes multiple values in a single request.
func (c *Client) WriteValues(ctx context.Context, writes ...*ua.WriteValue) ([]ua.StatusCode, error) {
	resp, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: writes,
	})
	if err != nil {
		return nil, err
	}
	return resp.Results, nil
}

// BrowseAll collects all hierarchical forward references for a node.
//
// It automatically follows continuation points until all references are
// retrieved. Results are accumulated in memory and returned as a slice.
//
// For streaming results without accumulating in memory, use
// [Node.BrowseAll] which returns an [iter.Seq2] iterator.
func (c *Client) BrowseAll(ctx context.Context, nodeID *ua.NodeID) ([]*ua.ReferenceDescription, error) {
	n := c.Node(nodeID)
	var refs []*ua.ReferenceDescription
	for ref, err := range n.BrowseAll(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true) {
		if err != nil {
			return refs, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// CallMethod calls a method on a server object.
//
// This is a convenience wrapper around [Client.Call] that automatically
// wraps the variadic args into [ua.Variant] values. For full control
// over the request, use [Client.Call] directly.
//
// objectID is the NodeID of the object that owns the method.
// methodID is the NodeID of the method to call.
func (c *Client) CallMethod(ctx context.Context, objectID, methodID *ua.NodeID, args ...any) (*ua.CallMethodResult, error) {
	variants := make([]*ua.Variant, len(args))
	for i, a := range args {
		v, err := ua.NewVariant(a)
		if err != nil {
			return nil, fmt.Errorf("opcua: call method arg %d: %w", i, err)
		}
		variants[i] = v
	}
	return c.Call(ctx, &ua.CallMethodRequest{
		ObjectID:       objectID,
		MethodID:       methodID,
		InputArguments: variants,
	})
}

// ServerStatus reads the server's ServerStatusDataType from node i=2256.
func (c *Client) ServerStatus(ctx context.Context) (*ua.ServerStatusDataType, error) {
	node := c.Node(ua.NewNumericNodeID(0, id.Server_ServerStatus))
	v, err := node.Value(ctx)
	if err != nil {
		return nil, err
	}
	eo, ok := v.Value().(*ua.ExtensionObject)
	if !ok {
		return nil, fmt.Errorf("opcua: server status: expected ExtensionObject, got %T", v.Value())
	}
	ss, ok := eo.Value.(*ua.ServerStatusDataType)
	if !ok {
		return nil, fmt.Errorf("opcua: server status: expected *ServerStatusDataType, got %T", eo.Value)
	}
	return ss, nil
}

// QueryFirst executes a QueryFirst service call.
func (c *Client) QueryFirst(ctx context.Context, req *ua.QueryFirstRequest) (*ua.QueryFirstResponse, error) {
	stats.Client().Add("QueryFirst", 1)
	return send[ua.QueryFirstResponse](ctx, c, req)
}

// QueryNext executes a QueryNext service call to continue a previous query.
func (c *Client) QueryNext(ctx context.Context, req *ua.QueryNextRequest) (*ua.QueryNextResponse, error) {
	stats.Client().Add("QueryNext", 1)
	return send[ua.QueryNextResponse](ctx, c, req)
}

// MethodArguments reads the InputArguments and OutputArguments properties
// of a method node. Returns nil slices for methods without declared arguments.
func (c *Client) MethodArguments(ctx context.Context, objectID, methodID *ua.NodeID) (inputs, outputs []*ua.Argument, err error) {
	methodNode := c.Node(methodID)
	refs, err := methodNode.References(ctx, id.HasProperty, ua.BrowseDirectionForward, ua.NodeClassVariable, true)
	if err != nil {
		return nil, nil, err
	}

	for _, ref := range refs {
		name := ref.BrowseName.Name
		if name != "InputArguments" && name != "OutputArguments" {
			continue
		}

		argNode := c.NodeFromExpandedNodeID(ref.NodeID)
		v, err := argNode.Value(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("opcua: method arguments: read %s: %w", name, err)
		}
		args, err := extractArguments(v)
		if err != nil {
			return nil, nil, fmt.Errorf("opcua: method arguments: decode %s: %w", name, err)
		}
		if name == "InputArguments" {
			inputs = args
		} else {
			outputs = args
		}
	}
	return inputs, outputs, nil
}

// extractArguments decodes an array of ExtensionObject-wrapped Argument structs
// from a Variant.
func extractArguments(v *ua.Variant) ([]*ua.Argument, error) {
	if v == nil || v.Value() == nil {
		return nil, nil
	}
	eos, ok := v.Value().([]*ua.ExtensionObject)
	if !ok {
		return nil, fmt.Errorf("opcua: expected []*ExtensionObject, got %T", v.Value())
	}
	var args []*ua.Argument
	for _, eo := range eos {
		arg, ok := eo.Value.(*ua.Argument)
		if !ok {
			return nil, fmt.Errorf("opcua: expected *Argument, got %T", eo.Value)
		}
		args = append(args, arg)
	}
	return args, nil
}

// ReadHistory reads raw historical values for a single node within a time range.
// It returns up to maxValues results. Use maxValues=0 for all values in the range.
func (c *Client) ReadHistory(ctx context.Context, nodeID *ua.NodeID, start, end time.Time, maxValues uint32) ([]*ua.DataValue, error) {
	nodes := []*ua.HistoryReadValueID{{NodeID: nodeID}}
	details := &ua.ReadRawModifiedDetails{
		StartTime:        start,
		EndTime:          end,
		NumValuesPerNode: maxValues,
		IsReadModified:   false,
		ReturnBounds:     false,
	}
	resp, err := c.HistoryReadRawModified(ctx, nodes, details)
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 {
		return nil, ua.StatusBadUnexpectedError
	}
	result := resp.Results[0]
	if result.StatusCode != ua.StatusOK && result.StatusCode != ua.StatusGood {
		return nil, result.StatusCode
	}
	hd, ok := result.HistoryData.Value.(*ua.HistoryData)
	if !ok {
		return nil, fmt.Errorf("opcua: history read: expected *HistoryData, got %T", result.HistoryData.Value)
	}
	return hd.DataValues, nil
}

// SecurityPolicy returns the security policy URI of the active secure channel.
func (c *Client) SecurityPolicy() string {
	return c.cfg.sechan.SecurityPolicyURI
}

// SecurityMode returns the message security mode of the active secure channel.
func (c *Client) SecurityMode() ua.MessageSecurityMode {
	return c.cfg.sechan.SecurityMode
}

// NamespaceURI returns the namespace URI for the given namespace index.
// Returns an error if the index is out of bounds.
func (c *Client) NamespaceURI(ctx context.Context, idx uint16) (string, error) {
	ns, err := c.NamespaceArray(ctx)
	if err != nil {
		return "", err
	}
	if int(idx) >= len(ns) {
		return "", fmt.Errorf("opcua: namespace index %d out of range (max %d)", idx, len(ns)-1)
	}
	return ns[idx], nil
}

// WriteAttribute writes a single attribute value to a node.
func (c *Client) WriteAttribute(ctx context.Context, nodeID *ua.NodeID, attrID ua.AttributeID, value *ua.DataValue) (ua.StatusCode, error) {
	resp, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{
				NodeID:      nodeID,
				AttributeID: attrID,
				Value:       value,
			},
		},
	})
	if err != nil {
		return ua.StatusBad, err
	}
	return resp.Results[0], nil
}

// ReadHistoryAll returns an iterator that reads all historical data values for a node
// within the given time range, automatically following continuation points.
func (c *Client) ReadHistoryAll(ctx context.Context, nodeID *ua.NodeID, start, end time.Time) iter.Seq2[*ua.DataValue, error] {
	return func(yield func(*ua.DataValue, error) bool) {
		details := &ua.ReadRawModifiedDetails{
			StartTime:      start,
			EndTime:        end,
			IsReadModified: false,
			ReturnBounds:   false,
		}

		var cp []byte
		for {
			nodes := []*ua.HistoryReadValueID{{NodeID: nodeID, ContinuationPoint: cp}}
			resp, err := c.HistoryReadRawModified(ctx, nodes, details)
			if err != nil {
				yield(nil, err)
				return
			}
			if len(resp.Results) == 0 {
				yield(nil, ua.StatusBadUnexpectedError)
				return
			}
			result := resp.Results[0]
			if result.StatusCode != ua.StatusOK && result.StatusCode != ua.StatusGood {
				yield(nil, result.StatusCode)
				return
			}
			hd, ok := result.HistoryData.Value.(*ua.HistoryData)
			if !ok {
				yield(nil, fmt.Errorf("opcua: history read: expected *HistoryData, got %T", result.HistoryData.Value))
				return
			}
			for _, dv := range hd.DataValues {
				if !yield(dv, nil) {
					return
				}
			}
			cp = result.ContinuationPoint
			if len(cp) == 0 {
				return
			}
		}
	}
}

// WriteNodeValue writes a Go value to the Value attribute of a node.
// The value is wrapped in a Variant using NewVariant, which auto-detects
// the OPC-UA type from the Go type.
func (c *Client) WriteNodeValue(ctx context.Context, nodeID *ua.NodeID, value any) (ua.StatusCode, error) {
	v, err := ua.NewVariant(value)
	if err != nil {
		return ua.StatusBad, fmt.Errorf("opcua: create variant: %w", err)
	}
	return c.WriteAttribute(ctx, nodeID, ua.AttributeIDValue, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        v,
	})
}
