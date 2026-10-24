// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"crypto/rand"
	"expvar"
	"fmt"
	"io"
	"iter"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/stats"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
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
	defer func() { _ = c.Close(ctx) }()
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
	defer func() { _ = c.Close(ctx) }()
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
	defer func() { _ = c.Close(ctx) }()
	res, err := c.GetEndpoints(ctx)
	if err != nil {
		return nil, err
	}
	return res.Endpoints, nil
}

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

	// activeEndpoint is the endpoint URL of the current connection if it
	// differs from endpointURL and ownListener is the reverse connect
	// listener the client opened for itself. See reverse.go. Guarded by
	// connMu.
	activeEndpoint string
	ownListener    *uacp.ReverseListener

	// sechan is the open secure channel.
	atomicSechan atomic.Value // *uasc.SecureChannel

	// sechanErr receives the errors of the current secure channel. Every
	// secure channel gets its own channel (see Dial) so that an error of a
	// channel that has already been replaced cannot be mistaken for an error
	// of its successor. Guarded by connMu.
	sechanErr chan error

	// atomicSession is the active atomicSession.
	atomicSession atomic.Value // *Session

	// leaving is the session ActivateSession is replacing: from the moment
	// it is being closed, faults of its requests are those of a session
	// the client has left, although it is still the active one until the
	// new session is set.
	leaving atomic.Pointer[Session]

	// subMux guards subs and pendingAcks.
	subMux sync.RWMutex

	// subs is the set of active subscriptions by id.
	subs map[uint32]*Subscription

	// subGen counts the subscriptions registered so far; a Publish fault
	// for a request sent before the last registration is stale (see
	// markSubscriptionsBrokenSince). Guarded by subMux.
	subGen uint64

	// pendingAcks contains the pending subscription acknowledgements
	// for all active subscriptions.
	pendingAcks []*ua.SubscriptionAcknowledgement

	// subCreating counts the CreateSubscription requests of Subscribe whose
	// subscription is not registered yet, and subCreatesLost those requests
	// that failed without telling whether the server created the
	// subscription. See createSubscription.
	subCreating    atomic.Int32
	subCreatesLost atomic.Int32

	// lastPublishResponse is when the last Publish response arrived (unix
	// nanoseconds), see markSilentSubscriptions.
	lastPublishResponse atomic.Int64

	// pausech pauses the subscription publish loop
	pausech chan struct{}

	// resumech resumes subscription publish loop
	resumech chan struct{}

	// publishPaused is the desired state of the publish loop and publishGen
	// counts how often it was resumed. See setPublishPaused.
	publishMu         sync.Mutex
	publishPaused     bool
	publishRecovering bool
	publishGen        uint64

	// subRecoverCh wakes the connection monitor when a subscription was
	// found to have ended on the server while the connection is fine. See
	// recoverBrokenSubscriptions.
	subRecoverCh chan struct{}

	// deliverMu serialises the delivery of live PublishResponses with the
	// republishing done during a connection recovery.
	deliverMu sync.Mutex

	// mctx is the context of the connection monitor and the publish loop;
	// mcancel stops them. Both are created with the client so that Close and
	// Connect can be called concurrently.
	mctx    context.Context
	mcancel func()

	// monitorDone is closed when the connection monitor has stopped;
	// monitorStarted tells whether it was ever started. inMonitorHandler is
	// set while the monitor runs a user supplied handler and closeDone once
	// Close has finished. See Close.
	monitorDone      chan struct{}
	monitorStarted   atomic.Bool
	inMonitorHandler atomic.Bool
	closeDone        atomic.Bool

	// timeout for sending PublishRequests
	atomicPublishTimeout atomic.Value // time.Duration

	// atomicState of the client
	atomicState atomic.Value // ConnState

	// stateCh is an optional channel for connection state changes. May be nil.
	stateCh chan<- ConnState

	// stateFunc is an optional func for connection state changes. May be nil.
	stateFunc func(ConnState)

	// recoveryFunc is an optional func called after each subscription recovery
	// attempt during automatic reconnect. May be nil.
	recoveryFunc func(SubscriptionRecoveryEvent)

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
// https://godoc.org/github.com/otfabric/go-opcua#Option
func NewClient(endpoint string, opts ...Option) (*Client, error) {
	cfg, err := ApplyConfig(opts...)
	if err != nil {
		return nil, err
	}
	// Propagate logger to sub-components.
	cfg.dialer.Logger = cfg.logger
	cfg.sechan.Logger = cfg.logger

	mctx, mcancel := context.WithCancel(context.Background())
	c := Client{
		endpointURL:  endpoint,
		cfg:          cfg,
		mctx:         mctx,
		mcancel:      mcancel,
		monitorDone:  make(chan struct{}),
		subRecoverCh: make(chan struct{}, 1),
		sechanErr:    make(chan error, 1),
		subs:         make(map[uint32]*Subscription),
		pendingAcks:  make([]*ua.SubscriptionAcknowledgement, 0),
		pausech:      make(chan struct{}, 2),
		resumech:     make(chan struct{}, 2),
		stateCh:      cfg.stateCh,
		stateFunc:    cfg.stateFunc,
		recoveryFunc: cfg.recoveryFunc,
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
		// nothing was established: do not leave the state at Connecting
		c.setState(ctx, Closed)

		return err
	}

	s, err := c.CreateSession(ctx, c.cfg.session)
	if err != nil {
		_ = c.Close(ctx)
		stats.RecordError(err)

		return err
	}

	if _, err := c.activateSession(ctx, s); err != nil {
		c.discardSession(s)
		_ = c.Close(ctx)
		stats.RecordError(err)

		return err
	}
	c.setState(ctx, Connected)

	c.monitorOnce.Do(func() {
		c.monitorStarted.Store(true)
		go c.monitor(c.mctx)
		go c.monitorSubscriptions(c.mctx)
	})

	// Close may have run while the connection was being established. It
	// could then not see (and close) what Connect has set up since, so
	// tear it down here instead of returning a client that looks connected.
	if c.mctx.Err() != nil {
		_ = c.Close(ctx)
		return ua.StatusBadConnectionClosed
	}

	// Update the client's namespace table from the server.
	// See https://github.com/otfabric/go-opcua/pull/512 for discussion.
	if !c.cfg.skipNamespaceUpdate {
		if err := c.UpdateNamespaces(ctx); err != nil {
			_ = c.Close(ctx)
			stats.RecordError(err)

			return err
		}
	}

	return nil
}

// monitor manages connection alteration.
func (c *Client) monitor(ctx context.Context) {
	c.cfg.logger.Debug("monitor: start")
	defer c.cfg.logger.Debug("monitor: done")

	// Runs last: Close waits for it.
	defer close(c.monitorDone)
	defer c.mcancel()
	defer c.setStateFromMonitor(ctx, Closed)
	defer func() {
		// Close normally waits for the monitor to stop before it closes the
		// session and the secure channel. It cannot wait when it is called
		// from a handler the monitor itself is running; a secure channel
		// that a reconnect attempt installs after such a Close has finished
		// would stay open forever, so close it here.
		if !c.closeDone.Load() {
			return
		}
		if sc := c.SecureChannel(); sc != nil {
			_ = sc.Close()
			c.setSecureChannel(nil)
		}
	}()

	// retryBroken fires when subscriptions that could not be recreated are
	// to be tried again. A recreation can fail although the connection is
	// fine (a request that timed out on a busy server, for example); without
	// another attempt the subscription would stay without its monitored
	// items, silently, until the connection is lost the next time.
	var retryBroken <-chan time.Time
	armRetry := func() {
		retryBroken = nil
		if !c.cfg.sechan.AutoReconnect || ctx.Err() != nil {
			return
		}
		if _, broken := c.partitionSubscriptions(); len(broken) > 0 {
			retryBroken = time.After(c.cfg.sechan.ReconnectInterval)
		}
	}

	// silence is the clock of the check for subscriptions the server has
	// stopped serving, see markSilentSubscriptions.
	var silence <-chan time.Time
	if c.cfg.sechan.AutoReconnect {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		silence = t.C
	}

	var action reconnectAction
	for {
		select {
		case <-ctx.Done():
			return

		case <-silence:
			if c.State() == Connected && c.markSilentSubscriptions() > 0 {
				c.recoverBrokenSubscriptions(ctx)
				armRetry()
			}

		case <-c.subRecoverCh:
			c.recoverBrokenSubscriptions(ctx)
			armRetry()

		case <-retryBroken:
			c.recoverBrokenSubscriptions(ctx)
			armRetry()

		case err, ok := <-c.secureChannelErrors():
			stats.RecordError(err)

			// return if channel or connection is closed
			if !ok || errors.Is(err, io.EOF) && c.State() == Closed {
				c.cfg.logger.Debug("monitor: closed")
				return
			}

			// A fault of a request sent in a session the client has left
			// (the application activated another one, or a reconnect
			// replaced it) says nothing about the session it uses now.
			var fault *uasc.RequestFault
			if errors.As(err, &fault) && c.leftSession(fault.AuthToken) {
				c.cfg.logger.Debug("monitor: fault of a session the client has left, ignoring", "error", err)
				continue
			}

			// tell the handler the connection is disconnected
			c.setStateFromMonitor(ctx, Disconnected)
			c.cfg.logger.Debug("monitor: disconnected")

			if !c.cfg.sechan.AutoReconnect {
				c.cfg.logger.Debug("monitor: auto-reconnect disabled")
				return
			}

			c.cfg.logger.Debug("monitor: auto-reconnecting")

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
				if eps, epErr := c.refetchEndpoints(ctx); epErr == nil {
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
				// unknown error has occurred
				action = createSecureChannel
			}

			// Hold the publish loop for the whole recovery. Missed notifications
			// are republished below, and a live PublishResponse delivered at
			// the same time would break their order.
			c.setPublishRecovering(true)

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

					case none:
						// no action needed

					case createSecureChannel:
						c.cfg.logger.Debug("monitor: action: createSecureChannel")

						// recreate a secure channel by brute forcing
						// a reconnection to the server

						// Close the previous secure channel. The secure channel owns
						// the underlying UACP connection so closing it is sufficient.
						// Only close the raw connection as a fallback when no secure
						// channel exists.
						if sc := c.SecureChannel(); sc != nil {
							_ = sc.Close()
							c.setSecureChannel(nil)
						} else {
							c.connMu.Lock()
							if c.conn != nil {
								_ = c.conn.Close()
							}
							c.connMu.Unlock()
						}

						c.setStateFromMonitor(ctx, Reconnecting)

						c.cfg.logger.Debug("monitor: trying to recreate secure channel")
						for {
							if err := c.Dial(ctx); err != nil {
								select {
								case <-ctx.Done():
									return
								case <-time.After(c.cfg.sechan.ReconnectInterval):
									c.cfg.logger.Debug("monitor: trying to recreate secure channel")
									continue
								}
							}
							break
						}
						c.cfg.logger.Debug("monitor: secure channel recreated")
						action = restoreSession

					case restoreSession:
						c.cfg.logger.Debug("monitor: action: restoreSession")

						c.setStateFromMonitor(ctx, Reconnecting)

						s := c.Session()
						if s == nil {
							c.cfg.logger.Debug("monitor: no session to restore")
							action = recreateSession
							continue
						}

						c.cfg.logger.Debug("monitor: trying to restore session")
						if _, err := c.activateSession(ctx, s); err != nil {
							c.cfg.logger.Debug("monitor: restore session failed", "error", err)
							action = recreateSession
							continue
						}
						c.cfg.logger.Debug("monitor: session restored")

						c.cfg.logger.Debug("monitor: trying to update namespaces")
						if !c.cfg.skipNamespaceUpdate {
							if err := c.UpdateNamespaces(ctx); err != nil {
								c.cfg.logger.Debug("monitor: updating namespaces failed", "error", err)
								action = c.retryReconnect(ctx)
								continue
							}
						}
						c.cfg.logger.Debug("monitor: namespaces updated")

						// The session survived, and with it its subscriptions.
						// Fetch the notifications that were sent while the
						// connection was down and resume publishing.
						subsToRepublish, subsToRecreate = c.partitionSubscriptions()
						availableSeqs = map[uint32][]uint32{}

						action = restoreSubscriptions

					case recreateSession:
						c.cfg.logger.Debug("monitor: action: recreateSession")

						c.setStateFromMonitor(ctx, Reconnecting)

						c.setSession(nil)

						c.cfg.logger.Debug("monitor: trying to recreate session")
						s, err := c.CreateSession(ctx, c.cfg.session)
						if err != nil {
							c.cfg.logger.Debug("monitor: recreate session failed", "error", err)
							action = c.retryReconnect(ctx)
							continue
						}
						if _, err := c.activateSession(ctx, s); err != nil {
							c.cfg.logger.Debug("monitor: reactivate session failed", "error", err)
							c.discardSession(s)
							action = c.retryReconnect(ctx)
							continue
						}
						c.cfg.logger.Debug("monitor: session recreated")

						c.cfg.logger.Debug("monitor: trying to update namespaces")
						if !c.cfg.skipNamespaceUpdate {
							if err := c.UpdateNamespaces(ctx); err != nil {
								c.cfg.logger.Debug("monitor: updating namespaces failed", "error", err)
								action = c.retryReconnect(ctx)
								continue
							}
						}
						c.cfg.logger.Debug("monitor: namespaces updated")

						action = transferSubscriptions

					case transferSubscriptions:
						c.cfg.logger.Debug("monitor: action: transferSubscriptions")

						// Subscriptions whose last recreation failed do not exist
						// on the server in a usable form; transferring them is
						// pointless, they have to be recreated.
						subIDs, broken := c.partitionSubscriptions()

						availableSeqs = map[uint32][]uint32{}
						subsToRecreate = nil
						subsToRepublish = nil

						var (
							res *ua.TransferSubscriptionsResponse
							err error
						)
						if len(subIDs) > 0 {
							res, err = c.transferSubscriptions(ctx, subIDs)
						}
						switch {

						case len(subIDs) == 0:
							// nothing to transfer

						case errors.Is(err, ua.StatusBadServiceUnsupported):
							c.cfg.logger.Debug("monitor: transfer subscriptions not supported, recreating all subscriptions", "error", err)
							subsToRepublish = nil
							subsToRecreate = subIDs

						case err != nil:
							c.cfg.logger.Debug("monitor: transfer subscriptions failed, recreating all subscriptions", "error", err)
							subsToRepublish = nil
							subsToRecreate = subIDs

						default:
							for i, subID := range subIDs {
								// a subscription without a result was not transferred
								if i >= len(res.Results) || res.Results[i] == nil {
									subsToRecreate = append(subsToRecreate, subID)
									continue
								}
								transferResult := res.Results[i]
								switch transferResult.StatusCode {
								case ua.StatusBadSubscriptionIDInvalid:
									c.cfg.logger.Debug("monitor: transfer subscription failed", "sub_id", subID)
									subsToRecreate = append(subsToRecreate, subID)

								default:
									subsToRepublish = append(subsToRepublish, subID)
									availableSeqs[subID] = transferResult.AvailableSequenceNumbers
								}
							}
						}
						subsToRecreate = append(subsToRecreate, broken...)

						action = restoreSubscriptions

					case restoreSubscriptions:
						c.cfg.logger.Debug("monitor: action: restoreSubscriptions")

						activeSubs = 0
						for _, subID := range subsToRepublish {
							avail := availableSeqs[subID]
							rr, err := c.republishSubscription(ctx, subID, avail)
							if err != nil {
								c.cfg.logger.Debug("monitor: republish of subscription failed", "sub_id", subID)
								subsToRecreate = append(subsToRecreate, subID)
								// Recovery event emitted below when recreating.
							} else {
								// Determine outcome for this transferred subscription.
								var outcome SubscriptionRecoveryOutcome
								var detail string
								switch {
								case rr.gapDetected && rr.republishedCount > 0:
									outcome = SubscriptionRecoveryPartial
									detail = fmt.Sprintf("transferred with gap: %d notifications recovered, next sequence number was missing from retransmission buffer", rr.republishedCount)
								case rr.gapDetected:
									outcome = SubscriptionRecoveryUnrecoverableGap
									detail = "transferred but next sequence number not in server retransmission buffer; notifications permanently lost"
								case rr.republishedCount > 0:
									outcome = SubscriptionRecoveryRepublished
									detail = fmt.Sprintf("transferred and %d notifications recovered via Republish", rr.republishedCount)
								default:
									outcome = SubscriptionRecoveryTransferred
									detail = "transferred successfully; no buffered notifications to recover"
								}
								c.notifyRecoveryFromMonitor(SubscriptionRecoveryEvent{
									SubscriptionID:           subID,
									Outcome:                  outcome,
									AvailableSequenceNumbers: avail,
									Detail:                   detail,
								})
							}
							activeSubs++
						}

						for _, subID := range subsToRecreate {
							if err := c.recreateSubscription(ctx, subID); err != nil {
								c.cfg.logger.Debug("monitor: recreate subscriptions failed", "error", err)
								// The subscription stays registered so that the
								// next recovery tries again; tell its consumer.
								c.notifySubscriptionOfError(ctx, subID, err)
								continue
							}
							c.notifyRecoveryFromMonitor(SubscriptionRecoveryEvent{
								SubscriptionID: subID,
								Outcome:        SubscriptionRecoveryRecreated,
								Detail:         "subscription recreated as new; previous notification history lost",
							})
							activeSubs++
						}

						// Errors reported up to here belong to the recovery
						// itself (requests failing while the session was
						// being replaced) and are obsolete now.
						c.drainSecureChannelErrors()

						// The connection may have been lost again while the
						// recovery was in progress. Its error has just been
						// discarded, and the secure channel reports only
						// once, so check explicitly: declaring the client
						// Connected on a dead channel would leave it stuck
						// there for good.
						if c.secureChannelLost() {
							c.cfg.logger.Debug("monitor: connection lost during recovery, starting over")
							action = c.retryReconnect(ctx)
							continue
						}

						c.setStateFromMonitor(ctx, Connected)
						action = none

					case abortReconnect:
						c.cfg.logger.Debug("monitor: action: abortReconnect")

						c.cfg.logger.Warn("monitor: reconnection not recoverable")
						return
					}
				}
			}

			c.setPublishRecovering(false)

			switch {
			case activeSubs > 0 || len(c.SubscriptionIDs()) > 0:
				c.cfg.logger.Debug("monitor: resuming subscriptions", "count", activeSubs)
				c.touchSubscriptions()
				c.resumeSubscriptions(ctx)
				c.cfg.logger.Debug("monitor: resumed subscriptions", "count", activeSubs)
			default:
				c.cfg.logger.Debug("monitor: no subscriptions to resume")
			}
			armRetry()
		}
	}
}

// Dial establishes a secure channel.
func (c *Client) Dial(ctx context.Context) error {
	stats.Client().Add("Dial", 1)

	if c.SecureChannel() != nil {
		return errors.ErrAlreadyConnected
	}

	// connMu must not be held while dialing: the dial can take as long as
	// its timeout and Close needs the mutex.
	var (
		conn     *uacp.Conn
		endpoint = c.endpointURL
		err      error
	)
	if c.cfg.reverse != nil {
		// reverse connect: wait for the server to connect to us
		conn, endpoint, err = c.acceptReverse(ctx)
	} else {
		conn, err = c.cfg.dialer.Dial(ctx, c.endpointURL)
	}
	if err != nil {
		return err
	}

	c.connMu.Lock()
	c.conn = conn
	c.activeEndpoint = endpoint
	c.connMu.Unlock()

	errCh := make(chan error, 1)
	sc, err := uasc.NewSecureChannel(endpoint, conn, c.cfg.sechan, errCh)
	if err != nil {
		_ = conn.Close()
		return err
	}

	if err := sc.Open(ctx); err != nil {
		// closing the secure channel also stops its dispatcher
		_ = sc.Close()
		_ = conn.Close()
		return err
	}
	c.connMu.Lock()
	c.sechanErr = errCh
	c.connMu.Unlock()
	c.setSecureChannel(sc)

	// Validate the server certificate configured via SecurityFromEndpoint
	// or RemoteCertificate before proceeding.
	if err := c.cfg.validateServerCertificate(c.cfg.sechan.RemoteCertificate, c.cfg.sechan.SecurityMode); err != nil {
		_ = sc.Close()
		_ = conn.Close()
		c.setSecureChannel(nil)
		return err
	}

	return nil
}

// refetchEndpoints asks the server for its endpoints on a connection of its
// own, the way the client itself connects.
func (c *Client) refetchEndpoints(ctx context.Context) ([]*ua.EndpointDescription, error) {
	opts, err := c.reverseOptions(ctx)
	if err != nil {
		return nil, err
	}
	return GetEndpoints(ctx, c.endpointURL, opts...)
}

// secureChannelErrors returns the channel on which the current secure channel
// reports its errors.
func (c *Client) secureChannelErrors() chan error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return c.sechanErr
}

// drainSecureChannelErrors discards the pending errors of the current secure
// channel.
func (c *Client) drainSecureChannelErrors() {
	ch := c.secureChannelErrors()
	for {
		select {
		case _, ok := <-ch:
			// The channel is never closed (see Close), but a closed one
			// would make this loop spin forever.
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// secureChannelLost reports whether the client has no secure channel or its
// connection is gone.
func (c *Client) secureChannelLost() bool {
	sc := c.SecureChannel()
	if sc == nil {
		return true
	}
	select {
	case <-sc.Disconnected():
		return true
	default:
		return false
	}
}

// retryReconnect waits for the reconnect interval and returns the action
// that starts the recovery over with a new secure channel. The wait keeps a
// recovery that fails immediately from spinning.
func (c *Client) retryReconnect(ctx context.Context) reconnectAction {
	select {
	case <-ctx.Done():
	case <-time.After(c.cfg.sechan.ReconnectInterval):
	}
	return createSecureChannel
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

	// Stop the connection monitor and the publish loop first and wait until
	// the monitor is gone. As long as it runs, the reconnect logic reacts to
	// the session being closed below (requests of other goroutines fail
	// with BadSessionIdInvalid) by creating a new session, which nobody
	// would ever close, and may replace the secure channel behind our back.
	if c.mcancel != nil {
		c.mcancel()
	}
	c.waitForMonitor(ctx)

	// try to close the session but ignore any error
	// so that we close the underlying channel and connection.
	_ = c.CloseSession(ctx)
	c.setState(ctx, Closed)

	if sc := c.SecureChannel(); sc != nil {
		_ = sc.Close()
		c.setSecureChannel(nil)
	}

	// https://github.com/otfabric/go-opcua/pull/462
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
		_ = c.conn.Close()
	}
	c.connMu.Unlock()

	// stop listening for reverse connections
	c.closeReverseListener()

	c.closeDone.Store(true)

	return nil
}

// waitForMonitor waits until the connection monitor has stopped, or ctx is
// done. It returns immediately if the monitor was never started, and when it
// is called from a handler (state or recovery handler) that the monitor
// itself is running: waiting there would wait for itself.
func (c *Client) waitForMonitor(ctx context.Context) {
	if !c.monitorStarted.Load() || c.inMonitorHandler.Load() {
		return
	}
	select {
	case <-c.monitorDone:
	case <-ctx.Done():
	}
}

// setStateFromMonitor is setState for the connection monitor. It marks the
// time the state handler runs so that a handler may call Close.
func (c *Client) setStateFromMonitor(ctx context.Context, s ConnState) {
	c.inMonitorHandler.Store(true)
	defer c.inMonitorHandler.Store(false)
	c.setState(ctx, s)
}

// notifyRecoveryFromMonitor is notifyRecovery for the connection monitor,
// see setStateFromMonitor.
func (c *Client) notifyRecoveryFromMonitor(ev SubscriptionRecoveryEvent) {
	c.inMonitorHandler.Store(true)
	defer c.inMonitorHandler.Store(false)
	c.notifyRecovery(ev)
}

// discardSession closes a session that was created on the server but could
// not be activated. Such a session is not the client's session, so nothing
// else would close it and it would occupy the server until its timeout
// expires. This is best effort and does not wait for the response.
func (c *Client) discardSession(s *Session) {
	sc := c.SecureChannel()
	if sc == nil || s == nil || s.resp == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.sechan.RequestTimeout)
	defer cancel()
	_ = sc.SendRequest(ctx, &ua.CloseSessionRequest{DeleteSubscriptions: true}, s.resp.AuthenticationToken, nil)
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

// notifyRecovery delivers a SubscriptionRecoveryEvent to the registered
// handler, if any. It is called synchronously from the reconnect goroutine.
func (c *Client) notifyRecovery(ev SubscriptionRecoveryEvent) {
	if c.recoveryFunc != nil {
		c.recoveryFunc(ev)
	}
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

// leftSession reports whether authToken is that of a session the client no
// longer uses. A nil token is a request outside any session.
func (c *Client) leftSession(authToken *ua.NodeID) bool {
	if authToken == nil {
		return false
	}
	if l := c.leaving.Load(); l != nil && l.resp.AuthenticationToken.Equal(authToken) {
		return true
	}
	s := c.Session()
	return s == nil || !s.resp.AuthenticationToken.Equal(authToken)
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
	if s != nil {
		c.leaving.CompareAndSwap(s, nil)
	}
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

	// clientNonce is the nonce sent in the CreateSession request. The channel
	// bound signatures of ActivateSession cover it.
	clientNonce []byte

	// serverEphemeralKey is the ephemeral public key the server handed out
	// most recently, for user identity tokens that are protected with an ECC
	// security policy. A key is used for one ActivateSession only; every
	// response brings the key for the next one.
	serverEphemeralKey []byte

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
// See Part 4, 5.6.2.
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
		EndpointURL:             c.endpoint(),
		SessionName:             name,
		ClientNonce:             nonce,
		ClientCertificate:       c.cfg.sechan.Certificate,
		RequestedSessionTimeout: float64(cfg.SessionTimeout / time.Millisecond),
	}

	// A user identity token that is protected with an ECC security policy
	// needs an ephemeral key of the server. Ask for it.
	ecdhPolicy := ecdhPolicyFor(sc, cfg)
	if ecdhPolicy != "" {
		req.RequestHeader = &ua.RequestHeader{AdditionalHeader: uasc.NewECDHPolicyHeader(ecdhPolicy)}
	}

	var s *Session
	// for the CreateSessionRequest the authToken is always nil.
	// use sc.SendRequest() to enforce this.
	err := sc.SendRequest(ctx, req, nil, func(v ua.Response) error {
		var res *ua.CreateSessionResponse
		if err := assign(v, &res); err != nil {
			return err
		}

		var serverSignature []byte
		if res.ServerSignature != nil {
			serverSignature = res.ServerSignature.Signature
		}
		err := sc.VerifyCreateSessionSignature(res.ServerCertificate, nonce, res.ServerNonce, serverSignature)
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
			clientNonce:       nonce,
			serverCertificate: res.ServerCertificate,
			revisedTimeout:    time.Duration(res.RevisedSessionTimeout) * time.Millisecond,
		}

		if ecdhPolicy != "" {
			key, err := serverEphemeralKey(sc, ecdhPolicy, res.ResponseHeader, res.ServerCertificate)
			if err != nil {
				return fmt.Errorf("opcua: server ephemeral key: %w", err)
			}
			s.serverEphemeralKey = key
		}

		return nil
	})
	return s, err
}

// ecdhPolicyFor returns the ECC security policy that protects the secret of
// the session's user identity token, or "" if the token has no secret or is
// protected otherwise. Tokens with a secret are the user name token (its
// password) and the issued token (its token data).
func ecdhPolicyFor(sc *uasc.SecureChannel, cfg *uasc.SessionConfig) string {
	switch cfg.UserIdentityToken.(type) {
	case *ua.UserNameIdentityToken, *ua.IssuedIdentityToken:
	default:
		return ""
	}
	if !sc.UserTokenPolicyIsECC(cfg.AuthPolicyURI) {
		return ""
	}
	if cfg.AuthPolicyURI != "" {
		return cfg.AuthPolicyURI
	}
	return sc.SecurityPolicyURI()
}

// serverEphemeralKey extracts the ephemeral key from the AdditionalHeader of
// a CreateSession or ActivateSession response and verifies that it was signed
// with the server's application instance key. It returns nil if the response
// carries no key.
func serverEphemeralKey(sc *uasc.SecureChannel, policyURI string, hdr *ua.ResponseHeader, serverCertificate []byte) ([]byte, error) {
	if hdr == nil {
		return nil, nil
	}
	key, err := uasc.ECDHKeyFromHeader(hdr.AdditionalHeader)
	if err != nil || key == nil {
		return nil, err
	}
	if uri, ok := uasc.ECDHPolicyFromHeader(hdr.AdditionalHeader); ok && uri != policyURI {
		return nil, fmt.Errorf("%w: key is for %s, not %s", ua.StatusBadSecurityPolicyRejected, uri, policyURI)
	}
	// An unsigned key could have been put there by anyone who can modify the
	// response; the secret would then be encrypted for them.
	if err := sc.VerifyEphemeralKeySignature(policyURI, serverCertificate, key.PublicKey, key.Signature); err != nil {
		return nil, fmt.Errorf("%w: %w", ua.StatusBadSecurityChecksFailed, err)
	}
	return key.PublicKey, nil
}

// takeServerEphemeralKey returns the server's ephemeral key and forgets it: a
// key protects a single secret.
func (s *Session) takeServerEphemeralKey() []byte {
	key := s.serverEphemeralKey
	s.serverEphemeralKey = nil
	return key
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
// See Part 4, 5.6.3.
func (c *Client) ActivateSession(ctx context.Context, s *Session) error {
	replaced, err := c.activateSession(ctx, s)
	if err != nil {
		return err
	}
	// The subscriptions of the client lived in the session it had before.
	// That session has just been closed, and its subscriptions with it, or
	// (after DetachSession) it stays behind with them. Either way they are
	// not in the session the client publishes in from now on: have them
	// recreated there. Without this the client would keep subscriptions
	// that never deliver again.
	if replaced && c.cfg.sechan.AutoReconnect && c.markSubscriptionsBroken() > 0 {
		c.requestSubscriptionRecovery()
	}
	return nil
}

// activateSession is ActivateSession without moving the subscriptions. It
// reports whether s replaced another session, or none, of the client. The
// reconnect logic uses it: it moves the subscriptions itself.
func (c *Client) activateSession(ctx context.Context, s *Session) (replaced bool, err error) {
	err = c.doActivateSession(ctx, s, &replaced)
	return replaced, err
}

func (c *Client) doActivateSession(ctx context.Context, s *Session, replaced *bool) error {
	sc := c.SecureChannel()
	if sc == nil {
		return ua.StatusBadServerNotConnected
	}
	stats.Client().Add("ActivateSession", 1)
	sig, sigAlg, err := sc.NewActivateSessionSignature(s.serverCertificate, s.serverNonce, s.clientNonce)
	if err != nil {
		return fmt.Errorf("opcua: create session signature: %w", err)
	}

	// identity is the token as it is sent. Protecting a token (encrypting the
	// password, signing with the user certificate) never changes the
	// configured one: the configuration is shared by every session of the
	// client, and the client's reconnect may activate a session while the
	// application activates another one.
	identity := s.cfg.UserIdentityToken
	tokenSignature := s.cfg.UserTokenSignature
	ecdhPolicy := ecdhPolicyFor(sc, s.cfg)

	switch tok := s.cfg.UserIdentityToken.(type) {
	case *ua.AnonymousIdentityToken:
		// nothing to do

	case *ua.UserNameIdentityToken:
		if ecdhPolicy != "" {
			// ECC: the password travels in an EccEncryptedSecret. Its
			// format is fixed by the security policy, so there is no
			// encryption algorithm to name.
			pass, err := sc.EncryptUserSecret(ecdhPolicy, []byte(s.cfg.AuthPassword), s.takeServerEphemeralKey(), s.serverNonce)
			if err != nil {
				c.cfg.logger.Warn("error encrypting user password", "error", err)
				return err
			}
			protected := *tok
			protected.Password = pass
			protected.EncryptionAlgorithm = ""
			identity = &protected
			break
		}
		pass, passAlg, err := sc.EncryptUserPassword(s.cfg.AuthPolicyURI, s.cfg.AuthPassword, s.serverCertificate, s.serverNonce)
		if err != nil {
			c.cfg.logger.Warn("error encrypting user password", "error", err)
			return err
		}
		protected := *tok
		protected.Password = pass
		protected.EncryptionAlgorithm = passAlg
		identity = &protected

	case *ua.X509IdentityToken:
		tokSig, tokSigAlg, err := sc.NewSessionUserTokenSignature(s.cfg.AuthPolicyURI, s.serverCertificate, s.serverNonce, s.clientNonce)
		if err != nil {
			c.cfg.logger.Warn("error creating session signature", "error", err)
			return err
		}
		tokenSignature = &ua.SignatureData{
			Algorithm: tokSigAlg,
			Signature: tokSig,
		}

	case *ua.IssuedIdentityToken:
		protected := *tok
		protected.EncryptionAlgorithm = ""
		identity = &protected
		if ecdhPolicy != "" {
			data, err := sc.EncryptUserSecret(ecdhPolicy, tok.TokenData, s.takeServerEphemeralKey(), s.serverNonce)
			if err != nil {
				c.cfg.logger.Warn("error encrypting issued token", "error", err)
				return err
			}
			protected.TokenData = data
		}
	}

	req := &ua.ActivateSessionRequest{
		ClientSignature: &ua.SignatureData{
			Algorithm: sigAlg,
			Signature: sig,
		},
		ClientSoftwareCertificates: nil,
		LocaleIDs:                  s.cfg.LocaleIDs,
		UserIdentityToken:          ua.NewExtensionObject(identity),
		UserTokenSignature:         tokenSignature,
	}
	if ecdhPolicy != "" {
		// The key of this activation is spent. Ask for the next one: the
		// session is activated again when the client reconnects.
		req.RequestHeader = &ua.RequestHeader{AdditionalHeader: uasc.NewECDHPolicyHeader(ecdhPolicy)}
	}
	return sc.SendRequest(ctx, req, s.resp.AuthenticationToken, func(v ua.Response) error {
		var res *ua.ActivateSessionResponse
		if err := assign(v, &res); err != nil {
			return err
		}

		// save the nonce for the next request
		s.serverNonce = res.ServerNonce

		if ecdhPolicy != "" {
			key, err := serverEphemeralKey(sc, ecdhPolicy, res.ResponseHeader, s.serverCertificate)
			if err != nil {
				return fmt.Errorf("opcua: server ephemeral key: %w", err)
			}
			if key != nil {
				s.serverEphemeralKey = key
			}
		}

		// close the previous session
		//
		// https://github.com/otfabric/go-opcua/issues/474
		//
		// We decided not to check the error of CloseSession() since we
		// can't do much about it anyway and it creates a race in the
		// re-connection logic.
		//
		// When the session being activated is the client's current one
		// (re-activation on a new secure channel after a reconnect) there
		// is no previous session: closing "it" would close the session
		// that was just activated and delete all of its subscriptions.
		//
		// The previous session is closed while it still is the client's
		// session (the request is sent in it). Taking it away first would
		// leave the client without a session for a moment, in which every
		// request of another goroutine, the publish loop included, fails
		// with BadSessionIdInvalid and sets off the reconnect logic.
		if prev := c.Session(); prev != s {
			*replaced = true
			c.leaving.Store(prev)
			stats.Client().Add("CloseSession", 1)
			_ = c.closeSession(ctx, prev)
		}

		c.setSession(s)
		return nil
	})
}

// CloseSession closes the current session.
//
// See Part 4, 5.6.4.
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
			if errors.Is(err, ua.StatusBadTimeout) {
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

// FindServers finds the servers available at an endpoint.
func (c *Client) FindServers(ctx context.Context) (*ua.FindServersResponse, error) {
	stats.Client().Add("FindServers", 1)

	req := &ua.FindServersRequest{
		EndpointURL: c.endpoint(),
	}
	return send[ua.FindServersResponse](ctx, c, req)
}

// FindServersOnNetwork finds the servers available at an endpoint.
func (c *Client) FindServersOnNetwork(ctx context.Context) (*ua.FindServersOnNetworkResponse, error) {
	stats.Client().Add("FindServersOnNetwork", 1)

	req := &ua.FindServersOnNetworkRequest{}
	return send[ua.FindServersOnNetworkResponse](ctx, c, req)
}

// GetEndpoints returns the list of available endpoints of the server.
func (c *Client) GetEndpoints(ctx context.Context) (*ua.GetEndpointsResponse, error) {
	stats.Client().Add("GetEndpoints", 1)

	req := &ua.GetEndpointsRequest{
		EndpointURL: c.endpoint(),
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
		RequestHeader:      req.RequestHeader,
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
		RequestHeader:                 req.RequestHeader,
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
// Part 4, Section 5.8.5.
func (c *Client) RegisterNodes(ctx context.Context, req *ua.RegisterNodesRequest) (*ua.RegisterNodesResponse, error) {
	stats.Client().Add("RegisterNodes", 1)
	stats.Client().Add("NodesToRegister", int64(len(req.NodesToRegister)))

	return send[ua.RegisterNodesResponse](ctx, c, req)
}

// UnregisterNodes unregisters node ids previously registered with RegisterNodes.
//
// Part 4, Section 5.8.6.
func (c *Client) UnregisterNodes(ctx context.Context, req *ua.UnregisterNodesRequest) (*ua.UnregisterNodesResponse, error) {
	stats.Client().Add("UnregisterNodes", 1)
	stats.Client().Add("NodesToUnregister", int64(len(req.NodesToUnregister)))

	return send[ua.UnregisterNodesResponse](ctx, c, req)
}

// SetPublishingMode enables or disables publishing of notification messages
// for one or more subscriptions.
//
// Part 4, Section 5.13.4.
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
// Part 4, Section 5.7.2.
func (c *Client) AddNodes(ctx context.Context, req *ua.AddNodesRequest) (*ua.AddNodesResponse, error) {
	stats.Client().Add("AddNodes", 1)
	stats.Client().Add("NodesToAdd", int64(len(req.NodesToAdd)))

	return send[ua.AddNodesResponse](ctx, c, req)
}

// DeleteNodes deletes one or more nodes from the server address space.
//
// Part 4, Section 5.7.3.
func (c *Client) DeleteNodes(ctx context.Context, req *ua.DeleteNodesRequest) (*ua.DeleteNodesResponse, error) {
	stats.Client().Add("DeleteNodes", 1)
	stats.Client().Add("NodesToDelete", int64(len(req.NodesToDelete)))

	return send[ua.DeleteNodesResponse](ctx, c, req)
}

// AddReferences adds one or more references to one or more nodes.
//
// Part 4, Section 5.7.4.
func (c *Client) AddReferences(ctx context.Context, req *ua.AddReferencesRequest) (*ua.AddReferencesResponse, error) {
	stats.Client().Add("AddReferences", 1)
	stats.Client().Add("ReferencesToAdd", int64(len(req.ReferencesToAdd)))

	return send[ua.AddReferencesResponse](ctx, c, req)
}

// DeleteReferences deletes one or more references from one or more nodes.
//
// Part 4, Section 5.7.5.
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
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadEventDetailsEncodingDefaultBinary),
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
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadRawModifiedDetailsEncodingDefaultBinary),
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
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadProcessedDetailsEncodingDefaultBinary),
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
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadAtTimeDetailsEncodingDefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        details,
		},
	}

	return send[ua.HistoryReadResponse](ctx, c, req)
}

// HistoryUpdateData updates historical data values for one or more nodes.
//
// Part 4, Section 5.10.5 / Part 11, Section 6.8.2.
func (c *Client) HistoryUpdateData(ctx context.Context, details ...*ua.UpdateDataDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryUpdateData", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.UpdateDataDetailsEncodingDefaultBinary),
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
// Part 4, Section 5.10.5 / Part 11, Section 6.8.4.
func (c *Client) HistoryUpdateEvents(ctx context.Context, details ...*ua.UpdateEventDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryUpdateEvents", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.UpdateEventDetailsEncodingDefaultBinary),
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
// Part 4, Section 5.10.5 / Part 11, Section 6.8.5.
func (c *Client) HistoryDeleteRawModified(ctx context.Context, details ...*ua.DeleteRawModifiedDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryDeleteRawModified", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.DeleteRawModifiedDetailsEncodingDefaultBinary),
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
// Part 4, Section 5.10.5 / Part 11, Section 6.8.6.
func (c *Client) HistoryDeleteAtTime(ctx context.Context, details ...*ua.DeleteAtTimeDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryDeleteAtTime", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.DeleteAtTimeDetailsEncodingDefaultBinary),
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
// Part 4, Section 5.10.5 / Part 11, Section 6.8.7.
func (c *Client) HistoryDeleteEvents(ctx context.Context, details ...*ua.DeleteEventDetails) (*ua.HistoryUpdateResponse, error) {
	stats.Client().Add("HistoryDeleteEvents", 1)

	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.DeleteEventDetailsEncodingDefaultBinary),
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
	node := c.Node(ua.NewNumericNodeID(0, id.ServerNamespaceArray))
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
	if len(resp.Results) != 1 || resp.Results[0] == nil {
		return nil, ua.StatusBadUnknownResponse
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
	if len(resp.Results) != 1 {
		return ua.StatusBad, ua.StatusBadUnknownResponse
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
	node := c.Node(ua.NewNumericNodeID(0, id.ServerServerStatus))
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
	if len(resp.Results) != 1 {
		return ua.StatusBad, ua.StatusBadUnknownResponse
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
