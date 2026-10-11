// SPDX-License-Identifier: MIT

package server

import (
	"context"
	stderrors "errors"
	"fmt"
	"slices"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

const (
	// DefaultRegisterInterval is how often a server renews its registration
	// with a discovery server (Part 4 §5.4.5 recommends 10 minutes at most).
	DefaultRegisterInterval = 10 * time.Minute

	defaultRegisterRequestTimeout = 10 * time.Second
	defaultRegisterBackoffMin     = time.Second
	defaultRegisterBackoffMax     = time.Minute
)

// RegistrationOption configures the registration with a discovery server
// enabled with [WithDiscoveryRegistration].
type RegistrationOption func(*registrationConfig)

type registrationConfig struct {
	url            string
	interval       time.Duration
	requestTimeout time.Duration
	backoffMin     time.Duration
	backoffMax     time.Duration
	insecure       bool
	policy         string
	mode           ua.MessageSecurityMode
	semaphoreFile  string
	discoveryURLs  []string
	mdnsName       string
	caps           []string
	validator      func(certDER []byte) error
	handler        func(RegistrationEvent)
}

// RegistrationEvent reports the outcome of one attempt to register with, or
// unregister from, a discovery server.
type RegistrationEvent struct {
	// DiscoveryServerURL is the URL given to [WithDiscoveryRegistration].
	DiscoveryServerURL string
	// Service is the service that was used last: "RegisterServer2" or
	// "RegisterServer".
	Service string
	// Online is true for a registration and false for the unregistration on
	// shutdown.
	Online bool
	// SecurityPolicyURI and SecurityMode are the security of the
	// SecureChannel that was used.
	SecurityPolicyURI string
	SecurityMode      ua.MessageSecurityMode
	// ConfigurationResults are the results the discovery server returned
	// for the discovery configurations of a RegisterServer2 request.
	ConfigurationResults []ua.StatusCode
	// Err is nil if the discovery server accepted the request.
	Err error
}

// WithDiscoveryRegistration registers the server with the discovery server
// at discoveryServerURL, e.g. the Local Discovery Server of its machine at
// "opc.tcp://localhost:4840", and keeps the registration alive.
//
// The registration runs in the background from [Server.Start] on: the server
// calls RegisterServer2 (with its mDNS server name and capabilities) and
// falls back to RegisterServer if the discovery server does not know that
// service; it repeats the call every [RegisterInterval] so that the
// registration does not expire, and it retries with an exponential back-off
// while the discovery server cannot be reached. Neither Start nor
// [Server.Close] wait for a discovery server that is down. On Close the
// server unregisters (IsOnline false).
//
// The SecureChannel to the discovery server is secured: the server picks the
// most secure endpoint the discovery server offers that one of its own
// certificates fits ([Certificate] and [PrivateKey], or [ApplicationIdentity]
// for the ECC policies) and uses that certificate, whose application URI is
// the ServerUri it registers. See [RegisterSecurity] and [RegisterInsecure].
//
// The option can be given several times to register with several discovery
// servers.
func WithDiscoveryRegistration(discoveryServerURL string, opts ...RegistrationOption) Option {
	return func(s *serverConfig) error {
		if _, _, err := uacp.ParseEndpoint(discoveryServerURL); err != nil {
			return fmt.Errorf("server: discovery server URL %q: %w", discoveryServerURL, err)
		}
		rc := &registrationConfig{url: discoveryServerURL}
		for _, opt := range opts {
			opt(rc)
		}
		if rc.policy != "" {
			if !slices.Contains(uapolicy.SupportedPolicies(), rc.policy) {
				return fmt.Errorf("server: unsupported security policy %q for the discovery registration", rc.policy)
			}
			if (rc.policy == ua.SecurityPolicyURINone) != (rc.mode == ua.MessageSecurityModeNone) {
				return fmt.Errorf("server: security policy %q cannot be used with mode %v for the discovery registration", rc.policy, rc.mode)
			}
		}
		s.registrations = append(s.registrations, rc)
		return nil
	}
}

// RegisterInterval sets how often the registration is renewed. The default
// is [DefaultRegisterInterval]. Choose a value well below the registration
// timeout of the discovery server.
func RegisterInterval(d time.Duration) RegistrationOption {
	return func(c *registrationConfig) { c.interval = d }
}

// RegisterRequestTimeout bounds one registration attempt, connecting
// included, and the unregistration on Close. The default is 10 seconds.
func RegisterRequestTimeout(d time.Duration) RegistrationOption {
	return func(c *registrationConfig) { c.requestTimeout = d }
}

// RegisterBackoff sets the delay before a failed registration is tried
// again: it starts at minDelay and doubles up to maxDelay. The defaults are
// one second and one minute.
func RegisterBackoff(minDelay, maxDelay time.Duration) RegistrationOption {
	return func(c *registrationConfig) { c.backoffMin, c.backoffMax = minDelay, maxDelay }
}

// RegisterInsecure allows the registration over a SecureChannel without
// security. A secured endpoint is still preferred if the server has a
// certificate and the discovery server offers one. Without this option a
// registration that cannot be secured fails.
func RegisterInsecure() RegistrationOption {
	return func(c *registrationConfig) { c.insecure = true }
}

// RegisterSecurity pins the security policy and mode of the SecureChannel to
// the discovery server instead of picking the most secure endpoint. policy is
// a policy URI or its short name ("Basic256Sha256").
func RegisterSecurity(policy string, mode ua.MessageSecurityMode) RegistrationOption {
	return func(c *registrationConfig) {
		c.policy, c.mode = ua.FormatSecurityPolicyURI(policy), mode
	}
}

// RegisterSemaphoreFile sets the semaphore file path of the registration
// (Part 4 §5.4.5). The discovery server, which must be on the same machine,
// keeps the registration for as long as the file exists; the server is
// responsible for creating and deleting it.
func RegisterSemaphoreFile(path string) RegistrationOption {
	return func(c *registrationConfig) { c.semaphoreFile = path }
}

// RegisterDiscoveryURLs sets the discovery URLs to register instead of the
// server's endpoint URLs, e.g. the address under which the server is
// reachable from outside a container.
func RegisterDiscoveryURLs(urls ...string) RegistrationOption {
	return func(c *registrationConfig) { c.discoveryURLs = slices.Clone(urls) }
}

// RegisterMdnsServerName sets the mDNS server name sent with RegisterServer2
// (MdnsDiscoveryConfiguration). The default is the name set with
// [MulticastServerName], or the application name.
func RegisterMdnsServerName(name string) RegistrationOption {
	return func(c *registrationConfig) { c.mdnsName = name }
}

// RegisterServerCapabilities sets the capability identifiers sent with
// RegisterServer2 (MdnsDiscoveryConfiguration). The default are the
// capabilities set with [MulticastCapabilities], or "NA".
func RegisterServerCapabilities(caps ...string) RegistrationOption {
	return func(c *registrationConfig) { c.caps = slices.Clone(caps) }
}

// RegisterCertificateValidator sets a function that decides whether the
// certificate of the discovery server (DER encoded) is trusted. It is called
// before a secured SecureChannel is opened; an error aborts the attempt. By
// default every certificate is accepted.
func RegisterCertificateValidator(fn func(certDER []byte) error) RegistrationOption {
	return func(c *registrationConfig) { c.validator = fn }
}

// RegisterEventHandler sets a function that is called after every attempt to
// register or unregister. It is called from the registration goroutine and
// must not block.
func RegisterEventHandler(fn func(RegistrationEvent)) RegistrationOption {
	return func(c *registrationConfig) { c.handler = fn }
}

func (c *registrationConfig) timeout() time.Duration {
	if c.requestTimeout > 0 {
		return c.requestTimeout
	}
	return defaultRegisterRequestTimeout
}

// checkRegistrations validates what could not be checked when the options
// were applied, because it depends on other options.
func (s *Server) checkRegistrations() error {
	for _, rc := range s.cfg.registrations {
		secure := s.cfg.canSecure()
		if rc.policy != "" && rc.policy != ua.SecurityPolicyURINone {
			// The certificate has to fit the policy: an RSA one for the RSA
			// policies, an ECC one of the right key type for the ECC ones.
			if _, key, ok := s.cfg.identityFor(rc.policy); !ok || key == nil {
				return fmt.Errorf("server: registration with %s over %s needs a certificate and private key", rc.url, rc.policy)
			}
		}
		if !secure && !rc.insecure && rc.policy == "" {
			return fmt.Errorf("server: registration with %s needs a certificate and private key (or RegisterInsecure)", rc.url)
		}
		if rc.policy == ua.SecurityPolicyURINone && !rc.insecure {
			return fmt.Errorf("server: registration with %s over SecurityPolicy None needs RegisterInsecure", rc.url)
		}
	}
	return nil
}

// registeredServer builds the description the server registers.
func (s *Server) registeredServer(rc *registrationConfig, online bool) *ua.RegisteredServer {
	app := s.applicationDescription()
	urls := rc.discoveryURLs
	if len(urls) == 0 {
		urls = app.DiscoveryURLs
	}
	return &ua.RegisteredServer{
		ServerURI:         app.ApplicationURI,
		ProductURI:        app.ProductURI,
		ServerNames:       []*ua.LocalizedText{app.ApplicationName},
		ServerType:        app.ApplicationType,
		GatewayServerURI:  app.GatewayServerURI,
		DiscoveryURLs:     slices.Clone(urls),
		SemaphoreFilePath: rc.semaphoreFile,
		IsOnline:          online,
	}
}

func (s *Server) mdnsConfiguration(rc *registrationConfig) *ua.MdnsDiscoveryConfiguration {
	name := rc.mdnsName
	if name == "" {
		name = s.cfg.multicast.serverName
	}
	if name == "" {
		name = s.cfg.applicationName
	}
	caps := rc.caps
	if len(caps) == 0 {
		caps = s.cfg.multicast.caps
	}
	if len(caps) == 0 {
		caps = []string{"NA"}
	}
	return &ua.MdnsDiscoveryConfiguration{MdnsServerName: name, ServerCapabilities: slices.Clone(caps)}
}

// registrationLoop keeps the server registered with one discovery server
// until ctx is done, and then unregisters.
func (d *discoveryManager) registrationLoop(ctx context.Context, rc *registrationConfig) {
	defer d.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logPanic(d.srv.cfg.logger, "registering with a discovery server", r)
		}
	}()
	log := d.srv.cfg.logger

	interval := rc.interval
	if interval <= 0 {
		interval = DefaultRegisterInterval
	}
	backoffMin, backoffMax := rc.backoffMin, rc.backoffMax
	if backoffMin <= 0 {
		backoffMin = defaultRegisterBackoffMin
	}
	if backoffMax < backoffMin {
		backoffMax = max(defaultRegisterBackoffMax, backoffMin)
	}

	st := &registrationState{}
	backoff := backoffMin
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			// Unregister if the discovery server has the registration, or
			// may have it: a request whose response was lost may well have
			// been accepted.
			if st.registered || st.sent {
				// The server's context is gone; the unregistration gets
				// its own, bounded one.
				uctx, cancel := context.WithTimeout(context.Background(), rc.timeout())
				ev := d.registerOnce(uctx, rc, st, false)
				cancel()
				// A discovery server that never got the request whose
				// outcome was unknown has nothing to remove.
				nothing := !st.registered && stderrors.Is(ev.Err, ua.StatusBadNothingToDo)
				if ev.Err != nil && !nothing {
					log.Warn("unregistering from the discovery server failed", "url", rc.url, "error", ev.Err)
				}
				d.emit(rc, ev)
			}
			return
		case <-timer.C:
		}

		actx, cancel := context.WithTimeout(ctx, rc.timeout())
		ev := d.registerOnce(actx, rc, st, true)
		cancel()
		if ctx.Err() != nil && ev.Err != nil {
			// Shutting down: the attempt was cut short. If the request was
			// already on its way the discovery server may have registered
			// the server (st.sent), so it is unregistered to be sure.
			continue
		}
		wait := interval
		if ev.Err != nil {
			log.Warn("registering with the discovery server failed", "url", rc.url, "error", ev.Err, "retry_in", backoff)
			wait = backoff
			backoff = min(backoff*2, backoffMax)
		} else {
			if !st.registered {
				log.Info("registered with the discovery server", "url", rc.url, "service", ev.Service)
			}
			st.registered = true
			backoff = backoffMin
		}
		d.emit(rc, ev)
		timer.Reset(wait)
	}
}

func (d *discoveryManager) emit(rc *registrationConfig, ev RegistrationEvent) {
	if rc.handler != nil {
		rc.handler(ev)
	}
}

// registrationState is what a registration loop remembers between attempts.
type registrationState struct {
	// registered says that the discovery server accepted a registration.
	registered bool
	// sent says that a registration request was sent on an open channel and
	// that it is not known what became of it: the discovery server did not
	// answer it, so it may or may not have registered the server.
	sent bool
	// legacy says that the discovery server does not implement
	// RegisterServer2, so RegisterServer is used.
	legacy bool
}

// registerOnce opens a SecureChannel to the discovery server, registers or
// unregisters, and closes the channel again.
func (d *discoveryManager) registerOnce(ctx context.Context, rc *registrationConfig, st *registrationState, online bool) RegistrationEvent {
	s := d.srv
	ev := RegistrationEvent{DiscoveryServerURL: rc.url, Online: online, Service: "RegisterServer2"}
	if st.legacy {
		ev.Service = "RegisterServer"
	}

	cfg, err := s.registrationChannelConfig(ctx, rc)
	if err != nil {
		ev.Err = err
		return ev
	}
	ev.SecurityPolicyURI, ev.SecurityMode = cfg.SecurityPolicyURI, cfg.SecurityMode
	sc, err := openDiscoveryChannel(ctx, rc.url, cfg)
	if err != nil {
		ev.Err = err
		return ev
	}
	defer func() { _ = sc.Close() }()

	// A request that is on its way is not cut short when the server shuts
	// down: the discovery server processes it all the same, possibly after
	// the unregistration that follows on another channel, and the closed
	// server would stay registered. The wait for the response ends with the
	// deadline of the attempt, shutdown or not.
	if err := ctx.Err(); err != nil {
		ev.Err = err
		return ev
	}
	if deadline, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.WithoutCancel(ctx), deadline)
		defer cancel()
	}

	server := s.registeredServer(rc, online)
	st.sent = st.sent || online
	// An answer of the discovery server, whatever it says, settles the
	// request: accepted (the caller sets st.registered) or refused. A
	// renewal that is refused leaves an earlier registration in place, and
	// with it st.registered.
	answered := func() {
		if online {
			st.sent = false
		}
	}
	if !st.legacy {
		req := &ua.RegisterServer2Request{
			Server:                 server,
			DiscoveryConfiguration: []*ua.ExtensionObject{ua.NewExtensionObject(s.mdnsConfiguration(rc))},
		}
		var resp *ua.RegisterServer2Response
		err := sc.SendRequestWithTimeout(ctx, req, nil, rc.timeout(), func(r ua.Response) error {
			answered()
			return assignResponse(r, &resp)
		})
		if err == nil {
			ev.ConfigurationResults = resp.ConfigurationResults
			return ev
		}
		if !registerServer2Unsupported(err) {
			ev.Err = err
			return ev
		}
		// An older discovery server: use RegisterServer from now on. The
		// outcome of that second request is open again.
		st.sent = st.sent || online
		s.cfg.logger.Info("discovery server does not support RegisterServer2, using RegisterServer", "url", rc.url, "error", err)
		st.legacy = true
		ev.Service = "RegisterServer"
	}

	var resp *ua.RegisterServerResponse
	ev.Err = sc.SendRequestWithTimeout(ctx, &ua.RegisterServerRequest{Server: server}, nil, rc.timeout(), func(r ua.Response) error {
		answered()
		return assignResponse(r, &resp)
	})
	return ev
}

// registerServer2Unsupported reports whether an error means that the
// discovery server does not offer RegisterServer2.
func registerServer2Unsupported(err error) bool {
	return stderrors.Is(err, ua.StatusBadServiceUnsupported) ||
		stderrors.Is(err, ua.StatusBadNotSupported) ||
		stderrors.Is(err, ua.StatusBadNotImplemented)
}

// assignResponse stores a response of the expected type, or turns a fault
// into its status code.
func assignResponse[T any](r ua.Response, dst **T) error {
	if v, ok := any(r).(*T); ok && v != nil {
		*dst = v
		if hdr := r.Header(); hdr != nil && hdr.ServiceResult != ua.StatusOK {
			return hdr.ServiceResult
		}
		return nil
	}
	if r != nil {
		if hdr := r.Header(); hdr != nil && hdr.ServiceResult != ua.StatusOK {
			return hdr.ServiceResult
		}
	}
	return fmt.Errorf("server: unexpected response %T from the discovery server", r)
}

// registrationChannelConfig decides how the SecureChannel to the discovery
// server is secured and returns its configuration.
func (s *Server) registrationChannelConfig(ctx context.Context, rc *registrationConfig) (*uasc.Config, error) {
	cfg := &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    rc.timeout(),
		Logger:            s.cfg.logger,
	}
	canSecure := s.cfg.canSecure()
	if rc.policy == ua.SecurityPolicyURINone || (!canSecure && rc.insecure) {
		return cfg, nil
	}

	// Ask the discovery server for its endpoints (always possible without
	// security) and pick one.
	endpoints, err := discoveryEndpoints(ctx, rc.url, cfg)
	if err != nil {
		return nil, fmt.Errorf("get endpoints of the discovery server: %w", err)
	}
	var best *ua.EndpointDescription
	for _, ep := range endpoints {
		if ep == nil || ep.SecurityMode == ua.MessageSecurityModeNone || ep.SecurityPolicyURI == ua.SecurityPolicyURINone ||
			len(ep.ServerCertificate) == 0 || !slices.Contains(uapolicy.SupportedPolicies(), ep.SecurityPolicyURI) {
			continue
		}
		if rc.policy != "" && (ep.SecurityPolicyURI != rc.policy || ep.SecurityMode != rc.mode) {
			continue
		}
		// Only what this server has a certificate for: an endpoint of an ECC
		// policy is of no use to a server with an RSA certificate, and the
		// other way round.
		if _, key, ok := s.cfg.identityFor(ep.SecurityPolicyURI); !ok || key == nil {
			continue
		}
		// The most secure endpoint: the highest security level and, among
		// equals, encryption over signing only.
		if best == nil || ep.SecurityLevel > best.SecurityLevel ||
			(ep.SecurityLevel == best.SecurityLevel &&
				ep.SecurityMode == ua.MessageSecurityModeSignAndEncrypt &&
				best.SecurityMode != ua.MessageSecurityModeSignAndEncrypt) {
			best = ep
		}
	}
	if best == nil {
		if rc.insecure && rc.policy == "" {
			return cfg, nil
		}
		return nil, fmt.Errorf("the discovery server offers no usable secured endpoint: %w", ua.StatusBadSecurityModeRejected)
	}
	if rc.validator != nil {
		if err := rc.validator(best.ServerCertificate); err != nil {
			return nil, fmt.Errorf("certificate of the discovery server rejected: %w", err)
		}
	}
	secured := *cfg
	secured.SecurityPolicyURI = best.SecurityPolicyURI
	secured.SecurityMode = best.SecurityMode
	// The certificate that fits the policy of the endpoint.
	secured.Certificate, secured.LocalPrivateKey, _ = s.cfg.identityFor(best.SecurityPolicyURI)
	secured.RemoteCertificate = best.ServerCertificate
	secured.Thumbprint = uapolicy.Thumbprint(best.ServerCertificate)
	return &secured, nil
}

// discoveryEndpoints calls GetEndpoints on a discovery server.
func discoveryEndpoints(ctx context.Context, url string, cfg *uasc.Config) ([]*ua.EndpointDescription, error) {
	sc, err := openDiscoveryChannel(ctx, url, cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sc.Close() }()
	var resp *ua.GetEndpointsResponse
	err = sc.SendRequestWithTimeout(ctx, &ua.GetEndpointsRequest{EndpointURL: url}, nil, cfg.RequestTimeout, func(r ua.Response) error {
		return assignResponse(r, &resp)
	})
	if err != nil {
		return nil, err
	}
	return resp.Endpoints, nil
}

// openDiscoveryChannel connects to url and opens a SecureChannel. The caller
// closes the channel, which also closes the connection.
func openDiscoveryChannel(ctx context.Context, url string, cfg *uasc.Config) (*uasc.SecureChannel, error) {
	conn, err := (&uacp.Dialer{}).Dial(ctx, url)
	if err != nil {
		return nil, err
	}
	// The channel reports asynchronous errors here; nobody reads them, so
	// the buffer keeps the channel's goroutine from blocking.
	errCh := make(chan error, 8)
	c := *cfg
	// The deadline of ctx bounds the whole attempt, of which the connection
	// has already used a part: OpenSecureChannel gets what is left of it, not
	// a full request timeout of its own.
	if deadline, ok := ctx.Deadline(); ok {
		left := time.Until(deadline)
		if left <= 0 {
			_ = conn.Close()
			return nil, context.DeadlineExceeded
		}
		if c.RequestTimeout <= 0 || left < c.RequestTimeout {
			c.RequestTimeout = left
		}
	}
	sc, err := uasc.NewSecureChannel(url, conn, &c, errCh)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// OpenSecureChannel is not cut short when the server shuts down: the
	// channel's dispatcher may be processing the response at that very
	// moment, and uasc does not support abandoning an open in flight. The
	// exchange is bounded by the request timeout of the channel instead,
	// which ends with the deadline of ctx.
	if err := sc.Open(context.WithoutCancel(ctx)); err != nil {
		_ = sc.Close()
		_ = conn.Close()
		return nil, err
	}
	return sc, nil
}
