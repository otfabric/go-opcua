// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

const (
	// DefaultRegistrationTimeout is how long a Local Discovery Server keeps a
	// registration that is not renewed (the default of open62541).
	DefaultRegistrationTimeout = 60 * time.Minute

	// maxDiscoveryURLs bounds the discovery URLs of one registration.
	maxDiscoveryURLs = 16

	defaultMaxRegisteredServers = 1024
)

// LDSOption configures the Local Discovery Server role enabled with
// [WithLocalDiscoveryServer].
type LDSOption func(*ldsConfig)

type ldsConfig struct {
	enabled       bool
	timeout       time.Duration
	allowInsecure bool
	skipURICheck  bool
	maxServers    int
	appType       ua.ApplicationType
	callback      func(server *ua.RegisteredServer)
}

// WithLocalDiscoveryServer makes the server a Local Discovery Server (LDS,
// OPC UA Part 12): it accepts RegisterServer and RegisterServer2 and returns
// the registered servers from FindServers, after itself.
//
// A registration is removed when the server unregisters (IsOnline false),
// when its semaphore file disappears, or when it has not been renewed within
// the registration timeout ([LDSRegistrationTimeout], an hour by default).
//
// Registration changes what clients are told about the network, so by default
// it is only accepted on a SecureChannel with message security (Sign or
// SignAndEncrypt), from an application whose certificate carries the
// registered ServerUri. Which certificates may open such a channel is decided
// by [WithClientCertificateTrustList]. See [LDSAllowInsecureRegistration] and
// [LDSSkipServerURICheck] for the lab settings.
//
// Combine it with [WithMulticastDiscovery] for the multicast extension
// (LDS-ME): registered servers are then announced with mDNS.
func WithLocalDiscoveryServer(opts ...LDSOption) Option {
	return func(s *serverConfig) error {
		s.lds.enabled = true
		for _, opt := range opts {
			opt(&s.lds)
		}
		return nil
	}
}

// LDSRegistrationTimeout sets how long a registration lives without being
// renewed. Zero or a negative value disables the expiry: registrations then
// only end by unregistering or through their semaphore file.
func LDSRegistrationTimeout(d time.Duration) LDSOption {
	return func(c *ldsConfig) {
		if d <= 0 {
			d = -1
		}
		c.timeout = d
	}
}

// LDSAllowInsecureRegistration accepts RegisterServer and RegisterServer2 on
// SecureChannels without security (SecurityPolicy None). Anybody who can
// reach the discovery server can then register, replace and remove servers.
// It is meant for tests and closed lab networks.
func LDSAllowInsecureRegistration() LDSOption {
	return func(c *ldsConfig) { c.allowInsecure = true }
}

// LDSSkipServerURICheck accepts a registration on a secured channel whose
// ServerUri is not the application URI of the certificate the channel was
// opened with. Without it an application can only register (and unregister)
// itself.
func LDSSkipServerURICheck() LDSOption {
	return func(c *ldsConfig) { c.skipURICheck = true }
}

// LDSMaxRegisteredServers bounds the number of registrations (1024 by
// default). Further servers are refused with BadResourceUnavailable.
func LDSMaxRegisteredServers(n int) LDSOption {
	return func(c *ldsConfig) { c.maxServers = n }
}

// LDSApplicationType sets the ApplicationType the server reports about
// itself. A discovery server that offers nothing else should use
// ua.ApplicationTypeDiscoveryServer; the default is ua.ApplicationTypeServer.
func LDSApplicationType(t ua.ApplicationType) LDSOption {
	return func(c *ldsConfig) { c.appType = t }
}

// LDSRegistrationCallback sets a function that is called for every accepted
// RegisterServer and RegisterServer2 request, registrations (IsOnline true,
// renewals included) and unregistrations alike. The argument is a copy. The
// function is called from the request handling goroutine and must not block.
func LDSRegistrationCallback(fn func(server *ua.RegisteredServer)) LDSOption {
	return func(c *ldsConfig) { c.callback = fn }
}

// registration is one entry of the registered servers table.
type registration struct {
	server   *ua.RegisteredServer
	lastSeen time.Time
	mdnsName string
	caps     []string
	// announced maps the mDNS instance names announced for the server to a
	// signature of what was announced. It is guarded by discoveryManager.mu.
	announced map[string]string
	// skipped holds the canonical instance names of the server that were
	// not announced because another responder, or another registration,
	// had them. The discovery server takes them over when they become
	// free. It is guarded by discoveryManager.mu.
	skipped map[string]bool
}

// discoveryManager holds the discovery state of a server: the registered
// servers of the LDS role, the mDNS node and ServerOnNetwork table of the
// multicast extension, and the registration loops towards other discovery
// servers.
type discoveryManager struct {
	srv *Server
	now func() time.Time

	// annMu serialises the changes to the registered servers with the mDNS
	// announcements that follow from them. Without it the announcement of
	// one registration and the withdrawal of another one of the same server
	// (a second registration, an unregistration, the expiry) can overtake
	// each other and leave a registered server unannounced. It is taken
	// before mu.
	annMu sync.Mutex

	mu      sync.Mutex
	servers map[string]*registration
	order   []string // ServerUris in registration order

	// multicast extension
	node     *mdns.Node
	hostname string
	records  []*networkRecord
	byName   map[string]*networkRecord // canonical instance name
	nextID   uint32
	resetAt  time.Time
	selfName string

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newDiscoveryManager(s *Server) *discoveryManager {
	return &discoveryManager{
		srv:     s,
		now:     time.Now,
		servers: map[string]*registration{},
		byName:  map[string]*networkRecord{},
	}
}

func (d *discoveryManager) ldsConfig() *ldsConfig { return &d.srv.cfg.lds }

// registrationTimeout returns the configured timeout, or 0 if registrations
// do not expire.
func (c *ldsConfig) registrationTimeout() time.Duration {
	switch {
	case c.timeout < 0:
		return 0
	case c.timeout == 0:
		return DefaultRegistrationTimeout
	}
	return c.timeout
}

// start launches the background work of the discovery manager. It is called
// once the server listens.
func (d *discoveryManager) start(ctx context.Context) error {
	ctx, d.cancel = context.WithCancel(ctx)
	if d.srv.cfg.multicast.enabled {
		if err := d.startMulticast(); err != nil {
			d.cancel()
			return err
		}
	}
	if d.ldsConfig().enabled {
		d.wg.Add(1)
		go d.cleanupLoop(ctx)
	}
	for _, rc := range d.srv.cfg.registrations {
		d.wg.Add(1)
		go d.registrationLoop(ctx, rc)
	}
	return nil
}

// stop ends the background work: the registration loops unregister from
// their discovery servers (bounded by their request timeout) and the mDNS
// node says goodbye.
func (d *discoveryManager) stop() {
	if d.cancel == nil {
		return
	}
	d.cancel()
	d.wg.Wait()
	d.mu.Lock()
	node := d.node
	d.node = nil
	d.mu.Unlock()
	if node != nil {
		_ = node.Close()
	}
	// A server that is not running has no servers on the network: what it
	// knew is out of date as soon as it stops listening. The node is closed
	// first, so that it does not report another server afterwards, and an
	// announcement in flight (annMu) is allowed to finish.
	d.annMu.Lock()
	d.mu.Lock()
	d.records = nil
	d.byName = map[string]*networkRecord{}
	d.mu.Unlock()
	d.annMu.Unlock()
}

func (d *discoveryManager) cleanupLoop(ctx context.Context) {
	defer d.wg.Done()
	// open62541 looks once a second; follow a short timeout more closely.
	interval := time.Second
	if t := d.ldsConfig().registrationTimeout(); t > 0 && t/4 < interval {
		interval = max(t/4, 10*time.Millisecond)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.cleanup(d.now())
		}
	}
}

// cleanup removes the registrations whose semaphore file is gone or that
// were not renewed in time. A registration with a semaphore file lives as
// long as the file does (Part 4 §5.4.5).
func (d *discoveryManager) cleanup(now time.Time) {
	timeout := d.ldsConfig().registrationTimeout()
	d.annMu.Lock()
	defer d.annMu.Unlock()
	d.mu.Lock()
	var gone []*registration
	for _, uri := range slices.Clone(d.order) {
		r := d.servers[uri]
		reason := ""
		if path := r.server.SemaphoreFilePath; path != "" {
			if !fileExists(path) {
				reason = "semaphore file deleted"
			}
		} else if timeout > 0 && now.Sub(r.lastSeen) > timeout {
			reason = "registration timed out"
		}
		if reason == "" {
			continue
		}
		d.removeLocked(uri)
		gone = append(gone, r)
		d.srv.cfg.logger.Info("registered server removed", "server_uri", uri, "reason", reason)
	}
	d.mu.Unlock()
	for _, r := range gone {
		d.withdraw(r)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (d *discoveryManager) removeLocked(uri string) {
	delete(d.servers, uri)
	if i := slices.Index(d.order, uri); i >= 0 {
		d.order = slices.Delete(d.order, i, i+1)
	}
}

// register implements RegisterServer and RegisterServer2 (Part 4 §5.4.5,
// §5.4.6). It returns the service result and one result per discovery
// configuration.
func (d *discoveryManager) register(sc *uasc.SecureChannel, rs *ua.RegisteredServer, configs []*ua.ExtensionObject) (ua.StatusCode, []ua.StatusCode) {
	cfg := d.ldsConfig()
	if !cfg.enabled {
		return ua.StatusBadServiceUnsupported, nil
	}

	// Who may register: only applications that prove their identity with a
	// certificate, unless the operator decided otherwise.
	secured := sc != nil && sc.SecurityMode() != ua.MessageSecurityModeNone &&
		sc.SecurityMode() != ua.MessageSecurityModeInvalid
	if !secured && !cfg.allowInsecure {
		return ua.StatusBadSecurityModeInsufficient, nil
	}
	if rs == nil {
		return ua.StatusBadInvalidArgument, nil
	}
	if rs.ServerURI == "" {
		return ua.StatusBadServerURIInvalid, nil
	}
	if secured && !cfg.skipURICheck && !certificateHasURI(sc.RemoteCertificate(), rs.ServerURI) {
		return ua.StatusBadServerURIInvalid, nil
	}

	// The discovery configurations: one MdnsDiscoveryConfiguration is
	// understood, and only by a discovery server with the multicast
	// extension. Everything else is reported as not supported; the
	// registration itself still takes place.
	var (
		results []ua.StatusCode
		mdnsCfg *ua.MdnsDiscoveryConfiguration
	)
	if len(configs) > 0 {
		results = make([]ua.StatusCode, len(configs))
		for i, eo := range configs {
			results[i] = ua.StatusBadNotSupported
			if eo == nil || mdnsCfg != nil || !d.srv.cfg.multicast.enabled {
				continue
			}
			if c, ok := eo.Value.(*ua.MdnsDiscoveryConfiguration); ok && c != nil {
				mdnsCfg = c
				results[i] = ua.StatusOK
			}
		}
	}

	if !rs.IsOnline {
		d.annMu.Lock()
		d.mu.Lock()
		r := d.servers[rs.ServerURI]
		if r != nil {
			d.removeLocked(rs.ServerURI)
		}
		d.mu.Unlock()
		if r == nil {
			d.annMu.Unlock()
			return ua.StatusBadNothingToDo, results
		}
		d.withdraw(r)
		d.annMu.Unlock()
		d.srv.cfg.logger.Info("server unregistered", "server_uri", rs.ServerURI)
		d.notify(rs)
		return ua.StatusOK, results
	}

	if rs.ServerType == ua.ApplicationTypeClient {
		return ua.StatusBadInvalidArgument, results
	}
	mdnsName := ""
	if mdnsCfg != nil {
		mdnsName = mdnsCfg.MdnsServerName
	}
	if mdnsName == "" {
		for _, n := range rs.ServerNames {
			if n != nil && n.Text != "" {
				mdnsName = n.Text
				break
			}
		}
	}
	if mdnsName == "" {
		return ua.StatusBadServerNameMissing, results
	}
	if len(rs.DiscoveryURLs) == 0 || slices.Contains(rs.DiscoveryURLs, "") {
		return ua.StatusBadDiscoveryURLMissing, results
	}
	if len(rs.DiscoveryURLs) > maxDiscoveryURLs {
		return ua.StatusBadTooManyOperations, results
	}
	if rs.SemaphoreFilePath != "" && !fileExists(rs.SemaphoreFilePath) {
		return ua.StatusBadSemaphoreFileMissing, results
	}

	r := &registration{server: cloneRegisteredServer(rs), lastSeen: d.now(), mdnsName: mdnsName}
	if mdnsCfg != nil {
		r.caps = slices.Clone(mdnsCfg.ServerCapabilities)
	}

	d.annMu.Lock()
	d.mu.Lock()
	old := d.servers[rs.ServerURI]
	if old == nil {
		limit := cfg.maxServers
		if limit <= 0 {
			limit = defaultMaxRegisteredServers
		}
		if len(d.servers) >= limit {
			d.mu.Unlock()
			d.annMu.Unlock()
			return ua.StatusBadResourceUnavailable, results
		}
		d.order = append(d.order, rs.ServerURI)
	}
	d.servers[rs.ServerURI] = r
	d.mu.Unlock()

	if old == nil {
		d.srv.cfg.logger.Info("server registered", "server_uri", rs.ServerURI, "discovery_urls", rs.DiscoveryURLs)
	}
	d.announce(old, r)
	d.annMu.Unlock()
	d.notify(rs)
	return ua.StatusOK, results
}

func (d *discoveryManager) notify(rs *ua.RegisteredServer) {
	if cb := d.ldsConfig().callback; cb != nil {
		cb(cloneRegisteredServer(rs))
	}
}

func cloneRegisteredServer(rs *ua.RegisteredServer) *ua.RegisteredServer {
	c := *rs
	c.DiscoveryURLs = slices.Clone(rs.DiscoveryURLs)
	c.ServerNames = make([]*ua.LocalizedText, 0, len(rs.ServerNames))
	for _, n := range rs.ServerNames {
		if n != nil {
			cp := *n
			c.ServerNames = append(c.ServerNames, &cp)
		}
	}
	return &c
}

// certificateHasURI reports whether the DER encoded certificate names uri as
// (one of) its application URIs.
func certificateHasURI(der []byte, uri string) bool {
	if len(der) == 0 {
		return false
	}
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil {
		return false
	}
	for _, u := range cert.URIs {
		if u != nil && u.String() == uri {
			return true
		}
	}
	return false
}

// RegisteredServers returns a copy of the servers currently registered with
// this Local Discovery Server, in registration order. It is empty unless the
// server was created with [WithLocalDiscoveryServer].
func (s *Server) RegisteredServers() []*ua.RegisteredServer {
	d := s.disc
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*ua.RegisteredServer, 0, len(d.order))
	for _, uri := range d.order {
		out = append(out, cloneRegisteredServer(d.servers[uri].server))
	}
	return out
}

// applicationDescription returns the description of the server itself.
func (s *Server) applicationDescription() *ua.ApplicationDescription {
	appType := ua.ApplicationTypeServer
	if s.cfg.lds.enabled && s.cfg.lds.appType != 0 {
		appType = s.cfg.lds.appType
	}
	return &ua.ApplicationDescription{
		ApplicationURI: s.cfg.applicationURI,
		ProductURI:     "urn:github.com:otfabric:opcua:server",
		ApplicationName: &ua.LocalizedText{
			EncodingMask: ua.LocalizedTextText,
			Text:         s.cfg.applicationName,
		},
		ApplicationType: appType,
		DiscoveryURLs:   slices.Clone(s.URLs()),
	}
}

// findServers implements FindServers (Part 4 §5.4.2): the server itself
// followed by the registered servers, restricted to the requested ServerUris.
func (d *discoveryManager) findServers(req *ua.FindServersRequest) []*ua.ApplicationDescription {
	wanted := func(uri string) bool {
		return len(req.ServerURIs) == 0 || slices.Contains(req.ServerURIs, uri)
	}
	var out []*ua.ApplicationDescription

	self := d.srv.applicationDescription()
	if wanted(self.ApplicationURI) {
		// The endpoint URL tells which of its network addresses the client
		// used. Return the discovery URLs on that host if the host is one of
		// ours, and all of them (the default) if it is not recognised.
		self.DiscoveryURLs = urlsForHost(self.DiscoveryURLs, req.EndpointURL)
		out = append(out, self)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, uri := range d.order {
		if !wanted(uri) {
			continue
		}
		rs := d.servers[uri].server
		out = append(out, &ua.ApplicationDescription{
			ApplicationURI:   rs.ServerURI,
			ProductURI:       rs.ProductURI,
			ApplicationName:  localizedName(rs.ServerNames, req.LocaleIDs),
			ApplicationType:  rs.ServerType,
			GatewayServerURI: rs.GatewayServerURI,
			DiscoveryURLs:    slices.Clone(rs.DiscoveryURLs),
		})
	}
	return out
}

// localizedName picks the server name for the first requested locale the
// server has a name in, and its first name otherwise.
func localizedName(names []*ua.LocalizedText, locales []string) *ua.LocalizedText {
	if len(names) == 0 {
		return &ua.LocalizedText{}
	}
	for _, locale := range locales {
		for _, n := range names {
			if strings.EqualFold(n.Locale, locale) {
				cp := *n
				return &cp
			}
		}
	}
	cp := *names[0]
	return &cp
}

// urlsForHost returns the URLs whose host is the host of endpointURL, or all
// URLs if there is none.
func urlsForHost(urls []string, endpointURL string) []string {
	host := urlHost(endpointURL)
	if host == "" {
		return urls
	}
	var match []string
	for _, u := range urls {
		if strings.EqualFold(urlHost(u), host) {
			match = append(match, u)
		}
	}
	if len(match) == 0 {
		return urls
	}
	return match
}

// urlHost returns the host name of an opc.tcp URL without the port, or "".
func urlHost(raw string) string {
	host, _, _ := splitDiscoveryURL(raw)
	return host
}

// splitDiscoveryURL splits an opc.tcp URL into host, port and path. The port
// defaults to 4840. The host is empty if the URL cannot be used.
func splitDiscoveryURL(raw string) (host string, port uint16, path string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || !strings.EqualFold(u.Scheme, "opc.tcp") {
		return "", 0, ""
	}
	port = 4840
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return "", 0, ""
		}
		port = uint16(n)
	}
	return u.Hostname(), port, u.Path
}
