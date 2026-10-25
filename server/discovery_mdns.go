// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/ua"
)

const (
	// opcuaServiceType is the DNS-SD service type of OPC UA servers that
	// speak opc.tcp (Part 12 Annex C).
	opcuaServiceType = "_opcua-tcp._tcp"

	defaultMaxServersOnNetwork = 1024

	// maxInstanceLabel is the longest DNS label, and therefore the longest
	// mDNS server name.
	maxInstanceLabel = 63
)

// MulticastOption configures the multicast discovery enabled with
// [WithMulticastDiscovery].
type MulticastOption func(*multicastConfig)

type multicastConfig struct {
	enabled    bool
	serverName string
	caps       []string
	interfaces []string
	hostname   string
	ipv4Only   bool
	maxRecords int

	// conns replaces the real sockets. It is set through internal/testhook.
	conns func() ([]mdns.PacketConn, error)
	// hostTTL and otherTTL replace the TTLs of the announced records. They
	// are set through internal/testhook.
	hostTTL, otherTTL uint32
}

// WithMulticastDiscovery enables multicast discovery (the multicast
// extension of OPC UA Part 12, mDNS and DNS-SD): the server announces itself
// as a "_opcua-tcp._tcp" service on the local network, keeps a table of the
// OPC UA servers announced by others and returns it from
// FindServersOnNetwork. A server that is also a Local Discovery Server
// ([WithLocalDiscoveryServer]) announces the servers registered with it as
// well.
//
// The mDNS implementation is built in and needs no system service. It uses
// UDP port 5353 on every multicast capable interface (see
// [MulticastInterfaces]) and shares the port with a system responder such as
// Avahi or Bonjour. [Server.Start] fails if no interface can be used.
//
// Multicast discovery tells everybody on the local network segment that the
// server exists, where it is and what it can do, and it trusts what others
// announce: see docs/security.md.
func WithMulticastDiscovery(opts ...MulticastOption) Option {
	return func(s *serverConfig) error {
		s.multicast.enabled = true
		for _, opt := range opts {
			opt(&s.multicast)
		}
		return nil
	}
}

// MulticastServerName sets the mDNS server name. The service instance is
// announced as "<name>-<hostname>", like open62541 does. The default is the
// application name ([ServerName]).
func MulticastServerName(name string) MulticastOption {
	return func(c *multicastConfig) { c.serverName = name }
}

// MulticastCapabilities sets the capability identifiers announced in the
// "caps" key of the TXT record, e.g. "DA", "HD", "LDS" (Part 12 Annex D).
// The default is "LDS" for a Local Discovery Server and "NA" otherwise.
func MulticastCapabilities(caps ...string) MulticastOption {
	return func(c *multicastConfig) { c.caps = slices.Clone(caps) }
}

// MulticastInterfaces restricts mDNS to the named network interfaces, e.g.
// "eth0". By default every interface that is up and multicast capable is
// used, except loopback and point-to-point interfaces.
func MulticastInterfaces(names ...string) MulticastOption {
	return func(c *multicastConfig) { c.interfaces = slices.Clone(names) }
}

// MulticastHostname sets the host name the server is announced under
// ("<hostname>.local"). The default is the host name of the machine.
func MulticastHostname(hostname string) MulticastOption {
	return func(c *multicastConfig) { c.hostname = hostname }
}

// MulticastIPv4Only keeps mDNS off IPv6 (ff02::fb).
func MulticastIPv4Only() MulticastOption {
	return func(c *multicastConfig) { c.ipv4Only = true }
}

// MulticastMaxServersOnNetwork bounds the number of servers discovered with
// mDNS that are kept in the ServerOnNetwork table (1024 by default). Servers
// announced beyond it are ignored until others disappear.
func MulticastMaxServersOnNetwork(n int) MulticastOption {
	return func(c *multicastConfig) { c.maxRecords = n }
}

// networkRecord is one row of the ServerOnNetwork table.
type networkRecord struct {
	rec *ua.ServerOnNetwork
	key string
	// owner is the ServerUri of the registered server the record was created
	// for, selfOwner for the server itself and empty for a server that was
	// discovered with mDNS.
	owner string
}

const selfOwner = "\x00self"

func (d *discoveryManager) startMulticast() error {
	mc := &d.srv.cfg.multicast
	log := d.srv.cfg.logger

	hostname := mc.hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	hostname = hostLabel(hostname)
	if hostname == "" {
		return fmt.Errorf("server: multicast discovery: cannot determine a host name, set MulticastHostname")
	}

	var conns []mdns.PacketConn
	if mc.conns != nil {
		var err error
		if conns, err = mc.conns(); err != nil {
			return fmt.Errorf("server: multicast discovery: %w", err)
		}
	} else {
		opts := mdns.ListenOptions{DisableIPv6: mc.ipv4Only}
		for _, name := range mc.interfaces {
			ifi, err := net.InterfaceByName(name)
			if err != nil {
				return fmt.Errorf("server: multicast discovery: interface %q: %w", name, err)
			}
			opts.Interfaces = append(opts.Interfaces, *ifi)
		}
		var (
			skipped []error
			err     error
		)
		if conns, skipped, err = mdns.Listen(opts); err != nil {
			return fmt.Errorf("server: multicast discovery: %w", err)
		}
		for _, e := range skipped {
			log.Warn("multicast discovery: interface not used", "error", e)
		}
	}

	limit := mc.maxRecords
	if limit <= 0 {
		limit = defaultMaxServersOnNetwork
	}
	node, err := mdns.New(mdns.Config{Conns: conns, Logger: log, MaxInstances: limit, HostTTL: mc.hostTTL, OtherTTL: mc.otherTTL})
	if err != nil {
		return fmt.Errorf("server: multicast discovery: %w", err)
	}

	d.mu.Lock()
	d.node = node
	d.hostname = hostname
	d.nextID = 0
	d.resetAt = d.now()
	d.records = nil
	d.byName = map[string]*networkRecord{}
	d.mu.Unlock()

	// Announce the server itself.
	name := mc.serverName
	if name == "" {
		name = d.srv.cfg.applicationName
	}
	caps := mc.caps
	if len(caps) == 0 {
		caps = []string{"NA"}
		if d.srv.cfg.lds.enabled {
			caps = []string{"LDS"}
		}
	}
	port, path := uint16(d.srv.Port()), ""
	if urls := d.srv.URLs(); len(urls) > 0 {
		if _, p, pa := splitDiscoveryURL(urls[0]); p != 0 {
			port, path = p, pa
		}
	}
	instance := instanceName(name, hostname)
	d.selfName = instance
	svc := mdns.Service{
		Instance: instance, Type: opcuaServiceType,
		Host: hostname + "." + mdns.Domain, Port: port,
		Text: txtRecord(path, caps), LocalHost: true,
	}
	if err := node.Register(svc); err != nil {
		_ = node.Close()
		return fmt.Errorf("server: multicast discovery: announce %q: %w", instance, err)
	}
	d.mu.Lock()
	d.putRecordLocked(instance, selfOwner, "opc.tcp://"+net.JoinHostPort(hostname, strconv.Itoa(int(port)))+path, caps)
	d.mu.Unlock()
	log.Info("multicast discovery started", "instance", instance, "host", svc.Host, "port", port)

	return node.Browse(opcuaServiceType, d.onNetworkEvent)
}

// hostLabel reduces a host name to its first label ("press7.example.com" and
// "press7.local" become "press7").
func hostLabel(host string) string {
	host = strings.TrimSpace(host)
	if i := strings.IndexByte(host, '.'); i >= 0 {
		host = host[:i]
	}
	if len(host) > maxInstanceLabel || !validHostName(host) {
		return ""
	}
	return host
}

// validHostName reports whether s only has the characters of a DNS host name.
func validHostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return !strings.HasPrefix(s, ".") && !strings.Contains(s, "..")
}

// instanceName builds the mDNS service instance name "<name>-<host>" the way
// open62541 does: the host part gives way if both do not fit the 63 bytes of
// a DNS label.
func instanceName(name, host string) string {
	name = truncateUTF8(name, maxInstanceLabel)
	if room := maxInstanceLabel - len(name) - 1; room > 0 && host != "" {
		return name + "-" + truncateUTF8(host, room)
	}
	return name
}

func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// txtRecord builds the TXT strings of Part 12 Annex C: the path of the
// discovery URL and the capabilities.
func txtRecord(path string, caps []string) []string {
	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(caps) == 0 {
		caps = []string{"NA"}
	}
	c := "caps=" + strings.Join(caps, ",")
	for len(c) > 255 && len(caps) > 1 {
		caps = caps[:len(caps)-1]
		c = "caps=" + strings.Join(caps, ",")
	}
	out := []string{truncateUTF8("path="+path, 255), truncateUTF8(c, 255)}
	return out
}

// putRecordLocked adds or updates a row of the ServerOnNetwork table. A new
// row gets the next record id; an updated row keeps its id.
func (d *discoveryManager) putRecordLocked(name, owner, discoveryURL string, caps []string) {
	key := strings.ToLower(name)
	if r := d.byName[key]; r != nil {
		// A discovered server cannot take over a row the discovery server
		// itself vouches for.
		if r.owner != "" && owner == "" {
			return
		}
		r.owner = owner
		r.rec.DiscoveryURL = discoveryURL
		r.rec.ServerCapabilities = slices.Clone(caps)
		return
	}
	r := &networkRecord{key: key, owner: owner, rec: &ua.ServerOnNetwork{
		RecordID:           d.nextID,
		ServerName:         name,
		DiscoveryURL:       discoveryURL,
		ServerCapabilities: slices.Clone(caps),
	}}
	d.nextID++
	if d.nextID == 0 {
		// The counter wrapped around: clients must start over.
		d.resetAt = d.now()
	}
	d.byName[key] = r
	d.records = append(d.records, r)
}

// dropRecordLocked removes the row of an instance if it belongs to owner. It
// reports whether it did.
func (d *discoveryManager) dropRecordLocked(name, owner string) bool {
	key := strings.ToLower(name)
	r := d.byName[key]
	if r == nil || r.owner != owner {
		return false
	}
	delete(d.byName, key)
	if i := slices.Index(d.records, r); i >= 0 {
		d.records = slices.Delete(d.records, i, i+1)
	}
	return true
}

// heirLocked returns the registration, other than the given owner, that
// wants the instance name but left it to the responder or registration
// that had it, or nil.
func (d *discoveryManager) heirLocked(name, owner string) *registration {
	key := strings.ToLower(name)
	for _, uri := range d.order {
		if r := d.servers[uri]; uri != owner && r.skipped[key] {
			return r
		}
	}
	return nil
}

// handOver announces a registered server under an instance name that has
// just become free, if one was waiting for it. Without it the server would
// stay unannounced, and without a row in the ServerOnNetwork table, until
// its next renewal changed something: a renewal that changes nothing is not
// announced again. It is called with annMu held.
func (d *discoveryManager) handOver(name, owner string) {
	d.mu.Lock()
	r := d.heirLocked(name, owner)
	d.mu.Unlock()
	if r != nil {
		d.announce(r, r)
	}
}

// onNetworkEvent applies what the mDNS browser found to the table.
func (d *discoveryManager) onNetworkEvent(e mdns.Event) {
	if e.Removed {
		// Another responder withdrew an instance, or its records expired.
		// A registered server that wants the name takes it over.
		d.annMu.Lock()
		defer d.annMu.Unlock()
		d.mu.Lock()
		dropped := d.dropRecordLocked(e.Instance.Name, "")
		d.mu.Unlock()
		if dropped {
			d.handOver(e.Instance.Name, "")
		}
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	discoveryURL, caps, ok := discoveredServer(e.Instance)
	if !ok {
		d.srv.cfg.logger.Debug("multicast discovery: ignored an announcement that is not a usable OPC UA server",
			"instance", e.Instance.Name, "host", e.Instance.Host)
		return
	}
	d.putRecordLocked(e.Instance.Name, "", discoveryURL, caps)
}

// discoveredServer turns a DNS-SD instance into a discovery URL and a list
// of capabilities. Everything in the instance comes from the network, so it
// is checked before it is handed to clients.
func discoveredServer(in mdns.Instance) (discoveryURL string, caps []string, ok bool) {
	host := strings.TrimSuffix(in.Host, ".")
	if in.Port == 0 || !validHostName(host) || !utf8.ValidString(in.Name) || in.Name == "" {
		return "", nil, false
	}
	path := ""
	for _, kv := range in.Text {
		key, value, _ := strings.Cut(kv, "=")
		if !utf8.ValidString(value) || strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			continue
		}
		switch strings.ToLower(key) {
		case "path":
			if len(value) > 1 { // "/" stands for no path
				path = value
				if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
			}
		case "caps":
			for _, c := range strings.Split(value, ",") {
				if c = strings.TrimSpace(c); c != "" {
					caps = append(caps, c)
				}
			}
		}
	}
	return "opc.tcp://" + net.JoinHostPort(host, strconv.Itoa(int(in.Port))) + path, caps, true
}

// announce publishes the mDNS records of a registered server: one service
// instance per discovery URL (Part 12 Annex C), and withdraws the instances
// of its previous registration that are no longer wanted.
func (d *discoveryManager) announce(old, r *registration) {
	d.mu.Lock()
	node := d.node
	hostname := d.hostname
	d.mu.Unlock()
	if node == nil {
		return
	}
	uri := r.server.ServerURI
	caps := r.caps
	if len(caps) == 0 {
		caps = []string{"NA"}
	}
	announced := map[string]string{}
	skipped := map[string]bool{}
	for _, raw := range r.server.DiscoveryURLs {
		host, port, path := splitDiscoveryURL(raw)
		target, local := srvTarget(host, hostname)
		if target == "" || port == 0 {
			// Part 12: a discovery URL with an IP address cannot be mapped
			// onto a DNS-SD service.
			d.srv.cfg.logger.Info("registered server not announced with mDNS: its discovery URL has no host name",
				"server_uri", uri, "discovery_url", raw)
			continue
		}
		instance := instanceName(r.mdnsName, host)
		if _, dup := announced[instance]; dup {
			continue
		}
		svc := mdns.Service{
			Instance: instance, Type: opcuaServiceType, Host: target, Port: port,
			Text: txtRecord(path, caps), LocalHost: local,
		}
		signature := fmt.Sprintf("%s|%d|%q|%s", svc.Host, svc.Port, svc.Text, raw)

		d.mu.Lock()
		row := d.byName[strings.ToLower(instance)]
		taken := row != nil && row.owner != uri
		selfAnnounced := taken && row.owner == ""
		if taken {
			// Remembered so that the name is taken over when it becomes
			// free (handOver). annMu keeps the row from going away
			// before this is recorded.
			skipped[strings.ToLower(instance)] = true
		}
		d.mu.Unlock()
		if selfAnnounced {
			// The server announces itself under this name: a second
			// responder for the same records would only be in its way.
			continue
		}
		if taken {
			d.srv.cfg.logger.Warn("registered server not announced with mDNS: the instance name is in use",
				"server_uri", uri, "instance", instance)
			continue
		}
		// A renewal that changes nothing is not announced again.
		if old == nil || old.announced[instance] != signature {
			if err := node.Register(svc); err != nil {
				d.srv.cfg.logger.Warn("registered server not announced with mDNS", "server_uri", uri, "error", err)
				continue
			}
		}
		announced[instance] = signature
		d.mu.Lock()
		d.putRecordLocked(instance, uri, raw, caps)
		d.mu.Unlock()
	}

	d.mu.Lock()
	r.announced = announced
	r.skipped = skipped
	current := d.servers[uri] == r
	d.mu.Unlock()
	if old != nil {
		for instance := range old.announced {
			if _, keep := announced[instance]; !keep {
				d.withdrawInstance(node, instance, uri)
			}
		}
	}
	if !current {
		// The registration was removed while it was being announced.
		d.withdraw(r)
	}
}

// withdraw removes the mDNS records of a registered server.
func (d *discoveryManager) withdraw(r *registration) {
	d.mu.Lock()
	node := d.node
	announced := r.announced
	r.announced = nil
	r.skipped = nil
	d.mu.Unlock()
	if node == nil {
		return
	}
	for instance := range announced {
		d.withdrawInstance(node, instance, r.server.ServerURI)
	}
}

// withdrawInstance withdraws one instance of a registered server and hands
// the name over to another registered server that wants it. It is called
// with annMu held.
func (d *discoveryManager) withdrawInstance(node *mdns.Node, instance, owner string) {
	node.Unregister(instance, opcuaServiceType)
	d.mu.Lock()
	dropped := d.dropRecordLocked(instance, owner)
	d.mu.Unlock()
	if dropped {
		d.handOver(instance, owner)
	}
}

// srvTarget maps the host of a discovery URL onto the target of a SRV
// record. A plain host name is taken to be on the local link ("press7"
// becomes "press7.local."); "localhost" stands for the discovery server's
// own machine. An IP address has no mapping.
func srvTarget(host, self string) (target string, local bool) {
	switch {
	case host == "" || net.ParseIP(host) != nil || !validHostName(host):
		return "", false
	case strings.EqualFold(host, "localhost"):
		return self + "." + mdns.Domain, true
	case !strings.Contains(host, "."):
		return host + "." + mdns.Domain, strings.EqualFold(host, self)
	}
	host = strings.TrimSuffix(host, ".")
	return host + ".", strings.EqualFold(host, self+".local")
}

// ServersOnNetwork returns a copy of the ServerOnNetwork table in record id
// order: the server itself, the registered servers it announces and the
// servers discovered with mDNS. It is empty unless the server was created
// with [WithMulticastDiscovery] and is running.
func (s *Server) ServersOnNetwork() []*ua.ServerOnNetwork {
	d := s.disc
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*ua.ServerOnNetwork, 0, len(d.records))
	for _, r := range d.records {
		cp := *r.rec
		cp.ServerCapabilities = slices.Clone(r.rec.ServerCapabilities)
		out = append(out, &cp)
	}
	return out
}

// findServersOnNetwork implements FindServersOnNetwork (Part 4 §5.4.3).
func (d *discoveryManager) findServersOnNetwork(req *ua.FindServersOnNetworkRequest) (time.Time, []*ua.ServerOnNetwork) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*ua.ServerOnNetwork
	for _, r := range d.records {
		if r.rec.RecordID < req.StartingRecordID || !hasCapabilities(r.rec.ServerCapabilities, req.ServerCapabilityFilter) {
			continue
		}
		if req.MaxRecordsToReturn != 0 && uint32(len(out)) >= req.MaxRecordsToReturn {
			break
		}
		cp := *r.rec
		cp.ServerCapabilities = slices.Clone(r.rec.ServerCapabilities)
		out = append(out, &cp)
	}
	return d.resetAt, out
}

// hasCapabilities reports whether a server has every capability of the
// filter. The comparison ignores case.
func hasCapabilities(have, filter []string) bool {
	for _, want := range filter {
		if !slices.ContainsFunc(have, func(c string) bool { return strings.EqualFold(c, want) }) {
			return false
		}
	}
	return true
}
