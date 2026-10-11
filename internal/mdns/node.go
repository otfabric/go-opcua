// SPDX-License-Identifier: MIT

package mdns

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// Domain is the mDNS top-level domain.
	Domain = "local."

	// Port is the mDNS UDP port.
	Port = 5353

	// serviceEnumeration is the DNS-SD service type enumeration name
	// (RFC 6763 §9).
	serviceEnumeration = "_services._dns-sd._udp.local."

	// DefaultHostTTL is the TTL of records that depend on a host name (SRV,
	// A, AAAA) and DefaultOtherTTL that of the other records (RFC 6762 §10).
	DefaultHostTTL  uint32 = 120
	DefaultOtherTTL uint32 = 4500

	// maxTTL caps the lifetime a peer can give a cached record.
	maxTTL = 24 * time.Hour

	// legacyTTL caps the TTLs of a legacy unicast response (RFC 6762 §6.7).
	legacyTTL uint32 = 10

	// maxPayload keeps packets below the Ethernet MTU (RFC 6762 §17).
	maxPayload = 1400

	defaultMaxInstances = 1024
	announceCount       = 2
	announceInterval    = time.Second
	initialQueryDelay   = time.Second
	maxQueryInterval    = time.Hour
	goodbyeGrace        = time.Second
	resolveAttempts     = 3
	rateLimit           = time.Second
)

// PacketConn is the datagram transport of a [Node]: one multicast capable
// socket on one interface. Implementations must be safe for one concurrent
// reader and any number of concurrent writers.
type PacketConn interface {
	// ReadFrom blocks until the next datagram arrives and returns its
	// source. It returns an error once the conn is closed.
	ReadFrom(b []byte) (n int, src netip.AddrPort, err error)
	// WriteMulticast sends a datagram to the mDNS group.
	WriteMulticast(b []byte) error
	// WriteTo sends a unicast datagram.
	WriteTo(b []byte, dst netip.AddrPort) error
	// Addrs returns the local addresses to publish in address records.
	Addrs() []netip.Addr
	Close() error
}

// Service is a DNS-SD service instance announced by a [Node].
type Service struct {
	// Instance is the instance name: a single label of at most 63 bytes. It
	// is not escaped; dots and spaces are allowed.
	Instance string
	// Type is the service type without the domain, e.g. "_opcua-tcp._tcp".
	Type string
	// Host is the target of the SRV record, e.g. "press7.local.".
	Host string
	Port uint16
	// Text holds the strings of the TXT record ("key=value").
	Text []string
	// Addrs are the addresses published for Host.
	Addrs []netip.Addr
	// LocalHost says that Host is this machine: the addresses of the
	// interface a packet is sent on are published for it in addition to
	// Addrs.
	LocalHost bool
}

// FullName returns the service instance name, e.g.
// "Press 7._opcua-tcp._tcp.local.".
func (s Service) FullName() string {
	return EscapeLabel(s.Instance) + "." + typeFQDN(s.Type)
}

func typeFQDN(typ string) string {
	return strings.TrimSuffix(typ, ".") + "." + Domain
}

// Instance is a service instance discovered by browsing.
type Instance struct {
	// Name is the unescaped instance label.
	Name string
	// Type is the service type without the domain.
	Type string
	// Host is the target of the SRV record with its trailing dot.
	Host string
	Port uint16
	Text []string
}

// Event reports that an instance appeared or changed (Removed is false) or
// that it went away (Removed is true).
type Event struct {
	Removed  bool
	Instance Instance
}

// Config configures a [Node].
type Config struct {
	// Conns are the transports to use, one per interface. The node takes
	// ownership and closes them.
	Conns []PacketConn
	// Logger receives diagnostics. Nil disables logging.
	Logger *slog.Logger
	// HostTTL and OtherTTL override the record TTLs (in seconds).
	HostTTL, OtherTTL uint32
	// MaxInstances bounds the browse cache. Further instances are ignored
	// until others expire.
	MaxInstances int
	// Now replaces time.Now. It is meant for tests.
	Now func() time.Time
}

// Node is an mDNS responder and browser.
type Node struct {
	cfg   Config
	conns []PacketConn
	log   *slog.Logger

	mu       sync.Mutex
	services map[string]*localService // canonical full name
	browses  map[string]*browse       // canonical type FQDN
	cache    map[string]*remote       // canonical full name
	sent     []map[string]time.Time   // per conn: record key -> last multicast
	out      []outPacket
	events   []pendingEvent
	closed   bool

	rx      chan rxPacket
	wake    chan struct{}
	closing chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

type localService struct {
	svc          Service
	announceLeft int
	nextAnnounce time.Time
	conflict     bool
}

type browse struct {
	typ       string // as given by the caller
	fqdn      string
	fn        func(Event)
	nextQuery time.Time
	interval  time.Duration
}

type remote struct {
	key  string
	name string // unescaped instance label
	b    *browse

	ptrExp, srvExp, txtExp time.Time
	ptrTTL                 uint32
	srv                    *SRV
	txt                    []string
	txtKnown               bool

	lifeStart   time.Time
	goodbyeAt   time.Time
	stage       int // refresh queries sent in the current lifetime
	resolves    int
	nextResolve time.Time

	reported bool
	last     Instance
}

type outPacket struct {
	conn    int // index into conns, or -1 for all
	msg     *Message
	perConn func(conn int) *Message // builds the message for one conn; overrides msg
	unicast netip.AddrPort          // valid: send there instead of to the group
}

type pendingEvent struct {
	fn func(Event)
	ev Event
}

type rxPacket struct {
	conn int
	data []byte
	src  netip.AddrPort
}

// New creates a node on the given transports and starts it.
func New(cfg Config) (*Node, error) {
	if len(cfg.Conns) == 0 {
		return nil, errors.New("mdns: no transport")
	}
	n := newNode(cfg)
	n.wg.Add(1 + len(n.conns))
	for i, c := range n.conns {
		go n.read(i, c)
	}
	go n.run()
	return n, nil
}

// newNode builds a node without starting its goroutines. Tests drive it with
// step and handlePacket.
func newNode(cfg Config) *Node {
	if cfg.HostTTL == 0 {
		cfg.HostTTL = DefaultHostTTL
	}
	if cfg.OtherTTL == 0 {
		cfg.OtherTTL = DefaultOtherTTL
	}
	if cfg.MaxInstances <= 0 {
		cfg.MaxInstances = defaultMaxInstances
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	n := &Node{
		cfg:      cfg,
		conns:    cfg.Conns,
		log:      log,
		services: map[string]*localService{},
		browses:  map[string]*browse{},
		cache:    map[string]*remote{},
		sent:     make([]map[string]time.Time, len(cfg.Conns)),
		rx:       make(chan rxPacket, 64),
		wake:     make(chan struct{}, 1),
		closing:  make(chan struct{}),
	}
	for i := range n.sent {
		n.sent[i] = map[string]time.Time{}
	}
	return n
}

// Register announces a service instance. Registering an instance again
// replaces its data and announces the new records.
func (n *Node) Register(s Service) error {
	if err := validateService(&s); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return errors.New("mdns: node is closed")
	}
	s.Text = slices.Clone(s.Text)
	s.Addrs = slices.Clone(s.Addrs)
	key := canonicalName(s.FullName())
	n.services[key] = &localService{svc: s, announceLeft: announceCount, nextAnnounce: n.cfg.Now()}
	// An instance we announce is not a discovery.
	if r := n.cache[key]; r != nil {
		n.remove(r)
	}
	n.kick()
	return nil
}

func validateService(s *Service) error {
	if s.Instance == "" || len(s.Instance) > maxLabelLen {
		return fmt.Errorf("mdns: instance name must be 1 to %d bytes: %q", maxLabelLen, s.Instance)
	}
	if s.Port == 0 {
		return errors.New("mdns: service without port")
	}
	if !strings.HasSuffix(s.Host, ".") {
		s.Host += "."
	}
	for _, name := range []string{s.FullName(), s.Host} {
		labels, err := SplitName(name)
		if err != nil {
			return err
		}
		if len(labels) < 2 {
			return fmt.Errorf("mdns: %q is not a fully qualified name", name)
		}
	}
	for _, t := range s.Text {
		if len(t) > 255 {
			return errors.New("mdns: TXT string longer than 255 bytes")
		}
	}
	return nil
}

// Unregister withdraws a service instance with a goodbye packet. It reports
// whether the instance was registered.
func (n *Node) Unregister(instance, typ string) bool {
	key := canonicalName(Service{Instance: instance, Type: typ}.FullName())
	n.mu.Lock()
	defer n.mu.Unlock()
	ls := n.services[key]
	if ls == nil || n.closed {
		return false
	}
	delete(n.services, key)
	n.queueGoodbye(ls)
	n.kick()
	return true
}

// Browse starts browsing for instances of a service type, e.g.
// "_opcua-tcp._tcp". fn is called from a single goroutine, in order, for
// every instance that appears, changes or disappears; it must not block for
// long. Instances registered on this node are not reported.
func (n *Node) Browse(typ string, fn func(Event)) error {
	fqdn := typeFQDN(typ)
	if _, err := SplitName(fqdn); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return errors.New("mdns: node is closed")
	}
	n.browses[canonicalName(fqdn)] = &browse{typ: strings.TrimSuffix(typ, "."), fqdn: fqdn, fn: fn, nextQuery: n.cfg.Now()}
	n.kick()
	return nil
}

// Close withdraws all registered instances with goodbye packets, stops the
// node and closes its transports. It is safe to call more than once.
func (n *Node) Close() error {
	n.once.Do(func() { close(n.closing) })
	n.wg.Wait()
	return nil
}

func (n *Node) kick() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// --- goroutines ---------------------------------------------------------------

func (n *Node) read(idx int, c PacketConn) {
	defer n.wg.Done()
	buf := make([]byte, MaxPacketSize)
	for {
		sz, src, err := c.ReadFrom(buf)
		if err != nil {
			select {
			case <-n.closing:
			default:
				n.log.Debug("mdns: read failed, transport abandoned", "conn", idx, "error", err)
			}
			return
		}
		p := rxPacket{conn: idx, data: slices.Clone(buf[:sz]), src: src}
		select {
		case n.rx <- p:
		case <-n.closing:
			return
		}
	}
}

func (n *Node) run() {
	defer n.wg.Done()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		out, events, next := n.step(n.cfg.Now())
		n.send(out)
		deliver(events)

		wait := time.Hour
		if !next.IsZero() {
			wait = max(next.Sub(n.cfg.Now()), time.Millisecond)
		}
		timer.Reset(wait)

		select {
		case p := <-n.rx:
			n.mu.Lock()
			n.handlePacket(n.cfg.Now(), p.conn, p.data, p.src)
			n.mu.Unlock()
		case <-timer.C:
		case <-n.wake:
		case <-n.closing:
			n.mu.Lock()
			n.closed = true
			for _, ls := range n.services {
				n.queueGoodbye(ls)
			}
			out := n.out
			n.out = nil
			n.mu.Unlock()
			n.send(out)
			for _, c := range n.conns {
				_ = c.Close()
			}
			return
		}
	}
}

// step runs everything that is due at now and returns the packets to send,
// the events to deliver and the time of the next deadline (zero if none).
func (n *Node) step(now time.Time) ([]outPacket, []pendingEvent, time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tick(now)
	out, events := n.out, n.events
	n.out, n.events = nil, nil
	return out, events, n.nextDeadline()
}

func deliver(events []pendingEvent) {
	for _, e := range events {
		e.fn(e.ev)
	}
}

func (n *Node) send(out []outPacket) {
	for _, p := range out {
		for i, c := range n.conns {
			if p.conn >= 0 && p.conn != i {
				continue
			}
			msg := p.msg
			if p.perConn != nil {
				msg = p.perConn(i)
			}
			if msg == nil {
				continue
			}
			for _, b := range splitPack(msg) {
				var err error
				if p.unicast.IsValid() {
					err = c.WriteTo(b, p.unicast)
				} else {
					err = c.WriteMulticast(b)
				}
				if err != nil {
					n.log.Debug("mdns: send failed", "conn", i, "error", err)
				}
			}
		}
	}
}

// splitPack encodes a message, spreading its answers over several packets if
// they do not fit one. Additional records that do not fit are dropped, as are
// the known answers of a query.
func splitPack(m *Message) [][]byte {
	if b, err := m.Pack(); err == nil && len(b) <= maxPayload {
		return [][]byte{b}
	}
	var out [][]byte
	if !m.Response {
		// A query: keep the questions and as many known answers as fit.
		q := &Message{Questions: m.Questions}
		best, err := q.Pack()
		if err != nil {
			return nil
		}
		for _, a := range m.Answers {
			q.Answers = append(q.Answers, a)
			b, err := q.Pack()
			if err != nil || len(b) > maxPayload {
				break
			}
			best = b
		}
		return [][]byte{best}
	}
	cur := &Message{ID: m.ID, Response: true, Authoritative: m.Authoritative, Questions: m.Questions}
	var last []byte
	for _, a := range m.Answers {
		cur.Answers = append(cur.Answers, a)
		b, err := cur.Pack()
		if err != nil {
			cur.Answers = cur.Answers[:len(cur.Answers)-1]
			continue
		}
		if len(b) > maxPayload && len(cur.Answers) > 1 {
			out = append(out, last)
			cur = &Message{ID: m.ID, Response: true, Authoritative: m.Authoritative, Answers: []Record{a}}
			if b, err = cur.Pack(); err != nil {
				cur.Answers = nil
				last = nil
				continue
			}
		}
		last = b
	}
	if last != nil {
		out = append(out, last)
	}
	return out
}

// --- timers -------------------------------------------------------------------

func (n *Node) tick(now time.Time) {
	for _, ls := range n.services {
		if ls.announceLeft > 0 && !now.Before(ls.nextAnnounce) {
			ls.announceLeft--
			ls.nextAnnounce = now.Add(announceInterval)
			n.queueAnnounce(now, ls)
		}
	}

	for _, b := range n.browses {
		if now.Before(b.nextQuery) {
			continue
		}
		if b.interval == 0 {
			b.interval = initialQueryDelay
		} else {
			b.interval = min(b.interval*2, maxQueryInterval)
		}
		b.nextQuery = now.Add(b.interval)
		n.out = append(n.out, outPacket{conn: -1, msg: n.browseQuery(now, b)})
	}

	for _, r := range n.cache {
		end := r.lifeEnd()
		if !now.Before(end) {
			n.remove(r)
			continue
		}
		if r.resolving() {
			if !now.Before(r.nextResolve) {
				r.resolves++
				r.nextResolve = now.Add(time.Duration(r.resolves) * time.Second)
				n.out = append(n.out, outPacket{conn: -1, msg: resolveQuery(r)})
			}
			continue
		}
		if r.refreshing() && !now.Before(r.refreshAt()) {
			r.stage++
			q := resolveQuery(r)
			q.Questions = append(q.Questions, Question{Name: r.b.fqdn, Type: TypePTR, Class: ClassIN})
			n.out = append(n.out, outPacket{conn: -1, msg: q})
		}
	}

	// Forget rate-limit entries that no longer matter.
	for _, m := range n.sent {
		for k, t := range m {
			if now.Sub(t) > rateLimit {
				delete(m, k)
			}
		}
	}
}

func (n *Node) nextDeadline() time.Time {
	var next time.Time
	consider := func(t time.Time) {
		if !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	for _, ls := range n.services {
		if ls.announceLeft > 0 {
			consider(ls.nextAnnounce)
		}
	}
	for _, b := range n.browses {
		consider(b.nextQuery)
	}
	for _, r := range n.cache {
		consider(r.lifeEnd())
		switch {
		case r.resolving():
			consider(r.nextResolve)
		case r.refreshing():
			consider(r.refreshAt())
		}
	}
	return next
}

// resolving reports whether the SRV or TXT record of the instance is still
// missing and worth asking for.
func (r *remote) resolving() bool {
	return (r.srv == nil || !r.txtKnown) && r.resolves < resolveAttempts && r.goodbyeAt.IsZero()
}

// refreshing reports whether a refresh query is still to be sent in the
// current lifetime of the instance.
func (r *remote) refreshing() bool {
	return !r.resolving() && r.srv != nil && r.stage < 2 && r.goodbyeAt.IsZero()
}

// lifeEnd is when the instance leaves the cache: when the first of its
// records expires, or at the end of the grace period after a goodbye.
func (r *remote) lifeEnd() time.Time {
	var end time.Time
	for _, t := range []time.Time{r.ptrExp, r.srvExp, r.txtExp, r.goodbyeAt} {
		if !t.IsZero() && (end.IsZero() || t.Before(end)) {
			end = t
		}
	}
	return end
}

// refreshAt is when the next refresh query is due: at 80% and 90% of the
// lifetime (RFC 6762 §5.2).
func (r *remote) refreshAt() time.Time {
	life := r.lifeEnd().Sub(r.lifeStart)
	return r.lifeStart.Add(life * time.Duration(8+r.stage) / 10)
}

func resolveQuery(r *remote) *Message {
	name := EscapeLabel(r.name) + "." + r.b.fqdn
	return &Message{Questions: []Question{
		{Name: name, Type: TypeSRV, Class: ClassIN},
		{Name: name, Type: TypeTXT, Class: ClassIN},
	}}
}

func (n *Node) browseQuery(now time.Time, b *browse) *Message {
	m := &Message{Questions: []Question{{Name: b.fqdn, Type: TypePTR, Class: ClassIN}}}
	// Known answers: the PTR records we hold with more than half of their
	// lifetime left (RFC 6762 §7.1).
	for _, r := range n.cache {
		if r.b != b || r.ptrExp.IsZero() || !r.goodbyeAt.IsZero() {
			continue
		}
		left := r.ptrExp.Sub(now)
		if left <= time.Duration(r.ptrTTL)*time.Second/2 {
			continue
		}
		m.Answers = append(m.Answers, Record{
			Name: b.fqdn, Type: TypePTR, Class: ClassIN,
			TTL: uint32(left / time.Second),
			PTR: EscapeLabel(r.name) + "." + b.fqdn,
		})
	}
	slices.SortFunc(m.Answers, func(a, b Record) int { return strings.Compare(a.PTR, b.PTR) })
	return m
}

// --- responder ----------------------------------------------------------------

// records returns the records of a service as sent on one conn. ttl0 builds
// the goodbye form.
func (n *Node) records(ls *localService, conn int, goodbye bool) (ptr, srv, txt Record, addrs []Record) {
	s := &ls.svc
	full := s.FullName()
	host, other := n.cfg.HostTTL, n.cfg.OtherTTL
	if goodbye {
		host, other = 0, 0
	}
	ptr = Record{Name: typeFQDN(s.Type), Type: TypePTR, Class: ClassIN, TTL: other, PTR: full}
	srv = Record{Name: full, Type: TypeSRV, Class: ClassIN, CacheFlush: true, TTL: host,
		SRV: &SRV{Port: s.Port, Target: s.Host}}
	txt = Record{Name: full, Type: TypeTXT, Class: ClassIN, CacheFlush: true, TTL: other, TXT: s.Text}
	addrs = n.addrRecords(s, conn, host)
	return
}

func (n *Node) addrRecords(s *Service, conn int, ttl uint32) []Record {
	list := slices.Clone(s.Addrs)
	if s.LocalHost && conn >= 0 && conn < len(n.conns) {
		list = append(list, n.conns[conn].Addrs()...)
	}
	var out []Record
	seen := map[netip.Addr]bool{}
	for _, a := range list {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		typ := TypeAAAA
		if a.Is4() {
			typ = TypeA
		}
		out = append(out, Record{Name: s.Host, Type: typ, Class: ClassIN, CacheFlush: true, TTL: ttl, Addr: a})
	}
	return out
}

func (n *Node) enumRecord(typ string, ttl uint32) Record {
	return Record{Name: serviceEnumeration, Type: TypePTR, Class: ClassIN, TTL: ttl, PTR: typeFQDN(typ)}
}

func (n *Node) queueAnnounce(now time.Time, ls *localService) {
	n.out = append(n.out, outPacket{conn: -1, perConn: func(conn int) *Message {
		ptr, srv, txt, addrs := n.records(ls, conn, false)
		m := &Message{Response: true, Authoritative: true}
		m.Answers = append(m.Answers, ptr, srv, txt)
		m.Answers = append(m.Answers, addrs...)
		m.Answers = append(m.Answers, n.enumRecord(ls.svc.Type, n.cfg.OtherTTL))
		return m
	}})
	for i := range n.sent {
		for _, k := range []string{recordKey(typeFQDN(ls.svc.Type), TypePTR, ls.svc.FullName()),
			recordKey(ls.svc.FullName(), TypeSRV, ""), recordKey(ls.svc.FullName(), TypeTXT, "")} {
			n.sent[i][k] = now
		}
	}
}

func (n *Node) queueGoodbye(ls *localService) {
	// The address records of the host are left alone: other instances, or
	// other responders on this machine, may still depend on them.
	ptr, srv, txt, _ := n.records(ls, -1, true)
	n.out = append(n.out, outPacket{conn: -1, msg: &Message{
		Response: true, Authoritative: true, Answers: []Record{ptr, srv, txt},
	}})
}

func recordKey(name string, typ uint16, data string) string {
	return fmt.Sprintf("%s|%d|%s", canonicalName(name), typ, asciiLower(data))
}

// handlePacket processes one received datagram. It must be called with the
// mutex held. Malformed packets are dropped.
func (n *Node) handlePacket(now time.Time, conn int, data []byte, src netip.AddrPort) {
	if n.closed || len(data) > MaxPacketSize {
		return
	}
	m, err := Unpack(data)
	if err != nil {
		n.log.Debug("mdns: dropped malformed packet", "source", src, "error", err)
		return
	}
	// RFC 6762 §18.3 and §18.11: messages with another opcode or a non-zero
	// response code are silently ignored.
	if m.Opcode != 0 || m.RCode != 0 {
		return
	}
	if m.Response {
		// RFC 6762 §6 wants responses from another source port than 5353
		// ignored. That rule is deliberately not applied: the mdnsd library
		// embedded in open62541 sends everything from an ephemeral port, and
		// an OPC UA discovery server that cannot see open62541 servers is of
		// little use. The transport already drops packets from sources that
		// are not on the local link (§11), which is what keeps off-link
		// senders out.
		n.handleResponse(now, m)
		return
	}
	n.handleQuery(now, conn, m, src)
}

func (n *Node) handleQuery(now time.Time, conn int, q *Message, src netip.AddrPort) {
	if len(n.services) == 0 {
		return
	}
	// A query from another port than 5353 comes from a conventional
	// resolver and gets a unicast answer (§6.7). Such resolvers pick a
	// query id; a query id of zero is the mark of a multicast querier
	// (§18.1), which mdnsd (open62541) is even though it does not send from
	// port 5353. It is answered by multicast like any other.
	legacy := src.Port() != Port && q.ID != 0
	resp := &Message{Response: true, Authoritative: true}
	var extra []Record
	have := map[string]bool{}
	add := func(dst *[]Record, r Record, data string) {
		k := recordKey(r.Name, r.Type, data)
		if have[k] {
			return
		}
		have[k] = true
		*dst = append(*dst, r)
	}
	// Known-answer suppression (§7.1): a record the querier already holds
	// with at least half of its lifetime left is not sent again.
	known := func(r Record) bool {
		for i := range q.Answers {
			if a := &q.Answers[i]; a.TTL >= r.TTL/2 && sameRecord(a, &r) {
				return true
			}
		}
		return false
	}
	wants := func(qt, rt uint16) bool { return qt == rt || qt == TypeANY }

	keys := make([]string, 0, len(n.services))
	for k := range n.services {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, question := range q.Questions {
		if question.Class != ClassIN && question.Class != ClassANY {
			continue
		}
		qname := canonicalName(question.Name)
		for _, k := range keys {
			ls := n.services[k]
			ptr, srv, txt, addrs := n.records(ls, conn, false)
			addAddrs := func(dst *[]Record) {
				for _, a := range addrs {
					add(dst, a, a.Addr.String())
				}
			}
			switch {
			case qname == serviceEnumeration && wants(question.Type, TypePTR):
				e := n.enumRecord(ls.svc.Type, n.cfg.OtherTTL)
				if !known(e) {
					add(&resp.Answers, e, e.PTR)
				}
			case qname == canonicalName(ptr.Name) && wants(question.Type, TypePTR):
				if known(ptr) {
					continue
				}
				add(&resp.Answers, ptr, ptr.PTR)
				add(&extra, srv, "")
				add(&extra, txt, "")
				addAddrs(&extra)
			case qname == k:
				if wants(question.Type, TypeSRV) && !known(srv) {
					add(&resp.Answers, srv, "")
					addAddrs(&extra)
				}
				if wants(question.Type, TypeTXT) && !known(txt) {
					add(&resp.Answers, txt, "")
				}
			case qname == canonicalName(ls.svc.Host):
				for _, a := range addrs {
					if wants(question.Type, a.Type) {
						add(&resp.Answers, a, a.Addr.String())
					}
				}
			}
		}
	}
	if len(resp.Answers) == 0 {
		return
	}
	// An additional record that is also an answer is sent once.
	inAnswers := map[string]bool{}
	for _, a := range resp.Answers {
		inAnswers[recordKey(a.Name, a.Type, dataKey(a))] = true
	}
	for _, r := range extra {
		if !inAnswers[recordKey(r.Name, r.Type, dataKey(r))] {
			resp.Additionals = append(resp.Additionals, r)
		}
	}

	if legacy {
		// RFC 6762 §6.7: a conventional unicast response that repeats the
		// query ID and question, without the cache-flush bit and with
		// short TTLs.
		resp.ID = q.ID
		resp.Questions = q.Questions
		for _, sec := range [][]Record{resp.Answers, resp.Additionals} {
			for i := range sec {
				sec[i].CacheFlush = false
				sec[i].TTL = min(sec[i].TTL, legacyTTL)
			}
		}
		n.out = append(n.out, outPacket{conn: conn, msg: resp, unicast: src})
		return
	}

	// §6: a record is not multicast again within one second on an interface.
	if conn >= 0 && conn < len(n.sent) {
		sent := n.sent[conn]
		kept := resp.Answers[:0]
		for _, a := range resp.Answers {
			k := recordKey(a.Name, a.Type, dataKey(a))
			if t, ok := sent[k]; ok && now.Sub(t) < rateLimit {
				continue
			}
			sent[k] = now
			kept = append(kept, a)
		}
		resp.Answers = kept
		if len(resp.Answers) == 0 {
			return
		}
	}
	n.out = append(n.out, outPacket{conn: conn, msg: resp})
}

// sameRecord reports whether two records have the same name, type and data.
func sameRecord(a, b *Record) bool {
	if a.Type != b.Type || !EqualNames(a.Name, b.Name) {
		return false
	}
	switch a.Type {
	case TypePTR:
		return EqualNames(a.PTR, b.PTR)
	case TypeSRV:
		return a.SRV != nil && b.SRV != nil && a.SRV.Port == b.SRV.Port && EqualNames(a.SRV.Target, b.SRV.Target)
	case TypeTXT:
		return slices.Equal(a.TXT, b.TXT)
	case TypeA, TypeAAAA:
		return a.Addr == b.Addr
	}
	return false
}

func dataKey(r Record) string {
	switch r.Type {
	case TypePTR:
		return r.PTR
	case TypeA, TypeAAAA:
		return r.Addr.String()
	}
	return ""
}

// --- browser ------------------------------------------------------------------

func (n *Node) handleResponse(now time.Time, m *Message) {
	touched := map[*remote]bool{}
	for _, sec := range [][]Record{m.Answers, m.Additionals} {
		for i := range sec {
			if r := n.absorb(now, &sec[i]); r != nil {
				touched[r] = true
			}
		}
	}
	for r := range touched {
		if n.cache[r.key] != r {
			continue // removed while the packet was processed
		}
		if r.srv == nil {
			continue // tick asks for the missing records
		}
		inst := Instance{Name: r.name, Type: r.b.typ, Host: r.srv.Target, Port: r.srv.Port, Text: slices.Clone(r.txt)}
		if r.reported && sameInstance(r.last, inst) {
			continue
		}
		r.reported, r.last = true, inst
		n.events = append(n.events, pendingEvent{fn: r.b.fn, ev: Event{Instance: inst}})
	}
}

func sameInstance(a, b Instance) bool {
	return a.Port == b.Port && EqualNames(a.Host, b.Host) && slices.Equal(a.Text, b.Text)
}

// absorb applies one received record to the browse cache and returns the
// instance it belongs to, if any.
func (n *Node) absorb(now time.Time, rec *Record) *remote {
	if rec.Class != ClassIN {
		return nil
	}
	var full string
	switch rec.Type {
	case TypePTR:
		if n.browses[canonicalName(rec.Name)] == nil {
			return nil
		}
		full = rec.PTR
	case TypeSRV, TypeTXT:
		full = rec.Name
	default:
		return nil
	}
	labels, err := SplitName(full)
	if err != nil || len(labels) < 2 {
		return nil
	}
	b := n.browses[canonicalName(JoinLabels(labels[1:]...))]
	if b == nil {
		return nil
	}
	if rec.Type == TypePTR && !EqualNames(rec.Name, b.fqdn) {
		return nil
	}
	key := canonicalName(full)
	if ls := n.services[key]; ls != nil {
		if rec.Type == TypeSRV && rec.TTL > 0 && rec.SRV != nil && !ls.conflict &&
			(rec.SRV.Port != ls.svc.Port || !EqualNames(rec.SRV.Target, ls.svc.Host)) {
			ls.conflict = true
			n.log.Warn("mdns: another responder announces the same service instance name with different data",
				"instance", full, "host", rec.SRV.Target, "port", rec.SRV.Port)
		}
		return nil
	}

	r := n.cache[key]
	if rec.TTL == 0 {
		// Goodbye: the record is gone one second from now unless another
		// responder renews it (RFC 6762 §10.1).
		if r != nil && r.goodbyeAt.IsZero() {
			r.goodbyeAt = now.Add(goodbyeGrace)
		}
		return nil
	}
	if r == nil {
		if len(n.cache) >= n.cfg.MaxInstances {
			return nil
		}
		r = &remote{key: key, name: labels[0], b: b}
		n.cache[key] = r
	}
	exp := now.Add(min(time.Duration(rec.TTL)*time.Second, maxTTL))
	switch rec.Type {
	case TypePTR:
		r.ptrExp, r.ptrTTL = exp, rec.TTL
	case TypeSRV:
		if rec.SRV == nil {
			return nil
		}
		srv := *rec.SRV
		r.srv, r.srvExp = &srv, exp
	case TypeTXT:
		r.txt, r.txtKnown, r.txtExp = slices.Clone(rec.TXT), true, exp
	}
	r.lifeStart, r.goodbyeAt, r.stage = now, time.Time{}, 0
	return r
}

func (n *Node) remove(r *remote) {
	delete(n.cache, r.key)
	if r.reported {
		n.events = append(n.events, pendingEvent{fn: r.b.fn, ev: Event{Removed: true, Instance: r.last}})
	}
}
