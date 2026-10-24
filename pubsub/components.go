// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// publishedDataSet is a PublishedDataSet. It has no state machine.
type publishedDataSet struct {
	base
	cfg    *ua.PublishedDataSetDataType
	items  []*ua.PublishedVariableDataType
	events *ua.PublishedEventsDataType
	md     *ua.DataSetMetaDataType
	// action is the PublishedAction (Part 14 §6.2.3.10.3 in 1.05) of an
	// Action data set: md is the response DataSetMetaData, action holds
	// the request DataSetMetaData and the Action targets.
	action *ua.PublishedActionDataType
	// methods are the Methods of the targets of a PublishedActionMethod,
	// by ActionTargetId.
	methods map[uint16]*ua.ActionMethodDataType
}

func (d *publishedDataSet) config() *ua.PublishedDataSetDataType {
	c, _ := clone(d.cfg)
	return c
}

type connection struct {
	base
	cfg    *ua.PubSubConnectionDataType // without groups
	pubID  message.PublisherID
	hasPub bool
	url    string
	iface  string
	broker bool
	wgs    []*writerGroup
	rgs    []*readerGroup

	// gen identifies the current run of the connection goroutine; cancel
	// stops it. tc is the open transport, nil until it is open.
	gen    uint64
	cancel context.CancelFunc
	tc     transport.Connection
	kick   chan struct{}
	// topics are the subscriptions the connection should have.
	topics map[string]byte

	// disc is the discovery configuration; shared tells whether the
	// connection address reaches the publishers and the subscribers alike
	// (multicast). dtc is the open transport of the DiscoveryAddress, nil
	// without.
	disc   datagramDiscovery
	shared bool
	dtc    transport.Connection
	// reasm reassembles the chunked NetworkMessages the connection
	// receives; annSeq numbers its discovery announcements and limiter
	// bounds those sent in answer to probes.
	reasm   *uadp.Reassembler
	annSeq  atomic.Uint32
	limiter *discoveryLimiter
	// gzip compresses the JSON messages the connection sends
	// (JsonCompression); gzipWarned is set once it was logged that the
	// transport cannot carry the compressed content type.
	gzip       bool
	gzipWarned atomic.Bool

	// subsCh is closed (and replaced) whenever the connection goroutine
	// updated its subscriptions; subscribed are the topics it has. Both
	// belong to the current run (gen); subsCh is nil while stopped.
	// topicsSeq counts the changes of topics, syncedSeq is the change the
	// subscriptions reflect.
	subsCh     chan struct{}
	subscribed map[string]bool
	// ready is closed once the run's first subscriptions are in place (or
	// failed): the writer groups of the connection publish only then, so
	// that its own readers and probe listener hear the first messages.
	ready     chan struct{}
	topicsSeq uint64
	syncedSeq uint64
	// act is the state of the PubSub Actions of the current run.
	act actionState
}

func (c *connection) config() *ua.PubSubConnectionDataType {
	out, _ := clone(c.cfg)
	out.Enabled = c.enabled
	for _, g := range c.wgs {
		out.WriterGroups = append(out.WriterGroups, g.config())
	}
	for _, g := range c.rgs {
		out.ReaderGroups = append(out.ReaderGroups, g.config())
	}
	return out
}

type writerGroup struct {
	base
	conn     *connection
	cfg      *ua.WriterGroupDataType // without writers
	enc      encoding
	uadpMsg  *ua.UADPWriterGroupMessageDataType
	jsonMsg  *ua.JSONWriterGroupMessageDataType
	brokerTS *ua.BrokerWriterGroupTransportDataType
	dgramTS  *ua.DatagramWriterGroupTransportDataType
	// announce is the DiscoveryAnnounceRate of the group
	// (DatagramWriterGroupTransport2DataType), 0 if it has none.
	announce  time.Duration
	interval  time.Duration
	keepAlive time.Duration
	offset    time.Duration
	mode      ua.MessageSecurityMode
	writers   []*dataSetWriter

	gen    uint64
	cancel context.CancelFunc
	keysOK bool

	// pubMu serialises the publish cycles; nmSeq belongs to the cycle.
	// nonceSeq is shared with the discovery announcements, which are
	// sent from the receive loop.
	pubMu    chanMutex
	nmSeq    uint16
	nonceSeq atomic.Uint32
}

// nextNonce is the sequence number of the next secured message of the
// group (Part 14 §7.2.4.4.3: unique for each message under a key).
func (g *writerGroup) nextNonce() uint32 { return g.nonceSeq.Add(1) }

func (g *writerGroup) config() *ua.WriterGroupDataType {
	out, _ := clone(g.cfg)
	out.Enabled = g.enabled
	for _, w := range g.writers {
		out.DataSetWriters = append(out.DataSetWriters, w.config())
	}
	return out
}

type dataSetWriter struct {
	base
	group    *writerGroup
	cfg      *ua.DataSetWriterDataType
	pds      *publishedDataSet
	uadpMask ua.UADPDataSetMessageContentMask
	jsonMask ua.JSONDataSetMessageContentMask
	brokerTS *ua.BrokerDataSetWriterTransportDataType

	// Publishing state, guarded by PubSub.mu.
	running     bool
	seq         uint32
	sinceKey    uint32
	needKey     bool
	last        []*ua.DataValue
	lastSent    time.Time
	metaPending bool
	metaSentAt  time.Time
	evGen       uint64
	evCancel    func()
	events      [][]*ua.Variant
}

func (w *dataSetWriter) config() *ua.DataSetWriterDataType {
	out, _ := clone(w.cfg)
	out.Enabled = w.enabled
	return out
}

type readerGroup struct {
	base
	conn    *connection
	cfg     *ua.ReaderGroupDataType // without readers
	readers []*dataSetReader
}

func (g *readerGroup) config() *ua.ReaderGroupDataType {
	out, _ := clone(g.cfg)
	out.Enabled = g.enabled
	for _, r := range g.readers {
		out.DataSetReaders = append(out.DataSetReaders, r.config())
	}
	return out
}

type dataSetReader struct {
	base
	group    *readerGroup
	cfg      *ua.DataSetReaderDataType
	pub      message.PublisherID
	hasPub   bool
	enc      encoding
	md       *ua.DataSetMetaDataType
	brokerTS *ua.BrokerDataSetReaderTransportDataType
	targets  []*ua.FieldTargetDataType
	mirror   *ua.SubscribedDataSetMirrorDataType
	timeout  time.Duration
	mode     ua.MessageSecurityMode
	groupID  string

	// Subscribing state, guarded by PubSub.mu.
	running  bool
	timer    *timerRef
	lastRecv time.Time
	streams  map[streamKey]*stream
	// lastGood is the last usable value per target variable.
	lastGood []*ua.DataValue
	// Discovery (Part 14 §7.2.4.6.12): needMeta is set by a
	// DataSetMessage of another MajorVersion; probe is the timer of the
	// next probe, probeWait the current interval between probes,
	// probeSent and probeSeen when this reader and another subscriber
	// last asked for the DataSetMetaData.
	needMeta  bool
	probe     *timerRef
	probeWait time.Duration
	probeSent time.Time
	probeSeen time.Time
}

func (r *dataSetReader) config() *ua.DataSetReaderDataType {
	out, _ := clone(r.cfg)
	out.Enabled = r.enabled
	if r.md != nil {
		out.DataSetMetaData, _ = clone(r.md)
	}
	return out
}

// chanMutex is a mutex whose Lock can be abandoned when a context ends.
type chanMutex struct{ ch chan struct{} }

func (m *chanMutex) init() { m.ch = make(chan struct{}, 1) }

func (m *chanMutex) lock(ctx context.Context) bool {
	select {
	case m.ch <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (m *chanMutex) unlock() { <-m.ch }

// AddPublishedDataSet adds a PublishedDataSet. Without DataSetMetaData, or
// with one without fields, the metadata is derived from the published
// variables (through the [FieldMetaDataResolver] of the DataSource if it has
// one). A ConfigurationVersion of 0 is set to the current VersionTime.
func (p *PubSub) AddPublishedDataSet(cfg *ua.PublishedDataSetDataType) (ComponentID, error) {
	p.lock()
	defer p.unlock()
	if p.closed {
		return 0, ErrClosed
	}
	return p.addPublishedDataSetLocked(cfg)
}

func (p *PubSub) addPublishedDataSetLocked(in *ua.PublishedDataSetDataType) (ComponentID, error) {
	path := "published data set"
	if in != nil {
		path = fmt.Sprintf("published data set %q", in.Name)
	}
	if err := validatePublishedDataSet(path, in); err != nil {
		return 0, err
	}
	for _, d := range p.pdss {
		if d.name == in.Name {
			return 0, fmt.Errorf("pubsub: %s: duplicate name: %w", path, ua.StatusBadBrowseNameDuplicated)
		}
	}
	cfg, err := clone(in)
	if err != nil {
		return 0, configErr(path, "%v", err)
	}
	d := &publishedDataSet{
		base: base{id: p.newID(), kind: KindPublishedDataSet, name: cfg.Name, parent: Root, enabled: true, state: ua.PubSubStateOperational},
		cfg:  cfg,
	}
	switch src := eoValue(cfg.DataSetSource).(type) {
	case *ua.PublishedDataItemsDataType:
		d.items = src.PublishedData
	case *ua.PublishedEventsDataType:
		d.events = src
	case *ua.PublishedActionDataType:
		d.action = src
	case *ua.PublishedActionMethodDataType:
		// ActionMethods[i] is the Method of ActionTargets[i]; the
		// targets call it with the ActionMethodCaller.
		d.action = &ua.PublishedActionDataType{RequestDataSetMetaData: src.RequestDataSetMetaData, ActionTargets: src.ActionTargets}
		d.methods = map[uint16]*ua.ActionMethodDataType{}
		for i, t := range src.ActionTargets {
			d.methods[t.ActionTargetID] = src.ActionMethods[i]
		}
	}
	d.md = p.completeMetaData(cfg)
	if d.action != nil {
		d.action.RequestDataSetMetaData = completeActionMetaData(d.action.RequestDataSetMetaData, cfg.Name+"Request", d.md.ConfigurationVersion)
		if src, ok := eoValue(cfg.DataSetSource).(*ua.PublishedActionMethodDataType); ok {
			src.RequestDataSetMetaData = d.action.RequestDataSetMetaData
		}
	}
	cfg.DataSetMetaData = d.md
	p.pdss = append(p.pdss, d)
	p.comps[d.id] = d
	p.emit(Event{Type: EventAdded, Component: d.info()})
	return d.id, nil
}

// completeMetaData returns the DataSetMetaData of a PublishedDataSet with the
// fields, names and version filled in.
func (p *PubSub) completeMetaData(cfg *ua.PublishedDataSetDataType) *ua.DataSetMetaDataType {
	md := cfg.DataSetMetaData
	if md == nil {
		md = &ua.DataSetMetaDataType{}
	}
	if md.Name == "" {
		md.Name = cfg.Name
	}
	if md.Description == nil {
		md.Description = &ua.LocalizedText{}
	}
	if md.DataSetClassID == nil {
		md.DataSetClassID = &ua.GUID{}
	}
	if md.ConfigurationVersion == nil || (md.ConfigurationVersion.MajorVersion == 0 && md.ConfigurationVersion.MinorVersion == 0) {
		v := versionTime(time.Now())
		md.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: v, MinorVersion: v}
	}
	var n int
	switch src := eoValue(cfg.DataSetSource).(type) {
	case *ua.PublishedDataItemsDataType:
		n = len(src.PublishedData)
		if len(md.Fields) == 0 {
			res, _ := p.opts.dataSource.(FieldMetaDataResolver)
			for i, v := range src.PublishedData {
				var f *ua.FieldMetaData
				if res != nil {
					f = res.FieldMetaData(v)
				}
				if f == nil {
					f = &ua.FieldMetaData{BuiltInType: uint8(ua.TypeIDVariant), DataType: ua.NewNumericNodeID(0, 24), ValueRank: -1}
				}
				if f.Name == "" {
					f.Name = fmt.Sprintf("Field%d", i)
				}
				md.Fields = append(md.Fields, f)
			}
		}
	case *ua.PublishedActionDataType, *ua.PublishedActionMethodDataType:
		// The response DataSetMetaData of an Action.
		n = len(md.Fields)
	case *ua.PublishedEventsDataType:
		n = len(src.SelectedFields)
		if len(md.Fields) == 0 {
			for i, sf := range src.SelectedFields {
				name := fmt.Sprintf("Field%d", i)
				if sf != nil && len(sf.BrowsePath) > 0 && sf.BrowsePath[len(sf.BrowsePath)-1] != nil {
					name = sf.BrowsePath[len(sf.BrowsePath)-1].Name
				}
				md.Fields = append(md.Fields, &ua.FieldMetaData{Name: name, BuiltInType: uint8(ua.TypeIDVariant), DataType: ua.NewNumericNodeID(0, 24), ValueRank: -1})
			}
		}
	}
	for i, f := range md.Fields {
		if i >= n {
			break
		}
		if f.Name == "" {
			f.Name = fmt.Sprintf("Field%d", i)
		}
		if f.Description == nil {
			f.Description = &ua.LocalizedText{}
		}
		if f.DataType == nil {
			f.DataType = ua.NewNumericNodeID(0, 24)
		}
		if f.DataSetFieldID == nil || !hasFieldID(f.DataSetFieldID) {
			f.DataSetFieldID = newGUID()
		}
	}
	return md
}

// RemovePublishedDataSet removes a PublishedDataSet and the DataSetWriters
// that publish it.
func (p *PubSub) RemovePublishedDataSet(id ComponentID) error {
	p.lock()
	defer p.unlock()
	d, ok := p.comps[id].(*publishedDataSet)
	if !ok {
		return notFound(KindPublishedDataSet, id)
	}
	for _, c := range p.conns {
		for _, g := range c.wgs {
			for _, w := range append([]*dataSetWriter(nil), g.writers...) {
				if w.pds == d {
					p.removeWriterLocked(w)
				}
			}
		}
	}
	for i, x := range p.pdss {
		if x == d {
			p.pdss = append(p.pdss[:i], p.pdss[i+1:]...)
			break
		}
	}
	delete(p.comps, id)
	p.emit(Event{Type: EventRemoved, Component: d.info()})
	p.reconcileLocked()
	return nil
}

// PublishedDataSetConfig returns the configuration of a PublishedDataSet,
// with its completed DataSetMetaData.
func (p *PubSub) PublishedDataSetConfig(id ComponentID) (*ua.PublishedDataSetDataType, error) {
	p.lock()
	defer p.unlock()
	d, ok := p.comps[id].(*publishedDataSet)
	if !ok {
		return nil, notFound(KindPublishedDataSet, id)
	}
	return d.config(), nil
}

func (p *PubSub) pdsByName(name string) *publishedDataSet {
	for _, d := range p.pdss {
		if d.name == name {
			return d
		}
	}
	return nil
}

func (p *PubSub) pdsNames() dataSets {
	m := make(dataSets, len(p.pdss))
	for _, d := range p.pdss {
		m[d.name] = d.action != nil
	}
	return m
}

// AddConnection adds a PubSubConnection with its groups, writers and
// readers. It returns the id of the connection.
func (p *PubSub) AddConnection(cfg *ua.PubSubConnectionDataType) (ComponentID, error) {
	p.lock()
	defer p.unlock()
	if p.closed {
		return 0, ErrClosed
	}
	id, err := p.addConnectionLocked(cfg)
	if err != nil {
		return 0, err
	}
	p.reconcileLocked()
	return id, nil
}

func (p *PubSub) addConnectionLocked(in *ua.PubSubConnectionDataType) (ComponentID, error) {
	path := "connection"
	if in != nil {
		path = fmt.Sprintf("connection %q", in.Name)
	}
	if err := validateConnection(path, in, p.pdsNames()); err != nil {
		return 0, err
	}
	for _, c := range p.conns {
		if c.name == in.Name {
			return 0, fmt.Errorf("pubsub: %s: duplicate name: %w", path, ua.StatusBadBrowseNameDuplicated)
		}
	}
	cfg, err := clone(in)
	if err != nil {
		return 0, configErr(path, "%v", err)
	}
	wgs, rgs := cfg.WriterGroups, cfg.ReaderGroups
	cfg.WriterGroups, cfg.ReaderGroups = nil, nil
	c := &connection{
		base: base{id: p.newID(), kind: KindConnection, name: cfg.Name, parent: Root, enabled: cfg.Enabled, state: ua.PubSubStateDisabled},
		cfg:  cfg,
	}
	c.pubID, c.hasPub, _ = publisherIDOf(cfg.PublisherID)
	c.url, c.iface, _ = connectionURL(cfg)
	c.broker = isBroker(cfg.TransportProfileURI, c.url)
	c.disc, _ = connectionDiscovery(cfg, c.broker)
	c.shared = !c.broker && sharedAddress(c.url)
	c.reasm = uadp.NewReassembler(p.opts.reassembly)
	c.limiter = newDiscoveryLimiter()
	c.gzip = jsonCompressed(cfg)
	p.conns = append(p.conns, c)
	p.comps[c.id] = c
	p.emit(Event{Type: EventAdded, Component: c.info()})
	for _, g := range wgs {
		if _, err := p.addWriterGroupLocked(c, g); err != nil {
			p.removeConnectionLocked(c)
			return 0, err
		}
	}
	for _, g := range rgs {
		if _, err := p.addReaderGroupLocked(c, g); err != nil {
			p.removeConnectionLocked(c)
			return 0, err
		}
	}
	return c.id, nil
}

// RemoveConnection removes a PubSubConnection with everything it contains.
func (p *PubSub) RemoveConnection(id ComponentID) error {
	p.lock()
	defer p.unlock()
	c, ok := p.comps[id].(*connection)
	if !ok {
		return notFound(KindConnection, id)
	}
	p.removeConnectionLocked(c)
	p.reconcileLocked()
	return nil
}

func (p *PubSub) removeConnectionLocked(c *connection) {
	for _, g := range append([]*writerGroup(nil), c.wgs...) {
		p.removeWriterGroupLocked(g)
	}
	for _, g := range append([]*readerGroup(nil), c.rgs...) {
		p.removeReaderGroupLocked(g)
	}
	p.stopConnection(c)
	for i, x := range p.conns {
		if x == c {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			break
		}
	}
	delete(p.comps, c.id)
	c.state = ua.PubSubStateDisabled
	p.emit(Event{Type: EventRemoved, Component: c.info()})
}

// ConnectionConfig returns the configuration of a connection with its
// groups.
func (p *PubSub) ConnectionConfig(id ComponentID) (*ua.PubSubConnectionDataType, error) {
	p.lock()
	defer p.unlock()
	c, ok := p.comps[id].(*connection)
	if !ok {
		return nil, notFound(KindConnection, id)
	}
	return c.config(), nil
}

// AddWriterGroup adds a WriterGroup (with its DataSetWriters) to a
// connection.
func (p *PubSub) AddWriterGroup(conn ComponentID, cfg *ua.WriterGroupDataType) (ComponentID, error) {
	p.lock()
	defer p.unlock()
	c, ok := p.comps[conn].(*connection)
	if !ok {
		return 0, notFound(KindConnection, conn)
	}
	id, err := p.addWriterGroupLocked(c, cfg)
	if err != nil {
		return 0, err
	}
	p.reconcileLocked()
	return id, nil
}

func (p *PubSub) addWriterGroupLocked(c *connection, in *ua.WriterGroupDataType) (ComponentID, error) {
	path := fmt.Sprintf("connection %q: writer group", c.name)
	if in != nil {
		path = fmt.Sprintf("connection %q: writer group %q", c.name, in.Name)
	}
	if !c.hasPub {
		return 0, configErr(path, "the connection has no PublisherId")
	}
	if err := validateWriterGroup(path, c.cfg.TransportProfileURI, c.broker, in, p.pdsNames()); err != nil {
		return 0, err
	}
	for _, g := range c.wgs {
		if g.name == in.Name {
			return 0, fmt.Errorf("pubsub: %s: duplicate name: %w", path, ua.StatusBadBrowseNameDuplicated)
		}
		if g.cfg.WriterGroupID == in.WriterGroupID {
			return 0, configErr(path, "WriterGroupId %d is used by writer group %q", in.WriterGroupID, g.name)
		}
	}
	cfg, err := clone(in)
	if err != nil {
		return 0, configErr(path, "%v", err)
	}
	writers := cfg.DataSetWriters
	cfg.DataSetWriters = nil
	g := &writerGroup{
		base:      base{id: p.newID(), kind: KindWriterGroup, name: cfg.Name, parent: c.id, enabled: cfg.Enabled, state: ua.PubSubStateDisabled},
		conn:      c,
		cfg:       cfg,
		enc:       groupEncoding(c.cfg.TransportProfileURI, cfg.MessageSettings),
		interval:  duration(cfg.PublishingInterval),
		keepAlive: duration(cfg.KeepAliveTime),
		mode:      securityMode(cfg.SecurityMode),
	}
	g.pubMu.init()
	switch ms := eoValue(cfg.MessageSettings).(type) {
	case *ua.UADPWriterGroupMessageDataType:
		g.uadpMsg = ms
	case *ua.JSONWriterGroupMessageDataType:
		g.jsonMsg = ms
	}
	if g.enc == encUADP {
		if g.uadpMsg == nil {
			g.uadpMsg = &ua.UADPWriterGroupMessageDataType{NetworkMessageContentMask: DefaultUADPNetworkMessageContentMask}
			cfg.MessageSettings = ua.NewExtensionObject(g.uadpMsg)
		}
		if g.uadpMsg.GroupVersion == 0 {
			g.uadpMsg.GroupVersion = versionTime(time.Now())
		}
		if g.uadpMsg.SamplingOffset > 0 {
			g.offset = duration(g.uadpMsg.SamplingOffset)
		}
		if len(g.uadpMsg.PublishingOffset) > 0 && g.uadpMsg.PublishingOffset[0] > 0 {
			g.offset = duration(g.uadpMsg.PublishingOffset[0])
		}
	} else if g.jsonMsg == nil {
		g.jsonMsg = &ua.JSONWriterGroupMessageDataType{NetworkMessageContentMask: DefaultJSONNetworkMessageContentMask}
		cfg.MessageSettings = ua.NewExtensionObject(g.jsonMsg)
	}
	switch ts := eoValue(cfg.TransportSettings).(type) {
	case *ua.BrokerWriterGroupTransportDataType:
		g.brokerTS = ts
	case *ua.DatagramWriterGroupTransportDataType:
		g.dgramTS = ts
	case *ua.DatagramWriterGroupTransport2DataType:
		g.dgramTS = &ua.DatagramWriterGroupTransportDataType{MessageRepeatCount: ts.MessageRepeatCount, MessageRepeatDelay: ts.MessageRepeatDelay}
		g.announce = time.Duration(ts.DiscoveryAnnounceRate) * time.Second
	}
	c.wgs = append(c.wgs, g)
	p.comps[g.id] = g
	p.emit(Event{Type: EventAdded, Component: g.info()})
	for _, w := range writers {
		if _, err := p.addWriterLocked(g, w); err != nil {
			p.removeWriterGroupLocked(g)
			return 0, err
		}
	}
	return g.id, nil
}

// RemoveWriterGroup removes a WriterGroup with its DataSetWriters.
func (p *PubSub) RemoveWriterGroup(id ComponentID) error {
	p.lock()
	defer p.unlock()
	g, ok := p.comps[id].(*writerGroup)
	if !ok {
		return notFound(KindWriterGroup, id)
	}
	p.removeWriterGroupLocked(g)
	p.reconcileLocked()
	return nil
}

func (p *PubSub) removeWriterGroupLocked(g *writerGroup) {
	for _, w := range append([]*dataSetWriter(nil), g.writers...) {
		p.removeWriterLocked(w)
	}
	p.stopWriterGroup(g)
	c := g.conn
	for i, x := range c.wgs {
		if x == g {
			c.wgs = append(c.wgs[:i], c.wgs[i+1:]...)
			break
		}
	}
	delete(p.comps, g.id)
	g.state = ua.PubSubStateDisabled
	p.emit(Event{Type: EventRemoved, Component: g.info()})
}

// WriterGroupConfig returns the configuration of a WriterGroup with its
// writers.
func (p *PubSub) WriterGroupConfig(id ComponentID) (*ua.WriterGroupDataType, error) {
	p.lock()
	defer p.unlock()
	g, ok := p.comps[id].(*writerGroup)
	if !ok {
		return nil, notFound(KindWriterGroup, id)
	}
	return g.config(), nil
}

// AddDataSetWriter adds a DataSetWriter to a WriterGroup. Its DataSetName
// must name an existing PublishedDataSet; an empty DataSetName makes a
// writer that sends only keep-alive messages.
func (p *PubSub) AddDataSetWriter(group ComponentID, cfg *ua.DataSetWriterDataType) (ComponentID, error) {
	p.lock()
	defer p.unlock()
	g, ok := p.comps[group].(*writerGroup)
	if !ok {
		return 0, notFound(KindWriterGroup, group)
	}
	id, err := p.addWriterLocked(g, cfg)
	if err != nil {
		return 0, err
	}
	p.reconcileLocked()
	return id, nil
}

func (p *PubSub) addWriterLocked(g *writerGroup, in *ua.DataSetWriterDataType) (ComponentID, error) {
	path := fmt.Sprintf("writer group %q: writer", g.name)
	if in != nil {
		path = fmt.Sprintf("writer group %q: writer %q", g.name, in.Name)
	}
	if err := validateWriter(path, g.enc, g.conn.broker, in, p.pdsNames()); err != nil {
		return 0, err
	}
	for _, w := range g.writers {
		if w.name == in.Name {
			return 0, fmt.Errorf("pubsub: %s: duplicate name: %w", path, ua.StatusBadBrowseNameDuplicated)
		}
		if w.cfg.DataSetWriterID == in.DataSetWriterID {
			return 0, configErr(path, "DataSetWriterId %d is used by writer %q", in.DataSetWriterID, w.name)
		}
	}
	action := in.DataSetName != "" && p.pdsNames()[in.DataSetName]
	switch {
	case action && g.conn.broker && (g.brokerTS == nil || g.brokerTS.QueueName == ""):
		return 0, configErr(path, "an Action writer needs the QueueName of its group (the request queue)")
	case !action && g.interval <= 0:
		return 0, configErr(path, "a writer group with PublishingInterval 0 only takes Action writers")
	case g.conn.broker && (g.brokerTS == nil || g.brokerTS.QueueName == ""):
		if ts, _ := eoValue(in.TransportSettings).(*ua.BrokerDataSetWriterTransportDataType); ts == nil || ts.QueueName == "" {
			return 0, configErr(path, "neither the writer nor its group has a broker QueueName")
		}
	}
	cfg, err := clone(in)
	if err != nil {
		return 0, configErr(path, "%v", err)
	}
	w := &dataSetWriter{
		base:  base{id: p.newID(), kind: KindDataSetWriter, name: cfg.Name, parent: g.id, enabled: cfg.Enabled, state: ua.PubSubStateDisabled},
		group: g,
		cfg:   cfg,
		seq:   0,
	}
	if cfg.DataSetName != "" {
		w.pds = p.pdsByName(cfg.DataSetName)
	}
	switch ms := eoValue(cfg.MessageSettings).(type) {
	case *ua.UADPDataSetWriterMessageDataType:
		w.uadpMask = ms.DataSetMessageContentMask
	case *ua.JSONDataSetWriterMessageDataType:
		w.jsonMask = ms.DataSetMessageContentMask
	default:
		if g.enc == encJSON {
			w.jsonMask = DefaultJSONDataSetMessageContentMask
			cfg.MessageSettings = ua.NewExtensionObject(&ua.JSONDataSetWriterMessageDataType{DataSetMessageContentMask: w.jsonMask})
		} else {
			w.uadpMask = DefaultUADPDataSetMessageContentMask
			cfg.MessageSettings = ua.NewExtensionObject(&ua.UADPDataSetWriterMessageDataType{DataSetMessageContentMask: w.uadpMask})
		}
	}
	if ts, ok := eoValue(cfg.TransportSettings).(*ua.BrokerDataSetWriterTransportDataType); ok {
		w.brokerTS = ts
	}
	g.writers = append(g.writers, w)
	p.comps[w.id] = w
	p.emit(Event{Type: EventAdded, Component: w.info()})
	return w.id, nil
}

// RemoveDataSetWriter removes a DataSetWriter.
func (p *PubSub) RemoveDataSetWriter(id ComponentID) error {
	p.lock()
	defer p.unlock()
	w, ok := p.comps[id].(*dataSetWriter)
	if !ok {
		return notFound(KindDataSetWriter, id)
	}
	p.removeWriterLocked(w)
	p.reconcileLocked()
	return nil
}

func (p *PubSub) removeWriterLocked(w *dataSetWriter) {
	p.stopWriter(w)
	g := w.group
	for i, x := range g.writers {
		if x == w {
			g.writers = append(g.writers[:i], g.writers[i+1:]...)
			break
		}
	}
	delete(p.comps, w.id)
	w.state = ua.PubSubStateDisabled
	p.emit(Event{Type: EventRemoved, Component: w.info()})
}

// DataSetWriterConfig returns the configuration of a DataSetWriter.
func (p *PubSub) DataSetWriterConfig(id ComponentID) (*ua.DataSetWriterDataType, error) {
	p.lock()
	defer p.unlock()
	w, ok := p.comps[id].(*dataSetWriter)
	if !ok {
		return nil, notFound(KindDataSetWriter, id)
	}
	return w.config(), nil
}

// AddReaderGroup adds a ReaderGroup (with its DataSetReaders) to a
// connection.
func (p *PubSub) AddReaderGroup(conn ComponentID, cfg *ua.ReaderGroupDataType) (ComponentID, error) {
	p.lock()
	defer p.unlock()
	c, ok := p.comps[conn].(*connection)
	if !ok {
		return 0, notFound(KindConnection, conn)
	}
	id, err := p.addReaderGroupLocked(c, cfg)
	if err != nil {
		return 0, err
	}
	p.reconcileLocked()
	return id, nil
}

func (p *PubSub) addReaderGroupLocked(c *connection, in *ua.ReaderGroupDataType) (ComponentID, error) {
	path := fmt.Sprintf("connection %q: reader group", c.name)
	if in != nil {
		path = fmt.Sprintf("connection %q: reader group %q", c.name, in.Name)
	}
	if err := validateReaderGroup(path, c.cfg.TransportProfileURI, c.broker, in); err != nil {
		return 0, err
	}
	for _, g := range c.rgs {
		if g.name == in.Name {
			return 0, fmt.Errorf("pubsub: %s: duplicate name: %w", path, ua.StatusBadBrowseNameDuplicated)
		}
	}
	cfg, err := clone(in)
	if err != nil {
		return 0, configErr(path, "%v", err)
	}
	readers := cfg.DataSetReaders
	cfg.DataSetReaders = nil
	g := &readerGroup{
		base: base{id: p.newID(), kind: KindReaderGroup, name: cfg.Name, parent: c.id, enabled: cfg.Enabled, state: ua.PubSubStateDisabled},
		conn: c,
		cfg:  cfg,
	}
	c.rgs = append(c.rgs, g)
	p.comps[g.id] = g
	p.emit(Event{Type: EventAdded, Component: g.info()})
	for _, r := range readers {
		if _, err := p.addReaderLocked(g, r); err != nil {
			p.removeReaderGroupLocked(g)
			return 0, err
		}
	}
	return g.id, nil
}

// RemoveReaderGroup removes a ReaderGroup with its DataSetReaders.
func (p *PubSub) RemoveReaderGroup(id ComponentID) error {
	p.lock()
	defer p.unlock()
	g, ok := p.comps[id].(*readerGroup)
	if !ok {
		return notFound(KindReaderGroup, id)
	}
	p.removeReaderGroupLocked(g)
	p.reconcileLocked()
	return nil
}

func (p *PubSub) removeReaderGroupLocked(g *readerGroup) {
	for _, r := range append([]*dataSetReader(nil), g.readers...) {
		p.removeReaderLocked(r)
	}
	c := g.conn
	for i, x := range c.rgs {
		if x == g {
			c.rgs = append(c.rgs[:i], c.rgs[i+1:]...)
			break
		}
	}
	delete(p.comps, g.id)
	g.state = ua.PubSubStateDisabled
	p.emit(Event{Type: EventRemoved, Component: g.info()})
}

// RemoveGroup removes a WriterGroup or a ReaderGroup (PubSubConnectionType
// RemoveGroup).
func (p *PubSub) RemoveGroup(id ComponentID) error {
	p.lock()
	defer p.unlock()
	switch g := p.comps[id].(type) {
	case *writerGroup:
		p.removeWriterGroupLocked(g)
	case *readerGroup:
		p.removeReaderGroupLocked(g)
	default:
		return fmt.Errorf("pubsub: no group with id %d: %w", id, ua.StatusBadNotFound)
	}
	p.reconcileLocked()
	return nil
}

// ReaderGroupConfig returns the configuration of a ReaderGroup with its
// readers.
func (p *PubSub) ReaderGroupConfig(id ComponentID) (*ua.ReaderGroupDataType, error) {
	p.lock()
	defer p.unlock()
	g, ok := p.comps[id].(*readerGroup)
	if !ok {
		return nil, notFound(KindReaderGroup, id)
	}
	return g.config(), nil
}

// AddDataSetReader adds a DataSetReader to a ReaderGroup.
func (p *PubSub) AddDataSetReader(group ComponentID, cfg *ua.DataSetReaderDataType) (ComponentID, error) {
	p.lock()
	defer p.unlock()
	g, ok := p.comps[group].(*readerGroup)
	if !ok {
		return 0, notFound(KindReaderGroup, group)
	}
	id, err := p.addReaderLocked(g, cfg)
	if err != nil {
		return 0, err
	}
	p.reconcileLocked()
	return id, nil
}

func (p *PubSub) addReaderLocked(g *readerGroup, in *ua.DataSetReaderDataType) (ComponentID, error) {
	path := fmt.Sprintf("reader group %q: reader", g.name)
	if in != nil {
		path = fmt.Sprintf("reader group %q: reader %q", g.name, in.Name)
	}
	if err := validateReader(path, g.conn.cfg.TransportProfileURI, g.conn.broker, in); err != nil {
		return 0, err
	}
	for _, r := range g.readers {
		if r.name == in.Name {
			return 0, fmt.Errorf("pubsub: %s: duplicate name: %w", path, ua.StatusBadBrowseNameDuplicated)
		}
	}
	if g.conn.broker {
		if ts, _ := eoValue(in.TransportSettings).(*ua.BrokerDataSetReaderTransportDataType); ts == nil || ts.QueueName == "" {
			return 0, configErr(path, "a reader on a broker connection needs a BrokerDataSetReaderTransportDataType with a QueueName")
		}
	}
	cfg, err := clone(in)
	if err != nil {
		return 0, configErr(path, "%v", err)
	}
	r := &dataSetReader{
		base:    base{id: p.newID(), kind: KindDataSetReader, name: cfg.Name, parent: g.id, enabled: cfg.Enabled, state: ua.PubSubStateDisabled},
		group:   g,
		cfg:     cfg,
		enc:     readerEncoding(g.conn.cfg.TransportProfileURI, cfg.MessageSettings),
		timeout: duration(cfg.MessageReceiveTimeout),
		md:      cfg.DataSetMetaData,
		streams: map[streamKey]*stream{},
	}
	r.pub, r.hasPub, _ = publisherIDOf(cfg.PublisherID)
	if ts, ok := eoValue(cfg.TransportSettings).(*ua.BrokerDataSetReaderTransportDataType); ok {
		r.brokerTS = ts
	}
	// A reader with a SecurityMode of its own overrides the security of its
	// group; a SecurityGroupId alone (with SecurityMode Invalid or None)
	// does not lower it.
	r.mode, r.groupID = securityMode(g.cfg.SecurityMode), g.cfg.SecurityGroupID
	if securityMode(cfg.SecurityMode) > ua.MessageSecurityModeNone {
		r.mode, r.groupID = securityMode(cfg.SecurityMode), cfg.SecurityGroupID
	}
	switch sds := eoValue(cfg.SubscribedDataSet).(type) {
	case *ua.TargetVariablesDataType:
		r.targets = sds.TargetVariables
		r.lastGood = make([]*ua.DataValue, len(r.targets))
	case *ua.SubscribedDataSetMirrorDataType:
		r.mirror = sds
	}
	g.readers = append(g.readers, r)
	p.comps[r.id] = r
	p.emit(Event{Type: EventAdded, Component: r.info()})
	return r.id, nil
}

// RemoveDataSetReader removes a DataSetReader.
func (p *PubSub) RemoveDataSetReader(id ComponentID) error {
	p.lock()
	defer p.unlock()
	r, ok := p.comps[id].(*dataSetReader)
	if !ok {
		return notFound(KindDataSetReader, id)
	}
	p.removeReaderLocked(r)
	p.reconcileLocked()
	return nil
}

func (p *PubSub) removeReaderLocked(r *dataSetReader) {
	p.stopReader(r, false)
	g := r.group
	for i, x := range g.readers {
		if x == r {
			g.readers = append(g.readers[:i], g.readers[i+1:]...)
			break
		}
	}
	delete(p.comps, r.id)
	r.state = ua.PubSubStateDisabled
	p.emit(Event{Type: EventRemoved, Component: r.info()})
}

// DataSetReaderConfig returns the configuration of a DataSetReader, with the
// DataSetMetaData it currently uses.
func (p *PubSub) DataSetReaderConfig(id ComponentID) (*ua.DataSetReaderDataType, error) {
	p.lock()
	defer p.unlock()
	r, ok := p.comps[id].(*dataSetReader)
	if !ok {
		return nil, notFound(KindDataSetReader, id)
	}
	return r.config(), nil
}
