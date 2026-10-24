// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"cmp"
	"fmt"
	"maps"
	"slices"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// The operation bits of a PubSubConfigurationRefMask (Part 14 §9.1.3.7.2).
const refOps = ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskElementMatch |
	ua.PubSubConfigurationRefMaskElementModify | ua.PubSubConfigurationRefMaskElementRemove

// configPath locates the element of a reference in the configuration after
// CloseAndUpdate: a kind and the names from the connection (or the published
// data set) down. A path without names has no object.
type configPath struct {
	kind  pubsub.ComponentKind
	names []string
}

// configUpdate applies the element operations of CloseAndUpdate to a copy of
// the configuration, which must be valid in the end; reconcilePubSub then
// brings the runtime to the result.
type configUpdate struct {
	file *ua.PubSubConfiguration2DataType
	cfg  *ua.PubSubConfigurationDataType

	defaultPublisherID *ua.Variant
	usedGroups         map[uint16]bool
	usedWriters        map[uint16]bool

	// The connections and groups of the file that an operation added or
	// matched, by their indices in the file.
	conns map[uint16]*ua.PubSubConnectionDataType
	wgs   map[[2]uint16]*ua.WriterGroupDataType
	rgs   map[[2]uint16]*ua.ReaderGroupDataType

	changed, failed bool
	matched         bool // set by apply when it matched an element
	values          []*ua.PubSubConfigurationValueDataType
	paths           []configPath
}

func newConfigUpdate(file *ua.PubSubConfiguration2DataType, cfg *ua.PubSubConfigurationDataType, pub *ua.Variant, usedGroups, usedWriters map[uint16]bool) *configUpdate {
	return &configUpdate{
		file: file, cfg: cloneConfig(cfg), defaultPublisherID: pub,
		usedGroups: usedGroups, usedWriters: usedWriters,
		conns: map[uint16]*ua.PubSubConnectionDataType{},
		wgs:   map[[2]uint16]*ua.WriterGroupDataType{},
		rgs:   map[[2]uint16]*ua.ReaderGroupDataType{},
	}
}

// cloneConfig returns a deep copy of a configuration.
func cloneConfig(cfg *ua.PubSubConfigurationDataType) *ua.PubSubConfigurationDataType {
	b, err := ua.Encode(cfg)
	if err != nil {
		panic(fmt.Sprintf("server: pubsub: encoding the configuration: %v", err))
	}
	out := &ua.PubSubConfigurationDataType{}
	if _, err := ua.Decode(b, out); err != nil {
		panic(fmt.Sprintf("server: pubsub: decoding the configuration: %v", err))
	}
	return out
}

// sameEncoding reports whether a and b have the same UA Binary encoding.
func sameEncoding(a, b any) bool {
	x, err1 := ua.Encode(a)
	y, err2 := ua.Encode(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// refLevel orders the operations so that parents come before children.
func refLevel(m ua.PubSubConfigurationRefMask) int {
	switch {
	case m&ua.PubSubConfigurationRefMaskReferencePubDataset != 0:
		return 0
	case m&ua.PubSubConfigurationRefMaskReferenceConnection != 0:
		return 1
	case m&(ua.PubSubConfigurationRefMaskReferenceWriterGroup|ua.PubSubConfigurationRefMaskReferenceReaderGroup) != 0:
		return 2
	}
	return 3
}

// run applies the references: the removals first, then the others with
// parents before children (Part 14 §9.1.3.7.6). It returns a result per
// reference.
func (u *configUpdate) run(refs []*ua.PubSubConfigurationRefDataType) []ua.StatusCode {
	results := make([]ua.StatusCode, len(refs))
	u.paths = make([]configPath, len(refs))
	order := make([]int, len(refs))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		ra := refs[a].ConfigurationMask&ua.PubSubConfigurationRefMaskElementRemove != 0
		rb := refs[b].ConfigurationMask&ua.PubSubConfigurationRefMaskElementRemove != 0
		if ra != rb {
			if ra {
				return -1
			}
			return 1
		}
		return cmp.Compare(refLevel(refs[a].ConfigurationMask), refLevel(refs[b].ConfigurationMask))
	})
	// The operations that changed the configuration, in the order applied.
	type done struct {
		i    int
		undo func()
	}
	var stack []done
	for _, i := range order {
		u.matched = false
		sc, path, v, undo := u.apply(refs[i])
		results[i] = sc
		if sc != ua.StatusOK {
			u.failed = true
			continue
		}
		u.paths[i] = path
		if v != nil {
			v.ConfigurationElement = refs[i]
			u.values = append(u.values, v)
		}
		if !u.matched {
			stack = append(stack, done{i, undo})
		}
	}
	// The result must be valid. An element may need others of the same
	// update (a WriterGroup of Actions without a PublishingInterval its
	// writers), so only the result is checked; while it is not valid the
	// last operation is undone and fails.
	for len(stack) > 0 && pubsub.Validate(u.cfg) != nil {
		d := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		d.undo()
		results[d.i] = ua.StatusBadConfigurationError
		u.paths[d.i] = configPath{}
		u.values = slices.DeleteFunc(u.values, func(v *ua.PubSubConfigurationValueDataType) bool { return v.ConfigurationElement == refs[d.i] })
		u.failed = true
	}
	u.changed = len(stack) > 0
	return results
}

// apply applies one reference and returns how to undo it.
func (u *configUpdate) apply(r *ua.PubSubConfigurationRefDataType) (ua.StatusCode, configPath, *ua.PubSubConfigurationValueDataType, func()) {
	m := r.ConfigurationMask
	kinds := 0
	for b := ua.PubSubConfigurationRefMaskReferenceWriter; b <= ua.PubSubConfigurationRefMaskReferencePushTarget; b <<= 1 {
		if m&b != 0 {
			kinds++
		}
	}
	op := m & refOps
	add, match := op&ua.PubSubConfigurationRefMaskElementAdd != 0, op&ua.PubSubConfigurationRefMaskElementMatch != 0
	switch {
	case kinds != 1 || m&^(refOps|(ua.PubSubConfigurationRefMaskReferencePushTarget<<1-ua.PubSubConfigurationRefMaskReferenceWriter)) != 0:
		return ua.StatusBadInvalidArgument, configPath{}, nil, nil
	case op == ua.PubSubConfigurationRefMaskElementAdd, op == ua.PubSubConfigurationRefMaskElementMatch,
		op == ua.PubSubConfigurationRefMaskElementAdd|ua.PubSubConfigurationRefMaskElementMatch,
		op == ua.PubSubConfigurationRefMaskElementModify, op == ua.PubSubConfigurationRefMaskElementRemove:
	default:
		return ua.StatusBadInvalidArgument, configPath{}, nil, nil
	}
	if match && m&(ua.PubSubConfigurationRefMaskReferenceConnection|ua.PubSubConfigurationRefMaskReferenceWriterGroup|ua.PubSubConfigurationRefMaskReferenceReaderGroup) == 0 {
		return ua.StatusBadInvalidArgument, configPath{}, nil, nil
	}
	var e *element
	var sc ua.StatusCode
	switch {
	case m&ua.PubSubConfigurationRefMaskReferencePubDataset != 0:
		e, sc = u.pdsElement(r)
	case m&ua.PubSubConfigurationRefMaskReferenceConnection != 0:
		e, sc = u.connElement(r)
	case m&ua.PubSubConfigurationRefMaskReferenceWriterGroup != 0:
		e, sc = u.writerGroupElement(r)
	case m&ua.PubSubConfigurationRefMaskReferenceReaderGroup != 0:
		e, sc = u.readerGroupElement(r)
	case m&ua.PubSubConfigurationRefMaskReferenceWriter != 0:
		e, sc = u.writerElement(r)
	case m&ua.PubSubConfigurationRefMaskReferenceReader != 0:
		e, sc = u.readerElement(r)
	default:
		// SubscribedDataSets, SecurityGroups and PubSubKeyPushTargets are
		// not part of the configuration of the runtime.
		return ua.StatusBadNotSupported, configPath{}, nil, nil
	}
	if sc != ua.StatusOK {
		return sc, configPath{}, nil, nil
	}

	var undo func()
	switch op {
	case ua.PubSubConfigurationRefMaskElementRemove:
		if undo = e.remove(); undo == nil {
			return ua.StatusBadNoMatch, configPath{}, nil, nil
		}
		e.path.names = nil
	case ua.PubSubConfigurationRefMaskElementModify:
		if undo = e.modify(); undo == nil {
			return ua.StatusBadNoMatch, configPath{}, nil, nil
		}
	default:
		if match {
			if sc := e.match(); sc != ua.StatusBadNoMatch || !add {
				if sc != ua.StatusOK {
					return sc, configPath{}, nil, nil
				}
				// A match changes nothing.
				u.matched = true
				return ua.StatusOK, e.path, e.value(), nil
			}
		}
		if e.exists() {
			return ua.StatusBadBrowseNameDuplicated, configPath{}, nil, nil
		}
		undo, sc = e.add()
		if sc != ua.StatusOK {
			return sc, configPath{}, nil, nil
		}
	}
	if e.commit != nil && op != ua.PubSubConfigurationRefMaskElementRemove {
		conns, wgs, rgs := maps.Clone(u.conns), maps.Clone(u.wgs), maps.Clone(u.rgs)
		e.commit()
		configUndo := undo
		undo = func() {
			u.conns, u.wgs, u.rgs = conns, wgs, rgs
			configUndo()
		}
	}
	var v *ua.PubSubConfigurationValueDataType
	if add {
		v = e.value()
	}
	return ua.StatusOK, e.path, v, undo
}

// element is the target of a reference, with the operations on it.
type element struct {
	path   configPath
	exists func() bool
	add    func() (func(), ua.StatusCode)
	match  func() ua.StatusCode
	modify func() func() // nil without an element of the name
	remove func() func()
	value  func() *ua.PubSubConfigurationValueDataType
	// commit records an added or matched parent.
	commit func()
}

func configValue(n string) *ua.PubSubConfigurationValueDataType {
	return &ua.PubSubConfigurationValueDataType{Name: n, Identifier: ua.MustVariant(nil)}
}

// uniqueName returns base followed by the lowest number that taken does not
// have.
func uniqueName(base string, taken func(string) bool) string {
	for i := 1; ; i++ {
		if n := fmt.Sprintf("%s%d", base, i); !taken(n) {
			return n
		}
	}
}

func fileElem[T any](xs []*T, i uint16) (*T, bool) {
	if int(i) >= len(xs) || xs[i] == nil {
		return nil, false
	}
	return xs[i], true
}

func findByName[T any](xs []*T, n string, nameOf func(*T) string) int {
	return slices.IndexFunc(xs, func(x *T) bool { return x != nil && nameOf(x) == n })
}

// removeAt returns an undo of removing element i of *xs.
func removeAt[T any](xs *[]*T, i int) func() {
	old := slices.Clone(*xs)
	*xs = slices.Delete(*xs, i, i+1)
	return func() { *xs = old }
}

func appendTo[T any](xs *[]*T, x *T) func() {
	old := *xs
	*xs = append(slices.Clone(*xs), x)
	return func() { *xs = old }
}

// replace returns an undo of setting *dst to v.
func replace[T any](dst *T, v T) func() {
	old := *dst
	*dst = v
	return func() { *dst = old }
}

func (u *configUpdate) pdsElement(r *ua.PubSubConfigurationRefDataType) (*element, ua.StatusCode) {
	in, ok := fileElem(u.file.PublishedDataSets, r.ElementIndex)
	if !ok {
		return nil, ua.StatusBadInvalidArgument
	}
	nameOf := func(d *ua.PublishedDataSetDataType) string { return d.Name }
	cp := *in
	e := &element{path: configPath{kind: pubsub.KindPublishedDataSet}}
	at := func() int { return findByName(u.cfg.PublishedDataSets, cp.Name, nameOf) }
	e.exists = func() bool { return at() >= 0 }
	e.add = func() (func(), ua.StatusCode) {
		if cp.Name == "" {
			cp.Name = uniqueName("PublishedDataSet", func(n string) bool { return findByName(u.cfg.PublishedDataSets, n, nameOf) >= 0 })
		}
		if at() >= 0 {
			return nil, ua.StatusBadBrowseNameDuplicated
		}
		e.path.names = []string{cp.Name}
		return appendTo(&u.cfg.PublishedDataSets, &cp), ua.StatusOK
	}
	e.modify = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		e.path.names = []string{cp.Name}
		return replace(u.cfg.PublishedDataSets[i], cp)
	}
	e.remove = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		undo := removeAt(&u.cfg.PublishedDataSets, i)
		// The writers of a removed data set are removed with it.
		var undos []func()
		for _, c := range u.cfg.Connections {
			for _, g := range c.WriterGroups {
				old := g.DataSetWriters
				g.DataSetWriters = slices.DeleteFunc(slices.Clone(old), func(w *ua.DataSetWriterDataType) bool { return w.DataSetName == cp.Name })
				undos = append(undos, func() { g.DataSetWriters = old })
			}
		}
		return func() {
			for _, f := range undos {
				f()
			}
			undo()
		}
	}
	e.value = func() *ua.PubSubConfigurationValueDataType { return configValue(cp.Name) }
	return e, ua.StatusOK
}

// connMatches compares the connection parameters Part 14 §9.1.3.7.2 lists for
// ElementMatch: TransportProfileUri, Address and TransportSettings, and the
// ConnectionProperties the file has.
func connMatches(have, want *ua.PubSubConnectionDataType) bool {
	return have.TransportProfileURI == want.TransportProfileURI &&
		sameEncoding(have.Address, want.Address) && sameEncoding(have.TransportSettings, want.TransportSettings) &&
		hasProperties(have.ConnectionProperties, want.ConnectionProperties)
}

func hasProperties(have, want []*ua.KeyValuePair) bool {
	for _, w := range want {
		if w == nil {
			continue
		}
		if !slices.ContainsFunc(have, func(h *ua.KeyValuePair) bool {
			return h != nil && sameEncoding(h, w)
		}) {
			return false
		}
	}
	return true
}

func (u *configUpdate) connElement(r *ua.PubSubConfigurationRefDataType) (*element, ua.StatusCode) {
	ci := r.ConnectionIndex
	in, ok := fileElem(u.file.Connections, ci)
	if !ok {
		return nil, ua.StatusBadInvalidArgument
	}
	nameOf := func(c *ua.PubSubConnectionDataType) string { return c.Name }
	cp := *in
	cp.WriterGroups, cp.ReaderGroups = nil, nil
	e := &element{path: configPath{kind: pubsub.KindConnection}}
	at := func() int { return findByName(u.cfg.Connections, cp.Name, nameOf) }
	var got *ua.PubSubConnectionDataType
	e.exists = func() bool { return at() >= 0 }
	e.add = func() (func(), ua.StatusCode) {
		if cp.Name == "" {
			cp.Name = uniqueName("Connection", func(n string) bool { return findByName(u.cfg.Connections, n, nameOf) >= 0 })
		}
		if at() >= 0 {
			return nil, ua.StatusBadBrowseNameDuplicated
		}
		if cp.PublisherID == nil || cp.PublisherID.Value() == nil {
			cp.PublisherID = u.defaultPublisherID
		}
		got = &cp
		return appendTo(&u.cfg.Connections, got), ua.StatusOK
	}
	e.match = func() ua.StatusCode {
		for _, c := range u.cfg.Connections {
			if connMatches(c, in) {
				got = c
				u.conns[ci] = c
				e.path.names = []string{c.Name}
				return ua.StatusOK
			}
		}
		return ua.StatusBadNoMatch
	}
	e.modify = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		c := u.cfg.Connections[i]
		n := cp
		n.WriterGroups, n.ReaderGroups = c.WriterGroups, c.ReaderGroups
		if n.PublisherID == nil || n.PublisherID.Value() == nil {
			n.PublisherID = c.PublisherID
		}
		got = c
		return replace(c, n)
	}
	e.remove = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		return removeAt(&u.cfg.Connections, i)
	}
	e.commit = func() {
		u.conns[ci] = got
		e.path.names = []string{got.Name}
	}
	e.value = func() *ua.PubSubConfigurationValueDataType {
		v := configValue(got.Name)
		v.Identifier = got.PublisherID
		return v
	}
	return e, ua.StatusOK
}

// parentConn returns the connection of index ci of the file in the
// configuration: the one added or matched for it, else the one of its name.
func (u *configUpdate) parentConn(ci uint16) (*ua.PubSubConnectionDataType, *ua.PubSubConnectionDataType, ua.StatusCode) {
	in, ok := fileElem(u.file.Connections, ci)
	if !ok {
		return nil, nil, ua.StatusBadInvalidArgument
	}
	if c := u.conns[ci]; c != nil {
		return in, c, ua.StatusOK
	}
	if i := findByName(u.cfg.Connections, in.Name, func(c *ua.PubSubConnectionDataType) string { return c.Name }); i >= 0 {
		return in, u.cfg.Connections[i], ua.StatusOK
	}
	return in, nil, ua.StatusBadNotFound
}

// groupNameTaken reports whether a group of c has the name n.
func groupNameTaken(c *ua.PubSubConnectionDataType, n string) bool {
	return findByName(c.WriterGroups, n, func(g *ua.WriterGroupDataType) string { return g.Name }) >= 0 ||
		findByName(c.ReaderGroups, n, func(g *ua.ReaderGroupDataType) string { return g.Name }) >= 0
}

// groupHeaderActive reports whether a WriterGroup sends the GroupHeader:
// such a group cannot be matched (Part 14 §9.1.3.7.2).
func groupHeaderActive(g *ua.WriterGroupDataType) bool {
	if g.MessageSettings == nil {
		return false
	}
	m, ok := g.MessageSettings.Value.(*ua.UADPWriterGroupMessageDataType)
	return ok && m.NetworkMessageContentMask&ua.UADPNetworkMessageContentMaskGroupHeader != 0
}

// writerGroupMatches compares the parameters Part 14 §9.1.3.7.2 lists for a
// WriterGroup.
func writerGroupMatches(have, want *ua.WriterGroupDataType) bool {
	key := func(g *ua.WriterGroupDataType) *ua.WriterGroupDataType {
		return &ua.WriterGroupDataType{
			SecurityMode: g.SecurityMode, SecurityGroupID: g.SecurityGroupID, SecurityKeyServices: g.SecurityKeyServices,
			MaxNetworkMessageSize: g.MaxNetworkMessageSize, PublishingInterval: g.PublishingInterval,
			KeepAliveTime: g.KeepAliveTime, Priority: g.Priority, HeaderLayoutURI: g.HeaderLayoutURI,
			TransportSettings: g.TransportSettings, MessageSettings: g.MessageSettings,
		}
	}
	return sameEncoding(key(have), key(want)) && hasProperties(have.GroupProperties, want.GroupProperties)
}

func readerGroupMatches(have, want *ua.ReaderGroupDataType) bool {
	key := func(g *ua.ReaderGroupDataType) *ua.ReaderGroupDataType {
		return &ua.ReaderGroupDataType{
			SecurityMode: g.SecurityMode, SecurityGroupID: g.SecurityGroupID, SecurityKeyServices: g.SecurityKeyServices,
			MaxNetworkMessageSize: g.MaxNetworkMessageSize, TransportSettings: g.TransportSettings, MessageSettings: g.MessageSettings,
		}
	}
	return sameEncoding(key(have), key(want)) && hasProperties(have.GroupProperties, want.GroupProperties)
}

func (u *configUpdate) writerGroupElement(r *ua.PubSubConfigurationRefDataType) (*element, ua.StatusCode) {
	inConn, c, sc := u.parentConn(r.ConnectionIndex)
	if inConn == nil {
		return nil, sc
	}
	in, ok := fileElem(inConn.WriterGroups, r.GroupIndex)
	if !ok {
		return nil, ua.StatusBadInvalidArgument
	}
	if sc != ua.StatusOK {
		return nil, sc
	}
	key := [2]uint16{r.ConnectionIndex, r.GroupIndex}
	nameOf := func(g *ua.WriterGroupDataType) string { return g.Name }
	cp := *in
	cp.DataSetWriters = nil
	e := &element{path: configPath{kind: pubsub.KindWriterGroup}}
	at := func() int { return findByName(c.WriterGroups, cp.Name, nameOf) }
	var got *ua.WriterGroupDataType
	e.exists = func() bool { return groupNameTaken(c, cp.Name) }
	e.add = func() (func(), ua.StatusCode) {
		if cp.Name == "" {
			cp.Name = uniqueName("WriterGroup", func(n string) bool { return groupNameTaken(c, n) })
		}
		if groupNameTaken(c, cp.Name) {
			return nil, ua.StatusBadBrowseNameDuplicated
		}
		if cp.WriterGroupID == 0 {
			x, ok := allocID(u.usedGroups)
			if !ok {
				return nil, ua.StatusBadResourceUnavailable
			}
			cp.WriterGroupID = x
		}
		got = &cp
		return appendTo(&c.WriterGroups, got), ua.StatusOK
	}
	e.match = func() ua.StatusCode {
		for _, g := range c.WriterGroups {
			if writerGroupMatches(g, in) {
				if groupHeaderActive(g) {
					return ua.StatusBadInvalidState
				}
				u.wgs[key] = g
				e.path.names = []string{c.Name, g.Name}
				got = g
				return ua.StatusOK
			}
		}
		return ua.StatusBadNoMatch
	}
	e.modify = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		g := c.WriterGroups[i]
		n := cp
		n.DataSetWriters = g.DataSetWriters
		if n.WriterGroupID == 0 {
			n.WriterGroupID = g.WriterGroupID
		}
		got = g
		return replace(g, n)
	}
	e.remove = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		return removeAt(&c.WriterGroups, i)
	}
	e.commit = func() {
		u.wgs[key] = got
		u.usedGroups[got.WriterGroupID] = true
		e.path.names = []string{c.Name, got.Name}
	}
	e.value = func() *ua.PubSubConfigurationValueDataType {
		v := configValue(got.Name)
		v.Identifier = ua.MustVariant(got.WriterGroupID)
		return v
	}
	return e, ua.StatusOK
}

func (u *configUpdate) readerGroupElement(r *ua.PubSubConfigurationRefDataType) (*element, ua.StatusCode) {
	inConn, c, sc := u.parentConn(r.ConnectionIndex)
	if inConn == nil {
		return nil, sc
	}
	in, ok := fileElem(inConn.ReaderGroups, r.GroupIndex)
	if !ok {
		return nil, ua.StatusBadInvalidArgument
	}
	if sc != ua.StatusOK {
		return nil, sc
	}
	key := [2]uint16{r.ConnectionIndex, r.GroupIndex}
	nameOf := func(g *ua.ReaderGroupDataType) string { return g.Name }
	cp := *in
	cp.DataSetReaders = nil
	e := &element{path: configPath{kind: pubsub.KindReaderGroup}}
	at := func() int { return findByName(c.ReaderGroups, cp.Name, nameOf) }
	var got *ua.ReaderGroupDataType
	e.exists = func() bool { return groupNameTaken(c, cp.Name) }
	e.add = func() (func(), ua.StatusCode) {
		if cp.Name == "" {
			cp.Name = uniqueName("ReaderGroup", func(n string) bool { return groupNameTaken(c, n) })
		}
		if groupNameTaken(c, cp.Name) {
			return nil, ua.StatusBadBrowseNameDuplicated
		}
		got = &cp
		return appendTo(&c.ReaderGroups, got), ua.StatusOK
	}
	e.match = func() ua.StatusCode {
		for _, g := range c.ReaderGroups {
			if readerGroupMatches(g, in) {
				u.rgs[key] = g
				e.path.names = []string{c.Name, g.Name}
				got = g
				return ua.StatusOK
			}
		}
		return ua.StatusBadNoMatch
	}
	e.modify = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		g := c.ReaderGroups[i]
		n := cp
		n.DataSetReaders = g.DataSetReaders
		got = g
		return replace(g, n)
	}
	e.remove = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		return removeAt(&c.ReaderGroups, i)
	}
	e.commit = func() {
		u.rgs[key] = got
		e.path.names = []string{c.Name, got.Name}
	}
	e.value = func() *ua.PubSubConfigurationValueDataType { return configValue(got.Name) }
	return e, ua.StatusOK
}

// parentWriterGroup returns the WriterGroup of indices ci, gi of the file in
// the configuration.
func (u *configUpdate) parentWriterGroup(ci, gi uint16) (*ua.WriterGroupDataType, *ua.PubSubConnectionDataType, *ua.WriterGroupDataType, ua.StatusCode) {
	inConn, c, sc := u.parentConn(ci)
	if inConn == nil {
		return nil, nil, nil, sc
	}
	in, ok := fileElem(inConn.WriterGroups, gi)
	if !ok {
		return nil, nil, nil, ua.StatusBadInvalidArgument
	}
	if g := u.wgs[[2]uint16{ci, gi}]; g != nil {
		return in, c, g, ua.StatusOK
	}
	if sc != ua.StatusOK {
		return in, nil, nil, sc
	}
	if i := findByName(c.WriterGroups, in.Name, func(g *ua.WriterGroupDataType) string { return g.Name }); i >= 0 {
		return in, c, c.WriterGroups[i], ua.StatusOK
	}
	return in, nil, nil, ua.StatusBadNotFound
}

func (u *configUpdate) parentReaderGroup(ci, gi uint16) (*ua.ReaderGroupDataType, *ua.PubSubConnectionDataType, *ua.ReaderGroupDataType, ua.StatusCode) {
	inConn, c, sc := u.parentConn(ci)
	if inConn == nil {
		return nil, nil, nil, sc
	}
	in, ok := fileElem(inConn.ReaderGroups, gi)
	if !ok {
		return nil, nil, nil, ua.StatusBadInvalidArgument
	}
	if g := u.rgs[[2]uint16{ci, gi}]; g != nil {
		return in, c, g, ua.StatusOK
	}
	if sc != ua.StatusOK {
		return in, nil, nil, sc
	}
	if i := findByName(c.ReaderGroups, in.Name, func(g *ua.ReaderGroupDataType) string { return g.Name }); i >= 0 {
		return in, c, c.ReaderGroups[i], ua.StatusOK
	}
	return in, nil, nil, ua.StatusBadNotFound
}

func (u *configUpdate) writerElement(r *ua.PubSubConfigurationRefDataType) (*element, ua.StatusCode) {
	inGroup, c, g, sc := u.parentWriterGroup(r.ConnectionIndex, r.GroupIndex)
	if inGroup == nil {
		return nil, sc
	}
	in, ok := fileElem(inGroup.DataSetWriters, r.ElementIndex)
	if !ok {
		return nil, ua.StatusBadInvalidArgument
	}
	if sc != ua.StatusOK {
		return nil, sc
	}
	nameOf := func(w *ua.DataSetWriterDataType) string { return w.Name }
	cp := *in
	e := &element{path: configPath{kind: pubsub.KindDataSetWriter}}
	at := func() int { return findByName(g.DataSetWriters, cp.Name, nameOf) }
	e.exists = func() bool { return at() >= 0 }
	e.add = func() (func(), ua.StatusCode) {
		if cp.Name == "" {
			cp.Name = uniqueName("DataSetWriter", func(n string) bool { return findByName(g.DataSetWriters, n, nameOf) >= 0 })
		}
		if at() >= 0 {
			return nil, ua.StatusBadBrowseNameDuplicated
		}
		if cp.DataSetWriterID == 0 {
			x, ok := allocID(u.usedWriters)
			if !ok {
				return nil, ua.StatusBadResourceUnavailable
			}
			cp.DataSetWriterID = x
		}
		return appendTo(&g.DataSetWriters, &cp), ua.StatusOK
	}
	e.modify = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		w := g.DataSetWriters[i]
		n := cp
		if n.DataSetWriterID == 0 {
			n.DataSetWriterID = w.DataSetWriterID
		}
		return replace(w, n)
	}
	e.remove = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		return removeAt(&g.DataSetWriters, i)
	}
	e.commit = func() {
		u.usedWriters[cp.DataSetWriterID] = true
		e.path.names = []string{c.Name, g.Name, cp.Name}
	}
	e.value = func() *ua.PubSubConfigurationValueDataType {
		v := configValue(cp.Name)
		v.Identifier = ua.MustVariant(cp.DataSetWriterID)
		return v
	}
	return e, ua.StatusOK
}

func (u *configUpdate) readerElement(r *ua.PubSubConfigurationRefDataType) (*element, ua.StatusCode) {
	inGroup, c, g, sc := u.parentReaderGroup(r.ConnectionIndex, r.GroupIndex)
	if inGroup == nil {
		return nil, sc
	}
	in, ok := fileElem(inGroup.DataSetReaders, r.ElementIndex)
	if !ok {
		return nil, ua.StatusBadInvalidArgument
	}
	if sc != ua.StatusOK {
		return nil, sc
	}
	nameOf := func(x *ua.DataSetReaderDataType) string { return x.Name }
	cp := *in
	e := &element{path: configPath{kind: pubsub.KindDataSetReader}}
	at := func() int { return findByName(g.DataSetReaders, cp.Name, nameOf) }
	e.exists = func() bool { return at() >= 0 }
	e.add = func() (func(), ua.StatusCode) {
		if cp.Name == "" {
			cp.Name = uniqueName("DataSetReader", func(n string) bool { return findByName(g.DataSetReaders, n, nameOf) >= 0 })
		}
		if at() >= 0 {
			return nil, ua.StatusBadBrowseNameDuplicated
		}
		return appendTo(&g.DataSetReaders, &cp), ua.StatusOK
	}
	e.modify = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		return replace(g.DataSetReaders[i], cp)
	}
	e.remove = func() func() {
		i := at()
		if i < 0 {
			return nil
		}
		return removeAt(&g.DataSetReaders, i)
	}
	e.commit = func() { e.path.names = []string{c.Name, g.Name, cp.Name} }
	e.value = func() *ua.PubSubConfigurationValueDataType { return configValue(cp.Name) }
	return e, ua.StatusOK
}
