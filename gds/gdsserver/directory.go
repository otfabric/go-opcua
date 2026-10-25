// SPDX-License-Identifier: MIT

package gdsserver

import (
	"context"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/ua"
)

// Limits of an ApplicationRecordDataType.
const (
	maxNames        = 16
	maxURLs         = 32
	maxCapabilities = 32
	maxStringLen    = 4096
)

func argValue[T any](args []*ua.Variant, i int) (T, bool) {
	var zero T
	if i >= len(args) || args[i] == nil {
		return zero, false
	}
	v, ok := args[i].Value().(T)
	return v, ok
}

// argNodeID returns a NodeId argument; a missing value is a null NodeId.
func argNodeID(args []*ua.Variant, i int) (*ua.NodeID, bool) {
	if i < len(args) && args[i] != nil && args[i].Value() == nil {
		return ua.NewTwoByteNodeID(0), true
	}
	return argValue[*ua.NodeID](args, i)
}

// argStrings returns a String array argument; a missing value is empty.
func argStrings(args []*ua.Variant, i int) ([]string, bool) {
	if i < len(args) && args[i] != nil && args[i].Value() == nil {
		return nil, true
	}
	return argValue[[]string](args, i)
}

// argBytes returns a ByteString argument; a missing value is empty.
func argBytes(args []*ua.Variant, i int) ([]byte, bool) {
	if i < len(args) && args[i] != nil && args[i].Value() == nil {
		return nil, true
	}
	return argValue[[]byte](args, i)
}

func isNull(n *ua.NodeID) bool {
	return n == nil || (n.Namespace() == 0 && n.Type() == ua.NodeIDTypeTwoByte && n.IntID() == 0) ||
		(n.Namespace() == 0 && n.Type() == ua.NodeIDTypeNumeric && n.IntID() == 0)
}

// argRecord decodes the ApplicationRecordDataType argument.
func (g *GDS) argRecord(args []*ua.Variant, i int) (*gds.ApplicationRecord, ua.StatusCode) {
	eo, ok := argValue[*ua.ExtensionObject](args, i)
	if !ok || eo == nil {
		return nil, ua.StatusBadTypeMismatch
	}
	r, err := gds.DecodeApplicationRecord(g.ns, eo)
	if err != nil {
		return nil, ua.StatusBadDecodingError
	}
	return r, ua.StatusOK
}

func absoluteURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && (u.Host != "" || u.Opaque != "" || u.Path != "")
}

func validString(s string) bool { return len(s) <= maxStringLen && utf8.ValidString(s) }

// validateRecord checks an ApplicationRecordDataType (Part 12 §6.6.4).
func validateRecord(r *gds.ApplicationRecord) ua.StatusCode {
	if !absoluteURI(r.ApplicationURI) || !validString(r.ApplicationURI) {
		return ua.StatusBadInvalidArgument
	}
	if r.ApplicationType > ua.ApplicationTypeDiscoveryServer {
		return ua.StatusBadInvalidArgument
	}
	if len(r.ApplicationNames) == 0 || len(r.ApplicationNames) > maxNames ||
		r.ApplicationNames[0] == nil || strings.TrimSpace(r.ApplicationNames[0].Text) == "" {
		return ua.StatusBadInvalidArgument
	}
	for _, n := range r.ApplicationNames {
		if n == nil || !validString(n.Text) || !validString(n.Locale) {
			return ua.StatusBadInvalidArgument
		}
	}
	if !absoluteURI(r.ProductURI) || !validString(r.ProductURI) {
		return ua.StatusBadInvalidArgument
	}
	if len(r.DiscoveryURLs) > maxURLs || len(r.ServerCapabilities) > maxCapabilities {
		return ua.StatusBadInvalidArgument
	}
	servers := 0
	for _, u := range r.DiscoveryURLs {
		if !validString(u) || !absoluteURI(strings.TrimPrefix(u, "rcp+")) {
			return ua.StatusBadInvalidArgument
		}
		if !strings.HasPrefix(u, "rcp+") {
			servers++
		}
	}
	if r.ApplicationType != ua.ApplicationTypeClient && servers == 0 {
		return ua.StatusBadInvalidArgument
	}
	for _, c := range r.ServerCapabilities {
		if c == "" || len(c) > 64 || !utf8.ValidString(c) {
			return ua.StatusBadInvalidArgument
		}
	}
	return ua.StatusOK
}

// recordOf returns the record of an application with its ApplicationId.
func (g *GDS) recordOf(app *Application) *gds.ApplicationRecord {
	r := cloneRecord(app.Record)
	r.ApplicationID = g.guidNode(app.ID)
	return r
}

func (g *GDS) recordVariant(app *Application) (*ua.Variant, ua.StatusCode) {
	eo, err := gds.EncodeApplicationRecord(g.ns, g.recordOf(app))
	if err != nil {
		return nil, ua.StatusBadEncodingError
	}
	return ua.MustVariant(eo), ua.StatusOK
}

// endpointIDsLocked gives every discovery URL a QueryServers record id:
// the one it had in old, or a new one.
func (g *GDS) endpointIDsLocked(meta *Meta, urls []string, old *Application) []uint32 {
	ids := make([]uint32, len(urls))
	for i, u := range urls {
		if old != nil {
			if j := slices.Index(old.Record.DiscoveryURLs, u); j >= 0 && j < len(old.EndpointIDs) {
				ids[i] = old.EndpointIDs[j]
				continue
			}
		}
		ids[i] = meta.NextRecordID
		meta.NextRecordID++
	}
	return ids
}

// putApplicationLocked stores the application and the counters and makes
// them the state.
func (g *GDS) putApplicationLocked(ctx context.Context, app *Application, meta *Meta) ua.StatusCode {
	if meta != nil {
		if err := g.store.PutMeta(ctx, meta); err != nil {
			g.log.Warn("gds: storing the counters failed", "error", err)
			return ua.StatusBadInternalError
		}
		g.meta = meta
	}
	if err := g.store.PutApplication(ctx, app); err != nil {
		g.log.Warn("gds: storing the application failed", "error", err)
		return ua.StatusBadInternalError
	}
	if old := g.apps[app.ID]; old != nil && g.byURI[old.Record.ApplicationURI] == app.ID {
		delete(g.byURI, old.Record.ApplicationURI)
	}
	g.apps[app.ID] = app
	g.byURI[app.Record.ApplicationURI] = app.ID
	return ua.StatusOK
}

// findApplications is FindApplications (Part 12 §6.6.4): any client may
// call it. The ApplicationUri must not be empty.
func (g *GDS) findApplications(_ context.Context, _ *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	uri, ok := argValue[string](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	if strings.TrimSpace(uri) == "" {
		return nil, ua.StatusBadInvalidArgument
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := []*ua.ExtensionObject{}
	if app := g.apps[g.byURI[uri]]; app != nil {
		eo, err := gds.EncodeApplicationRecord(g.ns, g.recordOf(app))
		if err != nil {
			return nil, ua.StatusBadEncodingError
		}
		out = append(out, eo)
	}
	return []*ua.Variant{ua.MustVariant(out)}, ua.StatusOK
}

// registerApplication is RegisterApplication (Part 12 §6.6.5): the
// DiscoveryAdmin role is required.
func (g *GDS) registerApplication(ctx context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if sc := c.channelCheck(false); sc != ua.StatusOK {
		return nil, sc
	}
	if !g.isDiscoveryAdmin(c) {
		return nil, ua.StatusBadUserAccessDenied
	}
	rec, sc := g.argRecord(args, 0)
	if sc != ua.StatusOK {
		return nil, sc
	}
	if sc := validateRecord(rec); sc != ua.StatusOK {
		return nil, sc
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.byURI[rec.ApplicationURI]; dup {
		return nil, ua.StatusBadEntryExists
	}
	if len(g.apps) >= g.cfg.MaxApplications {
		return nil, ua.StatusBadResourceUnavailable
	}
	rec = cloneRecord(rec)
	rec.ApplicationID = nil
	meta := cloneMeta(g.meta)
	app := &Application{ID: uuid.NewString(), RecordID: meta.NextRecordID, Record: rec}
	meta.NextRecordID++
	app.EndpointIDs = g.endpointIDsLocked(meta, rec.DiscoveryURLs, nil)
	if sc := g.putApplicationLocked(ctx, app, meta); sc != ua.StatusOK {
		return nil, sc
	}
	g.log.Info("gds: application registered", "application_uri", rec.ApplicationURI, "application_id", app.ID)
	return []*ua.Variant{ua.MustVariant(g.guidNode(app.ID))}, ua.StatusOK
}

// updateApplication is UpdateApplication (Part 12 §6.6.6): the
// DiscoveryAdmin role or the application itself, which may not change its
// ApplicationUri.
func (g *GDS) updateApplication(ctx context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if sc := c.channelCheck(false); sc != ua.StatusOK {
		return nil, sc
	}
	rec, sc := g.argRecord(args, 0)
	if sc != ua.StatusOK {
		return nil, sc
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	admin := g.isDiscoveryAdmin(c)
	old, sc := g.authorizeAppLocked(c, g.guidOf(rec.ApplicationID), admin)
	if sc != ua.StatusOK {
		return nil, sc
	}
	if !admin && rec.ApplicationURI != old.Record.ApplicationURI {
		return nil, ua.StatusBadUserAccessDenied
	}
	if sc := validateRecord(rec); sc != ua.StatusOK {
		return nil, sc
	}
	if other, dup := g.byURI[rec.ApplicationURI]; dup && other != old.ID {
		return nil, ua.StatusBadEntryExists
	}
	rec = cloneRecord(rec)
	rec.ApplicationID = nil
	app := cloneApplication(old)
	app.Record = rec
	meta := cloneMeta(g.meta)
	app.EndpointIDs = g.endpointIDsLocked(meta, rec.DiscoveryURLs, old)
	if sc := g.putApplicationLocked(ctx, app, meta); sc != ua.StatusOK {
		return nil, sc
	}
	return nil, ua.StatusOK
}

// unregisterApplication is UnregisterApplication (Part 12 §6.6.7): the
// DiscoveryAdmin role or the application itself. The certificates the GDS
// issued to the application are revoked and its requests dropped.
func (g *GDS) unregisterApplication(ctx context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if sc := c.channelCheck(false); sc != ua.StatusOK {
		return nil, sc
	}
	appID, ok := argNodeID(args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	app, sc := g.authorizeAppLocked(c, g.guidOf(appID), g.isDiscoveryAdmin(c))
	if sc != ua.StatusOK {
		return nil, sc
	}
	app = cloneApplication(app)
	for _, ic := range app.Certificates {
		if !ic.Revoked {
			if sc := g.revokeLocked(ctx, ic); sc != ua.StatusOK {
				return nil, sc
			}
			ic.Revoked = true
		}
	}
	for rid, r := range g.reqs {
		if r.ApplicationID == app.ID {
			if err := g.store.DeleteRequest(ctx, rid); err != nil {
				return nil, ua.StatusBadInternalError
			}
			delete(g.reqs, rid)
		}
	}
	if err := g.store.DeleteApplication(ctx, app.ID); err != nil {
		g.log.Warn("gds: deleting the application failed", "error", err)
		return nil, ua.StatusBadInternalError
	}
	delete(g.apps, app.ID)
	delete(g.byURI, app.Record.ApplicationURI)
	g.log.Info("gds: application unregistered", "application_uri", app.Record.ApplicationURI, "application_id", app.ID)
	return nil, ua.StatusOK
}

// getApplication is GetApplication (Part 12 §6.6.8): an authenticated user,
// an administrator or the application itself.
func (g *GDS) getApplication(_ context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	appID, ok := argNodeID(args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	admin := c.hasRole(ua.RoleAuthenticatedUser.NodeID()) || g.isDiscoveryAdmin(c) || g.isCAAdmin(c)
	app, sc := g.authorizeAppLocked(c, g.guidOf(appID), admin)
	if sc != ua.StatusOK {
		return nil, sc
	}
	v, sc := g.recordVariant(app)
	if sc != ua.StatusOK {
		return nil, sc
	}
	return []*ua.Variant{v}, ua.StatusOK
}

// query is the filter of QueryApplications and QueryServers.
type query struct {
	name, uri, product *likePattern
	caps               []string
}

func newQuery(name, uri, product string, caps []string) (*query, ua.StatusCode) {
	q := &query{caps: caps}
	for _, x := range []struct {
		p   **likePattern
		src string
	}{{&q.name, name}, {&q.uri, uri}, {&q.product, product}} {
		if x.src == "" {
			continue
		}
		p, err := compileLike(x.src)
		if err != nil || !validString(x.src) {
			return nil, ua.StatusBadInvalidArgument
		}
		*x.p = p
	}
	if len(caps) > 1 && slices.ContainsFunc(caps, func(c string) bool { return strings.EqualFold(c, "NA") }) {
		return nil, ua.StatusBadInvalidArgument
	}
	return q, ua.StatusOK
}

func (q *query) match(r *gds.ApplicationRecord) bool {
	name := ""
	if len(r.ApplicationNames) > 0 && r.ApplicationNames[0] != nil {
		name = r.ApplicationNames[0].Text
	}
	if !q.name.match(name) || !q.uri.match(r.ApplicationURI) || !q.product.match(r.ProductURI) {
		return false
	}
	for _, c := range q.caps {
		if !slices.Contains(r.ServerCapabilities, c) {
			return false
		}
	}
	return true
}

func (g *GDS) appsByRecordIDLocked() []*Application {
	out := make([]*Application, 0, len(g.apps))
	for _, a := range g.apps {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RecordID < out[j].RecordID })
	return out
}

// queryApplications is QueryApplications (Part 12 §6.6.10): any client.
func (g *GDS) queryApplications(_ context.Context, _ *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	start, ok1 := argValue[uint32](args, 0)
	maxRecords, ok2 := argValue[uint32](args, 1)
	name, ok3 := argValue[string](args, 2)
	uri, ok4 := argValue[string](args, 3)
	appType, ok5 := argValue[uint32](args, 4)
	product, ok6 := argValue[string](args, 5)
	caps, ok7 := argStrings(args, 6)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
		return nil, ua.StatusBadTypeMismatch
	}
	if appType > 3 {
		return nil, ua.StatusBadInvalidArgument
	}
	q, sc := newQuery(name, uri, product, caps)
	if sc != ua.StatusOK {
		return nil, sc
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	descs := []*ua.ApplicationDescription{}
	var next, last uint32
	for _, a := range g.appsByRecordIDLocked() {
		if a.RecordID <= start || !q.match(a.Record) {
			continue
		}
		t := a.Record.ApplicationType
		if appType == 1 && t == ua.ApplicationTypeClient ||
			appType == 2 && t != ua.ApplicationTypeClient && t != ua.ApplicationTypeClientAndServer {
			continue
		}
		if maxRecords != 0 && uint32(len(descs)) >= maxRecords {
			next = last
			break
		}
		last = a.RecordID
		descs = append(descs, &ua.ApplicationDescription{
			ApplicationURI:  a.Record.ApplicationURI,
			ProductURI:      a.Record.ProductURI,
			ApplicationName: cloneLT(a.Record.ApplicationNames[0]),
			ApplicationType: t,
			DiscoveryURLs:   slices.Clone(a.Record.DiscoveryURLs),
		})
	}
	return []*ua.Variant{ua.MustVariant(g.meta.CounterResetTime), ua.MustVariant(next), ua.MustVariant(eosOf(descs))}, ua.StatusOK
}

// queryServers is QueryServers (Part 12 §6.6.9): any client. Every
// discovery URL of a server is one record.
func (g *GDS) queryServers(_ context.Context, _ *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	start, ok1 := argValue[uint32](args, 0)
	maxRecords, ok2 := argValue[uint32](args, 1)
	name, ok3 := argValue[string](args, 2)
	uri, ok4 := argValue[string](args, 3)
	product, ok5 := argValue[string](args, 4)
	caps, ok6 := argStrings(args, 5)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return nil, ua.StatusBadTypeMismatch
	}
	q, sc := newQuery(name, uri, product, caps)
	if sc != ua.StatusOK {
		return nil, sc
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	var recs []*ua.ServerOnNetwork
	for _, a := range g.apps {
		if a.Record.ApplicationType == ua.ApplicationTypeClient || !q.match(a.Record) {
			continue
		}
		for i, u := range a.Record.DiscoveryURLs {
			if strings.HasPrefix(u, "rcp+") || i >= len(a.EndpointIDs) || a.EndpointIDs[i] <= start {
				continue
			}
			recs = append(recs, &ua.ServerOnNetwork{
				RecordID:           a.EndpointIDs[i],
				ServerName:         a.Record.ApplicationNames[0].Text,
				DiscoveryURL:       u,
				ServerCapabilities: slices.Clone(a.Record.ServerCapabilities),
			})
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].RecordID < recs[j].RecordID })
	if maxRecords != 0 && uint32(len(recs)) > maxRecords {
		recs = recs[:maxRecords]
	}
	return []*ua.Variant{ua.MustVariant(g.meta.CounterResetTime), ua.MustVariant(eosOf(recs))}, ua.StatusOK
}

func eosOf[T any](xs []*T) []*ua.ExtensionObject {
	out := make([]*ua.ExtensionObject, 0, len(xs))
	for _, x := range xs {
		out = append(out, ua.NewExtensionObject(x))
	}
	return out
}
