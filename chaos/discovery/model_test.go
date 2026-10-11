// SPDX-License-Identifier: MIT

package discovery

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

// entry is what the test knows about one server that registers with the
// discovery server.
type entry struct {
	uri  string
	urls []string
	// instances are the mDNS service instances the discovery server
	// announces for the server, one per discovery URL, and the names of its
	// rows in the ServerOnNetwork table.
	instances []string
	mdnsName  string
	caps      []string
	// legacy says that the server registers with RegisterServer: no mDNS
	// configuration, so its capabilities are "NA".
	legacy bool
}

// span is a time during which a server may have been in the table.
type span struct {
	from time.Time
	to   time.Time // zero: still running
}

// model records when every server may have been registered. A reader that is
// handed a server checks it against the model: the server must have been
// registered at some time while the reader was reading.
type model struct {
	// lease is how long the discovery server may keep a registration that is
	// not renewed.
	lease time.Duration

	mu         sync.Mutex
	entries    map[string]*entry
	byInstance map[string]*entry // lower-case instance name
	spans      map[string][]span
}

func newModel(lease time.Duration) *model {
	return &model{lease: lease, entries: map[string]*entry{}, byInstance: map[string]*entry{}, spans: map[string][]span{}}
}

func (m *model) add(e *entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[e.uri] = e
	for _, in := range e.instances {
		m.byInstance[strings.ToLower(in)] = e
	}
}

func (m *model) entry(uri string) *entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.entries[uri]
}

func (m *model) instance(name string) *entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byInstance[strings.ToLower(name)]
}

// begin says that the server may be registered from at on, until further
// notice. It is called before the request is sent.
func (m *model) begin(uri string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.spans[uri]
	if n := len(s); n > 0 && (s[n-1].to.IsZero() || !s[n-1].to.Before(at)) {
		s[n-1].to = time.Time{}
		return
	}
	m.spans[uri] = append(s, span{from: at})
}

// renewed says that the discovery server answered a registration at at: it
// keeps the server for at most the lease from then on.
func (m *model) renewed(uri string, at time.Time) { m.end(uri, at.Add(m.lease)) }

// end says that the server is not registered after at: the discovery server
// answered its unregistration.
func (m *model) end(uri string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.spans[uri]; len(s) > 0 {
		s[len(s)-1].to = at
	}
}

// live reports whether the server may have been registered at some time
// between from and to.
func (m *model) live(uri string, from, to time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.spans[uri] {
		if !s.from.After(to) && (s.to.IsZero() || !s.to.Before(from)) {
			return true
		}
	}
	return false
}

// uris returns the ServerUris of all servers the model knows.
func (m *model) uris() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.entries))
	for uri := range m.entries {
		out = append(out, uri)
	}
	slices.Sort(out)
	return out
}

// ---------------------------------------------------------------------------
// FindServersOnNetwork
// ---------------------------------------------------------------------------

// recordIDs remembers which server every record id of one discovery server
// stood for: an id is never given to another server.
type recordIDs struct {
	mu    sync.Mutex
	names map[uint32]string
	reset time.Time
}

func (r *recordIDs) check(sink *chaoskit.ErrSink, who string, resp *ua.FindServersOnNetworkResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names == nil {
		r.names = map[uint32]string{}
		r.reset = resp.LastCounterResetTime
	}
	if !resp.LastCounterResetTime.Equal(r.reset) {
		sink.Addf("%s: LastCounterResetTime changed from %v to %v", who, r.reset, resp.LastCounterResetTime)
	}
	for _, rec := range resp.Servers {
		if rec == nil {
			continue
		}
		name := strings.ToLower(rec.ServerName)
		if old, ok := r.names[rec.RecordID]; ok && old != name {
			sink.Addf("%s: record id %d stood for %q and now stands for %q", who, rec.RecordID, old, name)
		}
		r.names[rec.RecordID] = name
	}
}

// traverse pages through the ServerOnNetwork table of the server c is
// connected to, from record id start on, with pages of at most pageSize
// records (0: no limit) and the capability filter. It checks every page:
//
//   - at most pageSize records, none below the starting record id
//   - record ids strictly increasing, within the page and from page to page:
//     no record is returned twice
//   - every record has all the capabilities of the filter
//   - a record id always stands for the same server (ids)
//
// and that the traversal ends. It returns the records and the time the last
// page was read.
func traverse(sink *chaoskit.ErrSink, who string, c *opcua.Client, ids *recordIDs, start, pageSize uint32, filter []string) ([]*ua.ServerOnNetwork, time.Time, error) {
	var (
		all  []*ua.ServerOnNetwork
		last int64 = -1
	)
	what := fmt.Sprintf("%s: FindServersOnNetwork(page size %d, filter %v)", who, pageSize, filter)
	for page := 0; ; page++ {
		if page > 100000 {
			sink.Addf("%s: the traversal does not end", what)
			return all, time.Now(), nil
		}
		ctx, cancel := chaoskit.OpCtx()
		resp, err := c.FindServersOnNetworkWithFilter(ctx, start, pageSize, filter)
		cancel()
		if err != nil {
			return all, time.Now(), err
		}
		ids.check(sink, who, resp)
		if pageSize != 0 && uint32(len(resp.Servers)) > pageSize {
			sink.Addf("%s: page of %d records", what, len(resp.Servers))
		}
		if len(resp.Servers) == 0 {
			return all, time.Now(), nil
		}
		for _, rec := range resp.Servers {
			if rec == nil {
				sink.Addf("%s: nil record", what)
				continue
			}
			if rec.RecordID < start {
				sink.Addf("%s: record id %d below the starting record id %d", what, rec.RecordID, start)
			}
			if int64(rec.RecordID) <= last {
				sink.Addf("%s: record id %d after %d: not strictly increasing", what, rec.RecordID, last)
			}
			last = int64(rec.RecordID)
			for _, want := range filter {
				if !slices.ContainsFunc(rec.ServerCapabilities, func(c string) bool { return strings.EqualFold(c, want) }) {
					sink.Addf("%s: record %q with capabilities %v", what, rec.ServerName, rec.ServerCapabilities)
				}
			}
			all = append(all, rec)
		}
		if pageSize == 0 {
			// Everything was returned at once; one more call only confirms
			// that nothing follows, which churn can make untrue.
			return all, time.Now(), nil
		}
		start = uint32(last) + 1
	}
}

// names returns the sorted server names of the records.
func names(records []*ua.ServerOnNetwork) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.ServerName)
	}
	slices.Sort(out)
	return out
}
