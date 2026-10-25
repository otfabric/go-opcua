// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/internal/testhook"
)

func init() {
	testhook.ServerMulticastTransport = func(link any) any {
		return Option(func(c *serverConfig) error {
			network, ok := link.(*mdns.MemNetwork)
			if !ok || network == nil {
				return fmt.Errorf("server: multicast test transport: want *mdns.MemNetwork, got %T", link)
			}
			c.multicast.conns = func() ([]mdns.PacketConn, error) {
				return []mdns.PacketConn{network.Conn()}, nil
			}
			return nil
		})
	}
	testhook.ServerMulticastTTL = func(hostTTL, otherTTL uint32) any {
		return Option(func(c *serverConfig) error {
			c.multicast.hostTTL, c.multicast.otherTTL = hostTTL, otherTTL
			return nil
		})
	}
	testhook.ServerSessionsOf = func(v any) []string {
		s, ok := v.(*Server)
		if !ok || s == nil {
			return nil
		}
		s.sb.mu.Lock()
		defer s.sb.mu.Unlock()
		var out []string
		for _, sess := range s.sb.s {
			out = append(out, fmt.Sprintf("%v timeout=%v idle=%v activated=%v", sess.ID,
				time.Duration(sess.timeout.Load()),
				sess.idle(time.Now()).Round(time.Millisecond),
				sess.activated.Load()))
		}
		return out
	}
	testhook.ServerResourcesOf = func(v any) testhook.ServerResources {
		s, ok := v.(*Server)
		if !ok || s == nil {
			return testhook.ServerResources{}
		}
		return s.resourceCounts()
	}
}

// resourceCounts reports how many per-client resources the server currently
// holds. It exists for leak checks in tests (see internal/testhook).
func (s *Server) resourceCounts() testhook.ServerResources {
	var r testhook.ServerResources

	s.cb.mu.RLock()
	r.Channels = len(s.cb.s)
	s.cb.mu.RUnlock()

	s.sb.mu.Lock()
	r.Sessions = len(s.sb.s)
	s.sb.mu.Unlock()

	if ss := s.SubscriptionService; ss != nil {
		ss.Mu.Lock()
		r.Subscriptions = len(ss.Subs)
		ss.Mu.Unlock()
	}
	if ms := s.MonitoredItemService; ms != nil {
		ms.Mu.Lock()
		r.MonitoredItems = len(ms.Items)
		ms.Mu.Unlock()
	}
	if s.diag != nil {
		r.DiagnosticsSessionObjects = s.diag.sessionObjectCount()
	}
	return r
}
