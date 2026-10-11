// SPDX-License-Identifier: MIT

package server

import "github.com/otfabric/go-opcua/internal/testhook"

func init() {
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
	return r
}
