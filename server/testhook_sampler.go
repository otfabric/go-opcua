// SPDX-License-Identifier: MIT

package server

import "github.com/otfabric/go-opcua/internal/testhook"

func init() {
	testhook.ServerSamplerOf = func(v any) testhook.ServerSampler {
		s, ok := v.(*Server)
		if !ok || s == nil || s.MonitoredItemService == nil {
			return testhook.ServerSampler{}
		}
		return s.MonitoredItemService.samplerState()
	}
}

// samplerState reports the state of the sampler timer. It exists for leak
// checks in tests (see internal/testhook).
func (s *MonitoredItemService) samplerState() testhook.ServerSampler {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	r := testhook.ServerSampler{
		Due:     len(s.due),
		Running: int(s.samplerRuns.Load()),
	}
	if !s.samplerAt.IsZero() {
		r.Timers = 1
	}
	return r
}
