// SPDX-License-Identifier: MIT

package server

// SetPubSubBeforeReconcile makes fn run in every CloseAndUpdate and
// UpdatePubSubConfiguration of s between reading the PubSub configuration
// and applying the update.
func SetPubSubBeforeReconcile(s *Server, fn func()) {
	s.ps.mu.Lock()
	m := s.ps.model
	s.ps.mu.Unlock()
	m.file.beforeReconcile = fn
}
