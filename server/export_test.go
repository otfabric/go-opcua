// SPDX-License-Identifier: MIT

package server

import "github.com/otfabric/go-opcua/ua"

// SetPubSubBeforeReconcile makes fn run in every CloseAndUpdate and
// UpdatePubSubConfiguration of s between reading the PubSub configuration
// and applying the update.
func SetPubSubBeforeReconcile(s *Server, fn func()) {
	s.ps.mu.Lock()
	m := s.ps.model
	s.ps.mu.Unlock()
	m.file.beforeReconcile = fn
}

// SetPubSubUpdateBefore sets the configuration a Revert of u reconciles to,
// for the error paths of a revert the runtime refuses.
func SetPubSubUpdateBefore(u *PubSubConfigurationUpdate, before *ua.PubSubConfigurationDataType) {
	u.before = before
}
