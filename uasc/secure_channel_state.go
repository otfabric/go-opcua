// SPDX-License-Identifier: MIT

package uasc

// Disconnected returns a channel that is closed when the secure channel has
// stopped reading from its connection, because the connection was lost or
// the channel was closed. A client secure channel reports the loss of its
// connection only once on its error channel; Disconnected lets the owner
// check the current state at any later time.
//
// For a channel that was never opened the returned channel is never closed.
func (s *SecureChannel) Disconnected() <-chan struct{} {
	return s.disconnected
}
