// SPDX-License-Identifier: MIT

package mqtt

// ConnectErrorFatal exposes ConnectError.fatal to the external tests.
func ConnectErrorFatal(e *ConnectError) bool { return e.fatal() }

// InflightCount returns the number of unfinished QoS 1 and 2 publications.
func InflightCount(c *Client) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.inflight)
}
