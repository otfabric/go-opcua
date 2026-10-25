// SPDX-License-Identifier: MIT

package server

// SetValueFunc makes the node serve its Value attribute from f, whatever
// its access level: the way a server publishes values of nodes that
// clients may only read, for example the properties of a NodeSet it
// imported. A nil f removes the value.
func (n *Node) SetValueFunc(f ValueFunc) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.val = f
}
