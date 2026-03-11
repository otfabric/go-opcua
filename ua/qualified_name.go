// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ua

import "fmt"

// QualifiedName contains a qualified name. It is, for example, used as BrowseName.
// The name part of the QualifiedName is restricted to 512 characters.
//
// Specification: Part 3, 8.3
type QualifiedName struct {
	NamespaceIndex uint16
	Name           string
}

// String implements fmt.Stringer. Returns the name only when namespace is 0, otherwise "ns:name".
func (q *QualifiedName) String() string {
	if q == nil {
		return ""
	}
	if q.NamespaceIndex == 0 {
		return q.Name
	}
	return fmt.Sprintf("%d:%s", q.NamespaceIndex, q.Name)
}

func (q *QualifiedName) Encode() ([]byte, error) {
	buf := NewBuffer(nil)
	if q == nil {
		// OPC UA null QualifiedName: namespace 0, string length -1 (absent).
		// Must emit fixed layout so struct field offsets are preserved.
		buf.WriteUint16(0)
		buf.WriteUint32(0xffffffff) // null string
		return buf.Bytes(), buf.Error()
	}
	buf.WriteUint16(q.NamespaceIndex)
	buf.WriteString(q.Name)
	return buf.Bytes(), buf.Error()
}

func (q *QualifiedName) Decode(b []byte) (int, error) {
	buf := NewBuffer(b)
	q.NamespaceIndex = buf.ReadUint16()
	q.Name = buf.ReadString()
	return buf.Pos(), buf.Error()
}
