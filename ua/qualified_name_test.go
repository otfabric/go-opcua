// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ua

import (
	"testing"
)

func TestQualifiedName_Encode_NilReceiver(t *testing.T) {
	var q *QualifiedName
	b, err := q.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	// OPC UA null QualifiedName: namespace 0 + string length -1 (0xFFFFFFFF).
	// Must emit fixed layout so struct field offsets are preserved on the wire.
	want := []byte{0x00, 0x00, 0xff, 0xff, 0xff, 0xff}
	if len(b) != len(want) {
		t.Fatalf("nil QualifiedName.Encode() should return 6-byte null encoding, got len=%d", len(b))
	}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("nil QualifiedName.Encode() byte %d: got 0x%02x want 0x%02x", i, b[i], want[i])
		}
	}
}

func TestQualifiedName(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name:   "normal",
			Struct: &QualifiedName{NamespaceIndex: 1, Name: "foobar"},
			Bytes: []byte{
				// namespace index
				0x01, 0x00,
				// name
				0x06, 0x00, 0x00, 0x00,
				0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72,
			},
		},
		{
			Name:   "empty",
			Struct: &QualifiedName{NamespaceIndex: 1},
			Bytes: []byte{
				// namespace index
				0x01, 0x00,
				// name
				0xff, 0xff, 0xff, 0xff,
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestQualifiedName_String(t *testing.T) {
	tests := []struct {
		q    *QualifiedName
		want string
	}{
		{nil, ""},
		{&QualifiedName{NamespaceIndex: 0, Name: "Server"}, "Server"},
		{&QualifiedName{NamespaceIndex: 2, Name: "Temperature"}, "2:Temperature"},
	}
	for _, tt := range tests {
		got := tt.q.String()
		if got != tt.want {
			t.Errorf("QualifiedName.String() = %q, want %q", got, tt.want)
		}
	}
}
