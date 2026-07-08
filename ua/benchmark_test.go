// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

func BenchmarkVariantEncode_Int32(b *testing.B) {
	v := MustVariant(int32(42))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Encode(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVariantEncode_String(b *testing.B) {
	v := MustVariant("hello world OPC-UA benchmark test string")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Encode(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVariantEncode_Float64(b *testing.B) {
	v := MustVariant(float64(3.14159265358979))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Encode(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVariantDecode_Int32(b *testing.B) {
	v := MustVariant(int32(42))
	data, _ := v.Encode()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := new(Variant)
		if _, err := d.Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVariantDecode_String(b *testing.B) {
	v := MustVariant("hello world OPC-UA benchmark test string")
	data, _ := v.Encode()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := new(Variant)
		if _, err := d.Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNodeIDEncode_Numeric(b *testing.B) {
	n := NewNumericNodeID(0, 2258)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := n.Encode(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNodeIDEncode_String(b *testing.B) {
	n := NewStringNodeID(2, "MyVariable")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := n.Encode(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNodeIDDecode_Numeric(b *testing.B) {
	n := NewNumericNodeID(0, 2258)
	data, _ := n.Encode()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := new(NodeID)
		if _, err := d.Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNodeIDDecode_String(b *testing.B) {
	n := NewStringNodeID(2, "MyVariable")
	data, _ := n.Encode()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := new(NodeID)
		if _, err := d.Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBufferReadWrite(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf := NewBuffer(make([]byte, 0, 256))
		buf.WriteUint32(42)
		buf.WriteFloat64(3.14)
		buf.WriteString("benchmark")
		buf.WriteBool(true)
		data := buf.Bytes()
		r := NewBuffer(data)
		r.ReadUint32()
		r.ReadFloat64()
		r.ReadString()
		r.ReadBool()
	}
}
