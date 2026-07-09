// SPDX-License-Identifier: MIT

package ua

import (
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferRoundTripScalars(t *testing.T) {
	buf := NewBuffer(nil)
	buf.WriteBool(true)
	buf.WriteInt8(-3)
	buf.WriteUint8(200)
	buf.WriteInt16(-1234)
	buf.WriteUint16(4321)
	buf.WriteInt32(-42)
	buf.WriteUint32(4242)
	buf.WriteInt64(-9_000_000_000)
	buf.WriteUint64(9_000_000_000)
	buf.WriteFloat32(3.5)
	buf.WriteFloat64(3.14159)
	buf.WriteString("hello")
	buf.WriteByteString([]byte{1, 2, 3})
	buf.WriteTime(time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC))

	r := NewBuffer(buf.buf)
	assert.True(t, r.ReadBool())
	assert.Equal(t, int8(-3), r.ReadInt8())
	assert.Equal(t, uint8(200), r.ReadUint8())
	assert.Equal(t, int16(-1234), r.ReadInt16())
	assert.Equal(t, uint16(4321), r.ReadUint16())
	assert.Equal(t, int32(-42), r.ReadInt32())
	assert.Equal(t, uint32(4242), r.ReadUint32())
	assert.Equal(t, int64(-9_000_000_000), r.ReadInt64())
	assert.Equal(t, uint64(9_000_000_000), r.ReadUint64())
	assert.Equal(t, float32(3.5), r.ReadFloat32())
	assert.Equal(t, 3.14159, r.ReadFloat64())
	assert.Equal(t, "hello", r.ReadString())
	assert.Equal(t, []byte{1, 2, 3}, r.ReadBytes())
	assert.Equal(t, time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC), r.ReadTime())
	require.NoError(t, r.Error())
}

func TestBufferNaNAndNull(t *testing.T) {
	buf := NewBuffer(nil)
	buf.WriteFloat32(float32(math.NaN()))
	buf.WriteFloat64(math.NaN())
	buf.WriteString("")
	buf.WriteByteString(nil)

	r := NewBuffer(buf.buf)
	assert.True(t, math.IsNaN(float64(r.ReadFloat32())))
	assert.True(t, math.IsNaN(r.ReadFloat64()))
	assert.Nil(t, r.ReadBytes())
	assert.Nil(t, r.ReadBytes())
}

func TestBufferUnexpectedEOF(t *testing.T) {
	r := NewBuffer([]byte{1, 2})
	_ = r.ReadUint32()
	require.Error(t, r.Error())
	assert.Nil(t, r.Bytes())
}

func TestBufferWriteByteStringTooLarge(t *testing.T) {
	buf := NewBuffer(nil)
	buf.WriteByteString(make([]byte, math.MaxInt32+1))
	require.ErrorIs(t, buf.Error(), errors.ErrArrayTooLarge)
}

func TestBufferReadStruct(t *testing.T) {
	hdr := &RequestHeader{RequestHandle: 42, TimeoutHint: 1000}
	encoded, err := Encode(hdr)
	require.NoError(t, err)

	r := NewBuffer(encoded)
	var got RequestHeader
	r.ReadStruct(&got)
	require.NoError(t, r.Error())
	assert.Equal(t, uint32(42), got.RequestHandle)
}

func TestBufferWriteStruct(t *testing.T) {
	buf := NewBuffer(nil)
	buf.WriteStruct(&RequestHeader{RequestHandle: 7})
	require.NoError(t, buf.Error())
	require.NotEmpty(t, buf.buf)
}

func TestBufferPosLen(t *testing.T) {
	r := NewBuffer([]byte{1, 2, 3, 4})
	assert.Equal(t, 0, r.Pos())
	assert.Equal(t, 4, r.Len())
	_ = r.ReadUint16()
	assert.Equal(t, 2, r.Pos())
	assert.Equal(t, 2, r.Len())
}
