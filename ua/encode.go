// SPDX-License-Identifier: MIT

package ua

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"time"

	"github.com/otfabric/go-opcua/errors"
)

// BinaryEncoder is the interface implemented by an object that can
// marshal itself into a binary OPC/UA representation.
type BinaryEncoder interface {
	Encode() ([]byte, error)
}

var binaryEncoder = reflect.TypeOf((*BinaryEncoder)(nil)).Elem()

func isBinaryEncoder(val reflect.Value) bool {
	return val.Type().Implements(binaryEncoder)
}

func Encode(v interface{}) ([]byte, error) {
	val := reflect.ValueOf(v)
	return encode(val, val.Type().String())
}

func encode(val reflect.Value, name string) ([]byte, error) {
	slog.Debug("encode", "name", name, "type", val.Type(), "kind", val.Type().Kind())

	buf := NewBuffer(nil)
	switch {
	case isBinaryEncoder(val):
		v := val.Interface().(BinaryEncoder)
		return dump(v.Encode())

	case isTime(val):
		buf.WriteTime(val.Convert(timeType).Interface().(time.Time))

	default:
		switch val.Kind() {
		case reflect.Bool:
			buf.WriteBool(val.Bool())
		case reflect.Int8:
			buf.WriteInt8(int8(val.Int()))
		case reflect.Uint8:
			buf.WriteUint8(uint8(val.Uint()))
		case reflect.Int16:
			buf.WriteInt16(int16(val.Int()))
		case reflect.Uint16:
			buf.WriteUint16(uint16(val.Uint()))
		case reflect.Int32:
			buf.WriteInt32(int32(val.Int()))
		case reflect.Uint32:
			buf.WriteUint32(uint32(val.Uint()))
		case reflect.Int64:
			buf.WriteInt64(int64(val.Int()))
		case reflect.Uint64:
			buf.WriteUint64(uint64(val.Uint()))
		case reflect.Float32:
			buf.WriteFloat32(float32(val.Float()))
		case reflect.Float64:
			buf.WriteFloat64(float64(val.Float()))
		case reflect.String:
			buf.WriteString(val.String())
		case reflect.Pointer:
			if val.IsNil() {
				// Encode the zero value so the output is symmetric with
				// decode, which always allocates and reads pointer fields
				// (see decodeStruct). Writing nothing here corrupts the
				// stream whenever a pointer field is left nil.
				return dump(encode(reflect.New(val.Type().Elem()), name))
			}
			return dump(encode(val.Elem(), name))
		case reflect.Struct:
			return dump(writeStruct(val, name))
		case reflect.Slice:
			return dump(writeSlice(val, name))
		case reflect.Array:
			return dump(writeArray(val, name))
		default:
			return nil, fmt.Errorf("%w: %s", errors.ErrUnsupportedType, val.Type())
		}
	}
	return dump(buf.Bytes(), buf.Error())
}

func dump(b []byte, err error) ([]byte, error) {
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug("dump", "hex", hex.Dump(b))
	}
	return b, err
}

func writeStruct(val reflect.Value, name string) ([]byte, error) {
	var buf []byte
	valt := val.Type()
	for i := 0; i < val.NumField(); i++ {
		ft := valt.Field(i)
		fname := name + "." + ft.Name
		b, err := encode(val.Field(i), fname)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

func writeSlice(val reflect.Value, name string) ([]byte, error) {
	buf := NewBuffer(nil)
	if val.IsNil() {
		buf.WriteUint32(null)
		return buf.Bytes(), buf.Error()
	}

	if val.Len() > math.MaxInt32 {
		return nil, errors.ErrArrayTooLarge
	}

	buf.WriteUint32(uint32(val.Len()))

	// fast path for []byte
	if val.Type().Elem().Kind() == reflect.Uint8 {
		// fmt.Println("[]byte fast path")
		buf.Write(val.Bytes())
		return buf.Bytes(), buf.Error()
	}

	// loop over elements
	for i := 0; i < val.Len(); i++ {
		ename := fmt.Sprintf("%s[%d]", name, i)
		b, err := encode(val.Index(i), ename)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}
	return buf.Bytes(), buf.Error()
}

func writeArray(val reflect.Value, name string) ([]byte, error) {
	buf := NewBuffer(nil)

	if val.Len() > math.MaxInt32 {
		return nil, fmt.Errorf("%w: %d > %d", errors.ErrArrayTooLarge, val.Len(), math.MaxInt32)
	}

	buf.WriteUint32(uint32(val.Len()))

	// fast path for []byte
	if val.Type().Elem().Kind() == reflect.Uint8 {
		// fmt.Println("encode: []byte fast path")
		b := make([]byte, val.Len())
		reflect.Copy(reflect.ValueOf(b), val)
		buf.Write(b)
		return buf.Bytes(), buf.Error()
	}

	// loop over elements
	// we write all the elements, also the zero values
	for i := 0; i < val.Len(); i++ {
		ename := fmt.Sprintf("%s[%d]", name, i)
		b, err := encode(val.Index(i), ename)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}
	return buf.Bytes(), buf.Error()
}
