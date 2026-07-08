// SPDX-License-Identifier: MIT

package ua

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"time"

	"github.com/otfabric/go-opcua/errors"
)

var (
	binaryDecoder = reflect.TypeOf((*BinaryDecoder)(nil)).Elem()
	timeType      = reflect.TypeOf(time.Time{})
)

func isBinaryDecoder(val reflect.Value) bool {
	return val.Type().Implements(binaryDecoder)
}

func isTime(val reflect.Value) bool {
	return val.CanConvert(timeType)
}

type BinaryDecoder interface {
	Decode([]byte) (int, error)
}

func Decode(b []byte, v interface{}) (int, error) {
	val := reflect.ValueOf(v)
	return decode(b, val, val.Type().String())
}

func decode(b []byte, val reflect.Value, name string) (n int, err error) {
	slog.Debug("decode", "name", name, "type", val.Type(), "kind", val.Type().Kind(), "bytes", len(b))
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		defer func() {
			slog.Debug("decoded", "bytes", n, "name", name)
		}()
	}

	buf := NewBuffer(b)
	switch {
	case isBinaryDecoder(val):
		v := val.Interface().(BinaryDecoder)
		return v.Decode(b)
	case isTime(val):
		val.Set(reflect.ValueOf(buf.ReadTime()).Convert(val.Type()))
	default:
		// fmt.Printf("decode: %s is a %s\n", name, val.Kind())
		switch val.Kind() {
		case reflect.Bool:
			val.SetBool(buf.ReadBool())
		case reflect.Int8:
			val.SetInt(int64(buf.ReadInt8()))
		case reflect.Uint8:
			val.SetUint(uint64(buf.ReadUint8()))
		case reflect.Int16:
			val.SetInt(int64(buf.ReadInt16()))
		case reflect.Uint16:
			val.SetUint(uint64(buf.ReadUint16()))
		case reflect.Int32:
			val.SetInt(int64(buf.ReadInt32()))
		case reflect.Uint32:
			val.SetUint(uint64(buf.ReadUint32()))
		case reflect.Int64:
			val.SetInt(buf.ReadInt64())
		case reflect.Uint64:
			val.SetUint(buf.ReadUint64())
		case reflect.Float32:
			val.SetFloat(float64(buf.ReadFloat32()))
		case reflect.Float64:
			val.SetFloat(buf.ReadFloat64())
		case reflect.String:
			val.SetString(buf.ReadString())
		case reflect.Slice:
			return decodeSlice(b, val, name)
		case reflect.Array:
			return decodeArray(b, val, name)
		case reflect.Pointer:
			return decode(b, val.Elem(), name)
		case reflect.Struct:
			return decodeStruct(b, val, name)
		default:
			return 0, fmt.Errorf("%w: %s", errors.ErrUnsupportedType, val.Type())
		}
	}
	return buf.Pos(), buf.Error()
}

func decodeStruct(b []byte, val reflect.Value, name string) (int, error) {
	pos := 0
	valt := val.Type()
	for i := 0; i < val.NumField(); i++ {
		ft := valt.Field(i)
		fname := name + "." + ft.Name

		// if the field is a pointer we need to create
		// the value before we can marshal data into it.
		f := val.Field(i)
		if f.Type().Kind() == reflect.Pointer {
			f.Set(reflect.New(f.Type().Elem()))
			// fmt.Printf("decode: %s has type %v and has new value %#v\n", fname, f.Type(), f.Interface())
		}

		n, err := decode(b[pos:], f, fname)
		if err != nil {
			return pos, err
		}
		pos += n
	}
	return pos, nil
}

func decodeSlice(b []byte, val reflect.Value, name string) (int, error) {
	buf := NewBuffer(b)
	n := buf.ReadUint32()
	if buf.Error() != nil {
		return buf.Pos(), buf.Error()
	}

	if n == null {
		return buf.Pos(), nil
	}

	if n > math.MaxInt32 {
		return buf.Pos(), fmt.Errorf("%w: %d > %d", errors.ErrArrayTooLarge, n, math.MaxInt32)
	}

	// elemType is the type of the slice elements
	// e.g. *Foo for []*Foo
	elemType := val.Type().Elem()
	// fmt.Println("elemType: ", elemType.String())

	// fast path for []byte
	if elemType.Kind() == reflect.Uint8 {
		// fmt.Println("decode: []byte fast path")
		val.SetBytes(buf.ReadN(int(n)))
		return buf.Pos(), buf.Error()
	}

	pos := buf.Pos()
	// a is a slice of []*Foo
	a := reflect.MakeSlice(val.Type(), int(n), int(n))
	for i := 0; i < int(n); i++ {

		// if the slice elements are pointers we need to create
		// them before we can marshal data into them.
		if elemType.Kind() == reflect.Pointer {
			a.Index(i).Set(reflect.New(elemType.Elem()))
		}

		ename := fmt.Sprintf("%s[%d]", name, i)
		m, err := decode(b[pos:], a.Index(i), ename)
		if err != nil {
			return pos, err
		}
		pos += m
	}
	val.Set(a)

	return pos, nil
}

func decodeArray(b []byte, val reflect.Value, name string) (int, error) {
	buf := NewBuffer(b)
	n := buf.ReadUint32()
	if buf.Error() != nil {
		return buf.Pos(), buf.Error()
	}

	if n == null {
		return buf.Pos(), nil
	}

	if n > math.MaxInt32 {
		return buf.Pos(), fmt.Errorf("%w: %d > %d", errors.ErrArrayTooLarge, n, math.MaxInt32)
	}

	if n > uint32(val.Len()) {
		return buf.Pos(), fmt.Errorf("%w: %d > %d", errors.ErrArrayTooLarge, n, val.Len())
	}

	// elemType is the type of the slice elements
	// e.g. *Foo for []*Foo
	elemType := val.Type().Elem()
	// fmt.Println("elemType: ", elemType.String())

	// fast path for []byte
	if elemType.Kind() == reflect.Uint8 {
		// fmt.Println("decode: []byte fast path")
		reflect.Copy(val, reflect.ValueOf(buf.ReadN(int(n))))
		return buf.Pos(), buf.Error()
	}

	pos := buf.Pos()
	// a is a pointer to an array [n]*Foo, where n is know at compile time
	a := reflect.New(val.Type()).Elem()
	for i := 0; i < int(n); i++ {

		// if the slice elements are pointers we need to create
		// them before we can marshal data into them.
		if elemType.Kind() == reflect.Pointer {
			a.Index(i).Set(reflect.New(elemType.Elem()))
		}

		ename := fmt.Sprintf("%s[%d]", name, i)
		m, err := decode(b[pos:], a.Index(i), ename)
		if err != nil {
			return pos, err
		}
		pos += m
	}
	val.Set(a)

	return pos, nil
}
