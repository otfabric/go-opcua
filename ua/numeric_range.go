// SPDX-License-Identifier: MIT

package ua

import (
	"reflect"
	"strconv"
	"strings"
	"time"
)

// NumericRange is a one-dimensional inclusive index range ("i" or "i:j").
type NumericRange struct {
	Start int // inclusive
	End   int // inclusive
}

// ParseNumericRange parses a one-dimensional NumericRange string.
// Returns StatusBadIndexRangeInvalid for malformed input or multi-dim forms.
func ParseNumericRange(s string) (NumericRange, error) {
	ranges, err := ParseNumericRanges(s)
	if err != nil {
		return NumericRange{}, err
	}
	if len(ranges) != 1 {
		return NumericRange{}, StatusBadIndexRangeInvalid
	}
	return ranges[0], nil
}

// ParseNumericRanges parses a NumericRange that may contain multiple
// comma-separated dimensions ("i:j,k:l").
func ParseNumericRanges(s string) ([]NumericRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, StatusBadIndexRangeInvalid
	}
	parts := strings.Split(s, ",")
	out := make([]NumericRange, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, StatusBadIndexRangeInvalid
		}
		r, err := parseOneRange(p)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func parseOneRange(s string) (NumericRange, error) {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		i, err := strconv.Atoi(parts[0])
		if err != nil || i < 0 {
			return NumericRange{}, StatusBadIndexRangeInvalid
		}
		return NumericRange{Start: i, End: i}, nil
	case 2:
		// Allow "i:" as open-ended end → resolved against dimension length later
		// by callers via End < 0 sentinel. For Phase 13 we require both ends.
		if parts[0] == "" || parts[1] == "" {
			return NumericRange{}, StatusBadIndexRangeInvalid
		}
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || start < 0 || end < 0 || start > end {
			return NumericRange{}, StatusBadIndexRangeInvalid
		}
		return NumericRange{Start: start, End: end}, nil
	default:
		return NumericRange{}, StatusBadIndexRangeInvalid
	}
}

// Len returns the number of elements in the range (inclusive).
func (r NumericRange) Len() int {
	return r.End - r.Start + 1
}

// SliceVariantRead returns a new Variant containing the IndexRange subset of v.
// Supports one-dimensional arrays, ByteString (byte substring), and rectangular
// multi-dimensional arrays (nested Go slices or ArrayDimensions).
func SliceVariantRead(v *Variant, rangeStr string) (*Variant, StatusCode) {
	if v == nil {
		return nil, StatusBadIndexRangeInvalid
	}
	ranges, err := ParseNumericRanges(rangeStr)
	if err != nil {
		if sc, ok := err.(StatusCode); ok {
			return nil, sc
		}
		return nil, StatusBadIndexRangeInvalid
	}

	// Scalar ByteString: treat as a byte array for IndexRange.
	if !v.IsArray() {
		if v.Type() == TypeIDByteString {
			if len(ranges) != 1 {
				return nil, StatusBadIndexRangeInvalid
			}
			bs, ok := v.Value().([]byte)
			if !ok {
				return nil, StatusBadIndexRangeInvalid
			}
			return sliceBytes(bs, ranges[0])
		}
		return nil, StatusBadIndexRangeInvalid
	}

	dims := arrayDims(v)
	if len(ranges) != len(dims) {
		return nil, StatusBadIndexRangeInvalid
	}
	if len(dims) == 1 {
		return slice1D(v, ranges[0])
	}
	return sliceMatrix(v, dims, ranges)
}

func sliceBytes(bs []byte, r NumericRange) (*Variant, StatusCode) {
	n := len(bs)
	if n == 0 || r.Start >= n {
		return nil, StatusBadIndexRangeNoData
	}
	end := r.End
	if end >= n {
		end = n - 1
	}
	if end < r.Start {
		return nil, StatusBadIndexRangeNoData
	}
	out, err := NewVariant(append([]byte(nil), bs[r.Start:end+1]...))
	if err != nil {
		return nil, StatusBadIndexRangeInvalid
	}
	return out, StatusOK
}

func slice1D(v *Variant, r NumericRange) (*Variant, StatusCode) {
	rv := reflect.ValueOf(v.Value())
	if rv.Kind() != reflect.Slice {
		return nil, StatusBadIndexRangeInvalid
	}
	n := rv.Len()
	if n == 0 || r.Start >= n {
		return nil, StatusBadIndexRangeNoData
	}
	end := r.End
	if end >= n {
		end = n - 1
	}
	if end < r.Start {
		return nil, StatusBadIndexRangeNoData
	}
	sliced := rv.Slice(r.Start, end+1).Interface()
	out, err := NewVariant(sliced)
	if err != nil {
		return nil, StatusBadIndexRangeInvalid
	}
	return out, StatusOK
}

func arrayDims(v *Variant) []int {
	if d := v.ArrayDimensions(); len(d) > 0 {
		out := make([]int, len(d))
		for i, x := range d {
			out[i] = int(x)
		}
		return out
	}
	rv := reflect.ValueOf(v.Value())
	return nestedSliceDims(rv)
}

func nestedSliceDims(rv reflect.Value) []int {
	if rv.Kind() != reflect.Slice {
		return nil
	}
	dims := []int{rv.Len()}
	if rv.Len() == 0 {
		return dims
	}
	inner := rv.Index(0)
	if inner.Kind() == reflect.Interface {
		inner = reflect.ValueOf(inner.Interface())
	}
	if inner.Kind() == reflect.Slice {
		dims = append(dims, nestedSliceDims(inner)...)
	}
	return dims
}

func flattenMatrix(v *Variant, dims []int) (reflect.Value, error) {
	rv := reflect.ValueOf(v.Value())
	// Already flat 1D with ArrayDimensions set.
	if rv.Kind() == reflect.Slice && (len(dims) == 1 || !isNestedSlice(rv)) {
		return rv, nil
	}
	elemType, ok := leafElemType(rv)
	if !ok {
		return reflect.Value{}, StatusBadIndexRangeInvalid
	}
	total := 1
	for _, d := range dims {
		total *= d
	}
	flat := reflect.MakeSlice(reflect.SliceOf(elemType), 0, total)
	var walk func(reflect.Value) StatusCode
	walk = func(x reflect.Value) StatusCode {
		if x.Kind() == reflect.Interface {
			x = reflect.ValueOf(x.Interface())
		}
		if x.Kind() != reflect.Slice {
			flat = reflect.Append(flat, x)
			return StatusOK
		}
		for i := 0; i < x.Len(); i++ {
			if sc := walk(x.Index(i)); sc != StatusOK {
				return sc
			}
		}
		return StatusOK
	}
	if sc := walk(rv); sc != StatusOK {
		return reflect.Value{}, sc
	}
	if flat.Len() != total {
		return reflect.Value{}, StatusBadIndexRangeInvalid
	}
	return flat, nil
}

func isNestedSlice(rv reflect.Value) bool {
	if rv.Kind() != reflect.Slice || rv.Len() == 0 {
		return false
	}
	inner := rv.Index(0)
	if inner.Kind() == reflect.Interface {
		inner = reflect.ValueOf(inner.Interface())
	}
	return inner.Kind() == reflect.Slice
}

func leafElemType(rv reflect.Value) (reflect.Type, bool) {
	for rv.Kind() == reflect.Slice {
		if rv.Len() == 0 {
			return rv.Type().Elem(), true
		}
		el := rv.Index(0)
		if el.Kind() == reflect.Interface {
			el = reflect.ValueOf(el.Interface())
		}
		if el.Kind() != reflect.Slice {
			return el.Type(), true
		}
		rv = el
	}
	return nil, false
}

func sliceMatrix(v *Variant, dims []int, ranges []NumericRange) (*Variant, StatusCode) {
	flat, err := flattenMatrix(v, dims)
	if err != nil {
		if sc, ok := err.(StatusCode); ok {
			return nil, sc
		}
		return nil, StatusBadIndexRangeInvalid
	}
	selDims := make([]int, len(ranges))
	for i, r := range ranges {
		if r.Start >= dims[i] {
			return nil, StatusBadIndexRangeNoData
		}
		end := r.End
		if end >= dims[i] {
			end = dims[i] - 1
		}
		if end < r.Start {
			return nil, StatusBadIndexRangeNoData
		}
		selDims[i] = end - r.Start + 1
		ranges[i].End = end
	}

	total := 1
	for _, d := range selDims {
		total *= d
	}
	outFlat := reflect.MakeSlice(flat.Type(), total, total)
	idx := 0
	var fill func(dim int, base int)
	fill = func(dim int, base int) {
		if dim == len(dims) {
			outFlat.Index(idx).Set(flat.Index(base))
			idx++
			return
		}
		stride := 1
		for d := dim + 1; d < len(dims); d++ {
			stride *= dims[d]
		}
		for i := ranges[dim].Start; i <= ranges[dim].End; i++ {
			fill(dim+1, base+i*stride)
		}
	}
	fill(0, 0)

	nested := nestFlat(outFlat, selDims)
	out, err2 := NewVariant(nested)
	if err2 != nil {
		return nil, StatusBadIndexRangeInvalid
	}
	return out, StatusOK
}

func nestFlat(flat reflect.Value, dims []int) interface{} {
	if len(dims) == 1 {
		return flat.Interface()
	}
	// Build nested [][]...T
	elemType := flat.Type().Elem()
	var buildType func([]int) reflect.Type
	buildType = func(d []int) reflect.Type {
		if len(d) == 1 {
			return reflect.SliceOf(elemType)
		}
		return reflect.SliceOf(buildType(d[1:]))
	}
	var build func([]int, int) (reflect.Value, int)
	build = func(d []int, off int) (reflect.Value, int) {
		if len(d) == 1 {
			s := reflect.MakeSlice(reflect.SliceOf(elemType), d[0], d[0])
			for i := 0; i < d[0]; i++ {
				s.Index(i).Set(flat.Index(off + i))
			}
			return s, off + d[0]
		}
		s := reflect.MakeSlice(buildType(d), d[0], d[0])
		for i := 0; i < d[0]; i++ {
			var child reflect.Value
			child, off = build(d[1:], off)
			s.Index(i).Set(child)
		}
		return s, off
	}
	s, _ := build(dims, 0)
	return s.Interface()
}

// MergeVariantWrite merges newVal into current at the given IndexRange and
// returns the updated full array as a Variant.
func MergeVariantWrite(current *Variant, rangeStr string, newVal *Variant) (*Variant, StatusCode) {
	if current == nil {
		return nil, StatusBadIndexRangeInvalid
	}
	if newVal == nil || newVal.Value() == nil {
		return nil, StatusBadTypeMismatch
	}
	ranges, err := ParseNumericRanges(rangeStr)
	if err != nil {
		if sc, ok := err.(StatusCode); ok {
			return nil, sc
		}
		return nil, StatusBadIndexRangeInvalid
	}

	if !current.IsArray() {
		if current.Type() == TypeIDByteString {
			if len(ranges) != 1 {
				return nil, StatusBadIndexRangeInvalid
			}
			return mergeBytes(current, ranges[0], newVal)
		}
		return nil, StatusBadIndexRangeInvalid
	}

	dims := arrayDims(current)
	if len(ranges) != len(dims) {
		return nil, StatusBadIndexRangeInvalid
	}
	if len(dims) == 1 {
		return merge1D(current, ranges[0], newVal)
	}
	return mergeMatrix(current, dims, ranges, newVal)
}

func mergeBytes(current *Variant, r NumericRange, newVal *Variant) (*Variant, StatusCode) {
	bs, ok := current.Value().([]byte)
	if !ok {
		return nil, StatusBadIndexRangeInvalid
	}
	n := len(bs)
	if r.Start >= n || r.End >= n {
		return nil, StatusBadIndexRangeNoData
	}
	want := r.Len()
	var patch []byte
	switch v := newVal.Value().(type) {
	case []byte:
		patch = v
	default:
		return nil, StatusBadTypeMismatch
	}
	if len(patch) != want {
		return nil, StatusBadIndexRangeDataMismatch
	}
	merged := append([]byte(nil), bs...)
	copy(merged[r.Start:r.End+1], patch)
	out, err := NewVariant(merged)
	if err != nil {
		return nil, StatusBadIndexRangeInvalid
	}
	return out, StatusOK
}

func merge1D(current *Variant, r NumericRange, newVal *Variant) (*Variant, StatusCode) {
	curRV := reflect.ValueOf(current.Value())
	if curRV.Kind() != reflect.Slice {
		return nil, StatusBadIndexRangeInvalid
	}
	n := curRV.Len()
	if r.Start >= n || r.End >= n {
		return nil, StatusBadIndexRangeNoData
	}
	wantLen := r.Len()

	newRV := reflect.ValueOf(newVal.Value())
	if !newVal.IsArray() {
		if wantLen != 1 {
			return nil, StatusBadIndexRangeDataMismatch
		}
		if curRV.Type().Elem() != newRV.Type() {
			return nil, StatusBadTypeMismatch
		}
		merged := reflect.MakeSlice(curRV.Type(), n, n)
		reflect.Copy(merged, curRV)
		merged.Index(r.Start).Set(newRV)
		out, err := NewVariant(merged.Interface())
		if err != nil {
			return nil, StatusBadIndexRangeInvalid
		}
		return out, StatusOK
	}
	if newRV.Kind() != reflect.Slice {
		return nil, StatusBadIndexRangeDataMismatch
	}
	if newRV.Len() != wantLen {
		return nil, StatusBadIndexRangeDataMismatch
	}
	if curRV.Type() != newRV.Type() {
		return nil, StatusBadTypeMismatch
	}
	merged := reflect.MakeSlice(curRV.Type(), n, n)
	reflect.Copy(merged, curRV)
	for i := 0; i < wantLen; i++ {
		merged.Index(r.Start + i).Set(newRV.Index(i))
	}
	out, err := NewVariant(merged.Interface())
	if err != nil {
		return nil, StatusBadIndexRangeInvalid
	}
	return out, StatusOK
}

func mergeMatrix(current *Variant, dims []int, ranges []NumericRange, newVal *Variant) (*Variant, StatusCode) {
	flat, err := flattenMatrix(current, dims)
	if err != nil {
		if sc, ok := err.(StatusCode); ok {
			return nil, sc
		}
		return nil, StatusBadIndexRangeInvalid
	}
	selDims := make([]int, len(ranges))
	for i, r := range ranges {
		if r.Start >= dims[i] || r.End >= dims[i] {
			return nil, StatusBadIndexRangeNoData
		}
		selDims[i] = r.Len()
	}
	wantTotal := 1
	for _, d := range selDims {
		wantTotal *= d
	}

	patchFlat, sc := flattenPatch(newVal, selDims, flat.Type().Elem())
	if sc != StatusOK {
		return nil, sc
	}
	if patchFlat.Len() != wantTotal {
		return nil, StatusBadIndexRangeDataMismatch
	}

	merged := reflect.MakeSlice(flat.Type(), flat.Len(), flat.Len())
	reflect.Copy(merged, flat)

	idx := 0
	var apply func(dim int, base int)
	apply = func(dim int, base int) {
		if dim == len(dims) {
			merged.Index(base).Set(patchFlat.Index(idx))
			idx++
			return
		}
		stride := 1
		for d := dim + 1; d < len(dims); d++ {
			stride *= dims[d]
		}
		for i := ranges[dim].Start; i <= ranges[dim].End; i++ {
			apply(dim+1, base+i*stride)
		}
	}
	apply(0, 0)

	nested := nestFlat(merged, dims)
	out, err2 := NewVariant(nested)
	if err2 != nil {
		return nil, StatusBadIndexRangeInvalid
	}
	return out, StatusOK
}

func flattenPatch(newVal *Variant, selDims []int, elemType reflect.Type) (reflect.Value, StatusCode) {
	rv := reflect.ValueOf(newVal.Value())
	total := 1
	for _, d := range selDims {
		total *= d
	}
	flat := reflect.MakeSlice(reflect.SliceOf(elemType), 0, total)
	var walk func(reflect.Value) StatusCode
	walk = func(x reflect.Value) StatusCode {
		if x.Kind() == reflect.Interface {
			x = reflect.ValueOf(x.Interface())
		}
		if x.Kind() != reflect.Slice {
			if !x.Type().AssignableTo(elemType) {
				return StatusBadTypeMismatch
			}
			flat = reflect.Append(flat, x)
			return StatusOK
		}
		for i := 0; i < x.Len(); i++ {
			if sc := walk(x.Index(i)); sc != StatusOK {
				return sc
			}
		}
		return StatusOK
	}
	if sc := walk(rv); sc != StatusOK {
		return reflect.Value{}, sc
	}
	return flat, StatusOK
}

// ApplyTimestampsToReturn filters timestamp fields on dv according to ts.
// Mutates dv in place. Returns StatusBadTimestampsToReturnInvalid for invalid ts.
func ApplyTimestampsToReturn(dv *DataValue, ts TimestampsToReturn) StatusCode {
	if dv == nil {
		return StatusOK
	}
	now := time.Now().UTC()
	switch ts {
	case TimestampsToReturnSource:
		dv.EncodingMask &^= DataValueServerTimestamp | DataValueServerPicoseconds
		dv.ServerTimestamp = time.Time{}
		dv.ServerPicoseconds = 0
		if !dv.SourceTimestamp.IsZero() {
			dv.EncodingMask |= DataValueSourceTimestamp
		}
	case TimestampsToReturnServer:
		dv.EncodingMask &^= DataValueSourceTimestamp | DataValueSourcePicoseconds
		dv.SourceTimestamp = time.Time{}
		dv.SourcePicoseconds = 0
		if dv.ServerTimestamp.IsZero() {
			dv.ServerTimestamp = now
		}
		dv.EncodingMask |= DataValueServerTimestamp
	case TimestampsToReturnBoth:
		if dv.ServerTimestamp.IsZero() {
			dv.ServerTimestamp = now
		}
		dv.EncodingMask |= DataValueServerTimestamp
		if !dv.SourceTimestamp.IsZero() {
			dv.EncodingMask |= DataValueSourceTimestamp
		}
	case TimestampsToReturnNeither:
		dv.EncodingMask &^= DataValueSourceTimestamp | DataValueServerTimestamp |
			DataValueSourcePicoseconds | DataValueServerPicoseconds
		dv.SourceTimestamp = time.Time{}
		dv.ServerTimestamp = time.Time{}
		dv.SourcePicoseconds = 0
		dv.ServerPicoseconds = 0
	case TimestampsToReturnInvalid:
		return StatusBadTimestampsToReturnInvalid
	default:
		return StatusBadTimestampsToReturnInvalid
	}
	return StatusOK
}
