// SPDX-License-Identifier: MIT

package uamethod_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

type args interface {
	Pack() []*ua.Variant
	Unpack([]*ua.Variant) error
}

// filled returns the arguments of the generated contracts with a value
// other than the zero value in every field.
func filled() []args {
	n := ua.NewNumericNodeID(1, 42)
	return []args{
		&uamethod.FileTypeOpenInput{Mode: 3},
		&uamethod.FileTypeOpenOutput{FileHandle: 7},
		&uamethod.FileTypeCloseInput{FileHandle: 7},
		&uamethod.FileTypeReadInput{FileHandle: 7, Length: 10},
		&uamethod.FileTypeReadOutput{Data: []byte{1, 2}},
		&uamethod.FileTypeWriteInput{FileHandle: 7, Data: []byte{3}},
		&uamethod.FileTypeGetPositionInput{FileHandle: 7},
		&uamethod.FileTypeGetPositionOutput{Position: 9},
		&uamethod.FileTypeSetPositionInput{FileHandle: 7, Position: 9},
		&uamethod.FileDirectoryTypeCreateDirectoryInput{DirectoryName: "d"},
		&uamethod.FileDirectoryTypeCreateDirectoryOutput{DirectoryNodeID: n},
		&uamethod.FileDirectoryTypeCreateFileInput{FileName: "f", RequestFileOpen: true},
		&uamethod.FileDirectoryTypeCreateFileOutput{FileNodeID: n, FileHandle: 7},
		&uamethod.FileDirectoryTypeDeleteInput{ObjectToDelete: n},
		&uamethod.FileDirectoryTypeMoveOrCopyInput{ObjectToMoveOrCopy: n, TargetDirectory: n, CreateCopy: true, NewName: "x"},
		&uamethod.FileDirectoryTypeMoveOrCopyOutput{NewNodeID: n},
		&uamethod.RoleSetTypeAddRoleInput{RoleName: "r", NamespaceURI: "urn:x"},
		&uamethod.RoleSetTypeAddRoleOutput{RoleNodeID: n},
		&uamethod.RoleSetTypeRemoveRoleInput{RoleNodeID: n},
		&uamethod.RoleTypeAddIdentityInput{Rule: rule},
		&uamethod.RoleTypeRemoveIdentityInput{Rule: rule},
		&uamethod.RoleTypeAddApplicationInput{ApplicationURI: "urn:app"},
		&uamethod.RoleTypeRemoveApplicationInput{ApplicationURI: "urn:app"},
		&uamethod.RoleTypeAddEndpointInput{Endpoint: ep},
		&uamethod.RoleTypeRemoveEndpointInput{Endpoint: ep},
		&uamethod.ServerTypeGetMonitoredItemsInput{SubscriptionID: 3},
		&uamethod.ServerTypeGetMonitoredItemsOutput{ServerHandles: []uint32{1, 2}, ClientHandles: []uint32{7, 8}},
		&uamethod.ServerTypeResendDataInput{SubscriptionID: 3},
		&uamethod.ServerTypeSetSubscriptionDurableInput{SubscriptionID: 3, LifetimeInHours: 24},
		&uamethod.ServerTypeSetSubscriptionDurableOutput{RevisedLifetimeInHours: 12},
		&uamethod.ServerTypeRequestServerStateChangeInput{
			State: int32(ua.ServerStateShutdown), EstimatedReturnTime: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
			SecondsTillShutdown: 60, Reason: ua.NewLocalizedText("update"), Restart: true,
		},
	}
}

var (
	rule = &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "u"}
	ep   = &ua.EndpointType{EndpointURL: "opc.tcp://h:4840", SecurityMode: ua.MessageSecurityModeSign}
)

// The contracts of the RoleSet and Role Methods (OPC 10000-18 §4.2, §4.4):
// those of RoleType are Optional in the NodeSet.
func TestRoleContracts(t *testing.T) {
	for _, c := range []struct {
		m         *uamethod.Method
		id, typID uint32
		clause    string
		mandatory bool
		in, out   int
	}{
		{uamethod.RoleSetTypeAddRole, id.RoleSetTypeAddRole, id.RoleSetType, "OPC 10000-18 §4.2.2", true, 2, 1},
		{uamethod.RoleSetTypeRemoveRole, id.RoleSetTypeRemoveRole, id.RoleSetType, "OPC 10000-18 §4.2.3", true, 1, 0},
		{uamethod.RoleTypeAddIdentity, id.RoleTypeAddIdentity, id.RoleType, "OPC 10000-18 §4.4.5", false, 1, 0},
		{uamethod.RoleTypeRemoveIdentity, id.RoleTypeRemoveIdentity, id.RoleType, "OPC 10000-18 §4.4.6", false, 1, 0},
		{uamethod.RoleTypeAddApplication, id.RoleTypeAddApplication, id.RoleType, "OPC 10000-18 §4.4.7", false, 1, 0},
		{uamethod.RoleTypeRemoveApplication, id.RoleTypeRemoveApplication, id.RoleType, "OPC 10000-18 §4.4.8", false, 1, 0},
		{uamethod.RoleTypeAddEndpoint, id.RoleTypeAddEndpoint, id.RoleType, "OPC 10000-18 §4.4.9", false, 1, 0},
		{uamethod.RoleTypeRemoveEndpoint, id.RoleTypeRemoveEndpoint, id.RoleType, "OPC 10000-18 §4.4.10", false, 1, 0},
	} {
		require.Equal(t, c.id, c.m.ID, c.m.String())
		require.Equal(t, c.typID, c.m.ObjectTypeID, c.m.String())
		require.Equal(t, c.clause, c.m.Clause, c.m.String())
		require.Equal(t, c.mandatory, c.m.Mandatory, c.m.String())
		require.Len(t, c.m.InputArguments(), c.in, c.m.String())
		require.Len(t, c.m.OutputArguments(), c.out, c.m.String())
	}
	require.Equal(t, ua.NewNumericNodeID(0, id.IdentityMappingRuleType), uamethod.RoleTypeAddIdentity.InputArguments()[0].DataType)
	require.Equal(t, ua.NewNumericNodeID(0, id.EndpointType), uamethod.RoleTypeAddEndpoint.InputArguments()[0].DataType)
}

func fresh(a args) args { return reflect.New(reflect.TypeOf(a).Elem()).Interface().(args) }

func TestPackUnpackRoundTrip(t *testing.T) {
	for _, a := range filled() {
		t.Run(reflect.TypeOf(a).Elem().Name(), func(t *testing.T) {
			got := fresh(a)
			require.NoError(t, got.Unpack(a.Pack()))
			require.Equal(t, a, got)
			// The zero value round-trips too: a nil NodeId is the null
			// NodeId, which unpacks as itself.
			zero := fresh(a)
			require.NoError(t, fresh(a).Unpack(zero.Pack()))
		})
	}
}

func TestUnpackCount(t *testing.T) {
	for _, a := range filled() {
		t.Run(reflect.TypeOf(a).Elem().Name(), func(t *testing.T) {
			vs := a.Pack()
			got := fresh(a)
			err := got.Unpack(vs[:len(vs)-1])
			require.ErrorIs(t, err, ua.StatusBadArgumentsMissing)
			require.Equal(t, fresh(a), got, "unchanged on error")
			var ae *uamethod.ArgumentError
			require.ErrorAs(t, err, &ae)
			require.Equal(t, -1, ae.Index)
			require.Empty(t, ae.Name)
			require.Equal(t, ua.StatusBadArgumentsMissing, uamethod.StatusOf(err))

			err = got.Unpack(append(vs, ua.MustVariant(int32(1))))
			require.ErrorIs(t, err, ua.StatusBadTooManyArguments)
			require.Contains(t, err.Error(), "arguments")
		})
	}
}

// other returns a Variant of another built-in type than v.
func other(v *ua.Variant) *ua.Variant {
	if v.Type() == ua.TypeIDString {
		return ua.MustVariant(int32(1))
	}
	return ua.MustVariant("x")
}

func TestUnpackTypeMismatch(t *testing.T) {
	for _, a := range filled() {
		t.Run(reflect.TypeOf(a).Elem().Name(), func(t *testing.T) {
			vs := a.Pack()
			for i := range vs {
				bad := a.Pack()
				bad[i] = other(vs[i])
				got := fresh(a)
				err := got.Unpack(bad)
				require.ErrorIs(t, err, ua.StatusBadTypeMismatch, "argument %d", i)
				require.Equal(t, fresh(a), got)
				var ae *uamethod.ArgumentError
				require.ErrorAs(t, err, &ae)
				require.Equal(t, i, ae.Index)
				require.NotEmpty(t, ae.Name)
				require.Contains(t, err.Error(), ae.Name)

				// The same type as an array is another ValueRank.
				bad[i] = arrayOf(vs[i])
				require.ErrorIs(t, got.Unpack(bad), ua.StatusBadTypeMismatch, "argument %d as array", i)

				// The null Variant is of no type.
				bad[i] = nil
				require.ErrorIs(t, got.Unpack(bad), ua.StatusBadTypeMismatch, "argument %d null", i)
			}
		})
	}
}

// arrayOf returns an array of the type of v.
func arrayOf(v *ua.Variant) *ua.Variant {
	switch x := v.Value().(type) {
	case uint8:
		return ua.MustVariant([]uint8{x}) // a ByteString, of another type
	case uint32:
		return ua.MustVariant([]uint32{x})
	case int32:
		return ua.MustVariant([]int32{x})
	case uint64:
		return ua.MustVariant([]uint64{x})
	case bool:
		return ua.MustVariant([]bool{x})
	case string:
		return ua.MustVariant([]string{x})
	case []byte:
		return ua.MustVariant([][]byte{x})
	case *ua.NodeID:
		return ua.MustVariant([]*ua.NodeID{x})
	case *ua.ExtensionObject:
		return ua.MustVariant([]*ua.ExtensionObject{x})
	case time.Time:
		return ua.MustVariant([]time.Time{x})
	case *ua.LocalizedText:
		return ua.MustVariant([]*ua.LocalizedText{x})
	case []uint32:
		// A scalar is another ValueRank than an array.
		return ua.MustVariant(uint32(1))
	}
	panic("unexpected type")
}

func TestContracts(t *testing.T) {
	ms := []struct {
		m         *uamethod.Method
		id, typID uint32
		clause    string
		in, out   int
	}{
		{uamethod.FileTypeOpen, id.FileTypeOpen, id.FileType, "OPC 10000-20 §4.2.2", 1, 1},
		{uamethod.FileTypeClose, id.FileTypeClose, id.FileType, "OPC 10000-20 §4.2.3", 1, 0},
		{uamethod.FileTypeRead, id.FileTypeRead, id.FileType, "OPC 10000-20 §4.2.4", 2, 1},
		{uamethod.FileTypeWrite, id.FileTypeWrite, id.FileType, "OPC 10000-20 §4.2.5", 2, 0},
		{uamethod.FileTypeGetPosition, id.FileTypeGetPosition, id.FileType, "OPC 10000-20 §4.2.6", 1, 1},
		{uamethod.FileTypeSetPosition, id.FileTypeSetPosition, id.FileType, "OPC 10000-20 §4.2.7", 2, 0},
		{uamethod.FileDirectoryTypeCreateDirectory, id.FileDirectoryTypeCreateDirectory, id.FileDirectoryType, "OPC 10000-20 §4.3.3", 1, 1},
		{uamethod.FileDirectoryTypeCreateFile, id.FileDirectoryTypeCreateFile, id.FileDirectoryType, "OPC 10000-20 §4.3.4", 2, 2},
		{uamethod.FileDirectoryTypeDelete, id.FileDirectoryTypeDeleteFileSystemObject, id.FileDirectoryType, "OPC 10000-20 §4.3.5", 1, 0},
		{uamethod.FileDirectoryTypeMoveOrCopy, id.FileDirectoryTypeMoveOrCopy, id.FileDirectoryType, "OPC 10000-20 §4.3.6", 4, 1},
	}
	for _, c := range ms {
		t.Run(c.m.String(), func(t *testing.T) {
			require.Equal(t, c.id, c.m.ID)
			require.Equal(t, c.typID, c.m.ObjectTypeID)
			require.Equal(t, c.clause, c.m.Clause)
			require.True(t, c.m.Mandatory)
			require.Empty(t, c.m.Namespace)
			require.Equal(t, ua.NewNumericNodeID(2, c.id), c.m.NodeID(2))
			require.Equal(t, ua.NewNumericNodeID(0, c.typID), c.m.ObjectTypeNodeID(0))
			in, out := c.m.InputArguments(), c.m.OutputArguments()
			require.Len(t, in, c.in)
			require.Len(t, out, c.out)
			if c.out == 0 {
				require.Nil(t, out)
			}
			for _, a := range append(in, out...) {
				require.NotEmpty(t, a.Name)
				require.Equal(t, uint16(0), a.DataType.Namespace())
				require.Equal(t, int32(-1), a.ValueRank)
			}
			// A fresh slice on each call.
			in[0].Name = "changed"
			require.NotEqual(t, "changed", c.m.InputArguments()[0].Name)
		})
	}
	require.Equal(t, "Mode", uamethod.FileTypeOpen.InputArguments()[0].Name)

	// The Methods of ServerType (OPC 10000-5 §9) are Optional; the handles
	// of GetMonitoredItems are arrays.
	for _, c := range []struct {
		m       *uamethod.Method
		id      uint32
		clause  string
		in, out int
	}{
		{uamethod.ServerTypeGetMonitoredItems, id.ServerTypeGetMonitoredItems, "OPC 10000-5 §9.1", 1, 2},
		{uamethod.ServerTypeResendData, id.ServerTypeResendData, "OPC 10000-5 §9.2", 1, 0},
		{uamethod.ServerTypeSetSubscriptionDurable, id.ServerTypeSetSubscriptionDurable, "OPC 10000-5 §9.3", 2, 1},
		{uamethod.ServerTypeRequestServerStateChange, id.ServerTypeRequestServerStateChange, "OPC 10000-5 §9.4", 5, 0},
	} {
		require.Equal(t, c.id, c.m.ID, c.m.String())
		require.Equal(t, uint32(id.ServerType), c.m.ObjectTypeID)
		require.Equal(t, c.clause, c.m.Clause)
		require.False(t, c.m.Mandatory)
		require.Len(t, c.m.InputArguments(), c.in)
		require.Len(t, c.m.OutputArguments(), c.out)
	}
	out := uamethod.ServerTypeGetMonitoredItems.OutputArguments()
	require.Equal(t, "ServerHandles", out[0].Name)
	require.Equal(t, int32(1), out[0].ValueRank)
	state := uamethod.ServerTypeRequestServerStateChange.InputArguments()
	require.Equal(t, ua.NewNumericNodeID(0, id.ServerState), state[0].DataType)
	require.Equal(t, ua.NewNumericNodeID(0, id.LocalizedText), state[3].DataType)
	require.Equal(t, ua.NewNumericNodeID(0, id.Byte), uamethod.FileTypeOpen.InputArguments()[0].DataType)
}

// caller is a fake server of one Method.
type caller struct {
	req *ua.CallMethodRequest
	res *ua.CallMethodResult
	err error
}

func (c *caller) Call(_ context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	c.req = req
	return c.res, c.err
}

func TestCall(t *testing.T) {
	ctx := context.Background()
	obj := ua.NewNumericNodeID(1, 5)
	c := &caller{res: &ua.CallMethodResult{OutputArguments: []*ua.Variant{ua.MustVariant(uint32(4))}}}

	out, err := uamethod.CallFileTypeOpen(ctx, c, obj, nil, &uamethod.FileTypeOpenInput{Mode: 1})
	require.NoError(t, err)
	require.Equal(t, uint32(4), out.FileHandle)
	require.Equal(t, obj, c.req.ObjectID)
	require.Equal(t, ua.NewNumericNodeID(0, id.FileTypeOpen), c.req.MethodID, "the declaration")
	require.Equal(t, []*ua.Variant{ua.MustVariant(uint8(1))}, c.req.InputArguments)

	m := ua.NewStringNodeID(1, "obj.Open")
	_, err = uamethod.CallFileTypeOpen(ctx, c, obj, m, nil)
	require.NoError(t, err)
	require.Equal(t, m, c.req.MethodID)
	require.Equal(t, []*ua.Variant{ua.MustVariant(uint8(0))}, c.req.InputArguments, "nil input is the zero input")

	// Outputs that do not match.
	c.res = &ua.CallMethodResult{OutputArguments: []*ua.Variant{ua.MustVariant("h")}}
	_, err = uamethod.CallFileTypeOpen(ctx, c, obj, nil, nil)
	var ae *uamethod.ArgumentError
	require.ErrorAs(t, err, &ae)
	require.True(t, ae.Output)
	require.Equal(t, "FileHandle", ae.Name)
	require.Contains(t, err.Error(), "output argument 0 (FileHandle): a String, want a Uint32")

	// A Method without outputs refuses outputs.
	require.ErrorIs(t, uamethod.CallFileTypeClose(ctx, c, obj, nil, nil), ua.StatusBadTooManyArguments)
	c.res = &ua.CallMethodResult{}
	require.NoError(t, uamethod.CallFileTypeClose(ctx, c, obj, nil, &uamethod.FileTypeCloseInput{FileHandle: 1}))

	// A Bad result.
	c.res = &ua.CallMethodResult{StatusCode: ua.StatusBadInvalidArgument, InputArgumentResults: []ua.StatusCode{ua.StatusBadTypeMismatch}}
	err = uamethod.CallFileTypeClose(ctx, c, obj, nil, nil)
	var ce *uamethod.CallError
	require.ErrorAs(t, err, &ce)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	require.Equal(t, "FileType.Close", ce.Method)
	require.Equal(t, []ua.StatusCode{ua.StatusBadTypeMismatch}, ce.InputArgumentResults)
	require.Equal(t, "uamethod: FileType.Close: "+ua.StatusBadInvalidArgument.Error(), err.Error())
	_, err = uamethod.CallFileTypeRead(ctx, c, obj, nil, nil)
	require.ErrorAs(t, err, &ce)

	// An Uncertain result is not an error.
	c.res = &ua.CallMethodResult{StatusCode: ua.StatusUncertain, OutputArguments: []*ua.Variant{ua.MustVariant(uint64(3))}}
	pos, err := uamethod.CallFileTypeGetPosition(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(3), pos.Position)

	// A service error, and no result.
	c.err = errors.New("down")
	_, err = uamethod.CallFileTypeGetPosition(ctx, c, obj, nil, nil)
	require.ErrorContains(t, err, "uamethod: FileType.GetPosition: down")
	c.err, c.res = nil, nil
	_, err = uamethod.FileTypeGetPosition.Call(ctx, c, obj, nil, nil)
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)
}

func TestCallAll(t *testing.T) {
	ctx := context.Background()
	obj := ua.NewNumericNodeID(1, 5)
	n := ua.NewNumericNodeID(1, 6)
	c := &caller{}
	ok := func(out ...any) {
		c.res = &ua.CallMethodResult{}
		for _, o := range out {
			c.res.OutputArguments = append(c.res.OutputArguments, ua.MustVariant(o))
		}
	}
	bad := func() { c.res = &ua.CallMethodResult{StatusCode: ua.StatusBadNotFound} }

	ok([]byte{1})
	r, err := uamethod.CallFileTypeRead(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []byte{1}, r.Data)
	ok()
	require.NoError(t, uamethod.CallFileTypeWrite(ctx, c, obj, nil, nil))
	require.NoError(t, uamethod.CallFileTypeSetPosition(ctx, c, obj, nil, nil))
	require.NoError(t, uamethod.CallFileDirectoryTypeDelete(ctx, c, obj, nil, nil))
	ok(n)
	d, err := uamethod.CallFileDirectoryTypeCreateDirectory(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, n, d.DirectoryNodeID)
	mv, err := uamethod.CallFileDirectoryTypeMoveOrCopy(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, n, mv.NewNodeID)
	ok(n, uint32(3))
	f, err := uamethod.CallFileDirectoryTypeCreateFile(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, uint32(3), f.FileHandle)
	ok()
	require.NoError(t, uamethod.CallFileDirectoryTypeDelete(ctx, c, obj, nil, nil))
	require.Equal(t, ua.NewTwoByteNodeID(0), c.req.InputArguments[0].Value(), "the null NodeId for nil")

	ok([]uint32{4}, []uint32{9})
	mi, err := uamethod.CallServerTypeGetMonitoredItems(ctx, c, obj, nil, &uamethod.ServerTypeGetMonitoredItemsInput{SubscriptionID: 2})
	require.NoError(t, err)
	require.Equal(t, []uint32{4}, mi.ServerHandles)
	require.Equal(t, []uint32{9}, mi.ClientHandles)
	require.Equal(t, ua.NewNumericNodeID(0, id.ServerTypeGetMonitoredItems), c.req.MethodID)
	ok(uint32(5))
	d2, err := uamethod.CallServerTypeSetSubscriptionDurable(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, uint32(5), d2.RevisedLifetimeInHours)
	ok()
	require.NoError(t, uamethod.CallServerTypeResendData(ctx, c, obj, nil, nil))
	require.NoError(t, uamethod.CallServerTypeRequestServerStateChange(ctx, c, obj, nil, nil))
	require.Equal(t, &ua.LocalizedText{}, c.req.InputArguments[3].Value(), "the null LocalizedText for nil")

	bad()
	for _, call := range []func() error{
		func() error { _, err := uamethod.CallServerTypeGetMonitoredItems(ctx, c, obj, nil, nil); return err },
		func() error { return uamethod.CallServerTypeResendData(ctx, c, obj, nil, nil) },
		func() error {
			_, err := uamethod.CallServerTypeSetSubscriptionDurable(ctx, c, obj, nil, nil)
			return err
		},
		func() error { return uamethod.CallServerTypeRequestServerStateChange(ctx, c, obj, nil, nil) },
		func() error { _, err := uamethod.CallFileTypeOpen(ctx, c, obj, nil, nil); return err },
		func() error { _, err := uamethod.CallFileTypeRead(ctx, c, obj, nil, nil); return err },
		func() error { return uamethod.CallFileTypeWrite(ctx, c, obj, nil, nil) },
		func() error { _, err := uamethod.CallFileTypeGetPosition(ctx, c, obj, nil, nil); return err },
		func() error { return uamethod.CallFileTypeSetPosition(ctx, c, obj, nil, nil) },
		func() error {
			_, err := uamethod.CallFileDirectoryTypeCreateDirectory(ctx, c, obj, nil, nil)
			return err
		},
		func() error { _, err := uamethod.CallFileDirectoryTypeCreateFile(ctx, c, obj, nil, nil); return err },
		func() error { return uamethod.CallFileDirectoryTypeDelete(ctx, c, obj, nil, nil) },
		func() error { _, err := uamethod.CallFileDirectoryTypeMoveOrCopy(ctx, c, obj, nil, nil); return err },
	} {
		require.ErrorIs(t, call(), ua.StatusBadNotFound)
	}
	// Outputs of the wrong count.
	ok(int32(1), int32(2), int32(3), int32(4), int32(5))
	for _, call := range []func() error{
		func() error { _, err := uamethod.CallServerTypeGetMonitoredItems(ctx, c, obj, nil, nil); return err },
		func() error { return uamethod.CallServerTypeResendData(ctx, c, obj, nil, nil) },
		func() error {
			_, err := uamethod.CallServerTypeSetSubscriptionDurable(ctx, c, obj, nil, nil)
			return err
		},
		func() error { return uamethod.CallServerTypeRequestServerStateChange(ctx, c, obj, nil, nil) },
		func() error { _, err := uamethod.CallFileTypeOpen(ctx, c, obj, nil, nil); return err },
		func() error { _, err := uamethod.CallFileTypeRead(ctx, c, obj, nil, nil); return err },
		func() error { return uamethod.CallFileTypeWrite(ctx, c, obj, nil, nil) },
		func() error { _, err := uamethod.CallFileTypeGetPosition(ctx, c, obj, nil, nil); return err },
		func() error { return uamethod.CallFileTypeSetPosition(ctx, c, obj, nil, nil) },
		func() error {
			_, err := uamethod.CallFileDirectoryTypeCreateDirectory(ctx, c, obj, nil, nil)
			return err
		},
		func() error { _, err := uamethod.CallFileDirectoryTypeCreateFile(ctx, c, obj, nil, nil); return err },
		func() error { return uamethod.CallFileDirectoryTypeDelete(ctx, c, obj, nil, nil) },
		func() error { _, err := uamethod.CallFileDirectoryTypeMoveOrCopy(ctx, c, obj, nil, nil); return err },
	} {
		require.ErrorIs(t, call(), ua.StatusBadTooManyArguments)
	}
}

func TestStatusOf(t *testing.T) {
	require.Equal(t, ua.StatusOK, uamethod.StatusOf(nil))
	require.Equal(t, ua.StatusBadInvalidArgument, uamethod.StatusOf(errors.New("x")))
	var in uamethod.FileTypeOpenInput
	require.Equal(t, ua.StatusBadArgumentsMissing, uamethod.StatusOf(in.Unpack(nil)))
}
