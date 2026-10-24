// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// calcMethodPDS is a PublishedActionMethod "Calc": target 1 "Add" calls
// ns=1;s=Add of ns=1;s=Calc, target 2 "Sub" ns=1;s=Sub.
func calcMethodPDS() *ua.PublishedDataSetDataType {
	obj := ua.NewStringNodeID(1, "Calc")
	return PublishedActionMethods("Calc",
		[]Field{{Name: "A", Type: ua.TypeIDInt32}, {Name: "B", Type: ua.TypeIDInt32}},
		[]Field{{Name: "Sum", Type: ua.TypeIDInt32}},
		[]*ua.ActionTargetDataType{ActionTargetOf(1, "Add"), ActionTargetOf(2, "Sub")},
		[]*ua.ActionMethodDataType{ActionMethodOf(obj, ua.NewStringNodeID(1, "Add")), ActionMethodOf(obj, ua.NewStringNodeID(1, "Sub"))})
}

func TestValidateActionMethods(t *testing.T) {
	cfg := func(mut func(*ua.PublishedActionMethodDataType)) *ua.PubSubConfigurationDataType {
		pds := calcMethodPDS()
		mut(pds.DataSetSource.Value.(*ua.PublishedActionMethodDataType))
		return NewConfiguration([]*ua.PublishedDataSetDataType{pds})
	}
	require.NoError(t, Validate(cfg(func(*ua.PublishedActionMethodDataType) {})))
	for name, mut := range map[string]func(*ua.PublishedActionMethodDataType){
		"fewer methods": func(s *ua.PublishedActionMethodDataType) { s.ActionMethods = s.ActionMethods[:1] },
		"more methods": func(s *ua.PublishedActionMethodDataType) {
			s.ActionMethods = append(s.ActionMethods, s.ActionMethods[0])
		},
		"nil method":     func(s *ua.PublishedActionMethodDataType) { s.ActionMethods[1] = nil },
		"no object":      func(s *ua.PublishedActionMethodDataType) { s.ActionMethods[0].ObjectID = nil },
		"no method":      func(s *ua.PublishedActionMethodDataType) { s.ActionMethods[0].MethodID = nil },
		"null method id": func(s *ua.PublishedActionMethodDataType) { s.ActionMethods[0].MethodID = ua.NewNumericNodeID(0, 0) },
	} {
		require.ErrorIs(t, Validate(cfg(mut)), ua.StatusBadConfigurationError, name)
	}
}

type methodCall struct {
	obj, method *ua.NodeID
	inputs      []*ua.Variant
	inv         ActionInvocation
}

// TestActionMethodCaller: the targets of a PublishedActionMethod call their
// Method through the ActionMethodCaller; a registered handler takes
// precedence, and without a caller a target is not implemented.
func TestActionMethodCaller(t *testing.T) {
	url := memURL(t)
	var mu sync.Mutex
	var calls []methodCall
	caller := func(ctx context.Context, obj, method *ua.NodeID, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		inv, _ := ActionInvocationFrom(ctx)
		mu.Lock()
		calls = append(calls, methodCall{obj, method, in, inv})
		mu.Unlock()
		a, _ := in[0].Value().(int32)
		b, _ := in[1].Value().(int32)
		if method.StringID() == "Sub" {
			return int32s(a - b), ua.StatusGood
		}
		return int32s(a + b), ua.StatusGood
	}
	g := WriterGroup("Actions", 10, 50*time.Millisecond, DataSetWriter("CalcWriter", 100, "Calc"))
	resp := startReal(t, NewConfiguration([]*ua.PublishedDataSetDataType{calcMethodPDS()},
		AttachWriterGroups(memConnection("Responder", url, uint16(1)), g)), WithActionMethodCaller(caller))
	req := startReal(t, requestorConfig(url))
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)

	call := func(target uint16) *ActionResult {
		t.Helper()
		tg := calcTarget()
		tg.ActionTargetID = target
		res, err := req.CallAction(context.Background(), tg, int32s(7, 3))
		require.NoError(t, err)
		return res
	}
	res := call(1)
	require.Equal(t, ua.StatusGood, res.Status)
	require.Equal(t, int32(10), res.Outputs[0].Value())
	require.Equal(t, int32(4), call(2).Outputs[0].Value())
	mu.Lock()
	require.Len(t, calls, 2)
	require.Equal(t, "Calc", calls[0].obj.StringID())
	require.Equal(t, "Add", calls[0].method.StringID())
	require.Equal(t, int32s(7, 3), calls[0].inputs)
	require.Equal(t, uint16(1), calls[0].inv.ActionTargetID)
	require.Equal(t, "Calc", calls[0].inv.DataSet)
	require.Equal(t, "Sub", calls[1].method.StringID())
	mu.Unlock()

	// A handler takes precedence over the Method.
	resp.SetActionHandler("Calc", 2, func(context.Context, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return int32s(-1), ua.StatusGood
	})
	require.Equal(t, int32(-1), call(2).Outputs[0].Value())
	mu.Lock()
	require.Len(t, calls, 2)
	mu.Unlock()

	// Without a caller the targets are not implemented.
	url2 := memURL(t) + "-2"
	resp2 := startReal(t, NewConfiguration([]*ua.PublishedDataSetDataType{calcMethodPDS()},
		AttachWriterGroups(memConnection("Responder", url2, uint16(1)), WriterGroup("Actions", 10, 50*time.Millisecond, DataSetWriter("CalcWriter", 100, "Calc")))))
	req2 := startReal(t, requestorConfig(url2))
	waitRunning(t, resp2, "Responder")
	waitRunning(t, req2, "Requestor")
	waitResponder(t, resp2)
	res, err := req2.CallAction(context.Background(), calcTarget(), int32s(1, 2))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNotImplemented, res.Status)
}
