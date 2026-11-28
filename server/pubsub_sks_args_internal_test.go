// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// TestSKSHandlersUnpack: called without the argument checks of the Call
// service (which answers Bad_InvalidArgument first, OPC 10000-4
// §5.12.2.2), the SKS handlers make the checks of their generated
// contracts: too few arguments is Bad_ArgumentsMissing, a wrong built-in
// type Bad_InvalidArgument (uamethod.StatusOf).
func TestSKSHandlersUnpack(t *testing.T) {
	ctx := context.WithValue(context.Background(), methodCallerKey{}, &MethodCaller{
		SessionID: ua.NewNumericNodeID(1, 1), SecurityMode: ua.MessageSecurityModeSignAndEncrypt,
	})
	h := &SecurityKeyService{}
	wrong := []*ua.Variant{ua.MustVariant(int32(1))}
	for name, call := range map[string]func([]*ua.Variant) ua.StatusCode{
		"AddSecurityGroup": func(a []*ua.Variant) ua.StatusCode {
			_, st := h.addSecurityGroup(ctx, nil, a)
			return st
		},
		"RemoveSecurityGroup": func(a []*ua.Variant) ua.StatusCode {
			_, st := h.removeSecurityGroup(ctx, a)
			return st
		},
		"SetSecurityKeys": func(a []*ua.Variant) ua.StatusCode {
			_, st := setSecurityKeys(ctx, nil, nil, a)
			return st
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, ua.StatusBadArgumentsMissing, call(nil))
			args := make([]*ua.Variant, 0, 7)
			args = append(args, wrong...)
			for len(args) < argCount(name) {
				args = append(args, ua.MustVariant(int32(0)))
			}
			require.Equal(t, ua.StatusBadInvalidArgument, call(args))
		})
	}
}

// argCount is the number of InputArguments of the SKS Methods (OPC
// 10000-14 §8.5.2, §8.5.3, §9.1.3.3).
func argCount(name string) int {
	switch name {
	case "AddSecurityGroup":
		return 5
	case "RemoveSecurityGroup":
		return 1
	default:
		return 7
	}
}
