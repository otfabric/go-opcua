// SPDX-License-Identifier: MIT

package ua

import "github.com/otfabric/go-opcua/internal/testhook"

func init() {
	testhook.CodecStructs = func() []any { return codecTypes.registeredStructs() }
}
