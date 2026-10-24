//go:build interop

// SPDX-License-Identifier: MIT

package interop

// Opt-in peers: adapters of opcua-interop releases newer than interopVersion
// whose images are not pinned by digest yet. optionalPeerImageEnv lists their
// image env variables (see imageCapabilities: with the variable unset the
// peer runs only when its default image is present locally, and skips
// otherwise); peerInteropVersion the release each of them is written against
// (see requirePinnedVersion).
var (
	optionalPeerImageEnv = map[string]bool{
		asyncOpcuaEnv: true,
		dotnetEnv:     true,
		nodeOpcuaEnv:  true,
	}
	peerInteropVersion = map[string]string{
		asyncOpcuaEnv: asyncOpcuaInteropVersion,
		dotnetEnv:     dotnetInteropVersion,
		nodeOpcuaEnv:  nodeOpcuaInteropVersion,
	}
)
