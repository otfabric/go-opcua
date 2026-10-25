//go:build interop

// SPDX-License-Identifier: MIT

package interop

// Opt-in peers: adapters that are not among the pinned peers (yet), such as
// dotnet-gds of opcua-interop v0.16.0. optionalPeerImageEnv lists their
// image env variables (see imageCapabilities: with the variable unset the
// peer runs only when its default image is present locally, and skips
// otherwise); peerInteropVersion the release each of them is written against
// (see requirePinnedVersion). A new adapter starts here and moves to the
// pinned peers with the release that publishes it; all six peers of
// opcua-interop v0.16.0 are pinned.
var (
	optionalPeerImageEnv = map[string]bool{}
	peerInteropVersion   = map[string]string{}
)
