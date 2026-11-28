// SPDX-License-Identifier: MIT

package server

import (
	"slices"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The Mandatory Properties of ServerCapabilitiesType (OPC 10000-5 §6.3.2)
// that the built-in node set declares without a value, besides the
// continuation point limits (continuation_points.go): ServerProfileArray,
// LocaleIdArray, MinSupportedSampleRate, MaxHistoryContinuationPoints and
// SoftwareCertificates.

// defaultLocaleIDs are the LocaleIds of the texts the server writes itself
// (event Messages, state names): "en".
var defaultLocaleIDs = []string{"en"}

// WithServerProfiles sets the ServerProfileArray of the ServerCapabilities
// (OPC 10000-5 §6.3.2): the URIs of the Profiles of OPC 10000-7 the server
// supports, "limited to the Profiles the Server supports in its current
// configuration". The library does not determine its Profiles: without
// the option, or with no URIs, the array is empty.
func WithServerProfiles(uris ...string) Option {
	return func(s *serverConfig) error {
		s.serverProfiles = slices.Clone(uris)
		return nil
	}
}

// WithLocaleIDs sets the LocaleIdArray of the ServerCapabilities (OPC
// 10000-5 §6.3.2), the LocaleIds "that are known to be supported by the
// Server", for an application that serves texts in more locales. Without
// the option, or with no LocaleIds, the array is ["en"], the locale of the
// texts the server writes.
func WithLocaleIDs(locales ...string) Option {
	return func(s *serverConfig) error {
		s.localeIDs = slices.Clone(locales)
		return nil
	}
}

func (s *serverConfig) serverProfileArray() []string {
	if s.serverProfiles == nil {
		return []string{}
	}
	return slices.Clone(s.serverProfiles)
}

func (s *serverConfig) localeIDArray() []string {
	if len(s.localeIDs) == 0 {
		return slices.Clone(defaultLocaleIDs)
	}
	return slices.Clone(s.localeIDs)
}

// bindServerCapabilities serves the Mandatory ServerCapabilities
// Properties without a value in the node set (OPC 10000-5 §6.3.2):
//
//   - ServerProfileArray and LocaleIdArray from WithServerProfiles and
//     WithLocaleIDs;
//   - MinSupportedSampleRate 0: the "minimum supported sample rate,
//     including 0", and a sampling interval of 0 is supported, as
//     exception-based sampling (reviseSamplingInterval, OPC 10000-4
//     §5.13.1.2);
//   - MaxHistoryContinuationPoints 0, which "indicates that the Server does
//     not restrict the number of parallel continuation points": the server
//     refuses no HistoryRead for a count of continuation points (a
//     HistoryProvider may release those it cannot keep, OPC 10000-4 §7.9);
//   - SoftwareCertificates, the empty array: the server has none.
func (s *Server) bindServerCapabilities() {
	for _, c := range []struct {
		nodeID uint32
		value  func() any
	}{
		{id.ServerServerCapabilitiesServerProfileArray, func() any { return s.cfg.serverProfileArray() }},
		{id.ServerServerCapabilitiesLocaleIDArray, func() any { return s.cfg.localeIDArray() }},
		{id.ServerServerCapabilitiesMinSupportedSampleRate, func() any { return float64(0) }},
		{id.ServerServerCapabilitiesMaxHistoryContinuationPoints, func() any { return uint16(0) }},
		{id.ServerServerCapabilitiesSoftwareCertificates, func() any { return []*ua.ExtensionObject{} }},
	} {
		n := s.ownNode(c.nodeID)
		if n == nil {
			continue
		}
		value := c.value
		n.mu.Lock()
		n.val = func() *ua.DataValue { return DataValueFromValue(value()) }
		n.mu.Unlock()
	}
}
