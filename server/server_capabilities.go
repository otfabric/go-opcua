// SPDX-License-Identifier: MIT

package server

import (
	"slices"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
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
// configuration". Without the option the array holds the Profiles the
// library evidences: those whose mandatory ConformanceUnits all have tests
// in the inventory of docs/profiles.md. No Profile is evidenced yet, so the
// default array is empty. The option replaces that list; with no URIs the
// array is empty.
func WithServerProfiles(uris ...string) Option {
	return func(s *serverConfig) error {
		s.serverProfiles = append([]string{}, uris...)
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
		return slices.Clone(evidencedServerProfiles)
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
//
// and the Optional Properties the ConformanceUnits Base Info Server
// Capabilities 2 and Base Info Server Capabilities
// MaxMonitoredItemsQueueSize of OPC 10000-7 expose, from the limits the
// server enforces:
//
//   - MaxArrayLength, "the maximum length of a one or multidimensional
//     array supported by Variables, Method arguments and Event fields", in
//     a multidimensional array "the overall length": [ua.MaxVariantArrayLength],
//     the most elements the decoder accepts in a Variant, the type of every
//     Variable value, Method argument and Event field (Part 6 §5.2.2.16),
//     over all dimensions;
//   - MaxStringLength and MaxByteStringLength, "the maximum number of bytes
//     in Strings and LocalizedText" and "in a ByteString supported by
//     Variables, Method arguments and Event fields": the largest request
//     message the server accepts (requestMessageLimit). A String or
//     ByteString a client writes or passes to a Method is part of a
//     request, and the server refuses a request message larger than that
//     (Part 6 §7.1.2.4, MaxMessageSize of the Acknowledge); the server
//     imposes no other limit on them, so the value is an upper bound: the
//     headers of the request take some of it;
//   - MaxMonitoredItemsQueueSize, "the maximum size of data MonitoredItem
//     queues": the largest QueueSize CreateMonitoredItems and
//     ModifyMonitoredItems grant a data MonitoredItem (maxDataQueueSize).
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
		{id.ServerServerCapabilitiesMaxArrayLength, func() any { return capabilityValue(ua.MaxVariantArrayLength) }},
		{id.ServerServerCapabilitiesMaxStringLength, func() any { return requestMessageLimit() }},
		{id.ServerServerCapabilitiesMaxByteStringLength, func() any { return requestMessageLimit() }},
		{id.ServerServerCapabilitiesMaxMonitoredItemsQueueSize, func() any { return s.cfg.maxDataQueueSize() }},
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

// modellingRules are the ModellingRule Objects of OPC 10000-3 §6.4.4 the
// server supports: those of namespace 0 (§6.4.4.5), which its node sets use.
var modellingRules = []uint32{
	id.ModellingRuleMandatory,
	id.ModellingRuleOptional,
	id.ModellingRuleExposesItsArray,
	id.ModellingRuleOptionalPlaceholder,
	id.ModellingRuleMandatoryPlaceholder,
}

// bindModellingRules lets the ModellingRules Folder of the
// ServerCapabilities organize the ModellingRules: it "is an entry point to
// browse to all ModellingRules supported by the Server. All ModellingRules
// supported by the Server should be able to be browsed starting from this
// Object" (OPC 10000-5 §6.3.2). The node set leaves the Folder empty.
func (s *Server) bindModellingRules() {
	folder := s.ownNode(id.ServerServerCapabilitiesModellingRules)
	if folder == nil {
		return
	}
	for _, nid := range modellingRules {
		if n := s.ownNode(nid); n != nil {
			folder.AddRef(n, RefType(id.Organizes), true)
		}
	}
}

// requestMessageLimit returns the largest request message, in bytes, the
// server accepts: the MaxMessageSize of the Acknowledge of its opc.tcp and
// opc.wss listeners (uacp.DefaultServerACK, Part 6 §7.1.2.4), which is also
// the limit of an opc.https request body (httpsMaxRequestSize, equal by
// default). Zero, which an application may set, is no limit.
func requestMessageLimit() uint32 {
	return uacp.DefaultServerACK.MaxMessageSize
}

// maxDataQueueSize returns the largest queue of a data MonitoredItem: that
// of a durable subscription when durable subscriptions are enabled and
// allow more (reviseDurableQueueSize), else maxMonitoredItemQueueSize
// (reviseQueueSize).
func (s *serverConfig) maxDataQueueSize() uint32 {
	if !s.durable.Disabled {
		return max(s.durable.maxQueueSize(), maxMonitoredItemQueueSize)
	}
	return maxMonitoredItemQueueSize
}
