// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// buildPushModel serves the ServerConfiguration object of namespace 0
// (Part 12 §7.10.3) with the DefaultApplicationGroup and its TrustList.
func (s *Server) buildPushModel() {
	m := s.push
	if m == nil || s.Node(ua.NewNumericNodeID(0, id.ServerConfiguration)) == nil {
		return
	}
	set := func(nid uint32, v ValueFunc, dynamic bool) {
		if n := s.ownNode(nid); n != nil {
			n.mu.Lock()
			n.val = v
			n.mu.Unlock()
			if dynamic {
				m.nodes = append(m.nodes, n.ID())
			}
		}
	}
	set(id.ServerConfigurationServerCapabilities, static([]string{"NA"}), false)
	set(id.ServerConfigurationSupportedPrivateKeyFormats, static([]string{"PEM"}), false)
	set(id.ServerConfigurationMaxTrustListSize, static(m.cfg.MaxTrustListSize), false)
	set(id.ServerConfigurationMulticastDNSEnabled, static(s.cfg.multicast.enabled), false)
	set(id.ServerConfigurationApplicationURI, func() *ua.DataValue { return DataValueFromValue(s.cfg.applicationURI) }, false)
	set(id.ServerConfigurationProductURI, func() *ua.DataValue { return DataValueFromValue(s.applicationDescription().ProductURI) }, false)
	set(id.ServerConfigurationApplicationType, func() *ua.DataValue {
		return DataValueFromValue(int32(s.applicationDescription().ApplicationType))
	}, false)
	set(id.ServerConfigurationHasSecureElement, static(false), false)
	set(id.ServerConfigurationInApplicationSetup, static(false), false)
	set(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupCertificateTypes, func() *ua.DataValue {
		return DataValueFromValue(s.cfg.certificateTypes())
	}, true)

	set(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSize, func() *ua.DataValue {
		return DataValueFromValue(uint64(m.trust.Load().size))
	}, true)
	set(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenCount, func() *ua.DataValue {
		return DataValueFromValue(uint16(m.openCount.Load()))
	}, true)
	set(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListLastUpdateTime, func() *ua.DataValue {
		return DataValueFromValue(time.Unix(0, m.lastUpdate.Load()).UTC())
	}, true)
	set(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWritable, static(true), false)
	set(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListUserWritable, static(true), false)
	set(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListMaxByteStringLength, static(uint32(maxTrustListRead)), false)

	// Only the DefaultApplicationGroup is managed: the HTTPS and user token
	// groups, which have no function here, are taken out of the folder.
	if g := s.ownNode(id.ServerConfigurationCertificateGroups); g != nil {
		for _, nid := range []uint32{id.ServerConfigurationCertificateGroupsDefaultHTTPSGroup, id.ServerConfigurationCertificateGroupsDefaultUserTokenGroup} {
			g.RemoveRef(ua.NewNumericExpandedNodeID(0, nid), ua.NewNumericNodeID(0, id.HasComponent), true)
		}
	}

	type method struct {
		name   string
		method uint32
		h      func(context.Context, *MethodCaller, []*ua.Variant) ([]*ua.Variant, ua.StatusCode)
	}
	register := func(obj uint32, ms []method) {
		for _, x := range ms {
			s.RegisterMethod(ua.NewNumericNodeID(0, obj), ua.NewNumericNodeID(0, x.method), m.method(x.name, x.h))
		}
	}
	register(id.ServerConfiguration, []method{
		{"UpdateCertificate", id.ServerConfigurationUpdateCertificate, m.updateCertificate},
		{"CreateSigningRequest", id.ServerConfigurationCreateSigningRequest, m.createSigningRequest},
		{"GetRejectedList", id.ServerConfigurationGetRejectedList, m.getRejectedList},
		{"ApplyChanges", id.ServerConfigurationApplyChanges, m.applyChanges},
		{"CancelChanges", id.ServerConfigurationCancelChanges, m.cancelChanges},
	})
	register(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList, []method{
		{"Open", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpen, m.fileOpen},
		{"OpenWithMasks", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenWithMasks, m.fileOpenWithMasks},
		{"Close", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListClose, m.fileClose},
		{"Read", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRead, m.fileRead},
		{"Write", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWrite, m.fileWrite},
		{"GetPosition", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListGetPosition, m.fileGetPosition},
		{"SetPosition", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSetPosition, m.fileSetPosition},
		{"CloseAndUpdate", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListCloseAndUpdate, m.fileCloseAndUpdate},
		{"AddCertificate", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListAddCertificate, m.addCertificate},
		{"RemoveCertificate", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRemoveCertificate, m.removeCertificate},
	})
}
