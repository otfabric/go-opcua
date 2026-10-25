// SPDX-License-Identifier: MIT

package gds

import (
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/ua"
)

// ApplicationRecord is the ApplicationRecordDataType of Part 12 §6.6.4:
// the record of an application in the directory of a Global Discovery
// Server.
//
// Its encoding NodeId lies in the GDS namespace, whose index differs from
// server to server, so the type is not registered with package ua: use
// EncodeApplicationRecord and DecodeApplicationRecord with the namespace
// index of the server.
type ApplicationRecord struct {
	// ApplicationID is the NodeId the GDS assigned to the record (a null
	// NodeId for RegisterApplication).
	ApplicationID *ua.NodeID
	// ApplicationURI is the URI of the application, the URI in its
	// application instance certificate.
	ApplicationURI  string
	ApplicationType ua.ApplicationType
	// ApplicationNames are the names of the application in one or more
	// locales; at least one is required.
	ApplicationNames []*ua.LocalizedText
	ProductURI       string
	// DiscoveryURLs are the discovery URLs of a server.
	DiscoveryURLs []string
	// ServerCapabilities are the capability identifiers of a server
	// (Part 12 Annex D), for example "DA" or "NA".
	ServerCapabilities []string
}

// errNotRecord reports an ExtensionObject that does not hold an
// ApplicationRecordDataType.
var errNotRecord = errors.New("gds: not an ApplicationRecordDataType")

// ApplicationRecordEncodingID returns the NodeId of the binary encoding of
// the ApplicationRecordDataType in the GDS namespace ns.
func ApplicationRecordEncodingID(ns uint16) *ua.NodeID {
	return ua.NewNumericNodeID(ns, gdsid.ApplicationRecordDataTypeEncodingDefaultBinary)
}

func (r *ApplicationRecord) normalized() *ApplicationRecord {
	out := *r
	if out.ApplicationID == nil {
		out.ApplicationID = ua.NewTwoByteNodeID(0)
	}
	out.ApplicationNames = make([]*ua.LocalizedText, len(r.ApplicationNames))
	for i, n := range r.ApplicationNames {
		if n == nil {
			n = &ua.LocalizedText{}
		}
		out.ApplicationNames[i] = n
	}
	return &out
}

// EncodeApplicationRecord returns r as the ExtensionObject of an
// ApplicationRecordDataType in the binary encoding, for a server whose GDS
// namespace has the index ns.
func EncodeApplicationRecord(ns uint16, r *ApplicationRecord) (*ua.ExtensionObject, error) {
	if r == nil {
		return nil, errNotRecord
	}
	body, err := ua.Encode(r.normalized())
	if err != nil {
		return nil, err
	}
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewExpandedNodeID(ApplicationRecordEncodingID(ns), "", 0),
		Value:        body,
	}, nil
}

// DecodeApplicationRecord decodes the ExtensionObject of an
// ApplicationRecordDataType of a server whose GDS namespace has the index
// ns: a binary body, as package ua keeps it for a type it does not know
// (ExtensionObject.RawBody, or a []byte Value from the JSON and XML
// decoders), or an *ApplicationRecord a program registered.
func DecodeApplicationRecord(ns uint16, eo *ua.ExtensionObject) (*ApplicationRecord, error) {
	if eo == nil || eo.TypeID == nil || eo.TypeID.NodeID == nil {
		return nil, errNotRecord
	}
	if r, ok := eo.Value.(*ApplicationRecord); ok {
		return r, nil
	}
	if !eo.TypeID.NodeID.Equal(ApplicationRecordEncodingID(ns)) {
		return nil, fmt.Errorf("%w: encoding %v", errNotRecord, eo.TypeID.NodeID)
	}
	body := eo.RawBody
	if b, ok := eo.Value.([]byte); ok {
		body = b
	}
	if body == nil {
		return nil, fmt.Errorf("%w: no binary body", errNotRecord)
	}
	r := new(ApplicationRecord)
	n, err := ua.Decode(body, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotRecord, err)
	}
	if n != len(body) {
		return nil, fmt.Errorf("%w: %d trailing bytes", errNotRecord, len(body)-n)
	}
	return r, nil
}
