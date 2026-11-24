// SPDX-License-Identifier: MIT

package fxcm

import (
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// MaxFileSize is the largest file DecodeFile takes: 16 MiB. Library
// interpretation: F.2 and F.3 set no limit; this one bounds the memory a
// decode of untrusted input takes.
const MaxFileSize = 16 << 20

// DecodeFile decodes the content of a ConnectionConfigurationSet file
// (F.2 Table F.37): a UABinaryFileDataType (Part 5 §12.31) whose Body is
// an array of ConnectionConfigurationSetConfDataType. The input is
// untrusted. An empty Body array returns no sets and no error. Any defect
// is ErrConfig with ua.StatusBadTypeMismatch in the chain (Table F.40).
// The sets are decoded, not validated: NewConfig does that.
//
// The Namespaces of the file name the namespaces of the NodeIds in it;
// Part 5 §12.31 maps its first entry to NamespaceIndex 1, and F.2 asks for
// http://opcfoundation.org/UA/ and http://opcfoundation.org/UA/FX/CM/ in
// it. Library interpretation: when the Body does not decode with the
// indexes of Part 5 and the first entry is http://opcfoundation.org/UA/,
// DecodeFile tries the indexes of a NamespaceArray (the first entry is
// index 0), so that a file written either way is read.
func DecodeFile(b []byte) ([]*uafx.ConnectionConfigurationSetConf, error) {
	if len(b) > MaxFileSize {
		return nil, configError(ua.StatusBadTypeMismatch, "a file of %d bytes, more than %d", len(b), MaxFileSize)
	}
	var fd ua.UABinaryFileDataType
	n, err := ua.Decode(b, &fd)
	switch {
	case err != nil:
		return nil, configError(ua.StatusBadTypeMismatch, "not a UABinaryFileDataType: %v", err)
	case n != len(b):
		return nil, configError(ua.StatusBadTypeMismatch, "%d bytes after the UABinaryFileDataType", len(b)-n)
	case fd.Body == nil || fd.Body.Value() == nil:
		return nil, configError(ua.StatusBadTypeMismatch, "no Body")
	}
	eos, ok := fd.Body.Value().([]*ua.ExtensionObject)
	if !ok {
		return nil, configError(ua.StatusBadTypeMismatch, "the Body is a %s, not an array of structures", fd.Body.Type())
	}
	var firstErr error
	for _, offset := range []int{1, 0} {
		if offset == 0 && (len(fd.Namespaces) == 0 || fd.Namespaces[0] != uaNamespace) {
			break
		}
		ns, ok := fileNamespaces(fd.Namespaces, offset)
		if !ok {
			if firstErr == nil {
				firstErr = configError(ua.StatusBadTypeMismatch, "the Namespaces do not have %s", fxcmid.NamespaceURI)
			}
			continue
		}
		sets, err := decodeSets(eos, ns)
		if err == nil {
			return sets, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// fileNamespaces returns the indexes of the UAFX namespaces in the
// Namespaces of a file whose first entry has the index offset, and whether
// the CM namespace is among them.
func fileNamespaces(uris []string, offset int) (uafx.NamespaceIndexes, bool) {
	var ns uafx.NamespaceIndexes
	for i, u := range uris {
		idx := i + offset
		if idx == 0 || idx > 0xFFFF {
			continue
		}
		switch u {
		case fxdataid.NamespaceURI:
			ns.Data = uint16(idx)
		case fxacid.NamespaceURI:
			ns.AC = uint16(idx)
		case fxcmid.NamespaceURI:
			ns.CM = uint16(idx)
		}
	}
	return ns, ns.CM != 0
}

func decodeSets(eos []*ua.ExtensionObject, ns uafx.NamespaceIndexes) ([]*uafx.ConnectionConfigurationSetConf, error) {
	sets := make([]*uafx.ConnectionConfigurationSetConf, 0, len(eos))
	for i, eo := range eos {
		s, err := uafx.DecodeStructure(eo, ns)
		if err != nil {
			return nil, configError(ua.StatusBadTypeMismatch, "Body[%d]: %v", i, err)
		}
		set, ok := s.(*uafx.ConnectionConfigurationSetConf)
		if !ok || set == nil {
			return nil, configError(ua.StatusBadTypeMismatch, "Body[%d] is a %T, not a ConnectionConfigurationSetConfDataType", i, s)
		}
		sets = append(sets, set)
	}
	return sets, nil
}

// fileNS are the namespace indexes EncodeFile writes: the Namespaces of
// the file are the OPC UA, Data, AC and CM namespaces, the first with the
// index 1 (Part 5 §12.31).
var (
	fileNS   = uafx.NamespaceIndexes{Data: 2, AC: 3, CM: 4}
	fileURIs = []string{uaNamespace, fxdataid.NamespaceURI, fxacid.NamespaceURI, fxcmid.NamespaceURI}
)

// EncodeFile returns the content of a ConnectionConfigurationSet file for
// sets (F.2), which DecodeFile reads. Its Namespaces are
// http://opcfoundation.org/UA/ and the Data, AC and CM namespaces of UAFX.
// A NodeId in a set has the index of the Namespaces of its ServerAddress
// (F.1.2.2), not of the file, and is written as it is. The sets are not
// validated.
func EncodeFile(sets []*uafx.ConnectionConfigurationSetConf) ([]byte, error) {
	eos := make([]*ua.ExtensionObject, len(sets))
	for i, s := range sets {
		if s == nil {
			return nil, configError(ua.StatusBadInvalidArgument, "sets[%d] is nil", i)
		}
		eo, err := uafx.EncodeStructure(s, fileNS)
		if err != nil {
			return nil, configError(ua.StatusBadInvalidArgument, "sets[%d]: %v", i, err)
		}
		eos[i] = eo
	}
	b, err := ua.Encode(&ua.UABinaryFileDataType{Namespaces: fileURIs, Body: ua.MustVariant(eos)})
	if err != nil {
		return nil, configError(ua.StatusBadInvalidArgument, "%v", err)
	}
	return b, nil
}
