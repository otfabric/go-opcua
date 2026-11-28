// SPDX-License-Identifier: MIT

package gds

import (
	"context"
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/filetransfer"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// fileChunk is the size of the Read and Write calls on the TrustList file.
const fileChunk = 64 << 10

// maxTrustListFile bounds what ReadTrustList reads from a server.
const maxTrustListFile = 64 << 20

// EncodeTrustList returns the content of a TrustList file: the
// TrustListDataType in the OPC UA Binary encoding (Part 12 §7.8.2.1).
func EncodeTrustList(tl *ua.TrustListDataType) ([]byte, error) {
	if tl == nil {
		return nil, errNoTrustList
	}
	return ua.Encode(tl)
}

// DecodeTrustList decodes the content of a TrustList file.
func DecodeTrustList(b []byte) (*ua.TrustListDataType, error) {
	tl := new(ua.TrustListDataType)
	n, err := ua.Decode(b, tl)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoTrustList, err)
	}
	if n != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes", errNoTrustList, len(b)-n)
	}
	return tl, nil
}

func (g *Client) fileCall(ctx context.Context, name string, method uint32, outputs int, args ...*ua.Variant) ([]*ua.Variant, error) {
	return g.call(ctx, g.TrustList, name, g.trustListFallback(name, method), outputs, args...)
}

// trustListMethodIDs are the Methods of the TrustList file of the
// DefaultApplicationGroup, the fallback when browsing g.TrustList fails.
var trustListMethodIDs = map[string]uint32{
	"Open":        id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpen,
	"Close":       id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListClose,
	"Read":        id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRead,
	"Write":       id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWrite,
	"GetPosition": id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListGetPosition,
	"SetPosition": id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSetPosition,
}

// trustListFile returns the TrustList as a FileType Object (OPC 10000-20
// §4.2) whose Methods are called like the other Methods of g, so a failing
// call is an *Error.
func (g *Client) trustListFile() *filetransfer.Object {
	o := filetransfer.ObjectFunc(func(ctx context.Context, m *uamethod.Method, in []*ua.Variant) ([]*ua.Variant, error) {
		return g.fileCall(ctx, m.Name, trustListMethodIDs[m.Name], 0, in...)
	})
	o.Chunk = fileChunk
	return o
}

// ReadTrustList reads the lists of the trust list masks selects
// (ua.TrustListMasksAll for all of them) with OpenWithMasks.
func (g *Client) ReadTrustList(ctx context.Context, masks ua.TrustListMasks) (*ua.TrustListDataType, error) {
	in := uamethod.TrustListTypeOpenWithMasksInput{Masks: uint32(masks)}
	out, err := g.fileCall(ctx, "OpenWithMasks", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenWithMasks, 0, in.Pack()...)
	if err != nil {
		return nil, err
	}
	var o uamethod.TrustListTypeOpenWithMasksOutput
	if err := o.Unpack(out); err != nil {
		return nil, fmt.Errorf("gds: %w", err)
	}
	b, err := g.trustListFile().Attach(o.FileHandle, ua.OpenFileModeRead).ReadAllAndClose(ctx, maxTrustListFile)
	if err != nil {
		return nil, err
	}
	return DecodeTrustList(b)
}

// WriteTrustList writes tl to the TrustList file and closes it with
// CloseAndUpdate (Part 12 §7.8.2.3): the server replaces the lists that
// tl.SpecifiedLists names. It reports whether ApplyChanges must be called
// before the server uses the new trust list.
func (g *Client) WriteTrustList(ctx context.Context, tl *ua.TrustListDataType) (applyChangesRequired bool, err error) {
	b, err := EncodeTrustList(tl)
	if err != nil {
		return false, err
	}
	f, err := g.trustListFile().Open(ctx, ua.OpenFileModeWrite|ua.OpenFileModeEraseExisting)
	if err != nil {
		return false, err
	}
	if err := f.Write(ctx, b); err != nil {
		return false, errors.Join(err, f.Close(ctx))
	}
	in := uamethod.TrustListTypeCloseAndUpdateInput{FileHandle: f.Handle()}
	out, err := g.fileCall(ctx, "CloseAndUpdate", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListCloseAndUpdate, 0, in.Pack()...)
	if err != nil {
		return false, err
	}
	var o uamethod.TrustListTypeCloseAndUpdateOutput
	if err := o.Unpack(out); err != nil {
		return false, fmt.Errorf("gds: %w", err)
	}
	return o.ApplyChangesRequired, nil
}

// AddCertificate adds a certificate (DER) to the trusted certificates, or
// with trusted false to the issuer certificates, of the trust list (Part 12
// §7.8.2.4).
func (g *Client) AddCertificate(ctx context.Context, cert []byte, trusted bool) error {
	in := uamethod.TrustListTypeAddCertificateInput{Certificate: cert, IsTrustedCertificate: trusted}
	_, err := g.fileCall(ctx, "AddCertificate", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListAddCertificate, 0, in.Pack()...)
	return err
}

// RemoveCertificate removes the certificate with the thumbprint (see
// Thumbprint) from the trusted certificates, or with trusted false from the
// issuer certificates (Part 12 §7.8.2.5). The server also removes the CRLs
// of a CA certificate.
func (g *Client) RemoveCertificate(ctx context.Context, thumbprint string, trusted bool) error {
	in := uamethod.TrustListTypeRemoveCertificateInput{Thumbprint: thumbprint, IsTrustedCertificate: trusted}
	_, err := g.fileCall(ctx, "RemoveCertificate", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRemoveCertificate, 0, in.Pack()...)
	return err
}
