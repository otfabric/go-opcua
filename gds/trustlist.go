// SPDX-License-Identifier: MIT

package gds

import (
	"context"
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// fileChunk is the size of the Read and Write calls on the TrustList file.
const fileChunk = 64 << 10

// maxTrustListFile bounds what ReadTrustList reads from a server.
const maxTrustListFile = 64 << 20

// The modes of FileType.Open used on the TrustList (Part 20 §4.2.1).
const (
	openWriteErase byte = 0x06
)

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
	return g.call(ctx, g.TrustList, name, method, outputs, args...)
}

func handleOut(name string, v *ua.Variant) (uint32, error) {
	h, ok := v.Value().(uint32)
	if !ok {
		return 0, fmt.Errorf("gds: %s returned %T, want a UInt32", name, v.Value())
	}
	return h, nil
}

func (g *Client) closeFile(ctx context.Context, h uint32) error {
	_, err := g.fileCall(ctx, "Close", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListClose, 0, ua.MustVariant(h))
	return err
}

// ReadTrustList reads the lists of the trust list masks selects
// (ua.TrustListMasksAll for all of them) with OpenWithMasks.
func (g *Client) ReadTrustList(ctx context.Context, masks ua.TrustListMasks) (*ua.TrustListDataType, error) {
	out, err := g.fileCall(ctx, "OpenWithMasks", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenWithMasks, 1, ua.MustVariant(uint32(masks)))
	if err != nil {
		return nil, err
	}
	h, err := handleOut("OpenWithMasks", out[0])
	if err != nil {
		return nil, err
	}
	var b []byte
	for {
		out, err := g.fileCall(ctx, "Read", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRead, 1, ua.MustVariant(h), ua.MustVariant(int32(fileChunk)))
		if err != nil {
			return nil, errors.Join(err, g.closeFile(ctx, h))
		}
		chunk, _ := out[0].Value().([]byte)
		if len(chunk) == 0 {
			break
		}
		if len(b)+len(chunk) > maxTrustListFile {
			return nil, errors.Join(fmt.Errorf("gds: the TrustList file exceeds %d bytes", maxTrustListFile), g.closeFile(ctx, h))
		}
		b = append(b, chunk...)
	}
	if err := g.closeFile(ctx, h); err != nil {
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
	out, err := g.fileCall(ctx, "Open", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpen, 1, ua.MustVariant(openWriteErase))
	if err != nil {
		return false, err
	}
	h, err := handleOut("Open", out[0])
	if err != nil {
		return false, err
	}
	for len(b) > 0 {
		n := min(len(b), fileChunk)
		if _, err := g.fileCall(ctx, "Write", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWrite, 0, ua.MustVariant(h), ua.MustVariant(b[:n])); err != nil {
			return false, errors.Join(err, g.closeFile(ctx, h))
		}
		b = b[n:]
	}
	out, err = g.fileCall(ctx, "CloseAndUpdate", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListCloseAndUpdate, 1, ua.MustVariant(h))
	if err != nil {
		return false, err
	}
	return boolOut("CloseAndUpdate", out[0])
}

// AddCertificate adds a certificate (DER) to the trusted certificates, or
// with trusted false to the issuer certificates, of the trust list (Part 12
// §7.8.2.4).
func (g *Client) AddCertificate(ctx context.Context, cert []byte, trusted bool) error {
	_, err := g.fileCall(ctx, "AddCertificate", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListAddCertificate, 0,
		ua.MustVariant(cert), ua.MustVariant(trusted))
	return err
}

// RemoveCertificate removes the certificate with the thumbprint (see
// Thumbprint) from the trusted certificates, or with trusted false from the
// issuer certificates (Part 12 §7.8.2.5). The server also removes the CRLs
// of a CA certificate.
func (g *Client) RemoveCertificate(ctx context.Context, thumbprint string, trusted bool) error {
	_, err := g.fileCall(ctx, "RemoveCertificate", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRemoveCertificate, 0,
		ua.MustVariant(thumbprint), ua.MustVariant(trusted))
	return err
}
