// SPDX-License-Identifier: MIT

package pushstore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uapolicy"
)

// encode is ua.Encode, replaced by the tests to inject a failure.
var encode = ua.Encode

// recordFormat is the format byte of the records.
const recordFormat = 1

// Kinds of a certificate record.
const (
	kindDeleted     = 0
	kindCertificate = 1
)

// encodeTrustList returns the record of a trust list.
func encodeTrustList(x server.CertificateGroupTrustList) ([]byte, error) {
	tl := x.TrustList
	if tl == nil {
		tl = &ua.TrustListDataType{}
	}
	tl = &ua.TrustListDataType{
		SpecifiedLists:      uint32(ua.TrustListMasksAll),
		TrustedCertificates: tl.TrustedCertificates,
		TrustedCrls:         tl.TrustedCrls,
		IssuerCertificates:  tl.IssuerCertificates,
		IssuerCrls:          tl.IssuerCrls,
	}
	body, err := encode(tl)
	if err != nil {
		return nil, fmt.Errorf("pushstore: encode the trust list of %s: %w", x.Group, err)
	}
	var ns int64
	if !x.LastUpdateTime.IsZero() {
		ns = x.LastUpdateTime.UnixNano()
	}
	b := make([]byte, 0, 1+binary.MaxVarintLen64+len(body))
	b = append(b, recordFormat)
	b = binary.AppendVarint(b, ns)
	return append(b, body...), nil
}

// decodeTrustList decodes the record of a trust list. The record is
// untrusted: the bytes of a file.
func decodeTrustList(b []byte) (server.CertificateGroupTrustList, error) {
	var x server.CertificateGroupTrustList
	if len(b) < 2 || b[0] != recordFormat {
		return x, corrupt("trust list record")
	}
	ns, m := binary.Varint(b[1:])
	if m <= 0 {
		return x, corrupt("trust list record")
	}
	body := b[1+m:]
	tl := new(ua.TrustListDataType)
	n, err := ua.Decode(body, tl)
	if err != nil || n != len(body) || tl.SpecifiedLists != uint32(ua.TrustListMasksAll) {
		return x, corrupt("trust list record")
	}
	x.TrustList = tl
	if ns != 0 {
		x.LastUpdateTime = time.Unix(0, ns).UTC()
	}
	return x, nil
}

// encodeCert returns the record of a certificate, or of its deletion.
func encodeCert(x server.CertificateGroupChange) ([]byte, error) {
	if x.Deleted() {
		return []byte{recordFormat, kindDeleted}, nil
	}
	if x.PrivateKey == nil {
		return nil, fmt.Errorf("pushstore: the certificate of %s has no private key", x.Group)
	}
	key, err := uapolicy.MarshalPrivateKey(x.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("pushstore: the private key of %s cannot be stored: %w", x.Group, err)
	}
	fields := append([][]byte{x.Certificate, key}, x.Issuers...)
	n := 2 + 4 + 4*len(fields)
	for _, f := range fields {
		n += len(f)
	}
	b := make([]byte, 0, n)
	b = append(b, recordFormat, kindCertificate)
	b = appendBytes(b, x.Certificate)
	b = appendBytes(b, key)
	b = appendLen(b, len(x.Issuers))
	for _, is := range x.Issuers {
		b = appendBytes(b, is)
	}
	return b, nil
}

// decodeCert decodes the record of a certificate: the certificate and its
// issuers must be DER certificates, the key a PKCS #8 key that matches the
// certificate. The record is untrusted: the bytes of a file.
func decodeCert(b []byte) (server.CertificateGroupChange, error) {
	var x server.CertificateGroupChange
	if len(b) < 2 || b[0] != recordFormat {
		return x, corrupt("certificate record")
	}
	switch b[1] {
	case kindDeleted:
		if len(b) != 2 {
			return x, corrupt("certificate record")
		}
		return x, nil
	case kindCertificate:
	default:
		return x, corrupt("certificate record")
	}
	r := reader{b: b[2:]}
	cert := r.bytes()
	key := r.bytes()
	count := r.len()
	// Every issuer takes at least its length.
	if count > len(r.b)/4 {
		r.err = true
	}
	var issuers [][]byte
	for i := 0; i < count && !r.err; i++ {
		issuers = append(issuers, r.bytes())
	}
	if r.err || len(r.b) != 0 {
		return x, corrupt("certificate record")
	}
	for _, der := range append([][]byte{cert}, issuers...) {
		c, err := uapolicy.ParseCertificate(der)
		if err != nil || !bytes.Equal(c.Raw, der) {
			return x, corrupt("certificate in a certificate record")
		}
	}
	priv, err := uapolicy.ParsePrivateKey(key)
	if err != nil || !uapolicy.KeyMatchesCertificate(priv, cert) {
		return x, corrupt("private key in a certificate record")
	}
	x.Certificate, x.Issuers, x.PrivateKey = cert, issuers, priv
	return x, nil
}

func corrupt(what string) error { return fmt.Errorf("%w: pushstore: %s", fxstore.ErrCorrupt, what) }

// errLength reports a field the record format cannot hold.
var errLength = errors.New("pushstore: field too long")

func appendLen(b []byte, n int) []byte {
	if n < 0 || uint64(n) > math.MaxUint32 {
		panic(errLength) // fxstore.Limits keep a record far below 4 GiB
	}
	return binary.LittleEndian.AppendUint32(b, uint32(n))
}

func appendBytes(b, f []byte) []byte { return append(appendLen(b, len(f)), f...) }

// reader reads the fields of a record; err is set at the first field that
// does not fit.
type reader struct {
	b   []byte
	err bool
}

func (r *reader) len() int {
	if r.err || len(r.b) < 4 {
		r.err = true
		return 0
	}
	n := binary.LittleEndian.Uint32(r.b)
	r.b = r.b[4:]
	if uint64(n) > uint64(len(r.b)) {
		r.err = true
		return 0
	}
	return int(n)
}

func (r *reader) bytes() []byte {
	n := r.len()
	if r.err {
		return nil
	}
	f := bytes.Clone(r.b[:n])
	r.b = r.b[n:]
	return f
}
