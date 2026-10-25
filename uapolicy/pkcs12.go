// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // DES-EDE3 for reading PKCS #12 files only.
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 for reading PKCS #12 files only.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	stderrors "errors"
	"fmt"
	"hash"
	"io"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/otfabric/go-opcua/errors"
)

// PKCS #12 (RFC 7292) personal information exchange files ("PFX"), the
// PrivateKeyFormat "PFX" of Part 12 §7.10.4 UpdateCertificate.
//
// golang.org/x/crypto/pkcs12 reads only the legacy PKCS #12 PBE schemes and a
// single certificate, and parses keys with crypto/x509. ParsePFX reads what
// OpenSSL 1.x and 3.x, Windows and Java write:
//
//   - the password integrity mode with a PKCS #12 MAC (RFC 7292 §5, HMAC with
//     SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512, the key derived with the
//     PKCS #12 KDF of RFC 7292 Appendix B) or PBMAC1 (RFC 9579, PBKDF2), or
//     no MAC at all;
//   - the authenticated safe as data, its contents as data or as encryptedData
//     (RFC 5652 §8);
//   - PBES2 (RFC 8018 §6.2) with PBKDF2 (HMAC-SHA-1, -SHA-224, -SHA-256,
//     -SHA-384, -SHA-512) and AES-128-CBC, AES-192-CBC, AES-256-CBC or
//     DES-EDE3-CBC, and the PKCS #12 PBE schemes pbeWithSHAAnd3-KeyTripleDES-CBC,
//     pbeWithSHAAnd2-KeyTripleDES-CBC, pbeWithSHAAnd128BitRC2-CBC and
//     pbeWithSHAAnd40BitRC2-CBC (RFC 7292 Appendix C);
//   - keyBag and pkcs8ShroudedKeyBag (PKCS #8 keys as ParsePrivateKey reads
//     them: RSA, ECDSA on the NIST and Brainpool curves, Ed25519, Ed448),
//     certBag with X.509 certificates (ParseCertificate) and nested
//     safeContentsBag; CRL, secret and unknown bags are skipped.
//
// Passwords are BMPStrings with a terminating NUL for the PKCS #12 KDF and
// UTF-8 for PBKDF2, as OpenSSL does. An empty password is tried both as no
// password and as the empty BMPString, as OpenSSL does.
//
// The file, the AuthenticatedSafe, the SafeContents and the decrypted keys
// may be in BER (indefinite lengths, constructed OCTET STRINGs), as Java
// keytool before JDK 8u301 and Windows write them; see ber.go.
//
// Deliberately not supported, as OpenSSL 3 by default: the RC4 PBE schemes
// (pbeWithSHAAnd128BitRC4, pbeWithSHAAnd40BitRC4; RC4 is broken, RFC 7465)
// and the public-key integrity and privacy modes (an authSafe of
// signedData, contents of envelopedData), which need the certificate and
// key of the recipient rather than a password and are not what Part 12
// UpdateCertificate carries.
//
// Everything is bounded: the size of the file, the number of bags, the
// nesting of safeContentsBags and of BER elements, the iteration count of
// each key derivation and the iterations of all key derivations together.

// ErrPFXPassword reports a PKCS #12 file whose MAC does not verify or whose
// contents do not decrypt: in practice, a wrong password. It also matches
// errors.ErrInvalidPrivateKey.
var ErrPFXPassword = fmt.Errorf("%w: wrong PFX password or corrupt PFX", errors.ErrInvalidPrivateKey)

const (
	// maxPFXSize bounds the size of a PKCS #12 file ParsePFX reads.
	maxPFXSize = 1 << 20
	// maxPFXBags bounds the number of ContentInfos and SafeBags.
	maxPFXBags = 64
	// maxPFXDepth bounds the nesting of safeContentsBags.
	maxPFXDepth = 4
	// maxPFXSalt bounds the size of a salt.
	maxPFXSalt = 1024
	// maxPFXPassword bounds the size of a password.
	maxPFXPassword = 4096

	// The parameters of EncodePFX: those of OpenSSL 3.
	pfxEncodeIterations = 2048
	pfxSaltSize         = 16
)

// The iteration bounds; variables for the fuzz tests.
var (
	// pfxMaxIterations bounds the iteration count of one key derivation.
	pfxMaxIterations = 10_000_000
	// pfxMaxWork bounds the iterations of all key derivations of a ParsePFX
	// call.
	pfxMaxWork = 20_000_000
)

var (
	oidPKCS7Data          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7EncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidKeyBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidShroudedKeyBag      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidSafeContentsBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	oidCertTypeX509        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidAttributeLocalKeyID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}

	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHAAnd2KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
	oidPBEWithSHAAnd128BitRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}

	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

var (
	tagExplicit0 = cbasn1.Tag(0).Constructed().ContextSpecific()
	tagImplicit0 = cbasn1.Tag(0).ContextSpecific()
)

// pfxHash is a hash function of a MAC, a PBKDF2 PRF or the PKCS #12 KDF.
type pfxHash struct {
	digest asn1.ObjectIdentifier // the OID of the hash (DigestInfo)
	hmac   asn1.ObjectIdentifier // the OID of HMAC with the hash (PBKDF2 PRF)
	new    func() hash.Hash
}

var pfxHashes = []pfxHash{
	{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}, sha1.New},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}, asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}, sha256.New224},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}, sha256.New},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}, sha512.New384},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}, sha512.New},
}

var (
	pfxSHA1   = &pfxHashes[0]
	pfxSHA256 = &pfxHashes[2]
)

// pfxDigest returns the hash with the given digest OID, or nil.
func pfxDigest(oid asn1.ObjectIdentifier) *pfxHash {
	for i := range pfxHashes {
		if pfxHashes[i].digest.Equal(oid) {
			return &pfxHashes[i]
		}
	}
	return nil
}

// pfxHMAC returns the hash with the given HMAC OID, or nil.
func pfxHMAC(oid asn1.ObjectIdentifier) *pfxHash {
	for i := range pfxHashes {
		if pfxHashes[i].hmac.Equal(oid) {
			return &pfxHashes[i]
		}
	}
	return nil
}

// pbes2Cipher is an encryption scheme of PBES2.
type pbes2Cipher struct {
	oid     asn1.ObjectIdentifier
	keySize int
	newFunc func(key []byte) (cipher.Block, error)
}

var pbes2Ciphers = []pbes2Cipher{
	{oidAES128CBC, 16, aes.NewCipher},
	{oidAES192CBC, 24, aes.NewCipher},
	{oidAES256CBC, 32, aes.NewCipher},
	{oidDESEDE3CBC, 24, des.NewTripleDESCipher},
}

var pbes2AES256 = &pbes2Ciphers[2]

func pbes2CipherFor(oid asn1.ObjectIdentifier) *pbes2Cipher {
	for i := range pbes2Ciphers {
		if pbes2Ciphers[i].oid.Equal(oid) {
			return &pbes2Ciphers[i]
		}
	}
	return nil
}

// pfxPassword is a password in the two encodings PKCS #12 uses.
type pfxPassword struct {
	bmp  []byte // BMPString with NUL terminator, for the PKCS #12 KDF
	utf8 []byte // for PBKDF2 (PBES2, PBMAC1)
}

// pfxPasswords returns the encodings to try for a password. OpenSSL reads a
// file with an empty password first as one without password (no bytes at
// all), then with the empty BMPString (only the NUL terminator).
func pfxPasswords(password string) []pfxPassword {
	if password == "" {
		return []pfxPassword{{}, {bmp: []byte{0, 0}}}
	}
	return []pfxPassword{{bmp: bmpString(password), utf8: []byte(password)}}
}

// bmpString returns the UTF-16 big-endian encoding of s with a terminating
// NUL (RFC 7292 Appendix B.1). Characters outside the BMP are encoded as
// surrogate pairs, as OpenSSL does.
func bmpString(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(u)+2)
	for _, c := range u {
		out = append(out, byte(c>>8), byte(c))
	}
	return append(out, 0, 0)
}

// pkcs12KDF derives size bytes with the PKCS #12 KDF of RFC 7292 Appendix
// B.2: id 1 for keys, 2 for IVs, 3 for MAC keys.
func pkcs12KDF(h *pfxHash, password, salt []byte, id byte, iterations, size int) []byte {
	hh := h.new()
	u, v := hh.Size(), hh.BlockSize()
	d := bytes.Repeat([]byte{id}, v)
	fill := func(x []byte) []byte {
		if len(x) == 0 {
			return nil
		}
		out := make([]byte, v*((len(x)+v-1)/v))
		for i := range out {
			out[i] = x[i%len(x)]
		}
		return out
	}
	in := append(fill(salt), fill(password)...)
	out := make([]byte, 0, size+u)
	b := make([]byte, v)
	for {
		hh.Reset()
		hh.Write(d)
		hh.Write(in)
		a := hh.Sum(nil)
		for range iterations - 1 {
			hh.Reset()
			hh.Write(a)
			a = hh.Sum(a[:0])
		}
		out = append(out, a...)
		if len(out) >= size {
			return out[:size]
		}
		// I_j = (I_j + B + 1) mod 2^(8v) for each v byte block of I.
		for i := range b {
			b[i] = a[i%u]
		}
		for j := 0; j < len(in); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				s := int(in[j+k]) + int(b[k]) + carry
				in[j+k] = byte(s)
				carry = s >> 8
			}
		}
	}
}

// pfxDecoder holds the state of one attempt to decode a PKCS #12 file.
type pfxDecoder struct {
	password  pfxPassword
	work      *int // the iterations left for key derivations
	bags      int
	decrypted bool     // some of the contents came out of a decryption
	keys      [][]byte // PKCS #8 PrivateKeyInfos
	certs     [][]byte // DER certificates
}

func pfxError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errors.ErrInvalidPrivateKey}, args...)...)
}

// spend takes iterations from the work budget.
func (d *pfxDecoder) spend(iterations int) error {
	if iterations < 1 || iterations > pfxMaxIterations {
		return pfxError("PFX iteration count %d out of range", iterations)
	}
	if iterations > *d.work {
		return pfxError("PFX key derivations exceed the work limit")
	}
	*d.work -= iterations
	return nil
}

// pfx is the outer structure of a PKCS #12 file (RFC 7292 §4).
type pfx struct {
	authSafe []byte            // the content of the authSafe data
	mac      cryptobyte.String // the MacData contents, or nil
}

func parsePFXStructure(data []byte) (*pfx, error) {
	if len(data) > maxPFXSize {
		return nil, pfxError("PFX larger than %d bytes", maxPFXSize)
	}
	var (
		in                   = cryptobyte.String(data)
		seq, ci, content, ac cryptobyte.String
		version              int
		oid                  asn1.ObjectIdentifier
		p                    pfx
	)
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() || !seq.ReadASN1Integer(&version) {
		return nil, pfxError("malformed PFX")
	}
	if version != 3 {
		return nil, pfxError("unsupported PFX version %d", version)
	}
	if !seq.ReadASN1(&ci, cbasn1.SEQUENCE) || !ci.ReadASN1ObjectIdentifier(&oid) {
		return nil, pfxError("malformed PFX authSafe")
	}
	if !oid.Equal(oidPKCS7Data) {
		// signedData: the public-key integrity mode.
		return nil, pfxError("unsupported PFX authSafe content type %s", oid)
	}
	if !ci.ReadASN1(&content, tagExplicit0) || !content.ReadASN1(&ac, cbasn1.OCTET_STRING) || !content.Empty() || !ci.Empty() {
		return nil, pfxError("malformed PFX authSafe")
	}
	p.authSafe = ac
	if seq.PeekASN1Tag(cbasn1.SEQUENCE) {
		var mac cryptobyte.String
		if !seq.ReadASN1(&mac, cbasn1.SEQUENCE) {
			return nil, pfxError("malformed PFX MacData")
		}
		p.mac = mac
	}
	if !seq.Empty() {
		return nil, pfxError("trailing data in PFX")
	}
	return &p, nil
}

// verifyMAC reports whether the MAC verifies with the password. An error is
// a malformed or unsupported MAC.
func (d *pfxDecoder) verifyMAC(p *pfx) (bool, error) {
	var (
		in                     = p.mac
		digestInfo, algo, want cryptobyte.String
		salt                   cryptobyte.String
		oid                    asn1.ObjectIdentifier
		iterations             = 1 // DEFAULT 1
	)
	if !in.ReadASN1(&digestInfo, cbasn1.SEQUENCE) ||
		!digestInfo.ReadASN1(&algo, cbasn1.SEQUENCE) || !algo.ReadASN1ObjectIdentifier(&oid) ||
		!digestInfo.ReadASN1(&want, cbasn1.OCTET_STRING) || !digestInfo.Empty() ||
		!in.ReadASN1(&salt, cbasn1.OCTET_STRING) {
		return false, pfxError("malformed PFX MacData")
	}
	if in.PeekASN1Tag(cbasn1.INTEGER) && !in.ReadASN1Integer(&iterations) || !in.Empty() {
		return false, pfxError("malformed PFX MacData")
	}

	var key []byte
	var h *pfxHash
	if oid.Equal(oidPBMAC1) {
		// RFC 9579 §3: macSalt and iterations are ignored.
		var err error
		if h, key, err = d.pbmac1Key(algo); err != nil {
			return false, err
		}
	} else {
		if h = pfxDigest(oid); h == nil {
			return false, pfxError("unsupported PFX MAC algorithm %s", oid)
		}
		if !emptyOrNULL(algo) {
			return false, pfxError("malformed PFX MAC algorithm parameters")
		}
		if len(salt) > maxPFXSalt {
			return false, pfxError("PFX MAC salt too long")
		}
		if err := d.spend(iterations); err != nil {
			return false, err
		}
		key = pkcs12KDF(h, d.password.bmp, salt, 3, iterations, h.new().Size())
	}
	mac := hmac.New(h.new, key)
	mac.Write(p.authSafe)
	return hmac.Equal(mac.Sum(nil), want), nil
}

// pbmac1Key derives the key of a PBMAC1 MAC (RFC 9579) from the parameters
// in algo and returns it with the hash of the HMAC.
func (d *pfxDecoder) pbmac1Key(algo cryptobyte.String) (*pfxHash, []byte, error) {
	var (
		params, kdf, scheme cryptobyte.String
		kdfOID, schemeOID   asn1.ObjectIdentifier
	)
	if !algo.ReadASN1(&params, cbasn1.SEQUENCE) || !algo.Empty() ||
		!params.ReadASN1(&kdf, cbasn1.SEQUENCE) || !kdf.ReadASN1ObjectIdentifier(&kdfOID) ||
		!params.ReadASN1(&scheme, cbasn1.SEQUENCE) || !scheme.ReadASN1ObjectIdentifier(&schemeOID) ||
		!params.Empty() || !emptyOrNULL(scheme) {
		return nil, nil, pfxError("malformed PBMAC1 parameters")
	}
	if !kdfOID.Equal(oidPBKDF2) {
		return nil, nil, pfxError("unsupported PBMAC1 key derivation %s", kdfOID)
	}
	h := pfxHMAC(schemeOID)
	if h == nil {
		return nil, nil, pfxError("unsupported PBMAC1 MAC %s", schemeOID)
	}
	key, keyLength, err := d.pbkdf2(kdf, 0)
	if err != nil {
		return nil, nil, err
	}
	if keyLength == 0 {
		// RFC 9579 §5: the keyLength is required.
		return nil, nil, pfxError("PBMAC1 without key length")
	}
	return h, key, nil
}

// emptyOrNULL reports whether the parameters of an AlgorithmIdentifier are
// absent or NULL.
func emptyOrNULL(params cryptobyte.String) bool {
	return params.Empty() || params.ReadASN1(&params, cbasn1.NULL) && params.Empty()
}

// pbkdf2 derives a key with the PBKDF2 parameters (RFC 8018 Appendix A.2)
// in params. size is the key size of the cipher, or 0 for the key length of
// the parameters; the key length of the parameters is returned (0 if
// absent).
func (d *pfxDecoder) pbkdf2(params cryptobyte.String, size int) ([]byte, int, error) {
	var (
		seq, salt  cryptobyte.String
		iterations int
		keyLength  int
		h          = pfxSHA1 // DEFAULT hmacWithSHA1
	)
	if !params.ReadASN1(&seq, cbasn1.SEQUENCE) || !params.Empty() ||
		!seq.ReadASN1(&salt, cbasn1.OCTET_STRING) || // otherSource is not supported
		!seq.ReadASN1Integer(&iterations) {
		return nil, 0, pfxError("malformed PBKDF2 parameters")
	}
	if seq.PeekASN1Tag(cbasn1.INTEGER) {
		if !seq.ReadASN1Integer(&keyLength) || keyLength < 1 || keyLength > 256 {
			return nil, 0, pfxError("invalid PBKDF2 key length")
		}
	}
	if seq.PeekASN1Tag(cbasn1.SEQUENCE) {
		var prf cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !seq.ReadASN1(&prf, cbasn1.SEQUENCE) || !prf.ReadASN1ObjectIdentifier(&oid) || !emptyOrNULL(prf) {
			return nil, 0, pfxError("malformed PBKDF2 PRF")
		}
		if h = pfxHMAC(oid); h == nil {
			return nil, 0, pfxError("unsupported PBKDF2 PRF %s", oid)
		}
	}
	if !seq.Empty() {
		return nil, 0, pfxError("malformed PBKDF2 parameters")
	}
	if len(salt) > maxPFXSalt {
		return nil, 0, pfxError("PBKDF2 salt too long")
	}
	switch {
	case size == 0:
		size = keyLength
	case keyLength != 0 && keyLength != size:
		return nil, 0, pfxError("PBKDF2 key length %d does not fit the cipher", keyLength)
	}
	if size == 0 {
		return nil, 0, nil
	}
	if err := d.spend(iterations); err != nil {
		return nil, 0, err
	}
	key, err := pbkdf2.Key(h.new, string(d.password.utf8), salt, iterations, size)
	if err != nil {
		return nil, 0, pfxError("PBKDF2: %v", err)
	}
	return key, keyLength, nil
}

// decrypt decrypts data with the algorithm of the AlgorithmIdentifier
// algorithm (contents, without tag and length). A padding error is
// ErrPFXPassword.
func (d *pfxDecoder) decrypt(algorithm cryptobyte.String, data []byte) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	if !algorithm.ReadASN1ObjectIdentifier(&oid) {
		return nil, pfxError("malformed PFX encryption algorithm")
	}
	var (
		plain []byte
		err   error
	)
	if oid.Equal(oidPBES2) {
		plain, err = d.decryptPBES2(algorithm, data)
	} else {
		plain, err = d.decryptPKCS12PBE(oid, algorithm, data)
	}
	if err == nil {
		d.decrypted = true
	}
	return plain, err
}

func (d *pfxDecoder) decryptPBES2(params cryptobyte.String, data []byte) ([]byte, error) {
	var (
		seq, kdf, scheme, iv cryptobyte.String
		kdfOID, schemeOID    asn1.ObjectIdentifier
	)
	if !params.ReadASN1(&seq, cbasn1.SEQUENCE) || !params.Empty() ||
		!seq.ReadASN1(&kdf, cbasn1.SEQUENCE) || !kdf.ReadASN1ObjectIdentifier(&kdfOID) ||
		!seq.ReadASN1(&scheme, cbasn1.SEQUENCE) || !scheme.ReadASN1ObjectIdentifier(&schemeOID) ||
		!seq.Empty() {
		return nil, pfxError("malformed PBES2 parameters")
	}
	if !kdfOID.Equal(oidPBKDF2) {
		return nil, pfxError("unsupported PBES2 key derivation %s", kdfOID)
	}
	c := pbes2CipherFor(schemeOID)
	if c == nil {
		return nil, pfxError("unsupported PBES2 encryption scheme %s", schemeOID)
	}
	if !scheme.ReadASN1(&iv, cbasn1.OCTET_STRING) || !scheme.Empty() {
		return nil, pfxError("malformed PBES2 IV")
	}
	key, _, err := d.pbkdf2(kdf, c.keySize)
	if err != nil {
		return nil, err
	}
	block, err := c.newFunc(key)
	if err != nil {
		return nil, pfxError("PBES2: %v", err)
	}
	return decryptCBC(block, iv, data)
}

func (d *pfxDecoder) decryptPKCS12PBE(oid asn1.ObjectIdentifier, params cryptobyte.String, data []byte) ([]byte, error) {
	var keySize int
	switch {
	case oid.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC):
		keySize = 24
	case oid.Equal(oidPBEWithSHAAnd2KeyTripleDESCBC):
		keySize = 16
	case oid.Equal(oidPBEWithSHAAnd128BitRC2CBC):
		keySize = 16
	case oid.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		keySize = 5
	default:
		return nil, pfxError("unsupported PFX encryption algorithm %s", oid)
	}
	var (
		seq, salt  cryptobyte.String
		iterations int
	)
	if !params.ReadASN1(&seq, cbasn1.SEQUENCE) || !params.Empty() ||
		!seq.ReadASN1(&salt, cbasn1.OCTET_STRING) || !seq.ReadASN1Integer(&iterations) || !seq.Empty() {
		return nil, pfxError("malformed PKCS #12 PBE parameters")
	}
	if len(salt) > maxPFXSalt {
		return nil, pfxError("PKCS #12 PBE salt too long")
	}
	// Key and IV are two derivations.
	if err := d.spend(iterations); err != nil {
		return nil, err
	}
	if err := d.spend(iterations); err != nil {
		return nil, err
	}
	key := pkcs12KDF(pfxSHA1, d.password.bmp, salt, 1, iterations, keySize)
	iv := pkcs12KDF(pfxSHA1, d.password.bmp, salt, 2, iterations, 8)
	if keySize == 5 || oid.Equal(oidPBEWithSHAAnd128BitRC2CBC) {
		k, err := newRC2Key(key, 8*keySize)
		if err != nil {
			return nil, err
		}
		if len(data) == 0 || len(data)%rc2BlockSize != 0 {
			return nil, pfxError("PFX ciphertext is not a multiple of the block size")
		}
		return unpad(rc2DecryptCBC(k, iv, data), rc2BlockSize)
	}
	if keySize == 16 {
		key = append(key, key[:8]...) // K1 K2 K1
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, pfxError("3DES: %v", err)
	}
	return decryptCBC(block, iv, data)
}

func decryptCBC(block cipher.Block, iv, data []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, pfxError("PFX IV has the wrong size")
	}
	if len(data) == 0 || len(data)%bs != 0 {
		return nil, pfxError("PFX ciphertext is not a multiple of the block size")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return unpad(out, bs)
}

// unpad removes PKCS #7 padding (RFC 5652 §6.3) without branching on the
// padding bytes. Bad padding is ErrPFXPassword.
func unpad(b []byte, blockSize int) ([]byte, error) {
	n := len(b)
	p := int(b[n-1])
	good := subtle.ConstantTimeLessOrEq(1, p) & subtle.ConstantTimeLessOrEq(p, blockSize)
	for i := range blockSize {
		inPad := subtle.ConstantTimeLessOrEq(i+1, p)
		eq := subtle.ConstantTimeByteEq(b[n-1-i], byte(p))
		good &= subtle.ConstantTimeSelect(inPad, eq, 1)
	}
	if good != 1 {
		return nil, ErrPFXPassword
	}
	return b[:n-p], nil
}

// decodeAuthSafe decodes the AuthenticatedSafe: a sequence of ContentInfos,
// each data or encryptedData with SafeContents.
func (d *pfxDecoder) decodeAuthSafe(authSafe []byte) error {
	// The MAC covers the bytes as they are; they are parsed in DER.
	authSafe, err := berToDER(authSafe)
	if err != nil {
		return pfxError("malformed PFX AuthenticatedSafe")
	}
	var (
		in  = cryptobyte.String(authSafe)
		seq cryptobyte.String
	)
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return pfxError("malformed PFX AuthenticatedSafe")
	}
	for !seq.Empty() {
		var (
			ci, content cryptobyte.String
			oid         asn1.ObjectIdentifier
		)
		if !seq.ReadASN1(&ci, cbasn1.SEQUENCE) || !ci.ReadASN1ObjectIdentifier(&oid) ||
			!ci.ReadASN1(&content, tagExplicit0) || !ci.Empty() {
			return pfxError("malformed PFX ContentInfo")
		}
		if d.bags++; d.bags > maxPFXBags {
			return pfxError("PFX has more than %d bags", maxPFXBags)
		}
		switch {
		case oid.Equal(oidPKCS7Data):
			var data cryptobyte.String
			if !content.ReadASN1(&data, cbasn1.OCTET_STRING) || !content.Empty() {
				return pfxError("malformed PFX data")
			}
			if err := d.decodeSafeContents(data, 0); err != nil {
				return err
			}
		case oid.Equal(oidPKCS7EncryptedData):
			data, err := d.decryptEncryptedData(content)
			if err != nil {
				return err
			}
			if err := d.decodeSafeContents(data, 0); err != nil {
				return d.decryptedError(err)
			}
		default:
			return pfxError("unsupported PFX content type %s", oid)
		}
	}
	return nil
}

// decryptedError is the error for contents that do not parse when some of
// them were decrypted: a wrong password gives valid padding now and then
// (about 1 in 256 times). A verified MAC does not rule that out: the MAC
// covers the ciphertext, and a PFX may encrypt with another password than
// its MAC's (openssl pkcs12 -twopass).
func (d *pfxDecoder) decryptedError(err error) error {
	if !d.decrypted {
		return err
	}
	return fmt.Errorf("%w (%w)", ErrPFXPassword, err)
}

// decryptEncryptedData decrypts an EncryptedData (RFC 5652 §8).
func (d *pfxDecoder) decryptEncryptedData(content cryptobyte.String) ([]byte, error) {
	var (
		seq, eci, algo cryptobyte.String
		version        int
		oid            asn1.ObjectIdentifier
	)
	if !content.ReadASN1(&seq, cbasn1.SEQUENCE) || !content.Empty() ||
		!seq.ReadASN1Integer(&version) ||
		!seq.ReadASN1(&eci, cbasn1.SEQUENCE) || !eci.ReadASN1ObjectIdentifier(&oid) ||
		!eci.ReadASN1(&algo, cbasn1.SEQUENCE) {
		return nil, pfxError("malformed PFX EncryptedData")
	}
	if version != 0 || !oid.Equal(oidPKCS7Data) {
		return nil, pfxError("unsupported PFX EncryptedData")
	}
	// encryptedContent [0] IMPLICIT OCTET STRING: primitive, or constructed
	// from primitive OCTET STRINGs.
	var ciphertext []byte
	switch {
	case eci.PeekASN1Tag(tagImplicit0):
		var c cryptobyte.String
		if !eci.ReadASN1(&c, tagImplicit0) {
			return nil, pfxError("malformed PFX encrypted content")
		}
		ciphertext = c
	case eci.PeekASN1Tag(tagExplicit0):
		var c cryptobyte.String
		if !eci.ReadASN1(&c, tagExplicit0) {
			return nil, pfxError("malformed PFX encrypted content")
		}
		for !c.Empty() {
			var part cryptobyte.String
			if !c.ReadASN1(&part, cbasn1.OCTET_STRING) {
				return nil, pfxError("malformed PFX encrypted content")
			}
			ciphertext = append(ciphertext, part...)
		}
	default:
		return nil, pfxError("PFX EncryptedData without content")
	}
	// Unprotected attributes [1] are allowed and ignored.
	if !eci.Empty() || !seq.SkipOptionalASN1(cbasn1.Tag(1).Constructed().ContextSpecific()) || !seq.Empty() {
		return nil, pfxError("malformed PFX EncryptedData")
	}
	return d.decrypt(algo, ciphertext)
}

// decodeSafeContents decodes a SafeContents, a sequence of SafeBags (RFC
// 7292 §4.2).
func (d *pfxDecoder) decodeSafeContents(data []byte, depth int) error {
	data, err := berToDER(data)
	if err != nil {
		return pfxError("malformed PFX SafeContents")
	}
	var (
		in  = cryptobyte.String(data)
		seq cryptobyte.String
	)
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return pfxError("malformed PFX SafeContents")
	}
	for !seq.Empty() {
		var (
			bag, value cryptobyte.String
			oid        asn1.ObjectIdentifier
		)
		// bagAttributes (friendlyName, localKeyId) are not needed: the key
		// and its certificate are matched by their public keys.
		if !seq.ReadASN1(&bag, cbasn1.SEQUENCE) || !bag.ReadASN1ObjectIdentifier(&oid) ||
			!bag.ReadASN1(&value, tagExplicit0) ||
			!bag.SkipOptionalASN1(cbasn1.SET) || !bag.Empty() {
			return pfxError("malformed PFX SafeBag")
		}
		if d.bags++; d.bags > maxPFXBags {
			return pfxError("PFX has more than %d bags", maxPFXBags)
		}
		var err error
		switch {
		case oid.Equal(oidKeyBag):
			err = d.keyBag(value)
		case oid.Equal(oidShroudedKeyBag):
			err = d.shroudedKeyBag(value)
		case oid.Equal(oidCertBag):
			err = d.certBag(value)
		case oid.Equal(oidSafeContentsBag):
			if depth+1 > maxPFXDepth {
				return pfxError("PFX safeContentsBags nested too deeply")
			}
			err = d.decodeSafeContents(value, depth+1)
		default:
			// crlBag, secretBag and unknown bags.
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *pfxDecoder) keyBag(value cryptobyte.String) error {
	var key cryptobyte.String
	if !value.ReadASN1Element(&key, cbasn1.SEQUENCE) || !value.Empty() {
		return pfxError("malformed PFX keyBag")
	}
	d.keys = append(d.keys, key)
	return nil
}

func (d *pfxDecoder) shroudedKeyBag(value cryptobyte.String) error {
	var seq, algo, data cryptobyte.String
	if !value.ReadASN1(&seq, cbasn1.SEQUENCE) || !value.Empty() ||
		!seq.ReadASN1(&algo, cbasn1.SEQUENCE) || !seq.ReadASN1(&data, cbasn1.OCTET_STRING) || !seq.Empty() {
		return pfxError("malformed PFX pkcs8ShroudedKeyBag")
	}
	key, err := d.decrypt(algo, data)
	if err != nil {
		return err
	}
	d.keys = append(d.keys, key)
	return nil
}

func (d *pfxDecoder) certBag(value cryptobyte.String) error {
	var (
		seq, wrapper, cert cryptobyte.String
		oid                asn1.ObjectIdentifier
	)
	if !value.ReadASN1(&seq, cbasn1.SEQUENCE) || !value.Empty() ||
		!seq.ReadASN1ObjectIdentifier(&oid) || !seq.ReadASN1(&wrapper, tagExplicit0) || !seq.Empty() {
		return pfxError("malformed PFX certBag")
	}
	if !oid.Equal(oidCertTypeX509) {
		return nil // sdsiCertificate
	}
	if !wrapper.ReadASN1(&cert, cbasn1.OCTET_STRING) || !wrapper.Empty() {
		return pfxError("malformed PFX certBag")
	}
	d.certs = append(d.certs, cert)
	return nil
}

// ParsePFX decodes a PKCS #12 file (RFC 7292) with the password and returns
// its private key and its certificates. The file must hold exactly one
// private key; the certificate whose public key is the key's comes first,
// the others follow in the order of the file. See the comment at the top of
// pkcs12.go for the supported algorithms. A MAC that does not verify, or
// contents that do not decrypt, is ErrPFXPassword.
func ParsePFX(data []byte, password string) (crypto.Signer, []*x509.Certificate, error) {
	if len(password) > maxPFXPassword {
		return nil, nil, pfxError("PFX password too long")
	}
	if len(data) > maxPFXSize {
		return nil, nil, pfxError("PFX larger than %d bytes", maxPFXSize)
	}
	der, err := berToDER(data)
	if err != nil {
		return nil, nil, pfxError("malformed PFX: %v", err)
	}
	p, err := parsePFXStructure(der)
	if err != nil {
		return nil, nil, err
	}
	work := pfxMaxWork
	candidates := pfxPasswords(password)
	if p.mac != nil {
		for _, pw := range candidates {
			d := &pfxDecoder{password: pw, work: &work}
			ok, err := d.verifyMAC(p)
			if err != nil {
				return nil, nil, err
			}
			if ok {
				return d.decode(p)
			}
		}
		return nil, nil, ErrPFXPassword
	}
	// Without a MAC only decryption tells whether an empty password is
	// meant as no password or as the empty BMPString.
	var (
		key   crypto.Signer
		certs []*x509.Certificate
	)
	for _, pw := range candidates {
		d := &pfxDecoder{password: pw, work: &work}
		key, certs, err = d.decode(p)
		if !stderrors.Is(err, ErrPFXPassword) {
			break
		}
	}
	return key, certs, err
}

func (d *pfxDecoder) decode(p *pfx) (crypto.Signer, []*x509.Certificate, error) {
	if err := d.decodeAuthSafe(p.authSafe); err != nil {
		return nil, nil, err
	}
	switch len(d.keys) {
	case 0:
		return nil, nil, pfxError("PFX holds no private key")
	case 1:
	default:
		return nil, nil, pfxError("PFX holds %d private keys", len(d.keys))
	}
	pk, err := berToDER(d.keys[0])
	if err != nil {
		return nil, nil, d.decryptedError(pfxError("malformed PFX private key"))
	}
	key, err := parsePKCS8(pk)
	if err != nil {
		return nil, nil, d.decryptedError(err)
	}
	certs := make([]*x509.Certificate, 0, len(d.certs))
	leaf := -1
	for _, der := range d.certs {
		cert, err := ParseCertificate(der)
		if err != nil {
			return nil, nil, d.decryptedError(fmt.Errorf("%w: PFX certificate: %w", errors.ErrInvalidCertificate, err))
		}
		if leaf < 0 && keysEqual(cert.PublicKey, key.Public()) {
			leaf = len(certs)
		}
		certs = append(certs, cert)
	}
	if leaf > 0 {
		c := certs[leaf]
		copy(certs[1:leaf+1], certs[:leaf])
		certs[0] = c
	}
	return key, certs, nil
}

// EncodePFX encodes a private key and its certificates (DER) as a PKCS #12
// file protected with the password, as OpenSSL 3 does by default: the key in
// a pkcs8ShroudedKeyBag and the certificates in encryptedData, both with
// PBES2 (PBKDF2 with HMAC-SHA-256, 2048 iterations, AES-256-CBC), and an
// HMAC-SHA-256 MAC (2048 iterations), with random salts and IVs. The key is
// encoded with MarshalPrivateKey. One of the certificates must be the key's;
// a localKeyId attribute links it to the key.
func EncodePFX(key crypto.Signer, certs [][]byte, password string) ([]byte, error) {
	return encodePFX(rand.Reader, key, certs, password, pfxSHA256, pbes2AES256)
}

func encodePFX(rand io.Reader, key crypto.Signer, certs [][]byte, password string, prf *pfxHash, c *pbes2Cipher) ([]byte, error) {
	if key == nil || isNilKey(key) {
		return nil, pfxError("no key for the PFX")
	}
	if len(password) > maxPFXPassword {
		return nil, pfxError("PFX password too long")
	}
	pkcs8, err := MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	leaf := -1
	for i, der := range certs {
		cert, err := ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if leaf < 0 && keysEqual(cert.PublicKey, key.Public()) {
			leaf = i
		}
	}
	if len(certs) > 0 && leaf < 0 {
		return nil, pfxError("the PFX key belongs to none of the certificates")
	}
	var localKeyID []byte
	if leaf >= 0 {
		sum := sha1.Sum(certs[leaf]) //nolint:gosec // an identifier, as OpenSSL makes it.
		localKeyID = sum[:]
	}
	attributes := func(b *cryptobyte.Builder) {
		if localKeyID == nil {
			return
		}
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidAttributeLocalKeyID)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1OctetString(localKeyID)
				})
			})
		})
	}
	// The empty password as the empty BMPString, as OpenSSL writes it.
	candidates := pfxPasswords(password)
	pw := candidates[len(candidates)-1]

	// The certificates in encryptedData, the key in a pkcs8ShroudedKeyBag in
	// data, as OpenSSL orders them.
	var certInfo []byte
	if len(certs) > 0 {
		var sc cryptobyte.Builder
		sc.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for i, der := range certs {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidCertBag)
					b.AddASN1(tagExplicit0, func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddASN1ObjectIdentifier(oidCertTypeX509)
							b.AddASN1(tagExplicit0, func(b *cryptobyte.Builder) {
								b.AddASN1OctetString(der)
							})
						})
					})
					if i == leaf {
						attributes(b)
					}
				})
			}
		})
		plain, err := sc.Bytes()
		if err != nil {
			return nil, err
		}
		algo, ciphertext, err := encryptPBES2(rand, pw.utf8, plain, prf, c, pfxEncodeIterations)
		if err != nil {
			return nil, err
		}
		var ci cryptobyte.Builder
		ci.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPKCS7EncryptedData)
			b.AddASN1(tagExplicit0, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1Int64(0)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidPKCS7Data)
						b.AddBytes(algo)
						b.AddASN1(tagImplicit0, func(b *cryptobyte.Builder) {
							b.AddBytes(ciphertext)
						})
					})
				})
			})
		})
		if certInfo, err = ci.Bytes(); err != nil {
			return nil, err
		}
	}

	algo, ciphertext, err := encryptPBES2(rand, pw.utf8, pkcs8, prf, c, pfxEncodeIterations)
	if err != nil {
		return nil, err
	}
	var keySC cryptobyte.Builder
	keySC.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidShroudedKeyBag)
			b.AddASN1(tagExplicit0, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddBytes(algo)
					b.AddASN1OctetString(ciphertext)
				})
			})
			attributes(b)
		})
	})
	keyContents, err := keySC.Bytes()
	if err != nil {
		return nil, err
	}
	var as cryptobyte.Builder
	as.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(certInfo)
		addDataContentInfo(b, keyContents)
	})
	authSafeBytes, err := as.Bytes()
	if err != nil {
		return nil, err
	}

	// The MAC.
	salt := make([]byte, pfxSaltSize)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, err
	}
	macKey := pkcs12KDF(pfxSHA256, pw.bmp, salt, 3, pfxEncodeIterations, sha256.Size)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(authSafeBytes)

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(3)
		addDataContentInfo(b, authSafeBytes)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddBytes(mustAlgorithmIdentifier(pfxSHA256.digest, true))
				b.AddASN1OctetString(mac.Sum(nil))
			})
			b.AddASN1OctetString(salt)
			b.AddASN1Int64(pfxEncodeIterations)
		})
	})
	return b.Bytes()
}

// addDataContentInfo adds a ContentInfo of type data.
func addDataContentInfo(b *cryptobyte.Builder, data []byte) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidPKCS7Data)
		b.AddASN1(tagExplicit0, func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(data)
		})
	})
}

// encryptPBES2 encrypts plaintext with PBES2 and PBKDF2 and returns the DER
// AlgorithmIdentifier and the ciphertext.
func encryptPBES2(rand io.Reader, password, plaintext []byte, prf *pfxHash, c *pbes2Cipher, iterations int) ([]byte, []byte, error) {
	salt := make([]byte, pfxSaltSize)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, nil, err
	}
	key, err := pbkdf2.Key(prf.new, string(password), salt, iterations, c.keySize)
	if err != nil {
		return nil, nil, pfxError("PBKDF2: %v", err)
	}
	block, err := c.newFunc(key)
	if err != nil {
		return nil, nil, err
	}
	bs := block.BlockSize()
	iv := make([]byte, bs)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, nil, err
	}
	pad := bs - len(plaintext)%bs
	data := append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidPBES2)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidPBKDF2)
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1OctetString(salt)
					b.AddASN1Int64(int64(iterations))
					b.AddBytes(mustAlgorithmIdentifier(prf.hmac, true))
				})
			})
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(c.oid)
				b.AddASN1OctetString(iv)
			})
		})
	})
	algo, err := b.Bytes()
	return algo, data, err
}
