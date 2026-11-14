// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/otfabric/go-opcua/errors"
)

var pfxSHA512 = &pfxHashes[4]

// pbmac1Params are PBMAC1-params (RFC 9579): PBKDF2 with the PRF prf and
// the HMAC of mac.
func pbmac1Params(prf, mac *pfxHash, iterations, keyLength int64) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPBKDF2)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString([]byte("saltsalt"))
				b.AddASN1Int64(iterations)
				b.AddASN1Int64(keyLength)
				b.AddBytes(mustAlgorithmIdentifier(prf.hmac, true))
			})
		})
		b.AddBytes(mustAlgorithmIdentifier(mac.hmac, true))
	})
	return b.BytesOrPanic()
}

// addPBMAC1 adds a PBMAC1 MacData for the password to b.
func addPBMAC1(b *cryptobyte.Builder, authSafe []byte, password string, prf, mac *pfxHash, iterations, keyLength int) {
	key, err := pbkdf2.Key(prf.new, password, []byte("saltsalt"), iterations, keyLength)
	if err != nil {
		panic(err)
	}
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidPBMAC1)
				b.AddBytes(pbmac1Params(prf, mac, int64(iterations), int64(keyLength)))
			})
			b.AddASN1OctetString(hmacSum(mac, key, authSafe))
		})
		b.AddASN1OctetString([]byte("ignored")) // RFC 9579 §3
	})
}

// TestPFXSpend is the boundary table of the work budget: a key derivation
// of size bytes with a hash of output size hLen costs its iterations times
// ceil(size/hLen), and is refused, leaving the budget as it was, when that
// is more than is left.
func TestPFXSpend(t *testing.T) {
	const limit = 10_000_000 // pfxMaxIterations
	require.Equal(t, limit, pfxMaxIterations)
	for _, tt := range []struct {
		name                   string
		iterations, size, hLen int
		work                   int
		cost                   int // -1: refused
	}{
		{"no iterations", 0, 20, 20, 100, -1},
		{"negative iterations", -1, 20, 20, 100, -1},
		{"smallest 32-bit int", math.MinInt32, 20, 20, 100, -1},
		{"one iteration", 1, 20, 20, 100, 1},
		{"one byte", 1, 1, 20, 100, 1},
		{"one byte short of a block", 3, 19, 20, 100, 3},
		{"one block", 3, 20, 20, 100, 3},
		{"one byte over a block", 3, 21, 20, 100, 6},
		{"two blocks", 3, 40, 20, 100, 6},
		{"largest PBKDF2 key with SHA-1", 3, 256, 20, 100, 39},
		{"largest PBKDF2 key with SHA-512", 3, 256, 64, 100, 12},
		{"all of the budget", 25, 40, 20, 50, 50},
		{"one more than the budget", 25, 41, 20, 74, -1},
		{"one more than the budget, one block", 51, 20, 20, 50, -1},
		{"iterations one below the limit", limit - 1, 20, 20, pfxMaxWork, limit - 1},
		{"iterations at the limit", limit, 20, 20, pfxMaxWork, limit},
		{"iterations one above the limit", limit + 1, 20, 20, pfxMaxWork, -1},
		{"largest 32-bit iterations", math.MaxInt32, 20, 20, math.MaxInt32, -1},
		{"iterations at the limit, two blocks", limit, 40, 20, pfxMaxWork, 2 * limit},
		{"iterations at the limit, three blocks", limit, 41, 20, pfxMaxWork, -1},
		{"iterations at the limit, largest key", limit, 256, 20, pfxMaxWork, -1},
		{"product above the 32-bit range", limit, 256, 1, math.MaxInt32, -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			work := tt.work
			d := &pfxDecoder{work: &work}
			err := d.spend(tt.iterations, tt.size, tt.hLen)
			if tt.cost < 0 {
				require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
				require.Equal(t, tt.work, work, "the budget after a refused derivation")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.work-tt.cost, work)
		})
	}
}

// TestPBMAC1KeyLength is the boundary table of the key length of a PBMAC1
// MAC: from 1 to the block size of its HMAC. A longer key length is refused
// before anything is derived; an accepted one is charged per block of the
// PBKDF2 PRF.
func TestPBMAC1KeyLength(t *testing.T) {
	for _, mac := range []*pfxHash{pfxSHA1, pfxSHA256, pfxSHA512} {
		block, size := mac.new().BlockSize(), mac.new().Size()
		for _, prf := range []*pfxHash{pfxSHA1, pfxSHA256, pfxSHA512} {
			hLen := prf.new().Size()
			for _, tt := range []struct {
				keyLength int64
				ok        bool
			}{
				{-1, false},
				{0, false},
				{1, true},
				{int64(size), true},
				{int64(block) - 1, true},
				{int64(block), true},
				{int64(block) + 1, false},
				{256, false},
				{257, false},
				{math.MaxInt32, false},
				{math.MaxInt32 + 1, false},
			} {
				const iterations = 3
				work := 1000
				d := &pfxDecoder{password: pfxPassword{utf8: []byte("p")}, work: &work}
				h, key, err := d.pbmac1Key(cryptobyte.String(pbmac1Params(prf, mac, iterations, tt.keyLength)))
				if !tt.ok {
					require.ErrorIs(t, err, errors.ErrInvalidPrivateKey, "key length %d, MAC %s", tt.keyLength, mac.hmac)
					require.Equal(t, 1000, work, "key length %d, MAC %s: nothing is derived", tt.keyLength, mac.hmac)
					continue
				}
				require.NoError(t, err, "key length %d, MAC %s", tt.keyLength, mac.hmac)
				require.Same(t, mac, h)
				require.Len(t, key, int(tt.keyLength))
				blocks := (int(tt.keyLength) + hLen - 1) / hLen
				require.Equal(t, 1000-iterations*blocks, work, "key length %d, PRF %s", tt.keyLength, prf.hmac)
			}
		}
	}
}

// TestParsePFX_PBMAC1Work: ParsePFX reads a PBMAC1 MAC with the key length
// of the block size of its HMAC and charges the work of its key derivation
// per block of the PRF. At the iteration limit a key length of more than
// two blocks of the PRF is above the work limit, and a key length above the
// block size is refused, both before the key is derived.
func TestParsePFX_PBMAC1Work(t *testing.T) {
	key := newEd448Key(t)
	pkcs8, err := MarshalPrivateKey(key)
	require.NoError(t, err)
	contents := [][]byte{dataContent(safeBag(oidKeyBag, pkcs8))}
	withMAC := func(prf, mac *pfxHash, iterations, keyLength int) []byte {
		p := &pfxBuilder{password: "p", contents: contents, mac: func(b *cryptobyte.Builder, as []byte) {
			addPBMAC1(b, as, "p", prf, mac, iterations, keyLength)
		}}
		return p.bytes(t)
	}

	t.Run("block size", func(t *testing.T) {
		got, _, err := ParsePFX(withMAC(pfxSHA256, pfxSHA256, 2, 64), "p")
		require.NoError(t, err)
		require.True(t, keysEqual(got.Public(), key.Public()))
		got, _, err = ParsePFX(withMAC(pfxSHA512, pfxSHA512, 2, 128), "p")
		require.NoError(t, err)
		require.True(t, keysEqual(got.Public(), key.Public()))
	})

	t.Run("work per block", func(t *testing.T) {
		defer func(i, w int) { pfxMaxIterations, pfxMaxWork = i, w }(pfxMaxIterations, pfxMaxWork)
		pfxMaxIterations, pfxMaxWork = 10, 15
		// 10 iterations of one block of SHA-256 fit the work limit of 15,
		// two blocks do not.
		_, _, err := ParsePFX(withMAC(pfxSHA256, pfxSHA256, 10, 32), "p")
		require.NoError(t, err)
		_, _, err = ParsePFX(withMAC(pfxSHA256, pfxSHA256, 10, 33), "p")
		require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
		require.NotErrorIs(t, err, ErrPFXPassword)
		require.ErrorContains(t, err, "work limit")
		// The key length of the block size of HMAC-SHA1 is four blocks
		// of the SHA-1 PRF: 4 iterations fit 15, 4 blocks of 4 do not.
		_, _, err = ParsePFX(withMAC(pfxSHA1, pfxSHA1, 3, 64), "p")
		require.NoError(t, err)
		_, _, err = ParsePFX(withMAC(pfxSHA1, pfxSHA1, 4, 64), "p")
		require.ErrorContains(t, err, "work limit")
	})

	t.Run("at the limits", func(t *testing.T) {
		limit := int64(pfxMaxIterations)
		for _, tt := range []struct {
			name      string
			prf, mac  *pfxHash
			keyLength int64
			refusal   string
		}{
			{"three blocks of SHA-256", pfxSHA256, pfxSHA256, 64 + 1, "longer than 64"},
			{"three blocks of SHA-1", pfxSHA1, pfxSHA1, 41, "work limit"},
			{"block size of HMAC-SHA1", pfxSHA1, pfxSHA1, 64, "work limit"},
			{"largest PBKDF2 key length", pfxSHA1, pfxSHA1, 256, "longer than 64"},
			{"largest PBKDF2 key length, HMAC-SHA512", pfxSHA1, pfxSHA512, 256, "longer than 128"},
		} {
			// The MAC value does not matter: the parameters are refused
			// before the MAC is computed.
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidPBMAC1)
						b.AddBytes(pbmac1Params(tt.prf, tt.mac, limit, tt.keyLength))
					})
					b.AddASN1OctetString(make([]byte, tt.mac.new().Size()))
				})
				b.AddASN1OctetString([]byte("ignored"))
			})
			macData := b.BytesOrPanic()
			p := &pfxBuilder{password: "p", contents: contents, mac: func(b *cryptobyte.Builder, _ []byte) { b.AddBytes(macData) }}
			_, _, err := ParsePFX(p.bytes(t), "p")
			require.ErrorIs(t, err, errors.ErrInvalidPrivateKey, tt.name)
			require.NotErrorIs(t, err, ErrPFXPassword, tt.name)
			require.ErrorContains(t, err, tt.refusal, tt.name)
		}
	})

	t.Run("PBES2 per block", func(t *testing.T) {
		defer func(i, w int) { pfxMaxIterations, pfxMaxWork = i, w }(pfxMaxIterations, pfxMaxWork)
		pfxMaxIterations, pfxMaxWork = 10, 25
		// The MAC takes 10. The AES-256 key of PBES2 is one block of the
		// SHA-256 PRF, 10 more, and two blocks of the SHA-1 PRF, 20 more.
		pbes2 := func(prf *pfxHash) []byte {
			algo, ciphertext, err := encryptPBES2(rand.Reader, []byte("p"), safeContents(safeBag(oidKeyBag, pkcs8)), prf, pbes2AES256, 10)
			require.NoError(t, err)
			p := &pfxBuilder{password: "p", contents: [][]byte{encryptedContent(algo, ciphertext, false)}, mac: func(b *cryptobyte.Builder, as []byte) {
				addPKCS12MAC(b, as, "p", pfxSHA256, 10)
			}}
			return p.bytes(t)
		}
		got, _, err := ParsePFX(pbes2(pfxSHA256), "p")
		require.NoError(t, err, "20 is within 25")
		require.True(t, keysEqual(got.Public(), key.Public()))
		_, _, err = ParsePFX(pbes2(pfxSHA1), "p")
		require.ErrorContains(t, err, "work limit", "30 is above 25")
	})
}
