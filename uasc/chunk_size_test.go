// SPDX-License-Identifier: MIT

package uasc

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// TestReadChunk_OversizedChunkIsNotEOF feeds a channel a chunk that is larger
// than its receive buffer, and one that is smaller than its own header. The
// channel has to report what happened; it used to report io.EOF, as if the
// peer had closed the connection.
func TestReadChunk_OversizedChunkIsNotEOF(t *testing.T) {
	for _, tt := range []struct {
		size uint32
		want error
	}{
		{uacp.DefaultReceiveBufSize + 1, errors.ErrMessageTooLarge},
		{4, errors.ErrMessageTooSmall},
		{0, io.EOF}, // nothing sent: the end of the stream still is io.EOF
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		peerCh := make(chan net.Conn, 1)
		go func() {
			if c, err := ln.Accept(); err == nil {
				peerCh <- c
			}
		}()
		tc, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		peer := <-peerCh

		conn, err := uacp.NewConn(tc.(*net.TCPConn), nil)
		require.NoError(t, err)
		cfg := &Config{SecurityPolicyURI: ua.SecurityPolicyURINone, SecurityMode: ua.MessageSecurityModeNone, Logger: testLogger}
		s, err := NewServerSecureChannel("opc.tcp://"+ln.Addr().String(), conn, cfg, make(chan error, 1), 7, 1, 9)
		require.NoError(t, err)

		if tt.size > 0 {
			hdr := []byte("MSGF\x00\x00\x00\x00")
			binary.LittleEndian.PutUint32(hdr[4:], tt.size)
			_, err = peer.Write(hdr)
			require.NoError(t, err)
		}
		require.NoError(t, peer.Close())
		_, err = s.readChunk()
		require.ErrorIs(t, err, tt.want)
		if tt.want != io.EOF {
			require.NotErrorIs(t, err, io.EOF)
		}
		_ = tc.Close()
		_ = ln.Close()
	}
}

// symmetricPair returns the two ends of an open channel of a policy with a
// block cipher and an HMAC: the RSA policies and the ECC policies without
// authenticated encryption.
func symmetricPair(t *testing.T, uri string, mode ua.MessageSecurityMode) (client, server *channelInstance) {
	t.Helper()
	var calgo, salgo *uapolicy.EncryptionAlgorithm
	if uapolicy.LegacySequenceNumbers(uri) {
		cn, sn := make([]byte, 32), make([]byte, 32)
		_, _ = rand.Read(cn)
		_, _ = rand.Read(sn)
		var err error
		calgo, err = uapolicy.Symmetric(uri, cn, sn)
		require.NoError(t, err)
		salgo, err = uapolicy.Symmetric(uri, sn, cn)
		require.NoError(t, err)
	} else {
		ckx, err := uapolicy.NewKeyExchange(uri, uapolicy.RoleClient)
		require.NoError(t, err)
		skx, err := uapolicy.NewKeyExchange(uri, uapolicy.RoleServer)
		require.NoError(t, err)
		calgo, err = ckx.Symmetric(skx.Nonce())
		require.NoError(t, err)
		salgo, err = skx.Symmetric(ckx.Nonce())
		require.NoError(t, err)
	}
	instance := func(algo *uapolicy.EncryptionAlgorithm) *channelInstance {
		cfg := &Config{SecurityPolicyURI: uri, SecurityMode: mode, Logger: testLogger}
		return &channelInstance{
			sc: &SecureChannel{cfg: cfg}, algo: algo,
			zeroBasedSeq: !uapolicy.LegacySequenceNumbers(uri), seqStarted: true,
			secureChannelID: 9, securityTokenID: 3,
		}
	}
	return instance(calgo), instance(salgo)
}

// TestChunksFitTheSendBuffer sends a message that takes several chunks with
// every policy and mode and with send buffer sizes of every residue modulo
// the cipher block size. No secured chunk may be larger than the buffer the
// peer announced: a peer rejects a larger one and the connection is lost.
//
// Regression: with a block cipher the size of a full chunk was rounded up to
// the next block after the padding had been added, so that with the default
// buffer of 65535 bytes every full chunk was 65536 bytes long and no
// multi-chunk message got through a SignAndEncrypt channel.
func TestChunksFitTheSendBuffer(t *testing.T) {
	policies := []string{
		ua.SecurityPolicyURIBasic128Rsa15,
		ua.SecurityPolicyURIBasic256,
		ua.SecurityPolicyURIBasic256Sha256,
		ua.SecurityPolicyURIAes128Sha256RsaOaep,
		ua.SecurityPolicyURIAes256Sha256RsaPss,
		ua.SecurityPolicyURIECCNistP256,
		ua.SecurityPolicyURIECCNistP384,
		ua.SecurityPolicyURIECCNistP256AesGcm,
		ua.SecurityPolicyURIECCNistP256ChaChaPoly,
		ua.SecurityPolicyURIECCCurve25519,
	}
	sizes := []int{65535, 65536, 8192}
	for n := 1024; n < 1024+48; n++ {
		sizes = append(sizes, n)
	}
	// A value of at least four chunks: 200 kB for the 64k buffers, 5 kB for
	// the small ones.
	large := make([]byte, 200_000)
	_, _ = rand.Read(large)
	response := func(chunkSize int) (*ua.ReadResponse, []byte) {
		value := large
		if chunkSize < 8192 {
			value = large[:5000]
		} else if chunkSize == 8192 {
			value = large[:30_000]
		}
		return &ua.ReadResponse{
			ResponseHeader: &ua.ResponseHeader{},
			Results:        []*ua.DataValue{{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(value)}},
		}, value
	}

	for _, uri := range policies {
		for _, mode := range secureModes {
			t.Run(uri+"/"+mode.String(), func(t *testing.T) {
				for _, chunkSize := range sizes {
					server, client := symmetricPair(t, uri, mode)
					server.SetMaximumBodySize(chunkSize)
					resp, value := response(chunkSize)

					wires, _ := sendChunks(t, server, resp, id.ReadResponseEncodingDefaultBinary)
					require.Greater(t, len(wires), 3, "the message must take several chunks")
					var chunks []*MessageChunk
					for i, wire := range wires {
						require.LessOrEqual(t, len(wire), chunkSize, "chunk %d of %d with a send buffer of %d bytes", i, len(wires), chunkSize)
						chunk, err := deliver(client, wire)
						require.NoError(t, err, "chunk %d with a send buffer of %d bytes", i, chunkSize)
						chunks = append(chunks, chunk)
					}
					// A full chunk wastes less than two cipher blocks.
					require.Greater(t, len(wires[0]), chunkSize-33, "send buffer of %d bytes", chunkSize)

					_, svc, err := ua.DecodeService(mergeChunks(chunks))
					require.NoError(t, err)
					got, ok := svc.(*ua.ReadResponse)
					require.True(t, ok)
					require.True(t, bytes.Equal(value, got.Results[0].Value.Value().([]byte)), "send buffer of %d bytes", chunkSize)
				}
			})
		}
	}
}
