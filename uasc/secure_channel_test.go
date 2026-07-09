// SPDX-License-Identifier: MIT

package uasc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	uatest "github.com/otfabric/go-opcua/tests/python"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

func TestNewRequestMessage(t *testing.T) {
	fixedTime := func() time.Time { return time.Date(2019, 1, 1, 12, 13, 14, 0, time.UTC) }

	buildSecureChannel := func(sc *SecureChannel, instance *channelInstance) *SecureChannel {
		if instance == nil {
			instance = newChannelInstance(sc)
		}
		sc.activeInstance = instance
		sc.activeInstance.sc = sc
		return sc
	}

	tests := []struct {
		name      string
		sechan    *SecureChannel
		req       ua.Request
		authToken *ua.NodeID
		timeout   time.Duration
		m         *Message
	}{
		{
			name: "first-request",
			sechan: buildSecureChannel(&SecureChannel{
				cfg: &Config{Logger: testLogger},
				// reqhdr: &ua.RequestHeader{},
				time: fixedTime,
			}, nil),
			req: &ua.ReadRequest{},
			m: &Message{
				MessageHeader: &MessageHeader{
					Header: &Header{
						MessageType: MessageTypeMessage,
						ChunkType:   ChunkTypeFinal,
					},
					SymmetricSecurityHeader: &SymmetricSecurityHeader{},
					SequenceHeader: &SequenceHeader{
						SequenceNumber: 1,
						RequestID:      1,
					},
				},
				TypeID: ua.NewFourByteExpandedNodeID(0, id.ReadRequestEncodingDefaultBinary),
				Service: &ua.ReadRequest{
					RequestHeader: &ua.RequestHeader{
						AuthenticationToken: ua.NewTwoByteNodeID(0),
						Timestamp:           fixedTime(),
						RequestHandle:       1,
					},
				},
			},
		},
		{
			name: "subsequent-request",
			sechan: buildSecureChannel(
				&SecureChannel{
					cfg:       &Config{Logger: testLogger},
					requestID: 555,
					// reqhdr: &ua.RequestHeader{
					// 	RequestHandle: 444,
					// },
					time: fixedTime,
				},
				&channelInstance{
					sequenceNumber: 777,
				},
			),
			req: &ua.ReadRequest{},
			m: &Message{
				MessageHeader: &MessageHeader{
					Header: &Header{
						MessageType: MessageTypeMessage,
						ChunkType:   ChunkTypeFinal,
					},
					SymmetricSecurityHeader: &SymmetricSecurityHeader{},
					SequenceHeader: &SequenceHeader{
						SequenceNumber: 778,
						RequestID:      556,
					},
				},
				TypeID: ua.NewFourByteExpandedNodeID(0, id.ReadRequestEncodingDefaultBinary),
				Service: &ua.ReadRequest{
					RequestHeader: &ua.RequestHeader{
						AuthenticationToken: ua.NewTwoByteNodeID(0),
						Timestamp:           fixedTime(),
						RequestHandle:       556,
					},
				},
			},
		},
		{
			name: "counter-rollover",
			sechan: buildSecureChannel(
				&SecureChannel{
					cfg:       &Config{Logger: testLogger},
					requestID: math.MaxUint32,
					time:      fixedTime,
				},
				&channelInstance{
					sequenceNumber: math.MaxUint32 - 1023,
				}),
			req: &ua.ReadRequest{},
			m: &Message{
				MessageHeader: &MessageHeader{
					Header: &Header{
						MessageType: MessageTypeMessage,
						ChunkType:   ChunkTypeFinal,
					},
					SymmetricSecurityHeader: &SymmetricSecurityHeader{},
					SequenceHeader: &SequenceHeader{
						SequenceNumber: 1,
						RequestID:      1,
					},
				},
				TypeID: ua.NewFourByteExpandedNodeID(0, id.ReadRequestEncodingDefaultBinary),
				Service: &ua.ReadRequest{
					RequestHeader: &ua.RequestHeader{
						AuthenticationToken: ua.NewTwoByteNodeID(0),
						Timestamp:           fixedTime(),
						RequestHandle:       1,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := tt.sechan.activeInstance.newRequestMessage(tt.req, tt.sechan.nextRequestID(), tt.authToken, tt.timeout)
			require.NoError(t, err)
			require.Equal(t, tt.m, m)
		})
	}
}

func TestSignAndEncryptVerifyAndDecrypt(t *testing.T) {
	buildSecPolicy := func(bits int, uri string) *uapolicy.EncryptionAlgorithm {
		t.Helper()

		certPEM, keyPEM, err := uatest.GenerateCert("localhost", bits, 24*time.Hour)
		require.NoError(t, err)

		block, _ := pem.Decode(keyPEM)
		pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		require.NoError(t, err)

		certblock, _ := pem.Decode(certPEM)
		remoteX509Cert, err := x509.ParseCertificate(certblock.Bytes)
		require.NoError(t, err)

		remoteKey := remoteX509Cert.PublicKey.(*rsa.PublicKey)
		alg, _ := uapolicy.Asymmetric(uri, pk, remoteKey)
		return alg
	}

	getConfig := func(uri string) *Config {
		t.Helper()

		if uri == ua.SecurityPolicyURINone {
			return &Config{SecurityMode: ua.MessageSecurityModeNone, Logger: testLogger}
		}
		return &Config{SecurityMode: ua.MessageSecurityModeSignAndEncrypt, Logger: testLogger}
	}

	tests := []struct {
		name string
		c    *channelInstance
		m    *Message
		b    []byte
	}{}

	for _, uri := range ua.SecurityPolicyURIs {
		for i, keyLength := range []int{2048, 4096} {
			if i == 1 && (uri == ua.SecurityPolicyURIBasic128Rsa15 || uri == ua.SecurityPolicyURIBasic256) {
				continue
			}
			tests = append(tests, struct {
				name string
				c    *channelInstance
				m    *Message
				b    []byte
			}{fmt.Sprintf("encrypt/decrypt: bits: %d uri: %s", keyLength, uri),
				&channelInstance{
					sc:   &SecureChannel{cfg: getConfig(uri)},
					algo: buildSecPolicy(keyLength, uri),
				},
				&Message{
					MessageHeader: &MessageHeader{
						Header: &Header{
							MessageType: MessageTypeOpenSecureChannel,
							ChunkType:   ChunkTypeFinal,
						},
						AsymmetricSecurityHeader: &AsymmetricSecurityHeader{
							SecurityPolicyURI: "http://gopcua.example/OPCUA/SecurityPolicy#Foo",
						},
						SequenceHeader: &SequenceHeader{
							SequenceNumber: 1,
							RequestID:      1,
						},
					},
				},
				[]byte{ // OpenSecureChannelRequest
					// Message Header
					// MessageType: OPN
					0x4f, 0x50, 0x4e,
					// Chunk Type: Final
					0x46,
					// MessageSize: 131
					0x8E, 0x00, 0x00, 0x00,
					// SecureChannelID: 0
					0x00, 0x00, 0x00, 0x00,
					// AsymmetricSecurityHeader
					// SecurityPolicyURILength
					0x2e, 0x00, 0x00, 0x00,
					// SecurityPolicyURI
					0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x67,
					0x6f, 0x70, 0x63, 0x75, 0x61, 0x2e, 0x65, 0x78,
					0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x4f, 0x50,
					0x43, 0x55, 0x41, 0x2f, 0x53, 0x65, 0x63, 0x75,
					0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69,
					0x63, 0x79, 0x23, 0x46, 0x6f, 0x6f,
					// SenderCertificate
					0xff, 0xff, 0xff, 0xff,
					// ReceiverCertificateThumbprint
					0xff, 0xff, 0xff, 0xff,
					// Sequence Header
					// SequenceNumber
					0x01, 0x00, 0x00, 0x00,
					// RequestID
					0x01, 0x00, 0x00, 0x00,
					// TypeID
					0x01, 0x00, 0xbe, 0x01,

					// RequestHeader
					// - AuthenticationToken
					0x00, 0x00,
					// - Timestamp
					0x00, 0x98, 0x67, 0xdd, 0xfd, 0x30, 0xd4, 0x01,
					// - RequestHandle
					0x01, 0x00, 0x00, 0x00,
					// - ReturnDiagnostics
					0xff, 0x03, 0x00, 0x00,
					// - AuditEntry
					0xff, 0xff, 0xff, 0xff,
					// - TimeoutHint
					0x00, 0x00, 0x00, 0x00,
					// - AdditionalHeader
					//   - TypeID
					0x00, 0x00,
					//   - EncodingMask
					0x00,
					// ClientProtocolVersion
					0x00, 0x00, 0x00, 0x00,
					// SecurityTokenRequestType
					0x00, 0x00, 0x00, 0x00,
					// MessageSecurityMode
					0x01, 0x00, 0x00, 0x00,
					// ClientNonce
					0xff, 0xff, 0xff, 0xff,
					// RequestedLifetime
					0x80, 0x8d, 0x5b, 0x00,
				}})
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := tt.c.signAndEncrypt(tt.m, tt.b)
			require.NoError(t, err, "error: message encrypt")

			m := new(MessageChunk)
			_, err = m.Decode(cipher)
			require.NoError(t, err, "error: message decode")

			plain, err := tt.c.verifyAndDecrypt(m, cipher)
			require.NoError(t, err, "error: message decrypt")

			headerLength := 12 + m.AsymmetricSecurityHeader.Len()
			require.Equal(t, tt.b[headerLength:], plain, "header not equal")
		})
	}
}

func TestNewSecureChannel(t *testing.T) {
	t.Run("no connection", func(t *testing.T) {
		_, err := NewSecureChannel("", nil, nil, nil)
		require.ErrorContains(t, err, "not connected")
	})
	t.Run("no error channel", func(t *testing.T) {
		_, err := NewSecureChannel("", &uacp.Conn{}, nil, nil)
		require.ErrorContains(t, err, "invalid security configuration")
	})
	t.Run("no config", func(t *testing.T) {
		_, err := NewSecureChannel("", &uacp.Conn{}, nil, make(chan error))
		require.ErrorContains(t, err, "invalid security configuration")
	})
	t.Run("uri none, mode not none", func(t *testing.T) {
		cfg := &Config{SecurityPolicyURI: ua.SecurityPolicyURINone, SecurityMode: ua.MessageSecurityModeSign}
		_, err := NewSecureChannel("", &uacp.Conn{}, cfg, make(chan error))
		require.ErrorContains(t, err, "invalid security configuration")
		require.ErrorContains(t, err, "cannot be used with 'MessageSecurityModeSign'")
	})
	t.Run("uri not none, mode none", func(t *testing.T) {
		cfg := &Config{SecurityPolicyURI: ua.SecurityPolicyURIBasic256, SecurityMode: ua.MessageSecurityModeNone}
		_, err := NewSecureChannel("", &uacp.Conn{}, cfg, make(chan error))
		require.ErrorContains(t, err, "invalid security configuration")
		require.ErrorContains(t, err, "can only be used with")
	})
	t.Run("uri not none, security policy not none, mode invalid", func(t *testing.T) {
		cfg := &Config{SecurityPolicyURI: ua.SecurityPolicyURIBasic256, SecurityMode: ua.MessageSecurityModeInvalid}
		_, err := NewSecureChannel("", &uacp.Conn{}, cfg, make(chan error))
		require.ErrorContains(t, err, "invalid security configuration")
		require.ErrorContains(t, err, "can only be used with")
	})
	t.Run("uri not none, local key missing", func(t *testing.T) {
		cfg := &Config{SecurityPolicyURI: ua.SecurityPolicyURIBasic256, SecurityMode: ua.MessageSecurityModeSign}
		_, err := NewSecureChannel("", &uacp.Conn{}, cfg, make(chan error))
		require.ErrorContains(t, err, "invalid security configuration")
		require.ErrorContains(t, err, "requires a private key")
	})
}

func TestSecureChannel_Accessors(t *testing.T) {
	sc := &SecureChannel{
		cfg: &Config{
			SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			SecurityMode:      ua.MessageSecurityModeSign,
		},
		endpointURL: "opc.tcp://localhost:4840",
	}

	if got := sc.SecurityMode(); got != ua.MessageSecurityModeSign {
		t.Errorf("SecurityMode() = %v, want %v", got, ua.MessageSecurityModeSign)
	}
	if got := sc.SecurityPolicyURI(); got != ua.SecurityPolicyURIBasic256Sha256 {
		t.Errorf("SecurityPolicyURI() = %q, want %q", got, ua.SecurityPolicyURIBasic256Sha256)
	}
	if got := sc.LocalEndpoint(); got != "opc.tcp://localhost:4840" {
		t.Errorf("LocalEndpoint() = %q, want %q", got, "opc.tcp://localhost:4840")
	}
}

func TestConditionLocker(t *testing.T) {
	cl := newConditionLocker()

	// Initially unlocked: waitIfLock should return immediately.
	cl.waitIfLock()

	// Lock then unlock from a goroutine to verify broadcast wakes up waiter.
	cl.lock()
	done := make(chan struct{})
	go func() {
		cl.waitIfLock()
		close(done)
	}()
	cl.unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waitIfLock did not unblock after unlock")
	}
}

func TestSecureChannel_TimeNow(t *testing.T) {
	// With custom time func
	fixed := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	sc := &SecureChannel{
		cfg:  &Config{},
		time: func() time.Time { return fixed },
	}
	if got := sc.timeNow(); got != fixed {
		t.Errorf("timeNow() with custom func = %v, want %v", got, fixed)
	}

	// Without custom time func - exercises the default time.Now() branch
	sc2 := &SecureChannel{cfg: &Config{}}
	t0 := time.Now()
	got2 := sc2.timeNow()
	if got2.Before(t0) {
		t.Errorf("timeNow() without custom func returned past time")
	}
}

func TestMergeChunks(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if got := mergeChunks(nil); got != nil {
			t.Errorf("mergeChunks(nil) = %v, want nil", got)
		}
	})
	t.Run("single chunk", func(t *testing.T) {
		data := []byte{1, 2, 3}
		chunks := []*MessageChunk{{Data: data}}
		if got := mergeChunks(chunks); string(got) != string(data) {
			t.Errorf("mergeChunks single = %v, want %v", got, data)
		}
	})
	t.Run("multiple chunks", func(t *testing.T) {
		mkChunk := func(data []byte, seqnr uint32) *MessageChunk {
			return &MessageChunk{
				MessageHeader: &MessageHeader{
					SequenceHeader: &SequenceHeader{SequenceNumber: seqnr},
				},
				Data: data,
			}
		}
		chunks := []*MessageChunk{
			mkChunk([]byte{1, 2}, 1),
			mkChunk([]byte{3, 4}, 2),
		}
		want := []byte{1, 2, 3, 4}
		if got := mergeChunks(chunks); string(got) != string(want) {
			t.Errorf("mergeChunks multiple = %v, want %v", got, want)
		}
	})
	t.Run("duplicate chunk skipped", func(t *testing.T) {
		mkChunk := func(data []byte, seqnr uint32) *MessageChunk {
			return &MessageChunk{
				MessageHeader: &MessageHeader{
					SequenceHeader: &SequenceHeader{SequenceNumber: seqnr},
				},
				Data: data,
			}
		}
		chunks := []*MessageChunk{
			mkChunk([]byte{1, 2}, 1),
			mkChunk([]byte{1, 2}, 1), // duplicate
			mkChunk([]byte{3, 4}, 2),
		}
		want := []byte{1, 2, 3, 4}
		if got := mergeChunks(chunks); string(got) != string(want) {
			t.Errorf("mergeChunks deduplicated = %v, want %v", got, want)
		}
	})
}

func TestMessageBody_RequestResponse(t *testing.T) {
	// Test with a request type
	req := &ua.ReadRequest{}
	body := MessageBody{body: req}
	if got := body.Request(); got != req {
		t.Errorf("Request() = %v, want %v", got, req)
	}
	if got := body.Response(); got != nil {
		t.Errorf("Response() on request should be nil, got %v", got)
	}

	// Test with a response type
	resp := &ua.ReadResponse{}
	body2 := MessageBody{body: resp}
	if got := body2.Response(); got != resp {
		t.Errorf("Response() = %v, want %v", got, resp)
	}
	if got := body2.Request(); got != nil {
		t.Errorf("Request() on response should be nil, got %v", got)
	}
}

func TestIsReconnectTrigger(t *testing.T) {
	triggers := []error{
		ua.StatusBadSecureChannelIDInvalid,
		ua.StatusBadSessionIDInvalid,
		ua.StatusBadSubscriptionIDInvalid,
		ua.StatusBadNoSubscription,
		ua.StatusBadCertificateInvalid,
	}
	for _, err := range triggers {
		if !isReconnectTrigger(err) {
			t.Errorf("isReconnectTrigger(%v) = false, want true", err)
		}
	}

	if isReconnectTrigger(ua.StatusBadUserAccessDenied) {
		t.Error("isReconnectTrigger(StatusBadUserAccessDenied) = true, want false")
	}
	if isReconnectTrigger(nil) {
		t.Error("isReconnectTrigger(nil) = true, want false")
	}
}

func TestNotifyMonitor(t *testing.T) {
	sc := &SecureChannel{cfg: &Config{}}

	// Response is nil → should return true (not a reconnect trigger)
	bodyNoResp := &MessageBody{body: &ua.ReadRequest{}}
	if !sc.notifyMonitor(bodyNoResp) {
		t.Error("notifyMonitor with non-response body should return true")
	}

	// Response present, no error → isReconnectTrigger returns false
	bodyWithResp := &MessageBody{body: &ua.ReadResponse{}}
	if sc.notifyMonitor(bodyWithResp) {
		t.Error("notifyMonitor with response and nil error should return false")
	}

	// Response present, reconnect trigger error → true
	bodyWithErr := &MessageBody{body: &ua.ReadResponse{}, Err: ua.StatusBadSessionIDInvalid}
	if !sc.notifyMonitor(bodyWithErr) {
		t.Error("notifyMonitor with reconnect trigger error should return true")
	}
}

func TestGetActiveChannelInstance_NilReturnsError(t *testing.T) {
	sc := &SecureChannel{cfg: &Config{}}
	// No active instance set
	_, err := sc.getActiveChannelInstance()
	if err == nil {
		t.Error("getActiveChannelInstance with nil activeInstance should return error")
	}
}

func TestNewSecureChannel_ErrorBranches(t *testing.T) {
	errCh := make(chan error, 1)

	// nil conn
	_, err := newSecureChannel("opc.tcp://localhost", nil, &Config{}, client, errCh)
	if err == nil {
		t.Error("nil conn should fail")
	}

	// nil config - need a non-nil conn
	// We can use a *uacp.Conn pointer cast hack: pass a non-nil but invalid conn
	// Actually, we can test the switch cases by providing a fake conn that won't be dereferenced at construction time.
	// newSecureChannel only uses c to store it, so passing a typed nil is not possible.
	// Use a dummy conn pointer via unsafe, but instead just test config == nil:
	// We must pass a non-nil conn to reach the cfg check. Unfortunately uacp.Conn has no constructor
	// for testing, so we skip the nil-conn branch being already tested.

	// nil errCh
	fakeConn := &uacp.Conn{}
	_, err = newSecureChannel("opc.tcp://localhost", fakeConn, &Config{}, client, nil)
	if err == nil {
		t.Error("nil errCh should fail")
	}

	// policy None with non-None mode
	_, err = newSecureChannel("opc.tcp://localhost", fakeConn,
		&Config{
			SecurityPolicyURI: ua.SecurityPolicyURINone,
			SecurityMode:      ua.MessageSecurityModeSign,
		}, client, errCh)
	if err == nil {
		t.Error("None policy with Sign mode should fail")
	}

	// non-None policy with None mode
	_, err = newSecureChannel("opc.tcp://localhost", fakeConn,
		&Config{
			SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			SecurityMode:      ua.MessageSecurityModeNone,
		}, client, errCh)
	if err == nil {
		t.Error("non-None policy with None mode should fail")
	}

	// non-None policy with no local key
	_, err = newSecureChannel("opc.tcp://localhost", fakeConn,
		&Config{
			SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
			LocalKey:          nil,
		}, client, errCh)
	if err == nil {
		t.Error("non-None policy without local key should fail")
	}
}
