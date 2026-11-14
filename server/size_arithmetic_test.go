// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/binary"
	"log/slog"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

// widthBoundaries are UInt32 values around the largest value of a 32-bit
// int and at the top of the UInt32 range.
var widthBoundaries = []uint32{0x7ffffffc, 0x7ffffffd, 0x7ffffffe, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe, 0xffffffff}

// TestIntOfUint32: a UInt32 limit of a request keeps its value where int
// holds it and is math.MaxInt where it does not (int of 32 bits).
func TestIntOfUint32(t *testing.T) {
	for _, n := range append([]uint32{0, 1, 0xffff}, widthBoundaries...) {
		got := intOfUint32(n)
		require.GreaterOrEqual(t, got, 0, "%#x", n)
		if uint64(n) <= uint64(math.MaxInt) {
			require.Equal(t, int(n), got, "%#x", n)
		} else {
			require.Equal(t, math.MaxInt, got, "%#x", n)
		}
	}
}

// TestDrainQueuedNotificationsLimitBoundaries: a MaxNotificationsPerPublish
// at or above the number of queued notifications takes all of them, also
// for the values that have no 32-bit int value.
func TestDrainQueuedNotificationsLimitBoundaries(t *testing.T) {
	for _, max := range append([]uint32{3, 4, 0xffff}, widthBoundaries...) {
		svc := &MonitoredItemService{Subs: map[uint32][]*MonitoredItem{}}
		item := &MonitoredItem{
			Mode:      ua.MonitoringModeReporting,
			queueSize: 10,
			queue:     []*ua.MonitoredItemNotification{notif(1), notif(2), notif(3)},
		}
		svc.Subs[1] = []*MonitoredItem{item}
		out, more := svc.DrainQueuedNotifications(1, max)
		require.Equal(t, []int32{1, 2, 3}, valuesOf(out), "MaxNotificationsPerPublish %#x", max)
		require.False(t, more, "MaxNotificationsPerPublish %#x", max)
		require.Empty(t, item.queue)
	}
}

// TestDecryptUserPasswordLengthBoundaries: the length at the start of a
// legacy encrypted password is compared with the bytes that follow it as an
// unsigned number; a length they cannot hold, or shorter than the server
// nonce, is Bad_IdentityTokenInvalid.
func TestDecryptUserPasswordLengthBoundaries(t *testing.T) {
	rsaKey, rsaCert := testUserCert(t)
	srv := newTestServer()
	srv.cfg.certificate = rsaCert
	srv.cfg.privateKey = rsaKey
	svc := &SessionService{srv: srv}
	sc := uasc.NewCryptoChannel(&uasc.Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
	})
	pub, err := uapolicy.CertificatePublicKey(rsaCert)
	require.NoError(t, err)
	enc, err := uapolicy.AsymmetricKeys(ua.SecurityPolicyURIBasic256Sha256, nil, pub)
	require.NoError(t, err)

	nonce := []byte("0123456789abcdef0123456789abcdef")
	body := append([]byte("pw"), nonce...) // the password and the nonce
	token := func(length uint32) *ua.UserNameIdentityToken {
		plain := binary.LittleEndian.AppendUint32(nil, length)
		ct, err := enc.Encrypt(append(plain, body...))
		require.NoError(t, err)
		return &ua.UserNameIdentityToken{Password: ct, EncryptionAlgorithm: enc.EncryptionURI()}
	}

	got, st := svc.decryptUserPassword(sc, &session{}, token(uint32(len(body))), nonce)
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, "pw", string(got))

	// The length of the nonce alone: an empty password.
	got, st = svc.decryptUserPassword(sc, &session{}, token(uint32(len(nonce))), body[:len(nonce)])
	require.Equal(t, ua.StatusOK, st)
	require.Empty(t, got)

	for _, length := range append([]uint32{uint32(len(body)) + 1, uint32(len(nonce)) - 1, 0}, widthBoundaries...) {
		_, st := svc.decryptUserPassword(sc, &session{}, token(length), nonce)
		require.Equal(t, ua.StatusBadIdentityTokenInvalid, st, "length %#x", length)
	}
}

// TestQueryFirstMaxDataSetsToReturnBoundaries is the boundary table of
// MaxDataSetsToReturn: 0 and a limit at or above the number of results
// return all of them, a smaller limit that many and a continuation point,
// also for the values that have no 32-bit int value.
func TestQueryFirstMaxDataSetsToReturnBoundaries(t *testing.T) {
	srv := newTestServer()
	srv.cfg.query = true
	svc := &QueryService{srv: srv, cps: newCPStore[[]*ua.QueryDataSet]()}
	query := func(max uint32) *ua.QueryFirstResponse {
		t.Helper()
		resp, err := svc.QueryFirst(context.Background(), nil, &ua.QueryFirstRequest{
			RequestHeader:       reqHeader(),
			MaxDataSetsToReturn: max,
			NodeTypes: []*ua.NodeTypeDescription{{
				TypeDefinitionNode: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, id.PropertyType), "", 0),
			}},
		}, 1)
		require.NoError(t, err, "MaxDataSetsToReturn %#x", max)
		return resp.(*ua.QueryFirstResponse)
	}
	all := len(query(0).QueryDataSets)
	require.Greater(t, all, 2)
	n := uint32(all)
	for _, max := range append([]uint32{0, 1, n - 1, n, n + 1, 0xffff}, widthBoundaries...) {
		r := query(max)
		if max == 0 || max >= n {
			require.Len(t, r.QueryDataSets, all, "MaxDataSetsToReturn %#x", max)
			require.Empty(t, r.ContinuationPoint, "MaxDataSetsToReturn %#x", max)
			continue
		}
		require.Len(t, r.QueryDataSets, int(max), "MaxDataSetsToReturn %#x", max)
		require.NotEmpty(t, r.ContinuationPoint, "MaxDataSetsToReturn %#x", max)
		svc.cps = newCPStore[[]*ua.QueryDataSet]()
	}
}

// TestImportNodeSetXMLIntegerAttributeWidths is the boundary table of the
// integer attributes a NodeSet2 file can hold beyond Int32 (ValueRank of a
// variable, a variable type and a DataType field, and the Value of a field):
// a file reads the same where int has 32 bits. Every value of an Int64 is
// read; a variable's ValueRank outside -3..MaxInt32 falls back to Scalar.
func TestImportNodeSetXMLIntegerAttributeWidths(t *testing.T) {
	nodeSet := func(v string) []byte {
		return []byte(`<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:widths</Uri></NamespaceUris>
  <UADataType NodeId="ns=1;i=7101" BrowseName="1:Wide">
    <DisplayName>Wide</DisplayName>
    <Definition Name="1:Wide"><Field Name="A" DataType="i=6" ValueRank="` + v + `" Value="` + v + `"/></Definition>
  </UADataType>
  <UAVariableType NodeId="ns=1;i=7102" BrowseName="1:WideType" DataType="i=6" ValueRank="` + v + `">
    <DisplayName>WideType</DisplayName>
  </UAVariableType>
  <UAVariable NodeId="ns=1;i=7103" BrowseName="1:WideVar" DataType="i=6" ValueRank="` + v + `">
    <DisplayName>WideVar</DisplayName>
  </UAVariable>
</UANodeSet>`)
	}
	for _, tc := range []struct {
		v    string
		rank int32 // ValueRank of the variable
	}{
		{"0", 0},
		{"1", 1},
		{"-1", -1},
		{"-3", -3},
		{"-4", -1},
		{"2147483646", math.MaxInt32 - 1},
		{"2147483647", math.MaxInt32},
		{"2147483648", -1},
		{"-2147483648", -1},
		{"-2147483649", -1},
		{"4294967295", -1},
		{"4294967297", -1},
		{"9223372036854775807", -1},
		{"-9223372036854775808", -1},
	} {
		srv := newTestServer()
		srv.cfg.logger = slog.New(slog.DiscardHandler)
		require.NoError(t, srv.ImportNodeSetXML(nodeSet(tc.v)), "value %s", tc.v)
		n := srv.Node(ua.NewNumericNodeID(1, 7103))
		require.NotNil(t, n, "value %s", tc.v)
		dv, err := n.Attribute(ua.AttributeIDValueRank)
		require.NoError(t, err, "value %s", tc.v)
		require.Equal(t, tc.rank, dv.Value.Value.Value(), "value %s", tc.v)
	}
	for _, v := range []string{"9223372036854775808", "-9223372036854775809"} {
		err := newTestServer().ImportNodeSetXML(nodeSet(v))
		require.ErrorContains(t, err, "value out of range", "value %s", v)
	}
}
