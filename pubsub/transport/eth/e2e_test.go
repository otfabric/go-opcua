// SPDX-License-Identifier: MIT

//go:build linux || darwin || freebsd

package eth_test

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/transport/eth"
	"github.com/otfabric/go-opcua/ua"
)

// e2eInterfaces returns the interfaces of the end-to-end test: the pair
// (publisher on the first, subscriber on the second) or the single test
// interface for both. It skips without raw Ethernet access.
func e2eInterfaces(t *testing.T) (pub, sub string) {
	t.Helper()
	if a, b, ok := strings.Cut(os.Getenv(eth.RealPairEnv), ","); ok && a != "" && b != "" {
		pub, sub = a, b
	} else if name := os.Getenv(eth.RealIfaceEnv); name != "" {
		pub, sub = name, name
	} else if runtime.GOOS == "linux" {
		pub, sub = "lo", "lo"
	} else {
		eth.SkipReal(t, "set "+eth.RealIfaceEnv+" or "+eth.RealPairEnv+" to run the Ethernet end-to-end test")
	}
	// The runtime retries a connection that fails to open: probe first.
	c, err := eth.Open(context.Background(), transport.Config{URL: "opc.eth://ff-ff-ff-ff-ff-ff", Interface: sub})
	if err == nil {
		_, err = c.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
		_ = c.Close()
	}
	if errors.Is(err, os.ErrPermission) {
		eth.SkipReal(t, "no raw Ethernet access:", err)
	}
	require.NoError(t, err)
	return pub, sub
}

// TestE2EEthernetSecure runs a publisher and a subscriber over Ethernet with
// UADP and SignAndEncrypt: DataSets arrive decrypted and verified.
func TestE2EEthernetSecure(t *testing.T) {
	pubIf, subIf := e2eInterfaces(t)
	// Broadcast with a VLAN tag: needs no multicast membership (root on
	// macOS) and works on every interface.
	const url = "opc.eth://ff-ff-ff-ff-ff-ff:10.4"
	node := ua.NewStringNodeID(1, "eth-e2e")

	ks := security.NewKeyService()
	require.NoError(t, ks.AddSecurityGroup(security.SecurityGroupConfig{
		SecurityGroupID: "sg", SecurityPolicyURI: security.PolicyURIAes256CTR, KeyLifetime: time.Hour, MaxFutureKeyCount: 1,
	}))
	src, err := ks.KeySource("sg")
	require.NoError(t, err)

	values := pubsub.NewMemoryDataSource()
	require.NoError(t, values.Set(node, int32(4242)))
	pds := pubsub.PublishedDataItems("pds", pubsub.Var("v", node, ua.TypeIDInt32))
	// A random PublisherId: other runs on the same network are ignored.
	pubID := uint64(time.Now().UnixNano())
	pubCfg := pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		pubsub.AttachWriterGroups(pubsub.EthernetConnection("pub", url, pubIf, pubID),
			pubsub.Secure(pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.DataSetWriter("w", 1, "pds")),
				ua.MessageSecurityModeSignAndEncrypt, "sg")))
	subCfg := pubsub.NewConfiguration(nil,
		pubsub.AttachReaderGroups(pubsub.EthernetConnection("sub", url, subIf, nil),
			pubsub.Secure(pubsub.ReaderGroup("rg", pubsub.DataSetReader("r", pubID, 1, 1, pubsub.DataSetMetaDataOf(pds))),
				ua.MessageSecurityModeSignAndEncrypt, "sg")))
	require.NoError(t, pubsub.Validate(pubCfg))
	require.NoError(t, pubsub.Validate(subCfg))

	var got atomic.Int32
	sub, err := pubsub.New(subCfg, pubsub.WithKeySource("sg", src), pubsub.WithDataSetHandler(func(ds *pubsub.ReceivedDataSet) {
		if f := ds.Field("v"); f != nil && f.Value != nil {
			if v, ok := f.Value.Value().(int32); ok {
				got.Store(v)
			}
		}
	}))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	pub, err := pubsub.New(pubCfg, pubsub.WithKeySource("sg", src), pubsub.WithDataSource(values))
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() { _ = pub.Close() })

	require.Eventually(t, func() bool { return got.Load() == 4242 }, 10*time.Second, 5*time.Millisecond)
}
