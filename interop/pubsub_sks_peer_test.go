//go:build interop

// SPDX-License-Identifier: MIT

// PubSub Security Key Service (Part 14 §8) evidence against open62541.
// COVERAGE.md: pubsub / pubsub.sks.get-security-keys, pubsub.sks.pull,
// pubsub.sks.push, pubsub.sks.security-groups
//
// Directions (C→ = go-opcua is the client / key consumer, →S = open62541 is):
//
//   - go-opcua client (pubsub/sks.GetSecurityKeys, NewKeySource) against an
//     open62541 SKS (server --pubsub-config with "serveSks"), and the keys
//     used to verify and decrypt what that open62541 publisher sends.
//   - open62541 as SKS client ("sksClient") pulling from a go-opcua server
//     with EnableSecurityKeyService, and publishing SignAndEncrypt UADP with
//     those keys, which go-opcua decrypts with its KeyService.
//   - SetSecurityKeys pushed by go-opcua (pubsub/sks.Push) to an open62541
//     subscriber, and by the open62541 adapter client to a go-opcua server
//     with EnableSecurityKeyPush.
//   - AddSecurityGroup / RemoveSecurityGroup in both directions.
//
// The SKS methods run over Basic256Sha256 SignAndEncrypt sessions with the
// opcua-interop test PKI.

package interop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/sks"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

const (
	psSKSGroup       = "InteropGroup"
	psSKSKeyLifetime = 60 * time.Second
	psSKSUser        = "test-user"
	psSKSPassword    = "test-password"
)

// psSKSConfig is an open62541 SKS without PubSub components (or with the
// publisher of c, when given).
func psSKSConfig(policyURI string, publisher jobj) jobj {
	cfg := publisher
	if cfg == nil {
		cfg = jobj{"configuration": jobj{"PublishedDataSets": []jobj{}, "Connections": []jobj{}, "Enabled": true}}
	}
	cfg["securityGroups"] = []jobj{{
		"securityGroupId": psSKSGroup, "securityPolicyUri": policyURI,
		"keyLifetimeMs": psSKSKeyLifetime.Milliseconds(), "maxFutureKeyCount": 2, "maxPastKeyCount": 1,
	}}
	cfg["serveSks"] = true
	return cfg
}

func callMethod(t *testing.T, c *opcua.Client, object, method *ua.NodeID, args ...any) *ua.CallMethodResult {
	t.Helper()
	in := make([]*ua.Variant, len(args))
	for i, a := range args {
		in[i] = ua.MustVariant(a)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: object, MethodID: method, InputArguments: in})
	if err != nil {
		t.Fatalf("Call %v: %v", method, err)
	}
	return res
}

// TestPubSubSKS_GoClient_Open62541SKS: pubsub/sks.GetSecurityKeys against
// an open62541 SKS: policy, key length, key count, token ids and lifetime,
// and the refusal of sessions that are not encrypted.
func TestPubSubSKS_GoClient_Open62541SKS(t *testing.T) {
	srv := startPubSubServer(t, pubsubServerOpts{config: psSKSConfig(security.PolicyURIAes256CTR, nil), secure: true})
	c := dialSecureUserClient(t, srv.endpoint, "Basic256Sha256", "SignAndEncrypt", psSKSUser, psSKSPassword)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("get-security-keys", func(t *testing.T) {
		one, err := sks.GetSecurityKeys(ctx, c, psSKSGroup, 0, 1)
		if err != nil {
			t.Fatalf("GetSecurityKeys: %v", err)
		}
		if one.SecurityPolicyURI != security.PolicyURIAes256CTR {
			t.Errorf("SecurityPolicyUri %q", one.SecurityPolicyURI)
		}
		// open62541 1.5.9 returns a bogus negative TimeToNextKey
		// (contract §14.6); KeyLifetime is right.
		if one.KeyLifetime != psSKSKeyLifetime {
			t.Errorf("KeyLifetime %v, want %v", one.KeyLifetime, psSKSKeyLifetime)
		}
		t.Logf("FirstTokenId %d, TimeToNextKey %v (open62541 1.5.9 bug: not usable), KeyLifetime %v", one.FirstTokenID, one.TimeToNextKey, one.KeyLifetime)
		if len(one.Keys) != 2 {
			t.Fatalf("RequestedKeyCount 1: %d keys, want the current and one future key", len(one.Keys))
		}
		for i, k := range one.Keys {
			if len(k) != security.Aes256CTR().KeyLength() {
				t.Errorf("key %d: %d bytes, want %d (PubSub-Aes256-CTR)", i, len(k), security.Aes256CTR().KeyLength())
			}
		}
		if bytes.Equal(one.Keys[0], one.Keys[1]) {
			t.Error("the current and the future key are equal")
		}

		all, err := sks.GetSecurityKeys(ctx, c, psSKSGroup, 0, 0xFFFFFFFF)
		if err != nil {
			t.Fatalf("GetSecurityKeys(all): %v", err)
		}
		if len(all.Keys) != 3 || all.FirstTokenID != one.FirstTokenID {
			t.Fatalf("RequestedKeyCount max: %d keys from token %d, want 3 (current + MaxFutureKeyCount 2) from %d", len(all.Keys), all.FirstTokenID, one.FirstTokenID)
		}
		if !bytes.Equal(all.Keys[0], one.Keys[0]) || !bytes.Equal(all.Keys[1], one.Keys[1]) {
			t.Error("the keys differ between two calls")
		}

		next := security.NextTokenID(one.FirstTokenID)
		from, err := sks.GetSecurityKeys(ctx, c, psSKSGroup, next, 1)
		if err != nil {
			t.Fatalf("GetSecurityKeys(StartingTokenId %d): %v", next, err)
		}
		if from.FirstTokenID != next || len(from.Keys) != 2 || !bytes.Equal(from.Keys[0], all.Keys[1]) || !bytes.Equal(from.Keys[1], all.Keys[2]) {
			t.Errorf("StartingTokenId %d: first token %d, %d keys", next, from.FirstTokenID, len(from.Keys))
		}

		if _, err := sks.GetSecurityKeys(ctx, c, "NoSuchGroup", 0, 1); !errors.Is(err, ua.StatusBadNotFound) {
			t.Errorf("unknown SecurityGroup: %v, want BadNotFound", err)
		}
	})

	t.Run("refused-without-encryption", func(t *testing.T) {
		for _, mode := range []string{"None", "Sign"} {
			var cl *opcua.Client
			if mode == "None" {
				cl = dialClient(t, srv.endpoint)
			} else {
				cl = dialSecureUserClient(t, srv.endpoint, "Basic256Sha256", mode, psSKSUser, psSKSPassword)
			}
			if _, err := sks.GetSecurityKeys(ctx, cl, psSKSGroup, 0, 1); !errors.Is(err, ua.StatusBadSecurityModeInsufficient) {
				t.Errorf("GetSecurityKeys over %s: %v, want BadSecurityModeInsufficient", mode, err)
			}
		}
	})

	// AddSecurityGroup / RemoveSecurityGroup on PublishSubscribe.SecurityGroups
	// (bound by the adapter, contract §14.6).
	t.Run("security-groups", func(t *testing.T) {
		groups := ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroups)
		res := callMethod(t, c, groups, ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroupsAddSecurityGroup),
			"GoAddedGroup", float64(30000), security.PolicyURIAes128CTR, uint32(2), uint32(1))
		if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 2 {
			t.Fatalf("AddSecurityGroup: %v %v", res.StatusCode, res.OutputArguments)
		}
		if gid, _ := res.OutputArguments[0].Value().(string); gid != "GoAddedGroup" {
			t.Errorf("SecurityGroupId %v", res.OutputArguments[0].Value())
		}
		nodeID, ok := res.OutputArguments[1].Value().(*ua.NodeID)
		if !ok {
			t.Fatalf("SecurityGroupNodeId %T", res.OutputArguments[1].Value())
		}
		keys, err := sks.GetSecurityKeys(ctx, c, "GoAddedGroup", 0, 5)
		if err != nil {
			t.Fatalf("GetSecurityKeys of the added group: %v", err)
		}
		if keys.SecurityPolicyURI != security.PolicyURIAes128CTR || keys.KeyLifetime != 30*time.Second || len(keys.Keys) != 3 {
			t.Errorf("added group: policy %s lifetime %v %d keys", keys.SecurityPolicyURI, keys.KeyLifetime, len(keys.Keys))
		}
		for _, k := range keys.Keys {
			if len(k) != security.Aes128CTR().KeyLength() {
				t.Errorf("key of %d bytes, want %d (PubSub-Aes128-CTR)", len(k), security.Aes128CTR().KeyLength())
			}
		}
		res = callMethod(t, c, groups, ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroupsRemoveSecurityGroup), nodeID)
		if res.StatusCode != ua.StatusOK {
			t.Fatalf("RemoveSecurityGroup %v: %v", nodeID, res.StatusCode)
		}
		if _, err := sks.GetSecurityKeys(ctx, c, "GoAddedGroup", 0, 1); !errors.Is(err, ua.StatusBadNotFound) {
			t.Errorf("GetSecurityKeys of the removed group: %v, want BadNotFound", err)
		}
	})
}

// TestPubSubSKS_GoPulls_Open62541SKS: the open62541 publisher is the SKS of
// its SecurityGroup and publishes SignAndEncrypt UADP to the host; go-opcua
// pulls the keys with a pubsub/sks KeySource and decrypts the messages.
func TestPubSubSKS_GoPulls_Open62541SKS(t *testing.T) {
	c := psLiveCase{name: "sks", mode: ua.MessageSecurityModeSignAndEncrypt, policy: security.Aes256CTR(), vars: psVars}
	port, ch := psListenUDP(t)
	pub := startPubSubServer(t, pubsubServerOpts{config: psSKSConfig(c.policy.URI(), psUDPPublisherConfig(c, port)), secure: true})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ks, err := sks.NewKeySource(ctx, sks.Config{
		SecurityGroupID: psSKSGroup,
		Dial: func(context.Context) (*opcua.Client, error) {
			return dialSecureUserClient(t, pub.endpoint, "Basic256Sha256", "SignAndEncrypt", psSKSUser, psSKSPassword), nil
		},
	})
	if err != nil {
		t.Fatalf("NewKeySource: %v", err)
	}
	t.Cleanup(func() { _ = ks.Close() })

	values := psValues(c.vars, psFresh())
	writePubSubVars(t, pub.endpoint, c.vars, values)
	nm := psReceive(t, ch, psDecodeUADP(c, ks), values, psReceiveTimeout)
	cur, err := ks.CurrentKeys()
	if err != nil {
		t.Fatal(err)
	}
	c.tokenID = cur.TokenID
	assertPublisherHeaders(t, c, nm)
}

// startGoSKS starts a go-opcua server with Basic256Sha256 Sign and
// SignAndEncrypt endpoints, the go-server certificate of the test PKI, the
// adapter's client certificates trusted (CA), UserName login, the
// KeyService ks (if not nil) and SetSecurityKeys into rings (if not nil).
func startGoSKS(t *testing.T, ks *security.KeyService, rings *security.KeyRings) string {
	t.Helper()
	s, err := server.New(
		server.ListenOn("0.0.0.0:0"),
		server.EndPoint("host.docker.internal", 0),
		server.Certificate(loadGoServerCert(t)),
		server.PrivateKey(loadGoServerKey(t)),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == psSKSUser && pass == psSKSPassword {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithClientCertificateTrustList(loadCACertDER(t)),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if ks != nil {
		if _, err := s.EnableSecurityKeyService(ks); err != nil {
			t.Fatalf("EnableSecurityKeyService: %v", err)
		}
	}
	if rings != nil {
		if err := s.EnableSecurityKeyPush(rings); err != nil {
			t.Fatalf("EnableSecurityKeyPush: %v", err)
		}
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return fmt.Sprintf("opc.tcp://localhost:%d%s", s.Port(), endpointPath)
}

// TestPubSubSKS_Open62541Pulls_GoSKS: an open62541 publisher pulls the keys
// of its SecurityGroup from a go-opcua SKS (GetSecurityKeys over
// Basic256Sha256 SignAndEncrypt as test-user) and publishes SignAndEncrypt
// UADP with them; go-opcua decrypts with the keys of its KeyService.
func TestPubSubSKS_Open62541Pulls_GoSKS(t *testing.T) {
	requirePubSubServer(t)
	for _, policy := range []security.Policy{security.Aes128CTR(), security.Aes256CTR()} {
		t.Run(strings.TrimPrefix(policy.URI(), "http://opcfoundation.org/UA/SecurityPolicy#"), func(t *testing.T) {
			t.Parallel()
			ks := security.NewKeyService()
			if err := ks.AddSecurityGroup(security.SecurityGroupConfig{SecurityGroupID: psSKSGroup, SecurityPolicyURI: policy.URI(),
				KeyLifetime: psSKSKeyLifetime, MaxFutureKeyCount: 2, MaxPastKeyCount: 1}); err != nil {
				t.Fatalf("AddSecurityGroup: %v", err)
			}
			endpoint := startGoSKS(t, ks, nil)
			keys, err := ks.KeySource(psSKSGroup)
			if err != nil {
				t.Fatal(err)
			}
			tok, err := ks.CurrentTokenID(psSKSGroup)
			if err != nil {
				t.Fatal(err)
			}

			c := psLiveCase{name: "sks", mode: ua.MessageSecurityModeSignAndEncrypt, policy: policy, vars: psVars, tokenID: tok}
			port, ch := psListenUDP(t)
			cfg := psUDPPublisherConfig(c, port)
			cfg["securityGroups"] = []jobj{psSecurityGroupJSON(psSKSGroup, policy.URI(), 0, nil)}
			cfg["sksClient"] = jobj{
				"endpointUrl":       strings.ReplaceAll(endpoint, "localhost", "host.docker.internal"),
				"securityPolicyUri": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
				"securityMode":      "SignAndEncrypt", "username": psSKSUser, "password": psSKSPassword,
			}
			pub := startPubSubServer(t, pubsubServerOpts{config: cfg, secure: true})
			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)
			nm := psReceive(t, ch, psDecodeUADP(c, keys), values, psReceiveTimeout)
			assertPublisherHeaders(t, c, nm)
		})
	}
}

// TestPubSubSKS_GoPushes_Open62541Subscriber: an open62541 subscriber starts
// without keys; go-opcua pushes the keys of its KeyService with
// SetSecurityKeys (pubsub/sks.Push) and sends SignAndEncrypt UADP secured
// with them, which the subscriber decrypts into its TargetVariables.
func TestPubSubSKS_GoPushes_Open62541Subscriber(t *testing.T) {
	requirePubSubServer(t)
	c := psLiveCase{name: "push", mode: ua.MessageSecurityModeSignAndEncrypt, policy: security.Aes256CTR(), vars: psVars}
	port := freeUDPPort(t)
	cfg := psSubscriberConfig(c, psProfileUDP, fmt.Sprintf("opc.udp://0.0.0.0:%d", port), nil, false)
	cfg["securityGroups"] = []jobj{psSecurityGroupJSON(psSKSGroup, c.policy.URI(), 0, nil)}
	sub := startPubSubServer(t, pubsubServerOpts{config: cfg, udpPorts: []int{port}, secure: true})

	ks := security.NewKeyService()
	if err := ks.AddSecurityGroup(security.SecurityGroupConfig{SecurityGroupID: psSKSGroup, SecurityPolicyURI: c.policy.URI(),
		KeyLifetime: psSKSKeyLifetime, MaxFutureKeyCount: 2, MaxPastKeyCount: 1}); err != nil {
		t.Fatalf("AddSecurityGroup: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// SetSecurityKeys needs an encrypted session.
	signOnly := dialSecureUserClient(t, sub.endpoint, "Basic256Sha256", "Sign", psSKSUser, psSKSPassword)
	if err := sks.Push(ctx, ks, signOnly, psSKSGroup); !errors.Is(err, ua.StatusBadSecurityModeInsufficient) {
		t.Errorf("SetSecurityKeys over Sign: %v, want BadSecurityModeInsufficient", err)
	}

	cl := dialSecureUserClient(t, sub.endpoint, "Basic256Sha256", "SignAndEncrypt", psSKSUser, psSKSPassword)
	if err := sks.Push(ctx, ks, cl, psSKSGroup); err != nil {
		t.Fatalf("SetSecurityKeys: %v", err)
	}
	keys, err := ks.KeySource(psSKSGroup)
	if err != nil {
		t.Fatal(err)
	}
	values := psValues(c.vars, psFresh())
	conn := psDial(t, transport.Config{ProfileURI: psProfileUDP, URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port)})
	md := psLookup(psMetaData(c.vars, 0))
	var nonce uint32
	psSendLoop(t, conn, transport.PublishOptions{}, func(seq uint16) ([]byte, error) {
		nonce++
		return uadpEncodeSecured(psGoMessage(c, seq, values), keys, nonce, md)
	})
	waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
}

// psAdapterCall runs "client call" of the open62541 adapter on a go-opcua
// server over Basic256Sha256 SignAndEncrypt as test-user and returns the
// first result.
func psAdapterCall(t *testing.T, endpoint, object, method string, inputs ...string) (callResult struct {
	StatusCode      statusCodeObj     `json:"statusCode"`
	OutputArguments []json.RawMessage `json:"outputArguments"`
}) {
	t.Helper()
	args := []string{"--username", psSKSUser, "--password", psSKSPassword, "--object", object, "--method", method}
	for _, in := range inputs {
		args = append(args, "--input", in)
	}
	r := runSecureAdapterClientResult(t, "OPEN62541_IMAGE", defaultOpen62541Image, "open62541-client", endpoint, "call",
		"Basic256Sha256", "SignAndEncrypt", args...)
	var items []struct {
		StatusCode      statusCodeObj     `json:"statusCode"`
		OutputArguments []json.RawMessage `json:"outputArguments"`
	}
	if err := json.Unmarshal(r.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("call %s: %v; result %+v", method, err, r)
	}
	return items[0]
}

// TestPubSubSKS_Open62541Pushes_GoServer: the open62541 adapter client calls
// SetSecurityKeys on a go-opcua server (EnableSecurityKeyPush); the keys land
// in the KeyRing of the group.
func TestPubSubSKS_Open62541Pushes_GoServer(t *testing.T) {
	requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "call")
	requirePubSubServer(t)
	p := security.Aes128CTR()
	ring := security.NewKeyRing("PushGroup", p)
	rings := &security.KeyRings{}
	rings.Add(ring)
	endpoint := startGoSKS(t, nil, rings)

	cur, f1, f2 := psStaticKey128, bytes.Repeat([]byte{0x11}, 52), bytes.Repeat([]byte{0x22}, 52)
	b64 := base64.StdEncoding.EncodeToString
	res := psAdapterCall(t, endpoint, "i=14443", "i=17364",
		"String:PushGroup", "String:"+p.URI(), "UInt32:41", "ByteString:"+b64(cur),
		"ByteString[]:"+b64(f1)+","+b64(f2), "Double:0", "Double:60000")
	if res.StatusCode.Code != 0 {
		t.Fatalf("SetSecurityKeys: %s", res.StatusCode)
	}
	if ring.CurrentTokenID() != 41 || ring.FutureKeyCount() != 2 || ring.KeyLifetime() != time.Minute {
		t.Errorf("KeyRing: current token %d, %d future keys, lifetime %v; want 41, 2, 1m0s", ring.CurrentTokenID(), ring.FutureKeyCount(), ring.KeyLifetime())
	}
	for i, want := range [][]byte{cur, f1, f2} {
		got, err := ring.KeysForToken(uint32(41 + i))
		if err != nil {
			t.Fatalf("token %d: %v", 41+i, err)
		}
		split, _ := p.SplitKey(uint32(41+i), want)
		if !bytes.Equal(got.SigningKey, split.SigningKey) || !bytes.Equal(got.EncryptingKey, split.EncryptingKey) || !bytes.Equal(got.KeyNonce, split.KeyNonce) {
			t.Errorf("token %d: keys differ from those pushed", 41+i)
		}
	}

	// An unknown group and a wrong policy are refused.
	if r := psAdapterCall(t, endpoint, "i=14443", "i=17364", "String:NoSuchGroup", "String:"+p.URI(), "UInt32:1",
		"ByteString:"+b64(cur), "ByteString[]:", "Double:0", "Double:60000"); r.StatusCode.Code != uint32(ua.StatusBadNotFound) {
		t.Errorf("SetSecurityKeys of an unknown group: %s, want BadNotFound", r.StatusCode)
	}
	if r := psAdapterCall(t, endpoint, "i=14443", "i=17364", "String:PushGroup", "String:"+security.PolicyURIAes256CTR, "UInt32:1",
		"ByteString:"+b64(psStaticKey256), "ByteString[]:", "Double:0", "Double:60000"); r.StatusCode.Code != uint32(ua.StatusBadSecurityPolicyRejected) {
		t.Errorf("SetSecurityKeys with another policy: %s, want BadSecurityPolicyRejected", r.StatusCode)
	}
}

// TestPubSubSKS_Open62541Client_GoSecurityGroups: the open62541 adapter
// client adds and removes a SecurityGroup on a go-opcua SKS.
func TestPubSubSKS_Open62541Client_GoSecurityGroups(t *testing.T) {
	requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "call")
	requirePubSubServer(t)
	ks := security.NewKeyService()
	endpoint := startGoSKS(t, ks, nil)

	res := psAdapterCall(t, endpoint, "i=15443", "i=15444",
		"String:AdapterGroup", "Double:45000", "String:"+security.PolicyURIAes256CTR, "UInt32:3", "UInt32:1")
	if res.StatusCode.Code != 0 || len(res.OutputArguments) != 2 {
		t.Fatalf("AddSecurityGroup: %s %s", res.StatusCode, res.OutputArguments)
	}
	var gid, node string
	if err := json.Unmarshal(res.OutputArguments[0], &gid); err != nil || gid != "AdapterGroup" {
		t.Errorf("SecurityGroupId %s", res.OutputArguments[0])
	}
	if err := json.Unmarshal(res.OutputArguments[1], &node); err != nil || node == "" {
		t.Fatalf("SecurityGroupNodeId %s", res.OutputArguments[1])
	}
	cfg, ok := ks.SecurityGroup("AdapterGroup")
	if !ok {
		t.Fatal("the KeyService has no group AdapterGroup")
	}
	if cfg.SecurityPolicyURI != security.PolicyURIAes256CTR || cfg.KeyLifetime != 45*time.Second || cfg.MaxFutureKeyCount != 3 || cfg.MaxPastKeyCount != 1 {
		t.Errorf("group configuration %+v", cfg)
	}
	// GetSecurityKeys of the new group, by the adapter too.
	keys := psAdapterCall(t, endpoint, "i=14443", "i=15215", "String:AdapterGroup", "UInt32:0", "UInt32:3")
	if keys.StatusCode.Code != 0 || len(keys.OutputArguments) != 5 {
		t.Fatalf("GetSecurityKeys: %s %s", keys.StatusCode, keys.OutputArguments)
	}
	var policy string
	var list []string
	_ = json.Unmarshal(keys.OutputArguments[0], &policy)
	_ = json.Unmarshal(keys.OutputArguments[2], &list)
	want, err := ks.GetSecurityKeys("AdapterGroup", 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if policy != security.PolicyURIAes256CTR || len(list) != len(want.Keys) {
		t.Fatalf("GetSecurityKeys via open62541: policy %s, %d keys; want %d", policy, len(list), len(want.Keys))
	}
	for i, k := range list {
		if k != base64.StdEncoding.EncodeToString(want.Keys[i]) {
			t.Errorf("key %d differs", i)
		}
	}

	res = psAdapterCall(t, endpoint, "i=15443", "i=15447", "NodeId:"+node)
	if res.StatusCode.Code != 0 {
		t.Fatalf("RemoveSecurityGroup %s: %s", node, res.StatusCode)
	}
	if _, ok := ks.SecurityGroup("AdapterGroup"); ok {
		t.Error("the group is still in the KeyService")
	}
}
