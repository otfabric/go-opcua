// SPDX-License-Identifier: MIT

//go:build ignore

// Seed writes interop/capabilities.json and interop/coverage.json from the
// current inventory. Run from repo root:
//
//	go run ./internal/cmd/render-interop-coverage/seed.go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const pin = "v0.5.0"

var dirs = []string{
	"go-client-to-open62541-server",
	"go-client-to-milo-server",
	"open62541-client-to-go-server",
	"milo-client-to-go-server",
}

type capability struct {
	ID                   string   `json:"id"`
	Title                string   `json:"title"`
	Profile              string   `json:"profile"`
	ApplicableDirections []string `json:"applicableDirections"`
}

type peerInfo struct {
	Stack   string `json:"stack,omitempty"`
	Version string `json:"version,omitempty"`
}

type coverageEntry struct {
	Capability     string    `json:"capability"`
	Direction      string    `json:"direction"`
	Status         string    `json:"status"`
	Test           string    `json:"test,omitempty"`
	Case           string    `json:"case,omitempty"`
	Fixture        string    `json:"fixture,omitempty"`
	InteropVersion string    `json:"interopVersion,omitempty"`
	Peer           *peerInfo `json:"peer,omitempty"`
	Issue          string    `json:"issue,omitempty"`
	Reason         string    `json:"reason,omitempty"`
}

type rowSpec struct {
	cto, ctm, ots, mts string // status per direction
	ctoTest, ctmTest   string
	otsTest, mtsTest   string
	fixture            string
}

func main() {
	root := mustRoot()
	caps, entries := build()
	mustWrite(filepath.Join(root, "interop", "capabilities.json"), map[string]any{"capabilities": caps})
	mustWrite(filepath.Join(root, "interop", "coverage.json"), map[string]any{
		"interopVersion": pin,
		"entries":        entries,
	})
	fmt.Printf("seeded %d capabilities, %d entries\n", len(caps), len(entries))
}

func build() ([]capability, []coverageEntry) {
	type def struct {
		id, title, profile string
		applicable         []string // empty = all four
		spec               rowSpec
	}

	all := dirs
	clientOnly := []string{dirs[0], dirs[1]}
	serverOnly := []string{dirs[2], dirs[3]}

	v4 := func(ctoTest, ctmTest, otsTest, mtsTest string) rowSpec {
		return rowSpec{
			cto: "verified", ctm: "verified", ots: "verified", mts: "verified",
			ctoTest: ctoTest, ctmTest: ctmTest, otsTest: otsTest, mtsTest: mtsTest,
			fixture: "baseline",
		}
	}
	unverifiedAll := rowSpec{cto: "unverified", ctm: "unverified", ots: "unverified", mts: "unverified"}
	deferredAll := rowSpec{cto: "deferred", ctm: "deferred", ots: "deferred", mts: "deferred"}

	defs := []def{
		// Core session / discovery
		{"session.connect", "Connect / disconnect", "session", all, v4(
			"TestOpen62541Server_Connect", "TestMiloServer_Connect",
			"TestGoServer_Open62541Client_Endpoints", "TestGoServer_MiloClient_Endpoints")},
		{"session.namespace", "Namespace discovery", "session", all, v4(
			"TestOpen62541Server_Browse", "TestMiloServer_Browse",
			"TestGoServer_Open62541Client_Browse", "TestGoServer_MiloClient_Browse")},
		{"discovery.endpoints", "GetEndpoints", "discovery", all, v4(
			"TestOpen62541Server_Connect", "TestMiloServer_Connect",
			"TestGoServer_Open62541Client_Endpoints", "TestGoServer_MiloClient_Endpoints")},
		{"discovery.find-servers", "FindServers", "discovery", all, rowSpec{
			cto: "unverified", ctm: "unverified", ots: "unsupported", mts: "unverified", fixture: "baseline"}},
		{"discovery.find-servers-on-network", "FindServersOnNetwork", "discovery", all, deferredAll},
		{"discovery.lds-registration", "LDS registration", "discovery", all, deferredAll},

		// Browse
		{"browse.objects", "Browse Objects folder", "browse", all, v4(
			"TestOpen62541Server_Browse", "TestMiloServer_Browse",
			"TestGoServer_Open62541Client_Browse", "TestGoServer_MiloClient_Browse")},
		{"browse.namespace", "Browse interop namespace", "browse", all, v4(
			"TestOpen62541Server_BrowseInteropNamespace", "TestMiloServer_BrowseInteropNamespace",
			"TestGoServer_Open62541Client_BrowseObjectsNodes", "TestGoServer_MiloClient_BrowseObjectsNodes")},
		{"browse.scalars-folder", "Browse Scalars folder", "browse", all, v4(
			"TestOpen62541Server_BrowseScalarsFolder", "TestMiloServer_BrowseScalarsFolder",
			"TestGoServer_Open62541Client_BrowseScalarsFolder", "TestGoServer_MiloClient_BrowseScalarsFolder")},
		{"browse.next", "BrowseNext pagination", "browse", all, v4(
			"TestOpen62541Server_BrowseNext", "TestMiloServer_BrowseNext",
			"TestGoServer_Open62541Client_BrowseNext", "TestGoServer_MiloClient_BrowseNext")},
		{"browse.next-release", "BrowseNext early release", "browse", all, v4(
			"TestOpen62541Server_BrowseNextRelease", "TestMiloServer_BrowseNextRelease",
			"TestGoServer_Open62541Client_BrowseNextRelease", "TestGoServer_MiloClient_BrowseNextRelease")},
		{"browse.result-mask", "Browse ResultMask", "browse", all, v4(
			"TestOpen62541Server_BrowseResultMask", "TestMiloServer_BrowseResultMask",
			"TestGoServer_Open62541Client_BrowseResultMask", "TestGoServer_MiloClient_BrowseResultMask")},
		{"browse.filtering", "Browse NodeClassMask / IncludeSubtypes", "browse", all, v4(
			"TestOpen62541Server_BrowseFiltering", "TestMiloServer_BrowseFiltering",
			"TestGoServer_Open62541Client_BrowseFiltering", "TestGoServer_MiloClient_BrowseFiltering")},

		// Read / write
		{"read.scalar", "Read scalar values", "attribute", all, v4(
			"TestOpen62541Server_ReadScalarInt32", "TestMiloServer_ReadScalarInt32",
			"TestGoServer_Open62541Client_ReadScalarInt32", "TestGoServer_MiloClient_ReadScalarInt32")},
		{"read.array", "Read array values", "attribute", all, v4(
			"TestOpen62541Server_ReadArrayInt32", "TestMiloServer_ReadArrayInt32",
			"TestGoServer_Open62541Client_ReadArrayInt32", "TestGoServer_MiloClient_ReadArrayInt32")},
		{"read.batch", "Batch Read", "attribute", all, v4(
			"TestOpen62541Server_BatchRead", "TestMiloServer_BatchRead",
			"TestGoServer_Open62541Client_BatchRead", "TestGoServer_MiloClient_BatchRead")},
		{"read.dynamic", "Dynamic counter read", "attribute", all, v4(
			"TestOpen62541Server_ReadDynamicCounter", "TestMiloServer_ReadDynamicCounter",
			"TestGoServer_Open62541Client_ReadDynamicCounter", "TestGoServer_MiloClient_ReadDynamicCounter")},
		{"read.timestamps", "Read TimestampsToReturn", "attribute", all, v4(
			"TestOpen62541Server_TimestampsToReturn", "TestMiloServer_TimestampsToReturn",
			"TestGoServer_Open62541Client_TimestampsToReturn", "TestGoServer_MiloClient_TimestampsToReturn")},
		{"read.index-range", "IndexRange Read/Write", "attribute", all, v4(
			"TestOpen62541Server_IndexRangeSubset", "TestMiloServer_IndexRangeSubset",
			"TestGoServer_Open62541Client_IndexRangeSubset", "TestGoServer_MiloClient_IndexRangeSubset")},
		{"read.invalid-node", "Invalid NodeId service results", "attribute", all, v4(
			"TestOpen62541Server_InvalidNodeId", "TestMiloServer_InvalidNodeId",
			"TestGoServer_Open62541Client_InvalidNodeId", "TestGoServer_MiloClient_InvalidNodeId")},
		{"write.value", "Write and read-back", "attribute", all, v4(
			"TestOpen62541Server_WriteAndReadBack", "TestMiloServer_WriteAndReadBack",
			"TestGoServer_Open62541Client_Write", "TestGoServer_MiloClient_Write")},
		{"write.batch", "Batch Write per-item StatusCodes", "attribute", all, v4(
			"TestOpen62541Server_BatchWrite", "TestMiloServer_BatchWrite",
			"TestGoServer_Open62541Client_BatchWrite", "TestGoServer_MiloClient_BatchWrite")},
		{"write.type-mismatch", "Write type mismatch", "attribute", all, v4(
			"TestOpen62541Server_WriteTypeMismatch", "TestMiloServer_WriteTypeMismatch",
			"TestGoServer_Open62541Client_WriteTypeMismatch", "TestGoServer_MiloClient_WriteTypeMismatch")},
		{"write.encoding-mask", "Write EncodingMask / BadWriteNotSupported", "attribute", all, rowSpec{
			cto: "verified", ctm: "unverified", ots: "verified", mts: "verified",
			ctoTest: "TestOpen62541Server_WriteEncodingMask",
			otsTest: "TestGoServer_Open62541Client_WriteEncodingMask", mtsTest: "TestGoServer_MiloClient_WriteEncodingMask",
			fixture: "baseline",
		}},
		{"datavalue.timestamps", "DataValue source + server timestamp", "attribute", all, v4(
			"TestOpen62541Server_DataValue_GoodWithTimestamps", "TestMiloServer_DataValue_GoodWithTimestamps",
			"TestGoServer_Open62541Client_DataValue_GoodWithTimestamps", "TestGoServer_MiloClient_DataValue_GoodWithTimestamps")},
		{"datavalue.uncertain", "DataValue Uncertain status", "attribute", all, v4(
			"TestOpen62541Server_DataValue_Uncertain", "TestMiloServer_DataValue_Uncertain",
			"TestGoServer_Open62541Client_DataValue_Uncertain", "TestGoServer_MiloClient_DataValue_Uncertain")},
		{"access.read-only", "Access.ReadOnly write rejection", "attribute", all, v4(
			"TestOpen62541Server_Access_ReadOnly_WriteRejected", "TestMiloServer_Access_ReadOnly_WriteRejected",
			"TestGoServer_Open62541Client_Access_ReadOnly_WriteRejected", "TestGoServer_MiloClient_Access_ReadOnly_WriteRejected")},
		{"access.write-only", "Access.WriteOnly read rejection", "attribute", all, v4(
			"TestOpen62541Server_Access_WriteOnly_ReadRejected", "TestMiloServer_Access_WriteOnly_ReadRejected",
			"TestGoServer_Open62541Client_Access_WriteOnly_ReadRejected", "TestGoServer_MiloClient_Access_WriteOnly_ReadRejected")},

		// Methods
		{"method.call", "Method call", "method", all, v4(
			"TestOpen62541Server_CallMethodAdd", "TestMiloServer_CallMethodAdd",
			"TestGoServer_Open62541Client_CallMethod", "TestGoServer_MiloClient_CallMethod")},
		{"method.validation", "Method argument validation", "method", all, rowSpec{
			cto: "unverified", ctm: "unverified", ots: "verified", mts: "verified",
			otsTest: "TestGoServer_Open62541Client_MethodValidation", mtsTest: "TestGoServer_MiloClient_MethodValidation",
			fixture: "baseline",
		}},

		// Subscriptions / monitored items
		{"subscription.data-change", "Subscription data-change", "subscriptions", all, v4(
			"TestOpen62541Server_Subscribe", "TestMiloServer_Subscribe",
			"TestGoServer_Open62541Client_Subscribe", "TestGoServer_MiloClient_Subscribe")},
		{"subscription.queue-window", "Exact QueueSize / DiscardOldest windows", "subscriptions", all, v4(
			"TestOpen62541Server_Subscribe_DiscardOldest", "TestMiloServer_Subscribe_DiscardOldest",
			"TestGoServer_Open62541Client_Subscribe_DiscardOldest", "TestGoServer_MiloClient_Subscribe_DiscardOldest")},
		{"subscription.timestamps", "Subscription TimestampsToReturn", "subscriptions", all, rowSpec{
			cto: "unverified", ctm: "unverified", ots: "unverified", mts: "unverified",
			// Go↔Go only in subscription_timestamps_test; peer partially via adapter reverse where CLI exposes flags
		}},
		{"subscription.lifecycle.revise", "Subscription lifecycle revise", "subscriptions", serverOnly, rowSpec{
			ots: "verified", mts: "verified",
			otsTest: "TestGoServer_Open62541Client_SubscriptionLifecycle_Revise",
			mtsTest: "TestGoServer_MiloClient_SubscriptionLifecycle_Revise",
			fixture: "baseline",
		}},
		{"subscription.lifecycle.delete", "Subscription lifecycle delete", "subscriptions", serverOnly, rowSpec{
			ots: "verified", mts: "verified",
			otsTest: "TestGoServer_Open62541Client_SubscriptionLifecycle_Delete",
			mtsTest: "TestGoServer_MiloClient_SubscriptionLifecycle_Delete",
			fixture: "baseline",
		}},
		{"subscription.client.republish", "Client Republish helper", "subscriptions", clientOnly, rowSpec{
			cto: "verified", ctm: "unverified",
			ctoTest: "TestOpen62541Server_ClientRepublish",
			fixture: "baseline",
		}},
		{"subscription.server.republish", "Server Republish handler", "subscriptions", serverOnly, rowSpec{
			ots: "verified", mts: "unverified",
			otsTest: "TestGoServer_Open62541Client_Republish",
			fixture: "baseline",
		}},
		{"subscription.client.transfer", "Client TransferSubscriptions helper", "subscriptions", clientOnly, rowSpec{
			cto: "unverified", ctm: "unverified",
		}},
		{"subscription.server.transfer", "Server TransferSubscriptions handler", "subscriptions", serverOnly, rowSpec{
			ots: "unverified", mts: "verified",
			mtsTest: "TestGoServer_MiloClient_TransferSubscriptions",
			fixture: "baseline",
		}},
		{"subscription.recovery.reconnect", "Automatic subscription recovery", "subscriptions", clientOnly, rowSpec{
			cto: "unverified", ctm: "unverified",
		}},

		// Events (peer subscription verified on opcua-interop v0.5.0)
		{"event.subscription", "Event subscription create", "events", all, rowSpec{
			cto: "unverified", ctm: "unverified",
			ots: "verified", mts: "verified",
			otsTest: "TestGoServer_Open62541Client_EventSubscribe", mtsTest: "TestGoServer_MiloClient_EventSubscribe",
			fixture: "baseline",
		}},
		{"event.filter.select-clauses", "EventFilter SelectClauses", "events", all, unverifiedAll},
		{"event.filter.of-type", "EventFilter OfType", "events", all, unverifiedAll},
		{"event.filter.where-clause", "EventFilter WhereClause", "events", all, unverifiedAll},
		{"event.notification.decode", "Event notification decode", "events", clientOnly, rowSpec{
			cto: "unverified", ctm: "unverified",
		}},
		{"event.emission.base", "BaseEvent emission", "events", serverOnly, rowSpec{
			ots: "unverified", mts: "unverified",
			otsTest: "TestGoServer_Open62541Client_EventSubscribe", mtsTest: "TestGoServer_MiloClient_EventSubscribe",
		}},
		{"event.emission.custom", "Custom event emission", "events", serverOnly, rowSpec{
			ots: "unverified", mts: "unverified",
		}},
		{"event.queue-overflow", "Event queue overflow", "events", all, rowSpec{
			cto: "deferred", ctm: "deferred", ots: "deferred", mts: "deferred",
		}},

		// History (raw O→S / M→S verified on opcua-interop v0.5.0)
		{"history.read.raw", "HistoryRead raw", "history", all, rowSpec{
			cto: "unverified", ctm: "unverified",
			ots: "verified", mts: "verified",
			otsTest: "TestGoServer_Open62541Client_HistoryReadRaw", mtsTest: "TestGoServer_MiloClient_HistoryReadRaw",
			fixture: "baseline",
		}},
		{"history.read.continuation", "HistoryRead continuation points", "history", all, unverifiedAll},
		{"history.read.modified", "HistoryRead modified", "history", all, unverifiedAll},
		{"history.read.at-time", "HistoryRead at-time", "history", all, unverifiedAll},
		{"history.read.processed", "HistoryRead processed", "history", all, unverifiedAll},
		{"history.read.events", "HistoryRead events", "history", all, deferredAll},
		{"history.update.data", "HistoryUpdate data", "history", all, unverifiedAll},
		{"history.update.events", "HistoryUpdate events", "history", all, deferredAll},
		{"history.delete", "History delete", "history", all, unverifiedAll},

		// Security
		{"security.basic256sha256.sign", "Basic256Sha256 / Sign", "security", all, v4(
			"TestOpen62541Server_Basic256Sha256_Sign_ScalarRead", "TestMiloServer_Basic256Sha256_Sign_ScalarRead",
			"TestGoServer_Open62541Client_Basic256Sha256_Sign_ScalarRead", "TestGoServer_MiloClient_Basic256Sha256_Sign_ScalarRead")},
		{"security.basic256sha256.sign-encrypt", "Basic256Sha256 / SignAndEncrypt", "security", all, v4(
			"TestOpen62541Server_Basic256Sha256_SignAndEncrypt_ScalarRead", "TestMiloServer_Basic256Sha256_SignAndEncrypt_ScalarRead",
			"TestGoServer_Open62541Client_Basic256Sha256_SignAndEncrypt_ScalarRead", "TestGoServer_MiloClient_Basic256Sha256_SignAndEncrypt_ScalarRead")},
		{"security.aes128.sign-encrypt", "Aes128_Sha256_RsaOaep / SignAndEncrypt", "security", all, v4(
			"TestOpen62541Server_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead", "TestMiloServer_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead",
			"TestGoServer_Open62541Client_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead", "TestGoServer_MiloClient_Aes128Sha256RsaOaep_SignAndEncrypt_ScalarRead")},
		{"security.aes256.sign-encrypt", "Aes256_Sha256_RsaPss / SignAndEncrypt", "security", all, v4(
			"TestOpen62541Server_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead", "TestMiloServer_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead",
			"TestGoServer_Open62541Client_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead", "TestGoServer_MiloClient_Aes256Sha256RsaPss_SignAndEncrypt_ScalarRead")},
		{"security.cert.untrusted", "Untrusted cert rejection", "security", all, v4(
			"TestOpen62541Server_UntrustedCert_Rejected", "TestMiloServer_UntrustedCert_Rejected",
			"TestGoServer_Open62541Client_UntrustedCert_Rejected", "TestGoServer_MiloClient_UntrustedCert_Rejected")},
		{"security.cert.trusted", "Trusted cert accepted", "security", all, rowSpec{
			cto: "unverified", ctm: "unverified", ots: "verified", mts: "verified",
			otsTest: "TestGoServer_Open62541Client_TrustedCert_Accepted", mtsTest: "TestGoServer_MiloClient_TrustedCert_Accepted",
			fixture: "baseline",
		}},
		{"security.username.valid", "Username valid credentials", "security", all, v4(
			"TestOpen62541Server_Username_ValidCredentials", "TestMiloServer_Username_ValidCredentials",
			"TestGoServer_Open62541Client_Username_ValidCredentials", "TestGoServer_MiloClient_Username_ValidCredentials")},
		{"security.username.invalid", "Username invalid credentials", "security", all, v4(
			"TestOpen62541Server_Username_InvalidPassword_Rejected", "TestMiloServer_Username_InvalidPassword_Rejected",
			"TestGoServer_Open62541Client_Username_InvalidPassword_Rejected", "TestGoServer_MiloClient_Username_InvalidPassword_Rejected")},
		{"security.issued-token", "Issued identity token", "security", all, rowSpec{
			cto: "unverified", ctm: "unverified", ots: "unverified", mts: "unverified",
		}},
		{"security.cert.chains", "Intermediate certificate chains", "security", all, deferredAll},
		{"security.cert.crl", "Certificate revocation (CRL)", "security", all, deferredAll},
		{"security.channel.renewal", "SecureChannel renewal under subscription", "security", all, deferredAll},

		// Query / node management / custom types / A&C
		{"query.first", "QueryFirst", "query", all, rowSpec{
			cto: "unsupported", ctm: "unverified", ots: "unsupported", mts: "unverified",
		}},
		{"query.next", "QueryNext", "query", all, rowSpec{
			cto: "unsupported", ctm: "unverified", ots: "unsupported", mts: "unverified",
		}},
		{"nodemgmt.add-nodes", "AddNodes", "node-management", all, unverifiedAll},
		{"nodemgmt.delete-nodes", "DeleteNodes", "node-management", all, unverifiedAll},
		{"translate.browse-path", "TranslateBrowsePathsToNodeIDs", "view", all, unverifiedAll},
		{"custom.types.registered", "Registered custom DataTypes", "custom-types", all, unverifiedAll},
		{"custom.types.dynamic", "Dynamic structure decoding", "custom-types", clientOnly, rowSpec{
			cto: "deferred", ctm: "deferred",
		}},
		{"alarms.acknowledgeable", "AcknowledgeableConditionType", "alarms-conditions", all, deferredAll},
		{"nodeset2.import", "NodeSet2 import peer model", "information-model", all, unverifiedAll},
	}

	var caps []capability
	var entries []coverageEntry
	for _, d := range defs {
		app := d.applicable
		if len(app) == 0 {
			app = all
		}
		caps = append(caps, capability{ID: d.id, Title: d.title, Profile: d.profile, ApplicableDirections: app})
		entries = append(entries, expand(d.id, app, d.spec)...)
	}
	return caps, entries
}

func expand(id string, applicable []string, s rowSpec) []coverageEntry {
	statuses := map[string]string{
		dirs[0]: s.cto, dirs[1]: s.ctm, dirs[2]: s.ots, dirs[3]: s.mts,
	}
	tests := map[string]string{
		dirs[0]: s.ctoTest, dirs[1]: s.ctmTest, dirs[2]: s.otsTest, dirs[3]: s.mtsTest,
	}
	appSet := map[string]bool{}
	for _, d := range applicable {
		appSet[d] = true
	}
	var out []coverageEntry
	for _, d := range dirs {
		e := coverageEntry{Capability: id, Direction: d}
		if !appSet[d] {
			e.Status = "not-applicable"
			out = append(out, e)
			continue
		}
		st := statuses[d]
		if st == "" {
			st = "unverified"
		}
		e.Status = st
		if t := tests[d]; t != "" {
			e.Test = t
			if st == "verified" || st == "blocked" || st == "unverified" {
				e.Fixture = s.fixture
				if e.Fixture == "" {
					e.Fixture = "baseline"
				}
				e.InteropVersion = pin
				e.Peer = peerFor(d)
			}
		}
		out = append(out, e)
	}
	return out
}

func peerFor(direction string) *peerInfo {
	switch direction {
	case dirs[0], dirs[2]:
		return &peerInfo{Stack: "open62541", Version: "1.4.x"}
	case dirs[1], dirs[3]:
		return &peerInfo{Stack: "eclipse-milo", Version: "0.6.x"}
	default:
		return nil
	}
}

func mustRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		p := filepath.Dir(dir)
		if p == dir {
			panic("go.mod not found")
		}
		dir = p
	}
}

func mustWrite(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		panic(err)
	}
}
