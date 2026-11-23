// SPDX-License-Identifier: MIT

package uafx

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/release-b-golden.json")

// goldenFile holds the binary encoding of the EstablishConnections
// arguments of fullRequest and fullResult as the hand-written codec of
// v1.37.0 produced them, at two namespace indexes of the Data namespace.
// The generated codec must produce the same bytes and decode them to the
// same values.
const goldenFile = "testdata/release-b-golden.json"

func goldenArgs(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, data := range []uint16{testData, 300} {
		req, err := EncodeEstablishConnectionsRequest(fullRequest(), data)
		require.NoError(t, err)
		res, err := EncodeEstablishConnectionsResult(fullResult(), data)
		require.NoError(t, err)
		for name, args := range map[string][]*ua.Variant{"request": req, "result": res} {
			for i, v := range args {
				b, err := ua.Encode(v)
				require.NoError(t, err)
				out[name+"/ns="+itoa(int(data))+"/arg="+itoa(i)] = hex.EncodeToString(b)
			}
		}
	}
	return out
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestGoldenReleaseB(t *testing.T) {
	got := goldenArgs(t)
	if *updateGolden {
		b, err := json.MarshalIndent(got, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenFile), 0o755))
		require.NoError(t, os.WriteFile(goldenFile, append(b, '\n'), 0o644))
	}
	b, err := os.ReadFile(goldenFile)
	require.NoError(t, err)
	var want map[string]string
	require.NoError(t, json.Unmarshal(b, &want))
	assert.Equal(t, want, got)

	// The bytes decode to the values they were made of.
	for _, data := range []uint16{testData, 300} {
		args := func(name string, n int) []*ua.Variant {
			out := make([]*ua.Variant, n)
			for i := range out {
				raw, err := hex.DecodeString(want[name+"/ns="+itoa(int(data))+"/arg="+itoa(i)])
				require.NoError(t, err)
				v := new(ua.Variant)
				_, err = v.Decode(raw)
				require.NoError(t, err)
				out[i] = v
			}
			return out
		}
		req, err := DecodeEstablishConnectionsRequest(args("request", 5), data)
		require.NoError(t, err)
		assert.Equal(t, fullRequest().AssetVerifications, req.AssetVerifications)
		assert.Equal(t, fullRequest().ConnectionEndpointConfigurations, req.ConnectionEndpointConfigurations)
		res, err := DecodeEstablishConnectionsResult(args("result", 4), data)
		require.NoError(t, err)
		// Encoding what was decoded gives the same bytes again (null
		// ExtensionObjects of package ua decode as empty ones, so the
		// values are compared by their encoding).
		again, err := EncodeEstablishConnectionsRequest(req, data)
		require.NoError(t, err)
		for i, v := range again {
			b, err := ua.Encode(v)
			require.NoError(t, err)
			assert.Equal(t, want["request/ns="+itoa(int(data))+"/arg="+itoa(i)], hex.EncodeToString(b))
		}
		again, err = EncodeEstablishConnectionsResult(res, data)
		require.NoError(t, err)
		for i, v := range again {
			b, err := ua.Encode(v)
			require.NoError(t, err)
			assert.Equal(t, want["result/ns="+itoa(int(data))+"/arg="+itoa(i)], hex.EncodeToString(b))
		}
	}
}
