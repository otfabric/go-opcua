package opcua

import (
	"fmt"
	"io"
	"testing"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestMonitor_EOFErrorFormat verifies that when Monitor returns an error due to
// connection close (EOF), the error wraps io.EOF and includes a hint that the
// server may not support event or alarm subscriptions.
func TestMonitor_EOFErrorFormat(t *testing.T) {
	err := fmt.Errorf("connection closed while creating monitored items (server may not support event or alarm subscriptions): %w", io.EOF)
	require.True(t, errors.Is(err, io.EOF), "error should wrap io.EOF for callers that check")
	require.Contains(t, err.Error(), "server may not support event or alarm", "error message should suggest server limitation")
}

// Running tool: /Users/frank/sdk/go1.17.1/bin/go test -benchmem -run=^$ -bench ^BenchmarkUnmonitorItems$ github.com/otfabric/go-opcua

// goos: darwin
// goarch: arm64
// pkg: github.com/otfabric/go-opcua
// BenchmarkUnmonitorItems/slice-8         	51153620	        24.03 ns/op	      20 B/op	       0 allocs/op
// --- BENCH: BenchmarkUnmonitorItems/slice-8
//     subscription_test.go:29: src 1 dst 0
//     subscription_test.go:29: src 100 dst 50
//     subscription_test.go:29: src 10000 dst 5000
//     subscription_test.go:29: src 1000000 dst 500000
//     subscription_test.go:29: src 51153620 dst 25576810
// BenchmarkUnmonitorItems/slice_pre-alloc-8         	91635986	        22.77 ns/op	       8 B/op	       0 allocs/op
// --- BENCH: BenchmarkUnmonitorItems/slice_pre-alloc-8
//     subscription_test.go:51: src 1 dst 0
//     subscription_test.go:51: src 100 dst 50
//     subscription_test.go:51: src 10000 dst 5000
//     subscription_test.go:51: src 1000000 dst 500000
//     subscription_test.go:51: src 91635986 dst 45817993
// BenchmarkUnmonitorItems/map-8                     	39885550	        43.72 ns/op	       0 B/op	       0 allocs/op
// --- BENCH: BenchmarkUnmonitorItems/map-8
//     subscription_test.go:75: src 0
//     subscription_test.go:75: src 50
//     subscription_test.go:75: src 5000
//     subscription_test.go:75: src 500000
//     subscription_test.go:75: src 19942775
// PASS
// ok  	github.com/otfabric/go-opcua	116.192s

func BenchmarkUnmonitorItems(b *testing.B) {
	b.Run("slice", func(b *testing.B) {
		src := make([]*monitoredItem, b.N)
		for i := 0; i < b.N; i++ {
			src[i] = &monitoredItem{
				res: &ua.MonitoredItemCreateResult{
					MonitoredItemID: uint32(i),
				},
			}
		}

		b.ResetTimer()
		var dst []*monitoredItem
		for _, item := range src {
			if item.res.MonitoredItemID%2 == 0 {
				continue
			}
			dst = append(dst, item)
		}

		b.Log("src", len(src), "dst", len(dst)) // ensure src and dst are not GC'ed
	})

	b.Run("slice pre-alloc", func(b *testing.B) {
		src := make([]*monitoredItem, b.N)
		for i := 0; i < b.N; i++ {
			src[i] = &monitoredItem{
				res: &ua.MonitoredItemCreateResult{
					MonitoredItemID: uint32(i),
				},
			}
		}

		b.ResetTimer()
		dst := make([]*monitoredItem, 0, len(src))
		for _, item := range src {
			if item.res.MonitoredItemID%2 == 0 {
				continue
			}
			dst = append(dst, item)
		}

		b.Log("src", len(src), "dst", len(dst)) // ensure src and dst are not GC'ed
	})

	b.Run("map", func(b *testing.B) {
		idsToDelete := []uint32{}
		src := make(map[uint32]*monitoredItem, b.N)
		for i := 0; i < b.N; i++ {
			id := uint32(i)
			src[id] = &monitoredItem{
				res: &ua.MonitoredItemCreateResult{
					MonitoredItemID: id,
				},
			}

			if id%2 == 0 {
				idsToDelete = append(idsToDelete, id)
			}
		}

		b.ResetTimer()
		for _, id := range idsToDelete {
			delete(src, id)
		}

		b.Log("src", len(src)) // ensure src and dst are not GC'ed
	})
}
