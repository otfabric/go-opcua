// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// TestParallelManyGroups runs 50 writer groups on 5 UDP connections and 20
// on an MQTT connection, each with its own data set, into as many reader
// groups, while goroutines disable and enable random groups, writers and
// readers. Every reader must deliver intact data sets in order and all of
// them deliver again once everything is enabled.
func TestParallelManyGroups(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	b := mqttbroker.New(mqttbroker.Options{})
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)

	chk := newChecker()
	var pdss []*ua.PublishedDataSetDataType
	var pubConns, subConns []*ua.PubSubConnectionDataType
	var readers []string
	group := func(conn, g int, mqtt bool) (*ua.WriterGroupDataType, *ua.ReaderGroupDataType) {
		ds := fmt.Sprintf("ds%d-%d", conn, g)
		pdss = append(pdss, counterPDS(ds))
		readers = append(readers, ds)
		interval := time.Duration(10+g%3*5) * time.Millisecond
		w := pubsub.DataSetWriter("w"+ds, 1, ds)
		r := pubsub.DataSetReader(ds, uint16(10+conn), uint16(g+1), 1, pubsub.DataSetMetaDataOf(counterPDS(ds)))
		if mqtt {
			q := "many/" + ds
			pubsub.SetWriterQueue(w, q, "")
			pubsub.SetReaderQueue(r, q, "")
		}
		return pubsub.WriterGroup("wg"+ds, uint16(g+1), interval, w), pubsub.ReaderGroup("rg"+ds, r)
	}
	for conn := range 5 {
		port := freeUDPPort(t)
		pc := pubsub.UDPConnection(fmt.Sprintf("pub%d", conn), udpURL(port), uint16(10+conn))
		sc := pubsub.UDPConnection(fmt.Sprintf("sub%d", conn), udpURL(port), nil)
		for g := range 10 {
			wg, rg := group(conn, g, false)
			pubsub.AttachWriterGroups(pc, wg)
			pubsub.AttachReaderGroups(sc, rg)
		}
		pubConns, subConns = append(pubConns, pc), append(subConns, sc)
	}
	pc := pubsub.MQTTConnection("pubmqtt", b.URL(), uint16(15), pubsub.MappingUADP)
	sc := pubsub.MQTTConnection("submqtt", b.URL(), nil, pubsub.MappingUADP)
	for g := range 20 {
		wg, rg := group(5, g, true)
		pubsub.AttachWriterGroups(pc, wg)
		pubsub.AttachReaderGroups(sc, rg)
	}
	pubConns, subConns = append(pubConns, pc), append(subConns, sc)

	sub := startRuntime(t, pubsub.NewConfiguration(nil, subConns...), pubsub.WithDataSetHandler(chk.handle))
	pub := startRuntime(t, pubsub.NewConfiguration(pdss, pubConns...), pubsub.WithDataSource(newCounterSource()))
	chk.waitGrowth(t, 3, readers...)

	// Toggle groups, writers and readers from several goroutines.
	wd := chaoskit.NewWatchdog(t)
	var toggles []struct {
		rt *pubsub.PubSub
		c  pubsub.ComponentInfo
	}
	for _, rt := range []*pubsub.PubSub{pub, sub} {
		for _, c := range rt.Components() {
			switch c.Kind {
			case pubsub.KindWriterGroup, pubsub.KindReaderGroup, pubsub.KindDataSetWriter, pubsub.KindDataSetReader:
				toggles = append(toggles, struct {
					rt *pubsub.PubSub
					c  pubsub.ComponentInfo
				}{rt, c})
			default:
			}
		}
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	sink := chk.sink
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(i)))
			for {
				select {
				case <-stop:
					return
				default:
				}
				x := toggles[rng.Intn(len(toggles))]
				err := wd.Do("toggle", func() error {
					if rng.Intn(2) == 0 {
						return x.rt.Disable(x.c.ID)
					}
					return x.rt.Enable(x.c.ID)
				})
				if err != nil && !errors.Is(err, ua.StatusBadInvalidState) {
					sink.Addf("toggle %s: %v", x.c.Name, err)
				}
				_, _ = x.rt.Status(x.c.ID)
				time.Sleep(time.Duration(rng.Intn(5)) * time.Millisecond)
			}
		}()
	}
	time.Sleep(chaoskit.Duration(t, defaultDuration))
	close(stop)
	wd.Wait("togglers", &wg)
	for _, x := range toggles {
		_ = x.rt.Enable(x.c.ID)
	}
	chk.waitGrowth(t, 5, readers...)
	for _, r := range readers {
		waitState(t, sub, compID(t, sub, pubsub.KindDataSetReader, r), ua.PubSubStateOperational)
	}
	chk.sink.Report(t)
}

// TestParallelStartClose races Start, the cancellation of its context,
// Close, Enable and Disable of the runtime and Add and Remove of
// connections against each other while the runtime publishes and
// subscribes. Every call returns, Close leaves nothing running, and calls
// after Close fail with ErrClosed.
func TestParallelStartClose(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	wd := chaoskit.NewWatchdog(t)
	sink := &chaoskit.ErrSink{}
	end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
	for iter := 0; time.Now().Before(end); iter++ {
		rng := rand.New(rand.NewSource(seed + int64(iter)))
		port := freeUDPPort(t)
		cfg := pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("ds0")},
			pubsub.AttachReaderGroups(
				pubsub.AttachWriterGroups(pubsub.UDPConnection("c", udpURL(port), uint16(1)),
					pubsub.WriterGroup("wg", 1, 5*time.Millisecond, pubsub.DataSetWriter("w", 1, "ds0"))),
				pubsub.ReaderGroup("rg", pubsub.DataSetReader("ds0", uint16(1), 1, 1, pubsub.DataSetMetaDataOf(counterPDS("ds0"))))))
		chk := newChecker()
		rt, err := pubsub.New(cfg, pubsub.WithDataSource(newCounterSource()), pubsub.WithDataSetHandler(chk.handle), pubsub.WithRetryInterval(20*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		closed := make(chan struct{})
		for g := range 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rng := rand.New(rand.NewSource(seed + int64(iter*100+g)))
				for k := 0; k < 20; k++ {
					select {
					case <-closed:
						if err := rt.Start(context.Background()); !errors.Is(err, pubsub.ErrClosed) {
							sink.Addf("Start after Close: %v", err)
						}
						return
					default:
					}
					_ = wd.Do("op", func() error {
						// every operation but the reads may restart the reader
						switch rng.Intn(6) {
						case 0:
							ctx, cancel := context.WithCancel(context.Background())
							chk.restart(func() { _ = rt.Start(ctx) })
							if rng.Intn(2) == 0 {
								chk.restart(cancel)
							} else {
								time.AfterFunc(time.Duration(rng.Intn(20))*time.Millisecond, func() { chk.restart(cancel) })
							}
						case 1:
							chk.restart(func() { _ = rt.Start(context.Background()) })
						case 2:
							chk.restart(func() { _ = rt.Disable(pubsub.Root) })
						case 3:
							chk.restart(func() { _ = rt.Enable(pubsub.Root) })
						case 4:
							chk.restart(func() {
								if cid, err := rt.AddConnection(pubsub.UDPConnection(fmt.Sprintf("x%d", g), udpURL(port), uint16(2))); err == nil && rng.Intn(2) == 0 {
									_ = rt.RemoveConnection(cid)
								}
							})
						default:
							_ = rt.Components()
							_, _ = rt.Status(pubsub.Root)
						}
						return nil
					})
					time.Sleep(time.Duration(rng.Intn(3)) * time.Millisecond)
				}
			}()
		}
		time.Sleep(time.Duration(rng.Intn(30)) * time.Millisecond)
		if err := wd.Do("Close", rt.Close); err != nil {
			t.Fatal(err)
		}
		close(closed)
		wd.Wait("workers", &wg)
		if rt.Running() {
			sink.Addf("iteration %d: running after Close", iter)
		}
		if st, _ := rt.State(pubsub.Root); st == ua.PubSubStateOperational {
			sink.Addf("iteration %d: Operational after Close", iter)
		}
		if _, err := rt.AddConnection(pubsub.UDPConnection("late", udpURL(port), uint16(3))); !errors.Is(err, pubsub.ErrClosed) {
			sink.Addf("AddConnection after Close: %v", err)
		}
		chk.sink.Report(t)
	}
	sink.Report(t)
}
