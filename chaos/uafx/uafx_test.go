// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// NodeIds in fxtest.NS of the test address space.
const (
	motionID = 1200 // Controller/FunctionalEntities/Motion
	axisID   = 1210 // Motion/Axis, its SubFunctionalEntity
)

// env is a server with the UAFX test address space.
type env struct {
	srv *server.Server
	url string
	ns  fxserver.Namespaces
}

func newEnv(t *testing.T, opts ...server.Option) *env {
	t.Helper()
	e := &env{}
	e.srv, e.url = conformkit.NewServerPrepared(t, func(srv *server.Server) {
		var err error
		e.ns, err = fxtest.Prepare(srv, false)
		require.NoError(t, err)
	}, append([]server.Option{
		// The ApplicationUri of the test certificates: AddModel names
		// namespace 1 after it (Part 5 §6.3.1).
		server.ApplicationURI(testpki.ServerAppURI),
	}, opts...)...)
	return e
}

// test returns the NodeId i in the namespace of the test NodeSet.
func (e *env) test(t *testing.T, i uint32) *ua.NodeID {
	t.Helper()
	idx, ok := fxtest.Index(e.srv, fxtest.NS)
	require.True(t, ok)
	return ua.NewNumericNodeID(idx, i)
}

// client connects a client to url with opts, closed at the end of the test.
func client(t *testing.T, url string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	all := append([]opcua.Option{
		opcua.InsecureNoSecurity(),
		opcua.DialTimeout(10 * time.Second),
		opcua.RequestTimeout(60 * time.Second),
	}, opts...)
	if l := chaoskit.Logger(); l != nil {
		all = append(all, opcua.WithLogger(l.With("side", "client")))
	}
	c, err := opcua.NewClient(url, all...)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { chaoskit.CloseClient(c, nil) })
	return c
}

// baseline returns the report of an undisturbed run against url.
func baseline(t *testing.T, url string) *uafx.Report {
	t.Helper()
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	r, err := uafx.Inspect(ctx, client(t, url), uafx.Limits{})
	require.NoError(t, err)
	require.True(t, r.IsFXServer())
	require.Len(t, r.AutomationComponents, 2)
	return r
}

// controller returns the Controller of r.
func controller(t *testing.T, r *uafx.Report) *uafx.AutomationComponent {
	t.Helper()
	for i := range r.AutomationComponents {
		if r.AutomationComponents[i].BrowseName.Name == "Controller" {
			return &r.AutomationComponents[i]
		}
	}
	t.Fatalf("no Controller in the report")
	return nil
}

// TestInspectUnderFaults runs Inspect on several clients through a chaos
// proxy over a signed and encrypted channel while a monkey disturbs the
// connections, then checks that every client recovers.
func TestInspectUnderFaults(t *testing.T) {
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	e := newEnv(t, conformkit.SecureServerOpts(t)...)
	want := baseline(t, e.url)

	proxy := testutil.NewChaosProxy(t, fmt.Sprintf("localhost:%d", e.srv.Port()), seed)
	ep := conformkit.EndpointFor(t, e.url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	secure := conformkit.SecureClientOpts(t, ep, ua.UserTokenTypeAnonymous)
	const workers = 4
	clients := make([]*opcua.Client, workers)
	for i := range clients {
		clients[i] = client(t, proxy.EndpointURL(), append(slices.Clone(secure),
			opcua.AutoReconnect(true),
			opcua.ReconnectInterval(50*time.Millisecond),
			opcua.RequestTimeout(3*time.Second),
		)...)
	}

	wd := chaoskit.NewWatchdog(t)
	defer wd.Close()
	var (
		tally chaoskit.ErrorTally
		sink  chaoskit.ErrSink
		stop  atomic.Bool
		wg    sync.WaitGroup
	)
	for i, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				var r *uafx.Report
				err := wd.Do(fmt.Sprintf("inspect %d", i), func() (err error) {
					r, err = uafx.Inspect(ctx, c, uafx.Limits{})
					return err
				})
				cancel()
				tally.Add(err)
				switch {
				case err == nil:
					if diff := compare(want, r); diff != "" {
						sink.Addf("client %d: report differs from the undisturbed one: %s", i, diff)
					}
				case !errors.Is(err, uafx.ErrInspect):
					sink.Addf("client %d: error without uafx.ErrInspect: %v", i, err)
				case !isFaultError(err):
					sink.Addf("client %d: error not caused by the faults: %v", i, err)
				}
				if err != nil {
					// The client reconnects in the background.
					time.Sleep(20 * time.Millisecond)
				}
			}
		}()
	}

	faults := []func(){
		proxy.DropAll,
		func() { proxy.HalfClose(testutil.Direction(rng.Intn(2))) },
		func() {
			d := testutil.Direction(rng.Intn(2))
			proxy.SetBlackhole(d, true)
			time.Sleep(time.Duration(200+rng.Intn(800)) * time.Millisecond)
			proxy.SetBlackhole(d, false)
		},
		func() { proxy.SetLatency(time.Duration(rng.Intn(50))*time.Millisecond, 20*time.Millisecond) },
		func() { proxy.SetFragment(1 + rng.Intn(7)) },
		func() { proxy.SetThrottle(64 * 1024) },
		func() { proxy.TruncateNext(testutil.Direction(rng.Intn(2)), 1+rng.Intn(4096)) },
		func() { proxy.CorruptNext(testutil.Direction(rng.Intn(2)), 1+rng.Intn(3)) },
		proxy.Heal,
	}
	end := time.Now().Add(chaoskit.Duration(t, 8*time.Second))
	for time.Now().Before(end) {
		faults[rng.Intn(len(faults))]()
		time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
	}
	proxy.Heal()
	stop.Store(true)
	wd.Wait("the inspecting clients", &wg)
	t.Logf("fault phase: %s", &tally)
	sink.Report(t)

	// Every client recovers and gets the undisturbed report again.
	for i, c := range clients {
		var last error
		ok := chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r, err := uafx.Inspect(ctx, c, uafx.Limits{})
			if last = err; err != nil {
				return false
			}
			if diff := compare(want, r); diff != "" {
				last = errors.New(diff)
				return false
			}
			return true
		})
		require.True(t, ok, "client %d did not recover: %v", i, last)
	}
	require.Equal(t, want, baseline(t, e.url))
}

// compare returns "" if got is want, or what differs.
func compare(want, got *uafx.Report) string {
	if got == nil {
		return "no report"
	}
	if !equal(want, got) {
		return fmt.Sprintf("got %+v", *got)
	}
	return ""
}

// TestInspectWhileValuesChange runs Inspect on several clients while the
// server changes the AggregatedHealth of the Controller and the
// AuthorAssignedVersion of Motion. Every report holds one of the values
// the server had, never a value it did not write or a Finding about one.
func TestInspectWhileValuesChange(t *testing.T) {
	seed := chaoskit.Seed(t)
	e := newEnv(t)
	want := baseline(t, e.url)
	healthID, versionID := e.test(t, fxtest.AggregatedHealthID), e.test(t, fxtest.AuthorAssignedVersionID)

	healths := [][]byte{
		{0, 0, 0, 0, 0, 0},
		{0x01, 0x00, 0x00, 0x00, 0x0a, 0x00},
		fxtest.AggregatedHealth,
	}
	versions := [][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0},
		{9, 0, 8, 0, 7, 0, 6, 0},
		fxtest.AuthorAssignedVersion,
	}
	okHealth := map[string]bool{"OK/OK": true, "DeviceFailure/OperationalError|SubOperationalError": true, "DeviceMaintenanceRequired/OperationalWarning": true}
	okVersion := map[string]bool{"0.0.0.0": true, "9.8.7.6": true, "1.2.3.4": true}

	wd := chaoskit.NewWatchdog(t)
	defer wd.Close()
	var (
		sink chaoskit.ErrSink
		stop atomic.Bool
		wg   sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed))
		for !stop.Load() {
			if err := fxtest.SetStructure(e.srv, healthID, e.ns.AC, fxacid.AggregatedHealthDataTypeEncodingDefaultBinary, healths[rng.Intn(len(healths))]); err != nil {
				sink.Addf("set health: %v", err)
			}
			if err := fxtest.SetStructure(e.srv, versionID, e.ns.AC, fxacid.FxVersionEncodingDefaultBinary, versions[rng.Intn(len(versions))]); err != nil {
				sink.Addf("set version: %v", err)
			}
		}
	}()
	for i := range 4 {
		c := client(t, e.url)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				ctx, cancel := chaoskit.OpCtx()
				var r *uafx.Report
				err := wd.Do(fmt.Sprintf("inspect %d", i), func() (err error) {
					r, err = uafx.Inspect(ctx, c, uafx.Limits{})
					return err
				})
				cancel()
				if err != nil {
					sink.Addf("client %d: %v", i, err)
					continue
				}
				ac := controller(t, r)
				h := ac.AggregatedHealth
				v := ac.FunctionalEntities[0].AuthorAssignedVersion
				if h == nil || !okHealth[h.AggregatedDeviceHealth.String()+"/"+h.AggregatedOperationalHealth.String()] {
					sink.Addf("client %d: health %+v was never written", i, h)
				}
				if v == nil || !okVersion[v.String()] {
					sink.Addf("client %d: version %v was never written", i, v)
				}
				if !reflect.DeepEqual(r.Findings, want.Findings) {
					sink.Addf("client %d: findings %v", i, r.Findings)
				}
			}
		}()
	}
	time.Sleep(chaoskit.Duration(t, 5*time.Second))
	stop.Store(true)
	wd.Wait("the writer and the inspecting clients", &wg)
	sink.Report(t)
}

// TestInspectWhileModelChanges runs Inspect on several clients while the
// server removes the SubFunctionalEntity Axis of Motion and adds it again.
// Every report is the undisturbed one, with or without Axis.
func TestInspectWhileModelChanges(t *testing.T) {
	e := newEnv(t)
	want := baseline(t, e.url)
	without := baseline(t, e.url)
	controller(t, without).FunctionalEntities[0].SubFunctionalEntities = nil

	motion, axis := e.srv.Node(e.test(t, motionID)), e.srv.Node(e.test(t, axisID))
	require.NotNil(t, motion)
	require.NotNil(t, axis)

	wd := chaoskit.NewWatchdog(t)
	defer wd.Close()
	var (
		sink    chaoskit.ErrSink
		stop    atomic.Bool
		wg      sync.WaitGroup
		seen    [2]atomic.Int64 // reports with and without Axis
		toggles atomic.Int64
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		hasComponent := ua.NewNumericNodeID(0, id.HasComponent)
		for !stop.Load() {
			motion.RemoveRef(ua.NewExpandedNodeID(axis.ID(), "", 0), hasComponent, true)
			time.Sleep(time.Millisecond)
			motion.AddRef(axis, id.HasComponent, true)
			time.Sleep(time.Millisecond)
			toggles.Add(1)
		}
	}()
	for i := range 4 {
		c := client(t, e.url)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				ctx, cancel := chaoskit.OpCtx()
				var r *uafx.Report
				err := wd.Do(fmt.Sprintf("inspect %d", i), func() (err error) {
					r, err = uafx.Inspect(ctx, c, uafx.Limits{})
					return err
				})
				cancel()
				switch {
				case err != nil:
					sink.Addf("client %d: %v", i, err)
				case equal(want, r):
					seen[0].Add(1)
				case equal(without, r):
					seen[1].Add(1)
				default:
					sink.Addf("client %d: report with neither form of Motion: %+v", i, controller(t, r).FunctionalEntities)
				}
			}
		}()
	}
	time.Sleep(chaoskit.Duration(t, 5*time.Second))
	stop.Store(true)
	wd.Wait("the model changer and the inspecting clients", &wg)
	t.Logf("%d changes, %d reports with Axis, %d without", toggles.Load(), seen[0].Load(), seen[1].Load())
	sink.Report(t)
	motion.AddRef(axis, id.HasComponent, true)
	require.Equal(t, want, baseline(t, e.url))
}

// TestInspectServerClose closes the server with inspections in flight:
// every Inspect returns, with a report or a connection error, and nothing
// is left running.
func TestInspectServerClose(t *testing.T) {
	e := newEnv(t)
	_ = baseline(t, e.url)
	wd := chaoskit.NewWatchdog(t)
	defer wd.Close()
	var (
		sink    chaoskit.ErrSink
		wg      sync.WaitGroup
		started sync.WaitGroup
	)
	for i := range 8 {
		c := client(t, e.url, opcua.AutoReconnect(false))
		wg.Add(1)
		started.Add(1)
		go func() {
			defer wg.Done()
			first := true
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				if first {
					started.Done()
					first = false
				}
				err := wd.Do(fmt.Sprintf("inspect %d", i), func() error {
					_, err := uafx.Inspect(ctx, c, uafx.Limits{})
					return err
				})
				cancel()
				if err == nil {
					continue
				}
				if !errors.Is(err, uafx.ErrInspect) || !chaoskit.IsConnectionError(err) {
					sink.Addf("client %d: %v", i, err)
				}
				return
			}
		}()
	}
	started.Wait()
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, e.srv.Close())
	wd.Wait("the inspecting clients", &wg)
	sink.Report(t)
}
