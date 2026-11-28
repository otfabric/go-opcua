// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// connEnv is a server with the connection Methods on
// fxtest.ConnectionsNodeSet.
type connEnv struct {
	srv   *server.Server
	url   string
	ns    fxserver.Namespaces
	test  uint16
	conns *fxserver.Connections
	udp   string
}

func newConnEnv(t *testing.T, opts ...server.Option) *connEnv {
	t.Helper()
	e := &connEnv{udp: fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t))}
	e.srv, e.url = conformkit.NewServerPrepared(t, func(srv *server.Server) {
		var err error
		e.ns, e.test, err = fxtest.PrepareConnections(srv)
		require.NoError(t, err)
		e.conns, err = fxserver.EnableConnections(srv, e.ns, fxserver.ConnectionOptions{
			Interval: 5 * time.Millisecond, Logger: slog.New(slog.DiscardHandler)})
		require.NoError(t, err)
		cleanup.Register(t, func() { _ = e.conns.Close() })
	}, append([]server.Option{
		server.ApplicationURI(testpki.ServerAppURI),
		server.WithPubSub(nil),
	}, opts...)...)
	return e
}

func (e *connEnv) id(n uint32) *ua.NodeID { return ua.NewNumericNodeID(e.test, n) }

// request establishes the endpoint name of Motion with its own PubSub
// configuration (names of its own): a Publisher of Actual, or with sub
// also a Subscriber of Setpoint.
func (e *connEnv) request(name string, sub bool) *uafx.EstablishConnectionsRequest {
	pds := pubsub.PublishedDataItems("PDS-"+name, pubsub.Var("x", e.id(fxtest.ConnActual), ua.TypeIDDouble))
	w := pubsub.DataSetWriter("W-"+name, 1, "PDS-"+name)
	w.Enabled = false
	cfg := &ua.PubSubConfiguration2DataType{
		PublishedDataSets: []*ua.PublishedDataSetDataType{pds},
		Connections: []*ua.PubSubConnectionDataType{
			pubsub.AttachWriterGroups(pubsub.UDPConnection("P-"+name, e.udp, uint16(7)), pubsub.WriterGroup("WG-"+name, 1, 20*time.Millisecond, w)),
		},
		Enabled: true,
	}
	refs := []*ua.PubSubConfigurationRefDataType{
		{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferencePubDataset},
		{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferenceConnection},
		{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferenceWriterGroup},
		{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferenceWriter},
	}
	links := &uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceWriter}}
	p := &uafx.PubSubConnectionEndpointParameter{
		Name:                     name,
		ConnectionEndpointTypeID: ua.NewNumericNodeID(e.ns.AC, fxacid.PubSubConnectionEndpointType),
		OutputVariableIDs:        []*ua.NodeID{e.id(fxtest.ConnActual)},
		CleanupTimeout:           -1,
		RelatedEndpoint:          &uafx.RelatedEndpoint{Address: "opc.tcp://peer", ConnectionEndpointName: name},
		Mode:                     uafx.PubSubPublisher,
	}
	if sub {
		r := pubsub.SetTargetVariables(pubsub.DataSetReader("R-"+name, uint16(7), 1, 1, pubsub.MetaData("m", pubsub.Field{Name: "x", Type: ua.TypeIDDouble})),
			pubsub.Target(e.id(fxtest.ConnSetpoint)))
		r.Enabled = false
		cfg.Connections = append(cfg.Connections, pubsub.AttachReaderGroups(pubsub.UDPConnection("S-"+name, e.udp, nil), pubsub.ReaderGroup("RG-"+name, r)))
		refs = append(refs,
			&ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferenceConnection, ConnectionIndex: 1},
			&ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferenceReaderGroup, ConnectionIndex: 1},
			&ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferenceReader, ConnectionIndex: 1})
		links.DataSetReaderRef = &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceReader, ConnectionIndex: 1}
		p.Mode, p.InputVariableIDs = uafx.PubSubPublisherSubscriber, []*ua.NodeID{e.id(fxtest.ConnSetpoint)}
	}
	return &uafx.EstablishConnectionsRequest{
		CommandMask: uafx.CreateConnectionEndpointCmd | uafx.SetConfigurationDataCmd | uafx.SetCommunicationConfigurationCmd | uafx.EnableCommunicationCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
			FunctionalEntityNode: e.id(fxtest.ConnMotion),
			ConnectionEndpoint:   &uafx.ConnectionEndpointDefinition{Parameter: p},
			ConfigurationData:    []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: e.id(fxtest.ConnGain)}, Value: ua.MustVariant(float64(len(name)))}},
			CommunicationLinks:   links,
		}},
		CommunicationConfigurations: []*uafx.PubSubCommunicationConfiguration{{PubSubConfiguration: cfg, ConfigurationReferences: refs}},
	}
}

// checkBaseline checks that the server is as before the connections: only
// Preset, no DataSetReader or DataSetWriter (each was the endpoint's or
// the call's), and the health of Preset alone, Initial.
func (e *connEnv) checkBaseline(t *testing.T) {
	t.Helper()
	eps := e.conns.Endpoints()
	require.Len(t, eps, 1, "%v", eps)
	require.Equal(t, e.id(fxtest.ConnPreset).String(), eps[0].String())
	for _, c := range e.srv.PubSub().Components() {
		require.NotEqual(t, pubsub.KindDataSetReader, c.Kind, c.Name)
		require.NotEqual(t, pubsub.KindDataSetWriter, c.Kind, c.Name)
	}
	e.conns.RefreshHealth()
	oh, _ := e.srv.Node(e.id(fxtest.ConnMotionOH)).Value().Value.Value().(uint32)
	require.Equal(t, uint32(1), oh&0xffff, "CommInitial of Preset alone")
}

// closeAll closes every endpoint but Preset with Remove through c.
func (e *connEnv) closeAll(t *testing.T, c *opcua.Client) {
	t.Helper()
	var eps []*ua.NodeID
	for _, n := range e.conns.Endpoints() {
		if n.String() != e.id(fxtest.ConnPreset).String() {
			eps = append(eps, n)
		}
	}
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	sc, res, err := uafx.CloseConnections(ctx, c, e.id(fxtest.ConnCtl), eps, true)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sc, "%v", res)
}

// TestConnectionsParallel runs EstablishConnections and CloseConnections
// on several clients at once while another closes endpoints at random and
// the Status monitor runs. Every call returns Good or Uncertain (an abort,
// such as an input another enabled endpoint has, Part 81 Table 17, or an
// endpoint the other closed); in the end the server is as before.
func TestConnectionsParallel(t *testing.T) {
	seed := chaoskit.Seed(t)
	e := newConnEnv(t)
	wd := chaoskit.NewWatchdog(t)
	defer wd.Close()
	var (
		sink                chaoskit.ErrSink
		stop                atomic.Bool
		wg                  sync.WaitGroup
		good, uncertain, ok atomic.Int64
	)
	const workers = 4
	for i := range workers {
		c := client(t, e.url)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !stop.Load(); n++ {
				name := fmt.Sprintf("w%d-%d", i, n)
				ctx, cancel := chaoskit.OpCtx()
				var res *uafx.EstablishConnectionsResult
				err := wd.Do("establish "+name, func() (err error) {
					res, err = uafx.EstablishConnections(ctx, c, e.id(fxtest.ConnCtl), e.request(name, i == 0))
					return err
				})
				cancel()
				switch {
				case err != nil:
					sink.Addf("%s: %v", name, err)
					continue
				case res.Status == ua.StatusUncertain:
					uncertain.Add(1)
					continue
				case res.Status != ua.StatusOK:
					sink.Addf("%s: status %v", name, res.Status)
					continue
				}
				good.Add(1)
				ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
				ctx, cancel = chaoskit.OpCtx()
				var sc ua.StatusCode
				var results []ua.StatusCode
				err = wd.Do("close "+name, func() (err error) {
					sc, results, err = uafx.CloseConnections(ctx, c, e.id(fxtest.ConnCtl), []*ua.NodeID{ep}, true)
					return err
				})
				cancel()
				switch {
				case err != nil:
					sink.Addf("close %s: %v", name, err)
				case sc == ua.StatusOK:
					ok.Add(1)
				case sc != ua.StatusUncertain || results[0] != ua.StatusBadNodeIDUnknown:
					// Uncertain: the random closer removed it first.
					sink.Addf("close %s: %v %v", name, sc, results)
				}
			}
		}()
	}
	closer := client(t, e.url)
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed))
		for !stop.Load() {
			eps := e.conns.Endpoints()
			if len(eps) > 1 {
				ep := eps[rng.Intn(len(eps))]
				if ep.String() != e.id(fxtest.ConnPreset).String() {
					ctx, cancel := chaoskit.OpCtx()
					remove := rng.Intn(2) == 0
					err := wd.Do("random close", func() error {
						sc, res, err := uafx.CloseConnections(ctx, closer, e.id(fxtest.ConnCtl), []*ua.NodeID{ep}, remove)
						if err == nil && sc != ua.StatusOK && (len(res) != 1 || res[0] != ua.StatusBadNodeIDUnknown) {
							return fmt.Errorf("%v %v", sc, res)
						}
						return err
					})
					cancel()
					if err != nil {
						sink.Addf("random close: %v", err)
					}
				}
			}
			e.conns.RefreshHealth()
			time.Sleep(time.Duration(rng.Intn(10)) * time.Millisecond)
		}
	}()
	time.Sleep(chaoskit.Duration(t, 5*time.Second))
	stop.Store(true)
	wd.Wait("the clients", &wg)
	t.Logf("established %d, aborted %d, closed %d", good.Load(), uncertain.Load(), ok.Load())
	sink.Report(t)
	require.Positive(t, good.Load())

	e.closeAll(t, client(t, e.url))
	e.checkBaseline(t)
}

// TestConnectionsUnderFaults runs EstablishConnections and
// CloseConnections through a chaos proxy over a signed and encrypted
// channel while a monkey disturbs the connections. A call either completes
// or fails with an error of the faults; whatever the server did for a call
// whose answer was lost is a whole call: once the faults stop, closing what
// is left with Remove brings the server back to where it started.
func TestConnectionsUnderFaults(t *testing.T) {
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	e := newConnEnv(t, conformkit.SecureServerOpts(t)...)
	proxy := testutil.NewChaosProxy(t, fmt.Sprintf("localhost:%d", e.srv.Port()), seed)
	ep := conformkit.EndpointFor(t, e.url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	secure := conformkit.SecureClientOpts(t, ep, ua.UserTokenTypeAnonymous)

	wd := chaoskit.NewWatchdog(t)
	defer wd.Close()
	var (
		tally     chaoskit.ErrorTally
		sink      chaoskit.ErrSink
		stop      atomic.Bool
		wg        sync.WaitGroup
		uncertain atomic.Int64
	)
	const workers = 3
	for i := range workers {
		c := client(t, proxy.EndpointURL(), append(slices.Clone(secure),
			opcua.AutoReconnect(true),
			opcua.ReconnectInterval(50*time.Millisecond),
			opcua.RequestTimeout(3*time.Second),
		)...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !stop.Load(); n++ {
				name := fmt.Sprintf("f%d-%d", i, n)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				var res *uafx.EstablishConnectionsResult
				err := wd.Do("establish "+name, func() (err error) {
					res, err = uafx.EstablishConnections(ctx, c, e.id(fxtest.ConnCtl), e.request(name, false))
					return err
				})
				tally.Add(err)
				if err == nil && res.Status != ua.StatusOK {
					// A call the client sent again after a reconnect finds
					// the endpoint of the first (Bad_BrowseNameDuplicated).
					uncertain.Add(1)
				}
				if err == nil && res.Status == ua.StatusOK {
					ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
					err = wd.Do("close "+name, func() error {
						_, _, err := uafx.CloseConnections(ctx, c, e.id(fxtest.ConnCtl), []*ua.NodeID{ep}, true)
						return err
					})
					tally.Add(err)
				}
				cancel()
				switch {
				case err == nil:
				case !errors.Is(err, uafx.ErrCall):
					sink.Addf("%s: error without uafx.ErrCall: %v", name, err)
				case !isFaultError(err) && !errors.Is(err, context.DeadlineExceeded):
					sink.Addf("%s: error not caused by the faults: %v", name, err)
				}
				if err != nil {
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
	wd.Wait("the clients", &wg)
	t.Logf("fault phase: %s, %d aborted calls", &tally, uncertain.Load())
	sink.Report(t)

	e.closeAll(t, client(t, e.url, secure...))
	e.checkBaseline(t)
}
