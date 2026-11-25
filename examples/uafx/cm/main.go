// SPDX-License-Identifier: MIT

// Example uafx/cm runs an OPC UA server with a UAFX ConnectionManager (OPC
// 10000-81 §6.7): the ConnectionConfigurationSets of an fxcm.Manager below
// FxRoot.ConnectionManager, EditConnectionConfigurationSets,
// ProcessConnectionConfigurationSets and the file
// ConnectionManagerConfiguration (Annex F.3), through which a client
// writes sets.
//
// The ConnectionManager connects to the AutomationComponents of the sets
// without security and anonymously, as the AutomationComponent of
// examples/uafx/server accepts. This example grants the Role ConfigureAdmin
// (Part 3 §4.9.2), which the Methods need, to every session: a real server
// grants it to its administrators only.
//
// Usage:
//
//	go run ./examples/uafx/cm -port 4856 [-set sets.bin]
//
// -set loads the sets of a ConnectionConfigurationSet file (F.2,
// fxcm.EncodeFile) at start.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// applicationURI is the ApplicationUri of the server and of the sessions of
// its ConnectionManager, which the AutomationComponents record in the
// ConnectionManagerApplicationUri of the endpoints it creates (§6.6.2).
const applicationURI = "urn:example:uafx:cm"

func main() {
	host := flag.String("host", "localhost", "host name of the endpoint")
	port := flag.Int("port", 4856, "port of the endpoint (0: any)")
	sets := flag.String("set", "", "a ConnectionConfigurationSet file (F.2) to load at start")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	a, err := newApp(*host, *port)
	if err != nil {
		log.Fatal(err)
	}
	defer a.close()
	if *sets != "" {
		if err := a.load(*sets); err != nil {
			log.Fatal(err)
		}
	}
	if err := a.srv.Start(ctx); err != nil {
		log.Fatal(err)
	}
	log.Printf("UAFX ConnectionManager on opc.tcp://%s:%d", *host, a.srv.Port())
	<-ctx.Done()
}

// app is the server, its Manager and the ConnectionManager that exposes it.
type app struct {
	srv *server.Server
	m   *fxcm.Manager
	cm  *fxserver.ConnectionManager
}

func (a *app) close() {
	_ = a.cm.Close()
	_ = a.m.Close()
	_ = a.srv.Close()
}

// newApp returns a server, not started, with the UAFX CM model and a
// ConnectionManager.
func newApp(host string, port int) (*app, error) {
	srv, err := server.New(
		server.EndPoint(host, port),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI(applicationURI),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			return append(server.DefaultRoleMapper(tok), fxserver.ConfigureAdmin())
		}),
	)
	if err != nil {
		return nil, err
	}
	ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
	if err != nil {
		return nil, err
	}
	m, err := fxcm.New(fxcm.Options{
		Dialer: &fxcm.ClientDialer{Options: []opcua.Option{
			opcua.ApplicationURI(applicationURI), opcua.InsecureNoSecurity(),
		}},
		ApplicationURI: applicationURI,
		Monitor:        &fxcm.MonitorOptions{Interval: time.Second},
		Logger:         slog.Default(),
	})
	if err != nil {
		return nil, err
	}
	cm, err := fxserver.EnableConnectionManager(srv, ns, fxserver.ConnectionManagerOptions{
		Manager: m, Editable: true, File: true,
	})
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	return &app{srv: srv, m: m, cm: cm}, nil
}

// load adds the sets of the file path to the Manager.
func (a *app) load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sets, err := fxcm.DecodeFile(b)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, s := range sets {
		if _, err := a.m.Add(s); err != nil {
			return fmt.Errorf("%s: set %q: %w", path, s.BrowseName, err)
		}
	}
	a.cm.Flush()
	return nil
}
