//go:build interop

// SPDX-License-Identifier: MIT

// Command discoverypeer runs a go-opcua server for the discovery interop
// tests inside a container.
//
// mDNS needs both peers on one network segment. Docker Desktop does not route
// multicast between the host and its containers, so a go-opcua server that is
// to be discovered by (or to discover) a peer running in a container has to
// run in a container on the same user-defined network. The interop tests
// cross-compile this program, mount it into a container and talk to it
// through a published port.
//
// It prints "ready <port>" on stdout once the server listens and runs until
// it receives SIGTERM or SIGINT, on which it closes the server (unregistering
// from the discovery server and withdrawing its mDNS announcements).
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	var (
		port         = flag.Int("port", 4840, "TCP port to listen on")
		host         = flag.String("host", "", "host name to advertise in the endpoint URL (default: the host name)")
		name         = flag.String("name", "GoPeer", "application name and mDNS server name")
		uri          = flag.String("uri", "urn:otfabric:go-opcua:discoverypeer", "application URI")
		lds          = flag.Bool("lds", false, "act as a Local Discovery Server (registration without security allowed)")
		mdns         = flag.Bool("mdns", false, "enable multicast discovery")
		caps         = flag.String("caps", "", "comma separated capabilities to announce")
		registerWith = flag.String("register-with", "", "URL of a discovery server to register with (without security unless -secure)")
		interval     = flag.Duration("register-interval", 0, "registration renewal interval")
		timeout      = flag.Duration("registration-timeout", 0, "LDS: registration timeout")
		secure       = flag.Bool("secure", false, "generate a certificate, offer Basic256Sha256 endpoints and register over a secured channel")
		verbose      = flag.Bool("v", false, "log to stderr")
	)
	flag.Parse()

	if *host == "" {
		h, err := os.Hostname()
		if err != nil {
			fatal(err)
		}
		*host = h
	}
	opts := []server.Option{
		server.ListenOn(fmt.Sprintf("0.0.0.0:%d", *port)),
		server.EndPoint(*host, *port),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI(*uri),
		server.ServerName(*name),
	}
	if *secure {
		cert, key, err := selfSigned(*name, *uri, *host)
		if err != nil {
			fatal(err)
		}
		opts = append(opts,
			server.Certificate(cert), server.PrivateKey(key),
			server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
			server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		)
	}
	if *verbose {
		opts = append(opts, server.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	}
	if *lds {
		ldsOpts := []server.LDSOption{server.LDSAllowInsecureRegistration()}
		if *timeout > 0 {
			ldsOpts = append(ldsOpts, server.LDSRegistrationTimeout(*timeout))
		}
		opts = append(opts, server.WithLocalDiscoveryServer(ldsOpts...))
	}
	var capList []string
	if *caps != "" {
		capList = strings.Split(*caps, ",")
	}
	if *mdns {
		mc := []server.MulticastOption{server.MulticastServerName(*name)}
		if len(capList) > 0 {
			mc = append(mc, server.MulticastCapabilities(capList...))
		}
		opts = append(opts, server.WithMulticastDiscovery(mc...))
	}
	if *registerWith != "" {
		ro := []server.RegistrationOption{
			server.RegisterMdnsServerName(*name),
			server.RegisterEventHandler(func(e server.RegistrationEvent) {
				fmt.Fprintf(os.Stderr, "registration: service=%s online=%v security=%s/%v err=%v results=%v\n",
					e.Service, e.Online, e.SecurityPolicyURI, e.SecurityMode, e.Err, e.ConfigurationResults)
			}),
		}
		if !*secure {
			ro = append(ro, server.RegisterInsecure())
		}
		if len(capList) > 0 {
			ro = append(ro, server.RegisterServerCapabilities(capList...))
		}
		if *interval > 0 {
			ro = append(ro, server.RegisterInterval(*interval))
		}
		opts = append(opts, server.WithDiscoveryRegistration(*registerWith, ro...))
	}

	srv, err := server.New(append([]server.Option{server.InsecureNoSecurity()}, opts...)...)
	if err != nil {
		fatal(err)
	}
	if err := srv.Start(context.Background()); err != nil {
		fatal(err)
	}
	fmt.Printf("ready %d\n", srv.Port())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-sig:
			_ = srv.Close()
			return
		case <-tick.C:
			if *verbose {
				for _, r := range srv.ServersOnNetwork() {
					fmt.Fprintf(os.Stderr, "on-network: id=%d name=%q url=%s caps=%v\n", r.RecordID, r.ServerName, r.DiscoveryURL, r.ServerCapabilities)
				}
				for _, r := range srv.RegisteredServers() {
					fmt.Fprintf(os.Stderr, "registered: uri=%s urls=%v\n", r.ServerURI, r.DiscoveryURLs)
				}
			}
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "discoverypeer:", err)
	os.Exit(1)
}

// selfSigned creates an application instance certificate for the server.
func selfSigned(cn, appURI, host string) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(appURI)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"otfabric interop"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		URIs:                  []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}
