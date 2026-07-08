// SPDX-License-Identifier: MIT

// Example security demonstrates the different OPC-UA security configurations.
//
// It supports three authentication modes:
//   - Anonymous: No credentials required
//   - Username/Password: Traditional credential-based authentication
//   - Certificate: Client certificate-based authentication
//
// Combined with security policies (None, Basic256Sha256, Aes256_Sha256_RsaPss, etc.)
// and security modes (None, Sign, SignAndEncrypt), this covers all common
// OPC-UA security configurations.
//
// Usage:
//
//	go run security.go -endpoint opc.tcp://localhost:4840 -auth anonymous -sec-policy None -sec-mode None
//	# No security (development only)
//
//	go run security.go -endpoint opc.tcp://localhost:4840 -auth username -user admin -pass secret \
//	    -sec-policy Basic256Sha256 -sec-mode SignAndEncrypt -cert cert.pem -key key.pem
//	# Encrypted with username auth
//
//	go run security.go -endpoint opc.tcp://localhost:4840 -auth certificate \
//	    -sec-policy Basic256Sha256 -sec-mode SignAndEncrypt -cert cert.pem -key key.pem
//	# Encrypted with certificate auth
//
//	go run security.go -endpoint opc.tcp://localhost:4840 -auth anonymous -sec-policy auto -cert cert.pem -key key.pem
//	# Auto-detect best security from server endpoints
package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	var (
		endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
		policy   = flag.String("sec-policy", "auto", "Security policy: None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss, or auto")
		mode     = flag.String("sec-mode", "auto", "Security mode: None, Sign, SignAndEncrypt, or auto")
		auth     = flag.String("auth", "anonymous", "Authentication: anonymous, username, certificate")
		certfile = flag.String("cert", "", "Path to certificate PEM file (required for security != None)")
		keyfile  = flag.String("key", "", "Path to private key PEM file (required for security != None)")
		user     = flag.String("user", "", "Username for username authentication")
		pass     = flag.String("pass", "", "Password for username authentication")
	)
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")
	flag.Parse()

	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	ctx := context.Background()

	// Build the list of client options based on the chosen configuration.
	var opts []opcua.Option

	// --- Step 1: Configure authentication ---
	//
	// OPC-UA supports three authentication mechanisms. The choice of auth mode
	// is independent of the security policy (encryption), though username and
	// certificate auth should always be paired with encryption.
	switch strings.ToLower(*auth) {
	case "anonymous":
		// Anonymous authentication: no credentials needed.
		// Safe to use with encrypted channels when you don't need user identity.
		log.Println("Auth: Anonymous")
		opts = append(opts, opcua.AuthAnonymous())

	case "username":
		// Username/password authentication.
		// IMPORTANT: Always use with encryption (SecurityPolicy != None)
		// to protect credentials in transit.
		if *user == "" {
			log.Fatal("--user is required for username authentication")
		}
		log.Printf("Auth: Username (%s)", *user)
		opts = append(opts, opcua.AuthUsername(*user, *pass))

	case "certificate":
		// Certificate-based authentication: the client certificate serves as
		// the identity token. This provides strong mutual authentication.
		if *certfile == "" {
			log.Fatal("--cert is required for certificate authentication")
		}
		c, err := tls.LoadX509KeyPair(*certfile, *keyfile)
		if err != nil {
			log.Fatalf("Failed to load auth certificate: %v", err)
		}
		opts = append(opts, opcua.AuthCertificate(c.Certificate[0]))

	default:
		log.Fatalf("Unknown auth mode: %s", *auth)
	}

	// --- Step 2: Configure security policy and mode ---
	//
	// Security policies define the algorithms used for encryption and signing.
	// Security modes determine whether messages are signed, encrypted, or both.
	//
	// Recommended for production: Basic256Sha256 + SignAndEncrypt
	// Recommended for maximum security: Aes256_Sha256_RsaPss + SignAndEncrypt
	if *policy == "auto" || *mode == "auto" {
		// Auto-detection: discover the server's endpoints and select the best one.
		// SelectEndpoint picks the highest security level matching the criteria.
		log.Println("Auto-detecting security from server endpoints...")
		endpoints, err := opcua.GetEndpoints(ctx, *endpoint)
		if err != nil {
			log.Fatalf("Failed to get endpoints: %v", err)
		}

		var secPolicy string
		var secMode ua.MessageSecurityMode
		if *policy != "auto" {
			secPolicy = *policy
		}
		if *mode != "auto" {
			secMode = ua.MessageSecurityModeFromString(*mode)
		}

		ep, err := ua.SelectEndpoint(endpoints, secPolicy, secMode)
		if err != nil {
			log.Fatalf("No matching endpoint: %v", err)
		}
		log.Printf("Selected: %s / %s", ep.SecurityPolicyURI, ep.SecurityMode)

		var authType ua.UserTokenType
		switch strings.ToLower(*auth) {
		case "anonymous":
			authType = ua.UserTokenTypeAnonymous
		case "username":
			authType = ua.UserTokenTypeUserName
		case "certificate":
			authType = ua.UserTokenTypeCertificate
		}
		opts = append(opts, opcua.SecurityFromEndpoint(ep, authType))
	} else {
		// Explicit security configuration.
		opts = append(opts,
			opcua.SecurityPolicy(*policy),
			opcua.SecurityModeString(*mode),
		)
	}

	// --- Step 3: Load certificates (required for policies other than None) ---
	//
	// The client certificate and private key are used for:
	// - Secure channel establishment (asymmetric key exchange)
	// - Message signing (integrity)
	// - Message encryption (confidentiality)
	if *certfile != "" && *keyfile != "" {
		c, err := tls.LoadX509KeyPair(*certfile, *keyfile)
		if err != nil {
			log.Fatalf("Failed to load certificate: %v", err)
		}
		pk, ok := c.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			log.Fatal("Private key must be RSA")
		}
		opts = append(opts,
			opcua.Certificate(c.Certificate[0]),
			opcua.PrivateKey(pk),
		)
	}

	// --- Step 4: Connect and use the client ---
	c, err := opcua.NewClient(*endpoint, opts...)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	log.Println("Connected successfully!")

	// Read the server's current time as a simple connectivity test.
	dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, 2258))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Server time: %v\n", dv.Value.Value())
	log.Println("Security example completed successfully.")
}
