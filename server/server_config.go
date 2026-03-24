// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/logger"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

// Option is an option function type to modify the configuration.
type Option func(*serverConfig) error

// PrivateKey sets the RSA private key in the secure channel configuration.
func PrivateKey(key *rsa.PrivateKey) Option {
	return func(s *serverConfig) error {
		s.privateKey = key
		return nil
	}
}

// EndPoint adds an additional endpoint to the server based on the host name and port.
func EndPoint(host string, port int) Option {
	return func(s *serverConfig) error {
		if s.endpoints == nil {
			s.endpoints = make([]string, 0)
		}
		ep := fmt.Sprintf("opc.tcp://%s:%d", host, port)
		s.endpoints = append(s.endpoints, ep)
		return nil
	}
}

// Certificate sets the client X509 certificate in the secure channel configuration
// and also detects and sets the ApplicationURI from the URI within the certificate.
func Certificate(cert []byte) Option {
	return func(s *serverConfig) error {
		s.certificate = cert

		x509cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return fmt.Errorf("server: failed to parse x509 certificate: %w", err)
		}

		if len(x509cert.URIs) > 0 {
			s.applicationURI = x509cert.URIs[0].String()
		}
		return nil
	}
}

// EnableSecurity registers a new endpoint security mode to the server.
// This will also register the security policy against each enabled auth mode.
func EnableSecurity(secPolicy string, secMode ua.MessageSecurityMode) Option {
	return func(s *serverConfig) error {
		if !strings.HasPrefix(secPolicy, "http://opcfoundation.org/UA/SecurityPolicy#") {
			secPolicy = "http://opcfoundation.org/UA/SecurityPolicy#" + secPolicy
		}

		var ok bool
		ss := uapolicy.SupportedPolicies()
		for _, sp := range ss {
			if sp == secPolicy {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("server: unsupported security policy %q", secPolicy)
		}

		for _, sec := range s.enabledSec {
			if sec.secPolicy == secPolicy && sec.secMode == secMode {
				return fmt.Errorf("server: security policy %q with mode %v already exists", secPolicy, secMode)
			}
		}

		sec := security{
			secPolicy: secPolicy,
			secMode:   secMode,
		}

		s.enabledSec = append(s.enabledSec, sec)
		return nil
	}
}

// EnableAuthMode registers a new user authentication mode to the server.
// All AuthModes except Anonymous require encryption by default, so EnableSecurity()
// must also be called with at least one non-"None" SecurityPolicy.
func EnableAuthMode(tokenType ua.UserTokenType) Option {
	return func(s *serverConfig) error {
		for _, a := range s.enabledAuth {
			if a.tokenType == tokenType {
				return fmt.Errorf("server: auth mode %v already registered", tokenType)
			}
		}

		a := authMode{
			tokenType: tokenType,
		}

		s.enabledAuth = append(s.enabledAuth, a)
		return nil
	}
}

func defaultChannelConfig() *uasc.Config {
	return &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Lifetime:          uint32(time.Hour / time.Millisecond),
	}
}

func ServerName(name string) Option {
	return func(s *serverConfig) error {
		s.applicationName = name
		return nil
	}
}

func ManufacturerName(name string) Option {
	return func(s *serverConfig) error {
		s.manufacturerName = name
		return nil
	}
}

func ProductName(name string) Option {
	return func(s *serverConfig) error {
		s.productName = name
		return nil
	}
}

func SoftwareVersion(name string) Option {
	return func(s *serverConfig) error {
		s.softwareVersion = name
		return nil
	}
}

// SetLogger sets the logger for the server.
func SetLogger(l logger.Logger) Option {
	return func(s *serverConfig) error {
		s.logger = l
		return nil
	}
}

// WithSlogLogger sets the logger from an slog.Logger.
func WithSlogLogger(l *slog.Logger) Option {
	return func(s *serverConfig) error {
		s.logger = logger.NewSlogLogger(l.Handler())
		return nil
	}
}
