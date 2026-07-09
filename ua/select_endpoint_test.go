// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

func TestSelectEndpoint(t *testing.T) {
	eps := []*EndpointDescription{
		{
			SecurityPolicyURI: SecurityPolicyURIBasic256Sha256,
			SecurityMode:      MessageSecurityModeSignAndEncrypt,
			SecurityLevel:     2,
		},
		{
			SecurityPolicyURI: SecurityPolicyURINone,
			SecurityMode:      MessageSecurityModeNone,
			SecurityLevel:     1,
		},
	}

	t.Run("empty endpoints", func(t *testing.T) {
		_, err := SelectEndpoint(nil, "", MessageSecurityModeInvalid)
		if err == nil {
			t.Error("expected error for empty endpoints")
		}
	})

	t.Run("no policy or mode - return highest", func(t *testing.T) {
		ep, err := SelectEndpoint(eps, "", MessageSecurityModeInvalid)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ep.SecurityLevel != 2 {
			t.Errorf("expected highest security level 2, got %d", ep.SecurityLevel)
		}
	})

	t.Run("match mode only", func(t *testing.T) {
		ep, err := SelectEndpoint(eps, "", MessageSecurityModeNone)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ep.SecurityMode != MessageSecurityModeNone {
			t.Errorf("expected None mode, got %v", ep.SecurityMode)
		}
	})

	t.Run("match policy only", func(t *testing.T) {
		ep, err := SelectEndpoint(eps, SecurityPolicyURINone, MessageSecurityModeInvalid)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ep.SecurityPolicyURI != SecurityPolicyURINone {
			t.Errorf("expected None policy, got %v", ep.SecurityPolicyURI)
		}
	})

	t.Run("match policy and mode", func(t *testing.T) {
		ep, err := SelectEndpoint(eps, SecurityPolicyURIBasic256Sha256, MessageSecurityModeSignAndEncrypt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ep.SecurityLevel != 2 {
			t.Errorf("expected security level 2, got %d", ep.SecurityLevel)
		}
	})

	t.Run("no matching endpoint", func(t *testing.T) {
		_, err := SelectEndpoint(eps, "urn:not:found", MessageSecurityModeSign)
		if err == nil {
			t.Error("expected error for no matching endpoint")
		}
	})
}
