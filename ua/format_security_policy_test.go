// SPDX-License-Identifier: MIT

package ua

import "testing"

func TestFormatSecurityPolicyURI(t *testing.T) {
	if got := FormatSecurityPolicyURI(""); got != "" {
		t.Errorf("empty: got %q", got)
	}
	if got := FormatSecurityPolicyURI("None"); got != SecurityPolicyURINone {
		t.Errorf("None: got %q", got)
	}
	if got := FormatSecurityPolicyURI("Basic256Sha256"); got != SecurityPolicyURIBasic256Sha256 {
		t.Errorf("short name: got %q", got)
	}
	full := SecurityPolicyURIBasic256
	if got := FormatSecurityPolicyURI(full); got != full {
		t.Errorf("already full URI: got %q want %q", got, full)
	}
	shortSuffix := "CustomPolicy"
	if got := FormatSecurityPolicyURI(shortSuffix); got != SecurityPolicyURIPrefix+shortSuffix {
		t.Errorf("bare suffix: got %q", got)
	}
}
