// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestSameUser covers who may take over the subscriptions of a session with
// TransferSubscriptions (Part 4 §5.13.7).
//
// Regression: the service handed any subscription to any session that asked
// for it by id.
func TestSameUser(t *testing.T) {
	user := func(name string) *session {
		return &session{identityToken: &ua.UserNameIdentityToken{UserName: name}}
	}
	cert := func(user, app string) *session {
		return &session{identityToken: &ua.X509IdentityToken{CertificateData: []byte(user)}, remoteCertificate: []byte(app)}
	}
	anon := func(app string) *session {
		s := &session{identityToken: &ua.AnonymousIdentityToken{}}
		if app != "" {
			s.remoteCertificate = []byte(app)
		}
		return s
	}
	issued := func(app string) *session {
		return &session{identityToken: &ua.IssuedIdentityToken{TokenData: []byte("differs per session")}, remoteCertificate: []byte(app)}
	}
	alice := user("alice")

	tests := []struct {
		name     string
		from, to *session
		want     bool
	}{
		{"the session itself", alice, alice, true},
		{"same user name", alice, user("alice"), true},
		{"other user name", alice, user("bob"), false},
		{"user name to anonymous", alice, anon(""), false},
		{"anonymous to user name", anon(""), alice, false},
		{"same user certificate, other application", cert("u1", "app1"), cert("u1", "app2"), true},
		{"other user certificate", cert("u1", "app1"), cert("u2", "app1"), false},
		{"anonymous, same application", anon("app1"), anon("app1"), true},
		{"anonymous, other application", anon("app1"), anon("app2"), false},
		{"anonymous, no application certificates", anon(""), anon(""), true},
		{"anonymous without token object", &session{}, anon(""), true},
		{"anonymous, one without certificate", anon("app1"), anon(""), false},
		{"issued token, same application", issued("app1"), issued("app1"), true},
		{"issued token, other application", issued("app1"), issued("app2"), false},
		{"issued token to anonymous", issued("app1"), anon("app1"), false},
		{"no owner", nil, alice, false},
		{"no session", alice, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, sameUser(tt.from, tt.to))
		})
	}
}
