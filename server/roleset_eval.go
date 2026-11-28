// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

// roleFacts is what the rules of the RoleSet are evaluated against: the
// identity of a session and the channel and Endpoint it uses, as they were
// at its last ActivateSession (OPC 10000-18 §4.4.1, §4.4.3).
type roleFacts struct {
	anonymous bool
	userName  string
	isUser    bool
	// thumbprint, subject and issuer are those of the user certificate of
	// an X509IdentityToken; subject or issuer is "" when its name cannot be
	// written as an X509Subject criteria.
	thumbprint      string
	subject, issuer string
	// roles and groups are the claims of a JWT, prefixed with the issuer
	// (§4.4.3).
	roles, groups []string
	// signed: the channel is Sign or SignAndEncrypt. trusted: the server
	// validated the Client Certificate of the channel. appURI is the
	// ApplicationUri of that certificate.
	signed  bool
	trusted bool
	appURI  string
	// endpoints are the configured Endpoints the session uses; none when
	// its endpointUrl names no configured Endpoint.
	endpoints []*ua.EndpointDescription
}

// trustedApp reports a "Client application with a trusted ApplicationInstance
// Certificate" on "at least a signed communication channel" (§4.4.3).
func (f *roleFacts) trustedApp() bool { return f.signed && f.trusted }

// newRoleFacts returns the facts of the session sess activated with
// identity over sc. identity is the token as the client sent it; only its
// user name, certificate and issued token data are kept.
func (s *Server) newRoleFacts(sc *uasc.SecureChannel, sess *session, identity ua.IdentityToken) *roleFacts {
	f := &roleFacts{}
	switch t := identity.(type) {
	case *ua.AnonymousIdentityToken, nil:
		f.anonymous = true
	case *ua.UserNameIdentityToken:
		f.isUser, f.userName = true, t.UserName
	case *ua.X509IdentityToken:
		if cert, err := uapolicy.LeafCertificate(t.CertificateData); err == nil {
			f.thumbprint = thumbprint(cert.Raw)
			f.subject, _ = subjectCriteria(cert.Subject)
			f.issuer, _ = subjectCriteria(cert.Issuer)
		}
	case *ua.IssuedIdentityToken:
		if s.cfg.issuedTokenType == IssuedTokenTypeJWT {
			if c, ok := parseJWTClaims(t.TokenData); ok {
				f.roles, f.groups = c.qualified()
			}
		}
	}
	mode, policy := ua.MessageSecurityModeNone, ua.SecurityPolicyURINone
	var cert []byte
	if sc != nil {
		mode, policy, cert = sc.SecurityMode(), sc.SecurityPolicyURI(), sc.RemoteCertificate()
	}
	f.signed = mode == ua.MessageSecurityModeSign || mode == ua.MessageSecurityModeSignAndEncrypt
	if c, err := uapolicy.LeafCertificate(cert); err == nil {
		f.trusted = s.cfg.clientCertificateValidator != nil
		if len(c.URIs) > 0 {
			f.appURI = c.URIs[0].String()
		}
	}
	key := endpointURLKey(sess.obs.snapshot().EndpointURL)
	for _, ep := range s.Endpoints() {
		if endpointURLKey(ep.EndpointURL) == key && ep.SecurityPolicyURI == policy && ep.SecurityMode == mode {
			f.endpoints = append(f.endpoints, ep)
		}
	}
	return f
}

// grantedLocked returns the roles of the RoleSet whose rules f complies
// with (§4.4.1). rs.mu must be held.
func (rs *RoleSet) grantedLocked(f *roleFacts) []*ua.NodeID {
	var out []*ua.NodeID
	for _, r := range rs.roles {
		if r.grants(f) {
			out = append(out, r.id)
		}
	}
	return out
}

// grants reports whether the role is granted to a session with the facts
// f: "The UserIdentityToken complies with Identities", "The Applications
// Property is not configured or the Client Certificate complies with the
// Applications settings" and "The Endpoints Property is not configured or
// the Endpoint used complies with the Endpoints settings" (§4.4.1).
func (r *managedRole) grants(f *roleFacts) bool {
	return slices.ContainsFunc(r.identities, func(x *ua.IdentityMappingRuleType) bool { return ruleMatches(x, f) }) &&
		r.applicationsAllow(f) && r.endpointsAllow(f)
}

// applicationsAllow evaluates Applications and ApplicationsExclude: an
// include list grants the role to the listed applications only, an
// exclude list to all others, and "If Applications has entries in the
// array, the Role shall only be granted if the Session uses a signed or
// signed and encrypted communication channel" (§4.4.1). The entries are
// "an ApplicationUri from a Client Certificate which is trusted by the
// Server".
func (r *managedRole) applicationsAllow(f *roleFacts) bool {
	if len(r.applications) == 0 {
		return r.appsExclude
	}
	if !f.trustedApp() {
		return false
	}
	return slices.Contains(r.applications, f.appURI) != r.appsExclude
}

// endpointsAllow evaluates Endpoints and EndpointsExclude as
// applicationsAllow does Applications. A session without a configured
// Endpoint gets no role that has Endpoints.
func (r *managedRole) endpointsAllow(f *roleFacts) bool {
	if len(r.endpoints) == 0 {
		return r.epExclude
	}
	if len(f.endpoints) == 0 {
		return false
	}
	listed := slices.ContainsFunc(r.endpoints, func(x *ua.EndpointType) bool {
		return slices.ContainsFunc(f.endpoints, func(ep *ua.EndpointDescription) bool { return endpointMatches(x, ep) })
	})
	return listed != r.epExclude
}

// endpointMatches compares an Endpoint of a role with a configured
// Endpoint: "Fields that have default values as defined in the
// EndpointType DataType are ignored during the comparison" (§4.4.1,
// §4.4.2).
func endpointMatches(x *ua.EndpointType, ep *ua.EndpointDescription) bool {
	return endpointURLKey(x.EndpointURL) == endpointURLKey(ep.EndpointURL) &&
		(x.SecurityMode == ua.MessageSecurityModeInvalid || x.SecurityMode == ep.SecurityMode) &&
		(x.SecurityPolicyURI == "" || x.SecurityPolicyURI == ep.SecurityPolicyURI) &&
		(x.TransportProfileURI == "" || x.TransportProfileURI == ep.TransportProfileURI)
}

// ruleMatches reports whether a session with the facts f meets the rule
// (§4.4.3, §4.4.4).
func ruleMatches(x *ua.IdentityMappingRuleType, f *roleFacts) bool {
	switch x.CriteriaType {
	case ua.IdentityCriteriaTypeUserName:
		return f.isUser && f.userName == x.Criteria
	case ua.IdentityCriteriaTypeThumbprint:
		return f.thumbprint != "" && f.thumbprint == x.Criteria
	case ua.IdentityCriteriaTypeRole:
		return slices.Contains(f.roles, x.Criteria)
	case ua.IdentityCriteriaTypeGroupID:
		return slices.Contains(f.groups, x.Criteria)
	case ua.IdentityCriteriaTypeAnonymous:
		// "applies if no user credentials have been provided"
		return f.anonymous
	case ua.IdentityCriteriaTypeAuthenticatedUser:
		// "applies if any valid user credentials have been provided"
		return !f.anonymous
	case ua.IdentityCriteriaTypeApplication:
		return f.trustedApp() && f.appURI == x.Criteria
	case ua.IdentityCriteriaTypeX509Subject:
		return (f.subject != "" && f.subject == x.Criteria) || (f.issuer != "" && f.issuer == x.Criteria)
	case ua.IdentityCriteriaTypeTrustedApplication:
		return f.trustedApp()
	}
	return false
}

// checkRule validates an identity mapping rule (§4.4.3): Bad_InvalidArgument
// for a rule that is not valid, Bad_NotSupported for the Role and GroupId
// rules of a server without JWTs.
func (rs *RoleSet) checkRule(x *ua.IdentityMappingRuleType) error {
	if x == nil || len(x.Criteria) > maxRoleText {
		return ua.StatusBadInvalidArgument
	}
	switch x.CriteriaType {
	case ua.IdentityCriteriaTypeAnonymous, ua.IdentityCriteriaTypeAuthenticatedUser, ua.IdentityCriteriaTypeTrustedApplication:
		// "The criteria shall be null or an empty string for Anonymous,
		// AuthenticatedUser and TrustedApplication."
		if x.Criteria != "" {
			return ua.StatusBadInvalidArgument
		}
	case ua.IdentityCriteriaTypeUserName:
		if x.Criteria == "" {
			return ua.StatusBadInvalidArgument
		}
	case ua.IdentityCriteriaTypeRole, ua.IdentityCriteriaTypeGroupID:
		if x.Criteria == "" {
			return ua.StatusBadInvalidArgument
		}
		if rs.s.cfg.issuedTokenType != IssuedTokenTypeJWT {
			return ua.StatusBadNotSupported
		}
	case ua.IdentityCriteriaTypeThumbprint:
		// "encoded as a hexadecimal string with upper case characters and
		// without spaces": a SHA-1, 20 bytes.
		if !validThumbprint(x.Criteria) {
			return ua.StatusBadInvalidArgument
		}
	case ua.IdentityCriteriaTypeApplication:
		if !validURI(x.Criteria) {
			return ua.StatusBadInvalidArgument
		}
	case ua.IdentityCriteriaTypeX509Subject:
		if !validSubjectCriteria(x.Criteria) {
			return ua.StatusBadInvalidArgument
		}
	default:
		return ua.StatusBadInvalidArgument
	}
	return nil
}

// sameRule reports an "equivalent rule" (§4.4.5): the same criteriaType and
// criteria.
func sameRule(a, b *ua.IdentityMappingRuleType) bool {
	return a != nil && b != nil && a.CriteriaType == b.CriteriaType && a.Criteria == b.Criteria
}

// sameEndpoint reports "The Endpoint with the passed settings" (§4.4.9):
// the same settings, the EndpointUrl compared as GetEndpoints compares it.
func sameEndpoint(a, b *ua.EndpointType) bool {
	return a != nil && b != nil && endpointURLKey(a.EndpointURL) == endpointURLKey(b.EndpointURL) &&
		a.SecurityMode == b.SecurityMode && a.SecurityPolicyURI == b.SecurityPolicyURI &&
		a.TransportProfileURI == b.TransportProfileURI
}

func validThumbprint(s string) bool {
	if len(s) != 40 { // SHA-1: 20 bytes
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// validURI reports an ApplicationUri: a URI with a scheme (Part 4 §7.2).
func validURI(s string) bool {
	if s == "" || len(s) > maxRoleText || !printable(s) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme != ""
}

// validEndpoint reports an Endpoint AddEndpoint takes: an EndpointUrl with
// the scheme of an OPC UA transport and a host (Bad_InvalidArgument, "The
// EndpointUrl is not valid", §4.4.9) and a MessageSecurityMode (Part 4
// §7.20).
func validEndpoint(ep *ua.EndpointType) bool {
	if ep == nil || len(ep.EndpointURL) > maxRoleText || !printable(ep.EndpointURL) ||
		len(ep.SecurityPolicyURI) > maxRoleText || len(ep.TransportProfileURI) > maxRoleText {
		return false
	}
	if ep.SecurityMode > ua.MessageSecurityModeSignAndEncrypt {
		return false
	}
	u, err := url.Parse(ep.EndpointURL)
	if err != nil || u.Host == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "opc.tcp", "opc.wss", "opc.https", "https", "wss":
		return true
	}
	return false
}

// printable reports a string without control characters.
func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// subjectNames are the names of an X509Subject criteria in their order
// (§4.4.3, Table 10) with the OIDs of the attributes (RFC 5280 §4.1.2.4,
// RFC 4519 for DC).
var subjectNames = []struct {
	name string
	oid  asn1.ObjectIdentifier
}{
	{"CN", asn1.ObjectIdentifier{2, 5, 4, 3}},
	{"O", asn1.ObjectIdentifier{2, 5, 4, 10}},
	{"OU", asn1.ObjectIdentifier{2, 5, 4, 11}},
	{"DC", asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}},
	{"L", asn1.ObjectIdentifier{2, 5, 4, 7}},
	{"S", asn1.ObjectIdentifier{2, 5, 4, 8}},
	{"C", asn1.ObjectIdentifier{2, 5, 4, 6}},
	{"dnQualifier", asn1.ObjectIdentifier{2, 5, 4, 46}},
	{"serialNumber", asn1.ObjectIdentifier{2, 5, 4, 5}},
}

// subjectCriteria writes a name as an X509Subject criteria (§4.4.3): the
// attributes of Table 10 in its order, an attribute that occurs more than
// once in the order of the certificate, each as name="value", separated by
// '/'; the others are left out. false for a name that cannot be written
// so: a value with a '"', a control character or of another type than a
// string.
func subjectCriteria(n pkix.Name) (string, bool) {
	var parts []string
	for _, sn := range subjectNames {
		for _, atv := range n.Names {
			if !atv.Type.Equal(sn.oid) {
				continue
			}
			v, ok := atv.Value.(string)
			if !ok || strings.ContainsRune(v, '"') || !printable(v) {
				return "", false
			}
			parts = append(parts, sn.name+`="`+v+`"`)
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "/"), true
}

// validSubjectCriteria reports an X509Subject criteria in the form of
// §4.4.3: one or more name="value" separated by '/', each name of Table 10,
// in its order, the value of printable characters without '"'.
func validSubjectCriteria(s string) bool {
	order := -1
	for {
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return false
		}
		i := slices.IndexFunc(subjectNames, func(x struct {
			name string
			oid  asn1.ObjectIdentifier
		}) bool {
			return x.name == s[:eq]
		})
		if i < order || i < 0 {
			return false
		}
		order = i
		rest := s[eq+1:]
		if !strings.HasPrefix(rest, `"`) {
			return false
		}
		end := strings.IndexByte(rest[1:], '"')
		if end < 0 || !printable(rest[1:1+end]) {
			return false
		}
		s = rest[2+end:]
		if s == "" {
			return true
		}
		if s[0] != '/' {
			return false
		}
		s = s[1:]
	}
}

// jwtClaims are the claims of a JSON Web Token the RoleSet uses (Part 6
// §6.5.2.3, Table 56).
type jwtClaims struct {
	Iss    string   `json:"iss"`
	Roles  []string `json:"roles"`
	Groups []string `json:"groups"`
}

// parseJWTClaims returns the claims of a JWT in its compact serialization
// (RFC 7519 §3, RFC 7515 §7.1): the payload is the second of the three
// base64url parts. The token's signature was checked by the
// IssuedTokenValidator; false for data that is no JWT or whose claims do
// not have the types of Table 56.
func parseJWTClaims(data []byte) (*jwtClaims, bool) {
	parts := bytes.Split(data, []byte("."))
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimRight(parts[1], "=")))
	if err != nil {
		return nil, false
	}
	var c jwtClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, false
	}
	return &c, true
}

// qualified returns the roles and groups as the criteria name them: "If
// "iss" is present in the JWT IssuedIdentityToken, the criteria is
// prepended by the value of "iss" followed by a '/' (slash)" (§4.4.3).
func (c *jwtClaims) qualified() (roles, groups []string) {
	q := func(xs []string) []string {
		if c.Iss == "" {
			return xs
		}
		out := make([]string, len(xs))
		for i, x := range xs {
			out[i] = c.Iss + "/" + x
		}
		return out
	}
	return q(c.Roles), q(c.Groups)
}

// grantRoles sets the roles of the session sess activated with identity
// over sc: those of the RoleMapper and, with the managed RoleSet, those
// whose rules the session complies with.
func (s *Server) grantRoles(sc *uasc.SecureChannel, sess *session, identity ua.IdentityToken) {
	rm := s.cfg.roleMapper
	if rm == nil {
		rm = DefaultRoleMapper
	}
	mapped := rm(identity)
	rs := s.roleSet
	if rs == nil {
		sess.setRoles(mapped)
		return
	}
	facts := s.newRoleFacts(sc, sess, identity)
	sess.rolesMu.Lock()
	defer sess.rolesMu.Unlock()
	sess.mappedRoles, sess.roleFacts = mapped, facts
	sess.roles = rs.rolesOf(mapped, facts)
}

// rolesOf returns the roles of the RoleMapper, then those the RoleSet
// grants for the facts f, each once.
func (rs *RoleSet) rolesOf(mapped []*ua.NodeID, f *roleFacts) []*ua.NodeID {
	rs.mu.RLock()
	granted := rs.grantedLocked(f)
	rs.mu.RUnlock()
	out := make([]*ua.NodeID, 0, len(mapped)+len(granted))
	for _, r := range append(slices.Clone(mapped), granted...) {
		if r != nil && !slices.ContainsFunc(out, r.Equal) {
			out = append(out, r)
		}
	}
	return out
}

// reevaluate gives the activated sessions their roles again after a change
// of the RoleSet: "If the configuration of a Role is changed, the Role
// assignment to active Session shall be re-evaluated and applied"
// (§4.4.1). A session's next request is checked against its new roles.
func (rs *RoleSet) reevaluate() {
	for _, sess := range rs.s.sb.all() {
		sess.rolesMu.Lock()
		if sess.roleFacts == nil {
			sess.rolesMu.Unlock()
			continue
		}
		roles := rs.rolesOf(sess.mappedRoles, sess.roleFacts)
		sess.roles = roles
		sess.rolesMu.Unlock()
		sd := &sess.diag
		sd.mu.Lock()
		sd.roles = slices.Clone(roles)
		sd.mu.Unlock()
	}
}
