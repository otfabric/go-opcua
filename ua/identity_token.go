// SPDX-License-Identifier: MIT

package ua

// IdentityToken is implemented by all user identity token types.
type IdentityToken interface {
	SetPolicyID(string)
}

func (t *AnonymousIdentityToken) SetPolicyID(id string) { t.PolicyID = id }
func (t *UserNameIdentityToken) SetPolicyID(id string)  { t.PolicyID = id }
func (t *X509IdentityToken) SetPolicyID(id string)      { t.PolicyID = id }
func (t *IssuedIdentityToken) SetPolicyID(id string)    { t.PolicyID = id }
