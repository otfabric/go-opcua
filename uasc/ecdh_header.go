// SPDX-License-Identifier: MIT

package uasc

import (
	"fmt"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// Exchange of ephemeral keys for user identity tokens (Part 6 §6.8.2).
//
// With an ECC security policy the secret of a user identity token is
// encrypted with a key agreed between two ephemeral keys. CreateSession and
// ActivateSession have no parameter for them, so they travel in the
// AdditionalHeader of the request and response headers, an
// AdditionalParametersType with these entries:
//
//	ECDHPolicyUri  String            request: the policy the client wants a key for
//	                                 response: the policy the key belongs to
//	ECDHKey        EphemeralKeyType  response: the server's ephemeral public key,
//	                                 signed with its application instance key
//	                                 (or a StatusCode if no key could be created)
const (
	ecdhPolicyURIName = "ECDHPolicyUri"
	ecdhKeyName       = "ECDHKey"
)

// NewECDHPolicyHeader returns the AdditionalHeader with which a client asks
// the server for an ephemeral key of the given ECC security policy.
func NewECDHPolicyHeader(policyURI string) *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.AdditionalParametersType{
		Parameters: []*ua.KeyValuePair{
			{Key: &ua.QualifiedName{Name: ecdhPolicyURIName}, Value: ua.MustVariant(policyURI)},
		},
	})
}

// NewECDHKeyHeader returns the AdditionalHeader with which a server hands out
// an ephemeral key.
func NewECDHKeyHeader(policyURI string, key *ua.EphemeralKeyType) *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.AdditionalParametersType{
		Parameters: []*ua.KeyValuePair{
			{Key: &ua.QualifiedName{Name: ecdhPolicyURIName}, Value: ua.MustVariant(policyURI)},
			{Key: &ua.QualifiedName{Name: ecdhKeyName}, Value: ua.MustVariant(ua.NewExtensionObject(key))},
		},
	})
}

// additionalParameter returns the value of a parameter of an
// AdditionalParametersType header, or nil.
func additionalParameter(header *ua.ExtensionObject, name string) *ua.Variant {
	if header == nil {
		return nil
	}
	params, ok := header.Value.(*ua.AdditionalParametersType)
	if !ok || params == nil {
		return nil
	}
	for _, kv := range params.Parameters {
		if kv == nil || kv.Key == nil || kv.Key.NamespaceIndex != 0 || kv.Key.Name != name {
			continue
		}
		return kv.Value
	}
	return nil
}

// ECDHPolicyFromHeader returns the ECDHPolicyUri of an AdditionalHeader and
// whether there is one.
func ECDHPolicyFromHeader(header *ua.ExtensionObject) (string, bool) {
	v := additionalParameter(header, ecdhPolicyURIName)
	if v == nil {
		return "", false
	}
	uri, ok := v.Value().(string)
	return uri, ok
}

// ECDHKeyFromHeader returns the ephemeral key of an AdditionalHeader. It
// returns nil if the header does not carry one, and the StatusCode the server
// put in its place if it could not create a key.
func ECDHKeyFromHeader(header *ua.ExtensionObject) (*ua.EphemeralKeyType, error) {
	v := additionalParameter(header, ecdhKeyName)
	if v == nil {
		return nil, nil
	}
	switch x := v.Value().(type) {
	case *ua.ExtensionObject:
		if x != nil {
			if key, ok := x.Value.(*ua.EphemeralKeyType); ok && key != nil {
				return key, nil
			}
		}
	case ua.StatusCode:
		if x != ua.StatusOK {
			return nil, x
		}
		return nil, nil
	}
	return nil, fmt.Errorf("%w: ECDHKey is not an EphemeralKeyType", errors.ErrInvalidResponseType)
}
