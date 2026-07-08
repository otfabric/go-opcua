// SPDX-License-Identifier: MIT

package ua

import (
	"fmt"
	"sort"

	"github.com/otfabric/go-opcua/errors"
)

// SelectEndpoint returns the endpoint with the highest security level which matches
// security policy and security mode. policy and mode can be omitted so that
// only one of them has to match.
func SelectEndpoint(endpoints []*EndpointDescription, policy string, mode MessageSecurityMode) (*EndpointDescription, error) {
	if len(endpoints) == 0 {
		return nil, errors.ErrNoEndpoints
	}

	sort.Sort(sort.Reverse(bySecurityLevel(endpoints)))
	policy = FormatSecurityPolicyURI(policy)

	// don't care -> return highest security level
	if policy == "" && mode == MessageSecurityModeInvalid {
		return endpoints[0], nil
	}

	for _, p := range endpoints {
		// match only security mode
		if policy == "" && p.SecurityMode == mode {
			return p, nil
		}

		// match only security policy
		if p.SecurityPolicyURI == policy && mode == MessageSecurityModeInvalid {
			return p, nil
		}

		// match both
		if p.SecurityPolicyURI == policy && p.SecurityMode == mode {
			return p, nil
		}
	}
	return nil, fmt.Errorf("%w: policy=%s mode=%s", errors.ErrNoMatchingEndpoint, policy, mode)
}

type bySecurityLevel []*EndpointDescription

func (a bySecurityLevel) Len() int           { return len(a) }
func (a bySecurityLevel) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a bySecurityLevel) Less(i, j int) bool { return a[i].SecurityLevel < a[j].SecurityLevel }
