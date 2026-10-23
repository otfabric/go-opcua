// SPDX-License-Identifier: MIT

// Package sks is the client side of the OPC UA PubSub Security Key Service
// (Part 14 §8): GetSecurityKeys and SetSecurityKeys calls, a KeySource
// that pulls the keys of a SecurityGroup from an SKS and keeps them fresh,
// and a helper that pushes the keys of a local KeyService to a Publisher or
// Subscriber.
package sks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// Result is the result of GetSecurityKeys.
type Result = security.SecurityKeys

// Method NodeIds of the standard PublishSubscribe object.
var (
	publishSubscribe = ua.NewNumericNodeID(0, id.PublishSubscribe)
	getSecurityKeys  = ua.NewNumericNodeID(0, id.PublishSubscribeGetSecurityKeys)
	setSecurityKeys  = ua.NewNumericNodeID(0, id.PublishSubscribeSetSecurityKeys)
)

// ErrBadResponse is returned for a GetSecurityKeys response that does not
// have the output arguments of the method.
var ErrBadResponse = errors.New("pubsub/sks: malformed GetSecurityKeys response")

// GetSecurityKeys calls PublishSubscribe.GetSecurityKeys (i=15215) on the
// SKS c is connected to. startingTokenID 0 asks for the current key;
// requestedKeyCount is the number of future keys wanted (the SKS caps it).
// The SKS only answers over a SignAndEncrypt session. A Bad method result
// is returned as an error wrapping the ua.StatusCode.
func GetSecurityKeys(ctx context.Context, c *opcua.Client, securityGroupID string, startingTokenID, requestedKeyCount uint32) (*Result, error) {
	res, err := c.CallMethod(ctx, publishSubscribe, getSecurityKeys, securityGroupID, startingTokenID, requestedKeyCount)
	if err != nil {
		return nil, fmt.Errorf("pubsub/sks: GetSecurityKeys: %w", err)
	}
	if res.StatusCode != ua.StatusOK {
		return nil, fmt.Errorf("pubsub/sks: GetSecurityKeys %q: %w", securityGroupID, res.StatusCode)
	}
	return parseResult(res.OutputArguments)
}

// parseResult decodes the output arguments SecurityPolicyUri,
// FirstTokenId, Keys, TimeToNextKey and KeyLifetime.
func parseResult(out []*ua.Variant) (*Result, error) {
	if len(out) < 5 {
		return nil, fmt.Errorf("%w: %d output arguments", ErrBadResponse, len(out))
	}
	uri, ok1 := out[0].Value().(string)
	first, ok2 := out[1].Value().(uint32)
	keys, ok3 := out[2].Value().([][]byte)
	ttnk, ok4 := out[3].Value().(float64)
	life, ok5 := out[4].Value().(float64)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return nil, fmt.Errorf("%w: argument types", ErrBadResponse)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no keys", ErrBadResponse)
	}
	return &Result{
		SecurityPolicyURI: uri,
		FirstTokenID:      first,
		Keys:              keys,
		TimeToNextKey:     msDuration(ttnk),
		KeyLifetime:       msDuration(life),
	}, nil
}

// SetSecurityKeys calls PublishSubscribe.SetSecurityKeys (i=17364) on the
// Publisher or Subscriber c is connected to, pushing keys for a
// SecurityGroup: keys.Keys[0] is the current key with token id
// keys.FirstTokenID, the rest are future keys.
func SetSecurityKeys(ctx context.Context, c *opcua.Client, securityGroupID string, keys *Result) error {
	if keys == nil || len(keys.Keys) == 0 {
		return errors.New("pubsub/sks: SetSecurityKeys: no keys")
	}
	future := keys.Keys[1:]
	if future == nil {
		future = [][]byte{}
	}
	res, err := c.CallMethod(ctx, publishSubscribe, setSecurityKeys,
		securityGroupID, keys.SecurityPolicyURI, keys.FirstTokenID, keys.Keys[0], future,
		durationMS(keys.TimeToNextKey), durationMS(keys.KeyLifetime))
	if err != nil {
		return fmt.Errorf("pubsub/sks: SetSecurityKeys: %w", err)
	}
	if res.StatusCode != ua.StatusOK {
		return fmt.Errorf("pubsub/sks: SetSecurityKeys %q: %w", securityGroupID, res.StatusCode)
	}
	return nil
}

// Push sends the current and all future keys of a SecurityGroup of a local
// KeyService to the server c is connected to with SetSecurityKeys. Call it
// again after every key change (KeyLifetime) to keep the target supplied.
func Push(ctx context.Context, ks *security.KeyService, c *opcua.Client, securityGroupID string) error {
	keys, err := ks.GetSecurityKeys(securityGroupID, 0, math.MaxUint32)
	if err != nil {
		return fmt.Errorf("pubsub/sks: push: %w", err)
	}
	return SetSecurityKeys(ctx, c, securityGroupID, keys)
}

func durationMS(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func msDuration(ms float64) time.Duration {
	if math.IsNaN(ms) || ms <= 0 {
		return 0
	}
	if ms >= float64(math.MaxInt64/int64(time.Millisecond)) {
		return math.MaxInt64
	}
	return time.Duration(ms * float64(time.Millisecond))
}
