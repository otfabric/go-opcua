// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uamethod"
)

// The SecurityKeyServer of a set (Part 81 §6.8.2, §9.3, F.1.10): with
// Options.SecurityKeyServer an establish run adds the SecurityGroups of the
// set to the SKS before it configures the AutomationComponents (§6.7.3.2;
// E.5 recommends this order for the pull model), and tells the
// AutomationComponents where to pull the keys from (E.5: "SecurityKeyServer
// and SecurityGroupIds ... are configured by the ConnectionManager on the
// AutomationComponent as part of the EstablishConnections Call"), as the
// SecurityKeyServices of OPC 10000-14 §6.2.5.4. A remove run whose
// endpoints were all removed removes the SecurityGroups again (§6.7.3.3).

// ErrSKSConnection is in the chain of an error of a SecurityKeyServer when
// no session with the SKS could be opened: the Connections of the set fail
// with ExternalSksConnectionError (§10.25). Any other error of a
// SecurityKeyServer is ExternalSksProcessingError.
var ErrSKSConnection = errors.New("fxcm: no session with the SKS")

// SecurityKeyServer configures SecurityGroups on the SKS of a set: the
// SecurityKeyServerAddress (§10.45) has the current values of the
// SecurityKeyServer of the set (§9.3). LocalSKS is a KeyService in the
// process of the ConnectionManager (§9.3: "If the SKS is co-located with
// the ConnectionManager, the ConnectionManager may use internal
// vendor-specific communication with the SKS"), RemoteSKS a server with the
// SKS Methods of OPC 10000-14 §8.
type SecurityKeyServer interface {
	// AddSecurityGroup adds the SecurityGroup g, or finds one with its
	// parameters (OPC 10000-14 §8.5.2); created reports that it added
	// it. A SecurityGroup with the Name and other parameters is an error.
	AddSecurityGroup(ctx context.Context, sks uafx.SecurityKeyServerAddress, g *ua.SecurityGroupDataType) (created bool, err error)
	// RemoveSecurityGroup removes the SecurityGroup (OPC 10000-14
	// §8.5.3); one the SKS does not have is no error.
	RemoveSecurityGroup(ctx context.Context, sks uafx.SecurityKeyServerAddress, securityGroupID string) error
}

// SecurityGroupRecord is a SecurityGroup a Manager added to an SKS, which
// it removes when no set lists it any more.
type SecurityGroupRecord struct {
	// Address, SecurityPolicyURI and ServerURI are those of the
	// SecurityKeyServer of the set it was added for (§9.3); Address and
	// ServerURI identify the SKS.
	Address, SecurityPolicyURI, ServerURI string
	SecurityGroupID                       string
}

// LocalSKS is a SecurityKeyServer of a KeyService in the process of the
// ConnectionManager, such as the one a server serves with
// server.EnableSecurityKeyService. The address of the set is not used.
type LocalSKS struct {
	KeyService *security.KeyService
}

// AddSecurityGroup implements SecurityKeyServer.
func (l *LocalSKS) AddSecurityGroup(_ context.Context, _ uafx.SecurityKeyServerAddress, g *ua.SecurityGroupDataType) (bool, error) {
	cfg, err := groupConfig(g)
	if err != nil {
		return false, err
	}
	err = l.KeyService.AddSecurityGroup(cfg)
	if err == nil {
		return true, nil
	}
	if have, ok := l.KeyService.SecurityGroup(cfg.SecurityGroupID); ok && errors.Is(err, ua.StatusBadNodeIDExists) && sameGroup(have, cfg) {
		return false, nil
	}
	return false, err
}

// RemoveSecurityGroup implements SecurityKeyServer.
func (l *LocalSKS) RemoveSecurityGroup(_ context.Context, _ uafx.SecurityKeyServerAddress, securityGroupID string) error {
	// Bad_NotFound: there is no such SecurityGroup.
	if err := l.KeyService.RemoveSecurityGroup(securityGroupID); !errors.Is(err, ua.StatusBadNotFound) {
		return err
	}
	return nil
}

// RemoteSKS is a SecurityKeyServer reached with Dialer, always with
// SecurityMode SignAndEncrypt (§9.3), the SecurityPolicyUri and the
// ServerUri of the set: AddSecurityGroup and RemoveSecurityGroup of
// PublishSubscribe.SecurityGroups, GetSecurityGroup of PublishSubscribe
// (OPC 10000-14 §8.5.2, §8.5.3, §8.3.3), one session per operation. The
// identity of the Dialer must be allowed to configure the SKS.
type RemoteSKS struct {
	Dialer Dialer
}

func (r *RemoteSKS) dial(ctx context.Context, sks uafx.SecurityKeyServerAddress) (Session, error) {
	s, err := r.Dialer.Dial(ctx, ServerAddress{
		Address: sks.Address, SecurityMode: ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: sks.SecurityPolicyURI, ServerURI: sks.ServerURI,
	})
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrSKSConnection, sks.Address, err)
	}
	return s, nil
}

// callSKS calls a Method of an SKS with the InputArguments of its contract
// (package uamethod).
func callSKS(ctx context.Context, s Session, object, method uint32, in []*ua.Variant) (*ua.CallMethodResult, error) {
	return s.Call(ctx, &ua.CallMethodRequest{ObjectID: ua.NewNumericNodeID(0, object), MethodID: ua.NewNumericNodeID(0, method), InputArguments: in})
}

// AddSecurityGroup implements SecurityKeyServer.
func (r *RemoteSKS) AddSecurityGroup(ctx context.Context, sks uafx.SecurityKeyServerAddress, g *ua.SecurityGroupDataType) (bool, error) {
	cfg, err := groupConfig(g)
	if err != nil {
		return false, err
	}
	s, err := r.dial(ctx, sks)
	if err != nil {
		return false, err
	}
	defer func() { _ = s.Close(context.WithoutCancel(ctx)) }()
	in := uamethod.SecurityGroupFolderTypeAddSecurityGroupInput{
		SecurityGroupName: cfg.SecurityGroupID,
		KeyLifetime:       g.KeyLifetime,
		SecurityPolicyURI: cfg.SecurityPolicyURI,
		MaxFutureKeyCount: cfg.MaxFutureKeyCount,
		MaxPastKeyCount:   cfg.MaxPastKeyCount,
	}
	res, err := callSKS(ctx, s, id.PublishSubscribeSecurityGroups, id.PublishSubscribeSecurityGroupsAddSecurityGroup, in.Pack())
	switch {
	case err != nil:
		return false, fmt.Errorf("fxcm: AddSecurityGroup %q: %w", cfg.SecurityGroupID, err)
	case res.StatusCode == ua.StatusGoodDataIgnored:
		return false, nil
	case bad(res.StatusCode):
		return false, fmt.Errorf("fxcm: AddSecurityGroup %q: %w", cfg.SecurityGroupID, res.StatusCode)
	}
	return true, nil
}

// RemoveSecurityGroup implements SecurityKeyServer.
func (r *RemoteSKS) RemoveSecurityGroup(ctx context.Context, sks uafx.SecurityKeyServerAddress, securityGroupID string) error {
	s, err := r.dial(ctx, sks)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close(context.WithoutCancel(ctx)) }()
	get := uamethod.PubSubKeyServiceTypeGetSecurityGroupInput{SecurityGroupID: securityGroupID}
	res, err := callSKS(ctx, s, id.PublishSubscribe, id.PublishSubscribeGetSecurityGroup, get.Pack())
	if err != nil {
		return fmt.Errorf("fxcm: GetSecurityGroup %q: %w", securityGroupID, err)
	}
	if st := res.StatusCode; st == ua.StatusBadNoMatch || st == ua.StatusBadNotFound {
		// §8.3.3 Bad_NoMatch: there is no such SecurityGroup (Bad_NotFound
		// from SKSs that answer so).
		return nil
	}
	var out uamethod.PubSubKeyServiceTypeGetSecurityGroupOutput
	if bad(res.StatusCode) || out.Unpack(res.OutputArguments) != nil || out.SecurityGroupNodeID == nil {
		return fmt.Errorf("fxcm: GetSecurityGroup %q: %w", securityGroupID, orBad(res.StatusCode))
	}
	remove := uamethod.SecurityGroupFolderTypeRemoveSecurityGroupInput{SecurityGroupNodeID: out.SecurityGroupNodeID}
	res, err = callSKS(ctx, s, id.PublishSubscribeSecurityGroups, id.PublishSubscribeSecurityGroupsRemoveSecurityGroup, remove.Pack())
	switch {
	case err != nil:
		return fmt.Errorf("fxcm: RemoveSecurityGroup %q: %w", securityGroupID, err)
	case res.StatusCode == ua.StatusBadNodeIDUnknown:
		return nil // removed meanwhile
	case bad(res.StatusCode):
		return fmt.Errorf("fxcm: RemoveSecurityGroup %q: %w", securityGroupID, res.StatusCode)
	}
	return nil
}

// orBad is st, or Bad_UnexpectedError for a Good result without the
// output a Method has.
func orBad(st ua.StatusCode) ua.StatusCode {
	if bad(st) {
		return st
	}
	return ua.StatusBadUnexpectedError
}

// groupConfig is the SecurityGroupConfig of g, checked by checkGroup.
func groupConfig(g *ua.SecurityGroupDataType) (security.SecurityGroupConfig, error) {
	if err := checkGroup(g); err != nil {
		return security.SecurityGroupConfig{}, err
	}
	return security.SecurityGroupConfig{
		SecurityGroupID:   groupID(g),
		SecurityPolicyURI: g.SecurityPolicyURI,
		KeyLifetime:       time.Duration(g.KeyLifetime * float64(time.Millisecond)),
		MaxFutureKeyCount: g.MaxFutureKeyCount,
		MaxPastKeyCount:   g.MaxPastKeyCount,
	}, nil
}

// groupID is the SecurityGroupId of g: its Name when it has none (OPC
// 10000-14 §6.2.12.2: "The SecurityGroupId shall match the Name field").
func groupID(g *ua.SecurityGroupDataType) string {
	if g.SecurityGroupID != "" {
		return g.SecurityGroupID
	}
	return g.Name
}

// checkGroup checks a SecurityGroup of a set: a Name, a SecurityGroupId
// that is empty or the Name (OPC 10000-14 §6.2.12.2), a KeyLifetime the SKS
// can take. Library interpretation: AddSecurityGroup has no argument for
// RolePermissions and GroupProperties (§8.5.2), and a SecurityGroupFolder
// needs the folder Methods of §8.5.4; a SecurityGroup with any of them is
// Bad_NotSupported rather than added without them.
func checkGroup(g *ua.SecurityGroupDataType) error {
	switch {
	case g == nil || g.Name == "":
		return configError(ua.StatusBadConfigurationError, "a SecurityGroup without a Name")
	case g.SecurityGroupID != "" && g.SecurityGroupID != g.Name:
		return configError(ua.StatusBadConfigurationError, "the SecurityGroupId %q of the SecurityGroup %q is not its Name (OPC 10000-14 §6.2.12.2)", g.SecurityGroupID, g.Name)
	case math.IsNaN(g.KeyLifetime) || g.KeyLifetime <= 0 || g.KeyLifetime > float64(math.MaxInt64/int64(time.Millisecond)):
		return configError(ua.StatusBadConfigurationError, "the KeyLifetime %v of the SecurityGroup %q", g.KeyLifetime, g.Name)
	case len(g.RolePermissions) > 0, len(g.GroupProperties) > 0, len(g.SecurityGroupFolder) > 0:
		return configError(ua.StatusBadNotSupported, "the SecurityGroup %q has RolePermissions, GroupProperties or a SecurityGroupFolder", g.Name)
	}
	return nil
}

// sameGroup reports whether a has the parameters of b (OPC 10000-14
// §8.5.2).
func sameGroup(a, b security.SecurityGroupConfig) bool {
	return a.SecurityPolicyURI == b.SecurityPolicyURI && a.KeyLifetime == b.KeyLifetime &&
		a.MaxFutureKeyCount == b.MaxFutureKeyCount && a.MaxPastKeyCount == b.MaxPastKeyCount &&
		slices.Equal(a.SecurityGroupFolder, b.SecurityGroupFolder)
}

// sksAddress is the SecurityKeyServerAddress of the current values of the
// SecurityKeyServer of a set (§9.3, §10.45).
func sksAddress(c *uafx.SecurityKeyServerAddressConf) uafx.SecurityKeyServerAddress {
	return uafx.SecurityKeyServerAddress{Address: c.Address, SecurityPolicyURI: c.SecurityPolicyURI, ServerURI: c.ServerURI, UsePushModel: c.UsePushModel}
}

func sksKey(address, serverURI, securityGroupID string) string {
	return "sks/" + hashKey(address, serverURI, securityGroupID)
}

func (r SecurityGroupRecord) key() string { return sksKey(r.Address, r.ServerURI, r.SecurityGroupID) }

// sksOf returns the SecurityKeyServer of the set c when the Manager
// configures one for it: a SecurityKeyServer with SecurityGroups or
// PubSubKeyPushTargets (§6.7.3.2: an empty entry is skipped).
func (m *Manager) sksOf(c *Config) *uafx.SecurityKeyServerAddressConf {
	s := c.conf.SecurityKeyServer
	if m.opts.SecurityKeyServer == nil || nullSKS(s) || len(s.SecurityGroups) == 0 && len(s.PubSubKeyPushTargets) == 0 {
		return nil
	}
	return s
}

// lists reports whether the set c has the SecurityGroup r on its SKS.
func lists(c *Config, r SecurityGroupRecord) bool {
	s := c.conf.SecurityKeyServer
	if nullSKS(s) || s.Address != r.Address || s.ServerURI != r.ServerURI {
		return false
	}
	return slices.ContainsFunc(s.SecurityGroups, func(g *ua.SecurityGroupDataType) bool { return g != nil && groupID(g) == r.SecurityGroupID })
}

// SecurityGroups returns the SecurityGroups the Manager added to an SKS and
// has not removed (with a Store also those of before a restart), sorted.
func (m *Manager) SecurityGroups() []SecurityGroupRecord {
	m.sksMu.Lock()
	defer m.sksMu.Unlock()
	out := make([]SecurityGroupRecord, 0, len(m.sks))
	for _, r := range m.sks {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// own records r as added by the Manager, durably with a Store.
func (m *Manager) own(r SecurityGroupRecord, on bool) error {
	if m.p != nil {
		b := fxstore.Batch{Deletes: []string{r.key()}}
		var err error
		if on {
			var v []byte
			v, err = encodeRecord(&sksRecord{Address: r.Address, SecurityPolicyURI: r.SecurityPolicyURI, ServerURI: r.ServerURI, SecurityGroupID: r.SecurityGroupID})
			b = fxstore.Batch{Puts: map[string][]byte{r.key(): v}}
		}
		o := fxstore.NotCommitted
		if err == nil {
			o, err = m.p.write(b, 0)
		}
		if o != fxstore.Committed {
			return storeError(o, err)
		}
	}
	m.sksMu.Lock()
	defer m.sksMu.Unlock()
	if on {
		m.sks[r.key()] = r
	} else {
		delete(m.sks, r.key())
	}
	return nil
}

// sksFailure is the Failure of an error of the SKS step.
func sksFailure(err error) uafx.FxError {
	var ce *statusError
	switch {
	case errors.Is(err, ErrSKSConnection):
		return uafx.FxErrorExternalSksConnectionError
	case errors.As(err, &ce) && ce.sentinel == ErrConfig:
		return uafx.FxErrorConnectionConfigurationSetInvalid
	case errors.Is(err, errStore):
		return uafx.FxErrorRuntimeError
	}
	return uafx.FxErrorExternalSksProcessingError
}

// failAll fails every endpoint of the run with err: the SKS of a set is
// the set's, so its failure affects every Connection (§10.19 NOTE).
func (x *run) failAll(err error) {
	fx := sksFailure(err)
	for _, ep := range x.eps {
		x.failErr(ep, err, fx)
	}
}

// configureSKS adds the SecurityGroups of the set to its SKS (§6.7.3.2)
// and reports whether the run may go on. The push model is not supported:
// a set with UsePushModel or PubSubKeyPushTargets fails with
// ConnectionConfigurationSetInvalid and Bad_NotSupported (the SKS would
// need AddPushTarget and ConnectSecurityGroups, E.5).
func (x *run) configureSKS(ctx context.Context) bool {
	conf := x.m.sksOf(x.cfg)
	if conf == nil {
		return true
	}
	if conf.UsePushModel || len(conf.PubSubKeyPushTargets) > 0 {
		x.failAll(configError(ua.StatusBadNotSupported, "the SKS push model (UsePushModel, PubSubKeyPushTargets) is not supported"))
		return false
	}
	for _, g := range conf.SecurityGroups {
		if err := checkGroup(g); err != nil {
			x.failAll(err)
			return false
		}
	}
	at := sksAddress(conf)
	x.m.sksStep.Lock()
	defer x.m.sksStep.Unlock()
	for _, g := range conf.SecurityGroups {
		cctx, cancel := context.WithTimeout(ctx, x.m.opts.CallTimeout)
		created, err := x.m.opts.SecurityKeyServer.AddSecurityGroup(cctx, at, g)
		cancel()
		if err == nil && created {
			err = x.m.own(SecurityGroupRecord{Address: at.Address, SecurityPolicyURI: at.SecurityPolicyURI, ServerURI: at.ServerURI, SecurityGroupID: groupID(g)}, true)
		}
		if err != nil {
			x.failAll(err)
			return false
		}
		x.m.log.Debug("fxcm: SecurityGroup on the SKS", "set", x.r.key.String(), "run", x.r.id, "sks", at.Address, "group", groupID(g), "created", created)
	}
	return true
}

// removeSKS removes from their SKS the SecurityGroups the Manager added
// that no other set in use lists (§6.7.3.3), after a remove run of x's set
// that removed all its endpoints. A set is in use while it has endpoints or
// a run. A failure fails the run with
// ExternalSksConnectionError or ExternalSksProcessingError; the record
// stays, and a later remove run tries again.
func (x *run) removeSKS(ctx context.Context) {
	if x.m.opts.SecurityKeyServer == nil {
		return
	}
	x.m.sksStep.Lock()
	defer x.m.sksStep.Unlock()
	owned := x.m.SecurityGroups()
	if len(owned) == 0 {
		return
	}
	x.m.mu.Lock()
	others := make([]*set, 0, len(x.m.sets))
	for _, s := range x.m.sets {
		if s != x.s {
			others = append(others, s)
		}
	}
	x.m.mu.Unlock()
	var cfgs []*Config
	for _, s := range others {
		s.mu.Lock()
		if !s.removed && (len(s.records) > 0 || s.current != nil) {
			cfgs = append(cfgs, s.cfg)
		}
		s.mu.Unlock()
	}
	for _, r := range owned {
		if slices.ContainsFunc(cfgs, func(c *Config) bool { return lists(c, r) }) {
			continue
		}
		at := uafx.SecurityKeyServerAddress{Address: r.Address, SecurityPolicyURI: r.SecurityPolicyURI, ServerURI: r.ServerURI}
		cctx, cancel := context.WithTimeout(ctx, x.m.opts.CallTimeout)
		err := x.m.opts.SecurityKeyServer.RemoveSecurityGroup(cctx, at, r.SecurityGroupID)
		cancel()
		if err == nil {
			err = x.m.own(r, false)
		}
		if err != nil {
			x.m.log.Warn("fxcm: a SecurityGroup was not removed from the SKS", "set", x.r.key.String(), "run", x.r.id, "sks", r.Address, "group", r.SecurityGroupID, "error", err)
			x.extraFailure(failureOf(err, sksFailure(err)))
			continue
		}
		x.m.log.Debug("fxcm: SecurityGroup removed from the SKS", "set", x.r.key.String(), "run", x.r.id, "sks", r.Address, "group", r.SecurityGroupID)
	}
}

// securityKeyService is the element of the SecurityKeyServices of the
// groups of a set that pull their keys from its SKS (OPC 10000-14 §6.2.5.4
// Table 40): no EndpointUrl, the ServerUri as the ApplicationUri, the
// Address as the DiscoveryUrl, ApplicationType SERVER for the pull model,
// SignAndEncrypt and the SecurityPolicyUri.
func securityKeyService(c *uafx.SecurityKeyServerAddressConf) *ua.EndpointDescription {
	return &ua.EndpointDescription{
		Server: &ua.ApplicationDescription{
			ApplicationURI: c.ServerURI, ApplicationType: ua.ApplicationTypeServer, DiscoveryURLs: []string{c.Address},
		},
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: c.SecurityPolicyURI,
	}
}

// fillSecurityKeyServices sets the SecurityKeyServices of the secured
// WriterGroups, ReaderGroups and DataSetReaders of cfg whose
// SecurityGroupId is one of the set's and that name no SKS of their own to
// the SKS of the set (E.5). Without an Address the ConnectionManager has
// no SKS to name (a co-located SKS, §9.3): the configuration is left as it
// is.
func (m *Manager) fillSecurityKeyServices(c *Config, cfg *ua.PubSubConfiguration2DataType) {
	conf := m.sksOf(c)
	if conf == nil || conf.Address == "" || conf.UsePushModel {
		return
	}
	ids := map[string]bool{}
	for _, g := range conf.SecurityGroups {
		if g != nil {
			ids[groupID(g)] = true
		}
	}
	fill := func(mode ua.MessageSecurityMode, gid string, eps *[]*ua.EndpointDescription) {
		if (mode == ua.MessageSecurityModeSign || mode == ua.MessageSecurityModeSignAndEncrypt) && ids[gid] && len(*eps) == 0 {
			*eps = []*ua.EndpointDescription{securityKeyService(conf)}
		}
	}
	for _, cn := range cfg.Connections {
		if cn == nil {
			continue
		}
		for _, g := range cn.WriterGroups {
			if g != nil {
				fill(g.SecurityMode, g.SecurityGroupID, &g.SecurityKeyServices)
			}
		}
		for _, g := range cn.ReaderGroups {
			if g == nil {
				continue
			}
			fill(g.SecurityMode, g.SecurityGroupID, &g.SecurityKeyServices)
			for _, r := range g.DataSetReaders {
				if r != nil {
					fill(r.SecurityMode, r.SecurityGroupID, &r.SecurityKeyServices)
				}
			}
		}
	}
}
