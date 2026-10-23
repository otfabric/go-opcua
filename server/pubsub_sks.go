// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	pubsubsec "github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// DefaultSKSNamespaceURI is the namespace the nodes of SecurityGroups are
// created in unless SKSNamespace selects another one.
const DefaultSKSNamespaceURI = "urn:otfabric:go-opcua:pubsub:sks"

// accessRestrictionEncryptionRequired is the AccessRestrictions of the
// Security Key Service methods: they must be called over an encrypted
// channel (Part 14 §8.3, §8.4).
const accessRestrictionEncryptionRequired = uint16(ua.AccessRestrictionTypeEncryptionRequired)

// SKSOption configures EnableSecurityKeyService and EnableSecurityKeyPush.
type SKSOption func(*sksOptions)

type sksOptions struct {
	ns         *NodeNameSpace
	authorizer pubsubsec.Authorizer
}

// SKSNamespace selects the namespace the SecurityGroup and
// SecurityGroupFolder nodes are created in (default: a namespace with the
// URI DefaultSKSNamespaceURI).
func SKSNamespace(ns *NodeNameSpace) SKSOption {
	return func(o *sksOptions) { o.ns = ns }
}

// SKSAuthorizer sets the Authorizer of SetSecurityKeys for
// EnableSecurityKeyPush (default pubsubsec.DefaultAuthorizer). The methods
// of EnableSecurityKeyService use the Authorizer of the KeyService.
func SKSAuthorizer(a pubsubsec.Authorizer) SKSOption {
	return func(o *sksOptions) { o.authorizer = a }
}

// SecurityKeyService is a KeyService published in the address space of a
// server by [Server.EnableSecurityKeyService].
type SecurityKeyService struct {
	srv    *Server
	ks     *pubsubsec.KeyService
	ns     *NodeNameSpace
	cancel func()

	mu      sync.Mutex
	groups  map[string]*Node // SecurityGroupId -> SecurityGroup node
	folders map[string]*Node // escaped folder path -> SecurityGroupFolder node
	byNode  map[string]string
}

// EnableSecurityKeyService makes the server a Security Key Service (Part 14
// §8) for the SecurityGroups of ks. It implements the methods of the
// standard PublishSubscribe object (i=14443):
//
//   - GetSecurityKeys (i=15215): in SecurityGroupId String, StartingTokenId
//     IntegerId, RequestedKeyCount UInt32; out SecurityPolicyUri String,
//     FirstTokenId IntegerId, Keys ByteString[], TimeToNextKey Duration,
//     KeyLifetime Duration.
//   - GetSecurityGroup (i=15440): in SecurityGroupId String; out
//     SecurityGroupNodeId NodeId.
//   - SecurityGroups.AddSecurityGroup (i=15444, and SecurityGroupFolderType
//     AddSecurityGroup i=15461 on every SecurityGroupFolder): in
//     SecurityGroupName String, KeyLifetime Duration, SecurityPolicyUri
//     String, MaxFutureKeyCount UInt32, MaxPastKeyCount UInt32; out
//     SecurityGroupId String, SecurityGroupNodeId NodeId.
//   - SecurityGroups.RemoveSecurityGroup (i=15447, and i=15464 on every
//     SecurityGroupFolder): in SecurityGroupNodeId NodeId.
//
// Every SecurityGroup of ks gets a SecurityGroupType node below
// PublishSubscribe.SecurityGroups (or the SecurityGroupFolder of its
// SecurityGroupFolder path) with the properties SecurityGroupId,
// KeyLifetime, SecurityPolicyUri, MaxFutureKeyCount and MaxPastKeyCount;
// nodes follow groups added or removed later through ks.
//
// The methods only run over a SignAndEncrypt secure channel
// (Bad_SecurityModeInsufficient) and for callers the Authorizer of ks
// allows (Bad_UserAccessDenied). Call it once, before Start.
func (s *Server) EnableSecurityKeyService(ks *pubsubsec.KeyService, opts ...SKSOption) (*SecurityKeyService, error) {
	if ks == nil {
		return nil, errors.New("server: EnableSecurityKeyService: nil KeyService")
	}
	o := s.sksOptions(opts)
	h := &SecurityKeyService{
		srv:     s,
		ks:      ks,
		ns:      o.ns,
		groups:  make(map[string]*Node),
		folders: make(map[string]*Node),
		byNode:  make(map[string]string),
	}
	root := s.Node(ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroups))
	if root == nil {
		return nil, errors.New("server: EnableSecurityKeyService: no PublishSubscribe.SecurityGroups node")
	}
	h.folders[""] = root

	pubSub := ua.NewNumericNodeID(0, id.PublishSubscribe)
	s.RegisterMethod(pubSub, ua.NewNumericNodeID(0, id.PublishSubscribeGetSecurityKeys), h.getSecurityKeys)
	s.RegisterMethod(pubSub, ua.NewNumericNodeID(0, id.PublishSubscribeGetSecurityGroup), h.getSecurityGroup)
	h.registerFolderMethods(root.ID(), true)
	for _, m := range []uint32{
		id.PublishSubscribeGetSecurityKeys, id.PublishSubscribeGetSecurityGroup,
		id.PublishSubscribeSecurityGroupsAddSecurityGroup, id.PublishSubscribeSecurityGroupsRemoveSecurityGroup,
		id.SecurityGroupFolderTypeAddSecurityGroup, id.SecurityGroupFolderTypeRemoveSecurityGroup,
	} {
		s.restrictToEncryption(m)
	}

	h.cancel = ks.OnChange(func(ev pubsubsec.GroupEvent) {
		if ev.Added {
			h.addGroupNode(ev.Config)
		} else {
			h.removeGroupNode(ev.Config.SecurityGroupID)
		}
	})
	for _, cfg := range ks.SecurityGroups() {
		h.addGroupNode(cfg)
	}
	return h, nil
}

// EnableSecurityKeyPush makes the server a target of SetSecurityKeys (Part
// 14 §8.3.4, PublishSubscribe.SetSecurityKeys i=17364): an SKS pushes the
// keys of a SecurityGroup to the KeyRing registered in rings under its
// SecurityGroupId. Arguments: SecurityGroupId String, SecurityPolicyUri
// String, CurrentTokenId IntegerId, CurrentKey ByteString, FutureKeys
// ByteString[], TimeToNextKey Duration, KeyLifetime Duration.
//
// The method only runs over a SignAndEncrypt secure channel and for
// callers the SKSAuthorizer allows. Unknown groups are Bad_NotFound, a
// policy other than the ring's Bad_SecurityPolicyRejected and keys of the
// wrong length Bad_SecurityChecksFailed (as open62541). Call it before
// Start.
func (s *Server) EnableSecurityKeyPush(rings *pubsubsec.KeyRings, opts ...SKSOption) error {
	if rings == nil {
		return errors.New("server: EnableSecurityKeyPush: nil KeyRings")
	}
	o := s.sksOptions(opts)
	s.RegisterMethod(ua.NewNumericNodeID(0, id.PublishSubscribe), ua.NewNumericNodeID(0, id.PublishSubscribeSetSecurityKeys),
		func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			return setSecurityKeys(ctx, rings, o.authorizer, args)
		})
	s.restrictToEncryption(id.PublishSubscribeSetSecurityKeys)
	return nil
}

func (s *Server) sksOptions(opts []SKSOption) sksOptions {
	var o sksOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.ns == nil {
		for _, ns := range s.Namespaces() {
			if nns, ok := ns.(*NodeNameSpace); ok && ns.Name() == DefaultSKSNamespaceURI {
				o.ns = nns
			}
		}
		if o.ns == nil {
			o.ns = NewNodeNameSpace(s, DefaultSKSNamespaceURI)
		}
	}
	return o
}

// restrictToEncryption sets the AccessRestrictions of a namespace 0 method
// node to EncryptionRequired, so that the Call service rejects calls over
// unencrypted channels and clients can see the requirement.
func (s *Server) restrictToEncryption(method uint32) {
	if n := s.Node(ua.NewNumericNodeID(0, method)); n != nil {
		n.mu.Lock()
		n.attr[ua.AttributeIDAccessRestrictions] = DataValueFromValue(accessRestrictionEncryptionRequired)
		n.mu.Unlock()
	}
}

// Close detaches the server from the KeyService: groups added or removed
// later no longer change the address space. The methods stay registered.
func (h *SecurityKeyService) Close() {
	if h.cancel != nil {
		h.cancel()
	}
}

// KeyService returns the KeyService of the server.
func (h *SecurityKeyService) KeyService() *pubsubsec.KeyService { return h.ks }

// SecurityGroupNodeID returns the NodeId of the node of a SecurityGroup.
func (h *SecurityKeyService) SecurityGroupNodeID(securityGroupID string) (*ua.NodeID, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, ok := h.groups[securityGroupID]
	if !ok {
		return nil, false
	}
	return n.ID(), true
}

// SecurityGroupFolderNodeID returns the NodeId of a SecurityGroupFolder by
// its path below PublishSubscribe.SecurityGroups (empty: SecurityGroups).
// Folders are created for the SecurityGroupFolder paths of the groups.
func (h *SecurityKeyService) SecurityGroupFolderNodeID(path ...string) (*ua.NodeID, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, ok := h.folders[folderKey(path)]
	if !ok {
		return nil, false
	}
	return n.ID(), true
}

func folderKey(path []string) string {
	esc := make([]string, len(path))
	for i, p := range path {
		esc[i] = url.PathEscape(p)
	}
	return strings.Join(esc, "/")
}

func (h *SecurityKeyService) registerFolderMethods(folder *ua.NodeID, root bool) {
	add := func(ctx context.Context, obj, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return h.addSecurityGroup(ctx, obj, args)
	}
	remove := func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return h.removeSecurityGroup(ctx, args)
	}
	if root {
		h.srv.RegisterMethod(folder, ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroupsAddSecurityGroup), add)
		h.srv.RegisterMethod(folder, ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroupsRemoveSecurityGroup), remove)
	}
	h.srv.RegisterMethod(folder, ua.NewNumericNodeID(0, id.SecurityGroupFolderTypeAddSecurityGroup), add)
	h.srv.RegisterMethod(folder, ua.NewNumericNodeID(0, id.SecurityGroupFolderTypeRemoveSecurityGroup), remove)
}

// sksCaller converts the MethodCaller of a call for the security package.
func sksCaller(ctx context.Context) *pubsubsec.Caller {
	mc, ok := MethodCallerFromContext(ctx)
	if !ok {
		return nil
	}
	return &pubsubsec.Caller{
		SessionID:         mc.SessionID,
		SecurityPolicyURI: mc.SecurityPolicyURI,
		SecurityMode:      mc.SecurityMode,
		Identity:          mc.Identity,
		Roles:             mc.Roles,
	}
}

// requireEncryption rejects calls over channels that are not encrypted
// before anything else is looked at.
func requireEncryption(c *pubsubsec.Caller) ua.StatusCode {
	if c == nil || c.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
		return ua.StatusBadSecurityModeInsufficient
	}
	return ua.StatusOK
}

func (h *SecurityKeyService) getSecurityKeys(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	c := sksCaller(ctx)
	if st := requireEncryption(c); st != ua.StatusOK {
		return nil, st
	}
	if st := checkArgs(args, ua.TypeIDString, ua.TypeIDUint32, ua.TypeIDUint32); st != ua.StatusOK {
		return nil, st
	}
	gid, _ := args[0].Value().(string)
	start, _ := args[1].Value().(uint32)
	count, _ := args[2].Value().(uint32)
	if _, ok := h.ks.SecurityGroup(gid); !ok {
		return nil, ua.StatusBadNotFound
	}
	if err := h.ks.Authorize(ctx, c, pubsubsec.OpGetSecurityKeys, gid); err != nil {
		return nil, pubsubsec.StatusCode(err)
	}
	r, err := h.ks.GetSecurityKeys(gid, start, count)
	if err != nil {
		return nil, pubsubsec.StatusCode(err)
	}
	return []*ua.Variant{
		ua.MustVariant(r.SecurityPolicyURI),
		ua.MustVariant(r.FirstTokenID),
		ua.MustVariant(r.Keys),
		ua.MustVariant(durationMS(r.TimeToNextKey)),
		ua.MustVariant(durationMS(r.KeyLifetime)),
	}, ua.StatusOK
}

func (h *SecurityKeyService) getSecurityGroup(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	c := sksCaller(ctx)
	if st := requireEncryption(c); st != ua.StatusOK {
		return nil, st
	}
	if st := checkArgs(args, ua.TypeIDString); st != ua.StatusOK {
		return nil, st
	}
	gid, _ := args[0].Value().(string)
	nid, ok := h.SecurityGroupNodeID(gid)
	if !ok {
		return nil, ua.StatusBadNotFound
	}
	if err := h.ks.Authorize(ctx, c, pubsubsec.OpGetSecurityGroup, gid); err != nil {
		return nil, pubsubsec.StatusCode(err)
	}
	return []*ua.Variant{ua.MustVariant(nid)}, ua.StatusOK
}

func (h *SecurityKeyService) addSecurityGroup(ctx context.Context, folder *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	c := sksCaller(ctx)
	if st := requireEncryption(c); st != ua.StatusOK {
		return nil, st
	}
	if st := checkArgs(args, ua.TypeIDString, ua.TypeIDDouble, ua.TypeIDString, ua.TypeIDUint32, ua.TypeIDUint32); st != ua.StatusOK {
		return nil, st
	}
	path, ok := h.folderPath(folder)
	if !ok {
		return nil, ua.StatusBadNodeIDUnknown
	}
	name, _ := args[0].Value().(string)
	lifetime, _ := args[1].Value().(float64)
	uri, _ := args[2].Value().(string)
	maxFuture, _ := args[3].Value().(uint32)
	maxPast, _ := args[4].Value().(uint32)
	if err := h.ks.Authorize(ctx, c, pubsubsec.OpAddSecurityGroup, name); err != nil {
		return nil, pubsubsec.StatusCode(err)
	}
	d, ok := msDuration(lifetime)
	if !ok {
		return nil, ua.StatusBadInvalidArgument
	}
	err := h.ks.AddSecurityGroup(pubsubsec.SecurityGroupConfig{
		SecurityGroupID:     name,
		SecurityPolicyURI:   uri,
		KeyLifetime:         d,
		MaxFutureKeyCount:   maxFuture,
		MaxPastKeyCount:     maxPast,
		SecurityGroupFolder: path,
	})
	if err != nil {
		return nil, pubsubsec.StatusCode(err)
	}
	nid, ok := h.SecurityGroupNodeID(name)
	if !ok { // removed concurrently, or the server was detached
		return nil, ua.StatusBadInternalError
	}
	return []*ua.Variant{ua.MustVariant(name), ua.MustVariant(nid)}, ua.StatusOK
}

func (h *SecurityKeyService) removeSecurityGroup(ctx context.Context, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	c := sksCaller(ctx)
	if st := requireEncryption(c); st != ua.StatusOK {
		return nil, st
	}
	if st := checkArgs(args, ua.TypeIDNodeID); st != ua.StatusOK {
		return nil, st
	}
	nid, _ := args[0].Value().(*ua.NodeID)
	h.mu.Lock()
	gid, ok := "", false
	if nid != nil {
		gid, ok = h.byNode[nid.String()]
	}
	h.mu.Unlock()
	if !ok {
		return nil, ua.StatusBadNodeIDUnknown
	}
	if err := h.ks.Authorize(ctx, c, pubsubsec.OpRemoveSecurityGroup, gid); err != nil {
		return nil, pubsubsec.StatusCode(err)
	}
	if err := h.ks.RemoveSecurityGroup(gid); err != nil {
		return nil, ua.StatusBadNodeIDUnknown
	}
	return nil, ua.StatusOK
}

func setSecurityKeys(ctx context.Context, rings *pubsubsec.KeyRings, a pubsubsec.Authorizer, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	c := sksCaller(ctx)
	if st := requireEncryption(c); st != ua.StatusOK {
		return nil, st
	}
	if st := checkArgs(args, ua.TypeIDString, ua.TypeIDString, ua.TypeIDUint32, ua.TypeIDByteString, ua.TypeIDByteString, ua.TypeIDDouble, ua.TypeIDDouble); st != ua.StatusOK {
		return nil, st
	}
	gid, _ := args[0].Value().(string)
	uri, _ := args[1].Value().(string)
	tokenID, _ := args[2].Value().(uint32)
	current, _ := args[3].Value().([]byte)
	future, _ := args[4].Value().([][]byte)
	if !args[4].IsArray() || args[3].IsArray() {
		return nil, ua.StatusBadTypeMismatch
	}
	ttnk, _ := args[5].Value().(float64)
	lifetime, _ := args[6].Value().(float64)
	ring, ok := rings.Get(gid)
	if !ok {
		return nil, ua.StatusBadNotFound
	}
	if err := pubsubsec.Authorize(ctx, a, c, pubsubsec.OpSetSecurityKeys, gid); err != nil {
		return nil, pubsubsec.StatusCode(err)
	}
	ttnkD, ok1 := msDuration(ttnk)
	lifeD, ok2 := msDuration(lifetime)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadInvalidArgument
	}
	keys := append([][]byte{current}, future...)
	if err := ring.SetKeys(uri, tokenID, keys, ttnkD, lifeD); err != nil {
		return nil, pubsubsec.StatusCode(err)
	}
	return nil, ua.StatusOK
}

// checkArgs checks the number and built-in types of method arguments (the
// Call service validates them against the InputArguments too; this guards
// against a node without them).
func checkArgs(args []*ua.Variant, types ...ua.TypeID) ua.StatusCode {
	if len(args) < len(types) {
		return ua.StatusBadArgumentsMissing
	}
	if len(args) > len(types) {
		return ua.StatusBadTooManyArguments
	}
	for i, t := range types {
		if args[i] == nil || args[i].Type() != t {
			return ua.StatusBadTypeMismatch
		}
	}
	return ua.StatusOK
}

// durationMS returns d in milliseconds, the unit of Duration.
func durationMS(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// msDuration converts a Duration in milliseconds; it rejects negative, NaN
// and out of range values.
func msDuration(ms float64) (time.Duration, bool) {
	if math.IsNaN(ms) || ms < 0 || ms > float64(math.MaxInt64/int64(time.Millisecond)) {
		return 0, false
	}
	return time.Duration(ms * float64(time.Millisecond)), true
}

// folderPath returns the SecurityGroupFolder path of a folder node.
func (h *SecurityKeyService) folderPath(folder *ua.NodeID) ([]string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key, n := range h.folders {
		if n.ID().Equal(folder) {
			if key == "" {
				return nil, true
			}
			parts := strings.Split(key, "/")
			for i, p := range parts {
				parts[i], _ = url.PathUnescape(p)
			}
			return parts, true
		}
	}
	return nil, false
}

// folderLocked returns the SecurityGroupFolder node of a path, creating
// the missing folders.
func (h *SecurityKeyService) folderLocked(path []string) *Node {
	parent := h.folders[""]
	for i := range path {
		key := folderKey(path[:i+1])
		f, ok := h.folders[key]
		if !ok {
			f = NewNode(ua.NewStringNodeID(h.ns.ID(), "SecurityGroupFolder/"+key), Attributes{
				ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
				ua.AttributeIDBrowseName:    DataValueFromValue(&ua.QualifiedName{NamespaceIndex: h.ns.ID(), Name: path[i]}),
				ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(path[i], "")),
				ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
				ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
			}, nil, nil)
			h.ns.AddNode(f)
			h.addTypeDefinition(f, id.SecurityGroupFolderType)
			linkChild(parent, f, id.HasComponent)
			for _, m := range []uint32{id.SecurityGroupFolderTypeAddSecurityGroup, id.SecurityGroupFolderTypeRemoveSecurityGroup} {
				if mn := h.srv.Node(ua.NewNumericNodeID(0, m)); mn != nil {
					f.AddRef(mn, RefTypeIDHasComponent, true)
				}
			}
			h.registerFolderMethods(f.ID(), false)
			h.folders[key] = f
		}
		parent = f
	}
	return parent
}

func (h *SecurityKeyService) addGroupNode(cfg pubsubsec.SecurityGroupConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.groups[cfg.SecurityGroupID]; ok {
		return
	}
	parent := h.folderLocked(cfg.SecurityGroupFolder)
	base := "SecurityGroup/" + url.PathEscape(cfg.SecurityGroupID)
	g := NewNode(ua.NewStringNodeID(h.ns.ID(), base), Attributes{
		ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:    DataValueFromValue(&ua.QualifiedName{NamespaceIndex: h.ns.ID(), Name: cfg.SecurityGroupID}),
		ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(cfg.SecurityGroupID, "")),
		ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
	}, nil, nil)
	h.ns.AddNode(g)
	h.addTypeDefinition(g, id.SecurityGroupType)

	props := []struct {
		name     string
		dataType uint32
		value    any
	}{
		{"SecurityGroupId", id.String, cfg.SecurityGroupID},
		{"KeyLifetime", id.Duration, durationMS(cfg.KeyLifetime)},
		{"SecurityPolicyUri", id.String, cfg.SecurityPolicyURI},
		{"MaxFutureKeyCount", id.UInt32, cfg.MaxFutureKeyCount},
		{"MaxPastKeyCount", id.UInt32, cfg.MaxPastKeyCount},
	}
	for _, p := range props {
		dv := DataValueFromValue(p.value)
		pn := NewNode(ua.NewStringNodeID(h.ns.ID(), base+"/"+p.name), Attributes{
			ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{NamespaceIndex: 0, Name: p.name}),
			ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(p.name, "")),
			ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
			ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, p.dataType)),
			ua.AttributeIDValueRank:       DataValueFromValue(int32(-1)),
			ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		}, nil, func() *ua.DataValue { return dv })
		h.ns.AddNode(pn)
		h.addTypeDefinition(pn, id.PropertyType)
		linkChild(g, pn, id.HasProperty)
	}
	linkChild(parent, g, id.HasComponent)
	h.groups[cfg.SecurityGroupID] = g
	h.byNode[g.ID().String()] = cfg.SecurityGroupID
}

func (h *SecurityKeyService) removeGroupNode(securityGroupID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	g, ok := h.groups[securityGroupID]
	if !ok {
		return
	}
	delete(h.groups, securityGroupID)
	delete(h.byNode, g.ID().String())
	for _, ref := range g.refsSnapshot() {
		if ref == nil || ref.NodeID == nil || ref.ReferenceTypeID == nil {
			continue
		}
		switch {
		case ref.IsForward && ref.ReferenceTypeID.IntID() == id.HasProperty:
			_ = h.ns.DeleteNode(ref.NodeID.NodeID)
		case !ref.IsForward && ref.ReferenceTypeID.IntID() == id.HasComponent:
			if parent := h.srv.Node(ref.NodeID.NodeID); parent != nil {
				parent.RemoveRef(ua.NewExpandedNodeID(g.ID(), "", 0), ua.NewNumericNodeID(0, id.HasComponent), true)
			}
		}
	}
	_ = h.ns.DeleteNode(g.ID())
	h.srv.ChangeNotification(g.ID())
}

// addTypeDefinition adds the HasTypeDefinition reference of a node.
func (h *SecurityKeyService) addTypeDefinition(n *Node, typeDef uint32) {
	if t := h.srv.Node(ua.NewNumericNodeID(0, typeDef)); t != nil {
		n.AddRef(t, RefType(id.HasTypeDefinition), true)
	}
}

// linkChild adds the forward reference parent -> child and its inverse.
func linkChild(parent, child *Node, refType uint32) {
	parent.AddRef(child, RefType(refType), true)
	child.AddRef(parent, RefType(refType), false)
}
