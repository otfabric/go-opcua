// SPDX-License-Identifier: MIT

package server

import (
	"context"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// pubsubConfigMethods are the methods of the PubSub configuration model
// (Part 14 §9.1) that namespace 0 declares without RolePermissions. They
// receive the RolePermissions of PublishSubscribe.AddConnection, which the
// standard NodeSet grants to ConfigureAdmin, so that an RBACAccessController
// restricts all of them alike.
var pubsubConfigMethods = []uint32{
	id.PubSubStatusTypeEnable,
	id.PubSubStatusTypeDisable,
	id.DataSetFolderTypeAddPublishedDataItems,
	id.DataSetFolderTypeAddPublishedDataItemsTemplate,
	id.DataSetFolderTypeRemovePublishedDataSet,
	id.PubSubConnectionTypeAddWriterGroup,
	id.PubSubConnectionTypeAddReaderGroup,
	id.PubSubConnectionTypeRemoveGroup,
	id.WriterGroupTypeAddDataSetWriter,
	id.WriterGroupTypeRemoveDataSetWriter,
	id.ReaderGroupTypeAddDataSetReader,
	id.ReaderGroupTypeRemoveDataSetReader,
	id.PublishSubscribePubSubConfigurationOpen,
	id.PublishSubscribePubSubConfigurationClose,
	id.PublishSubscribePubSubConfigurationRead,
	id.PublishSubscribePubSubConfigurationWrite,
	id.PublishSubscribePubSubConfigurationGetPosition,
	id.PublishSubscribePubSubConfigurationSetPosition,
	id.PublishSubscribePubSubConfigurationReserveIDs,
	id.PublishSubscribePubSubConfigurationCloseAndUpdate,
}

// restrictPubSubMethods gives the PubSub configuration methods without
// RolePermissions those of AddConnection.
func (s *Server) restrictPubSubMethods() {
	def, ok := DefaultNodePermissions[id.PublishSubscribeAddConnection]
	if !ok || len(def.RolePermissions) == 0 {
		return
	}
	for _, mid := range pubsubConfigMethods {
		n := s.ownNode(mid)
		if n == nil {
			continue
		}
		n.mu.Lock()
		if len(n.rolePermissions) == 0 {
			perms := make([]*ua.RolePermissionType, len(def.RolePermissions))
			for i := range def.RolePermissions {
				rp := def.RolePermissions[i]
				perms[i] = &rp
			}
			n.rolePermissions = perms
		}
		n.mu.Unlock()
	}
}

// callerSession returns the session of a configuration method call, nil
// when the configuration does not come from a client.
func (m *pubsubModel) callerSession(ctx context.Context) (*session, bool) {
	c, ok := MethodCallerFromContext(ctx)
	if !ok || c.SessionID == nil {
		return nil, false
	}
	for _, s := range m.s.sb.all() {
		if s.ID.Equal(c.SessionID) {
			return s, true
		}
	}
	return nil, true
}

// checkConnectionTargets is checkReaderTargets for the readers of
// connections.
func (m *pubsubModel) checkConnectionTargets(ctx context.Context, conns ...*ua.PubSubConnectionDataType) ua.StatusCode {
	for _, c := range conns {
		if c == nil {
			continue
		}
		if st := m.checkGroupTargets(ctx, c.ReaderGroups...); st != ua.StatusOK {
			return st
		}
	}
	return ua.StatusOK
}

// checkGroupTargets is checkReaderTargets for the readers of reader groups.
func (m *pubsubModel) checkGroupTargets(ctx context.Context, groups ...*ua.ReaderGroupDataType) ua.StatusCode {
	for _, g := range groups {
		if g == nil {
			continue
		}
		if st := m.checkReaderTargets(ctx, g.DataSetReaders...); st != ua.StatusOK {
			return st
		}
	}
	return ua.StatusOK
}

// checkReaderTargets authorizes the TargetVariables of readers a client
// configures: the runtime writes them with the authority of the server, so
// the configuring session must be allowed to write each target as with the
// Write service. The Value needs CheckWrite of the AccessController and the
// CurrentWrite bit of AccessLevel / UserAccessLevel (Part 3 §5.6.2); any other
// Attribute needs CheckWrite and its WriteMask / UserWriteMask bit (Part 3
// §5.2.7, §5.2.8). A target that does not exist is left to the runtime,
// whose writes then fail with Bad_NodeIdUnknown.
func (m *pubsubModel) checkReaderTargets(ctx context.Context, readers ...*ua.DataSetReaderDataType) ua.StatusCode {
	sess, client := m.callerSession(ctx)
	if !client {
		return ua.StatusOK
	}
	for _, r := range readers {
		if r == nil || r.SubscribedDataSet == nil {
			continue
		}
		tv, ok := r.SubscribedDataSet.Value.(*ua.TargetVariablesDataType)
		if !ok || tv == nil {
			continue
		}
		for _, t := range tv.TargetVariables {
			if st := m.s.checkTargetWrite(ctx, sess, t); st != ua.StatusOK {
				return st
			}
		}
	}
	return ua.StatusOK
}

// checkTargetWrite authorizes one target of a reader for sess.
func (s *Server) checkTargetWrite(ctx context.Context, sess *session, t *ua.FieldTargetDataType) ua.StatusCode {
	if t == nil || t.TargetNodeID == nil {
		return ua.StatusOK
	}
	if st := s.checkWrite(ctx, sess, t.TargetNodeID); st != ua.StatusOK {
		return st
	}
	n := s.Node(t.TargetNodeID)
	if n == nil {
		return ua.StatusOK
	}
	if t.AttributeID == 0 || t.AttributeID == ua.AttributeIDValue {
		return n.AccessStatus(ua.AccessLevelTypeCurrentWrite)
	}
	ns, err := s.Namespace(int(t.TargetNodeID.Namespace()))
	if err != nil {
		return ua.StatusBadNodeIDUnknown
	}
	return attributeWritable(ns, t.TargetNodeID, t.AttributeID)
}

// attributeWritable is checkAttributeWrite without the value: the WriteMask
// rules of a non-Value Attribute. checkAttributeWrite checks the type of
// the value last, so a type mismatch of the missing value means writable.
func attributeWritable(ns NameSpace, nid *ua.NodeID, attr ua.AttributeID) ua.StatusCode {
	st := checkAttributeWrite(ns, nid, attr, nil)
	if st == ua.StatusBadTypeMismatch {
		return ua.StatusOK
	}
	return st
}

// checkPublishedRead authorizes a published variable a client configures:
// the runtime reads it with the authority of the server, so the session
// must be allowed to read it (CheckRead of the AccessController).
func (m *pubsubModel) checkPublishedRead(ctx context.Context, v *ua.PublishedVariableDataType) ua.StatusCode {
	sess, client := m.callerSession(ctx)
	if !client || v == nil || v.PublishedVariable == nil {
		return ua.StatusOK
	}
	return m.s.checkRead(ctx, sess, v.PublishedVariable)
}
