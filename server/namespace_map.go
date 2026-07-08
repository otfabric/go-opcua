// SPDX-License-Identifier: MIT

package server

import (
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// MapNamespace provides a convenient way to have data mapped to the OPC server
// without having to map your application data to the OPC-UA data abstraction.
//
// It (currently) supports ints, floats, strings, and timestamps. No maps inside of maps and no arrays.
//
// To notify subscribers of changes, be sure to call ChangeNotification(key) after changing the value.
// To be notified of changes from the opc-ua server to the map, receive on ExternalNotification channel.
type MapNamespace struct {
	srv  *Server
	name string
	Mu   sync.RWMutex
	Data map[string]any

	// This can be used to be alerted when a value is changed from the opc server
	ExternalNotification chan string

	id uint16
}

// GetValue returns the value associated with key from the MapNamespace.
// This function handles locking and getting the value.
//
// Returns nil if the value doesn't exist.
func (ns *MapNamespace) GetValue(key string) any {
	ns.Mu.RLock()
	defer ns.Mu.RUnlock()
	return ns.Data[key]
}

// SetValue updates the value associated with a key and triggers the change notification
// to the OPC server.
func (ns *MapNamespace) SetValue(key string, value any) {
	ns.Mu.Lock()
	defer ns.Mu.Unlock()
	ns.Data[key] = value
	ns.ChangeNotification(key)
}

// ChangeNotification notifies OPC UA subscribers if a key was changed without using the
// SetValue function.
func (ns *MapNamespace) ChangeNotification(key string) {
	ns.srv.ChangeNotification(ua.NewStringNodeID(ns.id, key))
}

func NewMapNamespace(srv *Server, name string) *MapNamespace {
	mrw := MapNamespace{
		srv:                  srv,
		name:                 name,
		Data:                 make(map[string]any),
		ExternalNotification: make(chan string),
	}
	srv.AddNamespace(&mrw)
	return &mrw
}

func (ns *MapNamespace) ID() uint16 {
	return ns.id
}
func (ns *MapNamespace) SetID(id uint16) {
	ns.id = id
}

func (ns *MapNamespace) Browse(bd *ua.BrowseDescription) *ua.BrowseResult {
	ns.Mu.RLock()
	defer ns.Mu.RUnlock()

	ns.srv.cfg.logger.Debug("browse request", "node_id", bd.NodeID, "result_mask", bd.ResultMask)
	if bd.NodeID.IntID() != id.RootFolder && bd.NodeID.IntID() != id.ObjectsFolder {
		refs := make([]*ua.ReferenceDescription, 0)
		return &ua.BrowseResult{
			StatusCode: ua.StatusGood,
			References: refs,
		}
		//return &ua.BrowseResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}

	if bd.NodeID.IntID() == id.RootFolder {

		refs := make([]*ua.ReferenceDescription, 1)
		newid := ua.NewNumericNodeID(ns.id, id.ObjectsFolder)
		expnewid := ua.NewNumericExpandedNodeID(ns.id, id.ObjectsFolder)
		refs[0] = &ua.ReferenceDescription{
			ReferenceTypeID: newid,
			NodeID:          expnewid,
			BrowseName:      &ua.QualifiedName{NamespaceIndex: ns.id, Name: "Objects"},
			DisplayName:     &ua.LocalizedText{EncodingMask: ua.LocalizedTextText, Text: "Objects"},
			TypeDefinition:  expnewid,
		}

		return &ua.BrowseResult{
			StatusCode: ua.StatusGood,
			References: refs,
		}

	}

	refs := make([]*ua.ReferenceDescription, len(ns.Data))

	keyid := 0
	for k := range ns.Data {
		key := k
		refid := ua.NewNumericNodeID(0, id.HasComponent)
		expnewid := ua.NewStringExpandedNodeID(ns.id, key)

		refs[keyid] = &ua.ReferenceDescription{
			ReferenceTypeID: refid,
			IsForward:       true,
			NodeID:          expnewid,
			BrowseName:      &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: key},
			DisplayName:     &ua.LocalizedText{EncodingMask: ua.LocalizedTextText, Text: key},
			NodeClass:       ua.NodeClassVariable, // when support is added for nested maps, this will be NodeClassObject
			TypeDefinition:  expnewid,
		}
		keyid++
	}

	return &ua.BrowseResult{
		StatusCode: ua.StatusGood,
		References: refs,
	}

}

func (ns *MapNamespace) Attribute(n *ua.NodeID, a ua.AttributeID) *ua.DataValue {
	ns.srv.cfg.logger.Debug("read", "node_id", n, "attribute", a)

	if n.IntID() != 0 {
		// this is not one of our normal tags.
		if n.IntID() != id.ObjectsFolder {
			return &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadNodeIDInvalid,
			}
		}

		attrval, err := ns.Objects().Attribute(a)
		if err != nil {
			return &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadAttributeIDInvalid,
			}
		}

		return attrval.Value

	}

	dv := &ua.DataValue{
		EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
		ServerTimestamp: time.Now(),
		Status:          ua.StatusBad,
	}

	key := n.StringID()

	var err error
	ns.srv.cfg.logger.Debug("read request", "key", key, "namespace", ns.name)

	// because our data is native go types we don't have any of the ua "attributes" attached to it.
	// so depending on what attribute the client wants, we'll inspect the data and return the appropriate
	// thing
	switch a {

	case ua.AttributeIDNodeID:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(n)

		// we are going to use the node id directly to look it up from our data map.
	case ua.AttributeIDValue:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		v, ok := ns.Data[key]
		if !ok {
			return &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadNodeIDUnknown,
			}
		}
		switch tv := v.(type) {
		case string:
			dv.Value = ua.MustVariant(tv)
		case int:
			// we can't use an int because it is of unspecified length.  I'm going to use int64 so that we don't
			// have to worry about cutting data off. probably.
			dv.Value = ua.MustVariant(int64(tv))
		case int32:
			dv.Value = ua.MustVariant(tv)
		case float32:
			dv.Value = ua.MustVariant(tv)
		case float64:
			dv.Value = ua.MustVariant(tv)
		case bool:
			dv.Value = ua.MustVariant(tv)
		default:
			dv.Value = ua.MustVariant(tv)
		}
		// nothing in this namespace has an ID Description
	case ua.AttributeIDDescription:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(&ua.LocalizedText{EncodingMask: ua.LocalizedTextText, Text: ""})

	case ua.AttributeIDBrowseName:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(attrs.BrowseName(key))
	case ua.AttributeIDDisplayName:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(attrs.DisplayName(key, key))
	case ua.AttributeIDAccessLevel:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		level := byte(ua.AccessLevelExTypeCurrentWrite | ua.AccessLevelExTypeCurrentRead)
		dv.Value = ua.MustVariant(level)

	case ua.AttributeIDNodeClass:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(int32(ua.NodeClassVariable))
		// nothing in this namespace has event notifiers
	case ua.AttributeIDEventNotifier:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(int16(0))

	// values are in section 5.1.2 of the standard.
	// https://reference.opcfoundation.org/Core/Part6/v104/docs/5.1.2
	case ua.AttributeIDDataType:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		v := ns.Data[key]
		switch v.(type) {
		case string:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 12))
			if err != nil {
				ns.srv.cfg.logger.Warn("problem creating variant", "error", err)
			}
		case int:
			// we can't use an int because it is of unspecified length.  I'm going to use int64 so that we don't
			// have to worry about cutting data off.
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 6))
			if err != nil {
				ns.srv.cfg.logger.Warn("problem creating variant", "error", err)
			}
		case int32:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 6))
			if err != nil {
				ns.srv.cfg.logger.Warn("problem creating variant", "error", err)
			}
		case float32:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 10))
			if err != nil {
				ns.srv.cfg.logger.Warn("problem creating variant", "error", err)
			}
		case float64:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 11))
			if err != nil {
				ns.srv.cfg.logger.Warn("problem creating variant", "error", err)
			}
		case bool:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 1))
			if err != nil {
				ns.srv.cfg.logger.Warn("problem creating variant", "error", err)
			}
		default:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 24))
			if err != nil {
				ns.srv.cfg.logger.Warn("problem creating variant", "error", err)
			}
		}

		// when we support arrays this will have to change.
	case ua.AttributeIDValueRank:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(int32(-1))

	// when we support arrays this will have to change.
	case ua.AttributeIDArrayDimensions:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant([]uint32{})
	default:
		return dv
	}

	if dv.Value == nil {
		ns.srv.cfg.logger.Warn("bad dv value")
	} else {
		ns.srv.cfg.logger.Debug("read complete", "key", key, "value", dv.Value)
	}

	return dv
}

func (ns *MapNamespace) SetAttribute(node *ua.NodeID, attr ua.AttributeID, val *ua.DataValue) ua.StatusCode {

	ns.Mu.Lock()
	defer ns.Mu.Unlock()
	ns.srv.cfg.logger.Debug("pre-write", "namespace", ns.name)

	key := node.StringID()

	// we would normally look up the node in our actual address space, but since that's dumb, we're just
	// going to use the node id directly to look it up from our data map.
	if attr == ua.AttributeIDValue {
		v := val.Value.Value()
		ns.Data[key] = v
	}

	// notify the opc ua server the value has changed.
	ns.srv.ChangeNotification(node)
	// notify the non-opc application the value has changed.
	select {
	case ns.ExternalNotification <- key:
	default:
	}

	return ua.StatusOK
}

func (ns *MapNamespace) Name() string {
	return ns.name
}
func (ns *MapNamespace) AddNode(n *Node) *Node {
	return n
}
func (ns *MapNamespace) DeleteNode(id *ua.NodeID) ua.StatusCode {
	return ua.StatusBadNodeIDUnknown
}
func (ns *MapNamespace) Node(id *ua.NodeID) *Node {
	return nil

}
func (ns *MapNamespace) Objects() *Node {
	oid := ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder)
	//eoid := ua.NewNumericExpandedNodeID(ns.ID(), id.ObjectsFolder)
	typedef := ua.NewNumericExpandedNodeID(0, id.ObjectsFolder)
	//reftype := ua.NewTwoByteNodeID(uint8(id.HasComponent)) // folder
	n := NewNode(
		oid,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:     DataValueFromValue(int32(ua.NodeClassObject)),
			ua.AttributeIDBrowseName:    DataValueFromValue(attrs.BrowseName(ns.name)),
			ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(ns.name, ns.name)),
			ua.AttributeIDDescription:   DataValueFromValue(uint32(ua.NodeClassObject)),
			ua.AttributeIDDataType:      DataValueFromValue(typedef),
			ua.AttributeIDEventNotifier: DataValueFromValue(int16(0)),
		},
		[]*ua.ReferenceDescription{},
		nil,
	)
	return n

}
func (ns *MapNamespace) Root() *Node {
	n := NewNode(
		ua.NewNumericNodeID(ns.ID(), id.RootFolder),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:   DataValueFromValue(int32(ua.NodeClassObject)),
			ua.AttributeIDBrowseName:  DataValueFromValue(attrs.BrowseName("Root")),
			ua.AttributeIDDisplayName: DataValueFromValue(attrs.DisplayName("Root", "")),
		},
		[]*ua.ReferenceDescription{},
		nil,
	)
	return n

}
