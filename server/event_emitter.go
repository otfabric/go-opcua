package server

import (
	"github.com/otfabric/go-opcua/ua"
)

// EventEmitter provides the ability to emit events on server nodes.
// Subscriptions monitoring those nodes for events will receive the notifications.
type EventEmitter interface {
	EmitEvent(nodeID *ua.NodeID, fields *ua.EventFieldList) error
}

// EmitEvent sends an event notification to all monitored items watching the given node.
// The fields should contain the event fields matching the select clauses requested by clients.
func (s *Server) EmitEvent(nodeID *ua.NodeID, fields *ua.EventFieldList) error {
	if s.MonitoredItemService == nil {
		return nil
	}

	s.MonitoredItemService.Mu.Lock()
	items, ok := s.MonitoredItemService.Nodes[nodeID.String()]
	if !ok {
		s.MonitoredItemService.Mu.Unlock()
		return nil
	}

	// Copy the list under the lock to avoid holding it while sending.
	targets := make([]*MonitoredItem, len(items))
	copy(targets, items)
	s.MonitoredItemService.Mu.Unlock()

	for _, item := range targets {
		if item == nil || item.Sub == nil {
			continue
		}
		ef := &ua.EventFieldList{
			ClientHandle: item.Req.RequestedParameters.ClientHandle,
			EventFields:  fields.EventFields,
		}
		select {
		case item.Sub.EventNotifyChannel <- ef:
		default:
			// Channel full, drop event for this item.
			s.cfg.logger.Warnf("event channel full, dropping event for monitored item id=%v", item.ID)
		}
	}

	return nil
}
