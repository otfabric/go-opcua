// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"strings"

	"github.com/otfabric/go-opcua/ua"
)

// DiagnosticInfo in responses (Part 4 §7.12). A client asks for diagnostics
// with the ReturnDiagnostics mask of the RequestHeader (Part 4 §7.33): five
// bits for the service (SymbolicId, LocalizedText, AdditionalInfo,
// InnerStatusCode, InnerDiagnostics) and the same five for the operations.
// Without the mask a response carries no diagnostics at all.
//
// What the server has to say about a status is its symbolic id (the name of
// the StatusCode in the namespace of the OPC Foundation), its description,
// and as AdditionalInfo the operation it belongs to, in terms of the request
// (the NodeId, the attribute, the subscription id): never anything that the
// client did not send, such as internal errors, peer addresses or secrets.
// A failed method call has the first failed input argument as its inner
// status, and each failed argument a DiagnosticInfo of its own.

// ua namespace of the symbolic ids of the standard status codes.
const uaNamespaceURI = "http://opcfoundation.org/UA/"

// The bits of one level (service or operation) of ReturnDiagnostics, shifted
// to the bits of the service level.
const (
	diagSymbolicID      = ua.ServiceLevelSymbolicID
	diagLocalizedText   = ua.ServiceLevelLocalizedText
	diagAdditionalInfo  = ua.ServiceLevelAdditionalInfo
	diagInnerStatusCode = ua.ServiceLevelInnerStatusCode
	diagInnerDiagnostic = ua.ServiceLevelInnerDiagnostics
	diagLevelBits       = ua.ServiceLevelAll
	diagOperationShift  = 5
)

// diagBuilder builds the DiagnosticInfos of one response and its string
// table.
type diagBuilder struct {
	table []string
	index map[string]int32
}

// str returns the index of s in the string table.
func (b *diagBuilder) str(s string) int32 {
	if i, ok := b.index[s]; ok {
		return i
	}
	if b.index == nil {
		b.index = map[string]int32{}
	}
	i := int32(len(b.table))
	b.table = append(b.table, s)
	b.index[s] = i
	return i
}

// info returns the DiagnosticInfo of status st with the fields bits asks for
// (bits of the service level), or nil if there is nothing to tell.
func (b *diagBuilder) info(bits uint32, st ua.StatusCode, additional string, inner ua.StatusCode) *ua.DiagnosticInfo {
	if st == ua.StatusOK && inner == 0 {
		return nil
	}
	d := &ua.DiagnosticInfo{}
	desc, known := ua.StatusCodes[st&^0xFFFF]
	if bits&diagSymbolicID != 0 && known && desc.Symbol != "" {
		d.SymbolicID = b.str(desc.Symbol)
		d.NamespaceURI = b.str(uaNamespaceURI)
		d.EncodingMask |= ua.DiagnosticInfoSymbolicID | ua.DiagnosticInfoNamespaceURI
	}
	if bits&diagLocalizedText != 0 && known && desc.Text != "" {
		d.LocalizedText = b.str(desc.Text)
		d.Locale = b.str("en")
		d.EncodingMask |= ua.DiagnosticInfoLocalizedText | ua.DiagnosticInfoLocale
	}
	if bits&diagAdditionalInfo != 0 && additional != "" {
		d.AdditionalInfo = additional
		d.EncodingMask |= ua.DiagnosticInfoAdditionalInfo
	}
	if inner != 0 {
		if bits&diagInnerStatusCode != 0 {
			d.InnerStatusCode = inner
			d.EncodingMask |= ua.DiagnosticInfoInnerStatusCode
		}
		if bits&diagInnerDiagnostic != 0 {
			if in := b.info(bits&^(diagInnerStatusCode|diagInnerDiagnostic|diagAdditionalInfo), inner, "", 0); in != nil {
				d.InnerDiagnosticInfo = in
				d.EncodingMask |= ua.DiagnosticInfoInnerDiagnosticInfo
			}
		}
	}
	if d.EncodingMask == 0 {
		return nil
	}
	return d
}

// opDiag describes the outcome of one operation.
type opDiag struct {
	status ua.StatusCode
	info   string
	inner  ua.StatusCode
}

// ops returns the DiagnosticInfos of n operations: empty if none of them
// has diagnostics, otherwise one per operation (Part 4 §7.12).
func (b *diagBuilder) ops(bits uint32, n int, op func(i int) opDiag) []*ua.DiagnosticInfo {
	var out []*ua.DiagnosticInfo
	for i := 0; i < n; i++ {
		o := op(i)
		if o.status&0xC0000000 == 0 && o.inner == 0 {
			continue // Good: nothing to diagnose
		}
		d := b.info(bits, o.status, o.info, o.inner)
		if d == nil {
			continue
		}
		if out == nil {
			out = make([]*ua.DiagnosticInfo, n)
			for j := range out {
				out[j] = &ua.DiagnosticInfo{}
			}
		}
		out[i] = d
	}
	if out == nil {
		return []*ua.DiagnosticInfo{}
	}
	return out
}

// addDiagnostics fills the DiagnosticInfos of a response as the
// ReturnDiagnostics mask of the request asks.
func addDiagnostics(req ua.Request, resp ua.Response) {
	if req == nil || resp == nil {
		return
	}
	hdr := req.Header()
	if hdr == nil || hdr.ReturnDiagnostics&ua.ReturnDiagnosticsAll == 0 {
		return
	}
	rh := resp.Header()
	if rh == nil {
		return
	}
	b := &diagBuilder{}
	svc := hdr.ReturnDiagnostics & diagLevelBits
	op := (hdr.ReturnDiagnostics >> diagOperationShift) & diagLevelBits
	if svc != 0 && rh.ServiceResult != ua.StatusOK {
		if d := b.info(svc, rh.ServiceResult, serviceInfo(req, rh.ServiceResult), 0); d != nil {
			rh.ServiceDiagnostics = d
		}
	}
	if op != 0 && rh.ServiceResult&0x80000000 == 0 {
		operationDiagnostics(b, op, req, resp)
	}
	if len(b.table) > 0 {
		rh.StringTable = b.table
	}
}

// serviceInfo is the AdditionalInfo of a failed service.
func serviceInfo(req ua.Request, st ua.StatusCode) string {
	switch st &^ 0xFFFF {
	case ua.StatusBadSessionIDInvalid:
		return "no session for the authentication token of the request (closed, timed out or unknown)"
	case ua.StatusBadSessionNotActivated:
		return "the session has not been activated"
	case ua.StatusBadServiceUnsupported:
		return "the server does not implement " + serviceName(req)
	case ua.StatusBadTooManyOperations:
		return fmt.Sprintf("%s with %d operations exceeds the operation limit of the server", serviceName(req), operationCount(req))
	case ua.StatusBadNothingToDo:
		return serviceName(req) + " without operations"
	default:
		return ""
	}
}

// operationCount returns the number of operations of a request.
func operationCount(req ua.Request) int {
	switch r := req.(type) {
	case *ua.ReadRequest:
		return len(r.NodesToRead)
	case *ua.WriteRequest:
		return len(r.NodesToWrite)
	case *ua.BrowseRequest:
		return len(r.NodesToBrowse)
	case *ua.CallRequest:
		return len(r.MethodsToCall)
	case *ua.HistoryReadRequest:
		return len(r.NodesToRead)
	case *ua.TranslateBrowsePathsToNodeIDsRequest:
		return len(r.BrowsePaths)
	case *ua.CreateMonitoredItemsRequest:
		return len(r.ItemsToCreate)
	case *ua.RegisterNodesRequest:
		return len(r.NodesToRegister)
	case *ua.AddNodesRequest:
		return len(r.NodesToAdd)
	case *ua.DeleteNodesRequest:
		return len(r.NodesToDelete)
	}
	return 0
}

func nodeInfo(n *ua.NodeID) string {
	if n == nil {
		return "null NodeId"
	}
	return n.String()
}

func attrInfo(n *ua.NodeID, a ua.AttributeID) string {
	return fmt.Sprintf("%s, attribute %s", nodeInfo(n), strings.TrimPrefix(a.String(), "AttributeID"))
}

// at returns xs[i] or the zero value.
func at[T any](xs []T, i int) (T, bool) {
	var zero T
	if i < 0 || i >= len(xs) {
		return zero, false
	}
	return xs[i], true
}

// operationDiagnostics fills the operation DiagnosticInfos of a response.
func operationDiagnostics(b *diagBuilder, bits uint32, req ua.Request, resp ua.Response) {
	switch r := resp.(type) {
	case *ua.ReadResponse:
		q, _ := req.(*ua.ReadRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{status: dataValueStatus(r.Results[i])}
			if q != nil {
				if n, ok := at(q.NodesToRead, i); ok && n != nil {
					o.info = attrInfo(n.NodeID, n.AttributeID)
				}
			}
			return o
		})
	case *ua.WriteResponse:
		q, _ := req.(*ua.WriteRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{status: r.Results[i]}
			if q != nil {
				if n, ok := at(q.NodesToWrite, i); ok && n != nil {
					o.info = attrInfo(n.NodeID, n.AttributeID)
				}
			}
			return o
		})
	case *ua.HistoryReadResponse:
		q, _ := req.(*ua.HistoryReadRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{}
			if res := r.Results[i]; res != nil {
				o.status = res.StatusCode
			}
			if q != nil {
				if n, ok := at(q.NodesToRead, i); ok && n != nil {
					o.info = nodeInfo(n.NodeID)
				}
			}
			return o
		})
	case *ua.HistoryUpdateResponse:
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			if res := r.Results[i]; res != nil {
				return opDiag{status: res.StatusCode}
			}
			return opDiag{}
		})
	case *ua.CallResponse:
		q, _ := req.(*ua.CallRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			res := r.Results[i]
			if res == nil {
				return opDiag{}
			}
			o := opDiag{status: res.StatusCode}
			for _, a := range res.InputArgumentResults {
				if a&0x80000000 != 0 {
					o.inner = a
					break
				}
			}
			if q != nil {
				if m, ok := at(q.MethodsToCall, i); ok && m != nil {
					o.info = fmt.Sprintf("method %s of object %s", nodeInfo(m.MethodID), nodeInfo(m.ObjectID))
				}
			}
			args := res.InputArgumentResults
			res.InputArgumentDiagnosticInfos = b.ops(bits, len(args), func(j int) opDiag {
				return opDiag{status: args[j], info: fmt.Sprintf("input argument %d", j)}
			})
			return o
		})
	case *ua.BrowseResponse:
		q, _ := req.(*ua.BrowseRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{}
			if res := r.Results[i]; res != nil {
				o.status = res.StatusCode
			}
			if q != nil {
				if n, ok := at(q.NodesToBrowse, i); ok && n != nil {
					o.info = nodeInfo(n.NodeID)
				}
			}
			return o
		})
	case *ua.BrowseNextResponse:
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			if res := r.Results[i]; res != nil {
				return opDiag{status: res.StatusCode, info: fmt.Sprintf("continuation point %d", i)}
			}
			return opDiag{}
		})
	case *ua.TranslateBrowsePathsToNodeIDsResponse:
		q, _ := req.(*ua.TranslateBrowsePathsToNodeIDsRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{}
			if res := r.Results[i]; res != nil {
				o.status = res.StatusCode
			}
			if q != nil {
				if p, ok := at(q.BrowsePaths, i); ok && p != nil {
					o.info = "browse path from " + nodeInfo(p.StartingNode)
				}
			}
			return o
		})
	case *ua.AddNodesResponse:
		q, _ := req.(*ua.AddNodesRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{}
			if res := r.Results[i]; res != nil {
				o.status = res.StatusCode
			}
			if q != nil {
				if n, ok := at(q.NodesToAdd, i); ok && n != nil && n.BrowseName != nil {
					o.info = "node " + n.BrowseName.Name
				}
			}
			return o
		})
	case *ua.AddReferencesResponse:
		q, _ := req.(*ua.AddReferencesRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{status: r.Results[i]}
			if q != nil {
				if n, ok := at(q.ReferencesToAdd, i); ok && n != nil {
					o.info = "reference from " + nodeInfo(n.SourceNodeID)
				}
			}
			return o
		})
	case *ua.DeleteNodesResponse:
		q, _ := req.(*ua.DeleteNodesRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{status: r.Results[i]}
			if q != nil {
				if n, ok := at(q.NodesToDelete, i); ok && n != nil {
					o.info = nodeInfo(n.NodeID)
				}
			}
			return o
		})
	case *ua.DeleteReferencesResponse:
		q, _ := req.(*ua.DeleteReferencesRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{status: r.Results[i]}
			if q != nil {
				if n, ok := at(q.ReferencesToDelete, i); ok && n != nil {
					o.info = "reference from " + nodeInfo(n.SourceNodeID)
				}
			}
			return o
		})
	case *ua.CreateMonitoredItemsResponse:
		q, _ := req.(*ua.CreateMonitoredItemsRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{}
			if res := r.Results[i]; res != nil {
				o.status = res.StatusCode
			}
			if q != nil {
				if n, ok := at(q.ItemsToCreate, i); ok && n != nil && n.ItemToMonitor != nil {
					o.info = attrInfo(n.ItemToMonitor.NodeID, n.ItemToMonitor.AttributeID)
				}
			}
			return o
		})
	case *ua.ModifyMonitoredItemsResponse:
		q, _ := req.(*ua.ModifyMonitoredItemsRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{}
			if res := r.Results[i]; res != nil {
				o.status = res.StatusCode
			}
			if q != nil {
				if n, ok := at(q.ItemsToModify, i); ok && n != nil {
					o.info = fmt.Sprintf("monitored item %d", n.MonitoredItemID)
				}
			}
			return o
		})
	case *ua.SetMonitoringModeResponse:
		q, _ := req.(*ua.SetMonitoringModeRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{status: r.Results[i]}
			if q != nil {
				if n, ok := at(q.MonitoredItemIDs, i); ok {
					o.info = fmt.Sprintf("monitored item %d", n)
				}
			}
			return o
		})
	case *ua.DeleteMonitoredItemsResponse:
		q, _ := req.(*ua.DeleteMonitoredItemsRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{status: r.Results[i]}
			if q != nil {
				if n, ok := at(q.MonitoredItemIDs, i); ok {
					o.info = fmt.Sprintf("monitored item %d", n)
				}
			}
			return o
		})
	case *ua.SetTriggeringResponse:
		q, _ := req.(*ua.SetTriggeringRequest)
		link := func(ids []uint32, i int) string {
			if n, ok := at(ids, i); ok {
				return fmt.Sprintf("link to monitored item %d", n)
			}
			return ""
		}
		var add, remove []uint32
		if q != nil {
			add, remove = q.LinksToAdd, q.LinksToRemove
		}
		r.AddDiagnosticInfos = b.ops(bits, len(r.AddResults), func(i int) opDiag {
			return opDiag{status: r.AddResults[i], info: link(add, i)}
		})
		r.RemoveDiagnosticInfos = b.ops(bits, len(r.RemoveResults), func(i int) opDiag {
			return opDiag{status: r.RemoveResults[i], info: link(remove, i)}
		})
	case *ua.SetPublishingModeResponse:
		q, _ := req.(*ua.SetPublishingModeRequest)
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			return opDiag{status: r.Results[i], info: subscriptionInfo(q, i)}
		})
	case *ua.DeleteSubscriptionsResponse:
		q, _ := req.(*ua.DeleteSubscriptionsRequest)
		var ids []uint32
		if q != nil {
			ids = q.SubscriptionIDs
		}
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{status: r.Results[i]}
			if n, ok := at(ids, i); ok {
				o.info = fmt.Sprintf("subscription %d", n)
			}
			return o
		})
	case *ua.TransferSubscriptionsResponse:
		q, _ := req.(*ua.TransferSubscriptionsRequest)
		var ids []uint32
		if q != nil {
			ids = q.SubscriptionIDs
		}
		r.DiagnosticInfos = b.ops(bits, len(r.Results), func(i int) opDiag {
			o := opDiag{}
			if res := r.Results[i]; res != nil {
				o.status = res.StatusCode
			}
			if n, ok := at(ids, i); ok {
				o.info = fmt.Sprintf("subscription %d", n)
			}
			return o
		})
	}
}

func subscriptionInfo(q *ua.SetPublishingModeRequest, i int) string {
	if q == nil {
		return ""
	}
	if n, ok := at(q.SubscriptionIDs, i); ok {
		return fmt.Sprintf("subscription %d", n)
	}
	return ""
}

// dataValueStatus returns the status of a DataValue result.
func dataValueStatus(dv *ua.DataValue) ua.StatusCode {
	if dv == nil {
		return ua.StatusOK
	}
	return dv.Status
}
