// SPDX-License-Identifier: MIT

package fxserver

import (
	"bytes"
	"context"
	"math"
	"reflect"
	"slices"
	"strings"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// endpointCommands are the commands that work on
// ConnectionEndpointConfigurations (Part 81 Table 8).
const endpointCommands = uafx.VerifyFunctionalEntityCmd | uafx.CreateConnectionEndpointCmd | uafx.EstablishControlCmd |
	uafx.SetConfigurationDataCmd | uafx.ReassignControlCmd | uafx.SetCommunicationConfigurationCmd | uafx.EnableCommunicationCmd

// bundleCommands are the commands an AutomationComponent with
// CommandBundleRequired takes only together (Part 81 §6.2.4.3.1).
const bundleCommands = uafx.CreateConnectionEndpointCmd | uafx.EstablishControlCmd | uafx.SetConfigurationDataCmd |
	uafx.ReassignControlCmd | uafx.SetCommunicationConfigurationCmd

func (c *Connections) establishHandler(ac *automationComponent) server.MethodHandler {
	return func(ctx context.Context, obj, method *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		out, sc := c.establish(ctx, ac, args)
		c.auditCall(ctx, ac, method, args, out, sc)
		return out, sc
	}
}

// establish runs an EstablishConnections call (Part 81 §6.2.4).
func (c *Connections) establish(ctx context.Context, ac *automationComponent, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	req, err := uafx.DecodeEstablishConnectionsRequest(args, c.ns.Data)
	if err != nil {
		c.log.Debug("uafx: EstablishConnections arguments", "error", err)
		return nil, ua.StatusBadInvalidArgument
	}
	if sc := c.checkArguments(req); sc != ua.StatusOK {
		return nil, sc
	}
	c.call.Lock()
	defer c.call.Unlock()
	x := newCall(ctx, c, ac, req)
	status := x.run()
	out, err := uafx.EncodeEstablishConnectionsResult(x.res, c.ns.Data)
	if err != nil {
		c.log.Error("uafx: EstablishConnections result", "error", err)
		return nil, ua.StatusBadInternalError
	}
	c.refreshAll()
	return out, status
}

// checkArguments checks the arguments against the commands (Part 81 Table
// 8, Table 9).
func (c *Connections) checkArguments(r *uafx.EstablishConnectionsRequest) ua.StatusCode {
	m := r.CommandMask
	bad := ua.StatusBadInvalidArgument
	if m == 0 || m&^uafx.AllFxCommands != 0 {
		return bad
	}
	if (m&uafx.VerifyAssetCmd != 0) != (len(r.AssetVerifications) > 0) ||
		(m&endpointCommands != 0) != (len(r.ConnectionEndpointConfigurations) > 0) ||
		(m&uafx.ReserveCommunicationIDsCmd != 0) != (len(r.ReserveCommunicationIDs) > 0) {
		return bad
	}
	if m&uafx.SetCommunicationConfigurationCmd != 0 && len(r.CommunicationConfigurations) != 1 ||
		m&uafx.SetCommunicationConfigurationCmd == 0 && len(r.CommunicationConfigurations) != 0 {
		return bad
	}
	var evv, param, cg, cfg, links bool
	needEndpoint := m&(uafx.EstablishControlCmd|uafx.SetConfigurationDataCmd|uafx.ReassignControlCmd|uafx.SetCommunicationConfigurationCmd|uafx.EnableCommunicationCmd) != 0
	for _, e := range r.ConnectionEndpointConfigurations {
		evv = evv || len(e.ExpectedVerificationVariables) > 0
		cg = cg || len(e.ControlGroups) > 0
		cfg = cfg || len(e.ConfigurationData) > 0
		links = links || e.CommunicationLinks != nil
		d := e.ConnectionEndpoint
		switch {
		case d == nil:
			if needEndpoint || m&uafx.CreateConnectionEndpointCmd == 0 {
				return bad
			}
		case d.Parameter != nil:
			param = true
			if m&uafx.CreateConnectionEndpointCmd == 0 {
				return bad
			}
		}
	}
	if m&uafx.VerifyFunctionalEntityCmd != 0 != evv ||
		m&uafx.CreateConnectionEndpointCmd != 0 && !param ||
		m&(uafx.EstablishControlCmd|uafx.ReassignControlCmd) != 0 != cg ||
		m&uafx.SetConfigurationDataCmd != 0 != cfg ||
		m&uafx.SetCommunicationConfigurationCmd != 0 != links {
		return bad
	}
	if c.opts.CommandBundleRequired && m&bundleCommands != 0 &&
		(m&uafx.CreateConnectionEndpointCmd == 0 || m&uafx.SetCommunicationConfigurationCmd == 0) {
		return bad
	}
	if c.opts.MaxConnectionsPerCall > 0 && len(r.ConnectionEndpointConfigurations) > int(c.opts.MaxConnectionsPerCall) {
		return ua.StatusBadTooManyOperations
	}
	return ua.StatusOK
}

// call is one EstablishConnections call.
type call struct {
	ctx context.Context
	c   *Connections
	ac  *automationComponent
	req *uafx.EstablishConnectionsRequest
	res *uafx.EstablishConnectionsResult
	els []*element

	// Rollback (Part 81 §6.2.4.3.11, Table 21).
	created    []*endpoint // CreateConnectionEndpointCmd
	restore    []func()    // preconfigured endpoints the call changed
	update     *server.PubSubConfigurationUpdate
	linkUndo   []func()             // SetCommunicationConfigurationCmd
	enabled    []pubsub.ComponentID // EnableCommunicationCmd
	cleanupsOn []*endpoint
	controlled []*controlGroup // EstablishControlCmd
}

// element is one ConnectionEndpointConfiguration of the call.
type element struct {
	cfg       *uafx.ConnectionEndpointConfiguration
	res       *uafx.ConnectionEndpointConfigurationResult
	fe        *ua.NodeID // nil until checked and valid
	feChecked bool
	ep        *endpoint
}

func newCall(ctx context.Context, c *Connections, ac *automationComponent, req *uafx.EstablishConnectionsRequest) *call {
	m := req.CommandMask
	x := &call{ctx: ctx, c: c, ac: ac, req: req, res: &uafx.EstablishConnectionsResult{Status: ua.StatusOK}}
	nothing := ua.StatusBadNothingToDo
	for range req.AssetVerifications {
		x.res.AssetVerificationResults = append(x.res.AssetVerificationResults, &uafx.AssetVerificationResultData{VerificationStatus: nothing})
	}
	if m&endpointCommands != 0 {
		for _, e := range req.ConnectionEndpointConfigurations {
			// What a command that does not run leaves (Part 81 §10.15);
			// a command that is requested and does not run because an
			// earlier one failed reports Bad_NothingToDo (§6.2.4.3.11).
			r := &uafx.ConnectionEndpointConfigurationResult{}
			if m&uafx.VerifyFunctionalEntityCmd != 0 {
				r.VerificationStatus = nothing
			}
			if m&uafx.CreateConnectionEndpointCmd != 0 && e.ConnectionEndpoint != nil && e.ConnectionEndpoint.Parameter != nil {
				r.ConnectionEndpointResult = nothing
			}
			if m&uafx.EstablishControlCmd != 0 && len(e.ControlGroups) > 0 {
				r.EstablishControlResult = fill(len(e.ControlGroups), nothing)
			}
			if m&uafx.SetConfigurationDataCmd != 0 && len(e.ConfigurationData) > 0 {
				r.ConfigurationDataResult = fill(len(e.ConfigurationData), nothing)
			}
			if m&uafx.ReassignControlCmd != 0 && len(e.ControlGroups) > 0 {
				r.ReassignControlResult = fill(len(e.ControlGroups), nothing)
			}
			if m&uafx.SetCommunicationConfigurationCmd != 0 && e.CommunicationLinks != nil {
				r.CommunicationLinksResult = nothing
			}
			if m&uafx.EnableCommunicationCmd != 0 {
				r.EnableCommunicationResult = nothing
			}
			x.res.ConnectionEndpointConfigurationResults = append(x.res.ConnectionEndpointConfigurationResults, r)
			x.els = append(x.els, &element{cfg: e, res: r})
		}
	}
	for range req.ReserveCommunicationIDs {
		x.res.ReserveCommunicationIDsResults = append(x.res.ReserveCommunicationIDsResults, &uafx.PubSubReserveCommunicationIDsResult{Result: nothing})
	}
	if m&uafx.SetCommunicationConfigurationCmd != 0 {
		x.res.CommunicationConfigurationResults = []*uafx.PubSubCommunicationConfigurationResult{{Result: nothing}}
	}
	return x
}

func fill(n int, sc ua.StatusCode) []ua.StatusCode {
	out := make([]ua.StatusCode, n)
	for i := range out {
		out[i] = sc
	}
	return out
}

// run processes the commands in the order of Part 81 §6.2.4.3.1 and
// returns the status of the call: Good, or Uncertain after an abort.
func (x *call) run() ua.StatusCode {
	steps := map[uafx.FxCommandMask]func() bool{
		uafx.VerifyAssetCmd:                   x.verifyAssets,
		uafx.VerifyFunctionalEntityCmd:        x.verifyFunctionalEntities,
		uafx.ReserveCommunicationIDsCmd:       x.reserve,
		uafx.CreateConnectionEndpointCmd:      x.create,
		uafx.EstablishControlCmd:              func() bool { return x.control(false) },
		uafx.SetConfigurationDataCmd:          x.configure,
		uafx.ReassignControlCmd:               func() bool { return x.control(true) },
		uafx.SetCommunicationConfigurationCmd: x.communicate,
		uafx.EnableCommunicationCmd:           x.enable,
	}
	for _, cmd := range x.req.CommandMask.Order() {
		if !steps[cmd]() {
			x.rollback()
			x.res.Status = ua.StatusUncertain
			return ua.StatusUncertain
		}
	}
	return ua.StatusOK
}

// rollback undoes what the call did (Part 81 Table 21): it disables what
// EnableCommunicationCmd enabled, deletes the References and the PubSub
// configuration SetCommunicationConfigurationCmd made, releases the
// ControlGroups EstablishControlCmd controlled and deletes the
// ConnectionEndpoints CreateConnectionEndpointCmd created. Verification,
// reserved ids, ConfigurationData and what ReassignControlCmd did stay
// (Table 21), except where the release of a ControlGroup or the removal of
// an endpoint undoes it.
func (x *call) rollback() {
	for i := len(x.enabled) - 1; i >= 0; i-- {
		if err := x.c.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error { return rt.Disable(x.enabled[i]) }); err != nil {
			x.c.log.Warn("uafx: rollback: disable", "component", x.enabled[i], "error", err)
		}
	}
	for _, e := range x.cleanupsOn {
		x.c.mu.Lock()
		e.cleanupOff = true
		x.c.mu.Unlock()
	}
	for i := len(x.linkUndo) - 1; i >= 0; i-- {
		x.linkUndo[i]()
	}
	if err := x.update.Revert(); err != nil {
		x.c.log.Warn("uafx: rollback: the PubSub configuration of the call stays", "error", err)
	}
	for i := len(x.controlled) - 1; i >= 0; i-- {
		x.c.release(x.controlled[i])
	}
	for _, e := range x.created {
		x.c.deleteEndpoint(e)
		for _, el := range x.els {
			if el.ep == e {
				el.res.ConnectionEndpointID = nil
				el.ep = nil
			}
		}
	}
	for i := len(x.restore) - 1; i >= 0; i-- {
		x.restore[i]()
	}
}

// --- VerifyAssetCmd, VerifyFunctionalEntityCmd -----------------------------

// verifyAssets runs VerifyAssetCmd (Part 81 §6.2.4.3.2).
func (x *call) verifyAssets() bool {
	ok := true
	assets := map[string]bool{}
	for _, r := range x.c.hierarchy(x.ac.assets) {
		assets[r.String()] = true
	}
	for i, av := range x.req.AssetVerifications {
		res := x.res.AssetVerificationResults[i]
		res.VerificationStatus = ua.StatusOK
		switch {
		case isNull(av.AssetToVerify):
			res.VerificationStatus = ua.StatusBadNodeIDInvalid
		case x.c.node(av.AssetToVerify) == nil:
			res.VerificationStatus = ua.StatusBadNodeIDUnknown
		case !assets[av.AssetToVerify.String()]:
			res.VerificationStatus = ua.StatusBadInvalidArgument
		case x.c.opts.AssetVerifier == nil:
			res.VerificationStatus = ua.StatusBadNotSupported
		default:
			res.VerificationResult, res.VerificationVariablesErrors, res.VerificationAdditionalVariablesErrors, res.VerificationStatus =
				x.c.opts.AssetVerifier(x.ctx, av.AssetToVerify, av.VerificationMode, av.ExpectedVerificationVariables, av.ExpectedAdditionalVerificationVariables)
		}
		switch {
		case res.VerificationStatus.Uint32()&0x80000000 != 0,
			res.VerificationResult == uafx.AssetVerificationNotSet,
			res.VerificationResult == uafx.AssetVerificationMismatch,
			res.VerificationResult == uafx.AssetVerificationCompatible && av.ExpectedVerificationResult == uafx.AssetVerificationMatch:
			ok = false
		}
	}
	return ok
}

// hierarchy returns n and the nodes in the hierarchy below it.
func (c *Connections) hierarchy(n *ua.NodeID) []*ua.NodeID {
	if n == nil {
		return nil
	}
	out := []*ua.NodeID{n}
	seen := map[string]bool{n.String(): true}
	for i := 0; i < len(out) && len(out) < 4096; i++ {
		for _, r := range c.children(out[i], id.HierarchicalReferences) {
			x := r.NodeID.NodeID
			if !seen[x.String()] {
				seen[x.String()] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// verifyFunctionalEntities runs VerifyFunctionalEntityCmd (Part 81
// §6.2.4.3.3).
func (x *call) verifyFunctionalEntities() bool {
	ok := true
	for _, el := range x.els {
		r := el.res
		if len(el.cfg.ExpectedVerificationVariables) == 0 {
			r.VerificationStatus, r.VerificationResult = ua.StatusGoodNoData, uafx.FunctionalEntityVerificationNotSet
			continue
		}
		if !x.checkFE(el) {
			r.VerificationStatus, r.VerificationResult = ua.StatusOK, uafx.FunctionalEntityVerificationMismatch
			ok = false
			continue
		}
		r.VerificationResult, r.VerificationVariablesErrors, r.VerificationStatus = x.c.verify(x.ctx, el.cfg.ExpectedVerificationVariables)
		if r.VerificationResult == uafx.FunctionalEntityVerificationMismatch ||
			r.VerificationResult == uafx.FunctionalEntityVerificationNotSet && len(r.VerificationVariablesErrors) > 0 ||
			r.VerificationStatus.Uint32()&0x80000000 != 0 {
			ok = false
		}
	}
	return ok
}

// verify runs the Verify Method of a FunctionalEntity (Part 81 §6.4.3): it
// compares each expected value with the value of its Variable (Table 45).
// The values are read with the rights of the caller in ctx.
func (c *Connections) verify(ctx context.Context, pairs []*uafx.NodeIDValuePair) (uafx.FunctionalEntityVerificationResult, []ua.StatusCode, ua.StatusCode) {
	if len(pairs) == 0 {
		return uafx.FunctionalEntityVerificationNotSet, nil, ua.StatusBadInvalidArgument
	}
	errs := make([]ua.StatusCode, len(pairs))
	match := true
	for i, p := range pairs {
		errs[i] = c.verifyOne(ctx, p)
		match = match && errs[i] == ua.StatusOK
	}
	if match {
		return uafx.FunctionalEntityVerificationMatch, errs, ua.StatusOK
	}
	return uafx.FunctionalEntityVerificationMismatch, errs, ua.StatusUncertain
}

// verifyOne verifies one NodeIdValuePair (Part 81 §6.4.3, Table 45). The
// value is read as the caller could read it with the Read service
// (server.ReadValue): a read the caller may not make fails the element with
// the status of the refused read, whatever the expected value, so that
// verification tells nothing about a value the caller cannot read. Table 45
// has no code for this; it is the status the Read service would return.
func (c *Connections) verifyOne(ctx context.Context, p *uafx.NodeIDValuePair) ua.StatusCode {
	if p == nil || p.Key == nil || isNull(p.Key.Node) {
		return ua.StatusBadNodeIDInvalid
	}
	n := c.node(p.Key.Node)
	if n == nil {
		return ua.StatusBadNodeIDUnknown
	}
	want := val(p.Value)
	if n.NodeClass() != ua.NodeClassVariable && n.NodeClass() != ua.NodeClassVariableType {
		if want != nil {
			return ua.StatusBadOutOfRange
		}
		return ua.StatusOK
	}
	if want == nil {
		return ua.StatusOK // "it shall be verified that NodeId exists"
	}
	dv, sc := c.srv.ReadValue(ctx, p.Key.Node)
	if sc != ua.StatusOK {
		return sc
	}
	got, sc := arrayElement(dv.Value, p.Key.ArrayIndex)
	if sc != ua.StatusOK {
		return sc
	}
	if got == nil || reflect.TypeOf(got) != reflect.TypeOf(want) {
		return ua.StatusBadTypeMismatch
	}
	if c.isApplicationIdentifier(n) {
		if eq, ok := c.sameApplicationIDs(got, want); ok {
			if !eq {
				return ua.StatusBadOutOfRange
			}
			return ua.StatusOK
		}
	}
	if !sameValue(trimStrings(got), trimStrings(want)) {
		return ua.StatusBadOutOfRange
	}
	return ua.StatusOK
}

// sameValue compares two values of one type. An ExtensionObject is compared
// by its TypeID and its binary body when it has one: the server holds the
// body of a type package ua does not know as Value ([]byte), a decoded
// request as RawBody, which are the same structure.
func sameValue(got, want any) bool {
	switch g := got.(type) {
	case *ua.ExtensionObject:
		return sameExtensionObject(g, want.(*ua.ExtensionObject))
	case []*ua.ExtensionObject:
		w := want.([]*ua.ExtensionObject)
		if len(g) != len(w) {
			return false
		}
		for i := range g {
			if !sameExtensionObject(g[i], w[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(got, want)
}

func sameExtensionObject(a, b *ua.ExtensionObject) bool {
	ab, bb := binaryBody(a), binaryBody(b)
	if ab == nil || bb == nil {
		return reflect.DeepEqual(a, b)
	}
	return a.TypeID != nil && b.TypeID != nil && a.TypeID.NodeID.Equal(b.TypeID.NodeID) && bytes.Equal(ab, bb)
}

// binaryBody returns the binary body of an ExtensionObject whose type
// package ua does not know, nil for any other.
func binaryBody(eo *ua.ExtensionObject) []byte {
	if eo == nil || eo.EncodingMask != ua.ExtensionObjectBinary {
		return nil
	}
	if eo.RawBody != nil {
		return eo.RawBody
	}
	b, _ := eo.Value.([]byte)
	return b
}

// trimStrings strips the leading and trailing whitespace of a String value
// or of the elements of a String array: "All string-type variables shall be
// stripped of leading and trailing whitespaces before processing" (Part 81
// §6.4.3).
func trimStrings(v any) any {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case []string:
		out := make([]string, len(x))
		for i, s := range x {
			out[i] = strings.TrimSpace(s)
		}
		return out
	}
	return v
}

// isApplicationIdentifier reports whether n is the ApplicationIdentifier
// Property of a FunctionalEntity (Part 81 §6.4.2), which the AC namespace
// defines.
func (c *Connections) isApplicationIdentifier(n *server.Node) bool {
	bn := n.BrowseName()
	return bn != nil && bn.NamespaceIndex == c.ns.AC && bn.Name == "ApplicationIdentifier"
}

// sameApplicationIDs compares ApplicationIdentifierDataType values, one or
// an array, by their UniqueIdentifier alone: "its Name sub-element shall
// always be ignored; only its UniqueIdentifier shall be used" (Part 81
// §6.4.3). ok is false when a value is not a binary
// ApplicationIdentifierDataType body (§10.3), which is then compared as a
// whole.
func (c *Connections) sameApplicationIDs(got, want any) (eq, ok bool) {
	switch g := got.(type) {
	case *ua.ExtensionObject:
		w, _ := want.(*ua.ExtensionObject)
		gi, ok1 := c.uniqueIdentifier(g)
		wi, ok2 := c.uniqueIdentifier(w)
		if !ok1 || !ok2 {
			return false, false
		}
		return bytes.Equal(gi, wi), true
	case []*ua.ExtensionObject:
		w, _ := want.([]*ua.ExtensionObject)
		if len(g) != len(w) {
			// Arrays of different lengths differ, if both are of the type.
			for _, x := range append(slices.Clone(g), w...) {
				if _, ok := c.uniqueIdentifier(x); !ok {
					return false, false
				}
			}
			return false, true
		}
		eq = true
		for i := range g {
			e, ok := c.sameApplicationIDs(g[i], w[i])
			if !ok {
				return false, false
			}
			eq = eq && e
		}
		return eq, true
	}
	return false, false
}

// uniqueIdentifier returns the encoded UniqueIdentifier (an ApplicationId
// union, §10.2) of the binary ApplicationIdentifierDataType body of eo: what
// follows its Name.
func (c *Connections) uniqueIdentifier(eo *ua.ExtensionObject) ([]byte, bool) {
	if eo == nil || eo.TypeID == nil || eo.TypeID.NodeID == nil ||
		eo.TypeID.NodeID.Namespace() != c.ns.AC || eo.TypeID.NodeID.IntID() != fxacid.ApplicationIdentifierDataTypeEncodingDefaultBinary {
		return nil, false
	}
	body := binaryBody(eo)
	if body == nil {
		return nil, false
	}
	var name ua.LocalizedText
	n, err := name.Decode(body)
	if err != nil || n > len(body) {
		return nil, false
	}
	return body[n:], true
}

// arrayElement returns the value of v, or with an ArrayIndex of one dimension
// the element it selects (Part 81 §10.31); Bad_OutOfRange for an index
// outside the array or of more dimensions.
func arrayElement(v *ua.Variant, index []uint32) (any, ua.StatusCode) {
	x := val(v)
	if len(index) == 0 {
		return x, ua.StatusOK
	}
	rv := reflect.ValueOf(x)
	if len(index) != 1 || x == nil || rv.Kind() != reflect.Slice || int64(index[0]) >= int64(rv.Len()) {
		return nil, ua.StatusBadOutOfRange
	}
	return rv.Index(int(index[0])).Interface(), ua.StatusOK
}

func val(v *ua.Variant) any {
	if v == nil {
		return nil
	}
	return v.Value()
}

func isNull(n *ua.NodeID) bool {
	return n == nil || n.Namespace() == 0 && n.Type() != ua.NodeIDTypeString && n.Type() != ua.NodeIDTypeGUID && n.Type() != ua.NodeIDTypeByteString && n.IntID() == 0
}

// checkFE checks the FunctionalEntityNode of el (Part 81 Table 11) and
// reports whether it is a FunctionalEntity of the AutomationComponent.
func (x *call) checkFE(el *element) bool {
	if !el.feChecked {
		el.feChecked = true
		fe := el.cfg.FunctionalEntityNode
		sc := ua.StatusOK
		switch {
		case isNull(fe):
			sc = ua.StatusBadNodeIDInvalid
		case x.c.node(fe) == nil:
			sc = ua.StatusBadNodeIDUnknown
		case !slices.ContainsFunc(x.c.functionalEntities(x.ac), fe.Equal):
			sc = ua.StatusBadInvalidArgument
		default:
			el.fe = fe
		}
		el.res.FunctionalEntityNodeResult = sc
	}
	return el.fe != nil
}

// --- ReserveCommunicationIdsCmd ------------------------------------------

// udpUADP is the transport profile of UDP with UADP (Part 14 §7.3.2).
const udpUADP = "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"

// reserve runs ReserveCommunicationIdsCmd (Part 81 §6.2.4.3.4) as the
// ReserveIds Method of Part 14 §9.1.3.7.5.
func (x *call) reserve() bool {
	for i, r := range x.req.ReserveCommunicationIDs {
		out := x.res.ReserveCommunicationIDsResults[i]
		res, sc := x.c.srv.ReservePubSubIDs(x.ctx, r.NumReqWriterGroupIDs, r.NumReqDataSetWriterIDs)
		out.Result = sc
		if sc != ua.StatusOK {
			return false
		}
		out.DefaultPublisherID, out.WriterGroupIDs, out.DataSetWriterIDs = res.DefaultPublisherID, res.WriterGroupIDs, res.DataSetWriterIDs
		if r.RequestTransportSpecificInfo && r.TransportProfileURI == udpUADP {
			out.TransportSpecificInfo = ua.MustVariant(x.c.opts.UDPPort)
		}
	}
	return true
}

// --- CreateConnectionEndpointCmd -----------------------------------------

// create runs CreateConnectionEndpointCmd (Part 81 §6.2.4.3.5).
func (x *call) create() bool {
	for _, el := range x.els {
		d := el.cfg.ConnectionEndpoint
		if d == nil || d.Parameter == nil {
			continue
		}
		if !x.checkFE(el) {
			el.res.ConnectionEndpointResult = ua.StatusBadNothingToDo
			return false
		}
		sc := x.createOne(el, d.Parameter)
		el.res.ConnectionEndpointResult = sc
		if sc != ua.StatusOK {
			return false
		}
		el.res.ConnectionEndpointID = el.ep.id
	}
	return true
}

func (x *call) createOne(el *element, p *uafx.PubSubConnectionEndpointParameter) ua.StatusCode {
	c := x.c
	base := ua.NewNumericNodeID(c.ns.AC, fxacid.ConnectionEndpointType)
	ps := ua.NewNumericNodeID(c.ns.AC, fxacid.PubSubConnectionEndpointType)
	switch {
	case isNull(p.ConnectionEndpointTypeID) || p.ConnectionEndpointTypeID.Equal(base) || !c.isSubtype(p.ConnectionEndpointTypeID, base):
		return ua.StatusBadInvalidArgument
	case !p.ConnectionEndpointTypeID.Equal(ps):
		return ua.StatusBadTypeDefinitionInvalid
	case p.IsPersistent:
		return ua.StatusBadNotSupported // SupportsPersistence is not
	case p.Mode < uafx.PubSubPublisherSubscriber || p.Mode > uafx.PubSubSubscriber:
		return ua.StatusBadInvalidArgument
	case p.Mode == uafx.PubSubPublisher && c.feedbackRequired(el.fe):
		return ua.StatusBadNotSupported
	case len(p.InputVariableIDs)+len(p.OutputVariableIDs) == 0:
		return ua.StatusBadInvalidArgument
	case p.Name == "" || p.RelatedEndpoint == nil || reflect.ValueOf(*p.RelatedEndpoint).IsZero():
		return ua.StatusBadInvalidArgument
	}
	ins, outs := c.folderVariables(el.fe, "InputData"), c.folderVariables(el.fe, "OutputData")
	for _, v := range p.InputVariableIDs {
		if v == nil || !ins[v.String()] {
			return ua.StatusBadInvalidArgument
		}
	}
	for _, v := range p.OutputVariableIDs {
		if v == nil || !outs[v.String()] {
			return ua.StatusBadInvalidArgument
		}
	}
	existing := x.endpointNamed(el.fe, p.Name)
	if p.IsPreconfigured {
		return x.usePreconfigured(el, p, existing)
	}
	if existing != nil {
		return ua.StatusBadBrowseNameDuplicated
	}
	c.mu.Lock()
	n := len(c.endpoints)
	c.mu.Unlock()
	if c.opts.MaxConnections > 0 && n >= int(c.opts.MaxConnections) {
		return ua.StatusBadResourceUnavailable
	}
	cm := ""
	if caller, ok := server.MethodCallerFromContext(x.ctx); ok {
		cm = caller.ClientApplicationURI
	}
	e, sc := c.createEndpoint(el.fe, p, cm)
	if sc != ua.StatusOK {
		return sc
	}
	el.ep = e
	x.created = append(x.created, e)
	return ua.StatusOK
}

// endpointNamed returns the node in the ConnectionEndpoints folder of fe
// with the name name.
func (x *call) endpointNamed(fe *ua.NodeID, name string) *ua.NodeID {
	f := x.c.childID(fe, "ConnectionEndpoints")
	for _, r := range x.c.children(f, id.HierarchicalReferences) {
		if r.BrowseName != nil && r.BrowseName.Name == name {
			return r.NodeID.NodeID
		}
	}
	return nil
}

// feedbackRequired reports whether the FeedbackSignalRequired capability
// of fe is TRUE (Part 81 §6.4.7).
func (c *Connections) feedbackRequired(fe *ua.NodeID) bool {
	v, _ := val(c.value(c.childID(c.childID(fe, "Capabilities"), "FeedbackSignalRequired"))).(bool)
	return v
}

// usePreconfigured checks the preconfigured endpoint n against p and sets
// its IsPersistent, CleanupTimeout and RelatedEndpoint (Part 81
// §6.2.4.3.5).
func (x *call) usePreconfigured(el *element, p *uafx.PubSubConnectionEndpointParameter, n *ua.NodeID) ua.StatusCode {
	c := x.c
	if n == nil {
		return ua.StatusBadInvalidArgument
	}
	c.mu.Lock()
	e := c.endpoints[n.String()]
	c.mu.Unlock()
	if e == nil || !sameNodes(e.inputs, p.InputVariableIDs) || !sameNodes(e.outputs, p.OutputVariableIDs) {
		return ua.StatusBadInvalidArgument
	}
	relID := c.childID(n, "RelatedEndpoint")
	old := c.value(relID)
	if c.inUse(old) {
		return ua.StatusBadInvalidState
	}
	body, err := ua.Encode(p.RelatedEndpoint)
	if err != nil {
		return ua.StatusBadInvalidArgument
	}
	rel := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewNumericExpandedNodeID(c.ns.Data, fxdataid.RelatedEndpointDataTypeEncodingDefaultBinary), Value: body}
	cleanupID := c.childID(n, "CleanupTimeout")
	oldCleanup, oldDuration := c.value(cleanupID), e.cleanup
	c.write(relID, ua.MustVariant(rel))
	c.write(cleanupID, ua.MustVariant(p.CleanupTimeout))
	c.write(c.childID(n, "IsPersistent"), ua.MustVariant(false))
	c.mu.Lock()
	e.cleanup = -1
	if d, ok := p.CleanupTimeoutDuration(); ok {
		e.cleanup = d
	}
	c.mu.Unlock()
	x.restore = append(x.restore, func() {
		c.write(relID, old)
		c.write(cleanupID, oldCleanup)
		c.mu.Lock()
		e.cleanup = oldDuration
		c.mu.Unlock()
	})
	el.ep = e
	return ua.StatusOK
}

// inUse reports whether a RelatedEndpoint value names another end (Part 81
// Table 12: a preconfigured ConnectionEndpoint in use).
func (c *Connections) inUse(v *ua.Variant) bool {
	eo, ok := val(v).(*ua.ExtensionObject)
	if !ok || eo == nil {
		return false
	}
	body, _ := eo.Value.([]byte)
	if body == nil {
		body = eo.RawBody
	}
	var r uafx.RelatedEndpoint
	if _, err := ua.Decode(body, &r); err != nil {
		return false
	}
	return r.Address != "" || r.ConnectionEndpointName != "" || len(r.ConnectionEndpointPath) > 0
}

// write sets the Value of the Variable n, if any, as the server: the
// Variables it writes (health, members of a ConnectionEndpoint) are
// read-only to clients. It notifies the monitored items of n.
func (c *Connections) write(n *ua.NodeID, v any) {
	node := c.node(n)
	if node == nil {
		return
	}
	if err := node.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(v)); err != nil {
		c.log.Debug("uafx: value not written", "node", n, "error", err)
		return
	}
	c.srv.ChangeNotification(n)
}

func sameNodes(a, b []*ua.NodeID) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, n := range a {
		set[n.String()] = true
	}
	for _, n := range b {
		if n == nil || !set[n.String()] {
			return false
		}
	}
	return true
}

// endpointOf resolves the ConnectionEndpoint of el for a command that needs
// one (Part 81 Table 12).
func (x *call) endpointOf(el *element) bool {
	if el.ep != nil {
		return true
	}
	if !x.checkFE(el) {
		return false
	}
	d := el.cfg.ConnectionEndpoint
	var sc ua.StatusCode
	switch {
	case d == nil || d.Parameter != nil:
		// A Parameter whose creation did not run: nothing to work on.
		sc = ua.StatusBadInvalidArgument
	case isNull(d.Node):
		sc = ua.StatusBadNodeIDInvalid
	case x.c.node(d.Node) == nil:
		sc = ua.StatusBadNodeIDUnknown
	default:
		x.c.mu.Lock()
		e := x.c.endpoints[d.Node.String()]
		x.c.mu.Unlock()
		switch {
		case e != nil && e.fe.Equal(el.fe):
			el.ep = e
			el.res.ConnectionEndpointID = e.id
			el.res.ConnectionEndpointResult = ua.StatusOK
			return true
		case e != nil || x.c.isA(d.Node, fxacid.ConnectionEndpointType):
			sc = ua.StatusBadNodeIDUnknown // not in this FunctionalEntity
		default:
			sc = ua.StatusBadInvalidArgument
		}
	}
	el.res.ConnectionEndpointResult = sc
	return false
}

// --- EstablishControlCmd, ReassignControlCmd ----------------------------

// control runs EstablishControlCmd (Part 81 §6.2.4.3.6) or, with reassign,
// ReassignControlCmd (§6.2.4.3.8) on the ControlGroups of each element. An
// element without ControlGroups has nothing to do.
//
// EstablishControlCmd controls a ControlGroup for the client of the
// caller, whose ApplicationUri is the LockContext; ReassignControlCmd gives
// it to the ConnectionEndpoint of the element, whose NodeId is the
// LockContext. The LockStatus of the Method becomes a StatusCode: -1 (a
// Lock held) is Bad_Locked for EstablishControl, -1 (not locked) and -2
// (cannot be locked or reassigned) Bad_InvalidState. A ControlGroup another
// client or ConnectionEndpoint controls is not reassigned:
// Bad_UserAccessDenied (Tables 65 and 70).
func (x *call) control(reassign bool) bool {
	for _, el := range x.els {
		if len(el.cfg.ControlGroups) == 0 {
			continue
		}
		if !x.endpointOf(el) {
			return false
		}
		res := el.res.EstablishControlResult
		if reassign {
			res = el.res.ReassignControlResult
		}
		scope := map[string]bool{}
		for _, fe := range x.c.feScope(el.fe) {
			for _, n := range x.c.hierarchy(x.c.childID(fe, "ControlGroups")) {
				scope[n.String()] = true
			}
		}
		for i, g := range el.cfg.ControlGroups {
			switch {
			case isNull(g):
				res[i] = ua.StatusBadNodeIDInvalid
			case x.c.node(g) == nil || !scope[g.String()]:
				res[i] = ua.StatusBadNodeIDUnknown
			case !x.c.isA(g, fxacid.ControlGroupType):
				res[i] = ua.StatusBadInvalidArgument
			default:
				res[i] = x.controlOne(el, g, reassign)
			}
			if res[i] != ua.StatusOK {
				return false
			}
		}
	}
	return true
}

// controlOne runs EstablishControl or ReassignControl on the ControlGroup g
// for the element el.
func (x *call) controlOne(el *element, n *ua.NodeID, reassign bool) ua.StatusCode {
	c := x.c
	c.ctl.mu.Lock()
	g := c.ctl.groups[n.String()]
	c.ctl.mu.Unlock()
	if g == nil {
		return ua.StatusBadNotSupported
	}
	if !reassign {
		o := callerOwner(x.ctx)
		if sc := c.authorize(x.ctx, ControlRequest{Operation: ControlEstablish, Group: g.id, LockContext: o.client}); sc != ua.StatusOK {
			return sc
		}
		switch c.control(g, o) {
		case lockOK:
			x.controlled = append(x.controlled, g)
			return ua.StatusOK
		case lockBusy:
			return ua.StatusBadLocked
		}
		return ua.StatusBadInvalidState
	}
	if sc := c.authorize(x.ctx, ControlRequest{Operation: ControlReassign, Group: g.id, LockContext: el.ep.id.String()}); sc != ua.StatusOK {
		return sc
	}
	if sc := c.mayChange(actingAs(x.ctx, el.ep), g); sc != ua.StatusOK {
		return sc
	}
	o := &lockOwner{client: el.ep.id.String(), user: endpointLockingUser, endpoint: el.ep}
	if c.reassign(g, o) != lockOK {
		return ua.StatusBadInvalidState
	}
	return ua.StatusOK
}

// --- SetConfigurationDataCmd ---------------------------------------------

// configure runs SetConfigurationDataCmd (Part 81 §6.2.4.3.7): it writes
// each value with the rights of the caller.
func (x *call) configure() bool {
	for _, el := range x.els {
		if len(el.cfg.ConfigurationData) == 0 {
			continue
		}
		if !x.endpointOf(el) {
			return false
		}
		vars := x.c.folderVariables(el.fe, "ConfigurationData")
		for i, p := range el.cfg.ConfigurationData {
			sc := x.configureOne(el, p, vars)
			el.res.ConfigurationDataResult[i] = sc
			if sc != ua.StatusOK {
				return false
			}
		}
	}
	return true
}

func (x *call) configureOne(el *element, p *uafx.NodeIDValuePair, vars map[string]bool) ua.StatusCode {
	if p == nil || p.Key == nil || isNull(p.Key.Node) {
		return ua.StatusBadNodeIDInvalid
	}
	n := p.Key.Node
	if x.c.node(n) == nil {
		return ua.StatusBadNodeIDUnknown
	}
	if !vars[n.String()] {
		return ua.StatusBadInvalidArgument
	}
	cur := x.c.value(n)
	v := p.Value
	if len(p.Key.ArrayIndex) > 0 {
		if _, sc := arrayElement(cur, p.Key.ArrayIndex); sc != ua.StatusOK {
			return ua.StatusBadInvalidArgument
		}
		arr := reflect.ValueOf(val(cur))
		cp := reflect.MakeSlice(arr.Type(), arr.Len(), arr.Len())
		reflect.Copy(cp, arr)
		ev := reflect.ValueOf(val(v))
		if !ev.IsValid() || ev.Type() != arr.Type().Elem() {
			return ua.StatusBadTypeMismatch
		}
		cp.Index(int(p.Key.ArrayIndex[0])).Set(ev)
		v = ua.MustVariant(cp.Interface())
	} else if cur != nil && val(cur) != nil && (v == nil || reflect.TypeOf(val(v)) != reflect.TypeOf(val(cur))) {
		return ua.StatusBadTypeMismatch
	}
	// The command acts as the ConnectionEndpoint, which may own the Locks
	// of a ControlGroup (Part 81 §6.5.2); a Lock that rejects the write is
	// Bad_UserAccessDenied (Table 14). Writing through the endpoint's own
	// Lock needs the ControlAuthorizer.
	if l := x.c.endpointLock(el.ep, n); l != nil {
		if sc := x.c.authorize(x.ctx, ControlRequest{Operation: ControlWriteAsEndpoint, Group: l.group.id, Lock: l.id,
			Endpoint: el.ep.id, Node: n}); sc != ua.StatusOK {
			return ua.StatusBadUserAccessDenied
		}
	}
	switch sc := x.c.srv.WriteValue(actingAs(x.ctx, el.ep), n, v); sc {
	case ua.StatusOK:
		return ua.StatusOK
	case ua.StatusBadNotWritable, ua.StatusBadUserAccessDenied, ua.StatusBadSecurityModeInsufficient, ua.StatusBadLocked:
		return ua.StatusBadUserAccessDenied
	case ua.StatusBadTypeMismatch:
		return ua.StatusBadTypeMismatch
	default:
		return ua.StatusBadConfigurationError
	}
}

// --- SetCommunicationConfigurationCmd ------------------------------------

// The mask bits of a PubSubConfigurationRefDataType (Part 14 §6.2.12.3).
const (
	refReader = ua.PubSubConfigurationRefMaskReferenceReader
	refWriter = ua.PubSubConfigurationRefMaskReferenceWriter
	refConn   = ua.PubSubConfigurationRefMaskReferenceConnection
	refWG     = ua.PubSubConfigurationRefMaskReferenceWriterGroup
	refRG     = ua.PubSubConfigurationRefMaskReferenceReaderGroup
	refAdd    = ua.PubSubConfigurationRefMaskElementAdd
	refModify = ua.PubSubConfigurationRefMaskElementModify
	refPDS    = ua.PubSubConfigurationRefMaskReferencePubDataset
)

// communicate runs SetCommunicationConfigurationCmd (Part 81
// §6.2.4.3.9.2): it applies the PubSub configuration as CloseAndUpdate
// does, sets the ToDataSetReader and ToDataSetWriter References of the
// CommunicationLinks and checks them.
func (x *call) communicate() bool {
	cc := x.req.CommunicationConfigurations[0]
	out := x.res.CommunicationConfigurationResults[0]
	if len(cc.ConfigurationReferences) == 0 {
		out.Result = ua.StatusBadNothingToDo
		return false
	}
	if cc.PubSubConfiguration == nil {
		out.Result = ua.StatusBadConfigurationError
		return false
	}
	// The links refer into the configuration of this call: check them
	// before it is applied.
	for _, el := range x.els {
		if el.cfg.CommunicationLinks == nil {
			continue
		}
		if !x.endpointOf(el) {
			out.Result = ua.StatusBadNothingToDo
			return false
		}
		if sc := checkLinks(cc.PubSubConfiguration, el.cfg.CommunicationLinks, el.ep.mode); sc != ua.StatusOK {
			el.res.CommunicationLinksResult = sc
			out.Result = ua.StatusBadNothingToDo
			return false
		}
	}
	x.c.mu.Lock()
	hook := x.c.beforeUpdate
	x.c.mu.Unlock()
	if hook != nil {
		hook()
	}
	u, sc := x.c.srv.UpdatePubSubConfiguration(x.ctx, cc.PubSubConfiguration, cc.RequireCompleteUpdate, cc.ConfigurationReferences)
	if sc != ua.StatusOK {
		out.Result = sc
		return false
	}
	x.update = u
	out.ChangesApplied, out.ReferenceResults, out.ConfigurationValues, out.ConfigurationObjects =
		u.ChangesApplied, u.ReferenceResults, u.ConfigurationValues, u.ConfigurationObjects
	out.Result = ua.StatusOK
	for _, r := range u.ReferenceResults {
		if r.Uint32()&0x80000000 != 0 {
			out.Result = ua.StatusBadConfigurationError
			return false
		}
	}
	for _, el := range x.els {
		l := el.cfg.CommunicationLinks
		if l == nil {
			continue
		}
		sc := x.link(el, cc, l)
		el.res.CommunicationLinksResult = sc
		if sc != ua.StatusOK {
			return false
		}
	}
	return true
}

// checkLinks checks the CommunicationLinks l of an endpoint of mode mode
// against the configuration cfg they refer into (Part 81 §10.13.3, Table
// 16).
func checkLinks(cfg *ua.PubSubConfiguration2DataType, l *uafx.PubSubCommunicationLinkConfiguration, mode uafx.PubSubConnectionEndpointMode) ua.StatusCode {
	reader, writer := l.DataSetReaderRef, l.DataSetWriterRef
	set := func(r *ua.PubSubConfigurationRefDataType) bool { return r != nil && r.ConfigurationMask != 0 }
	if set(reader) && reader.ConfigurationMask != refReader || set(writer) && writer.ConfigurationMask != refWriter {
		return ua.StatusBadInvalidArgument
	}
	if set(reader) != mode.Subscribes() || set(writer) != mode.Publishes() {
		return ua.StatusBadNoMatch
	}
	if set(reader) && readerAt(cfg, reader) == nil || set(writer) && writerAt(cfg, writer) == nil {
		return ua.StatusBadNotFound
	}
	return ua.StatusOK
}

func readerAt(cfg *ua.PubSubConfiguration2DataType, r *ua.PubSubConfigurationRefDataType) *ua.DataSetReaderDataType {
	if int(r.ConnectionIndex) >= len(cfg.Connections) || cfg.Connections[r.ConnectionIndex] == nil {
		return nil
	}
	gs := cfg.Connections[r.ConnectionIndex].ReaderGroups
	if int(r.GroupIndex) >= len(gs) || gs[r.GroupIndex] == nil || int(r.ElementIndex) >= len(gs[r.GroupIndex].DataSetReaders) {
		return nil
	}
	return gs[r.GroupIndex].DataSetReaders[r.ElementIndex]
}

func writerAt(cfg *ua.PubSubConfiguration2DataType, r *ua.PubSubConfigurationRefDataType) *ua.DataSetWriterDataType {
	if int(r.ConnectionIndex) >= len(cfg.Connections) || cfg.Connections[r.ConnectionIndex] == nil {
		return nil
	}
	gs := cfg.Connections[r.ConnectionIndex].WriterGroups
	if int(r.GroupIndex) >= len(gs) || gs[r.GroupIndex] == nil || int(r.ElementIndex) >= len(gs[r.GroupIndex].DataSetWriters) {
		return nil
	}
	return gs[r.GroupIndex].DataSetWriters[r.ElementIndex]
}

// link sets the References of the endpoint of el to the DataSetReader and
// DataSetWriter of its CommunicationLinks l and checks their DataSets
// (Part 81 §6.2.4.3.9.2).
func (x *call) link(el *element, cc *uafx.PubSubCommunicationConfiguration, l *uafx.PubSubCommunicationLinkConfiguration) ua.StatusCode {
	c, rt, e := x.c, x.c.srv.PubSub(), el.ep
	cfg := cc.PubSubConfiguration
	has := func(op ua.PubSubConfigurationRefMask, r *ua.PubSubConfigurationRefDataType) bool {
		for _, ref := range cc.ConfigurationReferences {
			if ref != nil && ref.ConfigurationMask&op != 0 && ref.ConfigurationMask&r.ConfigurationMask != 0 &&
				ref.ConnectionIndex == r.ConnectionIndex && ref.GroupIndex == r.GroupIndex && ref.ElementIndex == r.ElementIndex {
				return true
			}
		}
		return false
	}
	// addedAt: the call adds the element of kind on the path of r (an
	// ElementAdd reference), level 0 its connection, 1 its group; a
	// PublishedDataSet by its ElementIndex (Part 14 §6.2.12.3).
	addedAt := func(kind ua.PubSubConfigurationRefMask, r *ua.PubSubConfigurationRefDataType, level int) bool {
		for _, ref := range cc.ConfigurationReferences {
			if ref == nil || ref.ConfigurationMask&refAdd == 0 || ref.ConfigurationMask&kind == 0 {
				continue
			}
			switch {
			case level == 0 && ref.ConnectionIndex == r.ConnectionIndex,
				level == 1 && ref.ConnectionIndex == r.ConnectionIndex && ref.GroupIndex == r.GroupIndex,
				level == 2 && ref.ElementIndex == r.ElementIndex:
				return true
			}
		}
		return false
	}
	var readerNode, writerNode *ua.NodeID
	if r := l.DataSetReaderRef; r != nil && r.ConfigurationMask != 0 {
		conn := cfg.Connections[r.ConnectionIndex]
		g := conn.ReaderGroups[r.GroupIndex]
		connID, gid, cid, ok := lookupPath(rt, pubsub.KindReaderGroup, pubsub.KindDataSetReader,
			x.assigned(refConn, r, 0, conn.Name), x.assigned(refRG, r, 1, g.Name), x.assigned(refReader, r, 2, readerAt(cfg, r).Name))
		if !ok {
			return ua.StatusBadNotFound
		}
		x.markCreated(connID, addedAt(refConn, r, 0))
		x.markCreated(gid, addedAt(refRG, r, 1))
		dr, err := rt.DataSetReaderConfig(cid)
		if err != nil {
			return ua.StatusBadNotFound
		}
		var meta *ua.ConfigurationVersionDataType
		if dr.DataSetMetaData != nil {
			meta = dr.DataSetMetaData.ConfigurationVersion
		}
		if !versionMatches(l.ExpectedSubscribedDataSetVersion, meta) {
			return ua.StatusBadConfigurationError
		}
		if !contains(targetsOf(dr), e.inputs) {
			return ua.StatusBadNoMatch
		}
		readerNode, _ = c.srv.PubSubNodeID(cid)
		x.setLink(e, true, readerNode, has(refAdd, r), has(refModify, r))
	}
	if r := l.DataSetWriterRef; r != nil && r.ConfigurationMask != 0 {
		conn := cfg.Connections[r.ConnectionIndex]
		g := conn.WriterGroups[r.GroupIndex]
		connID, gid, cid, ok := lookupPath(rt, pubsub.KindWriterGroup, pubsub.KindDataSetWriter,
			x.assigned(refConn, r, 0, conn.Name), x.assigned(refWG, r, 1, g.Name), x.assigned(refWriter, r, 2, writerAt(cfg, r).Name))
		if !ok {
			return ua.StatusBadNotFound
		}
		x.markCreated(connID, addedAt(refConn, r, 0))
		x.markCreated(gid, addedAt(refWG, r, 1))
		dw, err := rt.DataSetWriterConfig(cid)
		if err != nil {
			return ua.StatusBadNotFound
		}
		pds := publishedDataSet(rt, dw.DataSetName)
		if pid, ok := rt.Lookup(pubsub.KindPublishedDataSet, pubsub.Root, dw.DataSetName); ok {
			i := slices.IndexFunc(cfg.PublishedDataSets, func(p *ua.PublishedDataSetDataType) bool {
				return p != nil && x.assignedPDS(cfg, p) == dw.DataSetName
			})
			if i >= 0 && i <= math.MaxUint16 {
				x.markCreated(pid, addedAt(refPDS, &ua.PubSubConfigurationRefDataType{ElementIndex: uint16(i)}, 2))
			}
		}
		var meta *ua.ConfigurationVersionDataType
		if pds != nil && pds.DataSetMetaData != nil {
			meta = pds.DataSetMetaData.ConfigurationVersion
		}
		if !versionMatches(l.ExpectedPublishedDataSetVersion, meta) {
			return ua.StatusBadConfigurationError
		}
		if !contains(publishedOf(pds), e.outputs) {
			return ua.StatusBadNoMatch
		}
		writerNode, _ = c.srv.PubSubNodeID(cid)
		x.setLink(e, false, writerNode, has(refAdd, r), has(refModify, r))
	}
	if readerNode == nil && writerNode == nil {
		return ua.StatusBadNotFound
	}
	return ua.StatusOK
}

// markCreated records that the call created the component id, so that
// CloseConnections with Remove removes it once nothing uses it (Part 81
// §6.2.5.2); the rollback forgets it. It is the call's when the call adds
// it (added: an ElementAdd reference) and the update of the call created
// it in the runtime (PubSubConfigurationUpdate.Created, recorded as the
// update applied the configuration): a component that was there, one
// another client added meanwhile, one the call matched or modified is not.
func (x *call) markCreated(id pubsub.ComponentID, added bool) {
	c := x.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if id == 0 || !added || !x.update.Created(id) || c.created[id] {
		return
	}
	c.created[id] = true
	x.linkUndo = append(x.linkUndo, func() {
		c.mu.Lock()
		delete(c.created, id)
		c.mu.Unlock()
	})
}

// assignedPDS returns the Name of the PublishedDataSet p of cfg: its own,
// or the one the server assigned to it (Part 81 §6.16.3).
func (x *call) assignedPDS(cfg *ua.PubSubConfiguration2DataType, p *ua.PublishedDataSetDataType) string {
	i := slices.Index(cfg.PublishedDataSets, p)
	for _, v := range x.update.ConfigurationValues {
		if e := v.ConfigurationElement; e != nil && e.ConfigurationMask&refPDS != 0 && v.Name != "" && int(e.ElementIndex) == i {
			return v.Name
		}
	}
	return p.Name
}

// assigned returns the Name the configuration of the call has for the
// element of kind on the path of r (level 0 its connection, 1 its group, 2
// the element), name when the call did not assign one: an element added
// with a null Name gets one from the server, given in the
// ConfigurationValues (Part 81 §6.16.3), and the links refer to it.
func (x *call) assigned(kind ua.PubSubConfigurationRefMask, r *ua.PubSubConfigurationRefDataType, level int, name string) string {
	for _, v := range x.update.ConfigurationValues {
		e := v.ConfigurationElement
		if e == nil || e.ConfigurationMask&kind == 0 || v.Name == "" || e.ConnectionIndex != r.ConnectionIndex ||
			level >= 1 && e.GroupIndex != r.GroupIndex || level == 2 && e.ElementIndex != r.ElementIndex {
			continue
		}
		return v.Name
	}
	return name
}

// setLink is Connections.setLink with an undo for the rollback.
// own is set when the call added the element; modified when it modified
// it in place (ElementModify).
func (x *call) setLink(e *endpoint, reader bool, n *ua.NodeID, own, modified bool) {
	c := x.c
	c.mu.Lock()
	prev, prevOwn := e.writer, e.ownWriter
	if reader {
		prev, prevOwn = e.reader, e.ownReader
	}
	c.mu.Unlock()
	// A later call that links the element again, or modifies the one the
	// endpoint has (ElementModify, as a ConnectionManager does to adapt a
	// DataSetReader to a PublisherId, Part 81 §6.16.3; the runtime may give
	// it a new node), keeps it the endpoint's own: CloseConnections still
	// removes what the endpoint's calls created (§6.2.5.2).
	own = own || prevOwn && (prev.Equal(n) || modified)
	c.setLinkLocked(e, reader, n, own)
	x.linkUndo = append(x.linkUndo, func() { c.setLinkLocked(e, reader, prev, prevOwn) })
}

// setLinkLocked is setLink under c.mu for the fields of e.
func (c *Connections) setLinkLocked(e *endpoint, reader bool, n *ua.NodeID, own bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLink(e, reader, n, own)
}

// lookupPath finds connection/group/element in the runtime and returns the
// ids of all three.
func lookupPath(rt *pubsub.PubSub, groupKind, kind pubsub.ComponentKind, conn, group, name string) (connID, gid, id pubsub.ComponentID, ok bool) {
	connID, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, conn)
	if !ok {
		return 0, 0, 0, false
	}
	gid, ok = rt.Lookup(groupKind, connID, group)
	if !ok {
		return 0, 0, 0, false
	}
	id, ok = rt.Lookup(kind, gid, name)
	return connID, gid, id, ok
}

// versionMatches checks a DataSet ConfigurationVersion against the expected
// one: a MajorVersion of 0 checks nothing, a MinorVersion of 0 only the
// MajorVersion (Part 81 §6.2.4.3.9.2).
func versionMatches(want, got *ua.ConfigurationVersionDataType) bool {
	if want == nil || want.MajorVersion == 0 {
		return true
	}
	if got == nil || got.MajorVersion != want.MajorVersion {
		return false
	}
	return want.MinorVersion == 0 || got.MinorVersion == want.MinorVersion
}

// targetsOf returns the TargetVariables of the SubscribedDataSet of r.
func targetsOf(r *ua.DataSetReaderDataType) map[string]bool {
	out := map[string]bool{}
	if r == nil || r.SubscribedDataSet == nil {
		return out
	}
	if t, ok := r.SubscribedDataSet.Value.(*ua.TargetVariablesDataType); ok && t != nil {
		for _, v := range t.TargetVariables {
			if v != nil && v.TargetNodeID != nil {
				out[v.TargetNodeID.String()] = true
			}
		}
	}
	return out
}

// publishedDataSet returns the PublishedDataSet name of the runtime.
func publishedDataSet(rt *pubsub.PubSub, name string) *ua.PublishedDataSetDataType {
	for _, p := range rt.Configuration().PublishedDataSets {
		if p != nil && p.Name == name {
			return p
		}
	}
	return nil
}

// publishedOf returns the published Variables of p.
func publishedOf(p *ua.PublishedDataSetDataType) map[string]bool {
	out := map[string]bool{}
	if p == nil || p.DataSetSource == nil {
		return out
	}
	if d, ok := p.DataSetSource.Value.(*ua.PublishedDataItemsDataType); ok && d != nil {
		for _, v := range d.PublishedData {
			if v != nil && v.PublishedVariable != nil {
				out[v.PublishedVariable.String()] = true
			}
		}
	}
	return out
}

func contains(set map[string]bool, nodes []*ua.NodeID) bool {
	for _, n := range nodes {
		if !set[n.String()] {
			return false
		}
	}
	return true
}

// --- EnableCommunicationCmd ----------------------------------------------

// enable runs EnableCommunicationCmd (Part 81 §6.2.4.3.10.2): it enables
// the DataSetReader and DataSetWriter of each endpoint and their groups and
// connections.
func (x *call) enable() bool {
	rt := x.c.srv.PubSub()
	for _, el := range x.els {
		if !x.endpointOf(el) {
			el.res.EnableCommunicationResult = ua.StatusBadNothingToDo
			return false
		}
		if sc := x.enableOne(rt, el.ep); sc != ua.StatusOK {
			el.res.EnableCommunicationResult = sc
			return false
		}
		el.res.EnableCommunicationResult = ua.StatusOK
	}
	return true
}

func (x *call) enableOne(rt *pubsub.PubSub, e *endpoint) ua.StatusCode {
	x.c.mu.Lock()
	reader, writer, mode := e.reader, e.writer, e.mode
	x.c.mu.Unlock()
	if mode.Subscribes() && reader == nil || mode.Publishes() && writer == nil {
		return ua.StatusBadInvalidState
	}
	if reader != nil && x.c.inputsTaken(e) {
		return ua.StatusBadRequestNotAllowed
	}
	for _, n := range []*ua.NodeID{reader, writer} {
		cid, ok := x.c.componentOf(n)
		if n == nil {
			continue
		}
		if !ok {
			return ua.StatusBadInvalidState
		}
		// The element, its group and its connection (Part 81
		// §6.2.4.3.10.2), each enabled unless it is already.
		for id := cid; id != pubsub.Root; {
			info, err := rt.Component(id)
			if err != nil {
				return ua.StatusBadInvalidState
			}
			if !info.Enabled {
				if err := x.c.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error { return rt.Enable(id) }); err != nil {
					return pubsub.StatusCodeOf(err)
				}
				x.enabled = append(x.enabled, id)
			}
			id = info.Parent
		}
	}
	x.c.mu.Lock()
	if e.cleanupOff {
		e.cleanupOff = false
		x.cleanupsOn = append(x.cleanupsOn, e)
	}
	x.c.mu.Unlock()
	return ua.StatusOK
}

// inputsTaken reports whether another endpoint with an enabled
// DataSetReader has an InputVariable of e (Part 81 Table 12, Table 17).
func (c *Connections) inputsTaken(e *endpoint) bool {
	c.mu.Lock()
	others := make([]*endpoint, 0, len(c.endpoints))
	for _, o := range c.endpoints {
		if o != e && o.reader != nil {
			others = append(others, o)
		}
	}
	c.mu.Unlock()
	mine := map[string]bool{}
	for _, n := range e.inputs {
		mine[n.String()] = true
	}
	for _, o := range others {
		cid, ok := c.componentOf(o.reader)
		if !ok {
			continue
		}
		info, err := c.srv.PubSub().Component(cid)
		if err != nil || !info.Enabled {
			continue
		}
		for _, n := range o.inputs {
			if mine[n.String()] {
				return true
			}
		}
	}
	return false
}

// auditCall reports an AuditUpdateMethodResultEventType event for a call of
// EstablishConnections or CloseConnections when the server audits (Part 81
// §6.2.4.2, §6.2.5.1, §8.4).
func (c *Connections) auditCall(ctx context.Context, ac *automationComponent, method *ua.NodeID, args, out []*ua.Variant, sc ua.StatusCode) {
	if !c.srv.Auditing() {
		return
	}
	if args == nil {
		args = []*ua.Variant{}
	}
	if out == nil {
		out = []*ua.Variant{}
	}
	name := "EstablishConnections"
	if n := c.node(method); n != nil && n.BrowseName() != nil {
		name = n.BrowseName().Name
	}
	ok := sc.Uint32()&0x80000000 == 0
	msg := name + " of " + ac.id.String()
	if !ok {
		msg += ": " + sc.Error()
	} else if !strings.Contains(msg, "?") {
		msg += ": " + sc.Error()
	}
	c.srv.ReportAuditEvent(ctx, &server.BaseEvent{
		EventType:  ua.NewNumericNodeID(c.ns.Data, fxdataid.AuditUpdateMethodResultEventType),
		SourceNode: ac.id,
		SourceName: "Method/" + name,
		Message:    ua.NewLocalizedText(msg),
		Fields: map[string]*ua.Variant{
			"Status":          ua.MustVariant(ok),
			"MethodId":        ua.MustVariant(method),
			"InputArguments":  ua.MustVariant(variants(args)),
			"OutputArguments": ua.MustVariant(variants(out)),
			"StatusCodeId":    ua.MustVariant(sc),
		},
	}, ac.id)
}

func variants(vs []*ua.Variant) []*ua.Variant {
	out := make([]*ua.Variant, len(vs))
	for i, v := range vs {
		if v == nil {
			v = &ua.Variant{}
		}
		out[i] = v
	}
	return out
}
