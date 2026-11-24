// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// translateSession is a Session whose TranslateBrowsePaths returns res or
// err and records the requests; the other services fail.
type translateSession struct {
	offlineSession
	res  *ua.TranslateBrowsePathsToNodeIDsResponse
	err  error
	reqs []*ua.TranslateBrowsePathsToNodeIDsRequest
}

type offlineSession struct{}

var errOffline = errors.New("offline")

func (offlineSession) NamespaceArray(context.Context) ([]string, error) { return nil, errOffline }
func (offlineSession) Read(context.Context, *ua.ReadRequest) (*ua.ReadResponse, error) {
	return nil, errOffline
}
func (offlineSession) Browse(context.Context, *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	return nil, errOffline
}
func (offlineSession) TranslateBrowsePaths(context.Context, *ua.TranslateBrowsePathsToNodeIDsRequest) (*ua.TranslateBrowsePathsToNodeIDsResponse, error) {
	return nil, errOffline
}
func (offlineSession) Call(context.Context, *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	return nil, errOffline
}
func (offlineSession) Close(context.Context) error { return nil }

func (s *translateSession) TranslateBrowsePaths(_ context.Context, req *ua.TranslateBrowsePathsToNodeIDsRequest) (*ua.TranslateBrowsePathsToNodeIDsResponse, error) {
	s.reqs = append(s.reqs, req)
	return s.res, s.err
}

func found(ids ...*ua.NodeID) *ua.TranslateBrowsePathsToNodeIDsResponse {
	r := &ua.BrowsePathResult{StatusCode: ua.StatusOK}
	for _, n := range ids {
		r.Targets = append(r.Targets, &ua.BrowsePathTarget{TargetID: &ua.ExpandedNodeID{NodeID: n}, RemainingPathIndex: 0xffffffff})
	}
	return &ua.TranslateBrowsePathsToNodeIDsResponse{Results: []*ua.BrowsePathResult{r}}
}

func testTarget(s Session) *target {
	return &target{
		addr:  ServerAddress{Address: "opc.tcp://ac:4840"},
		sess:  s,
		idx:   map[string]uint16{"urn:a": 2, "urn:b": 3},
		cache: &resolutionCache{nodes: map[string]*ua.NodeID{}},
	}
}

func fxOf(t *testing.T, err error) Failure {
	t.Helper()
	var se *stepError
	require.ErrorAs(t, err, &se)
	return Failure{FxError: se.fx, Status: se.status}
}

func TestResolvePortable(t *testing.T) {
	ctx := context.Background()
	start := ua.NewNumericNodeID(2, 1)
	want := ua.NewNumericNodeID(3, 9)
	s := &translateSession{res: found(want)}
	tg := testTarget(s)

	n, err := tg.resolvePortable(ctx, &uafx.PortableNodeIdentifier{Node: &ua.PortableNodeID{NamespaceURI: "urn:b", Identifier: ua.NewStringNodeID(1, "x")}}, start)
	require.NoError(t, err)
	assert.Equal(t, ua.NewStringNodeID(3, "x"), n)

	path := &uafx.PortableRelativePath{Elements: []*uafx.PortableRelativePathElement{
		{ReferenceTypeID: &ua.PortableNodeID{Identifier: ua.NewNumericNodeID(0, 47)}, IncludeSubtypes: true, TargetName: &ua.PortableQualifiedName{NamespaceURI: "urn:a", Name: "A"}},
		{TargetName: &ua.PortableQualifiedName{NamespaceURI: uaNamespace, Name: "B"}},
		{TargetName: &ua.PortableQualifiedName{Name: "C"}},
	}}
	n, err = tg.resolvePortable(ctx, &uafx.PortableNodeIdentifier{IdentifierBrowsePath: path}, start)
	require.NoError(t, err)
	assert.Equal(t, want, n)
	require.Len(t, s.reqs, 1)
	els := s.reqs[0].BrowsePaths[0].RelativePath.Elements
	assert.Equal(t, &ua.QualifiedName{NamespaceIndex: 2, Name: "A"}, els[0].TargetName)
	assert.Equal(t, &ua.QualifiedName{Name: "B"}, els[1].TargetName)
	assert.Equal(t, &ua.QualifiedName{NamespaceIndex: 1, Name: "C"}, els[2].TargetName)
	assert.Equal(t, ua.NewNumericNodeID(1, 47), els[0].ReferenceTypeID, "an empty NamespaceUri is the local server (CL-5)")

	// cached
	_, err = tg.resolvePortable(ctx, &uafx.PortableNodeIdentifier{IdentifierBrowsePath: path}, start)
	require.NoError(t, err)
	assert.Len(t, s.reqs, 1)

	alias := "x"
	for name, tc := range map[string]struct {
		p    *uafx.PortableNodeIdentifier
		want Failure
	}{
		"nil":             {nil, Failure{uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError}},
		"no identifier":   {&uafx.PortableNodeIdentifier{Node: &ua.PortableNodeID{}}, Failure{uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError}},
		"alias":           {&uafx.PortableNodeIdentifier{Alias: &alias}, Failure{uafx.FxErrorAliasNameProcessingError, ua.StatusBadNotSupported}},
		"null":            {&uafx.PortableNodeIdentifier{}, Failure{uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError}},
		"unknown ns":      {&uafx.PortableNodeIdentifier{Node: &ua.PortableNodeID{NamespaceURI: "urn:z", Identifier: ua.NewNumericNodeID(0, 1)}}, Failure{uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch}},
		"no target name":  {&uafx.PortableNodeIdentifier{IdentifierBrowsePath: &uafx.PortableRelativePath{Elements: []*uafx.PortableRelativePathElement{{}}}}, Failure{uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadConfigurationError}},
		"unknown ref ns":  {&uafx.PortableNodeIdentifier{IdentifierBrowsePath: &uafx.PortableRelativePath{Elements: []*uafx.PortableRelativePathElement{{ReferenceTypeID: &ua.PortableNodeID{NamespaceURI: "urn:z", Identifier: ua.NewNumericNodeID(0, 1)}, TargetName: &ua.PortableQualifiedName{Name: "A"}}}}}, Failure{uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch}},
		"unknown name ns": {&uafx.PortableNodeIdentifier{IdentifierBrowsePath: &uafx.PortableRelativePath{Elements: []*uafx.PortableRelativePathElement{{TargetName: &ua.PortableQualifiedName{NamespaceURI: "urn:z", Name: "A"}}}}}, Failure{uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tg.resolvePortable(ctx, tc.p, start)
			assert.Equal(t, tc.want, fxOf(t, err))
			assert.ErrorIs(t, err, ErrManager)
		})
	}

	s.err = errOffline
	_, err = testTarget(s).resolvePortable(ctx, &uafx.PortableNodeIdentifier{IdentifierBrowsePath: path}, start)
	assert.Equal(t, Failure{uafx.FxErrorResolvingPathsError, ua.StatusBadCommunicationError}, fxOf(t, err))
}

func TestTranslate(t *testing.T) {
	ctx := context.Background()
	start := ua.NewNumericNodeID(2, 1)
	rp := &ua.RelativePath{Elements: []*ua.RelativePathElement{{TargetName: &ua.QualifiedName{NamespaceIndex: 2, Name: "A"}}, {}}}
	assert.Equal(t, "/2:A/", pathString(rp))

	n, err := testTarget(offlineSession{}).translate(ctx, start, nil)
	require.NoError(t, err)
	assert.Equal(t, start, n)

	foreign := found(ua.NewNumericNodeID(2, 5))
	foreign.Results[0].Targets[0].TargetID.ServerIndex = 1
	partial := found(ua.NewNumericNodeID(2, 5))
	partial.Results[0].Targets[0].RemainingPathIndex = 1
	for name, tc := range map[string]struct {
		res  *ua.TranslateBrowsePathsToNodeIDsResponse
		want Failure
	}{
		"no result":  {&ua.TranslateBrowsePathsToNodeIDsResponse{}, Failure{uafx.FxErrorResolvingPathsError, ua.StatusBadUnexpectedError}},
		"bad":        {&ua.TranslateBrowsePathsToNodeIDsResponse{Results: []*ua.BrowsePathResult{{StatusCode: ua.StatusBadNoMatch}}}, Failure{uafx.FxErrorResolvingPathsError, ua.StatusBadNoMatch}},
		"none":       {found(), Failure{uafx.FxErrorResolvingPathsError, ua.StatusBadNoMatch}},
		"foreign":    {foreign, Failure{uafx.FxErrorResolvingPathsError, ua.StatusBadNoMatch}},
		"partial":    {partial, Failure{uafx.FxErrorResolvingPathsError, ua.StatusBadNoMatch}},
		"duplicated": {found(ua.NewNumericNodeID(2, 5), ua.NewNumericNodeID(2, 6)), Failure{uafx.FxErrorResolvingPathsError, ua.StatusBadBrowseNameDuplicated}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := testTarget(&translateSession{res: tc.res}).translate(ctx, start, rp)
			assert.Equal(t, tc.want, fxOf(t, err))
		})
	}
}

func TestWithNamespace(t *testing.T) {
	g := ua.NewGUIDNodeID(1, "72962B91-FA75-4AE6-8D28-B404DC7DAF63")
	for _, n := range []*ua.NodeID{
		ua.NewNumericNodeID(1, 7),
		ua.NewStringNodeID(1, "s"),
		g,
		ua.NewByteStringNodeID(1, []byte{1, 2, 3}),
	} {
		got := withNamespace(n, 300)
		assert.Equal(t, uint16(300), got.Namespace())
		assert.Equal(t, n.Type() == ua.NodeIDTypeTwoByte || n.Type() == ua.NodeIDTypeFourByte || n.Type() == ua.NodeIDTypeNumeric, got.Type() == ua.NodeIDTypeNumeric)
		assert.Equal(t, n.StringID(), got.StringID())
	}
	tg := testTarget(offlineSession{})
	n, err := tg.mapNodeID(nil, nil)
	require.NoError(t, err)
	assert.Nil(t, n)
	_, err = tg.mapNodeID(ua.NewNumericNodeID(5, 1), namespaceScope{uaNamespace})
	assert.Equal(t, Failure{uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch}, fxOf(t, err))
	_, err = tg.fxRoot()
	assert.Equal(t, Failure{uafx.FxErrorResolvingNamespacesError, ua.StatusBadNoMatch}, fxOf(t, err))
}

func TestFailureOf(t *testing.T) {
	se := failure(uafx.FxErrorVerifyAssetError, ua.StatusBadNoMatch, "x %d", 1)
	assert.Contains(t, se.Error(), "x 1")
	assert.ErrorIs(t, se, ErrManager)
	assert.ErrorIs(t, se, ua.StatusBadNoMatch)
	assert.Equal(t, Failure{uafx.FxErrorVerifyAssetError, ua.StatusBadNoMatch}, failureOf(se, uafx.FxErrorUnknownStatus))
	assert.Equal(t, Failure{uafx.FxErrorTargetServerConnectionError, ua.StatusBadTimeout}, failureOf(context.DeadlineExceeded, uafx.FxErrorTargetServerConnectionError))
	assert.Equal(t, Failure{uafx.FxErrorTargetServerConnectionError, ua.StatusBadCommunicationError}, failureOf(errOffline, uafx.FxErrorTargetServerConnectionError))
	assert.Equal(t, Failure{uafx.FxErrorTargetServerConnectionError, ua.StatusBadSessionClosed}, failureOf(ua.StatusBadSessionClosed, uafx.FxErrorTargetServerConnectionError))
}

func TestFxOfCommand(t *testing.T) {
	for c, want := range map[uafx.FxCommandMask]uafx.FxError{
		uafx.VerifyAssetCmd:                   uafx.FxErrorVerifyAssetError,
		uafx.VerifyFunctionalEntityCmd:        uafx.FxErrorVerifyFunctionalEntityError,
		uafx.CreateConnectionEndpointCmd:      uafx.FxErrorCreateConnectionEndpointError,
		uafx.EstablishControlCmd:              uafx.FxErrorEstablishControlError,
		uafx.SetConfigurationDataCmd:          uafx.FxErrorSetConfigurationDataError,
		uafx.ReassignControlCmd:               uafx.FxErrorReassignControlError,
		uafx.ReserveCommunicationIDsCmd:       uafx.FxErrorReserveCommunicationIDsError,
		uafx.SetCommunicationConfigurationCmd: uafx.FxErrorSetCommunicationConfigurationError,
		uafx.EnableCommunicationCmd:           uafx.FxErrorEnableCommunicationError,
	} {
		assert.Equal(t, want, fxOfCommand(c), "%v", c)
		assert.Equal(t, want, fxOfMask(c), "%v", c)
	}
	assert.Equal(t, uafx.FxErrorUnknownStatus, fxOfMask(0))
	assert.Equal(t, uafx.FxErrorVerifyAssetError, fxOfMask(uafx.VerifyAssetCmd|uafx.EnableCommunicationCmd))
}

func TestAssetFailure(t *testing.T) {
	_, ok := assetFailure(&uafx.EstablishConnectionsResult{AssetVerificationResults: []*uafx.AssetVerificationResultData{nil, {VerificationStatus: ua.StatusOK, VerificationResult: uafx.AssetVerificationMatch}}})
	assert.False(t, ok)
	f, ok := assetFailure(&uafx.EstablishConnectionsResult{AssetVerificationResults: []*uafx.AssetVerificationResultData{{VerificationStatus: ua.StatusBadNodeIDUnknown}}})
	assert.True(t, ok)
	assert.Equal(t, Failure{uafx.FxErrorVerifyAssetError, ua.StatusBadNodeIDUnknown}, f)
	f, ok = assetFailure(&uafx.EstablishConnectionsResult{AssetVerificationResults: []*uafx.AssetVerificationResultData{{VerificationResult: uafx.AssetVerificationMismatch}}})
	assert.True(t, ok)
	assert.Equal(t, Failure{uafx.FxErrorVerifyAssetError, ua.StatusBadNoMatch}, f)
}

func TestIsNullID(t *testing.T) {
	for _, v := range []any{nil, "", uint8(0), uint16(0), uint32(0), uint64(0)} {
		var vv *ua.Variant
		if v != nil {
			vv = ua.MustVariant(v)
		}
		assert.True(t, isNullID(vv), "%T %v", v, v)
	}
	for _, v := range []any{"p", uint8(1), uint16(1), uint32(1), uint64(1), int32(0)} {
		assert.False(t, isNullID(ua.MustVariant(v)), "%T %v", v, v)
	}
}

func TestRenameDataSet(t *testing.T) {
	w := &ua.DataSetWriterDataType{DataSetName: "old"}
	o := &ua.DataSetWriterDataType{DataSetName: "other"}
	cfg := &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{nil, {WriterGroups: []*ua.WriterGroupDataType{nil, {DataSetWriters: []*ua.DataSetWriterDataType{nil, w, o}}}}}}
	renameDataSet(cfg, "", "new")
	renameDataSet(cfg, "old", "old")
	assert.Equal(t, "old", w.DataSetName)
	renameDataSet(cfg, "old", "new")
	assert.Equal(t, "new", w.DataSetName)
	assert.Equal(t, "other", o.DataSetName)
	assert.Nil(t, connAt(cfg, &ua.PubSubConfigurationRefDataType{ConnectionIndex: 5}))
}

func TestModeOf(t *testing.T) {
	ref := &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd}
	for _, tc := range []struct {
		l    *uafx.PubSubCommunicationLinkConfiguration
		want uafx.PubSubConnectionEndpointMode
		ok   bool
	}{
		{nil, 0, false},
		{&uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: ref}, uafx.PubSubPublisher, true},
		{&uafx.PubSubCommunicationLinkConfiguration{DataSetReaderRef: ref}, uafx.PubSubSubscriber, true},
		{&uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: ref, DataSetReaderRef: ref}, uafx.PubSubPublisherSubscriber, true},
		{&uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: &ua.PubSubConfigurationRefDataType{}}, 0, false},
	} {
		m, ok := modeOf(&endpoint{}, tc.l)
		assert.Equal(t, tc.ok, ok)
		assert.Equal(t, tc.want, m)
	}
}

func TestRelatedEndpointAutonomous(t *testing.T) {
	addr := ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: "opc.udp://239.0.0.1:4840"})
	f := &flow{conf: &uafx.PubSubCommunicationFlowConfigurationConf{Address: &uafx.AddressSelection{Address: addr}}}
	pub := &endpoint{conn: &connection{}, outbound: f}
	pub.conn.endpoints = []*endpoint{pub}
	assert.Equal(t, &uafx.RelatedEndpoint{Address: "opc.udp://239.0.0.1:4840"}, relatedEndpoint(pub))
	sub := &endpoint{conn: &connection{}, inbound: &inbound{flow: f}}
	sub.conn.endpoints = []*endpoint{sub}
	assert.Equal(t, "opc.udp://239.0.0.1:4840", relatedEndpoint(sub).Address)
	none := &endpoint{conn: &connection{}}
	none.conn.endpoints = []*endpoint{none}
	assert.Equal(t, &uafx.RelatedEndpoint{}, relatedEndpoint(none))
}

func TestCheckServerURI(t *testing.T) {
	ep := &ua.EndpointDescription{Server: &ua.ApplicationDescription{ApplicationURI: "urn:ac"}}
	require.NoError(t, checkServerURI(ServerAddress{}, ep))
	require.NoError(t, checkServerURI(ServerAddress{ServerURI: "urn:ac"}, ep))
	err := checkServerURI(ServerAddress{ServerURI: "urn:other"}, ep)
	assert.ErrorIs(t, err, ua.StatusBadServerURIInvalid)
	assert.ErrorIs(t, checkServerURI(ServerAddress{ServerURI: "urn:ac"}, &ua.EndpointDescription{}), ua.StatusBadServerURIInvalid)
	_, err = (&ClientDialer{}).Dial(context.Background(), ServerAddress{Address: "opc.tcp://127.0.0.1:1"})
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "fxcm: GetEndpoints"))
}

func TestObserverFunc(t *testing.T) {
	var got []Event
	ObserverFunc(func(e Event) { got = append(got, e) }).Observe(Event{Run: 7})
	assert.Equal(t, []Event{{Run: 7}}, got)
}

// TestCheckNames: two endpoints with one Name in one resolved
// FunctionalEntity both fail (§6.12), whatever identifiers named it.
func TestCheckNames(t *testing.T) {
	x := &run{}
	a := &acRun{addr: ServerAddress{Address: "opc.tcp://ac:4840"}}
	fe := ua.NewNumericNodeID(2, 5)
	ep := func(name string, fe *ua.NodeID) *epRun {
		return &epRun{x: x, a: a, fe: fe, e: &endpoint{conf: &uafx.ConnectionEndpointConfigurationConf{Name: name}}}
	}
	e1, e2, e3, e4 := ep("E", fe), ep("E", ua.NewNumericNodeID(2, 5)), ep("F", fe), ep("E", nil)
	x.eps = []*epRun{e1, e2, e3, e4}
	x.checkNames()
	assert.True(t, e1.failed())
	assert.True(t, e2.failed())
	assert.False(t, e3.failed())
	assert.False(t, e4.failed())
	assert.Equal(t, uafx.FxErrorCreateConnectionEndpointError, e1.outcome.FxError)
	assert.Equal(t, ua.StatusBadBrowseNameDuplicated, e2.outcome.Status)
}

func TestLinksDecoding(t *testing.T) {
	l, err := links(nil)
	require.NoError(t, err)
	assert.Nil(t, l)
	want := &uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd}}
	l, err = links(ua.NewExtensionObject(want))
	require.NoError(t, err)
	assert.Same(t, want, l)
	_, err = links(ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: "x"}))
	assert.Equal(t, Failure{uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadNotSupported}, fxOf(t, err))
	// The set's builder chose its own namespace index for the type.
	eo, err := uafx.EncodeStructure(want, uafx.NamespaceIndexes{Data: 7, AC: 8})
	require.NoError(t, err)
	l, err = links(eo)
	require.NoError(t, err)
	assert.Equal(t, want.DataSetWriterRef.ConfigurationMask, l.DataSetWriterRef.ConfigurationMask)
	bad := *eo
	bad.Value = []byte{1}
	_, err = links(&bad)
	assert.Equal(t, Failure{uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadDecodingError}, fxOf(t, err))
}

func TestWalkPubSubNodeIDs(t *testing.T) {
	keep := func(n *ua.NodeID) (*ua.NodeID, error) { return n, nil }
	unsupported := Failure{uafx.FxErrorConnectionConfigurationSetInvalid, ua.StatusBadNotSupported}
	other := ua.NewExtensionObject(&ua.NetworkAddressURLDataType{})
	err := walkPubSubNodeIDs(&ua.PubSubConfiguration2DataType{PublishedDataSets: []*ua.PublishedDataSetDataType{nil, {Name: "P", DataSetSource: other}}}, keep)
	assert.Equal(t, unsupported, fxOf(t, err))
	err = walkPubSubNodeIDs(&ua.PubSubConfiguration2DataType{SubscribedDataSets: []*ua.StandaloneSubscribedDataSetDataType{nil, {Name: "S", SubscribedDataSet: other}}}, keep)
	assert.Equal(t, unsupported, fxOf(t, err))
	err = walkPubSubNodeIDs(&ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{nil, {ReaderGroups: []*ua.ReaderGroupDataType{nil, {DataSetReaders: []*ua.DataSetReaderDataType{nil, {Name: "R", SubscribedDataSet: other}}}}}}}, keep)
	assert.Equal(t, unsupported, fxOf(t, err))

	fail := func(*ua.NodeID) (*ua.NodeID, error) { return nil, errOffline }
	items := ua.NewExtensionObject(&ua.PublishedDataItemsDataType{PublishedData: []*ua.PublishedVariableDataType{nil, {PublishedVariable: ua.NewNumericNodeID(1, 1)}}})
	assert.ErrorIs(t, walkPubSubNodeIDs(&ua.PubSubConfiguration2DataType{PublishedDataSets: []*ua.PublishedDataSetDataType{{DataSetSource: items}}}, fail), errOffline)
	targets := ua.NewExtensionObject(&ua.TargetVariablesDataType{TargetVariables: []*ua.FieldTargetDataType{nil, {TargetNodeID: ua.NewNumericNodeID(1, 1)}}})
	assert.ErrorIs(t, walkPubSubNodeIDs(&ua.PubSubConfiguration2DataType{SubscribedDataSets: []*ua.StandaloneSubscribedDataSetDataType{{SubscribedDataSet: targets}}}, fail), errOffline)
}

func TestElementAt(t *testing.T) {
	cfg := &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{nil, {}}}
	for _, r := range []*ua.PubSubConfigurationRefDataType{nil, {ConnectionIndex: 9}, {ConnectionIndex: 0}, {ConnectionIndex: 1, GroupIndex: 3}} {
		c, g, w := writerAt(cfg, r)
		assert.Nil(t, c)
		assert.Nil(t, g)
		assert.Nil(t, w)
		assert.Nil(t, readerAt(cfg, r))
	}
	a := &acRun{defaultPublisherID: ua.MustVariant(uint16(9))}
	assert.Equal(t, ua.MustVariant(uint16(9)), a.publisherIDOf(&ua.PubSubConnectionDataType{}))
	assert.Equal(t, ua.MustVariant(uint16(3)), a.publisherIDOf(&ua.PubSubConnectionDataType{PublisherID: ua.MustVariant(uint16(3))}))
}
