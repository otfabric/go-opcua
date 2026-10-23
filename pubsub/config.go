// SPDX-License-Identifier: MIT

package pubsub

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

// Default content masks, used when a group or writer has no message settings.
const (
	DefaultUADPNetworkMessageContentMask = ua.UADPNetworkMessageContentMaskPublisherID |
		ua.UADPNetworkMessageContentMaskGroupHeader |
		ua.UADPNetworkMessageContentMaskWriterGroupID |
		ua.UADPNetworkMessageContentMaskGroupVersion |
		ua.UADPNetworkMessageContentMaskNetworkMessageNumber |
		ua.UADPNetworkMessageContentMaskSequenceNumber |
		ua.UADPNetworkMessageContentMaskPayloadHeader
	DefaultUADPDataSetMessageContentMask = ua.UADPDataSetMessageContentMaskTimestamp |
		ua.UADPDataSetMessageContentMaskStatus |
		ua.UADPDataSetMessageContentMaskMajorVersion |
		ua.UADPDataSetMessageContentMaskMinorVersion |
		ua.UADPDataSetMessageContentMaskSequenceNumber
	DefaultJSONNetworkMessageContentMask = ua.JSONNetworkMessageContentMaskNetworkMessageHeader |
		ua.JSONNetworkMessageContentMaskDataSetMessageHeader |
		ua.JSONNetworkMessageContentMaskPublisherID |
		ua.JSONNetworkMessageContentMaskWriterGroupName
	DefaultJSONDataSetMessageContentMask = ua.JSONDataSetMessageContentMaskDataSetWriterID |
		ua.JSONDataSetMessageContentMaskMetaDataVersion |
		ua.JSONDataSetMessageContentMaskSequenceNumber |
		ua.JSONDataSetMessageContentMaskTimestamp |
		ua.JSONDataSetMessageContentMaskStatus |
		ua.JSONDataSetMessageContentMaskMessageType
)

// clone deep-copies a configuration structure through the binary encoding.
func clone[T any](v *T) (*T, error) {
	if v == nil {
		return nil, nil
	}
	b, err := ua.Encode(v)
	if err != nil {
		return nil, err
	}
	out := new(T)
	if _, err := ua.Decode(b, out); err != nil {
		return nil, err
	}
	return out, nil
}

// eoValue returns the decoded body of an ExtensionObject, nil if there is
// none.
func eoValue(eo *ua.ExtensionObject) any {
	if eo == nil {
		return nil
	}
	return eo.Value
}

// variantValue returns the value of a Variant, nil for a nil or empty one.
func variantValue(v *ua.Variant) any {
	if v == nil {
		return nil
	}
	return v.Value()
}

// publisherIDOf converts the PublisherId of a connection or a reader; ok is
// false for an empty PublisherId.
func publisherIDOf(v *ua.Variant) (id message.PublisherID, ok bool, err error) {
	if variantValue(v) == nil {
		return message.PublisherID{}, false, nil
	}
	id, err = message.PublisherIDFromVariant(v)
	if err != nil {
		return message.PublisherID{}, false, err
	}
	return id, true, nil
}

// PublisherIDVariant converts a Go value to the Variant of a PublisherId:
// byte, uint16, uint32, uint64 and string are kept, other integers become
// UInt16, UInt32 or UInt64 depending on their value.
func PublisherIDVariant(v any) (*ua.Variant, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case *ua.Variant:
		if _, _, err := publisherIDOf(x); err != nil {
			return nil, err
		}
		return x, nil
	case message.PublisherID:
		return x.Variant(), nil
	case byte, uint16, uint32, uint64, string:
		return ua.MustVariant(x), nil
	case int:
		if x < 0 {
			return nil, fmt.Errorf("pubsub: negative PublisherId %d", x)
		}
		return uintPublisherID(uint64(x)), nil
	case int32:
		if x < 0 {
			return nil, fmt.Errorf("pubsub: negative PublisherId %d", x)
		}
		return uintPublisherID(uint64(x)), nil
	case int64:
		if x < 0 {
			return nil, fmt.Errorf("pubsub: negative PublisherId %d", x)
		}
		return uintPublisherID(uint64(x)), nil
	}
	return nil, fmt.Errorf("pubsub: PublisherId of type %T is not allowed", v)
}

func uintPublisherID(n uint64) *ua.Variant {
	switch {
	case n <= math.MaxUint16:
		return ua.MustVariant(uint16(n))
	case n <= math.MaxUint32:
		return ua.MustVariant(uint32(n))
	default:
		return ua.MustVariant(n)
	}
}

// isBroker reports whether a connection uses a broker transport.
func isBroker(profile, url string) bool {
	if profile == transport.ProfileMQTTJSON || profile == transport.ProfileMQTTUADP {
		return true
	}
	scheme, _ := transport.Scheme(url)
	return scheme == "mqtt" || scheme == "mqtts"
}

// connectionURL returns the address of a connection.
func connectionURL(c *ua.PubSubConnectionDataType) (url, iface string, ok bool) {
	switch a := eoValue(c.Address).(type) {
	case *ua.NetworkAddressURLDataType:
		return a.URL, a.NetworkInterface, a.URL != ""
	}
	return "", "", false
}

// groupEncoding returns the mapping of a WriterGroup: the type of its
// message settings or, without them, the transport profile.
func groupEncoding(profile string, ms *ua.ExtensionObject) encoding {
	switch eoValue(ms).(type) {
	case *ua.JSONWriterGroupMessageDataType:
		return encJSON
	case *ua.UADPWriterGroupMessageDataType:
		return encUADP
	}
	if profile == transport.ProfileMQTTJSON {
		return encJSON
	}
	return encUADP
}

// readerEncoding returns the mapping a DataSetReader expects.
func readerEncoding(profile string, ms *ua.ExtensionObject) encoding {
	switch eoValue(ms).(type) {
	case *ua.JSONDataSetReaderMessageDataType:
		return encJSON
	case *ua.UADPDataSetReaderMessageDataType:
		return encUADP
	}
	if profile == transport.ProfileMQTTJSON {
		return encJSON
	}
	return encUADP
}

// qosOf maps a requested delivery guarantee to the MQTT QoS.
func qosOf(q ua.BrokerTransportQoS, def byte) byte {
	switch q {
	case ua.BrokerTransportQoSBestEffort, ua.BrokerTransportQoSAtMostOnce:
		return 0
	case ua.BrokerTransportQoSAtLeastOnce:
		return 1
	case ua.BrokerTransportQoSExactlyOnce:
		return 2
	case ua.BrokerTransportQoSNotSpecified:
		return def
	}
	return def
}

// duration converts a Duration in milliseconds.
func duration(ms float64) time.Duration {
	if ms <= 0 || math.IsNaN(ms) || math.IsInf(ms, 0) {
		return 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// securityMode normalises a MessageSecurityMode: Invalid means None.
func securityMode(m ua.MessageSecurityMode) ua.MessageSecurityMode {
	if m == ua.MessageSecurityModeInvalid {
		return ua.MessageSecurityModeNone
	}
	return m
}

// Validate checks a PubSub configuration and returns the first problem as a
// [*ConfigError]. A configuration that passes can still fail at run time,
// for example when its transport cannot be opened.
func Validate(cfg *ua.PubSubConfigurationDataType) error {
	if cfg == nil {
		return configErr("", "nil configuration")
	}
	pdsNames := map[string]bool{}
	for i, pds := range cfg.PublishedDataSets {
		path := fmt.Sprintf("published data set %d", i)
		if pds != nil {
			path = fmt.Sprintf("published data set %q", pds.Name)
		}
		if err := validatePublishedDataSet(path, pds); err != nil {
			return err
		}
		if pdsNames[pds.Name] {
			return configErr(path, "duplicate name")
		}
		pdsNames[pds.Name] = true
	}
	connNames := map[string]bool{}
	for i, c := range cfg.Connections {
		path := fmt.Sprintf("connection %d", i)
		if c != nil {
			path = fmt.Sprintf("connection %q", c.Name)
		}
		if err := validateConnection(path, c, pdsNames); err != nil {
			return err
		}
		if connNames[c.Name] {
			return configErr(path, "duplicate name")
		}
		connNames[c.Name] = true
	}
	return nil
}

func validatePublishedDataSet(path string, pds *ua.PublishedDataSetDataType) error {
	if pds == nil {
		return configErr(path, "nil published data set")
	}
	if pds.Name == "" {
		return configErr(path, "Name is empty")
	}
	switch src := eoValue(pds.DataSetSource).(type) {
	case nil:
		// An empty data set: its writers send only keep-alive messages.
		if md := pds.DataSetMetaData; md != nil && len(md.Fields) > 0 {
			return configErr(path, "DataSetMetaData has %d fields but there is no DataSetSource", len(md.Fields))
		}
	case *ua.PublishedDataItemsDataType:
		for i, v := range src.PublishedData {
			if v == nil || v.PublishedVariable == nil {
				return configErr(path, "PublishedData[%d]: no PublishedVariable", i)
			}
			if v.AttributeID == 0 {
				return configErr(path, "PublishedData[%d]: AttributeId is 0 (use ua.AttributeIDValue)", i)
			}
			if v.IndexRange != "" {
				if _, err := ua.ParseNumericRanges(v.IndexRange); err != nil {
					return configErr(path, "PublishedData[%d]: IndexRange %q: %v", i, v.IndexRange, err)
				}
			}
		}
		if md := pds.DataSetMetaData; md != nil && len(md.Fields) > 0 && len(md.Fields) != len(src.PublishedData) {
			return configErr(path, "DataSetMetaData has %d fields for %d published variables", len(md.Fields), len(src.PublishedData))
		}
		if err := validateFieldNames(path, pds.DataSetMetaData); err != nil {
			return err
		}
	case *ua.PublishedEventsDataType:
		if src.EventNotifier == nil {
			return configErr(path, "PublishedEvents without EventNotifier")
		}
		if len(src.SelectedFields) == 0 {
			return configErr(path, "PublishedEvents without SelectedFields")
		}
		if md := pds.DataSetMetaData; md != nil && len(md.Fields) > 0 && len(md.Fields) != len(src.SelectedFields) {
			return configErr(path, "DataSetMetaData has %d fields for %d selected fields", len(md.Fields), len(src.SelectedFields))
		}
		if err := validateFieldNames(path, pds.DataSetMetaData); err != nil {
			return err
		}
	default:
		return configErr(path, "DataSetSource of type %T is not supported", src)
	}
	return nil
}

func validateFieldNames(path string, md *ua.DataSetMetaDataType) error {
	if md == nil {
		return nil
	}
	seen := map[string]bool{}
	for i, f := range md.Fields {
		if f == nil {
			return configErr(path, "DataSetMetaData field %d is nil", i)
		}
		if f.Name == "" {
			continue
		}
		if seen[f.Name] {
			return configErr(path, "DataSetMetaData field name %q is used twice", f.Name)
		}
		seen[f.Name] = true
	}
	return nil
}

func validateConnection(path string, c *ua.PubSubConnectionDataType, pds map[string]bool) error {
	if c == nil {
		return configErr(path, "nil connection")
	}
	if c.Name == "" {
		return configErr(path, "Name is empty")
	}
	_, hasPub, err := publisherIDOf(c.PublisherID)
	if err != nil {
		return configErr(path, "PublisherId: %v", err)
	}
	if !hasPub && len(c.WriterGroups) > 0 {
		return configErr(path, "a connection with writer groups needs a PublisherId")
	}
	switch c.TransportProfileURI {
	case transport.ProfileUDPUADP, transport.ProfileMQTTUADP, transport.ProfileMQTTJSON:
	case transport.ProfileEthUADP:
		return configErr(path, "TransportProfileUri %q is not supported", c.TransportProfileURI)
	case "":
		return configErr(path, "TransportProfileUri is empty")
	default:
		return configErr(path, "unknown TransportProfileUri %q", c.TransportProfileURI)
	}
	url, _, ok := connectionURL(c)
	if !ok {
		return configErr(path, "Address must be a NetworkAddressUrlDataType with a Url")
	}
	if _, err := transport.Scheme(url); err != nil {
		return configErr(path, "Address: %v", err)
	}
	broker := isBroker(c.TransportProfileURI, url)
	wgNames := map[string]bool{}
	wgIDs := map[uint16]bool{}
	for i, wg := range c.WriterGroups {
		wpath := fmt.Sprintf("%s: writer group %d", path, i)
		if wg != nil {
			wpath = fmt.Sprintf("%s: writer group %q", path, wg.Name)
		}
		if err := validateWriterGroup(wpath, c.TransportProfileURI, broker, wg, pds); err != nil {
			return err
		}
		if wgNames[wg.Name] {
			return configErr(wpath, "duplicate name")
		}
		if wgIDs[wg.WriterGroupID] {
			return configErr(wpath, "WriterGroupId %d is used twice", wg.WriterGroupID)
		}
		wgNames[wg.Name] = true
		wgIDs[wg.WriterGroupID] = true
	}
	rgNames := map[string]bool{}
	for i, rg := range c.ReaderGroups {
		rpath := fmt.Sprintf("%s: reader group %d", path, i)
		if rg != nil {
			rpath = fmt.Sprintf("%s: reader group %q", path, rg.Name)
		}
		if err := validateReaderGroup(rpath, c.TransportProfileURI, broker, rg); err != nil {
			return err
		}
		if rgNames[rg.Name] {
			return configErr(rpath, "duplicate name")
		}
		rgNames[rg.Name] = true
	}
	return nil
}

func validateSecurity(path string, mode ua.MessageSecurityMode, groupID string, enc encoding) error {
	switch securityMode(mode) {
	case ua.MessageSecurityModeNone:
		return nil
	case ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt:
		if groupID == "" {
			return configErr(path, "SecurityMode %v needs a SecurityGroupId", mode)
		}
		if enc == encJSON {
			return configErr(path, "the JSON message mapping has no message security")
		}
		return nil
	case ua.MessageSecurityModeInvalid:
		return nil
	}
	return configErr(path, "invalid SecurityMode %d", mode)
}

func validateWriterGroup(path, profile string, broker bool, wg *ua.WriterGroupDataType, pds map[string]bool) error {
	if wg == nil {
		return configErr(path, "nil writer group")
	}
	if wg.Name == "" {
		return configErr(path, "Name is empty")
	}
	if wg.WriterGroupID == 0 {
		return configErr(path, "WriterGroupId must not be 0")
	}
	if !(wg.PublishingInterval > 0) || math.IsInf(wg.PublishingInterval, 0) {
		return configErr(path, "PublishingInterval must be > 0 (milliseconds)")
	}
	if wg.KeepAliveTime < 0 || math.IsNaN(wg.KeepAliveTime) || math.IsInf(wg.KeepAliveTime, 0) {
		return configErr(path, "KeepAliveTime must be >= 0 (milliseconds)")
	}
	enc := groupEncoding(profile, wg.MessageSettings)
	switch ms := eoValue(wg.MessageSettings).(type) {
	case nil, *ua.UADPWriterGroupMessageDataType, *ua.JSONWriterGroupMessageDataType:
	default:
		return configErr(path, "MessageSettings of type %T is not supported", ms)
	}
	if enc == encJSON && !broker {
		return configErr(path, "the JSON message mapping needs a broker transport")
	}
	switch ts := eoValue(wg.TransportSettings).(type) {
	case nil:
	case *ua.DatagramWriterGroupTransportDataType:
		if broker {
			return configErr(path, "DatagramWriterGroupTransportDataType on a broker connection")
		}
	case *ua.BrokerWriterGroupTransportDataType:
		if !broker {
			return configErr(path, "BrokerWriterGroupTransportDataType on a datagram connection")
		}
	default:
		return configErr(path, "TransportSettings of type %T is not supported", ts)
	}
	if err := validateSecurity(path, wg.SecurityMode, wg.SecurityGroupID, enc); err != nil {
		return err
	}
	names := map[string]bool{}
	ids := map[uint16]bool{}
	for i, w := range wg.DataSetWriters {
		wpath := fmt.Sprintf("%s: writer %d", path, i)
		if w != nil {
			wpath = fmt.Sprintf("%s: writer %q", path, w.Name)
		}
		if err := validateWriter(wpath, enc, broker, w, pds); err != nil {
			return err
		}
		if names[w.Name] {
			return configErr(wpath, "duplicate name")
		}
		if ids[w.DataSetWriterID] {
			return configErr(wpath, "DataSetWriterId %d is used twice", w.DataSetWriterID)
		}
		names[w.Name] = true
		ids[w.DataSetWriterID] = true
	}
	return nil
}

func validateWriter(path string, enc encoding, broker bool, w *ua.DataSetWriterDataType, pds map[string]bool) error {
	if w == nil {
		return configErr(path, "nil writer")
	}
	if w.Name == "" {
		return configErr(path, "Name is empty")
	}
	if w.DataSetWriterID == 0 {
		return configErr(path, "DataSetWriterId must not be 0")
	}
	if w.DataSetName != "" && pds != nil && !pds[w.DataSetName] {
		return configErr(path, "no published data set %q", w.DataSetName)
	}
	switch ms := eoValue(w.MessageSettings).(type) {
	case nil:
	case *ua.UADPDataSetWriterMessageDataType:
		if enc != encUADP {
			return configErr(path, "UADP MessageSettings in a JSON writer group")
		}
	case *ua.JSONDataSetWriterMessageDataType:
		if enc != encJSON {
			return configErr(path, "JSON MessageSettings in a UADP writer group")
		}
	default:
		return configErr(path, "MessageSettings of type %T is not supported", ms)
	}
	switch ts := eoValue(w.TransportSettings).(type) {
	case nil:
	case *ua.BrokerDataSetWriterTransportDataType:
		if !broker {
			return configErr(path, "BrokerDataSetWriterTransportDataType on a datagram connection")
		}
	default:
		return configErr(path, "TransportSettings of type %T is not supported", ts)
	}
	return nil
}

func validateReaderGroup(path, profile string, broker bool, rg *ua.ReaderGroupDataType) error {
	if rg == nil {
		return configErr(path, "nil reader group")
	}
	if rg.Name == "" {
		return configErr(path, "Name is empty")
	}
	if err := validateSecurity(path, rg.SecurityMode, rg.SecurityGroupID, encUADP); err != nil {
		return err
	}
	names := map[string]bool{}
	for i, r := range rg.DataSetReaders {
		rpath := fmt.Sprintf("%s: reader %d", path, i)
		if r != nil {
			rpath = fmt.Sprintf("%s: reader %q", path, r.Name)
		}
		if err := validateReader(rpath, profile, broker, r); err != nil {
			return err
		}
		if names[r.Name] {
			return configErr(rpath, "duplicate name")
		}
		names[r.Name] = true
	}
	return nil
}

func validateReader(path, profile string, broker bool, r *ua.DataSetReaderDataType) error {
	if r == nil {
		return configErr(path, "nil reader")
	}
	if r.Name == "" {
		return configErr(path, "Name is empty")
	}
	if _, _, err := publisherIDOf(r.PublisherID); err != nil {
		return configErr(path, "PublisherId: %v", err)
	}
	if r.MessageReceiveTimeout < 0 || math.IsNaN(r.MessageReceiveTimeout) || math.IsInf(r.MessageReceiveTimeout, 0) {
		return configErr(path, "MessageReceiveTimeout must be >= 0 (milliseconds)")
	}
	enc := readerEncoding(profile, r.MessageSettings)
	if err := validateSecurity(path, r.SecurityMode, r.SecurityGroupID, enc); err != nil {
		return err
	}
	switch ms := eoValue(r.MessageSettings).(type) {
	case nil, *ua.UADPDataSetReaderMessageDataType, *ua.JSONDataSetReaderMessageDataType:
	default:
		return configErr(path, "MessageSettings of type %T is not supported", ms)
	}
	switch ts := eoValue(r.TransportSettings).(type) {
	case nil:
	case *ua.BrokerDataSetReaderTransportDataType:
		if !broker {
			return configErr(path, "BrokerDataSetReaderTransportDataType on a datagram connection")
		}
	default:
		return configErr(path, "TransportSettings of type %T is not supported", ts)
	}
	if err := validateFieldNames(path, r.DataSetMetaData); err != nil {
		return err
	}
	nfields := -1
	if r.DataSetMetaData != nil && len(r.DataSetMetaData.Fields) > 0 {
		nfields = len(r.DataSetMetaData.Fields)
	}
	switch sds := eoValue(r.SubscribedDataSet).(type) {
	case nil:
	case *ua.TargetVariablesDataType:
		for i, t := range sds.TargetVariables {
			if t == nil || t.TargetNodeID == nil {
				return configErr(path, "TargetVariables[%d]: no TargetNodeId", i)
			}
			if t.AttributeID == 0 {
				return configErr(path, "TargetVariables[%d]: AttributeId is 0 (use ua.AttributeIDValue)", i)
			}
			for _, rng := range []string{t.ReceiverIndexRange, t.WriteIndexRange} {
				if rng == "" {
					continue
				}
				if _, err := ua.ParseNumericRanges(rng); err != nil {
					return configErr(path, "TargetVariables[%d]: index range %q: %v", i, rng, err)
				}
			}
			if !hasFieldID(t.DataSetFieldID) && nfields >= 0 && i >= nfields {
				return configErr(path, "TargetVariables[%d] has no DataSetFieldId and the DataSet has only %d fields", i, nfields)
			}
		}
	case *ua.SubscribedDataSetMirrorDataType:
		if strings.TrimSpace(sds.ParentNodeName) == "" {
			return configErr(path, "SubscribedDataSetMirror without ParentNodeName")
		}
	default:
		return configErr(path, "SubscribedDataSet of type %T is not supported", sds)
	}
	return nil
}

// hasFieldID reports whether a DataSetFieldId is set (not the null GUID).
func hasFieldID(g *ua.GUID) bool {
	if g == nil {
		return false
	}
	if g.Data1 != 0 || g.Data2 != 0 || g.Data3 != 0 {
		return true
	}
	for _, b := range g.Data4 {
		if b != 0 {
			return true
		}
	}
	return false
}

func sameGUID(a, b *ua.GUID) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Data1 != b.Data1 || a.Data2 != b.Data2 || a.Data3 != b.Data3 || len(a.Data4) != len(b.Data4) {
		return false
	}
	for i := range a.Data4 {
		if a.Data4[i] != b.Data4[i] {
			return false
		}
	}
	return true
}

// versionTime returns the current time as a VersionTime: the seconds since
// 2000-01-01 UTC (Part 14 §6.2.3.2.3).
func versionTime(now time.Time) uint32 {
	epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	s := now.Sub(epoch) / time.Second
	if s <= 0 {
		return 1
	}
	return uint32(s)
}
