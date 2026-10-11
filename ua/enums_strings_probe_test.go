// SPDX-License-Identifier: MIT

package ua

import (
	"fmt"
	"strings"
	"testing"
)

// enumProbeValues covers every arm of the generated String methods: the dense
// ranges at the low end, each single-bit flag value, and values no enum
// defines.
func enumProbeValues() []int64 {
	vals := []int64{-1}
	for v := int64(0); v <= 1100; v++ {
		vals = append(vals, v)
	}
	for bit := uint(11); bit < 31; bit++ {
		vals = append(vals, int64(1)<<bit)
	}
	return append(vals, 1<<31-1)
}

// TestEnumStrings_NeverEmptyAndUnknownIsExplicit checks the two properties
// callers rely on when logging enum values: a String is never empty, and a
// value outside the enumeration is rendered as "Type(n)" rather than borrowing
// a neighbour's name.
func TestEnumStrings_NeverEmptyAndUnknownIsExplicit(t *testing.T) {
	probes := enumProbeValues()
	stringers := map[string]func(int64) fmt.Stringer{
		"AccessLevelExType":                      func(v int64) fmt.Stringer { return AccessLevelExType(v) },
		"AccessLevelType":                        func(v int64) fmt.Stringer { return AccessLevelType(v) },
		"AccessRestrictionType":                  func(v int64) fmt.Stringer { return AccessRestrictionType(v) },
		"ActionState":                            func(v int64) fmt.Stringer { return ActionState(v) },
		"AlarmMask":                              func(v int64) fmt.Stringer { return AlarmMask(v) },
		"ApplicationType":                        func(v int64) fmt.Stringer { return ApplicationType(v) },
		"AttributeID":                            func(v int64) fmt.Stringer { return AttributeID(v) },
		"AttributeWriteMask":                     func(v int64) fmt.Stringer { return AttributeWriteMask(v) },
		"AxisScaleEnumeration":                   func(v int64) fmt.Stringer { return AxisScaleEnumeration(v) },
		"BrokerTransportQoS":                     func(v int64) fmt.Stringer { return BrokerTransportQoS(v) },
		"BrowseDirection":                        func(v int64) fmt.Stringer { return BrowseDirection(v) },
		"BrowseResultMask":                       func(v int64) fmt.Stringer { return BrowseResultMask(v) },
		"ChassisIDSubtype":                       func(v int64) fmt.Stringer { return ChassisIDSubtype(v) },
		"ConfigurationUpdateType":                func(v int64) fmt.Stringer { return ConfigurationUpdateType(v) },
		"ConversionLimitEnum":                    func(v int64) fmt.Stringer { return ConversionLimitEnum(v) },
		"DataChangeTrigger":                      func(v int64) fmt.Stringer { return DataChangeTrigger(v) },
		"DataSetFieldContentMask":                func(v int64) fmt.Stringer { return DataSetFieldContentMask(v) },
		"DataSetFieldFlags":                      func(v int64) fmt.Stringer { return DataSetFieldFlags(v) },
		"DataSetOrderingType":                    func(v int64) fmt.Stringer { return DataSetOrderingType(v) },
		"DeadbandType":                           func(v int64) fmt.Stringer { return DeadbandType(v) },
		"DiagnosticsLevel":                       func(v int64) fmt.Stringer { return DiagnosticsLevel(v) },
		"Duplex":                                 func(v int64) fmt.Stringer { return Duplex(v) },
		"EventNotifierType":                      func(v int64) fmt.Stringer { return EventNotifierType(v) },
		"ExceptionDeviationFormat":               func(v int64) fmt.Stringer { return ExceptionDeviationFormat(v) },
		"FilterOperator":                         func(v int64) fmt.Stringer { return FilterOperator(v) },
		"HistoryUpdateType":                      func(v int64) fmt.Stringer { return HistoryUpdateType(v) },
		"IDType":                                 func(v int64) fmt.Stringer { return IDType(v) },
		"IdentityCriteriaType":                   func(v int64) fmt.Stringer { return IdentityCriteriaType(v) },
		"InterfaceAdminStatus":                   func(v int64) fmt.Stringer { return InterfaceAdminStatus(v) },
		"InterfaceOperStatus":                    func(v int64) fmt.Stringer { return InterfaceOperStatus(v) },
		"JSONDataSetMessageContentMask":          func(v int64) fmt.Stringer { return JSONDataSetMessageContentMask(v) },
		"JSONNetworkMessageContentMask":          func(v int64) fmt.Stringer { return JSONNetworkMessageContentMask(v) },
		"LldpSystemCapabilitiesMap":              func(v int64) fmt.Stringer { return LldpSystemCapabilitiesMap(v) },
		"LogRecordMask":                          func(v int64) fmt.Stringer { return LogRecordMask(v) },
		"ManAddrIfSubtype":                       func(v int64) fmt.Stringer { return ManAddrIfSubtype(v) },
		"MessageSecurityMode":                    func(v int64) fmt.Stringer { return MessageSecurityMode(v) },
		"ModelChangeStructureVerbMask":           func(v int64) fmt.Stringer { return ModelChangeStructureVerbMask(v) },
		"MonitoringMode":                         func(v int64) fmt.Stringer { return MonitoringMode(v) },
		"NamingRuleType":                         func(v int64) fmt.Stringer { return NamingRuleType(v) },
		"NegotiationStatus":                      func(v int64) fmt.Stringer { return NegotiationStatus(v) },
		"NodeAttributesMask":                     func(v int64) fmt.Stringer { return NodeAttributesMask(v) },
		"NodeClass":                              func(v int64) fmt.Stringer { return NodeClass(v) },
		"NodeIDType":                             func(v int64) fmt.Stringer { return NodeIDType(v) },
		"OpenFileMode":                           func(v int64) fmt.Stringer { return OpenFileMode(v) },
		"OverrideValueHandling":                  func(v int64) fmt.Stringer { return OverrideValueHandling(v) },
		"PasswordOptionsMask":                    func(v int64) fmt.Stringer { return PasswordOptionsMask(v) },
		"PerformUpdateType":                      func(v int64) fmt.Stringer { return PerformUpdateType(v) },
		"PermissionType":                         func(v int64) fmt.Stringer { return PermissionType(v) },
		"PortIDSubtype":                          func(v int64) fmt.Stringer { return PortIDSubtype(v) },
		"PubSubConfigurationRefMask":             func(v int64) fmt.Stringer { return PubSubConfigurationRefMask(v) },
		"PubSubDiagnosticsCounterClassification": func(v int64) fmt.Stringer { return PubSubDiagnosticsCounterClassification(v) },
		"PubSubState":                            func(v int64) fmt.Stringer { return PubSubState(v) },
		"RedundancySupport":                      func(v int64) fmt.Stringer { return RedundancySupport(v) },
		"RedundantServerMode":                    func(v int64) fmt.Stringer { return RedundantServerMode(v) },
		"SecurityTokenRequestType":               func(v int64) fmt.Stringer { return SecurityTokenRequestType(v) },
		"ServerState":                            func(v int64) fmt.Stringer { return ServerState(v) },
		"SortOrderType":                          func(v int64) fmt.Stringer { return SortOrderType(v) },
		"StructureType":                          func(v int64) fmt.Stringer { return StructureType(v) },
		"TimestampsToReturn":                     func(v int64) fmt.Stringer { return TimestampsToReturn(v) },
		"TrustListMasks":                         func(v int64) fmt.Stringer { return TrustListMasks(v) },
		"TrustListValidationOptions":             func(v int64) fmt.Stringer { return TrustListValidationOptions(v) },
		"TsnFailureCode":                         func(v int64) fmt.Stringer { return TsnFailureCode(v) },
		"TsnListenerStatus":                      func(v int64) fmt.Stringer { return TsnListenerStatus(v) },
		"TsnStreamState":                         func(v int64) fmt.Stringer { return TsnStreamState(v) },
		"TsnTalkerStatus":                        func(v int64) fmt.Stringer { return TsnTalkerStatus(v) },
		"TypeID":                                 func(v int64) fmt.Stringer { return TypeID(v) },
		"UADPDataSetMessageContentMask":          func(v int64) fmt.Stringer { return UADPDataSetMessageContentMask(v) },
		"UADPNetworkMessageContentMask":          func(v int64) fmt.Stringer { return UADPNetworkMessageContentMask(v) },
		"UserConfigurationMask":                  func(v int64) fmt.Stringer { return UserConfigurationMask(v) },
		"UserTokenType":                          func(v int64) fmt.Stringer { return UserTokenType(v) },
	}

	for name, conv := range stringers {
		named, unknown := 0, 0
		seen := map[string]int64{}
		for _, v := range probes {
			s := conv(v).String()
			if s == "" {
				t.Errorf("%s(%d).String() is empty", name, v)
				continue
			}
			if strings.HasPrefix(s, name+"(") {
				unknown++
				continue
			}
			named++
			// The conversion may wrap v for narrow underlying types, so two
			// probes can legitimately map to the same value; a clash between
			// different in-range probes is checked on the low range only.
			if prev, dup := seen[s]; dup && v <= 255 && prev <= 255 {
				t.Errorf("%s: values %d and %d both render as %q", name, prev, v, s)
			}
			seen[s] = v
		}
		if named == 0 {
			t.Errorf("%s: no probe value has a name", name)
		}
		if unknown == 0 {
			t.Errorf("%s: no probe value was rendered as unknown", name)
		}
	}
}
