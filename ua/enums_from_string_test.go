// SPDX-License-Identifier: MIT

package ua

import "testing"

func TestEnumFromStringRoundTrip(t *testing.T) {
	t.Run("NodeIDTypeFromString", func(t *testing.T) {
		if got := NodeIDTypeFromString("TwoByte"); got != 0 {
			t.Fatalf("NodeIDTypeFromString(%q) = %v, want %v", "TwoByte", got, 0)
		}
		_ = NodeIDTypeFromString("not-a-valid-enum-value")
	})
	t.Run("NamingRuleTypeFromString", func(t *testing.T) {
		if got := NamingRuleTypeFromString("Mandatory"); got != 1 {
			t.Fatalf("NamingRuleTypeFromString(%q) = %v, want %v", "Mandatory", got, 1)
		}
		_ = NamingRuleTypeFromString("not-a-valid-enum-value")
	})
	t.Run("RedundantServerModeFromString", func(t *testing.T) {
		if got := RedundantServerModeFromString("PrimaryWithBackup"); got != 0 {
			t.Fatalf("RedundantServerModeFromString(%q) = %v, want %v", "PrimaryWithBackup", got, 0)
		}
		_ = RedundantServerModeFromString("not-a-valid-enum-value")
	})
	t.Run("OpenFileModeFromString", func(t *testing.T) {
		if got := OpenFileModeFromString("Read"); got != 1 {
			t.Fatalf("OpenFileModeFromString(%q) = %v, want %v", "Read", got, 1)
		}
		_ = OpenFileModeFromString("not-a-valid-enum-value")
	})
	t.Run("IdentityCriteriaTypeFromString", func(t *testing.T) {
		if got := IdentityCriteriaTypeFromString("UserName"); got != 1 {
			t.Fatalf("IdentityCriteriaTypeFromString(%q) = %v, want %v", "UserName", got, 1)
		}
		_ = IdentityCriteriaTypeFromString("not-a-valid-enum-value")
	})
	t.Run("ConversionLimitEnumFromString", func(t *testing.T) {
		if got := ConversionLimitEnumFromString("NoConversion"); got != 0 {
			t.Fatalf("ConversionLimitEnumFromString(%q) = %v, want %v", "NoConversion", got, 0)
		}
		_ = ConversionLimitEnumFromString("not-a-valid-enum-value")
	})
	t.Run("AlarmMaskFromString", func(t *testing.T) {
		if got := AlarmMaskFromString("None"); got != 0 {
			t.Fatalf("AlarmMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = AlarmMaskFromString("not-a-valid-enum-value")
	})
	t.Run("TrustListValidationOptionsFromString", func(t *testing.T) {
		if got := TrustListValidationOptionsFromString("None"); got != 0 {
			t.Fatalf("TrustListValidationOptionsFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = TrustListValidationOptionsFromString("not-a-valid-enum-value")
	})
	t.Run("TrustListMasksFromString", func(t *testing.T) {
		if got := TrustListMasksFromString("None"); got != 0 {
			t.Fatalf("TrustListMasksFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = TrustListMasksFromString("not-a-valid-enum-value")
	})
	t.Run("ConfigurationUpdateTypeFromString", func(t *testing.T) {
		if got := ConfigurationUpdateTypeFromString("Insert"); got != 1 {
			t.Fatalf("ConfigurationUpdateTypeFromString(%q) = %v, want %v", "Insert", got, 1)
		}
		_ = ConfigurationUpdateTypeFromString("not-a-valid-enum-value")
	})
	t.Run("PubSubStateFromString", func(t *testing.T) {
		if got := PubSubStateFromString("Disabled"); got != 0 {
			t.Fatalf("PubSubStateFromString(%q) = %v, want %v", "Disabled", got, 0)
		}
		_ = PubSubStateFromString("not-a-valid-enum-value")
	})
	t.Run("DataSetFieldFlagsFromString", func(t *testing.T) {
		if got := DataSetFieldFlagsFromString("None"); got != 0 {
			t.Fatalf("DataSetFieldFlagsFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = DataSetFieldFlagsFromString("not-a-valid-enum-value")
	})
	t.Run("ActionStateFromString", func(t *testing.T) {
		if got := ActionStateFromString("Idle"); got != 0 {
			t.Fatalf("ActionStateFromString(%q) = %v, want %v", "Idle", got, 0)
		}
		_ = ActionStateFromString("not-a-valid-enum-value")
	})
	t.Run("DataSetFieldContentMaskFromString", func(t *testing.T) {
		if got := DataSetFieldContentMaskFromString("None"); got != 0 {
			t.Fatalf("DataSetFieldContentMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = DataSetFieldContentMaskFromString("not-a-valid-enum-value")
	})
	t.Run("OverrideValueHandlingFromString", func(t *testing.T) {
		if got := OverrideValueHandlingFromString("Disabled"); got != 0 {
			t.Fatalf("OverrideValueHandlingFromString(%q) = %v, want %v", "Disabled", got, 0)
		}
		_ = OverrideValueHandlingFromString("not-a-valid-enum-value")
	})
	t.Run("DataSetOrderingTypeFromString", func(t *testing.T) {
		if got := DataSetOrderingTypeFromString("Undefined"); got != 0 {
			t.Fatalf("DataSetOrderingTypeFromString(%q) = %v, want %v", "Undefined", got, 0)
		}
		_ = DataSetOrderingTypeFromString("not-a-valid-enum-value")
	})
	t.Run("UADPNetworkMessageContentMaskFromString", func(t *testing.T) {
		if got := UADPNetworkMessageContentMaskFromString("None"); got != 0 {
			t.Fatalf("UADPNetworkMessageContentMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = UADPNetworkMessageContentMaskFromString("not-a-valid-enum-value")
	})
	t.Run("UADPDataSetMessageContentMaskFromString", func(t *testing.T) {
		if got := UADPDataSetMessageContentMaskFromString("None"); got != 0 {
			t.Fatalf("UADPDataSetMessageContentMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = UADPDataSetMessageContentMaskFromString("not-a-valid-enum-value")
	})
	t.Run("JSONNetworkMessageContentMaskFromString", func(t *testing.T) {
		if got := JSONNetworkMessageContentMaskFromString("None"); got != 0 {
			t.Fatalf("JSONNetworkMessageContentMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = JSONNetworkMessageContentMaskFromString("not-a-valid-enum-value")
	})
	t.Run("JSONDataSetMessageContentMaskFromString", func(t *testing.T) {
		if got := JSONDataSetMessageContentMaskFromString("None"); got != 0 {
			t.Fatalf("JSONDataSetMessageContentMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = JSONDataSetMessageContentMaskFromString("not-a-valid-enum-value")
	})
	t.Run("BrokerTransportQoSFromString", func(t *testing.T) {
		if got := BrokerTransportQoSFromString("NotSpecified"); got != 0 {
			t.Fatalf("BrokerTransportQoSFromString(%q) = %v, want %v", "NotSpecified", got, 0)
		}
		_ = BrokerTransportQoSFromString("not-a-valid-enum-value")
	})
	t.Run("PubSubConfigurationRefMaskFromString", func(t *testing.T) {
		if got := PubSubConfigurationRefMaskFromString("None"); got != 0 {
			t.Fatalf("PubSubConfigurationRefMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = PubSubConfigurationRefMaskFromString("not-a-valid-enum-value")
	})
	t.Run("DiagnosticsLevelFromString", func(t *testing.T) {
		if got := DiagnosticsLevelFromString("Basic"); got != 0 {
			t.Fatalf("DiagnosticsLevelFromString(%q) = %v, want %v", "Basic", got, 0)
		}
		_ = DiagnosticsLevelFromString("not-a-valid-enum-value")
	})
	t.Run("PubSubDiagnosticsCounterClassificationFromString", func(t *testing.T) {
		if got := PubSubDiagnosticsCounterClassificationFromString("Information"); got != 0 {
			t.Fatalf("PubSubDiagnosticsCounterClassificationFromString(%q) = %v, want %v", "Information", got, 0)
		}
		_ = PubSubDiagnosticsCounterClassificationFromString("not-a-valid-enum-value")
	})
	t.Run("PasswordOptionsMaskFromString", func(t *testing.T) {
		if got := PasswordOptionsMaskFromString("None"); got != 0 {
			t.Fatalf("PasswordOptionsMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = PasswordOptionsMaskFromString("not-a-valid-enum-value")
	})
	t.Run("UserConfigurationMaskFromString", func(t *testing.T) {
		if got := UserConfigurationMaskFromString("None"); got != 0 {
			t.Fatalf("UserConfigurationMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = UserConfigurationMaskFromString("not-a-valid-enum-value")
	})
	t.Run("DuplexFromString", func(t *testing.T) {
		if got := DuplexFromString("Full"); got != 0 {
			t.Fatalf("DuplexFromString(%q) = %v, want %v", "Full", got, 0)
		}
		_ = DuplexFromString("not-a-valid-enum-value")
	})
	t.Run("InterfaceAdminStatusFromString", func(t *testing.T) {
		if got := InterfaceAdminStatusFromString("Up"); got != 0 {
			t.Fatalf("InterfaceAdminStatusFromString(%q) = %v, want %v", "Up", got, 0)
		}
		_ = InterfaceAdminStatusFromString("not-a-valid-enum-value")
	})
	t.Run("InterfaceOperStatusFromString", func(t *testing.T) {
		if got := InterfaceOperStatusFromString("Up"); got != 0 {
			t.Fatalf("InterfaceOperStatusFromString(%q) = %v, want %v", "Up", got, 0)
		}
		_ = InterfaceOperStatusFromString("not-a-valid-enum-value")
	})
	t.Run("NegotiationStatusFromString", func(t *testing.T) {
		if got := NegotiationStatusFromString("InProgress"); got != 0 {
			t.Fatalf("NegotiationStatusFromString(%q) = %v, want %v", "InProgress", got, 0)
		}
		_ = NegotiationStatusFromString("not-a-valid-enum-value")
	})
	t.Run("TsnFailureCodeFromString", func(t *testing.T) {
		if got := TsnFailureCodeFromString("NoFailure"); got != 0 {
			t.Fatalf("TsnFailureCodeFromString(%q) = %v, want %v", "NoFailure", got, 0)
		}
		_ = TsnFailureCodeFromString("not-a-valid-enum-value")
	})
	t.Run("TsnStreamStateFromString", func(t *testing.T) {
		if got := TsnStreamStateFromString("Disabled"); got != 0 {
			t.Fatalf("TsnStreamStateFromString(%q) = %v, want %v", "Disabled", got, 0)
		}
		_ = TsnStreamStateFromString("not-a-valid-enum-value")
	})
	t.Run("TsnTalkerStatusFromString", func(t *testing.T) {
		if got := TsnTalkerStatusFromString("None"); got != 0 {
			t.Fatalf("TsnTalkerStatusFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = TsnTalkerStatusFromString("not-a-valid-enum-value")
	})
	t.Run("TsnListenerStatusFromString", func(t *testing.T) {
		if got := TsnListenerStatusFromString("None"); got != 0 {
			t.Fatalf("TsnListenerStatusFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = TsnListenerStatusFromString("not-a-valid-enum-value")
	})
	t.Run("ChassisIDSubtypeFromString", func(t *testing.T) {
		if got := ChassisIDSubtypeFromString("ChassisComponent"); got != 1 {
			t.Fatalf("ChassisIDSubtypeFromString(%q) = %v, want %v", "ChassisComponent", got, 1)
		}
		_ = ChassisIDSubtypeFromString("not-a-valid-enum-value")
	})
	t.Run("PortIDSubtypeFromString", func(t *testing.T) {
		if got := PortIDSubtypeFromString("InterfaceAlias"); got != 1 {
			t.Fatalf("PortIDSubtypeFromString(%q) = %v, want %v", "InterfaceAlias", got, 1)
		}
		_ = PortIDSubtypeFromString("not-a-valid-enum-value")
	})
	t.Run("ManAddrIfSubtypeFromString", func(t *testing.T) {
		if got := ManAddrIfSubtypeFromString("None"); got != 0 {
			t.Fatalf("ManAddrIfSubtypeFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = ManAddrIfSubtypeFromString("not-a-valid-enum-value")
	})
	t.Run("LldpSystemCapabilitiesMapFromString", func(t *testing.T) {
		if got := LldpSystemCapabilitiesMapFromString("None"); got != 0 {
			t.Fatalf("LldpSystemCapabilitiesMapFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = LldpSystemCapabilitiesMapFromString("not-a-valid-enum-value")
	})
	t.Run("LogRecordMaskFromString", func(t *testing.T) {
		if got := LogRecordMaskFromString("None"); got != 0 {
			t.Fatalf("LogRecordMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = LogRecordMaskFromString("not-a-valid-enum-value")
	})
	t.Run("IDTypeFromString", func(t *testing.T) {
		if got := IDTypeFromString("Numeric"); got != 0 {
			t.Fatalf("IDTypeFromString(%q) = %v, want %v", "Numeric", got, 0)
		}
		_ = IDTypeFromString("not-a-valid-enum-value")
	})
	t.Run("NodeClassFromString", func(t *testing.T) {
		if got := NodeClassFromString("Unspecified"); got != 0 {
			t.Fatalf("NodeClassFromString(%q) = %v, want %v", "Unspecified", got, 0)
		}
		_ = NodeClassFromString("not-a-valid-enum-value")
	})
	t.Run("PermissionTypeFromString", func(t *testing.T) {
		if got := PermissionTypeFromString("None"); got != 0 {
			t.Fatalf("PermissionTypeFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = PermissionTypeFromString("not-a-valid-enum-value")
	})
	t.Run("AccessLevelTypeFromString", func(t *testing.T) {
		if got := AccessLevelTypeFromString("None"); got != 0 {
			t.Fatalf("AccessLevelTypeFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = AccessLevelTypeFromString("not-a-valid-enum-value")
	})
	t.Run("AccessLevelExTypeFromString", func(t *testing.T) {
		if got := AccessLevelExTypeFromString("None"); got != 0 {
			t.Fatalf("AccessLevelExTypeFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = AccessLevelExTypeFromString("not-a-valid-enum-value")
	})
	t.Run("EventNotifierTypeFromString", func(t *testing.T) {
		if got := EventNotifierTypeFromString("None"); got != 0 {
			t.Fatalf("EventNotifierTypeFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = EventNotifierTypeFromString("not-a-valid-enum-value")
	})
	t.Run("AccessRestrictionTypeFromString", func(t *testing.T) {
		if got := AccessRestrictionTypeFromString("None"); got != 0 {
			t.Fatalf("AccessRestrictionTypeFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = AccessRestrictionTypeFromString("not-a-valid-enum-value")
	})
	t.Run("StructureTypeFromString", func(t *testing.T) {
		if got := StructureTypeFromString("Structure"); got != 0 {
			t.Fatalf("StructureTypeFromString(%q) = %v, want %v", "Structure", got, 0)
		}
		_ = StructureTypeFromString("not-a-valid-enum-value")
	})
	t.Run("ApplicationTypeFromString", func(t *testing.T) {
		if got := ApplicationTypeFromString("Server"); got != 0 {
			t.Fatalf("ApplicationTypeFromString(%q) = %v, want %v", "Server", got, 0)
		}
		_ = ApplicationTypeFromString("not-a-valid-enum-value")
	})
	t.Run("MessageSecurityModeFromString", func(t *testing.T) {
		if got := MessageSecurityModeFromString("Invalid"); got != 0 {
			t.Fatalf("MessageSecurityModeFromString(%q) = %v, want %v", "Invalid", got, 0)
		}
		_ = MessageSecurityModeFromString("not-a-valid-enum-value")
	})
	t.Run("UserTokenTypeFromString", func(t *testing.T) {
		if got := UserTokenTypeFromString("Anonymous"); got != 0 {
			t.Fatalf("UserTokenTypeFromString(%q) = %v, want %v", "Anonymous", got, 0)
		}
		_ = UserTokenTypeFromString("not-a-valid-enum-value")
	})
	t.Run("SecurityTokenRequestTypeFromString", func(t *testing.T) {
		if got := SecurityTokenRequestTypeFromString("Issue"); got != 0 {
			t.Fatalf("SecurityTokenRequestTypeFromString(%q) = %v, want %v", "Issue", got, 0)
		}
		_ = SecurityTokenRequestTypeFromString("not-a-valid-enum-value")
	})
	t.Run("NodeAttributesMaskFromString", func(t *testing.T) {
		if got := NodeAttributesMaskFromString("None"); got != 0 {
			t.Fatalf("NodeAttributesMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = NodeAttributesMaskFromString("not-a-valid-enum-value")
	})
	t.Run("AttributeWriteMaskFromString", func(t *testing.T) {
		if got := AttributeWriteMaskFromString("None"); got != 0 {
			t.Fatalf("AttributeWriteMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = AttributeWriteMaskFromString("not-a-valid-enum-value")
	})
	t.Run("BrowseDirectionFromString", func(t *testing.T) {
		if got := BrowseDirectionFromString("Forward"); got != 0 {
			t.Fatalf("BrowseDirectionFromString(%q) = %v, want %v", "Forward", got, 0)
		}
		_ = BrowseDirectionFromString("not-a-valid-enum-value")
	})
	t.Run("BrowseResultMaskFromString", func(t *testing.T) {
		if got := BrowseResultMaskFromString("None"); got != 0 {
			t.Fatalf("BrowseResultMaskFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = BrowseResultMaskFromString("not-a-valid-enum-value")
	})
	t.Run("FilterOperatorFromString", func(t *testing.T) {
		if got := FilterOperatorFromString("Equals"); got != 0 {
			t.Fatalf("FilterOperatorFromString(%q) = %v, want %v", "Equals", got, 0)
		}
		_ = FilterOperatorFromString("not-a-valid-enum-value")
	})
	t.Run("TimestampsToReturnFromString", func(t *testing.T) {
		if got := TimestampsToReturnFromString("Source"); got != 0 {
			t.Fatalf("TimestampsToReturnFromString(%q) = %v, want %v", "Source", got, 0)
		}
		_ = TimestampsToReturnFromString("not-a-valid-enum-value")
	})
	t.Run("SortOrderTypeFromString", func(t *testing.T) {
		if got := SortOrderTypeFromString("Ascending"); got != 0 {
			t.Fatalf("SortOrderTypeFromString(%q) = %v, want %v", "Ascending", got, 0)
		}
		_ = SortOrderTypeFromString("not-a-valid-enum-value")
	})
	t.Run("HistoryUpdateTypeFromString", func(t *testing.T) {
		if got := HistoryUpdateTypeFromString("Insert"); got != 1 {
			t.Fatalf("HistoryUpdateTypeFromString(%q) = %v, want %v", "Insert", got, 1)
		}
		_ = HistoryUpdateTypeFromString("not-a-valid-enum-value")
	})
	t.Run("PerformUpdateTypeFromString", func(t *testing.T) {
		if got := PerformUpdateTypeFromString("Insert"); got != 1 {
			t.Fatalf("PerformUpdateTypeFromString(%q) = %v, want %v", "Insert", got, 1)
		}
		_ = PerformUpdateTypeFromString("not-a-valid-enum-value")
	})
	t.Run("MonitoringModeFromString", func(t *testing.T) {
		if got := MonitoringModeFromString("Disabled"); got != 0 {
			t.Fatalf("MonitoringModeFromString(%q) = %v, want %v", "Disabled", got, 0)
		}
		_ = MonitoringModeFromString("not-a-valid-enum-value")
	})
	t.Run("DataChangeTriggerFromString", func(t *testing.T) {
		if got := DataChangeTriggerFromString("Status"); got != 0 {
			t.Fatalf("DataChangeTriggerFromString(%q) = %v, want %v", "Status", got, 0)
		}
		_ = DataChangeTriggerFromString("not-a-valid-enum-value")
	})
	t.Run("DeadbandTypeFromString", func(t *testing.T) {
		if got := DeadbandTypeFromString("None"); got != 0 {
			t.Fatalf("DeadbandTypeFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = DeadbandTypeFromString("not-a-valid-enum-value")
	})
	t.Run("RedundancySupportFromString", func(t *testing.T) {
		if got := RedundancySupportFromString("None"); got != 0 {
			t.Fatalf("RedundancySupportFromString(%q) = %v, want %v", "None", got, 0)
		}
		_ = RedundancySupportFromString("not-a-valid-enum-value")
	})
	t.Run("ServerStateFromString", func(t *testing.T) {
		if got := ServerStateFromString("Running"); got != 0 {
			t.Fatalf("ServerStateFromString(%q) = %v, want %v", "Running", got, 0)
		}
		_ = ServerStateFromString("not-a-valid-enum-value")
	})
	t.Run("ModelChangeStructureVerbMaskFromString", func(t *testing.T) {
		if got := ModelChangeStructureVerbMaskFromString("NodeAdded"); got != 1 {
			t.Fatalf("ModelChangeStructureVerbMaskFromString(%q) = %v, want %v", "NodeAdded", got, 1)
		}
		_ = ModelChangeStructureVerbMaskFromString("not-a-valid-enum-value")
	})
	t.Run("AxisScaleEnumerationFromString", func(t *testing.T) {
		if got := AxisScaleEnumerationFromString("Linear"); got != 0 {
			t.Fatalf("AxisScaleEnumerationFromString(%q) = %v, want %v", "Linear", got, 0)
		}
		_ = AxisScaleEnumerationFromString("not-a-valid-enum-value")
	})
	t.Run("ExceptionDeviationFormatFromString", func(t *testing.T) {
		if got := ExceptionDeviationFormatFromString("AbsoluteValue"); got != 0 {
			t.Fatalf("ExceptionDeviationFormatFromString(%q) = %v, want %v", "AbsoluteValue", got, 0)
		}
		_ = ExceptionDeviationFormatFromString("not-a-valid-enum-value")
	})
}
