// SPDX-License-Identifier: MIT

package ua

import "testing"

// TestEnumStringMethods exercises the String() method for every generated
// enum type to drive branch coverage.
func TestEnumStringMethods(t *testing.T) {
	t.Run("AccessLevelExType", func(t *testing.T) {
		got := AccessLevelExTypeNone.String()
		if got == "" {
			t.Errorf("AccessLevelExType.String() returned empty string")
		}
	})
	t.Run("AccessLevelType", func(t *testing.T) {
		got := AccessLevelTypeNone.String()
		if got == "" {
			t.Errorf("AccessLevelType.String() returned empty string")
		}
	})
	t.Run("AccessRestrictionType", func(t *testing.T) {
		got := AccessRestrictionTypeNone.String()
		if got == "" {
			t.Errorf("AccessRestrictionType.String() returned empty string")
		}
	})
	t.Run("ActionState", func(t *testing.T) {
		got := ActionStateIdle.String()
		if got == "" {
			t.Errorf("ActionState.String() returned empty string")
		}
	})
	t.Run("AlarmMask", func(t *testing.T) {
		got := AlarmMaskNone.String()
		if got == "" {
			t.Errorf("AlarmMask.String() returned empty string")
		}
	})
	t.Run("ApplicationType", func(t *testing.T) {
		got := ApplicationTypeServer.String()
		if got == "" {
			t.Errorf("ApplicationType.String() returned empty string")
		}
	})
	t.Run("AttributeID", func(t *testing.T) {
		got := AttributeIDInvalid.String()
		if got == "" {
			t.Errorf("AttributeID.String() returned empty string")
		}
	})
	t.Run("AttributeWriteMask", func(t *testing.T) {
		got := AttributeWriteMaskNone.String()
		if got == "" {
			t.Errorf("AttributeWriteMask.String() returned empty string")
		}
	})
	t.Run("AxisScaleEnumeration", func(t *testing.T) {
		got := AxisScaleEnumerationLinear.String()
		if got == "" {
			t.Errorf("AxisScaleEnumeration.String() returned empty string")
		}
	})
	t.Run("BrokerTransportQoS", func(t *testing.T) {
		got := BrokerTransportQoSNotSpecified.String()
		if got == "" {
			t.Errorf("BrokerTransportQoS.String() returned empty string")
		}
	})
	t.Run("BrowseDirection", func(t *testing.T) {
		got := BrowseDirectionForward.String()
		if got == "" {
			t.Errorf("BrowseDirection.String() returned empty string")
		}
	})
	t.Run("BrowseResultMask", func(t *testing.T) {
		got := BrowseResultMaskNone.String()
		if got == "" {
			t.Errorf("BrowseResultMask.String() returned empty string")
		}
	})
	t.Run("ChassisIDSubtype", func(t *testing.T) {
		got := ChassisIDSubtypeChassisComponent.String()
		if got == "" {
			t.Errorf("ChassisIDSubtype.String() returned empty string")
		}
	})
	t.Run("ConfigurationUpdateType", func(t *testing.T) {
		got := ConfigurationUpdateTypeInsert.String()
		if got == "" {
			t.Errorf("ConfigurationUpdateType.String() returned empty string")
		}
	})
	t.Run("ConversionLimitEnum", func(t *testing.T) {
		got := ConversionLimitEnumNoConversion.String()
		if got == "" {
			t.Errorf("ConversionLimitEnum.String() returned empty string")
		}
	})
	t.Run("DataChangeTrigger", func(t *testing.T) {
		got := DataChangeTriggerStatus.String()
		if got == "" {
			t.Errorf("DataChangeTrigger.String() returned empty string")
		}
	})
	t.Run("DataSetFieldContentMask", func(t *testing.T) {
		got := DataSetFieldContentMaskNone.String()
		if got == "" {
			t.Errorf("DataSetFieldContentMask.String() returned empty string")
		}
	})
	t.Run("DataSetFieldFlags", func(t *testing.T) {
		got := DataSetFieldFlagsNone.String()
		if got == "" {
			t.Errorf("DataSetFieldFlags.String() returned empty string")
		}
	})
	t.Run("DataSetOrderingType", func(t *testing.T) {
		got := DataSetOrderingTypeUndefined.String()
		if got == "" {
			t.Errorf("DataSetOrderingType.String() returned empty string")
		}
	})
	t.Run("DeadbandType", func(t *testing.T) {
		got := DeadbandTypeNone.String()
		if got == "" {
			t.Errorf("DeadbandType.String() returned empty string")
		}
	})
	t.Run("DiagnosticsLevel", func(t *testing.T) {
		got := DiagnosticsLevelBasic.String()
		if got == "" {
			t.Errorf("DiagnosticsLevel.String() returned empty string")
		}
	})
	t.Run("Duplex", func(t *testing.T) {
		got := DuplexFull.String()
		if got == "" {
			t.Errorf("Duplex.String() returned empty string")
		}
	})
	t.Run("EventNotifierType", func(t *testing.T) {
		got := EventNotifierTypeNone.String()
		if got == "" {
			t.Errorf("EventNotifierType.String() returned empty string")
		}
	})
	t.Run("ExceptionDeviationFormat", func(t *testing.T) {
		got := ExceptionDeviationFormatAbsoluteValue.String()
		if got == "" {
			t.Errorf("ExceptionDeviationFormat.String() returned empty string")
		}
	})
	t.Run("FilterOperator", func(t *testing.T) {
		got := FilterOperatorEquals.String()
		if got == "" {
			t.Errorf("FilterOperator.String() returned empty string")
		}
	})
	t.Run("HistoryUpdateType", func(t *testing.T) {
		got := HistoryUpdateTypeInsert.String()
		if got == "" {
			t.Errorf("HistoryUpdateType.String() returned empty string")
		}
	})
	t.Run("IDType", func(t *testing.T) {
		got := IDTypeNumeric.String()
		if got == "" {
			t.Errorf("IDType.String() returned empty string")
		}
	})
	t.Run("IdentityCriteriaType", func(t *testing.T) {
		got := IdentityCriteriaTypeUserName.String()
		if got == "" {
			t.Errorf("IdentityCriteriaType.String() returned empty string")
		}
	})
	t.Run("InterfaceAdminStatus", func(t *testing.T) {
		got := InterfaceAdminStatusUp.String()
		if got == "" {
			t.Errorf("InterfaceAdminStatus.String() returned empty string")
		}
	})
	t.Run("InterfaceOperStatus", func(t *testing.T) {
		got := InterfaceOperStatusUp.String()
		if got == "" {
			t.Errorf("InterfaceOperStatus.String() returned empty string")
		}
	})
	t.Run("JSONDataSetMessageContentMask", func(t *testing.T) {
		got := JSONDataSetMessageContentMaskNone.String()
		if got == "" {
			t.Errorf("JSONDataSetMessageContentMask.String() returned empty string")
		}
	})
	t.Run("JSONNetworkMessageContentMask", func(t *testing.T) {
		got := JSONNetworkMessageContentMaskNone.String()
		if got == "" {
			t.Errorf("JSONNetworkMessageContentMask.String() returned empty string")
		}
	})
	t.Run("LldpSystemCapabilitiesMap", func(t *testing.T) {
		got := LldpSystemCapabilitiesMapNone.String()
		if got == "" {
			t.Errorf("LldpSystemCapabilitiesMap.String() returned empty string")
		}
	})
	t.Run("LogRecordMask", func(t *testing.T) {
		got := LogRecordMaskNone.String()
		if got == "" {
			t.Errorf("LogRecordMask.String() returned empty string")
		}
	})
	t.Run("ManAddrIfSubtype", func(t *testing.T) {
		got := ManAddrIfSubtypeNone.String()
		if got == "" {
			t.Errorf("ManAddrIfSubtype.String() returned empty string")
		}
	})
	t.Run("MessageSecurityMode", func(t *testing.T) {
		got := MessageSecurityModeInvalid.String()
		if got == "" {
			t.Errorf("MessageSecurityMode.String() returned empty string")
		}
	})
	t.Run("ModelChangeStructureVerbMask", func(t *testing.T) {
		got := ModelChangeStructureVerbMaskNodeAdded.String()
		if got == "" {
			t.Errorf("ModelChangeStructureVerbMask.String() returned empty string")
		}
	})
	t.Run("MonitoringMode", func(t *testing.T) {
		got := MonitoringModeDisabled.String()
		if got == "" {
			t.Errorf("MonitoringMode.String() returned empty string")
		}
	})
	t.Run("NamingRuleType", func(t *testing.T) {
		got := NamingRuleTypeMandatory.String()
		if got == "" {
			t.Errorf("NamingRuleType.String() returned empty string")
		}
	})
	t.Run("NegotiationStatus", func(t *testing.T) {
		got := NegotiationStatusInProgress.String()
		if got == "" {
			t.Errorf("NegotiationStatus.String() returned empty string")
		}
	})
	t.Run("NodeAttributesMask", func(t *testing.T) {
		got := NodeAttributesMaskNone.String()
		if got == "" {
			t.Errorf("NodeAttributesMask.String() returned empty string")
		}
	})
	t.Run("NodeClass", func(t *testing.T) {
		got := NodeClassAll.String()
		if got == "" {
			t.Errorf("NodeClass.String() returned empty string")
		}
	})
	t.Run("NodeIDType", func(t *testing.T) {
		got := NodeIDTypeTwoByte.String()
		if got == "" {
			t.Errorf("NodeIDType.String() returned empty string")
		}
	})
	t.Run("OpenFileMode", func(t *testing.T) {
		got := OpenFileModeRead.String()
		if got == "" {
			t.Errorf("OpenFileMode.String() returned empty string")
		}
	})
	t.Run("OverrideValueHandling", func(t *testing.T) {
		got := OverrideValueHandlingDisabled.String()
		if got == "" {
			t.Errorf("OverrideValueHandling.String() returned empty string")
		}
	})
	t.Run("PasswordOptionsMask", func(t *testing.T) {
		got := PasswordOptionsMaskNone.String()
		if got == "" {
			t.Errorf("PasswordOptionsMask.String() returned empty string")
		}
	})
	t.Run("PerformUpdateType", func(t *testing.T) {
		got := PerformUpdateTypeInsert.String()
		if got == "" {
			t.Errorf("PerformUpdateType.String() returned empty string")
		}
	})
	t.Run("PermissionType", func(t *testing.T) {
		got := PermissionTypeNone.String()
		if got == "" {
			t.Errorf("PermissionType.String() returned empty string")
		}
	})
	t.Run("PortIDSubtype", func(t *testing.T) {
		got := PortIDSubtypeInterfaceAlias.String()
		if got == "" {
			t.Errorf("PortIDSubtype.String() returned empty string")
		}
	})
	t.Run("PubSubConfigurationRefMask", func(t *testing.T) {
		got := PubSubConfigurationRefMaskNone.String()
		if got == "" {
			t.Errorf("PubSubConfigurationRefMask.String() returned empty string")
		}
	})
	t.Run("PubSubDiagnosticsCounterClassification", func(t *testing.T) {
		got := PubSubDiagnosticsCounterClassificationInformation.String()
		if got == "" {
			t.Errorf("PubSubDiagnosticsCounterClassification.String() returned empty string")
		}
	})
	t.Run("PubSubState", func(t *testing.T) {
		got := PubSubStateDisabled.String()
		if got == "" {
			t.Errorf("PubSubState.String() returned empty string")
		}
	})
	t.Run("RedundancySupport", func(t *testing.T) {
		got := RedundancySupportNone.String()
		if got == "" {
			t.Errorf("RedundancySupport.String() returned empty string")
		}
	})
	t.Run("RedundantServerMode", func(t *testing.T) {
		got := RedundantServerModePrimaryWithBackup.String()
		if got == "" {
			t.Errorf("RedundantServerMode.String() returned empty string")
		}
	})
	t.Run("SecurityTokenRequestType", func(t *testing.T) {
		got := SecurityTokenRequestTypeIssue.String()
		if got == "" {
			t.Errorf("SecurityTokenRequestType.String() returned empty string")
		}
	})
	t.Run("ServerState", func(t *testing.T) {
		got := ServerStateRunning.String()
		if got == "" {
			t.Errorf("ServerState.String() returned empty string")
		}
	})
	t.Run("SortOrderType", func(t *testing.T) {
		got := SortOrderTypeAscending.String()
		if got == "" {
			t.Errorf("SortOrderType.String() returned empty string")
		}
	})
	t.Run("StructureType", func(t *testing.T) {
		got := StructureTypeStructure.String()
		if got == "" {
			t.Errorf("StructureType.String() returned empty string")
		}
	})
	t.Run("TimestampsToReturn", func(t *testing.T) {
		got := TimestampsToReturnSource.String()
		if got == "" {
			t.Errorf("TimestampsToReturn.String() returned empty string")
		}
	})
	t.Run("TrustListMasks", func(t *testing.T) {
		got := TrustListMasksNone.String()
		if got == "" {
			t.Errorf("TrustListMasks.String() returned empty string")
		}
	})
	t.Run("TrustListValidationOptions", func(t *testing.T) {
		got := TrustListValidationOptionsNone.String()
		if got == "" {
			t.Errorf("TrustListValidationOptions.String() returned empty string")
		}
	})
	t.Run("TsnFailureCode", func(t *testing.T) {
		got := TsnFailureCodeNoFailure.String()
		if got == "" {
			t.Errorf("TsnFailureCode.String() returned empty string")
		}
	})
	t.Run("TsnListenerStatus", func(t *testing.T) {
		got := TsnListenerStatusNone.String()
		if got == "" {
			t.Errorf("TsnListenerStatus.String() returned empty string")
		}
	})
	t.Run("TsnStreamState", func(t *testing.T) {
		got := TsnStreamStateDisabled.String()
		if got == "" {
			t.Errorf("TsnStreamState.String() returned empty string")
		}
	})
	t.Run("TsnTalkerStatus", func(t *testing.T) {
		got := TsnTalkerStatusNone.String()
		if got == "" {
			t.Errorf("TsnTalkerStatus.String() returned empty string")
		}
	})
	t.Run("TypeID", func(t *testing.T) {
		got := TypeIDNull.String()
		if got == "" {
			t.Errorf("TypeID.String() returned empty string")
		}
	})
	t.Run("UADPDataSetMessageContentMask", func(t *testing.T) {
		got := UADPDataSetMessageContentMaskNone.String()
		if got == "" {
			t.Errorf("UADPDataSetMessageContentMask.String() returned empty string")
		}
	})
	t.Run("UADPNetworkMessageContentMask", func(t *testing.T) {
		got := UADPNetworkMessageContentMaskNone.String()
		if got == "" {
			t.Errorf("UADPNetworkMessageContentMask.String() returned empty string")
		}
	})
	t.Run("UserConfigurationMask", func(t *testing.T) {
		got := UserConfigurationMaskNone.String()
		if got == "" {
			t.Errorf("UserConfigurationMask.String() returned empty string")
		}
	})
	t.Run("UserTokenType", func(t *testing.T) {
		got := UserTokenTypeAnonymous.String()
		if got == "" {
			t.Errorf("UserTokenType.String() returned empty string")
		}
	})
}
