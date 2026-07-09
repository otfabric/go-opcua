// SPDX-License-Identifier: MIT

package ua

import "testing"

// TestEnumFromStringAllValues exercises every case branch of every generated
// FromString function to drive branch coverage to 100%.
func TestEnumFromStringAllValues(t *testing.T) {
	t.Run("NodeIDTypeFromString", func(t *testing.T) {
		if got := NodeIDTypeFromString("TwoByte"); int(got) != 0 {
			t.Errorf("NodeIDTypeFromString(%q) = %v, want 0", "TwoByte", got)
		}
		if got := NodeIDTypeFromString("FourByte"); int(got) != 1 {
			t.Errorf("NodeIDTypeFromString(%q) = %v, want 1", "FourByte", got)
		}
		if got := NodeIDTypeFromString("Numeric"); int(got) != 2 {
			t.Errorf("NodeIDTypeFromString(%q) = %v, want 2", "Numeric", got)
		}
		if got := NodeIDTypeFromString("String"); int(got) != 3 {
			t.Errorf("NodeIDTypeFromString(%q) = %v, want 3", "String", got)
		}
		if got := NodeIDTypeFromString("Guid"); int(got) != 4 {
			t.Errorf("NodeIDTypeFromString(%q) = %v, want 4", "Guid", got)
		}
		if got := NodeIDTypeFromString("ByteString"); int(got) != 5 {
			t.Errorf("NodeIDTypeFromString(%q) = %v, want 5", "ByteString", got)
		}
		_ = NodeIDTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("NamingRuleTypeFromString", func(t *testing.T) {
		if got := NamingRuleTypeFromString("Mandatory"); int(got) != 1 {
			t.Errorf("NamingRuleTypeFromString(%q) = %v, want 1", "Mandatory", got)
		}
		if got := NamingRuleTypeFromString("Optional"); int(got) != 2 {
			t.Errorf("NamingRuleTypeFromString(%q) = %v, want 2", "Optional", got)
		}
		if got := NamingRuleTypeFromString("Constraint"); int(got) != 3 {
			t.Errorf("NamingRuleTypeFromString(%q) = %v, want 3", "Constraint", got)
		}
		_ = NamingRuleTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("RedundantServerModeFromString", func(t *testing.T) {
		if got := RedundantServerModeFromString("PrimaryWithBackup"); int(got) != 0 {
			t.Errorf("RedundantServerModeFromString(%q) = %v, want 0", "PrimaryWithBackup", got)
		}
		if got := RedundantServerModeFromString("PrimaryOnly"); int(got) != 1 {
			t.Errorf("RedundantServerModeFromString(%q) = %v, want 1", "PrimaryOnly", got)
		}
		if got := RedundantServerModeFromString("BackupReady"); int(got) != 2 {
			t.Errorf("RedundantServerModeFromString(%q) = %v, want 2", "BackupReady", got)
		}
		if got := RedundantServerModeFromString("BackupNotReady"); int(got) != 3 {
			t.Errorf("RedundantServerModeFromString(%q) = %v, want 3", "BackupNotReady", got)
		}
		_ = RedundantServerModeFromString("__invalid__") // exercises default branch
	})
	t.Run("OpenFileModeFromString", func(t *testing.T) {
		if got := OpenFileModeFromString("Read"); int(got) != 1 {
			t.Errorf("OpenFileModeFromString(%q) = %v, want 1", "Read", got)
		}
		if got := OpenFileModeFromString("Write"); int(got) != 2 {
			t.Errorf("OpenFileModeFromString(%q) = %v, want 2", "Write", got)
		}
		if got := OpenFileModeFromString("EraseExisting"); int(got) != 4 {
			t.Errorf("OpenFileModeFromString(%q) = %v, want 4", "EraseExisting", got)
		}
		if got := OpenFileModeFromString("Append"); int(got) != 8 {
			t.Errorf("OpenFileModeFromString(%q) = %v, want 8", "Append", got)
		}
		_ = OpenFileModeFromString("__invalid__") // exercises default branch
	})
	t.Run("IdentityCriteriaTypeFromString", func(t *testing.T) {
		if got := IdentityCriteriaTypeFromString("UserName"); int(got) != 1 {
			t.Errorf("IdentityCriteriaTypeFromString(%q) = %v, want 1", "UserName", got)
		}
		if got := IdentityCriteriaTypeFromString("Thumbprint"); int(got) != 2 {
			t.Errorf("IdentityCriteriaTypeFromString(%q) = %v, want 2", "Thumbprint", got)
		}
		if got := IdentityCriteriaTypeFromString("Role"); int(got) != 3 {
			t.Errorf("IdentityCriteriaTypeFromString(%q) = %v, want 3", "Role", got)
		}
		if got := IdentityCriteriaTypeFromString("GroupId"); int(got) != 4 {
			t.Errorf("IdentityCriteriaTypeFromString(%q) = %v, want 4", "GroupId", got)
		}
		if got := IdentityCriteriaTypeFromString("Anonymous"); int(got) != 5 {
			t.Errorf("IdentityCriteriaTypeFromString(%q) = %v, want 5", "Anonymous", got)
		}
		if got := IdentityCriteriaTypeFromString("AuthenticatedUser"); int(got) != 6 {
			t.Errorf("IdentityCriteriaTypeFromString(%q) = %v, want 6", "AuthenticatedUser", got)
		}
		if got := IdentityCriteriaTypeFromString("Application"); int(got) != 7 {
			t.Errorf("IdentityCriteriaTypeFromString(%q) = %v, want 7", "Application", got)
		}
		if got := IdentityCriteriaTypeFromString("X509Subject"); int(got) != 8 {
			t.Errorf("IdentityCriteriaTypeFromString(%q) = %v, want 8", "X509Subject", got)
		}
		if got := IdentityCriteriaTypeFromString("TrustedApplication"); int(got) != 9 {
			t.Errorf("IdentityCriteriaTypeFromString(%q) = %v, want 9", "TrustedApplication", got)
		}
		_ = IdentityCriteriaTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("ConversionLimitEnumFromString", func(t *testing.T) {
		if got := ConversionLimitEnumFromString("NoConversion"); int(got) != 0 {
			t.Errorf("ConversionLimitEnumFromString(%q) = %v, want 0", "NoConversion", got)
		}
		if got := ConversionLimitEnumFromString("Limited"); int(got) != 1 {
			t.Errorf("ConversionLimitEnumFromString(%q) = %v, want 1", "Limited", got)
		}
		if got := ConversionLimitEnumFromString("Unlimited"); int(got) != 2 {
			t.Errorf("ConversionLimitEnumFromString(%q) = %v, want 2", "Unlimited", got)
		}
		_ = ConversionLimitEnumFromString("__invalid__") // exercises default branch
	})
	t.Run("AlarmMaskFromString", func(t *testing.T) {
		if got := AlarmMaskFromString("None"); int(got) != 0 {
			t.Errorf("AlarmMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := AlarmMaskFromString("Active"); int(got) != 1 {
			t.Errorf("AlarmMaskFromString(%q) = %v, want 1", "Active", got)
		}
		if got := AlarmMaskFromString("Unacknowledged"); int(got) != 2 {
			t.Errorf("AlarmMaskFromString(%q) = %v, want 2", "Unacknowledged", got)
		}
		if got := AlarmMaskFromString("Unconfirmed"); int(got) != 4 {
			t.Errorf("AlarmMaskFromString(%q) = %v, want 4", "Unconfirmed", got)
		}
		_ = AlarmMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("TrustListValidationOptionsFromString", func(t *testing.T) {
		if got := TrustListValidationOptionsFromString("None"); int(got) != 0 {
			t.Errorf("TrustListValidationOptionsFromString(%q) = %v, want 0", "None", got)
		}
		if got := TrustListValidationOptionsFromString("SuppressCertificateExpired"); int(got) != 1 {
			t.Errorf("TrustListValidationOptionsFromString(%q) = %v, want 1", "SuppressCertificateExpired", got)
		}
		if got := TrustListValidationOptionsFromString("SuppressHostNameInvalid"); int(got) != 2 {
			t.Errorf("TrustListValidationOptionsFromString(%q) = %v, want 2", "SuppressHostNameInvalid", got)
		}
		if got := TrustListValidationOptionsFromString("SuppressRevocationStatusUnknown"); int(got) != 4 {
			t.Errorf("TrustListValidationOptionsFromString(%q) = %v, want 4", "SuppressRevocationStatusUnknown", got)
		}
		if got := TrustListValidationOptionsFromString("SuppressIssuerCertificateExpired"); int(got) != 8 {
			t.Errorf("TrustListValidationOptionsFromString(%q) = %v, want 8", "SuppressIssuerCertificateExpired", got)
		}
		if got := TrustListValidationOptionsFromString("SuppressIssuerRevocationStatusUnknown"); int(got) != 16 {
			t.Errorf("TrustListValidationOptionsFromString(%q) = %v, want 16", "SuppressIssuerRevocationStatusUnknown", got)
		}
		if got := TrustListValidationOptionsFromString("CheckRevocationStatusOnline"); int(got) != 32 {
			t.Errorf("TrustListValidationOptionsFromString(%q) = %v, want 32", "CheckRevocationStatusOnline", got)
		}
		if got := TrustListValidationOptionsFromString("CheckRevocationStatusOffline"); int(got) != 64 {
			t.Errorf("TrustListValidationOptionsFromString(%q) = %v, want 64", "CheckRevocationStatusOffline", got)
		}
		_ = TrustListValidationOptionsFromString("__invalid__") // exercises default branch
	})
	t.Run("TrustListMasksFromString", func(t *testing.T) {
		if got := TrustListMasksFromString("None"); int(got) != 0 {
			t.Errorf("TrustListMasksFromString(%q) = %v, want 0", "None", got)
		}
		if got := TrustListMasksFromString("TrustedCertificates"); int(got) != 1 {
			t.Errorf("TrustListMasksFromString(%q) = %v, want 1", "TrustedCertificates", got)
		}
		if got := TrustListMasksFromString("TrustedCrls"); int(got) != 2 {
			t.Errorf("TrustListMasksFromString(%q) = %v, want 2", "TrustedCrls", got)
		}
		if got := TrustListMasksFromString("IssuerCertificates"); int(got) != 4 {
			t.Errorf("TrustListMasksFromString(%q) = %v, want 4", "IssuerCertificates", got)
		}
		if got := TrustListMasksFromString("IssuerCrls"); int(got) != 8 {
			t.Errorf("TrustListMasksFromString(%q) = %v, want 8", "IssuerCrls", got)
		}
		if got := TrustListMasksFromString("All"); int(got) != 15 {
			t.Errorf("TrustListMasksFromString(%q) = %v, want 15", "All", got)
		}
		_ = TrustListMasksFromString("__invalid__") // exercises default branch
	})
	t.Run("ConfigurationUpdateTypeFromString", func(t *testing.T) {
		if got := ConfigurationUpdateTypeFromString("Insert"); int(got) != 1 {
			t.Errorf("ConfigurationUpdateTypeFromString(%q) = %v, want 1", "Insert", got)
		}
		if got := ConfigurationUpdateTypeFromString("Replace"); int(got) != 2 {
			t.Errorf("ConfigurationUpdateTypeFromString(%q) = %v, want 2", "Replace", got)
		}
		if got := ConfigurationUpdateTypeFromString("InsertOrReplace"); int(got) != 3 {
			t.Errorf("ConfigurationUpdateTypeFromString(%q) = %v, want 3", "InsertOrReplace", got)
		}
		if got := ConfigurationUpdateTypeFromString("Delete"); int(got) != 4 {
			t.Errorf("ConfigurationUpdateTypeFromString(%q) = %v, want 4", "Delete", got)
		}
		_ = ConfigurationUpdateTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("PubSubStateFromString", func(t *testing.T) {
		if got := PubSubStateFromString("Disabled"); int(got) != 0 {
			t.Errorf("PubSubStateFromString(%q) = %v, want 0", "Disabled", got)
		}
		if got := PubSubStateFromString("Paused"); int(got) != 1 {
			t.Errorf("PubSubStateFromString(%q) = %v, want 1", "Paused", got)
		}
		if got := PubSubStateFromString("Operational"); int(got) != 2 {
			t.Errorf("PubSubStateFromString(%q) = %v, want 2", "Operational", got)
		}
		if got := PubSubStateFromString("Error"); int(got) != 3 {
			t.Errorf("PubSubStateFromString(%q) = %v, want 3", "Error", got)
		}
		if got := PubSubStateFromString("PreOperational"); int(got) != 4 {
			t.Errorf("PubSubStateFromString(%q) = %v, want 4", "PreOperational", got)
		}
		_ = PubSubStateFromString("__invalid__") // exercises default branch
	})
	t.Run("DataSetFieldFlagsFromString", func(t *testing.T) {
		if got := DataSetFieldFlagsFromString("None"); int(got) != 0 {
			t.Errorf("DataSetFieldFlagsFromString(%q) = %v, want 0", "None", got)
		}
		if got := DataSetFieldFlagsFromString("PromotedField"); int(got) != 1 {
			t.Errorf("DataSetFieldFlagsFromString(%q) = %v, want 1", "PromotedField", got)
		}
		_ = DataSetFieldFlagsFromString("__invalid__") // exercises default branch
	})
	t.Run("ActionStateFromString", func(t *testing.T) {
		if got := ActionStateFromString("Idle"); int(got) != 0 {
			t.Errorf("ActionStateFromString(%q) = %v, want 0", "Idle", got)
		}
		if got := ActionStateFromString("Executing"); int(got) != 1 {
			t.Errorf("ActionStateFromString(%q) = %v, want 1", "Executing", got)
		}
		if got := ActionStateFromString("Done"); int(got) != 2 {
			t.Errorf("ActionStateFromString(%q) = %v, want 2", "Done", got)
		}
		_ = ActionStateFromString("__invalid__") // exercises default branch
	})
	t.Run("DataSetFieldContentMaskFromString", func(t *testing.T) {
		if got := DataSetFieldContentMaskFromString("None"); int(got) != 0 {
			t.Errorf("DataSetFieldContentMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := DataSetFieldContentMaskFromString("StatusCode"); int(got) != 1 {
			t.Errorf("DataSetFieldContentMaskFromString(%q) = %v, want 1", "StatusCode", got)
		}
		if got := DataSetFieldContentMaskFromString("SourceTimestamp"); int(got) != 2 {
			t.Errorf("DataSetFieldContentMaskFromString(%q) = %v, want 2", "SourceTimestamp", got)
		}
		if got := DataSetFieldContentMaskFromString("ServerTimestamp"); int(got) != 4 {
			t.Errorf("DataSetFieldContentMaskFromString(%q) = %v, want 4", "ServerTimestamp", got)
		}
		if got := DataSetFieldContentMaskFromString("SourcePicoSeconds"); int(got) != 8 {
			t.Errorf("DataSetFieldContentMaskFromString(%q) = %v, want 8", "SourcePicoSeconds", got)
		}
		if got := DataSetFieldContentMaskFromString("ServerPicoSeconds"); int(got) != 16 {
			t.Errorf("DataSetFieldContentMaskFromString(%q) = %v, want 16", "ServerPicoSeconds", got)
		}
		if got := DataSetFieldContentMaskFromString("RawData"); int(got) != 32 {
			t.Errorf("DataSetFieldContentMaskFromString(%q) = %v, want 32", "RawData", got)
		}
		_ = DataSetFieldContentMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("OverrideValueHandlingFromString", func(t *testing.T) {
		if got := OverrideValueHandlingFromString("Disabled"); int(got) != 0 {
			t.Errorf("OverrideValueHandlingFromString(%q) = %v, want 0", "Disabled", got)
		}
		if got := OverrideValueHandlingFromString("LastUsableValue"); int(got) != 1 {
			t.Errorf("OverrideValueHandlingFromString(%q) = %v, want 1", "LastUsableValue", got)
		}
		if got := OverrideValueHandlingFromString("OverrideValue"); int(got) != 2 {
			t.Errorf("OverrideValueHandlingFromString(%q) = %v, want 2", "OverrideValue", got)
		}
		_ = OverrideValueHandlingFromString("__invalid__") // exercises default branch
	})
	t.Run("DataSetOrderingTypeFromString", func(t *testing.T) {
		if got := DataSetOrderingTypeFromString("Undefined"); int(got) != 0 {
			t.Errorf("DataSetOrderingTypeFromString(%q) = %v, want 0", "Undefined", got)
		}
		if got := DataSetOrderingTypeFromString("AscendingWriterId"); int(got) != 1 {
			t.Errorf("DataSetOrderingTypeFromString(%q) = %v, want 1", "AscendingWriterId", got)
		}
		if got := DataSetOrderingTypeFromString("AscendingWriterIdSingle"); int(got) != 2 {
			t.Errorf("DataSetOrderingTypeFromString(%q) = %v, want 2", "AscendingWriterIdSingle", got)
		}
		_ = DataSetOrderingTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("UADPNetworkMessageContentMaskFromString", func(t *testing.T) {
		if got := UADPNetworkMessageContentMaskFromString("None"); int(got) != 0 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("PublisherId"); int(got) != 1 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 1", "PublisherId", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("GroupHeader"); int(got) != 2 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 2", "GroupHeader", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("WriterGroupId"); int(got) != 4 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 4", "WriterGroupId", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("GroupVersion"); int(got) != 8 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 8", "GroupVersion", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("NetworkMessageNumber"); int(got) != 16 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 16", "NetworkMessageNumber", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("SequenceNumber"); int(got) != 32 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 32", "SequenceNumber", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("PayloadHeader"); int(got) != 64 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 64", "PayloadHeader", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("Timestamp"); int(got) != 128 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 128", "Timestamp", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("PicoSeconds"); int(got) != 256 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 256", "PicoSeconds", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("DataSetClassId"); int(got) != 512 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 512", "DataSetClassId", got)
		}
		if got := UADPNetworkMessageContentMaskFromString("PromotedFields"); int(got) != 1024 {
			t.Errorf("UADPNetworkMessageContentMaskFromString(%q) = %v, want 1024", "PromotedFields", got)
		}
		_ = UADPNetworkMessageContentMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("UADPDataSetMessageContentMaskFromString", func(t *testing.T) {
		if got := UADPDataSetMessageContentMaskFromString("None"); int(got) != 0 {
			t.Errorf("UADPDataSetMessageContentMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := UADPDataSetMessageContentMaskFromString("Timestamp"); int(got) != 1 {
			t.Errorf("UADPDataSetMessageContentMaskFromString(%q) = %v, want 1", "Timestamp", got)
		}
		if got := UADPDataSetMessageContentMaskFromString("PicoSeconds"); int(got) != 2 {
			t.Errorf("UADPDataSetMessageContentMaskFromString(%q) = %v, want 2", "PicoSeconds", got)
		}
		if got := UADPDataSetMessageContentMaskFromString("Status"); int(got) != 4 {
			t.Errorf("UADPDataSetMessageContentMaskFromString(%q) = %v, want 4", "Status", got)
		}
		if got := UADPDataSetMessageContentMaskFromString("MajorVersion"); int(got) != 8 {
			t.Errorf("UADPDataSetMessageContentMaskFromString(%q) = %v, want 8", "MajorVersion", got)
		}
		if got := UADPDataSetMessageContentMaskFromString("MinorVersion"); int(got) != 16 {
			t.Errorf("UADPDataSetMessageContentMaskFromString(%q) = %v, want 16", "MinorVersion", got)
		}
		if got := UADPDataSetMessageContentMaskFromString("SequenceNumber"); int(got) != 32 {
			t.Errorf("UADPDataSetMessageContentMaskFromString(%q) = %v, want 32", "SequenceNumber", got)
		}
		_ = UADPDataSetMessageContentMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("JSONNetworkMessageContentMaskFromString", func(t *testing.T) {
		if got := JSONNetworkMessageContentMaskFromString("None"); int(got) != 0 {
			t.Errorf("JSONNetworkMessageContentMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := JSONNetworkMessageContentMaskFromString("NetworkMessageHeader"); int(got) != 1 {
			t.Errorf("JSONNetworkMessageContentMaskFromString(%q) = %v, want 1", "NetworkMessageHeader", got)
		}
		if got := JSONNetworkMessageContentMaskFromString("DataSetMessageHeader"); int(got) != 2 {
			t.Errorf("JSONNetworkMessageContentMaskFromString(%q) = %v, want 2", "DataSetMessageHeader", got)
		}
		if got := JSONNetworkMessageContentMaskFromString("SingleDataSetMessage"); int(got) != 4 {
			t.Errorf("JSONNetworkMessageContentMaskFromString(%q) = %v, want 4", "SingleDataSetMessage", got)
		}
		if got := JSONNetworkMessageContentMaskFromString("PublisherId"); int(got) != 8 {
			t.Errorf("JSONNetworkMessageContentMaskFromString(%q) = %v, want 8", "PublisherId", got)
		}
		if got := JSONNetworkMessageContentMaskFromString("DataSetClassId"); int(got) != 16 {
			t.Errorf("JSONNetworkMessageContentMaskFromString(%q) = %v, want 16", "DataSetClassId", got)
		}
		if got := JSONNetworkMessageContentMaskFromString("ReplyTo"); int(got) != 32 {
			t.Errorf("JSONNetworkMessageContentMaskFromString(%q) = %v, want 32", "ReplyTo", got)
		}
		if got := JSONNetworkMessageContentMaskFromString("WriterGroupName"); int(got) != 64 {
			t.Errorf("JSONNetworkMessageContentMaskFromString(%q) = %v, want 64", "WriterGroupName", got)
		}
		_ = JSONNetworkMessageContentMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("JSONDataSetMessageContentMaskFromString", func(t *testing.T) {
		if got := JSONDataSetMessageContentMaskFromString("None"); int(got) != 0 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("DataSetWriterId"); int(got) != 1 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 1", "DataSetWriterId", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("MetaDataVersion"); int(got) != 2 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 2", "MetaDataVersion", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("SequenceNumber"); int(got) != 4 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 4", "SequenceNumber", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("Timestamp"); int(got) != 8 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 8", "Timestamp", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("Status"); int(got) != 16 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 16", "Status", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("MessageType"); int(got) != 32 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 32", "MessageType", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("DataSetWriterName"); int(got) != 64 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 64", "DataSetWriterName", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("FieldEncoding1"); int(got) != 128 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 128", "FieldEncoding1", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("PublisherId"); int(got) != 256 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 256", "PublisherId", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("WriterGroupName"); int(got) != 512 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 512", "WriterGroupName", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("MinorVersion"); int(got) != 1024 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 1024", "MinorVersion", got)
		}
		if got := JSONDataSetMessageContentMaskFromString("FieldEncoding2"); int(got) != 2048 {
			t.Errorf("JSONDataSetMessageContentMaskFromString(%q) = %v, want 2048", "FieldEncoding2", got)
		}
		_ = JSONDataSetMessageContentMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("BrokerTransportQoSFromString", func(t *testing.T) {
		if got := BrokerTransportQoSFromString("NotSpecified"); int(got) != 0 {
			t.Errorf("BrokerTransportQoSFromString(%q) = %v, want 0", "NotSpecified", got)
		}
		if got := BrokerTransportQoSFromString("BestEffort"); int(got) != 1 {
			t.Errorf("BrokerTransportQoSFromString(%q) = %v, want 1", "BestEffort", got)
		}
		if got := BrokerTransportQoSFromString("AtLeastOnce"); int(got) != 2 {
			t.Errorf("BrokerTransportQoSFromString(%q) = %v, want 2", "AtLeastOnce", got)
		}
		if got := BrokerTransportQoSFromString("AtMostOnce"); int(got) != 3 {
			t.Errorf("BrokerTransportQoSFromString(%q) = %v, want 3", "AtMostOnce", got)
		}
		if got := BrokerTransportQoSFromString("ExactlyOnce"); int(got) != 4 {
			t.Errorf("BrokerTransportQoSFromString(%q) = %v, want 4", "ExactlyOnce", got)
		}
		_ = BrokerTransportQoSFromString("__invalid__") // exercises default branch
	})
	t.Run("PubSubConfigurationRefMaskFromString", func(t *testing.T) {
		if got := PubSubConfigurationRefMaskFromString("None"); int(got) != 0 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ElementAdd"); int(got) != 1 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 1", "ElementAdd", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ElementMatch"); int(got) != 2 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 2", "ElementMatch", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ElementModify"); int(got) != 4 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 4", "ElementModify", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ElementRemove"); int(got) != 8 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 8", "ElementRemove", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ReferenceWriter"); int(got) != 16 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 16", "ReferenceWriter", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ReferenceReader"); int(got) != 32 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 32", "ReferenceReader", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ReferenceWriterGroup"); int(got) != 64 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 64", "ReferenceWriterGroup", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ReferenceReaderGroup"); int(got) != 128 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 128", "ReferenceReaderGroup", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ReferenceConnection"); int(got) != 256 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 256", "ReferenceConnection", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ReferencePubDataset"); int(got) != 512 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 512", "ReferencePubDataset", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ReferenceSubDataset"); int(got) != 1024 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 1024", "ReferenceSubDataset", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ReferenceSecurityGroup"); int(got) != 2048 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 2048", "ReferenceSecurityGroup", got)
		}
		if got := PubSubConfigurationRefMaskFromString("ReferencePushTarget"); int(got) != 4096 {
			t.Errorf("PubSubConfigurationRefMaskFromString(%q) = %v, want 4096", "ReferencePushTarget", got)
		}
		_ = PubSubConfigurationRefMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("DiagnosticsLevelFromString", func(t *testing.T) {
		if got := DiagnosticsLevelFromString("Basic"); int(got) != 0 {
			t.Errorf("DiagnosticsLevelFromString(%q) = %v, want 0", "Basic", got)
		}
		if got := DiagnosticsLevelFromString("Advanced"); int(got) != 1 {
			t.Errorf("DiagnosticsLevelFromString(%q) = %v, want 1", "Advanced", got)
		}
		if got := DiagnosticsLevelFromString("Info"); int(got) != 2 {
			t.Errorf("DiagnosticsLevelFromString(%q) = %v, want 2", "Info", got)
		}
		if got := DiagnosticsLevelFromString("Log"); int(got) != 3 {
			t.Errorf("DiagnosticsLevelFromString(%q) = %v, want 3", "Log", got)
		}
		if got := DiagnosticsLevelFromString("Debug"); int(got) != 4 {
			t.Errorf("DiagnosticsLevelFromString(%q) = %v, want 4", "Debug", got)
		}
		_ = DiagnosticsLevelFromString("__invalid__") // exercises default branch
	})
	t.Run("PubSubDiagnosticsCounterClassificationFromString", func(t *testing.T) {
		if got := PubSubDiagnosticsCounterClassificationFromString("Information"); int(got) != 0 {
			t.Errorf("PubSubDiagnosticsCounterClassificationFromString(%q) = %v, want 0", "Information", got)
		}
		if got := PubSubDiagnosticsCounterClassificationFromString("Error"); int(got) != 1 {
			t.Errorf("PubSubDiagnosticsCounterClassificationFromString(%q) = %v, want 1", "Error", got)
		}
		_ = PubSubDiagnosticsCounterClassificationFromString("__invalid__") // exercises default branch
	})
	t.Run("PasswordOptionsMaskFromString", func(t *testing.T) {
		if got := PasswordOptionsMaskFromString("None"); int(got) != 0 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := PasswordOptionsMaskFromString("SupportInitialPasswordChange"); int(got) != 1 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 1", "SupportInitialPasswordChange", got)
		}
		if got := PasswordOptionsMaskFromString("SupportDisableUser"); int(got) != 2 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 2", "SupportDisableUser", got)
		}
		if got := PasswordOptionsMaskFromString("SupportDisableDeleteForUser"); int(got) != 4 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 4", "SupportDisableDeleteForUser", got)
		}
		if got := PasswordOptionsMaskFromString("SupportNoChangeForUser"); int(got) != 8 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 8", "SupportNoChangeForUser", got)
		}
		if got := PasswordOptionsMaskFromString("SupportDescriptionForUser"); int(got) != 16 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 16", "SupportDescriptionForUser", got)
		}
		if got := PasswordOptionsMaskFromString("RequiresUpperCaseCharacters"); int(got) != 32 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 32", "RequiresUpperCaseCharacters", got)
		}
		if got := PasswordOptionsMaskFromString("RequiresLowerCaseCharacters"); int(got) != 64 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 64", "RequiresLowerCaseCharacters", got)
		}
		if got := PasswordOptionsMaskFromString("RequiresDigitCharacters"); int(got) != 128 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 128", "RequiresDigitCharacters", got)
		}
		if got := PasswordOptionsMaskFromString("RequiresSpecialCharacters"); int(got) != 256 {
			t.Errorf("PasswordOptionsMaskFromString(%q) = %v, want 256", "RequiresSpecialCharacters", got)
		}
		_ = PasswordOptionsMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("UserConfigurationMaskFromString", func(t *testing.T) {
		if got := UserConfigurationMaskFromString("None"); int(got) != 0 {
			t.Errorf("UserConfigurationMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := UserConfigurationMaskFromString("NoDelete"); int(got) != 1 {
			t.Errorf("UserConfigurationMaskFromString(%q) = %v, want 1", "NoDelete", got)
		}
		if got := UserConfigurationMaskFromString("Disabled"); int(got) != 2 {
			t.Errorf("UserConfigurationMaskFromString(%q) = %v, want 2", "Disabled", got)
		}
		if got := UserConfigurationMaskFromString("NoChangeByUser"); int(got) != 4 {
			t.Errorf("UserConfigurationMaskFromString(%q) = %v, want 4", "NoChangeByUser", got)
		}
		if got := UserConfigurationMaskFromString("MustChangePassword"); int(got) != 8 {
			t.Errorf("UserConfigurationMaskFromString(%q) = %v, want 8", "MustChangePassword", got)
		}
		_ = UserConfigurationMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("DuplexFromString", func(t *testing.T) {
		if got := DuplexFromString("Full"); int(got) != 0 {
			t.Errorf("DuplexFromString(%q) = %v, want 0", "Full", got)
		}
		if got := DuplexFromString("Half"); int(got) != 1 {
			t.Errorf("DuplexFromString(%q) = %v, want 1", "Half", got)
		}
		if got := DuplexFromString("Unknown"); int(got) != 2 {
			t.Errorf("DuplexFromString(%q) = %v, want 2", "Unknown", got)
		}
		_ = DuplexFromString("__invalid__") // exercises default branch
	})
	t.Run("InterfaceAdminStatusFromString", func(t *testing.T) {
		if got := InterfaceAdminStatusFromString("Up"); int(got) != 0 {
			t.Errorf("InterfaceAdminStatusFromString(%q) = %v, want 0", "Up", got)
		}
		if got := InterfaceAdminStatusFromString("Down"); int(got) != 1 {
			t.Errorf("InterfaceAdminStatusFromString(%q) = %v, want 1", "Down", got)
		}
		if got := InterfaceAdminStatusFromString("Testing"); int(got) != 2 {
			t.Errorf("InterfaceAdminStatusFromString(%q) = %v, want 2", "Testing", got)
		}
		_ = InterfaceAdminStatusFromString("__invalid__") // exercises default branch
	})
	t.Run("InterfaceOperStatusFromString", func(t *testing.T) {
		if got := InterfaceOperStatusFromString("Up"); int(got) != 0 {
			t.Errorf("InterfaceOperStatusFromString(%q) = %v, want 0", "Up", got)
		}
		if got := InterfaceOperStatusFromString("Down"); int(got) != 1 {
			t.Errorf("InterfaceOperStatusFromString(%q) = %v, want 1", "Down", got)
		}
		if got := InterfaceOperStatusFromString("Testing"); int(got) != 2 {
			t.Errorf("InterfaceOperStatusFromString(%q) = %v, want 2", "Testing", got)
		}
		if got := InterfaceOperStatusFromString("Unknown"); int(got) != 3 {
			t.Errorf("InterfaceOperStatusFromString(%q) = %v, want 3", "Unknown", got)
		}
		if got := InterfaceOperStatusFromString("Dormant"); int(got) != 4 {
			t.Errorf("InterfaceOperStatusFromString(%q) = %v, want 4", "Dormant", got)
		}
		if got := InterfaceOperStatusFromString("NotPresent"); int(got) != 5 {
			t.Errorf("InterfaceOperStatusFromString(%q) = %v, want 5", "NotPresent", got)
		}
		if got := InterfaceOperStatusFromString("LowerLayerDown"); int(got) != 6 {
			t.Errorf("InterfaceOperStatusFromString(%q) = %v, want 6", "LowerLayerDown", got)
		}
		_ = InterfaceOperStatusFromString("__invalid__") // exercises default branch
	})
	t.Run("NegotiationStatusFromString", func(t *testing.T) {
		if got := NegotiationStatusFromString("InProgress"); int(got) != 0 {
			t.Errorf("NegotiationStatusFromString(%q) = %v, want 0", "InProgress", got)
		}
		if got := NegotiationStatusFromString("Complete"); int(got) != 1 {
			t.Errorf("NegotiationStatusFromString(%q) = %v, want 1", "Complete", got)
		}
		if got := NegotiationStatusFromString("Failed"); int(got) != 2 {
			t.Errorf("NegotiationStatusFromString(%q) = %v, want 2", "Failed", got)
		}
		if got := NegotiationStatusFromString("Unknown"); int(got) != 3 {
			t.Errorf("NegotiationStatusFromString(%q) = %v, want 3", "Unknown", got)
		}
		if got := NegotiationStatusFromString("NoNegotiation"); int(got) != 4 {
			t.Errorf("NegotiationStatusFromString(%q) = %v, want 4", "NoNegotiation", got)
		}
		_ = NegotiationStatusFromString("__invalid__") // exercises default branch
	})
	t.Run("TsnFailureCodeFromString", func(t *testing.T) {
		if got := TsnFailureCodeFromString("NoFailure"); int(got) != 0 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 0", "NoFailure", got)
		}
		if got := TsnFailureCodeFromString("InsufficientBandwidth"); int(got) != 1 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 1", "InsufficientBandwidth", got)
		}
		if got := TsnFailureCodeFromString("InsufficientResources"); int(got) != 2 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 2", "InsufficientResources", got)
		}
		if got := TsnFailureCodeFromString("InsufficientTrafficClassBandwidth"); int(got) != 3 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 3", "InsufficientTrafficClassBandwidth", got)
		}
		if got := TsnFailureCodeFromString("StreamIdInUse"); int(got) != 4 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 4", "StreamIdInUse", got)
		}
		if got := TsnFailureCodeFromString("StreamDestinationAddressInUse"); int(got) != 5 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 5", "StreamDestinationAddressInUse", got)
		}
		if got := TsnFailureCodeFromString("StreamPreemptedByHigherRank"); int(got) != 6 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 6", "StreamPreemptedByHigherRank", got)
		}
		if got := TsnFailureCodeFromString("LatencyHasChanged"); int(got) != 7 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 7", "LatencyHasChanged", got)
		}
		if got := TsnFailureCodeFromString("EgressPortNotAvbCapable"); int(got) != 8 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 8", "EgressPortNotAvbCapable", got)
		}
		if got := TsnFailureCodeFromString("UseDifferentDestinationAddress"); int(got) != 9 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 9", "UseDifferentDestinationAddress", got)
		}
		if got := TsnFailureCodeFromString("OutOfMsrpResources"); int(got) != 10 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 10", "OutOfMsrpResources", got)
		}
		if got := TsnFailureCodeFromString("OutOfMmrpResources"); int(got) != 11 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 11", "OutOfMmrpResources", got)
		}
		if got := TsnFailureCodeFromString("CannotStoreDestinationAddress"); int(got) != 12 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 12", "CannotStoreDestinationAddress", got)
		}
		if got := TsnFailureCodeFromString("PriorityIsNotAnSrcClass"); int(got) != 13 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 13", "PriorityIsNotAnSrcClass", got)
		}
		if got := TsnFailureCodeFromString("MaxFrameSizeTooLarge"); int(got) != 14 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 14", "MaxFrameSizeTooLarge", got)
		}
		if got := TsnFailureCodeFromString("MaxFanInPortsLimitReached"); int(got) != 15 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 15", "MaxFanInPortsLimitReached", got)
		}
		if got := TsnFailureCodeFromString("FirstValueChangedForStreamId"); int(got) != 16 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 16", "FirstValueChangedForStreamId", got)
		}
		if got := TsnFailureCodeFromString("VlanBlockedOnEgress"); int(got) != 17 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 17", "VlanBlockedOnEgress", got)
		}
		if got := TsnFailureCodeFromString("VlanTaggingDisabledOnEgress"); int(got) != 18 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 18", "VlanTaggingDisabledOnEgress", got)
		}
		if got := TsnFailureCodeFromString("SrClassPriorityMismatch"); int(got) != 19 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 19", "SrClassPriorityMismatch", got)
		}
		if got := TsnFailureCodeFromString("FeatureNotPropagated"); int(got) != 20 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 20", "FeatureNotPropagated", got)
		}
		if got := TsnFailureCodeFromString("MaxLatencyExceeded"); int(got) != 21 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 21", "MaxLatencyExceeded", got)
		}
		if got := TsnFailureCodeFromString("BridgeDoesNotProvideNetworkId"); int(got) != 22 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 22", "BridgeDoesNotProvideNetworkId", got)
		}
		if got := TsnFailureCodeFromString("StreamTransformNotSupported"); int(got) != 23 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 23", "StreamTransformNotSupported", got)
		}
		if got := TsnFailureCodeFromString("StreamIdTypeNotSupported"); int(got) != 24 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 24", "StreamIdTypeNotSupported", got)
		}
		if got := TsnFailureCodeFromString("FeatureNotSupported"); int(got) != 25 {
			t.Errorf("TsnFailureCodeFromString(%q) = %v, want 25", "FeatureNotSupported", got)
		}
		_ = TsnFailureCodeFromString("__invalid__") // exercises default branch
	})
	t.Run("TsnStreamStateFromString", func(t *testing.T) {
		if got := TsnStreamStateFromString("Disabled"); int(got) != 0 {
			t.Errorf("TsnStreamStateFromString(%q) = %v, want 0", "Disabled", got)
		}
		if got := TsnStreamStateFromString("Configuring"); int(got) != 1 {
			t.Errorf("TsnStreamStateFromString(%q) = %v, want 1", "Configuring", got)
		}
		if got := TsnStreamStateFromString("Ready"); int(got) != 2 {
			t.Errorf("TsnStreamStateFromString(%q) = %v, want 2", "Ready", got)
		}
		if got := TsnStreamStateFromString("Operational"); int(got) != 3 {
			t.Errorf("TsnStreamStateFromString(%q) = %v, want 3", "Operational", got)
		}
		if got := TsnStreamStateFromString("Error"); int(got) != 4 {
			t.Errorf("TsnStreamStateFromString(%q) = %v, want 4", "Error", got)
		}
		_ = TsnStreamStateFromString("__invalid__") // exercises default branch
	})
	t.Run("TsnTalkerStatusFromString", func(t *testing.T) {
		if got := TsnTalkerStatusFromString("None"); int(got) != 0 {
			t.Errorf("TsnTalkerStatusFromString(%q) = %v, want 0", "None", got)
		}
		if got := TsnTalkerStatusFromString("Ready"); int(got) != 1 {
			t.Errorf("TsnTalkerStatusFromString(%q) = %v, want 1", "Ready", got)
		}
		if got := TsnTalkerStatusFromString("Failed"); int(got) != 2 {
			t.Errorf("TsnTalkerStatusFromString(%q) = %v, want 2", "Failed", got)
		}
		_ = TsnTalkerStatusFromString("__invalid__") // exercises default branch
	})
	t.Run("TsnListenerStatusFromString", func(t *testing.T) {
		if got := TsnListenerStatusFromString("None"); int(got) != 0 {
			t.Errorf("TsnListenerStatusFromString(%q) = %v, want 0", "None", got)
		}
		if got := TsnListenerStatusFromString("Ready"); int(got) != 1 {
			t.Errorf("TsnListenerStatusFromString(%q) = %v, want 1", "Ready", got)
		}
		if got := TsnListenerStatusFromString("PartialFailed"); int(got) != 2 {
			t.Errorf("TsnListenerStatusFromString(%q) = %v, want 2", "PartialFailed", got)
		}
		if got := TsnListenerStatusFromString("Failed"); int(got) != 3 {
			t.Errorf("TsnListenerStatusFromString(%q) = %v, want 3", "Failed", got)
		}
		_ = TsnListenerStatusFromString("__invalid__") // exercises default branch
	})
	t.Run("ChassisIDSubtypeFromString", func(t *testing.T) {
		if got := ChassisIDSubtypeFromString("ChassisComponent"); int(got) != 1 {
			t.Errorf("ChassisIDSubtypeFromString(%q) = %v, want 1", "ChassisComponent", got)
		}
		if got := ChassisIDSubtypeFromString("InterfaceAlias"); int(got) != 2 {
			t.Errorf("ChassisIDSubtypeFromString(%q) = %v, want 2", "InterfaceAlias", got)
		}
		if got := ChassisIDSubtypeFromString("PortComponent"); int(got) != 3 {
			t.Errorf("ChassisIDSubtypeFromString(%q) = %v, want 3", "PortComponent", got)
		}
		if got := ChassisIDSubtypeFromString("MacAddress"); int(got) != 4 {
			t.Errorf("ChassisIDSubtypeFromString(%q) = %v, want 4", "MacAddress", got)
		}
		if got := ChassisIDSubtypeFromString("NetworkAddress"); int(got) != 5 {
			t.Errorf("ChassisIDSubtypeFromString(%q) = %v, want 5", "NetworkAddress", got)
		}
		if got := ChassisIDSubtypeFromString("InterfaceName"); int(got) != 6 {
			t.Errorf("ChassisIDSubtypeFromString(%q) = %v, want 6", "InterfaceName", got)
		}
		if got := ChassisIDSubtypeFromString("Local"); int(got) != 7 {
			t.Errorf("ChassisIDSubtypeFromString(%q) = %v, want 7", "Local", got)
		}
		_ = ChassisIDSubtypeFromString("__invalid__") // exercises default branch
	})
	t.Run("PortIDSubtypeFromString", func(t *testing.T) {
		if got := PortIDSubtypeFromString("InterfaceAlias"); int(got) != 1 {
			t.Errorf("PortIDSubtypeFromString(%q) = %v, want 1", "InterfaceAlias", got)
		}
		if got := PortIDSubtypeFromString("PortComponent"); int(got) != 2 {
			t.Errorf("PortIDSubtypeFromString(%q) = %v, want 2", "PortComponent", got)
		}
		if got := PortIDSubtypeFromString("MacAddress"); int(got) != 3 {
			t.Errorf("PortIDSubtypeFromString(%q) = %v, want 3", "MacAddress", got)
		}
		if got := PortIDSubtypeFromString("NetworkAddress"); int(got) != 4 {
			t.Errorf("PortIDSubtypeFromString(%q) = %v, want 4", "NetworkAddress", got)
		}
		if got := PortIDSubtypeFromString("InterfaceName"); int(got) != 5 {
			t.Errorf("PortIDSubtypeFromString(%q) = %v, want 5", "InterfaceName", got)
		}
		if got := PortIDSubtypeFromString("AgentCircuitId"); int(got) != 6 {
			t.Errorf("PortIDSubtypeFromString(%q) = %v, want 6", "AgentCircuitId", got)
		}
		if got := PortIDSubtypeFromString("Local"); int(got) != 7 {
			t.Errorf("PortIDSubtypeFromString(%q) = %v, want 7", "Local", got)
		}
		_ = PortIDSubtypeFromString("__invalid__") // exercises default branch
	})
	t.Run("ManAddrIfSubtypeFromString", func(t *testing.T) {
		if got := ManAddrIfSubtypeFromString("None"); int(got) != 0 {
			t.Errorf("ManAddrIfSubtypeFromString(%q) = %v, want 0", "None", got)
		}
		if got := ManAddrIfSubtypeFromString("Unknown"); int(got) != 1 {
			t.Errorf("ManAddrIfSubtypeFromString(%q) = %v, want 1", "Unknown", got)
		}
		if got := ManAddrIfSubtypeFromString("PortRef"); int(got) != 2 {
			t.Errorf("ManAddrIfSubtypeFromString(%q) = %v, want 2", "PortRef", got)
		}
		if got := ManAddrIfSubtypeFromString("SystemPortNumber"); int(got) != 3 {
			t.Errorf("ManAddrIfSubtypeFromString(%q) = %v, want 3", "SystemPortNumber", got)
		}
		_ = ManAddrIfSubtypeFromString("__invalid__") // exercises default branch
	})
	t.Run("LldpSystemCapabilitiesMapFromString", func(t *testing.T) {
		if got := LldpSystemCapabilitiesMapFromString("None"); int(got) != 0 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 0", "None", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("Other"); int(got) != 1 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 1", "Other", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("Repeater"); int(got) != 2 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 2", "Repeater", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("Bridge"); int(got) != 4 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 4", "Bridge", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("WlanAccessPoint"); int(got) != 8 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 8", "WlanAccessPoint", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("Router"); int(got) != 16 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 16", "Router", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("Telephone"); int(got) != 32 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 32", "Telephone", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("DocsisCableDevice"); int(got) != 64 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 64", "DocsisCableDevice", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("StationOnly"); int(got) != 128 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 128", "StationOnly", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("CvlanComponent"); int(got) != 256 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 256", "CvlanComponent", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("SvlanComponent"); int(got) != 512 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 512", "SvlanComponent", got)
		}
		if got := LldpSystemCapabilitiesMapFromString("TwoPortMacRelay"); int(got) != 1024 {
			t.Errorf("LldpSystemCapabilitiesMapFromString(%q) = %v, want 1024", "TwoPortMacRelay", got)
		}
		_ = LldpSystemCapabilitiesMapFromString("__invalid__") // exercises default branch
	})
	t.Run("LogRecordMaskFromString", func(t *testing.T) {
		if got := LogRecordMaskFromString("None"); int(got) != 0 {
			t.Errorf("LogRecordMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := LogRecordMaskFromString("EventType"); int(got) != 1 {
			t.Errorf("LogRecordMaskFromString(%q) = %v, want 1", "EventType", got)
		}
		if got := LogRecordMaskFromString("SourceNode"); int(got) != 2 {
			t.Errorf("LogRecordMaskFromString(%q) = %v, want 2", "SourceNode", got)
		}
		if got := LogRecordMaskFromString("SourceName"); int(got) != 4 {
			t.Errorf("LogRecordMaskFromString(%q) = %v, want 4", "SourceName", got)
		}
		if got := LogRecordMaskFromString("TraceContext"); int(got) != 8 {
			t.Errorf("LogRecordMaskFromString(%q) = %v, want 8", "TraceContext", got)
		}
		if got := LogRecordMaskFromString("AdditionalData"); int(got) != 16 {
			t.Errorf("LogRecordMaskFromString(%q) = %v, want 16", "AdditionalData", got)
		}
		_ = LogRecordMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("IDTypeFromString", func(t *testing.T) {
		if got := IDTypeFromString("Numeric"); int(got) != 0 {
			t.Errorf("IDTypeFromString(%q) = %v, want 0", "Numeric", got)
		}
		if got := IDTypeFromString("String"); int(got) != 1 {
			t.Errorf("IDTypeFromString(%q) = %v, want 1", "String", got)
		}
		if got := IDTypeFromString("Guid"); int(got) != 2 {
			t.Errorf("IDTypeFromString(%q) = %v, want 2", "Guid", got)
		}
		if got := IDTypeFromString("Opaque"); int(got) != 3 {
			t.Errorf("IDTypeFromString(%q) = %v, want 3", "Opaque", got)
		}
		_ = IDTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("NodeClassFromString", func(t *testing.T) {
		if got := NodeClassFromString("Unspecified"); int(got) != 0 {
			t.Errorf("NodeClassFromString(%q) = %v, want 0", "Unspecified", got)
		}
		if got := NodeClassFromString("Object"); int(got) != 1 {
			t.Errorf("NodeClassFromString(%q) = %v, want 1", "Object", got)
		}
		if got := NodeClassFromString("Variable"); int(got) != 2 {
			t.Errorf("NodeClassFromString(%q) = %v, want 2", "Variable", got)
		}
		if got := NodeClassFromString("Method"); int(got) != 4 {
			t.Errorf("NodeClassFromString(%q) = %v, want 4", "Method", got)
		}
		if got := NodeClassFromString("ObjectType"); int(got) != 8 {
			t.Errorf("NodeClassFromString(%q) = %v, want 8", "ObjectType", got)
		}
		if got := NodeClassFromString("VariableType"); int(got) != 16 {
			t.Errorf("NodeClassFromString(%q) = %v, want 16", "VariableType", got)
		}
		if got := NodeClassFromString("ReferenceType"); int(got) != 32 {
			t.Errorf("NodeClassFromString(%q) = %v, want 32", "ReferenceType", got)
		}
		if got := NodeClassFromString("DataType"); int(got) != 64 {
			t.Errorf("NodeClassFromString(%q) = %v, want 64", "DataType", got)
		}
		if got := NodeClassFromString("View"); int(got) != 128 {
			t.Errorf("NodeClassFromString(%q) = %v, want 128", "View", got)
		}
		_ = NodeClassFromString("__invalid__") // exercises default branch
	})
	t.Run("PermissionTypeFromString", func(t *testing.T) {
		if got := PermissionTypeFromString("None"); int(got) != 0 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 0", "None", got)
		}
		if got := PermissionTypeFromString("Browse"); int(got) != 1 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 1", "Browse", got)
		}
		if got := PermissionTypeFromString("ReadRolePermissions"); int(got) != 2 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 2", "ReadRolePermissions", got)
		}
		if got := PermissionTypeFromString("WriteAttribute"); int(got) != 4 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 4", "WriteAttribute", got)
		}
		if got := PermissionTypeFromString("WriteRolePermissions"); int(got) != 8 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 8", "WriteRolePermissions", got)
		}
		if got := PermissionTypeFromString("WriteHistorizing"); int(got) != 16 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 16", "WriteHistorizing", got)
		}
		if got := PermissionTypeFromString("Read"); int(got) != 32 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 32", "Read", got)
		}
		if got := PermissionTypeFromString("Write"); int(got) != 64 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 64", "Write", got)
		}
		if got := PermissionTypeFromString("ReadHistory"); int(got) != 128 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 128", "ReadHistory", got)
		}
		if got := PermissionTypeFromString("InsertHistory"); int(got) != 256 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 256", "InsertHistory", got)
		}
		if got := PermissionTypeFromString("ModifyHistory"); int(got) != 512 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 512", "ModifyHistory", got)
		}
		if got := PermissionTypeFromString("DeleteHistory"); int(got) != 1024 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 1024", "DeleteHistory", got)
		}
		if got := PermissionTypeFromString("ReceiveEvents"); int(got) != 2048 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 2048", "ReceiveEvents", got)
		}
		if got := PermissionTypeFromString("Call"); int(got) != 4096 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 4096", "Call", got)
		}
		if got := PermissionTypeFromString("AddReference"); int(got) != 8192 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 8192", "AddReference", got)
		}
		if got := PermissionTypeFromString("RemoveReference"); int(got) != 16384 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 16384", "RemoveReference", got)
		}
		if got := PermissionTypeFromString("DeleteNode"); int(got) != 32768 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 32768", "DeleteNode", got)
		}
		if got := PermissionTypeFromString("AddNode"); int(got) != 65536 {
			t.Errorf("PermissionTypeFromString(%q) = %v, want 65536", "AddNode", got)
		}
		_ = PermissionTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("AccessLevelTypeFromString", func(t *testing.T) {
		if got := AccessLevelTypeFromString("None"); int(got) != 0 {
			t.Errorf("AccessLevelTypeFromString(%q) = %v, want 0", "None", got)
		}
		if got := AccessLevelTypeFromString("CurrentRead"); int(got) != 1 {
			t.Errorf("AccessLevelTypeFromString(%q) = %v, want 1", "CurrentRead", got)
		}
		if got := AccessLevelTypeFromString("CurrentWrite"); int(got) != 2 {
			t.Errorf("AccessLevelTypeFromString(%q) = %v, want 2", "CurrentWrite", got)
		}
		if got := AccessLevelTypeFromString("HistoryRead"); int(got) != 4 {
			t.Errorf("AccessLevelTypeFromString(%q) = %v, want 4", "HistoryRead", got)
		}
		if got := AccessLevelTypeFromString("HistoryWrite"); int(got) != 8 {
			t.Errorf("AccessLevelTypeFromString(%q) = %v, want 8", "HistoryWrite", got)
		}
		if got := AccessLevelTypeFromString("SemanticChange"); int(got) != 16 {
			t.Errorf("AccessLevelTypeFromString(%q) = %v, want 16", "SemanticChange", got)
		}
		if got := AccessLevelTypeFromString("StatusWrite"); int(got) != 32 {
			t.Errorf("AccessLevelTypeFromString(%q) = %v, want 32", "StatusWrite", got)
		}
		if got := AccessLevelTypeFromString("TimestampWrite"); int(got) != 64 {
			t.Errorf("AccessLevelTypeFromString(%q) = %v, want 64", "TimestampWrite", got)
		}
		_ = AccessLevelTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("AccessLevelExTypeFromString", func(t *testing.T) {
		if got := AccessLevelExTypeFromString("None"); int(got) != 0 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 0", "None", got)
		}
		if got := AccessLevelExTypeFromString("CurrentRead"); int(got) != 1 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 1", "CurrentRead", got)
		}
		if got := AccessLevelExTypeFromString("CurrentWrite"); int(got) != 2 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 2", "CurrentWrite", got)
		}
		if got := AccessLevelExTypeFromString("HistoryRead"); int(got) != 4 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 4", "HistoryRead", got)
		}
		if got := AccessLevelExTypeFromString("HistoryWrite"); int(got) != 8 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 8", "HistoryWrite", got)
		}
		if got := AccessLevelExTypeFromString("SemanticChange"); int(got) != 16 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 16", "SemanticChange", got)
		}
		if got := AccessLevelExTypeFromString("StatusWrite"); int(got) != 32 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 32", "StatusWrite", got)
		}
		if got := AccessLevelExTypeFromString("TimestampWrite"); int(got) != 64 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 64", "TimestampWrite", got)
		}
		if got := AccessLevelExTypeFromString("NonatomicRead"); int(got) != 256 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 256", "NonatomicRead", got)
		}
		if got := AccessLevelExTypeFromString("NonatomicWrite"); int(got) != 512 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 512", "NonatomicWrite", got)
		}
		if got := AccessLevelExTypeFromString("WriteFullArrayOnly"); int(got) != 1024 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 1024", "WriteFullArrayOnly", got)
		}
		if got := AccessLevelExTypeFromString("NoSubDataTypes"); int(got) != 2048 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 2048", "NoSubDataTypes", got)
		}
		if got := AccessLevelExTypeFromString("NonVolatile"); int(got) != 4096 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 4096", "NonVolatile", got)
		}
		if got := AccessLevelExTypeFromString("Constant"); int(got) != 8192 {
			t.Errorf("AccessLevelExTypeFromString(%q) = %v, want 8192", "Constant", got)
		}
		_ = AccessLevelExTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("EventNotifierTypeFromString", func(t *testing.T) {
		if got := EventNotifierTypeFromString("None"); int(got) != 0 {
			t.Errorf("EventNotifierTypeFromString(%q) = %v, want 0", "None", got)
		}
		if got := EventNotifierTypeFromString("SubscribeToEvents"); int(got) != 1 {
			t.Errorf("EventNotifierTypeFromString(%q) = %v, want 1", "SubscribeToEvents", got)
		}
		if got := EventNotifierTypeFromString("HistoryRead"); int(got) != 4 {
			t.Errorf("EventNotifierTypeFromString(%q) = %v, want 4", "HistoryRead", got)
		}
		if got := EventNotifierTypeFromString("HistoryWrite"); int(got) != 8 {
			t.Errorf("EventNotifierTypeFromString(%q) = %v, want 8", "HistoryWrite", got)
		}
		_ = EventNotifierTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("AccessRestrictionTypeFromString", func(t *testing.T) {
		if got := AccessRestrictionTypeFromString("None"); int(got) != 0 {
			t.Errorf("AccessRestrictionTypeFromString(%q) = %v, want 0", "None", got)
		}
		if got := AccessRestrictionTypeFromString("SigningRequired"); int(got) != 1 {
			t.Errorf("AccessRestrictionTypeFromString(%q) = %v, want 1", "SigningRequired", got)
		}
		if got := AccessRestrictionTypeFromString("EncryptionRequired"); int(got) != 2 {
			t.Errorf("AccessRestrictionTypeFromString(%q) = %v, want 2", "EncryptionRequired", got)
		}
		if got := AccessRestrictionTypeFromString("SessionRequired"); int(got) != 4 {
			t.Errorf("AccessRestrictionTypeFromString(%q) = %v, want 4", "SessionRequired", got)
		}
		if got := AccessRestrictionTypeFromString("ApplyRestrictionsToBrowse"); int(got) != 8 {
			t.Errorf("AccessRestrictionTypeFromString(%q) = %v, want 8", "ApplyRestrictionsToBrowse", got)
		}
		_ = AccessRestrictionTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("StructureTypeFromString", func(t *testing.T) {
		if got := StructureTypeFromString("Structure"); int(got) != 0 {
			t.Errorf("StructureTypeFromString(%q) = %v, want 0", "Structure", got)
		}
		if got := StructureTypeFromString("StructureWithOptionalFields"); int(got) != 1 {
			t.Errorf("StructureTypeFromString(%q) = %v, want 1", "StructureWithOptionalFields", got)
		}
		if got := StructureTypeFromString("Union"); int(got) != 2 {
			t.Errorf("StructureTypeFromString(%q) = %v, want 2", "Union", got)
		}
		if got := StructureTypeFromString("StructureWithSubtypedValues"); int(got) != 3 {
			t.Errorf("StructureTypeFromString(%q) = %v, want 3", "StructureWithSubtypedValues", got)
		}
		if got := StructureTypeFromString("UnionWithSubtypedValues"); int(got) != 4 {
			t.Errorf("StructureTypeFromString(%q) = %v, want 4", "UnionWithSubtypedValues", got)
		}
		_ = StructureTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("ApplicationTypeFromString", func(t *testing.T) {
		if got := ApplicationTypeFromString("Server"); int(got) != 0 {
			t.Errorf("ApplicationTypeFromString(%q) = %v, want 0", "Server", got)
		}
		if got := ApplicationTypeFromString("Client"); int(got) != 1 {
			t.Errorf("ApplicationTypeFromString(%q) = %v, want 1", "Client", got)
		}
		if got := ApplicationTypeFromString("ClientAndServer"); int(got) != 2 {
			t.Errorf("ApplicationTypeFromString(%q) = %v, want 2", "ClientAndServer", got)
		}
		if got := ApplicationTypeFromString("DiscoveryServer"); int(got) != 3 {
			t.Errorf("ApplicationTypeFromString(%q) = %v, want 3", "DiscoveryServer", got)
		}
		_ = ApplicationTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("MessageSecurityModeFromString", func(t *testing.T) {
		if got := MessageSecurityModeFromString("Invalid"); int(got) != 0 {
			t.Errorf("MessageSecurityModeFromString(%q) = %v, want 0", "Invalid", got)
		}
		if got := MessageSecurityModeFromString("None"); int(got) != 1 {
			t.Errorf("MessageSecurityModeFromString(%q) = %v, want 1", "None", got)
		}
		if got := MessageSecurityModeFromString("Sign"); int(got) != 2 {
			t.Errorf("MessageSecurityModeFromString(%q) = %v, want 2", "Sign", got)
		}
		if got := MessageSecurityModeFromString("SignAndEncrypt"); int(got) != 3 {
			t.Errorf("MessageSecurityModeFromString(%q) = %v, want 3", "SignAndEncrypt", got)
		}
		_ = MessageSecurityModeFromString("__invalid__") // exercises default branch
	})
	t.Run("UserTokenTypeFromString", func(t *testing.T) {
		if got := UserTokenTypeFromString("Anonymous"); int(got) != 0 {
			t.Errorf("UserTokenTypeFromString(%q) = %v, want 0", "Anonymous", got)
		}
		if got := UserTokenTypeFromString("UserName"); int(got) != 1 {
			t.Errorf("UserTokenTypeFromString(%q) = %v, want 1", "UserName", got)
		}
		if got := UserTokenTypeFromString("Certificate"); int(got) != 2 {
			t.Errorf("UserTokenTypeFromString(%q) = %v, want 2", "Certificate", got)
		}
		if got := UserTokenTypeFromString("IssuedToken"); int(got) != 3 {
			t.Errorf("UserTokenTypeFromString(%q) = %v, want 3", "IssuedToken", got)
		}
		_ = UserTokenTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("SecurityTokenRequestTypeFromString", func(t *testing.T) {
		if got := SecurityTokenRequestTypeFromString("Issue"); int(got) != 0 {
			t.Errorf("SecurityTokenRequestTypeFromString(%q) = %v, want 0", "Issue", got)
		}
		if got := SecurityTokenRequestTypeFromString("Renew"); int(got) != 1 {
			t.Errorf("SecurityTokenRequestTypeFromString(%q) = %v, want 1", "Renew", got)
		}
		_ = SecurityTokenRequestTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("NodeAttributesMaskFromString", func(t *testing.T) {
		if got := NodeAttributesMaskFromString("None"); int(got) != 0 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := NodeAttributesMaskFromString("AccessLevel"); int(got) != 1 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 1", "AccessLevel", got)
		}
		if got := NodeAttributesMaskFromString("ArrayDimensions"); int(got) != 2 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 2", "ArrayDimensions", got)
		}
		if got := NodeAttributesMaskFromString("BrowseName"); int(got) != 4 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 4", "BrowseName", got)
		}
		if got := NodeAttributesMaskFromString("ContainsNoLoops"); int(got) != 8 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 8", "ContainsNoLoops", got)
		}
		if got := NodeAttributesMaskFromString("DataType"); int(got) != 16 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 16", "DataType", got)
		}
		if got := NodeAttributesMaskFromString("Description"); int(got) != 32 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 32", "Description", got)
		}
		if got := NodeAttributesMaskFromString("DisplayName"); int(got) != 64 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 64", "DisplayName", got)
		}
		if got := NodeAttributesMaskFromString("EventNotifier"); int(got) != 128 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 128", "EventNotifier", got)
		}
		if got := NodeAttributesMaskFromString("Executable"); int(got) != 256 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 256", "Executable", got)
		}
		if got := NodeAttributesMaskFromString("Historizing"); int(got) != 512 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 512", "Historizing", got)
		}
		if got := NodeAttributesMaskFromString("InverseName"); int(got) != 1024 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 1024", "InverseName", got)
		}
		if got := NodeAttributesMaskFromString("IsAbstract"); int(got) != 2048 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 2048", "IsAbstract", got)
		}
		if got := NodeAttributesMaskFromString("MinimumSamplingInterval"); int(got) != 4096 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 4096", "MinimumSamplingInterval", got)
		}
		if got := NodeAttributesMaskFromString("NodeClass"); int(got) != 8192 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 8192", "NodeClass", got)
		}
		if got := NodeAttributesMaskFromString("NodeId"); int(got) != 16384 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 16384", "NodeId", got)
		}
		if got := NodeAttributesMaskFromString("Symmetric"); int(got) != 32768 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 32768", "Symmetric", got)
		}
		if got := NodeAttributesMaskFromString("UserAccessLevel"); int(got) != 65536 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 65536", "UserAccessLevel", got)
		}
		if got := NodeAttributesMaskFromString("UserExecutable"); int(got) != 131072 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 131072", "UserExecutable", got)
		}
		if got := NodeAttributesMaskFromString("UserWriteMask"); int(got) != 262144 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 262144", "UserWriteMask", got)
		}
		if got := NodeAttributesMaskFromString("ValueRank"); int(got) != 524288 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 524288", "ValueRank", got)
		}
		if got := NodeAttributesMaskFromString("WriteMask"); int(got) != 1048576 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 1048576", "WriteMask", got)
		}
		if got := NodeAttributesMaskFromString("Value"); int(got) != 2097152 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 2097152", "Value", got)
		}
		if got := NodeAttributesMaskFromString("DataTypeDefinition"); int(got) != 4194304 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 4194304", "DataTypeDefinition", got)
		}
		if got := NodeAttributesMaskFromString("RolePermissions"); int(got) != 8388608 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 8388608", "RolePermissions", got)
		}
		if got := NodeAttributesMaskFromString("AccessRestrictions"); int(got) != 16777216 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 16777216", "AccessRestrictions", got)
		}
		if got := NodeAttributesMaskFromString("All"); int(got) != 33554431 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 33554431", "All", got)
		}
		if got := NodeAttributesMaskFromString("BaseNode"); int(got) != 26501220 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 26501220", "BaseNode", got)
		}
		if got := NodeAttributesMaskFromString("Object"); int(got) != 26501348 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 26501348", "Object", got)
		}
		if got := NodeAttributesMaskFromString("ObjectType"); int(got) != 26503268 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 26503268", "ObjectType", got)
		}
		if got := NodeAttributesMaskFromString("Variable"); int(got) != 26571383 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 26571383", "Variable", got)
		}
		if got := NodeAttributesMaskFromString("VariableType"); int(got) != 28600438 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 28600438", "VariableType", got)
		}
		if got := NodeAttributesMaskFromString("Method"); int(got) != 26632548 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 26632548", "Method", got)
		}
		if got := NodeAttributesMaskFromString("ReferenceType"); int(got) != 26537060 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 26537060", "ReferenceType", got)
		}
		if got := NodeAttributesMaskFromString("View"); int(got) != 26501356 {
			t.Errorf("NodeAttributesMaskFromString(%q) = %v, want 26501356", "View", got)
		}
		_ = NodeAttributesMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("AttributeWriteMaskFromString", func(t *testing.T) {
		if got := AttributeWriteMaskFromString("None"); int(got) != 0 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := AttributeWriteMaskFromString("AccessLevel"); int(got) != 1 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 1", "AccessLevel", got)
		}
		if got := AttributeWriteMaskFromString("ArrayDimensions"); int(got) != 2 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 2", "ArrayDimensions", got)
		}
		if got := AttributeWriteMaskFromString("BrowseName"); int(got) != 4 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 4", "BrowseName", got)
		}
		if got := AttributeWriteMaskFromString("ContainsNoLoops"); int(got) != 8 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 8", "ContainsNoLoops", got)
		}
		if got := AttributeWriteMaskFromString("DataType"); int(got) != 16 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 16", "DataType", got)
		}
		if got := AttributeWriteMaskFromString("Description"); int(got) != 32 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 32", "Description", got)
		}
		if got := AttributeWriteMaskFromString("DisplayName"); int(got) != 64 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 64", "DisplayName", got)
		}
		if got := AttributeWriteMaskFromString("EventNotifier"); int(got) != 128 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 128", "EventNotifier", got)
		}
		if got := AttributeWriteMaskFromString("Executable"); int(got) != 256 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 256", "Executable", got)
		}
		if got := AttributeWriteMaskFromString("Historizing"); int(got) != 512 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 512", "Historizing", got)
		}
		if got := AttributeWriteMaskFromString("InverseName"); int(got) != 1024 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 1024", "InverseName", got)
		}
		if got := AttributeWriteMaskFromString("IsAbstract"); int(got) != 2048 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 2048", "IsAbstract", got)
		}
		if got := AttributeWriteMaskFromString("MinimumSamplingInterval"); int(got) != 4096 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 4096", "MinimumSamplingInterval", got)
		}
		if got := AttributeWriteMaskFromString("NodeClass"); int(got) != 8192 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 8192", "NodeClass", got)
		}
		if got := AttributeWriteMaskFromString("NodeId"); int(got) != 16384 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 16384", "NodeId", got)
		}
		if got := AttributeWriteMaskFromString("Symmetric"); int(got) != 32768 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 32768", "Symmetric", got)
		}
		if got := AttributeWriteMaskFromString("UserAccessLevel"); int(got) != 65536 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 65536", "UserAccessLevel", got)
		}
		if got := AttributeWriteMaskFromString("UserExecutable"); int(got) != 131072 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 131072", "UserExecutable", got)
		}
		if got := AttributeWriteMaskFromString("UserWriteMask"); int(got) != 262144 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 262144", "UserWriteMask", got)
		}
		if got := AttributeWriteMaskFromString("ValueRank"); int(got) != 524288 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 524288", "ValueRank", got)
		}
		if got := AttributeWriteMaskFromString("WriteMask"); int(got) != 1048576 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 1048576", "WriteMask", got)
		}
		if got := AttributeWriteMaskFromString("ValueForVariableType"); int(got) != 2097152 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 2097152", "ValueForVariableType", got)
		}
		if got := AttributeWriteMaskFromString("DataTypeDefinition"); int(got) != 4194304 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 4194304", "DataTypeDefinition", got)
		}
		if got := AttributeWriteMaskFromString("RolePermissions"); int(got) != 8388608 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 8388608", "RolePermissions", got)
		}
		if got := AttributeWriteMaskFromString("AccessRestrictions"); int(got) != 16777216 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 16777216", "AccessRestrictions", got)
		}
		if got := AttributeWriteMaskFromString("AccessLevelEx"); int(got) != 33554432 {
			t.Errorf("AttributeWriteMaskFromString(%q) = %v, want 33554432", "AccessLevelEx", got)
		}
		_ = AttributeWriteMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("BrowseDirectionFromString", func(t *testing.T) {
		if got := BrowseDirectionFromString("Forward"); int(got) != 0 {
			t.Errorf("BrowseDirectionFromString(%q) = %v, want 0", "Forward", got)
		}
		if got := BrowseDirectionFromString("Inverse"); int(got) != 1 {
			t.Errorf("BrowseDirectionFromString(%q) = %v, want 1", "Inverse", got)
		}
		if got := BrowseDirectionFromString("Both"); int(got) != 2 {
			t.Errorf("BrowseDirectionFromString(%q) = %v, want 2", "Both", got)
		}
		if got := BrowseDirectionFromString("Invalid"); int(got) != 3 {
			t.Errorf("BrowseDirectionFromString(%q) = %v, want 3", "Invalid", got)
		}
		_ = BrowseDirectionFromString("__invalid__") // exercises default branch
	})
	t.Run("BrowseResultMaskFromString", func(t *testing.T) {
		if got := BrowseResultMaskFromString("None"); int(got) != 0 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 0", "None", got)
		}
		if got := BrowseResultMaskFromString("ReferenceTypeId"); int(got) != 1 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 1", "ReferenceTypeId", got)
		}
		if got := BrowseResultMaskFromString("IsForward"); int(got) != 2 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 2", "IsForward", got)
		}
		if got := BrowseResultMaskFromString("NodeClass"); int(got) != 4 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 4", "NodeClass", got)
		}
		if got := BrowseResultMaskFromString("BrowseName"); int(got) != 8 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 8", "BrowseName", got)
		}
		if got := BrowseResultMaskFromString("DisplayName"); int(got) != 16 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 16", "DisplayName", got)
		}
		if got := BrowseResultMaskFromString("TypeDefinition"); int(got) != 32 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 32", "TypeDefinition", got)
		}
		if got := BrowseResultMaskFromString("All"); int(got) != 63 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 63", "All", got)
		}
		if got := BrowseResultMaskFromString("ReferenceTypeInfo"); int(got) != 3 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 3", "ReferenceTypeInfo", got)
		}
		if got := BrowseResultMaskFromString("TargetInfo"); int(got) != 60 {
			t.Errorf("BrowseResultMaskFromString(%q) = %v, want 60", "TargetInfo", got)
		}
		_ = BrowseResultMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("FilterOperatorFromString", func(t *testing.T) {
		if got := FilterOperatorFromString("Equals"); int(got) != 0 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 0", "Equals", got)
		}
		if got := FilterOperatorFromString("IsNull"); int(got) != 1 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 1", "IsNull", got)
		}
		if got := FilterOperatorFromString("GreaterThan"); int(got) != 2 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 2", "GreaterThan", got)
		}
		if got := FilterOperatorFromString("LessThan"); int(got) != 3 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 3", "LessThan", got)
		}
		if got := FilterOperatorFromString("GreaterThanOrEqual"); int(got) != 4 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 4", "GreaterThanOrEqual", got)
		}
		if got := FilterOperatorFromString("LessThanOrEqual"); int(got) != 5 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 5", "LessThanOrEqual", got)
		}
		if got := FilterOperatorFromString("Like"); int(got) != 6 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 6", "Like", got)
		}
		if got := FilterOperatorFromString("Not"); int(got) != 7 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 7", "Not", got)
		}
		if got := FilterOperatorFromString("Between"); int(got) != 8 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 8", "Between", got)
		}
		if got := FilterOperatorFromString("InList"); int(got) != 9 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 9", "InList", got)
		}
		if got := FilterOperatorFromString("And"); int(got) != 10 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 10", "And", got)
		}
		if got := FilterOperatorFromString("Or"); int(got) != 11 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 11", "Or", got)
		}
		if got := FilterOperatorFromString("Cast"); int(got) != 12 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 12", "Cast", got)
		}
		if got := FilterOperatorFromString("InView"); int(got) != 13 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 13", "InView", got)
		}
		if got := FilterOperatorFromString("OfType"); int(got) != 14 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 14", "OfType", got)
		}
		if got := FilterOperatorFromString("RelatedTo"); int(got) != 15 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 15", "RelatedTo", got)
		}
		if got := FilterOperatorFromString("BitwiseAnd"); int(got) != 16 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 16", "BitwiseAnd", got)
		}
		if got := FilterOperatorFromString("BitwiseOr"); int(got) != 17 {
			t.Errorf("FilterOperatorFromString(%q) = %v, want 17", "BitwiseOr", got)
		}
		_ = FilterOperatorFromString("__invalid__") // exercises default branch
	})
	t.Run("TimestampsToReturnFromString", func(t *testing.T) {
		if got := TimestampsToReturnFromString("Source"); int(got) != 0 {
			t.Errorf("TimestampsToReturnFromString(%q) = %v, want 0", "Source", got)
		}
		if got := TimestampsToReturnFromString("Server"); int(got) != 1 {
			t.Errorf("TimestampsToReturnFromString(%q) = %v, want 1", "Server", got)
		}
		if got := TimestampsToReturnFromString("Both"); int(got) != 2 {
			t.Errorf("TimestampsToReturnFromString(%q) = %v, want 2", "Both", got)
		}
		if got := TimestampsToReturnFromString("Neither"); int(got) != 3 {
			t.Errorf("TimestampsToReturnFromString(%q) = %v, want 3", "Neither", got)
		}
		if got := TimestampsToReturnFromString("Invalid"); int(got) != 4 {
			t.Errorf("TimestampsToReturnFromString(%q) = %v, want 4", "Invalid", got)
		}
		_ = TimestampsToReturnFromString("__invalid__") // exercises default branch
	})
	t.Run("SortOrderTypeFromString", func(t *testing.T) {
		if got := SortOrderTypeFromString("Ascending"); int(got) != 0 {
			t.Errorf("SortOrderTypeFromString(%q) = %v, want 0", "Ascending", got)
		}
		if got := SortOrderTypeFromString("Descending"); int(got) != 1 {
			t.Errorf("SortOrderTypeFromString(%q) = %v, want 1", "Descending", got)
		}
		_ = SortOrderTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("HistoryUpdateTypeFromString", func(t *testing.T) {
		if got := HistoryUpdateTypeFromString("Insert"); int(got) != 1 {
			t.Errorf("HistoryUpdateTypeFromString(%q) = %v, want 1", "Insert", got)
		}
		if got := HistoryUpdateTypeFromString("Replace"); int(got) != 2 {
			t.Errorf("HistoryUpdateTypeFromString(%q) = %v, want 2", "Replace", got)
		}
		if got := HistoryUpdateTypeFromString("Update"); int(got) != 3 {
			t.Errorf("HistoryUpdateTypeFromString(%q) = %v, want 3", "Update", got)
		}
		if got := HistoryUpdateTypeFromString("Delete"); int(got) != 4 {
			t.Errorf("HistoryUpdateTypeFromString(%q) = %v, want 4", "Delete", got)
		}
		_ = HistoryUpdateTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("PerformUpdateTypeFromString", func(t *testing.T) {
		if got := PerformUpdateTypeFromString("Insert"); int(got) != 1 {
			t.Errorf("PerformUpdateTypeFromString(%q) = %v, want 1", "Insert", got)
		}
		if got := PerformUpdateTypeFromString("Replace"); int(got) != 2 {
			t.Errorf("PerformUpdateTypeFromString(%q) = %v, want 2", "Replace", got)
		}
		if got := PerformUpdateTypeFromString("Update"); int(got) != 3 {
			t.Errorf("PerformUpdateTypeFromString(%q) = %v, want 3", "Update", got)
		}
		if got := PerformUpdateTypeFromString("Remove"); int(got) != 4 {
			t.Errorf("PerformUpdateTypeFromString(%q) = %v, want 4", "Remove", got)
		}
		_ = PerformUpdateTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("MonitoringModeFromString", func(t *testing.T) {
		if got := MonitoringModeFromString("Disabled"); int(got) != 0 {
			t.Errorf("MonitoringModeFromString(%q) = %v, want 0", "Disabled", got)
		}
		if got := MonitoringModeFromString("Sampling"); int(got) != 1 {
			t.Errorf("MonitoringModeFromString(%q) = %v, want 1", "Sampling", got)
		}
		if got := MonitoringModeFromString("Reporting"); int(got) != 2 {
			t.Errorf("MonitoringModeFromString(%q) = %v, want 2", "Reporting", got)
		}
		_ = MonitoringModeFromString("__invalid__") // exercises default branch
	})
	t.Run("DataChangeTriggerFromString", func(t *testing.T) {
		if got := DataChangeTriggerFromString("Status"); int(got) != 0 {
			t.Errorf("DataChangeTriggerFromString(%q) = %v, want 0", "Status", got)
		}
		if got := DataChangeTriggerFromString("StatusValue"); int(got) != 1 {
			t.Errorf("DataChangeTriggerFromString(%q) = %v, want 1", "StatusValue", got)
		}
		if got := DataChangeTriggerFromString("StatusValueTimestamp"); int(got) != 2 {
			t.Errorf("DataChangeTriggerFromString(%q) = %v, want 2", "StatusValueTimestamp", got)
		}
		_ = DataChangeTriggerFromString("__invalid__") // exercises default branch
	})
	t.Run("DeadbandTypeFromString", func(t *testing.T) {
		if got := DeadbandTypeFromString("None"); int(got) != 0 {
			t.Errorf("DeadbandTypeFromString(%q) = %v, want 0", "None", got)
		}
		if got := DeadbandTypeFromString("Absolute"); int(got) != 1 {
			t.Errorf("DeadbandTypeFromString(%q) = %v, want 1", "Absolute", got)
		}
		if got := DeadbandTypeFromString("Percent"); int(got) != 2 {
			t.Errorf("DeadbandTypeFromString(%q) = %v, want 2", "Percent", got)
		}
		_ = DeadbandTypeFromString("__invalid__") // exercises default branch
	})
	t.Run("RedundancySupportFromString", func(t *testing.T) {
		if got := RedundancySupportFromString("None"); int(got) != 0 {
			t.Errorf("RedundancySupportFromString(%q) = %v, want 0", "None", got)
		}
		if got := RedundancySupportFromString("Cold"); int(got) != 1 {
			t.Errorf("RedundancySupportFromString(%q) = %v, want 1", "Cold", got)
		}
		if got := RedundancySupportFromString("Warm"); int(got) != 2 {
			t.Errorf("RedundancySupportFromString(%q) = %v, want 2", "Warm", got)
		}
		if got := RedundancySupportFromString("Hot"); int(got) != 3 {
			t.Errorf("RedundancySupportFromString(%q) = %v, want 3", "Hot", got)
		}
		if got := RedundancySupportFromString("Transparent"); int(got) != 4 {
			t.Errorf("RedundancySupportFromString(%q) = %v, want 4", "Transparent", got)
		}
		if got := RedundancySupportFromString("HotAndMirrored"); int(got) != 5 {
			t.Errorf("RedundancySupportFromString(%q) = %v, want 5", "HotAndMirrored", got)
		}
		_ = RedundancySupportFromString("__invalid__") // exercises default branch
	})
	t.Run("ServerStateFromString", func(t *testing.T) {
		if got := ServerStateFromString("Running"); int(got) != 0 {
			t.Errorf("ServerStateFromString(%q) = %v, want 0", "Running", got)
		}
		if got := ServerStateFromString("Failed"); int(got) != 1 {
			t.Errorf("ServerStateFromString(%q) = %v, want 1", "Failed", got)
		}
		if got := ServerStateFromString("NoConfiguration"); int(got) != 2 {
			t.Errorf("ServerStateFromString(%q) = %v, want 2", "NoConfiguration", got)
		}
		if got := ServerStateFromString("Suspended"); int(got) != 3 {
			t.Errorf("ServerStateFromString(%q) = %v, want 3", "Suspended", got)
		}
		if got := ServerStateFromString("Shutdown"); int(got) != 4 {
			t.Errorf("ServerStateFromString(%q) = %v, want 4", "Shutdown", got)
		}
		if got := ServerStateFromString("Test"); int(got) != 5 {
			t.Errorf("ServerStateFromString(%q) = %v, want 5", "Test", got)
		}
		if got := ServerStateFromString("CommunicationFault"); int(got) != 6 {
			t.Errorf("ServerStateFromString(%q) = %v, want 6", "CommunicationFault", got)
		}
		if got := ServerStateFromString("Unknown"); int(got) != 7 {
			t.Errorf("ServerStateFromString(%q) = %v, want 7", "Unknown", got)
		}
		_ = ServerStateFromString("__invalid__") // exercises default branch
	})
	t.Run("ModelChangeStructureVerbMaskFromString", func(t *testing.T) {
		if got := ModelChangeStructureVerbMaskFromString("NodeAdded"); int(got) != 1 {
			t.Errorf("ModelChangeStructureVerbMaskFromString(%q) = %v, want 1", "NodeAdded", got)
		}
		if got := ModelChangeStructureVerbMaskFromString("NodeDeleted"); int(got) != 2 {
			t.Errorf("ModelChangeStructureVerbMaskFromString(%q) = %v, want 2", "NodeDeleted", got)
		}
		if got := ModelChangeStructureVerbMaskFromString("ReferenceAdded"); int(got) != 4 {
			t.Errorf("ModelChangeStructureVerbMaskFromString(%q) = %v, want 4", "ReferenceAdded", got)
		}
		if got := ModelChangeStructureVerbMaskFromString("ReferenceDeleted"); int(got) != 8 {
			t.Errorf("ModelChangeStructureVerbMaskFromString(%q) = %v, want 8", "ReferenceDeleted", got)
		}
		if got := ModelChangeStructureVerbMaskFromString("DataTypeChanged"); int(got) != 16 {
			t.Errorf("ModelChangeStructureVerbMaskFromString(%q) = %v, want 16", "DataTypeChanged", got)
		}
		_ = ModelChangeStructureVerbMaskFromString("__invalid__") // exercises default branch
	})
	t.Run("AxisScaleEnumerationFromString", func(t *testing.T) {
		if got := AxisScaleEnumerationFromString("Linear"); int(got) != 0 {
			t.Errorf("AxisScaleEnumerationFromString(%q) = %v, want 0", "Linear", got)
		}
		if got := AxisScaleEnumerationFromString("Log"); int(got) != 1 {
			t.Errorf("AxisScaleEnumerationFromString(%q) = %v, want 1", "Log", got)
		}
		if got := AxisScaleEnumerationFromString("Ln"); int(got) != 2 {
			t.Errorf("AxisScaleEnumerationFromString(%q) = %v, want 2", "Ln", got)
		}
		_ = AxisScaleEnumerationFromString("__invalid__") // exercises default branch
	})
	t.Run("ExceptionDeviationFormatFromString", func(t *testing.T) {
		if got := ExceptionDeviationFormatFromString("AbsoluteValue"); int(got) != 0 {
			t.Errorf("ExceptionDeviationFormatFromString(%q) = %v, want 0", "AbsoluteValue", got)
		}
		if got := ExceptionDeviationFormatFromString("PercentOfValue"); int(got) != 1 {
			t.Errorf("ExceptionDeviationFormatFromString(%q) = %v, want 1", "PercentOfValue", got)
		}
		if got := ExceptionDeviationFormatFromString("PercentOfRange"); int(got) != 2 {
			t.Errorf("ExceptionDeviationFormatFromString(%q) = %v, want 2", "PercentOfRange", got)
		}
		if got := ExceptionDeviationFormatFromString("PercentOfEURange"); int(got) != 3 {
			t.Errorf("ExceptionDeviationFormatFromString(%q) = %v, want 3", "PercentOfEURange", got)
		}
		if got := ExceptionDeviationFormatFromString("Unknown"); int(got) != 4 {
			t.Errorf("ExceptionDeviationFormatFromString(%q) = %v, want 4", "Unknown", got)
		}
		_ = ExceptionDeviationFormatFromString("__invalid__") // exercises default branch
	})
}
