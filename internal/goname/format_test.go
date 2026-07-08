// SPDX-License-Identifier: MIT

package goname

import "testing"

func TestFormat(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		// Standard underscore hierarchy names.
		{"ServerType_ServerArray", "ServerTypeServerArray"},
		{"WellKnownRole_Anonymous", "WellKnownRoleAnonymous"},
		{"GoodEdited_DependentValueChanged", "GoodEditedDependentValueChanged"},
		{"PriorityValue_PCP", "PriorityValuePCP"},
		{"Server_ServerStatus_CurrentTime", "ServerServerStatusCurrentTime"},
		{"AggregateFunction_Average", "AggregateFunctionAverage"},
		{"ModellingRule_Mandatory", "ModellingRuleMandatory"},

		// Encoding suffixes.
		{"FindServersRequest_Encoding_DefaultBinary", "FindServersRequestEncodingDefaultBinary"},
		{"DataTypeDefinition_Encoding_DefaultBinary", "DataTypeDefinitionEncodingDefaultBinary"},

		// Initialisms.
		{"NodeId", "NodeID"},
		{"NamespaceUri", "NamespaceURI"},
		{"ServerUri", "ServerURI"},
		{"SessionId", "SessionID"},
		{"GuidValue", "GUIDValue"},
		{"XmlElement", "XMLElement"},
		{"JsonDataSetWriterMessage", "JSONDataSetWriterMessage"},
		{"TcpTransport", "TCPTransport"},
		{"DefaultHttpsGroup", "DefaultHTTPSGroup"},
		{"HttpTransport", "HTTPTransport"},
		{"UadpNetworkMessage", "UADPNetworkMessage"},
		{"EndpointUrl", "EndpointURL"},

		// Initialism + underscore combo.
		{"OpcUa_BinarySchema", "OpcUaBinarySchema"},
		{"OpcUa_XmlSchema", "OpcUaXMLSchema"},

		// Fix: IDentity should not be mangled.
		{"UserIdentityToken", "UserIdentityToken"},
		{"AnonymousIdentityToken", "AnonymousIdentityToken"},

		// Fix: IDentifier should not be mangled.
		{"NumericIdentifier", "NumericIdentifier"},

		// Fix: IDle should not be mangled.
		{"IdleState", "IdleState"},

		// Already correct CamelCase (no underscores).
		{"FindServersRequest", "FindServersRequest"},
		{"ReadRequest", "ReadRequest"},
		{"WriteResponse", "WriteResponse"},

		// Repeated underscores.
		{"A__B", "AB"},
		{"Foo___Bar", "FooBar"},

		// Leading/trailing underscores.
		{"_Foo", "Foo"},
		{"Foo_", "Foo"},
		{"_Foo_Bar_", "FooBar"},

		// Digits preserved.
		{"Base64", "Base64"},
		{"SHA256", "SHA256"},
		{"X509Certificate", "X509Certificate"},

		// Single-segment names.
		{"Server", "Server"},
		{"Boolean", "Boolean"},

		// QualityOfService abbreviation.
		{"QualityOfServiceDatagramPubSub", "QoSDatagramPubSub"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := Format(tt.in)
			if got != tt.want {
				t.Errorf("Format(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsValidIdent(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"Foo", true},
		{"fooBar", true},
		{"_private", true},
		{"x509", true},
		{"", false},
		{"123abc", false},
		{"func", false},
		{"type", false},
		{"return", false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := IsValidIdent(tt.in)
			if got != tt.want {
				t.Errorf("IsValidIdent(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
