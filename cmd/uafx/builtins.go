// SPDX-License-Identifier: MIT

package main

// wire is how the generated code encodes a value of namespace 0.
type wire int

const (
	wBool    wire = iota // Boolean, as Buffer.WriteBool
	wUint8               // Byte
	wUint16              // UInt16
	wInt32               // Int32
	wUint32              // UInt32
	wFloat64             // Double and its subtypes
	wString              // String and its subtypes
	wPtr                 // a pointer type of package ua, encoded as package ua encodes it
	wValue               // a value type of package ua (StatusCode, enumerations), likewise
	wEO                  // an abstract DataType: an ExtensionObject (Part 6 §5.2.2.15)
)

type builtin struct {
	name   string // the BrowseName
	goType string
	wire   wire
}

// builtins are the DataTypes of namespace 0 the UAFX NodeSets use. A
// DataType that is not here fails the generator: add it when a new version
// of the NodeSets uses it.
var builtins = map[uint32]builtin{
	1:     {"Boolean", "bool", wBool},
	3:     {"Byte", "uint8", wUint8},
	5:     {"UInt16", "uint16", wUint16},
	6:     {"Int32", "int32", wInt32},
	7:     {"UInt32", "uint32", wUint32},
	12:    {"String", "string", wString},
	14:    {"Guid", "*ua.GUID", wPtr},
	15:    {"ByteString", "[]byte", wValue},
	17:    {"NodeId", "*ua.NodeID", wPtr},
	19:    {"StatusCode", "ua.StatusCode", wValue},
	20:    {"QualifiedName", "*ua.QualifiedName", wPtr},
	21:    {"LocalizedText", "*ua.LocalizedText", wPtr},
	22:    {"Structure", "*ua.ExtensionObject", wPtr},
	24:    {"BaseDataType", "*ua.Variant", wPtr},
	290:   {"Duration", "float64", wFloat64},
	302:   {"MessageSecurityMode", "ua.MessageSecurityMode", wValue},
	540:   {"RelativePath", "*ua.RelativePath", wPtr},
	14533: {"KeyValuePair", "*ua.KeyValuePair", wPtr},
	14593: {"ConfigurationVersionDataType", "*ua.ConfigurationVersionDataType", wPtr},
	15502: {"NetworkAddressDataType", "*ua.ExtensionObject", wEO},
	15578: {"PublishedDataSetDataType", "*ua.PublishedDataSetDataType", wPtr},
	23600: {"StandaloneSubscribedDataSetDataType", "*ua.StandaloneSubscribedDataSetDataType", wPtr},
	23601: {"SecurityGroupDataType", "*ua.SecurityGroupDataType", wPtr},
	23602: {"PubSubConfiguration2DataType", "*ua.PubSubConfiguration2DataType", wPtr},
	23604: {"TransmitQosDataType", "*ua.ExtensionObject", wEO},
	23608: {"ReceiveQosDataType", "*ua.ExtensionObject", wEO},
	23751: {"UriString", "string", wString},
	24105: {"PortableQualifiedName", "*ua.PortableQualifiedName", wPtr},
	24106: {"PortableNodeId", "*ua.PortableNodeID", wPtr},
	25270: {"PubSubKeyPushTargetDataType", "*ua.PubSubKeyPushTargetDataType", wPtr},
	25519: {"PubSubConfigurationRefDataType", "*ua.PubSubConfigurationRefDataType", wPtr},
	25520: {"PubSubConfigurationValueDataType", "*ua.PubSubConfigurationValueDataType", wPtr},
}

// optionSetBases are the unsigned integers an OptionSet DataType can be a
// subtype of (Part 3 §8.40), by NodeId, with their Go type.
var optionSetBases = map[uint32]string{3: "uint8", 5: "uint16", 7: "uint32"}
