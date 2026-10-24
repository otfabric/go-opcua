// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"testing"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

func FuzzDecode(f *testing.F) {
	seeds := []string{
		`{"MessageId":"ABCDEFGH","MessageType":"ua-data","PublisherId":"65535","DataSetClassId":"00000001-0002-0003-0000-000000000000","Messages":[{"DataSetWriterId":12345,"SequenceNumber":4711,"MetaDataVersion":{"MajorVersion":42,"MinorVersion":7},"Timestamp":"1601-01-13T20:38:31.1111111Z","Status":{"Code":12345,"Symbol":"Good"},"MessageType":"ua-keyframe","Payload":{"Field1":{"UaType":7,"Value":27}}}]}`,
		`{"MessageType":"ua-data","Messages":{"DataSetWriterId":1,"Payload":{"a":{"UaType":6,"Value":1,"Status":{"Code":1073741824},"SourceTimestamp":"1970-01-15T06:56:07Z"}}}}`,
		`[{"DataSetWriterId":5,"MessageType":"ua-keepalive"},{"x":1,"y":[1,2],"z":{"Type":6,"Body":3}}]`,
		`{"a":1,"b":"x","c":true,"d":null,"e":{"UaTypeId":"i=14593","MajorVersion":1}}`,
		`{"MessageId":"m","MessageType":"ua-metadata","PublisherId":"7","DataSetWriterId":9,"MetaData":{"Name":"ds","Fields":[{"Name":"a","BuiltInType":6}]}}`,
		`{"MessageType":"ua-status","Status":2,"IsCyclic":true}`,
		`{"MessageType":"ua-endpoints"}`,
		`{"MessageId":"m","MessageType":"ua-action-metadata","PublisherId":"7","DataSetWriterId":100,"Timestamp":"2024-01-01T00:00:00Z","ActionTargets":[{"ActionTargetId":1,"Name":"Add"}],"Request":{"Name":"Calc","Fields":[{"Name":"A","BuiltInType":6}]},"Response":{"Name":"Calc"},"ActionMethods":[{"ObjectId":"ns=1;s=Calc","MethodId":"ns=1;s=Add"}]}`,
		`{"MessageId":"m","MessageType":"ua-action-responder","PublisherId":"7","Timestamp":"2024-01-01T00:00:00Z","Connection":{"Name":"c","WriterGroups":[{"Name":"g","DataSetWriters":[{"Name":"w","DataSetWriterId":100}]}]}}`,
		`{"MessageId":"m","MessageType":"ua-action-request","PublisherId":"7","Timestamp":"2024-01-01T00:00:00Z","ResponseAddress":"r","CorrelationData":"AQID","RequestorId":"req","TimeoutHint":1500,"Messages":[{"DataSetWriterId":3,"ActionTargetId":1,"RequestId":9,"ActionState":1,"Payload":{"a":{"UaType":6,"Value":1}}}]}`,
		`{"MessageId":"m","MessageType":"ua-action-response","PublisherId":"7","Timestamp":"2024-01-01T00:00:00Z","RequestorId":"req","Messages":{"DataSetWriterId":3,"ActionTargetId":1,"Status":{"Code":2150891520},"MessageType":"ua-action-response","RequestId":9,"ActionState":"Done_2","Payload":{}}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{
		{Name: "a", BuiltInType: 6, ValueRank: -1},
		{Name: "e", BuiltInType: 22, DataType: ua.NewNumericNodeID(0, 14593), ValueRank: -1},
		{Name: "x", BuiltInType: 24, ValueRank: -1},
	}}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeAny(b, &DecodeOptions{MaxFields: 64, MaxDataSetMessages: 64})
		nm, err := Decode(b, &DecodeOptions{
			MetaData: func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType { return md },
		})
		if err != nil {
			return
		}
		if out, err := Encode(nm, nil); err == nil {
			if _, err := Decode(out, nil); err != nil {
				t.Fatalf("re-decode of %s: %v", out, err)
			}
		}
	})
}
