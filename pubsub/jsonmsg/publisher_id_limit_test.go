// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
)

// TestStringPublisherIDBound: a String PublisherId, in the header of a
// NetworkMessage, of a DataSetMessage, of a metadata, status or action
// message, and a String RequestorId are at most MaxCorrelationData bytes
// long, the bound of the UADP decoder; a longer one is a decode error.
func TestStringPublisherIDBound(t *testing.T) {
	t.Parallel()
	require.Equal(t, 4096, MaxCorrelationData)

	// Each decoder takes the PublisherId as JSON text.
	decoders := map[string]func(id string) (message.PublisherID, error){
		"NetworkMessage": func(id string) (message.PublisherID, error) {
			nm, err := Decode(fmt.Appendf(nil, `{"MessageType":"ua-data","PublisherId":%s,"Messages":[]}`, id), nil)
			if err != nil {
				return message.PublisherID{}, err
			}
			return nm.PublisherID, nil
		},
		"DataSetMessage": func(id string) (message.PublisherID, error) {
			nm, err := Decode(fmt.Appendf(nil, `{"MessageType":"ua-data","Messages":[{"DataSetWriterId":1,"PublisherId":%s,"Payload":{}}]}`, id), nil)
			if err != nil {
				return message.PublisherID{}, err
			}
			require.Len(t, nm.Messages, 1)
			return *nm.Messages[0].PublisherID, nil
		},
		"metadata": func(id string) (message.PublisherID, error) {
			m, err := DecodeMetaData(fmt.Appendf(nil, `{"MessageType":"ua-metadata","PublisherId":%s,"MetaData":{}}`, id), nil)
			if err != nil {
				return message.PublisherID{}, err
			}
			return m.PublisherID, nil
		},
		"status": func(id string) (message.PublisherID, error) {
			m, err := DecodeStatus(fmt.Appendf(nil, `{"MessageType":"ua-status","PublisherId":%s,"Status":2}`, id), nil)
			if err != nil {
				return message.PublisherID{}, err
			}
			return m.PublisherID, nil
		},
		"action request": func(id string) (message.PublisherID, error) {
			nm, err := Decode(fmt.Appendf(nil, `{"MessageType":"ua-action-request","PublisherId":%s,"Messages":[{"DataSetWriterId":1,"ActionTargetId":1,"RequestId":1,"ActionState":1,"Payload":{}}]}`, id), nil)
			if err != nil {
				return message.PublisherID{}, err
			}
			return nm.PublisherID, nil
		},
		"RequestorId": func(id string) (message.PublisherID, error) {
			nm, err := Decode(fmt.Appendf(nil, `{"MessageType":"ua-action-request","PublisherId":"p","RequestorId":%s,"Messages":[{"DataSetWriterId":1,"ActionTargetId":1,"RequestId":1,"ActionState":1,"Payload":{}}]}`, id), nil)
			if err != nil {
				return message.PublisherID{}, err
			}
			require.NotNil(t, nm.Action)
			require.NotNil(t, nm.Action.RequestorID)
			return *nm.Action.RequestorID, nil
		},
	}
	for name, decode := range decoders {
		for _, n := range []int{1, 2, 4095, 4096, 4097, 8192, 1 << 20} {
			id := strings.Repeat("p", n)
			got, err := decode(strconv.Quote(id))
			if n > MaxCorrelationData {
				require.ErrorIs(t, err, ErrDecode, "%s: %d bytes", name, n)
				require.ErrorContains(t, err, fmt.Sprintf("of %d bytes", n), "%s", name)
				continue
			}
			require.NoError(t, err, "%s: %d bytes", name, n)
			require.Equal(t, message.StringPublisherID(id), got, "%s: %d bytes", name, n)
		}
		// The bound is on the decoded string, in bytes: an escape counts as
		// the bytes it stands for, a rune as its UTF-8 bytes.
		esc := `\` + "u0070" // the JSON escape of "p"
		got, err := decode(`"` + strings.Repeat(esc, MaxCorrelationData) + `"`)
		require.NoError(t, err, "%s: escaped", name)
		require.Equal(t, message.StringPublisherID(strings.Repeat("p", MaxCorrelationData)), got, "%s", name)
		_, err = decode(`"` + strings.Repeat(esc, MaxCorrelationData+1) + `"`)
		require.ErrorIs(t, err, ErrDecode, "%s: escaped, one byte over", name)
		twoBytes := strings.Repeat(string(rune(0xe9)), MaxCorrelationData/2) // two bytes in UTF-8
		got, err = decode(strconv.Quote(twoBytes))
		require.NoError(t, err, "%s: UTF-8", name)
		require.Equal(t, message.StringPublisherID(twoBytes), got, "%s", name)
		_, err = decode(strconv.Quote(twoBytes + "x"))
		require.ErrorIs(t, err, ErrDecode, "%s: UTF-8, one byte over", name)
		// A numeric PublisherId in a string is a number, not a string.
		got, err = decode(`"4096"`)
		require.NoError(t, err, "%s", name)
		require.Equal(t, message.NewPublisherID(message.PublisherIDUInt64, 4096), got, "%s", name)
		// An empty string stays a String PublisherId.
		got, err = decode(`""`)
		require.NoError(t, err, "%s", name)
		require.Equal(t, message.StringPublisherID(""), got, "%s", name)
	}
}
