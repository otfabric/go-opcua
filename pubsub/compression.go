// SPDX-License-Identifier: MIT

package pubsub

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/otfabric/go-opcua/pubsub/transport"
	mqtttransport "github.com/otfabric/go-opcua/pubsub/transport/mqtt"
	"github.com/otfabric/go-opcua/ua"
)

// DefaultJSONDecompressionLimit is the largest JSON NetworkMessage a
// subscriber decompresses from a gzip compressed message by default (see
// [WithJSONDecompressionLimit]).
const DefaultJSONDecompressionLimit = 16 << 20

// errCompressedJSON is the decode error of a gzip compressed JSON message
// (Part 14 §7.3.4.9.1) that cannot be decompressed.
var errCompressedJSON = errors.New("pubsub: gzip compressed JSON message")

// gzipMagic starts every gzip stream (RFC 1952 §2.3.1). A UADP
// NetworkMessage cannot start with it: its version would be 15.
var gzipMagic = []byte{0x1f, 0x8b}

// SetJSONCompression sets the compression of the JSON NetworkMessages a
// connection sends (the go-opcua connection property JsonCompression):
// "gzip" sends them gzip compressed with the Content Type
// application/json+gzip of Part 14 §7.3.4.9.1, "none" uncompressed. Part 14
// defines the compressed content type for MQTT 5.0 only: Validate accepts
// the property on MQTT connections with the JSON mapping, and a connection
// that runs MQTT 3.1.1 (MqttVersion BestAvailable with a broker without
// 5.0) sends uncompressed. Subscribers decompress whatever compressed
// messages they receive, whatever this setting.
func SetJSONCompression(c *ua.PubSubConnectionDataType, compression string) *ua.PubSubConnectionDataType {
	return SetConnectionProperty(c, mqtttransport.PropJSONCompression, compression)
}

// jsonCompressed reports whether a connection compresses its JSON
// messages.
func jsonCompressed(cfg *ua.PubSubConnectionDataType) bool {
	return strings.TrimSpace(connectionProperties(cfg.ConnectionProperties)[mqtttransport.PropJSONCompression]) == mqtttransport.CompressionGzip
}

// versioned is a transport connection that reports its MQTT version.
type versioned interface{ Version() string }

// body returns the payload and content type with which a NetworkMessage of
// encoding enc goes out over tc: a JSON message of a connection that
// compresses is gzip compressed when tc can say so (MQTT 5.0).
func (p *PubSub) body(c *connection, tc transport.Connection, enc encoding, b []byte) ([]byte, string, error) {
	if enc != encJSON || !c.gzip {
		return b, enc.contentType(), nil
	}
	if v, ok := tc.(versioned); !ok || v.Version() != mqtttransport.Version5 {
		if !c.gzipWarned.Swap(true) {
			p.log.Warn("pubsub: the connection runs MQTT 3.1.1, which cannot carry a content type: JSON messages are sent uncompressed", "connection", c.name)
		}
		return b, enc.contentType(), nil
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), transport.ContentTypeJSONGzip, nil
}

// isGzipped reports whether a received message is gzip compressed JSON: its
// content type says so or, without one (MQTT 3.1.1 subscribers get no
// content type), it starts like a gzip stream.
func isGzipped(m *transport.Message) bool {
	ct, _, _ := strings.Cut(m.ContentType, ";")
	switch strings.ToLower(strings.TrimSpace(ct)) {
	case transport.ContentTypeJSONGzip:
		return true
	case "":
		return bytes.HasPrefix(m.Payload, gzipMagic)
	}
	return false
}

// decompress returns a received gzip compressed JSON message as the JSON
// message it holds. A message that does not decompress, or that holds more
// than limit bytes, is an error.
func decompress(m *transport.Message, limit int) (*transport.Message, error) {
	zr, err := gzip.NewReader(bytes.NewReader(m.Payload))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCompressedJSON, err)
	}
	b, err := io.ReadAll(io.LimitReader(zr, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCompressedJSON, err)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes decompressed", errCompressedJSON, limit)
	}
	out := *m
	out.Payload = b
	out.ContentType = transport.ContentTypeJSON
	return &out, nil
}
