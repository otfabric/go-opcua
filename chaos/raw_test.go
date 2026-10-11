// SPDX-License-Identifier: MIT

package chaos

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/otfabric/go-opcua/uacp"
)

// rawFrame builds a UACP frame with an arbitrary (possibly lying) size field.
func rawFrame(msgType string, chunk byte, size uint32, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	copy(b, msgType)
	b[3] = chunk
	binary.LittleEndian.PutUint32(b[4:], size)
	return append(b, body...)
}

// frame builds a well-formed UACP frame around body.
func frame(msgType string, chunk byte, body []byte) []byte {
	return rawFrame(msgType, chunk, uint32(8+len(body)), body)
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

// secureHeader returns the bytes that follow the UACP header of a symmetric
// MSG/CLO chunk: SecureChannelID, TokenID, SequenceNumber, RequestID.
func secureHeader(channelID, tokenID, seq, reqID uint32) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], channelID)
	binary.LittleEndian.PutUint32(b[4:], tokenID)
	binary.LittleEndian.PutUint32(b[8:], seq)
	binary.LittleEndian.PutUint32(b[12:], reqID)
	return b
}

// rawAttack describes one hostile byte stream sent from a bare TCP
// connection. If handshake is set the stream is preceded by a valid HEL/ACK
// exchange so that it reaches the secure channel layer.
type rawAttack struct {
	name      string
	handshake bool
	payload   func(rng *rand.Rand) [][]byte
}

var rawAttacks = []rawAttack{
	{name: "random bytes instead of HEL", payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{randBytes(rng, 1+rng.Intn(512))}
	}},
	{name: "HEL with a huge size field", payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{rawFrame("HEL", 'F', 0xFFFFFFFF, randBytes(rng, 64))}
	}},
	{name: "HEL with size below the header size", payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{rawFrame("HEL", 'F', uint32(rng.Intn(8)), nil)}
	}},
	{name: "truncated HEL", payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{rawFrame("HEL", 'F', 200, randBytes(rng, rng.Intn(100)))}
	}},
	{name: "HEL with garbage body", payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("HEL", 'F', randBytes(rng, 20+rng.Intn(200)))}
	}},
	{name: "unknown message type", payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("XYZ", 'F', randBytes(rng, 32))}
	}},
	{name: "ERR instead of HEL", payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("ERR", 'F', randBytes(rng, 8))}
	}},
	{name: "MSG before OPN", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("MSG", 'F', append(secureHeader(rng.Uint32(), rng.Uint32(), 1, 1), randBytes(rng, 64)...))}
	}},
	{name: "OPN with garbage body", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("OPN", 'F', randBytes(rng, 16+rng.Intn(300)))}
	}},
	{name: "OPN truncated mid-message", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{rawFrame("OPN", 'F', 4000, randBytes(rng, 100))}
	}},
	{name: "oversized chunk after handshake", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{rawFrame("MSG", 'F', 0x7FFFFFFF, randBytes(rng, 1024))}
	}},
	{name: "undersized chunk after handshake", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{rawFrame("MSG", 'F', 4, nil)}
	}},
	{name: "chunk shorter than the secure channel header", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		// 8..11 bytes: a valid transport frame, too short for the 12 byte
		// secure conversation header
		return [][]byte{frame("MSG", 'F', randBytes(rng, rng.Intn(4)))}
	}},
	{name: "OPN shorter than the secure channel header", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("OPN", 'F', randBytes(rng, rng.Intn(4)))}
	}},
	{name: "chunk with a header only", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("MSG", 'F', randBytes(rng, 4+rng.Intn(12)))}
	}},
	{name: "endless intermediate chunks", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		var out [][]byte
		for i := 0; i < 600; i++ {
			out = append(out, frame("MSG", 'C', append(secureHeader(1, 1, uint32(i+1), 7), randBytes(rng, 32)...)))
		}
		return out
	}},
	{name: "abort chunk for an unknown request", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("MSG", 'A', append(secureHeader(rng.Uint32(), 1, 1, rng.Uint32()), randBytes(rng, 8)...))}
	}},
	{name: "invalid chunk type", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("MSG", 'Z', append(secureHeader(1, 1, 1, 1), randBytes(rng, 16)...))}
	}},
	{name: "CLO without a channel", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("CLO", 'F', append(secureHeader(rng.Uint32(), rng.Uint32(), 1, 1), randBytes(rng, 16)...))}
	}},
	{name: "second HEL after handshake", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{frame("HEL", 'F', randBytes(rng, 40))}
	}},
	{name: "random bytes after handshake", handshake: true, payload: func(rng *rand.Rand) [][]byte {
		return [][]byte{randBytes(rng, 1+rng.Intn(4096))}
	}},
}

// sendRawAttack opens a bare TCP connection to addr, plays the attack and
// waits (bounded) for the server's reaction. It reports whether the server
// closed the connection.
func sendRawAttack(addr, endpoint string, a rawAttack, rng *rand.Rand, linger time.Duration) (closedByServer bool, err error) {
	var conn net.Conn
	if a.handshake {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := uacp.Dial(ctx, endpoint)
		if err != nil {
			return false, fmt.Errorf("handshake: %w", err)
		}
		conn = c
	} else {
		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return false, fmt.Errorf("dial: %w", err)
		}
		conn = c
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	for _, b := range a.payload(rng) {
		if _, err := conn.Write(b); err != nil {
			// the server already hung up on us: that is a valid reaction
			return true, nil
		}
	}

	// Drain whatever the server answers (typically an ERR message) until it
	// closes the connection or we lose patience.
	_ = conn.SetReadDeadline(time.Now().Add(linger))
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return false, nil
			}
			return true, nil
		}
	}
}
