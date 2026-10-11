// SPDX-License-Identifier: MIT

package mdns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Resource record types used by DNS-SD over mDNS.
const (
	TypeA    uint16 = 1
	TypePTR  uint16 = 12
	TypeTXT  uint16 = 16
	TypeAAAA uint16 = 28
	TypeSRV  uint16 = 33
	TypeANY  uint16 = 255
)

// Classes. The top bit of the class field has a different meaning in mDNS: in
// a question it asks for a unicast response, in a record it is the cache-flush
// bit (RFC 6762 §5.4, §10.2).
const (
	ClassIN  uint16 = 1
	ClassANY uint16 = 255

	classMask uint16 = 0x7fff
	classTop  uint16 = 0x8000
)

// Limits of the wire format (RFC 1035 §2.3.4) and of this implementation.
const (
	maxLabelLen = 63
	maxNameLen  = 255
	headerLen   = 12

	// MaxPacketSize is the largest mDNS message accepted or produced
	// (RFC 6762 §17: 9000 bytes including the IP and UDP headers).
	MaxPacketSize = 9000

	// maxPointerHops bounds the compression pointers followed for one name.
	// Pointers must also point strictly backwards, so the bound is never
	// reached by a well-formed message; it is a second line of defence.
	maxPointerHops = 32
)

// Errors returned by [Unpack] and [Message.Pack].
var (
	ErrShortMessage = errors.New("mdns: message too short")
	ErrBadName      = errors.New("mdns: malformed domain name")
	ErrBadPointer   = errors.New("mdns: bad compression pointer")
	ErrBadRData     = errors.New("mdns: malformed resource data")
	ErrTooLarge     = errors.New("mdns: message too large")
	ErrTooMany      = errors.New("mdns: record count exceeds message size")
)

// Question is one entry of the question section.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
	// Unicast is the QU bit: the querier would accept a unicast response.
	Unicast bool
}

// SRV is the data of a service location record (RFC 2782).
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// Record is one resource record. Which of the data fields is set depends on
// Type: PTR for TypePTR, SRV for TypeSRV, TXT for TypeTXT, Addr for TypeA and
// TypeAAAA, Data (the raw resource data) for every other type.
type Record struct {
	Name  string
	Type  uint16
	Class uint16
	// CacheFlush is the cache-flush bit of a record in a response.
	CacheFlush bool
	TTL        uint32

	PTR  string
	SRV  *SRV
	TXT  []string
	Addr netip.Addr
	Data []byte
}

// Message is a DNS message as used by mDNS.
type Message struct {
	ID            uint16
	Response      bool
	Opcode        uint8
	Authoritative bool
	Truncated     bool
	RCode         uint8

	Questions   []Question
	Answers     []Record
	Authorities []Record
	Additionals []Record
}

// Domain names are handled in their presentation format: labels separated by
// dots, with a trailing dot. A dot or backslash inside a label is escaped with
// a backslash and a byte outside the printable ASCII range is written as a
// three-digit decimal escape (RFC 1035 §5.1), so that instance names such as
// "Line 3.Press" survive a round trip.

// EscapeLabel returns the presentation form of a single label.
func EscapeLabel(label string) string {
	var b strings.Builder
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c == '.' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// SplitName splits a name in presentation format into its unescaped labels.
// The root name "." has no labels.
func SplitName(name string) ([]string, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: empty name", ErrBadName)
	}
	if name == "." {
		return nil, nil
	}
	var (
		labels []string
		cur    []byte
		total  = 1 // the terminating root label
	)
	flush := func() error {
		if len(cur) == 0 {
			return fmt.Errorf("%w: empty label in %q", ErrBadName, name)
		}
		if len(cur) > maxLabelLen {
			return fmt.Errorf("%w: label longer than %d bytes in %q", ErrBadName, maxLabelLen, name)
		}
		total += 1 + len(cur)
		if total > maxNameLen {
			return fmt.Errorf("%w: name longer than %d bytes", ErrBadName, maxNameLen)
		}
		labels = append(labels, string(cur))
		cur = cur[:0]
		return nil
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch c {
		case '.':
			if err := flush(); err != nil {
				return nil, err
			}
		case '\\':
			if i+1 >= len(name) {
				return nil, fmt.Errorf("%w: dangling escape in %q", ErrBadName, name)
			}
			if d := name[i+1]; d >= '0' && d <= '9' {
				if i+3 >= len(name) || !isDigit(name[i+2]) || !isDigit(name[i+3]) {
					return nil, fmt.Errorf("%w: bad decimal escape in %q", ErrBadName, name)
				}
				v := int(d-'0')*100 + int(name[i+2]-'0')*10 + int(name[i+3]-'0')
				if v > 255 {
					return nil, fmt.Errorf("%w: bad decimal escape in %q", ErrBadName, name)
				}
				cur = append(cur, byte(v))
				i += 3
			} else {
				cur = append(cur, d)
				i++
			}
		default:
			cur = append(cur, c)
		}
	}
	// A name without the trailing dot is accepted and treated as absolute.
	if len(cur) > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	return labels, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// JoinLabels builds the presentation form of a name from unescaped labels.
func JoinLabels(labels ...string) string {
	if len(labels) == 0 {
		return "."
	}
	var b strings.Builder
	for _, l := range labels {
		b.WriteString(EscapeLabel(l))
		b.WriteByte('.')
	}
	return b.String()
}

// EqualNames reports whether two names in presentation format are the same
// name. DNS names compare case-insensitively for ASCII letters.
func EqualNames(a, b string) bool {
	return canonicalName(a) == canonicalName(b)
}

// canonicalName is the map key of a name: ASCII lower case, trailing dot.
func canonicalName(name string) string {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return asciiLower(name)
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if c := b[j]; c >= 'A' && c <= 'Z' {
					b[j] = c + 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// --- decoding -----------------------------------------------------------------

// Unpack decodes a DNS message. It never panics, whatever the input: every
// length and offset is checked against the message, compression pointers must
// point backwards, and the record counts of the header are validated against
// the bytes that are actually there before anything is allocated.
func Unpack(b []byte) (*Message, error) {
	if len(b) < headerLen {
		return nil, ErrShortMessage
	}
	if len(b) > 0xffff {
		return nil, ErrTooLarge
	}
	flags := binary.BigEndian.Uint16(b[2:])
	m := &Message{
		ID:            binary.BigEndian.Uint16(b[0:]),
		Response:      flags&0x8000 != 0,
		Opcode:        uint8(flags>>11) & 0xf,
		Authoritative: flags&0x0400 != 0,
		Truncated:     flags&0x0200 != 0,
		RCode:         uint8(flags & 0xf),
	}
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	ns := int(binary.BigEndian.Uint16(b[8:]))
	ar := int(binary.BigEndian.Uint16(b[10:]))

	// A question takes at least 5 bytes (root name, type, class) and a
	// record at least 11 (root name, type, class, TTL, length).
	if qd*5+(an+ns+ar)*11 > len(b)-headerLen {
		return nil, ErrTooMany
	}

	off := headerLen
	var err error
	if qd > 0 {
		m.Questions = make([]Question, 0, qd)
	}
	for i := 0; i < qd; i++ {
		var q Question
		if q, off, err = unpackQuestion(b, off); err != nil {
			return nil, err
		}
		m.Questions = append(m.Questions, q)
	}
	if m.Answers, off, err = unpackRecords(b, off, an); err != nil {
		return nil, err
	}
	if m.Authorities, off, err = unpackRecords(b, off, ns); err != nil {
		return nil, err
	}
	if m.Additionals, _, err = unpackRecords(b, off, ar); err != nil {
		return nil, err
	}
	return m, nil
}

func unpackQuestion(b []byte, off int) (Question, int, error) {
	name, off, err := unpackName(b, off)
	if err != nil {
		return Question{}, 0, err
	}
	if len(b)-off < 4 {
		return Question{}, 0, ErrShortMessage
	}
	class := binary.BigEndian.Uint16(b[off+2:])
	return Question{
		Name:    name,
		Type:    binary.BigEndian.Uint16(b[off:]),
		Class:   class & classMask,
		Unicast: class&classTop != 0,
	}, off + 4, nil
}

func unpackRecords(b []byte, off, n int) ([]Record, int, error) {
	if n == 0 {
		return nil, off, nil
	}
	out := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		r, next, err := unpackRecord(b, off)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
		off = next
	}
	return out, off, nil
}

func unpackRecord(b []byte, off int) (Record, int, error) {
	name, off, err := unpackName(b, off)
	if err != nil {
		return Record{}, 0, err
	}
	if len(b)-off < 10 {
		return Record{}, 0, ErrShortMessage
	}
	class := binary.BigEndian.Uint16(b[off+2:])
	r := Record{
		Name:       name,
		Type:       binary.BigEndian.Uint16(b[off:]),
		Class:      class & classMask,
		CacheFlush: class&classTop != 0,
		TTL:        binary.BigEndian.Uint32(b[off+4:]),
	}
	rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
	off += 10
	if len(b)-off < rdlen {
		return Record{}, 0, ErrShortMessage
	}
	end := off + rdlen

	switch r.Type {
	case TypePTR:
		target, next, err := unpackName(b[:end], off)
		if err != nil {
			return Record{}, 0, err
		}
		if next != end {
			return Record{}, 0, fmt.Errorf("%w: trailing bytes after PTR target", ErrBadRData)
		}
		r.PTR = target
	case TypeSRV:
		if rdlen < 7 {
			return Record{}, 0, fmt.Errorf("%w: SRV shorter than 7 bytes", ErrBadRData)
		}
		target, next, err := unpackName(b[:end], off+6)
		if err != nil {
			return Record{}, 0, err
		}
		if next != end {
			return Record{}, 0, fmt.Errorf("%w: trailing bytes after SRV target", ErrBadRData)
		}
		r.SRV = &SRV{
			Priority: binary.BigEndian.Uint16(b[off:]),
			Weight:   binary.BigEndian.Uint16(b[off+2:]),
			Port:     binary.BigEndian.Uint16(b[off+4:]),
			Target:   target,
		}
	case TypeTXT:
		txt, err := unpackTXT(b[off:end])
		if err != nil {
			return Record{}, 0, err
		}
		r.TXT = txt
	case TypeA:
		if rdlen != 4 {
			return Record{}, 0, fmt.Errorf("%w: A record of %d bytes", ErrBadRData, rdlen)
		}
		r.Addr = netip.AddrFrom4([4]byte(b[off:end]))
	case TypeAAAA:
		if rdlen != 16 {
			return Record{}, 0, fmt.Errorf("%w: AAAA record of %d bytes", ErrBadRData, rdlen)
		}
		r.Addr = netip.AddrFrom16([16]byte(b[off:end]))
	default:
		if rdlen > 0 {
			r.Data = append([]byte(nil), b[off:end]...)
		}
	}
	return r, end, nil
}

// unpackTXT splits TXT resource data into its strings. An empty record and
// the conventional single empty string (RFC 6763 §6.1) both yield no strings.
func unpackTXT(b []byte) ([]string, error) {
	var out []string
	for len(b) > 0 {
		n := int(b[0])
		if len(b)-1 < n {
			return nil, fmt.Errorf("%w: TXT string exceeds the record", ErrBadRData)
		}
		if n > 0 {
			out = append(out, string(b[1:1+n]))
		}
		b = b[1+n:]
	}
	return out, nil
}

// unpackName reads the domain name at off and returns it in presentation
// format together with the offset of the first byte after it.
func unpackName(b []byte, off int) (string, int, error) {
	var (
		sb      strings.Builder
		next    = -1 // offset after the name in the original position
		hops    int
		wireLen = 1
		limit   = off // a pointer must point before the start of the name part it is in
	)
	for {
		if off >= len(b) {
			return "", 0, ErrShortMessage
		}
		c := int(b[off])
		switch c & 0xc0 {
		case 0x00:
			if c == 0 {
				if next < 0 {
					next = off + 1
				}
				if sb.Len() == 0 {
					return ".", next, nil
				}
				return sb.String(), next, nil
			}
			if off+1+c > len(b) {
				return "", 0, ErrShortMessage
			}
			wireLen += 1 + c
			if wireLen > maxNameLen {
				return "", 0, fmt.Errorf("%w: longer than %d bytes", ErrBadName, maxNameLen)
			}
			sb.WriteString(EscapeLabel(string(b[off+1 : off+1+c])))
			sb.WriteByte('.')
			off += 1 + c
		case 0xc0:
			if off+2 > len(b) {
				return "", 0, ErrShortMessage
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			if ptr >= limit {
				return "", 0, fmt.Errorf("%w: forward or self reference", ErrBadPointer)
			}
			if hops++; hops > maxPointerHops {
				return "", 0, fmt.Errorf("%w: too many indirections", ErrBadPointer)
			}
			if next < 0 {
				next = off + 2
			}
			off, limit = ptr, ptr
		default:
			return "", 0, fmt.Errorf("%w: reserved label type 0x%02x", ErrBadName, c&0xc0)
		}
	}
}

// --- encoding -----------------------------------------------------------------

// Pack encodes the message. Domain names are compressed (RFC 1035 §4.1.4;
// RFC 6762 §18.14 allows it in the SRV target as well).
func (m *Message) Pack() ([]byte, error) {
	if len(m.Questions) > 0xffff || len(m.Answers) > 0xffff ||
		len(m.Authorities) > 0xffff || len(m.Additionals) > 0xffff {
		return nil, ErrTooMany
	}
	p := &packer{buf: make([]byte, headerLen, 512), names: map[string]int{}}
	binary.BigEndian.PutUint16(p.buf[0:], m.ID)
	var flags uint16
	if m.Response {
		flags |= 0x8000
	}
	flags |= uint16(m.Opcode&0xf) << 11
	if m.Authoritative {
		flags |= 0x0400
	}
	if m.Truncated {
		flags |= 0x0200
	}
	flags |= uint16(m.RCode & 0xf)
	binary.BigEndian.PutUint16(p.buf[2:], flags)
	binary.BigEndian.PutUint16(p.buf[4:], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(p.buf[6:], uint16(len(m.Answers)))
	binary.BigEndian.PutUint16(p.buf[8:], uint16(len(m.Authorities)))
	binary.BigEndian.PutUint16(p.buf[10:], uint16(len(m.Additionals)))

	for i := range m.Questions {
		q := &m.Questions[i]
		if err := p.name(q.Name); err != nil {
			return nil, err
		}
		class := q.Class & classMask
		if q.Unicast {
			class |= classTop
		}
		p.buf = binary.BigEndian.AppendUint16(p.buf, q.Type)
		p.buf = binary.BigEndian.AppendUint16(p.buf, class)
	}
	for _, section := range [][]Record{m.Answers, m.Authorities, m.Additionals} {
		for i := range section {
			if err := p.record(&section[i]); err != nil {
				return nil, err
			}
		}
	}
	if len(p.buf) > 0xffff {
		return nil, ErrTooLarge
	}
	return p.buf, nil
}

type packer struct {
	buf   []byte
	names map[string]int // name suffix -> offset
}

func (p *packer) name(name string) error {
	labels, err := SplitName(name)
	if err != nil {
		return err
	}
	for i := range labels {
		key := JoinLabels(labels[i:]...) // case-sensitive: compression must not change the spelling
		if off, ok := p.names[key]; ok {
			p.buf = binary.BigEndian.AppendUint16(p.buf, 0xc000|uint16(off))
			return nil
		}
		if off := len(p.buf); off < 0x4000 {
			p.names[key] = off
		}
		p.buf = append(p.buf, byte(len(labels[i])))
		p.buf = append(p.buf, labels[i]...)
	}
	p.buf = append(p.buf, 0)
	return nil
}

func (p *packer) record(r *Record) error {
	if err := p.name(r.Name); err != nil {
		return err
	}
	class := r.Class & classMask
	if r.CacheFlush {
		class |= classTop
	}
	p.buf = binary.BigEndian.AppendUint16(p.buf, r.Type)
	p.buf = binary.BigEndian.AppendUint16(p.buf, class)
	p.buf = binary.BigEndian.AppendUint32(p.buf, r.TTL)
	lenOff := len(p.buf)
	p.buf = append(p.buf, 0, 0)

	switch r.Type {
	case TypePTR:
		if err := p.name(r.PTR); err != nil {
			return err
		}
	case TypeSRV:
		if r.SRV == nil {
			return fmt.Errorf("%w: SRV record without data", ErrBadRData)
		}
		p.buf = binary.BigEndian.AppendUint16(p.buf, r.SRV.Priority)
		p.buf = binary.BigEndian.AppendUint16(p.buf, r.SRV.Weight)
		p.buf = binary.BigEndian.AppendUint16(p.buf, r.SRV.Port)
		if err := p.name(r.SRV.Target); err != nil {
			return err
		}
	case TypeTXT:
		if len(r.TXT) == 0 {
			p.buf = append(p.buf, 0) // RFC 6763 §6.1: a single empty string
		}
		for _, s := range r.TXT {
			if len(s) == 0 {
				continue
			}
			if len(s) > 255 {
				return fmt.Errorf("%w: TXT string longer than 255 bytes", ErrBadRData)
			}
			p.buf = append(p.buf, byte(len(s)))
			p.buf = append(p.buf, s...)
		}
	case TypeA:
		if !r.Addr.Is4() {
			return fmt.Errorf("%w: A record needs an IPv4 address", ErrBadRData)
		}
		a := r.Addr.As4()
		p.buf = append(p.buf, a[:]...)
	case TypeAAAA:
		if !r.Addr.Is6() {
			return fmt.Errorf("%w: AAAA record needs an IPv6 address", ErrBadRData)
		}
		a := r.Addr.As16()
		p.buf = append(p.buf, a[:]...)
	default:
		p.buf = append(p.buf, r.Data...)
	}

	rdlen := len(p.buf) - lenOff - 2
	if rdlen > 0xffff {
		return fmt.Errorf("%w: resource data longer than 65535 bytes", ErrBadRData)
	}
	binary.BigEndian.PutUint16(p.buf[lenOff:], uint16(rdlen))
	return nil
}
