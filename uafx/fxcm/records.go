// SPDX-License-Identifier: MIT

package fxcm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"strconv"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// The records of a Manager in the "cm" namespace of its store (design
// docs/design/uafx-persistent-connections.md §6.1). Keys:
//
//	counters        the generation and RunID counters
//	set/<set>       a ConnectionConfigurationSet as committed
//	ep/<endpoint>   an EndpointRecord with its evidence
//	run/<run>       the journal of a run (§6.3)
//	next/<run>      the set a Replace in run <run> switches to
//	call/<run>/<n>  the intent of an EstablishConnections or CloseConnections
//
// <set> and <endpoint> are hex SHA-256 prefixes of the SetKey and of the
// place of the endpoint (server, FunctionalEntity, Name), so that a key
// never depends on a namespace index; <run> is the RunID in hex. Remote
// NodeIds are stored with the NamespaceArray of their server (§6.1:
// "Remote NodeIds are stored URI-qualified").

// recordSchema is the schema of the records (fxstore.DomainOptions.Schema).
const recordSchema = 1

// recordFormat is the first byte of every value.
const recordFormat = 1

// storeNS are the namespace indexes a set is encoded with in its record.
// Part of schema 1: they never change.
var storeNS = uafx.NamespaceIndexes{Data: 2, AC: 3, CM: 4}

// Run phases (§6.3).
const (
	phasePlanned          uint8 = 1
	phaseExecuting        uint8 = 2
	phaseRollbackRequired uint8 = 3
	phaseReconciling      uint8 = 4
)

// Call kinds of an intent.
const (
	callEstablish uint8 = 1
	callClose     uint8 = 2
)

// countersRecord holds the counters a crash must not reset (§3.5: never
// reused).
type countersRecord struct {
	Generation uint64
	RunID      uint64
}

// setRecord is a committed ConnectionConfigurationSet (§6.1).
type setRecord struct {
	Folder  []string
	Name    string
	Version uint32
	// Generation is the Manager-wide counter of the change that committed
	// it, never reset (a Replace resets Version, not the generation).
	Generation uint64
	// Fingerprint is the SHA-256 of Conf.
	Fingerprint []byte
	// Conf is the set, encoded with storeNS.
	Conf []byte
}

// epStored is an EndpointRecord with its evidence (§6.1, §6.5).
type epStored struct {
	Folder     []string
	SetName    string
	Connection string
	Endpoint   int64

	Address           string
	SecurityMode      uint32
	SecurityPolicyURI string
	ServerURIConf     string // ServerAddress.ServerURI

	// Namespaces is the NamespaceArray of the server the NodeIds are of.
	Namespaces       []string
	ServerURI        string // the ApplicationUri of the server
	ACNode           *ua.NodeID
	FunctionalEntity *ua.NodeID
	Name             string
	NodeID           *ua.NodeID

	Class        int64
	Run          uint64
	Version      uint32
	ClosePending bool
	// Generation and Fingerprint are the set configuration the endpoint
	// was made from.
	Generation  uint64
	Fingerprint []byte
}

// runRecord is the journal of a run (§6.3).
type runRecord struct {
	Run             uint64
	Folder          []string
	SetName         string
	Generation      uint64
	Action          int32
	RollbackOnError bool
	Phase           uint8
	// Next is the generation a set change switches to (Replace, Remove,
	// Update), 0 for a Process.
	Next uint64
	// Endpoints are the keys of the endpoint records the run made or
	// closed so far.
	Endpoints []string
}

// callRecord is the intent of a call (§6.3): what the proof of an unknown
// outcome needs after a restart.
type callRecord struct {
	Run     uint64
	Folder  []string
	SetName string
	Kind    uint8

	Address           string
	SecurityMode      uint32
	SecurityPolicyURI string
	ServerURIConf     string
	Namespaces        []string
	ServerURI         string
	ACNode            *ua.NodeID

	// Names and FunctionalEntities of an establish, one per endpoint
	// configuration; Request is the input arguments as sent (the
	// ConnectionEndpointParameters among them), encoded with the indexes
	// of Namespaces.
	Names              []string
	FunctionalEntities []*ua.NodeID
	Request            []byte
	// AbsentBefore is, per Name, that the browse before the call found no
	// endpoint of it; Preconfigured the NodeId it takes otherwise.
	AbsentBefore  []bool
	Preconfigured []*ua.NodeID
	// Nodes and Remove of a close.
	Nodes  []*ua.NodeID
	Remove bool

	Generation  uint64
	Fingerprint []byte
}

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// errRecord reports a record that does not decode.
var errRecord = errors.New("fxcm: corrupt record")

// encodeRecord encodes v as a value: the format byte and v as one
// length-prefixed, checksummed part.
func encodeRecord(v any) ([]byte, error) {
	b, err := ua.Encode(v)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: too large", errRecord)
	}
	out := make([]byte, 0, 1+4+len(b)+4)
	out = append(out, recordFormat)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(b)))
	out = append(out, b...)
	return binary.LittleEndian.AppendUint32(out, crc32.Checksum(b, crcTable)), nil
}

// decodeRecord decodes a value of encodeRecord into v.
func decodeRecord(val []byte, v any) error {
	if len(val) < 9 || val[0] != recordFormat {
		return fmt.Errorf("%w: format", errRecord)
	}
	n := binary.LittleEndian.Uint32(val[1:])
	if uint64(n) != uint64(len(val)-9) {
		return fmt.Errorf("%w: length", errRecord)
	}
	part := val[5 : 5+n]
	if crc32.Checksum(part, crcTable) != binary.LittleEndian.Uint32(val[5+n:]) {
		return fmt.Errorf("%w: checksum", errRecord)
	}
	return decodeExact(part, v)
}

// decodeExact decodes b into v and fails unless it takes all of b.
func decodeExact(b []byte, v any) (err error) {
	defer func() {
		// The reflective decoder must not take the Manager down on a
		// hostile record.
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", errRecord, r)
		}
	}()
	n, err := ua.Decode(b, v)
	if err != nil {
		return fmt.Errorf("%w: %w", errRecord, err)
	}
	if n != len(b) {
		return fmt.Errorf("%w: %d bytes left", errRecord, len(b)-n)
	}
	return nil
}

// encodeConf encodes conf for its record and returns its fingerprint.
func encodeConf(conf *uafx.ConnectionConfigurationSetConf) (b, fingerprint []byte, err error) {
	eo, err := uafx.EncodeStructure(withRawLinks(conf), storeNS)
	if err != nil {
		return nil, nil, err
	}
	b, err = ua.Encode(eo)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", uafx.ErrCodec, err)
	}
	sum := sha256.Sum256(b)
	return b, sum[:], nil
}

// decodeConf decodes the Conf of a set record.
func decodeConf(b []byte) (*uafx.ConnectionConfigurationSetConf, error) {
	eo := new(ua.ExtensionObject)
	if err := decodeExact(b, eo); err != nil {
		return nil, err
	}
	s, err := uafx.DecodeStructure(eo, storeNS)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errRecord, err)
	}
	conf, ok := s.(*uafx.ConnectionConfigurationSetConf)
	if !ok {
		return nil, fmt.Errorf("%w: not a ConnectionConfigurationSetConf", errRecord)
	}
	return conf, nil
}

// hashKey returns a key segment for the parts.
func hashKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(p))))
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func setStoreKey(k SetKey) string { return "set/" + hashKey(keyString(k)) }

// epStoreKey is the key of the record of an endpoint, by the key of the
// set's map (recordKey) and the set: the same place in two sets is two
// records.
func epStoreKey(set SetKey, rk string) string { return "ep/" + hashKey(keyString(set), rk) }

func runStoreKey(id RunID) string { return "run/" + strconv.FormatUint(uint64(id), 16) }

func nextStoreKey(id RunID) string { return "next/" + strconv.FormatUint(uint64(id), 16) }

func callStoreKey(id RunID, n int) string {
	return "call/" + strconv.FormatUint(uint64(id), 16) + "/" + strconv.Itoa(n)
}

// orNil returns nil for a null NodeId: a nil NodeId of a record decodes as
// the null NodeId (Part 6 §5.2.2.9).
func orNil(n *ua.NodeID) *ua.NodeID {
	if n == nil {
		return nil
	}
	switch n.Type() {
	case ua.NodeIDTypeTwoByte, ua.NodeIDTypeFourByte, ua.NodeIDTypeNumeric:
		if n.Namespace() == 0 && n.IntID() == 0 {
			return nil
		}
	default:
	}
	return n
}
