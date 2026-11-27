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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// The records of a Manager in the "cm" namespace of its store (design
// docs/design/uafx-persistent-connections.md §6.1). Keys:
//
//	counters        the generation and RunID counters
//	set/<set>       a ConnectionConfigurationSet as committed
//	ep/<endpoint>   an EndpointRecord with its evidence (§6.1, §6.5)
//	run/<run>       the journal of a run (§6.3)
//	tx/<run>        the set change a Replace, Remove or complete Update
//	                in run <run> makes after its closes (§6.2)
//	call/<run>/<n>  the intent of an EstablishConnections or CloseConnections
//
// <set> and <endpoint> are hex SHA-256 prefixes of the SetKey and of the
// place of the endpoint (server, FunctionalEntity by namespace URI, Name),
// so that a key never depends on a namespace index; <run> is the RunID in
// hex. Remote NodeIds are stored URI-qualified (qualifiedID; §6.1: "Remote
// NodeIds are stored URI-qualified"), with the NamespaceArray of their
// server, which the encoded arguments of an intent need.

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

// qualifiedID is a remote NodeId with the URI of its namespace instead of
// its index (§6.1). ID is the identifier in the NodeId string form without
// a namespace ("i=5", "s=fe"); an index outside the NamespaceArray it was
// qualified with keeps it ("ns=9;i=5") and an empty NamespaceURI.
type qualifiedID struct {
	NamespaceURI string
	ID           string
}

// qualify returns n with the URI of its namespace in nsa; nil for nil.
func qualify(n *ua.NodeID, nsa []string) *qualifiedID {
	if n == nil {
		return nil
	}
	idx := int(n.Namespace())
	if idx >= len(nsa) {
		return &qualifiedID{ID: n.String()}
	}
	c := *n
	_ = c.SetNamespace(0) // namespace 0 is valid for every NodeId type
	return &qualifiedID{NamespaceURI: nsa[idx], ID: c.String()}
}

// String is the namespace-independent form of q, for keys.
func (q *qualifiedID) String() string {
	if q == nil {
		return ""
	}
	return "nsu=" + q.NamespaceURI + ";" + q.ID
}

// unqualify returns the NodeId of q on a server with the NamespaceArray
// nsa; nil for nil.
func unqualify(q *qualifiedID, nsa []string) (*ua.NodeID, error) {
	if q == nil || q.ID == "" && q.NamespaceURI == "" {
		return nil, nil
	}
	if q.NamespaceURI == "" {
		return ua.ParseNodeID(q.ID)
	}
	idx := slices.Index(nsa, q.NamespaceURI)
	if idx < 0 || idx > math.MaxUint16 {
		return nil, fmt.Errorf("%w: the namespace %q is not in the NamespaceArray", errRecord, q.NamespaceURI)
	}
	if idx == 0 {
		return ua.ParseNodeID(q.ID)
	}
	return ua.ParseNodeID("ns=" + strconv.Itoa(idx) + ";" + q.ID)
}

// serverEvidence is the identity of the server a record or intent was made
// with (§6.5): its ApplicationUri as the session reported it, and the
// thumbprint of its certificate when the channel was secured.
type serverEvidence struct {
	ApplicationURI string
	Secured        bool
	Thumbprint     []byte
	// Source is where ApplicationURI and Thumbprint come from:
	// identityUnavailable, identityReported (by the server, unproven) or
	// identityAuthenticated (the peer of the secure channel). The
	// configured identity is the ServerAddress's (ServerURIConf).
	Source uint8
}

// thumbprintSize is the size of a certificate thumbprint, a SHA-1 hash
// (OPC 10000-6 §6.7.4).
const thumbprintSize = 20

// The sources of the identity of a server (serverEvidence.Source).
const (
	identityUnavailable   uint8 = 0
	identityReported      uint8 = 1
	identityAuthenticated uint8 = 2
)

// check checks the identity evidence e.
func (e serverEvidence) check() error {
	switch {
	case e.Source > identityAuthenticated:
		return errSemantic("the identity source %d", e.Source)
	case e.Source == identityAuthenticated && (!e.Secured || len(e.Thumbprint) != thumbprintSize):
		return errSemantic("an authenticated identity without the thumbprint of a secured channel")
	case e.Source == identityUnavailable && (e.ApplicationURI != "" || len(e.Thumbprint) != 0):
		return errSemantic("an identity of no source")
	}
	return nil
}

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

	// Server is the identity of the server the endpoint is on.
	Server serverEvidence
	// Namespaces is the NamespaceArray of that server when the record was
	// made.
	Namespaces       []string
	ACNode           *qualifiedID
	FunctionalEntity *qualifiedID
	Name             string
	NodeID           *qualifiedID
	// CreationTime is the Diagnostics CreationTime of the endpoint (§6.6.2
	// Table 74), zero when the AutomationComponent does not expose it.
	CreationTime time.Time
	// CMApplicationURI is the ConnectionManagerApplicationUri read from
	// the endpoint; CMObserved that it was read.
	CMApplicationURI string
	CMObserved       bool

	Class        int64
	Run          uint64
	Version      uint32
	ClosePending bool
	// Generation and Fingerprint are the set configuration of the run that
	// made the endpoint; EndpointFingerprint is the SHA-256 of the
	// ConnectionEndpointConfiguration it sent for it.
	Generation          uint64
	Fingerprint         []byte
	EndpointFingerprint []byte
}

// runRecord is the journal of a run (§6.3).
type runRecord struct {
	Run             uint64
	Folder          []string
	SetName         string
	Generation      uint64
	Fingerprint     []byte
	Action          int32
	RollbackOnError bool
	Phase           uint8
	// Next is the generation a Replace switches the set to, 0 for none.
	// A set change has its tx record.
	Next uint64
	// Endpoints are the keys of the endpoint records the run made or
	// closed so far.
	Endpoints []string
}

// txOp is one operation of a set change (F.3.3.2).
type txOp struct {
	Op      int32 // uafx.ConnectionConfigurationSetOperation
	Folder  []string
	Name    string
	Version uint32
	// Old is the generation of the set it removes or replaces, 0 for an
	// Add; New the generation it commits, 0 for a Remove.
	Old, New    uint64
	Fingerprint []byte
	Conf        []byte
}

// txRecord is the set change a run closes the Connections for (§6.2): all
// operations of a Replace, Remove or complete Update, which one write
// switches after the closes (RequireCompleteUpdate, Table F.39).
type txRecord struct {
	Run uint64
	Ops []txOp
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
	Server            serverEvidence
	Namespaces        []string
	ACNode            *qualifiedID

	// Names and FunctionalEntities of an establish, one per endpoint
	// configuration, with the SHA-256 of each configuration as sent;
	// Request is the input arguments as sent (the
	// ConnectionEndpointParameters among them), encoded with the indexes
	// of Namespaces.
	Names                []string
	FunctionalEntities   []*qualifiedID
	EndpointFingerprints [][]byte
	Request              []byte
	// AbsentBefore is, per Name, that the browse before the call found no
	// endpoint of it; Preconfigured the NodeId it takes otherwise.
	AbsentBefore  []bool
	Preconfigured []*qualifiedID
	// Nodes and Remove of a close.
	Nodes  []*qualifiedID
	Remove bool

	// Generation and Fingerprint are the set configuration of the run.
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

// epStoreKey is the key of the record of an endpoint: the set, the
// ServerAddress, the FunctionalEntity by namespace URI and the Name. The
// same place in two sets is two records; the key does not change with the
// namespace index of the FunctionalEntity (§6.1).
func epStoreKey(set SetKey, addr ServerAddress, fe *qualifiedID, name string) string {
	return "ep/" + hashKey(keyString(set), addr.Address, strconv.Itoa(int(addr.SecurityMode)), addr.SecurityPolicyURI, addr.ServerURI, fe.String(), name)
}

func runStoreKey(id RunID) string { return "run/" + strconv.FormatUint(uint64(id), 16) }

func txStoreKey(id RunID) string { return "tx/" + strconv.FormatUint(uint64(id), 16) }

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

// The semantic checks of the records at load (design §3.2: a record that
// does not decode or does not make sense is kept, reported and never
// overwritten). A checksum proves the bytes are what was written, not that
// what was written is a record of this key.

// errSemantic reports a record that decodes but is not valid.
func errSemantic(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errRecord, fmt.Sprintf(format, args...))
}

// check checks the set record r of key k against the counters c.
func (r *setRecord) check(k string, c countersRecord) error {
	sum := sha256.Sum256(r.Conf)
	switch {
	case setStoreKey(SetKey{Folder: r.Folder, Name: r.Name}) != k:
		return errSemantic("the key is not of the set %s", SetKey{Folder: r.Folder, Name: r.Name})
	case r.Name == "":
		return errSemantic("a set without a Name")
	case r.Version == 0:
		return errSemantic("Version 0")
	case r.Generation == 0 || r.Generation > c.Generation:
		return errSemantic("the generation %d is not of the counters (%d)", r.Generation, c.Generation)
	case string(r.Fingerprint) != string(sum[:]):
		return errSemantic("the fingerprint is not of the configuration")
	}
	return nil
}

// check checks the endpoint record r of key k against the counters c.
func (r *epStored) check(k string, c countersRecord) error {
	addr := ServerAddress{Address: r.Address, SecurityMode: ua.MessageSecurityMode(r.SecurityMode), SecurityPolicyURI: r.SecurityPolicyURI, ServerURI: r.ServerURIConf}
	switch {
	case r.SetName == "" || r.Name == "" || r.Connection == "":
		return errSemantic("an endpoint record without a set, Connection or Name")
	case r.Endpoint < 0 || r.Endpoint > math.MaxInt32:
		return errSemantic("the endpoint number %d", r.Endpoint)
	case r.Class < int64(Foreign) || r.Class > int64(Unresolved):
		return errSemantic("the class %d", r.Class)
	case r.SecurityMode > math.MaxInt32:
		return errSemantic("the SecurityMode %d", r.SecurityMode)
	case epStoreKey(SetKey{Folder: r.Folder, Name: r.SetName}, addr, r.FunctionalEntity, r.Name) != k:
		return errSemantic("the key is not of the endpoint %q", r.Name)
	case r.Run == 0 || r.Run > c.RunID:
		return errSemantic("the run %d is not of the counters (%d)", r.Run, c.RunID)
	case r.Generation > c.Generation:
		return errSemantic("the generation %d is not of the counters (%d)", r.Generation, c.Generation)
	case len(r.Fingerprint) != 0 && len(r.Fingerprint) != sha256.Size, len(r.EndpointFingerprint) != 0 && len(r.EndpointFingerprint) != sha256.Size:
		return errSemantic("a fingerprint of %d bytes", len(r.Fingerprint))
	}
	for _, q := range []*qualifiedID{r.ACNode, r.FunctionalEntity, r.NodeID} {
		if _, err := unqualify(q, r.Namespaces); err != nil {
			return err
		}
	}
	return r.Server.check()
}

// validAction reports whether a is the Action of a run.
func validAction(a int32) bool {
	switch uafx.FxProcess(a) {
	case uafx.ActionEstablishConnectionsEnabled, uafx.ActionEstablishConnectionsDisabled, uafx.ActionEstablishConnections,
		uafx.ActionRemoveConnections, uafx.ActionEnableConnections, uafx.ActionDisableConnections, ActionReconcile, ActionRemoveSet:
		return true
	default:
		return false
	}
}

// check checks the run record r of key k against the counters c.
func (r *runRecord) check(k string, c countersRecord) error {
	switch {
	case runStoreKey(RunID(r.Run)) != k:
		return errSemantic("the key is not of the run %d", r.Run)
	case r.Run == 0 || r.Run > c.RunID:
		return errSemantic("the run %d is not of the counters (%d)", r.Run, c.RunID)
	case r.SetName == "":
		return errSemantic("a run record without a set")
	case r.Phase < phasePlanned || r.Phase > phaseReconciling:
		return errSemantic("the phase %d", r.Phase)
	case !validAction(r.Action):
		return errSemantic("the action %d", r.Action)
	case r.Generation > c.Generation || r.Next > c.Generation:
		return errSemantic("a generation that is not of the counters (%d)", c.Generation)
	case r.Next != 0 && uafx.FxProcess(r.Action) != ActionRemoveSet:
		return errSemantic("a switch of a run that is no set change")
	}
	for _, e := range r.Endpoints {
		if len(e) <= len("ep/") || e[:3] != "ep/" {
			return errSemantic("the endpoint key %q", e)
		}
	}
	return nil
}

// check checks the set change r of key k against the counters c.
func (r *txRecord) check(k string, c countersRecord) error {
	if txStoreKey(RunID(r.Run)) != k || r.Run == 0 || r.Run > c.RunID {
		return errSemantic("the key is not of the run %d", r.Run)
	}
	if len(r.Ops) == 0 {
		return errSemantic("a set change without operations")
	}
	for _, o := range r.Ops {
		sum := sha256.Sum256(o.Conf)
		switch uafx.ConnectionConfigurationSetOperation(o.Op) {
		case uafx.ElementAdd, uafx.ElementReplace:
			if o.New == 0 || o.New > c.Generation || string(o.Fingerprint) != string(sum[:]) || o.Version == 0 {
				return errSemantic("the operation on %s", SetKey{Folder: o.Folder, Name: o.Name})
			}
			if _, err := decodeConf(o.Conf); err != nil {
				return err
			}
		case uafx.ElementRemove:
			if o.New != 0 || len(o.Conf) != 0 {
				return errSemantic("the removal of %s", SetKey{Folder: o.Folder, Name: o.Name})
			}
		default:
			return errSemantic("the operation %d", o.Op)
		}
		if o.Name == "" || o.Old > c.Generation {
			return errSemantic("the operation on %s", SetKey{Folder: o.Folder, Name: o.Name})
		}
	}
	return nil
}

// runOfCall returns the run of the intent key k.
func runOfCall(k string) (RunID, bool) {
	rest, ok := strings.CutPrefix(k, "call/")
	if !ok {
		return 0, false
	}
	run, n, ok := strings.Cut(rest, "/")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseUint(run, 16, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	if i, err := strconv.Atoi(n); err != nil || i <= 0 || callStoreKey(RunID(id), i) != k {
		return 0, false
	}
	return RunID(id), true
}

// check checks the intent r of key k against the counters c.
func (r *callRecord) check(k string, c countersRecord) error {
	run, ok := runOfCall(k)
	switch {
	case !ok || uint64(run) != r.Run:
		return errSemantic("the key is not of an intent of the run %d", r.Run)
	case r.Run > c.RunID:
		return errSemantic("the run %d is not of the counters (%d)", r.Run, c.RunID)
	case r.SetName == "":
		return errSemantic("an intent without a set")
	case r.Generation > c.Generation:
		return errSemantic("the generation %d is not of the counters (%d)", r.Generation, c.Generation)
	case r.SecurityMode > math.MaxInt32:
		return errSemantic("the SecurityMode %d", r.SecurityMode)
	}
	if err := r.Server.check(); err != nil {
		return err
	}
	switch r.Kind {
	case callEstablish:
		n := len(r.Names)
		if len(r.FunctionalEntities) != n || len(r.AbsentBefore) != n || len(r.Preconfigured) != n || len(r.EndpointFingerprints) != n || len(r.Nodes) != 0 {
			return errSemantic("an establish intent with %d Names and %d FunctionalEntities", n, len(r.FunctionalEntities))
		}
		for i := range n {
			if _, err := unqualify(r.FunctionalEntities[i], r.Namespaces); err != nil {
				return err
			}
			if _, err := unqualify(r.Preconfigured[i], r.Namespaces); err != nil {
				return err
			}
		}
	case callClose:
		if len(r.Nodes) == 0 || len(r.Names) != 0 {
			return errSemantic("a close intent with %d nodes", len(r.Nodes))
		}
		for _, q := range r.Nodes {
			if _, err := unqualify(q, r.Namespaces); err != nil {
				return err
			}
		}
	default:
		return errSemantic("the call kind %d", r.Kind)
	}
	_, err := unqualify(r.ACNode, r.Namespaces)
	return err
}
