# Release v0.1.11

**Date:** 2026-03-11
**Previous release:** v0.1.10

## Summary

Exposes the remaining standard-node name lookups in the `id` package and adds
a type-definition display helper so browse UIs can show "PropertyType",
"FolderType", and other well-known names instead of raw NodeIDs.

## Type definition display

- **`id.VariableTypeName(id uint32) string`** — Standard name for well-known VariableTypes in namespace 0 (e.g. 68 → "PropertyType", 63 → "BaseDataVariableType"), or "" if unknown.
- **`id.ObjectTypeName(id uint32) string`** — Same for ObjectTypes (e.g. 58 → "BaseObjectType", 61 → "FolderType").
- **`TypeDefinitionDisplayName(typeDefID *ua.NodeID) string`** — Root package: tries VariableTypeName then ObjectTypeName; otherwise returns the NodeID string. Use when displaying type definition columns (e.g. browse) so "PropertyType" is shown instead of "i=68".

## id package: Object, Variable, Method names

All seven name maps used by `id.Name(id)` are now exposed as dedicated helpers:

- **`id.ObjectName(id uint32) string`** — Well-known Object nodes (e.g. 84 → "RootFolder", 85 → "ObjectsFolder", 2253 → "Server").
- **`id.VariableName(id uint32) string`** — Well-known Variable nodes (e.g. 2256 → "Server_ServerStatus", 2258 → "Server_ServerStatus_CurrentTime").
- **`id.MethodName(id uint32) string`** — Well-known Method nodes (e.g. 11492 → "Server_GetMonitoredItems").

Together with existing `DataTypeName`, `ReferenceTypeName`, `VariableTypeName`, and `ObjectTypeName`, callers can resolve standard names by node class when displaying NodeIDs (e.g. in browse or diagnostics).

---

# Release v0.1.10

**Date:** 2026-03-11
**Previous release:** v0.1.9

## Summary

Adds type and status display helpers, namespace-qualified path resolution,
symbolic node name lookup, TCP-only dial for diagnostics, and documentation
improvements for path semantics and CSV/JSON consistency.

## DataType display names

- **`id.DataTypeName(id uint32) string`** — Returns the standard OPC UA name for well-known DataTypes in namespace 0 (e.g. 10 → "Float", 12 → "String", 294 → "UtcTime"), or "" if unknown.
- **`DataTypeDisplayName(dataTypeID *ua.NodeID) string`** — Convenience in the root package: standard name for known ns=0 DataTypes, otherwise the NodeID string. Use to normalize type rendering (e.g. "Float" instead of "i=10").

## Status code helpers

- **`StatusCode.Symbol() string`** — Short symbolic name only (e.g. "Good", "BadServiceUnsupported"), stripping the "Status" prefix. Use for compact status rendering instead of `Error()`.
- **`StatusCode.Uint32() uint32`** — Raw 32-bit value for consistent CSV/JSON serialization.

## Variant array

- **`Variant.IsArray() bool`** — Returns true if the variant value is an array (one- or multi-dimensional). `ArrayDimensions()` was already present (returns `[]int32`).

## Connection diagnostics

- **`uacp.DialTCP(ctx, endpoint) (net.Conn, error)`** — TCP-only connect to the endpoint host:port; no OPC UA HEL/ACK or secure channel. Caller must close the returned connection. Use for TCP reachability checks (e.g. ping) without creating a session.

## Path resolution

- **Path semantics docs** — Godoc and API.md/client-guide now state start node, namespace handling, and error behavior for `NodeFromPath`, `NodeFromPathInNamespace`, `Node.TranslateBrowsePathInNamespaceToNodeID`, and `Node.TranslateBrowsePathsToNodeIDs`.
- **`Client.NodeFromQualifiedPath(ctx, path) (*Node, error)`** — Parses namespace-qualified path syntax `ns:segment.ns:segment` (e.g. `0:Server.0:ServerStatus`, `2:DeviceSet.4:PLC_Name`) and calls TranslateBrowsePathsToNodeIDs with per-segment namespace indices. Start node is Objects folder.

## Symbolic node names

- **`id.NodeIDByName(name string) (uint32, bool)`** — Reverse lookup from well-known standard node names (namespace 0) to numeric ID. Names include full spec names ("Server", "ObjectsFolder", "Server_ServerStatus_CurrentTime") and short aliases: "CurrentTime" → 2258, "ServerStatus" → 2256, "Objects" → 85.
- **`StandardNodeID(name string) (*ua.NodeID, bool)`** — Root package helper: returns `ua.NewNumericNodeID(0, id)` when `id.NodeIDByName(name)` succeeds. Use for CLI or config that accepts symbolic names (e.g. `get value -n CurrentTime` instead of `-n i=2258`).

## CSV/JSON and canonical form

- **`ua.NodeID.String()`** — Godoc and API.md now state that output is canonical (namespace 0 omitted; round-trip with `ParseNodeID`).
- **`StatusCode.Uint32()`** — See above; supports consistent numeric serialization.

## Endpoint troubleshooting

- **Verification** — `EndpointDescription` fields `TransportProfileURI`, `ServerCertificate`, and `Server.ApplicationURI` are already exposed and used; no code change; documented for endpoint output tooling.

## Documentation

- README.md path resolution row updated with `NodeFromQualifiedPath` and symbolic names (`StandardNodeID`, `id.NodeIDByName`). Quickstart comment added for `StandardNodeID("CurrentTime")`.
- docs/client-guide.md: connection diagnostics (ping) section, path semantics table with `NodeFromQualifiedPath`, and symbolic node names (`StandardNodeID`) subsection.
- API.md: all new functions and tables (path semantics, DataType/StatusCode/Variant, uacp.DialTCP, id.NodeIDByName, StandardNodeID, NodeID canonical, StatusCode.Uint32).

---

# Release v0.1.9

**Date:** 2026-03-11
**Previous release:** v0.1.8

## Summary

Adds an API to resolve well-known reference type NodeIDs to their standard
names (e.g. "HasComponent", "Organizes") so tools like `opcuactl browse refs` can
show names instead of raw NodeIDs (i=47, i=46) in the reference type column.

## Reference type display names

- **`id.ReferenceTypeName(id uint32) string`** — Returns the standard OPC UA
  name for a well-known reference type in namespace 0 (e.g. 47 → "HasComponent",
  35 → "Organizes"), or "" if unknown.
- **`ReferenceTypeDisplayName(refTypeID *ua.NodeID) string`** — Convenience
  helper in the root package: returns the standard name when the NodeID is in
  namespace 0 and known, otherwise returns the NodeID string. Use when
  displaying the reference type column in browse refs or similar UIs.

Clients can call `ReferenceTypeDisplayName(ref.ReferenceTypeID)` when rendering
`ReferenceDescription` rows to show "HasComponent" instead of "i=47".

---

# Release v0.1.8

**Date:** 2026-03-11
**Previous release:** v0.1.7

## Summary

Adds subscription sampling interval control and a deduplicating walk API:
callers can set the server-side sampling rate for monitored items independently
of the publishing interval, and can walk the address space with each node
yielded at most once.

## Client: Subscription sampling interval

- **`SubscriptionBuilder.SamplingInterval(d time.Duration)`** — Sets the
  requested sampling interval for monitored items added by `Monitor` or
  `MonitorEvents`. The server samples at this rate (converted to milliseconds
  on the wire); the subscription's publishing interval still controls how often
  notifications are sent to the client. If not set or zero, the server uses
  the fastest practical rate (unchanged from before).

## Browsing: WalkLimitDedup

- **`Node.WalkLimitDedup(ctx, maxDepth)`** — Same as `WalkLimit` but yields
  each node at most once, keyed by NodeID. When a node is reachable via
  multiple hierarchical paths, only the first occurrence (by traversal order) is
  yielded. Callers no longer need to maintain their own visited set to avoid
  duplicate nodes.

---

# Release v0.1.7

**Date:** 2026-03-11
**Previous release:** v0.1.6

## Summary

Fixes a **regression introduced in v0.1.5** that broke connection establishment
(e.g. `opcuactl browse` or any client connecting with `--security-mode None`).
The generic encoder no longer skips nil optional fields; nil is now encoded as
the correct OPC UA null representation so message layout stays valid.

## Bug fix: Encoder regression (nil optional fields)

In v0.1.5 we changed `ua/encode.go` to skip nil pointer fields entirely
(return `nil, nil`) to avoid calling `BinaryEncoder.Encode()` on a nil receiver.
That broke the OPC UA binary wire format: the server expects **all fields at
fixed offsets**. Omitting bytes for nil optional fields corrupted the message
layout and caused "failed to open a new secure channel" / EOF during connect.

- **`ua/encode.go`** — Reverted the early-exit that returned no bytes for any
  nil pointer. Nil optional fields are no longer skipped.
- **`ua/qualified_name.go`** — When the receiver is nil, `Encode()` now
  returns the OPC UA null QualifiedName encoding (namespace 0 + string length
  -1), i.e. 6 bytes, so struct field offsets are preserved.
- **`ua/node_id.go`** — When the receiver is nil, `Encode()` now returns the
  OPC UA null NodeID (two-byte form, id=0), i.e. 2 bytes, so optional NodeID
  fields keep a fixed layout.

Connection establishment and all messages with optional `*QualifiedName` or
`*NodeID` fields now encode correctly.

## Other changes

- **testutil**: Test client uses longer `DialTimeout` and `RequestTimeout`
  (30s) so tests have time to connect under load (e.g. race detector).
- **examples/browse**: Test uses `testutil.NewTestServer` / `NewTestClient`
  (dynamic port, shared timeouts); removed unused `join` helper (lint).

---

# Release v0.1.6

**Date:** 2026-03-11
**Previous release:** v0.1.5

## Summary

Improves error messages when the server closes the connection (EOF) during
subscription or monitored-item creation. Callers (e.g. `monitor event` /
`monitor alarm` against servers that do not support event subscriptions) now
see a clear hint instead of a raw "EOF".

## Client: EOF handling in subscription path

When the server closes the connection instead of returning a service fault
(e.g. WAGO PLC not supporting OPC UA event or alarm subscriptions), the SDK
previously surfaced **io.EOF** with no context.

- **`Subscription.Monitor()`** — If the request returns `io.EOF`, the
  returned error now wraps it with: "connection closed while creating
  monitored items (server may not support event or alarm subscriptions)".
  Callers can still use `errors.Is(err, io.EOF)`.
- **`Client.Subscribe()`** — If `CreateSubscription` returns `io.EOF`, the
  returned error now wraps it with: "connection closed while creating
  subscription (server may not support subscriptions)".

Documentation and doc comments for `Monitor` and `SubscriptionBuilder.Start`
note that connection-close errors may wrap `io.EOF` with this hint.

---

# Release v0.1.5

**Date:** 2026-03-11
**Previous release:** v0.1.4

## Summary

Adds the depth-limited `WalkLimit` API for browsing the address space and fixes a
nil pointer dereference when encoding `HistoryReadRequest` with optional
`DataEncoding` (e.g. `history value` / `history event` commands).

## Client: WalkLimit (depth-limited walk)

- **`Node.WalkLimit(ctx, maxDepth)`** — Same as `Walk` but stops recursing when
  depth reaches `maxDepth`. The node at `maxDepth` is still yielded. Use for
  "find node", "find type", or "browse tree" style tools to avoid unbounded
  traversal (e.g. a `-depth` flag on the CLI). If `maxDepth < 0`, depth is
  unlimited (equivalent to `Walk`).
- **`Node.Walk(ctx)`** — Unchanged; now implemented via `WalkLimit(ctx, -1)`.

## Bug fix: HistoryReadRequest encoding with nil DataEncoding

Encoding a `HistoryReadRequest` whose `HistoryReadValueID` entries had
`DataEncoding == nil` caused a panic in `QualifiedName.Encode()` (nil pointer
dereference). This affected `HistoryReadRawModified`, `HistoryReadEvent`, and
other history read calls when the optional `DataEncoding` field was omitted.

- **`ua/encode.go`** — Nil pointer fields that implement `BinaryEncoder` are
  now encoded as no bytes instead of calling `Encode()` on a nil receiver.
- **`ua/qualified_name.go`** — `QualifiedName.Encode()` guards against a nil
  receiver and returns `(nil, nil)`.

---

# Release v0.1.4

**Date:** 2026-03-11
**Previous release:** v0.1.3

## Summary

Adds server certificate validation infrastructure and two new client options:
`InsecureSkipVerify()` and `TrustedCertificates()`. When `SecurityMode` is
`Sign` or `SignAndEncrypt`, the client now validates the server certificate by
default. Use `TrustedCertificates()` to trust self-signed servers or private
CAs, or `InsecureSkipVerify()` to disable validation for development.

## Client: Server Certificate Validation

The SDK previously performed no X.509 trust-chain validation of the server's
certificate — it parsed the certificate only to extract the RSA public key for
signing and encryption. This release adds opt-in validation and a deprecation
path toward secure-by-default behavior.

### New Options

| Option | Description |
|--------|-------------|
| `TrustedCertificates(certs ...*x509.Certificate)` | Add CA or self-signed certificates to the trust pool. Merged with the system CA pool. Enables full validation (chain, expiry, key usage). |
| `InsecureSkipVerify()` | Disable all server certificate validation. Certificate is still parsed for its public key. **INSECURE — development only.** |

### Validation Checks (when `TrustedCertificates` is configured)

| Check | Description |
|-------|-------------|
| **Trust chain** | Verifies the certificate chains to a trusted root CA (system pool + user-supplied certs) |
| **Expiration** | Rejects expired or not-yet-valid certificates |
| **Key usage** | Warns if `DigitalSignature` / `KeyEncipherment` bits are missing |

### Validation Points

Server certificate validation runs at two points in the connection flow:

- **`Dial()`** — validates `RemoteCertificate` (set via `SecurityFromEndpoint`
  or `RemoteCertificate` option) after `OpenSecureChannel`
- **`CreateSession()`** — validates `ServerCertificate` from the
  `CreateSessionResponse` after verifying the session signature

### Behavioral Summary

| Scenario | Certificate check | How to configure |
|----------|------------------|------------------|
| `SecurityMode == None` | No certificate exchanged, nothing to validate | Default |
| `Sign` or `SignAndEncrypt` (default) | Full validation: chain, expiry, key usage | Default |
| `Sign` or `SignAndEncrypt` + self-signed server | Fails unless cert added to trust pool | `TrustedCertificates(serverCACert)` |
| `Sign` or `SignAndEncrypt` + skip verify | No validation, just parse for public key | `InsecureSkipVerify()` |

### Config Changes

Added `serverCertValidator` to the internal `Config` struct:

```go
type serverCertValidator struct {
    insecureSkipVerify bool
    trustedCerts       *x509.CertPool
    trustedCertsList   []*x509.Certificate
}
```

## Documentation

- **API.md** — added `InsecureSkipVerify()` and `TrustedCertificates()` to the
  options table
- **docs/security.md** — new "Server Certificate Validation" section with
  usage examples, trust configuration, and dev-mode skip
- **docs/client-guide.md** — added new options to the client options table
- **README.md** — updated security feature description

## Files Changed

6 files changed. Hand-written Go: 3 files (config.go, client.go, config_test.go).

---

# Release v0.1.3

**Date:** 2026-03-11
**Previous release:** v0.1.2

## Summary

Patch release with a small improvement for anonymous authentication when using
the client (e.g. `--auth anonymous` in example CLIs).

## Client: anonymous auth without pre-set PolicyID

When `AuthAnonymous()` is applied before the server's endpoints are known (for
example when using `--auth anonymous` on the command line), the
`AnonymousIdentityToken` is created without a policy ID. The client now
resolves the correct anonymous user token policy from the server's advertised
endpoints after `CreateSession` and sets it on the token, so anonymous
authentication works correctly without requiring endpoint or security options
to be applied first.

---

# Release v0.1.2

**Date:** 2026-03-11
**Previous release:** v0.1.1

## Summary

This release brings the OPC UA schema files up to the latest OPC Foundation
specification and adds a security layer to the server: access restrictions,
role-based access control (RBAC), and session identity-to-role mapping. Three
new code generators were added and the existing service generator was hardened
to skip JSON-only types.

## Schema Update

Updated all schema files from the OPC Foundation UA-Nodeset repository:

- **NodeIds.csv** — refreshed; thousands of new/renamed node identifiers
- **StatusCode.csv** — new status codes added
- **Opc.Ua.Types.bsd** — new structured types and enumerations
- **Opc.Ua.NodeSet2.xml** — expanded node set with role permissions
- **Opc.Ua.PredefinedNodes.xml** — added (new file, used by .NET tooling)
- **AttributeIds.csv** — added (new file, 27 attribute IDs)
- **ServerCapabilities.csv** — added (new file, 39 capability identifiers)
- **Opc.Ua.NodeIds.permissions.csv** — added (new file, 557 default permission entries)

## New Code Generators

| Generator | Input | Output | Description |
|-----------|-------|--------|-------------|
| `cmd/attrid` | `AttributeIds.csv` | `ua/enums_attribute_id_gen.go` | AttributeID enum constants (replaces hand-maintained block) |
| `cmd/capability` | `ServerCapabilities.csv` | `ua/server_capabilities_gen.go` | 39 `ServerCapability*` constants, `KnownCapabilities` map, `ValidateCapability()` |
| `cmd/permissions` | `Opc.Ua.NodeIds.permissions.csv` | `server/default_permissions_gen.go` | 557 default node permission entries for RBAC |

## Code Generation Fixes

- **Service generator** (`cmd/service`): added `-nodeids` flag and
  `filterByBinaryEncoding()` to skip types that only have a JSON encoding in
  the spec — prevents generating codec registrations for types that cannot be
  serialized over OPC UA Binary.
- **`generate.sh`**: updated to run the three new generators; added descriptive
  header comment; fixed shellcheck warnings (SC2035, SC2086).

## Server Security & RBAC

### Access Restrictions (OPC UA Part 3 §5.2.11)

- `checkAccessRestrictions()` enforces `SigningRequired` and
  `EncryptionRequired` bits against the secure channel's security mode.
- `checkAccessRestrictionsForBrowse()` only enforces restrictions when the
  `ApplyRestrictionsToBrowse` bit is set.
- Wired into Read, Write, Browse, and Call service handlers.
- Added `SecurityMode()` getter on `SecureChannel`.

### Role-Based Access Control

- **`RBACAccessController`** — checks node `rolePermissions` against the
  session's assigned roles for Read, Write, Browse, and Call operations.
  Nodes without role permissions are unrestricted.
- **`RoleMapper`** function type and `DefaultRoleMapper` — maps identity tokens
  to well-known role NodeIDs (anonymous → `Anonymous`, others →
  `AuthenticatedUser`). Configurable via `WithRoleMapper()` server option.
- **Session identity tracking** — `ActivateSession` now extracts the
  `UserIdentityToken` and resolves roles through the configured `RoleMapper`.

### Well-Known Roles

- New `ua/well_known_role.go`: 12 well-known roles from the spec (Anonymous,
  AuthenticatedUser, Observer, Operator, Engineer, Supervisor, ConfigureAdmin,
  SecurityAdmin, SecurityKeyServer, SecurityKeyServerAdmin,
  SecurityKeyServerAccess, SecurityKeyServerPush).
- Each role has `String()`, `NodeID()` methods and lookup via `RoleByName` map.

### Node RolePermissions

- Server `Node` stores `[]*ua.RolePermissionType` resolved from the generated
  default permissions at import time via `resolveRolePermissions()`.
- `AttributeIDRolePermissions` and `AttributeIDUserRolePermissions` are served
  from the node as `[]*ua.ExtensionObject`.

## Server Capabilities Expansion

- `OperationalLimits` expanded from 1 field to 12 (all defaulting to 32):
  `MaxNodesPerRead`, `MaxNodesPerWrite`, `MaxNodesPerBrowse`,
  `MaxNodesPerMethodCall`, `MaxNodesPerRegisterNodes`,
  `MaxNodesPerTranslateBrowsePathsToNodeIDs`, `MaxNodesPerNodeManagement`,
  `MaxMonitoredItemsPerCall`, `MaxNodesPerHistoryReadData`,
  `MaxNodesPerHistoryReadEvents`, `MaxNodesPerHistoryUpdateData`,
  `MaxNodesPerHistoryUpdateEvents`.
- Server capability nodes generated dynamically from the struct.

## Code Quality

- Enabled `unparam` linter in `.golangci.yml` — `make check` now catches
  unused parameters.
- Fixed 4 genuine unused-parameter issues in `secure_channel.go` and
  `race_test.go`:
  - `newSecureChannel`: removed 3 dead parameters (`secureChannelID`,
    `sequenceNumber`, `securityTokenID`) — values were only used by
    `NewServerSecureChannel` which sets them on `openingInstance` directly.
  - `sendResponseWithContext`: wired up `ctx` for cancellation checks and
    write deadlines.
  - `mergeChunks`: removed always-nil error return.
  - `race_test.go`: removed unused goroutine parameter.

## Generated Code Changes

All generated files were regenerated from the updated schema:

- `id/` — NodeID constants (DataType, Method, Object, ObjectType, ReferenceType,
  Variable, VariableType)
- `ua/enums_gen.go` — updated/new enum types
- `ua/enums_strings_gen.go` — stringer output for all enums
- `ua/extobjs_gen.go` — extension object codecs
- `ua/register_extobjs_gen.go` — filtered to binary-encoded types only
- `ua/status_gen.go` — new status codes
- `connstate_strings_gen.go` — regenerated

## Files Changed

52 files changed, ~232k insertions, ~53k deletions (bulk is schema XML and
generated code). Hand-written Go: 19 files, +866 / -73 lines.
