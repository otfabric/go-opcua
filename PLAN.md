Plan: Make generated OPC UA Go identifiers fully idiomatic

Target release: v1.0.0
Change type: breaking change
Tracking issue: TBD

Progress

- [x] Phase 0: Lock naming policy
- [x] Phase 1: Centralize identifier normalization (internal/goname/)
- [x] Phase 2: Add formatter tests
- [x] Phase 3: Add collision detection
- [x] Phase 4: Reserved-word / invalid-identifier handling
- [x] Phase 5: Preserve spec names in id.Name()
- [x] Phase 6: Regenerate all code
- [x] Phase 7: Update all handwritten callers
- [x] Phase 8: Remove lint exclusions
- [x] Phase 9: Regression protection in CI (collision detection built into generators)
- [x] Phase 10: Migration and release notes

Goal

Make all generated public Go identifiers fully idiomatic and lint-clean by removing spec-derived underscore names from exported constants, fields, and related generated symbols.

This includes:
	•	exported id.* constants
	•	generated status identifiers
	•	generated service/extension object field names
	•	any other generated public Go symbols that currently inherit underscore-separated spec tokens

The target standard is simple:
	•	public Go identifiers must be idiomatic CamelCase
	•	known Go initialisms must follow standard Go casing (ID, XML, URI, URL, GUID, TCP, etc.)
	•	generated code must pass staticcheck / ST1003 without exclusions
	•	exact spec names must remain available separately where needed for runtime lookups, diagnostics, and spec fidelity

⸻

Problem

The repository currently suppresses ST1003 for generated files and schema/ files because the generators preserve OPC UA spec underscore names in exported Go identifiers.

Examples:

const (
    ServerType_ServerArray = 2005
    ServerType_NamespaceArray = 2006
    GoodEdited_DependentValueChanged = 0x01160000
)

type SomeStruct struct {
    PriorityValue_PCP uint8
}

These names are not idiomatic Go and lower the quality of the public API.

⸻

Root cause

The generator naming pipeline currently normalizes some abbreviations but does not consistently convert underscore-separated spec tokens into proper CamelCase Go identifiers.

The OPC UA schema files use underscores as hierarchical/spec separators:

ServerType_ServerArray
Server_ServerStatus_CurrentTime
GoodEdited_DependentValueChanged
PriorityValue_PCP

Those spec names should not leak verbatim into exported Go identifiers.

⸻

Design principles

1. Separate Go names from spec names

There are two distinct naming domains:
	•	Go identifier name: idiomatic exported symbol name used in generated Go code
	•	spec name: exact original OPC UA token from CSV/XML/BSD

These must not be conflated.

Examples:
	•	spec name: ServerType_ServerArray
	•	Go identifier: ServerTypeServerArray
	•	spec name: GoodEdited_DependentValueChanged
	•	Go identifier: GoodEditedDependentValueChanged

2. Generated code must meet the same standards as handwritten code

Generated code is part of the public library surface and must satisfy the same naming and lint expectations as handwritten code.

3. Runtime/domain APIs should prefer spec names where appropriate

Functions that expose official OPC UA names to users should return the original spec token, not the spelling of internal Go symbols.

⸻

Scope

Generated files affected

Generator	Output file(s)	Impact
cmd/id	id/id_*_gen.go	large exported constant rename set
cmd/id	id/id_names_gen.go	mapping behavior may change
cmd/status	ua/status_gen.go	a few status identifier renames
cmd/service	ua/extobjs_gen.go	a few generated field renames
other generators	TBD	must be reviewed for public identifier output

Handwritten callers affected

Mechanical renames across handwritten code, tests, and examples.

Representative examples:
	•	id.ServerType_ServerArray → id.ServerTypeServerArray
	•	id.AggregateFunction_Average → id.AggregateFunctionAverage
	•	id.WellKnownRole_Anonymous → id.WellKnownRoleAnonymous
	•	id.Server_ServerStatus_CurrentTime → id.ServerServerStatusCurrentTime
	•	StatusGoodEdited_DependentValueChanged → StatusGoodEditedDependentValueChanged
	•	PriorityValue_PCP → PriorityValuePCP

⸻

Non-goals
	•	changing the OPC UA schema/spec files
	•	preserving old underscore identifiers as deprecated aliases
	•	keeping runtime APIs coupled to Go symbol spellings
	•	broad lint exemptions for generated code

⸻

Naming policy

A single shared naming policy will be used by all generators that emit public Go identifiers.

Input

Original spec token, for example:
	•	ServerType_ServerArray
	•	GoodEdited_DependentValueChanged
	•	PriorityValue_PCP

Output

Idiomatic exported Go identifier, for example:
	•	ServerTypeServerArray
	•	GoodEditedDependentValueChanged
	•	PriorityValuePCP

Rules
	1.	underscores are treated as separators, not preserved
	2.	empty underscore segments are ignored
	3.	tokens are combined into CamelCase
	4.	Go initialisms are normalized using standard Go casing
	5.	digits are preserved
	6.	output must be a valid Go identifier
	7.	collisions after normalization are generator errors
	8.	special-case overrides are explicit, centralized, and tested

⸻

Implementation plan

Phase 0: Lock the policy before changing output

Before touching generated files, document and freeze the identifier normalization contract.

Add a package-level comment in the shared naming utility describing:
	•	underscore removal
	•	CamelCase conversion
	•	initialism normalization
	•	collision handling
	•	spec name preservation

This prevents accidental future drift between generators.

⸻

Phase 1: Centralize identifier normalization

Create or refine a single shared formatter used by all generators that emit public Go identifiers.

Required change

cmd/id must stop using any local/custom naming logic and use the shared formatter.

All relevant generators must use the same function for public identifier generation.

Required behavior

Pseudo-flow:
	1.	trim input
	2.	split on _
	3.	drop empty segments
	4.	uppercase first rune of each segment
	5.	join segments
	6.	normalize known initialisms
	7.	apply explicit fixes/overrides
	8.	validate final identifier

Important note

Do not use a naive underscore removal implementation without tests and validation. The formatter must define behavior for:
	•	repeated underscores
	•	leading/trailing underscores
	•	digits
	•	mixed acronym tokens
	•	odd or malformed inputs

Example target behavior

Input	Output
ServerType_ServerArray	ServerTypeServerArray
WellKnownRole_Anonymous	WellKnownRoleAnonymous
GoodEdited_DependentValueChanged	GoodEditedDependentValueChanged
PriorityValue_PCP	PriorityValuePCP
NamespaceURI	NamespaceURI
A__B	AB


⸻

Phase 2: Add formatter tests before regeneration

Add table-driven unit tests for the shared naming formatter.

Minimum required test cases
	•	standard underscore hierarchy names
	•	initialisms (ID, XML, URI, URL, GUID, TCP, etc.)
	•	already-correct CamelCase inputs
	•	repeated underscores
	•	leading/trailing underscores
	•	whitespace input
	•	digits in identifiers
	•	known tricky inputs from actual OPC UA schema files

Why this phase is mandatory

This change renames a large public surface. The naming behavior must be verified at the formatter level before regenerating thousands of symbols.

⸻

Phase 3: Add collision detection

After normalization, distinct spec names may collapse into the same Go identifier.

Examples of possible collision patterns:
	•	Foo_Bar
	•	FooBar

or acronym-related variants.

Required behavior

The generator must fail with a clear error when a collision is detected.

The error should include:
	•	source file/input record
	•	original spec names involved
	•	normalized Go identifier

Rule

Never silently overwrite or emit duplicate Go identifiers.

⸻

Phase 4: Define reserved-word / invalid-identifier handling

The formatter/generator must define behavior for names that would become:
	•	invalid Go identifiers
	•	Go keywords
	•	otherwise unacceptable public names

Preferred approach:
	•	explicit override table for known bad cases
	•	otherwise fail generation loudly

Do not silently generate awkward or unstable names.

⸻

Phase 5: Preserve spec names explicitly

The original OPC UA spec token must remain available separately from the Go identifier.

This matters for:
	•	runtime name lookup
	•	diagnostics
	•	logs
	•	documentation
	•	spec alignment
	•	user expectations

Strong recommendation

Review id.Name() and related lookup helpers.

If id.Name() currently returns the Go identifier spelling, change it to return the official spec name instead.

Preferred behavior:

id.Name(2005) == "ServerType_ServerArray"

not:

id.Name(2005) == "ServerTypeServerArray"

If the Go symbol spelling is needed internally, expose a separate internal or secondary mapping rather than using Name() for both purposes.

⸻

Phase 6: Regenerate all code

Run:

make gen

Then inspect the output carefully, not just the compile result.

Verify specifically
	•	exported constant names
	•	generated struct field names
	•	reverse lookup tables/maps
	•	service / extension object generated code
	•	serialization tags and schema tags
	•	any reflection-sensitive code paths

Special attention

For generated struct fields such as:
	•	PriorityValue_PCP → PriorityValuePCP

ensure that renaming the Go field does not break:
	•	XML tags
	•	binary encoding metadata
	•	schema-derived field mapping
	•	reflection-dependent behavior

⸻

Phase 7: Update all handwritten callers

Mechanically rename all references in:
	•	non-generated code
	•	tests
	•	examples

This should be straightforward once regenerated output is stable.

Typical rewrites
	•	id.ServerType_ServerArray → id.ServerTypeServerArray
	•	id.Server_ServerCapabilities_LocaleIdArray → id.ServerServerCapabilitiesLocaleIDArray
(or equivalent final normalized form depending on initialism policy)
	•	id.*_Encoding_DefaultBinary → id.*EncodingDefaultBinary

Be especially careful with acronym normalization so replacements match the formatter exactly.

⸻

Phase 8: Remove lint exclusions

Delete the current ST1003 exclusion once the generated code is clean.

Current removal target:

exclusions:
  rules:
    - linters: [staticcheck]
      text: "ST1003"
      path: "(_gen\\.go$|^schema/)"

Also remove any no-longer-needed staticcheck.checks customization if it only existed to support this exception.

Policy after cleanup

No broad naming exemption for generated code.

If any remaining exception is needed, it must be narrow, justified, and documented.

⸻

Phase 9: Add regression protection in CI

Add or tighten CI checks for:
	•	make gen idempotence
	•	formatter unit tests
	•	make check / lint passes
	•	no generated exported identifiers containing underscores
	•	collision detection works and fails clearly

Optional extra guard

A simple CI assertion can scan generated files for exported identifiers containing underscores and fail if any are found.

⸻

Phase 10: Migration and release notes

Because this is a breaking change, add a short migration note for downstream users.

Include
	•	underscore identifiers were renamed to idiomatic CamelCase
	•	no compatibility aliases were added
	•	id.Name() behavior changed, if changed
	•	examples of common rename patterns

Do not include
	•	deprecated alias layer
	•	compatibility shims for old symbol names

At pre-1.0, a clean break is preferable.

⸻

Risks and considerations

Breaking API surface

This is a large exported rename across generated constants and some generated fields. Downstream users will get compile errors and need to update imports/usages.

This is acceptable and preferable to carrying non-idiomatic API baggage forward.

Name collisions

Normalization may reveal collisions not visible before. This must be handled at generation time, not ignored.

Runtime lookup behavior

If id.Name() changes semantics, that is a behavioral break in addition to a compile-time symbol rename. This is likely still the right choice, but it must be called out explicitly in release notes.

Serialization/reflection sensitivity

Generated struct field renames must preserve external wire/schema behavior via tags/metadata.

⸻

Open decisions

1. id.Name() semantics

Recommended decision: return original OPC UA spec names.

Reason:
	•	better for users
	•	matches official spec vocabulary
	•	decouples runtime API from Go symbol spelling

2. Go initialism policy

Use standard Go initialism casing consistently.

Examples:
	•	ID
	•	XML
	•	URI
	•	URL
	•	GUID
	•	TCP

This policy must be shared across all generators.

3. schema/uaNodeSet.go

Review it, but do not change it unless it emits non-idiomatic public Go identifiers or causes API quality problems.

⸻

Acceptance criteria

The work is done when all of the following are true:
	•	all generated public Go identifiers are idiomatic CamelCase
	•	no exported generated identifiers contain underscore separators
	•	all relevant generators use a single shared naming formatter
	•	formatter tests cover real schema edge cases
	•	normalization collisions fail generation explicitly
	•	original spec names remain available where needed
	•	handwritten code, tests, and examples are updated
	•	make gen is idempotent
	•	make check passes without ST1003 exclusions for generated code

⸻

Summary

This cleanup is worth doing and should be treated as a quality upgrade of the public API, not just a lint fix.

The core approach is:
	1.	centralize and formalize identifier normalization
	2.	preserve spec names separately from Go names
	3.	add tests and collision detection before regenerating
	4.	regenerate and update callers
	5.	remove lint exemptions and lock the standard in CI

That yields a cleaner, more idiomatic, and more durable Go API.