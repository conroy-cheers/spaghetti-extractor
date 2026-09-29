# Physical ABI analysis and matching

Spaghetti Extractor treats a call boundary as three related artifacts rather
than one C prototype:

1. `PhysicalAbiProfileV1` describes machine value transport, stack cleanup,
   preserved state, and callback value locations.
2. `PortablePrototypeV1` supplies optional source names and C types for lifting.
3. `BoundaryEffectsV1` describes memory, resource, and callback effects only
   where a component or external boundary needs them.

The physical profile is authoritative for compatibility. Source types never
override machine evidence, and effect metadata does not make two incompatible
calling conventions compatible.

## Evidence and status

ABI facts come from independently content-bound sources:

- checked root-independent transition and SCC summaries;
- canonical external-site contracts;
- a pinned toolchain's symbol-decoration model;
- pinned header AST or debug metadata declarations;
- explicit reviewed assumptions bound to a binary or catalog snapshot.

The finite-domain solver intersects these facts. A declaration can fill a fact
that machine analysis cannot recover, but conflicting machine and declaration
facts produce `violated`. Missing facts and bounded alternatives produce
`incomplete`; neither is widened into a guessed ABI.

`PhysicalAbiDeclarationSetV1` binds declarations to one exact library snapshot
and source digest. An authored declaration spec must name the digest of the
header AST, debug artifact, or reviewed source it was derived from; the spec's
own digest is recorded separately as a dependency. A declaration may include portable prototype and boundary
effect metadata, but those remain separate from its physical profile.
`catalogPack.abiDeclarationSpec` is the concise authored input; Nix converts it
to the canonical declaration set in its own content-addressed derivation.

Header-derived machine-import profiles contain physical declarations only.
`sdk.environment.nativeCallthroughProfile { abiProfile = ...; effectProfile = ...; }`
combines them with an explicitly authored static machine-import profile V2 using
the existing `exact_native_dll_callthrough_v1` rule. Each selected effect entry
must agree with the header's calling convention, physical word arity and result
register relations. The composition preserves and rechecks the canonical boundary,
including hidden aggregate return transport, and binds both input profiles.
Unselected imports remain ABI-only. Changing an effect contract changes the
resulting binding even when the C signature is unchanged.

This constructor does not infer effects from pointer types or prove a DLL body.
The call-through contract explicitly requires the same pinned DLL implementation,
exact machine arguments and direct use of the candidate address space; ordinary
provider/native admission must still establish those prerequisites. The jq
output pilot uses this path for `jv_copy` and `jv_dumpf`. The original DLL retains
their heap, resource and output behavior; the authored component calls those
services and transports the returned value. This is neither a portable libjq
implementation nor a checked summary of libjq's internal heap algorithms.

## Function and call-site boundaries

Machine units are not presumed to be procedures. A linked-library function
match defines a function-region subject over all of its units. Only observations
that are valid at the whole region boundary, such as checked return cleanup,
are projected from member units. Block-local stack and register facts cannot be
promoted to a procedure ABI.

Call sites are separate subjects. Checked call-site facts are reconciled with
the matched function-region profile. This permits one function profile to be
validated at several callers while retaining precise locations for any
contradiction.

## Cached pipeline

The Nix dependency path is deliberately split:

```text
immutable library blobs
  -> artifact and function index
  -> physical ABI catalog + declarations
  -> target ABI evidence
  -> exact match ABI resolution
  -> island/component qualification
```

Changing a declaration does not re-index archive files. Changing one target
summary does not rebuild catalog extraction. Each downstream artifact records
the exact evidence, declaration, catalog, match, and solver identities it used.

## Operator workflow

`library status` and `library inspect` expose ABI completion with the existing
constellation results. The useful repair frontier is a field on a specific
function region or call site, not a global "prototype unknown" count.

Typical next actions are:

- add or regenerate a pinned header/debug declaration;
- resolve an ambiguous decorated symbol;
- improve checked call-site argument or result recovery;
- add a reviewed, content-bound assumption when the binary cannot encode a
  source-level distinction;
- correct a conflicting component interface.

The original binary is never executed to recover these facts. Candidate runtime
tests remain downstream smoke checks and are not ABI authority.
