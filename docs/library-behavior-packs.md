# Generic library behavior packs

Reusable library behavior is target-neutral. A pack describes the portable
implementation and the behavior its checked qualification covers; target
recognition and adoption bind that reusable artifact later.

## Behavior pack V2

Behavior-pack V2 adds a canonical `LibraryBehaviorContractV2` beside the
portable interface. The interface remains the type and call surface. The
behavior contract is the normalized authority input for behavior that is not a
pure function signature:

- framework-managed state fields and initial values;
- operation pre-states, post-states, and protocol state transitions;
- direct and service-mediated memory effects;
- logical resource effects;
- callback effects and callback operation kinds;
- externally visible observable and control effects;
- the exact services each operation may invoke and each service's effects.

Every record is typed, canonically ordered, and content-hashed. The contract
binds the exact portable-interface hash, while the pack binds the contract,
source package, implementation mapping, compile receipt, and static
qualification receipt. Loading V2 recomputes the behavior contract from the
portable interface and requires exact equality. An orphan effect, unknown
service, stale effect category, or contract for another interface fails closed.

`ReusableLibraryBehaviorPackV1` remains readable for diagnostics and migration.
Its flat interface/effect inventory does not provide the explicit behavioral
record required from V2 authority consumers.

## ABI declaration ingestion

`CatalogMemberIdentityV1` pins a catalog function to its catalog and snapshot,
the exact source-index hash, member and function IDs, symbols, and available
exact or normalized byte hashes. `CatalogMemberAbiDeclarationV1` embeds the
complete reviewed `PhysicalAbiDeclarationV1` and its declaration-set hash under
that identity. The ABI declaration therefore travels with the exact member it
describes instead of depending on a later symbol-only lookup.

`ingest_abi_declarations` merges those bindings with existing
`AbiExtractionResultV1` objects. The output retains canonical typed subjects,
evidence, facts, equalities, member declarations, and issues in one self-hashed
artifact. Reviewed prototypes and boundary effects remain inside the bound
declaration; physical profile facts enter the same finite-domain model as
machine extraction facts.

Ingestion does not make an authority decision. Its statuses are `complete`,
`incomplete`, and `contradiction`. Snapshot or symbol disagreement, stale
subject/evidence references, conflicting profiles, prototypes, or boundary
effects produce typed `contradiction` issues. The authority caller must map a
contradiction to its own `violated` result rather than allowing ingestion to
select one side or silently fall back to a symbol match.
