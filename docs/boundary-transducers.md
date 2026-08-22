# Checked boundary transducers

Portable components do not receive raw x86 addresses, callback words, or
resource handles.  The component boundary is compiled from a checked Relation
IR document into an immutable operation plan.  The runtime executes that plan;
the older machine-binding projection is evidence for compilation, not a second
source of runtime semantics.

The artifact chain is:

1. a portable interface declares logical values and effects;
2. a checked machine binding identifies exact machine places and events;
3. an interaction inventory identifies exact service, atomic, and callback
   occurrences and the reusable contracts that match their typed ports;
4. an operator declaration selects contracts where more than one checked
   interpretation is possible;
5. Relation IR V3 describes constructive observers, realizers, and
   occurrence-local interaction frames;
6. the relation kernel proves the finite lens laws, exact event coverage, and
   origin obligations;
7. a closed primitive registry supplies the only authority-bearing operations;
8. a component boundary plan V2 fixes phase order, footprints, effects, and
   primitive implementations;
9. a plan receipt authorizes runtime lowering and semantic refinement; and
10. activation receipt V3 binds the original seven facets plus the relation and
   boundary-plan receipts.

Unchecked relations, unknown primitives, stale authorities, missing plan
receipts, ambiguous address origins, expired generations, and nonconstructive
writeback all fail closed.

## Primitive registry

The framework-owned registry currently includes origin resolve/realize,
capability import/export, atomic operations, callback invocation/exchange, and
service invocation.  A target declaration may select a primitive and a stable
authority binding, but cannot insert evaluator code or change the primitive's
phase, effect class, arity, result types, or proof requirements.

## Object origins

Machine object authority assigns stable domain/object identities to image,
static, stack, process, external, TLS, and resource origins.  Dynamic instances
add a generation, base, extent, permissions, and liveness.  Resolving an x86
word produces an object-relative `spx_ref_v1`; realizing a reference produces a
machine word only after the same origin, generation, bounds, nullability,
one-past, and permission rules have been checked.

Reference and view machine projections name stable semantic authorities rather
than artifact hashes or runtime object numbers.  The workflow derives the
content-bound authority artifact and allocates deterministic object identities.
This lets an operator describe `argv` storage, a stack object, a process global,
or an external allocation without embedding build products in intent files.

## Runtime rule

Relation-enabled runtime packages require an authorizing boundary-plan receipt
for every portable component.  Scalar, resource, callback, reference, and view
imports are reconstructed from plan observers; state/result writeback is
reconstructed from plan realizers.  The native runtime provides origin
resolution and realization across image, invocation-stack, process/external,
and thread-environment ranges.

The pure Python evaluator is a reference implementation for deterministic plan
semantics.  It stages every guard and value before exposing writes, which makes
multi-place realization transactional at the component boundary.  World
effects remain in their specialized atomic, callback, and service backends.

## Checked external-call adapters

An external-site service gets its machine calling convention from the checked
external contract, never from a component declaration.  Semantic service
events preserve exactly the nonvolatile registers named by that ABI and apply
its caller/callee stack adjustment.  For a structured result, the component
binding may add a `result_projection` that wraps the contract-authorized result
register as a reference, view, callback, or resource.  Materialization rejects
a wrapper of the wrong logical kind, a different source register, or a source
observed outside the call.

This is deliberately only a boundary adapter.  Origin relationships among a
service's arguments and result must be stated as checked relations; matching
authority labels are not themselves proof of aliasing or derivation.

## Reusable interaction contracts

Interaction contracts are target-neutral, reviewed descriptions of typed
ports, preconditions, postconditions, and effects.  They can state, for
example, that a nullable reference returned by a C runtime search is either
null or has the same origin as its input view.  The contract catalog is
content-addressed and separately receipted.  A target file may only select a
contract for an exact inventoried occurrence; it cannot add a predicate or
implementation.

The checked boundary plan specializes the selected contract to that occurrence
and is the common input to runtime lowering and the CBMC refinement harness.
Consequently, machine loads through a returned interior pointer are admitted
only when the exact service result has a checked origin guarantee.  The
refinement harness represents views and references as object-relative values,
keeps their raw machine-word realization separate, and uses one memory oracle
for both machine loads and portable view reads.  This removes the former
scalar-word shortcut without granting arbitrary pointer dereferences semantic
authority.

Provider postconditions also constrain generated service results.  The
reviewed `strrchr` contract, for example, states that a non-null result for a
non-NUL needle retains at least one following byte in the input origin.  A
NUL-terminated input view is modeled with its terminal byte in that same
memory oracle, so contract bounds and portable checked reads describe one
object rather than unrelated assumptions.
