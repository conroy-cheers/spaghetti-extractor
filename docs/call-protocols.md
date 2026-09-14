# Checked call protocols

A source prototype is not enough to lift an x86 call boundary. It conflates
semantic type identity, target-specific layout, machine transport, ownership,
and presentation choices that can vary independently. Spaghetti Extractor
therefore checks a call as a family of content-bound artifacts.

## Layers

`BoundarySchemaV1` is the canonical target-neutral type and signature model.
`PortableTypeGraphV1` remains its read-only call migration input. Both describe
scalars, enums, pointers, arrays, records, unions, functions, qualifiers, and
recursive pointer graphs without assigning target offsets or registers.

`TargetDataLayoutV1` binds the canonical schema to one target and ABI dialect;
`TargetLayoutSetV1` is retained as the V1 adapter. Size,
alignment, record-field placement, storage units, and pointer width live here.
Two targets may share a type graph while selecting different layout sets.

`PhysicalCallFrameV3` content-binds a V2 physical transport to canonical value
paths, schema, target layout, signature, and dialect rules. Its underlying
`PhysicalCallFrameV2` describes transport at a particular boundary. Logical
argument and result slots are split into explicit register, stack, memory,
vector, or x87 fragments. It also records transfer kind, stack cleanup,
preserved state, exceptional outcomes, and the observation phase. Padding is
explicitly unspecified rather than invented as a source value.

`CallFrameRelationV1` compiles the physical frame into the shared constructive
Relation IR. Its receipt proves that observing machine locations and realizing
logical values form a checked boundary lens. Calls consequently reuse the same
relation solver and executable-boundary vocabulary as components instead of
maintaining a second ABI-only expression language.

`CallLifecycleV1` separately describes borrows, consumption, transfer,
production, conditional initialization, updates, retain/release, and callback
escape. Provider-owned transitions bind interaction-contract identities. A
payload layout cannot silently stand in for ownership or lifetime evidence.

`CheckedCallProtocolV2` binds the canonical schema, data layout, V3 frame,
field-wise evidence receipt, lifecycle receipt, and optional projection
receipt. V1 remains an explicitly named compatibility artifact. An optional
`IdiomaticCallViewV1` can then project the faithful protocol into an
operator-reviewed C interface, for example a pointer/length view or an
out-parameter result. The faithful protocol remains available underneath that
view.

## Evidence and proposals

The PE32 IA-32 dialect checker derives an expected frame independently from
compiler output. Partial decoded observations are reconciled field by field;
no individual source must pretend to observe the complete frame. A pinned
compiler proposal cannot authorize an observation obligation. Callback machine
evidence is derived directly from transfer-v2 plus the resolved runtime profile;
the callback-authority adapter and its binary side input are absent.

This division is intentional:

- `abi/` continues to recover and reconcile physical ABI evidence for library
  regions and call sites, including compatibility with retained profiles;
- `calls/` is the checked boundary model consumed by lifting, callbacks, and
  source rendering;
- legacy word counts and source prototypes are not protocol authority.

New consumers should depend on checked call protocols. Existing ABI/profile
consumers can migrate incrementally as their evidence becomes strong enough to
construct the required layers without guesses.

## Operator workflow

Authored intent contains stable semantic choices: the subject, ABI dialect,
portable types, source names, lifecycle facts, and optional idiomatic
projections. Generated digests, frames, and receipts are rejected from intent.

The public workflow is:

1. `boundary propose` captures a pinned compiler proposal for review.
2. `boundary inspect` presents the target's checked artifact and repair frontier.
3. `boundary adopt` writes reviewed call intent without adopting generated
   authority. Component source uses the separate atomic `component start`
   transition; component seeds remain proposals until canonical intent exists.
4. `boundary check` builds the target-SDK protocol derivation.
5. `boundary status` aggregates non-authorizing work state by stable `kind:id`
   subject identity across calls, callbacks, exports, component operations, and
   services.

The expert `call-protocol-check` leaf is the low-level reproducible checker used
internally by `nix/call-protocol-workflow.nix`. Its output includes the full
artifact family and a faithful C header. Target declarations do not pass the
binary, machine IR, callback-authority artifact, callback protocol identity, or
a second copy of boundary intent into that phase. The target SDK owns those
facts and injects the validated executable transfer plan plus the remaining
workflow and external-environment bindings. The checker obtains the exact
machine-IR digest from that canonical plan; a protocol boundary declares only
its stable subject and layout intent.

The real CLI vertical exercises this path with its Win32 unhandled-exception
filter callback. The checked result is a `stdcall` function taking an
`EXCEPTION_POINTERS *`, backed by exact transfer/environment evidence.
Additional jq and DX-Ball boundaries should be added as ordinary protocol
instances; broadening the dialect checker is engine work only when their
transport cannot be represented by the existing graph, layout, frame,
relation, and lifecycle layers.

## Whole-range release conditions

A machine-import `dynamicRangeRelease` effect requires both
`world_effect_argument` (the allocation base argument) and
`world_effect_release`. The latter contains an explicit `success` selector
(`always`, `eax_zero`, or `eax_nonzero`) and an `argument_equals` list of
`{ "argument_index": N, "value": WORD }` constraints. An empty list is explicit;
missing conditions, unknown fields, duplicate argument constraints and out-of-ABI
indices are rejected. Typed operation world effects carry the same condition
under `release`, parsed by the same codec. Conditions survive checked-contract
serialization, exact profile matching and native range-rule lowering.

Argument constraints delimit supported calls and are checked before the host
call. A mismatch returns `SPX_CALL_UNIMPLEMENTED` with diagnostic `0x2206`, the
argument index, observed word and required word; malformed native condition
metadata reports `0x2205`. Result handling repeats these checks and removes the
range only when the declared success selector matches. `always` means every
normal return, including APIs with no result value; it does not establish that
an arbitrary pointer is a valid input. Missing conditions never imply `always`.

The existing VirtualFree row admits size zero and exactly `MEM_RELEASE`
(`0x8000`). Partial decommit and placeholder operations are rejected before
callthrough because the range inventory does not yet model those operations.
VirtualFree distinguishes decommit from releasing the original reservation and
returns nonzero on success. [VirtualFree contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree).
The existing [HeapFree](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree),
[FreeEnvironmentStringsA](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-freeenvironmentstringsa),
[FreeEnvironmentStringsW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-freeenvironmentstringsw),
and [UnmapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile)
rows also use nonzero success. The [CRT free](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/free?view=msvc-170)
row uses `always` because it has no return value.

This is native range-lifetime bookkeeping and an explicit supported-call
boundary. The ownership checks below extend native admission; neither mechanism
proves general partial page transitions, callback/concurrent lifetime safety, or Portable-C caller
preconditions. The fixed GlobalAlloc/GlobalFree contracts are described below;
this change does not promote their native callthrough profiles to portable
allocation proofs.

## Allocation producer sites

An `external_allocation` or `resource` locator can bind a group of producer sites
using one checked contract. Grouping requires the same import/interface identity,
exact profile binding, ABI, disposition and normalized effect contract. The
runtime inventory retains their digest as `contract_identity_sha256`. A matching
contract display id alone is insufficient. Conflicting result shapes, duplicate
physical site rules and competing object authorities remain blockers.

Group members retain their own instruction RVA, target selectors and argument
frame offset. The existing locator selector names the group's first producer;
each generated range rule carries that representative and its checked object
selector. Runtime registration checks those selectors before issuing an origin.
Every allocation instance still has its own generation, address and producer
provenance. Reusing an address at a different member site cannot revive a released
reference or expire an unrelated live instance.

This removes the former one-call-site restriction. It does not add an allocator
API contract or prove that a returned word is fresh, correctly initialized, or
owned by a particular caller. Those facts and the current linked runtime remain
separate qualification requirements.

## Native allocation ownership

Range results and whole-range releases can carry
`"ownership": {"family": "kernel32.heap", "owner_argument": 0}`. The family
names the allocator namespace; `owner_argument` is a captured argument index,
or null for a family without a per-call owner word. Checked profile loading,
site contracts, runtime lowering and rendering preserve this metadata. The
renderer rejects disagreement between release metadata and the range rule,
including a dropped ownership field. Typed operation contracts also check the
owner index against the operation's own argument count.

The current HeapAlloc/HeapFree rows use `kernel32.heap` and argument zero;
malloc/calloc/free use `msvcrt.heap` with no owner argument. Before invoking a
release, native admission requires the tracked base, family and captured owner
to agree. Unknown owned pointers, interior pointers, and attempts to release an
owned allocation through an unowned contract fail closed. Diagnostics `0x2210`
through `0x2214` distinguish malformed owner capture, family mismatch, owner
mismatch, untracked pointer and interior pointer. Failed host releases preserve
the allocation; successful releases expire its generation. Address reuse can
establish a fresh allocation under a different owner without reviving old refs.

Null allocation results register nothing. Non-null zero-size owned allocations
remain tracked and releasable, but grant no byte extent. Overlapping live owned
allocations fail with `0x2111`; unowned registration cannot overwrite an owned
base (`0x2112`). Ownership is retained only in the current native range inventory.
It is not a Portable-C allocator theorem or a general proof-world lifetime
transition. Heap destruction/reuse, exceptional allocator outcomes, concurrency,
reallocation, and Metapad's caller/proof integration remain separate work.

## Guarded fixed global allocations

The checked `GlobalAlloc` row now lives in the kernel32 runtime profile. Its
owned range result uses `kernel32.global-fixed`, argument one as the requested
extent, and explicit allocation metadata:

```json
"allocation": {
  "argument_masks": [{"argument_index": 0, "allowed_mask": 64}],
  "initialization": {"kind": "argument_flag", "argument_index": 0, "mask": 64}
}
```

Native admission permits flags 0 or 64 and rejects other bits before host
callthrough. This covers fixed memory, optionally zero initialized; movable
handles, obsolete flag combinations, reallocations and GlobalSize-derived extra
capacity are outside this row's supported domain. The distinction follows the
[GlobalAlloc contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalalloc).
The `GlobalFree` row uses the same family, its first argument as the base and
`eax_zero` as success, following the
[GlobalFree contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalfree).
Nonzero release results preserve the allocation inventory; null allocation
results register nothing. A non-null zero-size fixed result is tracked and
releasable without granting byte access.

The common allocation codec also represents explicit `zero` and `uninitialized`
initialization. Flag-controlled zero initialization must name one bit admitted
by an argument mask. Profile loading, checked receipt parsing and native lowering
reject malformed masks, unbound initialization flags and allocation metadata on
unowned or non-range results. Native diagnostic `0x2220` identifies malformed
allocation argument capture/table bounds; `0x2221` reports unsupported flag bits,
including argument index, observed word and admitted mask.

Initialization metadata describes the selected host contract. Native lowering
does not initialize host memory itself. Contextual proof-call admission still
rejects these effects until this contract is connected to the paired allocation
world and checked caller lifetimes. The fixed contract does not qualify movable
global objects, caller buffers, or the whole Metapad application.

## External range effects in contextual proofs

The external-service binding now retains the complete selected profile payload
as `external_effect_contract`. Proof-call specifications include this payload
in their behavior identity and in the trusted adapter receipt. Moving a physical
call site preserves that identity; changing its effect contract does not.
Missing payloads or missing memory/world effect categories fail before proof
world construction.

The current scalar-response call oracle has no allocation or release transition
model. It therefore rejects declared `dynamicRanges`, `dynamicRangeRelease`,
dynamic range results, and out-pointer range relations with
`proof_service_lifetime_effect_unsupported`. Release metadata or ownership fields
cannot bypass this check by appearing behind `world_effect: none`. Native range
registration and pre-call ownership checks do not justify a portable proof about
allocation freshness, freed references, initialized bytes or caller ownership.
This check concerns declared range effects; it does not complete models for
opaque resources, callbacks, or arbitrary external memory effects.

Python and jq receipt readers require
`declared_external_range_effects_checked: true`. Historical receipts without the
check are insufficient for current authority, even while pilot rebuilding is
deferred. Completing the allocator path requires checked lifetime transitions in
the shared proof world, including fresh/reused memory and borrowed aliases, bound
to the selected external contract and to discharged caller preconditions. The
same transition model must govern exact and source calls before this blocker can
be cleared.

The existing paired sparse proof world now contains bounded allocation-instance
primitives. A successful non-null birth records its family, owner, extent,
initialization mode and fresh logical generation. Successful release expires
issued references; failed release preserves them. Reusing an address cannot
restore an older reference or expose writes or shadow bytes from its previous
lifetime. Zero-size instances are releasable but grant no byte access. Raw
accesses must stay within a single live allocation when they touch tracked heap
storage, and an issued one-past reference retains its original allocation even
when an adjacent allocation appears. Paired memory comparison includes lifetime
state while allowing different write widths and history positions.

These primitives are not yet called by external-service lowering. They do not
establish allocator freshness against all incoming caller memory or the complete
native image, a correspondence between logical and native generations, incoming
heap ownership, or lifetime state across proof cutpoints. Generation numbers are
proof bookkeeping, not an exposed portable allocator result. The checked API
contracts, exact/source call integration and caller preconditions must establish
those relations before `proof_service_lifetime_effect_unsupported` can be removed.

Call replay now observes allocation lifetimes as well as bytes. Each call retains
the exact allocation count and one independently chosen allocation-index witness.
For a valid index, replay compares the saved instance's base, extent, family,
owner, logical generation, liveness and initialization mode with the source world
at that call. The witness is universally checked and never constrains a service
response. This uses constant snapshot storage per call rather than copying the
entire allocation table into every call. Lifetime comparison occurs before any
private-byte exemption. The comparator excludes write/shadow history positions,
which may differ for equivalent writes.

Both machine and typed replay use the same saved observation; typed exact
recording saves it too. An early source release cannot be hidden by equal zero
bytes or by a later exact release that makes the final worlds equal. Comparing
the final exact inventory at replay time would also reject valid executions, so
the immutable call-time snapshot is required. Both contextual receipt readers
require `call_allocation_lifetimes_checked: true`. Earlier receipts without it
cannot authorize activation. This closes a shared-oracle prerequisite; it does
not admit allocator APIs or establish incoming caller ownership.
