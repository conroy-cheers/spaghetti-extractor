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
3. `boundary adopt` writes reviewed intent without adopting generated authority.
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
