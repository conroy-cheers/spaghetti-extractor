# Canonical boundary schema

Calls, components, callbacks, provider services, and source rendering share one
target-neutral boundary vocabulary. New producers use `BoundarySchemaV1` for
structural types, signatures, value interpretations, references, views,
resources, and callbacks. `TargetDataLayoutV1` separately supplies the selected
target's size, alignment, field placement, padding, pointer width, and ABI
classification.

The separation is strict. A record does not acquire PE32 offsets merely because
one consumer checks a call boundary, and a machine frame does not become an
ownership contract merely because it transports a pointer. Recursive types are legal
through pointers; direct value recursion, implicit padding, incomplete stored
types, and stale content digests fail closed.

## Shared consumers

- `PhysicalCallFrameV3` binds register/stack/memory transport to exact canonical
  parameter and result paths. Hidden structure-return pointers are explicit.
- `CheckedCallProtocolV2` binds the schema, target layout, physical frame,
  field-wise evidence receipt, lifecycle receipt, and optional idiomatic
  projection receipt.
- `CallbackProtocolV3` binds both the registration API and invocation protocol.
  A callback embedded in a referenced record, such as `WNDCLASSA.lpfnWndProc`,
  resolves through the same portable value-path semantics.
- `PortableComponentInterfaceV5` references checked projections and lifecycles
  over the same signatures. Component state, effects, and services no longer
  need a parallel logical type graph.

Retired call type graphs, layouts, frames, and lifecycle records are not accepted
by production readers. New authoring and all production consumers use the
canonical boundary artifacts directly.

## Evidence

Boundary facts form a field-wise lattice: unknown, exact, alternatives, or
contradiction. Independent machine observations can prove complementary parts
of a frame. Compiler and decompiler results remain proposals; they cannot meet
an observation obligation. Conflicting authoritative facts produce a violated
receipt rather than source-order precedence.

Dialect rules constrain legal physical realizations. Aggregate return policy is
an explicit layout classification (`aggregate-register` or
`aggregate-memory`), not a size-only heuristic. This makes a PE32 jq `jv`
return select hidden-sret transport while still permitting a reviewed small
trivial aggregate in `EAX:EDX`.

## Target validation

The unified `boundary status|inspect|propose|adopt|check` workbench validates
boundary intent and reports stable `kind:id` subjects. It emits canonical
schema, layout, and frame artifacts plus a deterministic C header. The target
SDK's boundary workflow additionally cross-compiles selected idiomatic C
translation units with MinGW.

The jq target exercises its real 16-byte `jv` layout, copy/free/dump calls, the
`__setusermatherr` registration call, and its typed callback. The DX-Ball target
exercises `RegisterClassA`, the 40-byte PE32 `WNDCLASSA` layout, its interior
`WNDPROC` field, and the stdcall callback frame. These checks compile C; they do
not require Wine or claim behavioral equivalence to the complete programs.
