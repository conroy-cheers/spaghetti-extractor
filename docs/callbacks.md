# Checked callbacks

Callbacks are provider-owned capabilities, not raw function pointers. A
`spaghetti-extractor-callback-protocol-v1` contract describes one registration,
replacement, removal, or invocation action together with its callback
signature, instance key, sentinel meanings, lifetime, delivery timing, thread
relationship, and cardinality. The contract records observable concurrency
constraints; it does not invent an engine scheduler.

Static machine-import profiles V2 carry this protocol as one structured value.
The older independent `callback_source`, `callback_abi`, `callback_lifetime`,
`callback_result`, and `callback_behavior` fields are rejected in V2 profiles.
Legacy readers may derive their private adapter view from the structured
protocol while older profile formats migrate, but the structured protocol is
the source of truth.

Transfer-v2 plus the resolved external environment bind that protocol to the
exact registration event, target unit/RVA, physical frame, entry state, and
lifetime. The semantic object emits the resulting callback capability and
relocations once; semantic linking establishes rooted activation. There is no
callback-authority artifact or separate operator callback-target list.

Portable component interface V3 represents callbacks as distinct opaque C
handle types. It exposes ownership, nullability, logical parameters, and a
logical result, but no calling convention, stack cleanup, machine address, or
function pointer. Exact PE32 details live in a checked `callback_handle`
machine projection naming the protocol and semantic capability. Calls to an
operating-system or C-runtime registration API remain typed injected services,
so provider behavior stays at the environment boundary.

The generated backend uses the same checked capability lifecycle core as
atomics. Handles have a domain type, backend identity, generation, and live or
expired state. Replacement linearizes one provider instance: new admissions
use the new generation, while invocations admitted before replacement may
finish. Cardinality is scoped to a registration generation. Deferred and
externally concurrent delivery therefore remain representable without making
the extraction engine responsible for thread creation or scheduling.
