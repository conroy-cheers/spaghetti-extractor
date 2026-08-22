# Checked atomics

Machine IR v3 represents memory as a graph of `read`, `write`, `rmw`, and
`fence` actions. `memory_events` remains provenance, but it cannot authorize a
candidate because separate read and write events lose atomicity.

The initial checked profile is `x86-pe32-user-wb-tso-v1`: IA-32 user mode,
write-back memory, TSO, and naturally aligned 1, 2, 4, or 8-byte accesses.
Split locks, page-crossing locked accesses, non-write-back memory, MMIO, and
thread creation are outside the profile and fail closed. Unknown memory is
shared. A private action may be erased from a concurrency signature only when
an explicit private-memory proof names that action.

The semantic dependency receipt pins ArchSem commit
`dccdcdaeb1fb44d11a5e9ac0b0a9f4391620e453` and its
`ArchSemX86/AxiomaticX86TSO.v` model. Spaghetti Extractor supplies predecoded
events from its checked PE32 instruction path; it does not use ArchSem's small
Sail decoder. Herdtools7 with `x86tso-mixed.cat` is a differential oracle, not
an authority source.

Preservation requires labeled event-graph isomorphism after proof-backed
private-memory erasure. In particular, compare/exchange is one RMW action and
has a write cycle on success and failure; only the written value is
conditional. Implementations made from an ordinary load/store pair or a CAS
loop do not match that graph.

Lifted C uses the opaque `spx_atomic_object` API in `spx-atomics.h`. Raw
`_Atomic`, `volatile`, inline assembly, and machine addresses remain confined
to generated runtime backends. A portable interface exposes the object as a
borrowed `atomic_object` resource. Its machine projection names one exact RMW
action, profile, width, and proved address; the generated adapter constructs
the capability and translates backend faults back into machine memory faults.
Thread lifecycle and scheduling stay at the external boundary; the engine
preserves memory-model-visible actions without pretending to create or
schedule threads.
