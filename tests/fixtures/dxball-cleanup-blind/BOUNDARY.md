# Binary-only cleanup boundary

Authoring used the pinned DX-Ball PE32 (SHA-256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`),
its disassembly, and the toolkit's public component/service interfaces. No
original DX-Ball source or third-party reimplementation was consulted. Existing
graphics fixture infrastructure and its bank layout were known beforehand;
the selected operations were previously unprepared. This is not a claim that
the operator had no prior knowledge of DX-Ball or of the toolkit.

| Component | Half-open RVA body | Inputs and effects |
| --- | --- | --- |
| cleanup-select | `bd70..bd7a` | cdecl word argument; store it at VA `434968`; no validation |
| cleanup-dispose | `c510..c59e` | cdecl slot; read selected bank; optional surface release; free sprite; clear slot |
| cleanup-clear | `bcc0..bd00` | clear count, select bank, dispose slots 0 through 254, for banks 0 through 2 |

Names are operator interpretations, not recovered symbols. Native EAX residue
is unobserved: examined callers discard these results. Stack/register calling
conventions are retained in the x86 adapter. All selected instructions are
ordinary integer, load/store, branch and call operations. Internal loop cuts
used for machine-C recovery do not become production APIs.

The state is three rows at VA `433d18`, stride `418` hex. Each row contains
255 sprite pointers, one count and six retained words. The selected bank is at
VA `434968`. Disposal reads a nullable surface pointer at sprite offset zero;
callers allocate 45-byte sprite objects (observed at `be2a` and `c18f`). The
remaining 41 bytes are transported and observed unchanged. The portable layout
uses actual pointers and carries those bytes without assigning invented field
meanings. The adapter gives each object a stable identity and preserves aliases.

`release` is the indirect call at `c53b`, vtable offset 8. `free_sprite` is the
call at `c577` to `e2a0`. Both are explicit controlled environment services;
their actual DirectDraw/allocator implementations and ordinary game startup
are outside this experiment. Service order, arguments, current bank, bank counts,
slot identity, object contents, surface references and live/dead objects are
observed. Releases and frees may change the current bank synchronously. Disposal
must reload the bank and slot after either call, exactly where the binary does.
No exclusive ownership or memory-safety assumption is silently imposed: a
second slot may retain a now-dead sprite pointer in a direct disposal case.

Premises: single-threaded calls, normal returns, valid initialized state, a valid
slot 0..254 for disposal and a selected bank 0..2 when dereferenced. Services
return normally and preserve the live objects required by subsequent reads;
the release callback may select another live sprite, leaving the originally
released sprite allocated. Selection itself accepts every 32-bit word. No
arbitrary reentrancy, concurrency, failed allocation, full heap model, or checked
summary is claimed. Cases include aliases, missing surface, empty slot, edge
slots, callbacks and calls from the unchanged native cleanup loop. Allocations
are controlled fixture objects with explicit lifetime tracking, not production
heap allocations. Each case starts a new process.

The original side executes the original instructions. The source side traps the
selected original bodies and installs ABI adapters to the authored C. In a local
supplier comparison the surrounding original cleanup consumer still runs. In
the connected comparison all three bodies are replaced. Neighboring code and
services remain explicit dependencies, not evidence of a complete game lift.
