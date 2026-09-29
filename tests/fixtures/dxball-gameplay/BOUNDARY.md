# Gameplay frame and shared objects

The actual entry is `0x4044d0..0x404ac2` in DX-Ball PE32 SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
Authoring uses its instructions/data and the existing scene/menu declarations;
no original game source is consulted. This component owns one natural frame
operation, not synthetic control-flow APIs. Helper bodies remain explicit
synchronous services and are separate lifting work.

The frame borrows the established menu/scene objects, mutable ball/shot/event
lists, pending-cell bytes, numeric tables and scalar gameplay state. List cursors,
first and last pointers share the same objects as their owners. Ball nodes contain
thirteen 32-bit payload words then next/previous links; shot nodes four payload
words then links; event nodes kind/column/row then links. Native transport maps
complete initialized records and pointer identities, rather than interpreting
native pointer words as portable pointers. The list descriptor's fourth native
word is retained without inventing count semantics.

Lists are finite, internally consistent and acyclic when traversed, and reachable
objects remain live until the free service. Services may change cursors, shared
fields, list membership and contents between calls. The C must reread values at
the same points as the native routine. Free sees unlinking already completed;
its callback may alter the remaining list. Local observations include live/dead
identity, payloads, links, descriptor state and ordered calls. Event processing
preserves the original extra iterator advance after removal, including surviving
intervening nodes. This is not replaced with a conventional drain loop.

Kind-one events call `read_pending(state,column,row)`, which returns the byte at
`uint32_t(0x42cc10 + 20*row + column)` in the selected original address space.
It returns 0..255, preserves memory and performs no callbacks. The memory owner
must preserve aliasing and lifetime; a proven access failure can use the declared
nonlocal `memory-fault` outcome. Missing mappings are adapter capability errors,
not zeros or inferred native faults. The service called `hit_tile` is blast
creation at `0x406070`, not the collision hit routine at `0x405c80`. Its admitted
coordinates must agree with the selected memory backend. Earlier bounded
consumers retain their explicit in-grid domains; the brick network supplies
out-of-grid saved-board aliases and a mapped mutable page.

Sine/cosine views expose 361 signed words: negative multiples of 360 read
the extra native word at index 360. The native angle negation/remainder for
INT32_MIN can address beyond that view and is outside this admitted table span.
Tables are immutable during a frame's direct arithmetic, but service calls can
change the borrowed state before subsequent operations. The measured native
floating control word is `0x027f`: nearest rounding with 53-bit precision. The C
materializes each binary64 multiplication before `_ftol`-equivalent truncation
and retaining the low 32 bits. All possible signed table/speed products here fit
the signed 64-bit conversion after scaling. Local integer-boundary cases validate
the numeric behavior separately from game workloads. A different rounding or
precision environment requires a reviewed numeric boundary.

The frame only tests and copies identities for brick-effect/explosion lists;
it does not claim their payload or allocation semantics. Other workers keep those
objects and platform resources. Allocation, physics, audio and rendering behind
the declared services are not silently considered lifted. Helper names describe
their observed consumer role; native addresses remain in `prepare.py`.

Local original checks execute the real native frame with retained inputs and
controlled helpers. Source-side hooks replace the complete frame body. A missing
formal proof rule does not block these practical comparisons; it does not grant
strong qualification either. Any later integration discrepancy must become a
local or small connected regression. Inability to express its state, lifetime or
interaction without the full application is a tooling gap.
