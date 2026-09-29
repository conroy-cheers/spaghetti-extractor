# Explosion lifecycle boundary

The pinned PE entries 0x404100..0x404117, 0x406d30..0x406e02 and
0x406e10..0x406ee2 reset, create and draw/expire explosions. Each record has
three payload words and next/previous links. The component owns the tail and
retained word; it borrows the existing gameplay explosion current/first slots.
The frame only copies/tests opaque effect identities. In ordinary C those slots
hold pointers to the same concrete explosion records, converted without changing
the existing shared declaration or dereferencing an incompatible record type.

The native adapter preserves root aliases through the existing address/view
mapping. It transports complete live payloads and links at service boundaries;
a reconstructed address alone is not evidence of preserved contents or lifetime.
The shared root storage stays live and keeps its identity during an operation.
List nodes followed by an operation remain live, and lists are finite. Synchronous
allocation, disposal, termination and sprite services may change surviving roots,
payloads, links and the retained word. Drawing rereads current after callbacks.

Allocation supplies an explosion record with three readable payload words; new
links are initialized by the C. Failure calls termination with status 1. If a
controlled termination backend returns, it must leave a live current record,
because native creation continues through that pointer. Normal termination uses
the native nonreturning runtime; returning test coverage does not claim exit
coverage. Disposal must not leave followed roots referring to a freed object.

Creation subtracts 24/23 with 32-bit wrapping, then applies the native signed
clamps, including wrapping sums used by the right/bottom checks. Drawing selects
sprite 145+frame, calls the graphics service, increments the current frame, removes
it at signed frame >=22 and advances again. Preserve the skipped successor and
final reset to first. The graphics backend determines which sprite indices and
coordinates it admits; controlled local services also exercise unusual integers.

Reset clears the four native root/retained words and does not free orphaned nodes.
The frame can independently reset current to first when considering level advance.
Ball contact and the last-brick helper create explosions; scene teardown unlinks
them separately. These external writes are part of the shared-state boundary,
not private state that neighboring components may assume unchanged.

Concrete comparisons are practical evidence, not checked general heap summaries
or strong qualification. Any semantic integration discrepancy must be replayable
locally or through a small connected consumer without complete game startup.
