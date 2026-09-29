# DX-Ball damage tracking and presentation

Source-blind inputs are the pinned DXBall.exe instructions and literal data.
The twelve contiguous entries at 0x401000..0x401a16 own damage reset, transparent
and opaque tracked sprites, current-page marking, background erase, both-page
damage, restoration, background/destination selection, presentation, flushing
and selection sorting. Rectangle overlap at 0x40d5e0..0x40d6a8 is an additional
natural entry used by flushing. These are one replacement group with ordinary
internal C calls, not synthetic production APIs forced by proof cuts.

`damage_state` owns two interleaved 1000-rectangle histories, 2000 pending
rectangles, their 2000 sorting keys, counters, selected page and timing state.
It borrows existing scene/title/font/sprite objects and live surface handles.
The drawing destination is the existing title software surface, not another
independent view. Surface slots may be unbound at reset or setter boundaries;
operations invoking graphics require the corresponding live surfaces. Observers
must preserve this distinction rather than dereference absent handles.
Counts are 0..capacity and page is 0 or 1 at entry and after
callbacks. Sprite bank/slot references must designate live objects; their pixel
and metadata storage outlives synchronous service calls. Direct sort admits valid
inclusive subranges and empty ranges (including 0,-1). Rectangle coordinate words,
flag words and timestamps use exact 32-bit arithmetic and signed tests where the
original does. Overflowing, inverted and odd rectangles are not silently repaired.

Callbacks may change queue bytes/counts/page, flags, sprite metadata and shared
surface selections synchronously, preserving these storage/lifetime limits.
Graphics receive the actual queue rectangle or the original local by-value copy;
source and destination rectangle pointers can be identical. The sprite service
receives its live metadata object, preserving the embedded rectangle's identity.
Changes to sprite dimensions during drawing do not change the already captured
damage extent. Restoration rereads the page and count after each graphics call;
flush observes appended work. Queues and sorting keys remain observable after
draining. Reset clears only the histories, pending buffer, counts and page.

Graphics, clock, wait, flip and recovery are explicit synchronous services. Blit
results are ignored by the original. Flip retries only its specific busy code;
surface loss calls recovery and returns without an automatic retry. Progress
depends on the environment eventually ending a busy sequence and not perpetually
appending work. Local comparisons use owned pixel storage and controlled service
responses. The backend records invalid rectangle calls and returns an error
without accessing pixels; this does not assert that every real graphics backend
has that behavior. No UI, wall-clock scheduling or complete playthrough is needed
to execute the original entries. Live integration and portable platform delivery
remain separate obligations.

Each semantic discrepancy discovered during whole-game testing must become a
retained component, boundary or small connected regression. If this boundary
cannot express the required state, lifetime or interactions, that is a tooling
gap; merely lacking a previously chosen input is a coverage gap. Comparisons
provide practical finite evidence, not universal proof or activation authority.
