# Runtime clock, wait and random state

The complete selected machine bodies are clock setup `40dba0..40dbd2`, clock read
`40db20..40db7b`, elapsed test `40db80..40db9f`, refresh wait `402240..4022a4`, seed
from clock `40ae30..40ae49`, bounded random `40ae20..40ae2d`, and the two statically
linked generator bodies `40ea60..40ea6a` and `40ea70..40ea9a`. They are from the
pinned DX-Ball image, SHA-256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
No original application source is used, and host `rand()` is not substituted.

The component owns explicit counter selection/divisor and generator state. It
borrows the existing bootstrap clock cell, application graphics slot and scene
refresh flag. Root C object identities remain stable during calls. Services may
synchronously change the scalars and resource slots; those changes are transported
at the actual call boundaries. The graphics resource must remain live while used.

Clock setup always sets the version query size to 148, ignores its API status,
and enables the counter unless the resulting platform word is exactly 1. It
does not reset the divisor. The original's incoming platform-word history is
an explicit input. Clock read likewise takes the two incoming scratch words as
an input and keeps that storage shared between frequency and counter queries.
Partial/failed writes retain that history. Query status is ignored for the
counter; only frequency failure takes the millisecond fallback. High words are
preserved at service boundaries but do not contribute to the returned time.
The divisor is floor(low frequency / 1000), cached and reloaded after callbacks.
Zero divisor causes the original arithmetic fault; C routes that outcome through
a nonreturning service, without invoking undefined C division. Local native
entry wrappers seed the reviewed stack slots. Normal platform adapters require
the counter output to be complete and diagnose a failure needing explicit caller
history, as existing capability-query adapters do.

Elapsed means `now < previous || now >= previous + delay` with uint32 wrapping,
not subtraction of two modular timestamps. Wait chooses its mode once. Positive
signed counts make either that many vertical-blank calls, reloading the device,
or poll the same elapsed rule with delay 17. The latter reads the shared previous
time after each clock callback and makes a separate final clock call before
publishing the next previous time. API statuses do not cancel vertical waits.
Zero/negative counts return; finite polling requires a progressing input schedule.
Local fixtures expose each clock callback. Normal runs retain the existing scoped
paddle/frame clock inputs and observe actual workload results, rather than equate
poll counts or absolute times from different process executions.

The generator is a uint32 recurrence with multiplier 214013 and increment
2531011, followed by the original 15-bit projection. Bounded random uses the
magnitude of its signed divisor (the dividend is always nonnegative). Zero limit
faults after advancing the generator. Clock seeding uses unsigned remainder 300.
Generator storage is shared across callers; it is not silently thread-local.

Finite comparisons, meaningful defect replay and real consumer execution supply
experimental evidence. Service declarations and these premises are not formal
heap summaries or a universal equivalence claim. Platform APIs remain explicit
services; these bodies alone do not deliver a standalone desktop game.
