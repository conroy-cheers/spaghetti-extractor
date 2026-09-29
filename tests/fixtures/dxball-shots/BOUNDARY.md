# Shot lifecycle boundary

The pinned executable entries 0x4069c0..0x406aeb, 0x406af0..0x406cb3 and
0x406cc0..0x406d26 move shots, fire a pair and remove the current shot.
They borrow the existing motion/gameplay/menu/sprite/board objects. The existing
play_shot records contain four payload words and next/previous pointers; their
roots, retained word and count keep their existing gameplay owner. Impact
velocity and piercing keep the motion owner. No new shared representation is
introduced.

Allocation returns opaque backing storage sized/aligned for a play_shot, with
four readable payload words. Its contents are not assumed zero. Ordinary C
converts that storage to the existing record type; no new incompatible shot
record tag is introduced. Disposal consumes that allocation identity. Both are
synchronous services that can change shared state. Newly allocated links are
initialized by the component; old coordinates remain retained until movement.

Allocation failure calls the existing termination service with status 1. A
returning test backend must leave a live current shot, because the native code
continues through that pointer if termination returns. Normal termination uses
the original nonreturning runtime service. Comparison of a returning test
backend is evidence for the call and continuation, not process-exit coverage.

Randomness, brick hits, sound and panning remain ordered services. Callbacks may
change current roots, payloads, metadata, bank aliases, board bytes and counters;
the shared object chain stays live and retains identity during an operation.
Lists are finite and links followed by the operation refer to live records.
Free callbacks may change surviving roots and the shot count. Movement advances
again after removal, including its skipped successor and final root reset.
Null removal still decrements the count with 32-bit wrapping.

Sprite slot 32 is valid. Movement interprets coordinates and width with native
signed arithmetic and 32-bit wrapping, then divides by 30/15 toward zero. Any
board byte actually read must lie within the existing 400-byte board; the native
linear indexing is retained, including valid cross-row aliases. A brick backend
may require a narrower coordinate domain, made explicit by its consumer.
Firing materializes the executable's binary64 -0.425/0.43 products in the target's
nearest/53-bit floating mode before truncation. Native allocation payloads and
all followed object bytes must be readable.

These are practical comparisons, not checked general heap summaries or strong
qualification. Any semantic integration discrepancy must be reproducible locally
or through a small connected consumer without starting the complete game.
