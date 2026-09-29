# Particle lifecycle boundary

The pinned PE entries at 0x407b00, 0x407bf0 and 0x407db0 create, advance and
draw particles. Creation rejects signed x outside 21..618 and y outside 1..478.
The 44-byte native record has nine payload words followed by next/previous links;
the portable representation uses ordinary pointers. Roots are at 0x42ca28/2c/30.
Drawing borrows the software-surface slot at 0x41c728 (the existing title
state's software field), independently of the font destination at 0x434960.
A pointer to the shared slot preserves reassignment across callbacks. The PCX
surface-view interface is reused.

Allocation, disposal, termination, surface description/locking/unlocking and
damage registration are synchronous services. Callbacks may change roots, live
payloads, links and the destination. The implementation rereads state at the
same service boundaries as the native body. Allocation failure calls termination
with status 1; the production service exits. A controlled returning termination
service must supply a valid current object, matching the native continuation.

Lists are finite and acyclic. Live references, including those remaining after
callbacks, identify valid objects. A removed object is observed before free and
not dereferenced afterwards. Allocation supplies readable initial payloads.
List removal adjusts current, then iteration advances again; this can skip the
successor and is preserved. Gravity applies only when its flag equals one.
All counters and coordinates retain 32-bit wrapping and native signed branches.

Drawing assumes a successful lock eventually supplies a valid byte-addressed
surface with nonnegative pitch and space for every selected 2x2 particle. Its
lease persists until unlock, including callbacks. Dimensions/offsets fit the
native address arithmetic. Color uses its low byte. Describe and lock may change
the current object or destination; damage may change the next iteration. The
surface passed to unlock is the current destination, as in the executable.

Comparison adapters observe complete live payloads/links, roots, allocation/free
identity, surface identity, ordered service effects and exact pixel changes from
a known initial image, including padding/guards. These are concrete practical
checks, not checked heap summaries or universal memory-safety claims. Shared
state/lifetime failures must be reproducible locally or in a small consumer.
