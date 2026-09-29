# Round cleanup and gameplay departure

Native clear 0x408fd0..0x409221 and scene leave 0x408f70..0x408fcb dispose gameplay
objects. Clear owns private typed removal bodies 0x409230..0x409286,
0x409290..0x4092e6, 0x4092f0..0x409346, 0x409350..0x4093a6 and
0x4093b0..0x409406. The pinned executable's direct calls to those helpers are
all inside clear. They become private typed C helpers, not synthetic production
APIs. List/record types remain those of the existing components.

The shared state borrows progression, powerup, particle and explosion objects.
Progression and powerup refer to the same motion/gameplay state. Brick and explosion
owners retain their existing projections into the frame's opaque effect roots;
adapters synchronize these views at component and service boundaries. Full record
payloads, links, root identities and lifetimes are preserved, not reconstructed
from pointer identities alone.

Disposal order is shots, live balls, brick effects, live events, pickups, particles,
staged balls, queued cells and explosions. Each list starts at its current cursor,
which may be the head, middle, tail or null. Null current does not imply an empty
first/last pair; clear does not select the head. Each unlink updates neighboring
links and roots before synchronous free. It rereads the current cursor after the
callback, which can redirect, stop or extend later work. Reintroducing an object
into an already processed list does not restart that earlier phase.

List retention words and gameplay counters are not reset. Free consumes exactly
one live record allocation and may mutate surviving shared state; it must not
leave a live reference to disposed storage. The source service's opaque storage
pointer is the complete existing typed allocation, transported by the adapter.
Comparisons exercise finite, well-formed list graphs and terminating callbacks.

Full leave conditionally fades only when no transition is pending, clears the
current back and primary surfaces, releases sounds and sprites, stops music,
then disposes lists. Each surface is read at the native callback boundary.
Partial leave performs only list disposal. Shared object identity remains stable
during callbacks even when contents, surfaces, roots and counts change.

Concrete comparisons are practical evidence, not strong qualification. Every
semantic integration discrepancy requires a retained local or small connected
reproduction without the complete game workflow.
