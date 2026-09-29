# Paddle movement and drawing boundary

The pinned PE entries 0x406730..0x4067a6 and 0x4067b0..0x4069b2 move and draw
the paddle. The component borrows the existing pickup/motion/play/menu/scene
object chain, sprite banks and software surface. It owns only animation phase,
last animation tick, spark deadline, previous spark width and spark sprite.
Paddle width, sprite, coordinates, input mouse coordinates, windowed mode and
powerup flags retain their existing shared owners. No copied representation
of those fields is introduced.

Movement uses signed comparisons, truncating half-width and 32-bit wrapping.
It applies the two clamps in native order, calls the cursor service only in
fullscreen when clamping changes x, rereads paddle x after that callback, then
sets the shared paddle sprite to 68. Drawing selects the animation variant before
advancing the phase. Spark deadlines use unsigned comparison. Cropping uses the
executable's binary64 constants 0.075/0.03 and truncation, including its untrimmed
damage width. Clock, random, cursor, graphics and damage calls remain explicit
synchronous services with ordered arguments, results and effects.

The shared object chain stays live and retains its identity during an operation.
Callbacks may change scalar fields, bank selection, sprite metadata, aliases,
surfaces and rectangles. Cached values and rereads follow the native call order.
The sprite divisor is nonzero and the signed quotient fits 32 bits; selected
slots refer to valid sprites. Cropping follows the target's nearest/53-bit
floating mode; the product is materialized as binary64 before integer conversion.
The graphics backend defines valid image rectangles and surface lifetimes.
Local controlled services observe values without imposing a new graphics policy.

Native mapping retains complete sprite payloads, bank aliases and all borrowed
scalar state. Concrete comparisons are practical evidence, not checked global
heap summaries or strong composition authority. Any integration discrepancy must
be replayable through a local or small connected consumer without game startup.
