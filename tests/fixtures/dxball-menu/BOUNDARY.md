# Main menu and dot animation

The authority is DXBall.exe, SHA-256
191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f.
Existing cdecl void entries (RVAs) are enter ae80..af76, redraw af80..b1e4,
update b1f0..b29c, key b2a0..b2ca, leave bbf0..bc90, initialize_dots b2d0..ba38
and animate ba40..bbf0. Key/leave accept a 32-bit word; key examines its low
byte. Leave is shared by scenes 0 and 3 and has one replacement body.

The menu borrows the existing scene/animation/font/palette/flow objects and live
surface backing. Its 287 dot records and 360 two-word offsets retain their native
layout values; the literal dot mask is recovered from native immediate stores.
Sine and cosine backing has 361 readable signed samples between -1024 and 1024,
unchanged during calls. Initial offset calculations use only indices 0..359 and
integer products divided by 1024 with truncation toward zero. Readable display
spans retain the exact byte counts, including padding. The last score is unsigned
and formatted as unsigned decimal. No original source is consulted.

Structural object links stay valid. Synchronous services may mutate shared
fields, replace surface aliases and change the font or selected bank; operation
order and post-callback reads are preserved. Rectangle/name/text inputs are
read-only borrows for the call. A successful pixel lock provides real writable
storage with sufficient pitch and extent, retained until unlock; each computed
dot coordinate must be in that storage and each phase lookup within 0..359.
Failure is retried as in the original. Permanent lock failure can therefore hang;
it is not replaced by success. A service cannot invalidate a live pixel lease.

Clock values are explicit inputs. Elapsed checks and the subsequent clock read
remain separate interactions; the native wrap and threshold decision belongs
to the elapsed service. Mouse clamping and button consumption match the title
scene except that a menu click requests gameplay. The low byte 0x70 requests
scene 2 only when input_ready is nonzero. Space has no effect. Leave reason zero
performs no cleanup; nonzero reasons release banks, sounds and the music track.

Local comparisons use actual original bodies with controlled clocks, platform
calls and owned pixel backing; existing font/drawing/cleanup units are composed.
Finite observations include text spans, shared records, palette storage, pixels,
callback order and cleanup. Live integration retains actual file/graphics/audio
services. Neither local cases nor bounded live workloads prove unrestricted
playthrough, audio or asynchronous device equivalence.

The older cleanup fixture's first guard at 433d14 is the menu's final offset
word. The connected consumer observes that alias as the actual offset value,
checks the native correspondence and retains the other three independent guards.
