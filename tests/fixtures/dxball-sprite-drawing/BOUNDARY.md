# Binary-derived sprite drawing boundary

The pinned DX-Ball 1.09 PE32 is the only operation oracle. No original game
source or third-party implementation is used. `sprite-drawing` owns destination
selection (`bd60..bd6a`), transparent drawing (`bd90..bdcf`), and opaque drawing
(`bdd0..be0f`). These are complete cdecl entries.

Reuse the existing `font_state`, shared cleanup banks and live sprite/surface
objects. Destination is VA 434960; drawing uses cleanup's selected bank at
434968, independently of font selection at 43496c. Valid banks are 0..2 and
slots 0..254; the selected sprite, its surface and destination must be live.
Selection itself accepts null and only stores the surface identity.

Both draw calls preserve coordinate words, including negative signed encodings,
and return the exact 32-bit graphics result without retries. The graphics
service receives flags 0x11 or 0x10 and the original sprite object. Its source
rectangle aliases that object's offsets 20..35; it is not an independent value.
Services may mutate rectangle bytes, sprite metadata, selection or destination.
The adapter must preserve those effects and pointer identity. Calls are
synchronous; the supported input domain excludes invalid pointers and concurrent
mutation. No ownership, safety or unrestricted graphics equivalence is assumed.

Native cases compare call arguments, result words, shared objects, neighboring
font behavior and cleanup, including service-side mutation and source/destination
aliasing. Live integration uses the actual native heap and DirectDraw services.
The portable consumer uses a controlled graphics backend. Frames, audio and an
entire playthrough require separate integration observations.
