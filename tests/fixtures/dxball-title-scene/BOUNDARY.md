# Title scene lifecycle

The pinned DXBall.exe (SHA-256
191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f)
is the authority. Existing cdecl entries are enter a0b0..a1fa, redraw a200..a50e,
update a510..a5e1, key a5f0..a605 and leave a610..a6ba. Key and leave accept one
32-bit word. All return void. Scene 4 uses these through the existing game-flow
dispatch. No original source is consulted.

The scene borrows the existing animation, font, sprite-bank, palette and flow
objects. Structural object links stay valid for the whole call. Surface identities
refer to live backend storage; primary, back, flip, overlay and software surfaces
can alias. The message is readable and terminated, with length fitting uint32_t;
the existing animation contract governs its samples, indices and palette widths
(0..160). The 66-entry palette rotation table is mutable shared storage, not a
reconstructed pointer. Presentation mode at 417a04 differs from windowed mode at
434998. Mouse coordinates are signed words: x clamps to 8..599, y only to a
maximum of 447. Negative y survives. Key values are ignored. Leave reason zero
stops sound but retains banks and graphics.

Services are synchronous and return. Callbacks may mutate shared fields or change
surface aliases, but do not invalidate borrowed objects or structural links.
Rectangles, asset names and text bytes are borrowed read-only for that call and
are not retained. Text lengths preserve the binary's explicit spans, including
padding and terminating bytes. Native return values that the scene ignores remain
ignored. Graphics flags, inclusive line/fill endpoints, operation order, nested
redraw dispatch and post-callback field reads are preserved.

Local comparisons retain the actual five native bodies and compose real font,
animation, destination and cleanup implementations. They use controlled file,
audio, fade, damage and presentation services with owned pixel storage; font
services observe glyph geometry. These controlled services are explicit test
boundaries, not claimed replacements for PCX loading, DirectDraw or audio. Normal
game integration uses the actual existing PCX/loader providers and native platform
services. Observations include per-operation state, full palette/rotation bytes,
pixel hashes, final pixels, ordered service calls and font/animation interactions.
Finite cases do not qualify all rendering, audio, asynchronous callbacks, device
failure, allocation exhaustion or arbitrary playthrough behavior.
