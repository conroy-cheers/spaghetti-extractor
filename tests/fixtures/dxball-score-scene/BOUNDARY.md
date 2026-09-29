# DX-Ball score screen

The pinned PE32 score-screen entries are enter 0x409410..0x40950d, redraw
0x409510..0x409698, update 0x4096a0..0x4098d7, key 0x4098e0..0x4098f7,
draw-table 0x409900..0x409a25 and edit-name 0x409f80..0x40a0a7. The shared
leave entry remains the existing menu component. No original sources were used.

The screen shares the existing menu's current score and scene/animation/font/
surface objects, and the score-table component's fifteen byte-backed records and
closed file identity. The 40-byte name buffer has independent retained padding;
length is in 0..30, its indexed terminator and first NUL agree, and table names
terminate in their 40-byte fields. Corrupt nonterminated names and invalid length
indices are outside this boundary. Blink/entering/show flags retain their actual
integer values; equality-to-one and nonzero tests remain distinct. The shared
shift flag equals one to request uppercase; keyboard codes use their low byte.
ASCII letter conversion reflects the original program's default C locale.

Scene services own surfaces, loaded banks, file/image decoding, damage, frame
presentation and music. The existing font component supplies text and widths;
the existing score table supplies loading and insertion. Timers return explicit
external values. Standard C decimal formatting implements the native unsigned
base-ten conversion. Name and table backing remains live across services.

Callbacks are synchronous: redraw may reenter the selected screen with the
current shared state. Adapters transport this state before and after native
services; native pointers alone are not substitutes for retained record bytes.
The screen does not allocate or invent a production API between its helpers.
Local consumers use controlled file and graphics services with real C callees;
normal consumers use actual platform services. Finite comparisons and declared
contracts are practical evidence, not strong qualification or full playthroughs.
