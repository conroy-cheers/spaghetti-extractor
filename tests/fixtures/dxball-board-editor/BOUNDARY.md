# DX-Ball board editor

Pinned PE32 entries: enter 0x403570..0x403658, redraw 0x403660..0x403748,
update 0x403750..0x4039f7, key 0x403a00..0x403b54, palette 0x403b60..0x403bc4,
status 0x403bd0..0x403d41 and leave 0x403f30..0x403f6d. Only instructions,
literal data and assets from the pinned executable are used. No original game
source or third-party implementation is consulted.

The editor holds the selected tile (0x42ca18), board index (0x42ca54), and live
references to the existing menu/scene and board-storage objects. The current
400-byte grid and all 20,000 saved bytes retain their contents across component
calls. Copy indices remain 0..49. Status/palette drawing requires admitted sprite
slots; update stores the low byte of a selected tile without sanitizing it.
The last-file identity shares the existing CRT cell at 0x434964, including its
retained identity after close. The board component supplies actual load, save,
select, store and tile-mapping behavior.

Hit-region services share 25 records at 0x4349d8 and the count at 0x435cf4.
Editor initialization requests 23: native reset sets the count to 24 and clears
records 0..24. Definitions use records 1..22. Hit testing uses signed inclusive
coordinates, accepts any nonzero enabled word and chooses the last matching
record among indices 1 through count-1. Broader native region-table use is outside
this editor boundary.

Services are synchronous. They may change observed shared state or call redraw
synchronously; the adapter transports the full editor, board, menu and scene
state around these calls. Update rereads input flags and board index after
rendering. Ctrl means repeated drawing. Mouse buttons use exact values 1 and 2;
they are separate tests, so a service-induced change may trigger both paths.
Cursor coordinates use the original signed clamps and board edges are strict.
Key dispatch uses only the low byte. Backspace clears the current grid without
implicitly storing it; subsequent caller operations decide when to persist it.

The local graphics/file/input backend is controlled. It retains complete board
and region bytes, service order, text spans, pixel backing and file state. Its
board renderer and cursor are explicit services, not additional lifted game
entries. The normal-program save probe exercises the original editor with its
native board renderer, hit-region helpers, cursor, CRT and assets through the
previously prepared graphics/scene network. It does not select the new editor C;
that live integration remains a separate step. The runner now compares the
declared mutable board file's saved bytes. These target helper bodies and platform
backends remain dependencies until
lifted in their own right. Finite comparisons are practical evidence, not strong
qualification or complete game portability.
