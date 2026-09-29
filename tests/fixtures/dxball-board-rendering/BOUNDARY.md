# DX-Ball board rendering

Pinned PE32 entries: full board 0x405a90..0x405ac4 and cell
0x405ad0..0x405c1d, with the cell dispatch table at 0x405c20. Authoring uses
executable instructions/data and retained assets, without original game source.

The renderer borrows the existing menu/scene/font objects and byte-backed board
set. Cell coordinates are 0..19. Each grid byte is admitted, including values
outside the tile vocabulary. The complete saved collection remains a frame;
the current board can change through an explicitly synchronous service callback.
The outer operation selects the current back surface once, then visits columns
before rows. Each cell reads the current grid byte and scene state at its turn.

Tiles 1..22 use the native sprite mapping. Tile 0 always copies the background;
tile 7 copies it only in scene 1 and draws sprite 19 otherwise. Other bytes cause
no drawing. The native sign extension and unsigned dispatch bound give that same
behavior for all bytes 128..255. A zero mode records the 30 by 15 damage rectangle
even if nothing is drawn; every nonzero mode suppresses that call. Graphics
return codes are ignored. The source and destination can refer to the same live
surface. Pixel backing and object identities are preserved by the existing
graphics boundary, not inferred from reconstructed addresses.

Services may change shared board, scene and destination state synchronously.
The next cell observes those changes. A background-copy service receives the
actual local cell rectangle; a permitted change to it remains visible to the
following damage call. Native sprite metadata/graphics services retain their
existing contracts. Local cases use owned surfaces and compare ordered graphics
and damage calls, final bytes and shared state. The real editor integration uses
the actual platform services. These are finite practical comparisons, not
universal proof or complete platform portability.
