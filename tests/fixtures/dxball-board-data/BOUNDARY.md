# DX-Ball board data

Pinned PE32 functions: load collection 0x403d50..0x403d90, save collection
0x403d90..0x403dd0, tile-to-sprite mapping 0x403dd0..0x403ecc, select board
0x403ed0..0x403ef4 and store board 0x403f00..0x403f24. These real entries serve the
board editor and gameplay. Only original binary instructions/data and assets are
used; no original source or third-party implementation is consulted.

The shared representation is a live current 20-by-20 byte board and fifty saved
boards. It preserves every byte, including unknown tile values. The current grid
at 0x42ca60 and the collection at 0x42cdf8 are disjoint. Index arguments for copies
are in 0..49, as maintained by the editor; out-of-range memory corruption is not
assigned invented safe semantics. The scalar sprite mapping accepts every u32,
returns the mapped value for 0..22, and otherwise preserves the input.

Load/save open the supplied name in binary mode, transfer exactly 20,000 bytes
as one-byte elements, ignore the transfer count and close. Failed opens set the
shared file cell to null. Short reads retain the unread suffix of the actual
collection; short writes affect only the written file prefix. The current board
is unaffected. The global at 0x434964 retains the last FILE identity after close,
shared with score/asset services; closed storage must not be dereferenced.

Services are synchronous and nonreentrant, and mutate collection backing only
through the explicitly supplied byte view. Names are live, terminated and
unchanged throughout the call. Live adapters preserve the native shared file
cell and map observed identities to wrappers; they do not infer file contents
or lifetime from an address. Portable consumers own the actual byte arrays.

Local native comparisons retain current/saved/disk bytes, frame canaries, file
identity/liveness and service order. Actual program callers use the original CRT
and assets. Finite comparisons are practical evidence, not strong qualification.
