# Sprite capture and restoration

Binary authority is the pinned DXBall.exe (SHA-256
191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f).
Capture is cdecl RVA be10..c076 with slot, x, y, width and height words.
Restore is cdecl RVA bd00..bd59. No original game source is used.

Both operations use the existing cleanup table, sprite metadata, surfaces and
asset/font states. The two states share the same object table. The selected bank
is valid, slots are in 0..254, and service calls are synchronous. Coordinates and
HRESULTs retain their 32-bit encodings. Unnamed sprite and bank bytes are retained.
Capture disposes the previous slot, allocates a 45-byte native sprite, initializes
its known fields and requests a surface with capabilities 0x840. A creation error
returns with the partially initialized sprite installed. Allocation failure exits
1. The describe loop retries without a native iteration bound. No automatic repair
or stronger memory-safety contract is added.

The copy service receives the live sprite, not a copied destination rectangle:
its destination rectangle aliases bytes 20..35. The source rectangle is a local
four-word value and the source surface comes from the drawing state. Service
writes to the sprite and shared state survive return. The platform adapter uses
Blt flags 0x01000000 and a null effects pointer. The descriptor adapter preserves
size 0x6c; the native write of 0x1ff9ee is to descriptor flags, not its size.

Restoration visits all 255 slots in each bank whose retained mode equals exactly
1, skips null sprites/surfaces, ignores Restore HRESULTs and reloads that bank in
mode 1. Its reload service receives the bank identity, retaining the filename's
alias to the bank's 20-byte serialized name rather than making a snapshot part of
the component contract. The controlled adapter decodes a short terminated name
before invoking the existing lifted loader. Its cleanup/allocation/file services
do not mutate bank names, making this snapshot valid for that adapter. A backend
allowing such mutation must carry a live name view into the loader instead.

Native comparisons use actual machine operation bodies and controlled ordinary C
services. Source comparisons trap both original bodies and select the existing
loader, metrics, rendering and cleanup components. They observe sprite/table
contents, lifetime records, exact graphics/file calls, pixels, results and cleanup.
Finite cases cover creation and copy failure, retries and aliased rectangle writes;
allocation exhaustion and permanently failing describe calls are not exercised.
Passing these cases is practical comparison evidence, not universal qualification
or a complete portable game/backend.
