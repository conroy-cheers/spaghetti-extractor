# Sprite bank loading (`c080..c510`)

This is recovered from the pinned executable and exercised with its shipped
Sysfont.sbk, Sfont.sbk and Thefont.sbk assets. No original source is consulted.
The ordinary C loader shares the existing cleanup objects and font consumers.
It reads little-endian count/width/height/baseline words, a character byte and
width*height pixel bytes. It creates color-keyed surfaces, copies the input rows
bottom-to-top using the returned pitch, and leaves padding untouched.

The environment implements file reads using C stdio and graphics/allocation using
ordinary C adapters. Original and replacement use the same environment: native
CRT entries are intercepted for fopen/fread/fclose/malloc/free, and COM calls
are routed through typed methods. The original loader and font bodies supply the
oracle. All selected bodies are removed on the source side. Asset bytes and all
published sprite metadata, file progress, allocation sizes/lifetimes, service
ordering, surface bytes including padding, rendering calls, and cleanup effects
are observed. This is finite executable comparison, not a checked heap summary.

The reviewed domain is readable complete files, at most 254 records, names below
20 bytes, nonnegative bounded dimensions, successful file open/allocation and
returning synchronous services. Fresh allocations contain known bytes; allocator
internals, arbitrary allocation failure, malformed/truncated files, overflowed
native name copies, nontermination and real DirectDraw rasterization are outside
these cases. Resource failure is represented by nonzero surface-creation results;
describe/lock also return retry statuses before succeeding. Read-only rectangles,
no retained stack views, and no service mutation of the bank selection are the
environment conventions for this loader, not inferred properties of opaque C
pointers. File and pixel allocation identities remain live as observer tombstones
after close/free; the program cannot reuse their storage in these executions.

Preserved quirks matter: the loader fills slots 1..count but publishes count,
so font lookup's strictly-less-than comparison excludes the last loaded slot.
Initial disposal visits slots 1..253, leaving 0 and 254;
an empty bank leaves its previous count/metadata; creation failure returns without
closing the file, freeing its pixel buffer or restoring the previous bank. The
native incidental return word is not observed: the retained callers use this as
a void operation. Direct source termination uses C exit(1) for open/allocation
failure, but those paths are not claimed by this case domain. Shared CRT FILE
internals are not transported across original and replacement allocators.
