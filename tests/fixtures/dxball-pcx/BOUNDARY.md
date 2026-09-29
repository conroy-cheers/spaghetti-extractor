# PCX image and palette loading

Authority is the pinned DXBall.exe, SHA-256
191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f.
No original source is consulted. Entries are cdecl RVA 2490..270d (surface,
filename, palette mode, x, y), 2320..23da (current palette, filename) and
23e0..2481 (staged palette, filename). Native callers discard EAX.

This is the binary's decoder, not a replacement standards-compliant PCX library.
It reads 128 header bytes, treats x/y maxima as signed 16-bit values, wraps a row
after x-max plus one pixels, and decodes while the count is at most x-max*y-max.
The final run is not truncated at that threshold. Header minima, plane count,
bytes-per-line and format markers are ignored. Prefix c0 consumes another byte
and emits zero pixels. EOF narrows to ff. Signed clipping and 32-bit coordinate
wrap are retained. Lock retries without a fixed iteration limit. The dimensions
and pitch used for writes come from description before locking, even if Lock
returns different fields. Missing files, descriptions without initialized fields,
permanent lock failure and inaccessible pixel storage are outside this boundary.

A successful graphics backend exposes live writable storage covering every
admitted clipped offset. Pixel format is eight bits per pixel with nonnegative
dimensions/pitch and valid backing for width/height. The controlled adapter
observes full storage, including untouched padding and guards; it does not replace
the decoder with a precomputed expected image. The live adapter uses actual
DirectDraw allocations. Unlock ends the pixel view's lifetime.

The buffered file view carries a live cursor and a 32-bit available-byte count.
Reads decrement that count, consume the represented backing buffer for nonnegative
counts, or ask the backend to refill. The backend owns buffer storage until the
next refill, seek or close; its callback must update the view, not reconstruct a
pointer without contents/lifetime. File services change file state, not palette
or graphics memory. This preserves ordinary buffered I/O without one instrumented
service event per input byte. Native adapters preserve the CRT cursor/count; no
CRT layout is exposed in the portable component beyond this reader abstraction.

Palette loading seeks -768 from EOF and reads RGB triples, preserving each fourth
flag byte. Palette mode one loads current entries at native VA 42c148 and applies
them; mode two loads staged entries at 42c548 without application. Other modes
leave palettes alone. The apply service receives the live current palette,
including its flags and any callback writes. Short/malformed streams keep the
binary's behavior within the admitted file and memory domain; no safety repair is
silently introduced. These finite comparisons and explicit assumptions are not
universal qualification or complete image-format validation.
