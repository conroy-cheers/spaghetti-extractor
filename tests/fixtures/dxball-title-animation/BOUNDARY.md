# Title-screen scrolling, waves and palette cycling

Source authority is the pinned DXBall.exe, SHA-256
191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f.
Four existing cdecl void entries are replaced: scroll a780..a84e, wave a6c0..a77a,
wobble a850..a970 and cycle a970..aa4a (RVAs). The original title scene calls
these functions during redraw and frame updates. No synthetic production entry
or original source code is required.

The boundary borrows existing font, palette and flow objects, live surface
identities, a readable message buffer and 361 signed integer sine samples. Message
and sine backing remains alive and unchanged throughout each operation. Message
indices must remain accessible, including zero after the original signed length
test; length does not supply storage by itself. The table includes entry 360,
used for negative multiples of 360. Samples are between -1024 and 1024, and table
lookup arguments exclude INT32_MIN (whose native negation addresses beyond this
table). Palette width is 0..160 and resulting palette writes are inside 256 entries.
These bounds include the shipped title screen. The selected original numeric
helper remains real on the native side and reads the same initialized table.

The binary's sine helper multiplies an integer by exactly 1/1024 in x87; each
consumer multiplies by an integer and truncates toward zero. In this domain,
an int64 product divided by 1024 preserves the result without platform floating
point or an emulated x87 stack. Table generation remains the caller's job. This
does not claim a replacement for unrestricted x87 arithmetic or its status flags.

Scroll increments its index before drawing, substitutes width 15 for a missing
glyph and copies overlapping storage by four pixels. Graphics services preserve
the existing rectangle bounds, flags, object aliases and ignored status behavior.
Rectangles are borrowed read-only inputs for the duration of the call; graphics
services neither mutate nor retain those stack objects.
Callbacks may change the shared objects; wobble retains its initial fast/software
branch while reloading that branch's surface for the second call. File/graphics
backends own storage and lifetime; an object identity alone is not pixel storage.

Palette subtraction wraps bytes rather than saturating. Green/flag bytes remain
unchanged except for explicit callback writes. SetEntries receives first=48 and
count=width+48, retaining the binary's unusually wide application range. Windowed
cycle is a no-op. Services are synchronous and return; full driver behavior,
concurrency, floating-point flags, allocation failure and scene lifecycle are
outside these four operations. Assumptions and finite comparisons are not proof
qualification or authorization for production activation.
