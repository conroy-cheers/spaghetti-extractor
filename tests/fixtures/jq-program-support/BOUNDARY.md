# jq program support

The first twenty entries cover UTF-8 conversion/scanning, immutable opcode
descriptors, bytecode disassembly/destruction and retained source-location objects.
The four ordinary C files are source-assisted from pinned jq 1.8.1 under COPYING.
They reuse the existing jv, bytecode and locfile layouts rather than reconstructing
objects or inventing production APIs.

UTF-8 input spans are borrowed live bytes. Cursor outputs are interior pointers
into that same buffer, or NULL; invalid/truncated sequences, untouched output
parameters and encoder writes outside the selected output slice are observable.
Backtracking preserves the original one-byte special case. The portable code
avoids forming a pointer before the buffer or past its extent while preserving
the original results. Encoding accepts the original code-point domain, including
surrogate values; it does not introduce stricter validation than the native API.

Opcode descriptors are immutable objects with process lifetime and stable
identity within one implementation. Bytecode arrays/graphs are well-formed input
from the compiler. Parent edges and shared globals are borrowed by child nodes;
root destruction alone owns the global symbol table. Constants/debug values use
the existing consuming jv conventions. Disassembly observes exact emitted bytes.

Source-location creation copies the input bytes and owns filename, data and line
map. Retain aliases the same object and increments its reference count; freeing
one alias preserves the others. Diagnostics borrow a live jq context and invoke
its real error callback. Variadic arguments remain a live va_list for the call.
The unused error field is not initialized or read by this module, as in the
original. Lengths and indexes fit the original signed integer arithmetic.

Values, allocation, formatting, compiler and interpreter are executable neighbor
dependencies. Direct cases observe byte effects, pointer offsets/aliases, frames,
reference counts, diagnostics and allocation lifetime. Real compiler consumers
exercise two jq contexts, nested closures, execution, disassembly and teardown.
Native source checks disable all selected old bodies and their selected private
helpers. Passing tests and declared relationships are not checked formal summaries.

The profile excludes corrupt pointers/graphs, invalid API kinds, allocation
failure, concurrent mutation, arithmetic overflow outside the original valid
domain, and arbitrary assertion/CRT behavior. Original behavior on invalid UTF-8
and the documented unusual edge cases remains included. Strong qualification is
separate from this practical comparison and source delivery.

Home lookup follows the original Windows precedence: HOME, USERPROFILE, then
HOMEDRIVE plus HOMEPATH. The environment is borrowed only during the call, and
returned strings copy its bytes. Only the ~/ prefix expands. Expansion consumes
one input reference while preserving other aliases; embedded NULs retain the
original formatting behavior. Environment mutation must not race these calls.
Memory search borrows exact
byte spans, permits aliases and returns an interior pointer without mutation.
As in the Windows binary, an empty haystack yields NULL even for an empty needle.
Lengths fit the original 32-bit size_t and name expansion's signed byte lengths.


The path refinement adds jq_realpath and the existing dirname/basename runtime
entries. Canonicalization uses the original 260-byte destination capacity,
consumes one jv path and preserves that input reference on expansion failure.
It is lexical, including nonexistent paths; input aliases remain intact. Path
parts borrow writable NUL-terminated strings. Results may alias those strings,
read-only literals, or dirname's declared module scratch buffer, which remains
borrowed only until the next dirname call. Calls sharing that buffer cannot race.
The native harness observes returned strings, input frames and alias classes.
CRT scratch allocations are kept separate from observed jv allocations.

The shared C library adapts Wine 11.0 path collapse and MinGW-w64 path parts;
retain LGPL-2.1-or-later and public-domain notices with the source. UTF-8 and
single-byte path encodings are admitted; DBCS path encodings are not qualified.
Windows uses its actual current/per-drive directories. The POSIX environment
adapter maps a logical Windows namespace to host paths: Z defaults to /;
SPX_WINDOWS_DRIVE_X and SPX_WINDOWS_UNC_ROOT configure drives and shares,
SPX_WINDOWS_CWD and SPX_WINDOWS_CWD_X describe current directories. Unknown
mappings fail explicitly. These environment declarations must describe the same
filesystem state as the consumer; they do not imply proof of OS equivalence.
