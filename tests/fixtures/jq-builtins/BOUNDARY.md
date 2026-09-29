# jq builtin library boundary

The twelve existing entries are eleven consuming value binary operators and
`builtins_bind`. The latter owns the builtin jq source, parses and constructs its
instruction graph, registers C callbacks, then binds referenced definitions into
the caller's graph. Private functions remain inside ordinary C. This is a
source-assisted translation of the pinned jq implementation, under COPYING.

The immutable C callback table and builtin source text have module lifetime.
Native compiler graphs initially borrow callback descriptors; compiled bytecode
copies descriptors and retains callback addresses until the jq state is destroyed.
The code must remain loaded while any such bytecode can execute. No pointer is
reconstructed, and no heap contents or callback lifetime follow merely from a
compatible signature. Values use the consuming jv ownership convention; callers
retain aliases explicitly with jv_copy. The compiler, VM, objects, allocator and
runtime library remain executable dependencies at this boundary.

Math function availability matches the pinned PE32 feature set, including its
six unavailable functions. The calendar conversion keeps its 32-bit CRT range
even on hosts with wider time_t, and preserves supplied UTC formatting fields.
Regex uses the pinned Oniguruma ABI. Time, locale and
process environment are runtime dependencies; the compared profile is a controlled
single-threaded process. Allocation failure, malformed native pointers, unloading
live callback code, concurrent locale/environment changes and stack exhaustion
are outside this comparison. Real clock tests observe result type, not identical
wall-clock samples. Existing undefined behavior is not strengthened into safety.

Temporary allocation and release use the existing jv allocator pair; the native
adapter observes both sides of that pair. Comparison runs real compilation and execution in two jq states, retaining
bytecode/constant/debug structure, callback interactions, outputs/errors, input
aliases and allocation lifetime. Entry hooks select the authored module during
native execution and trap the superseded private handlers between those entries.
Portable assembly replaces the same production entries. These
are finite comparisons and explicit runtime assumptions, not formal summaries or
universal equivalence.
