# jq numeric value boundary

Eleven production entries own construction, literal representation, conversion,
comparison, sign changes and numeric release. This is source-assisted from the
pinned jq 1.8.1 jv.c under COPYING. The decimal payload layout is preserved on
native x86 and compiled for the destination ABI in standalone projects. A literal
owns its decimal digits, cached double and optional cached display string.

Reads borrow their input. Absolute value and negation return a new value without
consuming the input; release consumes exactly one reference. Shared aliases must
continue to see the same cached values and correct reference count. Literal text
is borrowed until its number is destroyed. Floating-point results retain their
binary representation, including signed zero and observed NaN payload behavior.

The existing allocator, decNumber arithmetic, dtoa conversion and thread-local
decimal context are explicit shared runtime dependencies. Native comparison uses
the original context and key, including its sticky status and lifetime; standalone
assembly exposes that same backend context with an ordinary C accessor. This
component neither duplicates the context nor claims to lift its thread lifecycle.
Decimal arithmetic and conversion libraries are not silently counted as authored
number code. Existing equality, value storage and other components stay selected.

The native harness disables the eleven original entry bodies and runs direct C
API scenarios plus real parser/interpreter consumers in two contexts. Observations
include literal strings, exact double bits, cache identity, aliases, reference
counts and residual allocation effects. Native glue preserves optimized x86
calling conventions, including the x87 double result. Private numeric helpers
still needed by original neighboring routines are not claimed as absent.

The compared profile uses the pinned decimal feature configuration, valid value
handles and the default floating-point environment. Allocation failure, corrupted
handles, concurrent access to one mutable payload and non-default rounding modes
remain untested assumptions. These finite comparisons are practical validation,
not a universal equivalence proof or activation authority.
