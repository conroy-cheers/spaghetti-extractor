# jq value algorithms

This source-assisted component owns key enumeration, value ordering, stable
sorting, grouping, uniqueness, membership and recursive path deletion. Its eight
entries consume their `jv` arguments and return one owned value, except `compare`,
which returns an integer. `keys` and `keys_unsorted` consume only `first`;
other operations consume `first` and `second`. The output record's `value` field
is initialized by value operations and `comparison` by `compare`.

The existing shared value ABI defines reference counting and copy-on-write.
Callers retain aliases with `jv_copy`; mutations and release of the returned
value must leave those aliases usable and unchanged. Sort/group/unique require
arrays of equal length; keys requires an array or object; compare requires valid
values. Deletion and membership retain target error values and ownership rules.
Path arrays may contain numeric indexes, string keys and slice objects. The
10,000-level path limit, recursive traversal and target number conversions are
retained. This does not add memory safety for inputs on which the pinned target
has undefined or invalid behavior, including out-of-range floating-to-int casts.

Private C helpers and temporary sort storage stay inside this module. Shared
value constructors/accessors, number literal comparison, allocation, value
equality, get/set and error formatting are executable C services. Their code is
not duplicated in this component. The native adapter binds the two private
number functions by reviewed DLL RVA; portable assembly uses their existing C
provider. Decimal literal comparison, NaN ordering and the exact signed result
of comparison must not be replaced by a different number model.
Unequal string bytes yield -1/+1 under the pinned CRT; equal prefixes return the
length difference. The portable comparator implements that result explicitly.

The C sorting service carries the comparison/swap sequence of the pinned Wine
11.0 MSVCRT runtime. jq compares NaN less than itself, so substituting an arbitrary
ISO C qsort can change observable ordering. The shared `windows-sort.c` library
preserves the tested runtime algorithm without jq-specific types or callbacks.
This dependency is LGPL-2.1-or-later; its source notice and license accompany the
source project. Equivalence with other versions of the Windows CRT, including
their invalid-parameter callbacks, is outside this runtime profile.

The reference is the pinned jq 1.8.1 PE32 DLL. Native comparisons replace the
eight public entries and trap their former bodies and exclusively owned helper
bodies. The native slice helper also serves unmodified get/set, so remains there
for those consumers; the replacement has its own private C implementation.
Retained and generated cases observe results, errors, retained aliases and final
jq heap lifetime. Normal-entry consumers additionally exercise interactions with
the existing lifted network on x86-64 and AArch64.

Finite comparisons, declared C dependencies and the shared ABI are not formal
summaries or universal equivalence. Allocation failure, native stack exhaustion,
all malformed paths and untested platform-library behavior are not qualified.
