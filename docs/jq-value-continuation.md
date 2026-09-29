# jq continuation: value algorithms and relations

The continuation uses the existing component workflow to replace the remaining
`jv_aux.c` algorithms and jq's recursive value relations/object merging. The two
new modules provide 13 native entries. They reuse the existing value, number and
allocation services; ordinary C implements their loops, recursion and ownership.
No new checker, compiler, proof rule or artifact format is needed.

**Native comparison matches 85 value-algorithm and 59 value-relation scenarios.**
The standalone projects now select 33 components, retaining all 31 previous
component records/files. The combined x86-64 and AArch64 programs match 140 normal
CLI cases and 32 live-value scenarios. A separate C API caller compares the exact
integer result of 14 value comparisons against retained native observations.
These remain finite comparisons and source-assisted partial lifting, not complete
machine-code recovery or strong qualification.

## Boundaries and ordinary C

The [value-algorithm module](../tests/fixtures/jq-value-algorithms/README.md)
contains comparison, sorted/unsorted key enumeration, sort/group/unique,
membership and recursive path deletion. It consumes owned value references;
callers retain aliases using the existing `jv_copy` convention. Internal sort
storage and path traversal remain private helpers, without synthetic production
APIs. A local refactor puts the sort buffer and its length in a private C record
and shares its construction across sorting, grouping and uniqueness. Only that
translation unit recompiles; six neighboring objects are reused.

The [value-relation module](../tests/fixtures/jq-value-relations/README.md)
implements equality, representation identity, recursive containment and shallow/
recursive object merging. It uses public value accessors instead of copying
private heap allocation layouts. Identity still needs the shared `jv` handle
fields. Presence is checked separately from an invalid-valued object slot.
Retained aliases, reference counts and final heap lifetime are observed directly.

The pinned target has a surprising equality shortcut: equal-length slices sharing
one array allocation can compare equal even when their offsets differ. The new
C preserves it; identity still distinguishes the offsets. Native scenarios create
actual shared slices, rather than reconstructing pointers or assuming that their
contents/lifetimes survived transport.

Both modules remove their old public bodies and exclusively owned helpers from
the source backend. Native comparisons trap those bodies. Shared helpers still
used by native neighbors remain there: slice parsing serves original get/set,
and string equality serves original object lookup. The portable assembly has no
remaining algorithm bodies in `jv_aux.c`.

## Problems found through actual consumers

The first normal-entry comparison found different ordering for NaN sort keys.
The original produced `[2,0,3,1]`; the host implementation produced `[0,2,3,1]`.
jq's comparator treats NaN as less than itself, so the C library's sorting
sequence becomes observable. Changing the comparator to a mathematical ordering
would change target behavior.

The solution is the reusable C
[sorting provider](../tests/fixtures/portable-runtime/windows-sort.c), derived
from [Wine 11.0's MSVCRT implementation](https://github.com/wine-mirror/wine/blob/wine-11.0/dlls/msvcrt/misc.c).
It retains that runtime's comparison/swap sequence, with no jq types or platform
dependencies. Its LGPL-2.1-or-later notice, complete source and license accompany
the fixture and standalone projects. Both small and larger NaN workloads now
match, including grouping and uniqueness. This is a pinned runtime profile;
equivalence to every Windows CRT version or invalid-parameter callback is not
claimed. The comparator and output observations are not normalized to hide the
different ordering.

A direct C caller exposed a second library difference after CLI cases passed.
For unequal string bytes the pinned runtime returns -1/+1, whereas host `memcmp`
can return their arithmetic difference. The component now explicitly preserves
the target's integer result; equal prefixes still return the length difference.
The same 14 native comparison cases run through the exported C API on both
portable architectures. Initial mismatches are retained under `api-before/`.
This illustrates why PE32 replacement comparison alone cannot validate a changed
platform-library implementation; consumers must also exercise the delivered C.

Source assembly also exposed a small error in the jq build recipe. It treated
every removed definition as a public entry that must exist in the final binary,
including obsolete private helpers. The existing assembly manifest already
distinguishes entry mappings from replacement definitions. The recipe now uses
that distinction: every removed definition must be absent from the backend,
and every declared native entry must be defined exactly once. No new manifest
fields or relaxed entry checks were introduced.

## Evidence and costs

The retained experiment is `build/jq-value-algorithms-2026-09-27/`:

- `component/checked/` and `component/refactored/` record the initial comparison
  and local sort-buffer edit, with one compiled and six reused objects.
- `runtime-component/final/` records the final value algorithm/native comparison,
  including the sorting provider and explicit string-comparison result.
- `relations/final/` records 59 native cases for recursive value relations;
  its refreshed handoff reuses all six compiler objects.
- `program/` and `arm-project/` are the final standalone source projects.
  `program-delivered-build/`, `arm-project-delivered-build/`, the corresponding
  `*-delivered-run/` and `*-api/` receipts, and `result.json` identify exact inputs,
  original observations, preserved neighbors and phase costs. All 363 host and
  360 ARM files in the 31 previous component packages retain their bytes.
- `program-run/` and `arm-project-run/` retain the original NaN discrepancies;
  later successful runs do not overwrite them.

No pilot was rebuilt and no model/solver work was performed. Adding the shared
sorting provider changes four standalone objects, taking approximately 0.26
seconds on x86-64 or 3.62 seconds for AArch64. Integrating value relations changes
five objects, taking 0.57 or 5.77 seconds. These are tool execution costs; manual
boundary analysis, C authoring, runtime investigation and native adapter work are
not independently timed. First preparation remains more work than a local edit.
The final comparator repair compiles one native object and reuses seven, spending
about 0.064 seconds each in compilation and linking; 85 paired executions take
10.88 seconds, with runner startup recorded separately.

Validation is deliberately focused on native comparisons, normal program use,
the delivered C API and the changed assembly recipe. Three existing assembly
tests pass, as do the Nix repository-metadata, format-registry and
production-Python-lint gates and `git diff --check`. The broad proof matrix was
not rerun for unchanged engine/compiler internals.
All Wine applications ran in headless Wayland desktops. Unrelated dirty-tree
work and previous component packages are preserved.

## Remaining jq work

No significant tooling limitation blocks these two modules. The existing workflow
supports their boundaries, local C changes, native comparison, reusable runtime
library, source assembly and architecture checks. The small assembly-recipe bug
was fixed directly. The runtime differences were ordinary implementation work
under an explicit profile, rather than reasons to extend proof machinery.

Full jq is still incomplete. Significant source backend remains for builtins,
compiler IR construction, execution setup, primitive number/string/object
services and platform/math/time/regex support. This continuation did not turn
those dependencies into independently authored/reviewed components. The earlier
file/console runtime limits also remain, including the separately recorded
default stdout CRLF policy difference. Further progress should continue through
real operations and shared services, not count additional fixtures as full recovery.
