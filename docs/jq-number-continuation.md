# jq numeric value continuation

The attempt continues from the validated builtin project using the existing
component workflow. `tests/fixtures/jq-numbers/numbers.c` lifts numeric storage,
literal construction, cached decimal/binary conversion, comparison, sign changes
and reference-counted release as one manageable C module. Its eleven entries
are integrated into both standalone source projects. No significant tooling
blocker was found, and no checker, compiler or assembly internals changed.

This is source-assisted work against the pinned jq 1.8.1 implementation, not a
claim that the source was recovered unaided from machine code. The active goal
remains full jq lifting, with a stop if a significant tooling limitation is found.

## Boundary and shared runtime

The number payload owns its decimal digits, cached double and optional literal
string. Read operations borrow the value. Absolute value and negation allocate
a result without consuming their input; release consumes one reference. Aliases
share the same caches and reference count. Existing equality, containers and
allocation components retain their contracts and implementation records.

decNumber arithmetic, dtoa conversion, allocation and the thread-local decimal
context remain explicit runtime dependencies. The native provider calls the
original context getter with its actual key and reviewed EAX argument convention.
The portable assembly adds an ordinary C accessor beside the existing backend's
private TLS state. Both paths preserve one shared context, including its sticky
status and lifetime. The module does not claim to lift that runtime lifecycle or
the arithmetic/conversion libraries. No new ownership or solver model is required.

## Evidence and issues encountered

Retained evidence is under `build/jq-number-lifting-2026-09-27/`:

- `numbers/final/` matches **53 native scenarios**: 42 direct numeric API
  cases and 11 real parser/interpreter cases. Each interpreter case uses two jq
  contexts.
  Observations include exact double bits, signed zero, NaN payloads, decimal
  strings beyond binary64 precision/range, cache identity, aliases, reference
  counts and allocation lifetime. All eleven selected old entry bodies are
  disabled; private helpers used by neighboring original code remain available.
- `program/` and `arm-project/` each select **37 components**. Their retained
  `host-final-*` and `arm-final-*` build/run receipts match **215 CLI
  and 32 live-value cases** through normal entry on x86-64 and AArch64/QEMU.
  The eleven backend bodies are absent and each production entry has exactly
  one provider in the final executable.
- `verify.py` and `result.json` bind the reuse audit: all **36 prior component
  records** and **454 host / 451 ARM exported files** remain unchanged.
  **170 host / 169 ARM live objects** retain both bytes and modification times.
  Only the two number objects, their adapter, observations and backend `jv.o`
  rebuild. All Wine processes run through a headless Wayland desktop.

The first native build needed the usual unused-header-helper reference. Direct
API comparisons then matched, while real interpreter consumers exposed a native
adapter defect: a GCC naked function with a by-value struct parameter emitted
argument-copying instructions before its handwritten trampoline. The adapter
now defines that trampoline at assembler file scope; it preserves general
registers and transports the double result through x87. The authored numeric C
did not need a behavioral change.

The comparison also initially attempted to parse jq's very large decimal output
as host JSON numbers. It now records the exact output bytes, preserving precision
and values outside the host parser's finite double range. The failed checks are
retained in `numbers/checked/` and `numbers/rechecked/`; the repaired run reuses
four objects and recompiles only the driver and native entry adapter. The final
source-format cleanup recheck reuses five objects; both projects are then applied
and exercised again with the exact final source binding.

## Cost and remaining scope

The final native check records 0.014s preparation, 0.064s compilation,
0.064s linking and 9.203s summed case execution. Its two Wine startups overlap
and take 5.696s wall time. These are automated phase measurements, separate from
the operator work of reviewing ownership, ABI layout, runtime access and adapter
failures. Model, solver and pilot-rebuild costs are zero.

Initial standalone integration build wall times are **0.52s host / 5.98s ARM**; initial full run
wall times are **11.38s / 19.83s**. The build receipts separate backend, component
and adapter compilation from linking; summed child times can exceed wall time.

Repository metadata freshness, production Python lint, format-registry validation
and `git diff --check` pass. The tree audit preserves 2,375 unrelated pre-existing
files; only the current-goal and documentation index receive pre-existing-file
edits. New files are confined to this fixture and report. `validation.json`
retains that audit and checks the final fixture source against comparison inputs.

Full jq lifting remains incomplete. Remaining core backend work includes string
and other value primitives, object mutation, decimal/TLS and conversion support,
Unicode/bytecode/location helpers, and the CLI entry/runtime profile. Vendor
libraries and platform services need explicit delivery choices. Finite practical
comparisons and assumptions remain distinct from formal qualification; none of
these receipts claims universal equivalence or unrestricted portability.
