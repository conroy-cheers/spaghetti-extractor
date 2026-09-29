# jq shared value-runtime continuation

The attempt continues from the numeric-value checkpoint with a substantial
connected C module: immediate and invalid values, array construction/append,
string storage/mutation/formatting/hashing, object mutation/iteration and reference
counts. Thirty-nine existing production entries use thirty-eight operations;
the two variadic formatting entries share a va_list operation. The implementation
is 769 lines of source-assisted ordinary C under the pinned jq license.

No significant tooling blocker was found. The work uses the existing public
component and candidate workflow, ordinary adapters and retained inputs. No
checker, compiler, artifact format or target pilot changes were needed.

## Boundaries and integration

The module retains the existing payload layouts, consuming jv conventions,
borrowed string bytes and iteration behavior. String writes preserve retained
aliases through copy-on-write and invalidate cached hashes. Object growth
transfers references before releasing the old table. Hashing explicitly reads
little-endian bytes, replacing the original host-word cast and its alignment
assumption. Array storage, numeric values, object allocation/unsharing/release,
Unicode conversion, allocation and seed initialization remain shared dependencies.

The projects had different retained selections: x86-64 already selected string
indexing, while ARM selected a separate string-hash component and seed accessor.
The default assembly supplies the new hash entry. The existing-provider variant
retains ARM's hash component and accessor, binding the other 38 entries to the
new module. Both adapters use one shared header. The choice preserves the actual
shared seed/cache convention, not merely the public signature.

ARM's remaining original `jv_string_indexes` is then replaced using the already
checked component used by x86-64. Its retained four-case comparison is validated
and reused through `candidate apply`, followed by normal program execution. No
new implementation or proof rule is needed. Both `jv.o` objects now contain only
the non-array release dispatcher, decimal TLS/seed initialization and ordinary
service accessors; the value operations have moved to selected components.

## Evidence and useful failures

Evidence is retained under `build/jq-value-runtime-lifting-2026-09-27/`:

- `values/transport-checked/` matches **47 native scenarios**: 35 direct cases
  and 12 real compiler/interpreter cases, the latter each using two jq contexts.
  Observations cover exact bytes, invalid UTF-8 repair, string self-append and
  retained aliases, hash caching, object growth/deletion/iteration, invalid slots,
  formatting beyond its initial buffer and allocation lifetime. All 39 selected
  original entry bodies are disabled during source execution.
- `program/` selects **38 components** and `arm-project/` selects **39**. Both
  match **227 CLI and 32 live-value cases** through normal entry, on x86-64 and
  AArch64/QEMU. Final receipts are `host-final-*` and `arm-indexes-*`; the latter
  follows the successful `arm-final-*` value-module integration.
- `verify.py` and `result.json` audit unchanged component records, exported C,
  object reuse, absent backend bodies and one provider per production entry.
  All **37 previous component records** and **469 host / 466 ARM exported files**
  remain unchanged. The ARM hash neighbor is retained. All Wine applications run
  inside headless Wayland desktops.

Native consumers caught a boundary-authoring error that direct API tests missed:
collapsing repeated local symbol names lost a function boundary, so the range for
`jv_get_kind` also trapped a neighboring `jv_is_valid`. The corrected declaration
uses all code addresses. No implementation behavior changed for that repair.

The first harness also passed Unicode directly through Wine's narrow argument
conversion. Hex encoding preserves the intended UTF-8 bytes. Changing this
representation correctly prevents claiming corpus reuse; the corrected harness
establishes a fresh baseline. The original process consistently exited with
signal 11 for a 5,000-character hex argument. Reconstructing exactly the same
2,500-byte formatting input from a compact descriptor passes on both sides. This
isolates the failure to the long argument representation; its lower-level cause
was not established. No target input or long-buffer exercise was removed.

The first ARM assembly rejected a duplicate seed accessor. The working project
remained unchanged. Selecting the existing hash provider through ordinary binding
declarations resolves the conflict. Failed preparations and transactions remain
available beside the final evidence.

## Costs and remaining work

The successful native comparison records 0.024s preparation, 0.704s compilation,
0.064s linking, 3.712s overlapping Wine startup wall time and 8.232s summed case
execution. Model, solver and pilot-rebuild costs are zero. These automated phase
measurements exclude operator analysis, source preparation and diagnosis.

Initial successful value-module builds take **0.51s host / 7.23s ARM**, changing
five objects each. The host adapter refinement then builds in 0.21s, and adding
the already checked string-indexes component to ARM builds in 3.12s. Final full
run times are **13.29s / 21.12s**. Per-phase compilation/linking costs and object
hash/mtime reuse are retained separately.

Repository metadata freshness, production Python lint, format-registry validation
and `git diff --check` pass. `validation.json` confirms the final fixture source
and native adapters match their comparison inputs, and records preservation of
2,394 unrelated pre-existing files. Only the documentation index and current-goal
file receive pre-existing-file edits; new files are confined to this fixture/report.

Full jq lifting remains incomplete. Remaining executable backend work includes
the CLI, Unicode/bytecode/location helpers and runtime support such as decimal
TLS, seed initialization and floating conversion. Reusable third-party libraries
and platform compatibility need explicit delivery choices. Existing output/CRT
profile limitations are not erased by additional passing component cases.
These are finite practical comparisons with explicit assumptions, not universal
equivalence proofs or unrestricted portability claims. The full goal remains active.
