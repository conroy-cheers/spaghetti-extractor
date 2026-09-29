# Applying component sources and program bindings together

`candidate apply` stages component export, the existing target assembly recipe,
and optional build/workload commands in one copied project. It publishes that
project only after all supplied commands succeed. Use the same action for a C
edit, entry refinement, provider move, or component regrouping. The declarations
describe the desired selection; there is no separate replacement mode to choose.

For the retained jq lifecycle refinement, run in the lifting environment:

```sh
lifting_repo="$PWD"
spaghetti-extractor candidate apply jq \
  --project build/my-jq \
  --comparison build/jq-ir-lifting-2026-09-27/lifecycle/final \
  --component execution-lifecycle \
  --accept-boundary-change execution-lifecycle \
  --assembly-command "python $lifting_repo/tests/fixtures/jq-portable/refresh.py {project} --bindings $lifting_repo/tests/fixtures/jq-execution-lifecycle/portable-bindings.json" \
  --check-command 'make -j2 jq live-values'
```

Commands use shell-style argument quoting but execute **without a shell**. They
run in the staged project; `{project}` expands to its absolute path. Use absolute
paths for external recipes and inputs. Commands must write project changes to
that staged directory. Explicit external outputs, such as retained build/run
receipts, are outside the transaction and remain after failure. Add another
`--check-command` for the affected workloads. Wine commands always go through
`spaghetti-headless-wayland`.

Omit comparisons and selection flags for an adapter-only change. For a split or
merge, supply comparisons for the new selection, name superseded units with
`--remove-component`, and acknowledge new/changed boundaries with
`--accept-boundary-change`. The existing source exporter checks dependencies,
retains unaffected component evidence and C drafts, and invalidates affected
library objects. `candidate export` remains useful when delivering only a library.

The assembly recipe remains operator-owned ordinary code. This command does not
infer calling conventions, shared state, lifecycle or compatible contracts from
symbol names. jq uses its existing `refresh.py` and retained `--bindings` choices;
another target can use its own recipe with the same shared facilities.

Normal program assemblies can call
`candidate.source_export_bindings.render_source_service_bridges(..., trace_services=False)`
with their reviewed bindings to omit service call/return and scope logging.
The default remains traced. This choice leaves adapter calls, value transport,
outcome predicates and failure diagnostics intact; coverage reports the missing
protocol observations. Comparison preparation always uses traced bridges, and an
untraced execution cannot satisfy a required service-observation check.

Keep program objects separate from traced comparison consumers. The DX-Ball
assembly recipe uses this option without changing component C or its records,
retains each existing bridge's compiler recipe and offers `--trace-services` for
program diagnostics. Regeneration verifies the exact already-selected service
binding before changing logging; it does not choose a backend from an example.

## Reconciliation and local edits

`candidate.source_assembly.assembly_delta` reports added/removed entry providers,
provider moves, and backend bodies to retire/restore. Entry providers must be
unique. Backend definitions are identified by **file and symbol**, so unrelated
private helpers can share names. Several component declarations can share one
retirement; its body returns only when its last owner leaves. A private retired
helper need not be an externally callable entry. The binding guides retain each
entry's operation mapping and lifetime description.

`candidate.source_replacements` retains the exact original body, its hash, and
the marker/declaration replacing it inside the existing project metadata. Restore
checks those bytes and leaves surrounding C intact. Legacy projects that retained
only a hash can supply `refresh.py --restore-from ORIGINAL_BACKEND_TREE`; the
original body must match that recorded hash. Partial target-specific rewrites
still require their own inverse. Ordinary multiline C declarations are supported;
macro-generated or ambiguous definitions still need an explicit source adapter.

jq refresh uses this delta for existing and newly added components. It removes
obsolete generated binding files, preserves surrounding backend edits, rejects
duplicate providers/unknown operations, and uses the existing three-way merge
for generated files. Local changes to a file being removed block removal. For a
conflicting file that remains selected, merge the proposal and pass the existing
`--keep-reviewed FILE` to the recipe. Declaring an explicit `native_symbol` selects
the generated bridge instead of retaining a previously selected grouped adapter.

Failures retain the staged project, command logs and `apply-result.json`. They
leave the live project unchanged. Publication checks for concurrent edits and
retains the entire previous project; unchanged files keep their mtimes. Directory
publication uses two same-filesystem renames with rollback, not a crash-atomic
filesystem transaction. Do not edit/build the project concurrently with the short
publication step. A process interruption there can require restoring the retained
`previous/` directory. The command is a local source-project operation, not a
deployment mechanism.

New source integration marks program validation stale. Successful commands are
recorded as practical checks; they do not establish universal equivalence or grant
formal qualification. Omitting checks delivers an explicitly unvalidated assembly.
Existing formal standards and comparison/export provenance rules remain intact.

## Retained jq exercise

Evidence is under `build/component-assembly-update-2026-09-27/`. `exercise.py` uses
the installed CLI on copies of the actual failed lifecycle checkpoint, with the
27-entry export restored from its exact retained backup. It supplies the already
matching 39-case native comparison, rather than rerunning the pilot.

- An update with the old adapter fails linking `_jq_path_append`. The live tree
  is byte-for-byte unchanged; `rejected-link.log`, `rejected-build/` and the
  failed transaction retain the proposed inputs and diagnostic.
- The corrected 28-entry binding applies through the same command. No backend
  retirement changes are needed: the helper was already in the replacement group.
  All 34 neighbors keep their component records and 405 host/402 ARM exported files.
  Operator notes and a deliberate edit to surrounding backend C remain intact.
- Both source projects match **148 CLI and 32 live-value cases** on x86-64 and
  AArch64/QEMU, with normal program entry and all selected components exercised.
  Wine runs in headless Wayland desktops. Build/link checks establish exactly one
  provider per declared entry and absence of retired definitions in their backend
  objects.
- Each build changes four objects: two lifecycle objects, its entry adapter, and
  `builtin.o` for the deliberate local edit. **165 host / 164 ARM objects** retain
  bytes and mtimes. Build times are 0.77s / 8.83s; total apply/check times are
  15.6s / 29.4s. Preparation, compiler and link costs are retained separately.
  Model/solver and pilot-rebuild costs are zero. These are tool timings, not total
  operator analysis time.

Focused tests also exercise shared retirements during provider moves, restoration
amid local edits, duplicate rejection, legacy hash verification, concurrent edits,
failed assembly/check commands and successful public application. This resolves
the assembly-refinement blocker from the [IR continuation](jq-ir-continuation.md).
It does not complete jq lifting or expand the previously documented runtime scope.
