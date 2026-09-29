# Practical product delivery audit — 2026-09-25

Status: **the scoped practical operator-workflow and standalone-program milestone
is delivered**. Operator/program outcomes and repository reconciliation have
terminal evidence. Full jq/DX-Ball and general Win32 recovery remain outside this
completion claim.
This audit applies the [practical product criteria](whole-target-independent-lifting.md#practical-product-completion)
and the current [operator priorities](current-goal.md). It neither substitutes a
full jq lift or G1–G7 qualification for those criteria nor counts them as delivered.

Evidence is retained under `build/practical-product-audit-2026-09-25/` and the
subsequent `build/practical-repository-closure-2026-09-25/`. The
retained-artifact audit uses current comparison and source-export readers.
Historical runs are distinguished from new execution. The preceding status-only
goal turn made no implementation progress; this audit revalidated that assessment
and found the concrete assembly and repository work below.

| Required outcome | Inspected evidence | Result and scope |
| --- | --- | --- |
| Establish an unfamiliar boundary using documented interfaces and ordinary C | Hello string-conversion boundary, disassembly/adapter effort record, seven retained local checks and program integration; later interface-first jq string split and object lifecycle handoffs | Delivered by agent-run trials. The first Hello authoring interval is 503s, excluding earlier investigation; automatic preparation is measured separately. This is not an independent human usability study. |
| Expose local inputs, objects, services, outcomes, assumptions and examples | Current installed CLI opens Hello and DX-Ball from retained results, prints local status, checks them and exports component guides; current jq exports retain their guides | New installed-CLI handoff passes. Shared layouts and services remain explicit; establishing boundaries still requires manual analysis and adapters. |
| Diagnose discrepancies, replay after repair, reuse unaffected work | Current readers validate 44 retained comparisons, including Hello/DX-Ball defects and replay, jq reference leaks, separate leaf checks and changed layouts | Passed within recorded case scopes. Fresh Hello/DX-Ball repeats perform zero compiler/link/execution/model/solver work. The jq lifecycle repair rebuilt one C unit and reused eight. |
| Carry compatible representation changes through consumers | Retained DX-Ball local, connected and native layout handoff, mixed-layout rejection and reviewed source update; fresh native comparison of the revised selection | Valid evidence. Same signatures did not permit mixed layouts. This is explicit group migration, not automatic representation compatibility. |
| Deliver standalone application C and reusable runtime backends | Hello exported project, recorded build-source hashes, ordinary build recipes, separate application/runtime C and portable argument/output adapters | Source and binary bindings validate. The program runs without original application bodies, Behavioral-C fallback, Python or the extractor. Frontend recovery is source-assisted. |
| Execute on x86 and another architecture | New Hello normal-entry comparisons on x86-64 and AArch64 under QEMU | All 82 cases pass on each architecture. Scope remains UTF-8 entry, Windows-1252 target semantics and redirected streams. Earlier 17-case allocation-failure reports and replay revalidate; those failure runs were not repeated. |
| Transfer source assembly and preserve real consumers | New jq normal-entry comparisons using the latest object-lifecycle source builds | 62 cases and 32 existing live-value scenarios pass on each architecture. All selected components execute. Source backend dependencies remain explicit; this is partial source-assisted jq. |
| Preserve validation, export, policy and qualification boundaries | Thirteen current Nix gates, source-export readers, 248 affected unit/repository/architecture tests, current installed-CLI handoffs | The initial failures below are resolved. All affected tests pass after the documented map correction, and PE32-project plus qualified-platform gates now pass. These gates do not establish full target qualification. No proof or activation standard was weakened. |

The scopes are unchanged: standalone Hello in the recorded environment,
source-assisted partial jq, and connected DX-Ball graphics with controlled
services. Full jq/DX-Ball, native DirectDraw, other Hello console/locale profiles
and arbitrary Win32 recovery remain later work. Memory observations are finite;
reconstructed pointers and shared signatures are not lifetime proofs.

## Program handoff findings

The old jq matrix matched all 61 workloads but did not call the newly selected
array-index, string-index and object-delete units. Its coverage gate rejected the
run. The recipe now accepts operator-authored case files using the existing case
shape: identifier, argument vector and stdin bytes. One additional workload
exercises those three entries. Both architectures pass without recompiling the
program or weakening entry coverage. Adding a workload needs no runner-code edit.

Hello's original process terminated with Linux signal 11 before reporting state
for a long-argument/broken-pipe case when inheriting the development environment.
The smaller lifting shell alone did not fix it. The same original, portable build
and input pass with an explicit runtime environment retaining PATH, user/home,
temporary directory, desktop/session, font configuration and Python module paths,
plus `LC_ALL=C.UTF-8`. The runner still supplies each case's locale/POSIX and fault
settings. Inherited environment size was 46,816 bytes versus 8,127 bytes in the
probe; the responsible variable or Wine loader defect was not isolated.
The full 82-case runs then pass on both architectures. This records a supported
execution environment and a startup failure, not a target-code repair or support
for arbitrary inherited environments. All Wine processes ran in headless Wayland.

## Repository reconciliation

The first repository/architecture run finished with 32 passing and five failing
tests. The failures identify:

1. Two component modules importing the candidate source-export reader. Shared
   source provenance/draft reading belongs below both layers; move it without
   changing artifact semantics or the public source handoff.
2. The public native-preparation helper missing from declared operator API roots.
   Its role is now declared in `pyproject.toml`, rather than adding a fake
   production consumer or exempting it from validation.
3. Generated workspace paths written as repository-file references in the guide.
   They now use explicit workspace/component placeholders.
4. Three oversized production files: command workflows, exact bisimulation and
   refinement. Split by responsibility while preserving algorithms and proof
   standards.
5. Four oversized test modules: public commands, comparison, composition and
   machine overlay. Split existing tests by behavior for independent Nix
   invalidation; additional test scenarios are unnecessary for that housekeeping.

A broader gate realization initially reported conflicting Nix content-addressed
outputs for the PE32 project fixture; the old registered local path is absent.
The new fixture exists, but the requested gate did not finish. Its PE timestamps
are already deterministic; changing timestamp flags without evidence would not
address this conflict. The separate PE32-project and qualified-platform invocation
was **not counted as passing**. Its diagnostic remains retained separately from
the subsequent successful run; no target pilot was rebuilt.

The source-handoff reader now belongs to `components/source_handoff.py`, below
both comparison preparation and candidate assembly. The existing public reader
imports remain available. Parser/status handling and proof-header/assertion
rendering were split by responsibility; the oversized test modules were split
without adding scenarios. An AST audit confirms that 98 function bodies and all
114 tests in the split modules retain their behavior. The two separately tracked
unrelated dirty files remain byte-identical to the pre-refactor snapshot.

The affected 248-test run passed everything except the newly added audit's missing
repository-map entry. Adding that entry and rerunning its test passes. The generated
format registry needed regeneration after moving its readers; that failed run is
also retained. All thirteen Nix gates then pass, including the previously blocked
PE32-project and qualified-platform checks.

The PE32 cause was the DLL's default image base depending on its output pathname.
Two builds with identical timestamps but different output directories produced
different DLLs. Linking to a stable relative filename before installation produces
byte-identical DLLs and executables across both directories. The corrected Nix
fixture also passes `nix build --rebuild`. No store database repair, timestamp
workaround or weaker acceptance rule was needed.

The rebuilt installed CLI completes seventeen public commands: Hello and DX-Ball
start/status/check/reuse/export, plus jq's edited multi-file source imported into
both its local and real native-consumer workspaces, checked, reused and exported.
All four unchanged repeats report zero compiler/link/execution/model/solver work.
The broader program binaries and backends did not change during this refactor;
their source and execution bindings were revalidated instead of rebuilding pilots.

The closure directory retains `ast-audit.json`, `affected-tests.log`,
`map-recheck.log`, `practical-validation.json`, `target-transfer.json`,
`jq-handoff.json`, `retained.json` and `completion-audit.json`. The current
requirement/evidence audit uses those terminal results together with the standalone
and two-architecture evidence above. First-boundary preparation is still manual,
the trials are agent-run, and broader target/backend coverage remains future work.
