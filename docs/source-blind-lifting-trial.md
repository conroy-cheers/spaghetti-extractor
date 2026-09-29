# Binary-only component workflow trial — 2026-09-27

The bounded trial succeeded: three previously unprepared, connected DX-Ball
operations were recovered without original source, edited locally, compared
against native instructions, and assembled into a portable source consumer.
It supports the practical workflow direction. It also confirms that preparing a
new boundary and its execution adapter remains much more work than editing C
inside an established boundary.

This addresses a limitation of the preceding jq exercise, which used known jq C
sources and headers extensively. That exercise established source-assisted
component integration and portability, not independent binary-to-C recovery.
This trial consulted the DX-Ball executable, its disassembly, toolkit APIs and
existing fixture infrastructure. Prior knowledge included the shared sprite-bank
layout; the new algorithms and object accesses were checked against instructions.
It is a source-blind subsystem trial, not a claim of an operator unfamiliar with
the whole target or a clean-room development process.

## Scope and retained evidence

The [operator fixture](../tests/fixtures/dxball-cleanup-blind/README.md) provides
the recipe and [boundary](../tests/fixtures/dxball-cleanup-blind/BOUNDARY.md).
The binary is pinned by SHA-256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.

| Unit | Entry RVA | Responsibility |
| --- | --- | --- |
| `cleanup-select` | `bd70` | Set the current bank, accepting every 32-bit word |
| `cleanup-dispose` | `c510` | Release an optional surface, free the selected sprite, clear its slot |
| `cleanup-clear` | `bcc0` | Clear counts and dispose 255 slots in each of three banks |

Ordinary C uses real pointers and shared structs. Adapters transport all 786 bank
words, selected bank, sprite identities and contents, aliases and guard words.
Observations include ordered service arguments/state, surface reference counts
and sprite lifetimes. A direct case deliberately leaves an alias to a freed
sprite; the adapter records its identity rather than assuming unique ownership.
The controlled allocator keeps tombstones, not real freed host storage.

The original executes native PE32 bodies. Source execution redirects only the
selected entries and traps their original ranges; local supplier cases execute
the unchanged native cleanup caller. The connected comparison replaces all three
bodies. Machine-derived C and semantic inputs are also retained, but do not stand
in for native execution. Loop proof regions, the three component interfaces and
their shared representation group retain distinct purposes.

Evidence root: `build/source-blind-component-trial-2026-09-27/`.

- `SOURCE-EXPOSURE.md`, `selection.json`, `disassembly.txt`: input provenance and
  exact manually chosen boundaries.
- `prepared-4/`: interface-first workspaces, generated machine C and executable
  comparison packages. Preparation uses the public installed toolkit.
- `workflow-2/workflow.json`: completed reproducible edit/check/defect/replay/repair
  sequence; `results.json` and `commands.json` retain costs and work counts.
- `workflow-1/program.apply-5sv961n6/apply-result.json`: successful source update;
  two integration commands pass and both unchanged component objects are retained.
- `workflow-1/program/`: standalone source consumer; `arm-project/`, `arm-2.json`
  and `arm-elf.stdout`: corresponding AArch64 build and QEMU execution.

All 57 initial native comparisons match: 6 selector, 28 disposal and 23 connected
cases, including generated inputs. All 23 standalone cases match the retained
x86 observations on both x86-64 and AArch64. The standalone consumer needs no
original executable or toolkit to build and run. No full-game, native DirectDraw,
production allocator, arbitrary concurrency or universal equivalence claim follows.
Every Wine process runs inside a headless Wayland desktop.

## What the trial caught

Disposal reloads the current bank and slot after releasing the surface. A
deliberate mutant cached the original sprite across that call. A synchronous
service mutation selected another bank; the comparison reported
`$.objects[0].surface` as original `1`, source `0`. Replaying retained inputs
reproduced the mismatch after the editable source had already been repaired.
This is a meaningful interaction discrepancy, not a test of output formatting.

An implementation-only refactor rebuilt one C file in the local check and one
in the connected check. The selector's independent evidence was reused without
compilation or execution. The connected caller's implementation and adapters
reused their objects while its cases ran again. Repairing the deliberate mutant
under the same environment reused the prior passing result without fresh work.
`candidate apply` then changed only disposal's selected source, retained both
neighbors, rebuilt its object and ran the standalone workloads before publication.

## Costs and ergonomics

The first native match arrived about **12 minutes** after trial orientation began
(06:06:57 to 06:18:53 UTC). Selecting the operation took about four minutes; C,
state transport, cases and setup consumed the remaining eight. These are elapsed
times for this agent session, including small authoring mistakes and a packaging
repair; they are not measurements of an unfamiliar human operator's productivity.
Existing toolkit/target familiarity and a retained executable reduced preparation.

Automatic package preparation took **0.66 seconds**, including **0.056 seconds**
for machine-C recovery. No pilot was rebuilt and no model or solver ran. The first
local edit plus local check, unchanged-neighbor reuse and connected recheck took
**25.3 seconds**. First-run costs below come from `workflow-1/`; later reproduction
varies with runtime startup and scheduling.

| Step | Wall seconds | C compilation | Link | Case execution |
| --- | ---: | ---: | ---: | ---: |
| Disposal baseline, 28 cases | 9.85 | 0.21 | 0.06 | 4.74 |
| Connected baseline, 23 cases | 13.96 | 0.31 | 0.06 | 5.10 |
| Disposal local edit | 11.26 | 0.03 | 0.06 | 4.89 |
| Unchanged selector reuse | 0.45 | 0 | 0 | 0 |
| Connected recheck | 13.02 | 0.03 | 0.06 | 5.20 |

Wine startup accounts for roughly 3.5–6.4 wall seconds per fresh comparison here;
remaining time includes cache validation, instrumentation, hashing and teardown.
Original/source startup overlaps, so summed phase durations are not wall time.
The source-project update compiled and linked in 0.06 seconds and its 23 workloads
ran in 0.06 seconds. A clean AArch64 build took 4.61 seconds and QEMU checks 0.52.
No formal qualification was requested or inferred from these timings.

The practical shortcomings are concrete:

1. **Preparation remains adapter-heavy.** The three operation files total 41
   lines, with a 21-line shared layout; the comparison runtime is 265 lines and
   preparation recipe 154. The walkthrough and assembly add orchestration. Some
   of that is reusable infrastructure, but identifying addresses, ABI, lifetime,
   observation scope and transport remains manual. Newly encountered state is
   still the expensive part. No new target-specific tool internals were needed.
2. **Installed-package coverage had a gap.** `observation_headers()` worked from
   the checkout but its header was omitted from the installed package. Adding
   `resources/comparison/*.h` to package data fixed it. The rebuilt installed
   helper and its existing compiler-backed test pass. This was a packaging repair,
   not new component semantics or a target special case.
3. **Execution reuse is sensitive to the whole environment.** A fresh headless
   desktop changes its fingerprint and reruns otherwise identical cases. Switching
   from the walkthrough's Python launcher to the installed CLI also changed Python
   and compiler environment identities and rebuilt objects. Within one consistent
   environment, the expected reuse worked. A deliberately controlled execution
   environment would be a useful improvement; blindly ignoring variables would
   weaken what the retained result means.
4. **The state boundary remains partly C and prose.** Services and caller
   dependencies are visible and bound; object layout and permitted mutations are
   supplied through the shared header, boundary notes and executable observations.
   They are not checked heap summaries. This is usable for a careful operator but
   still requires discipline when changing interfaces or adding observations.

The next useful work is reusing this object/interaction setup for a neighboring
operation, or improving reusable transport and environment setup when another
target needs it. More formal machinery or polishing this tiny example would not
address the main cost observed here.

Validation: the installed observation-helper test, complete public walkthrough,
both standalone architectures, repository metadata, production Python lint,
format registry and `git diff --check` pass. `validation.json` and
`tree-audit.json` retain the results. The audit confirms 2,507 baseline files are
unchanged and the two edited shared files preserve all prior dirty-tree edits.
