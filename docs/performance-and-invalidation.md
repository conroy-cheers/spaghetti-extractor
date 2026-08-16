# Performance And Invalidation

Performance is a correctness property of the interactive reconstruction
workflow. A phase that reads an undeclared global artifact may produce the
right answer, but it makes unrelated candidate edits expensive and is not an
accepted v3 phase design.

## Supported Workflow

Use only the Nix-first entrypoints:

```console
nix run .#test -- smoke
nix run .#test -- affected
nix run .#test -- full
nix run .#test -- benchmark
nix run ./targets#test -- <target-id>
nix run .#dev -- doctor
nix run .#dev -- fixtures
nix run .#dev -- refresh --check
nix run .#dev -- scaffold test <subsystem> <name>
nix run .#dev -- scaffold phase <map-units|map-sccs|reduce> <name>
nix run .#dev -- explain-rebuild --before before.json --after after.json
```

The scaffolder creates files by default, refuses overwrites and repository
escapes, and emits the affected Nix command. `--dry-run` renders the proposed
files. A real scaffold transaction refreshes both the Python import index and
the stable test manifest, and rolls its new files back if either metadata build
fails. `refresh` is the only supported writer for those checked manifests.
Test-only manifests and planners are excluded from the distributable toolkit
source, so changing test topology cannot rebuild the installed CLI package.
Direct Lean, compiler, emulator, Nix, or Wine execution from tests is a
policy error; tests consume a shared fixture. Wine fixtures are headless.

The test runner caches only the expensive evaluation from a filtered source
snapshot to the selected derivation paths. The receipt binds the full admitted
source hash, exact Nix expression, Nix executable and version, host system, and
derivation paths, and carries an integrity checksum. A hit still asks Nix to
realize the derivations, so Nix remains the sole build and substitution
authority. A concurrent source change prevents receipt publication. Inspect
receipt location, count, and size with `nix run .#dev -- doctor`.

Target component graphs contain controlled IFD boundaries because reviewed
selectors are resolved against content produced by static analysis. A cold
target-flake evaluation may therefore realize those CA preparation derivations
even when invoked with `--no-build`; the option suppresses requested check
realization, not evaluator dependencies. After preparation, `--no-build` is a
pure warm graph check and all content-derived paths substitute normally.

Library recognition has an orthogonal content-addressed chain:

```text
immutable artifact pack -> catalog signature shards
target machine IR -> target signature packs
catalog index + target signatures -> sparse constellation hypotheses
adoption intent + canonical boundaries -> checked whole-island receipt
checked island + reusable behavior pack -> generated ordinary component
generated component + runtime ownership -> candidate component package
```

Generated and authored components then converge on the same CA subgraph:

```text
interface + normalized semantics -> universal contract
exact machine projection          -> universal machine binding
source/IR/library authority       -> selected implementation
contracts + service graph         -> dependency SCC graph
dependency graph + activation     -> hybrid and portable release gates
```

Contract and implementation identities are deliberately separate. Editing
portable source cannot invalidate a consumer whose required interface did not
change. Editing an interface invalidates only its binding, implementation,
dependent contract edges, and release descendants. The total activation-plan
hash is included only at the release-gate layer, where fallback ownership is a
whole-configuration property.

Catalog lookup is inverted by ABI partition, fixed anchors, normalized hashes,
and structural features. It scales with target features plus sparse hits, not
catalog functions multiplied by executable-section bytes. Adding a pack does
not rebuild target signatures; changing an adoption does not rerun extraction or
matching. Native retrieval emits proposals only, and checked Python authority
revalidates selected witnesses from canonical pack records.

The Nix implementation uses separate phase-specific Python closures for catalog
ingestion, target signatures, catalog search, constellation solving,
checked-island authority, and generated-component construction. A catalog
change therefore does not invalidate target signatures; a target-unit change
does not rebuild the catalog; and an adoption change rebuilds only its authority
receipt, generated component, and downstream candidate ownership closure. On
the GNU Hello benchmark, a recognition-only
rebuild with machine IR available measured 27.394 seconds. A cold end-to-end
realization after source-closure changes, including the original MinGW build,
PE inventory, rooted state machine, and machine IR, measured 115.195 seconds;
the immediately repeated library-status realization measured 0.051 seconds.
The warm result is the important interactive invariant. Clean prerequisite and
scheduling cost remains a separate optimization target.

## Artifact DAG

The v3 authority graph has two checked planning boundaries:

1. Exact structural units are partitioned by stable identity and resource
   class.
2. Record dependencies are decomposed into exact SCCs and condensation edges.

Phase authors declare a pure `map_units`, `map_sccs`, or `reduce` transform.
The framework owns input access tracking, record dependencies, completeness,
packing, Nix realization, and deterministic merge. A reduction requires an
independent completeness hook. Submitted schedules are checked against the
independently derived universe and fail with `planner_omission` if they omit or
invent work.

Arbitrary binaries enter through one bounded source-plan derivation. It emits
canonical per-unit files and a checked structural inventory; Nix immediately
re-interns each unit by content. The preparation pass may rerun after a
monolithic extractor output changes, but unchanged units regain identical
store and downstream derivation identities. Per-unit artifacts bind the exact
PE and exact unit bytes, not a global machine-IR serialization hash.

Stable packs are assigned by identity hash and resource class, never sequence
number. Adding one unit therefore cannot reshuffle unrelated packs. A local
candidate edit must invalidate its exact byte/unit evidence, one transition
pack, affected dependency SCCs, and composition descendants. Static extraction,
independent SCCs, shared Lean kernels, and emulator fixtures remain substitutable.

## Native Acceleration Boundary

The supported Python package includes a Nix-built PyO3 extension for measured
CPU-bound artifact kernels. Native calls are deliberately coarse grained: the
canonical reader validates and converts one complete bounded NDJSON pack in a
single call. Python retains typed schemas, dependency tracking, completeness,
diagnostics, and verdict production, so a native result cannot turn missing or
contradictory evidence into acceptance.

Every native operation has a Python reference implementation and differential
tests for valid, malformed, noncanonical, oversized, and Unicode inputs.
Authority derivations require the pinned native API and fail closed when it is
missing. Developer use may fall back to the reference implementation for
diagnosis. Further modules, such as graph fixed-point kernels, are justified
only when profiling shows that kernel remains dominant after choosing the right
algorithm and data representation. Fine-grained per-record or per-edge PyO3
calls are prohibited because they move overhead across the FFI boundary rather
than removing it.

## Budgets

The release gates are:

| Gate | Limit |
|---|---:|
| Smoke, cold | below 10 seconds |
| Smoke, warm | below 2 seconds |
| Warm generic `nix flake check` | below 10 seconds, zero builders |
| Clean generic suite | below 4 minutes with configured builders |
| Warm Lean/Unicorn differential pair | below 10 seconds |
| Common source edit | dependent shards below 60 seconds |
| One target unit edit | one transition pack plus graph descendants |
| DX-Ball transition artifact | at most 64 MiB |
| Unchanged DX-Ball authority | no slower than 1.3 seconds, zero builders |
| Clean DX-Ball static analysis | below 5 minutes |
| Ordinary shard/pack peak RSS | below 2 GiB |
| Explicit large shard/pack peak RSS | below 4 GiB |

Oracle processes may use a separately declared budget, but they must remain
shared fixtures and cannot be hidden inside an ordinary proof shard. Every test
shard reports elapsed seconds, peak RSS, resource class, and budget compliance.

The completed migration has the following measured results on the validation
host. Times are wall-clock unless the row names aggregate shard execution.

| Gate | Measured result |
|---|---:|
| Smoke, cold / warm | 5.62 s / 0.17 s |
| Warm generic `nix flake check` | 2.06 s, zero builders |
| Wide post-migration generic release build | 59.25 s with configured builders |
| Warm Lean/Unicorn benchmark | 4.72 aggregate shard seconds; 0.53 s warm realization |
| Common source edit (`semantic_index.py`) | 7.06 s for 24 dependent shards plus smoke |
| Test-only edit | one changed stable shard plus cached smoke, 19.02 s including evaluation |
| DX-Ball transition members | 32,541,657 bytes for 9,041 records |
| DX-Ball final authority, clean / warm | 174.39 s / 0.09 s |
| Generic full-suite peak shard RSS | 163,416 KiB |

The first native artifact migration reduced the GNU Hello parametric proposal
phase from 85.25 seconds to 7.06 seconds and the checked-summary producer from
79.5 seconds to 7.26 seconds. The proposal retained its exact 7,934 records and
artifact identity. The summary output likewise retained its artifact identity;
an independent storage replay takes 0.86 seconds. These are phase-level results,
not a claim that every target-analysis phase is now native or equally fast.

Machine-consumed JSON is emitted in canonical compact form. On the GNU Hello
analysis artifacts this reduced the exact static-program contract from 70.2 MiB to
30.5 MiB, ABI callsites from 57.1 MiB to 25.5 MiB, the machine-IR manifest from
32.1 MiB to 18.0 MiB, and the reconstruction plan from 59.0 MiB to 30.8 MiB.
The v2 component-proposal package is 59 MiB instead of the former 143.5 MiB
monolith: its selector index is 8,153,250 bytes and its 64 bounded rich-record
packs total 33,871,985 compressed bytes, with a 666,639-byte largest pack.
Semantic proposal metadata lives in the selector index; the package manifest
is only a transport inventory. The producer validates all records once in pack
order,
while component resolution validates only the index and selected record.
Exact ISA request planning for 21,040 unique instruction locations takes about
0.33 seconds after replacing pairwise overlap discovery with one canonical sort
and adjacent-interval check. Rebuilding the real GNU Hello proposal package
from warm upstream analysis inputs took 97.7 seconds after the package
migration. The first `component status` after that package identity changed
took 37.1 seconds; an unchanged warm invocation took 1.17 seconds. Component
resolution now consumes a controlled-IFD selected-proposal input: changing an
unselected or diagnostic-only discovery field reruns only the preparation,
while preserving the selected input and every downstream derivation identity.
A changed selected membership or identity invalidates resolution and its
actual descendants. On GNU Hello the resulting selected input is 16,421 bytes,
down from the 59 MiB complete proposal package. The first status invocation
after introducing the boundary rebuilt its closure in 51.36 seconds; the
immediate unchanged invocation took 0.295 seconds. The corresponding selected
inputs are 21,860 bytes for jq and 3,172 bytes for DX-Ball.

Component status has a second authority boundary. Pure component development
and activation leaves do not depend on canonical external sites, ISA
qualification, implementation capability coverage, or final authority. Only a
component whose authored binding declares an `external_site` service consumes
the pre-ISA canonical external-site graph. Whole-target ISA qualification and
release authority are evaluated only by candidate release products.

Framework-owned planning for the 9,041-unit DX-Ball structural universe takes
about 1.70 seconds and 73 MiB RSS. The controlled Nix mutation fixture verifies
that changing one unit changes one transition pack, two dependent SCC and
composition packs in its fixture graph, and no independent pack. The full
generic suite now runs 1,889 tests, up from the 1,664-case pre-migration
inventory; 364 generated corruption cases exercise authority-family failures.

GNU Hello, jq, and DX-Ball retain exact structural universes of 7,882, 4,516,
and 9,041 units respectively. Their stronger formal-analysis aggregates remain
truthfully `incomplete`: Hello and jq stop at callback frontier
`original-cutpoint-00001040-0000104d`, while DX-Ball stops at
`original-cutpoint-000010cb-000010d0`. The migration did not hide or relabel
those blockers.

## Guardrails

- Every artifact and schedule has bounded parsing, canonical ordering, exact
  dependency identities, and corruption tests.
- `incomplete` means required evidence is absent; `violated` identifies a
  contradictory location. Neither can authorize candidate generation.
- Target names and policy stay in the independent `targets/` consumer flake;
  generic evaluation and cache fingerprints exclude that corpus entirely.
- Test-only changes retain stable shard assignment. New tests use convention
  directories, so no central shard list needs editing.
- Diagnostic formatting cannot be an authority dependency.
- CA derivations improve substitution, but never compensate for a monolithic
  semantic dependency. Invalidation is tested by comparing derivation paths
  under controlled unit, edge, phase, checker, and test mutations.
