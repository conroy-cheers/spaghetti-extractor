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
nix run .#test -- target <target-id>
nix run .#test -- benchmark
nix run .#dev -- doctor
nix run .#dev -- fixtures
nix run .#dev -- scaffold test <subsystem> <name>
nix run .#dev -- scaffold phase <map-units|map-sccs|reduce> <name>
nix run .#dev -- explain-rebuild --before before.json --after after.json
```

The scaffolder creates files by default, refuses overwrites and repository
escapes, and emits the affected Nix command. `--dry-run` renders the proposed
files. Direct Lean, compiler, emulator, Nix, or Wine execution from tests is a
policy error; tests consume a shared fixture. Wine fixtures are headless.

The test runner caches only the expensive evaluation from a filtered source
snapshot to the selected derivation paths. The receipt binds the full admitted
source hash, exact Nix expression, Nix executable and version, host system, and
derivation paths, and carries an integrity checksum. A hit still asks Nix to
realize the derivations, so Nix remains the sole build and substitution
authority. A concurrent source change prevents receipt publication. Inspect
receipt location, count, and size with `nix run .#dev -- doctor`.

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

Framework-owned planning for the 9,041-unit DX-Ball structural universe takes
about 1.70 seconds and 73 MiB RSS. The controlled Nix mutation fixture verifies
that changing one unit changes one transition pack, two dependent SCC and
composition packs in its fixture graph, and no independent pack. The full
generic suite now runs 1,889 tests, up from the 1,664-case pre-migration
inventory; 364 generated corruption cases exercise authority-family failures.

GNU Hello, jq, and DX-Ball retain exact structural universes of 7,882, 4,516,
and 9,041 units respectively. Their current final-authority results remain
truthfully `incomplete`: Hello and jq stop at callback frontier
`original-cutpoint-00001040-0000104d`, while DX-Ball stops at
`original-cutpoint-000010cb-000010d0`. The migration did not hide or relabel
those blockers.

## Guardrails

- Every artifact and schedule has bounded parsing, canonical ordering, exact
  dependency identities, and corruption tests.
- `incomplete` means required evidence is absent; `violated` identifies a
  contradictory location. Neither can authorize candidate generation.
- Target names and policy stay under `targets/`; generic code consumes target
  manifests without naming validation binaries.
- Test-only changes retain stable shard assignment. New tests use convention
  directories, so no central shard list needs editing.
- Diagnostic formatting cannot be an authority dependency.
- CA derivations improve substitution, but never compensate for a monolithic
  semantic dependency. Invalidation is tested by comparing derivation paths
  under controlled unit, edge, phase, checker, and test mutations.
