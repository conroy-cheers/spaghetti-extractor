# Spaghetti Extractor

Spaghetti Extractor is a binary reimplementation and equivalence-proof toolkit.
Its current validation target is `jq.exe` for 32-bit MinGW Windows.

The active workflow is whole-program-proof-first:

1. Stage A consumes the original binary statically and emits
   `reference_contract.json` plus sidecars.
2. Stage B generates or repairs candidate source from that contract.
3. Local iteration rebuilds and checks candidate slices outside the Nix sandbox.
4. Acceptance is decided only by the relational Stage A whole-program theorem.
   Public candidate-only behavior tests are a final backstop after Stage A
   passes.

Stage B must not execute or trace the original binary during repair iteration.
Original runtime output is not an oracle. If a candidate satisfies Stage A but
fails public behavior checks, that is a Stage A/toolchain problem to investigate.

## Commands

Build the Python tools:

```sh
nix build .#spaghetti-extractor --no-link
```

Export the versioned schema, artifact, Lean-interface, and parallel-workstream
boundaries used by Stage A development:

```sh
spaghetti-extractor stage-a-export-interfaces --out stage-a-interfaces.json
```

Prepared proofs embed and hash the same manifest. See
[Parallel Stage A Development](docs/stage-a-parallel-development.md).

Run the compact Stage A fixture suite:

```sh
nix build .#stage-a-fixtures-check --no-link
```

Run the phase-oriented relational tests as independently cached per-case Nix
builds. The repository builders file schedules the heavy Lean suites remotely,
while `stage-a-relational-kernel-cache` supplies the source-matched compiled
static kernel to every case:

```sh
nix build .#stage-a-relational-tests --no-link \
  --builders "$(cat nix/stage-a-builders)" --max-jobs 0
```

Build and validate the full Windows x86 jq alignment-pair contract:

```sh
nix build .#stage-a-jq-fixtures --no-link
nix build .#stage-a-jq-fixtures-check --no-link \
  --builders "$(cat nix/stage-a-builders)" --max-jobs 0
```

The jq path is split into independently cacheable derivations:
`stage-a-jq-prepared-proof` performs static extraction and prepares the proof
graph, `stage-a-jq-reference-contract` exports Stage B feedback from that graph,
and `stage-a-jq-fixtures-check` performs the lightweight acceptance audit. A
report or assertion change therefore does not repeat PE extraction or hidden
Lean compilation. Preparation currently remains one coarse Nix derivation: its
Lean extraction shards use 16 workers on one selected builder, but are not yet
independent derivations schedulable across multiple hosts. The generated proof
module graph is the finer-grained distributed build boundary.

Generate a relation contract with reusable machine-level external-call schemas:

```sh
spaghetti-extractor stage-a-generate-relation-contract \
  --original original.exe \
  --candidate candidate.exe \
  --mapping block-map.json \
  --external-profile profiles/pe32-kernel32-lockstep-v1.json \
  --out relation-contract.json
```

External profiles are checked theorem inputs, not trusted API implementations.
Stage A selects only declarations whose exact import identity occurs in both
binaries, validates every declaration, and still requires Lean to close each
reachable external boundary. See [profiles/README.md](profiles/README.md).

Bootstrap a jq skeleton from the Stage A contract:

```sh
nix build .#stage-b-jq-skeleton --no-link
```

Prepare a local slice workspace from the canonical jq Stage A contract:

```sh
nix run .#spaghetti-extractor-slice -- --work-dir build/spaghetti-extractor-slices prepare jq --realize-nix
nix run .#spaghetti-extractor-slice -- --work-dir build/spaghetti-extractor-slices next jq --top-k 10
```

For the hot loop, pass local candidate outputs to `spaghetti-extractor-slice check` or build
them with `spaghetti-extractor-slice build`. This avoids rebuilding Ghidra exports or Nix
candidate artifacts when only a small source slice changed.

## Current Surface

Retained:

- `src/spaghetti_extractor/relational/`: authoritative whole-program relational pipeline,
  typed artifact boundaries, analyses, Lean generation, and verdict logic.
- `src/spaghetti_extractor/stage_a_relational.py`: compatibility import facade only.
- `src/spaghetti_extractor/contract_tools.py`: untrusted mapping proposals and reusable
  contract serialization used around the relational proof core.
- `src/spaghetti_extractor/stage_b*.py`: jq skeleton, provenance, candidate-only delta, and
  public expected-output helpers.
- `src/spaghetti_extractor/slice_loop.py`: incremental contract-first slice iteration.
- `tools/ghidra/SpaghettiExtractorStageBExport.java`: optional cold bootstrap exporter.
- `tools/stage-a-fixtures/`: compact Stage A regression fixtures.

Removed:

- runtime tracing/original-output oracle tooling;
- target-specific catalog/database/reporting stacks;
- VM and dynamic instrumentation packaging;
- sample-game and old block-recovery tooling.

## Validation Discipline

Use Stage A first. Runtime checks should not run as a substitute for unresolved
Stage A contract failures. When Wine is needed for candidate-only diagnostics,
run it under a headless Wayland/X session.

See [docs/stage-a-architecture.md](docs/stage-a-architecture.md) for the
normative trust boundary and command authority.
