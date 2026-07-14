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

Run the compact Stage A fixture suite:

```sh
nix build .#stage-a-fixtures-check --no-link
```

Build and validate the full Windows x86 jq alignment-pair contract:

```sh
nix build .#stage-a-jq-fixtures --no-link
nix build .#stage-a-jq-fixtures-check --no-link
```

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
