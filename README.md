# Spaghetti Extractor

Spaghetti Extractor is a reusable toolkit for reconstructing 32-bit Windows PE
programs as progressively more portable C. It extracts a static reference
contract from an opaque original binary, generates a machine-oriented baseline,
and supports replacing bounded components with reviewed source while reporting
precise remaining gaps.

The toolkit does not claim a whole-program mathematical equivalence theorem.
Confidence comes from independently qualified instruction semantics, exact
static artifact binding, fail-closed analysis, bounded component checks, and
candidate-only behavioral suites. The original binary is never executed during
repair iteration.

## Workflow

1. Inventory the original PE, executable bytes, imports, relocations, roots,
   code regions, and required ISA forms.
2. Emit an original-only reference contract and canonical machine IR.
3. Recognize libraries and external interfaces, then emit typed v3 evidence
   packs for exact units, transitions, memory, targets, induction, external
   sites, callbacks, roots, exceptions, ISA qualification, and fallback
   capabilities.
4. Require an authorizing `final-authority-v3` record and a separately checked,
   exact fallback-coverage receipt before generating an executable candidate.
5. Generate the complete machine-oriented baseline and propose components.
6. Replace components with portable C using explicit interface contracts while
   retaining complete fallback coverage.
7. Run curated candidate-only behavior tests under headless Wine only after the
   static gate passes.
8. Repeat lifting and candidate-only validation without using runtime execution
   to discover missing original regions.

Generated analyses are proposals unless a checker explicitly qualifies them.
Unsupported instructions, ambiguous targets, stale hashes, missing interfaces,
and uncovered executable bytes remain `incomplete`; observed contradictions are
`violated`.

## Quick Start

```console
nix develop
spaghetti-extractor --help
spaghetti-extractor project status gnu-hello
spaghetti-extractor project analyze gnu-hello
spaghetti-extractor component list gnu-hello
spaghetti-extractor component status gnu-hello ascii-to-lower
spaghetti-extractor component build gnu-hello ascii-to-lower
spaghetti-extractor component check gnu-hello ascii-to-lower
spaghetti-extractor candidate list gnu-hello
spaghetti-extractor candidate status gnu-hello
spaghetti-extractor project check gnu-hello
```

Public realizations automatically use the nearest checked-in
`nix/stage-a-builders` inventory when one exists. Use `--local` to disable
remote builders for one command, or `--builders-file FILE` to select an
explicit CA-capable inventory. This prevents unrelated host-global builder
configuration from silently taking over an analysis; when no inventory can be
found, the command explicitly uses the local builder.

Individual pipeline leaves are available only in the explicit expert namespace:

```console
spaghetti-extractor expert stage-a-inventory-binary \
  --binary original.exe --out build/inventory.json
spaghetti-extractor expert stage-a-inventory-isa \
  --binary original.exe --inventory build/inventory.json \
  --out build/isa.json
spaghetti-extractor expert stage-a-export-opaque-reconstruction \
  --original original.exe --inventory build/inventory.json \
  --out build/static-export
```

The release gates are Nix-native and content-addressed:

```console
nix run .#test -- smoke
nix run .#test -- affected
nix run .#test -- full
nix run .#test -- benchmark
nix run ./targets#test -- dxball
nix flake check
nix flake check ./targets
nix build .#roundtrip-qualification --no-link
nix build .#isa-kernel --no-link
```

`nix run .#test` is the supported generic-toolkit test path. It creates a
filtered source snapshot, plans import/resource impact, and realizes stable CA
shards. Unchanged shards substitute without executing a builder. Heavy tests
consume shared compiler, Lean, Bochs, Nix, PE32, and headless-Wine fixtures.
Validation targets are independent consumers and run through
`nix run ./targets#test -- <id>`.

Developer operations use the same conventions:

```console
nix run .#dev -- doctor
nix run .#dev -- fixtures
nix run .#dev -- refresh --check
nix run .#dev -- scaffold test control branch_targets
nix run .#dev -- scaffold phase map-sccs pointer_provenance
nix run .#dev -- explain-rebuild --before before.json --after after.json
```

`refresh` transactionally regenerates both checked repository manifests;
`refresh --check` verifies them without writing. Scaffolding creates
convention-wired files, refreshes both manifests, and rolls the new files back
if metadata generation fails. Add `--dry-run` to inspect the generated files
without changing the worktree.

Portable-source iteration is also Nix-native. GNU Hello exposes the canonical
component and target-gate workflow:

```console
spaghetti-extractor component list gnu-hello
spaghetti-extractor component status gnu-hello ascii-to-lower
spaghetti-extractor component build gnu-hello ascii-to-lower
spaghetti-extractor component check gnu-hello ascii-to-lower
spaghetti-extractor component build gnu-hello --configuration operator-one-leaf
spaghetti-extractor project check gnu-hello
spaghetti-extractor project check gnu-hello --acceptance
spaghetti-extractor candidate list gnu-hello
spaghetti-extractor candidate status gnu-hello
spaghetti-extractor candidate build gnu-hello
spaghetti-extractor candidate test jq
```

Regression remains buildable while whole-program authority is incomplete.
Building one component or group produces a non-authorizing static work package;
building a configuration produces its runtime package. Acceptance and every
executable candidate stay behind the explicit final-authority gate. Candidate
tests exist only when a target declares curated expected-output cases, run only
the generated candidate, and execute Wine through an isolated headless X
session. `project status` and `candidate status` combine checked authority and
component-configuration diagnostics without opening either gate.

## Public Surfaces

- `spaghetti-extractor`: project, component, and candidate operator workflows,
  plus explicit `expert` access to individual pipeline leaves.
- `nix run .#test`: cached smoke, affected, full, and benchmark toolkit gates.
- `nix run ./targets#test`: validation for one explicitly registered consumer.
- `nix run .#dev`: scaffolding, fixture discovery, environment diagnosis, and
  rebuild explanations.
- `flake.lib.mkTargetSdk`: the stable configured Nix interface for analysis,
  authority, candidate, lifting, validation, and target-bundle construction.
- [Composable component lifting](docs/components.md): exact leaf/group
  boundaries, qualification profiles, fallback ownership, and incremental Nix
  artifacts.
- `targets/`: a separate in-tree consumer flake containing authored validation
  intent and source, never generic Python implementation code.

See [REPOSITORY_MAP.md](REPOSITORY_MAP.md) for every subsystem and dependency,
and [docs/architecture.md](docs/architecture.md) for the assurance model.

## Scope

The current machine profile is IA-32 PE32. Capstone and `pefile` provide
untrusted extraction proposals; the compact Lean model, Unicorn, Bochs, and
hardware-derived corpora qualify supported ISA behavior. Z3 assists bounded
symbolic analysis, and CBMC checks finite component contracts. Ghidra remains an
optional proposal source.

The intended output is initially conservative C, not beautiful C. Components
can then be coarsened and rewritten into idiomatic, portable source without
requiring the entire program to retain x86 register state.
