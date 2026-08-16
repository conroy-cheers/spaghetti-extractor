# Spaghetti Extractor

Spaghetti Extractor is a reusable toolkit for reconstructing 32-bit Windows PE
programs as progressively more portable C. It extracts an original-only static
program contract from an opaque binary, generates a machine-oriented baseline,
and supports replacing bounded components with reviewed source while reporting
precise remaining gaps.

The toolkit does not claim a whole-program mathematical equivalence theorem.
Confidence comes from independently qualified instruction semantics, exact
static artifact binding, fail-closed analysis, and machine-derived component
refinement checks. Optional candidate-only behavior suites are veto diagnostics,
not reconstruction evidence or release authority. The original binary is never
executed during repair iteration.

## Workflow

1. Inventory the original PE, executable bytes, imports, relocations, roots,
   code regions, and required ISA forms.
2. Emit an original-only static-program contract and canonical machine IR.
3. Recognize libraries and external interfaces, then emit checked structural
   facts for units, targets, external sites, callbacks, roots, exceptions, and
   fallback capabilities.
4. Require `structural-executable-v1`: every runtime transfer is represented,
   every structural unit has an implementation owner, and the fallback can
   execute every unlifted unit.
5. Generate the executable machine-oriented baseline and propose components.
6. Replace components with portable C through machine-free interface V2,
   framework-managed state, exact machine bindings, machine-derived semantic
   refinement, service graphs, and activation receipts.
7. Require ISA qualification and exact authority for every enabled component.
8. Optionally run candidate-only behavior tests under headless Wine after static
   acceptance. A failure vetoes confidence but a pass never authorizes a lift.

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
spaghetti-extractor component status gnu-hello ascii-to-lower --development
spaghetti-extractor component status gnu-hello ascii-to-lower
spaghetti-extractor component build gnu-hello ascii-to-lower
spaghetti-extractor component check gnu-hello ascii-to-lower
spaghetti-extractor library status gnu-hello
spaghetti-extractor library inspect gnu-hello --family mingw-w64
spaghetti-extractor candidate list gnu-hello
spaghetti-extractor candidate status gnu-hello
spaghetti-extractor project check gnu-hello
```

A newly registered target does not need component intent up front. Its analysis
and authority graph can run first; `component list <target>` then displays
the compact selector index from a bounded v2 proposal package. Rich proposal
diagnostics are stored in stable hash buckets. A checked preparation resolves
reviewed selectors once, then re-interns only each selected proposal's exact
resolution fields as the downstream component input; diagnostic and unrelated
discovery changes therefore do not invalidate component resolution. The
producer still validates every complete record before publishing the package.
Component build and candidate commands remain unavailable until reviewed
intent and a default configuration are declared together.

Linked-library discovery is ABI-first and independently cached. Immutable
catalog packs contribute per-function byte, structural, call, and ABI evidence;
the target-wide constellation solver uses those function matches to identify a
release and exact ownership island. An operator may adopt a reusable behavior
pack, but adoption intent is non-authorizing. The checked-island phase rechecks
identity, canonical crossings, and implementation bindings; candidate generation
then materializes an ordinary component whose exact unit inventory is rebound by
the component machine-binding checker. Compile, semantic refinement, services,
and exclusive ownership must still close before portable source replaces machine
IR. Unselected application code remains owned by the machine-IR fallback.

Public realizations use an explicit portable builder policy. They prefer a
CLI-selected inventory, then `SPAGHETTI_EXTRACTOR_BUILDERS_FILE`, the nearest
ignored `nix/builders.local`, and the XDG configuration file
`$XDG_CONFIG_HOME/spaghetti-extractor/builders`. Use `--local` to disable
remote builders for one command. When no inventory is found, the command
explicitly selects local execution instead of inheriting host-global builders.

Individual pipeline leaves are available only in the explicit expert namespace:

```console
spaghetti-extractor expert static-inventory-binary \
  --binary original.exe --out build/inventory.json
spaghetti-extractor expert isa-inventory \
  --binary original.exe --inventory build/inventory.json \
  --out build/isa.json
spaghetti-extractor expert static-program-export \
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
nix run .#dev -- scaffold target sample-app
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

Building one component or group produces a non-authorizing development package;
building a configuration produces its runtime package. Whole-candidate
generation is gated by structural executability, not by the older formal
aggregate. Release acceptance is stricter: it requires qualified ISA forms and
the exact activation or legacy qualification receipt selected by the structural
plan. Declared candidate tests run only the generated candidate through an
isolated headless X session after static acceptance, and remain optional veto
diagnostics.
`project status` remains diagnostic. `candidate status` adds one selected
configuration and its declared candidate-only suites; neither status command
opens a gate.

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
  boundaries, portable interface V2, deterministic local checks, activation
  authority, fallback ownership, and incremental Nix artifacts.
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
