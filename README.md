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
3. Generate a baseline interpreter or C representation.
4. Recognize libraries and external interfaces, then propose components.
5. Replace components with portable C using explicit interface contracts.
6. Rebuild the candidate and run static contract checks.
7. Run curated candidate-only behavior tests under headless Wine.
8. Repeat until no material reconstruction gaps remain.

Generated analyses are proposals unless a checker explicitly qualifies them.
Unsupported instructions, ambiguous targets, stale hashes, missing interfaces,
and uncovered executable bytes remain `incomplete`; observed contradictions are
`violated`.

## Quick Start

```console
nix develop
spaghetti-extractor --help
spaghetti-extractor stage-a-inventory-binary \
  --binary original.exe --out build/inventory.json
spaghetti-extractor stage-a-inventory-isa \
  --binary original.exe --inventory build/inventory.json \
  --out build/isa.json
spaghetti-extractor stage-a-export-opaque-reconstruction \
  --original original.exe --inventory build/inventory.json \
  --out build/static-export
```

The release gates are Nix-native and content-addressed:

```console
nix flake check
nix build .#roundtrip-qualification --no-link
nix build .#isa-kernel --no-link
```

Use `spaghetti-extractor-slice` for repeated local candidate edits after the
static contract has been prepared. The loop caches the original-side artifacts
and invalidates candidate checks by content hash.

## Public Surfaces

- `spaghetti-extractor`: inventory, contract, ISA, machine-IR, component,
  source-rendering, candidate assurance, and functional-test commands.
- `spaghetti-extractor-slice`: incremental component/slice iteration.
- `flake.lib`: generic Nix constructors for ISA qualification, round trips,
  components, libraries, source substitutions, and functional suites.
- `targets/`: validation bundles containing authored intent and source, never
  generic Python implementation code.

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
