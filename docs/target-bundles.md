# Validation Target Bundles

Spaghetti Extractor is target-neutral. Real binaries used to validate it live
under `targets/<id>/`; they are consumers of the generic package, not package
inputs.

Each bundle has a reviewed `target.json` containing a stable target ID, the
expected input hash, and relative paths to authored material. A bundle may
contain:

- `intent/`: operator decisions, selectors, scopes, and accepted assumptions;
- `source/`: handwritten or progressively lifted candidate source;
- `python/`: target-only proof emitters or validation adapters;
- `nix/` and `default.nix`: the target's Nix DAG;
- `tests/`: curated candidate-only behavior cases;
- `docs/`: target-specific reports and design notes.

The generic distribution under `src/spaghetti_extractor/` and generic Nix
constructors under `nix/` must not import a target bundle. The repository flake
is the composition root: it may instantiate generic constructors with a target
bundle and expose selected validation outputs.

## Authored Versus Generated

Authored intent identifies binary facts using stable semantic selectors such
as an exact RVA span and proposal class. It must not embed generated proposal
IDs, artifact hashes, inferred effects, statuses, proof results, or coverage
counts.

Nix derivations resolve that intent against pinned inputs and emit bound
artifacts with hashes, statuses, evidence, and provenance sidecars. Those
artifacts remain in the Nix store and are never checked into `targets/` or
`docs/`. Changing one authored selector therefore produces a new immutable
derivation result without mixing machine output into the reviewable source.

The authoritative boundary is implemented by
`nix/stage-b-target-intent.nix` and
`spaghetti_extractor.target_intent`. `repository-boundaries-check` enforces the
directory and dependency rules.

## Adding A Target

1. Add `targets/<id>/target.json` and pin the expected input hash.
2. Add only reviewed intent, source, tests, and target adapters.
3. Instantiate generic Nix constructors from the target's `default.nix`.
4. Keep generated reports in derivation outputs.
5. Add the target validation output at the flake composition root.
6. Run `nix build .#repository-boundaries-check --no-link` before target tests.

Target-specific logic that becomes useful to another binary should move into a
generic module with a target-neutral schema and a small synthetic fixture. The
validation targets then consume that module independently.
