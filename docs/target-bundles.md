# Target Bundles

`targets/<id>/` contains validation data for one program. A target is a consumer
of the generic toolkit, not a Python extension point.

Required `target.json` fields identify the target, expected input hash, and
relative authored paths. A bundle may contain:

- `intent/`: reviewed component, linked-island, source-project, runtime-import,
  and slice-loop intent;
- `source/`: manually created or reviewed portable source;
- `tests/`: curated candidate-only expectations;
- `default.nix`: acquisition or build wiring;
- `tools/`: target-local operator scripts when a generic command cannot express
  an authored workflow.

Target bundles must not contain generic analysis implementation, copied Python
packages, Lean modules, generated proof/data graphs, downloaded binaries, Nix
store outputs, or runtime traces. Generated files belong in ignored `build/` or
Nix outputs. Private inputs belong in ignored `private/` paths.

Adding a target should require no changes under `src/`. New generic behavior is
appropriate only when the target exposes a reusable capability gap, and it must
be validated first with a small generic fixture.
