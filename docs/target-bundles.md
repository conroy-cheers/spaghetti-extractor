# Target Bundles

`targets/<id>/` contains validation data for one program. A target is a consumer
of the generic toolkit, not a Python extension point.

`targets/flake.nix` owns target composition. `targets/registry.nix` is the
explicit registry. In-tree modules receive `{ pkgs, sdk }`; out-of-tree users
construct the same interface with `spaghetti-extractor.lib.mkTargetSdk`.

A bundle contains:

- `target.json`: identity, display name, input kind/hash, and declarative paths;
- target Nix module (`targets/<id>/default.nix`): acquisition plus one
  `sdk.workflow.pe32` invocation;
- `intent/components.json`: authored component boundaries/configurations;
- `intent/reviews/`: reviewed logical component interfaces;
- `source/`: manually authored portable component source;
- optional candidate-only tests and runtime assets.

Generated reports, downloaded binaries, Nix outputs, traces, and copied toolkit
code do not belong in a target directory. Generated data stays in Nix outputs
or ignored `build/`; private inputs stay in ignored `private/` paths.

## Standard Outputs

The PE32 workflow exposes exact analysis, final authority, component artifacts,
and candidate constructors. A target should publish those under stable artifact
families rather than create target-specific wrapper scripts.

Regression and acceptance are deliberately separate:

```sh
nix run ./targets#test -- gnu-hello
nix run ./targets#test -- --acceptance gnu-hello
```

Regression validates the target input, extraction/component contracts, and
other incomplete-capable repair artifacts. It must remain useful while whole
program closure is incomplete. Acceptance additionally builds the final Stage A
gate and static candidate; it is expected to fail closed until all authority
families are complete.

Candidate behavior suites may run only after acceptance. Wine execution is
candidate-only and must use the headless constructors. The original is never
executed or traced during repair iteration.

## Adding A Target

1. Add `targets/<id>/target.json`, its target Nix module, and component intent.
2. Add exactly one entry to `targets/registry.nix`.
3. Instantiate `sdk.workflow.pe32`; do not import private files under `nix/`.
4. Expose cheap regression checks and strict `acceptanceChecks`.
5. Add portable source only through reviewed component entries.

No root-flake, generic Nix-module, Python, or Lean change is required unless the
new target demonstrates a genuinely reusable missing capability.
