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

`target.json` uses `spaghetti-extractor-target-bundle-v2` and declares
`workflow.default_configuration`. That configuration must exist in the
component intent and selects the standard regression configuration, component
runtime, diagnostic candidate, and strict acceptance candidate.

Generated reports, downloaded binaries, Nix outputs, traces, and copied toolkit
code do not belong in a target directory. Generated data stays in Nix outputs
or ignored `build/`; private inputs stay in ignored `private/` paths.

## Standard Outputs

Targets return `sdk.target.pe32Bundle { ... }`. The constructor publishes the
standard `analysis`, `authority`, `components`, and `candidate` families for
every component configuration. Targets supply only input acquisition, profiles,
the workflow, target-specific artifacts, and additional checks; they do not
manually duplicate the toolkit artifact graph.

The authority family includes the final gate, diagnostics, graph metadata, and
all phase derivations under `authority.phases`.

Component runtimes are available under `components.runtimes.<configuration>`.
Static and diagnostic candidate packages are indexed under
`candidate.{static,diagnostic}.<configuration>`. These attributes are lazy:
exporting the complete family does not realize every candidate.

Regression and acceptance are deliberately separate:

```sh
spaghetti-extractor project check gnu-hello
spaghetti-extractor project check gnu-hello --acceptance
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
2. Declare `workflow.default_configuration` in `target.json`.
3. Add exactly one entry to `targets/registry.nix`.
4. Instantiate `sdk.workflow.pe32`; do not import private files under `nix/`.
5. Return `sdk.target.pe32Bundle` with acquired inputs and target-specific
   checks. Standard component and acceptance checks are added automatically.
6. Add portable source only through reviewed component entries.

No root-flake, generic Nix-module, Python, or Lean change is required unless the
new target demonstrates a genuinely reusable missing capability.
