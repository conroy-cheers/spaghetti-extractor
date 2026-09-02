# Target Bundles

`targets/<id>/` contains validation data for one program. A target is a consumer
of the generic toolkit, not a Python extension point.

`targets/flake.nix` owns target composition. `targets/registry.nix` is the
explicit registry. In-tree modules receive `{ pkgs, sdk }`; out-of-tree users
construct the same interface with `spaghetti-extractor.lib.mkTargetSdk`.

A bundle starts with:

- `target.json`: identity, display name, input kind/hash, and declarative paths;
- target Nix module (`targets/<id>/default.nix`): acquisition plus one
  `sdk.workflow.pe32` invocation;
- optionally, after proposal review, `intent/components.json`: authored
  component boundaries/configurations;
- optionally, `intent/reviews/`: reviewed logical component interfaces;
- optionally, `source/`: manually authored portable component source;
- optional candidate-only tests and runtime assets.

`target.json` uses `spaghetti-extractor-target-bundle-v3`. Its `paths.components`
and `workflow.default_configuration` fields are either both set or both `null`.
This lets a new target run extraction, authority analysis, and component
discovery before the operator has authored component intent. Once set, the
default configuration must exist in the component intent and selects the
standard regression configuration, component runtime, and strict acceptance
candidate. The SDK validates this schema
strictly and verifies the SHA-256 of the workflow's primary PE against
`input.expected_sha256`; individual targets must not duplicate that check.

Generated reports, downloaded binaries, Nix outputs, traces, and copied toolkit
code do not belong in a target directory. Generated data stays in Nix outputs
or ignored `build/`; private inputs stay in ignored `private/` paths.

## Standard Outputs

Targets return `sdk.target.pe32Bundle { ... }`. The constructor publishes the
standard `analysis`, `environment`, `platform`, `components`, and `candidate`
families that exist for the workflow. Targets supply only input acquisition,
profiles, the workflow, target-specific artifacts, and additional checks; they
do not manually duplicate the toolkit artifact graph.

The retired authority-v3 graph is not a public target family. Linked semantic
module blockers, evidence, and root provenance are the operator-facing semantic
authority. Temporary authority-v3 producers may remain behind individual
component or library migration adapters, but bundling a graph-wide final gate,
metadata object, or every phase would turn one target check back into the old
fan-out and is forbidden.

Native realization packages are indexed under
`candidate.native-realizations.<configuration>`. Candidate attributes remain
lazy. A realization may materialize an incomplete diagnostic receipt and PE,
but the checked candidate build, acceptance path, and Wine suites fail closed
unless that exact receipt is complete and its candidate hash matches.

Regression and acceptance are deliberately separate:

```sh
spaghetti-extractor project check gnu-hello
spaghetti-extractor project check gnu-hello --acceptance
```

Regression validates the target input, extraction/component contracts, and
other incomplete-capable repair artifacts. It must remain useful while whole
program closure is incomplete. Acceptance additionally builds total semantic
provider selection, native realization, candidate observation, and every
candidate-only suite declared by the target; it is expected to fail closed
until every linked-module, selection, realization, and observation blocker is
complete.

The operator-facing readiness views are non-authorizing checked artifacts:

```sh
spaghetti-extractor project status gnu-hello
spaghetti-extractor candidate list gnu-hello
spaghetti-extractor candidate status gnu-hello \
  --configuration ascii-to-lower-enabled
```

`project status` consumes only `linked-semantic-module-v1` and remains usable
when component intent is absent, broken, or expensive to realize. `component
status` reports one independently selected leaf, group, or configuration.
`candidate status` reads that same linked module plus one exact
`implementation-selection-v1` and reports separate module and configuration
subjects in `operator-work-status-v1`. It does not read activation, structural,
runtime, realization, or candidate-test products. All three reports are
diagnostic and cannot open an authority or runtime gate.

Public realization commands resolve builders in this order: explicit CLI
arguments, `SPAGHETTI_EXTRACTOR_BUILDERS_FILE`, the nearest ignored
`nix/builders.local`, XDG configuration, then explicit local execution.
`--local` disables remote builders. Trusted keys follow the same policy via
`SPAGHETTI_EXTRACTOR_TRUSTED_PUBLIC_KEYS_FILE` or the companion file. Templates
are in `nix/builders.example` and `nix/trusted-public-keys.example`.

Every executable default candidate configuration requires at least one
candidate-only behavior suite. Analysis-only targets may omit suites because
they cannot produce an executable candidate. Tests run only after final
authority closes, and Wine execution always uses the headless constructors.
The original is never executed or traced during repair iteration.

## Adding A Target

Start with `nix run .#dev -- scaffold target <id>`. The scaffold is deliberately
not registered and its Nix module fails evaluation until an exact reproducible
PE derivation and expected hash are supplied.

1. Add `targets/<id>/target.json` and its target Nix module. Start with
   `paths.components` and `workflow.default_configuration` set to `null`.
2. Run `project analyze` and inspect the generated proposals with
   `component list`.
   The list is served from the compact v2 selector index. The analysis
   producer has already checked every rich proposal pack, while selection
   rechecks the chosen record and its exact machine-unit bindings without
   decoding unrelated diagnostic packs.
3. Add exactly one entry to `targets/registry.nix`.
4. Instantiate `sdk.workflow.pe32`; do not import private files under `nix/`.
5. Return `sdk.target.pe32Bundle` with acquired inputs and target-specific
   checks. Standard component and acceptance checks are added automatically.
6. Add component intent, set its path and default configuration atomically,
   then add portable source only through reviewed component entries.

No root-flake, generic Nix-module, Python, or Lean change is required unless the
new target demonstrates a genuinely reusable missing capability.
