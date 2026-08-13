# Target Bundles

`targets/<id>/` contains validation data for one program. A target is a consumer
of the generic toolkit, not a Python extension point.

`targets/flake.nix` owns target composition and exports structured artifact
families. `targets/registry.nix` is the explicit, reviewed registry. The root
flake neither imports nor enumerates validation targets. In-tree target modules
receive `{ pkgs, sdk }`; out-of-tree consumers construct the same SDK with
`spaghetti-extractor.lib.mkTargetSdkV1 { inherit pkgs; }`.

Required `target.json` fields identify the target, expected input hash, and
relative paths consumed by the generic intent resolver. The supported path
keys are `nix`, `components`, `linked_islands`, `source_projects`, and
`source_evidence`; unknown keys fail closed. A bundle may contain:

- `intent/`: reviewed component, linked-island, source-project, runtime-import,
  and source-evidence intent;
- `source/`: manually created or reviewed portable source;
- `tests/`: curated candidate-only expectations;
- `targets/<id>/default.nix`: acquisition or build wiring;
- `tools/`: target-local input conversion helpers only when a generic command
  cannot express the operation; build and validation loops remain Nix-native.

Target bundles must not contain generic analysis implementation, copied Python
packages, Lean modules, generated proof/data graphs, downloaded binaries, Nix
store outputs, or runtime traces. Generated files belong in ignored `build/` or
Nix outputs. Private inputs belong in ignored `private/` paths.

Adding a target should require no changes under `src/`. New generic behavior is
appropriate only when the target exposes a reusable capability gap, and it must
be validated first with a small generic fixture.

## Canonical Lift Outputs

A target that supplies a portable source project should expose two explicit Nix
outputs. A lift workbench contains only static evidence, source diagnostics,
compiled-but-unexecuted candidates, and an incomplete-capable static receipt.
A release workflow ends at the fail-closed portable completion receipt and may
depend on authority-gated candidate behavior evidence.

For GNU Hello the entrypoint is:

```sh
nix build './targets#legacyPackages.x86_64-linux.targets.gnu-hello.completion.workbench'
jq . result/source-iteration-audit/source-iteration-audit.json
jq . result/authority-diagnostics-v3/authority-diagnostics-v3.json
```

After final authority passes, the release join is:

```sh
nix build './targets#legacyPackages.x86_64-linux.targets.gnu-hello.completion.workflow'
jq . result/completion-receipt-v2/lift-completion-report-v2.json
```

The workbench remains useful while authority is incomplete and cannot authorize
candidate execution. The release workflow must not paper over a failed
authority gate or substitute candidate behavior tests for static closure.

Cheap source-repair artifacts are exposed separately so ordinary edits do not
need to evaluate the full authority graph:

```sh
nix build './targets#legacyPackages.x86_64-linux.targets.gnu-hello.source.iteration-audit' --no-link
nix build './targets#legacyPackages.x86_64-linux.targets.gnu-hello.source.call-report' --no-link
nix build './targets#legacyPackages.x86_64-linux.targets.gnu-hello.source.dependency-audit' --no-link
nix build './targets#legacyPackages.x86_64-linux.targets.gnu-hello.authority.diagnostics' --no-link
nix build './targets#legacyPackages.x86_64-linux.targets.gnu-hello.authority.isa-requirements' --no-link
nix build './targets#legacyPackages.x86_64-linux.targets.gnu-hello.authority.isa-frontiers' --no-link
```

`authority.isa-frontiers` is the normal ISA repair surface. It reports exact
forms, instruction RVAs, disputed observation fields, and concrete next
actions. The report validates its binding to the already checked ISA-selection
summary but does not replay the full oracle corpus. Oracle replay remains an
upstream authoritative derivation, so diagnostic wording changes cannot
invalidate semantic evidence or its downstream closure.

The source qualification, ownership ledger, candidate validation, and final
completion receipt are release joins. Candidate behavior suites remain behind
the final-authority gate and therefore do not run during an incomplete static
analysis iteration.

Target regression tests and acceptance are deliberately separate commands:

```sh
nix run ./targets#test -- gnu-hello
nix build './targets#legacyPackages.x86_64-linux.targets.gnu-hello.authority.gate' --no-link
```

The regression command must remain useful while authority is incomplete. The
explicit gate is expected to fail closed until every authoritative family is
complete; candidate runtime and release outputs depend on that gate.

Adding a target requires one `targets/registry.nix` entry but no root-flake, generic
Nix-module, Python, or Lean change. Target modules may contain acquisition and
program-specific workflow composition, but must call the SDK and may not import
private files under `nix/` directly.
