# Composable Component Lifting

Components are the supported unit of Stage B work. They let an operator replace
one exact machine region, a procedure-sized group, or a larger subsystem while
every other structural unit remains owned by the machine-IR fallback.

## Two Graphs

The machine-IR graph is canonical. Component boundaries do not alter it. The
authored component catalog is a work graph over exact machine-unit membership.
Alternative groups may overlap, but one selected configuration may not: every
structural unit has exactly one implementation owner.

This is what makes local work possible without a complete understanding of the
target. Selecting one component does not require lifting its callers, callees,
or unrelated regions first.

## V3 Lifecycle

Version 2 is retained only for authored/input wire schemas: catalog intent,
resolution, boundary review, component contract, and source package. These are
parsed inputs, not executable authority. Evidence, qualification, configuration
ownership, portable selection, runtime completion, and candidate authorization
are native v3 artifacts; no v2 artifact can activate source.

The component DAG produces these independently cached artifacts:

1. `resolution`: selectors and groups bound to exact machine units.
2. `contracts.<id>`: a machine boundary and reviewed logical interface.
3. `sourcePackages.<id>`: exact portable source bytes plus a `logical-c-v1`
   entry symbol.
4. `evidences.<id>`: candidate-only exhaustive or functional evidence bound to
   the contract, source, machine IR, domain, and producer.
5. `qualifications.<id>`: a fail-closed activation decision.
6. `activationPlans.<configuration>`: total, exclusive portable, fallback, or
   explicitly blocked ownership. An enabled but stale or unqualified component
   is blocked rather than silently downgraded.
7. `runtimeConfigurations.<configuration>`: the only input accepted by the
   executable component runtime package.
8. `runtimePackages.<configuration>`: independently buildable component
   runtimes, all bound to the workflow's shared machine-IR interpreter.

The runtime package is constructed directly by the component DAG. It does not
construct a candidate or require whole-program acceptance. It
generates the machine-state adapter, copies exact authored source,
cross-compiles it as a PE32 translation unit, marks internal component members
as subsumed, and forbids silent fallback inside an enabled component. The same
interpreter derivation is reused by standalone component runtimes and all
candidates, and the same portable-selection artifact is consumed by fallback
coverage, native dispatch, candidate authority, and completion checks.

## Evidence

`structural-draft-v1` organizes work but never authorizes replacement.

`bounded-equivalence-v1` uses a declared finite input domain. The current
`exhaustive-finite-domain-v1` producer compiles the portable C and compares it
against concrete evaluation of the exact machine IR for every case. It never
executes the original binary. A concrete mismatch is `violated` and includes
the source-level arguments, expected value, and observed value. Unsupported
semantics, an excessive domain, or compiler failure is `incomplete`.

`validation-backed-v1` uses `candidate-only-functional-suite-v1`. Intent lists
stable case IDs, exact logical arguments, and expected results. The producer
compiles and executes only the portable replacement; a mismatch is `violated`
and identifies the first case and concrete values. This profile makes no claim
beyond the declared cases and is appropriate when exhaustive machine-IR
evaluation is impractical. No evidence report may authorize a component unless
its profile and producer match and all exact contract, source, machine-IR,
verification, and source-entry bindings match.

```json
{
  "evidence_profile": "validation-backed-v1",
  "verification": {
    "producer": "candidate-only-functional-suite-v1",
    "cases": [
      {"id": "zero", "arguments": {"value": 0}, "expected": 0}
    ]
  }
}
```

## Configuration Safety

- Enabled, checked, qualified components use portable source.
- Draft, missing, or incomplete components retain machine-IR fallback.
- Every unselected structural unit retains machine-IR fallback.
- Overlapping ownership is rejected.
- Enabled component members may not fall back individually.
- Whole-program candidate generation still requires final Stage A authority.

## Public Interface

Targets normally use `sdk.workflow.pe32`, then inspect
`workflow.components`. Low-level construction remains available as
`sdk.lifting.components` for tooling tests.

```nix
workflow = sdk.workflow.pe32 {
  original = originalExe;
  binaryIdentity = "program.exe";
  externalProfile = runtimeProfile;
  machineImportProfiles = [ runtimeProfile ];
  launchProfileTemplate = launchProfile;
  componentIntent = ./intent/components.json;
  componentReviewRoot = ./intent/reviews;
  componentSourceRoot = ./source;
  namePrefix = "program";
};

runtime = workflow.componentRuntimeFor "one-enabled-component";
candidate = workflow.candidateFor {
  configurationId = "one-enabled-component";
};
```

`runtime` above is exactly the runtime package consumed by the default-compiler
candidate. Building it does not pull an executable candidate into its closure.
`workflow.componentRuntimes` and `workflow.candidates.static` provide the
corresponding configuration-indexed families. The operator-facing interface
also exposes independently cached work packages, status reports, and checks for
every leaf or group, plus runtime/status/check products for each configuration.

Adding a target should not require generic Python or Nix changes. A reusable
capability gap must be implemented in the toolkit and covered by a small
target-independent fixture before a validation target relies on it.
