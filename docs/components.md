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

The runtime package generates the machine-state adapter, copies exact authored
source, cross-compiles it as a PE32 translation unit, marks internal component
members as subsumed, and forbids silent fallback inside an enabled component.
The same portable-selection artifact is consumed by fallback coverage, native
dispatch, candidate authority, and completion checks.

## Evidence

`structural-draft-v1` organizes work but never authorizes replacement.

`bounded-equivalence-v1` uses a declared finite input domain. The current
`exhaustive-finite-domain-v1` producer compiles the portable C and compares it
against concrete evaluation of the exact machine IR for every case. It never
executes the original binary. A concrete mismatch is `violated` and includes
the source-level arguments, expected value, and observed value. Unsupported
semantics, an excessive domain, or compiler failure is `incomplete`.

Candidate-only functional evidence is appropriate for stateful or larger
components, but its tested scope must remain explicit. No evidence report may
authorize a component unless all exact hashes and the source entry ABI match.

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

Adding a target should not require generic Python or Nix changes. A reusable
capability gap must be implemented in the toolkit and covered by a small
target-independent fixture before a validation target relies on it.
