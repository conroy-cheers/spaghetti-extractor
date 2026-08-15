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

1. `resolution`: the complete checked catalog used for configuration ownership,
   plus `resolutionSlices.<id>` containing only one component or operator group.
   Contracts consume the slice, so adding or editing an unrelated component
   cannot invalidate an existing contract or its evidence descendants.
2. `contracts.<id>`: a machine boundary and reviewed logical interface.
3. `sourcePackages.<id>`: exact portable source bytes plus a supported logical
   C entry symbol.
4. `adapterPlans.<id>`: a checked lowering from the reviewed machine boundary
   to the logical C ABI, plus an explicit completion back to machine state.
5. `evidences.<id>`: candidate-only exhaustive or functional evidence bound to
   the contract, source, adapter, machine IR, domain, and producer.
6. `qualifications.<id>`: a fail-closed activation decision.
7. `activationPlans.<configuration>`: total, exclusive portable, fallback, or
   explicitly blocked ownership. An enabled but stale or unqualified component
   is blocked rather than silently downgraded.
8. `runtimeConfigurations.<configuration>`: the only input accepted by the
   executable component runtime package.
9. `runtimePackages.<configuration>`: independently buildable component
   runtimes, all bound to the workflow's shared machine-IR interpreter.

The runtime package is constructed directly by the component DAG. It does not
construct a candidate or require whole-program acceptance. It
generates the machine-state adapter, copies exact authored source,
cross-compiles it as a PE32 translation unit, marks internal component members
as subsumed, and forbids silent fallback inside an enabled component. The same
interpreter derivation is reused by standalone component runtimes and all
candidates, and the same portable-selection artifact is consumed by fallback
coverage, native dispatch, candidate authority, and completion checks.

Two logical source ABIs are currently supported. `logical-c-v1` accepts scalar
values and uses a checked machine projection for the surrounding register,
flag, stack, and control effects. A scalar result may replace either an exact
register result or the condition selecting a checked finite branch exit.
`logical-object-c-v1` additionally accepts borrowed read-only byte views.
`read-only-bytes-v1` exposes a checked `read_u8` callback and explicit extent.
`nul-terminated-bytes-v1` exposes the same checked read operation without
inventing an extent that the machine program did not have; finite evidence must
provide an in-bounds NUL terminator and rejects reads beyond the supplied case.
Portable code never receives a raw machine address. A scalar result may declare
`offset-into-view-v1`, which makes a returned interior pointer portable: evidence
subtracts the exact case allocation base and bounds-checks the offset, while the
reviewed completion explicitly rebuilds the machine pointer from the entry base
and logical offset. The adapter declares total register/flag state, exact memory
writes, and the return target. Evidence checks that completion against concrete
machine-IR evaluation before qualification, while runtime invokes the portable
function exactly once and never replays the replaced machine region as fallback.

## Evidence

`structural-draft-v1` organizes work but never authorizes replacement.

`bounded-equivalence-v1` uses a declared finite input domain. The current
`exhaustive-finite-domain-v1` producer compiles the portable C and compares it
against concrete evaluation of the exact machine IR for every case. It never
executes the original binary. A concrete mismatch is `violated` and includes
the source-level arguments, expected value, and observed value. Unsupported
semantics, an excessive domain, compiler failure, timeout, subprocess crash, or
malformed evidence protocol is `incomplete`. Object-view cases compare the
logical result and the complete reviewed register, flag, memory-write, and
control completion. The C evaluator runs in an isolated subprocess, so a bad
replacement is a localized evidence failure rather than a crashed build
orchestrator. Finite-domain evidence proves only the declared bounded domain;
it is not a universal function theorem.

`validation-backed-v1` uses `candidate-only-functional-suite-v1`. Intent lists
stable case IDs, exact logical arguments, and expected results. The producer
compiles and executes only the portable replacement; a mismatch is `violated`
and identifies the first case and concrete values. This profile makes no claim
beyond the declared cases and is appropriate when exhaustive machine-IR
evaluation is impractical. No evidence report may authorize a component unless
its profile and producer match and all exact contract, source, machine-IR,
adapter-plan, verification, and source-entry bindings match.

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

Reviewed interfaces may avoid copying long synthesized effect inventories by
using `adapter_effects.inherit_synthesized_except`. Each exclusion names one
exact family, machine-unit ID, and effect index that is represented elsewhere
by a logical result or explicit completion. Missing, duplicate, or stale
references fail contract construction, and the final interface checker still
requires every synthesized effect to have exactly one owner.

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
