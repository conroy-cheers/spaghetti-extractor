# Composable Component Lifting

Components are the supported unit of candidate reconstruction work. They let an operator replace
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

## Canonical Lifecycle

Artifact version numbers describe individual wire formats, not one global
component generation. New boundary-aware components use
`PortableComponentInterfaceV5`, which references the shared canonical schema,
checked operation projections, and lifecycles. Portable interfaces V2-V4 remain
migration readers for existing targets, and source package V3 remains the
implementation package. The interface is machine-free; exact machine meaning lives in a
separate checked binding. Older logical source ABIs remain readable while
existing targets migrate, but are not the recommended authoring path.

The component DAG produces these independently cached artifacts:

1. `resolution`: the complete checked catalog used for configuration ownership,
   plus `resolutionSlices.<id>` containing only one component or operator group.
   Contracts consume the slice, so adding or editing an unrelated component
   cannot invalidate an existing contract or its evidence descendants.
2. `developmentContracts.<id>`: the operator boundary, source operation map,
   and reviewed portable interface. This small, nonauthorizing input does not
   depend on proposal discovery or whole-target analysis.
3. `contracts.<id>`: a machine boundary, reviewed logical interface, and
   projected canonical external-site evidence used for activation.
4. `sourcePackages.<id>`: exact portable source bytes plus one C symbol per
   interface operation.
5. `compileReceipts.<id>`: host and PE32 ABI conformance, exact source/interface
   binding, and a prohibition on component-owned mutable globals.
6. `machineBindingReceipts.<id>`: exact unit membership and checked projections
   between machine values/effects and portable operations. For an explicitly
   selected library island this facet also consumes the structural boundary
   receipt, requires exact equality of both unit inventories, and binds the
   receipt hash. The receipt cannot bypass semantic refinement.
7. `semanticContracts.<id>` and `refinementReceipts.<id>`: machine-derived
   operation paths and a universal CBMC check over portable source, with service
   responses treated as unconstrained environment inputs.
8. `serviceGraphs`: configuration-scoped resolution of every service dependency
   to another component operation or a canonical external site.
9. `ownershipReceipts.<id>`: exclusive structural-unit ownership.
10. `activationReceipts.<id>`: one reducer over interface, compile, machine
    binding, semantic refinement, service graph, and ownership facets. Missing evidence is
    `incomplete`; contradictory or stale evidence is `violated`.
11. `activationPlans.<configuration>`: total, exclusive portable, fallback, or
    explicitly blocked ownership. An enabled component without an exact checked
    activation receipt is blocked rather than silently downgraded.
12. `runtimeConfigurations.<configuration>`: the only input accepted by the
   executable component runtime package.
13. `runtimePackages.<configuration>`: independently buildable component
    runtimes, all bound to the workflow's shared machine-IR interpreter.

### Universal Contract Boundary

The lifecycle above feeds one common authority model instead of separate models
for authored C, recognized libraries, machine IR, and pinned implementations:

```text
component-contract-v3.json
  machine-independent types, operations, state, effects, services, callbacks,
  protocol states, and normalized machine-derived operation semantics

machine-binding-v3.json
  exact PE, machine-IR, structural units, and operation projections

implementation-v3.json
  one checked portable-C, machine-IR, pinned-binary, or environment realization

component-dependency-graph-v3.json
  contract-to-contract service edges, exact callsites, external dependencies,
  reverse consumers, and SCCs
```

Consumers depend on provider contract hashes, never provider implementation
hashes. Replacing a machine-IR implementation with portable C therefore rebuilds
that implementation, its configuration graph, and release descendants without
invalidating independently checked consumers. A contract change still
invalidates consumers because it changes the behavior they are allowed to rely
on.

Generated library components enter through exactly these files. Library
constellation, checked-island, and behavior-pack evidence is consumed by the
library-owned adapter that emits the universal records; configuration and
runtime code do not interpret recognition-specific receipts. External sites
remain explicit checked environment dependencies because the operating system
is not a hidden component implementation.

Every release gate also binds the total activation plan and checks that its
selected component inventory and ownership kinds exactly match the universal
dependency graph. `hybrid` permits
checked machine-IR or pinned ownership for remaining units. `portable` requires
zero machine-IR fallback among units in the checked root-reachable behavioral
projection. Structurally classified but unreachable units retain fallback
ownership without blocking portable-lift completion.

The runtime package is constructed directly by the component DAG. It does not
construct a candidate or require whole-program acceptance. It
generates the machine-state adapter, copies exact authored source,
cross-compiles it as a PE32 translation unit, marks internal component members
as subsumed, and forbids silent fallback inside an enabled component. The same
interpreter derivation is reused by standalone component runtimes and all
candidates, and the same portable-selection artifact is consumed by fallback
coverage, native dispatch, candidate authority, and completion checks.

### Portable Interfaces V2 and V3

Portable interface V2 defines typed operations, framework-managed instance
state, protocol states, logical resources, effects, and injected services.
Portable interface V3 adds opaque, typed callback handles without exposing a
machine ABI or raw function pointer. Both contain no x86 registers, raw
addresses, PE ranges, import IDs, or
external-site identities. Authored source may not define mutable global state.

The stable component ID and generated C interface namespace are separate. For
example, component `directdraw-init` uses interface namespace
`dxball_directdraw_init`. Receipts bind both explicitly instead of requiring an
operator-facing ID to be a C identifier.

The DX-Ball DirectDraw draft validates independent source work: its V2 interface
and source compile without executing DX-Ball. It remains nonauthorizing until
its machine binding, machine-derived refinement, and configuration service
graph close.

### Legacy Source ABIs

Existing targets may still contain older adapters. `logical-c-v1` accepts scalar
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

`portable-interface-v1` was the first component ABI. Its typed IR defines
portable scalars, records, bounded byte views, logical resources, callbacks,
effects, and injected service dependencies. The generated C interface contains
no x86 registers or raw machine addresses. Service calls are explicit function
pointers over a context object, so the same component can use deterministic
mocks in development and checked external adapters after activation. New
components should use portable interface V2; V1 exists only for migration.

## Static Refinement Loop

Portable source may be authored and compiled from only its reviewed interface.
This development derivation is intentionally small and nonauthorizing: it does
not depend on proposal discovery, resolved machine membership, rooted authority,
or another component's intent.

Activation adds an exact machine binding. The toolkit derives finite symbolic
paths from canonical machine IR, checks that every bound operation path is
represented, and generates a CBMC harness relating arbitrary interface inputs
and arbitrary external-service responses to the exact C operation. A concrete
or symbolic mismatch is `violated` with its operation/path location. Missing
semantics or unrepresentable state is `incomplete`. Operator-authored examples
and expected outputs cannot enter this authority path.

A `finite_control_target` result may replace a recovered indirect jump only
when its selector expression, closed target inventory, table bytes, and target
addresses are already machine-derived and checked. The binding assigns portable
logical route values to that exact target set. Materialization expands every
checked selector value into a route, static refinement assumes only the proven
entry domain, and runtime lowering rejects values outside that domain before it
maps the logical route back to the exact machine continuation. A stale table,
selector expression, inventory digest, or non-bijective route map fails closed.

## Legacy Evidence

This section describes the migration path for older logical C adapters.
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

## Configuration Safety

- Enabled components with exact checked activation authority use portable source.
- Draft, missing, or incomplete components retain machine-IR fallback.
- Every unselected structural unit retains machine-IR fallback.
- Overlapping ownership is rejected.
- Enabled component members may not fall back individually.
- Whole-program candidate generation requires structural executability; release
  acceptance additionally requires ISA qualification and the activation-bound
  universal component/dependency gate. Candidate-only tests are optional veto
  diagnostics.

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

For an authored portable unit, `component build` realizes the independent
compile receipt. `component status --development` reports the local
contract/source/evidence progress without pulling activation authority.
`component status` reports the strongest available canonical activation state,
and `component check` requires that exact machine-derived activation authority.
Draft units remain independently compilable; configurations remain authority
gated.

`candidate check --mode hybrid` requires complete component dependencies while
allowing checked fallback. `candidate check --mode portable` requires wholly
portable ownership throughout the checked root-reachable projection. `candidate
build` always consumes the strict hybrid
check plus the target's static release gate; diagnostic dependency reports
cannot make a candidate executable.

Pure component activation depends only on its selected machine-IR units and
checked component artifacts. A component that declares an external-site service
also depends on the canonical target/ABI evidence for that site. Neither path
depends on root-scoped target ISA qualification or final candidate acceptance; those
remain release-level gates.

`runtime` above is exactly the runtime package consumed by the default-compiler
candidate. Building it does not pull an executable candidate into its closure.
`workflow.componentRuntimes` and `workflow.candidates.static` provide the
corresponding configuration-indexed families. The operator-facing interface
also exposes independently cached work packages, status reports, and checks for
every leaf or group, plus runtime/status/check products for each configuration.

Adding a target should not require generic Python or Nix changes. A reusable
capability gap must be implemented in the toolkit and covered by a small
target-independent fixture before a validation target relies on it.

## Library Islands

`library status` and `library inspect` discover ABI-compatible whole-library
islands. `library adopt --island ... --recipe ...` writes a content-bound V1
adoption intent for an available reusable behavior pack; `--draft` records an
operator recipe that still needs static qualification. Discovery, adoption,
checked-island authority, and generated component construction are separate
content-addressed phases.

An adopted island becomes executable only when the canonical checker closes
identity, every crossing boundary, and the selected implementation, then emits
a complete generated ordinary component. The component runtime consumes that
package through the same ownership, adapter, semantic-contract, and compilation
path as an operator-authored component. Unselected or incomplete islands do not
block the target and retain machine-IR fallback ownership.

Automatic generated-component materialization currently covers stateless,
nonvariadic scalar ABIs with register or stack arguments and scalar results.
Stateful services, variadic calls, hidden return storage, out-parameters, and
externally visible effects fail closed until the behavior pack supplies an
explicit checked machine-to-portable mapping template.
