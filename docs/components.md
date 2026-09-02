# Composable Component Lifting

Components are the supported unit of candidate reconstruction work. They let an operator replace
one exact machine region, a procedure-sized group, or a larger subsystem while
every other structural unit remains owned by the machine-IR fallback.

The current canonical operator artifact is `component-work-package-v6`, a
non-authorizing content-addressed `semantic-slice-v2` projection from
`linked-semantic-module-v2`.  Its owned definitions are distinct from the
faithful-C context shown to the operator.  Portable authority is
`semantic-provider-qualification-v2`; the direct path runs contextual
refinement, generates the machine overlay, and compiles the PE32 objects from
the V6 package without consuming a component-contract V4, machine-binding V5,
or component-implementation V4 artifact.  Total
`implementation-selection-v2` then explicitly selects that provider or the
generated Behavioral-C provider for every definition.

GNU Hello's `ascii-to-lower` is the first deployed direct vertical.  The
program-name, callback-registration, induction, and reusable-library verticals
exercise the same path. jq and DX-Ball also emit direct V6 work packages, but
their unresolved machine-effect and portable-interface reviews remain explicit
blockers. The public V4 contract/implementation/dependency DAG has been removed.
Some proof-kernel types still carry historical names internally; they are
in-memory implementation details and must not be serialized or exposed as a
second component system.

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
checked operation projections, and lifecycles. Source package V3 remains the
implementation package. The interface is machine-free; exact machine meaning
lives in the checked binding intent and its content-addressed semantic slice.

The component DAG produces these independently cached artifacts:

1. `v5Interfaces.<id>`: the checked human-facing operation and boundary schema.
2. `bindingIntentPaths.<id>`: reviewed operation-to-definition projections,
   services, callbacks, lifecycles, object selectors, and honest blockers.
3. `sourcePackages.<id>`: exact authored source bytes plus one C symbol per
   operation.
4. `v6SemanticSlices.<id>`: the independently cached, content-addressed subset
   of `linked-semantic-module-v2` needed to refine the component.
5. `v6WorkPackages.<id>`: a non-authorizing operator package containing the
   interface, semantic slice, immutable faithful-C context, skeleton, required
   dependencies, suggested veto tests, and current blockers.
6. A direct `portable-c-work-package-provider-v2` qualification compiles the
   source for host and PE32, checks the exact ABI and source profile, runs the
   contextual CBMC/refinement, relation, induction, lifecycle, service, and
   ownership kernels that apply, and publishes native objects only when all
   required authority closes.
7. Component-operation service edges are expanded directly from binding intent;
   every selected dependency must itself have a qualified direct provider.
8. `semanticImplementationSelections.<configuration>` is the sole total
   definition-ownership decision. It selects portable objects or immutable
   generated Behavioral C with no implicit per-component fallback.
9. Native realization links selected objects beside generated Behavioral C
   through the one shared runtime and dispatch registry.

Callback authority is a semantic link fact, not a native-ingress input to a
component. `linked-semantic-module-v1` materializes each reachable callback as
a content-bound code capability with its original target RVA, protocol,
lifetime, target symbol, and root provenance. Component refinement validates
its logical handle against that registry and emits only the semantic target
RVA. At execution, the shared runtime resolves that RVA through the one native
code registry. Bridge symbols and candidate addresses therefore remain native
realization details and cannot enter a component contract or source package.

### One Semantic Boundary

Authored components, adopted libraries, generated Behavioral C, runtime
providers, and the external environment all qualify definitions in the same
semantic-module namespace. A consumer binds the provider operation and semantic
slice identity, never a native object address. Changing presentation-only work
package content therefore does not invalidate contextual proof; changing an
operation's checked semantics does.

Library recognition and adoption remain distinct non-authorizing stages. An
adopted behavior pack uses the same direct provider qualifier and publishes the
same V2 qualification/object records as operator-authored source. Configuration
and runtime code do not interpret recognition-specific receipts. External sites
remain explicit checked environment providers because the operating system is
not a hidden component implementation.

`hybrid` permits generated Behavioral-C ownership for unlifted definitions.
`portable` requires zero generated-C ownership in the selected root-reachable
definition closure. Neither mode permits a selected authored component to
silently fall back.

The component DAG emits no standalone runtime. It generates direct machine-state
overlays, copies exact authored source, cross-compiles PE32 objects, marks owned
units in the total activation plan, and forbids silent fallback inside an
enabled component. Native linking combines those selected objects with immutable
generated behavioral C and the module's one shared runtime.

### Portable Component Interface V5

Portable interface V5 defines typed operations, framework-managed instance
state, protocol states, logical resources, effects, injected services, objects,
lifecycles, callbacks, and checked outcomes without exposing a machine ABI or
raw function pointer. It contains no x86 registers, raw
addresses, PE ranges, import IDs, or
external-site identities. Authored source may not define mutable global state.

The stable component ID and generated C interface namespace are separate. For
example, component `directdraw-init` uses interface namespace
`dxball_directdraw_init`. Receipts bind both explicitly instead of requiring an
operator-facing ID to be a C identifier.

The DX-Ball DirectDraw draft validates independent source work: its V5 interface
and source compile without executing DX-Ball. It remains nonauthorizing until
its machine binding, machine-derived refinement, and configuration service
graph close.

### Source Contract

Every authored source package is V3 and maps each V5 operation ID to one C
symbol. Single-entry source packages and adapter-specific ABIs are rejected.
Borrowed references, interior pointers, services, callbacks, effects, and
outcomes are expressed by the V5 interface and its checked machine binding,
then imported through the shared runtime boundary transducer.

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
- Draft, missing, or incomplete components retain generated Behavioral-C
  ownership.
- Every unselected semantic definition retains generated Behavioral-C
  ownership.
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
environment = sdk.environment.pe32 {
  id = "program-win32";
  profilePacks = [ runtimeProfile ];
  interfacePacks = [ ];
  launchProfile = launchProfile;
  boundaryIntents = { };
  support.processTermination = null;
};

workflow = sdk.workflow.pe32 {
  original = originalExe;
  targetId = "program";
  binaryIdentity = "program.exe";
  externalEnvironment = environment;
  lifting = {
    boundaries = [ ];
    components = {
      intent = ./intent/components.json;
      operatorRoot = ./intent;
      sourceRoot = ./source;
    };
    libraries = { packs = [ ]; adoptionRoot = ./intent/libraries; };
  };
  backend = { kind = "behavioral-c"; sourcePresentation = null; };
  analysisLimits = { maxUnits = 512; maxCandidatesPerSeed = 12; };
};

workPackage =
  workflow.components.v6WorkPackages."ascii-to-lower";
selection =
  workflow.semanticImplementationSelections."one-enabled-component";
candidate = workflow.nativeRealizations."one-enabled-component";
```

For an authored portable unit, `component build` realizes the independent
compile receipt. `component status --development` reports the local
contract/source/evidence progress without pulling realization authority.
`component status` reports the strongest available checked implementation and
dependency state, and `component check` requires those machine-derived facts.
Draft units remain independently compilable; configurations remain authority
gated.

`candidate check --mode hybrid` requires complete component dependencies while
allowing checked fallback. `candidate check --mode portable` requires wholly
portable ownership throughout the checked root-reachable projection. `candidate
build` always consumes the strict hybrid
check plus the target's static release gate; diagnostic dependency reports
cannot make a candidate executable.

Pure component qualification depends only on its selected machine-IR units and
checked component artifacts. A component that declares an external-site service
also depends on the canonical target/ABI evidence for that site. Neither path
depends on root-scoped target ISA qualification or final candidate acceptance; those
remain release-level gates.

`runtime` above is exactly the runtime package consumed by the default-compiler
candidate. Building it does not pull an executable candidate into its closure.
`workflow.components.v6SemanticSlices`,
`workflow.components.v6WorkPackages`,
`workflow.semanticImplementationSelections`, and
`workflow.nativeRealizations` provide the corresponding
configuration-indexed families. The operator-facing interface
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
