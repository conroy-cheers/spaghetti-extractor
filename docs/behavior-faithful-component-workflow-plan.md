# Behavior-faithful C component workflow

Status: completed implementation milestone, 2026-09-16; F1–F7 complete within
their documented scopes, with terminal acceptance and repository evidence.
The [current goal](current-goal.md) tracks completion. This plan supersedes the
next-work recommendations in the [jq assessment](jq-path-network-assessment.md)
where those recommendations imply a blanket ownership or memory-safety policy.
It preserves the completed G1–G6 milestone and its evidence.

## Objective and semantic policy

Make independently authored C components practical to define, check, edit and
compose, using the existing four-operation jq path/value network as the acceptance
consumer. Faithfully reproduce the selected original binary's behavior under the
declared environment and observation scope, including known original defects
when that scope requires them. Do not make a general borrow checker, universal
memory safety, or repairing the original program prerequisites for lifting.

Keep three independent findings in the public workflow and retained evidence:

1. **Behavioral difference:** original and replacement differ in an admitted
   case under the selected observations. Retained mismatches remain failures.
2. **Resource diagnostic:** the checker observed a leak, expired handle, unusual
   alias, invalid access or protocol event. State the side, coverage and rule;
   a diagnostic by itself is not an equivalence verdict or a universal veto.
3. **Contract violation:** the caller, implementation or service contradicts a
   premise used by composition. Dependent applicability must be withdrawn or
   marked unresolved until the premise is repaired and rechecked. An explicitly
   conditional theorem may remain valid while insufficient for execution.

Known original behavior belongs in explicit contract effects, outcomes or scoped
expectations with exact evidence binding. It must not be hidden by dropping an
observation, ignoring a failed premise, or globally disabling resource checks.
Changes to allowed behavior invalidate the affected evidence even if the C
signature is unchanged. A deliberate bug fix is a separately requested semantic
change, with its differences retained; it is not silently called equivalence.

C remains the authoring language. Restrict or model constructs where needed for
reliable compiler semantics. Source-level undefined behavior is not a faithful
encoding of arbitrary machine behavior: use defined arithmetic and existing
memory views/relations to represent relevant accesses, reuse or faults explicitly.
If the environment cannot reproduce an effect, report the capability gap rather
than inventing a result. No universal heap or VM model is required by this plan.

## Baseline and architecture

Inspect current source and retained evidence before implementing; recorded
statuses can lag the main thread. Reuse
`build/jq-path-network-2026-09-16/` inputs and the actual pinned PE32 oracle.
The baseline has 106 isolated cases, a 37-case full network including ten actual
interpreter programs, correct unaffected-neighbor reuse, a missed reference leak,
unread-header invalidation, unsupported float rendering, flat dependency
selection, and a persistent-Wine pipe-cleanup hang.

Extend existing interface/schema, lifecycle/effect, relation, source-package,
comparison, experimental manifest, SDK, testkit and Nix infrastructure. Resource
checking is boundary instrumentation with explicit coverage, not a new language
type system. Introduce artifact boundaries or schema fields only for an actual
semantic distinction or measured invalidation need; preserve typed readers and
exact evidence binding. Keep proof regions, components and representation
replacement groups distinct.

The principal implementation surfaces are `components/comparison_*`,
`components/component_c_v5.py`, existing interface/lifecycle contracts,
`candidate/experimental_run.py`, `candidate/functional.py`, the headless runtime
helpers and `sdk.lifting`. Target-specific semantic adapters can remain C fixture
code. Component creation must not require new target-specific production Python
or Nix orchestration.

## Implementation sequence and mandatory exits

### F1. Bounded runtime sessions and cancellation

Unify comparison and experimental runtime lifecycle beneath their existing
admission rules. Own the desktop, server, prefix and detached runtime helpers;
keep every Wine application, boot and server command inside headless Wayland.
Bound execution, output collection, termination escalation and teardown. Preserve
partial logs and distinguish timeout from cleanup failure. Do not wait forever
for EOF after killing only the root process group.

Enable persistence only with declared case-state/reset rules. Fresh executable
processes do not guarantee fresh registry/filesystem/service state. Keep original
and replacement state independent. Retain suite and per-case admission checks.
Measure startup, execution, validation and teardown separately; dispose of
terminal prefixes without discarding replay inputs or observations.

**Exit:** reproduce the detached-writer/persistent-server failure in a bounded
regression; it always returns within the configured execution deadline plus a
documented finite cleanup allowance, including cancellation and startup failure.
The 37-case selected jq suite passes through the public runner. Record comparable
before/after costs and any state contamination checks; do not claim the failed
persistence assay established a speedup.

### F2. Contract-specific resource diagnostics

Build on the existing owned-handle fixture support and resource/lifecycle model.
Track resource events and ownership transfers through instrumented services,
including duplication, borrowing, consumption, return and declared retention.
Separate reference tokens from shared object identity. Support nested calls and
returned resources without a global rule that all resources must be released at
each return. Make capacity, generation and unsupported instrumentation explicit.

Observe retained aliases and promised contents as well as results/errors. Where
rules are enforced, derive them from the selected contract. Raw reference counts
are useful diagnostics for a particular representation, not a required equality
across different valid representations. Report effects outside instrumentation
coverage, especially native service internals, as unobserved rather than checked.

**Exit:** the jq injected reference leak is detected by the standard workflow
without editing its driver to add one-off observations. Double consumption,
expired tokens, nested transfer and error cleanup have meaningful negative and
positive cases under contracts that require those properties. Add a retained
original or explicitly labelled small semantic fixture with a known leak/unsafe
effect: preserving it under an explicit contract remains behaviorally matching
while its resource diagnostic remains visible; a newly introduced difference is
distinguished. Exercise a false safety/ownership premise and show dependent
applicability fails. Preserve at least one machine-like unsafe behavior using
defined C plus explicit memory semantics; never rely on host C undefined behavior.

### F3. Reusable service definitions and simpler authoring

Define each supported service once using existing contracts: types, resource
roles, effects, outcomes, protocol and available checkers. Generate mechanical
C declarations, bridge plumbing, checking wrappers and observation scaffolding.
Make unsupported behavior visible before an operator writes adapters around it.
Retain hand-authored target semantics where conversion is not mechanical.

Supply argument/state-sensitive controlled dependencies for the jq consumer,
including permitted failures. Do not substitute a recoverable error for an
originally terminating failure without a justified contract. Validate controlled
service behavior and binding on both sides; label it as executable local evidence
until an actual checked-summary composition rule exists.

**Exit:** migrate the four jq operations to reusable service definitions; report
the reduction in handwritten setup and remaining bespoke adapters. Demonstrate
public start/edit/check/divergence/replay/repair with resource diagnostics. At
least one significant caller check uses a controlled dependency without executing
its native or authored implementation body. A compatible supplier edit preserves
that local evidence while supplier and real-integration checks rerun.

### F4. Explicit, resolved composition

Resolve declared requirements and operator-selected implementations transitively.
Expose the resolved graph, contract/representation identities and inclusion
provenance. Deduplicate consistent selections and reject ambiguous or conflicting
ones. Treat recursion as an explicit group with requirements; discovering a cycle
does not establish progress or correctness. Do not manufacture production APIs
solely to accommodate the resolver.

**Exit:** selecting composed getpath brings in its selected get supplier without
manual flattening or duplicated bridge wiring. Full jq integration resolves all
four operations consistently. Missing/conflicting suppliers, mixed representations
and same-signature changed effects reject or require explicit refinement. A
supported recursive selection is handled explicitly; unsupported recursive shapes
produce an actionable capability diagnostic. The operator sees exactly which
local evidence and integrations a body or contract edit invalidates.

### F5. Precise compilation and evidence reuse

Cache compilation per translation unit using compiler/toolchain, options,
generated ABI and effective inputs. Account for include resolution, including a
new header shadowing an old include; previous dependency-file contents alone are
insufficient. Separate compile/link reuse from behavioral-observation reuse.
Preserve checker, observations, fixture, oracle, runtime and environment bindings.
Do not promote observations to proofs when reusing them.

**Exit:** the existing get-body edit recompiles only affected translation units,
relinks affected integrations and preserves unchanged isolated neighbors with zero
compiler/link/model/solver/execution work. The unread-header edit incurs no such
work once irrelevance is established. Relevant header/interface changes, include
shadowing, checker/observation changes and consumed supplier changes invalidate
the appropriate results. Record preparation, compiler, model, solver, execution,
link, hashing/retention and storage costs separately.

### F6. Consistent C capabilities and focused assurance

Carry ordinary binary32/binary64 scalar interfaces through declaration rendering,
compiler/conformance checks and native adapters. Test relevant NaN, infinity,
signed-zero and conversion edge cases. Distinguish source validity, executable
bindings, comparison support and proof eligibility in early diagnostics.

Implement one useful focused local check for a supported resource protocol,
permitted effect or arithmetic obligation in this service-bearing workflow,
reusing the semantic engine and existing relations. State its property, premises,
coverage and limitations. Other obligations may remain unavailable; a focused
check must never imply complete heap safety or original/source equivalence.

**Exit:** numeric normalization can be authored in C through a supported scalar
interface instead of being forced into native glue. Positive/negative native ABI
and arithmetic cases pass or reject as intended. A focused check demonstrates an
accepted property, a meaningful violation and an unsupported-premise diagnostic;
its result and reuse remain distinct from differential comparisons and strong
qualification. Original memory-safety defects do not become blanket admission
failures merely because this checker exists.

### F7. End-to-end acceptance and documentation

Run a fresh public operator walkthrough of the same jq network using F1–F6.
Retain exact commands, inputs, first differences, resource findings, assumption
failures, repair/replay, selected graph, reuse decisions and phase measurements.
Preserve the 106 isolated and 37 composed baseline cases or document a justified
replacement without dropping counterexamples. Run affected shared-regression
consumers, including existing DX-Ball lifecycle and representation coverage,
targeted tests, applicable Nix and repository checks. Refresh generated metadata
after production Python changes and attribute pre-existing failures separately.

**Exit:** every F1–F6 row has current executable evidence, including negative
controls, and the remaining unsupported semantics/qualification gaps are listed.
No result labelled complete may depend on an unfinished validation job. Update
the design, assessment and current goal with exact scope and terminal results.

## Completion boundary and working constraints

F1 is the first bounded reliability fix; F2–F3 establish the main usable checkpoint.
F4–F7 are required before completing this goal. Track each exit and its evidence
in the current goal document. Do not
complete the goal after documentation, isolated diagnostics or one passing pilot.

Preserve unrelated dirty-tree work. Prefer retained inputs and small fixtures to
expensive pilot rebuilds. No commit, push, deployment, automatic boundary discovery,
new GUI, Rust integration, general borrow checker, universal concurrency model,
component-count target or complete application lift is required by this milestone.

The existing contextual-bisimulation contract remains strong proof authority.
Conditional local results, tests and declared effects do not authorize activation.
Existing pilot, native-link, repository-validation, export and portability gates
remain required for their corresponding claims; this milestone does not waive
them or require solving every pre-existing full-target qualification blocker.

## Acceptance evidence (complete within documented scope)

All retained paths below are under `build/behavior-faithful-workflow-2026-09-16/`.
The current goal records commands, phase costs, negative controls and terminal
session results. Scope restrictions in this plan remain part of acceptance.

| Exit | Evidence covering the requirement |
|---|---|
| F1 | `f1-final-focused-v2.log`, `f1-wayland-final.log`, `persistent-runtime-owned-v2/audit.json`, and the fresh `acceptance-workflow-v1/experimental-run-v2/`: bounded detached-writer/cancellation/startup/cleanup tests, private comparison sides, explicit suite state, 37 cases and 38 admissions with separate phase costs. |
| F2 | `test_comparison_resources.py`, `test_behavior_faithful_memory.py`, `f2-trace-audit.json`, and fresh `reference-leak` / `reference-leak-replay` checks: nested retention/alias/generation/error cases, visible allowed original defects, rejected false premises, defined-C expired reads/reuse/faults, and the real jq leak without driver edits. |
| F3 | `f7-rechecked-f3.json`: 16 current-reader validations of generated service bridges, nine service scenarios, six callee-body-free caller cases, 2734 erased native bytes, absent authored get symbol, edit/replay/repair and unchanged caller reuse after supplier/integration rechecks. Historical setup reduction is 584 to 420 lines before later composition/scalar additions. |
| F4 | `test_comparison_composition.py`, `f7-rechecked-f4.json`, and the fresh selected graph: transitive getpath/get resolution, consistent deduplication, middle/leaf edits, same-signature contract rejection naming consumers, representation/conflict/missing-supplier checks and explicit recursion with unproved progress. |
| F5 | `test_comparison_compile_cache.py`, `f7-rechecked-f5.json`, and the fresh workflow: one changed TU out of fourteen, relink/re-execution of affected integration, zero-work neighbors/unread headers, read-header/shadow/optional-include/checker invalidation, exact bindings, phase costs and retained storage. Unsupported preprocessing recompiles. |
| F6 | `float-pe32-v1/audit.json`, scalar/header unit tests, `shared-workflow-v1/audit.json`, and current authored `numeric-index.h`: binary32/64 ABI/edge/conversion checks, meaningful negative saturation/signature cases, and a separate conditional shared-service property with prove/disprove/unavailable/refine/reuse results. |
| F7 | `f7-audit-v1.json`: 106 isolated, 26 composed getpath and 37 full-network cases; 37 experimental cases; retained differences/resource failures/repairs; eight-case DX-Ball lifecycle regression; raw negative control; shared/representation regressions; metadata and scoped lint. `f7-final-audit-v1.json` binds terminal repository validation and current source hashes. |

The first broad Nix attempt timed out an existing allocation-cut query at its
unchanged 40-second limit. The identical shard passed in isolation. The two-job
affected run then completed with 249 passing derivations and one stale assertion
that treated supported 32-bit entry-register transport as unsupported. The
negative now uses unsupported partial-width transport; all 20 related local
tests and their Nix gates pass. The same 250-derivation selection with this
corrected shard passes offline with no rebuilds. Current header/scalar/shared
Nix checks also pass; all 55 acceptance source profiles remain unchanged.
The final audit binds these separate snapshots explicitly. No proof obligation,
timeout or activation gate was weakened.

The fresh walkthrough retained two rejected setup attempts: stale derived graph
after a contract edit, and isolated getpath evidence for a composed selection.
The fixture now refreshes the derived graph and supplies the composed comparison.
Corrected remaining commands completed using the same retained acceptance inputs.
No failed result was rewritten into a pass or used to authorize activation.
