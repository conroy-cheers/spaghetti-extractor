# Independent lifting: practical subsystem milestone and whole-target plan

Scope correction, 2026-09-29: delivery is idiomatic C compiled into a Windows
application, using Windows runtimes and preferably tested through Wine in a
headless Wayland desktop. Porting that C to native runtimes on other operating
systems is outside this project. This supersedes earlier mandatory portability
and second-architecture delivery requirements in this plan. Retain their completed
experiments as evidence; do not treat unfinished non-Windows backends as blockers
to the lifting workflow. See [the current goal](current-goal.md).

Status: reviewed 2026-09-22. Active practical delivery goal. Practical P1–P4 walkthroughs delivered;
strong whole-program qualification and broad runtime coverage remain unfinished.
H1–H3 are delivered in their bounded scopes. Standalone Hello now runs on x86-64
and AArch64 under QEMU within a Windows-1252 redirected-stream scope. Practical product
completion and the stronger G1–G7 qualification objective have separate exits below.
The selected twelve-unit jq subsystem also has a conventional source/runtime
handoff through normal program execution on both architectures, with an explicit
unlifted source backend; see the [current checkpoint](current-goal.md#portable-jq-subsystem-program-execution-and-local-updates--2026-09-22).
The [failure follow-up](current-goal.md#portable-jq-allocation-failure-interaction--2026-09-22)
also exercises selected real allocator/handler paths on both architectures. It
records a cold shared-context representation difference and a reference-only
defect, without expanding the network or adding a proof-completion requirement.
The later [cold-context adapter](current-goal.md#compare-a-changed-runtime-layout-without-pre-initializing-it--2026-09-24)
observes that object's actual lifetime and empty pointer slots on both architectures,
so the cold consumer now compares without pre-initializing it. Physical differences
remain explicit, and unrelated heap/reference discrepancies still fail.
The [public consumer handoff](current-goal.md#carry-the-cold-consumer-through-the-public-component-workflow--2026-09-24)
now carries that observation through ordinary check/edit/replay/export commands
and both portable projects while preserving the component contract and neighbors.
It demonstrates assembly and local updates beyond Hello, not a full jq lift.
The later [workspace/boundary reuse checkpoint](current-goal.md#local-boundary-workspace-and-reusable-jq-services--2026-09-22)
projects existing contracts into local authoring guides and validates them on a
new string operation using shared services/adapters. That operation joins the
portable project with actual program execution on both architectures; preparation
and local-edit costs remain distinct. This closes a concrete operator trial,
not broad-target readiness or another required formal campaign.
The later [byte-length trial](../tests/fixtures/jq-string-byte-length/README.md)
closes a retained string dependency using the same facilities. A shared C object
view removes a recursive adapter dependency; local edit/diagnosis/reuse and the
updated source program pass, including AArch64 execution. This is another concrete
operator finding about executable boundaries, not a new component-count exit.
This follows the operator's request to establish a complete manual partition
before adding more isolated demonstrations. The prior F1–F7 practical jq milestone
remains complete within its original scope.

## Practical subsystem milestone and sequencing

Reprioritised 2026-09-21 and reaffirmed by the 2026-09-22 side-thread review.
**Deliver and improve the executable stateful workflow before extending universal
composition proofs.** Completing the bounded P1–P4 examples does not automatically
return development priority to formal closure. First-time operator effort and
integration through real consumers control acceptance; H1–H3 now demonstrate both.
This section supersedes earlier next-step instructions in
this plan, the experiment history and the earlier goal text requiring all G1–G7
for product completion. The operator's later 2026-09-22 review changes completion
criteria as well as sequencing: general operator usefulness and a practically
validated whole-program lift control delivery. G1–G7 retain their full requirements
for the separate strong-assurance objective; universal qualification is not a
later compulsory phase of practical product delivery.

### Practical product completion

The acceptance test is: an operator can establish a new component boundary,
author idiomatic C, diagnose meaningful behavioral differences, reuse unaffected
work, and exercise the replacement through normal program execution using
documented facilities. The process must transfer to a structurally different
component without developing new checker, artifact or compiler internals.

H1–H3 are delivered. A practically validated whole-program lift must deliver
all of the following independently of formal closure:

- A previously unprepared boundary trial and different-target reuse, with manual
  analysis, C adapter work and first preparation effort recorded separately from
  warm edits. A runnable prepared example alone does not satisfy this criterion.
- Local workspaces exposing inputs, shared objects, services, outcomes, examples
  and assumptions. Define shared layouts and lifecycle conventions once and reuse
  them. Boundary establishment/refinement may require surrounding-code analysis;
  ordinary implementation edits use that recorded knowledge locally. Affected
  integration tests may rerun without requiring the operator to redesign neighbors.
- A standalone source project for complete Hello, with authored application C,
  explicit runtime/platform dependencies and reusable executable backends. The
  delivered configuration must not require original application bodies
  or generated Behavioral-C fallback. Mixed original/lifted execution is an
  intermediate integration step, not this whole-program exit.
- Builds and representative execution of the Windows source application, using
  Wine where appropriate, with retained original comparisons, generated cases,
  memory/interaction observations, deliberate defect detection and real workloads.
  Document widths, layouts, locale and other runtime assumptions and any
  unobserved behavior. Other-platform execution is outside project scope.
- Applicable practical integration, export, pilot and repository checks, exact
  source/runtime/tool bindings, reproducible commands and accurate invalidation.
  Maintain the existing strong gates and report their status separately; a gate
  whose purpose is formal qualification controls that claim, not practical
  readiness. Known discrepancies, stale evidence or missing executable behavior
  are not passing practical results.

This is readiness within the stated target and environment scope, not a theorem
about arbitrary Win32 programs. Tested behavior, assumptions, unobserved effects
and proved properties remain distinguishable. Focused proofs are available where
useful. Strong qualification still requires all corresponding G1–G7 evidence;
finite comparisons cannot supply it, and its standards are unchanged.

The [2026-09-25 practical delivery audit](practical-product-audit.md) now records
terminal evidence for these exits in their stated scopes: standalone Hello on
x86-64 and AArch64, source-assisted partial jq, and connected DX-Ball with
controlled graphics services. Repository reconciliation and the current installed
operator handoffs pass. This completes the scoped practical milestone; full jq,
native DirectDraw, wider runtime environments and G1–G7 remain separate work.

The [standalone Hello checkpoint](../tests/fixtures/hello-standalone/README.md)
now delivers source assembly, application/runtime C and execution on x86-64 and
AArch64 under QEMU for a Windows-1252 redirected-stream configuration. Its 73-case
matrix includes generated inputs, argument errors and output failures. A deliberate
UTF-16 defect leaves text unchanged and is caught by memory observations, then
replayed after source repair. The project builds outside the checkout without
original application bodies or a toolkit build dependency. This is a bounded
practical whole-program result, not broad runtime readiness: target narrow-byte
arguments, source-assisted frontend control and the remaining locale/interactive/
failure-path exclusions are explicit. Next work must address those concrete
operator/runtime gaps, not restore mandatory universal qualification.

The subsequent portable UTF-8 entry closes the argument-preparation gap for that
profile: the source program itself computes the original narrow bytes, with no
Windows API dependency. Its 82-case program matrix passes on both architectures,
as does the raw-entry regression. A best-fit mapping defect changes option parsing
and is detected/replayed/repaired without changing neighboring component contracts.
The shared adapter's ownership and input/failure contracts accompany the exported
source project. Other locales and native terminal output remain concrete delivery
gaps; this is not a broader qualification claim.

The subsequent allocation-failure checkpoint exercises the real fatal path through
normal program entry, with an explicit lower-service fault instead of simulated
termination. Seventeen cases pass on x86-64 and AArch64, including ten reached
faults and seven bypass/disabled/unreached controls; the ordinary 82-case regression
also passes. A wrong exit status with identical diagnostics is detected, replayed
and repaired while component contracts/receipts stay unchanged. The conventional
source project carries the optional diagnostic C/linker overlay and runs outside
the checkout. Physical exhaustion and unrelated entry/CRT allocation failures
remain unobserved. This closes a concrete integration gap without adding proof
machinery or making stronger qualification a practical-delivery prerequisite.

The standalone handoff subsequently exposed a missing round-trip operation:
re-exporting a checked component required manual replacement of an existing source
library. Public `candidate export --update` now closes that gap for unchanged
boundaries and shared/header inputs, preserving application/backend work and a
prior-tree backup. A different Hello scan implementation passes local checks,
zero-work neighbor reuse, mismatch/replay/repair and 82 program cases on both
architectures. The same update/build operation transfers to the jq source selection.
This improves the operator workflow; it does not qualify changed contracts or turn
the jq library into a complete portable program. Remaining work should follow the
measured adapter/setup and runtime-startup costs, not isolated fixture counts.

The subsequent stream-close trial establishes a previously unprepared boundary
with existing tooling and replaces the standalone backend's decision logic with
its compared C. Seven native/local cases, detected error/lifetime defects,
zero-work neighbor reuse and normal shutdown exercise the operator acceptance
test above. Eighty-two program cases pass on x86-64 and AArch64. Initial work remains
mostly adapters, observations and assembly; this adds no formal-completion gate.

The normal loop is manual boundary definition, ordinary C, original/replacement
comparison, discrepancy replay, real-consumer integration and reuse. Focused
proofs supplement this loop where supported. An unavailable rule or solver timeout
must not block an otherwise executable configuration under an explicit experimental
policy. A behavioral discrepancy or missing runtime transport is a different
finding and must remain visible. Preserve the existing policy's rejection of
disproved contracts; do not erase an existing counterexample by omitting a check.

Current code already separates these paths: `comparison_run.py` records formal
checking separately, and `experimental_manifest.py` permits `not-requested`,
`unavailable` and `timeout` when the selected policy explicitly accepts them.
The immediate work is to make difficult boundaries executable and reusable through
that path, rather than introduce another assurance format or weaken strong readers.

The [array storage checkpoint](../tests/fixtures/jq-array-storage/README.md)
connects seven authored storage operations to the four path/value callers and
demonstrates edit/compare/replay/repair/reuse. The first experimental assembly
passes 37 cases. The cleanup follow-up adds nineteen retained/generated storage
sequences, lifetime-only negative controls and matching observations through real
consumers. It also exposes an original NaN-index reference leak that the authored
setter must preserve; the corrected local setter and connected network pass 29
and 38 comparisons respectively. The revised edit/reuse workflow and experimental
assembly also pass, including all 38 consumer cases with cleanup observations.
The subsequent nonlocal protocol also passes five actual guarded-allocation
failures in the connected array network and a public C edit/replay/repair workflow.
Ordinary path/interpreter regressions still pass with the updated engine. The
subsequent path follow-up carries actual failure through those consumers and
corrects two C differences exposed by allocation failure: early index release and
an omitted empty-tail allocation. The current public eleven-unit assembly passes
42 cases, including a real interpreter failure, with formal checks not requested.
Both incorrect C variants have retained replay and zero-work repair evidence.
The selected native crossings are now inventoried at the adapter/source level;
they still constrain representation changes.

The [fresh-boundary checkpoint](../tests/fixtures/jq-path-controlled/README.md)
subsequently defines the caller interface from retained runtime/type inputs and
ordinary C using the documented package API. Six controlled caller cases exclude
both the native get body and the authored supplier while retaining real array
services. The public workflow reuses that caller across a supplier edit, reruns
27 actual integration cases, and rejects/replays a faulty supplier. This delivers
the selected jq setup and isolation demonstration. Shared suite admission then
reduces the same retained 42-case experimental run from 212.155s to 25.262s, with
content/lookup checks around every case and unchanged experimental policy.
The subsequent private-descriptor migration now completes the bounded
representation example: same-signature mixed layouts reject before compilation,
a coherent wrong conversion fails and replays, affected comparisons rerun, and
the eleven-unit experimental assembly passes all 42 cases. The unchanged native
get-service check and a getter unaffected by a setter edit reuse independently.
Eight Nix shards pass 58 tests and six repository/SDK gates. Native backing-array
layout dependencies remain explicit.

The subsequent [DX-Ball walkthrough](../tests/fixtures/dxball-graphics-network/README.md)
delivers P4 with actual initialization, shared-table reset, surface binding and
sprite blit. It prepares manual interfaces and C through the same APIs, compares
37 connected cases, rechecks a compatible reset edit while reusing unaffected
neighbors, detects/replays table-state and stale-window defects, and passes a
four-unit experimental assembly. All formal checks are not requested. No per-unit
toolkit/checker extension was required. The original oracle is retained
machine-derived C; controlled platform services and synchronous window mutation
remain explicit assumptions. P1–P4's selected implementation/execution exits are
delivered, with repository validation recorded in the current ledger. These
checkpoints do not establish arbitrary-target usability or whole-program
qualification.

### Scheduling and useful checkpoints

Choose the next task by the operator action it enables: define a boundary, execute
its state and interactions, diagnose a discrepancy, edit one implementation, reuse
unaffected evidence or assemble the selected network. An ordinary new unit should
require interface declarations and C, not a new proof rule. Extend shared runtime
facilities only for a concrete consumer, then test their reuse on the second target.
Existing examples are regression assets, not an open-ended polishing queue. A new
trial should expose a repeated boundary-preparation, adapter, observation or
assembly task; address the shared obstacle and stop once the operator can complete
that action and reuse it on a structurally different consumer. Preparation effort
matters independently of warm edit speed. Additional example coverage and marginal
runtime optimizations do not substitute for that outcome.

The [handoff ledger](current-goal.md#operatorprogram-handoff) records the completed
bounded milestone; [standalone delivery](current-goal.md#next-delivery) is the work queue.
The [source-library handoff](../tests/fixtures/hello-source/README.md) now exports
the nine compared Hello components with their existing source packages, interfaces
and contract assumptions, then compiles them outside the checkout. Application
entry, portable service/runtime bindings and second-architecture execution remain
required; this library checkpoint does not satisfy whole-program delivery.
The selected jq failure/assembly, boundary setup, isolation/representation and
connected DX-Ball demonstrations are delivered. The subsequent
[allocation/quoting checkpoint](../tests/fixtures/hello-allocation-growth/README.md)
replaces simulated growth with the actual operation, independent local checks and
a three-unit experimental assembly. Its subsequent
[native-caller handoff](../tests/fixtures/hello-native-quoting/README.md) now passes
public editing, replay, reuse and experimental execution with the same authored
units. The subsequent fresh-package pass removes the historical free-wrapper
package dependency and consolidates supplier binding through the existing APIs.
It reproduces Hello setup from original slices and repeats the jq/DX-Ball consumers.
The [complete cleanup extension](../tests/fixtures/hello-quoting-cleanup/README.md)
now lifts the shared-cache release loop through that setup. Local comparisons
omit the supplier body; native integration selects four authored components and
demonstrates independent cleanup editing, discrepancy replay and neighbor reuse.
Its declared local release assumptions remain separate from the connected native
evidence and later checked-summary obligations.
The subsequent [reallocation extension](../tests/fixtures/hello-reallocation/README.md)
owns the complete lower wrapper and return, adds 216 local cases without CRT
supplier bodies, and integrates beneath actual native `xrealloc`. Independent
editing, local/native discrepancy replay, free-neighbor reuse and a five-unit
experimental assembly pass without new tool or proof machinery. Higher wrappers
still share a return/fatal-failure tail and require deliberate ownership review;
the new scope does not claim that tail or actual allocation exhaustion.
The [checked allocation family](../tests/fixtures/hello-checked-allocation/README.md)
now addresses that ownership gap by grouping eight operations and two aliases with
their shared return/failure tail. The public local/native workflow passes with
the shared tail removed, controlled nonlocal failure, independent editing and
neighbor reuse. A concrete `void(void)` callback limitation is fixed in existing
service contracts and checked through real C; jq and DX-Ball regressions pass.
This is manual grouped ownership with explicit lower-service assumptions, not
general split/merge proof or actual fatal-process coverage.
The subsequent [terminal adapter](../tests/fixtures/hello-native-quoting/README.md#actual-fatal-diagnostics-and-process-termination)
now closes that specific execution gap using ordinary C: child processes run the
actual fatal body, diagnostic output and CRT exit/abort after injected allocation
failure. Public editing, retained discrepancy replay, unaffected-neighbor reuse
and experimental assembly pass without adding a component or proof machinery.
Capture errors reject; startup/TLS, physical allocator exhaustion and arbitrary
callback/signal behavior remain outside the tested scope.
The [complete quoting-engine extension](../tests/fixtures/hello-quote-engine/README.md)
then removes the substantial retained quoting loop from native consumer execution.
It authors all eleven styles in ordinary C, preserving live buffer/mask aliases
and making locale/conversion services explicit. The public local/native edit,
NUL-elision discrepancy replay, controlled-caller reuse and seven-component
experimental assembly pass. The connected jq consumer and actual-terminal Hello
regression also pass with the shared large-body interception helper. No new proof
rule or tool-internal component implementation was needed. The native locale
services and original startup remain distinct unfinished portability obligations.
The [stateful conversion family](../tests/fixtures/hello-multibyte/README.md) now
adds complete conversion/reset operations and two implicit state cells beneath
the same engine. Local and both consumer levels pass public edit/replay/repair,
unchanged-neighbor reuse and an eight-component experimental run. Native locales
remain separate from its controlled UTF-8 context; the lower CRT is still retained.
That closes the in-flight dependency extension. Freeze this connected scope for
H1–H3 below, instead of selecting another dependency simply because it remains
native. Continue measuring setup and edit/diagnosis costs, and verify shared
changes through the existing consumers.
A missing callback path
can justify one executable delivery adapter; it does not by itself justify a
general callback calculus or universal environment model. Retain actual mismatches
and unsupported paths even when choosing a bounded scope for the next checkpoint.

Publish each completed executable checkpoint with its tested scope, assumptions,
formal status and remaining native dependencies. Operators need not wait for P4,
complete Hello qualification or another architecture to use an eligible experimental
configuration. P1–P4 measure whether that workflow is reusable; G1–G7 measure the
later stronger whole-program claims. Neither criterion substitutes for the other.

Acceptance requires a reproducible first-time setup as well as editing an already
prepared package. An operator may supply manual declarations through documented
authoring APIs and write target-specific C adapters. Reusable templates must own
routine package construction, generated identities and compiler setup. Requiring
a new checker or changes to tool internals for each ordinary component fails this
criterion, regardless of how many prepared fixtures pass. Record which common
facilities both targets actually use and the manual work each needs.

The active goal's earlier comparison/lowercase pair is an achieved intermediate
gate, not the next work item. This mandatory plan controls current sequencing.
Schedule formal work for an explicitly chosen stronger claim or a concrete
behavioral risk; do not make completion of the practical examples a trigger for
broader proof closure. Optimize measured setup, warm editing and diagnosis costs
first. Repeated evidence validation is currently more relevant than another
unrestricted Hello solver attempt or pilot rebuild. All G1–G7 qualification
obligations remain required for the separate strong-assurance objective.

The 2026-09-22 priority review bounds the representation delivery to one coherent
jq walkthrough, now delivered alongside connected DX-Ball reuse. A changed private
descriptor with explicit conversions is a valid example
if its retained native backing-layout dependency is disclosed; it does not claim
arbitrary heap-layout migration. Do not expand this example into universal memory
transport before a concrete consumer requires it. Additional toolkit work must
address a demonstrated runtime gap, discrepancy, repeated operator step or measured
edit-loop cost. Preserve
required regressions and strong readers while keeping optional proof development
out of the practical milestone's critical path.

### H1–H3: operator handoff and program execution

Status: delivered within its recorded experimental scopes on 2026-09-22.
Fresh-input Hello and DX-Ball recipes pass, with the retained jq regression.
Normal-entry Hello passes within its twelve-workload scope. The subsequently
[unprepared string-conversion boundary](../tests/fixtures/hello-string-conversion/README.md)
passes local author/edit/diagnose/replay/reuse and normal-program execution without
new tool internals. This supersedes the instruction to grow connected Hello
coverage. The bounded jq storage/path and DX-Ball lifecycle demonstrations already
establish useful practical results. This milestone makes that work repeatable and
carries the Hello selection through actual program execution. Continue with the
practical standalone-source/runtime/second-architecture exits; do not replace them
with more component fixtures or a compulsory universal proof campaign.

**H1 — Fresh-input operator handoff.** Start in a fresh output directory with
pinned original/runtime inputs and the supported tools. Document how those inputs
are obtained or exported once; a developer's historical comparison output must
not be a setup prerequisite. Reuse existing package factories, SDK exports and
authoring APIs. Manual boundary declarations and target-specific C adapters are
acceptable; routine model, digest, generated-code or Nix edits are not.

Reproduce the current Hello network, then define a previously unprepared component
using the documented facilities. Select it for a different boundary shape, not an
additional count. Existing reviewed types/services and general templates may be
reused, but a prewritten declaration/adapter for that exact component cannot stand
in for the trial. Record prior knowledge, analysis steps, elapsed preparation
effort and manual adapter/declaration work; automated preparation seconds alone
do not measure first-time operator effort. A needed checker, artifact-machinery
or compiler-infrastructure change is a tooling gap to resolve and retest, not a
successful independent-component trial.

Expose the component's inputs, shared objects, services, outcomes, examples and
assumptions in its workspace, referencing common layouts/lifecycle conventions.
Demonstrate a compatible C edit, a memory/service discrepancy,
retained replay after repair, correct integration invalidation, unchanged-neighbor
reuse and experimental build/run. Record which work is authored, generated or
reused and the time for setup, first comparison, warm editing and diagnosis.
Separate compiler, model, solver, execution, linking and evidence-validation costs.
Do not require a fresh human participant where unavailable: an agent can perform
the documented trial, but must report that limitation and cannot claim an
independent human usability study. Ordinary edits must remain local; changes to
the boundary must expose their dependencies and integration invalidation.

**H2 — Normal program execution.** Use the H1 selection through Hello's normal
program entry, with original startup/TLS and retained services either executed or
explicitly implemented. The current DLL-style routine image clears entry/TLS and
does not satisfy this exit. Reuse the existing native-entry/runtime infrastructure;
introduce new machinery only for an observed execution gap.

Derive command-line workloads from actual program behavior: normal/custom greeting,
help/version, malformed arguments, relevant conversion and output/failure paths.
Compare original and experimental replacement exit status, output and relevant
boundary state/interactions. Demonstrate that workloads actually enter selected C,
including stateful allocation/conversion behavior. Report entries not reached;
their presence in the binary or in a separate routine suite is not execution
coverage. In particular, do not assume every linked quoting operation is exercised
by Hello's command line. A deliberate implementation defect must propagate to a
replayable program-level discrepancy, then disappear after repair. Retained native
services are permitted by the explicit experimental policy and remain inventoried.

The [normal-entry Hello recipe](../tests/fixtures/hello-program/README.md) now
delivers this bounded program handoff: twelve workloads through original startup
and both TLS callbacks, a compatible local edit, unchanged-neighbor reuse, a
program-output defect, retained replay after repair and a passing repaired run.
It reports selected but unexecuted operations. The selected routine case misses
the decoded-character defect that actual program output detects. It remains a
mixed original/lifted experiment; allocation exhaustion, output-I/O failure
injection and general asynchronous/termination behavior are outside this matrix.

**H3 — Transfer and close the handoff.** Apply the H1 input/setup path to the
connected DX-Ball lifecycle/graphics scope using the same public authoring and
runtime facilities. Target adapters may differ. Reuse existing evidence wherever
it already meets these criteria and its bindings remain current; rerun affected
integration when shared facilities change. Preserve jq's connected state/allocation
regressions. Record shared facilities, manual adapter work and unsupported
semantics. Controlled retained-C graphics execution remains that bounded claim;
this milestone does not require or claim a complete native DirectDraw environment.

**Completion and scheduling.** All three exits require retained executable results
and a reproducible recipe. An unavailable formal rule or solver timeout is not a
blocker when accepted by the existing experimental policy. A missing executable
binding, stale input, observed mismatch or disproved contract is not a pass.
Keep tested, assumed, unobserved and proved findings separate. Further unit lifting,
runtime generalization or performance work must resolve a practical delivery gap
or a measured operator cost; close that workflow after the fix. Universal memory/callback proofs,
automatic boundary recommendations and extra fixture counts are deferred.

H1–H3 are a practical completion point independent of G1–G7 formal closure. They
do not alone complete the practical whole-program delivery above. The subsequent
standalone source/backend/second-architecture checkpoint now supplies those paths
within its documented environment scope; wider runtime coverage remains open. Preserve
contextual-bisimulation and qualified-native-admission standards for the stronger
claims; do not require them to approve an explicitly experimental configuration.
An experimental x86 program run supplies neither complete portability nor proof.

### P1: freeze a connected scope and executable boundaries

Use the existing jq path/value network as the consumer. Extend downward into
**array storage and lifetime operations**: creation, retain/release, shared reads,
mutation with copy-on-write, growth and destruction. The existing path get/set
callers provide multiple contexts, nested values and real interpreter consumers.
Begin by mapping the actual pinned original operations, representation readers
and service calls; finalize a coherent replacement group before editing bodies.
These are proposed semantic responsibilities, not assumed one-to-one function cuts.

Record exactly which value kinds, operations, entries, outcomes and runtime
services are covered. Trace storage and ownership through real callers. For the
completed milestone, in-scope candidate storage, reference accounting and
copy-on-write must be authored C;
wrapping native `jv` references in tokens does not meet this exit. A narrow platform
allocator and explicit services for outside-scope value kinds may remain. Record
those dependencies, and reject unsupported crossings instead of silently falling
back to the original implementation. Preserve identity and sharing when a value
crosses that boundary; rebuilding equal JSON values is insufficient.

Use canonical interfaces, service catalogs, representation groups, comparison
packages and the existing SDK. Generate routine headers, bridges and observations.
Supply nonmechanical runtime semantics through documented, reusable C adapters.
Within the supported dialect, allocation goes through an executable typed service
and mutable state through explicit context. Neither requires a new solver rule.
Using a documented Python authoring API is acceptable; requiring edits to toolkit
Python or a bespoke package/checker implementation for each unit is not. Generate
routine package metadata through existing facilities. Do not require operators to
hand-edit proof models, generated hashes or Nix expressions for each unit.

**Exit:** a reviewed boundary map, an executable original-side oracle, runtime
transport/service adapters and materialized public C work packages. Inventory
every retained native dependency and unobserved effect. Package preparation alone
does not complete the milestone.

### P2: lift, compare and diagnose the stateful subsystem

Complete the selected responsibilities in ordinary C and connect the existing
value/path consumers through public `component start` and `component check`.
Keep the pinned original oracle independent of the authored candidate. A shared
transport helper must not implement the algorithm on both comparison sides.

Use retained examples and deterministically generated operation sequences with
replayable seeds and inputs. Exercise shared and unique arrays, nested aliases,
growth, in-place mutation, copy-on-write, release after mutation and allocation
failure according to the original's actual failure behavior. Observe returned
values, retained aliases, current memory effects, lifecycle/resource effects,
service ordering and outcomes. Compare logical observations across representations;
raw pointer equality or equal final JSON alone is inadequate. Distinguish observed
effects from assumed or unobserved native internals. Existing original defects can
be preserved under an explicit contract using defined C.

Include a sequence that retains an alias, updates the original, then reads and
releases both; a missing copy-on-write must leave a replayable discrepancy.
Inject a reference/lifetime defect that final-value equality would miss, and an
allocation-failure discrepancy. Show the first useful difference, replay after
editing the draft, repair, and rerun through actual jq consumers. Generation and
fault control belong in reusable C drivers/adapters; they do not demand a universal
environment model or new target-specific Python checker.

**Exit:** the connected subsystem runs with matching declared observations,
meaningful negative controls and repair evidence through the public workflow.
Missing formal rules remain reported as unavailable. This is tested behavior
under explicit assumptions, not whole-jq equivalence or a proof of its heap.

### P3: demonstrate independent editing and integration

Perform a compatible local implementation edit. Recheck its supplier and affected
integrations while reusing unchanged local neighbors. Include a caller comparison
against controlled dependency behavior with the callee body absent on both sides;
its reuse is conditional on those stated behaviors. Separate that local result
from the real-supplier integration run. A same-signature contract change and a
shared-representation change must identify affected consumers accurately.

Demonstrate one compatible representation change with a coherent group selection,
preserved contents/aliases/lifetime and fresh affected evidence. Do not demand that
representation-dependent neighbors reuse unchanged evidence. Build and test the
network with `candidate build --experimental-comparison` and
`candidate test --experimental-package`; verify selected implementations actually
execute. An otherwise eligible network must still run with formal checking
unavailable or timed out under its explicit policy. Experimental receipts remain
unacceptable to strong qualification/link/export readers.

**Exit:** a reproducible public author/edit/compare/replay/repair/integrate/reuse
walkthrough. Measure preparation, compilation, comparison execution, evidence
validation, linking, optional model/solver work and retained storage separately.
Report cold setup, warm edits, unchanged reuse and time to the first discrepancy.
Also record operator-written declarations/adapters versus generated setup and any
required changes to tool internals. Optimize the measured edit loop; no new broad
pilot rebuild or proof optimization is justified solely by an isolated timeout.

### P4: reuse on a structurally different connected target

Apply the same facilities to DX-Ball's initialization/resource lifecycle, extending
beyond the existing two early-failure branches to a normal continuation and an
actual connected consumer. Map the real entries and interactions first; do not
invent cleanup absent from the original. Exercise mutable resource identity,
service failure and any callback needed by the selected path using executable
adapters. Missing callback delivery, reentrancy or memory transport is an explicit
runtime gap even when no proof is requested.

Reuse the public workflow, service/runtime facilities and evidence machinery.
Target-specific C adapters are expected; per-unit proof-engine extensions are not
an acceptance dependency. Retain the distinction between controlled retained-C
execution and actual Win32 execution. Every Wine process uses headless Wayland.

**Exit:** a second connected author/edit/diagnose/integrate/reuse walkthrough and
a concrete account of which facilities were reused and which semantics remain
unsupported. A second leaf or another copy of the jq transport demo is insufficient.

P1–P4 and H1–H3 record delivered bounded practical milestones. Use their observed
gaps to prioritize the practical whole-program source, backend
and portability exits above. Stronger G2/G4/G5 assurance and G6's executable-bound
strong receipts remain a separate objective. Applicable pilot/native-link/export/
repository gates retain their requirements for their corresponding claims.
Practical readiness does not establish general Win32 coverage.

The operator's later 2026-09-22 direction explicitly limits exhaustive runtime
edge-case work: after a useful bounded backend result, return to component
handoff unless an actual operator task is blocked. The console follow-up retains
its known control-character mismatch; closing that matrix is not the next
component-workflow milestone. Prefer a new boundary prepared with documented
facilities, a local C edit, useful discrepancy feedback, reuse and integration.

## Operator needs and acceptance contract

This section and G1–G7 specify the stronger qualification objective. The practical
product completion criteria above control ordinary delivery and do not require
universal formal closure.

The requested workflow has three connected outcomes. All are required; success
at one stage cannot stand in for the next.

| Operator need | Required demonstration | Acceptance exits |
|---|---|---|
| Carefully partition a large machine-decompiled target into manageable units, manually if necessary | Review complete ownership and semantic interfaces; author and refine boundaries with checked state transport, coverage and progress; obtain usable C work packages and actionable unsupported-feature diagnostics | G1, G3, G4 |
| Lift each unit into reasonably idiomatic portable C with high assurance of original behavior | Check the implementation against admitted machine states and neighboring contracts without importing neighboring bodies; recheck a local edit while reusing unaffected evidence; reject incompatible contracts and incorrect implementations | G2, G4, G5 |
| Assemble all lifted units into a behavior-preserving program on x86, with demonstrated portability | Discharge composition and runtime premises, select complete portable coverage, bind strong receipts to the actual executable, and execute the complete program on x86 and a second architecture | G6, G7 |

Here, **independent** means an operator needs the selected unit's original
semantics, its implementation, and its explicit dependency contracts. They do
not need to inspect or reprove neighboring implementations for a compatible local
edit. Establishing those contracts and discharging their premises at integration
still requires system knowledge. A changed contract or shared representation can
legitimately affect consumers; the tooling must show exactly which assumptions
changed and which evidence remains reusable. Query-cache hits alone do not meet
the zero caller model/compiler/solver-work requirement in G2.

Keep assurance claims attached to their scope: original executable identity,
admitted inputs and environment, observations and outcomes, machine/C relation,
and trusted compiler/runtime/model assumptions. Strong equivalence within that
scope is the x86 acceptance claim. Finite comparisons support practical confidence
but do not prove equivalence for all executions. A second-architecture run supplies
portability evidence, not an unconditional guarantee for every platform. Preserve
explicitly modeled original defects through defined C rather than silently
requiring a safer original program.

GNU Hello is the first complete-program acceptance target. The connected jq or
DX-Ball reuse case must exercise structurally different contracts through the
same public workflow. Neither milestone establishes support for arbitrary Win32
programs: unsupported interactions must remain visible and fail closed. Further
breadth follows actual target requirements, rather than adding component counts
or automatic boundary recommendations before this workflow works.

### Required operator walkthrough

Retain a reproducible public-command walkthrough that connects these outcomes:

1. Select a manually defined operation from the target inventory and inspect its
   complete ownership, admitted states, memory and service contracts, dependency
   assumptions, and unsupported features.
2. Obtain a C work package, author its implementation, and check it against the
   original operation using checked neighboring contracts with their bodies absent.
3. Edit a supplier implementation compatibly, check that supplier, and reuse the
   unchanged caller evidence without generating, compiling or solving caller models.
   Separately reject a wrong implementation and a same-signature incompatible
   contract; identify the affected consumers and evidence.
4. Refine a boundary with a manual split and merge, checking state transport,
   coverage and progress and showing precisely which evidence needs replacement.
5. Qualify and select the replacements, link the executable, and inspect the
   current composition and dispatch/link receipts. Repeat through complete Hello
   assembly and second-architecture execution, then demonstrate connected reuse
   on jq or DX-Ball.

Record the input identities, commands, terminal results and separate preparation,
model, compiler, solver and link costs at each relevant step. This walkthrough
ties G1–G7 together; separate successful fixtures do not establish that operators
can perform the combined workflow. The first comparison/lowercase pair exercises
the initial integration gate without replacing the later completion requirements.

For each open exit, the current-goal handoff must identify the missing operator
capability or acceptance result, the next concrete demonstration, and the exact
terminal evidence. Keep historical experiments separate from current status.
When performance prevents completion, record the failing obligation and phase
costs; investigate retained models before repeating pilot builds or increasing
solver budgets. A tooling optimization is progress only toward the connected
walkthrough, and cannot replace its edit/reuse and executable acceptance gates.

## What is now concrete

`targets/gnu-hello/intent/whole-program-partition.json` assigns every original
transfer to one of 370 proposed routine boundaries. It transcribes the original
PE's named COFF routines; aliases share ownership, duplicated local names retain
their RVAs, and eleven cold fragments stay with their corresponding hot routine.
Alignment transfers remain covered. These are planning units, not 370 checked
components. No automatic boundary recommender was added.

The new `boundary inventory` command checks this plan against the existing
packaged linked semantic module and projects its canonical relocations. It checks
nonoverlap, rejects cuts through a transfer, exposes missing ownership, and keeps
runtime dispatch, callbacks, storage, roots, semantic holes and analysis frontiers
visible. Checked-infeasible no-return continuations remain recorded; they are not
resurrected from the earlier raw control graph.

The partition intent is needed because the existing component indexes describe
selected replacements, not ownership of the whole target. It is a small planning
overlay on the canonical universe. It supplies no machine binding, contract,
proof, selection, or independent authority. The derived report is diagnostic
output and is not accepted by qualification or native-link readers.

The inventory reads existing V5 interface/binding indexes and optional V2
qualifications. It includes declared interfaces, owned units, unowned proof
context, current qualified definitions and uncovered definitions. Qualification
and exact-context slices must match the supplied semantic module. Signature or
range equality alone cannot establish contract compatibility. A complete coverage
result never changes `activation_authorized: false`.

The first run found a stale index hash for `last-path-component`; the index now
matches the already-authored binding. No binding semantics were changed.

## Reproduce without rebuilding the pilot

Use a retained *package*, including the semantic object and its members:

```sh
spaghetti-extractor boundary inventory gnu-hello \
  --partition targets/gnu-hello/intent/whole-program-partition.json \
  --semantic-module "$hello_module/linked-semantic-module.json" \
  --bindings targets/gnu-hello/intent/bindings-v5/index.json \
  --interfaces targets/gnu-hello/intent/interfaces-v5/index.json \
  --output build/hello-partition-inventory.json
```

`--qualification PATH` is repeatable. Exit 1 means incomplete structural coverage;
malformed, overlapping, foreign-image and stale inputs reject. Exit 0 means only
that every original transfer has a planning owner. Edits, splits and merges are
manual JSON changes followed by this audit. They do not edit production APIs or
establish state transport, progress or proof reuse. Those remain checked by the
existing V5/V6 and contextual-bisimulation machinery.

The inspected retained package is
`/nix/store/rfhqmavs5kfmibk0fglssxfyjqhykcbf-spaghetti-extractor-gnu-hello-linked-semantic-module-v2`.
Its semantic identity is
`7ea3a5d978dd421dfb52a44215e266b9321fb11252c5b11ff51df2343c3f3c2e`;
the original PE SHA-256 is
`71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c`.
Two other retained versions failed current schema readers and were not used.
This is validated retained evidence, not a fresh rebuild of today's complete target.

`build/hello-whole-partition-2026-09-16/inventory.json` contains the measured audit:

| Item | Observed |
|---|---:|
| Original transfers assigned exactly once | 7,849 / 7,849 |
| Proposed routine boundaries | 370 |
| Non-code definitions retained separately | 170 |
| Residual provider obligations retained | 109 |
| Distinct per-routine dependency subjects | 973 |
| Existing canonical component bindings inspected | 12 |
| Existing bindings with unowned proof context | 6 |
| Routines larger than 100 transfer units | 18 |

Two supplied retained complete portable qualifications cover three definitions.
This is evidence supplied to this audit, not an exhaustive count of proofs in the
repository. Neither those three definitions nor the 370 partition entries imply
three or 370 completely lifted routines.

The measured run spent 5.284 seconds validating the retained module, 0.011 seconds
validating catalogs and 0.022 seconds computing the inventory. Preparation builds,
compiler invocations, model builds, solver invocations and links were all zero.
This establishes a cheap planning loop, not improved proof performance.

## What the partition reveals: strong-qualification backlog

The original inventory order below describes the stronger whole-Hello work.
The [practical subsystem milestone](#practical-subsystem-milestone-and-sequencing)
now determines immediate implementation order.

1. **Close whole-operation boundaries.** `c_tolower`, `c_strcasecmp`, `strnlen`,
   `last_component`, `memeq` and `set_program_name` have configured subcomponents
   with unowned proof context. The context is inside each proposed routine, so
   closing its return/continuation is preferable to creating artificial public
   tail APIs. Establish full routine ownership with the existing canonical
   interface, state transport and contextual proof. Do not merely transfer
   ownership of a tail whose proof still assumes generated machine code.
2. **Connect checked neighboring contracts through final admission.** Use the
   actual `c_strcasecmp` -> `c_tolower` consumer first: the current ordinary C
   already calls `lower_ascii`. Preserve the source service, read-only memory,
   aliases, returns and frames. Prove the caller without the supplier body, change
   the supplier and reuse the caller evidence, then qualify the combined
   selection with both full routine bodies replaced. Existing conditional
   summaries are reusable infrastructure; their conditional premises still need
   discharge before strong activation. Do not weaken exact-context selection.
3. **Address stateful families using actual consumers.** Quoting has option and
   slot state; allocation and big-number conversion share lifetime and mutable
   objects; multibyte conversion shares locale/conversion state; CRT startup has
   TLS, handlers and deferred callbacks. Author those contracts in the existing
   interfaces and use implemented summary rules where applicable. Missing rules
   must name an actual boundary and premise. No whole-heap model or declared
   effects masquerading as checked summaries is required by this inventory.
4. **Keep large logic behind reasonable interfaces.** `gdtoa` has 710 transfers,
   quoting 531, multibyte search 332, and narrow/wide formatting 296/305. Introduce
   proof regions and loop invariants inside these routines, or split at a real
   helper boundary where state transport is understood. A large routine is not
   itself evidence for creating dozens of public components. Replacement groups
   can coordinate representation changes without conflating them with proof cuts.
5. **Finish actual program assembly.** Select providers for every definition and
   obligation, including 83 indirect external callthrough, 14 callback-publication
   and 12 internal-dispatch obligations in this retained module. These are not
   necessarily missing runtime implementations: validate existing providers
   first. The existing portable selection must reject generated Behavioral-C
   fallbacks, and native realization must produce its exact dispatch/link receipt.
   Run target/export/repository gates and a second-platform build and behavioral
   comparison. Host compilation alone does not establish cross-platform behavior.

Completion requires an end-to-end whole-program selection and executable, plus a
public local-edit/neighbor-reuse demonstration in that selection. This inventory
does not complete that milestone. The original first comparison/lowercase
connection now has retained qualification and reuse evidence; the practical
stateful subsystem is the next implementation priority.

## Inventory validation

The new small-fixture tests exercise omissions, overlap, invalid range endpoints,
partial-transfer cuts, foreign images, hot/cold ownership, callbacks and storage,
manual split/merge crossings, unowned proof context, stale qualification and
context slices, residual obligations, and CLI exit status. They keep structural
coverage distinct from proof and activation. The real retained Hello audit uses
the normal package, index and qualification readers.

All 65 targeted unit tests pass. The six selected Nix test shards and five
repository checks (metadata freshness, format registry, production lint, module
closure and retired-architecture boundary) pass. The retained real-target
negative test omits `main`, reports 22 unassigned transfers and exits 1. Exact
commands, logs and results are under `build/hello-whole-partition-2026-09-16/`.
No pilot, proof, Wine session or complete native executable was rebuilt.

## Required implementation and acceptance: G1–G7

These exits remain mandatory for the separate strong-assurance objective, not
for practical product readiness. Historical progress entries below retain their
original proof scope and do not override the current delivery criteria above.

The stronger objective is an operator-usable, manually decomposed GNU Hello lift whose
ordinary portable-C components can be edited and assured against stable checked
contracts, composed into a complete qualified executable, and reused through the
same workflow on another target. Existing retained inventory counts are baseline
observations, not acceptance quotas. Inspect current implementation and evidence
before deciding what remains to implement.

| Exit | Required result | Current status |
|---|---|---|
| G1 | Complete operation ownership and checked boundaries | Open for whole Hello; full lowercase and comparison local qualifications pass |
| G2 | Body-independent local assurance connected to native admission | Comparison/lowercase local and Nix zero-work caller reuse plus combined native link pass; broader contracts remain open |
| G3 | Practical manual contract authoring, review and invalidation | Partial; public scalar-contract refinement and internal-region split/merge reach caller reuse/native admission on retained builders; full SDK and ownership-changing boundaries remain |
| G4 | Reusable shared-state and interaction contracts through real consumers | Real quoting constructor/setter/caller has conditional assurance and reuse; checked slot growth, lifetimes, runtime interactions and native admission remain open |
| G5 | Manageable regional proofs and measured independent edit costs | Open for the complete target workflow |
| G6 | Complete portable Hello selection, executable and portability validation | Open |
| G7 | Reuse on another target, regressions and terminal acceptance evidence | Open |

### G1: complete operations

Close the `c_tolower` and `c_strcasecmp` boundaries first, including their returns
and continuations. Address the other four inventoried context-bearing bindings
and every additional ownership gap exposed while completing Hello. Inspect
whether each context belongs inside an operation, is an actual neighboring
operation, or requires a coordinated replacement group; do not mechanically move
IDs or create public tail functions to make the inventory green.

For each selected operation, retain exact original ownership, all entries/exits,
admitted machine/C states, input-memory correspondence, aliases, preserved state,
service/effect observations and outcomes. Check entry and return adapters as well
as local C behavior. Original storage contents and object lifetime require
evidence beyond pointer reconstruction. No uncovered instruction, entry,
exceptional outcome or continuation may disappear when boundaries change.

### G2: local assurance through final admission

Use the real `c_strcasecmp` -> `c_tolower` connection as the first end-to-end gate:

- Both complete routines have ordinary portable-C implementations and checked
  contracts, with no generated-machine-code remainder inside either operation.
- The caller model consumes the supplier contract with the supplier body absent.
  Increasing supplier implementation size does not expand the caller model.
  The retained 2026-09-20 `supplier-growth` experiment qualifies a 26-case
  lowercase implementation and reproduces both original caller GOTO files byte
  for byte. The later five-region caller qualifies with the supplier body absent
  and reuses all five proofs after the compatible supplier edit. Combined native
  admission also passes, with fourteen portable definitions and both original
  routine objects omitted. Retained results are in `single-call-regions/`.
- A compatible supplier edit is rechecked locally, reuses unchanged caller proof
  evidence with zero caller model/compiler/solver work, and produces a current
  combined provider selection and native link. Rebuilding the changed supplier
  and relinking the executable are accounted for separately.
- An incorrect supplier edit is rejected; a same-signature incompatible contract
  edit invalidates the actual consumers. Reports name the missing premise or
  guarantee and retain the counterexample or checked diagnostic.
  The retained public weaker-guarantee experiment now qualifies the unchanged
  supplier, invalidates two actual caller regions and refuses native admission.
  Restoring the authored guarantee restores complete caller/native admission.
  A separately compiled wrong caller implementation also produces a result
  counterexample and native refusal. These do not rely on exit status alone:
  `candidate status` can successfully report an incomplete selection.
- Real caller entry, adapter, memory, frame and runtime premises are discharged
  through the existing qualification path. Conditional results remain conditional
  until this happens. No exact-context or activation reader is weakened.

This pair is the first milestone, not sufficient to complete the goal. Apply the
same composition path to the contracts required for G4 and G6.

### G3: operator contract workflow

Make the public workflow connect a manual planning boundary to canonical
interface/binding inputs, a usable C work package, local assurance and final
selection. Operators must be able to inspect and deliberately refine:

- Parameters/results and admitted input states, including explicit environment
  assumptions and unsupported cases.
- Shared objects/views, initial contents, aliases, lifetimes, readable/writable
  regions, frame guarantees and representation relations.
- Dependencies, callbacks, service protocols, normal/fault/nonreturn outcomes,
  applicable checking rules and evidence still required for admission.

Expose these facts per unit in the inventory/work package, distinguishing
declared contracts, checked summaries, sampled comparisons, conditional proofs,
qualified replacements and integration results. A missing rule must identify the
specific unsupported boundary feature and prevent the corresponding claim.
Inventory coverage must never imply contract or activation completeness.

Exercise a manual split and merge through semantic checks, not just RVA coverage:
preserve state transport, coverage and progress; show affected contract consumers
and accurate invalidation. Reuse the current interfaces, relations, packages and
commands. Routine authoring must not require editing generated hashes, solver
models or Nix expressions. No automatic boundary recommendations are required.

The retained real lowercase experiment now splits and merges **internal proof
regions** through public proposal/application/check commands. The predecessor
checks EAX/ECX/EDX and carry-flag transport; incorrect or omitted carry transport
produces a counterexample. Both valid forms preserve complete original coverage,
the public interface and the consumed checked scalar guarantee. Their caller
proofs reuse with zero model/compiler/solver work through current native
admission. This does not change component ownership, exercise loop progress or
establish the full SDK workflow: those broader G3 checks remain open. Evidence:
`build/hello-loop-header-2026-09-20/semantic-cut-refinement/`.

Expose proof-storage bounds and their checking obligations alongside the contract,
separately from admitted input limits. The Hello experiment's default origin tables
have 15/17 entries although four entries pass the focused entry capacity check.
An operator should be able to inspect the derived size, propose a smaller size,
see its overflow obligation and compare phase costs through the public workflow.
A smaller table is acceptable only after its capacity assertions and the complete
affected proof pass; a timeout must not silently become an input restriction.

The comparison experiment exposed a public-workflow gap: ordinary diagnostics
previously required `--conditional` and configured runtime assumptions. The
ordinary `component check --region` path now uses the existing scheduler,
assertion inventory and contextual receipt without adding those assumptions.
Omitted regions remain unresolved with no execution evidence; even an all-region
diagnostic supplies no qualification. Exact-query reuse into a subsequent full
check is exercised by the small integrated test, along with missing-region,
stale-model and attempted-activation negatives. Python validates the diagnostic;
the strong JQ admission reader rejects diagnostic selections. The real retained
Hello walkthrough passes source checking and the renamed `left_folded` region,
with four regions deferred. Complete edited-provider checking and the public
handoff of retained diagnostic evidence into that check remain unfinished. Do not
use one-second whole-provider runs as the public preparation API.

The existing `boundary propose`/`boundary adopt` workflow now supplies normal
component drafts with editable interface, binding and optional cutpoint inputs.
Configured review reuses the seed normalization and V6 package, checks the current
baseline, and computes derived digests. A retained real Hello walkthrough exercises
the public commands and rejects a changed owner; multi-operation tests keep cuts
within their respective operations. See [the editing workflow](components.md#editing-configured-component-contracts).
Review can export a standalone canonical draft or apply declarations to the local
target's SDK-discovered indexes. Application preserves neighboring entries and C
source, rejects stale local inputs and rolls back caught write failures. The
connected check/invalidation/selection workflow remains unfinished. A structural
edit still needs the separate transport, coverage/progress
and complete admission checks above; normalization is not proof.

#### Next connected workflow acceptance

Complete the following against the existing comparison/lowercase consumer before
expanding isolated examples. These are concrete G2/G3/G5 checks, not replacement
completion criteria for G1–G7.

1. **Apply reviewed declarations to the configured target.** Resolve its actual
   interface/binding indexes and cutpoint inputs through the existing target
   infrastructure. Update only the reviewed component and necessary index
   identities; preserve other components, replacement groups, configuration and
   unrelated edits. Reject stale baselines and conflicting destinations before
   mutation. Serialize cooperating writers and roll back failed application.
   Test stale-input and interrupted-write failures. Applying declarations grants
   no proof or activation authority.
2. **Keep authored C explicit.** Show which source the target will check and how
   the operator installs the edited implementation. Never overwrite existing C
   with a generated skeleton or silently discard draft source. If source is
   applied automatically, bind it to a checked original snapshot and reject
   intervening edits. Report declaration-only application accurately.
3. **Check through the public workflow.** Continue from the applied target to
   local checking, qualification, selection and current native link evidence
   without hand-merging hashes or editing experiment Nix recipes. Provide ordinary
   focused region diagnostics with omitted obligations visibly unresolved and
   activation blocked; do not require invented runtime assumptions for diagnostics.
4. **Exercise real contract invalidation.** Recheck a correct supplier that exports
   a valid weaker guarantee with the same signature. Identify the specific caller
   premise that no longer follows and withhold its old qualification/reuse.
   Restore compatibility or refine and reprove the affected caller, while retaining
   unaffected evidence. A supplier whose own equivalence check fails is a separate
   negative and does not demonstrate this contract-refinement case.
5. **Check a semantic split and merge.** Use a real operation and retain its
   entries, outcomes, state transport, coverage and progress. Distinguish an
   internal proof cut from a component ownership change and from a coordinated
   replacement group; introduce no artificial production API merely for proof.
6. **Retain one connected walkthrough.** Record public commands, exact inputs,
   dependency changes, terminal results and separate phase costs. Include the
   compatible supplier edit with zero caller model/compiler/solver work, the
   incompatible-contract case, and final executable-bound admission. Use retained
   inputs first. Report work not measured or not executed explicitly rather than
   assigning it zero cost or inferring success from an earlier artifact.

Finish this walkthrough before treating the configured editing feature as complete.
The subsequent stateful consumers, complete portable Hello, second-architecture
execution and connected jq/DX-Ball reuse remain mandatory.

Authored scalar-export implementation now uses the existing relation intent and
source-summary checker. Configured packages/review/application carry the optional
relation declaration. Small connected tests demonstrate valid weaker exports and
consumer invalidation with unchanged supplier C; the real lowercase provider
qualifies with a weaker export and rejects a false one. The real comparison
consumer's focused check fails with a `left_folded` invariant counterexample,
with both implementations unchanged. Public supplier proposal/application/check
and restoration pass. Complete weaker-contract candidate checking is running;
restored caller/native admission remains unverified. Item 4's full connected
refinement/admission cycle is therefore still open.
Evidence: `build/hello-loop-header-2026-09-20/scalar-contract-refinement/`.

#### Immediate deliverable: regional evidence to complete public checking

The public `component check --reuse-proof DIR` handoff is now implemented through
the existing provider, SDK product and receipt readers. Small-fixture validation
and repository gates pass. The edited Hello caller now qualifies all five regions,
reuses its retained regional queries and passes prepared public hybrid admission.
The new generic candidate-hint path passes CLI/SDK and actual graph-invalidation
checks. Public candidate hints on retained inputs now pass real qualification,
selection and native admission with zero caller model/compiler/solver work.
The incorrect-edit check is running; it has not yet established rejection.
The retained runtime fixture and full SDK graph/wrapper tests have separate scopes.
The implementation and connected walkthrough must meet these requirements:

- Accept a retained proof package without operator edits to Nix recipes, generated
  identities or receipts. Preserve its required package members and closure when
  handing it to a sandboxed build.
- Validate the supplied evidence and component identity. Reuse only evidence whose
  relevant model, tool, query and dependency bindings match. A well-formed cache
  miss must cause checking of the affected obligations; malformed or foreign
  evidence must produce an actionable diagnostic, never successful admission.
- A complete check must discharge every obligation, including regions omitted
  from the diagnostic, and perform the existing qualification checks. Selecting
  every region in diagnostic mode still does not authorize activation.
- Expose the resulting evidence location, unresolved obligations and reuse costs.
  Distinguish query reuse, which can still require model generation/compilation,
  from unchanged-neighbor proof reuse with zero model/compiler/solver work.
- Carry operator-supplied evidence through configured candidate selection and
  realization as reuse hints for the current provider graph. A successful
  parameterized component check must not require a Nix recipe edit or another
  complete proof run merely to assemble the same implementation. Check current
  sources, contracts and dependencies before reuse; do not substitute an old
  qualification that silently selects an earlier implementation. Demonstrate
  both the unchanged case and invalidation after a subsequent source edit.
- First test the public path with small fixtures, including stale evidence,
  changed dependencies, deferred regions and attempted activation. Then finish
  the applied Hello `left_folded` caller using its retained regional package,
  obtain complete qualification and current combined selection/link evidence.
  Record exactly what was reused and what was rechecked; do not inherit success
  from the original `left_converted` caller.

This deliverable is one step in G2/G3/G5. Follow it with the valid weaker-contract
export and consumer invalidation case, then semantic split/merge. Neither a cut
rename nor a cache hit demonstrates either of those remaining capabilities.

### G4: state and interactions

P1–P4 establish the next executable workflow; the following requirements concern
its stronger qualification and the eventual whole-Hello goal. A missing rule here
does not prevent an otherwise eligible experimental run.

Audit and reuse existing memory and service composition rules before adding any.
Close the actual Hello consumers involving quoting/slot state, allocation and
big-number object lifetimes, locale/conversion state, and CRT/TLS/handler/callback
protocols. First establish small retained positive and negative examples for each
missing rule, then exercise it through its real consumer. Keep unmet obligations
visible until existing checked providers or implemented rules discharge them.

The next retained consumer is the complete `_quotearg_n_options` operation:
40 transfers, ten service call sites, five direct callers and three tail callers.
Its exact slice and call inventories are under
`build/hello-quoting-state-2026-09-21/quoting-slots/`. The inventory separately
retains a cold abort continuation from the quoting engine; its infeasibility needs
the actual termination contract. The source archive is an authoring reference,
not evidence of binary equivalence. The full operation's service bodies are
absent, but it is not proved. Use the existing captured external-target rules for
the two indirect errno accesses, and allocation class/generation machinery for
slot-table growth and buffer replacement. A successful zero-argument direct
import test does not establish either indirect target authority or TLS lifetime.
Repeated sites now share one checked service definition; call-time dynamic
footprints, realloc contents, borrowed return lifetimes and nonlocal allocation
failure still need connected rules. Carry these into the existing quoting caller
before expanding unrelated leaf examples.

The conditional public caller now transports captured indirect targets with the
existing entry-register/current-image-slot rules. Retained checks cover the real
prologue and first errno call, plus the second site under an explicit incoming
invariant; wrong target/stack definitions fail. This does not prove transport
through the intervening operation, import authority or the errno result relation.
The selected runtime relation promises a related four-byte result range, but
does not establish that successive calls return the same cell. The next returned
view rule must preserve each actual result's contents and aliases, and state its
lifetime premise; it must not force a constant address to fit a fixed-view rule.

The next hand-defined consumer is the actual `_rpl_free` supplier. Its retained
complete ten-transfer slice has five errno calls and one free call; the ordinary
C draft preserves their order and consumes each returned view separately.
The public checker now supports void/runtime-only callers and an explicit
call-scoped returned-byte-view rule. The complete wrapper passes conditional
checking with arbitrary per-call addresses and current aliased contents. The
first unrestricted result premise fails: a returned span overlaps the errno
import slot, so writing zero changes the source's next target. A typed separation
premise closes that local counterexample and has a checked nonempty result domain.
Concrete CRT/TLS lifetime, import-slot separation, free applicability/release
effects and native realization remain unverified. Evidence is under
`build/hello-quoting-state-2026-09-21/returned-view-composition/`; current integrated
validation and exact costs are recorded in `current-goal.md`.

Next discharge those premises and consume the actual wrapper's checked summary
from the complete quoting operation. Extend persistent borrowed objects and
allocation transitions using the existing lifetime/generation machinery; an
ephemeral access grant is not that machinery. Keep the real service order and
all physical return/adapter obligations. Neither compiler success nor a local
conditional theorem supplies an admitted supplier summary.

Review the import-slot premise against the actual adapter semantics: this wrapper
captures the target once in its prologue, while the current typed slot adapter
reads the slot at every call. Establish separation only if the admitted runtime
really guarantees it. If admitted original states allow the slot to change,
transport the original capture in the generated adapter; do not exclude those
states just to make the current-slot proof pass. The selected errno profile's
`dynamic_range_base` relation alone does not establish this separation. The
selected free profile already carries `dynamicRangeRelease` for `msvcrt.heap`;
reuse its checked lifetime rules when connecting concrete runtime admission.

The `entry-target-capture/` checkpoint now implements explicit operation-entry
sampling in the generated adapter, typed proof thunk and public finite caller.
The complete real wrapper passes the SDK check without the errno/import-slot
separation premise, even when free may modify the slot. Current-slot sampling
remains the default; a small aliasing consumer disproves that choice for an
original saved target. Exact sampling changes invalidate reuse. Captures are
per invocation, and resumed contextual cuts currently reject without capture
transport. Native admission and runtime/lifetime premises remain unverified.

The subsequent `finite-supplier-composition/` checkpoint implements a checked
normal-return scalar summary for complete caller theorems. A three-level mutable
aliasing fixture passes with absent supplier bodies and zero-work reuse at both
caller levels after a leaf implementation change. The complete real wrapper is
reproved for quantified protected service bounds and now exports checked facts
through the public supplier reader. Those bounds retain explicit runtime premises
and do not introduce synthetic production arguments. This supersedes the older
unsupported-evidence-family probe, without proving the complete quoting consumer.
An enclosing-operation memory envelope is still required when a caller's exported
footprint depends on changing internal call arguments; the reader rejects that
missing rule. Complete the real quoting network, persistent object/lifetime
transport and concrete runtime/native admission. Small-network success alone does
not close G4.

Factor object invariants so every component does not repeat a global heap/VM
model. Demonstrate mutable alias-sensitive state, allocation/lifetime changes and
an applicable interaction through checked summaries. Include a compatible internal
representation change with preserved external relations and neighbor reuse.
Preserve call-time memory and observation order, exceptional outcomes and actual
reentrancy/concurrency requirements where the target admits them; do not silently
restrict the target to a convenient synchronous fixture.

The `complete-quoting-network-v2/` checkpoint makes the full operation and its
actual free child concrete through ordinary typed C and existing public comparison
packages. It covers 128 controlled sequences/446 invocations, all service sites,
persistent table and buffer changes, explicit terminal failures and host/PE32
layout differences. A supplier edit recompiles only its unit; unchanged comparison
reuse and incorrect-code/incompatible-contract rejection pass. The fixture
relation, allocation bookkeeping and token/reference bridge are diagnostic
adapters, not the missing checked transport. Its formal capability probe explicitly
reports the stateful opaque interface unavailable.

Use [this same consumer](../tests/fixtures/hello-quoting-state/slots/README.md#required-checked-transport)
for the next rules: persistent typed-record contents/aliases/frames/generations;
growth with preserved old slots and exactly initialized new slots; buffer
reference transport into the checked free wrapper; and an enclosing memory
envelope for the complete caller. Keep the slot-size store before release and
allocation, buffer publication before the second quote, and actual cached versus
reread options. Recheck the deliberately delayed-size-store counterexample when
changing observation/composition rules. These requirements must become checked
contracts and native premises before this consumer can close G4.

The first `boundary.records` rule now relates fixed incoming C records and byte
objects to the existing current-memory world. It supports explicit native field
offsets, canonical pointer aliases and embedded subobjects, plus logical state
projections over noncontiguous globals. Calls check current contents and carry
declared byte effects back into the actual C objects. C field types are checked
against the bound authored header; reordered C fields can retain native offsets.
The small public caller regression uses the unchanged quoting header, including
its persistent slot pointer and aliased bytes. Its theorem retains an explicit,
unverified operation-long lifetime premise. Scalar-summary export rejects these
record proofs until callable lifetime and complete memory transport are checked.

The actual complete quoting source has compilation/layout evidence under this
new relation. A separate kernel proves its incoming record contents, second-slot
update, state-pointer change, embedded-mask alias and service write; it rejects
a wrong-slot update. That kernel does not prove the complete quoting algorithm.
Ordinary caller-local records now use that layout vocabulary and the existing
paired-call byte rule. A complete small caller checks live field contents, exact
aliases, writeback, representation changes and unchanged reuse. A regional check
also executes both actual growth branches and the unchanged full authored C to
their `xpalloc` call boundary, checking the local count and five native arguments.
It starts the original at `0x4ef1` under an explicit register relation; predecessor
applicability and the growth outcome/continuation remain unproved. This is not a
complete caller proof or a new production component.
The subsequent borrowed-errno checkpoint changes that runtime-owned storage to
the existing call-scoped byte-view interface; ordinary structs remain in the
slot algorithm. The same experiment now executes from the actual entry `0x4eb3`,
including errno and the prologue, and checks saved errno and growth arguments on
the admitted growth branch. Its old assumed predecessor relation is superseded.
It still stops before allocation returns and is not complete caller assurance.
The subsequent growth-memory checkpoint proves the actual successful-return to
clearing-call region, with symbolic counts, preserved old contents, the static
slot copy, pointer publication and exactly cleared new storage. It uses checked
snapshot-copy/fill effects in the existing sparse byte world and permits arbitrary
allocator changes outside the preserved prefix/globals. Bad copy and clear
implementations reject. Success/lifetime/separation and the resumed native state
remain explicit premises; neither the allocator nor the two regions' composition
is proved. This is not general resizable C-array transport or a reusable stateful
callee summary. Retained evidence:
`build/hello-quoting-growth-memory-2026-09-21/terminal-audit.json`.
Continue with pointer-to-token free binding, growing slot arrays and buffer
allocation/release, including complete-operation transport of their state.
The reference-transport checkpoint now checks that binding at the actual
`0x4fc3` free-call region using the unchanged release service signature and the
current `_rpl_free` summary with its body absent. Explicit identity representations
preserve null/aliases without granting bytes or native lifetime. Incorrect
arguments and missing supplier premises reject; unchanged regional proof reuse
does no model/compiler/solver work. A connected fixture also reuses after a
compatible supplier edit. The region is a proof-only projection; applicability,
release generations, returned identities and complete-operation composition
remain open. See [the public definition rule](components.md#passing-an-opaque-identity-to-a-checked-scalar-supplier).
The subsequent returned-identity rule now checks the connected four-transfer
release/allocation/publication continuation through `0x4fec`. Returned addresses
need no incoming inventory entry; their canonical identities preserve null and
aliases and can be published by ordinary C. Checked scalar result transport has
supplier-edit/parent-proof reuse and rejects incorrect publication and storage
access. The real release consumes current checked facts, while allocation still
has a conditional normal-return/effect contract. This is no allocation or lifetime
grant and no proof of the complete operation. Retained evidence:
`build/hello-quoting-returned-identities-2026-09-21/terminal-audit.json`.
The subsequent record-snapshot primitive composes current C fields with sparse
copy/fill history and passes focused overlap/order/identity regressions. Its
combined growth-region experiment now passes complete conditional checking,
wrong-copy/wrong-clear rejection and exact-query reuse. Readonly field frames
avoid unnecessary writeback; checked byte-history spans permit native global
reads without bypassing current C fields or snapshots. Static/moved/in-place
admission witnesses and nominal C field checking pass. The static slot/count use
record storage; arbitrary-length array contents still use the sparse byte world.
This is not general growing C-array transport, a checked allocator/lifetime rule,
complete quoting assurance or native admission. The terminal audit and prior
failed models are under
`build/hello-quoting-record-snapshots-2026-09-21/`. Continue by connecting entry,
growth outcome and continuation through checked count/storage/lifetime transport.
The current `--connected` experiment uses the actual entry through normal clear
return and count publication at the real `0x4f62` barrier. It retains the entire
original operation and ordinary C, checks the saved incoming frame and uses the
existing local count-record transport. Its complete attempts are terminal and
incomplete; the latest prepared model has no complete connected theorem. The
safety timeouts and measured event-slot/callback changes are retained
under `build/hello-quoting-growth-connection-2026-09-21/`. Conditional successful
allocation and object lifetime are still premises. This experiment must not be
treated as a checked allocator, general growing-array rule or complete caller.
The v12 `--concrete-case` diagnostics additionally check actual continuation
reachability and all properties on retained static, moved and in-place examples.
Their fixed inputs and observation byte are bound explicitly, and their positive
results remain case-scoped. They are neither exhaustive partitions nor a
substitute for the symbolic regional proof or checked transport between regions.
An incoming fixed
inventory does not prove those transitions or cover unbounded arrays. Prove any
finite bound from real caller/runtime applicability, or extend the representation
rule; do not restrict full-operation inputs to make this first model pass. The
enclosing memory envelope, strong qualification and all later exits remain open.

### G5: granular proof performance

Use internal cutpoints and invariants for the large routines, with an actual loop
and mutable/shared state in the acceptance examples. Check relation transport,
coverage and progress across cuts. Keep proof regions, components and replacement
groups distinct; production APIs should reflect meaningful boundaries.

Record preparation, compiler, model, solver and link costs separately for initial
checking, a local implementation edit, contract refinement and unchanged reuse.
Demonstrate that unchanged neighbors reuse their evidence and callee growth does
not expand parent proofs. Isolate expensive target preparation behind existing
content-bound Nix products. Retained inputs and small fixtures come before pilot
rebuilds; rebuild only when consumed evidence changes. Do not weaken obligations
or hide timeouts to meet a performance target. Explain remaining dominant costs.

The current manual refinement experiment separates comparison from its real
epilogue without changing component ownership or introducing a tail API:

| Proof cut | Machine point | Transported C state and relation |
|---|---|---|
| `scan` | `0x67dc`, before reading the next byte | Both parameter views, `offset`, zero `result`; EDI/ESI equal the respective view addresses plus offset; the offset is within both views |
| `finish` | `0x6804`, after computing the return bits | Both parameter views and unsigned `result`; EAX equals those bits; the C return converts them to signed form using defined arithmetic |

Both cuts use invocation scope `ESP + 28`. The checked parameter-slot frame can
therefore transport pointer bits across `scan -> finish`, after proving scope
equality, as well as across the loop backedge. Contents, aliases, lifetime and
native reference admission remain separate checks. The epilogue still transports
the parameter descriptors required by the current resumed adapter, although its
return calculation only needs `result`; do not erase that constructor obligation
without a checked rule for unused parameters. The structured C draft joins its
return after the loop. Coverage planning and local frame tests have passed.
The three-region provider check in `finish-cut-v2/` passes entry and finish but
remains incomplete at the scan view-reference-address assertion (60-second
timeout). Correction: the subsequent 36.456s address-reuse probe selected finish,
not scan; numeric model-directory order differs from receipt shard order. It is
non-authorizing and provides no evidence that the loop timeout was resolved.
The updated engine passes 49 focused Nix tests and five repository gates, but its
full provider run remains incomplete at entry origin recording and scan right
context (60-second limits); finish passes. The complete provider check and
remaining capacity obligations are still required before accepting this refinement.

The later call-specific address checks clear that timeout and expose a concrete
invariant gap: offset 67 is inside a 68-byte readable origin remainder but beyond
the checked 13-byte NUL extent. The `nul-progress-cut/` refinement therefore keeps
the same boundaries and C algorithm while requiring offset below both existing
checked NUL extents. This proof-only expression does not shrink runtime views or
create a production string-length API. Its complete provider and integration
checks remain required; the earlier rejected invariant must not be adopted.

The NUL-refined run passes its scan invariant but still times out at scan
alignment, including a 300-second retry. The next manual proposal,
`nul-decision-cut/`, adds `decide` at `0x67f4` after both conversion calls.
It transports both low-byte results (EBX/EAX), the existing views/cursors, and
the implications that `offset + 1 == nul_extent(view)` makes that view's
conversion result zero. These implications are outgoing proof obligations of
the read/call region, not extra unchecked assumptions. The decision region uses
them to preserve NUL progress. All four regions, coverage, capacity and admission
checks remain required. No additional component or production API is introduced.
The terminal four-region run passes entry, decide and finish, and proves the new
decision invariant in scan; scan alignment still times out at 120 seconds.
A retained checked call-completion implication isolated this cost. Its subsequent
integration now adds checked assert-before-assume lemmas to ordinary provider
evidence; both Python and Nix/JQ readers enforce their exact binding and query
prerequisites. The four-region integrated run proves alignment but remains
incomplete at source-call readiness. The active five-region refinement separates
the two calls at `left_converted` and also matches source read/call order to the
machine. The complete five-region operation and compatible supplier edit now
qualify, reusing every caller proof with zero caller model/compiler/solver work.
The exact proved source and intent are adopted into Hello. Combined Nix native
admission passes, including zero-work reuse against the Nix baseline. See the
[current implementation handoff](current-goal.md#immediate-implementation-handoff)
for terminal evidence and live-run status. Neither a passing lemma nor a subset
of regions closes G5.

### G6: complete program and portability

Qualify and select implementations for every required Hello definition and
obligation, including non-code storage and runtime/platform services. Reuse checked
runtime providers where sufficient; record their supported environment and trusted
boundary. The final `portable` selection must contain no generated Behavioral-C
fallbacks. Exact machine-context dependencies on replaced application definitions
must be discharged or removed by valid reproof/composition, never ignored.

Produce the existing strong portable dispatch/link receipts bound to the actual
objects and executable. Pass applicable original-versus-replacement x86 behavior,
pilot, native-link, export and portability gates for the complete program. Preserve
the declared original environment/observation scope and distinguish checked
equivalence within that scope from sampled runtime observations.

Removing the last generated transfer of a routine must also remove its original
object from the link. Retained dispatcher references may resolve only to checked
replacement routes or rejecting fallback guards; they must not force retention
of the old body. Owned interior entries without proved adapters reject. Keep
the selection, registry source/object and final executable evidence bound together,
including when multiple portable components jointly replace one generated object.

The earlier second-architecture delivery requirement is superseded by the
2026-09-29 scope correction. Deliver and exercise the Windows source program
against its declared Windows runtime dependencies, preferably through Wine in
headless Wayland. Existing cross-architecture results remain useful evidence;
porting to another platform is not a G6 delivery requirement for this project.

### G7: transferability and final validation

Reuse the workflow and at least one implemented contract/composition capability
on a structurally different connected jq or DX-Ball portion, using existing
consumers and packages. Demonstrate author/edit/check/reuse and expose its actual
admission status without adding target-specific proof exceptions. This goal does
not require fully lifting both jq and DX-Ball, but their affected regressions and
existing pilot obligations remain required. A second leaf-only fixture is not
sufficient evidence of reuse on a different target.

Retain public command walkthroughs, exact input/source/contract/evidence identities,
negative tests, phase measurements and terminal results for G1–G6 and the reuse
case. Refresh metadata and run targeted tests plus applicable Nix/repository
validation. Reconcile registries, status documents and this table with observed
results. Attribute pre-existing failures without counting them as successes.

### Execution constraints and completion rule

P1–P4 and H1–H3 are delivered in their bounded scopes. Fresh setup, the selected
normal-entry Hello workflow, the previously unprepared string boundary and bounded
different-target transfer now pass. The standalone source/runtime path and
second-architecture execution now also pass for the explicit Windows-1252 scope.
The practical delivery audit now closes the operator handoff and repository
validation exits within that scope. Subsequent work may expand runtime/target
coverage; those broader exclusions do not reopen the delivered scoped milestone.
The existing G1/G2 comparison/lowercase result remains
a stronger-assurance baseline. Schedule further formal work for a concrete risk
or an explicitly selected stronger claim, not as a mandatory next campaign.
Standalone diagnostics, component counts and isolated proof plumbing cannot
substitute for the operator and whole-program outcomes.

Reuse the semantic engine, canonical interfaces/relations, V6 work packages, SDK,
testkit and Nix infrastructure. Add artifact boundaries only for semantics or
measured invalidation. Preserve unrelated dirty work. Run every Wine application,
boot and server command within a headless Wayland desktop. No commit, push or
deployment is requested.

Preserve original behavior within the declared scope, including explicitly
modeled original defects. Use defined C and the existing memory abstractions;
do not impose blanket memory safety, introduce host C undefined behavior, hide
failed premises, or promote finite comparisons to strong proof authority.
The existing contextual-bisimulation contract remains proof authority.

Mark practical product completion only after its operator, standalone-source,
Windows runtime integration and validation exits have terminal evidence. H1–H3 alone,
an inventory, prepared fixture counts or tests expecting incomplete execution
are insufficient. Mark the separate strong-assurance objective complete only
after all G1–G7 have implementation and terminal evidence. This replaces the
earlier completion rule that tied general usefulness to universal qualification.
Name each unsupported required capability and keep its corresponding exit open.
