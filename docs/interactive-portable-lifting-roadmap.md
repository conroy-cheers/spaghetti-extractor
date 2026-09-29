# Roadmap: Interactive, Verified Portable Lifting

Status: implementation in progress, 2026-09-05. This document defines the path from the unfinished
Portable-C contextual-bisimulation migration to a useful operator-assisted
lifting workflow. Its stages require evidence of implementation and do not authorize execution.

Implementation sequencing now follows the [independent lifting plan](independent-portable-lifting-plan.md). Its decomposition and proof-reuse experiments preserve the outcomes and retained milestones in this roadmap.

The 2026-09-15 [practical lifting design](practical-independent-lifting-design.md)
further separates useful independent development from strong qualification. It
proposes local differential validation, optional focused proofs and an explicit
experimental execution route. The existing qualified route remains unchanged;
the new route is design work, not a currently available execution permission.

## Outcome and scope

An operator can import an unfamiliar native IA-32 PE32 application, inspect a
faithful generated baseline and its unresolved obligations, progressively
replace meaningful regions with readable Portable-C, understand and repair
localized proof failures, and export a standalone source project. A subsequent
milestone replaces one Windows service family with a qualified portable
backend and runs a scoped application configuration on another platform.

Round-trip means preservation of declared observable behavior through binary,
reconstructed source, and rebuilt candidate. It does not require byte-identical
binaries or recovery of the author's original names and abstractions. Intentional
behavior changes must be recorded as a different specification; equivalence to
the original cannot authorize them.

General Win32 usefulness is an expanding, explicit capability matrix. It is not
a promise that every application will admit automatic, complete equivalence
proof. Analysis, source authoring, and localized qualification must remain useful
when whole-application activation is blocked.

## Starting evidence and contract precedence

The reviewed checkout starts at HEAD `2df8e33` with a large dirty tree, including
183 tracked changed files and the untracked, imported
`components/bisimulation_connected.py`. These counts are a review snapshot, not
a source identity. Preserve unrelated work and establish exact snapshot identity
before implementation or performance comparisons.

The review observed 58 passing focused tests and passing metadata/whitespace
checks. It inspected a saved complete jq output-value-pipeline qualification.
It did not rebuild the full pilots or run the full repository gates. The
[current checkpoint](current-goal.md#current-findings) records the saved jq
paths and earlier Hello/DX-Ball timeouts; those are not fresh results for every
byte of this checkout.

The [contextual-bisimulation contract](portable-c-contextual-bisimulation.md)
remains the implemented authority contract. Authored acyclic cutpoints now use
the checked region engine, with generated-C solver fixtures and mandatory public
memory/pairing checks at boundaries and operation exits. The first body-free scalar
strategy has checked frame/context-independence certificates, typed postconditions,
and a qualified real scalar caller. The paired-model callee-growth fixture and
qualified-model inspection pass for that case; interactive latency and general
composition remain open. Retained diagnostics now preserve region-specific
compile paths and per-query timings. The corrected scalar entry replay passes
its 90 queries in 616.26 seconds; this exceeds the interactive budget and does
not qualify a new provider. A subsequent omitted-local audit exposed incomplete
cut-state handling. Compiler-derived local havoc and a mandatory receipt policy
now address that case. The scalar caller qualified under the local-only policy
in 1,019.27 seconds, but a subsequent audit found a reassigned context pointer
was reset at resume. The inventory now includes mutable automatic parameters;
all earlier receipts require rebuilding under the new storage and argument-binding
policies. A parameter capture must now bind its actual compiler argument, including
lexical scope, after a separate local-substitution false acceptance was reproduced.
Capture codecs now also require supported parameter reconstruction and checked
source-value decoder round trips; the previous forward-only check admitted a
lossy relation. Distinct per-cut local capture sets now compose across a three-region solver fixture,
with omitted later values and broken incoming relations rejected.
Public `component check` now explains bound failure obligations with recorded
source/proof locations and relevant next steps. These remain diagnostic, and do
not map edited workspace files or generate repairs. Automatic cutpoint proposals,
measured region budgets, and general summary composition remain unfinished. Change the contract
together with code, readers, producers, and negative tests as these stages land.
The existing migration's unsatisfied pilot and validation exits remain mandatory.

The native-image cut relation now uses the production operation's selector,
canonical full object metadata and interior-pointer remainder. A normal two-region
view proof exercises entry admission, the source barrier and resumed exit; the
integration also removes an unnecessary synthetic ESP shift for register-only
decoders. This is a reusable image-view composition step. Native caller/runtime
instances and general memory/lifetime summaries still block broader admission.
See the current-goal findings and `build/reference-namespace/native-cuts/`.

The native authority format now distinguishes fixed-size objects from an explicit
allocation/resource instance remainder. This allows one object class to represent
variable-size buffers without changing fixed rules or inventing an extent from a
pointer. The shared native resolver checks each live instance's actual size and
generation; producer and incoming-lifetime qualification remain mandatory.
The normal proof harness continues to reject unqualified runtime instances.

Allocation freshness now also protects the mapped image before its first borrow,
and native registration protects borrowed external ranges from becoming new
owned allocations. The frozen trial's caller trace exposes the next composition
requirements: a guest-local count word, an out-pointer buffer producer, variable
size arithmetic, and an allocation-failure handler with a return path. None can
be replaced by assuming that a currently visible pointer is owned and non-null.
The trace and focused checks are retained in the current-goal findings; the public
caller qualification milestone remains open.

Bound local allocation records now project into the native reference namespace
with distinct native generation and proof birth tokens. Solver fixtures compare
the actual generated native allocation/release helpers with that projection,
including compaction and smaller address reuse. Checked local allocating calls
now establish the origin evidence consumed by ordinary runtime reference hooks.
The normal typed adapter and provider pass checked class/site premises through
lowering and contextual proof construction. An allocation/extent/release fixture
passes the normal checker and both receipt readers; its four Nix tests pass with
zero skips after declaring the jq fixture. Source-level allocated-buffer access
now uses nullable service-result views and accessors that check live references.
Its normal allocation/write/read/release fixture and both receipt readers pass
at the production ceiling in 702.26 seconds; interactive latency remains unmet
and the result-view batch passes affected validation in 1,237.71 seconds with
two concurrent local builds. Subsequent test-infrastructure dependency fixes
still need combined validation.
Incoming runtime instances, caller proofs and lifetime composition across cuts
remain closed. This is not an accepted trial region or native activation.

The native/proof producer identity now shares resolved-import normalization:
profile-only changes reach the proof call transcript even if effects and logical
service names stay equal. Real allocation/release profiles retain their native
range-rule digests, and both readers require the adapter correspondence. Linked
producer indexes, complete native family numbering and caller lifetime admission
remain separate unfinished requirements; no trial region is qualified by this
identity plumbing alone.

Supplied native range inventories now translate producer selectors and family
numbers into proof allocation records through shared native lowering. A fixture
with different local/native ordinals checks full native reference tuples, two
producer sites, release and smaller reuse. This removes ordinal equality as an
assumption. Local provider proofs now use conditional allocation classes without
requiring that complete native inventory. Selected native construction checks
consumed class and call-site correspondence separately. Incoming caller instances,
cross-cut lifetime admission and an integrated allocation-backed activation remain
unfinished; supplied correspondence alone cannot qualify the trial region.

## Product checkpoint: 2026-09-05

Progress is concentrated in proof correctness, not yet in demonstrated operator
usefulness. The recorded scalar ASCII comparison provider qualified in 1,084.57
seconds and both receipt readers accepted it under the earlier policy. The
normal-exit result and partial-overlap cache policy updates now reject that
historical receipt. Its current-policy rebuild took 1,245.05 seconds: the scan
shard passed, while the entry exit-value query timed out at 300 seconds, leaving
qualification incomplete. The other required pilot proofs,
fresh linked activation, and the full current-tree validation remain unfinished.
The scalar qualification is a build measurement, not a measured edit latency.

| Outcome | Current evidence | Remaining exit |
|---|---|---|
| Faithful and checked replacement | Common proof regions, cut-state checks, scalar summaries; current scalar scan shard proved | Scalar entry query, general memory/effect summaries; all required pilots and activation |
| Interactive proof feedback | Bound CLI failure diagnostics and retained query timings | Source-oriented repair, automatic cut proposals and measured edit budgets |
| Idiomatic source authoring | Typed interfaces, persistent proposal review/adoption and public source-error/repair feedback on Metapad | Assisted names/types/contracts, behavioral repair loop and readability trial |
| Unfamiliar application | Frozen external Metapad SDK input; one selected region registered with authored source | Five local proof blockers; accepted lifting session, platform coverage and candidate scenarios |
| Real portability | Defined standalone export and alternate-backend contracts in this plan | Built standalone export and qualified host/backend demonstration |
| General usefulness | Explicit staged acceptance criteria | Independent second application and maintained capability matrix |

The first trial workflow now lists four alternatives at Metapad's newline
region, explicitly selects the nine-unit boundary, and exports a persistent
editable draft through public commands in roughly 1–2 seconds per command with
analysis cached. It also exposed and fixed selection of an unrelated region
through a hole in its enclosing span. Reviewed interface/binding inputs now
export atomically through public `boundary adopt`, and public `component start
--apply` installs its source skeleton. The operator has replaced that skeleton
with a compilable typed-view C operation. Review can proceed despite unrelated
whole-application coverage gaps; the incomplete generated source still cannot
qualify a provider. Canonical contract authoring and SDK registration remain
manual. Public `component check --source` now exercises both production compiler
targets and source-profile checks independently of qualification. A seeded
Metapad compile error is reported with its source line and clears after repair.
The first check takes 6.21 seconds, the new error 5.91 seconds, and unchanged or
restored checks about 0.9 seconds; these are single observations and the new-error
measurement exceeds the planned five-second source-feedback budget. Five explicit
proof blockers remain, and default `component check` stops at the absent
qualification product. The behavioral diagnose/repair/qualify cycle has not yet
been demonstrated.
Evidence is in the [baseline](baselines/2026-09-05-interactive-lifting-baseline.md#first-unfamiliar-application-boundary-workflow).

A subsequent Metapad alias review found that importing the count word before
text edits loses updates when the two overlap. The installed source now borrows
the count word and reads it after normalization. The real generated region and
revised source agree in a bounded diagnostic; full regional qualification remains
open. Public adoption now accepts revisions of configured seeds with identity and
staleness checks. The revised source check passes in 14.80 seconds initially and
1.09 seconds unchanged, observed alongside affected validation. These observations
do not close the source-edit latency or public behavioral repair milestones.

Public checking before qualification exists now reports the canonical binding's
declared blockers and a bound artifact path, with a follow-up development-status
command preserving the external target flake. Metapad's two warm checks take
0.49 and 0.46 seconds and still exit incomplete. This is prerequisite feedback,
not a completed behavioral proof/repair cycle.

The editable newline-normalization loop draft uses one sync, nine exact units
and zero materialized paths. Its earlier two-obligation success was superseded
when inspection found that the logical projection merged the fixed count view
with the text NUL contract. The corrected value-specific projection and aliased
view resolver restore entry success. Checked outgoing view admission now carries
the non-null, non-wrapping range outside the resumed private window across
the cut, and both obligations pass. Both readers reject an inventory missing
that assertion even after its digest is refreshed. The window is derived from
the captured outgoing ESP; an older check of the preceding window is insufficient.
The caller/view domain,
continuation and object authority remain unqualified.
The installed binding remains incomplete and the public qualification cycle
is still the next integration task. A concrete original-transfer path into this
region places the count cell at ESP+8, inside the formerly excluded private
window. Canonical shared-view admission now includes declared stack ranges;
the successful direct proof cannot stand in for caller qualification.
The world renderer now supports frozen shared stack spans and explicit equality
of prospective shared ranges, with solver checks for aliases, crossing writes,
omitted writes and source-frame clobbers. The normal harness now registers
canonical parameter spans, including full aliased NUL reference extents, before
effects. It checks that source-frame reconstruction preserves borrowed bytes
before assuming the resumed relation. The normal cutpoint header checks each captured view's full reference
range, including bytes beyond its visible prefix and currently private bytes;
both readers require that assertion.
Access-method tuples are also checked against entry snapshots and carried into
resumption. The callback-clearing mutation now gives an explicit counterexample
at the captured view; its failing query takes 0.58 seconds.
Reference domain, generation, offset, permissions and element width now have
separate checked transport. A count-view permission mutation previously passed;
it now fails at the cut, and both readers require the metadata assertion.
The unchanged draft exceeds its 10-second memory-query budget under this policy;
a retained isolated replay passes in 12.17 seconds. A subsequent direct check
with a 30-second per-query budget satisfies both shards, and both readers accept
its evidence while rejecting missing metadata assertions. Production limits
remain unchanged. Callback contexts now use the same declaration as the native
overlay, with checked identity, runtime fields, permissions, address and visible
extent at each cut. A permissions mutation behind an unchanged context pointer
is rejected. Full-width reference addresses are checked too. This does not
qualify the component. Canonical requested/reference/visible extents now also
have checked transport, including aliased NUL origins, outgoing range admission
and zero final bytes in both worlds. Memory equality covers the full reference
range; older visible-only receipts are insufficient. The unchanged direct proof
passes and a matching view/context extent shrink is rejected. Attempt twenty
passes both shards with canonical shared stack-span admission and checked frame
preservation (78/79 authored properties, 83/84 queries). Caller ownership and
the public qualification cycle remain open.
Canonical boundary and complete view-state transport integration remain required.
Static safety partitions now select IDs
under consistent instrumentation (v9); historical v8 receipts are not reused.

Public seed adoption now carries an optional reviewed bisimulation intent with
the interface and binding, checking identity and cut membership and refreshing
its self-digest. The real Metapad export completed in 12.30 seconds, preserving
all five binding blockers and the installed inputs. This removes a manual proof
file/reference export step; installation, caller qualification and the public
behavioral proof/repair cycle remain unfinished.

The public trial now installs that reviewed proof intent and source marker as a
draft, with all three machine write facts mapped to the two logical memory
effects. The generic binding parser permits distinct facts for one effect while
rejecting duplicate fact identities and noncanonical ordering. The SDK pin is
updated to the current shared-view implementation. Public source checking passes
in 7.60 seconds initially and 1.58 seconds unchanged. A binding-only guidance edit
returns the exact same source-check receipt in 2.36 seconds. Public qualification
still reports the three unresolved text-origin, continuation and caller-frame
ownership contracts with concrete next steps. Cold development status takes
80.19 seconds and remains a performance gap. This installs reviewed inputs; it
does not complete the behavioral proof/repair or provider qualification cycle.

Continuation review now reuses retained canonical inputs through the existing
dependency engine, starting at actual units without synthetic transfers.
Metapad's ECX difference reaches two concrete call-contract obligations; a small
paired exact-C diagnostic confirms that the five incoming arithmetic flags are
overwritten at the first continuation unit. This narrows the installed guidance
without clearing its blocker or rebuilding a pilot. Discharging those contracts
and integrating the complete continuation relation remain required.

The normal provider checker now enforces the equality case for architectural
state at intrafunction continuation exits. This closes a reproduced hole where
an unbound ECX write passed a result-only proof. Current readers reject old or
weakened receipts. Admitting justified dead-state differences still requires
checked context relations and call contracts; this repair does not complete
that roadmap step or qualify the Metapad draft.

Bounded shared exact continuation prefixes are now available as conditional
proofs. They retain unowned context separately from replacement membership,
execute the same exact prefix on both sides and check its effects and outgoing
state. Register-overwrite, observable-store and bound-exhaustion cases exercise
the normal engine. Metapad's first continuation unit also passes a retained-input
flag diagnostic through this generated code. Selection and dispatch/link validation
now enforce the exact-context dependency, including selected generated objects and
strong linked symbols. A synthetic conditional proof/PE32-link fixture passes;
the local proof remains non-authorizing until that link. Metapad's caller and
unsupported context-call prerequisites remain explicit. No full pilot rebuild is needed to
develop or validate these local obligations.

The next product checkpoint must exercise one meaningful region of the frozen
application through the public source-edit, diagnose, repair and qualification
workflow. Backend work should identify which required pilot or observed trial
blocker it removes. Soundness repairs remain mandatory; another tuned proof alone
does not satisfy the operator, portability or repeatability milestones.

Caller-origin investigation now has a public retained-input `semantic-diagnose
--view callers` query. It reports direct sites, captured inputs and source
locations with bounded output, retaining indirect/callback/host-entry uncertainty.
Metapad and independent GNU Hello inputs exercise the same query without target
evaluation. This improves navigation to the required contracts; it does not
establish caller ownership or complete either application's lifting workflow.

## Invariants throughout the work

- Keep transfer-v2 as the sole executable semantic body language and the
  semantic object/module as the canonical packaging and linking boundary.
- Keep total provider ownership, immutable generated Behavioral-C, source/object
  binding, and exact strong dispatch/link evidence. A qualified source receipt
  alone does not authorize a candidate.
- Tests, traces, status projections, discovery, and operator/AI proposals remain
  non-authorizing. Counterexamples can veto; passing examples cannot prove.
- Assumptions must be named and discharged by callers, checked platform
  contracts, or explicitly reviewed environment assumptions. Inhabited entry
  relations do not prove that all reachable callers satisfy them.
- Timeouts, exhausted bounds, unsupported semantics, and unproved dependencies
  remain incomplete. Never shrink the input domain to meet a performance budget.
- Reuse current interfaces, Relation IR, proof plans, work packages, and Nix
  phases. Version a format only for a necessary semantic change, migrate all
  consumers, and reject stale data. Add no parallel semantic engine or cache.
- Target bundles contain data, source, intent, and acquisition. Every reusable
  algorithm, proof adapter, and primitive belongs to generic toolkit code.
- Preserve the repository's candidate-only runtime-test policy. During repair,
  use static original evidence; execute candidates only through applicable gates.

## Sequence

| Stage | Deliverable | Dependency |
|---|---|---|
| 0 | Reproducible baseline and frozen unfamiliar-app trial | Start now |
| 1 | Sound, genuinely modular connected summaries | 0 |
| 2 | Bounded proof regions, including acyclic cutpoints | 0; integrate with 1 |
| 3 | Completed current migration and repository validation | 1 and 2 |
| 4 | Assisted source authoring and actionable diagnostics | Instrument in 0; finish after 3 |
| 5 | Reusable heap, callback, and service coverage demanded by trial | Inventory in 0; qualify after 3 |
| 6 | Standalone export and one qualified platform substitution | 4 and required parts of 5 |
| 7 | Unfamiliar-app acceptance and repeatability trial | 4, 5, and 6 |
| 8 | Measured expansion across Win32 capability families | 7 |

The unfamiliar application is selected in stage 0 and exercised throughout.
Do not postpone discovery of its requirements until stage 7. This dependency
table permits independent workstreams; it does not require parallel agents.

## Stage 0: Establish evidence and choose the trial

**Work.** Inventory staged, unstaged, and untracked changes; distinguish this
migration from unrelated work. Include required new modules in the actual build
snapshot without sweeping unrelated edits into it. Record source/toolchain
identities, commands, host resources, cache state, and provider receipt paths.
Rebuild the existing pilot qualifications and relevant selection/link products,
recording actual blockers rather than inheriting documentation statuses.

Select one previously untuned native PE32 application with modest size, mutable
heap state, callbacks or reentrant event handling, and file or graphics effects.
Freeze the binary identity, distribution assets, intended environment, and
acceptance scenarios before modifying the engine for it. Prefer a redistributable
input and inspectable upstream source for later diagnostic comparison, while
keeping the lifting input binary-driven. Start with an out-of-tree target bundle
using the public SDK, then register an in-tree regression fixture if appropriate.

Audit existing callback, ownership, SEH, library, and environment support against
that application. Record each feature as demonstrated, synthetic-only, blocked,
or out of the initial scope. Do not silently substitute an easier application
when it exposes a missing capability. If it is unsuitable, document the reason
and retain it as a coverage case before choosing a replacement.

**Owners.** `testkit/`, `targets/`, public SDK and operator workflows, and
`docs/baselines/` narrative evidence. Generated reports stay in Nix or `build/`.

**Exit.** Reproducible pilot baseline; frozen trial and scenarios; ranked primary
blockers; cold/warm timing baseline; source snapshot includes every imported file.
No claim that the current migration already passes.

## Stage 1: Make connected summaries a sound abstraction boundary

**Work.** Audit the new connected wrapper before broadening its admission. Its
current replay checks logical arguments and copies results/effects, but still
executes the callee once inside the parent model. Retain this only as an
explicit transitional strategy with its own validated scope.

Define the reusable relational summary over the existing proof/interface types:
logical inputs and results; read/write footprints; alias and object-generation
relations; allocation/free effects where supported; public state; ordered service
and atomic behavior; and return, fault, callback, and continuation outcomes.
State the admitted environment and progress/divergence conditions explicitly.

Prove the summary against the callee's exact slice and Portable-C implementation.
At each parent call, prove both sides meet its preconditions and relate the
memory the callee may read. Apply related nondeterministic results and allowed
effects, preserve the frame outside those effects, and consume only the proved
postrelation. Neither copying the exact result nor proving equal addresses and
event counts establishes input-memory equivalence. Overapproximation must cover
all admitted callee outcomes; a weak summary may block a parent proof but must
not remove behavior. Relational coupling needs justification beyond two separate
one-sided postconditions.

Bind summary dependencies to exact source, slice, contract, environment, checker,
and qualification identities. Use an acyclic dependency order initially. Reject
recursive summary cycles until simultaneous induction has an explicit checked
rule; already having a receipt is not permission for circular assumptions.

**Owners.** `components/bisimulation_connected.py`, `bisimulation_harness.py`,
`bisimulation_refinement.py`, `bisimulation_world.py`, `bisimulation_summary_contracts.py`,
`bisimulation_postconditions.py`,
`semantic_providers/portable_c_*.py`, qualification and connected-service tests.

**Exit.** Real Hello connected callers pass through the selected production
summary path. Inspect their GOTO models to establish that summarized callee
bodies are absent, rather than merely observing faster queries. A fixed-interface
callee-size experiment demonstrates parent model size does not grow with callee
body size. An alias/mutable-memory test must reject equal-view-metadata calls
whose readable contents differ; further mutations cover stale generations,
unframed writes, wrong effects, missing outcomes, unmet preconditions, stale
receipts, and circular dependencies. Include actual solver fixtures, not only
rendered-string assertions.

CBMC's [function-contract documentation](https://diffblue.github.io/cbmc/contracts-functions.html)
and [replacement semantics](https://diffblue.github.io/cbmc/contracts-requires-ensures.html)
are useful references for checked preconditions, nondeterministic permitted
effects, and postconditions. They do not by themselves establish this project's
paired relational rule. Evaluate the pinned CBMC's facilities with a small
fixture before adopting them; no new solver is required by this plan.

## Stage 2: Bound proof regions without shaping production source

**Work.** Generalize cutpoints beyond cyclic SCCs. Generate proposals at service
boundaries, joins, and suitable internal locations using a checked size/cost
budget. Derive local unit, expression, memory, and transcript inventories rather
than relying on transfer count alone. Operators may adjust proposals through the
same relation/capture mechanism; small acyclic functions retain one obligation.

Check complete entry/exit/exception and inter-region transition coverage, barrier
alignment, and relation preservation. Cycles require induction; acyclic cuts
require composition without losing branch alternatives. Arbitrary cuts are
safe only when their connecting relations are proved. Reject unmatched source
barriers and uncovered control. Define any permitted stuttering/progress rule
before accepting rewrites with different internal step counts.

Keep exact and source slices specialized to each region, retain source-language
definedness and unwinding inventories, and preserve assert-before-assume checks.
Then optimize measured memory bottlenecks, including exact-write-specific affine
stack handlers. Cache compatibility must remain proved. Keep resource scheduling
bounded; partitioning is not permission for nested unbounded solver pools.

**Owners.** `components/bisimulation.py`, `bisimulation_exact.py`,
`contextual_bisimulation.py`, harness/world/refinement modules, and
`transfer/behavioral_c_{layout,render}.py`.

**Exit.** DX-Ball's full declared DirectDraw-init pilot, including all admitted
success/failure behavior, passes through bounded regions. Hello loop and connected
pilots and jq retain their obligations. Plans materialize zero complete paths.
Negative fixtures reject a missing branch, skipped barrier, weakened connecting
relation, omitted fault, undefined source operation, and exhausted bound.
Benchmark generated model sizes and solver costs across branching/loop families;
do not claim linear solver complexity from linear plan size.

## Stage 3: Close the current migration

**Work.** Discharge every required existing pilot shard, build the exact provider
objects, select them in declared candidates, and verify the strong dispatch/link
chain through native realization and downstream execution gates. Keep jq's
unrelated whole-target blockers explicit: use its scoped provider gate and a
closed execution fixture where whole-jq activation is unavailable. A fixture
must not be presented as executing a complete jq application.

Inventory every producer and consumer of finite-path and synthetic
`init`/`step`/`finish` authority. Migrate remaining consumers before removing the
superseded authority paths; retained diagnostic fixtures must have no route to
activation. Remove transitional connected-call strategies once their production
users have migrated. Update formats, registries, SDK constructors, tests, and
documentation together. Distinguish harmless historical type names from active
legacy authority rather than deleting by name alone.

**Owners.** `semantic_providers/`, `native_realization/`, `candidate/`, generic
Nix constructors, `targets/{gnu-hello,jq,dxball}`, registries and documentation.

**Exit.** All migration pilot contextual receipts satisfy their full scope;
applicable candidate objects and dispatch are verified; stale/weak/duplicate/
partial/source-only mutations fail closed. Required target, native PE32,
headless-Wine, architecture/absence, metadata, and repository gates pass.
An incomplete receipt is a correct diagnostic outcome but does not complete
this milestone for a required pilot. Refresh the checkpoint from exact outputs.

## Stage 4: Make the operator work in source concepts

**Work.** Extend existing component discovery, V6 work packages, `component start`,
`component check`, and operator projections. Provide a bounded review view linking
the source operation, exact instructions, recovered CFG, service calls, ownership,
and assumptions. Start with CLI/text plus structured JSON; add a visual client
only over these same products, without a second state or authority system.

Generate editable proposals for names, types, component boundaries, source
bodies, captures/codecs, candidate invariants, and matching library/interaction
contracts. Separate mechanically derivable facts from ambiguous choices.
An optional AI proposer uses the same API and cannot write qualified artifacts.
Persist accepted edits transactionally in canonical target intent/source, with
preview, stale-input checks, rollback, and explicit proof invalidation. Reuse the
existing component-start transaction rather than inventing an adoption ledger.

Translate failures into source-level differences with original instruction
locations and checked model assumptions. Separate behavioral mismatch, source
undefined behavior, unsupported semantics, insufficient relation, and solver
resource exhaustion. A timeout gets a cost explanation and subdivision proposal;
it must not be presented as a behavioral counterexample. Preserve raw evidence
for expert inspection, and reject traces bound to stale source.

Improve ordinary-C support from observed needs. Prefer checked frontend facts
for language/profile and source-location analysis as constructs grow beyond
the existing lexical scanners. Permit familiar helpers, const data, structs,
and supported ownership patterns through one production/proof compilation
configuration; do not expand the C subset by bypassing definedness checks.

**Owners.** `commands/{workflows,component_start,proposal_components}.py`,
`components/{discovery,proposal_package,work_package_v6,source_profile}.py`,
`components/cbmc_backend.py`, `operator/`, and existing library workflows.

**Exit.** On the frozen application, a recorded session discovers and starts a
region, reviews proposals, edits readable C, diagnoses a seeded mismatch, repairs
it, qualifies the replacement, and selects the candidate through public commands.
Routine regions need no hand-authored hashes, register-codec JSON, or internal
Nix expressions. Ambiguous memory/type facts still receive explicit review.
Cancellation/restart preserves work, stale proposals are rejected, and a local
edit does not rerun original extraction or unrelated provider qualifications.

## Stage 5: Turn required platform support into reusable contracts

**Work.** Use the stage-0 capability inventory to extend existing machinery in
small complete verticals: heap allocation/failure/reallocation/free and aliasing;
callback registration/lifetime/reentrant delivery; and the file, window, or
graphics services needed by the trial. Audit existing runtime and ingress
support before adding another mechanism. Preserve exact exceptional outcomes.

Each vertical supplies one shared meaning to proof lowering, runtime adapters,
source views, and provider qualification. Keep platform assumptions visible.
Package reusable bindings and recognition data in existing profiles and library
packs; matching an SDK name or recognizing library bytes is still a proposal.
Never fix an unfamiliar binary with hardcoded target addresses in generic code.

**Owners.** `external/`, `calls/`, component interaction/lifecycle/value-codec and
machine-overlay modules, `qualified_platform/`, candidate runtime/ingress,
`profiles/`, and linked-library constructors.

**Exit.** The trial's required platform capabilities close through generic
contracts and exact linked adapters. Heap aliases, allocation failure, stale
handles, callback-after-release, reentrancy, and missing exceptional paths have
negative fixtures as applicable. Reuse at least one new contract in a second
independent consumer. Retain a capability matrix for features still incomplete,
including concurrency, COM apartments, loader variation, and unmodelled SEH.

## Stage 6: Export maintainable source and demonstrate a real port

**Work.** Add a public export workflow over the selected source/provider closure.
Emit authored C/headers, required generated adapters and runtime source, assets,
dependency/license information, build instructions, and a bounded provenance
manifest. Use relative paths and a conventional build entrypoint. Separate
application logic from platform adapters and generated compatibility code;
report remaining generated-C and pinned-binary ownership explicitly.

A clean build must work outside this checkout without the extractor, its Python
modules, an existing Nix store, or the original PE as a runtime dependency for a
configuration advertised as fully source-portable. Nix remains the canonical
reproducible qualification environment. An arbitrary external rebuild is an
export-validation result, not automatically the previously qualified executable;
bind changed compiler/object identities through qualification before claiming it.

Choose one service family required by the trial for a portable replacement.
Describe both implementations against a shared observable service protocol,
including failures, resources, callbacks, and allowed internal steps. Qualify
the new backend and its composition using existing environment/provider and
transducer boundaries. Keep exact-call mode intact for existing Windows builds;
do not globally weaken transcript equality to permit the new backend.

The second platform also needs its own qualified compilation and realization
profile. Account for integer/pointer widths, object layout, endianness where
relevant, source-language definedness, and the actual host runtime. Reuse the
provider/object/link evidence chain, but do not accept a PE32 receipt as proof
of a different host executable. Qualify the platform adapter's implementation
separately from any reviewed assumptions about the underlying operating system.
Missing host support is an explicit stage-6 deliverable, not something a passing
cross-compilation or runtime test can discharge.

**Owners.** Public commands/SDK, component source packaging, semantic-provider
selection, candidate/native build code, environment contracts and target assets.

**Exit.** Build the exported Windows configuration in a clean environment and
observe its declared scenarios through applicable gates. Build and execute a
clearly scoped configuration on a second platform with the qualified service
replacement, no Wine dependency, and no concealed x86 interpreter or PE runtime
requirement. A selected subsystem port is labeled as such until the entire
application's platform closure qualifies. Readability review confirms ordinary
functions/data structures and isolates proof/runtime plumbing at boundaries.

## Stage 7: Evaluate usefulness and repeatability

**Work.** Run the frozen unfamiliar application from import through faithful
baseline, partial portable selection, source export, and the declared port scope.
Exercise normal use, failure paths, cleanup, and callback behavior. Record every
manual intervention and any generic toolkit fixes. Candidate observations remain
veto evidence alongside the required static authority.

Then repeat the workflow on a second independently selected application or
subsystem using the same contracts and public tools. Keep validation input
selection independent of which examples currently prove quickly.

**Exit.** Publish a reproducible narrative and generated evidence locations:
what built and ran, exact qualified scope, remaining fallback and platform
dependence, timing distributions, operator effort, and primary blockers. A
second operator can follow the workflow without undocumented internal commands.
One successful GUI demo is insufficient if it required target-specific checker
code or manual edits to generated authority.

## Stage 8: Expand coverage based on demonstrated blockers

Grow a maintained corpus across optimized C/C++, indirect dispatch and jump-table
forms, DLL/data/TLS and loader behavior, SEH and C++ exception runtimes, COM
lifetime/apartments, and asynchronous/concurrent services. Follow with packed or
self-modifying code only under an explicit new admitted profile. Treat x64 and
managed .NET as separate architecture/runtime expansions, not implicit PE32
coverage. Every capability needs an exact model, negative cases, a real consumer,
and the same operator/latency acceptance; prioritize by observed application
coverage rather than raw instruction or API counts.

## Measurements and decision rules

Record hardware, pinned tools, concurrency, memory, prerequisite/cache state,
sample count, median, and tail latency. Separate CLI/status, compilation, model
generation, solver, selection/link, and runtime-readiness costs. Report actual
builders executed, not only Nix's advertised derivation count.

Initial engineering targets for the recorded local warm environment are:

| Interaction | Target |
|---|---|
| Read already-indexed local status | At most 1 second |
| Reuse an unchanged qualified component | At most 5 seconds |
| Compile a small source edit and report syntax/profile errors | At most 5 seconds |
| Prove a representative small edited region | At most 30 seconds |
| Prove the trial's larger, partitioned interactive regions | At most 120 seconds per region |

These are planned product budgets, not observed results or proof assumptions.
Stage 0 records feasibility before tuning; any revised budget needs a written
reason and unchanged semantic scope. Stage 3 still requires real satisfied
proofs even if they exceed an interactive target; stages 4/7 additionally require
the recorded interactive budgets. Cold preparation and full validation are
reported separately. Do not hide a minutes-long proof behind a fast status read.

Also measure operator minutes per accepted region, manually authored proof
annotations, proposal acceptance/correction rates, source readability, qualified
portable coverage, runtime/platform dependencies, and number of generic fixes
needed for each new input. Weight coverage with application scenarios and owned
semantic size; definition counts alone can overstate progress.

If parent models still grow with summarized callee bodies, fix composition before
raising solver limits. If modest acyclic regions remain expensive, inspect
footprints and region boundaries before adding solver backends. If ordinary
work requires register JSON, improve proposal/checker integration. If a new app
requires target-specific Python, generalize the contract. If export still needs
the extractor workspace, standalone portability is unfinished. Revisit Nix cache
granularity only after measured unnecessary rebuilding justifies it.

## Validation and immediate execution order

Batch real-pilot rebuilds at integration checkpoints. During an implementation
batch, use focused solver regressions for changed proof mechanisms, public trial
commands for operator changes, and affected validation for the resulting batch.
Do not rebuild every real pilot after each individual soundness repair or
diagnostic edit. Finish and inspect an already running build before considering
another run; bind its evidence to the exact inputs it used. The next real-pilot
checkpoint follows the Metapad proof-plan integration batch, or an earlier
specific question that requires the real pilot's behavior.

A changed proof contract invalidates older authority immediately even when its
pilot rebuild is deferred. Existing Nix phase input closures and content-addressed
outputs continue to govern reuse. Final current-tree pilot, selection/link,
native and repository gates remain mandatory. Further cache granularity work
requires evidence of avoidable rebuilding of unchanged obligations.

Use focused existing fixture-backed test shards for each changed mechanism,
including meaningful negative cases. At milestone boundaries run the supported
repository paths as applicable:

```console
nix run .#dev -- refresh --check
nix run .#test -- affected
nix run .#test -- full
nix run .#test -- benchmark
nix run ./targets#test -- gnu-hello
nix run ./targets#test -- jq
nix run ./targets#test -- dxball
nix flake check -L
nix flake check ./targets -L
git diff --check
```

Refresh generated manifests through their owning tools when code or schemas
change. Use shared CBMC/compiler/PE32/headless-Wine fixtures. Add the new target
to the same public SDK validation path. Preserve stable incomplete diagnostics
for unsupported scope while keeping required completed-scope acceptance strict.

The first implementation sequence is: capture stage-0 evidence and trial;
add adversarial connected-memory/composition fixtures; implement checked
body-free summaries; generalize acyclic cuts and align source barriers; discharge
the real pilots; finish migration/absence/link gates. Instrument operator costs
throughout. Then complete assisted authoring, required platform contracts,
standalone export, and the two-input usefulness trial in the dependency order
above. Do not start by adding a GUI, another artifact registry, or another solver.
