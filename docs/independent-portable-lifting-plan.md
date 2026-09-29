# Plan: Independently Liftable Portable-C Components

Scope correction (2026-09-29): the project delivers idiomatic C Windows
applications using Windows runtimes, preferably exercised through Wine. Porting
the lifted applications to other operating systems is outside project scope.
The historical Portable-C terminology and experiments below do not impose a
non-Windows runtime requirement. [Current delivery scope](current-goal.md).

Current sequencing (2026-09-21): follow
[P1–P4 in the whole-target plan](whole-target-independent-lifting.md#practical-subsystem-milestone-and-sequencing)
for the next practical connected subsystem and different-target reuse milestone.
That order takes precedence over the historical formal-composition steps below.
The normal path is executable C boundaries, comparison, replay, integration and
reuse, with focused proof as additional evidence. Strong whole-program
qualification is a separate optional objective; its standards remain unchanged.

Product-direction update (2026-09-15): the operator has accepted practical modular
lifting with explicit assurance and optional focused proofs. The
[practical independent lifting design](practical-independent-lifting-design.md)
now specifies the proposed next implementation sequence and experimental execution
policy. Universal formal composition is not a prerequisite for that practical
workflow. This is a design update, not an implemented relaxation of existing
strong qualification or native-activation readers. The formal composition work
below remains the path to stronger assurance.

The first real independent-component milestone is complete for the hand-defined
Metapad network under explicit trusted runtime contracts. See the
[completion audit](baselines/2026-09-14-independent-component-milestone.md) for its
current evidence and limits. The remaining plan generalizes that demonstrated
workflow; it does not inherit general-target or activation authority.

The v120 runtime extension exercises the same consumer network through real
resource retrieval and notice delivery. Both exact resource implementations from
the public proof/reuse experiment run through the generated logical adapter;
actual LoadStringA and MessageBoxA use the retained PE's resource and caption.
Production image origins and dynamic origins share the native resolver. The
fixture's explicit image-address translation and memory/stack admission remain
outside general loader qualification. Consumer proofs still import unchanged with
zero model/compiler/solver work. Complete the milestone audit next; wider target
coverage is a subsequent generalization, not a reason to keep extending this
runtime fixture indefinitely. See the leading checkpoint in `current-goal.md`.

The v119 runtime experiment connects the actual save and guarded UI caller
transfers and ordinary-C implementations to the existing complete cleanup adapters.
Twenty-six executions use real allocation, copy/release/length and EDIT-window
services; they cover callback-mutated current memory, aliases, lifetime, mode/count
boundaries and fault prefixes. All seven new tests and four prior adapter tests
pass, while existing local proofs remain importable without generation or process
execution. This factors concrete runtime validation outside the application proof
models. Image/stack admission and the notice-suppressed scope remain explicit;
the resource/message-box path and complete applicability audit are next. Finite
cases do not replace local proofs or authorize activation. See [current evidence](current-goal.md).

The v118 public network experiment now withdraws a checked cleanup frame
guarantee and identifies its actual consumers. Save reuses its exact proof without
model/compiler/solver work; UI reports the missing EDI preservation and cannot
reuse its proof. Explicit per-consumer requirements are checked by complete
original/C queries with all unselected registers arbitrary. The existing supplier
product exports a weaker conjunction without rerunning its stronger proof.
Every non-frame contract term remains exactly bound. This supplies the milestone's
concrete contract-change/selective-invalidation example, while broader refinement
rules remain future work. Continue with actual caller/adapter/runtime applicability
and the full acceptance audit. See [current evidence](current-goal.md).

The v117 public experiment now has two real ordinary-C consumers of the same
checked cleanup operation: save preparation and guarded UI replacement. Both
reject a wrong local edit and reuse their unchanged proofs after a compatible
resource implementation change through cleanup, without callee bodies or any
consumer model/compiler/solver runs. This establishes the selected multi-context
local workflow. Concrete caller/adapter/runtime applicability and a public
contract-refinement/invalidation sequence remain open; the component profiles
are still explicitly supported rather than generated from arbitrary boundaries.
Continue with those obligations, not additional component counts or proof cuts.
See [current evidence](current-goal.md).

The v116 experiment now uses the complete conditional cleanup contract in a
real save-path authoring operation. Public wrong-edit detection, repair and
transitive resource -> cleanup -> save proof reuse pass with supplier bodies
absent and zero unchanged-consumer model/compiler/solver runs. This is the first
real complete-operation consumer, not the completed multi-context milestone.
Next consume the contract in the second real caller and qualify actual entry,
adapter and runtime/service premises; general contract refinement remains open.
See [current evidence](current-goal.md).

The v115 public composition phase connects checked service observations across
the real cleanup regions, retaining the entry prefix on memory-fault exits. A
compatible resource implementation change reuses the consumer and composition
proofs without model/compiler/solver work. This still requires assembly into a
consumable conditional operation contract and use in the actual caller network;
additional standalone transport kernels do not complete that milestone. Entry
now proves unchanged incoming public memory at every service boundary, because
equal final memory alone cannot justify equal call-time contents. Concrete
allocator, caller, lifetime and service applicability remain separate. See
[current evidence](current-goal.md).

The v114 composition step consumes guarded postconditions from the actual
regional proofs, complete source-region ownership and the private saved-word
mapping. It checks loop ranking and normal return-frame composition without
application bodies or unrolling the operation's full loop. Continue by composing
the remaining current-state and interaction guarantees and admitting actual
callers through the existing contracts. The conditional control step does not
qualify blocking/diverging services or finish the multi-level authoring network.
See [current evidence](current-goal.md).

The v113 public composition product now includes the actual production accessor
relation and a checked use profile over cleanup's complete owned compiler graph.
Compatible supplier changes reuse it and the tail proof without consumer model,
compiler or solver execution. The relation handles canonical null, interior origin
coordinates, supported widths and outcome-dependent read values. Concrete runtime
and service premises stay visible and unqualified. Continue by composing the
complete cleanup state/control theorem and admitting real callers, then exercise
the multi-level authoring network. These reusable premises do not themselves
complete that milestone. See [current evidence](current-goal.md).

The v112 integration uses the complete existing cleanup overlay with the current
ordinary-C service ABI. Six finite operation cases and negative controls now run
in the repository's headless PE32/Wine test infrastructure. It exposed and repaired
a retained binding mismatch in copy/release result types. This does not discharge
the adapter's representation relation: actual returned views have reference-aware
span callbacks and canonical-null results, while the regional proof uses local
descriptor conventions. Next check source observability, supported widths and
fault-path outputs when transporting between those representations, then compose
the operation and actual callers. Do not replace these proof obligations with
the new runtime test's passing outcomes.

The v111 public product adds checked live descriptor/accessor substitution and
the complete ordinary-source scratch grant protocol. Compatible supplier changes
still reuse both consumer proofs without model/compiler/solver runs. Four explicit
runtime requirements cover persistent borrow storage, hook frames, service
non-retention and physical release outcomes; all remain unverified. Next qualify
the actual runtime and the two real caller contexts, then finish the operation
theorem and multi-level authoring network. Access revocation alone does not prove
physical deallocation, and fault exits may still hold an active grant.

The runtime applicability audit reuses the unchanged native invocation-owner
proof. It refreshes the small actual `GlobalAlloc`/`GlobalFree` PE32/Wine test for
the changed fixture context layout, with four rejected controls. It leaves explicit
gaps for the complete cleanup adapter, current access hooks, actual callers,
length/copy and UI effects, and all admitted release outcomes. Consume this scoped
evidence instead of repeating unchanged platform/issuer checks or treating the
finite allocation test as a complete runtime contract.

The v110 public composition product binds current-memory substitution to the
actual entry/loop/tail guarantees and premises. Current contents survive cuts
without carrying accumulated write history; the tail's zero-suffix representation
is justified by the predecessor guarantee. Compatible supplier edits reuse this
proof and the tail proof without model/compiler/solver work. Continue with live
descriptor/context transport and actual caller/service qualification, then
complete the cleanup theorem and its real multi-level authoring network. The
conditional byte theorem alone does not establish any of those obligations.

The v109 composition product now checks the actual regional private-cell
representations against a shared byte-backed object, including saved-frame,
count, partial-word and untouched-byte transport. The same-input store relation
is inductive, and a compatible resource implementation reuses both tail and
composition proofs. Continue with public-memory/descriptor/lifetime transport
and actual caller/runtime compatibility before claiming the complete cleanup
theorem or multi-level authoring-component network. See [current evidence](current-goal.md).

The v108 public composition admission phase now consumes the real regional
receipts without their bodies, exposes the missing tail stack/image requirements,
and proves that a named caller/allocator envelope would suffice spatially. A
compatible resource edit reuses the tail and admission proofs with no model,
compiler or solver execution in either consumer. Establish these requirements in
the two actual calling contexts and check contents/private-state/lifetime transport
next. Spatial implication remains distinct from complete state composition and
does not complete the authoring-component network. See [current evidence](current-goal.md).

The v107 public entry, loop and tail products now share one hand-defined source
graph, with no uncovered reachable source instructions and a checked 35-transfer
original control cover. Actual allocation error/repair runs through the public
workflow. Continue with checked state/private-frame and persistent object/image
admission across these cuts, then concrete runtime compatibility and the complete
cleanup component in its real caller network. Common graph coverage and regional
success do not by themselves establish composition. See [current evidence](current-goal.md).

The v106 implementation promotes the actual cleanup tail into the existing
public region engine. It checks source effects and the original resource call
edge, imports the complete checked supplier domain without supplier bodies, and
binds C callback type conformance. The public edit/repair and
neighbor-reuse sequence now passes with identical consumer proof files and no
consumer processes after the supplier change. Compose the actual cleanup
entry/loop/tail and qualify concrete service and caller admission next. A terminal regional product alone
does not finish the component-network milestone. See [current evidence](current-goal.md).

The v105 consumer audit found and corrected a mismatched `copy` callback
return type that GOTO compilation had accepted. The corrected complete tail now
passes with full view/reference checks, explicit post-release write rejection
and arbitrary shared scalar service results. Compiled source-effect admission and
real reference/lifetime/result edit failures are bound to that model. Promote this
admitted consumer through the public tail product and compose the actual regional
and supplier receipts next; the experiment is not the public network milestone.

The v104 public loop product now supports explicit runtime revision 3: a
writable text descriptor, the null-scratch pending-text invariant, and all eight
public-memory guarantees checked at both normal cuts. Revision 2 remains explicit
or the default; refinement invalidates its proof. This is a prerequisite for
consuming the actual entry/loop/tail receipts. Public receipt composition,
complete editable-tail effect admission and concrete service compatibility remain
the next work; regional refinement is not completion of the component network.

The v103 retained tail now passes a complete conditional query using the checked
resource supplier transition, with both supplier bodies absent. The baseline and
loop-edited suppliers are rechecked through the public command and expose equal
transition domains. A wrong resource ID in the actual consumer source fails its
call-argument obligation. Entry and loop have also been rechecked using the tail's
writable text descriptor. Continue by composing these actual regions through the
public workflow and qualifying their service/entry assumptions; neither three
passing regional queries nor equal supplier domains completes the network milestone.
See [current evidence](current-goal.md).

The v102 tail consumer identified a missing regional invariant for failed
allocation. The proposed current-memory refinement is now established by entry
and preserved by the real loop at both normal exits. The tail's actual compiled
body also matches a terminal region with ordinary returns and no synthetic exit
API. Its complete correctness query remains incomplete, and these regional facts
are not yet composed through public proof receipts. Continue through this actual
consumer and the resource supplier; additional proof regions do not satisfy the
component-network milestone. See [current evidence](current-goal.md).

The v101 retained entry proof now covers real cleanup entry, its three service
invocations and its finite short-input path, and asserts the loop's shared
public-memory domain. The entry proof is still conditional and fixture-driven;
public source preparation alone does not integrate it as a public correctness
product. Connect entry/loop/tail evidence and real service contracts next, then
exercise the existing resource supplier through the complete consumer. No new
component ownership or network completion follows from these proof regions.
See [current evidence](current-goal.md).

The v100 public region product now checks the real cleanup loop under an explicit
byte-compaction boundary contract and imports its proof after an outside-loop
source edit without regenerating or solving the model. An actual wrong store
fails; incomplete region closure rejects. The existing compiler transport checks
are engine code. This closes the public graph-to-loop-proof integration task;
entry admission, prefix/tail coverage, runtime compatibility and the meaningful
component network are now the next work. A proof region remains distinct from an
authoring component. See [current evidence](current-goal.md).

The v99 public source-check product now prepares the real manually anchored
cleanup region graph. It exposes control edges, calls, storage and uncovered
scope; local body changes preserve unaffected region bindings. This does not
import a correctness proof. Connect the existing local application proofs and
their state contracts to that public graph next, then complete operation coverage
and the actual component network. Copy/advance remains internal to cleanup:
removing its source statements from cleanup's own proof is not an extra milestone
requirement. Independence is required across actual component dependencies, while
proof-region reuse requires checked boundary compatibility. See
[current evidence](current-goal.md) and [configuration](components.md).

The v97/v98 experiments bind the compiled ordinary cleanup loop and compose its
original side through a checked shared copy/advance transition. The same
transition serves the real second-byte short-input context; both consumer original
slices omit the shared bodies. This resolves the identified local shared-entry
case under explicit entry domains. It does not create an independently editable
application component: source copy statements still execute in the consumers,
and entry admission, complete cleanup coverage and runtime qualification remain
separate. The later v100 product exposes the loop cut proof publicly. Complete the
remaining operation coverage and actual dependency composition next. Do not grow helper counts or assume a
performance gain: the composed loop currently takes longer than the bound loop.
See [current evidence and limitations](current-goal.md).

The v95 checkpoint puts the actual source-bound caller proof and checked
supplier rebind into the public operator product. The composed workflow prepares
ordinary C automatically, rejects a wrong argument, preserves all consumer proof
files across a compatible supplier edit, and rejects an incompatible private
frame before solving. This establishes one conditional call region. Complete
application regions and the multi-level network remain the next substantive
work; additional single-call projections cannot satisfy them. See
[current evidence and exact scope](current-goal.md).

The earlier v96 retained experiment proves a complete actual cleanup iteration under a
compact local memory contract, including allocation-failure outcomes and back-edge
progress. Its source-cut resume/capture correspondence is not yet checked for
public import. Original CFG inspection exposes the next real composition case:
the copy block 0x5601 is shared with the short-input predecessor 0x55fa. Account
for both entry contexts and bind source state transport before treating it as an
independent unit. This remains application composition work, not a reason to
resume global heap-model partitioning.

Immediate acceptance priority (2026-09-13): demonstrate the contract-only local
proof boundary on a small real Metapad component network through the public
workflow. A neighbor implementation change preserving its contract must not
recompile or solve the consumer model. A contract change must invalidate affected
consumers. Manual boundaries, real stateful interactions and complete local
application obligations are required; source-only frame/input-dependence checks
and additional solver partitions remain supporting evidence. The active
[goal](current-goal.md) records these exits and the current implementation gap.

Conditional caller composition (2026-09-13, v93): two actual resource-call cuts
now check against ordinary logical-call fragments with the supplier bodies absent.
A checked transition reader binds public functional supplier evidence, and a
public supplier loop edit reuses both caller-cut proofs without consumer model
generation, compilation or solving. A separately checked stack-domain extension
identifies both callers for rechecking. This supplies the missing actual-call
composition experiment; binding those fragments to the authored caller through
the public cut workflow and completing the multi-level network remain required.
Keep caller coverage, MessageBox safety and native service compatibility open.

Native adapter evidence (2026-09-13, v92): tests now connect the generated logical
caller to the actual native image namespace with retained Metapad origins. They
check current aliases, full-buffer offsets and rejected stale/changed descriptors.
This closes one validation facet, not the runtime contract as a whole. Preserve
the public `unverified` compatibility status until the actual service, memory and
caller obligations are discharged. The next composition work remains the real
caller consuming a checked shared transition, without the supplier body.

Public original/source integration (2026-09-13, v91): the existing source-contract
product now checks the real resource-text baseline and loop edit against the
original body using its already validated opaque source object. The actual
public Nix workflow detects an incorrect resource ID that satisfies the auxiliary
source contract, and exact repair reuses the existing product. Runtime assumptions
and remaining compatibility are visible in feedback. Bind the real caller and
transitive summary composition next; this leaf check is not the network exit.
See [current evidence](current-goal.md) and [configuration](components.md).

The compact original/source experiment (2026-09-13, v90) now proves the complete
retained resource-text leaf and a loop-based C edit under a borrowed-image,
private-stack and selected-service domain in about five seconds each. The
ordinary service profile suffices without assuming a terminating write on result
zero. It preserves the full 500-byte extent and all selected safety/unwinding
assertions. This supplies a functional comparison to integrate with the public
contract workflow, not a new trusted provider. Bind runtime compatibility,
source opacity and exact evidence, then compose the real caller. Keep its
current-string invariant separate from the helper's alias/effect equivalence.
See [current evidence and limitations](current-goal.md).

An initial reuse rule now separates a consumed fixed-memory source contract from
its supplier's complete implementation certificate. It validates replacement
supplier evidence and reuses unchanged consumer models and outputs across two
fixture levels without any compiler/solver subprocess. Public dependency feedback
shows both the consumed contract digest and supplying receipt digest. This applies
to auxiliary memory theorems, including a shared service consumer of fixed-memory
dependencies. The generated compiler header now declares those dependency calls,
so authors need not repeat their signatures by hand. This does not yet supply
transitive shared machine qualification or the application-equivalence workflow.

Public manual-boundary checkpoint (2026-09-13, v86): the real ordinary cleanup
edit now passes through `component check --source --compare-baseline` with a
boundary before its byte-read and failure check. An identical-prefix correspondence
preserves those effects and checks the changed decision universally; this is not
a newly trusted reader summary. Wrong behavior is rejected, exact repair reuses
evidence, and state/call/interface changes invalidate the restricted comparison.
The existing 25 bounded safety queries survive with their original scope, while
all twelve application obligations remain incomplete. This advances public
boundary ergonomics and edit/reuse, but application-runtime composition and
compatible contract refinement remain the next substantive gaps. See
[current measurements and scope](current-goal.md).

Actual incoming boundary checkpoint (2026-09-13, v85): the retained Metapad
application now discharges the preconditions of a separately qualified image-origin
initialization protocol. Its precise frame avoids whole-registry snapshots while
retaining all capacities and original application inputs. A local adapter edit
reuses the actual caller proof; incorrect metadata and out-of-frame writes are
rejected. This advances composition through a real consumer, but the full
application selection still times out and the edit is not ordinary application C
through the public operator path. Prioritize that remaining application-local
check and public dependency/reuse connection over further standalone adapter
variants. See [current evidence and failed generic-boundary trials](current-goal.md).

Application contract refinement (2026-09-13, v84): an extended run turns the
previous aggregate timeout into an actionable `lookahead_one` counterexample.
The reader contract was missing its value-to-memory relationship. Checking
that relationship against the concrete reader and consuming it makes the
unchanged application invariant pass. Keep this refinement directed toward the
complete application selection and public edit/refine/reuse workflow; do not
count its observer as an additional completed application component or infer
improved performance. See [current evidence](current-goal.md).

Neighbor-service composition (2026-09-13, v83): the caption/edit-window admission
pair now consumes a separately qualified registry-extension contract with the
neighbor body absent. A local implementation rewrite requalifies that contract;
a prefix violation is rejected. The checked consumer program is unchanged except
for an unreferenced automatic declaration, and a restricted relation reuses the
consumer proof without rerunning its solver. Input snapshot correspondence,
caller applicability, frames and original service assertions are checked.

This is a concrete service-level edit/violation/reuse demonstration, still in
retained experiments. Next carry it into the actual application-component boundary
and public workflow. Do not count these service roots as completed application
components. All twelve public application obligations, general native continuity
and the same-object concrete trial remain open. See [current evidence](current-goal.md).

Readonly continuity experiment (2026-09-13, v81): the retained parent checks
explicit applicability for using the proposed invariant on four readonly
parameters. Adapter violations are detected and exact repair reuses evidence,
but the complete application/guard selection still times out with both SAT
and SMT. This neither qualifies native continuity nor completes the public
component edit/refine/reuse milestone. Next check the actual origin-registry
effects and the read footprint that must survive neighboring operations;
lookup wrappers must not be treated as pure by declaration. Keep this work
directed toward the real connected consumer. See [current evidence](current-goal.md).

Fault-relation checkpoint (2026-09-13, v80): a checked allocation footprint
now preserves the first binary reader's fault condition, replacing the rejected
unconditional guarantee. All three reader bodies can be omitted in the full
parent, and all 16 caller preconditions pass. The broader 811-property
application/guard check still times out with all 122 original source/root
assertions preserved. Independent primitive checks reject lost liveness,
incorrect history precedence and invalid spans. This is a repaired contract
relationship, not a complete component result or demonstrated speedup.

Next factor reusable entry/reference invariants and their preservation, keeping
faults and exact admission dependencies visible. Complete original outgoing
obligations and public application-component edit/refine/reuse before growing
component counts. See [current evidence and limits](current-goal.md).

Reader composition checkpoint (2026-09-13, v79): full-parent consumption exposes
a missing fault relationship in the locally checked reader summaries. Adding
an unconditional nonfaulting guarantee is rejected for the first binary reader
and checked for the second in the retained caller domain. The revised consumer
keeps the first reader concrete and passes the second/source summaries' caller
preconditions, preserving all 122 original source/root assertions. Its broader
814-property application/guard check still times out at 180s. Complete
application composition and public edit/refine/neighbor-reuse remain open.
See [current evidence and next action](current-goal.md).

Prioritize checked transport of lifetime admission and fault relationships.
Neither a later successful descriptor check nor a local no-fault assumption
qualifies an earlier read. Keep the actual failed refinement and all remaining
outgoing obligations visible. Further batching of the retained parent's
assertions has timed out; it is not the next scaling milestone.

Descriptor-domain checkpoint (2026-09-13, v78): the actual caller checks
descriptor readability and separation from local writable storage without
changing its executable prefix. The local binary/C consumer now checks both
standalone and shared descriptor storage, preserves every descriptor field,
rejects a descriptor write, and reaches both outcomes for each storage origin.
This removes a fresh-descriptor-only restriction from that local experiment;
it does not establish arbitrary heap admission or complete component assurance.

Next compose these entry/storage premises with the existing checked runtime,
local outcome/frame and unchanged-context relations to discharge the actual
outgoing cut requirements. Keep the experimental fifth runtime premise separate
from the public four-contract baseline. Complete a real component result,
connected consumer reuse and compatible public contract refinement before
adding more storage variants or component counts. See [current evidence](current-goal.md).

Public query-transport checkpoint (2026-09-13, v77): the real Metapad edit now
carries 25 completed bounded safety-query results through checked processed
contexts. Exact repair reuses the processed context and local query; the public
cycle also detects a wrong branch and rejects unsupported state/contract changes.
This completes a query-result transport step, not the complete-component network
milestone. All twelve baseline application obligations remain incomplete.

Next obtain a complete real application-component result with explicit runtime
assumptions and entry/memory/lifetime scope, then consume it across a connected
component boundary and demonstrate compatible contract refinement. Keep bounded
safety partitions, conditional component theorems and strong activation authority
separate. Do not repeat the already completed entry-query reuse experiment or
substitute more pure-scalar features or artificial component counts.

Earlier checkpoint v76:

Baseline-context integration checkpoint (2026-09-13, v76): the public edit
workflow now checks the local source theorem in the exact retained Metapad
application proof environment, using four implemented runtime contracts. It
reproduces the original model, checks both marker erasures and complete contexts,
and binds the same universal local query. Dense local labels remove an accidental
dependency on caller instruction numbering while preserving concrete context
bindings. Correct edit/repair take 23.368s/22.145s with the stronger check enabled.

Next consume completed baseline query evidence through that relation. The baseline
has checked entry/safety subproofs even though its aggregate application
obligations remain incomplete. Preserve that distinction during reuse; do not
require a fabricated complete baseline or promote partial evidence into a
component theorem. Baseline-query transport, compatible contract refinement and
neighboring application-proof reuse remain unfinished. See [current evidence](current-goal.md).

Public edit workflow checkpoint (2026-09-13, v75): a real Metapad ordinary-C
edit, incorrect branch and repair now run through the public CLI/Nix path in
4.7--5.5 seconds with a retained baseline packet and no pilot rebuild. Repair reuses the exact local query;
existing-state and interface changes remain incomplete. This closes public
exposure and complete-command measurement for the restricted edit relation.

The missing connection is semantic baseline composition. A Nix-store search
found 15 exact-source diagnostic packets, all currently parseable but none with
a completed application obligation. Public feedback must retain those statuses
and check the full interface contract as well as source identity. The separately
checked experimental parent queries do not become public baseline theorems.
Next establish a qualifying obligation in the actual configured environment and
consume its evidence with checked edit/context transport, unchanged assumptions
and accurate dependencies. Keep contract refinement and neighboring-proof reuse
as acceptance criteria; do not substitute more scalar-profile work or component
counts. See [measurements and limits](current-goal.md).

Edit-composition checkpoint (2026-09-13, v74): the real source refactor now has a
universal after-read scalar comparison, checked unchanged caller context and
marker erasure to both ordinary sources. Correct and inverted branches pass/fail
in about 0.020s, and a transient write is rejected. This avoids repeating runtime
or descriptor admission inside the pure edit proof. The original parent's
conditional scope remains unchanged, and its exact queries replay without a new
solver run. Public theorem import and neighboring-proof reuse remain unfinished.

Next integrate the bound old/new source relation and retained baseline evidence
through the existing operator edit/check/repair path, with unchanged assumptions
visible and unsupported refinements rejected. Measure that complete path. The
experimental continuity lowering still needs justified public support; do not
bypass its guard or present this restricted refactor as the multi-component
network milestone. Keep wider hand-defined boundaries and the original
qualification obligations active. See [evidence and limits](current-goal.md).

Combined consumer checkpoint (2026-09-13, v73): local outcomes and a complete
application write frame now pass together with all three read implementations
absent. Both actual binary-read body/frame contracts and separate caller
preconditions pass, with rejected runtime return/write violations. The edited
local query costs 0.555s; checked source-prefix correspondence allows both
expensive runtime qualifiers to replay in 0.016s. This is prerequisite reuse,
not the public behavioral-neighbor milestone.

The specification audit corrected signature-only binding by checking CBMC's
actual `contract::` clauses and declaration/type dependencies. All retained
consumers match. Next complete the needed descriptor/entry projection and
unchanged-context substitution, then implement public edit/refine/repair/reuse.
The experimental continuity premise needs justified configured lowering before
public conditional packets can consume it. Keep complete frames around unobserved
memory and do not bypass existing authority guards. See [audit and limits](current-goal.md).

Local runtime-consumer checkpoint (2026-09-13, v72): the real region now consumes
the exact contextual reader contract, with the reader body absent and no separate
assumed source-byte-reader model. Correct original/edit checks take 0.215s, a wrong
branch fails, and both local exits are reachable. Compiled contracts/types and the
actual region/observer arguments are bound to those results. The actual scalar
entry mappings are checked separately, with a rejected wrong-coordinate control.

This closes part of runtime composition; it does not complete public independent
lifting. Complete the descriptor and actual binary-read observation transport,
keeping unobserved memory behind complete frame obligations, then consume the
local outcome/frame/context evidence through public edit, violation,
repair, contract refinement and neighboring-proof reuse. The descriptor storage
shape comes from the real decoder; other callers require their own admission.
Keep component counts secondary to that acceptance gate. See [audit and limits](current-goal.md).

Real caller-context checkpoint (2026-09-13, v71): the real original and edited
caller contexts now match outside the selected region, including their generated
entry and exit checks. Both actual bodies match strengthened local observers
that include all six parameter values. A parameter reassignment that passes the
old outcome and heap-write gates is rejected; the correct edit remains a 0.133s
local query. This closes a concrete boundary-state omission, not the complete
proof-import or public workflow milestone.

Next bind the caller's admitted input domain and the checked runtime read's
value/bookkeeping effects to these local models. Combine context correspondence,
local outcomes, parameter captures and complete memory frames through the public
edit/refine/repair/neighbor-reuse path. Keep the prior parent results as retained
evidence; do not silently reuse them for changed compiled models or reintroduce
an assumed application-region summary. See [audit and limits](current-goal.md).

Measured runtime-contract composition (2026-09-13, v70): the real contextual
reader has selected body/frame checks, separate caller admission, a reachable
return and rejected actual value/write violations. An ordinary full parent omits
its body and passes both selected original outgoing memory checks, with separate
reachability, without adding an application-region assumption. Tail still costs 151.936s, with 449.456s total cold
body/caller/tail queries before other checks and preparation. The retained
experimental reference-continuity runtime premise is not production-qualified.

This narrows the next implementation decision: stop treating body omission as a
sufficient performance boundary. Connect the existing local paired outcome/frame
proofs to reusable runtime applicability and shared-state cut transport, then
route those dependencies through public edit/refine/repair and neighboring-proof
reuse. Preserve the actual incoming domain and outgoing cut arguments. Do not
promote the older canonical application-summary experiment merely because the
new runtime reader contract checks pass. Complete that real workflow before
increasing component counts; see [audit and limitations](current-goal.md).

Conditional parent experiment (2026-09-13, v69): the existing tail and lookahead
memory observers pass with a canonical loop-region summary. A correct local edit
and repair preserve parent model bytes and replay its three selected queries in
0.018s total. A direct-write negative control requires the existing complete empty
frame proof in addition to local outcomes; ordinary C writes must not bypass an
API-call inventory. Both original and correct edited source have checked frame
body transport and passing local frame queries.

The parent still trusts an experimental application-region summary. Discharge that
premise through checked composition before counting this as independent application
assurance. The intended trust boundary remains explicit runtime contracts. Then
exercise public edit/refine/repair and neighboring behavioral-proof reuse; do not
replace that acceptance gate with more canonicalization experiments or component
counts. See [audited results and limitations](current-goal.md).

Real local comparison checkpoint (2026-09-13, v68): the actual Metapad binary
region and ordinary C now pass a conditional local read/branch/state comparison.
A correct C refactor passes, four deliberate behavioral/effect violations fail,
and repair reuses local evidence. Compiled cut-observer arguments and private
scalar scope renaming are checked. The edited C also preserves the actual runtime
prefix, reusing its selected 147.693s qualification without another solver run.

This demonstrates an inexpensive local problem and reusable runtime qualification,
not the complete connected-component milestone. Incoming heap correspondence,
actual paired-cut codecs and general native fault transport remain obligations.
The 0.12s local query cannot be compared as an equivalent replacement for the
158s full tail-memory query. Next connect those remaining semantics and exercise
the existing public edit/refine/repair/neighbor-proof workflow before increasing
component counts. See [audited scope and measurements](current-goal.md).

Body-omission checkpoint (2026-09-13, v67): both actual byte observers can be
replaced in the experimental parent, and 20,400 bytes of provider growth leave
parent C/GOTO inputs unchanged. A checked dependency family binds their readable
globals, rooted pointer reads and sole set-to-one observation effect to retained
local congruence evidence. Production summary/key transport remains unqualified.

The whole-world functional key gives an abstract counterexample at 177.886s.
Adding independently qualified public-byte admission correspondence leaves the
consumer incomplete at 180.615s, plus 83.177s qualification. This is no measured
speedup or completed application proof. Next put relational byte-read values and
effects at the real cut, with separate applicability evidence and the actual binary
region in the local consumer. Keep public edit/refine/repair/neighbor-proof reuse
as acceptance. See [audited scope and measurements](current-goal.md).

Paired-consumption checkpoint (2026-09-13, v66): measured assumptions and scalar
value substitution inside the same application model do not deliver a practical
speedup. The tail obligation takes 158.269s baseline, 157.705s with checked frame
assumptions, and 156.157s after a separately qualified equality-preserving byte
substitution. The latter adds an 88.158s qualifier. Actual read calls and effects
remain; the rules require whole-program requalification after an edit.

The next decomposition boundary must omit repeated memory-observation computation
from parent proofs through checked composition. The actual byte-projection lemma
and negative controls expose all required categories: world, initial fill, public
exposure, address and the observation-bit effect. Their local evidence is not yet
a checked body-independent summary. Prioritize a measured real consumer and then
the public edit/refine/repair/neighbor-proof workflow over more standalone facts
or larger component counts. See [audited measurements and limits](current-goal.md).

Compiled body-transport checkpoint (2026-09-13, v65): the real region's generated
entry restores and body/control graph now match its local frame model, with
negative controls for wrong restores, swapped cut exits and stale branch relations.
The local argument pointers are unconstrained. This does not yet connect the
actual paired-cut observers/codecs or public memory domain. Complete that bridge
before importing the local theorem. The experimental integer cut-return encoding
rejects collisions with source returns; generalization must use tagged proof
outcomes without changing ordinary production signatures. See
[evidence, validation and remaining integration](current-goal.md).

Body-independent frame checkpoint (2026-09-13, v64): the real source region can
use a named read-effect contract with no read implementation in its model. Provider
growth leaves that model unchanged; local repair reuses exact evidence. Actual
runtime read projections have separate selected qualification and matched-prefix
reuse across the public branch edit. A compiler-backed invocation inventory rejects
new reads/writes before solving and never equates payload matching with argument
state or contract validity. These are experimental ingredients; source cut-state
and body/control transport, application consumption and the public component
network remain open. Complete that integration before adding component counts.
See [audited evidence and limits](current-goal.md).

Source-local frame milestone candidate (2026-09-12, v63): the real cleanup C,
entered at its existing loop cut, passes a separate complete local frame/safety/
unwinding query in 9.310s using shared dynamic spans and the existing sparse
memory/view model. Actual memory and context-state writes are rejected. Repair
reuses exact evidence; a one-byte scratch-frame refinement accepts its intended
write and rejects a neighboring byte. The original public function stays intact.

This advances the missing body-preservation boundary, but is not yet the public
edit/refine/neighbor-proof workflow. The inverted public branch passes a frame
check and still requires functional proof. The wider frame cannot satisfy an
old empty-frame consumer. Next check cut-state/body transport and the runtime
memory abstraction before importing the local fact into the paired application.
Do not equate matching source/types, local query replay or a declared footprint
with checked composition. See [evidence, costs and remaining work](current-goal.md).

Actual-prefix integration (2026-09-12, v62): a selected memory-admission fact is
now qualified with the application's actual binary-before-C execution order,
then consumed at a checked prefix use site. Its body-free model and exact query
survive a retained public C branch edit. The experimental transport checker rejects
uses outside that prefix, address escapes and changes beyond the matching
assert-then-assume insertion. This is a structural rule with separate proof
obligations, not automatic summary acceptance.

Admission-only consumption fails to improve the measured application memory
query (166.757s baseline, 176.771s consumer). Next make remaining body-preservation
checks local relative to the admitted frame through existing frame/source-summary
machinery, then qualify the complete models and public edit/refine/reuse workflow.
Do not substitute more component counts or another unchanged broad inventory
for this integration. See [audited scope and costs](current-goal.md).

Earlier checkpoints:

Current milestone status (2026-09-12, v61): whole-memory correspondence and
per-side preservation now pass as separate selected predicates on the real
region. Their consumption reduces a matched tail query from 161s to 33s, but
qualification costs 468s. A separate entry-memory predicate, outside the editable
application body, passes in 89s and reuses exact evidence after a real C edit
in 5ms. These are conditional, selected bounded results; the new models' full
inventories and production summary consumption remain open.

The next integration is checked transport and consumption of that independently
qualified admission fact in the application proof, with memory/scope dependencies
and invalidation enforced. Reuse of an entry query does not demonstrate reuse
of a neighboring business-component proof. Keep the public edit/violation/repair/
refine/reuse network as acceptance, before increasing component counts. See
[current evidence and limits](current-goal.md).

Earlier checkpoints:

Readonly-image consumer (2026-09-12): the same proposed continuity invariant now
passes applicability and the original context check for `tail:suppress_notice`,
with its distinct selector, permission and span checked. Actual native image
helpers pass bounded positive cases and reject deliberately broken locator and
permission code. This advances the real consumer beyond text-only reuse; it
does not establish a complete component or production summary. Five bounded
exposure cases also pass against current bodies, including partial/reordered
coverage and scope invalidation; real removed-guard and late-write controls fail.
Complete admission/issuer enforcement and production lowering before promoting
the invariant.
The whole-region attempt returns incomplete after 2,305.081s, with all safety
groups and 73/393 authored assertions passing. The unresolved boundary is now
whole public-memory equality at `tail`; 319 assertions remain unexecuted.
Factor incoming whole-memory correspondence and preservation through the actual
region, using existing memory machinery without treating descriptor stability
or text-range equality as a global memory theorem. The public edit/repair/refine/
reuse network remains the acceptance milestone. See [evidence and limits](current-goal.md).

Second-cut consumption (2026-09-12): one proposed reference-continuity contract
now serves the actual text view at both `lookahead_one` and `tail`, with passing
applicability, metadata/context predicates and tail-assertion coverage. It keeps
the same implementation, inputs and trust identity. The broader run still finds
an unresolved context predicate for another incoming view. Use the existing
captured view/context and admission machinery to check that consumer's distinct
selector, permissions and span before generalizing. This is progress on invariant
reuse, while the complete region and public component-network milestone remain
open. See [audited evidence and costs](current-goal.md).

Explicit continuity checkpoint (2026-09-12): a new proposed trusted reference
invariant resolves the selected real metadata/context checks, with applicability
checked separately. Eleven bounded actual native/proof-runtime scenarios pass,
including byte changes, aliasing, origin append, release/reuse and internal
allocation exhaustion; deliberate address/lifetime faults are detected. The
revised contract checks private/exposed scope omitted by the first prototype.
It remains experimental and is rejected by production readers.

Complete the real-region comparison and validate admission/issuer enforcement,
the actual selector and exposed-range behavior before production integration.
Then demonstrate the public edit/violation/repair/refinement/neighbor-reuse
workflow. Passing predicates whose runtime guarantees are explicitly assumed
cannot substitute for that milestone or independently validate those guarantees.
See [current evidence and precise limits](current-goal.md).

Reference-boundary follow-through (2026-09-12): real outgoing-cut descriptor,
context, address, identity and source-world frame checks pass, with actual-cut
reachability and an actual runtime-generation mutation rejected. Supplying those
three checked facts does not resolve the application's metadata/context pair;
whole origin bookkeeping remains unresolved. A guarded pure-lookup cache also
fails the 180-second comparison and adds about 9.1% symbolic steps. It remains
unqualified and is not promoted.

Investigate the selected reference's issuance/live-object invariant through the
existing interfaces, keeping pure lookup separate from origin registration.
The consumer must demonstrate checked omission or reuse of substantial repeated
reasoning. More frame facts in the intact call chain or additional ordinary
memoization are not supported by these measurements. Preserve the existing
inputs, failures, alias/lifetime/byte obligations and effect order. The public
edit/repair/refine/neighbor-reuse acceptance gate remains open. See
[current evidence](current-goal.md) and [measurements](performance-and-invalidation.md).

Measured sequencing revision (2026-09-12): actual admission-to-read transport
and call reachability pass on the real Metapad loop; a C read-index mutation
fails the unchanged transport predicate. However, experimentally omitting the
source reader body leaves both selected application metadata/context checks
incomplete at 180 seconds and removes only about 0.15% of symbolic steps.
This does not justify a full qualification cycle for that substitution as a
performance optimization. First factor and measure the reference/memory work
still retained in the caller, with the same actual inputs and obligations.
Preserve the transport evidence and the unqualified candidate for comparison.
Neither selected frame checks nor this body-absence experiment completes a
region, establishes neighboring business-proof reuse, or authorizes activation.
The real-network public edit/refine/repair/reuse acceptance gate remains open.
See [current evidence](current-goal.md) and
[matched measurements](performance-and-invalidation.md).

Complete entry/read probe checkpoint (2026-09-12): all 248 authored assertions,
24 safety groups, unwinding and relation nonvacuity pass. Across the retained
public body edit, all 134 property/discovery/coverage processes reuse with zero
fresh queries, about 5s query work versus 932s cold. Actual wrong-width and
returned-byte mutations are detected. The next step is checked post-read
view/context, memory, lifetime/origin and bookkeeping frames plus transport to
actual application sites, before summary substitution. This qualifies the probe,
not the whole application or the public component-network workflow.
See [audited evidence and scope](current-goal.md).

Independent qualification checkpoint (2026-09-12): actual read success/value
checks pass in the existing source-entry model after loop admission, without
new assumptions or the ordinary portable-C body. Regeneration from a retained
public application edit leaves the qualifier unchanged and reuses its query;
an actual wrong-width read is detected. Complete qualifier checks now pass above;
post-read frame/application-site transport remain required. This is evidence for reusable
qualification outside application bodies, not yet a production read summary or
the public component-network milestone. See [measurements](current-goal.md).

Full-run follow-through (2026-09-12): the fourteen-fact model passes all safety
groups and 44/383 authored assertions, then returns incomplete after 1,676.234s.
Text metadata and context transport at `lookahead_one` remain unresolved; 337
assertions are unexecuted. Root-memory progress has not completed the real
region or made the whole local edit cycle interactive. Use these limits to
evaluate the independent entry/read boundary below before adding more facts
inside the complete application model.

Read-boundary checkpoint (2026-09-12): actual read-success facts qualify after
the source loop's existing admission and enable a checked residual-root barrier.
An earlier assertion saw inputs excluded by that admission; do not treat it as
an admitted-loop counterexample or move the later fact backward without checked
transport. All implementation bodies remain in this diagnostic composition.
The next boundary experiment should qualify actual reads in the existing
independent entry model, then establish frame/transport and implementation-edit
reuse. More facts inside the whole application model do not replace the public
component-network acceptance gate. See [evidence and costs](current-goal.md).

Complete-inventory checkpoint (2026-09-12): the witnessed real-loop model passes
all safety groups and relation nonvacuity. The normal partitioner returns
incomplete after 518.501s: 13 of 380 authored assertions pass, root public-memory
equality remains unresolved and 366 assertions are unexecuted. Examine that
whole-memory boundary with retained query evidence; matching-cut text frames
cannot be assumed to cover residual root outcomes. This still does not complete
the real region or the public component-network workflow below.

Memory-factoring checkpoint (2026-09-12): four checked input/span/byte-preservation
facts complete one tail-text memory assertion in 82.273s against a matched
180.211s timeout. Qualification adds about 271s; deliberate span, exact-byte and
source-memory corruptions are detected. All bodies remain and the transformation
is diagnostic, not a production summary rule or completed component. This is a
useful local decomposition result, with complete region assurance and the small
real network's public edit/refine/repair/neighbor-reuse acceptance gate still open.
Do not scale component counts or infer interactive edit latency from this query.
See [current evidence](current-goal.md).

Real composition and public bug detection checkpoint (2026-09-12): the retained
loop now has independently checked byte-read result/fault/frame observations.
Their diagnostic composition with decoder facts completes one root assertion;
normal cut alignment and state transport still require checking. All bodies stay
present, and no production summary rule or new runtime trust is introduced.

The public workflow now reaches and detects a deliberately inverted C branch
using V15 cut-first scheduling and a 180-second query budget. Its unchanged-model
60-second run still times out. The budget retry reuses all 161 entry queries;
this does not establish neighboring business-component proof reuse. Preserve the
real network acceptance gate below. The exact source repair
reuses all 161 entry queries but still times out on alignment at 180 seconds;
its public command takes 385.190s. The diagnostic composition now passes both normal
cut alignments in 41.051s, but the other 104 outgoing-state assertions time out
at 180.268s. Consuming sixteen more already qualified frame facts
does not complete the same batch. Existing smaller-group ordering passes the
first caption memory assertion, then times out on four other memory assertions
together. All four pass individually under the same model and budget; successful
checking of those five properties totals 397.969s, excluding failed attempts and
qualification. The recursive continuation returned with nine original state
assertions satisfied, one unresolved and 94 unexecuted. The new witnessed model
above resolves the selected remaining memory assertion without completing that
original inventory. Preserve this coverage distinction: a combined-query
timeout did not establish an individual boundary limitation, and these five
successes do not complete the region or demonstrate an interactive edit cycle. Do not generalize a
single passing root assertion into a component-performance claim. See
[current evidence and limitations](current-goal.md).

Real decoder boundary experiment (2026-09-12): fifteen local observations now
check repeated reference resolution results and world/origin frames in the
actual application model. A diagnostic consumer replaces those five calls with
their established results, preserving ordinary C and live view construction.
Measure its effect on the same application control obligation before building a
general production summary mechanism. A successful local result/frame check is
not complete application assurance, native applicability or a component network.
Keep the public violation/repair/refinement and neighboring-proof reuse criteria.
See [current evidence](current-goal.md).

The measurement rejects this narrow boundary as a sufficient performance fix:
the substitution removes about ten percent of symbolic steps, while both control
checks still exceed 180 seconds. Do not make production decoder-summary support
the next prerequisite. Retain the result and test a boundary that factors the
remaining shared input-memory and cut-state construction, preserving aliases,
contents, lifetime and failure outcomes. Its acceptance criterion remains a
completed real application comparison and the public local-edit workflow.

Real loop entry milestone (2026-09-12): the repaired entry now qualifies under
the four existing runtime contracts, and a public ordinary-C branch edit reuses
all 158 entry processes with zero fresh entry queries. The application model
changes, the entry model does not, and compiler correspondence is checked anew.
Command latency for this edit/check is 49.572s; application checking remains
incomplete at its selected two-second budget. This is complete entry-proof reuse,
not complete application assurance or neighboring business-component proof reuse.

The larger-budget application check reuses the qualified boundary but still
times out on control equivalence at 180s. The engine continues checking the
original application model. Next implement and measure consumption of an explicit
checked entry result/frame relation in that model, preserving memory, lifetime,
alias, reference-issuance and effect correspondence. Retain the original
performance, violation/repair/refinement and real-network acceptance criteria. No new runtime trust or native authority follows from this
milestone. See [current evidence](current-goal.md).

Real loop follow-up (2026-09-12): fault-case partitioning does not yet make the
retained control proof practical. Production now fixes the generated owner-pointer
storage identity across nested-cut extraction; the real public command passes its
unchanged compiled-prefix comparison and reaches independent entry checks. Those
checks remain incomplete under the selected two-second budgets, with no reused
entry processes or activation authority. All 38 selected Nix tests pass.

Continue on this corresponding real entry and the unresolved application faults.
Do not add more component counts or weaker entry-success assumptions as substitutes
for the measured edit/refine/reuse demonstration. The next measurement must include
completed boundary evidence and its reuse, not only compiler correspondence.
See [current evidence and limitations](current-goal.md).

Real comparison before more exit machinery (2026-09-12): the retained enclosing
cleanup operation already has a normal return boundary and twelve proof regions.
Its `loop` region supplies a matched baseline/conditional experiment while the
smaller helper's machine exit relation remains open. The selected exact region has
one basic block; it is not a separately qualified component or a scaling benchmark.

Four existing runtime contracts roughly halve symbolic steps for its control query,
but both modes exhaust 120 seconds with CaDiCaL and with the existing Z3 backend.
Auxiliary service-unreachability and nonvacuity checks improve. The public regional
command runs with the real supplied helper and reports incomplete without activation.
A newly observed generated-local identity mismatch prevents this region's independent
entry proof from being reused. These results support continuing contract factoring,
but do not establish that the current workflow is sufficiently fast or reliable.

Keep the current unresolved application formula and exact compiler inventories as
the next inputs. Do not count more cuts or codecs as the missing public edit/refine/
neighbor-reuse demonstration. Native admission and caller applicability remain
separate requirements. See [the measured comparison](performance-and-invalidation.md).

Production bridge repair connected to the real consumer (2026-09-12): the
scratch-reference output now uses an existing input plus an explicit machine exit
projection, preserving the ordinary C signature. Its current-reference encoding,
proof assertion and plan binding are implemented and pass targeted Nix validation.
The real finite consumer replay passes with production transport and fails when
that store is removed. Public normalization and semantic construction preserve the
binding, while full adapter generation retains the mixed-exit blocker.

This is a bridge milestone, not the component-network acceptance gate. The next
work must connect a checked observation boundary and actual caller premises to the
real body comparison and public edit/refine/reuse workflow. More independently
passing codecs or component counts do not substitute for that result. No new
trusted runtime contract or measured application-proof speedup is established.

Real-consumer correction (2026-09-12): do not treat mixed exit-kind support as
the only next prerequisite. Executing the actual following Metapad block exposes
an additional scratch-pointer machine output required by the copy-back caller.
A finite bridge repair through live reference realization passes that check
without changing the helper signature, while other register differences remain.
The boundary needs explicit residual machine relations derived from existing
logical parameters and results. Keep them separate from the logical component
API and replacement-group activation. The run-versus-step observation choice
also needs an explicit checked scope; bounded run-consumer tests do not widen the
current contextual proof contract. The real proof comparison and public workflow
remain open. See [measurements and findings](current-goal.md).


Bound input transport milestone (2026-09-12): the retained real byte-transform
interface now passes public logical lowering and semantic-contract construction.
Nullable remaining-origin byte inputs require current complete machine bindings;
borrowed descriptors cross cuts through the checked native codec with owner,
current-content, alias and lifetime checks. All 83 targeted/regression Nix tests
pass. The actual entry/cut harness compiles, but no complete body proof follows.
The next blocker is its mixed branch/fallthrough exits, followed by caller/frame
applicability and the actual public edit/refine/reuse comparison. Preserve the
existing outcome distinctions while resolving that boundary; do not add a trusted
contract or synthetic production API merely to admit it. See
[current evidence and next action](current-goal.md).


Paired nullable-input setup (2026-09-12): the shared initializer now has a checked
primitive for the explicit byte origin-remainder input shape. It compares the
two worlds' checked pointer reads, resolution status, full reference metadata
and current origin contents; null exposes no memory. Seven new tests and 16
related tests pass through Nix. The real three-input boundary prepares and
compiles in a private lowering probe. Public kernel admission remains closed
until parameter descriptor transport across cuts is implemented and verified.
Valid original input resolution remains a declared domain whose actual caller
applicability is unproved. This is no complete component proof or activation
receipt; see [current evidence and remaining work](current-goal.md).


Checked stack buffer coordinates (2026-09-12): allocation filled-suffix facts
now use the existing checked private-coordinate reader for a stack-held buffer
pointer as well as a stack-held suffix bound. Pointer readability is checked
before the nullable empty branch; both receipt readers require those checks.
The actual retained `ESP+12` byte-transform projection prepares and compiles with
this rule, and all 16 memory-fact Nix tests pass. This closes the coordinate
representation gap only. Nullable operation-parameter proof admission, paired
cut transport, caller-established contents and the real edit/refine/reuse
workflow remain open. See [current evidence](current-goal.md).


Nullable input decoder and real loop replay (2026-09-12): the production
adapter now imports a nullable byte-buffer parameter from an explicitly bound
origin-remainder projection. A successful null pointer-word read constructs the
canonical empty descriptor; a failed pointer-word read remains a memory fault.
Live inputs preserve actual extent and interior offset and use the existing
allocator-result accessors, which recheck reference generation and permission
at access. This does not reuse the legacy input view's cached physical address.
The initial decoder scope requires byte elements, a same-entry 32-bit pointer,
a constant requested extent and an explicit origin-remainder machine projection;
other input shapes remain unsupported.

Eight focused tests exercise actual generated native registration, release,
resolution and realization bodies, including arbitrary representable allocation
sizes/interior offsets, preserved bytes, alias writes, expiry/address reuse,
forged metadata, bounds, read-only access and backend denial. Deliberately losing
the pointer-read fault or replacing the remaining extent with one byte is
detected. The complete native adapter compiles on host and PE32. Backing memory
in these solver fixtures is bounded; they are not a whole-target theorem.

The actual 20-block Metapad byte loop also runs in a finite PE32 replay against
the unchanged ordinary helper with the new decoder. Empty text/null scratch
returns normally, nonempty text/null scratch preserves the memory-fault outcome,
and successful scratch storage yields the same result and complete buffer bytes
for `a\r\r\nb`. Denying the actual scratch-pointer slot faults both sides.
Restoring the old null-rejecting decoder is detected by the empty-input case.
The replay uses actual native admission and allocation/reference runtime bodies;
null scratch is a supplied post-length cut state, not proof of caller admission
or an observed allocation failure for that short string.

No nullable operation parameter is admitted into proof yet. Logical-kernel
lowering, initial paired-memory admission and parameter cut transport still
reject this scope. Next reuse the existing checked local service-view codec for
this input representation, including canonical null descriptors and complete
current-memory/lifetime correspondence. Do not merely remove parser guards.
Mixed branch/fallthrough exit relations, stack-based filled-suffix facts and
caller state remain required. The replay compares result, scratch bytes and
fault class; normal exit kinds and full caller state remain unresolved. Strong
receipts, activation, neighboring-proof reuse and practical speedup are not
established. Evidence: `practical-assurance/nullable-input-audit-v1.json`.

Smaller real-component integration (2026-09-12): the byte-transform proposal now
has a canonical three-input/two-view interface, an exact 20-block machine binding,
a semantic slice, source package and V6 work package. Selection follows control
edges from `0x55dd` to the cut before `0x5623`, including out-of-line loop blocks.
The text projection and allocation selectors are copied by identity from the
retained binding. No allocation-success or non-alias assumption is added.
The ordinary helper compiles against its newly generated interface; the package
retains its caller, lifetime, loop and memory-admission blockers.

This experiment exposed an unsupported normal result in `ESP+16`. The existing
result binding/adapter now supports a stack destination: explicit fault results
skip storage and continuation; a missing or denied writer produces a memory
fault; successful storage precedes the existing continuation. Focused generated
adapter checks cover arbitrary results, stack addresses, permissions and signed
displacements. This is adapter validation, not a proof of the real helper.

The smaller component still cannot reach proof construction. Kernel lowering
rejects its nullable scratch-view parameter; the generic no-extent service-result
shape must not be repurposed as a checked input extent. Native overlay generation
also rejects the two exits: a branch and a fallthrough both reach `0x5623`, but
that shared address alone does not establish equivalent outcomes. Current-memory
filled-suffix transport still requires a register-based view, while this entry
loads scratch from `ESP+12`. Preserve all three limitations explicitly. No real
component receipt, solver speedup, neighboring-proof reuse or activation follows.

Next: define and check nullable, runtime-sized buffer input transport using this
retained package as the consumer, including null/empty and failed-access cases.
Then handle its mixed exit outcomes through checked cut/continuation relations,
keeping proof regions distinct from native replacement groups. Do not assume
allocation success, substitute a fixed one-byte extent, or normalize exit kinds
merely to get the component accepted. Stack-based current-memory transport and
caller-established entry state remain required before a qualified loop proof.
Evidence: `build/independent-lifting/practical-assurance/byte-transform-boundary-audit-v1.json`.

Measured context boundary (2026-09-12): an unregistered
`native-context-spans:1` candidate has seven passing native predicate checks and
an actual Metapad IAT-section admission check. This validates local rules under
explicit premises, not actual caller/loader applicability. The real consumer
still times out with both equivalent permission encodings and with separate
null/non-null allocation cases. A literal-comparison shortcut also fails to help
and its production change was removed. No new strong or conditional component
qualification follows from these experiments.

The next concrete boundary proposal extracts the ordinary byte transform with
only text, scratch and length inputs, leaving allocation, both length calls,
copy-back, release and UI in the caller. The C helper is retained and type-compiles;
it is not a checked component. Its proposed `0x55dd` entry needs the scratch
pointer loaded from `ESP+12`, with checked backing, current contents and lifetime.
Parsing accepts that scalar-view base, but filled-suffix transport currently
requires a register base. Validate the existing work-package/transport path for
this smaller interface before counting components or claiming performance. Keep
all failure, loop-progress, neighboring-proof and native qualification exits.
See [current goal](current-goal.md) and [measurements](performance-and-invalidation.md).

Boundary derivation experiment (2026-09-12): distinguish reconstructed cut
storage from execution of the actual predecessor. The former does not prove
that earlier calls established a valid target or that earlier stack stores
succeeded. Selected checks on the actual allocating prefix now establish three
candidate outgoing facts under the modeled service premises: next argument-word
write permission, a nonzero length target, and IAT-slot read permission. Failed
and successful allocations both reach the cut in separate coverage checks.
The first-call target-validity premise itself fails for a readable zero IAT
word, so these facts are not yet a qualified summary or permission-context
transport rule. An explicit two-fact consumer hypothesis still fails because
it omits IAT-slot read permission. Keep value, permission and caller admission
separate; do not turn these diagnostic hypotheses into production assumptions.
See the latest [goal evidence](current-goal.md).

The three-fact consumer hypothesis still times out after 180 seconds. This does
not support promoting the hypotheses or claiming practical performance. Check
frame backing for future accesses and actual loader/call-target admission;
reconstructing state and remembering past access success are insufficient to
supply either contract. No new boundary schema or checked summary is introduced
by these diagnostic probes.

A negative predecessor check reaches the allocated cut but rejects write
permission for the future scratch spill at `ESP+12` (`EBP-12`) in 18.01 seconds.
Thus successful earlier stack accesses cannot establish the full frame's
permission. Prioritize binding the existing captured/physical frame and loader
context over enumerating more isolated access hypotheses.

Status: implementation authorized and in progress, 2026-09-07. The initial
[experiment baseline](baselines/2026-09-07-independent-lifting-experiment.md)
records live inspection and conditional composition probes. This plan does not
qualify any capability.

Sequencing update (2026-09-10): the operator has authorized the
[practical-assurance comparison](current-goal.md#current-implementation-priority-practical-assurance-2026-09-10)
as the next milestone. Measure rigorous application checks conditional on
explicit, independently validated runtime contracts against the retained strong
baseline before further isolated strong-proof plumbing. The hand-defined
boundaries and real-network workflow below remain the target. Their full strong
qualification is not a prerequisite to this comparison, and conditional evidence
must not enter the existing strong activation chain.

### Conditional permission composition (2026-09-12)

The real operation now has an implemented conditional native-access abstraction:
untracked accesses consult a shared stable permission function; native-registered
allocations retain span/lifetime checks, and private footprints do not grant
access. Independent small checks exercise native correspondence and omitted
premises. The public operator accepts the selection and rejects reuse of the
older permission model. These checks remain incomplete on the real component.

The consumer identified and drove a correction to the proof adapter's IAT-read
fault channel. A subsequent counterexample still permits the original argument
stack write to fault before the call while the portable side fails a null-target
premise. Establish actual frame backing and callable-target facts across the cut,
or preserve those early faults, before requalifying it. Do not add a successful
access premise solely to make the query pass. Connected summaries explicitly
reject consumption until permission-context transport exists; do not silently
reuse older body-free summaries under the new access semantics. See the
[contract and scope](portable-c-contextual-bisimulation.md) and
[audited measurements](current-goal.md).

### Native admission replay (2026-09-12)

The retained generated Metapad prefix now runs against the actual runtime
read/write predicates in a small PE32 executable, alongside unchanged portable
C stopped at its existing loop marker. Native denial produces the original
memory fault and portable empty-view rejection. A deliberately permissive null
store reproduces the disagreement. Successful allocations produce matching
prefix bytes at the loop cut. The independent allocation/reference runtime test
also exercises admission and revocation, with nine detected negative controls;
15 targeted Nix tests pass. See the [current evidence and scope](current-goal.md).

Use this to implement the missing admission/fault correspondence, not to change
the cleanup algorithm or declare its current proof qualified. Bind image
metadata, real stack bounds, live external ranges and priority-provider behavior
at the entry. Preserve null and untracked addresses as distinct cases. A private
proof footprint does not supply native stack bounds. The replay's absent
frame/exception providers are a premise, and original Windows page permissions
are not established merely by executing the generated runtime predicate.

### Real-consumer scheduling measurement (2026-09-12)

The real paired consumer now passes safety, unwinding and nonvacuity under its
existing named contracts. Five descriptor context/metadata/extent assertions
remain unresolved at 180 seconds; this still does not qualify the region or
component. The measured legacy order delays application exit observations behind
those checks. V14 conditional SAT scheduling moves exit observations ahead while
retaining every transport, frame and progress obligation and preserving legacy
receipt validation. Fifty targeted Nix tests and four repository checks pass.

The pinned public same-model comparison returned an exit-control counterexample
in 123.11 seconds, reusing 42 consumer processes and executing one. It exposes
exact-side address-zero permission versus an empty portable view fault. Establish
matching native memory-admission semantics before changing the cleanup algorithm
or attributing a failure to the prepared wrong-byte edit. The public native
permission/fault repair and refinement must retain allocation failure and lead
to neighboring business-proof reuse. The completed entry theorem must not be re-proved merely
because the consumer implementation or scheduling changes.

### Real-consumer transport diagnosis (2026-09-11)

The public baseline/edit integration is now audited: complete conditional entry
qualification in both variants, 171 entry processes reused with zero fresh entry
queries after the actual C edit. Public commands take 620.15/50.19 seconds; the
baseline consumes earlier partial evidence. Both components remain incomplete.
This closes real public entry-proof reuse, not the real network acceptance gate.
Next reuse this entry while checking consumer effects, then demonstrate the
contract violation/repair/refinement and neighboring business-proof workflow.
Evidence: `practical-assurance/entry-qualified-audit-v2.json`.

The earlier retained real entry is fully qualified under the existing conditional
runtime contracts: all 259 authored assertion sites, safety and nonvacuity pass.
The actual public counter edit reuses all 141 retained entry processes with fresh
solver execution forbidden. This is a real entry-proof reuse result, not the
complete component-network workflow. The new public `--entry-query-timeout`
option permits first qualification without enlarging ordinary component-query
deadlines; its baseline/edit integration is audited above. Keep the real
consumer effects, violation/repair/refinement, caller admission and remaining
activation obligations explicit.

Independent entry assertion/safety/nonvacuity queries and exact process reuse
are now integrated. The real public counter edit preserves the entry model and
reuses 46 safety checks plus four inventories; its paired model changes. Both
commands remain incomplete. The small fixture qualifies its entry and replays
all 51 entry queries with fresh solver execution forbidden. This advances the
reuse mechanism, but does not finish the real consumer or establish neighboring
business-component proof reuse. See the [measurement record](performance-and-invalidation.md).

The real entry still exposes 21,638 safety sites. An eight-second budget causes
costly subdivision before authored assertions run. A retained-model continuation
at 30 seconds passes every safety partition, then stops at the native-view
byte-index assertion; its buffered log does not establish the exhausted phase.
A later unchanged-model query passes that assertion, with SAT solving dominant.
The 90-second continuation passed scratch admission and nonvacuity; the later
180-second continuation discharged reference-address validity too. The current
public result above supersedes that earlier entry blocker. Carry its evidence
into real consumer checks and the edit/violation/repair and refinement workflow.
Keep unresolved obligations visible and do not expand component counts as a
substitute.

Earlier compiled-prefix checkpoint:

Restricted compiled-prefix correspondence is now integrated into the conditional
public workflow. Both real counter variants match the independent entry, including
unknown branches, failure exits, exact storage/effects and every other compiled
function. The actual public model/root convention and inventory digests are bound;
startup mismatches are not ignored. Entry model bytes and the relation digest
survive the edit. The selected public escape assertion passes, and an earlier
compiled negative that disables the probe both rejects correspondence and produces
a CBMC violation. This moves the source-entry gate beyond type preparation, but
full entry safety and coverage remain open. Bind those assertion/coverage queries
and exact-evidence reuse next; consume only qualified entry evidence in native-view
admission/access and the real component effects. Do not expand component counts
or claim public neighboring-proof reuse from this selected result.

Independent entry preparation is now integrated into the conditional public
path. The actual Metapad counter edit preserves the separately compiled entry
model and its boundary binding while changing the original paired model.
Public details retain the model and distinguish checked compiled types from
unchecked source conformance and unchecked entry obligations. All original
queries still run on the original model. No entry theorem or neighboring-proof
reuse follows from preparation. The small preparation profile rejects stateful
prefixes and unsupported types, allowing only discarded nonvolatile parameter
values before BEGIN. Three targeted Nix shards pass 29 tests without skips.
Establish input/alias/entry-exit conformance next, then add bound entry query
inventories and reuse through the existing evidence path. Keep incomplete
results available throughout; passing all entry obligations remains mandatory
before consuming a summary. See [the measured public run](performance-and-invalidation.md).

The earlier experiment and correction below motivated this integration.

A compiler-inventoried entry prototype now makes the real post-cut edit and
1,000-statement growth independent of the compiled entry model. It preserves
boundary types and the existing relation/havoc code, rejects unsupported
pre-BEGIN state, and detects type/layout/parameter-escape dependency changes.
This is a restricted generated proof source, not a new production API or public
admission rule. Its selected checks reuse through the existing exact-process
cache, but full entry checking found a construction-order failure also present
in the original model. Production cache reset now avoids observing initial
memory before declared facts are installed; 24 targeted Nix tests pass. The
corrected entry's construction-order and nonvacuity checks pass and reuse after
the edit with zero fresh queries; its complete check still times out at 120
seconds. Do not count selected reuse as a qualified entry theorem. Implement
source-entry conformance and separate entry models in the conditional public
workflow, preserving incomplete results while qualification remains open.
Only consume an entry theorem once its full gates pass, then use that boundary
to factor native-view access and discharge real consumer effects. Exact results
and limitations are in
[performance and invalidation](performance-and-invalidation.md).

The following earlier results explain why that entry boundary was needed.

The byte-frame composition candidate now demonstrates a conditional benefit:
the real text assertion passes in about 23 seconds when it consumes a separately
checked byte law and an event witness. Entry predicates pass with SAT and entry
nonvacuity passes, but both effect guards still time out with SAT and SMT. Full
entry safety and public admission remain open. The observation itself omits the
runtime reader; the full component still executes native-view/reference machinery.
The entry-only model already produces 192,522 symbolic steps and about 12 million
SAT clauses. Factor native-view admission and access contracts next, with exact
evidence binding, metadata/lifetime invalidation and body-absence measurements.
The candidate's tests cover actual write transport and lifecycle/effect controls,
including rejection after removing a required write hook; they do not establish
general confinement or qualify a native provider. Do not expand component counts
or claim a public editing/reuse workflow from this conditional result. The audit
and measurements are in [performance and invalidation](performance-and-invalidation.md).

A measured ordinary-C counter rewrite after the entry cut changes the entry GOTO
hash while its prefix, header and relation harness stay unchanged; exact repair
restores the hash. Compilation is about 0.55 seconds per variant. Thus entry-only
execution still lacks an implementation-independent evidence boundary. Factor
dependency bodies out of the entry model and preserve semantic input dependencies;
do not bypass existing hash checks or call exact restoration neighboring reuse.

The latest investigation finds an under-specified internal boundary: the
allocated cut admits overlapping text/scratch views with the same object and
generation. Freshness cannot follow from valid reconstruction alone. The
existing `bytes_address` operator now lowers for local native views while keeping
full codec obligations. A hand-defined proposal states overflow-safe separation
at all eight scratch cuts. Public checking rejects the old exact-C manifest;
regeneration from retained transfers changes its binding but not its source or
cut labels, then public feedback accurately reports incomplete proof obligations.
The source and original component inputs are unchanged; internal cut domains are
explicitly strengthened, pending predecessor establishment and preservation.
The corrected allocator-predecessor separation conjunct now passes in 95.02
seconds using the already checked output coordinate. Full predecessor proof and
the separate allocation-outcome reachability check remain unresolved. Consumer
shape/admission passes in 22.43 seconds; exact/source terminator preservation
still times out separately at 120 seconds each. A checked incoming-address
normalization does not complete the original compound assertion. A disjoint-store
byte-frame lemma passes but does not discharge the remaining consumer obligations.
Continue through this real refinement dependency, keeping
aliasing supported for other components; do not impose blanket non-aliasing or
substitute a passing metadata query for content preservation. The 21 targeted
Nix tests and static checks pass. Full measurements and exact bindings are in
[performance and invalidation](performance-and-invalidation.md).

A subsequent latest-write selector passes equivalence against the full retained
byte reader and detects an oldest-write mutation, but the real text assertion
still times out. It is not integrated. The next experiment must compose an
entry-established live-view/current-byte frame through permitted mutations and
services, with explicit invalidation and substituted-body absence, rather than
continue rearranging per-access lookups. The current four conditional contracts
and the helper lemma do not yet supply that composition rule.

The integrated selected allocation-region check now passes its safety groups
and nonvacuity, but remains incomplete after 1,123.12 seconds at required
application assertions. A separate check of the caption context identity and
all runtime fields passes in 17.99 seconds; adding reference translation is
still unresolved. Direct forwarding to the existing translator does not resolve
that assertion at 120 seconds. These results do not justify weakening the
context invariant or registering another dispatch contract.

The subsequent stage checks pass origin selection, address and span checks,
while current-world lifetime remains unresolved. Checked origin normalization
and a per-access checked image frame do not finish the real assertion at the
same budget. A separate exact-helper lemma establishes image-lifetime
specialization under image/heap separation; existing emitted-native freshness
tests validate scoped admission and deliberate guard-removal controls.

An additional, explicit but unregistered mapped-image-lifetime premise then
lets the original caption assertion pass in 102.68 seconds. This is the first
consumer benefit from this boundary, not practical component latency. Its broader
selected-region run remains incomplete after 1,099.66 seconds, with nine
application assertions unresolved despite passing safety and nonvacuity. Keep
the premise unregistered. A subsequent Z3 query passes the original full caption
assertion in 32.50 seconds without this fifth premise; measure that alternative
across the region before extending the runtime trust boundary. The retained
pinned-Z3 diagnostic now passes all safety groups, nonvacuity and 15 application
queries; text metadata and extent still time out, leaving 294 later assertions
deferred. Its 510.29-second total includes 15 reused inventory/safety queries,
so it is not a cold complete-proof speedup. A real extent error is detected in
53.49 seconds and exact repair reuses the caption query, but the public full
component/neighbor-reuse milestone remains open. The alternate SMT array encoding
also times out on both text queries. The next boundary experiment should establish
preservation of the incoming dynamic text descriptor and terminator across the
length service and disjoint scratch writes using existing frame/service rules.
Keep current resolver correspondence, alias/lifetime, arithmetic, admitted spans
and both memories' byte obligations explicit. This preservation summary is not
yet implemented; additional runtime trust requires its own validation and controls.

The first preservation experiments now establish a useful limit: a concrete
namespace footprint lemma passes, and the real address/namespace frame guards
pass, but neither pure-lookup abstraction nor checked normalization completes
the original text queries. The resolver wrapper also validates public range,
current allocation lifetime and previously issued origins. The next candidate
must cover preservation of that issued-reference validity through permitted
operations, with release/reuse, conflicting-origin and private-range controls;
retain the text's current-byte and alias obligations separately. Neither
candidate is integrated or admitted, and no public editing/reuse claim follows.
Whole invariant composition and caller confinement remain required: the
runtime's private metadata cannot simply be assumed uncorrupted by arbitrary
application code. Image unload/remap and heap-object lifetimes are outside this
shortcut and must retain their own contracts and checks.

The full-footprint issued-reference cache now passes the real metadata assertion
in 32.17 seconds, but extent still times out. Seventeen reachable bounded
resolver scenarios pass and a missing-lifetime-generation control fails. The
arbitrary-state preservation law remains unresolved with SAT and SMT, and a real
text-generation bit corruption also times out. A zero-generation corruption is
rejected in 84.74 seconds; retain both results. Exact source restoration reuses one
passing query; it is not independent neighboring-proof reuse. Keep this cache
unregistered: its original resolver remains on misses, and neither general
substitution validity nor body-growth independence is established. Separate
origin/lifetime preservation and current-byte frame rules before expanding the
network; do not add more components or cache special cases to substitute for
that missing composition. The detailed record is in
[performance and invalidation](performance-and-invalidation.md).

Keep the full original application assertions, failed outcomes and alias checks.
Any later reusable origin witness must bind owner, identity, extent, permissions
and generation, with checked creation/release/reuse and invalidation rules. A
pointer or cached successful lookup alone is insufficient. The
[performance record](performance-and-invalidation.md) contains the exact retained
evidence and limitations. No new summary rule or assurance claim is yet admitted.

### Measured runtime boundary revision (2026-09-10)

The retained Metapad comparison does not yet justify exposing the issued-reference
cache as a practical assurance mode. Its full allocation region remains
incomplete after 2,002.02 seconds, at the compound allocated-cut invariant.
The first decomposition of that invariant into equivalent checks redundantly
includes loop-unwinding checks in every query. Its memory-query timeouts cannot
isolate the cost of the invariant terms. The matched-policy rerun passes the
conditional scratch-zero check in 87.67 seconds while the original reaches
90 seconds; old-text preservation remains unresolved in both. This does not
establish a stable speedup or interactive regional latency. Preparation and
compilation remain below one second each;
the detailed results are in the [performance record](performance-and-invalidation.md).
The split experiment diagnoses the cost and does not replace regional proof.

Since matched query decomposition remains insufficient for the practical
milestone, the next experiment should put the **allocation transition and its memory frame** behind
one explicit conditional boundary, consumed by the same real region. Prefer
this boundary over further reference-cache special cases. Reuse the
existing allocation classes, views, service outcomes and current-memory rules:

1. On failure, return the modeled nullable failure result without creating an
   object or changing any existing live object's bytes, identity or lifetime.
   Check the caller's size arithmetic; the summary must not assume it correct.
2. On successful zero-initialized allocation, introduce one fresh, disjoint live
   object of the requested extent with zero current bytes. Its zero state is a
   birth fact, not an invariant after stores. Imported allocations retain their
   arbitrary current contents. Preserve all existing objects and their aliases.
3. Express subsequent reads and writes against object identity and offset. Keep
   the PE32 address/reference correspondence and service-call matching as
   explicit transport dependencies instead of repeating native namespace scans
   and unrelated history in every application read. Unsupported correspondence
   must remain visible, even in conditional mode.
4. Retain outcome reachability, observable allocation/release order, frames,
   source-versus-exact memory correspondence and the original application
   invariants. In particular, the old text's terminator must follow from its
   incoming facts and preservation; it cannot become an allocator assumption.

Test this on the retained region before another full pilot build or standalone
strong allocator theorem. Measure the complete region and a deliberate source
error, not just a convenient scalar or memory lemma. Extend the independent
native controls to distinguish fresh zero initialization from later writes,
imported storage, release and address reuse before promoting the boundary.
The existing finite Wine results are supporting observations; they do not yet
validate a new implementation of this summary or every supported platform.
If the measured consumer improves, integrate the implemented contract selection
and validation bindings into the existing public source/work-package workflow,
then demonstrate neighboring business-proof reuse. This is the next hypothesis,
not a checked summary, public capability or completed milestone.

Follow-up results: factoring byte reads, decoding the allocator's returned view,
projecting preserved input objects and even adding explicit pointwise allocator
guarantees leave the same real compound invariant incomplete at 180 seconds.
Pinned SMT also remains incomplete. The byte projection has a passing retained
equivalence check and deliberate counterexamples, and native runtime controls
cover the new semantics, but these do not establish a useful consumer workflow.
Before extending another such optimization, the next conditional consumer model
must omit the selected runtime helper implementations behind their explicit
semantic contracts. Check that changing or growing those omitted bodies leaves
the parent model unchanged, while contract or binding changes invalidate it.
Preserve the actual application's input domain and all relevant obligations.
This is a gate on the next implementation experiment, not a new proof authority
or a reason to require isolated strong helper qualification before measuring it.

The first combined body-omission result now passes the selected compound
invariant in 161.04 seconds, but the full regional check remains incomplete
after 1,979.14 seconds at exact-output read validity. Seventeen required
assertions remain unresolved in its checked prefix. The model removes
five native reference helpers and demonstrates consumer-model independence from
conversion-body growth. This is useful evidence for factoring the model, but
the allocating service and byte-history machinery still execute in it. It does
not implement steps 1–4 above. Inspection of the existing public shared-source
contract path also confirms that it accepts fixed views and scalar service
results and rejects allocation lifetime effects; it cannot yet express this
returned allocation view. Extending that path must model the new object's
identity, contents and lifetime together, retaining its existing contract and
service binding checks, rather than merely accepting the returned pointer shape.

The measured complete repair still takes 181.39 seconds: 104 completed queries
are reused, but read validity remains unresolved. The extent-edit control rejects
and its selected-query repair is quick; a later scratch-byte write is still not
detected within the query budget, even with directed observation and partially
replayed inputs. This does not justify promoting the reference-summary prototype
as the operator's practical assurance workflow. The next implementation remains
the semantic boundary in steps 1–4: allocation outcomes and current object bytes
must compose through an explicit contract, with native address transport bound
separately. Keep caller read validity, later writes, aliases, lifetime and all
remaining coverage obligations visible. Do not replace an unresolved application
assertion with an assumption or make another isolated helper theorem a
prerequisite to testing that conditional consumer.

The fresh-object array experiment reinforces this distinction: changing current
byte storage while retaining the allocator, reference transport and history
fallback is not yet the semantic boundary above. Its real allocated-cut
invariant takes 176.60 seconds, versus the retained 161.04-second result. Keep the
existing body-absent model as the comparison baseline. Do not turn a fast memory
fixture or a different backing representation into a claimed practical lifting
workflow; the next consumer must demonstrate the contract boundary and its
application obligations together.

The same later-write control expands to 1.07 million symbolic steps in the
retained baseline and 1.14 million with fresh-object storage. The next conditional
consumer must therefore include object-relative view-access transitions in the
allocator/current-memory boundary. Keep permissions, extent arithmetic, aliases,
lifetime and effect order in its contract; bind native address realization and
namespace validation as explicit transport dependencies. Check that the local
application query consumes these transitions without expanding unrelated
runtime/service implementations. This is a refinement of steps 1–4, not
permission to assume an application assertion or omit a transport obligation.

The subsequent issued-reference-access consumer completes the retained allocation
region in 26.9 minutes with two selected proofs already cached. Its exact
repaired-source recheck takes 1.19 seconds,
reusing all eligible completed queries. This is evidence for retaining explicit
contract identities and exact evidence reuse, while new proof work and
unrestricted negative edits remain too slow for an interactive workflow. A fully
cold regional run was not measured. Chosen-input checks
detect both a contract-domain violation and the real scratch-tail write; these
finite witnesses complement the full normal regional proof and do not replace
the unresolved arbitrary-input negative checks. The detailed measurements and
scope are in the [performance record](performance-and-invalidation.md).

Do not extend this result into a public general-purpose allocator contract by
accepting a returned pointer shape. The next implementation still needs the
allocation/current-memory boundary above, with separate native transport binding.
Use the completed region and the two actual source-edit controls as retained
acceptance cases. Public integration must make the chosen contract, its native
validation scope, unmet caller premises and resulting assurance visible; a
conditional result must remain unable to produce a strong receipt. Neighboring
business-proof reuse requires an unchanged checked contract across a real
implementation edit, rather than an exact restoration of the old model or growth
of an omitted proof-support body.

## Goal and relationship to the existing plan

Make an unfamiliar supported binary progressively liftable through many small,
independently manageable units. An operator can establish a boundary, write
ordinary C, check that unit against the original, and reuse the result without
re-executing neighboring implementations in its proof. Boundaries can begin as
concrete machine-state relations and evolve into typed, idiomatic interfaces.

The decisive outcome is independent work under stable contracts, rather than a
large count of component declarations or individually numbered solver queries.

This plan pivots the sequencing in
[the interactive lifting roadmap](interactive-portable-lifting-roadmap.md).
Prioritize a complete decomposition, editing, proof-reuse, and composition
workflow. Develop operator feedback and the memory/resource capabilities needed
by that workflow together. Use the pilots as integration evidence for reusable
capabilities, rather than repeatedly rebuilding them as the default development
loop. Complete the retained pilot and repository exits before declaring their
migration finished.

The [current goal](current-goal.md) remains the historical work/evidence record.
The [contextual-bisimulation contract](portable-c-contextual-bisimulation.md)
remains the implemented proof authority. A design in this document cannot
override an implemented rejection or authorize a candidate. Change producers,
readers, runtime adapters, tests, and that contract together when a capability
lands. The existing standalone-export, real-port, and unfamiliar-target goals
remain in scope after the decomposition milestones.

The current design checkpoint is
[component contracts, proof cuts and independent lifting](component-boundary-design.md).
It specifies state/transport, paired summary, frame, interaction and reuse rules
and tests their intended scope against worked examples. Complete that review
before extending the engine with further boundary fields. Its proposed rules
do not override the contextual-bisimulation contract or count as implemented
capabilities; its gates preserve the real-network milestone below.

The [broader target review](component-boundary-design-review.md) corrects the
initial design's storage, interaction and lifetime assumptions and adds a
capability/combination acceptance matrix. Its broad-target gates do not postpone
the real sequential network until all Win32 capabilities exist; they prevent
that network's restricted success from being reported as general coverage.

Its [final composition/evolution pass](component-boundary-design-review.md#7-final-pass-composition-interpretation-and-evolution)
closes the current design checkpoint with additional interpretation, coherence,
adapter and invalidation obligations. Use its stopping rule to resume the real
network rather than require every reviewed target capability before useful
implementation. The rules remain proposals until their existing authority
producers, readers, runtime lowerings and consumer checks implement them.

The next implementation priority is to validate sufficiently expressive hand-defined
boundaries using the acceptance cases below. Do not implement automatic boundary
discovery, ranking or recommendations yet. Existing manual proposal/check
commands remain useful; new recommendation heuristics are outside this stage.

The current string-boundary experiment adds a checked current-byte offset
relation, not an inferred `strlen` implementation. Its real predecessor check
derives the allocation-size premise under an explicit environment proposal.
The next retained check uses the explicitly selected string contract and the
generated typed adapter, reading the original import slot without assuming a
post-load register value at component entry. It passes for the first call;
the environment remains incomplete and full caller/lifetime composition is
still required. Neither this regional check nor a stable signature discharges
those obligations. This remains supporting work for the
real network, not completion of the edit/refine/reuse acceptance milestone.

The broader decomposition program continues beyond the first Metapad network
milestone: generalize checked boundary splitting, refinement and merging, and
repeat the public workflow on an unrelated target. Later milestones add shared
logical objects and coordinated representation changes. These remain required
for the broader plan; the completed small-network demonstration is assessed
against the four explicit requirements in its completion audit.

## Starting architecture and evidence boundary

This is based on read-only source and documentation inspection on 2026-09-07.
No fresh pilot qualification, repository validation, or timing experiment was
run to prepare this plan. Saved results require their normal identity checks.

| Existing mechanism | Role in this plan | Current limit relevant to the pivot |
|---|---|---|
| V5 component interfaces and canonical boundary schemas | Operations, values, state, effects, services, lifecycle declarations | Expressibility does not establish a general summary theorem |
| Relation IR and machine bindings | Executable projections and predicates relating original and source states | General heap abstraction and reusable invariant reasoning need checked rules |
| Unified entry/sync proof engine | Local proof regions without complete path enumeration | Public-memory equality at cuts constrains transformations across those cuts |
| Connected replay | Transitional composition for its checked scope | Still executes a provider within the consuming proof |
| Scalar summaries that omit the body | Initial example of implementation-independent caller models | Stateless, service-free scalar scope; recursive summary rules remain unavailable |
| V6 work packages and proposal/start/check workflows | Operator editing and evidence navigation | Routine contract refinement and decomposition repair remain incomplete |
| Provider qualification and strong dispatch/link receipts | Bind the selected implementation to actual executable artifacts | A local proof or conditional contract is not activation authority |
| Nix content-addressed phases | Reuse preparation and qualification artifacts | Internal proof regions are not automatically independent cache entries |

Relevant implementation areas include `components/interface_v5.py`,
`interface_package_v5.py`, `relation_ir.py`, `binding_intent.py`, `bisimulation.py`,
`bisimulation_connected.py`, `bisimulation_summary_contracts.py`,
`contextual_bisimulation.py`, and `work_package_v6.py` under
`src/spaghetti_extractor/`.

## 1. Distinguish the units of work

| Concept | Meaning | Independence promised |
|---|---|---|
| Subsystem | Navigation group such as jq values or execution | No automatic proof or deployment boundary |
| Component | Stable interface and shared logical state with one or more operations | Consumers use its checked contract |
| Operation | An externally callable or logically meaningful transition | Can be authored and checked separately when its dependencies are fixed |
| Proof region | Original/source segments between checked boundaries | Local proof obligation; need not be a production function |
| Replacement group | Implementations and adapters that must be selected compatibly | Coordinated deployment, potentially with separate operation proofs |

Independent proof, independent editing, and independent replacement are
different properties. Do not report one as another. An internal proof region
can remain in one ordinary C function. A representation change may need several
operations activated together. Extracting a C helper need not create a public
component or a new runtime dispatch boundary.

Use existing component and semantic-module packaging. Replacement-group
constraints should extend existing selection/ownership checks where possible;
introduce a new public format only if a reviewed semantic requirement needs it.

## 2. Model a unit as behavior with explicit boundaries

A unit is open to its surroundings through entries, exits, and interactions.
Its contract supplies:

1. **Entries:** admitted original and source states and their relationship.
2. **Exits:** return, branch/continuation, fault, or other supported outcomes,
   each with its own state relation and control identity.
3. **Interactions:** permitted calls, responses, callbacks, observable events,
   and any required ordering or intermediate state obligations.
4. **Frame:** readable and writable storage, preserved state, alias conditions,
   object identity/generation, and resource transitions.
5. **Dependencies:** precisely named guarantees consumed from other units and
   the environment.
6. **Progress:** the rule governing cycles, termination/divergence, and any
   unmatched internal steps between original and replacement.

These are logical requirements to express through the existing interfaces,
relations, lifecycle data, and proof plans. They are not a second executable IR.
Keep transfer-v2 as the original executable semantic body language.

For each admitted entry, prove the required correspondence for all admitted
behaviors, covering effects and outcomes as well as final values. A predecessor
must establish the successor's actual entry relation. At a branch, retain the
association between the exit identity and its state facts. At a join, cover all
admitted predecessors without inventing correlations or discarding alternatives.

Check every possible entry into an owned region, including indirect entries and
callbacks where supported. A convenient entry precondition is not justified by
one successful caller or by nonvacuity. Unknown incoming coverage remains an
explicit composition obligation.

Start with the existing matched-barrier rules. More flexible stuttering or
cross-boundary optimization requires a reviewed progress rule and negative
evidence for termination/divergence mismatches. Do not infer that rule from
passing bounded executions.

## 3. Permit progressive abstraction

Support these levels concurrently:

| Level | Typical boundary | Purpose |
|---|---|---|
| Concrete | Live registers, relevant bytes, continuation identity | Begin local lifting before domain abstractions are recovered |
| Typed | Fields, bounded buffers, references, resource handles | Remove repetitive machine details and establish reusable access rules |
| Abstract | Sequences, values, object invariants, protocol transitions | Hide implementations and permit idiomatic representation choices |

Recover only the abstractions needed for the next useful operation. A caller can
use an abstract array service while another dependency retains a concrete byte
contract. Each abstraction layer must have a checked relationship to its
underlying representation; a convenient type name or predicate is not evidence.

Do not require a full mathematical specification of every algorithm before
lifting it. Direct original/source correspondence can establish local
equivalence. Export checked facts that consumers actually need, and refine the
summary when a consumer exposes an insufficient postcondition.

Conversely, do not assume two bodies are equivalent merely because they satisfy
the same weak unary specification. Paired nondeterministic results and effects
need a justified relational rule covering the original and replacement behavior.

## 4. Make shared state compositional

Represent invariants as reusable, factored predicates with explicit dependencies
and footprints. A VM handler should consume the facts about its operand slots,
current frame, and instruction, while preserving unrelated state through a
checked frame rule. Naming one whole-VM predicate is insufficient if every
consumer expands its complete implementation in the solver.

Begin with bounded buffers and fixed records, then live allocations and shared
values. Support real aliases rather than assuming exclusive ownership globally.
Introduce checked ways to access and restore an object's invariant; record the
points at which external interactions require it to hold. A callback may observe
temporarily inconsistent state unless a contract rules that out.

At an internal cut, preserve current contents, aliases, live and retired objects,
generations, permissions, and required relationships. Reconstructing a pointer
or reapplying allocation-time initialization cannot substitute for preserving
the current heap. Omitted state is arbitrary unless irrelevance or a frame rule
has been established; it must not silently regain an earlier value.

For recursive data or mutually recursive calls, add explicit induction rules
when demanded by the selected consumer. Shared assumptions do not close their
own dependency cycle. Initially reject unsupported cycles or use a larger
checked region/group. Do not hide circularity behind existing receipt IDs.

## 5. Separate contract use from implementation qualification

There are three distinct products, using existing authority layers where possible:

- A stable contract and representation/environment convention.
- Evidence that an exact original/replacement pair supplies that contract.
- A consumer proof parameterized by precisely identified dependency contracts.

At a summarized call, prove entry requirements and the necessary readable-state
relation, apply related outcomes/effects covering all admitted possibilities,
preserve the frame, and use only checked postrelations. Inspect generated GOTO
models to establish that the callee body is absent.

A local proof may be checked under unresolved dependency assumptions. Expose it
as conditional, with the dependency edges attached. It cannot authorize provider
selection or activation until the assumptions are discharged. Unlifted code can
remain a supplier through an appropriate checked original/baseline contract;
the mere existence of its binary body does not establish that contract.

Keep the stable contract identity separate from the implementation receipt
identity. The consumer's reusable theorem may depend on the former; composition
must validate current evidence for the latter. If the current producer fuses
these dependencies, separate the stages deliberately rather than dropping a
source or receipt hash from an existing authority check.

| Change | Intended invalidation |
|---|---|
| Callee source; same proved contract and representation convention | Callee qualification, evidence composition, affected link artifacts |
| Caller source | Its affected proof obligations and dependent assembly |
| Consumed contract fact, frame, outcome, or environment assumption | All consumers that rely on the changed guarantee |
| Shared representation convention | Affected operation proofs, adapters, and replacement compatibility |
| Checker, semantic model, or runtime meaning | Every artifact depending on the changed semantics |

Same C signature is not sufficient for reuse. New optional facts can coexist
with previously checked facts; removal or change of a consumed fact invalidates
its consumers. Evidence remains bound to exact sources, slices, checker options,
and policy even when consumer theorem reuse is possible.

## 6. Make decomposition editable

The operator can split a proof region, move a cut, merge regions, extract an
operation, or group replacements. Generate proposals with the live-state and
effect costs of each choice, original/source locations, and affected consumers.

For example, two original stores separated by a cut may correspond to one final
store in idiomatic C when no admitted observer sees the intermediate state.
Move or merge the cut to check that rewrite. Do not weaken the current public
memory equality rule silently. An observable interaction between the stores
may make the rewrite invalid regardless of boundary placement.

Prefer cuts with small live state and simple relations. Include expression size,
alias uncertainty, memory model expansion, and interaction history in cost
estimates. Instruction count alone is not a sufficient estimator. Proposals
remain untrusted until the existing coverage and relation checks pass.

Persist source and intent through the current proposal/start transaction with
stale-input checks, a reviewable diff, and recovery. Internal cuts should not
force permanent production state-machine APIs or one wrapper call per region.

## 7. Provide one operator workflow

Extend the current CLI/work-package products first. A later visual client and
an optional AI proposer consume the same state and proposal APIs.

The review view should connect source, binary locations, interface, shared
invariants, ownership/effects, entry coverage, consumed facts, and proof status.
Routine work must not require authored hashes, register-codec JSON, or internal
Nix expressions. Automatically derive mechanical details and ask for genuinely
ambiguous boundary or environmental decisions.

Illustrative interaction, not promised current command syntax:

1. Select a routine and inspect a proposed typed buffer boundary.
2. Review its incoming callers and unresolved origin/alias obligations.
3. Edit ordinary C and receive local compiler feedback.
4. Check the operation; inspect a source-linked behavioral mismatch.
5. Repair the source or propose and prove a missing boundary fact.
6. Qualify the operation and inspect which existing consumer proofs are reused.
7. Select compatible implementations and run the required integration gate.

Use explicit status distinctions: proposed, structurally checked, locally
proved under assumptions, fully qualified, and selected/linked. Use existing
status vocabulary where it expresses these distinctions faithfully. A timeout,
unsupported feature, stale result, false postcondition, and behavioral mismatch
must have different explanations and next actions.

Each contract fact should show where it came from, what proves it, and which
consumers require it. An operator-accepted proposal is still not a proved fact.
Trace locations must bind to the exact checked source, not a later edit.

## 8. Preserve incremental deployment and idiomatic code

Initially preserve exposed layouts so original and lifted routines can coexist.
Introduce representation changes only when access is encapsulated or checked
adapters connect the representations. Inspect escaped pointers, direct native
field accesses, callbacks, and indirect entry coverage before claiming privacy.

If several routines share a representation, allow a replacement group whose
operations have separate proofs but whose implementations must be selected
together. Reject mixed incompatible selections. Check adapters and actual linked
objects through the existing native authority chain.

Do not make complete encapsulation a prerequisite for useful source cleanup.
Track layout-preserving lifting and abstract representation replacement as
distinct achievements. A small number of coordinated changes is compatible with
many independently managed proof and authoring tasks.

## 9. Implementation sequence and exits

Every phase includes the minimal public diagnostic workflow and cost reporting
needed to use it. Do not defer ergonomics until general proof support is finished.

### Hand-defined boundary acceptance

Author the boundary first, then implement any missing semantics needed to check
it. Do not narrow the authored contract merely to fit the current summary shape,
or manufacture production functions to fit proof cuts. Use the existing V5
interfaces, relations, bindings, lifecycle rules and bisimulation intents; this
is an acceptance corpus, not another contract format.

For each case record these stages independently:

1. **Represented:** canonical artifacts express the required facts, including
   aliases, frame, outcomes and progress, rather than just parameter types.
2. **Transported:** entry, interaction and exit adapters preserve those facts
   and current storage. Reconstructing a pointer is insufficient.
3. **Locally checked:** the implementation establishes the promised facts for
   all admitted states and outcomes, with exact retained evidence.
4. **Composed:** consumers use the checked facts with dependency bodies absent;
   checked entry conditions establish the actual callee premises.
5. **Editable:** public commands show the facts consumed, reuse neighboring
   proofs after a compatible implementation edit, and invalidate consumers of
   a changed fact. A stable C signature does not establish compatibility.

Mark an unsupported stage explicitly. A generated header, successful compiler
check, declaration of an effect, or a passing concrete execution does not advance
a case to a later stage. Neither this table nor its tests authorize activation.

| Hand-defined case | Required boundary behavior | Existing starting evidence and missing exit |
|---|---|---|
| B1: fixed readable views | Same admitted bytes, overlapping ranges and descriptor aliases; bounds and read permission; preserved memory | `test_bisimulation_readonly_summary.py` checks body-free conditional composition and negative cases. Retain those checks as the narrow foundation. |
| B2: looping mutable buffer | Current writes visible through aliases, checked frame, result/outcomes and progress; two consumers | `test_bisimulation_mutable_model.py`, `test_bisimulation_mutable_summary.py` and the retained transitive-machine experiment support the fixed image-memory scope. Integrate the real cleanup loop and actual caller premises. |
| B3: shared state and returned view | Return aliases existing shared storage; repeated operations expose current bytes through previously returned views; preserve live object identity and frame | The actual Metapad resource helper passes public provider qualification, now including a checked image/private access frame. The framed shared strategy has producer and reader rules; selected actual cleanup-CALL checks pass with released scratch history retained. Conditional two-consumer tests preserve live contents and dead identities. Full caller qualification, cleanup-loop coverage and public composition remain open. |
| B4: internal cuts and multiple exits | Branch identity remains paired with its facts; all incoming paths covered; live state transported; loops retain progress; cuts can move/merge inside ordinary C | `test_bisimulation_cutpoints.py` checks public-memory and call correspondence at cuts. Real predecessor evidence corrects the actual frame. Public split/merge with coverage, progress and neighboring reuse remains an exit. |
| B5: service interaction | Ordered calls, current shared writes, failure outcomes and caller obligations across the interaction | The actual helper's LoadStringA site now selects a reviewed positive-buffer profile; domain checks precede oracle effects and native invocation. The two-call check remains conditional on fixture image authority. Composed helper/cleanup summaries and real caller admission remain open. Do not assume a terminated result from the helper, which ignores the service result. |
| B6: shared object lifetime | Aliases, ownership, generations, allocation failure, release and stale-reference rejection | The actual cleanup allocator/release sites now pass production binding and a conditional paired regional check, including nullable results, zeroed contents and both release outcomes. The non-wrapping size premise and intervening loop transport remain owed by the full caller. Factored shared invariants and composition through real consumers remain required; pointer reconstruction cannot supply contents or lifetime. |
| B7: representation and contract changes | Compatible representation change or explicit replacement group; selected fact refinement invalidates exactly affected consumers | The transitive experiment demonstrates an implementation edit under an unchanged contract. It does not yet demonstrate semantic contract compatibility, real shared-object representation changes or the public refinement workflow. |

These rows are required examples, not a claim to model every Win32 boundary.

The cleanup outcome case now has explicit scalar-result transport in the
existing machine binding: designated u32 error values can map to memory or
external faults. Generated machine and logical adapters preserve the mapping;
the conditional original/C empty and nonempty cleanup witnesses pass, and
erasing the mapping fails correspondence. This advances represented/transported
failure behavior without establishing production heap admission, the complete
cleanup proof or either actual caller. See
[the implemented scope](portable-c-contextual-bisimulation.md#explicit-scalar-failure-outcomes).

The immediate hand-defined acceptance sequence is:

Finite internal copy loops now have an explicit operation-level
`source_unwind_limit` in the existing bisimulation intent. The paired engine
checks progress at that limit; it does not assume termination or introduce a
production helper. This removes the scanner restriction for the full cleanup's
two bounded copy loops while retaining the main inductive cut. Full cleanup
execution and predecessor/successor relations still need their own evidence.
See [the proof-shape rule](portable-c-contextual-bisimulation.md#proof-shape).

Current-content predicates on canonical local views now use the existing
`byte_read` expression with checked bounds and input/successor memory selection.
The cleanup proposal uses this to state counter correspondence and terminators
at the scratch allocation's final byte, with a distinct null-allocation branch.
This is an authored content boundary, not a selected `lstrcpyA` contract. The
actual loop's selected invariant/access queries pass under the retained live
allocation and image-input premises; full local proof and predecessor/caller
establishment remain required before consumers may use those facts.

The full cleanup now also has a hand-authored cut immediately after allocation
at original RVA `0x55d7`, before the second length call. It retains the same
ordinary C function and adds only a proof marker. The proposed boundary carries
nullable scratch identity, extent, lifetime and current final-byte facts,
parameter views, the actual frame relation and initialized counters. Its plan
has entry, allocation and loop obligations across the same 35 original units;
the public source compilation/profile check passes. This is structural/source
acceptance, not a completed split proof. In particular, the resumed region
consumes a machine fact not yet represented by this proposal: `EBX` equals the
current `lstrlenA` import slot. Establish and transport that relation rather
than assuming a register value or adding a synthetic C parameter. The original
source `length` local is dead at this cut and does not need transport.

The constructor transport check also rejects the current string-view proposal:
a terminated span inside an object is not a promise that the object's final
byte is zero. The original string model consumes the former; the generated
source adapter demands the latter when its view spans the remaining capacity.
The proof adapter now accepts the existing registered terminated prefix after
realizing the borrowed reference: the prefix must fit the visible view and end
in a current zero, and the final read uses the actual runtime. Storage identity,
capacity and lifetime remain attached to the original reference. Regression
checks reject a lost registration, a truncated view, a changed terminator and
an unavailable reader. Both receipt readers bind this shared implementation.
The actual constructor
passes its five string-admission/scratch-descriptor assertions plus unwinding.
The complete cut query instead rejects allocation history when ESP movement
shifts the private-memory window across live allocation bytes. Preserve a
consistent private/public scope across predecessor and successor proofs before
calling this a usable split. Preserve its earlier
counterexample and do not add an unused-capacity zero premise.

For the cleanup loop, include an explicit local-allocation cut case: allocate,
write, cross an internal cut, then read through an alias and release. Preserve
current bytes and the complete live reference across the cut; neither replaying
zero initialization nor capturing only an address is acceptable. Exercise
changed bytes, stale generations, lost aliases and allocation failure as
negative or distinct-outcome cases. The current parameter-view capture support
does not establish transport of a service-returned local view. Keep this inside
ordinary C, and require predecessor establishment of every resumed premise.
This is a B4/B6 prerequisite consumed by the real cleanup, not a new public API
or a reason to delay the complete network workflow for unrelated diagnostics.

The current constructor/regional checkpoint supports that next step without
admitting production cuts yet. Imported allocations retain current input bytes
and lifetime metadata; the real nine-transfer cleanup loop region passes a
conditional one-region check and all three control-path witnesses, with the
allocating/string prefix absent. Incorrect birth-time zeroing is rejected.
This does not establish the complete incoming logical-origin state, the local
view's predecessor relation or inductive successor premises. Wire those facts
through canonical cuts before removing the empty-allocation admission guard;
do not substitute more isolated constructor probes for this integration.

1. Use the qualified resource-text helper as the supplier and the real cleanup
   operation as its first consumer. Retain its fixed shared buffer, module cell,
   returned alias and selected service contract. Do not invent a NUL guarantee.
2. Establish the consumer's actual call-entry premises, then admit the checked
   shared summary through the producer and both contextual readers together.
   Inspect the generated consumer model for absence of both helper bodies;
   reject stale source/service evidence and incorrect memory or alias transport.
3. Carry the same boundary through the cleanup loop and both actual callers.
   Check coverage, progress and outcomes as well as successful return values.
   The cleanup's scratch allocation makes the original empty-allocation-world
   summary premise insufficient, even after a successful release: the world
   retains allocation history. The checked leaf extension now supplies a frame across the
   image-only helper call, preserving unrelated allocation identities, contents,
   generations, liveness and history. Carry it through the real allocation and
   release predecessor, including failure outcomes; the conditional CALL fixture
   does not establish those service semantics. Reject overlap or stale-reference cases.
   The actual allocator/release regions now pass their conditional paired check,
   but their combined helper consumer exposes differing private stack windows.
   The authored supplier access footprint, including reads, now passes public
   helper qualification v6. The actual lifetime/helper consumer's entry-only
   assertion now passes. Its grouped check times out, and the full partitioned
   check remains incomplete at the pointer-safety query; complete caller
   qualification is still open.
   Private-write evidence alone does not
   justify narrowing the required frame or strengthening allocator assumptions.
   Do not erase that state at the call or replace the empty-world guard without
   a checked extension of the supplier theorem.
4. Exercise a local implementation edit, consumed-fact refinement and internal
   cut movement through public commands, recording which neighboring proofs
   are reused or invalidated. Proceed to the lifetime and representation cases
   required by those consumers.

Public helper qualification is now demonstrated by the retained
`service-buffer/public-qualified-helper-v3/` and `public-qualified-helper-v4/`
products under `build/independent-lifting/real-network/`. Attaching the checked
shared source certificate reuses all 100 machine queries with identical machine
models. This is evidence-attachment reuse, not an implementation edit or
neighboring-proof reuse. The checkpoint and remaining obligations are recorded
in [the current goal](current-goal.md). The chronological experiments below
include earlier blockers; they do not supersede this current acceptance status.

For B3/B5, the paired oracle now applies fixed or argument-scaled byte footprints
over checked public image objects. Its range events preserve aliases and ordering
without enumerating buffer bytes. Eleven small tests cover correspondence, frames,
permissions, bounds, lifetime and rejected invented guarantees. A retained
conditional run compares the real resource helper's four transfers with its
ordinary C candidate across two calls, including a changed module and an old
returned alias. The current run uses the canonically selected service contract
and passes all 6,124 properties under Nix; the complete helper overlay compiles
for host and PE32. Authoritative image admission, local qualification and composed
state/service summaries are still required. Selecting a reviewed footprint does
not prove LoadStringA's implementation or discharge the helper's caller premises.

The paired helper experiment now derives its shared object from the real PE
section authority. Component semantic admission no longer rejects unrelated
explicitly unresolved imports: requested missing contracts, duplicates and partial
rows still fail closed, and the full environment identity remains bound. The real
helper's semantic contract now passes admission. The `paired-scoped/` driver
omitted the standard checked typed-service proof overlay and timed out while
checking the native adapter directly. With the standard overlay, `paired-typed/`
passes the return comparison; its remaining public-memory query passes separately
on the exact retained GOTO. The follow-up with a 300s query limit passes both
comparisons, but its typed buffer-argument correspondence assertion times out.
That receipt remains incomplete; 63 of 64 recorded steps pass. A subsequent
retry uses exact completed query outputs from that validated incomplete receipt,
reuses 62 queries, and checks the 21 previously unfinished queries. The argument
check passes in 384.725s and the complete local contextual result is satisfied.
No memory-factoring or focus optimization was retained. The compiled model stays
unchanged. This clears the local helper proof blocker, while public provider
qualification and composed B3/B5 summaries remain open. Current evidence is under
`real-network/service-buffer/paired-resumed/`.

After B1/B2, prioritize B3 together with its B5 interaction, reconnect it to the
cleanup operation and both real callers, and then exercise B4/B6/B7. The next
summary rule must consume an explicitly authored result-to-state relation,
preserve the current module and buffer memory correspondence, and compose the
ordered service interaction and its frame. Prove these facts locally before a
consumer may omit the helper body. Repeated calls must keep old returned views
attached to current storage. Keep the existing rejection of state/service summary
shapes until those producer, reader and consumer rules are implemented together;
removing the shape guard or adding an unchecked relation declaration is not this
exit. Keep small
hand-defined negative cases beside each capability. For example, a stale shared
buffer snapshot, silently disjoint aliases, an unframed service write, a dropped
exit, a freed generation, or an invented NUL guarantee must be rejected at the
stage responsible for it. Do not simulate success by weakening a contract.

The helper's next transport check now replays service range events with their
call identities and chronological stores, including the extra service-event
budget. Five hand-defined checks and a pinned two-invocation real-helper replay
pass. This clears an effect-transport defect; the original-side helper body
remains in that experiment. It does not satisfy the body-free B3/B5 composition
exit or change the provider-summary rejection.

The following conditional renderer now omits both supplier bodies while using
the real helper's checked source/service and entry/frame premises. It preserves
current aliases through arbitrary framed post-bytes before interactions and at
return, and returns each caller's own checked buffer view. Internal store-count
budgets do not enter the generated wrapper. The actual full-image model passes
6,182 properties; its GOTO inventory confirms body absence. This advances the
hand-defined boundary experiment, but actual machine caller admission and public
provider composition still reject the experimental strategy. Integrate that
rule into the real cleanup/caller workflow next; conditional logical consumers
do not complete B3/B5 or the edit/refine/reuse milestone.

The actual helper's exact proof-bound source now also passes the separate
shared-state/service GOTO opacity rule. This admits declared logical views and
own-context service dispatch while rejecting private transport observations.
The actual helper now also passes the B3/B5 local input-dependence and frame
proofs under a fixed-view service response/footprint model. Its chronological
sparse events preserve arbitrary initial bytes and aliases without enumerating
buffer length; an arbitrary-byte probe checks memory before calls and on return.
The public source-check product presents this conditional local theorem. The selected service argument domain and footprint now pass local admission,
and the retained source theorem is bound to the exact paired supplier and its
regenerated selected-service overlay. The subsequent complete helper rerun and
pinned binding check establish its supplementary wider entry, private frame and
declared machine clobbers. This closes the local machine-frame prerequisite;
actual caller admission, provider-qualified summary substitution and real network consumption
remain open. Existing provider-summary admission
explicitly rejects the new local policy until those rules are implemented.

Supplementary machine-frame generation now supports this hand-defined helper's
fixed shared-image grants and direct returned-view register base. Small checks
reject a service range wider than its component grant and state bindings moved
across cuts. The actual helper's raw cut/anchor probes pass, while write and
revised exit-frame queries exhaust 180s budgets. No caller-entry receipt or
shared-state summary follows from these exploratory results. Use this measured
gap to guide the next real-consumer prerequisite; boundary recommendations remain
deferred.

The first persisted real helper case is
[`tests/fixtures/hand-defined-boundaries/resource-text`](../tests/fixtures/hand-defined-boundaries/resource-text/README.md).
Its source execution checks only authoring and shared-view behavior under a
fixture environment. The machine binding and real service remain explicit open
obligations. Retained exact target inputs are used for subsequent integration;
ordinary corpus changes do not require a pilot rebuild.

Exit for this stage: hand-defined cases demonstrate the boundary semantics
needed by the real network across the five stages above, with decisive negative
tests. Keep the full pilot/native-link/repository/export/portability exits.
Only after this acceptance work should automated recommendations propose
instances of the same checked boundaries; they must not add proof authority.

### Phase 0: Define and freeze the decomposition experiment

Inventory current implemented capabilities and exact input identities. Select a
real target operation with a loop, mutable shared memory, and at least two
caller contexts. Use existing buffer/lifetime fixtures to isolate mechanisms,
but require a real consumer and a second unrelated target for the main exit.

Record current proof-region, component, and replacement boundaries separately.
Retain canonical extraction inputs and a pinned trial SDK for the experiment.
Measure preparation, source compilation, model generation, solver, and linking
separately. Create a small support matrix distinguishing represented, checked,
composed without body execution, and demonstrated on a real consumer.

Exit: reviewable contract/decomposition proposal, named blockers, measured
baseline, and exact acceptance cases. No full pilot rebuild is needed merely to
write this inventory; rebuild when current integrated evidence is required.

### Phase 1: Prove memory summaries without callee expansion

Generalize scalar summaries to bounded read-only memory, then a bounded mutable
buffer operation. Implement input-memory correspondence, frame enforcement,
post-memory relations, and explicit alias handling. Bind summary proofs and
consumer use through both authority readers.

Exercise a real caller appropriate to the admitted capability. A service-calling
Hello helper cannot be treated as service-free because its logical purpose is a
memory comparison; retain its interaction obligations or choose another slice.

Exit: both bodies absent from parent proof models, complete local qualification,
parent model size independent of child body growth, and rejection of mismatched
readable bytes, undeclared writes, wrong results, and unmet preconditions.

### Phase 2: Close state across cuts and support local editing

Add the allocation/current-memory and invariant fragments needed by the selected
experiment. Implement checked split/merge proposals over the existing barriers.
Make contract facts and their consumers visible through public diagnostics.

Separate stable consumer contracts from selected implementation evidence. Keep
the existing Nix cache initially; introduce operation/region artifact boundaries
only where measured edit invalidation requires them. Preserve semantic closure
tracking and avoid a second proof cache or state database.

Exit: edit one implementation, requalify it, reuse neighboring proofs, refine
one fact with accurate invalidation, and merge cuts to admit a valid rewrite.
Public diagnostics reject stale proposals and explain false facts, undefined C,
unsupported semantics, and resource exhaustion distinctly.

### Phase 3: Demonstrate shared objects and many local operations

Factor the jq value/ownership predicates required by a selected container
operation and caller. Progress from concrete representation to typed and logical
contracts only where checked. Add retain/release, shared aliases, and failure
outcomes according to the actual routines. Avoid expanding one global heap/VM
invariant into every consumer.

Use controlled families with increasing unit counts and fixed local contracts
to measure per-unit model size, dependency checks, and edit cost. These scaling
fixtures supplement real target evidence; they do not prove whole-jq coverage.

Exit: multiple independently checked operations sharing state; at least one
caller uses the summaries without value-storage bodies; observed model size and
edit invalidation remain local as unrelated units are added.

### Phase 4: Check interactions and replacement compatibility

Add the stateful service summaries needed by jq output and DX-Ball initialization,
including actual success/failure outcomes and ordered observations. Add a checked
reentrancy rule only when required; do not model a callback-capable call as atomic
without evidence. Unsupported interaction families remain explicit.

Demonstrate one representation change across a compatible replacement group.
Prove its operations independently and check selection/adapters as a group.

Exit: reject incompatible mixed layouts, hidden native accesses, missing failure
or callback paths, and stale linked implementations. Demonstrate the changed
representation through the applicable candidate gate.

### Phase 5: Repeat on an unfamiliar target and close retained milestones

Repeat the decomposition workflow on an unrelated target with the same public
tools and reusable contracts. Record every target-specific engine change and
eliminate routine dependencies on such changes. Have another operator reproduce
the workflow from the recorded artifacts and instructions.

Requalify the full declared Hello, jq output-value-pipeline, and DX-Ball
directdraw-init pilots under the final applicable policy. Complete metadata,
native link/activation, absence/migration, and repository gates. A scoped jq
pilot does not establish whole-jq completion.

Continue the existing roadmap's standalone export and qualified alternate
platform backend demonstration. Broader Win32 families extend the capability
matrix based on actual blockers; they are not prerequisites for every local unit.

Exit: repeatable independent lifting plus the retained migration exits, with
remaining whole-application and portability limitations stated explicitly.

## 10. Acceptance experiments

| Experiment | Required observation |
|---|---|
| Larger child, same contract | Parent omits child bodies and its model does not grow with them |
| More unrelated components | Existing unit's model stays unchanged; report graph/assembly overhead separately |
| Local implementation edit | Only necessary qualification and composition/link artifacts rebuild |
| Contract refinement | Exact fact consumers are identified; stale or false facts are rejected |
| Split and merge | All exits remain covered; a valid cross-cut rewrite becomes checkable after a merge |
| Shared aliases | Real overlap is modeled; equal pointer metadata with different readable bytes rejects |
| Lifetime across a cut | Current writes, live identity, generation, permissions, and bounds survive correctly |
| Cyclic assumptions | Unjustified cycles reject; any admitted cycle carries its checked induction rule |
| Progress mismatch | Unsupported or invalid divergence/termination correspondence cannot qualify |
| Representation group | Compatible group qualifies; incompatible mixed selection rejects |
| Partial lifting | Local work progresses with unresolved contracts visibly conditional; activation stays gated |
| Unfamiliar target | Same mechanisms and public workflow work without routine target-specific engine patches |

Use actual solver fixtures and integrated consumers for semantic assertions,
not only generated-string tests. Check source definedness, exhausted bounds,
entry coverage, frame violations, outcome omissions, and both receipt readers.
Do not claim linear solver complexity merely because the proof graph is linear.

## 11. Performance and development policy

Reuse the [performance and invalidation policy](performance-and-invalidation.md).
The warm engineering budgets from the existing roadmap remain targets:

| Interaction | Target |
|---|---|
| Read indexed status | 1 second |
| Reuse unchanged qualification | 5 seconds |
| Small source edit feedback | 5 seconds |
| Representative small proof | 30 seconds |
| Larger partitioned interactive proof | 120 seconds per region |

These are not current performance claims or semantic bounds. Record hardware,
tools, concurrency, memory, cache state, sample count, median, and tail latency.
Measure full edited-operation latency as well as individual query times. A
thousand cheap-looking queries may still make one edit unusable.

Also record operator minutes, manually supplied facts, generic toolkit changes,
callee-body presence, model size, and actual derivations realized per edit.
Keep compilation, proof, assembly, and cold preparation costs distinguishable.

During development, use retained canonical inputs and focused checks; run
affected validation for coherent batches and full pilot/provider builds at
specific integration checkpoints. Limit solver concurrency at the workload
level. A timeout is not permission to restart a duplicate run or weaken scope.

If proof cost follows callee size, fix summary replacement. If it follows global
state size, inspect invariant expansion and framing. If edit cost follows the
whole target, inspect artifact dependencies. Increase budgets only with an
explicit measurement-based reason and unchanged semantic claims.

## 12. Implementation responsibilities and guardrails

| Area | Primary responsibility |
|---|---|
| `components/` interface, relation, lifecycle, and summary modules | Contract meaning, local proof rules, framing, and summary replacement |
| `components/bisimulation*`, exact slices, transfer Behavioral-C lowering | Region coverage, source alignment, state transport, and progress checks |
| `semantic_providers/` and Nix provider constructors | Stable contract dependencies, exact evidence binding, and measured reuse |
| `commands/`, `operator/`, work packages and proposals | Public split/merge/refine/edit workflow and source-level diagnostics |
| `native_realization/`, selection, module/link constructors | Compatible replacement groups and exact executable authority |
| Target bundles and tests | Declarative examples, real consumers, repeatability, and negative evidence |

Preserve unrelated dirty-tree work. Target bundles contain intent, data, and
source; reusable proof algorithms belong in generic toolkit code. Keep generated
Behavioral-C immutable and retain one semantic authority chain. Change formats
only for necessary meaning changes, update all consumers, and reject old
incompatible receipts.

Tests and operator proposals remain non-authorizing. Keep original execution and
candidate execution within the repository's applicable policies. Unknown callers,
timeouts, unsupported semantics, and unproved assumptions remain visible rather
than shrinking the admitted behavior to make a component appear independent.

## Technical references

- [Abstraction Logic](https://arxiv.org/abs/2109.02991): combines contextual
  refinement with local assumptions and ownership reasoning. A reference for
  the composition rule, not a requirement to introduce another prover.
- [Certified Abstraction Layers](https://flint.cs.yale.edu/certikos/publications/dscal.html):
  implementation independence across checked abstraction boundaries in C and
  assembly.
- [CompCert simulations](https://github.com/AbsInt/CompCert/blob/master/common/Smallstep.v):
  examples of explicit progress conditions for unmatched internal steps.
- [CBMC contract replacement](https://diffblue.github.io/cbmc/contracts-requires-ensures.html)
  and [frames](https://diffblue.github.io/cbmc/contracts-assigns.html): mechanisms
  to evaluate against the pinned checker; they do not themselves prove the
  project's paired binary/source composition rule.
