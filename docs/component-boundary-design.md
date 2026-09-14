# Design: component contracts, proof cuts and independent lifting

The [Metapad milestone audit](baselines/2026-09-14-independent-component-milestone.md)
records the completed small-network conditional proof/edit/refine/reuse demonstration.
It separates trusted runtime contracts and finite validation from strong authority,
and records current model dependencies, costs and remaining generalization work.

The v120 consumer experiment connects the checked resource implementation to
actual mapped image storage and actual notice services. Exact source/header binding
matters: the older generic resource fixture was not byte-identical to the public
proof input and has been replaced in this network by the retained normal and
loop-edit implementations. Production image origin resolution now checks the
resource's section identity, extent, coordinates and live mapping alongside dynamic
allocation origins. The explicit translation between retained and mapped addresses
is fixture-owned and is not evidence of a general relocation adapter. Removing
image admission after unmapping rejects a saved reference; same-base reload
identity remains outside this evidence. See `current-goal.md` for validation.

The v119 runtime consumer network uses the existing generated logical cleanup
adapter across ordinary-C component boundaries and its machine adapter from the
retained original callers. It validates actual reference origins and current view
contents independently of the canonical proof representation. A wrong caption
section is rejected at admission, even though scalar address/signature shape alone
would not establish its origin. Interior text aliases remain live across cleanup;
released scratch and owner-released input references expire.

The EDIT callback mutates the image's edit-window word during SetFocus. The caller
must read that word after cleanup; moving its read earlier rejects in actual runtime
execution as well as in the local proof. UI contents survive mutation and release
of the borrowed input, checking copying at this service boundary in the tested cases.
These are concrete finite checks under fixture-owned image/stack admission and a
controlled EDIT subclass. They do not establish arbitrary caller reachability,
callback safety, notice delivery or native activation. The proof/implementation
boundaries remain unchanged. See [current evidence](current-goal.md).

The v118 experiment separates three identities: the supplier's proved domain,
its exported contract, and the contract facts consumed by a particular caller.
A checked `normal-frame-subset-v1` export may remove equalities from a proved
normal-return conjunction. Evidence binds the source and exported contract hashes;
none of the memory, lifetime, outcome, progress or environment premises may change
through this rule. Export changes alone leave the stronger proof queries reusable.

Consumers explicitly require a subset of those normal-frame facts. Their models
leave all other native registers arbitrary, so a passing original/C query proves
that the declared subset suffices. Provided/consumed identities and exact supplier
evidence remain distinct. Withdrawal of EDI preservation is compatible with the
actual save operation, which overwrites EDI after cleanup, and incompatible with
UI argument setup, which uses it. Public checks reuse save and identify UI's exact
missing equality. A deliberate underdeclaration fails the actual UI proof.

This checked conjunction rule replaces whole-contract equality only for that
supported dimension. All other terms remain exactly bound; changed signatures,
new predicates or caller assumptions do not establish compatibility. The public
experiment does not qualify concrete caller/adapter/runtime assumptions or grant
activation authority. See [current evidence](current-goal.md).

The v117 UI consumer demonstrates why an authoring boundary must include
relevant branch contexts. The five-unit 0xb18e operation owns both cleanup bypass
guards and the subsequent UI call; selecting only cleanup and argument setup
would leave bypass entries inside the region. Its ordinary C expresses mode
selection, cleanup and message delivery without synthetic stack APIs. Native
argument pushes remain checked continuation obligations. A fault tag separate
from the uint32 value admits every UI return value, including UINT32_MAX.

The caller loads the window handle from current memory after cleanup. The paired
contract preserves correspondence at this interaction, but exports no guaranteed
NUL-terminated post-text. Such service applicability cannot be inferred from equal
references or equal bytes. It requires a checked stronger guarantee or a separately
justified runtime premise. Both actual consumer profiles now support public
edit/error/repair/compatible-neighbor reuse; general contract refinement and
concrete caller/runtime qualification remain open. See [current evidence](current-goal.md).

The v116 hand-defined save operation exercises an authoring-component boundary
around actual work: cleanup plus adjustment of the current text length. Its
ordinary C calls a checked dependency contract and contains no machine-stack
protocol. Two native outgoing argument pushes are separate continuation transport
obligations. The paired proof preserves all uint32 length inputs and memory-fault
exits, checks input-memory/view correspondence before summary substitution, and
rejects hidden pre-call or extra normal-return writes. Compatible resource edits
reuse the save proof transitively through cleanup. This supported operation
profile does not yet establish the second caller, concrete entry/runtime
applicability or general contract-refinement support. See [current evidence](current-goal.md).

Service-prefix composition (2026-09-14, v115): observation contracts must cover
memory at interactions, not merely equal final bytes. The real cleanup entry
establishes a stronger sufficient premise: zero public write events before every
service invocation. Its exact reader and common incoming-world binding then give
corresponding call-time contents. The tail uses checked call-time byte records;
the loop proves no service invocation. Ordered prefix concatenation preserves
observations when entry, loop or tail faults. Helper rules and all-outcome count/
memory guarantees are bound to validated regional evidence; declared effects or
matching labels alone are insufficient. Hidden recorder effects, changed readers
and narrowed fault scopes reject. Exact setup bindings also prevent changing
source/native recorder sides, counters or the arbitrary probe before invocation.

This is the registered cleanup model's conditional observation profile, not an
arbitrary service-contract interpreter. Allocation's already-zero scratch model,
service return assumptions and pointer/view transport remain explicit premises.
The result does not qualify concrete heap lifetime, nonreturning services or
native fault-register observations, and does not authorize activation.

Scoped control composition (2026-09-14, v114): a postcondition's guard is part
of its contract. The composition reader parses the registered regional proof
suffixes and retains each assertion's nested conditions. Normal return-frame
facts cannot be used at fault exits, and loop progress applies only to back-edges.
Extra post-call assumptions, mutations and unsupported control reject. Matching
assertion descriptions alone would not establish any of these implications.

The same complete source graph is collapsed into the three proved segments.
Internal proof cuts remain internal; only entry-to-loop, loop-to-loop and
loop-to-tail continuations are admitted. Missing/overlapping ownership and an
incoming edge to a successor interior reject. Segment-local termination comes
from the retained complete queries, including their unwinding assertions. A
64-bit ranking over entry, loop, tail and terminal phases decreases even across
arbitrarily many loop iterations, conditional on the dependency invocations
returning. This does not bound how long a UI interaction may wait or qualify
blocking/diverging services.

Saved native words are related through the previously checked private-byte
transport. Entry and tail coordinates must agree, and every loop-writable cell
must be disjoint from those saved words. The checked stack algebra recovers the
original caller's stack plus four, and the cursor domain excludes the fault
sentinel from normal removed counts. This closes conditional control/ranking and
normal return-frame algebra; full current-state/effect-trace composition and
actual caller/adapter/service compatibility remain separate obligations.

Production representation substitution (2026-09-14, v113): the public product
checks the actual returned-view helper code against the canonical regional
accessors. Different namespace identities, context layouts and null descriptors
are related through their admitted accesses, not equated as raw structures. The
conditional reference-realization model requires live issued origins and exact
metadata, and remains distinct from qualification of the actual native issuer.
Complete access arguments and at-most-one-hook checks support the effect relation.

The source-use checker consumes the same complete compiler graph as the regional
proofs. It permits opaque local copies and admitted service uses, rejects scalar
observations of descriptor fields, and checks every read-fault suffix has a finite
silent constant return independent of the output value. Widths must be constant
one, two or four. These are checked premises of this representation profile;
unsupported edits require another relation. Passing this structural check alone
does not prove changed scalar behavior correct. All service results, lifetime
transitions, retained contexts and callback effects still need their separate
contracts before complete operation composition can consume the relation.

Complete adapter review (2026-09-14, v112): compatibility must bind the transitive
C ABI, including the service table in `portable-component.h`. An unchanged
implementation header did not reveal the cleanup copy/release result-type change.
The actual overlay can express the current ABI through the existing reference
result projection; a cross-compiler negative control rejects the earlier table.

Keep source-region and production-adapter representations distinct. Actual
allocator results use the enclosing runtime as access context, reference-aware
span callbacks and an all-zero null view. Regional callbacks use scoped numeric
identities and explicit address/extent contexts. The current runtime integration
passes, but equal observed examples do not establish reference parametricity.
Authored scalar expressions can observe descriptor fields unless a checked
footprint or relational proof excludes that dependence. Likewise, failed reads
may leave different local output values; correspondence must follow the actual
fault outcome and liveness of those values. Actual span callbacks admit widths
one, two and four, whereas regional callbacks also accept three. Bind the owned
source's supported uses before importing a representation substitution theorem.
Do not silently broaden supported edits or identify a zero-extent local descriptor
with a canonical null reference merely because both prevent byte access.

Descriptor and lifetime review (2026-09-14, v111): preserve public reference fields
exactly when replacing opaque contexts at a cut. Cleanup now checks the actual
six view accessors against separate live context objects and corresponding hooks,
including the tail's added write guard. An arbitrary access compares results,
faults and complete effect arguments. A checked at-most-one-hook property makes
the compact effect record adequate; doubling the hook on both sides must reject.
The accessors themselves do not enforce reference-generation validity. This
transport theorem therefore cannot replace concrete lifetime qualification.

A finite-state check of the complete owned source graph tracks the scratch grant
from unissued through active to revoked. It consumes the existing compiler graph
and seven proved source regions, reaching a fixed point without enumerating loop
iterations. Normal returns require revocation; fault returns retain their actual
grant state. Unknown dependencies and unsupported graph shapes reject. Existing
regional footprints justify the supported source access paths; this is not a
general alias analysis. Persistent context storage, hook frame preservation,
service non-retention and physical release results are named versioned runtime
requirements, exposed as unverified until separately qualified. Proof-private
lexical contexts are not evidence that a production adapter supplies that storage.

Current-memory review (2026-09-14, v110): a cut may replace an accumulated write
history by an arbitrary incoming-memory function only by instantiating that
function with the complete current contents of the predecessor. Choosing a new
unrelated function would forget writes and break composition. Source and native
successors must use the same instantiation at every physical address, including
aliases. This is a logical substitution in the imported regional theorem, not
a runtime buffer copy or a new production API.

The public cleanup composition phase now checks this rule against the real
regional clauses. Entry and loop prove eight public predicates on normal exits;
loop and tail consume them. The loop uses the current function directly. The
tail additionally represents its scratch suffix as zero, so its reader must be
extensionally equal to the predecessor memory under the checked suffix invariant.
An arbitrary-probe query checks that equality and all consumer predicates.
The premise is a suffix invariant at every address; a single observed zero byte
would not justify the rule. Tests reject an unrelated base function, missing
suffix premise, altered regional clause and overwrite beyond the suffix.

The check has no application or write-history expansion. Physical object mapping,
descriptor identity/context observability, lifetime and service compatibility
remain separate obligations; current byte equality cannot discharge them.

Private-object review (2026-09-14, v109): regional scalar cells must be related
to preserved bytes across cuts. Cleanup's entry words, sparse loop cells and
tail words now share a checked 76-byte backing relation with arbitrary contents.
The actual direct unsigned-cell accessors lower to tables consumed by a fixed
proof recipe. Scalar and byte updates receive the same arbitrary store value;
the relation remains closed under stores and all other bytes remain unchanged.
Saved-frame and partial-word transport use this relation. Counterexamples expose
lost bytes, wrong anchors, stale overlapping aliases and corrupted store values.

Keep that representation theorem distinct from physical-frame admission and
lifetime. Public heap contents and descriptor contexts still need their own
transport rules, and concrete services/callers must satisfy the premises. The
private recipe and table checker can be imported without reconstruction; current
regional implementation receipts are rebound separately. No production API or
authoring-component count is introduced by this proof layer.

Admission review (2026-09-14, v108): compare the actual premises of the checked
models before joining regional receipts. Cleanup's entry-private span is smaller
than the tail's required span after translating stack coordinates. Entry excludes
the length IAT word, while tail excludes the whole image. Public admission now
checks these implications and exposes the missing requirements explicitly.
Allocation-result freshness is a future allocator guarantee, not an entry input
that a caller can establish. The proposed spatial envelope is nonempty and each
omitted requirement produces a counterexample, but actual caller admission,
private-byte framing, current heap contents, object lifetime and services remain
unqualified. Do not turn this spatial subtheorem into a component theorem.

Admission evidence is a separate semantic phase: its key binds the consumed
admission expressions and checker/producer identity; current regional receipts
are revalidated and rebound separately. A resource implementation change can
therefore reuse both the tail and admission queries. Import checks every retained
admission statement without invoking model generation or compilation. The public
operation status remains incomplete until the other composition obligations hold.

Shared graph review (2026-09-14, v107): proof regions for one operation should
refer to the same compiled source graph when checking their combined coverage.
Cleanup's entry, loop and tail now do so. The graph separately reports uncovered
reachable instructions and compiler records after returns. Removing a terminal
loop region exposes a coverage hole even when every remaining region is prepared.
All selected regional digests and source/native cut identities bind to the same
operation; shared original copy/advance transfers are allowed in two proof
contexts without becoming two authoring components.

Coverage is only one composition premise. Public entry proves the complete
scratch descriptor, saved frame and eight refined memory predicates, while the
loop preserves the public predicates and advances its repeated cut. Actual
private/image separation, persistent reference/lifetime transport and concrete
service behavior still require checked compatibility. Keep these obligations
visible rather than interpreting common cut names or three passing local queries
as a complete component theorem.

Public terminal dependency binding (2026-09-14, v106): keep the consumer theorem's
dependency domain distinct from the current supplier implementation receipt.
The public terminal cleanup loader validates both, including the original call
edge, exact borrowed reference, permitted private writes and live stack words.
A compatible supplier implementation can retain the consumer key; the output
must still rebind and validate the changed implementation evidence. C callback
type checking is part of model admission because GOTO acceptance alone missed an
incompatible aggregate return. The supported tail profile explicitly retains its
stack/view convention and unqualified concrete service/lifetime obligations.

Typed service and lifetime review (2026-09-14, v105): checking an interface
signature is insufficient if the model's callback implementation has a different
C type. The actual cleanup `copy` callback returned a word where the declared
service returns a reference aggregate; host C rejects the mismatch even though
GOTO compilation accepted it. The corrected model returns the complete destination
reference, and its native call returns the corresponding address.

Partial descriptor equality and physical byte equality also miss observable
contract dimensions. The tail now checks complete copy/message descriptors and
release references, and asserts lifetime on source scratch writes. Scalar service
results are shared arbitrary words; replacing an ignored result with a constant
would admit incorrect result-sensitive edits. Real generation, post-release write
and return-expression edits fail after compiled source matching. The source
footprint excludes unmodeled public context/metadata loads and pointer aliases;
it deliberately leaves scalar/reference correctness to the paired theorem.
These are conditional consumer checks, not concrete runtime qualification.

Public refinement semantics (2026-09-14, v104): a boundary revision changes
both admission and guarantees. The loop contract's optional `runtime_revision`
selects revision 2 (default) or 3; other values reject. Revision 3 retains a full
writable text descriptor and the null-scratch pending-CR/LF predicate, and checks
the complete public domain at both normal exits. Its public proof cannot reuse a
revision-2 key. These guarantees establish a regional interface only: caller
admission, private-frame/lifetime transport and receipt composition remain separate.

Preserved-object and descriptor review (2026-09-14, v103): a physical span may
reuse its arbitrary incoming bytes only when every modeled write discharges its
preservation obligation. This is stronger than a read-only view, which can alias
writable storage. The sparse runtime now implements that rule and checks it
against an independent byte array, with alias and missing-frame negative controls.
The real tail consumes it for fixed module/window/notice fields and imports the
resource supplier's checked reference, clobbers and complete private write frame.
Discarded callee code cannot silently turn those private writes into preservation.

Sharing scalar and byte predicates is also insufficient for regional composition:
entry/loop used a read-only text descriptor while the tail needs writable
copy-back. Both now have passing experiments with the complete writable
descriptor. Public receipt composition, source-effect admission and concrete
service/lifetime compatibility remain separate work, including callback effects
that could invalidate a proposed preserved span.

Terminal-boundary review (2026-09-14, v102): terminal regions retain ordinary
return expressions and need no artificial exit APIs. A single inert entry marker
is sufficient when the complete body graph, storage, effects and actual returns
match. If a local model also encodes cuts as integer returns, symbolic source
returns still require distinct outcome tagging to avoid collisions. Transport
never discharges the paired result, runtime, memory or progress obligations.

The real cleanup tail also demonstrates why an attractive boundary is not yet
a sufficient contract. Its null-allocation paths require a fact about pending
text bytes, not just cursors and pointer metadata. The entry now establishes a
proposed refinement and the loop preserves it at every normal exit, using actual
current memory. This is a regional invariant within cleanup, not an additional
component or dependency API. Tail correctness and evidence composition remain
open; no allocator-success restriction was substituted for the missing invariant.

Entry-to-region admission review (2026-09-14, v101): reuse the actual consumer
predicates at the producer's outgoing cut. The real cleanup entry revealed an
extra loop assumption about the last byte of the text span; that assumption was
removed instead of narrowing the admitted caller inputs. Public storage and
service expressions also need explicit source admission: a harness's concrete
unused context fields must not become accidental premises for authored edits.
Finite graph matching and outgoing local capture establish correspondence only;
cyclic execution, repeated calls, lifetime, service contracts and receipt
composition remain independent obligations. See [current evidence](current-goal.md).

Public manual graph preparation (2026-09-13, v99): the source-check workflow
now inventories multiple cuts in complete ordinary C, including cycles between
regions and early returns. Internal cycles require another cut. Compiler labels
and constant routing immediately preceding a cut belong to that port, allowing
the real cleanup joins to be shared without attributing their routing to one
predecessor. Calls, referenced storage, external interior entries and uncovered
scope remain visible. A per-region digest binds typed instructions, storage and
control destinations independently of their absolute compiler positions.

Prepared graphs do not establish state liveness/transport, frame or memory
contracts, behavior or progress. A wrong store can prepare successfully, and a
stable neighbor digest does not prove contract compatibility or authorize reuse.
The shared copy region is part of cleanup's authoring component; its source
statements need not disappear from cleanup's own proof to satisfy independence
across actual component dependencies. Prioritize connecting local proofs to this
public graph and completing meaningful component coverage over imposing another
source-copy abstraction prerequisite. See [current scope](current-goal.md).

Shared proof regions and ownership (2026-09-13, v97/v98): the retained Metapad
copy/advance instructions now have one checked original transition with two entry
ordinals, consumed from the loop and the second-byte short-input path. Each
consumer proves its own entry applicability, current-memory correspondence and
outgoing state. Both omit the shared original instructions. Source cuts remain
ordinary-C anchors with compiled body/restoration/observer correspondence, and
the source copy statements still execute in these experiments.

The copy/advance region belongs to the cleanup authoring component. Sharing its
proof neither duplicates replacement ownership nor requires a production helper
API. A complete component proof must cover every admitted incoming path and
preserve progress across the region graph. In particular, the second-byte source
context fixes its local loop counter to one; it does not establish admission from
cleanup entry or the first byte. Source-side summary substitution and public
multi-region composition remain implementation work.

The shared transition checks every machine-state field, including flags and x87
state, the full memory result, private-frame preservation and failure outcomes.
The consumer must dispatch all admitted edge kinds: the first retained loop
driver missed an unconditional jump and the functional proof rejected it. The
source transport checker also verifies storage metadata and transitive types for
all referenced data symbols, beyond explicitly restored locals. Deleting lifetime
end instructions cannot make changing an automatic local into static storage
compatible. These checks remain non-authorizing until integrated with the public
proof and compatibility readers. See [current evidence](current-goal.md).

Shared original control-flow context (2026-09-13, v96): a compact paired check
of the actual cleanup iteration can prove its current-memory, cursor/count,
zero-suffix and progress relations without surrounding heap/service bodies.
However, the original copy block 0x5601 also has an incoming edge from the
short-input predecessor 0x55fa. A proof starting at loop entry 0x5606 does not
establish that other context or sole ownership of the shared block. Before
composing it as an independently replaceable unit, introduce a checked shared
copy cut or represent and check each entry contract explicitly. Do not infer a
single-entry component from the authored C loop's lexical shape. The experimental
source resume/capture macros also need compiled state-transport correspondence;
the local CBMC result alone cannot establish that boundary transformation.

Public caller proof composition (2026-09-13, v95): actual authored call regions
now consume checked supplier transitions through the operator product. Source
preparation is an independent cached input. Caller contracts explicitly declare
private-stack admission, live word frames and returned-reference representation;
a larger supplier frame cannot silently narrow caller inputs. The consumer proof
key binds the full consumed domain, source projection, exact original behavior,
options/tools and producer graph. The supplying implementation receipt is bound
separately. A valid replacement with the same domain can reuse all consumer proof
files without regeneration or solving, while incompatible admission fails closed.

This implementation accepts one normal borrowed-image cdecl call region. Its
projection is tied to complete compiled ordinary C by inert-marker correspondence;
it does not introduce a production API. The public result remains conditional
and identifies the missing caller entry/coverage/progress and runtime obligations.
It cannot act as a transitive functional summary for a complete caller until those
obligations are discharged. The retained public Metapad cycle demonstrates actual
argument-error detection and supplier proof reuse, but not the required complete
multi-level application network.

Conditional paired transitions (2026-09-13, v93): a complete original/source leaf
comparison can now be read as an explicit transition premise. The reader validates
its source certificate, original slice and binding, regenerated model, compiler
inputs, tools and complete raw query. The consumed domain retains original
behavior identity, interface/binding, service assumptions, runtime domain and
result relation. Implementation receipts remain separate. Auxiliary source-memory
event capacities do not enter this domain: they are checked proof resources,
not restrictions on a caller's input or the supplier's permitted implementation.

Two actual Metapad caller cuts consume such a transition without either supplier
body. Before coupling a child step, the model checks matching scalar arguments
and the declared readable input union at a universally arbitrary byte. Temporary
differences in unrelated globals are not callee inputs; a positive control
changes and restores a neighboring word outside that union. A fresh byte function over
the writable union covers arbitrary framed post-memory; the returned alias stays
live. Matched internal effects come from the separately checked functional child
under the same service/runtime assumptions. They cannot be inferred from the
signature or a declared effect list. This rule requires a non-reentrant normal
call with no allocation, callbacks or nonlocal exit in the selected child domain;
it does not yet generalize those behaviors or register qualification authority.

The cuts retain pending caller stack words and nonvolatile registers. The actual
region footprint is asserted; the callee's checked private writes lie below the
live caller words. Future cuts must separately establish their entry relation and
coverage. These are two proof regions, not two complete caller components or new
production APIs. Whole-caller progress, MessageBox input safety and runtime
compatibility remain independent obligations. A changed original/domain identity
requires caller rechecking even if a regenerated C model happens to be identical.

Native namespace check (2026-09-13, v92): a logical view's access grant and extent
must remain distinct from its enclosing origin's metadata. The real Metapad
module and buffer share a writable section origin, although the module view is
read-only. Tests now exercise actual native resolution/realization and generated
logical adapters with those retained origins, current buffer bytes and deliberate
descriptor, remapping and admission failures. These checks validate a runtime
facet with controlled memory/services; they do not establish loader lifetime,
service ABI compatibility or authorize the conditional functional leaf. Consumers
still need checked transitions and actual call/cut admission before composition.

Public functional boundary (2026-09-13, v91): local source-contract products may
also check the exact original leaf under an explicit borrowed-image domain. The
source profile/opacity certificate binds the authored GOTO object actually linked
into the functional model. This avoids a second source compilation under different
headers and retains independent checks for original file identity, compiler
includes, named stdcall events, private stack and register frames. A source-only
frame/input-dependence theorem can succeed while this functional comparison
rejects an incorrect resource ID. Feedback distinguishes both results and keeps
runtime compatibility unverified. No original-comparison result is consumed by
the strong qualification reader or connected-summary selector yet.

Original/source domain experiment (2026-09-13, v90): the same sparse memory and
ordered service model can compare an actual retained Behavioral-C leaf with
ordinary C. Private stack bytes are separate from borrowed image views; the
entry return word and scalar inputs cannot overlap, and an admitted stack must
exist. Every original access, named stdcall site, normal return and undeclared
register clobber is checked. A loop edit passes without a service-output NUL
premise. This demonstrates a useful local functional boundary, but the renderer
is not provider authority: actual adapter/runtime compatibility and source
opacity must be bound by its eventual consuming checker. The caller's string
invariant remains distinct from the leaf's alias/effect contract.

Contract/evidence separation checkpoint (2026-09-13): auxiliary fixed-memory
consumer theorems can retain their compiled models and solver outputs when a
supplier is requalified under the same consumed contract. The contract identity
includes the checker rule for frames, opacity and input dependence, plus the
interface; it is not a signature-only compatibility test. Current supplier bytes
and complete certificates remain separately validated. The composed certificate
changes to bind those suppliers, while the original consumer query bindings remain
intact. The final validator checks current generated model meaning and all retained
evidence without invoking compiler or solver processes. A changed consumer,
contract, tool or checking policy cannot take this reuse path.

The auxiliary shared-state/service checker can also consume fixed-memory
dependencies. It uses the same input-byte and alias-aware functional summaries in
its sparse mutable world, retaining ordered service observations and the authored
returned-state alias. Its own service/alias contract is an additional reuse input.
This composed policy remains separate from the leaf shared policy: transitive
machine qualification is unsupported and is rejected explicitly. A module-reader
source contract proves frame and input dependence, not that it returns the actual
module word; original-behavior qualification is still required before application
composition can rely on that stronger fact.

This is an auxiliary theorem substitution rule, not application behavior
equivalence or activation authority. The immediate design acceptance requirement
is to demonstrate this separation for complete local application proofs on a real
hand-defined network, including shared state, caller compatibility, ordinary edits
and incompatible contract refinement through the public workflow.

Composed-boundary reachability checkpoint (2026-09-13, v87): the exact v85
Metapad consumer now has independently reparsed bounded witnesses after source
admission and at both matching binary/source outgoing cuts. The checked coverage
sites follow the actual admission call or alignment guard, with no alternate
branch entering after that predecessor. This checks a distinct boundary duty:
the composed input relation and selected runtime contracts admit real paths.
It does not replace their universal correctness, memory/frame, progress or caller
obligations. In particular, successful root assertions behind an unreachable
residual path do not witness fault behavior. The separate 1,066-property partition
experiment must retain all unresolved scope; see the current goal and performance
record for the exact evidence and limits.

Common-prefix source-edit composition (2026-09-13, v86): a manual proof region
may include identical effectful code before a changed pure decision. The checker
first binds complete compiled helpers, symbols and surrounding context, then
matches prefix instructions and branch successors on both sides. A call is
preserved with its exact target, arguments and result storage; it is not replaced
by an assumed summary. Identical early returns retain their values and epilogues.
Every continuing path must meet one frontier, and the changed suffix cannot
reenter the prefix. Its universal scalar proof preserves all preexisting storage.
The prefix may write memory, fault or diverge; the result records preserved common
effects separately from the pure suffix's frame.

The actual public Metapad edit now places its entry before the byte-read/failure
check. Both raw-source and retained proof-environment correspondences pass, and
bounded query evidence is transported with unchanged scope. Changed arguments,
extra calls, changed failure behavior, transient suffix writes and missing entry
coverage are rejected by compiler-backed controls. Growing an identical helper
on both sides leaves the local query unchanged; changing it on only one side still
requires separate evidence. This supports practical manual boundary placement,
not general shared-heap summaries or compatible contract refinement. See
[current measurements and limits](current-goal.md).

Incoming protocol/frame experiment (2026-09-13, v85): a whole-registry snapshot
is not required when a real operation has a checked initialization protocol and a
precise write frame. The four actual image admissions establish or reuse a canonical
two-origin prefix while preserving the rest of the 17-slot registry and memory.
The stronger phase and image-disjointness premises are discharged at the actual
application callers. Qualification keeps neighboring-world state independent;
no callee-body fact silently narrows that caller domain.

An independently qualified adapter edit reuses the actual caller selection through
identical checked functions, common contracts/symbols and property inventories,
plus one checked unused automatic declaration. Metadata and out-of-frame mutations
fail qualification. The aggregate application proof remains incomplete. This
supports protocol-aware hand-defined boundaries and exact dependency transport;
it does not establish general heap composition or the public application-edit
workflow. See [measurements and limitations](current-goal.md).

Byte-memory composition finding (2026-09-13, v84): preserving a reader's scalar
result, address, fault condition and write frame does not connect the result to
the memory that a consumer subsequently observes. The real application exposes
that omission at `lookahead_one`. A separately checked postcondition relating
the successful result to the generated byte projection makes the unchanged
invariant pass with the reader bodies absent. The original application code,
input domain and cut header are unchanged. This is evidence for the contents
relationship, not a general native memory qualification or a small consumer
model: the projection still retains the sparse allocation/write history.
See [current measurements and remaining checks](current-goal.md).

Neighbor-service contract experiment (2026-09-13, v83): a real edit-window
reference admission composes through a checked registry snapshot, append bound,
preserved prefix, failure frame and allowed writes. The caption consumer retains
its original assertions with the neighboring body omitted. Fresh snapshot storage
alone is insufficient: its contents must equal the actual pre-call registry,
and caller applicability must be checked. The snapshot parameter belongs to the
proof wrapper; no synthetic production API is introduced.

An implementation rewrite satisfies the unchanged complete contract, while a
prefix violation fails qualification. All checked consumer functions remain
exactly equal after the rewrite, although an unused automatic declaration changes
the file hash. The retained experiment reuses evidence through a deliberately
restricted relation: identical functions including control/property metadata,
identical common symbols/contracts, identical property inventory, and one
unreferenced scalar local from the omitted body. Original evidence stays bound
to its original model. This is not signature-based compatibility or permission
to discard arbitrary symbol differences, and the public import path is not yet
implemented. See [current evidence and limitations](current-goal.md).

Checked origin read footprint (2026-09-13, v82): repeated issuance can tolerate
changes to surrounding world state when its actual read footprint survives.
The retained issuer's primitive law permits arbitrary changes outside allocation
count, per-record base/size/live/generation and private low/high, with the exposed
ranges, registry and reference inputs fixed. The full retained 17-slot query
passes with safety/unwinding checks; generation, visibility and physical-origin
mutations reject the claimed guarantee. This is evidence for factoring a
specific invariant instead of carrying every world field into each consumer.

The footprint is operation-specific. Native namespace lookup reads additional
allocation-producer/identity fields, and byte reads have separate content
dependencies. Therefore this primitive law must not narrow the complete
continuity contract's dependencies by itself. Registry extension also needs its
own preserved-prefix/issuer rule before neighboring admissions can reuse the
law. Initial argument storage is separate in this harness; arbitrary storage
aliasing is not covered. See [current scope and evidence](current-goal.md).

Readonly continuity consumer (2026-09-13, v81): explicit use guards allow the
existing experimental premise to stand for repeated outgoing metadata/span
checks, while the incoming cut retains its actual native admission. Passing
those guards does not prove the premise's native guarantees. Original assertion
IDs also do not establish unchanged predicates: the outgoing predicates now
consume that premise. The complete parent selection still times out with both
SAT and SMT. See [current results](current-goal.md).

Reference lookup wrappers can register origins. A reusable admission invariant
therefore needs a checked rule for registry effects, including idempotent
re-registration and preserved lifetime/physical binding, in addition to a
stable descriptor and allocation footprint. Neither pointer equality nor a
declaration that lookup is pure supplies this rule. Public readers continue to
reject the unqualified experimental continuity contract.

Fault-footprint refinement (2026-09-13, v80): the rejected first-read success
guarantee is replaced by a checked relationship between its fault and the
allocation-access predicate. A closed projection of count/base/size/live
matches the actual helper on arbitrary retained-capacity histories and widths
with safety/unwinding checks. Negative controls detect lost liveness,
incorrect record precedence and spans crossing one object's bound. This shows
why a compact interface must preserve semantic relationships, not merely expose
separate scalar fields. It does not grant native reference identity,
permissions, generation validity or heap contents.

The full parent can now omit all three reader bodies while checking their
caller preconditions. The broader original application/guard check still times
out, so a small runtime footprint alone has not solved composition cost.
The next boundary work must let application regions reuse checked entry and
reference-preservation invariants, retaining their exact admission and state
dependencies. See [current evidence](current-goal.md). The five-premise
experimental environment remains separate from public proof authority.

Consumer-driven fault refinement (2026-09-13, v79): a locally useful summary
can preserve the complete write frame yet omit an outcome relationship needed
by its caller. In the real Metapad parent, summaries for both binary reads allow
a second-read fault that the source-reader contract cannot accept. Testing a
stronger nonfaulting guarantee against the concrete implementations succeeds
for the second reader but fails for the first: the first reader's qualification
domain includes a tracked dead allocation. The failed stronger guarantee is
not selected for consumption. The revised consumer retains the first concrete
reader and successfully checks the preconditions of the second/source summaries.

The boundary rule is to preserve fault outcomes and their relationship to
object admission, permissions and lifetime. A postcondition that merely names
a fault flag loses that relationship; an unconditional success postcondition
can be false. Admission established later in the caller cannot be retroactively
used to qualify an earlier read without a checked transport rule. This is an
input-domain/composition requirement, not justification for assuming faults
away. All original source/root assertions remain in the experiment. Its
bounded, five-premise qualification still does not authorize public component
theorems or native activation. See `reader-refinement-audit-v1.json` under the
practical-assurance directory and [current status](current-goal.md).

Descriptor storage experiment (2026-09-13, v78): the actual caller establishes
descriptor readability and separation from local writable storage with added
assertions whose erasure preserves the complete compiled program. A local
binary/C consumer checks a standalone descriptor and a descriptor embedded in
shared cut state, preserving every field at each exit and retaining its complete
write frame. Both branch outcomes are reachable for each storage origin; an
actual descriptor write is rejected.

The failed attempt to use an arbitrary pointer plus a readability assumption
reinforces a modeling boundary: the descriptor needs a justified live storage
origin. A field tuple alone does not supply one. CBMC's contract memory
predicates distinguish object creation, pointer equality and interior pointers;
their [enforcement and replacement semantics](https://diffblue.github.io/cbmc/contracts-memory-predicates.html)
must be respected when constructing that input model. The passing two-origin
experiment proves neither arbitrary heap admission nor the lifetime/contents
of objects referenced by descriptor fields. Actual input admission, local field
preservation and outgoing machine/world relations remain separate premises
until their composition is checked. The experimental runtime assumption set
still cannot authorize the public four-contract application baseline.

Query-scope transport checkpoint (2026-09-13, v77): a finite proof region can
be acyclic while containing a numerically backward GOTO. CBMC assigns such a
jump an unwind counter, so source-level progress alone is insufficient to reuse
a bounded query. The processed-context relation now preserves actual assertion
IDs and predicates and tags each backward GOTO with its checked loop ID. This
initial pure-edit transport rejects backward GOTOs inside the local region and
compares every remaining tagged context. It also rejects instruction-depth and
partial-loop shortcuts whose scope can change under finite refactoring.

The real public experiment transports bounded safety results, with their exact
runtime contracts and inactive loop limits visible. It does not introduce a
production API or turn proof regions into independently qualified components.
Complete application results, compatible shared-state representation changes
and neighboring component theorem reuse remain required.

Proof-environment embedding (2026-09-13, v76): the configured public edit
checker now reproduces an actual retained conditional model and checks the same
local edit inside that model's complete surrounding context. The ordinary and
instrumented callers may number instructions differently; generated local query
labels therefore use dense local numbering, while the embedding retains actual
indices, named ports, types and complete model hashes. Reusing a local theorem
requires this freshly checked embedding, not matching C signatures or labels.

The demonstrated profile still changes only a nonescaping scalar. No runtime
premise, heap correspondence, lifecycle obligation or progress condition is
removed. The embedding supplies the relation needed for baseline query transport;
it does not import that evidence or qualify a neighboring component. A configured
but unsupported embedding keeps the requested check incomplete. See
[public configuration](components.md) and [measured costs](performance-and-invalidation.md).

Public manual-boundary checkpoint (2026-09-13, v75): the real scalar refactor
uses exact complete-line entry and exit anchors configured for the existing
operation. Only copied proof inputs receive empty marker calls. Both marker
erasures and complete surrounding compiled contexts are checked; production C
needs no extra function or API. A finite inverted conditional/jump form from
compiler lifetime cleanup is normalized only without an additional incoming edge
or intermediate property meaning. This preserves control flow and progress.

The operator can now edit, detect a branch violation and repair with local-query
reuse. Existing-state changes and contract changes stay unsupported for this
profile. The baseline bridge checks full interface identity as well as source
identity and displays baseline obligations separately. Neither matching metadata
nor successful source comparison imports an application proof: composition still
needs the exact baseline proof environment, retained assumptions and discharged
coverage. See [operator configuration](components.md) and [current evidence](current-goal.md).

Edit-local boundary (2026-09-13, v74): a proof region can begin after a common
read even though the component still owns the complete operation and its loop.
For the real `has_byte` refactor, the remaining original region is one branch.
The changed region writes only a new nonescaping scalar. A finite scalar query
therefore compares exit ports for every byte value while preserving all existing
state. Complete compiled-context correspondence and inert-marker erasure are
checked separately. No synthetic production function or component is introduced.

This is a restricted sequential C edit rule, not a general boundary language or
a replacement for memory/lifetime relations. Reads of shared objects, changes to
existing storage, effects, arithmetic outside the supported total operations,
representation changes and cycles require the broader rules. The experiment
demonstrates how to avoid re-proving heap admission for this pure edit; initial
binary lifting and contract refinement retain those obligations. Public evidence
composition must preserve the baseline's exact authority and assumptions.
Next consume this result through the real public workflow, rather than expanding
the restricted profile in isolation. See [checkpoint and evidence](current-goal.md).

Specification identity and combined frames (2026-09-13, v73): the audit found
that a function's ordinary CBMC type omits its contract clauses. They live on
the separate `contract::<function>` symbol. Equal function types therefore cannot
bind changed requires, ensures, assigns or frees clauses. The experimental
identity checker now compares those ASTs, free storage declarations and recursive
struct/union/enum definitions. Predicate helper bodies need separate semantic
dependencies and are rejected by this initial rule. Initializers remain part of
caller-domain evidence, not contract identity; changed implementations still need
their own qualification even when contract identity is stable.

The real local consumer now proves its outcomes and complete application write
frame together under three contextual reader contracts. Actual binary-reader
frame checks reject a transient world write, while the local frame rejects an
unlisted C global write. Runtime and application frames are separate dependencies.
The exact-read contracts admit arbitrary faults; the nonfault scope is justified
by the retained real caller, not inferred from the read signature. Descriptor/entry
projection and unchanged-context substitution still precede public behavioral
neighbor reuse. See [current evidence and limitations](current-goal.md).

Contract consumers and storage domains (2026-09-13, v72): a local proof can now
consume the exact compiled contextual reader contract with its implementation
absent. Bind the clauses and referenced global/aggregate types, not only the C
signature. The actual local branch, live values and parameter captures pass under
that contract; a branch mutation fails. Runtime assumptions remain separate from
the application proof, and complete frame/context composition is still required.

Do not treat arbitrary pointer bits as arbitrary valid objects. The first local
consumer fails pointer-validity checks; the actual decoder instead passes a live
automatic text descriptor. Its local model now preserves that storage shape with
arbitrary contents. A compiled argument/storage inventory supports this choice,
but does not establish general object renaming, aliases, backing memory or lifetime.
The runtime structure itself is arbitrary: a zero initializer masked a deliberate
runtime-dependent negative control. See [current checks and limitations](current-goal.md).

Parameter values and shared exits (2026-09-13, v71): the actual operation has
a counterexample to treating heap frames as complete cut-state frames. Changing
the local `text` parameter after the read passes the previous outcome and heap
write checks, but changes what the next cut observes. The local proof now checks
all six parameter values as well as the existing captured locals. Its observer
arguments are matched to the actual compiled region; no new production API is
introduced. Parameter identity, backing memory and lifetime remain separate.

The context relation also handles an actual shared tail label reached from other
regions. Empty compiler labels immediately before an exit are part of that exit;
they are not interior logic that must have a unique incoming edge. Other entries
into region logic and internal cycles without progress rules remain rejected.
The whole surrounding compiled context, storage and helpers must match; a new
private scalar can end its lifetime outside the region only if its address and
uses do not escape. This structural relation needs local behavior/frame and
input-domain evidence before it can justify substitution. See [current results](current-goal.md).

Contract instrumentation and scope (2026-09-13, v70): the retained actual read
experiment separately checks callee postconditions/write effects, caller
preconditions and return reachability. Actual result corruption and a transient
public-world write are rejected. All original static initializers must survive
instrumentation unchanged when importing evidence about the retained caller
domain; repairing a failed proof by adding a zero assumption would not establish
that correspondence.

The ordinary parent can omit that reader body under its checked contextual
contract, but the selected memory query remains about 152s. Small code bodies
do not remove repeated shared-state reasoning. Boundary design therefore needs
reusable applicability and state-transport obligations as well as reusable callee
behavior. The five retained runtime assumptions still include an experimental
continuity premise rejected by production. These selected checks do not qualify
arbitrary callers, heap lifetimes, fault transport or the v69 application-region
substitution. See [current evidence and next integration](current-goal.md).

Complete frame requirement (2026-09-13): the real local experiment now has a
negative example where a direct write to an unlisted C global passes branch/value
and selected descriptor checks. The existing DFCC empty-public-write proof rejects
it. A component's assurance must bind both its observable outcomes and its complete
allowed effects to the same implementation; neither an API-call inventory nor
selected endpoint equalities supplies a frame. The correct local refactor passes
both, and the experimental parent reuse gate now requires both results.

Canonical parent generation can stabilize expensive proof inputs across such an
edit, but a declared application-region summary cannot authorize that substitution.
Its input domain, output/cut relation and runtime contracts need checked composition.
Keep application proof obligations outside the trusted runtime surface. See
[current evidence and limits](current-goal.md).

Readonly-image reuse (2026-09-12): the proposed continuity contract now has a
second view kind as a real consumer. `tail:suppress_notice` checks the existing
captured descriptor/context, its image selector, four-byte span and read access;
the text helper remains unchanged. Its applicability and original context
assertion pass. Actual native image helpers pass bounded metadata, alias,
changed-byte, scope and boundary cases, and reject deliberate locator/permission
faults. A section rule may grant read/write permission while its consumer view
requests only read permission; those two permissions must not be conflated.

This experiment retains the native metadata predicate and uses the trusted
contract only for repeated span realization. It is not production lowering or a
general admission/issuer rule. Captured context equality does not freeze pointed-to
memory, and the current global diagnostic snapshot does not establish nested-call
or reentrant ownership. The complete run now passes 73/393 authored assertions
and all safety groups, but whole public-memory equality at `tail` remains
unresolved and 319 assertions are unexecuted. Entry nonvacuity and the actual
readonly-tail context site are reachable on that same model.

The next memory boundary must establish the incoming correspondence and each
side's preservation over the actual region. Text-range equality covers only its
checked span; unchanged reference descriptors do not establish bytes elsewhere,
allocation correspondence or observation visibility. Preserve those obligations
when factoring the existing memory model. Five bounded exposure cases now check
the existing visibility/registration/realization bodies, including partial and
reordered spans and invalidated exposure. Actual removed-guard and late-write
controls are rejected. These qualify this constructed visibility dependency,
not native permission or a general neighboring-effect frame. Admission/issuer
enforcement, complete region qualification and public application-proof reuse
remain required.
See [current evidence](current-goal.md).

Second-cut consumer (2026-09-12): the unchanged experimental reference-continuity
contract now has passing applicability checks across two actual outgoing cuts,
`lookahead_one:text` and `tail:text`. Their four metadata/context predicates pass,
and the actual tail context assertion is reachable. The helper, admission inputs
and trust selection remain unchanged; three tail header calls now consume it.
This is useful invariant reuse across real contexts, not complete region
qualification or neighboring application-proof reuse. Other incoming views and
their selectors, permissions and spans still need their own checked applicability;
the text view's read/write admission cannot simply be assumed for them.

Explicit trust boundary experiment (2026-09-12): continued validity of an admitted
reference can be a named runtime assumption rather than repeatedly proving the
whole origin registry in every application query. The experimental continuity
contract requires the same descriptor/context/owner/address, allocation metadata
and access scope; only the checked issuer may append origins. Bytes and ordinary
application effects remain separate obligations. The first prototype's omission
of private/exposed ranges demonstrates why a stable descriptor and allocation
table alone are insufficient: registration reads the access scope as well.

Revision 2 has passing selected applicability/application checks and eleven
bounded native/proof-runtime scenarios with negative controls. This is evidence
for an explicit conditional boundary, not a general preservation theorem or a
production summary. Admission, issuer enforcement, the real selector and exposed
scope, fresh result storage, complete application qualification and public
dependency/reuse behavior remain obligations. Production readers reject this
experimental identity. See [evidence and limitations](current-goal.md).

The current applicability guard conservatively compares every allocation record
and exposed-range slot in this retained model. Even an unrelated allocation or
scope change invalidates it. This is not yet the selected-object footprint needed
for broad independence across allocating neighbors. Narrowing that footprint must
account for competing namespace matches, overlapping ranges and lifetime changes;
dropping fields solely because a tested descriptor stays unchanged is unsound.

Reference effects and invariant scope (2026-09-12): the real outgoing cut now
has passing descriptor/context/address, identity and source-world frame checks,
actual-cut reachability, and a rejected runtime generation mutation. Full
origin-table/initial-memory equality remains unresolved. Supplying the passing
facts while retaining the actual reference predicates still times out; ordinary
guarded pure-lookup caching also times out and enlarges symbolic work by 9.1%.
Neither experiment is a production composition rule.

The next candidate boundary is the selected reference's issuance and live-object
invariant. Pure namespace lookup and origin-registering wrappers have distinct
effects. A reusable contract must establish continued validity of the selected
identity, extent, permissions, lifetime and contents under its admitted
neighboring effects. It must also preserve lookup failures and observable
effects. Descriptor stability alone and unproved equality of a global origin
table cannot supply that contract. Measure actual consumer omission/reuse of
this reasoning before expanding cases. See [evidence](current-goal.md) and
[costs](performance-and-invalidation.md).

Actual-consumer boundary result (2026-09-12): the real loop now has passing
checks that its admitted view, context, index and memory survive to the first
read, plus actual-call reachability and a rejected C argument mutation. The
consumer also proves its initial-fill observation flag is one. Do not widen a
contract's bookkeeping domain merely for generality when the actual consumer
can establish the narrower domain without restricting its inputs. A broader
per-read bit experiment remains partially unresolved.

Body absence alone is insufficient evidence of a useful decomposition. The
candidate source-reader omission retains 99.85% of symbolic steps, and the
same real metadata/context assertions time out with and without that body.
The next measured boundary must address the retained reference/memory
predicates, with checked admission, preservation and dependency binding.
Transport checks do not themselves prove entry-domain correspondence or fresh
result-storage separation; those and complete qualifier checks remain owed
before any production substitution. No new trusted contract or activation
authority was introduced. See [current evidence](current-goal.md) and the
[matched measurements](performance-and-invalidation.md).

Complete entry/read probe validation (2026-09-12): all authored and safety checks,
unwinding and relation nonvacuity pass, and every query reuses across the tested
public body edit. Actual wrong-width and byte-corruption controls fail. This
establishes a reusable qualification boundary for the probe, with about 932s cold
query work versus 5s reused. It does not supply a post-read frame or a theorem
transporting the result across application execution. Qualify those rules before
removing runtime bodies from the consuming application proof; preserve current
bytes, view/context state, live and retired origins, aliases and observation
bookkeeping through that transformation. See [evidence](current-goal.md).

Independent read qualification (2026-09-12): checking actual reads after admitted
entry in the existing source-entry model proves success/value assertions while
excluding the ordinary portable-C body. The qualifier is unchanged across an
actual retained public body edit, and a zero-width runtime-call mutation is
detected. This is a useful dependency boundary: body-only edits can preserve
qualification, while entry relations, interfaces, runtime code and selected
contracts remain semantic inputs. Complete qualifier checks now pass above;
the post-read frame/transport theorem is still required before these results can replace
runtime execution inside an application proof. Reuse of this diagnostic query
does not establish neighboring business-component assurance.
The tested branch edit preserves the compiler-derived entry storage inventory;
changes to that inventory can invalidate qualification despite a stable signature.

Root-barrier follow-through (2026-09-12): all 27 safety groups and 44/383 authored
assertions pass; text metadata/context transport at `lookahead_one` remain
unresolved and 337 assertions are unexecuted. The 1,676.234s complete attempt
reinforces the need for reusable qualification outside the application body.
The proposed independent entry/read probe is not yet a summary or a proof of
transport across application execution. Retain those obligations explicitly.

Fact scope across an entry boundary (2026-09-12): an observation made during
original execution can precede the source cut's input assumptions. A read-success
assertion at that earlier point finds a wrapping index into retired storage;
the later loop invariant excludes the index. This is a wider-prefix
counterexample, not a valid admitted-loop failure. Recording the original
outcome and checking it after the existing source-entry relation proves both
read-success facts. Consume them there; moving a fact backward across admission
requires its own checked transport. Exact code, input relation and observation
site belong to the dependency, not merely the predicate or C signature.

Those two facts establish root unreachability at the public-memory check without
changing inputs or memory semantics. An assert-then-assume barrier at that exact
proved site leaves normal-cut memory and state transport required. Qualification
and mutation sensitivity precede consumption; this remains a diagnostic
composition experiment rather than an implemented production summary rule.

Whole-region follow-through (2026-09-12): all safety groups and relation
nonvacuity now pass on the witnessed model, but the complete partitioner stops
at unresolved root public-memory equality: 13 of 380 authored assertions pass,
one is unresolved and 366 are unexecuted. Matching-cut text-byte preservation
does not establish a whole public-memory frame on residual root outcomes.
Preserve that distinction when choosing the next memory boundary. Projection
validation also needs initial-memory observation bookkeeping, not just returned
bytes; the focused regression now exercises that dependency and its mutation.
See [current evidence](current-goal.md).

Memory observation decomposition (2026-09-12): separately checking input-byte
correspondence, backing-span preservation and exact/source byte preservation
at the two matching normal cuts lets one real tail-text correspondence assertion
pass in 82.273s, versus a matched witnessed-baseline timeout at 180.211s.
Qualification itself takes about 271s. This supports factoring a memory relation
into checked premises without weakening it; it does not yet establish a reusable
production boundary, complete region assurance or improved cold edit latency.
The fresh arbitrary-byte witness is invisible to ordinary C. Its input observer
must restore the bookkeeping flag changed by initial-byte lookup. Span and byte
corruption controls are detected, but all bodies remain and the new instrumented
model still needs its remaining authored checks; the later full-run attempt
above passes safety, unwind and relation nonvacuity.
Qualify these transformations before exposing them as production composition.
See [current evidence](current-goal.md).

State-boundary evidence refinement (2026-09-12): exact consumption of sixteen
separately checked read/decoder frame facts does not complete the 104-property
state batch at 180 seconds. This does not isolate an inherently expensive memory
invariant: the first caption memory assertion passes alone in 55.221s using the
existing smaller-group ordering. The next four-view memory batch times out.
All four subsequently pass individually in the same model (58.080s, 52.921s,
73.472s and 158.275s). Keep the distinction between a difficult combined query
and a difficult individual boundary; this evidence does not justify weakening
the memory contract. The subsequent recursive run returned with nine original
state assertions satisfied, one unresolved and 94 unexecuted. Preserve this
model-specific coverage when evaluating the new witnessed model above. No new
production summary rule follows from the frame-fact experiment.

Normal-cut follow-through (2026-09-12): the composed result/fault facts discharge
two normal successor-alignment assertions in 41.051s, but the remaining 104
outgoing-state assertions time out at 180.268s. Exact public source restoration
also remains incomplete at 180 seconds while reusing all 161 entry queries.
Thus neither control alignment nor entry reuse establishes independently
assured state transport. Keep the complete frame, alias, lifetime and effect
obligations, and qualify a useful state boundary before generalizing composition.
See the audited [current evidence](current-goal.md).

Read/result/fault composition and diagnostic reach (2026-09-12): the real
loop's two original byte reads and first portable read have eleven checked
sequence/address, fault, value and frame assertions. Combining their exact
fault/value facts with five separately proved decoder results completes one
previously unresolved root exit-control assertion. Every runtime body remains;
this diagnostic is not a general reusable summary rule. A production boundary
still needs exact applicability/dependency binding and independent qualification
of its input, lifetime, alias, fault and frame premises.

Root exit equivalence and normal cut alignment are distinct obligations: normal
paths may stop at cuts before reaching the root assertion. The deliberately
inverted C branch demonstrates why both matter. Public V15 scheduling checks cut
alignment first and detects the wrong tail successor under a 180-second budget;
the 60-second run remains incomplete. V14 evidence retains its historical ordering.
No successful subset removes the other obligations or grants activation. Complete
normal-cut state checks and the public edit/repair/refine/reuse workflow remain
the acceptance criteria. See the latest [evidence](current-goal.md).

Concrete decoder-summary candidate (2026-09-12): five repeated parameter
resolutions in the real application now have checked result and frame
observations. The candidate reuses input setup's reference values at those
exact call sites, while retaining each view's stack owner and callback identity.
This avoids treating reconstructed pointers as preserved memory or returning
references to dead adapter locals. A production rule would still need checked
call-site/input dependencies, complete effects and safety coverage, exact
evidence consumption, and invalidation when the resolver or its assumptions
change. The diagnostic checks do not introduce a generally trusted memoizer.

Consuming these results reduces symbolic steps by about ten percent, but both
matched application control queries still time out at 180 seconds. This narrow
boundary is therefore insufficient for practical assurance. Do not generalize it
into a production feature solely because its local checks pass. The next measured
candidate must factor the remaining shared input-memory and cut-state relation,
including contents, aliasing, lifetime and fault behavior; shrinking source logic
or memoizing additional scalar results is not evidence that this cost is removed.

Entry qualification also does not automatically prove arrival: the current
relation root discards early adapter returns. Its escaped-cut assertion is inside
the extracted source function. Arrival/fault outcomes must therefore be checked
explicitly or represented by the summary; a success-only substitution cannot
follow merely from the existing satisfied receipt. The real additional
no-adapter-return observation passes under its declared entry assumptions.
See [current measurements and scope](current-goal.md).

Production entry-summary consumption remains unimplemented (2026-09-12): the real entry
can now qualify and reuse, but the application control query still exceeds 180s
with that entry fully reused. Current execution passes the original GOTO model
to application checking. A useful next boundary must carry an explicit checked
entry result and frame into the application model: logical values, aliases, live
view owners, current bytes, issued-reference state and observable effects.
A compiled-prefix relation and a satisfied entry receipt do not by themselves
specify those outputs or authorize reconstructing pointers to expired storage.
Implement this transport through existing relations and summaries on the real
consumer, preserving fault outcomes, before claiming entry factoring reduces
application proof cost. See [measured follow-through](performance-and-invalidation.md).

Real loop entry qualification and reuse (2026-09-12): compiler correspondence
now leads to a complete conditional entry theorem for the retained mutable-memory
loop boundary. All 245 authored entry assertions, safety/unwinding and nonvacuity
pass. A public ordinary-C branch edit changes the application model while preserving
the entry model; rechecking correspondence allows all 158 entry processes to be
reused with no fresh entry queries. This validates the distinction between entry
and application dependencies on a real loop cut, not only an extracted fixture.

The complete entry remains conditional on its named runtime contracts and declared
inputs. Its proof neither establishes native caller applicability nor discharges
the application body. The public edited component remains incomplete. Next use
this boundary evidence for the real application comparison and subsequent contract
violation/repair/refinement demonstration; do not count entry reuse as a completed
multi-component network. See [measurements](performance-and-invalidation.md).

Real entry extraction follow-up (2026-09-12): compiler storage identity must
survive moving a proof cut out of its original nested control flow. The generated
owner pointer is now declared at the common BEGIN and assigned only at the same
validated cut location. The production prefix checker accepts the real loop entry
without an identity-renaming exemption. A changed owner assignment still fails
the regression. This repairs preparation; entry safety/nonvacuity and native
caller applicability remain separate obligations.

The real control-query investigation also retains failures before source cut
resumption. Splitting by outcome, phase or adapter fault site does not complete
the memory-fault case. An internal boundary cannot simply assume successful
adapter entry or use a source-side cut assumption to erase earlier failures.
Qualify and reuse entry evidence through the existing path before relying on it
to make a local body check cheaper. See [measurements](performance-and-invalidation.md)
and [current evidence](current-goal.md).

Granularity experiment on the real enclosing component (2026-09-12): one exact
basic block at the existing cleanup loop cut still generates a roughly 300 KB
proof harness and over 33,000 compiled instructions. Its application-control query
remains unresolved at 120 seconds under both the full proof-world runtime and the
four-contract abstraction, despite lower symbolic-execution cost in the latter.
Small control-flow regions alone therefore do not establish manageable proof cost.

The comparison keeps ordinary C, input relations, memory/lifetime facts and boundary
assertions identical. An irrelevant service is forbidden with a checked unreachable
assertion in the diagnostic closure; this does not supply its behavior or qualify the
whole component. The public check retains the actual conditional supplier and is
reported separately. A generated owner temporary also exposes lexical compiler
storage identities as a current limitation of extracted-entry correspondence.

These findings concern proof regions and input machinery. They do not establish
independent component contracts, transitive neighboring-proof reuse or replacement
group activation. Keep the mixed-exit helper boundary open while investigating this
existing whole-operation comparison path. See [current findings](current-goal.md).

Implemented input-reference machine output (2026-09-12): an operation parameter
may declare `exit_projection` using an existing 32-bit register projection at exit.
Current support is a direct nullable byte input with explicit origin-remainder
entry projection and no scalar codec. Destinations are EAX/EBX/ECX/EDX/ESI/EDI;
ESP/EBP, duplicate destinations and overlaps with result/state storage are rejected.
Results must use ordinary scalar register/stack storage in this scope.

The value transported is the original borrowed reference saved before the C call,
not a descriptor the implementation may have changed or a reloaded pointer word.
Normal completion checks its live generation through the actual runtime realizer;
canonical null encodes zero. All references are encoded before parameter outputs
are published, and ordinary result-storage faults prevent their publication.
Authored body effects are not rolled back. Exact fault/effect equivalence remains
an application-proof obligation. No bytes or lifetime are granted by this encoder.

Proof plans and assertions bind the declared outputs. The real Metapad replay now
repairs its scratch argument through production renderers; removing the store fails.
This closes that finite bridge repair, not general residual-state composition or
mixed-exit observation. The full adapter remains blocked. See [current evidence](current-goal.md).

Real normal-port and machine-bridge requirements (2026-09-12): the retained
Metapad transform provides a concrete distinction between a logical component
boundary and its replacement bridge. Its meaningful C result is the removed-byte
count; the caller also needs EBX to denote the input scratch reference after the
region. Returning a second, redundant scratch value from ordinary C solely to
repair that machine register would impose a synthetic API. Instead, the machine
exit relation must be able to project an existing logical parameter back into
caller-visible machine storage, with checked null, identity, extent, permissions,
contents and lifetime. This is a design requirement, not an implemented general
post-parameter codec or checked summary.

Finite execution of the actual next block proves why this matters: mapped result
storage makes both continuations branch identically, yet the copy-back path lacks
the scratch pointer. A diagnostic bridge using live reference realization repairs
that argument without editing the ordinary helper. ECX still differs, so the
experiment does not establish a complete residual frame. Existing clobber checks
are restricted to supported fixed mutable views and cannot be borrowed as a waiver
for a nullable runtime-sized allocation.

Observation scope is separate again. The actual generated run consumer handles
all three direct control kinds alike; a single-step caller can distinguish them.
Bounded tests support investigating an explicit run/continuation relation, but do
not authorize silently widening the current kind-equality rule. A component's
conditional logical proof, its residual bridge obligations, and a replacement
group's activation evidence must remain distinct. See [current evidence](current-goal.md).


Checked nullable operation inputs (2026-09-12): direct borrowed byte views may
use an explicit origin-remainder extent in the private logical kernel when public
lowering validates their current total operation binding against the production
decoder rule. This is representational admission, not caller applicability.
Unbound lowering and use through state, results, nested records or callbacks do
not gain this input rule. Null remains in the entry domain.

A native-view parameter capture observes the borrowed descriptor after all other
capture restorations; it cannot repair corruption or assume descriptor validity.
Owner identity, complete metadata, current origin contents, aliases and lifetime
remain checked. The actual C argument must be stable and decoder-bound. The real
Metapad interface and generated harness now prepare, with 83 Nix tests passing;
its mixed normal exits and actual caller/frame premises still prevent a complete
component qualification. See [current evidence](current-goal.md).


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

Status: proposed design, 2026-09-08. This document records design decisions,
worked examples and implementation acceptance requirements. It is not a new
artifact schema, an implemented checker policy or qualification evidence.

The [broader target review](component-boundary-design-review.md) identifies
corrections to the first draft, additional counterexamples and capability gates.
This revision incorporates its core rules. The first review did not establish
coverage of asynchronous, concurrent or general native application boundaries.

The [final pass](component-boundary-design-review.md#7-final-pass-composition-interpretation-and-evolution)
adds path-dependent interpretation, joint representation coherence, adapter
transparency, absence dependencies and safe adoption requirements. It defines
the stopping rule for this design checkpoint: implement and falsify the core
through the real network rather than continue expanding an abstract wishlist.

The [contextual-bisimulation contract](portable-c-contextual-bisimulation.md)
remains proof authority. The [independent lifting plan](independent-portable-lifting-plan.md)
retains the real-network, public-workflow, pilot, native-link, repository,
export and portability exits. Automatic boundary recommendations remain deferred.
Engine extensions follow this design checkpoint. The contextual contract now
specifies the implemented invocation-scope transport profile; its retained
prefix results and remaining network obligations are recorded in
[the current goal](current-goal.md). The broader design remains proposed.

## 1. Decision and adequacy claim

The conditional native-access implementation now factors untracked permission
into a shared stable function instead of reconstructing a complete map. This is
useful only when entry facts identify the actual admissible context. The real
consumer still admits a failed original argument-stack write and a null portable
call target after the target adapter's fault-channel correction. Valid frame
backing and callable-target facts must be transported from the predecessor or
caller, or those failures must be preserved. They cannot be inferred from equal
register values, the private footprint or a target slot's address. Connected
summary consumption is explicitly blocked under this new contract until its
permission-context transport is checked. Details and evidence are in the
[current goal](current-goal.md).

The native replay of the real prefix (2026-09-12) confirms that permission and
fault domains belong in the boundary relation. The original fragment faults
under native null denial, deliberately permissive admission recreates the
disagreement, and successful original/portable prefixes preserve matching bytes.
This finite replay does not provide a checked memory-map contract. Such a
contract must relate loader metadata, host stack bounds, active priority access
providers and live external ranges, including allocation/release updates. Private
effect footprints remain separate from access permission. A zero-width or
overflowing access must follow the selected runtime's rules; the runtime's
exclusive end must be representable, while existing proof reads allow the final
32-bit byte. That distinction needs a checked correspondence or an explicit
unsupported case. Generated runtime image admission also does not alone prove
agreement with original Windows page protections. These premises cannot be
inferred from reference reconstruction or an unchanged signature.

The real consumer now passes its safety/unwinding and nonvacuity checks, while
five view descriptor assertions remain incomplete. Conditional V14 scheduling
puts observable disagreements ahead of those metadata checks. Ordering may
improve diagnostic latency; it does not turn successful observations into a
complete boundary theorem. The same coverage, progress, state transport and
caller obligations remain required. Legacy receipt orders are preserved, and
exact process reuse is checked across scheduling versions. The real public
comparison now finds an exact-side address-zero store versus a portable empty-view
fault. Its [0, 5120) private stack footprint does not establish native permission
to access address zero, and checking allocation lifetime does not admit untracked
addresses. Permission, frame classification and view validity must agree before
claiming native equivalence. Repair that domain disagreement before the deliberate
wrong-byte control; component independence remains unestablished.


The audited public workflow now reuses all 171 entry processes with zero fresh
entry queries after the actual Metapad C counter edit. Both variants have complete
conditional entry evidence, unchanged entry models and changed paired models.
The public commands take 620.15/50.19 seconds; the baseline uses preceding partial
evidence. Both retain unresolved component obligations. This demonstrates entry
proof independence through the operator path, while complete business-component
composition, contract refinement and neighbor reuse remain acceptance work.
See `practical-assurance/entry-qualified-audit-v2.json`.

The earlier retained real entry has complete conditional assertion, safety and
nonvacuity evidence. Its theorem survives the actual public counter edit:
141 entry processes are reused with fresh solver execution forbidden, while the
paired model changes. This establishes an implemented instance of entry-proof
independence. It does not establish a complete independently liftable business
component, its callers, or the public network edit/refine/repair milestone.
Separate entry-query scheduling budgets now support measuring first qualification
without raising every ordinary component-query deadline.

Independent entry qualification now uses the existing complete assertion,
safety and nonvacuity readers. The compiled site manifest binds property IDs,
descriptions and source functions; repeated descriptions are allowed and every
site must agree with checker discovery. A complete entry theorem remains
conditional on its named runtime contracts. It cannot discharge caller admission,
other regions or activation merely because its prefix relation matches.

The real public counter edit reuses 46 safety-query results and four inventories
while preserving entry bytes and changing the paired model. Its entry remains
incomplete. A small fixture passes and replays all 51 entry queries with fresh
execution forbidden. These results validate partial process independence, not
the complete real component-network workflow. The retained larger-budget probe
passes real entry safety. A further continuation also passes byte-index, scratch
admission and nonvacuity, but reference-address validity remains unresolved.
An added span-bound lemma and aggregate assertion query have not demonstrated
an overall improvement. Boundary adequacy must include inexpensive transport of input bounds
and memory invariants; small application code alone does not establish it.
See [current evidence](current-goal.md) and [phase costs](performance-and-invalidation.md).

Earlier compiled-prefix checkpoint:

The initial compiled-prefix correspondence rule is now integrated into the
conditional public workflow and exercised on the real baseline and counter edit. It preserves exact local symbol identities
and DECL/DEAD order, havoc, assumptions, effects, unknown branch arms and the
complete common helper/static-state environment. Deleted automatic objects and
types must have no references in the matched prefix or retained environment.
Compiler failed-pointer object bindings remain checked. Finite silent paths may
be folded; silent cycles reject so that deletion cannot manufacture progress.
The entry's false assertion marks a guarded frontier, not an assumed unreachable
cut. Its selected real check passes, and disabling the probe produces a violation.
This is a restricted structural relation conditional on full entry qualification;
it is not a general alias theorem or independently assured component. Public
inventory/root binding is checked; full safety/coverage and query routing remain
open. Both models use the ordinary compilation convention, with startup generated
by CBMC for the explicit query root. No initializer or startup mismatch is ignored.

Public entry preparation now implements one artifact boundary justified by the
measured invalidation defect. A real post-cut C edit changes the paired model
but preserves the separate entry GOTO bytes and boundary binding. The production
conditional path checks compiled type/tag closure and exposes preparation
separately from conformance and entry proof. Its packet reader refuses to turn
those unchecked states into proof authority. The original query path is retained.
Source-entry conformance still needs an alias-preserving state mapping and
coverage of every entry-prefix exit before queries can use the new model.
The initial profile permits only discarded nonvolatile parameter values before
BEGIN; stable constants/aliases and other stateful prefixes remain unsupported.
This preparation result does not establish a component theorem or neighboring
proof reuse. See [the measurements](performance-and-invalidation.md).

The 2026-09-11 entry experiment now distinguishes model independence from entry
validity. A compiler-derived proof source omits the real operation's post-cut
body; counter edits and 1,000 added statements leave its GOTO bytes identical,
while boundary type/layout and parameter-escape changes remain dependencies.
The first profile explicitly rejects pre-BEGIN state, including stable aliases
and constants, pending a conformance rule that transports them. It does not
claim general source slicing or change any production API.

A full check then rejects the original and isolated entry models because eager
stack-cache initialization observes bytes before initial-memory facts are
constructed. The production correction defers that cache when facts are
selected; it preserves ordinary byte reads and write-driven cache invalidation.
The corrected order and nonvacuity checks pass and reuse after an actual local
edit, but full entry qualification still times out. A stable compiled model and
reusable selected queries therefore remain insufficient for composition
admission. Entry contracts must include construction order and complete safety,
not only matching state predicates and a reachable witness. Details:
[performance and invalidation](performance-and-invalidation.md).

Use **relational contracts over explicitly owned or shared state**, with internal
proof cuts as a separate way to decompose their verification. Keep original
execution in transfer-v2, typed values in the canonical boundary schema, machine
transport in checked relations/plans, and qualification in the existing evidence
chain. Do not introduce another general program IR or a target-authored evaluator.

The design must support three different kinds of independence:

| Kind | Required property | What it does not imply |
|---|---|---|
| Proof | A consumer model uses a checked contract without either callee body | Arbitrary changes to that contract are compatible |
| Editing | Local C and proof annotations can change without regenerating unrelated consumer queries | Every cut corresponds to a callable function |
| Replacement | Selected implementations and adapters can run together | Individually proved implementations use compatible shared layouts |

A subsystem is a navigation group. A component owns a stable interface and
possibly shared logical state. An operation is one transition through that
interface. A proof region is an internal verification segment. A replacement
group expresses coordinated selection constraints. These are not interchangeable.

The proposal supplies obligations for the sequential, bounded-memory examples
below. Broad-target adequacy remains **unestablished**: the deeper review found
missing distinctions in storage aliasing, open protocols and enduring resource
obligations. This revision corrects those design gaps but does not establish an
implemented general composition theorem. In particular, callback-aware
summaries, factored invariant rules, abstract representation transport and general
progress remain implementation gates. Unknown entry coverage, unmodeled native
observers and unsupported concurrent interference remain visible blockers.

The practical target is dozens or hundreds of useful authoring units with a
small dependency surface each. That does not promise hundreds of independently
replaceable layouts, constant solver time, or complete support for arbitrary
Win32 programs from these rules alone.

The byte-frame experiment now distinguishes a small observation from a small
component proof. A checked input-byte law and event witness make the selected
text assertion tractable, but their real effect guards remain unresolved. The
isolated observation has no reachable runtime reader or allocation lookup; the
surrounding component still executes the native-view machinery. Even its entry
relation, without application effects, produces about 192,000 symbolic steps
and 12 million SAT clauses. Native-view admission and access therefore need their
own reusable contract boundary. A passing entry predicate and nonvacuity do not
replace full entry safety, source confinement or checked composition admission.
Ghost witness creation must preserve existing observation effects; later fills,
releases, reuse and relevant writes must invalidate or update the witness. The
retained hook-removal control rejects a missed write, but does not qualify a
general instrumentation rule. See [the measurements](performance-and-invalidation.md).

The same experiment measures an invalidation boundary: changing a loop counter
after the entry cut changes the entry GOTO hash even though its entry prefix,
header and relation harness do not change. Matched compiler paths and exact
repair isolate the implementation edit. An entry model must actually omit those
dependency bodies to support independent reuse. A policy that merely disregards
changed source/model hashes would lose evidence binding; it is not a solution.

The 2026-09-10 retained allocated-region experiment adds a concrete cost boundary:
an indirect write through a generated view accessor can make symbolic execution
expand unrelated runtime/service callbacks despite a small source region and
real terminating cuts. A prototype with checked write-target dispatch passes all
454 bounds properties and its applicability assertion in 65.12 seconds; the
original model cannot finish one selected bounds property in 120 seconds. A wrong
callback is detected by the prototype. This motivates factoring checked runtime
dispatch, not assuming every small region already has a small proof model.
Because the prototype changes generated adapter code, the specialization still
needs a substitution/equivalence rule bound to the exact sources or an explicitly selected
conditional runtime contract. Its target assertion is necessary but does not by
itself prove the adapter rewrite correct. Full region and network qualification
remain open; see [the measurements](performance-and-invalidation.md).

The subsequent integration selects that substitution through the explicit
`canonical-view-write-dispatch:1` trusted contract. The shared accessor keeps
its native branch, while conditional compilation selects checked forwarding.
The required target assertion is independently enforced by evidence validation;
the conditional policy identifies the substituted overlay. Symbolic and native
forwarding controls pass, but they validate this adapter boundary with
instrumented callbacks, not all heap or lifetime behavior. The first real caller
attempt rejects the retained helper's changed generated-overlay binding. This
illustrates a distinct dependency: changing shared generation can require a
supplier recheck even when its authored implementation and contracts stay
unchanged. It does not demonstrate local implementation-edit invalidation or
neighboring business-proof reuse.

The subsequent receiver-lifetime experiment distinguishes **runtime owner scope**
from **guest object lifetime**. The actual native entry owns an automatic runtime
object while it invokes the application. Factoring that lexical guarantee can
remove expensive interference with the guest heap's dead-object model: an
unregistered prototype passes the previously unresolved receiver check and the
first 1,024 pointer properties. This does not authorize assuming guest liveness,
contents, allocation success or preserved aliases. Native issuer/accessor
controls validate in-call use and detect use after return, with unrelated native
behavior stubbed. A checked nonnull receiver identity is necessary but insufficient:
the binding must come from the live owning scope, must not be silently rebound,
and must not escape that scope. Nested native invocations having distinct owners
does not establish that a single global proof binding models general reentrancy.
Persisted and asynchronous views need another supported ownership rule. Measure
the complete real consumer and enforce exact generation/binding dependencies
before treating this prototype as an implemented trusted contract; see
[the performance record](performance-and-invalidation.md).

Further testing found a stronger solution for the two receiver-lifetime
bottlenecks: **checked state normalization at the cut**. The implemented v2
local-view transport checks the complete restored descriptor, checks its owner
pointer against the current runtime (or null for an empty view), then substitutes
that equal pointer. It assumes no lifetime or heap-content fact. Corrupt owners
must fail before normalization can repair them; expired owners remain subject
to ordinary pointer checks. The v2 owner assertion is mandatory in Python and
JQ, while v1 models retain their original checks and are not relabeled. This
changes the proof header, preserving native accessor bytes and existing helper
bindings. The retained real region now passes its language-safety groups but
still times out on outgoing view-context/metadata/extent checks. This supports
making boundary state explicit to the prover; it does not yet demonstrate
complete, fast, independently editable components.

The next real-consumer measurement separates a stable platform invariant from
individual reference checks. Context identity/runtime fields, issued-origin
selection, address and span checks pass separately; current-world lifetime
remains expensive. Allocation admission already excludes the loaded image.
A helper lemma establishes image-lifetime specialization under that separation,
but checking the frame again at each access does not complete the real query.
Explicitly trusting mapped-image lifetime does let one original application
assertion pass, with an ordinary-C extent corruption still detected. The full
selected region remains incomplete after 1,099.66 seconds; the premise remains
unregistered. Z3 subsequently proves the original caption assertion without
that extra premise in 32.50 seconds. This supports evaluating solver encoding
and scheduling before enlarging the trusted boundary; it does not establish a
complete-region speedup. The pinned broader diagnostic passes safety,
nonvacuity and 15 application queries, but text metadata/extent still time out
and 294 later assertions are deferred. Dynamic text transport remains an open
consumer requirement; passing fixed-image views does not establish that case.
A real extent error is still detected under the four-contract solver policy,
and exact repair reuses that selected query. Public full-component and
neighboring-proof reuse remain separate milestones.

The existing typed source-opacity gate also accepts the actual cleanup C while
rejecting a write-and-restore through its opaque service context, both in about
0.07 seconds including compilation and inventory. The lexical C profile accepts
both. Reuse this existing typed gate as one part of caller confinement, while
keeping source frames, permitted service mutations and runtime-invariant
preservation as separate obligations. This diagnostic does not qualify the
allocating operation for the existing fixed-buffer summary rules.

A subsequent real-consumer experiment separates namespace determinism from
issued-reference validity. The concrete namespace lookup reads allocation count
and five fields per live candidate slot (live flag, native selector, base, size,
native generation); equal projections give equal status/output while preserving
world memory. A missing-generation control fails. Nevertheless, passing the real
address/namespace preservation guards and normalizing those equal fields does
not discharge text metadata/extent. Pure-lookup abstraction also fails to do so.
The surrounding resolver still checks public-range admission, actual lifetime
generation and consistency with recorded origins. A reusable boundary must
therefore include the lifecycle of an issued reference and the transitions that
preserve or invalidate it, not just the pure namespace function's input footprint.
Bytes and observable service effects remain separate checked obligations. These
experiments introduce no supported summary rule or activation authority.

The follow-up cache experiment checks eight allocation fields, public-range
state and the previously observed origin prefix, with exact call arguments and
full resolver fallback. It demonstrates the desired metadata/byte distinction
in 17 reachable bounded scenarios: byte writes preserve reusable metadata while
release, stale generations and conflicting origins invalidate it. Omitting the
actual lifetime generation is unsound even with unchanged native generation.
The real metadata assertion passes in 32.17 seconds, but the current-byte/extent
obligation and arbitrary-state substitution law remain unresolved. A real
generation-bit edit times out; a zero-generation edit is rejected in 84.74
seconds. This is evidence about a candidate footprint, not an
implemented checked summary. Keeping a callee body on misses also falls short of
consumer independence from callee growth. These limits require separate
origin/lifetime preservation and current-memory frame composition rules; they
cannot be inferred from a stable descriptor or a successful cached lookup.

The real cut also demonstrates why freshness must be a relational fact. Its
existing admission permits text and scratch to be overlapping views of the same
object and generation. This is legitimate view aliasing in general, but a cut
after a fresh allocation needs the relevant producer separation fact. The
hand-defined proposal adds it at eight cuts using existing address/extent and
unsigned comparison operators; no synthetic production function is introduced.
Local service views now support `bytes_address` through their checked current
machine coordinate, with the full descriptor codec still mandatory. The public
workflow rejects stale exact-C bindings after this refinement and accepts a
regenerated manifest whose exact source and cut labels are unchanged. This
establishes proposal/preparation behavior, not the refinement theorem. The
selected allocating-predecessor separation check now passes when it uses the
same checked coordinate as the generated invariant. Full predecessor proof,
allocation-outcome reachability and consumer byte preservation remain unresolved.
Separately passing shape/admission and address-equality checks do not discharge
the two executions' current-byte obligations. Incoming normalization must also
wait until every restoration is complete because captures may alias descriptor
members; an address observed before those writes is not a reusable witness.
A model-level disjoint-store frame law cannot supply a missing separation premise.
Preserve aliasing by default; require and check a stronger relation only where
that operation's actual producer and callers justify it.

A reusable runtime invariant therefore needs an owner and lifetime, an entry
establishment rule, permitted state mutations and preservation rules, and exact
native/model evidence dependencies. For mapped images this includes allocation
admission, imported histories, module unload/remap and confinement of private
runtime metadata. The experimental shortcut covers a fixed live image interval;
it grants no heap-object lifetime, byte contents, pointer-origin or permission
facts. Native helper tests and a conditional helper lemma must remain distinct
from establishing the invariant for all callers. Promotion into a checked
summary or an explicit supported trust mode requires its composition and
invalidation rules; a shared predicate name alone supplies no authority.

## 2. What current evidence tells us

Live inspection on 2026-09-08 found useful, deliberately restricted mechanisms:

| Mechanism | Existing role | Design pressure |
|---|---|---|
| V5 interfaces, canonical types, checked boundary plans | Logical values, machine transport, services and lifecycle declarations | A declaration or a lens check does not prove an operation summary |
| Entry/sync engine | Paired segments, current public-memory equality, checked cuts and bounded internal loops | Cut construction and output admission must describe the same state domain |
| Scalar/readable/mutable/shared summary policies | Checked body omission for selected shapes and authority domains | Generalization currently crosses several shape-specific modules |
| Allocation history and origins | Live/retired generations and current bytes at selected cuts | Heap state, visibility and execution-frame coordinates must stay distinct |
| Python and JQ evidence readers | Independent binding and required-assertion checks | A new semantic capability needs a complete rule, not only another accepted field |

The later real notification experiment (`0x5646`–`0x5662`) confirms another
distinction. Its hand-defined operation normalizes, compiles as ordinary C and
consumes the qualified resource-text helper with both helper implementations
absent. However, cleanup reaches that operation through ordinary control flow;
the implemented connected-summary dispatcher substitutes internal CALL events.
Operation-boundary expressiveness alone therefore does not establish parent
summary substitution across an arbitrary region edge. Such substitution needs
checked entry/exit transport and coverage without an invented machine CALL.
The current bounded network uses existing helper/cleanup/caller CALL edges;
this experiment does not prove global absence of indirect entries into the region.

The retained constructor counterexample in
`build/independent-lifting/real-network/cleanup-entry-allocation-v4/transport-check-v2/frame-finding.json`
has entry ESP 8,388,608 and cut ESP 8,388,580. A live allocation
`[8,387,474, 8,387,584)` is disjoint from the entry private window but overlaps the
recomputed cut window by 28 bytes. This is a concrete inconsistency in scope
transport, not evidence that the allocation is impossible.

The same retained model has four original transfers, 167 functions and 10,625
GOTO instructions. Selected service/descriptor checks pass in about 146 seconds;
the complete cut check finds the counterexample in about 177 seconds. These are
retained conditional results, not fresh qualification in this review. They show
why body absence and region count need separate model-cost measurements.

Relevant implementations include
[`bisimulation.py`](../src/spaghetti_extractor/components/bisimulation.py),
[`bisimulation_allocation_cuts.py`](../src/spaghetti_extractor/components/bisimulation_allocation_cuts.py),
[`bisimulation_world.py`](../src/spaghetti_extractor/components/bisimulation_world.py),
[`bisimulation_world_memory.py`](../src/spaghetti_extractor/components/bisimulation_world_memory.py),
[`bisimulation_connected.py`](../src/spaghetti_extractor/components/bisimulation_connected.py),
[`bisimulation_summary_contracts.py`](../src/spaghetti_extractor/components/bisimulation_summary_contracts.py)
and [`relation_ir.py`](../src/spaghetti_extractor/components/relation_ir.py).

## 3. Semantic state and the contract vocabulary

### 3.1 State has identities as well as bytes

For reasoning, describe a paired state as `(M, C, W, K)`:

- `M` is original control, registers and storage; `C` is authored-C control,
  locals and storage. They need not have the same layout.
- `W` records related object instances, their current memory, permissions,
  lifetime and representation relations, plus selected environment/resource state.
- `K` records continuations and the state of admitted interactions, including
  outstanding calls and invariant obligations.

This is mathematical vocabulary for existing mechanisms, not a new serialized
world that every proof must expand. Each obligation sees its relevant projection
and a checked relation to the omitted state.

Distinguish a logical object/reference instance, its address-space mapping and
its backing storage. Each has the identity/lifetime relevant to its role. An
address is a realization through a mapping, not a unique storage identity.
Separate mappings can alias the same backing cells, and subobjects can share a
larger allocation. A view adds bounds, element width and permitted access; it
does not duplicate bytes. Unmapping one view need not retire the backing object
or another mapping. Copy-on-write is an explicit change to the backing relation.
The common heap case may use one identity mapping without requiring every proof
to model virtual memory. Related original/C objects may differ in layout and
cardinality; the correspondence must be explicit.

Integer arithmetic, pointer comparisons, hashes of addresses, escaped pointers
and direct native field access can expose a representation. Their actual
observations must be preserved or connected through checked adapters. Merely
calling a reference opaque cannot hide observations made by remaining code.

Facts name their state phase: operation entry, a particular interaction, cut
entry or current state. `old(buffer)` is a defined snapshot, not whatever input
bytes a later region happens to reconstruct. Each fact has explicit object,
memory and protocol dependencies. Immutable schema facts can persist; a
terminated-prefix fact about mutable memory needs preservation or rechecking.

### 3.2 One contract, with distinct responsibilities

Conceptually write an operation contract as
`C = (Domain, Observations, Entry, Footprint, Protocol, Outcomes, Progress, Dependencies)`.
Represent each part through existing types, relations, effects and proof intent.

| Part | Meaning |
|---|---|
| Domain | Environment, machine/C semantics, arithmetic, capacity and admitted caller conditions |
| Observations | Selected observable values, events, memory, control and timing/readiness behavior, with a checked original/portable environment relation |
| Entry | Paired input relation, including current readable state and required invariants |
| Footprint | Reads, writes, allocation/release, escapes and preserved state, indexed by object ranges or invariant instances |
| Protocol | Ordered calls/responses, callback admission, observations and intermediate obligations |
| Outcomes | Tagged return, continuation, fault and other supported outcomes, each retaining its state relation |
| Progress | How finite segments, repeated cuts, divergence and unmatched steps are handled |
| Dependencies | The exact premises and contract facts used to prove each guarantee |

`Observations` is a checked semantic policy, not an operator switch for hiding
mismatches. Native identity-sensitive clients may require equal addresses; a
different portable service implementation must establish its environment
relation. Observational equivalence under that relation is distinct from
deliberately changing behavior during a port. The domain also includes ambient
state used without explicit arguments: thread-local errors, floating-point mode,
locale, process state and pending external operations when applicable.

Interpretation is path- and phase-dependent. A zero-length branch that never
reads a pointer must not acquire an unconditional readable-view requirement.
Tagged/sentinel variants need checked discriminants and definedness for the
active interpretation only. A structural type or SDK pointer spelling does not
prove that every path dereferences it. The resulting transport must preserve
observable validation/fault order as well as the decoded value.

The interface gives names and types. The representation relation explains their
connection to both implementations. The behavioral contract establishes what
transitions are related. A successful type check, projection round trip or
declared effect establishes only its own part.

Start with concrete relations when needed. Typed buffers and abstract sequences
can coexist with live-register captures elsewhere. Do not require a complete
functional specification before a local equivalence proof is useful. Export
only the additional semantic facts that actual consumers need.

The admitted domain cannot silently remove inconvenient original behavior.
For example, replacing defined machine wraparound with signed-C overflow needs
a checked bound or defined portable arithmetic. Original faults must map to the
selected supported outcomes; undefined C behavior is not a replacement outcome.
Allocation failure, partial service writes and exceptional continuations retain
their own post-state obligations rather than sharing an undifferentiated error
case. Restricting a precondition is valid only when actual callers establish it.

### 3.3 Semantics, execution frames and proof optimizations

Keep four concepts distinct, even if some initially share stored values:

1. An invocation/frame identity and the stack storage that actually belongs to it.
2. The current machine cursor, such as ESP, which changes during execution.
3. The memory visibility/ownership relation, established for admitted observers.
4. A solver cache anchor used to encode known affine addresses cheaply.

A cut cannot change item 3 merely by rebasing item 2 or 4. Stack growth, address
escape, allocation and callback admission may change visibility, but require an
explicit proved transition. Private means that omitted differences cannot be
observed by any admitted context, including native code that constructs addresses;
it is not established solely by the absence of a captured pointer.

The admitted observer set must be closed under native address construction,
aliases, indirect calls and later code loading in the selected domain. Excluding
an unknown observer yields a conditional theorem, not privacy evidence. Calls
that publish a pointer or capability update this observer relation explicitly.

The current `private_anchor` also participates in stack caching and footprints.
Do not reset worlds at one anchor and later mutate this field without checking
those meanings. A stable invocation anchor is one possible concrete lowering,
not the definition of privacy. Dynamic frames and recursion require per-instance
relations rather than a single process-wide root.

## 4. Proof-cut rules

### 4.1 Constructor coverage and preservation

Let `Bq` be the paired relation at cut `q`, and `Gq` the arbitrary-state
constructor used to begin its successor proof. Require both:

- **Coverage:** every actual predecessor state satisfying its outgoing
  obligations has a representation in `Gq` that preserves all relevant
  observations and future behavior.
- **Input validity:** every state generated by `Gq` satisfies the assumptions
  under which the successor theorem is checked.

Thus reachable cut states must be included in the modeled domain, and the
successor is checked universally over that domain. A larger domain can make
proof harder but is safe. A smaller domain silently excludes executions unless
each predecessor proves the restriction. Nonvacuity witnesses are useful
diagnostics, not coverage proofs.

For a predecessor region, execute from its own admitted domain and prove the
outgoing tag, state relation and successor admission together. Entry predicates
are assumptions only in that region's local theorem; real callers or preceding
regions must discharge them before composition becomes unconditional.

### 4.2 What crosses a cut

For each state fragment, choose one checked treatment:

| Treatment | Obligation |
|---|---|
| Carry a value/relation | Reconstruct its current value, phase and identities; establish both directions of the needed transport correspondence |
| Frame unchanged state | Prove no local or admitted environmental effect changes the facts being reused |
| Abstract state | Supply a representation relation and an abstraction rule preserving the observations/future transitions consumers use |
| Forget state | Prove it irrelevant, or allow arbitrary replacements and prove the successor for all of them |

Unmentioned registers do not become zero. A reconstructed reference does not
restore memory. Birth-time zero initialization does not describe a live object
after writes. Retired generations cannot disappear when a stale reference could
still be presented. History can eventually be compressed only under a checked
abstraction preserving future resolve/release behavior.

A fixed bound on *all past allocations* cannot support an indefinitely running
application that repeatedly allocates and frees a single object. Cut transport
must eventually summarize relevant live/retired identities and outstanding
references, with a proved history abstraction or invariant. Generation wrap and
address reuse require their actual semantics. Increasing the history table is
not a solution to this expressiveness limit; until compression is checked,
qualification must expose its finite-history domain.

Every live value must be defined on every path that reaches its cut. Undefined
C locals cannot be read by a marker merely because a proof branch will later
discard them. Snapshot facts crossing several regions need explicit snapshot
transport or an inductive replacement; they must not be rebound to current data.

Within today's policy, current public memory remains equal at cuts. A proposed
abstract memory relation cannot silently replace that check. Such a capability
requires coordinated changes to lowering, composition rules and both readers.

### 4.3 Coverage, joins and progress

All original incoming edges, indirect entries, exceptional transfers and
supported callbacks into owned regions must be accounted for. An unresolved
incoming edge keeps the proof conditional. Join relations preserve alternatives:
`(tag=A and PA) or (tag=B and PB)`, not uncorrelated facts drawn from both paths.

Split/merge proposals change proof structure while preserving ownership and
entry/exit coverage. They recompute affected edge obligations and cycle coverage.
They do not create runtime functions or alter observable interactions.

Initially keep matched barriers and the implemented progress rules: each exact
cycle is cut, and finite uncut source loops must discharge unwinding assertions.
A bound is an asserted domain/progress obligation, not an assumption truncating
execution. A source-only infinite loop cannot match a returning original merely
because its postcondition is unreachable.

More flexible cut alignment needs a well-founded measure for unmatched internal
steps, matching of observable actions and a rule preserving the required
termination/divergence behavior. This is a separate semantic extension. Mutual
recursive contracts require induction or a checked strongly connected proof
group; receipt dependencies cannot justify one another circularly.

## 5. Composition without callee bodies

### 5.1 A paired summary is not two unary specifications

Separate three products:

1. A stable contract and its representation/environment convention.
2. Qualification that the exact original and C implementation pair supplies it.
3. A consumer theorem parameterized by the contract facts it actually assumes.

Suppose the original returns `0` and a replacement returns `1`. Both satisfy
`result <= 1`. That unary postcondition cannot justify coupling their results.
Likewise, equal final bytes cannot justify omitting a callback or changing its
observed intermediate state.

A usable relational summary needs a proved matching rule: for every admitted
related input state, each relevant original behavior has a matching replacement
behavior and conversely where required by contextual bisimulation. Matching
includes outcomes, frame, interactions, lifetime and progress, not just values.
For open interactions it must respond to environment choices as they occur;
it cannot select a match using future callback responses.

Make choice ownership explicit. For each related state, admitted environment
input and original transition chosen so far, a matching replacement transition
must exist using only that history; establish the required reverse direction
as well. Preserve enabled inputs, blocking, termination and selected divergence
observations. Do not replace this obligation with equality of complete successful
traces or with a solver that chooses the environment to avoid a failing branch.
The shared-oracle encoding is valid only for a checked rule with these meanings.

For the deterministic supported subset, paired qualification plus checked
input dependence, frame and progress can justify one shared arbitrary result
or memory transition. A caller then proves its property for all admitted shared
choices. For general stateful/nondeterministic behavior, the summary needs an
explicit paired transition rule. Neither determinism nor hidden-state
independence may be inferred from a C signature.

The summary may overapproximate related outcomes. Extra possibilities can cause
a false proof failure; excluding an actual outcome is unsound. Unary facts may
restrict an already justified paired summary only when its supplier proves
them. A shared arbitrary oracle without that supplier proof remains conditional.

### 5.2 Call rule

At each summarized call:

1. Establish the actual argument, readable-memory, alias and protocol entry
   relation, including original machine-frame and selected-target obligations.
2. Transfer the required access/invariant permissions for the admitted interval.
3. Execute a checked abstract transition or interaction protocol, with neither
   callee implementation in the consumer model.
4. Relate outcomes and current effects, restore required invariants, and frame
   the remainder of the caller state.
5. Continue with only the postrelations actually supplied, retaining their
   dependency and memory/protocol phase.

For service-free sequential calls, a return transition can summarize the whole
call. Calls that permit callbacks or other observers must expose the relevant
intermediate protocol transitions. They cannot become one atomic final-memory
update unless a separately checked atomicity rule permits it.

Persist abstract state across repeated calls. Repeated calls may use independent
overapproximating choices, but consumers cannot assume determinism or result
stability unless those laws are exported and qualified. A callback transcript
must be causal, preserve nesting and admitted target identity, and bind current
memory at each observation.

An operation that returns with pending work transfers enduring obligations to
the resource/protocol state. Its pending record identifies the request instance,
borrowed backing ranges, completion authority and permitted cancellation/races.
Return does not restore borrowed access automatically; a cancellation request
does not establish completion. Those obligations cross later calls and cuts and
must be discharged by the admitted completion, failure or teardown protocol.

Exceptional/nonlocal transitions carry partial effects, handler identity,
unwind actions, invalidated frames/borrows and any resumption state. They are
edges in composition, not merely alternative return values. A handler that can
resume within a region creates another checked entry. Use existing outcome/SEH
authority; unsupported nonlocal or asynchronous rules keep composition incomplete.

### 5.3 Aliases and the frame rule

There is one current value per backing cell on each side. Aliased mappings,
subobjects and overlapping views resolve consistently to those cells, even at
different virtual addresses. A mutable summary updates the union of its writable
footprints with one consistent post-memory relation; it does not choose a new
array independently for each argument. Reads refer to the correctly versioned
pre- or post-state. Overlap of read and write footprints is legal when the
operation contract admits it.

Unchanged facts can be framed when their dependencies are disjoint from every
possible modifying effect, including effects through aliases, callbacks and
resource transitions. Allocation/free footprints include identity metadata.
Bytes outside a writable range remain unchanged on each side, and their existing
cross-side relation remains valid. Equal bytes alone cannot frame liveness.

The frame rule also needs locality of behavior under admissible context
extension and stability under interference. Merely preserving the context's
bytes is insufficient if its allocations change address availability or failure,
or another thread changes a fact between reads. Include allocator/resource
state in dependencies when it affects behavior. For each supported concurrent
rule, prove framed predicates stable under the admitted environment transitions
and that local guarantees preserve neighboring assumptions. Thread identifiers,
TLS and synchronization/event state are part of this relation when consumed.

Footprint expressions are evaluated in a declared phase and checked for bounds,
permissions and arithmetic overflow. Data-dependent footprints need checked
membership rules; they must not select an artificially small range after seeing
which assertion would fail. Hidden reads must either be represented or shown
irrelevant by a checked input-dependence rule.

Begin with bounded ranges, records and explicit protocol state. Do not require
exclusive ownership of all aliases. Distinguish permission to mutate storage
from the existence of a reference to it. Shared readers and sequential writers
can coexist under a checked protocol; concurrency needs additional rules.

### 5.4 Why these rules compose

The intended theorem is conditional substitution: if a consumer pair is checked
using a summary, and a qualified supplier pair implements that summary under
the same conventions, substituting those suppliers preserves the consumer's
contextual-bisimulation result. It requires the following proof structure:

1. Relate initial states using the caller-established entry relation. Carry one
   consistent witness for hidden related state; do not pick incompatible hidden
   states independently at successive calls.
2. For an ordinary regional step, use its local paired theorem. At a cut, use
   constructor coverage to embed its actual successor state in the universally
   checked successor domain, preserving the continuation tag and framed state.
3. At a summarized call, use supplier qualification to match every actual
   transition with an admitted paired summary transition. The consumer theorem
   holds for all such summary transitions, including any extra choices in the
   overapproximation. The frame rule extends the match to untouched context.
4. At an environment interaction, apply the selected open protocol to related
   observations and every admitted response. Establish reentrant entry
   obligations before descending into a callback; continue with its actual
   post-state. Matching cannot depend on future responses.
5. Repeat for finite prefixes, preserving outcome tags and observation traces.
   Extend to divergence only under the explicit progress/productivity rule.
   Run the required reverse matching as well; one-way trace inclusion is not
   silently promoted to contextual bisimulation.

This is a proof outline, not an implementation of the theorem. It explains why
summary coverage, cut coverage, state consistency and progress are separate
obligations. In a finite acyclic dependency graph, suppliers can be discharged
bottom-up. A callback or recursion cycle is not justified by this simple order;
it needs the checked recursive rule or a supported larger proof group.

The composed environment must discharge the joint assumptions for all admitted
executions. Existence of one cooperative environment or one satisfying witness
does not establish activation readiness. Callback/rely cycles need a simultaneous
invariant or induction argument, not mutually citing conditional receipts. The
world relation must remain consistent when new allocations, mappings, requests
or capabilities extend it; witnesses cannot reinterpret earlier escaped values.

## 6. Shared invariants and representation changes

A reusable invariant is a predicate with typed parameters, a defined footprint,
a representation convention, opening/closing rules and checked lemmas. Each
instance has an identity. It is not a target-provided uninterpreted assertion
that every consumer may assume.

Examples are a bounded sequence in a buffer, a jq-style shared value and its
ownership state, or a graphics resource in a live/lost/released protocol state.
Primitive facts about lengths or capabilities can be consumed without unfolding
the representation, once the exporting lemma and composition rule are checked.

Opening an invariant grants the required access to its representation; closing
re-establishes it after mutation. Permissions cannot be duplicated by naming the
same overlapping storage as two invariant instances. An invariant can depend on
other invariants, but dependency cycles need a defined recursive rule.

Before an interaction, close each invariant that the admitted observer may use,
or establish a protocol that explicitly permits observation of the intermediate
state. Assuming a single thread does not exclude synchronous reentrancy. A
callback can mutate state and invalidate pre-call facts even if its final return
value is unchanged. General concurrent delivery needs checked rely/guarantee,
atomicity and memory-model rules; declaration support alone is insufficient.

Representation changes relate logical observations, not necessarily byte
equality or one-to-one objects. For example a segmented array may correspond to
one abstract sequence. Its operations must preserve the same abstract relation,
and escaped native observers must be adapted or included in the replacement
group. Allocation failure, pointer identity and service traces remain observable
unless the selected contract proves otherwise.

Constructive runtime transport remains distinct from logical abstraction.
Many-to-one abstraction does not imply that arbitrary concrete bytes can be
written back safely. Existing exact lens laws stay in force for current plans;
abstract realization needs explicit laws for admitted representatives,
frame/lifetime preservation and observable round trips. It cannot reuse an exact
lens certificate by changing the interpretation of equality.

A compatible representation is fixed for an activation. Live conversion of
already running objects would need an additional migration protocol; ordinary
build-time replacement-group selection does not establish hot-swap safety.

Shared representation parameters and invariant instances must have a jointly
consistent instantiation across selected providers. Pairwise witnesses or equal
interface names are insufficient; checked conversions must compose coherently
around cycles. Bind those constraints in the existing selection/evidence chain
without expanding a global heap in each local proof.

A partial abstraction may omit information and conservatively overapproximate
outcomes. It cannot supply a deterministic guarantee that depends on omitted
information, such as element order discarded by a multiset abstraction. Retain
the necessary hidden relation or refine the abstraction. Persistent formats and
remaining native consumers are observers too; changing an internal layout does
not automatically authorize changing serialization or identity behavior.

### Minimal rule set and deliberate restrictions

Implement a small checked rule set, rather than accepting arbitrary predicates
and hoping that later composition gives them meaning:

| Rule | Premises | Result |
|---|---|---|
| View introduction | Live origin, valid offset/extent, width and permissions | A view of the existing store, retaining alias identity |
| Range update | Admitted write footprint and old/current phase | One new store version; all aliases resolve through it |
| Frame | No modifying effect intersects a fact's byte, lifetime or protocol dependencies | That fact remains valid in the successor state |
| Allocate/retire | Checked service outcome, fresh generation and ownership transition | Current storage and reference validity change together |
| Invariant open/close | Exclusive required mutation permission or the supported shared-access protocol; proved representation predicate | Access to concrete facts, followed by restoration of the same invariant instance |
| Lemma use | Qualified lemma and all instantiated premises, including footprint and domain | Only its named conclusions, with transitive dependencies |
| Call substitution | Entry admission plus qualified paired transition/progress contract | Related outcomes/effects and preserved frame without bodies |
| Cut continuation | Outgoing relation, constructor coverage and successor validity | A local successor theorem applies to the actual state |

For an invariant `I(object, abstract_value)`, opening reveals its checked
representation relation and consumes the permission needed to mutate it; closing
proves `I(object, new_abstract_value)` and returns that permission. Shared readers
cannot manufacture a writer. Persistent pure facts about an immutable abstract
value differ from claims that a mutable object's *current* value is unchanged.
Externally visible abstract values are related across both implementations;
they are not independently chosen at every lemma call.

Initially restrict these rules to the existing finite machine domains, bounded
ranges and reviewed lemma families. A lemma about a sequence prefix can be
checked by the existing local engine with an inductive cut or an adequate finite
domain; unsupported quantifiers, recursion and permission protocols reject.
Do not install universally quantified axioms from a few finite tests. The
small rule set itself needs the composition justification described in section
10; enumerating the names above does not implement it.

This chooses extensibility at the level of reviewed rules and lemma instances.
It avoids adding a separate summary policy for every combination of image/heap,
read/write, local/shared and service/no-service, while allowing the existing
restricted policies to remain until their replacements have equal evidence.

## 7. Worked examples and attempted counterexamples

These examples derive required rules. Except where retained evidence is named,
they are design cases, not claims about qualified target behavior.

### E1. A live allocation crosses a stack-changing cut

Use the retained numeric counterexample from section 2. The operation moves ESP
by 28 bytes without releasing the scratch allocation. Its object identity,
generation, extent and current bytes must remain admitted on both sides.

The predecessor establishes an invocation-scope relation; the successor
transports that same relation and separately reconstructs its current ESP.
If actual stack growth claims overlapping storage, the predecessor must prove
the relevant disjointness or model the real alias; a declaration cannot hide it.
Rebasing a solver cache has no authority to claim storage.

This case rejects both a moving-window constructor and a patch that merely
assumes the allocator returns a more distant address. It does not yet prove
which concrete frame representation is sufficient for every caller. The next
implementation must check input construction, outgoing admission, runtime
reference realization, private-byte comparisons and cache behavior together.

### E2. A terminated prefix inside a larger borrowed view

Let a live object occupy `[4096, 4112)`, and a readable view start at 4100 with
visible extent 12. Suppose byte 4103 is zero while byte 4111 is 7. A registered
four-byte prefix can establish a readable terminator within the view; requiring
the final capacity byte to be zero rejects a legitimate string.

The witness says there exists a current readable zero at offset 3. It does not
say that offset 3 is the first zero. A length result additionally requires the
checked relation excluding earlier zeros. A write through an alias to byte 4103
invalidates the termination fact unless preservation is proved or it is rechecked.
Freeing the object invalidates the reference regardless of those bytes.

The current borrowed-prefix change handles the scoped service-admission issue.
The design generalizes it as a versioned memory fact, keeping object capacity,
visible extent, existence of a terminator and first-terminator position distinct.

### E3. Overlapping mutable arguments

Start with bytes `[1, 2, 3, 4]`. A three-byte move from offset 0 to offset 1
produces `[1, 1, 2, 3]` under snapshot/memmove semantics. A forward byte-copy
loop instead produces `[1, 1, 1, 1]`. An alias beginning at offset 2 must observe
`[2, 3]` after the move.

Independent post-arrays for destination and alias can incorrectly give different
answers at the same address. One object store plus an explicit old-state
relation prevents that. Conversely, a disjoint-only copy contract must reject
this call; it cannot be strengthened to memmove merely because the types match.
Framing an overlapping read-only view as unchanged is also invalid: read-only
describes its access permission, not immunity to writes through another view.

### E4. A cleanup loop, scratch storage and ordinary C

Consider removing byte 1 from a NUL-terminated input. The illustrative original
allocates zeroed scratch, scans `i` input bytes, keeps `j` bytes in scratch,
then copies the resulting string back. A useful loop invariant includes:

```text
0 <= j <= i <= n
scratch[0:j] = filter(input_at_loop_entry[0:i], byte != 1)
scratch[j] = 0
input is unchanged during the scan
scratch and input are live, appropriately sized, and disjoint
```

`n` is the first-NUL position established at entry; bounds include the terminator.
With the loop guard `i < n`, the measure `n-i` decreases. The zero fact follows
from zeroed allocation plus the write footprint, not from reapplying zeroing
at each cut. The base case comes from the allocator branch; the step preserves
the prefix relation; the exit supplies the copy precondition and result relation.

A source loop may use pointers instead of `i` and `j`, provided its captures
relate offsets and progress without undefined pointer arithmetic. Removing or
moving an internal cut can admit a different loop structure without changing
the production signature.

The retained Metapad experiment (2026-09-09) gives a concrete implementation
constraint: a single `scratch[j] == 0` input fact does not establish the next
terminator when the real copy branch advances `j`. Its nine-transfer iteration
passes a universal-probe suffix/frame check with a constructed current-memory
zero suffix; the single-byte variant produces a next-terminator counterexample.
The real iteration recognizes CR/CR/LF, unlike the illustrative byte filter above.
The experiment uses distinct admitted input/scratch instances and installs the
range before heap observations. A public range-fact lowering must preserve that
observation ordering, object lifetime, alias consistency and the complete input
domain, including active versus inactive branches. A sampled assumption at one
arbitrary address is not a constructor for a universally quantified input fact.
The prototype is retained under `real-network/cleanup-zero-suffix-v1/`. The
implemented `memory_facts` filled-suffix rule now preserves these conditions,
with matching construction and outgoing checks and independent receipt rules.
Its real nine-transfer check passes 6,681 properties; a corrupt next output byte
fails. The full ordinary cleanup C is unchanged in the two-cut public proposal
`real-network/public-cleanup-memory-facts-v8/`. This remains conditional region
evidence: the full paired cleanup, actual callers and composed workflow are open.

An in-place filter can have the same final input bytes, including preserved tail
bytes, but omitting scratch allocation may remove an observable allocation
failure or service event. Memory equivalence alone does not authorize that
rewrite. First demonstrate an idiomatic implementation retaining the observable
allocation/service skeleton; hide or remove it only under a checked contract
that justifies doing so. This prevents the design from promising unrestricted
algorithmic cleanup merely because region proofs compose.

### E5. Multiple callers, a join and a loaded service target

One caller supplies a terminated image view; another supplies a live heap view
and retains an alias. The callee may abstract over their storage origins only
after each caller establishes the same readable/current-memory requirements,
with the correct authority and lifetime. Proving the image case cannot qualify
the heap caller by generalizing the parameter name.

Allocation success and failure reach different outcomes. At a join keep
`(success and live scratch) or (failure and null scratch)` together. Combining
`success` from one predecessor with scratch metadata from another invents state.

In the real cleanup, a loaded target must remain related to the selected length
service. The proposed `EBX = current import slot` fact is meaningful only if the
slot has not changed since the load. Either prove that stability or retain a
snapshot/capability for the loaded value and check its target authority at use.
Moving a cut must not convert a historical equality into a current-memory fact.
The current parser rejection of the general projection expression remains a
capability gap; accepting the syntax alone would not settle this semantic issue.

### E6. Shared returned storage, repeated calls and reuse of addresses

`get_text()` returns a view of shared buffer `B`; a consumer saves `p`. A later
operation overwrites `B`, then another consumer reads through `p`. If the
contract grants no snapshot, `p` observes the new bytes. A summary that allocates
fresh storage on each `get_text()` hides the alias and proves false properties.

Track one object generation and a current-memory version through both consumers.
The relation for `p` persists while facts about its old contents do not. If `B`
is released and a new allocation reuses its address, its new generation must
not revive `p`. Address reconstruction and content equality cannot discharge
this lifetime obligation. This example requires stateful summary composition,
not only a mutable argument frame.

### E7. Callback observation of a partially updated record

Suppose a shared record has `(length=0, data=empty)`. An operation stores
`length=1`, calls an admitted observer, then installs a one-element data buffer.
Another implementation installs both fields before the callback. Their final
records agree, but the callback can distinguish them or encounter an invalid
record on the first implementation.

A summary must expose the callback observation and its permitted state. If the
original permits the intermediate state, the contract must describe it; an
always-valid abstract sequence invariant is unsuitable at that interaction.
If the selected environment forbids observation/reentry, that restriction needs
evidence and remains a dependency. Assuming a no-callback contract for an
unknown import is invalid. A later callback write also requires re-establishing
facts used after the call.

The design supports this with explicit protocol phases and invariant access.
The current sequential final-state summary rules do not establish its general
implementation. Initially report unsupported callback composition rather than
silently treating the call as atomic.

### E8. Weak specifications and inconsistent nondeterminism

`return 0` and `return 1` both meet `result in {0,1}` but are distinguishable by
`return callee() == 0`. Their qualification must fail the paired rule even if
both unary checks pass. A summary that arbitrarily chooses one common result
without supplier equivalence evidence would mask this difference.

Likewise, a service that chooses once and returns that value on every call is
distinguishable from a service that chooses independently each time. A consumer
may test equality across two calls. Preserve protocol/abstract state when it is
part of the supplier behavior. Independent choices are a safe overapproximation
for some caller checks, but cannot prove result stability or qualify a supplier
that changes the set of observable traces.

These cases require local pair matching, complete outcome coverage and temporal
state, not a stronger collection of unrelated unary postconditions.

### E9. jq-style shared values and a layout change

As a design case, let `a` and `b` refer to one shared sequence value. A copy-like
operation acquires a live reference; releasing `a` must leave `b` usable; only
the final release can retire the shared payload. A mutation may require unique
access or copy-on-write. The exact target semantics must decide which rule holds.

Factor the payload/value relation, reference ownership and container slots.
A consumer asking for sequence length should use the length lemma without
expanding reference-count arithmetic or every unrelated VM slot. A release
proof needs ownership/lifetime facts but not the whole JSON evaluator.

Changing contiguous storage to chunks can preserve the abstract sequence while
changing physical allocation behavior. It is compatible only if all consumed
observations, including admitted failure/effect behavior, are preserved. A native
consumer that reads fields or retains a direct element pointer prevents a
layout-independent boundary unless it receives a checked adapter or joins the
replacement group. Operation proofs can remain separate within that group.

This is an adequacy requirement for jq, not a recovered specification or proof
of its current implementation. Recursive values and VM call cycles still need
the corresponding induction rule or a larger supported proof region.

### E10. DX-Ball-style resource initialization and failure

Consider `create device -> create surface -> attach`, with failure possible at
each step. A useful abstract state is an ownership/protocol state, not merely
three nullable machine words. If surface creation fails after device creation,
the cleanup path must release exactly the acquired obligations and preserve
any resources owned by the caller.

An interface alias to the same underlying resource cannot become a second
independently owned object just because its pointer differs. Identity and
reference/lifetime operations belong to the selected service contracts. Any
callbacks admitted during initialization must observe the corresponding phase.

This permits separate initialization, use and cleanup operations that share a
small invariant. It rejects unconditional success assumptions, double release,
stale handles and reordering observable service calls. Actual DirectDraw and
COM contracts must establish the identities, failures and observations; these
illustrative phases do not supply them.

### E11. Moving a cut cannot move an observation

Compare `x=1; x=2;` with `x=2;`. A cut between the original stores may require
an intermediate relation the source does not establish. Merging the regions
can make the rewrite provable if no admitted observer sees the intermediate
value and the stores have no other observable effect.

Insert `observe(x)` between the stores: merging cuts no longer helps, because
the trace contains 1 on one side and 2 on the other. Volatile/atomic accesses
or concurrent observers also need their actual semantics. The contract's
observation policy is not an operator-controlled switch for ignoring mismatches.

Similarly, `while (true) {}` cannot replace a returning computation merely by
deleting the exit cut. Coverage and progress are mandatory independently of
whether a return assertion becomes unreachable.

### E12. Local editing, contract refinement and multiple dependency levels

Let `A -> B -> C`, and an independent `D -> C`, consume a buffer operation.
`C` exports a paired frame guarantee and a terminated-prefix guarantee. `B`
exports a derived value fact to `A`; `D` needs only the frame guarantee.

Changing C's implementation while re-proving the same supplied facts should
reuse B, D and A's consumer models and completed queries. C's qualification,
dependency discharge and affected link artifacts change. Revalidation must
still prove that the new C qualifies under the conventions those old theorems
assume.

Removing the terminated-prefix guarantee invalidates B's dependent theorem.
A can retain its conditional theorem against B's old export, but qualification
of the assembled network stays incomplete until B supplies that export again
or A is rechecked against a different one. D may reuse its theorem only if
its actual premise manifest excludes the changed fact and its consequences.

Adding a stronger guarantee can preserve old contracts through a checked
entailment. Strengthening a required precondition is generally incompatible
with old callers. Renaming an interface or retaining its C signature establishes
neither direction of compatibility. A changed internal cut affects adjacent
regions and the enclosing supplier proof; it need not invalidate consumer
theorems that never depended on that cut.

## 8. Artifact ownership, compatibility and operator experience

### 8.1 Responsibility map

| Responsibility | Existing home | Required design discipline |
|---|---|---|
| Types, references and protocol identity | Canonical boundary schema, V5 interface/lifecycle | Keep semantic type and machine layout separate |
| Concrete observation and realization | Relation IR, checked bindings and boundary plans | Explicit phases, permissions and transport laws |
| Behavior and cut obligations | Bisimulation intent/engine and checked summary policies | One specified rule per capability, no target-authored executable predicates |
| Local abstraction lemmas | Existing source/pair supplementary evidence | Bind lemma premises, implementation and footprint; no assertion-only authority |
| Dependency discharge and selection | Existing provider/work-package/native selection | Conditional theorems stay distinct from qualified suppliers |
| Exact implementation and linked execution | Current Python/JQ readers and strong link receipts | Preserve complete evidence binding and independent rejection |

Reuse the relation expression vocabulary, but do not force logical predicates
to be executable writeback lenses. Extending it with an operation must define
its sort, state phase, definedness, footprint, evaluation/lowering and reader
obligations. A generic expression escape hatch is not an acceptable shortcut.

Write down shared semantic requirements once and map them to producer, proof
input construction, outgoing checks, runtime lowering and independent readers.
Do not deduplicate the readers by letting a producer supply its own trusted
obligation list. Missing assertions must remain independently detectable.

### 8.2 Reuse keys and compatibility

The semantic premise manifest of a consumer includes contract fact definitions
and their dependency closure, entry requirements, representation/observation
conventions, environment/progress policy and semantics versions. A fact identifier
without these meanings is not a reusable contract identity.

Every assumption actually admitted to a query counts as a dependency, whether
or not the solver happens to use it. For finer reuse, generate the query with
only selected facts. Do not infer unused assumptions by inspecting a successful
proof or omitting inconvenient hashes.

Absence facts also belong in the premise manifest: no other entry, observer,
writer or callback is a claim about a checked scope/inventory. New discovery,
export or target-selection facts must revalidate affected closure premises even
if existing positive dependency edges and C source remain unchanged. A cached
conditional theorem may survive while its composition discharge becomes stale.

The local theorem additionally binds original slices, authored source and
headers, boundary relations, generated model, tools and proof options. Supplier
discharge binds exact current provider evidence for the premise manifest.
Link evidence binds the selected objects and adapters. Separate these products
only where existing work-package/provider boundaries can express the distinction
or measured invalidation requires a new boundary.

For unchanged conventions, a sufficient contract compatibility check is:
old callers' entry domain implies the new supplier's entry domain, and the new
supplier's guaranteed outcomes/protocol/frame imply every old fact being reused.
For relational/open contracts this must be a checked simulation/entailment with
the appropriate environment variance and progress, not just a postcondition
comparison. Representation changes additionally need checked adapters or
compatible selection constraints. Unsupported entailments conservatively recheck.

This is compatibility for reuse of a consumer theorem, not permission to remove
original behaviors. A supplier with fewer failure outcomes may satisfy a weaker
old specification and still violate original/replacement bisimulation. Exact
pair qualification remains independently necessary. Changes to admitted
observers, thread/interference policy, mapping/lifetime rules or ambient state
invalidate the corresponding premise closure even with identical C interfaces.

### 8.3 The manual workflow

Extend existing `boundary` and `component` proposal/check/work-package commands;
the sequence below is a required interaction design, not new CLI syntax:

1. Select an operation and author boundary facts, seeing original/source sites,
   entry coverage, shared objects and unresolved service/lifetime assumptions.
2. Review a split/merge or contract proposal with its semantic changes and
   predicted affected proofs. Adopt with existing stale-input and recovery rules.
3. Write ordinary C. Keep proof cuts as annotations/intent with no synthetic
   `init/step/finish` API. Show which source constructs the current backend supports.
4. Check locally. Report represented, transported, locally proved, composed and
   activation-qualified separately, including negative or missing obligations.
5. Edit C or a fact. Show which theorem queries were reused, which supplier
   bindings were revalidated and why any consumers were invalidated.

An actionable failure names the fact, exact/source location, relevant object
and phase, a counterexample if available, and the missing rule or premise. It
should distinguish invalid code, insufficient contract, failed transport,
unsupported semantics, stale evidence and timeout. Do not make operators repair
internal digest files or Nix derivation references as routine authoring work.

Show whether each premise is conjectured, assumed, structurally checked,
supplier-proved or discharged by actual callers/environment. A proof under a
conjecture does not prove that conjecture. Results and adoption bind immutable
source/intent snapshots so an asynchronous result cannot qualify later edits.

Keep fallback in explicit total provider selection. Restarting the original
after a replacement has produced observable effects can duplicate them. A
different supported fallback policy would need proved pre-effect admission or
a related resume state; no silent retry or hot switching is introduced here.

Ordinary C means structured functions/loops and normal algorithms within a
declared supported C profile; fixed-width arithmetic and checked boundary/service
types may remain necessary. Native pointers, standard-library calls, arbitrary
malloc ownership and layout changes need their actual supported semantics.
Keep proof witnesses and bookkeeping out of production APIs; performance-critical
helpers may be inlined at build time only under the normal checked toolchain.

Production adapters must preserve the selected observable effects, fault order
and resource behavior. Transactional writeback is valid only under its checked
scope, not for arbitrary original partial writes followed by faults. Lens laws
and exact hashes remain necessary but do not establish this full behavior by
themselves. Ghost operations erased from production have different obligations
from runtime guards, allocations, synchronization and stack consumption.

## 9. Cost model and implementation gates

The ideal local model depends on the region's code, accessible footprint shape,
summary interface and interaction budget, not the size of neighboring bodies.
This is a measurement requirement, not a solver complexity theorem. Alias cases,
invariant instantiations and protocol state can still make local proofs expensive.

Record input preparation, model generation, compiler, symbolic conversion/solver
(separately when measurable), evidence validation and link costs. Keep exact
retained inputs. Change callee size at fixed contract and inspect parent model
bytes, symbols and dependencies; absence of the top-level symbol alone does not
exclude inlined body content or hidden artifact dependencies.

Use arbitrary-byte/sparse memory encodings only with a checked extensional-memory
rule. A fresh universally checked byte probe can establish equality of bounded
memories under the model's conditions; one chosen byte test cannot. Do not expand
every buffer byte, heap object or VM slot merely to name an invariant. Assert
event/allocation/unwind capacity limits rather than truncating behaviors.

| Gate | Required implementation outcome | Design examples |
|---|---|---|
| G0: explicit rules | Review this design; map every supported capability to its input, output, composition, runtime and reader obligations | All |
| G1: consistent transport | Fix real frame/scope transport, preserve current heap and loaded-target facts, complete the full allocating/looping operation under explicit premises | E1, E2, E4, E5 |
| G2: real network independence | Actual multiple caller contexts and service consumer qualify; several dependency levels omit callee bodies; local C edit reuses neighbors through public commands | E3, E6, E8, E12 |
| G3: editable decomposition | Public split/move/merge preserves coverage/progress; contract refinement has measured, accurate invalidation | E4, E5, E11, E12 |
| G4: shared abstraction | Checked factored invariants and lifecycle composition, admitted callback protocol, compatible representation change and unrelated-target reuse | E6, E7, E9, E10 |
| G5: retained exits | Hello, jq and DX-Ball obligations, strong native/link receipts, export, portability and repository validation | Existing plans |

The [broader review's capability matrix](component-boundary-design-review.md#4-coverage-matrix-for-target-families)
adds combination gates for asynchronous work, mapping aliases, nonlocal control,
ambient state, concurrency and long-running history. G1-G3 remain the immediate
sequential implementation workflow; passing them does not discharge those wider
capabilities. Unsupported combinations cannot select a body-free summary.

G1 is not permission to polish isolated plumbing indefinitely. Every extension
must unblock a named real-network step and include a small negative case, then
return to that consumer. G2/G3 are the immediate workflow milestone; no number
of fixture certificates substitutes for them. G4 is required before claiming
general shared-object abstraction; unsupported callbacks cannot be counted as
handled merely because the schema represents them.

Do not expand the current monolithic world into a general VM model first. Do not
replace the semantic engine, adopt a new prover as a prerequisite, build boundary
recommendation heuristics, or remove existing authority checks as part of this
design checkpoint.

## 10. Review outcome and outstanding proof work

The worked examples require the proposed distinctions: identity versus address,
current memory versus snapshots, visibility versus frame coordinates, paired
behavior versus unary facts, and conditional theorem reuse versus supplier
qualification. Removing any of those distinctions admits a concrete failure
above. The design gives each failure an explicit rejecting obligation and allows
useful ordinary-C rewrites without forcing a public function at every cut.

Three implementation proof packages must precede broad capability claims:

1. **Transport:** constructor coverage, relation validity and observationally
   adequate reconstruction for each supported boundary form, including memory,
   lifetime, tags and progress. Check production and proof lowerings agree.
2. **Composition:** substitution of the qualified paired summary into an open
   consumer preserves contextual behavior, including the frame, environment
   choices and repeated interactions. Prove rules per supported scope rather
   than treating arbitrary predicates as summaries.
3. **Abstraction:** invariant opening/closing, representation realization and
   compatibility rules preserve the observations of all admitted native and
   portable consumers. Verify recursive/concurrent rules before enabling them.

The equations and examples here are proof specifications and reasoning, not
machine-checked meta-theorems. Passing a finite example or CBMC instance would
not establish those general packages. Conversely, a full new general-purpose
logic is not required before delivering G1-G3 in an explicitly checked subset.

### Reproducible finite review checks

The following self-contained Python checks exercise the arithmetic and small
counterexamples used in E1-E4 and E7-E8. They do not invoke the semantic engine,
prove a general composition rule, or qualify a target. In particular the cleanup
comparison deliberately checks only memory; E4 explains its missing allocation
and interaction obligations. Extract this fenced block and run it with Python 3.
The review run checked 2,430 copy cases (180 distinguish forward copy from move),
63 cleanup-memory cases, and the explicit frame/prefix/trace counterexamples.

```python
from itertools import product
import json

entry_esp, cut_esp = 8388608, 8388580
base, size = 8387474, 110
entry_low, cut_low = entry_esp - 1024, cut_esp - 1024
assert base + size <= entry_low
overlap = max(0, min(base + size, cut_esp) - max(base, cut_low))
assert overlap == 28

view = [9, 8, 7, 0] + [6] * 7 + [7]
assert len(view) == 12 and view[3] == 0 and view[-1] != 0
earlier_zero = [0] + view[1:]
assert earlier_zero[3] == 0 and earlier_zero.index(0) != 3
alias_write = view.copy()
alias_write[3] = 5
assert 0 not in alias_write

move_cases = forward_copy_mismatches = 0
for data in product(range(3), repeat=4):
    for count in range(1, 5):
        for src in range(5 - count):
            for dst in range(5 - count):
                expected = list(data)
                expected[dst:dst + count] = data[src:src + count]
                actual = list(data)
                for i in range(count):
                    actual[dst + i] = actual[src + i]
                move_cases += 1
                forward_copy_mismatches += actual != expected
assert forward_copy_mismatches > 0
old = [1, 2, 3, 4]
moved = old.copy()
moved[1:4] = old[0:3]
assert moved == [1, 1, 2, 3] and moved[2:4] == [2, 3]

cleanup_cases = 0
for n in range(6):
    for payload in product((1, 2), repeat=n):
        original = list(payload) + [0, 7, 8]
        scratch = [0] * (n + 1)
        j = 0
        for i in range(n + 1):
            assert 0 <= j <= i <= n
            assert scratch[:j] == [x for x in payload[:i] if x != 1]
            assert scratch[j] == 0
            if i < n and payload[i] != 1:
                scratch[j] = payload[i]
                j += 1
        copied_back = original.copy()
        copied_back[:j + 1] = scratch[:j + 1]
        in_place = original.copy()
        k = 0
        for i in range(n):
            if in_place[i] != 1:
                in_place[k] = in_place[i]
                k += 1
        in_place[k] = 0
        assert in_place == copied_back
        assert in_place[k + 1:] == original[k + 1:]
        cleanup_cases += 1

assert all(result <= 1 for result in (0, 1))
assert (0 == 0) != (1 == 0)  # same unary spec, different caller result
persistent = {(0, 0), (1, 1)}
independent = set(product((0, 1), repeat=2))
assert persistent < independent
assert (1, 0) != (1, 1)  # observer sees different intermediate records

print(json.dumps({
    "authorizing": False,
    "moving_window_overlap_bytes": overlap,
    "move_cases": move_cases,
    "forward_copy_mismatches": forward_copy_mismatches,
    "cleanup_memory_cases": cleanup_cases,
    "scope": "finite design examples only; no engine or target qualification",
}, indent=2))
```

Background used to check the design vocabulary: Reynolds's
[separation-logic paper](https://www.cs.cmu.edu/~jcr/seplogic.pdf) provides local
heap reasoning with a frame rule; the [Iris documentation](https://plv.mpi-sws.org/iris/appendix-3.4.pdf)
makes invariant access and its restrictions explicit; CompCert's
[Smallstep development](https://compcert.org/doc/html/compcert.common.Smallstep.html)
defines simulations, well-founded matching and composition. These are design
references, not evidence that this repository implements their rules, nor a
proposal to import their entire frameworks.


### Compiler-bound authored service-call projection (v94)

Manual source anchors now reuse the public source-edit inventory compiler and
inert-marker correspondence. A restricted single-call projection accounts for
all compiled instructions: fresh view storage, the service invocation, its exact
result copy, and the compiler temporary lifetime end. The existing structural
cut checker rejects internal branches/cycles and incoming edges bypassing entry.
The service context expression, constant scalar arguments, result type and type
closure remain bound; source text anchors alone establish no correspondence.

This projection introduces only a proof-model fragment. The ordinary caller API
and surrounding implementation remain intact. A projected region still needs
incoming context/service-table admission, a supplier transition and functional
comparison with its selected original behavior. Its outgoing live view does not
by itself establish caller reachability, preserved heap lifetime, string safety,
complete operation coverage or progress. Public feedback identifies preparation
as non-authorizing and functional proof as pending. General mutable regions,
multiple outcomes and representation changes continue to require their existing
state, memory and progress relations; they cannot be squeezed into this narrow
projection by dropping instructions or outputs.
