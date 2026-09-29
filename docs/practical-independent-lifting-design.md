# Practical independent lifting

Status: accepted implementation design, 2026-09-15. The operator has accepted
the product direction: make modular lifting useful without requiring universal
formal verification. This document specifies the workflow; the
[current goal ledger](current-goal.md) records implemented demonstrations and
remaining verification. Design requirements alone are not completion evidence.

Scope correction, 2026-09-29: the deliverable is idiomatic application C that
builds into a Windows binary. Windows runtimes are supported dependencies; Wine
in a headless Wayland desktop is the preferred validation environment. Porting
the application to other operating systems is outside project scope. Earlier
portability experiments remain evidence, not a delivery prerequisite.

The [completed caller milestone](baselines/2026-09-15-reusable-caller-composition.md)
demonstrates local proof and neighbor reuse for supported finite callers.
This design changes subsequent sequencing: practical authoring, local validation
and experimental integration come first; stronger assurance can be added without
changing the component's identity or rewriting its implementation.
The existing [contextual-bisimulation contract](portable-c-contextual-bisimulation.md)
continues to define strong qualification. Experimental execution has a different,
explicit policy and must never manufacture that qualification.

The [workbench review](practical-lifting-workbench-review.md) refines this proposal:
use a consistently supported restricted C dialect, begin with one concrete test
driver, and introduce controlled dependency isolation incrementally. It supplies
the detailed operator sketch and takes precedence on initial sequencing.

The subsequent [behavior-faithful C workflow milestone](behavior-faithful-component-workflow-plan.md)
supplies the active implementation sequence after G1–G6 and the larger jq trial.
Resource checks follow explicit contracts; they do not impose universal memory
safety or a C borrow checker. Preserve scoped original defects and distinguish
behavioral differences, resource diagnostics and failed composition premises.

## 1. Product contract

An operator can select a meaningful original operation, establish a useful
boundary, write ordinary C, compare it with the original locally, inspect a
concrete mismatch, and try the replacement in an explicitly experimental build.
Neighboring implementations need not be understood or revalidated locally after
every edit. Their assumed contracts and the current evidence supporting those
contracts remain visible.

Independence means working against a boundary. Establishing that boundary may
require investigating callers, shared state and services. Integration still tests
whether the actual surroundings satisfy it. We do not promise to eliminate those
tasks or infer complete contracts from finite observations.

The default development cycle is:

```text
review boundary -> edit ordinary C -> compile -> local comparison -> inspect/repair
                                              |
                                  optional focused proof
                                              |
                           experimental integration and execution
```

Formal proof is a selectable source of evidence, not the universal gate in this
cycle. An unsupported proof shape or proof timeout does not prevent local testing
or an otherwise eligible experimental run. A known behavioral mismatch remains
a failure, regardless of which verification method found it.

Here, ordinary C may mean a documented subset of standard C. The operator has
explicitly accepted that restriction provided the infrastructure supports it
ergonomically. Generated headers, state/service helpers, compilation commands,
fixtures and diagnostics must support the same dialect. Dialect conformance,
executable bindings and proof-rule applicability are separate checks: valid code
can be executable even when no formal composition rule covers its boundary.

## 2. One component model, several kinds of evidence

Keep existing component IDs, semantic slices, V5 interfaces, source V3 packages,
bindings, relations and V6 work packages. The practical path must not inherit the
finite caller checker's one-operation/one-supplier restrictions merely because
that checker is the most recent implementation. Its applicability is reported
per check. Concrete execution can exercise loops and stateful operations before
their general formal composition rules are implemented.

Separate four things that currently tend to be presented together:

| Concern | Meaning | Source of authority |
|---|---|---|
| Boundary meaning | Admitted inputs, object relationships, outcomes, observations and dependency requirements | Reviewed interface/binding/relation inputs; review alone is not proof |
| Executable setup | How to construct states, call each side, intercept services and compare observations | Bound adapter and fixture implementations, with their own validation |
| Evidence | Concrete tests, monitored executions, conditional proofs and qualified proofs | Exact retained results and their stated scope |
| Selection policy | Which evidence and assumptions permit this particular build/run | Explicit project/configuration policy, separate from evidence |

Do not compress assurance into a score or a ladder where enough tests become a
proof. Show independent facets, including structural readiness, original-scope
coverage, local comparison, dependency assumptions, formal obligations, integration,
portability and freshness. For example, a component may have passing local tests,
a proved arithmetic region, an assumed allocator contract, untested callbacks
and permission for experimental execution, while strong qualification is missing.

An operator can continue authoring when any facet is incomplete. The UI explains
which requested action that incompleteness prevents. Missing formal evidence
blocks strong qualification; it need not block practical validation. Missing
executable argument transport prevents invoking that boundary at all.

A proof of one bounds condition or unary postcondition is displayed as that
specific result. It does not become a component-equivalence badge. Likewise,
agreement with a faithful-C oracle is conditional on its recovered semantics;
native-original comparison supplies a different check on that assumption. Record
the oracle kind rather than treating every original-side execution as interchangeable.

## 3. Minimum useful boundary

Start with the information necessary to run and observe the selected operation:

| Boundary part | Initial practical representation |
|---|---|
| Scope | Original entries/continuations, owned units and known outside entries; unresolved coverage stays visible |
| Inputs | Scalars, bounded byte views, typed fields and explicit object/handle references |
| Shared state | Relevant contents, alias relationships, access permissions and lifetime expectations |
| Interactions | Services called, arguments, responses, significant intermediate observations and callback expectations |
| Outcomes | Returns, errors, faults, exceptions or continuations supported by the adapter |
| Observation | What is compared, when it is compared, and any deliberate abstraction or ignored detail |
| Assumptions | Named dependencies, applicability conditions and unsupported behaviors |

These are reviewed claims initially. Some can be mechanically checked, exercised
with tests or monitored at runtime. Others can be formally proved later. Avoid
requiring a mathematical specification of the entire algorithm: executing the
original provides the initial behavioral oracle.

The authoring surface should expose these choices concisely. Existing canonical
JSON remains the machine representation; addresses, register transport and hashes
are derived or isolated in the binding view. Common object and service fixtures
are reusable templates. Target-specific setup C is permitted for constructing
real OS objects, but remains explicit test code with bound inputs, not a hidden
proof rule or a required production Python/Nix extension.

A test-only predicate may execute as fixture code. It cannot silently become a
formal assumption or checked summary. A formal check still needs an implemented
typed meaning for every predicate it uses. Unsupported formal meaning leaves
that check unavailable while practical execution remains possible.

Narrowing a contract after a mismatch is an observable contract change. Replay
retained caller observations and report excluded cases. Do not let an operator
accidentally turn a discovered bug into a passing test by dropping its input from
the admitted domain. An intentional behavior change gets a distinct specification
and comparison policy rather than an equivalence claim.

## 4. Three complementary execution modes

These are capabilities to introduce incrementally, not three prerequisites for
local authoring. A first differential driver can execute pinned real dependencies
on both sides, with isolated fixture state. That result depends on their exact
implementations. Replace expensive or awkward dependencies with controlled
responses when local isolation warrants the extra setup. Dependency choice is per
check, and may mix real and controlled suppliers where the adapters support it.

### Local comparison with controlled dependencies

Execute the original slice and ordinary C against the same logical inputs and
scripted service responses. Generated slice harnesses omit supplier implementation
bodies. A native-image oracle may contain those bodies physically; interception
must establish that the controlled calls do not execute them. Validate service
identity, argument relationships and relevant current
memory before delivering a shared response. Comparing only final return values
would miss wrong service arguments and effects overwritten by later operations.

These runs establish agreement on concrete cases under the scripted dependencies.
They do not establish that actual suppliers satisfy those scripts. Independently
exercise each edited supplier against its contract and run affected integration
tests. A mock that is consistent with a declaration is not evidence about the
real implementation.

### Replay of captured interactions

Capture input state and boundary events from a supported original execution,
then replay them against the lifted implementation. Bind captures to the original
binary/slice, contract, adapter, environment and observation policy. A replay
validates matching call inputs before returning the recorded result or applying
recorded writes. A changed call sequence is a mismatch or requires an explicit
supported observational relation; it is not repaired by silently resynchronizing.

Capture is one way to obtain test inputs, not a prerequisite for every component.
Retained faithful C and generated object fixtures provide a cheaper first path.
Capturing an opaque native pointer does not capture the object it names. Record
object identity, relevant storage, aliasing and lifetime, or use an explicit
fixture factory. If neither is available, the case is not replayable.

### Integration with actual dependencies

Run selected real implementations and runtime services together. This exercises
the contract assumptions that local mocks and replay deliberately hold fixed.
Keep its results separate: a supplier edit may preserve every consumer local
result while invalidating the integration result that used its old binary.

Actual side effects must not accidentally execute twice against the same live
state. Each differential side gets fresh fixture state or isolated external
resources; supported services can instead be recorded and replayed. A DLL handle,
window, file or allocation cannot be cloned by copying its numeric address.

## 5. Inputs, observations and diagnostics

Use three input sources: curated regression cases, operator/captured examples,
and generated cases. Begin with deterministic generators for bounded buffers,
scalars and small object graphs. Then add coverage-guided mutation behind the
same harness. LLVM's [libFuzzer interface](https://llvm.org/docs/LibFuzzer.html)
is a useful reusable runner model; no new fuzzing engine is required.

Construction and minimization must preserve intended aliases, interior references,
ownership and protocol state. Keep admitted-input tests distinct from deliberate
contract-violation tests. Report empty domains, rejected-case counts and generator
limits so a campaign cannot appear successful because it executed nothing useful.

Compare outputs, current observed bytes/fields, object identity relationships,
observable allocation/release behavior and ordered service events. Preserve
relevant untouched state through snapshots or supported access instrumentation.
Do not claim that a sampled comparison proves the absence of all hidden accesses.
Adapter capabilities say exactly which reads/writes and native service effects
are observable. Equal raw addresses across processes are not an object relation.

Start with layout-preserving correspondence. Later, permit different layouts
through explicit logical observations such as sequence contents and ownership
relationships. Do not automatically ignore padding, internal allocations or
timing unless the boundary states why they are outside the observation policy.

For supported source/toolchain combinations, add sanitizers as independent
checks. [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)
can detect classes of memory errors in executed instrumented code; it is not a
general proof of lifetime correctness or coverage of native libraries. Report
instrumented scope and unsupported configurations. Optional sanitizer support
must not become a new universal prerequisite for the practical path.

Each failure includes exact source/binary locations where available, the initial
state, first divergent event, expected/actual values, assumption provenance and
a replay command. Minimized cases become permanent regressions. Distinguish:

- Behavioral mismatch on an admitted case.
- Boundary assumption violated by a caller or supplier.
- Invalid generated setup, unavailable oracle or unsupported observation.
- Source compile failure or detected undefined behavior.
- Runtime failure, timeout, nondeterministic/inconclusive replay or stale evidence.
- Formal counterexample versus an unfinished/unsupported proof.

A timeout is not evidence that the two implementations diverge. Independent
nondeterministic executions need controlled external choices or an explicit
comparison relation; arbitrary output filtering would hide real differences.
An original crash also needs classification against the admitted domain and
declared fault outcomes, rather than being treated automatically as bad test data.

## 6. Independence and invalidation

Use the existing separation between stable contract meaning and exact supplier
evidence for both tests and proofs. A local test result binds its own original and
lifted implementations, contract, corpus/generator, scripted dependencies,
observation policy, adapters, tools and execution environment. It does not depend
on real supplier bodies when those bodies were absent from that test.

| Change | Work that becomes stale | Work that can remain reusable |
|---|---|---|
| Local C edit | Its compilation, comparisons, selected proofs and affected integration/build results | Other components' local results under unchanged contracts |
| Supplier implementation, same contract | Supplier conformance evidence, consumer comparisons executing it, and integrations/builds selecting it | Consumer comparisons with controlled dependencies and proofs under the unchanged contract |
| Consumed contract meaning | Dependent comparisons/proofs and applicable integration results | Unrelated components and facts |
| New tests or stronger evidence, same meaning | Campaign/report and execution-eligibility assessment | Existing exact local proofs and unrelated tests |
| Discovered false dependency assumption | Runtime applicability/readiness of affected consumers | A theorem explicitly conditional on that assumption, visibly insufficient for execution eligibility |
| Representation, adapter, oracle or checker semantics | Every result consuming the changed meaning | Results with independently unchanged semantic inputs |

Reuse means the earlier local result is still valid for its stated inputs and
assumptions. It does not mean the edited program has already passed integration.
Practical compatibility can be reviewed and tested; label that basis explicitly.
It must not stand in for a formal implication theorem when importing a proof
under a different contract. A changed signature alone proves neither compatibility
nor incompatibility of the full behavior.

Track dependencies as a graph, including assumption cycles. Mocked components
can be developed in a cycle, but their mutually assumed contracts do not establish
application correctness. Actual cyclic integration and any later induction proof
have separate results. New evidence changes the graph's readiness without forcing
unchanged local queries to execute again.

## 7. Experimental execution without false qualification

The current `candidate-test-suite.nix` requires a complete `NativeRealizationV2`
before execution. Its receipt also explicitly says the original binary was not
executed. Neither product can be reused unchanged as a practical differential
or experimental-execution receipt.
The per-case runner in `candidate-test-aggregate.nix` independently enforces the
strong realization and actual binary digest. Extract a shared typed admission
boundary for practical execution; changing only the outer suite gate is insufficient.

Introduce an explicit project/configuration execution policy with two routes:

| Route | Admission | Claim |
|---|---|---|
| Qualified | Existing complete qualification, provider selection and native realization | Existing strong policy, unchanged |
| Experimental | Buildable bound adapters and objects; an explicit implementation selection; required practical checks; named accepted unresolved assumptions | This exact selected build may run under the experimental policy; equivalence is not universally established |

Experimental construction still checks identities, implemented ABI/argument
transport, linker symbols, object availability, selected ownership and compatible
representation groups. It permits unresolved semantic claims and incomplete
formal proofs. It does not pretend an unimplemented adapter can execute.
Acceptance of assumptions is recorded in project policy and persists for its
declared scope; it need not cause repeated confirmation on ordinary edits.

The default experimental readiness policy requires current compilation and the
selected smoke/regression campaign, with no known unresolved admitted-input
mismatch. Missing broad formal proofs remain reported, not execution blockers.
Running a known failing case to debug it is a separately identified diagnostic
action; it must not produce a passing readiness record. Policies can require
additional focused proofs for selected components without making them mandatory
everywhere.

Use an experimental execution manifest with a distinct format/kind, binding the
policy, selected implementations, adapters, runtime, accepted assumptions, test
results and actual linked binary. It cannot deserialize as a qualified provider,
strong implementation selection or strong native-realization receipt. It contains
no fabricated `qualification_sha256`. Its experimental execution permission is
separate from existing proof `authorizing` flags, which remain false as appropriate.

Share low-level materialization, compilation, linker validation and runner code.
Extract neutral operations beneath the policy-specific entry points where needed;
do not add a permissive boolean to every strong reader. The different execution
manifest is justified by a different authority boundary, not a second component
graph, runtime or artifact database.

Remaining code may use explicitly selected faithful implementations where they
are executable. A native-backed original island is an additional backend capability,
not something to assume already available or call portable. Unknown boundaries
stay inside a larger original region until an adapter is available. No silent
fallback after replacement code has already produced effects: rebuilding or
relaunching the last known configuration is the recovery path unless a future
explicit transactional adapter establishes safe runtime fallback.

Experimental export may produce clearly labelled runnable/source artifacts.
Portability remains separate: running under Wine or wrapping Win32 calls in C
does not establish a standalone alternate-platform implementation. Existing
qualified export and portability gates retain their requirements.

Every run declares its scope: a component-network driver, a selected original
entry, or a full application configuration. An executable network is not whole-jq
completion. Missing original semantics, unrecovered control flow or unavailable
runtime transport can still prevent a wider build even when formal proof is
optional. The interface must distinguish these execution gaps from proof gaps.

## 8. Operator experience and scheduling

Keep `boundary inspect/propose/adopt`, `component start/check`, work packages and
the target SDK. Add practical validation and execution-policy selection to these
existing workflows. Final flag spelling and schema versions are implementation
decisions; no new command syntax is promised by this document.

The component view shows the source and original locations beside the boundary,
the exact dependencies being substituted, local results, untested interactions
and the next available actions. Prefer a message such as “the replacement read
the old window handle before a service that changed it” over a raw solver
property name. The advanced view retains full memory/call traces and evidence.

Suggested scheduling defaults, to be measured on the first real network:

- On edit: cached source preparation plus a deterministic small regression set.
- On demand: a bounded exploratory campaign, initially targeting tens of seconds.
- On demand/background: selected proofs with an explicit budget and cancellation.
- Before an experimental run: only stale required checks and affected integration.

Keep latency measurements outside semantic identities. Persist corpus entries,
seeds and results in existing artifact storage; use Nix for immutable preparation,
toolchains and builds. Interactive mutable corpus collection sits outside a Nix
derivation until snapshotted. Runtime outcomes that are nondeterministic or depend
on uncontrolled external state must not be cached as universally reproducible
facts. A stronger campaign supplements rather than erases earlier failures.

Validate shared dependency evidence once per request graph where semantics allow;
use existing content-addressed reuse instead of a second cache. Avoid whole-pilot
rebuilds for local testing. Report preparation, compilation, execution, evidence
validation and linking separately. Larger unrelated program size should add no
supplier body or global heap model to a comparison with controlled dependencies.
A check using real implementations reports and binds its actual dependency set.

## 9. Worked design tests

### jq shared-value operation

Select actual operations after inspecting retained inputs; the initial roles are
value retention, reading/updating a container and release. Construct small value
graphs with shared backing storage, interior views where applicable, empty values
and allocation-failure cases. Preserve graph identity while creating independent
original/source worlds. Start with the original representation.

A consumer tests against scripted supplier operations without their bodies. An
edited supplier runs its own conformance/differential cases; the real network runs
integration separately. A missing retain or premature release should produce a
replayable lifetime/content mismatch. If local mocks miss it, the report attributes
the integration failure to the violated dependency assumption rather than calling
every unchanged consumer's local test stale.

No universal heap invariant is required for this finite campaign. An operator can
later add focused proofs of particular ownership or arithmetic obligations. This
is also how multiple suppliers and stateful operations can become useful before
their general proof-summary composition is available.

### DX-Ball service lifecycle and callback

Use a retained real service sequence with success, partial-initialization failure
and cleanup. Add a supported callback schedule that changes a handle while an
operation is suspended. Compare ordered events and the state visible at callback
entry; do not model the whole call as atomic without declaring that assumption.
Windows [SendMessage behavior](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessage)
illustrates why even apparently synchronous UI calls require such attention.

One callback schedule tests one behavior, not all reentrancy. Unsupported schedules
remain visible and can be kept within a larger native/faithful component. A
reference-counting or lifecycle protocol may initially be reviewed and tested,
then formally checked when its value justifies the effort.

### Representation change

After layout-preserving operation tests work, replace a private storage layout
and compare logical contents, alias behavior and lifetime at its public boundary.
Select all operations sharing that layout as a replacement group. Reject a mixed
selection with a known incompatible native reader. Escaped access whose privacy
is not established stays an explicit assumption or blocks that particular layout
change; it does not block unrelated source cleanup.

### Failure of the harness itself

Deliberately break alias-preserving input cloning, change a replayed service
argument, omit an observable store, narrow the input domain, remove a callback,
change a loaded binary after testing and mislabel experimental evidence as strong.
Each must yield the corresponding invalid-setup, mismatch, coverage-change,
stale-input or authority diagnostic. Passing original/source comparisons alone
does not establish that the oracle and observation adapter are adequate.

## 10. Reuse of existing systems

| Existing owner | Planned extension | Boundary to preserve |
|---|---|---|
| `components/interface_package_v5.py`, binding and relation modules | Concise review projections and executable fixture descriptions over existing semantics | No parallel interface IR; formal lowering only for implemented meanings |
| `components/work_package_v6.py`, `commands/component_start.py`, `commands/workflows.py` | Materialize local test setup, reviewed assumptions and source-linked feedback | Work packages remain editing projections; schemas are versioned where required |
| `operator/source_check.py`, `operator/source_call_check.py` | Schedule independent compile, practical validation and optional formal facets | Practical success cannot become a checked supplier summary |
| `operator/work_status.py`, `operator/projections.py` | Project validation, applicability and execution-readiness facets | Existing strict authority vocabulary is not silently reinterpreted |
| Existing source/region/supplier evidence readers | Retain exact proof reuse and show consumed assumptions | No arbitrary predicates or tests promoted into formal guarantees |
| Native integration fixtures and `testkit` | Reusable object factories, oracle adapters, negative controls and phase timings | Native and modeled-oracle evidence retain different scope |
| Candidate Nix suite/aggregate and native materialization | Share runners/build plumbing under distinct qualified and experimental gates | Existing candidate-only and strong-realization receipts retain their meaning |
| Target SDK, component source packages and Nix closures | Public construction, selective rebuilding and reproducible toolchains | No per-component production Python/Nix phase, second cache or status database |

One local validation result binds case/corpus results, oracle and adapter identity,
observation scope and assumptions. Extend an existing suitable result family where
possible; introduce a versioned format only if its semantics do not fit. The
experimental execution manifest is the one deliberate new authorization boundary.
Neither artifact replaces the existing formal proof formats.

The original executable, when used as an oracle, is an explicit bound oracle
input. It must not be smuggled through candidate `runtimeData`, whose current
checks and receipts intentionally exclude that use.

## 11. Delivery sequence and acceptance

1. **Public local validation.** Reuse Metapad as a quick regression consumer, then
   construct a hand-defined jq network that combines multiple supplier operations
   and mutable shared values. Exercise original/source comparisons without first
   implementing general formal heap composition. Prepare, edit, validate and
   replay through public tools; no internal path/hash editing is required.
2. **Independent edit and evidence flow.** Make a real supplier implementation
   change under the same contract. Reuse unchanged consumer local results, recheck
   the supplier, and rerun only integrations selecting it. Detect a deliberately
   false ownership assumption and show affected consumers. Refining a contract
   reruns relevant practical checks without demanding an unavailable formal proof.
3. **Experimental integration.** Build and run an explicitly selected mixture of
   executable faithful and lifted operations. Bind the actual linked bytes and
   policy; demonstrate that all existing strong readers reject the experimental
   manifest. An unsupported proof and a bounded proof timeout must not prevent
   this run when the practical policy is otherwise satisfied.
4. **Different interaction shape.** Repeat with a real DX-Ball lifecycle/service
   consumer and a supported callback or failure sequence. Record every adapter
   capability added. The experiment must not depend on duplicating Metapad-specific
   orchestration. Validate the first representation change only after this local
   workflow is useful.

Use the more incremental ordering in the
[workbench review](practical-lifting-workbench-review.md#7-a-narrower-delivery-sequence)
to implement this scope: a real-dependency driver can precede controlled isolation.
The first milestone is steps 1–3 as a usable vertical workflow, including the
negative controls. It is not another collection of proof primitives. Keep optional
proofs available and demonstrate at least one existing proof reused alongside
practical-only evidence, with the distinction visible.

Measure edit latency, compiler/solver invocations, local model size, evidence import,
integration selection and link cost. Grow unrelated fixture units while holding
the tested component constant. Acceptance requires supplier bodies to remain absent
from generated controlled-dependency consumer harnesses and their unchanged local
work to remain reusable, not merely a larger component count. Native-oracle capture and integration
explicitly report any actual dependency execution instead of claiming body absence.

A fresh operator should be able to reproduce a mismatch, repair ordinary C and run
the resulting experimental build from the documented work package. Do not require
automatic boundary recommendations, universal heap proofs, general concurrency,
a new GUI, all Win32 APIs or full Hello/jq/DX-Ball completion for that milestone.
Those remain subsequent capability and qualification work.
