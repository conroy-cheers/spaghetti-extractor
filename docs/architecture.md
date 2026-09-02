# Architecture And Assurance

## Objective

Spaghetti Extractor reconstructs IA-32 PE32 applications as progressively more
portable C. It must first produce a statically complete machine-oriented
baseline, then allow bounded regions to be replaced by reviewed source without
losing coverage of the original program.

The toolkit does not claim an unrestricted whole-program equivalence theorem.
Its assurance comes from exact binary binding, independently qualified machine
semantics, fail-closed static closure, complete fallback ownership, and
machine-derived component refinement. Candidate-only behavior tests are
optional veto diagnostics. Runtime execution of the original binary is
forbidden during repair iteration.

## Canonical Pipeline

```text
original PE bytes
  -> exact PE inventory and executable-byte classification
  -> rooted static state machine and byte-bound unit preparation
  -> canonical byte-free machine IR
  -> executable-transfer-plan-v2 (the sole executable semantic body language)
  -> semantic-object-v1
       { transfer-v2, exact module interface, resolved environment,
         object authority, ISA requirements, exceptional semantics }
  -> linked-semantic-module-v2 + qualified-platform-v1
       { one conservative may-reach closure, semantic holes,
         residual runtime obligations, and analysis frontiers }
  -> one implementation provider per reachable semantic definition
       { generated Behavioral C, independently checked Portable C,
         pinned binary, or external environment }
  -> native-realization-v2
       { runtime, generic ingress, native link, loader-surface composition,
         candidate hash, and exact realization receipt }
  -> candidate-observed project completion
  -> optional deployment-bound veto tests in headless Wine
```

`semantic-object-v1` is the relocatable checked semantic unit.
`linked-semantic-module-v2` is the one module-wide semantic closure and cache
boundary. It resolves typed relocations, propagates root provenance once,
selects the qualified platform meaning, and separates genuine reachable
semantic holes from typed residual runtime obligations and non-authorizing
analysis frontiers. It does not authorize execution and is not a container
around independently authoritative subsystems. All execution consumers use
its transfer-v2 bodies and checked relations directly.

The authority-v3 fixed-point graph, `structural-executable-v1`, and the older
component/build/deployment receipts described below are migration inputs only.
They remain fail-closed until their facts have moved into the semantic object
and passed exact parity gates; they are not the destination architecture and
must not regain new consumers.

Extraction and proposal phases may use Capstone, `pefile`, Z3, SDK catalogs,
library signatures, and operator-authored hints. Those inputs are not authority.
Each accepting record is rebound to exact PE, machine-IR, unit, event, profile,
and dependency identities by a checker-owned phase.

Ghidra is exposed only through `static-export-ghidra-proposal`. The adapter
performs static headless analysis, verifies the exact binary hash in its output,
and labels the result `untrusted-proposal`; it is not imported by or accepted as
an authority phase.

The structural universe is prepared independently of source lifting. Replacing
a component changes its source and implementation evidence; it does not reopen
original PE extraction or permit an unrepresented executable region.

## Package Ownership

The Python package enforces the same separation physically:

- `extraction/` may depend on neutral PE, ISA, and utility code, never authority,
  candidate, or component implementations;
- neutral bindings and analyses live directly in `reconstruction/`, `external/`,
  or `qualified_platform/`; there is no authority-input adapter layer;
- no standalone Python authority package exists; semantic objects and their
  total linked closure own executable authority;
- `components/` is an authority-neutral lifting subsystem over exact machine-IR
  and component contracts;
- `candidate/` consumes checked structural policies and component runtime ownership, but
  cannot invoke extraction or proposal discovery.

Repository boundary tests parse imports and reject a dependency that crosses
these ownership rules. Shared schemas belong in small dependency-free modules,
not in a higher pipeline layer.

## Transitional Native V3 Facts

The target-wide v3 authority registry and graph have been removed. The
remaining local checkers are transitional typed fact producers; production
roots may consume a fact only through an explicit `semantic-object-v1` member
and the total `linked-semantic-module-v2` closure. The historical phase order
below documents those fact dependencies during their clean-cut migration:

| Phase | Responsibility |
|---|---|
| `exact-units-v3` | Bind every submitted unit to its exact machine-IR and PE identity. |
| `semantic-index-v3` | Normalize checked control, memory, call, and exception occurrences. |
| `transition-summaries-v3` | Emit one typed local transition summary per exact unit. |
| `parametric-unit-facts-v3` | Check root-independent unit transfer facts over explicit symbolic inputs, memory effects, calls, and exits. |
| `memory-versions-v3` | Build alias components, versions, merges, writes, reads, and unknown-write kills. |
| `structural-target-proposals-v3` | Propose finite indirect destinations without granting reachability authority. |
| `indirect-target-certificates-v3` | Check target expressions, finite alternatives, mapped destinations, and evidence dependencies. |
| `parametric-scc-summaries-v3` | Check dependency-SCC invariant certificates and export finite facts without replaying rooted paths. |
| `inductive-authority-v3` | Check SCC entry facts, preservation, exports, and bounded circular invariants. |
| `canonical-external-sites-v3` | Bind resolved external transfers to exact ABI, argument, effect, and continuation evidence. |
| `call-boundary-contracts-v3` | Reconcile call-site intent, ABI facts, and exact machine transport into checked boundary contracts. |
| `incoming-call-frames-v3` | Bind externally entered functions and callbacks to exact incoming physical frames. |
| `callback-authority-v4` | Bind one canonical callback protocol to registration, entry state, ABI, lifetime, and target evidence. |
| `launch-root-closure-v3` | Derive rooted closure from PE entry/export/TLS roots and checked callback roots. |
| `exceptional-transitions-v5` | Classify feasible faults as supported transfer, observable termination, or an exact handler/unwind/resumption chain. |
| `isa-qualification-v3` | Bind every reachable instruction form to qualified decode and semantics evidence. |
| `fallback-coverage-v3` | Check one supported fallback implementation for every structural unit. |
| `final-authority-v3` | Preserve the stronger formal-analysis aggregate as diagnostic evidence; it is not the executable or release gate. |

There is no registry whose completeness can authorize execution. Generated
status fields cannot create authority. During migration, checked facts may feed
a semantic object only through an explicit typed member with exact replay. The
linked semantic module and selected realization—not
`structural-executable-v1` or `release-acceptance-v1`—are the destination
execution and release boundaries.

## Trust Boundaries

Authoritative inputs are limited to exact bytes, checked profiles, qualified
machine-semantics artifacts, checker code, and explicitly reviewed assumptions.
Hashes identify content and dependencies; they do not prove correctness by
themselves.

The following are proposals only:

- Capstone and `pefile` extraction results;
- Ghidra output, symbols, linker maps, library matches, and source locations;
- Z3-generated finite facts or invariants;
- component boundaries and C rendering suggestions;
- runtime diagnostics and candidate behavior reports.

Lean, Unicorn, Bochs, and hardware-derived corpora qualify the supported ISA
profile. Unicorn and Bochs are veto oracles, not proof authorities. Disputed or
unsupported observations leave the corresponding form incomplete.

Operator-authored target intent selects reviewed facts using stable selectors.
Generated hashes, statuses, blocker counts, and proposal IDs may not be checked
into intent files. Resolution produces fresh binary-bound artifacts in Nix.

## Status Vocabulary

- `complete` means the checker closed the artifact's declared bounded scope.
- `incomplete` means evidence, support, coverage, or a finite invariant is
  missing. It is cacheable diagnostic output and cannot authorize the gate or
  activation facet that requires it.
- `violated` means supplied evidence contradicts exact bytes, identities,
  schema, semantics, or another checked dependency.

Dependent fallout uses explicit `blocked_by` relationships. Operator progress
is measured using primary unresolved certificates, SCCs, external sites, ISA
forms, and environment frontiers rather than duplicated downstream errors.

## Static Closure And Fallback

Candidate generation requires structural executability:

- every executable byte is classified;
- every structurally discovered unit has exact machine IR;
- every rooted transfer remains inside the structural universe;
- direct, indirect, callback, call, return, and exceptional exits are closed;
- every external site has a checked machine-level contract;
- every structural unit has exactly one fallback or reviewed-source owner;
- the fallback engine can lower every selected machine-IR form; and
- the independently reduced `structural-executable-v1` receipt matches all
  exact inputs and is complete.

Release acceptance additionally requires qualified reachable ISA forms, the
exact activation or legacy qualification receipt selected for every enabled
component, and no disputed oracle results. Candidate-only tests do not enter
the acceptance reducer.

The fallback engine interprets canonical machine IR and uses explicit native
bridges for PE32 ABI and external operations. While structural closure is
incomplete, the toolkit may compile one portable component against its reviewed
interface, but cannot execute it as evidence, compose a PE candidate, or invoke
the original program. Whole-candidate source, object code, and PE composition
require structural executability. Optional Wine tests run only after static
release acceptance and cannot feed that gate.

## External Operations

External interactions use exact site identities and machine-level contracts.
Contracts describe transfer kind, calling convention, argument expressions,
register effects, memory footprints, resource changes, callback adapters, and
continuations. C prototypes and friendly SDK names are source-lifting metadata,
not authority.

The initial environment profile requires exact one-for-one interactions with a
pinned runtime or a separately qualified replacement. Concrete addresses and
handles may differ only through checked runtime bindings. Threads, unknown
asynchronous callbacks, direct syscalls, unmodelled SEH, and executable-memory
writes remain explicit frontiers.

## Components And Source Lifting

Components are reviewed groupings of machine units. Their interfaces describe
logical inputs, outputs, objects, services, effects, and claims while retaining
an exact projection back to machine ranges and events.

The component development contract is intentionally weaker than the activation
contract. It binds the operator-declared selector or group membership, source
operation map, and reviewed portable interface V2, then renders deterministic C
headers. It does not resolve machine members, consume target proposals, or
assert that machine effects or external sites are closed, and can never
authorize activation. This small boundary keeps local compile/test iteration
independent of whole-target analysis.

A portable V2 replacement must provide:

- a reviewed architecture-independent operation interface;
- an exact content-bound source package with one symbol per operation;
- host and PE32 compile receipts and no component-owned mutable globals;
- machine-derived semantic refinement for every bound operation;
- a checked machine binding for arguments, results, effects, and continuations;
- a checked service graph for component and external dependencies;
- a checked activation receipt for the exact selected configuration;
- a checked universal implementation and complete contract dependency graph;
- complete, exclusive ownership of its selected machine units;
- no loss of machine-IR fallback coverage outside the replacement.

The component runtime package is the sole executable source authority. It
generates ABI adapters, cross-compiles portable source, and supplies one
portable-selection artifact to dispatch, fallback coverage, candidate
authority, and completion checks. Diagnostic contracts and source bundles
cannot authorize candidate code independently.

## Library Recognition

Library recognition accelerates component discovery; it is not a parallel
replacement authority. The canonical ABI-first path produces independently
cached target signatures, catalog search records, constellation hypotheses,
tracked adoption intent, and a checked whole-island receipt. An adoption intent
selects one reusable behavior pack, but neither a name match nor operator intent
can authorize executable source.

Each complete selected island generates one ordinary portable component. Its
machine-binding checker requires exact equality between the checked island's
machine-unit inventory and the component inventory and binds the checked-island
hash into the candidate package. Compile, semantic refinement, service graph,
ownership, and activation checks remain unchanged. Code outside explicitly
selected islands stays in machine-IR fallback, so recognizing one library never
requires classifying the entire application.

## Nix And Invalidation

Nix is the only first-class build and test system. Phase-specific Python import
closures, content-addressed artifact packs, and registry-derived dependency
graphs keep unrelated source changes out of a derivation's identity.

The pivoted stable invalidation boundaries are:

```text
PE interface + checked machine IR + environment intent
  -> semantic-object-v1
qualified-platform-v1 -----------------┘
  -> linked-semantic-module-v2
  -> provider qualifications + implementation selection
  -> native-realization-v2
  -> independent candidate/project observation and veto-only tests
```

During the staged migration, legacy authority derivations may still construct
members of `semantic-object-v1`, but they are not stable cache boundaries. Each
fact family is moved into the object or the single semantic-link worklist and
its superseded scheduling path is then removed. Splitting cheap projections
back into independently scheduled derivations or adding a mutable cache would
recreate the fan-out that the semantic-module design is intended to eliminate.

`native-realization-v2` is a direct fact table rather than an envelope around
the retired candidate pipeline. It binds the total implementation selection to
the exact provider definitions, linked object hashes, semantic-symbol address
kinds, bridge-equivalence classes, runtime/TLS/private-stack facts, native link
and relocation inventories, decoded loader surface, and candidate bytes. A
selected provider object must exist as exact bytes inside its qualification
package before realization begins, and the same digest must occur in the linked
native-object inventory under every selected semantic symbol that claims it.
Runtime-platform and native-realizer provider objects are compiled directly
from their content-bound source packages; qualification and selection do not
depend on a pre-existing native link. This preserves the one-way dependency
from semantic selection to realization while byte-parity checks against the
transitional linker remain veto-only.
A selected non-external provider object absent from the linked object inventory is
an intrinsic realization blocker. Production construction loads provider facts
from their qualification receipts; it cannot accept operator-authored provider
rows.

The migrated native-realization constructor consumes the total selection
directly: selected provider package and realization-infrastructure objects are
staged by exact hash, and it rejects partial or surplus object consumption
before invoking the linker. The same content-addressed phase owns the payload,
map, relocation inventory, composition, decoded candidate surface, candidate
bytes, and realization receipt. The synthetic PE32/Wine vertical uses this path
exclusively and observes the realization-owned candidate. The SDK, Hello, jq,
DX-Ball, and native fixtures all consume this V2 path; the V1 provider,
selection, and realization codecs and constructors are retired tombstones.

Runtime and environment providers use the same ownership rule. The V2
generated-C, qualified-runtime, and external-environment constructors emit
separate exact qualifications, and one total V2 selection names every active
definition and residual obligation. Fixtures and targets may select those
records, but may not reproduce the compiler or synthesize missing platform
symbols. A conditional runtime handler such as typed x87 remains incomplete
unless it is present in the compiled object and its qualified platform identity
matches the linked semantic module.

The resolved external environment and machine object authority are already
content-bound semantic-object members. `external/resolved.py` owns the strict
resolved-environment codec while `external/environment.py` owns
intent compilation. Semantic linking, closure projection, independent replay,
and performance checks open those members through the semantic object; they do
not accept independent environment or object-authority phase inputs. Checked
external-function symbols carry the selected logical boundary schema, physical
frame, exact environment-contract digest, optional loader-service-contract
digest, and declaration role into the link. Original loader-slot declarations
carry the same identities, so loader storage and semantic calls cannot silently
select different contracts. The production linker consumes these fields
directly while the native worklist cross-checks them against one compact total
catalog independently projected from the content-bound environment member.
The narrower executable external-call adapter table remains an implementation
projection: checked declarations whose effects are not yet lowerable stay
explicit blockers. Loader-service status is never inferred from an API name.

Evidence is not a parallel graph. Each semantic object contains one canonical
content-bound evidence catalog, and each definition carries only a sorted list
of indices into it. The policy is derived from definition kind and exact unit
facts: transfer bodies bind transfer, qualified-ISA, and exceptional evidence
as applicable, while mapped-object and loader definitions bind interface and
object authority. Reachable implementation requirements preserve those exact
indices. The strict codec, optimized production link view, native link input,
and independent replay cross-check the same compact relation; no consumer may
accept a separately scheduled evidence map or copy whole receipts per symbol.

The semantic object is a complete checked relocatable, not an authority and not
a migration-status surrogate. Its `status = complete`,
`role = checked_relocatable`, and `authority = false` mean that construction and
all content bindings closed successfully; unresolved relocation holes remain
ordinary link inputs. Only `linked-semantic-module-v2` decides whether those
holes are root-reachable and reports semantic completeness; it never grants
execution authority. Target workflows do
not schedule an independent closure for parity: independent object replay and
independent linked-module replay provide the veto boundaries without creating
a second production fixed point.

Executable root identity is deliberately distinct from root RVA. The native
fixed point operates on unique RVAs, while semantic linking expands each RVA
to every stable entry/export/TLS identity declared for that one semantic
function. EAT aliases therefore share execution and one target symbol but keep
distinct provenance throughout symbols, edges, effects, objects, and reference
facts. Conflicting semantic targets at one root RVA fail closed. Data exports
and forwarders do not seed executable reachability: data aliases remain exact
object-authority anchors, and forwarders remain loader/provider declarations.

Checked exception behavior is linked, not consulted as a side registry. Exact
fault occurrences are part of transfer-v2. Generic terminal/infeasible
semantics are derived from those occurrences and the resolved launch policy
inside semantic-object construction, then retained in the resident object
view. The legacy authority-v3 exception artifact is accepted only for the
still-migrating handled/unwind/resumption protocol. Each
function with an authorized transition has a typed
`exception_transition_activation` relocation to one semantic transition
definition; handler, resumption, and unwind edges originate at that definition.
Root provenance therefore reaches exception semantics through the ordinary
link worklist, and every reachable transition must resolve and select an
implementation provider with its exact evidence dependencies. Native SEH
realization must implement that selected definition before execution can be
authorized.

Callback physical transport has no independent authority graph either. The
resolved runtime profile declares the provider callback protocol and the exact
transfer-v2 registration occurrence proves a non-sentinel callback word. That
pair produces the checked boundary frame. The linked semantic worklist then
proves target reachability, ownership, escape lifetime, and capability
selection. This keeps frame checking, callback discovery, and root closure as
different relations over one semantic module rather than three pipelines that
reconstruct one another.

The post-propagation unresolved-definition guard is intentionally narrower than
external resolution. It diagnoses only an unresolved semantic definition made
newly reachable by a typed relocation, such as an activated exception
transition. External functions and loader/IAT anchors are classified by the
resolved-environment and loader-storage policies even when relocation
propagation adds root provenance; the generic guard must not duplicate or
override those domain-specific blockers.

Object lifetime meaning follows the same discipline. A linked object derives
its single generation mode from the existing authority locator, generation
seed, and lifetime; typed object views are projected only from typed data-
export anchors already present in that authority. These derived fields make
the contract explicit to native realization without creating another object or
lifecycle artifact. The linked codec and independent replay validate the total
relation. A realization may authorize a rule only when its resolver implements
that exact generation mode.

Runtime primitive dependencies follow the same rule. `semantic-object-v1`
stores one compact, sorted effect row per required provider, binding the
platform symbol to the exact semantic function symbols that need it. Checked
external-call relocations already carry external provenance. The linker has no
parallel provider/external source maps and does not expand provider use into
pseudo-relocations. Independent replay reconstructs both projections from the
canonical transfer member and vetoes any disagreement. Performance policy is
speed-first: content-bound in-memory indexes and compact read views are
welcome. Link, closure, and ordinary test phases have no project RSS veto; the
host/Nix resource boundary owns exhaustion, while reports retain peak RSS for
diagnosis. CPU and wall-clock latency, rather than compact resident state, are
the performance constraints: a content-bound phase may retain fully decoded
members, indexes, joins, and output-ready projections together when doing so
avoids a second parse or traversal.

Object authority is also a semantic-object member, not a parallel linker
argument. The object carries a total canonical object-rule-to-symbol relation;
strict object replay derives it from machine-object-authority-v2 and the
semantic declarations, while the native semantic worklist consumes it
directly. The linker cannot be called with a second environment or object
registry that disagrees with the object it is linking.

Production linking opens a content-bound link view of that same semantic
object instead of replaying the full transfer member twice. The view validates
the object/package hashes, transfer identity, and every smaller typed member;
the same-pass native worklist independently reconstructs the exact transfer
function universe, runtime-provider dependencies, and all transfer-derived
relocations before accepting the view. This is a loader mode, not a second IR
or receipt. Public parsing and independent replay always use the strict full
semantic-object codec, and an architecture gate prevents the fast view from
spreading to replay or other consumers.

A candidate source edit should rebuild its source package, compile and semantic
refinement receipts, activation receipt, runtime adapter, affected native object pack, and candidate. It
must not regenerate original extraction,
ISA oracle corpora, or unrelated authority packs. Diagnostic formatting must
not invalidate authority evidence.

Operator status follows the same dependency discipline. Project status is a
non-authorizing `operator-work-status-v1` projection whose sole semantic input
is the materialized `linked-semantic-module-v2`; it does not read the legacy
authority diagnostics, component configurations, candidate source, or
candidate tests. Candidate status uses the same projector and public format,
adding exactly one configuration's `implementation-selection-v2`; it no longer
reduces structural-executable-v2, activation-v4, or test metadata. The module
and configuration remain separate subjects rather than a synthetic combined
authority. A broken provider selection may block its configuration subject,
but cannot prevent an operator from inspecting the semantic module's exact
blockers.

Component resolution follows the same rule. The full checked catalog owns
configuration overlap checks, but each component contract consumes a canonical
single-unit resolution slice built from its authored intent row and selected
proposal. An unrelated intent edit therefore leaves the component's contract,
adapter, evidence, and qualification derivation identities unchanged.

The development branch is narrower still. Its per-component declaration is
projected directly from authored intent and contains no selected proposal or
resolved unit inventory. Consequently local source compilation remains
available before discovery succeeds, and edits to unrelated target
components do not invalidate that loop.

`python_module_index.py` derives the production module closure from installed
entrypoints and Nix phase roots. Package modules reachable only from tests are a
repository error. This keeps retired analyzers from silently remaining in the
distributed package or test graph.

## Runtime Policy

The original binary is consumed statically only. Before semantic closure,
portable source may be compiled but not executed as reconstruction evidence.
After the linked semantic module, total provider selection, and native
realization are complete, optional runtime suites execute that exact candidate
against curated public expectations in an isolated headless Wine session. A
whole-candidate runtime failure vetoes confidence and is treated as a tooling
defect or an unsound assumption, not as ordinary region discovery. A passing
runtime suite never authorizes a component or closes a semantic hole.

## Completion Criteria

A target is fully reconstructed only when:

1. `linked-semantic-module-v2` has no reachable semantic holes;
2. one total `implementation-selection-v2` owns every reachable semantic
   definition with independently checked provider qualifications;
3. component contracts, machine bindings, lifecycle, services, relations,
   induction, and ownership facets required by selected portable providers are
   complete;
4. reachable platform semantics and physical boundary protocols have no
   missing or disputed forms;
5. `native-realization-v2` is complete, binds every selected object and loader
   fact, and its exact candidate is confirmed by candidate-observed project
   completion.

Optional candidate-only suites may be applied after this gate as independent
vetoes.

GNU Hello is the small end-to-end source-lifting validation target. jq tests
larger CLI/library behavior and analysis scale. DX-Ball tests legacy multimedia
APIs, callbacks, mutable resources, loops, and a substantially larger control
universe. New generic mechanisms must first pass a small target-independent
fixture before a validation target relies on them.
