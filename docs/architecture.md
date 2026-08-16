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
  -> checked structural transfer, external-site, callback, and exception facts
  -> complete fallback capability and implementation ownership
  -> structural-executable-v1
  -> executable interpreter/native hybrid baseline
  -> reviewed portable component interface V2
  -> independent host/PE32 compile receipt
  -> machine binding + semantic refinement + service graph + ownership receipts
  -> component activation receipt and one total component runtime package
  -> ISA qualification and static release acceptance
  -> optional candidate-only tests in headless Wine
  -> release-acceptance-v1
```

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
- `authority_inputs/` may construct checked record types, but may not depend on
  terminal authority, diagnostics, candidate code, or components;
- `authority/` contains the complete checker-owned graph and imports no proposal
  adapters or implementation layers;
- `components/` is an authority-neutral lifting subsystem over exact machine-IR
  and component contracts;
- `candidate/` consumes checked structural policies and component runtime ownership, but
  cannot invoke extraction or proposal discovery.

Repository boundary tests parse imports and reject a dependency that crosses
these ownership rules. Shared schemas belong in small dependency-free modules,
not in a higher pipeline layer.

## Native V3 Authority

`authority/registry.py` is the complete authority-family registry. The active
phases, in dependency order, are:

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
| `callback-authority-v3` | Bind callback registration, entry state, ABI, lifetime, and nested transition evidence. |
| `launch-root-closure-v3` | Derive rooted closure from PE entry/export/TLS roots and checked callback roots. |
| `exceptional-transitions-v3` | Classify feasible faults as supported transfer, observable termination, or frontier. |
| `isa-qualification-v3` | Bind every reachable instruction form to qualified decode and semantics evidence. |
| `fallback-coverage-v3` | Check one supported fallback implementation for every structural unit. |
| `final-authority-v3` | Preserve the stronger formal-analysis aggregate as diagnostic evidence; it is not the executable or release gate. |

The registry rejects missing phases, duplicate names, duplicate artifact
producers, and phases without independent completeness hooks. Generated status
fields cannot create authority. Candidate execution is authorized only by the
independently reduced `structural-executable-v1` receipt; release uses
`release-acceptance-v1`.

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

The stable invalidation boundaries are:

```text
PE inventory
  -> machine IR preparation
  -> bounded machine-IR packs
  -> local v3 summaries
  -> dependent SCC and target certificates
  -> rooted structural facts
  -> structural execution and fallback receipts
  -> component activation and runtime package
  -> candidate tests and release receipt
```

A candidate source edit should rebuild its source package, compile and semantic
refinement receipts, activation receipt, runtime adapter, affected native object pack, and candidate. It
must not regenerate original extraction,
ISA oracle corpora, or unrelated authority packs. Diagnostic formatting must
not invalidate authority evidence.

Operator status follows the same dependency discipline. Project status is an
authority-only leaf and has no dependency on component configurations,
candidate source, or candidate tests. Candidate status composes that checked
project status with exactly one configuration status and only its declared
tests. A broken component may block its candidate status, but cannot prevent an
operator from inspecting static authority progress.

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

The original binary is consumed statically only. Before static closure, portable
source may be compiled but not executed as reconstruction evidence. After static
release acceptance, optional runtime suites execute the whole candidate against
curated public expectations and always use an isolated headless Wine session. A
whole-candidate runtime failure after static closure vetoes confidence and is
treated as a tooling defect or an unsound assumption, not as ordinary region
discovery. A passing runtime suite never authorizes a component.

## Completion Criteria

A target is fully reconstructed only when:

1. `structural-executable-v1` passes for the complete declared PE and
   environment profile;
2. fallback coverage and implementation ownership are complete;
3. the universal component gate binds the exact activation plan, checked
   implementations, and complete contract dependency graph;
4. reachable ISA qualification has no missing or disputed forms;
5. `release-acceptance-v1` passes and all artifacts are reproducible through
   the checked Nix graph.

Optional candidate-only suites may be applied after this gate as independent
vetoes.

GNU Hello is the small end-to-end source-lifting validation target. jq tests
larger CLI/library behavior and analysis scale. DX-Ball tests legacy multimedia
APIs, callbacks, mutable resources, loops, and a substantially larger control
universe. New generic mechanisms must first pass a small target-independent
fixture before a validation target relies on them.
