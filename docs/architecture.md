# Architecture And Assurance

## Objective

Spaghetti Extractor reconstructs IA-32 PE32 applications as progressively more
portable C. It must first produce a statically complete machine-oriented
baseline, then allow bounded regions to be replaced by reviewed source without
losing coverage of the original program.

The toolkit does not claim an unrestricted whole-program equivalence theorem.
Its assurance comes from exact binary binding, independently qualified machine
semantics, fail-closed static closure, complete fallback ownership, bounded
component checks, and candidate-only behavior tests. Runtime execution of the
original binary is forbidden during repair iteration.

## Canonical Pipeline

```text
original PE bytes
  -> exact PE inventory and executable-byte classification
  -> rooted static state machine and byte-bound unit preparation
  -> canonical byte-free machine IR
  -> typed v3 evidence and authority graph
  -> final-authority-v3
  -> candidate-authority-v3 plus complete fallback receipt
  -> interpreter/native fallback candidate
  -> component contracts and logical-c-v1 source packages
  -> candidate-only evidence and component qualification
  -> one total component runtime package
  -> candidate-only tests in headless Wine
```

Extraction and proposal phases may use Capstone, `pefile`, Z3, SDK catalogs,
library signatures, and operator-authored hints. Those inputs are not authority.
Each accepting record is rebound to exact PE, machine-IR, unit, event, profile,
and dependency identities by a checker-owned phase.

Ghidra is exposed only through `stage-a-export-ghidra-proposal`. The adapter
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
- `candidate/` consumes final authority and component runtime ownership, but
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
| `memory-versions-v3` | Build alias components, versions, merges, writes, reads, and unknown-write kills. |
| `structural-target-proposals-v3` | Propose finite indirect destinations without granting reachability authority. |
| `indirect-target-certificates-v3` | Check target expressions, finite alternatives, mapped destinations, and evidence dependencies. |
| `inductive-authority-v3` | Check SCC entry facts, preservation, exports, and bounded circular invariants. |
| `canonical-external-sites-v3` | Bind resolved external transfers to exact ABI, argument, effect, and continuation evidence. |
| `callback-authority-v3` | Bind callback registration, entry state, ABI, lifetime, and nested transition evidence. |
| `launch-root-closure-v3` | Derive rooted closure from PE entry/export/TLS roots and checked callback roots. |
| `exceptional-transitions-v3` | Classify feasible faults as supported transfer, observable termination, or frontier. |
| `isa-qualification-v3` | Bind every reachable instruction form to qualified decode and semantics evidence. |
| `fallback-coverage-v3` | Check one supported fallback implementation for every structural unit. |
| `final-authority-v3` | Reduce all required families and dependencies into the sole static acceptance record. |

The registry rejects missing phases, duplicate names, duplicate artifact
producers, and phases without independent completeness hooks. Generated status
fields cannot create final authority.

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
  missing. It is cacheable diagnostic output but cannot authorize execution.
- `violated` means supplied evidence contradicts exact bytes, identities,
  schema, semantics, or another checked dependency.

Dependent fallout uses explicit `blocked_by` relationships. Operator progress
is measured using primary unresolved certificates, SCCs, external sites, ISA
forms, and environment frontiers rather than duplicated downstream errors.

## Static Closure And Fallback

Candidate generation requires all of the following:

- every executable byte is classified;
- every structurally discovered unit has exact machine IR;
- every rooted transfer remains inside the structural universe;
- direct, indirect, callback, call, return, and exceptional exits are closed;
- every external site has a checked machine-level contract;
- every reachable instruction form is qualified;
- every structural unit has exactly one fallback or reviewed-source owner;
- the `final-authority-v3` record is complete and authorizing;
- the independently recomputed candidate-authority receipt matches all inputs.

The fallback engine interprets canonical machine IR and uses explicit native
bridges for PE32 ABI and external operations. Diagnostic candidate modes may be
built for static inspection, but only a static-closed candidate may reach the
runtime test constructors.

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

A source replacement must provide:

- a reviewed logical interface with an exact projection to machine effects;
- an exact content-bound source package and `logical-c-v1` entry;
- candidate-only evidence bound to the contract, source, machine IR, producer,
  and declared domain;
- qualification for the exact selected configuration;
- complete, exclusive ownership of its selected machine units;
- no loss of machine-IR fallback coverage outside the replacement.

The component runtime package is the sole executable source authority. It
generates ABI adapters, cross-compiles portable source, and supplies one
portable-selection artifact to dispatch, fallback coverage, candidate
authority, and completion checks. Diagnostic contracts and source bundles
cannot authorize candidate code independently.

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
  -> rooted/final authority
  -> fallback and candidate receipts
  -> component evidence, qualification, and runtime package
```

A candidate source edit should rebuild its source package, evidence,
qualification, runtime adapter, affected native object pack, and candidate. It
must not regenerate original extraction,
ISA oracle corpora, or unrelated authority packs. Diagnostic formatting must
not invalidate authority evidence.

`python_module_index.py` derives the production module closure from installed
entrypoints and Nix phase roots. Package modules reachable only from tests are a
repository error. This keeps retired analyzers from silently remaining in the
distributed package or test graph.

## Runtime Policy

The original binary is consumed statically only. Runtime suites execute the
candidate against curated public expectations and always use an isolated
headless Wine session. A runtime failure after static closure is treated as a
tooling defect or an unsound assumption, not as ordinary region discovery.

## Completion Criteria

A target is fully reconstructed only when:

1. `final-authority-v3` passes for the complete declared PE and environment
   profile;
2. fallback coverage and implementation ownership are complete;
3. every selected portable component has exact satisfied evidence and is
   qualified in the active runtime package;
4. the candidate-authority receipt passes;
5. candidate-only smoke, functional, and upstream suites pass where available;
6. all artifacts are reproducible through the checked Nix graph.

GNU Hello is the small end-to-end source-lifting validation target. jq tests
larger CLI/library behavior and analysis scale. DX-Ball tests legacy multimedia
APIs, callbacks, mutable resources, loops, and a substantially larger control
universe. New generic mechanisms must first pass a small target-independent
fixture before a validation target relies on them.
