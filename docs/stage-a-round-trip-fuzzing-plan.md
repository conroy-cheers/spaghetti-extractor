# Stage A Structured Round-Trip Fuzzing Plan

## Status And Scope

This document is both the implementation plan and the qualification record for
a structured, property-based Stage A and Stage B handoff. As of 2026-07-22,
Phases 0-5 and the initial full-corpus qualification are complete for the
bounded `structured-spike-v1` x86 PE32 profile. Phase 6 is deliberately a
future capability-expansion program, not part of the initial feasibility
decision.

The repository now contains:

- strict typed v1 corpus, case, semantic-program, run-result, violation-witness,
  violation-audit, and opaque Stage B provenance schemas;
- public `stage-a-fuzz-generate` and `stage-a-fuzz-run` commands;
- deterministic semantic-IR-to-GNU-assembly/object/PE32/map lowering;
- a real no-CRT Phase 0 canary assembled for `i686-pc-windows-msvc` with
  clang 21.1.8 and linked with lld-link 21.1.8; it contains an internal call,
  input-dependent branch, return, stack memory, static relocations, exact
  lockstep Windows imports, and termination;
- proof-core execution through the ordinary Stage A prepare and distributed
  Nix build interfaces, with final-theorem and zero-trust auditing;
- corpus-wide preparation and result IFD barriers which preserve parallel Nix
  scheduling while keeping generated graph evaluation deterministic;
- content-bound warm reuse which invalidates generated proofs when the Stage A
  proof generator or Lean model changes;
- strict validation of Lean-checked violation witnesses and an isolated
  opaque-artifact Stage B input bundle;
- a Lean-kernel-checked final
  `StageA.GeneratedRelational.candidatePE32ProgramsEquivalent` theorem for the
  independent LLVM/MSVC-compatible canary, with Lean trust zero and no
  unexpected axioms;
- deterministic generation and proof orchestration for the four initial
  semantic families, checked positive transformations, and isolated negative
  mutations;
- a 24-positive/12-negative feasibility spike and a promoted
  50-positive/25-negative Nix corpus, with all positives accepted only by a
  final whole-program Lean theorem and all negatives rejected by checked
  violation witnesses;
- a structure-aware deterministic reducer qualified against regenerated real
  PE, map, and contract artifacts;
- mapping discovery qualified for proof handoff on all four initial families,
  without granting discovery output proof authority;
- an opaque-artifact Stage B round trip from static Stage A evidence through a
  generated state machine and ugly C to a MinGW PE32 candidate and final Lean
  theorem; and
- measured static, warm-proof, cache-reuse, and genericity gates, all
  satisfied.

The checked Phase 0 record is in
[`stage-a-round-trip-phase0-report.md`](stage-a-round-trip-phase0-report.md).
The complete bounded-profile qualification and measurements are in
[`stage-a-round-trip-fuzzing-report.md`](stage-a-round-trip-fuzzing-report.md),
with machine-readable evidence in
[`stage-a-round-trip-feasibility-report.json`](stage-a-round-trip-feasibility-report.json),
[`stage-a-round-trip-qualification-evidence.json`](stage-a-round-trip-qualification-evidence.json),
and
[`stage-a-round-trip-discovery-qualification.json`](stage-a-round-trip-discovery-qualification.json).

This completion is a go decision for using the structured corpus as a rapid
qualification layer. It is not a claim of complete IA-32, Windows, jq, or
arbitrary compiler-output coverage. The Phase 0 canary also still resolves
Windows imports through MinGW's `libkernel32.a`; a Windows SDK import-library
lane remains an orthogonal future toolchain qualification.

The system targets the supported 32-bit x86 PE profile. It is not a claim of
complete IA-32 or Windows coverage. Unsupported instructions, environment
effects, control-flow forms, or proof obligations must remain explicit
`incomplete` results.

## Context

Stage A is intended to prove whole-program observational equivalence between an
opaque reference PE32 binary and a deliberately compatible reimplementation.
The final authority is the Lean-checked whole-program theorem. Extraction,
mapping proposals, solver output, emulators, source symbols, and fixture
metadata are untrusted inputs or diagnostics and cannot authorize `pass`.

The current implementation has accumulated a broad set of analyses and proof
paths while being driven by a small number of large binaries and manually
constructed fixtures. That creates two related risks:

1. A handler may accidentally encode a compiler, fixture, or target-specific
   shape instead of a reusable semantic rule.
2. Changes may be validated only after expensive jq- or hello-sized proof
   builds, making architectural mistakes slow to discover and tempting
   developers to add narrow shortcuts.

The repository already has useful pieces for addressing this:

- exact PE extraction and a fail-closed relational proof pipeline;
- a Lean whole-program acceptance theorem;
- a Stage A state-machine artifact and Stage B semantic-C backend;
- a tiny PE32 fixture builder and pinned MinGW environments;
- batched Lean ISA evaluation and emulator conformance infrastructure;
- content-addressed proof phases and Nix-distributed Lean builds.

This plan supplies a fast way to generate many small, semantically controlled
program pairs, prove expected-equivalent pairs, reject known inequivalent
pairs, reduce failures, and measure whether support is coming from general
proof constructs or an expanding collection of shape recognizers.

## How The Design Was Reached

Blind byte fuzzing is poorly matched to Stage A. Most random byte streams are
not useful PE programs, do not have meaningful relational invariants, and do
not provide a known equivalence result. Random compiler invocations alone are
also insufficient: when a proof fails, it is difficult to tell whether the
cause is decoding, mapping, invariant synthesis, environment modeling,
composition, or an actual semantic difference.

The proposed approach therefore generates a small semantic program first and
derives two real PE32 implementations from it. The pair is equivalent by
construction, but structurally different. The generator also records the
ground-truth mapping, guards, effects, and expected observations. Separate
single-fault mutations create known-negative pairs. This yields both kinds of
evidence required to improve a prover:

- positive cases expose incompleteness and excessive structural prescription;
- negative cases expose unsoundness and accidentally weakened validation.

This is a qualification and development tool, not part of the proof trust
boundary. Stage A must still derive and Lean-check the whole-program theorem
from exact binary bytes and accepted proof objects.

## Goals

1. Reduce the edit-to-diagnostic loop for generic Stage A work to seconds on
   small cases.
2. Exercise semantic variation across register allocation, layout, CFG shape,
   stack usage, calls, memory, and relocations without target-specific rules.
3. Distinguish proof-core limitations from mapping-discovery limitations.
4. Verify that Stage B semantic-C output can participate in the same
   binary-to-binary proof pipeline.
5. Detect unsound acceptance with deterministic negative mutations.
6. Produce minimized, reproducible fixtures suitable for regression tests.
7. Measure proof-schema reuse so corpus growth does not silently become
   profile-handler growth.

## Non-Goals

- Fuzzing is not evidence for final equivalence and cannot replace Lean.
- Emulator agreement cannot close a proof obligation.
- The first version does not generate arbitrary C, arbitrary PE files, threads,
  SEH, self-modifying code, or the complete x86 instruction set.
- Mapping discovery need not recover the generator's labels or source names.
  It must recover a semantically valid relation which Stage A checks.
- The tool does not execute or trace an opaque original application. Generated
  fixtures may be executed because both sides are synthetic test artifacts.
- The corpus must not add jq-, hello-, compiler-version-, or fixture-specific
  acceptance rules.

## Core Principle

Generate semantic programs, not byte strings:

```text
seed + capability profile
        |
        v
typed semantic program
        |
        +--> original lowering ----> PE32 original
        |
        +--> candidate lowering ---> PE32 candidate
        |
        +--> checked ground truth -> mappings, guards, effects, observations
        |
        +--> negative mutation ----> deliberately inequivalent candidate
```

The two lowerings may differ in implementation shape while sharing a defined
machine-level behavior. Both outputs must be assembled and linked as real
PE32 binaries. Stage A receives no special authority from the generator's
ground truth; the ground truth selects and diagnoses test cases.

## Feasibility Spike

### Purpose

Before constructing a large corpus, establish that generated pairs reach the
actual whole-program theorem, that negative cases fail closed, and that the hot
loop is substantially faster than testing against a full application.

Phase 0 must first close one small but representative real PE32 pair through
the exact final `pe32ProgramsEquivalent` acceptance theorem. Use a no-CRT
program with an explicit entrypoint, built with pinned `clang-cl`/`lld-link`
or MSVC-compatible tools and, where redistribution permits, pinned Windows SDK
headers and import libraries. The fixture should exercise an internal call, a
branch or bounded loop, stack memory, a static relocation, one exact lockstep
canonical Windows import, and termination. It is an infrastructure canary, not
a substitute for the generated corpus. If it cannot reach final acceptance,
record and repair that truthful frontier before treating corpus pass counts as
meaningful.

### Initial Semantic Templates

Implement exactly four template families for the spike:

1. **Straight-line arithmetic**
   - Inputs in declared registers and stack slots.
   - Width-correct arithmetic and logic.
   - Defined flag production where relevant.
   - A return value or externally observable memory result.

2. **Guarded branch**
   - A symbolic input guard.
   - Two paths with distinct state updates.
   - Candidate branch inversion and successor reordering.
   - Complete guard partition in the expected relational graph.

3. **Bounded loop**
   - A finite counter or pointer-range loop.
   - A generator-supplied invariant and ranking expression.
   - Candidate induction-variable or block-layout variation.
   - Observable result after termination.

4. **Internal call with stack memory**
   - Caller-prepared stack arguments.
   - A relocated continuation address.
   - Callee stack reads/writes, preserved registers, return value, and return.
   - Candidate spill and prologue/epilogue variation.

The four generated template families deliberately exclude imported calls.
Internal composition and stack frames must work before external protocol
modeling is added to the generated corpus. The separate Phase 0 acceptance
canary may use one canonical imported termination operation so it exercises
the real external-event acceptance boundary without turning the spike into an
API-semantics corpus.

### Structural Transformations

Each positive pair applies one or more transformations selected from:

- register reassignment with correct save/restore behavior;
- temporary stack spills;
- basic-block split or merge;
- direct-branch inversion;
- equivalent instruction selection for a supported semantic operation;
- function and block reordering;
- code/data relocation and alignment changes;
- changed unconditional-jump layout;
- different but equivalent prologue/epilogue shape.

Transformation preconditions must be typed and checked by the generator. A
transformation that cannot establish its own equivalence-by-construction
preconditions must reject generation rather than emit an expected-positive
case.

### Negative Mutations

Generate at least one isolated semantic fault from each applicable family:

- wrong arithmetic constant or operator;
- inverted branch without swapped successors;
- off-by-one loop bound;
- wrong stack slot or memory width;
- omitted memory write;
- incorrect preserved-register restoration;
- wrong direct destination or continuation;
- changed return value;
- changed fault/termination outcome where supported.

Each mutation must identify the single intended semantic delta. A negative
mutation wholly inside the qualified semantic profile must be reachable under
an admissible input, affect an observable result or required continuation
relation, and return `violated`. Merely returning `incomplete` does not qualify
such a case: a prover which gives up on every pair is fail-closed but has not
demonstrated useful discrimination.

`violated` requires a deterministic, replayable witness checked against the
exact decoded semantics. At minimum the witness binds:

- both binary hashes and the capability/environment profile;
- a stable obligation and violation identifier;
- original and candidate semantic locations, RVAs, bytes, cutpoints, and path;
- an admissible pre-state containing the relevant registers, flags, memory,
  world state, and path guards;
- the expected relation atom and conflicting original/candidate effects;
- the observation or continuation made unequal;
- the checker identity and exact replay command.

A raw solver `sat` result cannot establish `violated`. Solver models may propose
witnesses, but the supported witness fragment must be replayed by a checked
semantic evaluator or a Lean theorem. Source locations, cause hints, and repair
suggestions are diagnostic metadata and do not belong to the trusted witness.
Describe the result as the "first proved mismatch under this witness", not as
an assertion that it is necessarily the source-level root cause.

Separate capability-boundary negative cases may expect `incomplete`, for
example when they intentionally introduce an unsupported instruction,
unbounded indirect target, or unsupported environment event. Reports and
aggregate metrics must distinguish these from semantic `violated` cases. Any
negative case reaching final `pass` remains a release-blocking soundness
failure.

### Spike Corpus

Produce at least:

- 24 positive pairs, with every template and transformation represented;
- 12 negative pairs, with no pair depending solely on malformed input;
- one Stage B round trip from a Stage A state machine through generated
  semantic C to a compiled PE32 candidate.

Use deterministic seeds and pinned assembly/link tools. Store the seed,
generator version, capability profile, source artifacts, command lines, binary
hashes, and expected result in each case manifest.

### Spike Gates

Proceed to the full implementation only if all of the following hold:

- at least 12 structurally distinct positive cases reach a final
  Lean-authorized whole-program `pass`;
- every supported, reachable, observable negative mutation reaches
  witness-backed `violated`;
- every declared capability-boundary negative reaches `incomplete` with its
  expected reason family;
- no negative case reaches `pass`;
- positive failures report stable semantic frontiers rather than generic build
  failures or order-dependent errors;
- no target-, corpus-, seed-, fixed-RVA-, or transformation-name rule is added
  to acceptance logic;
- generation plus static preflight has a median below 1 second per tiny case;
- a warm-cache tiny final theorem has a median below 10 seconds;
- rerunning an unchanged corpus reuses at least 90 percent of proof-phase work;
- a failure can be deterministically reduced while preserving its predicate;
- growth in proof constructors and generic semantic rules is substantially
  smaller than growth in exercised binary shapes.

If these gates fail, stop corpus expansion. First fix batching, cache boundaries,
normalization, diagnostics, or the proof abstraction which caused the failure.
Do not compensate by adding more fixture-specific profiles.

## Proposed Package Layout

Keep the implementation isolated from the relational proof core:

```text
src/spaghetti_extractor/roundtrip_fuzz/
  __init__.py
  model.py          # immutable typed semantic and artifact models
  generator.py      # deterministic semantic-program generation
  transforms.py     # checked equivalence-preserving transformations
  mutations.py      # isolated expected-negative mutations
  lower.py          # original/candidate assembly lowerings
  toolchain.py      # pinned assembler/linker invocation and provenance
  contracts.py      # ground-truth and proposal artifact construction
  runner.py         # staged execution, timing, caching, reports
  reducer.py        # structure-aware deterministic reduction
  metrics.py        # coverage, genericity, cache, and timing summaries
```

The subsystem may call public Stage A and Stage B interfaces. It must not import
private proof-generation helpers merely to force a case through acceptance. If
the public interfaces are insufficient, stabilize those interfaces separately.

## Typed Semantic Model

Use immutable dataclasses or equivalent typed models with centralized strict
JSON parsing. Do not pass mutable `dict[str, Any]` values between generator
phases.

The initial IR needs:

- scalar bit-vector expressions with explicit widths;
- register and flag inputs/outputs;
- flat-memory reads and writes with explicit address expressions and widths;
- labels, conditional branches, direct jumps, calls, returns, and termination;
- functions, basic blocks, roots, and cutpoints;
- stack-frame declarations and ABI effects;
- static code/data objects and relocatable pointers;
- invariants, guards, ranking expressions, and observations;
- capability requirements for every operation and instruction form.

Every node has a stable semantic identifier derived from the seed-independent
program structure. Binary RVAs, source labels, and lowered block boundaries are
separate implementation identities.

The semantic evaluator used to check generator invariants is testing code only.
It must not become a trusted replacement for Lean semantics.

## Lowering And PE Production

### Assembly First

Use generated assembly for the feasibility spike. It gives precise control over
registers, stack layouts, relocations, and CFG transformations while still
producing real linked binaries. Introduce compiler-generated C pairs later as a
separate source of variation.

### Real PE32 Artifacts

The lowerer must:

- emit original and candidate assembly from the same semantic program;
- assemble and link with pinned `i686-w64-mingw32` tools;
- use deterministic linker settings where possible;
- retain linker maps and disassembly inputs as untrusted diagnostics;
- emit imports, relocations, sections, image base, entrypoint, and hashes;
- reject outputs outside the selected PE32 capability profile.

Do not patch raw executable bytes to simulate a compiler transformation unless
the test specifically targets the PE parser or decoder. Relational corpus cases
should pass through normal assembly and linking.

## Corpus Artifacts

Use canonical JSON with explicit schema versions and sorted serialization.

### Corpus Manifest

The corpus manifest records:

- corpus format and generator version;
- root seed and selected capability profile;
- case identifiers and canonical hashes;
- required toolchain identity;
- expected positive/negative counts;
- shard assignments which do not change case identity.

### Case Manifest

Each case records:

- semantic-program hash and parent seed;
- template and transformation parameters;
- positive or negative expectation;
- mutation identity and intended delta for negative cases;
- expected negative disposition (`violated` or `incomplete`) and required
  witness family;
- source, object, PE, map, and contract hashes;
- original and candidate lowering metadata;
- capability inventory;
- generator-known cutpoints, mappings, guards, effects, and observations;
- expected proof family coverage;
- replay command and reducer predicate.

### Result Manifest

Each run records:

- exact input bindings and Stage A version;
- per-phase status, cache key, cache hit, duration, and peak resource class;
- Stage A frontiers and final acceptance authority;
- checked violation-witness bindings, replay status, and first proved mismatch
  for `violated` results;
- whether the observed result matched the expected class;
- proof constructor/family coverage;
- mapping recovery quality where applicable;
- minimized reproducer binding when reduction ran.

All manifests must reject unknown required fields, missing hashes, duplicate
identifiers, and noncanonical references.

## Execution Modes

### 1. Proof-Core Mode

Supply the generator-known mapping and cutpoints as an untrusted relation
proposal. This mode asks whether extraction, semantics, segment refinement,
composition, and final Lean acceptance can prove an already-mapped pair.

It isolates proof-core incompleteness from discovery heuristics. The known map
does not bypass Lean checks of exact bytes, decoded control flow, graph
completeness, invariants, or effects.

### 2. Discovery Mode

Withhold some or all mapping hints and run the ordinary Stage A proposal path.
Compare the recovered proposal semantically against generator ground truth.

A valid recovered relation need not reproduce source labels or the exact
generator map. Success means it supports a checked proof or reaches a precise
mapping frontier without relying on fixture metadata.

Discovery failures must never be reported as proof unsoundness. Report them as
a separate phase and retain proof-core results for the same case.

### 3. Stage B Round-Trip Mode

Exercise the intended opaque-binary workflow:

```text
synthetic original PE32
  -> Stage A static extraction and state-machine contract
  -> Stage B semantic-C generation
  -> optional bounded manual/LLM-style repair fixture
  -> MinGW candidate build
  -> Stage A binary-to-binary whole-program proof
```

The candidate must bind the exact state-machine and implementation manifests.
The original is consumed statically; candidate-only smoke execution may be used
after Stage A passes. Generated semantic C may be ugly and state-machine-like.
Source aesthetics are irrelevant.

This mode must enforce an opaque-artifact provenance boundary. Stage B may
consume only artifacts available through the normal static Stage A export
interfaces for an opaque binary, plus explicit human/LLM annotations permitted
by those interfaces. It must not receive the generator's semantic program,
seed, transformation history, ground-truth map, source labels, or private
lowering metadata. A machine-readable provenance audit binds every Stage B
input to an allowed Stage A artifact or recorded manual annotation and fails
closed on undeclared inputs. Proof-core mode may use the generator-known map as
an untrusted proposal; Stage B round-trip mode may not use that exemption.

The spike needs only one simple case. Full expansion follows after proof-core
and discovery behavior are stable.

## Command Surface

The eventual user-facing interface should be small:

```text
spaghetti-extractor stage-a-fuzz-generate \
  --seed SEED \
  --count COUNT \
  --profile PROFILE \
  --out CORPUS

spaghetti-extractor stage-a-fuzz-run \
  --corpus CORPUS \
  --mode proof-core|discovery|stage-b-roundtrip \
  --out REPORT

spaghetti-extractor stage-a-fuzz-reduce \
  --case CASE \
  --predicate PREDICATE \
  --out REDUCED_CASE
```

Useful runner selectors may include seed, case ID, template, transformation,
capability, expectation, and changed proof family. Do not create separate
commands for each semantic template or transformation.

## Fast Staged Runner

Execute the cheapest, most diagnostic stages first:

1. Validate corpus and case schemas and hashes.
2. Check generator transformation/mutation preconditions.
3. Reuse or build source, object, and PE artifacts.
4. Parse both PEs and verify capability/profile eligibility.
5. Decode changed paths and reject unsupported forms.
6. Validate graph and relation references.
7. Run mapping proposal or inject the known untrusted proposal.
8. Generate only affected semantic and segment artifacts.
9. Compile affected Lean modules in batches.
10. Build composition and the final acceptance theorem.
11. Audit theorem identity, axioms, hashes, and acceptance authority.

A smoke failure stops the case before expensive Lean work. One failing case
does not prevent independent cases or shards from completing.

## Caching And Parallelism

Cache by semantic phase rather than by a monolithic test invocation:

- semantic program;
- original/candidate lowering;
- object and PE link outputs;
- PE extraction;
- decoded semantics per side;
- mapping proposal;
- relational contract;
- segment certificates;
- product composition;
- final acceptance audit.

Cache keys must include all semantic inputs, tool versions, capability profiles,
and proof-source hashes. Diagnostic formatting changes should not invalidate
decode or proof artifacts.

Nix is the supported development and qualification layer. Batch cases within
derivations through persistent Python workers and persistent Lean kernel/module
caches; avoid one Lean or emulator process per vector. Keep semantic phases in
separate derivations so an unchanged phase substitutes instead of rerunning.

The reproducible qualification graph includes:

- a small deterministic smoke derivation;
- corpus-generation derivations by seed range;
- independently schedulable proof shards;
- aggregate positive/negative and genericity reports;
- remote builder and binary cache compatibility.

Do not use Nix derivation granularity so fine that evaluation, SSH, or store
copy overhead dominates tiny proofs. Pack cases according to measured resource
classes and dependency reuse.

## Reducer

The reducer operates on the typed semantic program and transformation history,
not arbitrary bytes. Given a deterministic predicate, it attempts to remove:

- unreachable functions and blocks;
- unrelated branches and loop iterations;
- unused inputs, registers, memory objects, and relocations;
- transformations not required to reproduce the failure;
- instructions and effects while preserving type and CFG validity;
- negative mutations unrelated to the observed false acceptance.

After every reduction, regenerate both binaries and all derived artifacts. A
reducer must never hand-edit a contract or retain stale mappings.

Supported initial predicates:

- unexpected final `pass`;
- expected-positive not accepted;
- expected `violated` without a checked witness;
- selected stable violation identity or mismatch family;
- a selected proof frontier/category;
- crash or internal exception;
- nondeterministic artifact hash;
- cache-key mismatch;
- excessive phase duration.

The reducer emits a standalone case with the original seed lineage and exact
replay command.

For a `violated` case, reduction must preserve the same stable violation
identity or an explicitly approved semantically equivalent mismatch family.
It must regenerate and replay the checked witness after every accepted
reduction step.

## Genericity Guardrails

The corpus is useful only if it reduces special-casing pressure. Enforce the
following in review and automated reports:

1. Acceptance code must not branch on target names, source symbols, fixture
   IDs, corpus IDs, seeds, fixed RVAs, compiler versions, or transformation
   names.
2. Linker maps, symbols, and generator mappings remain untrusted proposals.
3. New support should normally extend a compact semantic family:
   - expressions and guards;
   - memory reads, writes, footprints, and framing;
   - direct and provenance-classified indirect control;
   - stack and runtime frames;
   - external events and relational world updates;
   - invariants, rankings, and product-graph composition.
4. Every new generic rule gets a small standalone positive and negative
   fixture before it is relied on for jq.
5. Unsupported or ambiguous states remain `incomplete`; budget overflows must
   not silently widen to an accepted relation.
6. Function recovery and source-level names may organize diagnostics and cache
   shards but cannot be trusted composition premises.

Track these measurements over time:

- distinct generated structural shapes;
- semantic IR and Lean constructor coverage;
- proof rules exercised;
- new profile branches and special-case conditionals;
- positive acceptance rate by family;
- negative rejection category;
- unresolved proof and discovery frontiers;
- source lines or constructors added per newly supported shape.

A rising acceptance rate accompanied by proportional profile-handler growth is
not success. It signals that the abstraction boundary needs repair.

## Emulator And Concrete Execution Role

Generated cases may be evaluated concretely by the semantic test evaluator,
Unicorn, Bochs, Wine in a headless Wayland/X session, or hardware harnesses.
These checks are useful for finding decoder and machine-semantics errors.

They are veto-only:

- disagreement blocks semantic qualification;
- agreement does not prove relational equivalence;
- undefined flags and CPU-profile-dependent behavior must be masked or
  classified explicitly;
- every observation records CPU model, segment state, fault class, and tool
  version;
- emulator output must never directly close a Lean obligation.

For tiny synthetic cases, concrete input enumeration can supplement negative
mutation validation where the input domain is deliberately bounded. It still
does not replace the universal theorem.

## Diagnostics

Failures should identify the first responsible semantic phase and retain the
complete downstream dependency frontier. At minimum report:

- case, seed, template, transformation, mutation, and capability profile;
- original and candidate semantic IDs, RVAs, and decoded bytes;
- expected relation, guard, effect, edge, or observation;
- for `violated`, the checked pre-state, conflicting effects, failed relation
  atom, observation/event index where applicable, and witness replay status;
- observed proposal/proof status and deterministic reason code;
- whether the failure is generation, toolchain, extraction, decoding,
  discovery, local refinement, invariant, composition, environment, audit, or
  performance;
- nearest source/state-machine location for Stage B cases;
- a ranked repair class and concrete next action for Stage B cases, clearly
  separated from the trusted witness;
- exact replay and reduction commands.

Do not collapse all expected-positive failures into `proof incomplete`, and do
not treat mapping failure as a failed equivalence theorem.

## Implementation Sequence

### Phase 0: Interface Inventory (Complete)

- Identify the stable public Stage A prepare/build/audit interfaces.
- Identify the canonical relation proposal and state-machine schemas.
- Record existing cache boundaries and Nix proof graph inputs.
- Define typed corpus, case, expected-result, and run-result schemas.
- Confirm the tiny PE path produces binaries accepted by ordinary extraction.
- Build the representative no-CRT PE32 canary and require it to close through
  the exact final `pe32ProgramsEquivalent` theorem.

Deliverable: schema document and one hand-authored representative case flowing
through current public interfaces without proof-core shortcuts and reaching a
Lean-kernel-checked final whole-program `pass`. Until this succeeds, later
corpus cases are diagnostic and cannot satisfy feasibility pass-count gates.

### Phase 1: Feasibility Generator (Complete)

- Implement the four semantic templates.
- Implement the initial transformations and negative mutations.
- Add deterministic assembly lowering and MinGW linking.
- Emit canonical manifests, known mappings, and replay metadata.
- Generate the 24-positive/12-negative spike corpus.

Deliverable: deterministic real-PE corpus with byte-identical regeneration
under the pinned toolchain.

### Phase 2: Proof-Core Runner (Complete)

- Add staged validation and content-addressed phase reuse.
- Route known relation proposals through normal Stage A validation.
- Batch Lean work and record phase timing/cache metrics.
- Classify proof frontiers without changing acceptance semantics.
- Add expected-result aggregation which treats any negative `pass` as fatal.
- Require checked witness replay for supported expected-`violated` cases and
  preserve `incomplete` only for declared capability-boundary cases.

Deliverable: proof-core spike report and reduced examples for each unexpected
failure family.

### Phase 3: Feasibility Decision (Complete)

- Evaluate every spike gate.
- Audit source changes for target/transformation/profile dispatch.
- Compare proof-schema growth with exercised shape growth.
- Measure cold and warm runs separately.
- Document go, revise, or stop with concrete evidence.

Deliverable: checked-in feasibility report. Do not proceed automatically when a
gate fails.

### Phase 4: Discovery Mode (Complete For Initial Families)

- Withhold mappings at controlled levels.
- Run ordinary proposal generation.
- Compare recovered relations semantically with known ground truth.
- Add mapping-specific reduction predicates and metrics.
- Keep discovery artifacts and proof artifacts independently cacheable.

Deliverable: per-family discovery success/frontier report with no change to
proof authority.

### Phase 5: Stage B Round Trip (Complete)

- Export a state machine from a simple original fixture.
- Generate semantic C through the normal Stage B backend.
- Compile it as a PE32 candidate in the pinned environment.
- Preserve source-map and implementation-manifest bindings.
- Audit that every Stage B input came from an allowed opaque-binary Stage A
  artifact or an explicit recorded manual annotation.
- Prove the resulting pair through the same final Stage A path.

Deliverable: one reproducible end-to-end opaque-binary-style round trip, with
manual repairs explicitly recorded if required.

### Phase 6: Corpus Expansion (Future Work)

Only after the spike passes, add families in this order:

1. multiple joins and nested loops;
2. nested and recursive internal calls;
3. static writable data and pointer relocation;
4. bounded jump tables and indirect calls;
5. paired dynamic ranges and allocation-like events;
6. exact 1:1 imported calls and opaque resources;
7. callbacks with nested internal/external frames;
8. x87 and additional qualified instruction families;
9. compiler-generated C variants under controlled flags.

Each family starts with explicit positive/negative qualification cases and must
be reduced before being promoted to the permanent corpus.

## Tests

### Unit Tests

- canonical schema parsing and deterministic hashes;
- deterministic generation from seed;
- transformation precondition rejection;
- negative mutations alter exactly one declared semantic property;
- supported negative witnesses replay against exact decoded semantics;
- raw solver status, malformed witness data, or stale binary bindings cannot
  produce `violated`;
- Stage B provenance rejects generator semantics, seeds, ground-truth maps,
  and private lowering metadata;
- lowering preserves labels, relocations, and capability inventory;
- toolchain failures are stable and actionable;
- reducer preserves the selected predicate;
- cache keys change only with semantic dependencies;
- genericity scanner catches forbidden fixture dispatch.

### Integration Tests

- build and parse a PE pair for every spike template;
- run positive and negative smoke subsets through Stage A preflight;
- Lean-check at least one positive from every template;
- verify every negative is non-passing;
- verify supported negatives produce checked, source-mappable `violated`
  witnesses and capability-boundary negatives produce expected `incomplete`;
- run one discovery case with mappings withheld;
- run one Stage B state-machine-to-C-to-PE-to-proof case;
- regenerate the corpus and compare canonical hashes;
- perform a warm rerun and assert cache reuse thresholds.

### Nix Qualification

- expose the pinned generation/toolchain environment;
- add a cheap smoke check before the full corpus;
- shard promoted proof cases as derivation packs based on measured cost;
- aggregate reports without rerunning successful shards;
- record derivation/store identities in proof reports;
- allow remote builders to schedule independent packs;
- keep the complete corpus as a release gate, not the inner edit loop.

## Initial Full-Corpus Qualification Target

After the spike succeeds, the first promoted corpus should contain at least:

- 50 positive pairs;
- 25 negative pairs;
- all spike templates and transformations;
- at least one discovery case per template;
- at least one Stage B semantic-C round trip;
- multiple seeds per semantic family.

Qualification requires:

- every promoted positive reaches the exact final whole-program theorem;
- no negative reaches `pass`;
- every supported negative has a replayed checked `violated` witness;
- no case is accepted through legacy or intermediate certificate authority;
- artifacts and reports regenerate deterministically;
- all unsupported capability requests fail closed;
- warm-cache and cache-reuse targets remain satisfied;
- genericity metrics show semantic-rule reuse across structurally distinct
  cases.

## Risks And Mitigations

### Equivalent-By-Construction Bugs

The generator may incorrectly label a pair as equivalent. Mitigate with typed
transformation preconditions, independent semantic evaluation, concrete
cross-checks, small templates, and reviewable emitted assembly. Such checks
validate the corpus expectation, not Stage A acceptance.

### Testing Only Generator-Shaped Programs

A compact generator can become its own artificial compiler. Add orthogonal
lowerings, compiler-produced variants, reduced real blockers, and periodic
coverage comparison against jq instruction/control inventories.

### Optimizing For Fixture Passes

Track forbidden dispatch and semantic-rule reuse. Require each new rule to be
stated independently of the triggering case and validated by unrelated
positive and negative fixtures.

### Proof Runs Still Too Slow

Do not lower correctness gates. Profile phase invalidation, increase batching,
stabilize Lean module boundaries, reuse persistent kernels, and adjust Nix pack
sizes. If tiny warm proofs remain slow, repair architecture before expanding the
corpus.

### False Confidence From Positive Coverage

Positive acceptance measures completeness only. Maintain a substantial
negative corpus and make any negative `pass` a hard blocker. Include mutations
at decode, control, memory, ABI, environment, termination, and manifest levels
as those capabilities are introduced.

### Drift Between Diagnostic And Formal Models

Generate contracts, diagnostics, and source maps from the same typed semantic
objects serialized into Lean-checked proof inputs. Do not maintain an
independent permissive diagnostic schema that can report closure absent from
the formal proof graph.

## Definition Of Done

All ten conditions below are satisfied for the bounded initial profile. The
checked results and scope limitations are recorded in
[`stage-a-round-trip-fuzzing-report.md`](stage-a-round-trip-fuzzing-report.md).
Future Phase 6 families must qualify independently under the same conditions;
they do not inherit support merely from this completion record.

The feature is complete when:

1. The feasibility spike has passed its stated gates and its report is checked
   in.
2. The three modes share canonical typed artifacts and stable public Stage
   A/Stage B interfaces.
3. Positive cases close only through the final Lean whole-program theorem.
4. Negative mutations never pass and produce reproducible reduced cases.
   Supported semantic mutations specifically produce replayed `violated`
   witnesses; declared capability-boundary mutations produce `incomplete`.
5. The warm development loop meets its timing and cache targets.
6. The promoted Nix corpus is reproducible, shardable, remotely buildable, and
   independently aggregatable.
7. Genericity reports demonstrate broad structural coverage without
   proportional profile or handler growth.
8. At least one Stage B semantic-C candidate generated from static Stage A
   evidence is compiled and formally proved against its synthetic original,
   with an audit proving that no generator-only semantic knowledge crossed the
   opaque-artifact boundary.
9. Adding a new generated shape normally requires data and existing semantic
   constructors, not a new named proof profile.
10. Failures in unsupported regions remain precise, actionable, and fail
    closed.

Only after these conditions hold should this corpus be used as the rapid
qualification layer for broadening Stage A toward complete jq coverage and,
later, more varied x86 PE32 applications.
