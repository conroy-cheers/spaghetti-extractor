# High-Assurance Reimplementation Direction

## Status

This document defines the primary project direction as of 2026-08-01.

The objective is to produce a correct and faithful reimplementation while
minimizing the realistic ways that extraction, lowering, repair, compilation,
or refactoring mistakes can survive. A final end-to-end Lean theorem is useful
when practical, but it is not a mandatory condition for a successful
reimplementation.

The stricter binary-to-binary and source-relative theorem tracks remain
available as optional assurance layers and research profiles. Their existing
`pass` and `conditional_pass` terms retain their strict meanings. A locally
checked result, test result, or high-assurance qualification must never be
reported as one of those formal verdicts.

## Objective

The primary completion claim is:

> Produce a high-assurance reconstruction in which every transformation is
> formally checked, exhaustively checked, differentially tested, or explicitly
> recorded as an assumption, with no reachable behavior silently omitted.

Formal methods are used where they most effectively prevent mistakes. They are
not an end in themselves, and the architecture must not turn a practical
reimplementation into a prerequisite for solving general whole-program
equivalence.

The original binary remains a static input. It must not be executed or traced
during extraction, generation, repair, or validation. Executable reference
behavior comes from the statically derived canonical IR model and, after that
model has been qualified, from the generated baseline candidate.

## Core Tradeoff

A practical generic system cannot cheaply provide all three of:

1. A tiny trusted base.
2. A theorem beginning at arbitrary raw x86 bytes.
3. A human-readable equivalent implementation.

This direction deliberately enlarges and audits the trusted base. It may trust
a pinned x86 decoder/lifter, a constrained solver, ABI catalogs, a compiler and
linker, and an extensional external-environment law. Independent conformance
oracles, exact provenance, mutation testing, and fail-closed coverage reduce
the risk introduced by those assumptions.

The trust tradeoff must remain visible in every report. Agreement between
oracles is validation, not a Lean proof.

## Target Pipeline

```text
exact original PE
    |
    | static extraction only
    v
pinned decoder/lifter + independent qualification
    v
canonical executable machine IR
    |                         |
    |                         +-- executable IR reference model
    v
checked and tested IR-to-C0 lowering
    v
generated full-machine-state C0 baseline
    v
pinned reproducible compilation
    v
candidate PE
    v
candidate-only integration and behavior validation
    v
progressive source reconstruction against the qualified baseline
```

The canonical IR, not Python status fields or decompiler output, is the common
semantic artifact. Source generation, source maps, region contracts,
diagnostics, validation vectors, and the executable reference model must all
derive from the same versioned IR.

## Trusted Components

The initial profile may explicitly trust:

- a pinned PE parser and x86 decoder/lifter;
- the normalized machine-IR semantics;
- a pinned Z3 version for an approved bitvector and array fragment;
- reviewed machine-level ABI and import-signature catalogs;
- the pinned C compiler, assembler, linker, and ABI lowering;
- the external extensionality law described below.

Each trusted component must have an exact version, source or binary identity,
configuration, capability profile, and reason for trust recorded in the final
assurance report.

The x86 frontend should be qualified against multiple independent sources,
including Bochs, Unicorn, hardware-produced vectors where practical, strict
instruction corpora, and at least one independent decoder or lifter. Undefined
architectural results must be represented explicitly rather than compared as
ordinary values. A disagreement produces `violated` or `incomplete`; majority
agreement does not silently select a winner.

## External Environment

Stage A does not need to implement Windows, libc, Direct3D, a driver, or a GPU.
The initial environment profile assumes the following relational law:

```text
related external histories
+ the same normalized call or callback identity
+ related scalar and resource arguments
+ equal relevant pointed-to input bytes
---------------------------------------------------
related results, writes, callbacks, and successor worlds
```

The tooling must still establish event identity, order, ABI state, arguments,
memory footprints, callback targets, and continuation use. Time, input,
scheduler choices, asynchronous completion, and other nondeterminism are
external responses. Concrete pointers and handles may differ through checked
pairings.

Using the same pinned external libraries makes this assumption more
defensible, but does not remove the need to validate pointed-to memory and
resource relationships.

## Generated Baseline

The first reconstruction is deliberately low level. It should use a canonical
state such as:

```c
struct MachineState {
    uint32_t eax, ebx, ecx, edx;
    uint32_t esi, edi, ebp, esp;
    uint32_t eip;
    Flags flags;
    X87State x87;
    GuestMemory memory;
    ExternalWorld world;
};
```

Generated regions update this state and return a next control point, external
event, return, fault, or termination result. The baseline may be unattractive
and slow. Its purpose is to be a dependable executable semantic reference.

Normalized IR is preferred over shipping original instruction bytes. A
runtime decoder carrying the original executable image is a separate,
explicit specialized-emulator profile and must not be confused with an
independent source reconstruction. Self-modifying code, executable-memory
writes, and JIT execution fail closed in the initial static-translation
profile.

## Validation Units

The default validation unit is an acyclic basic block or short path between
semantic cutpoints. Units may be split or merged according to symbolic and
solver complexity. Cutpoints normally include roots, branch targets, loop
headers, calls, external events, callbacks, indirect control, faults, and
termination.

Each unit must bind:

- exact original RVA and byte provenance;
- normalized IR and instruction-form inventory;
- generated C0 AST and exact source location;
- entry assumptions and live state;
- register, flag, x87, memory, and world effects;
- complete guarded exits and target identities;
- external events and ABI footprints;
- local validation evidence and unresolved assumptions.

The preferred boundary relation is the canonical full-machine-state
representation. This avoids discovering a program-specific relation at every
loop or join. Higher-level relations are introduced only during progressive
reconstruction.

## Evidence Classes

Every material claim must carry one or more evidence classes:

- `formal`: checked by Lean from reviewed generic rules;
- `exhaustive`: checked over a complete finite domain;
- `solver`: discharged by the pinned approved solver fragment;
- `differential`: agreed by independent implementations over recorded cases;
- `fuzzed`: exercised by reproducible generated cases;
- `integration`: exercised by curated or upstream behavior tests;
- `assumed`: explicitly trusted and identified;
- `unsupported`: not qualified.

Evidence classes are not interchangeable. Reports must preserve the exact
class and scope instead of collapsing them into an undifferentiated `pass`.

A reachable unit may not remain `unsupported`. A reachable assumption may be
accepted only when the selected qualification profile explicitly permits that
assumption and records its consequences.

## Formal Work Priorities

Formal or solver-backed checking is highest value for:

- generic instruction and IR semantics;
- generic IR-to-C0 lowering rules;
- register, flag, x87, and memory effects;
- direct exits and finite indirect-target checks;
- ABI stack and register conventions;
- memory footprints and pointer provenance;
- local source-to-source replacements;
- exact artifact, coverage, and composition checkers.

The initial high-assurance profile does not require formal proofs of:

- complete end-to-end execution;
- termination or divergence of arbitrary loops;
- Windows or imported-library implementations;
- every callback protocol as a Lean response family;
- every human-readable refactoring;
- every compiled-candidate machine transition;
- a bidirectional whole-program bisimulation.

The strict theorem tracks may continue to pursue those results, but they must
not block the primary reconstruction workflow.

## Qualification Gate

Runtime validation may begin only after the static qualification gate confirms:

- every selected root and reachable unit is present;
- every unit has a supported lowering and recorded evidence;
- direct exits are complete;
- indirect targets are checked or covered by an explicitly selected trusted
  target-inventory profile;
- all external boundaries have machine-level signatures and footprints;
- source maps and transfer identities are exact and unique;
- source and build inputs are content-bound;
- there are no unknown reachable control or external boundaries.

This gate is not a whole-program theorem. It exists to prevent runtime testing
from masking grossly incomplete reconstruction.

Runtime tests execute only the IR reference model, generated candidate, proved
baseline, or later derivatives. They never execute the original PE. Wine runs
must use a headless Wayland/X session. A candidate behavior failure after all
local evidence is clean is a red flag for the lifter, lowering, ABI bridge,
external profile, compiler assumption, or coverage analysis.

## Progressive Reconstruction

Every generated region exposes a stable semantic contract independent of its
implementation. The intended replacement rule is:

```text
baseline implementation satisfies regional contract
+ replacement implementation satisfies the same contract
---------------------------------------------------------
replacement may be installed without revisiting the original binary
```

Operator-defined semantic components sit above cutpoint-bounded validation
units. They may combine one block, a noncontiguous procedure, a subsystem, or
child components. The machine boundary is derived from canonical IR; the
logical interface remains an untrusted proposal until separately refined.
Component definition, implementation, refinement, and assurance statuses must
remain distinct. Completing a component cannot hide reachable or potentially
reachable units omitted from the global residual coverage ledger.

Reconstruction should proceed through these layers:

1. Full-machine-state C0.
2. Local variables and SSA-like expressions.
3. Typed views over stack, static, and dynamic memory.
4. Recovered call frames and ordinary C calls.
5. Structured branches, switches, and loops.
6. Real structs, arrays, ownership, and data-layout abstractions.
7. Algorithmic and library-level replacements.

Typed views should precede layout changes. A memory range may change
representation only after its ownership, aliasing, pointer identity, and
external visibility are understood. Externally visible buffers either retain
their exact byte layout or use validated encode/decode adapters.

For each replacement, the tooling should generate regional input states,
symbolic obligations where tractable, reproducible differential tests, source
maps, external-event comparisons, and a precise residual risk report. The IR
model or qualified baseline is the reference oracle; the original binary is
not run.

The supported operator loop is now explicit:

```sh
spaghetti-extractor stage-b-plan-reconstruction \
  --machine-ir machine-ir-package \
  --signature-catalog profiles/pe32-runtime-v1.json \
  --out reconstruction-plan.json
spaghetti-extractor stage-b-create-replacement \
  --plan reconstruction-plan.json \
  --machine-ir machine-ir-package \
  --interpreter-package interpreter-package \
  --entry-rva 0x1038 --out-dir work/compare
# Edit only work/compare/src/implementation.c and its portable header.
spaghetti-extractor stage-b-rebind-replacement --workspace work/compare
spaghetti-extractor stage-b-run-replacement-check \
  --workspace work/compare \
  --interpreter-package interpreter-package \
  --out-dir work/compare
spaghetti-extractor stage-b-promote-replacements \
  --workspace work/compare --out-dir promoted
spaghetti-extractor stage-b-reconstruction-status \
  --plan reconstruction-plan.json \
  --registry promoted/reconstruction-registry.json \
  --out reconstruction-status.json
```

For semantic-component replacements, use the stricter component workspace
commands documented in `docs/semantic-component-framework.md`. Sampled
regional comparison is integration evidence only; component activation also
requires source evidence, exact generated-adapter integrity, checked component
call closure, and a content-bound qualification artifact.

The portable implementation and generated machine adapter are separate,
content-bound translation units with recorded source-line boundaries. Portable
code may use typed values and service interfaces, but not
`stage_b_machine_state`, registers, flags, or guest-memory callbacks. The
generated adapter owns those details. A pristine generated source is retained
so a failed check can rank exact edited lines as repair locations.

Template selection is fail-closed and checks complete normalized semantic
shapes. A mnemonic resemblance is insufficient. Unsupported clusters remain
ranked work with a blocker rather than receiving speculative C. Human or
LLM-guided implementations are permitted and expected; automation only has to
make their contracts, boundaries, validation, and residual risk precise.

## Lifting Workbench Evidence

The plan derives disjoint clusters from the decoded rooted control graph.
Reachability has three states:

- `reachable`: reached through checked direct or finite indirect edges from a
  checked root;
- `potential`: not reached by the closed graph, but not excludable while a
  rooted indirect frontier remains unresolved;
- `unreachable`: excluded only after rooted closure is complete.

A broad target profile or unchecked function inventory cannot promote a
potential unit to reachable or unreachable.

Cluster contracts project typed memory views, valid-memory and alias
preconditions, locked atomic effects, machine-import signatures, callback
lifetimes, and nested callback frames. Finite jump tables retain their
path-bound selector expression, immutable table hash, every table entry, and
every destination. Workspaces generate boundary, branch, exhaustive dispatch,
valid/faulting memory, alias, and mutation cases from those same contracts.

Straight-line pure transformations may be checked with:

```sh
spaghetti-extractor stage-b-check-semantic-claim \
  --reference reference-claim.json \
  --proposed proposed-claim.json \
  --out semantic-claim-result.json
```

This command proves or refutes explicit normalized bitvector output and
control expressions. It does not claim to prove arbitrary C text, memory,
external services, x87 state, or concurrency. Unsupported claims return
`incomplete`; a semantic mismatch returns `violated` with a concrete input.

Local source-to-source proofs are encouraged for sensitive transformations.
They are not mandatory for all readability work. A derivative that leaves the
formally checked class is labeled test-validated and does not inherit an
optional whole-program theorem held by its baseline.

## Assurance Report

The final report is an assurance case, not a disguised proof verdict. It must
include at least:

- exact original, IR, source, toolchain, and candidate identities;
- root, unit, executable-byte, exit, indirect-target, and external-boundary
  coverage;
- ISA forms and their qualification evidence;
- validation evidence by class and unit;
- oracle disagreement and mutation-test results;
- imported ABI and footprint coverage;
- candidate-only functional and integration results;
- explicit trusted components and assumptions;
- every known unsupported or untested behavior;
- whether an optional formal theorem exists and its exact axiom inventory.

No report may claim stronger assurance than its weakest undisclosed dependency.

## Performance And Caching

The following are separate content-addressed Nix phases:

- exact static extraction;
- pinned lifting and IR packs;
- ISA qualification;
- C0 lowering packs;
- local solver and differential validation packs;
- external-boundary qualification;
- source rendering;
- candidate compilation;
- static qualification aggregation;
- candidate-only runtime suites;
- optional Lean theorem composition.

Adding or replacing one region should invalidate its IR/lowering evidence,
direct dependents, affected source objects, and aggregate reports. It must not
rerun unrelated lifting, Ghidra/skeleton generation, ISA qualification, or
runtime suites. A trivial static smoke check runs before expensive validation.

## Scalability Tests

The architecture is viable only if manual work scales with distinct semantic
and interface classes rather than block count.

For every benchmark, report:

- generated unit count;
- distinct instruction and IR forms;
- unsupported ISA forms;
- distinct external protocol classes;
- unresolved indirect-control classes;
- site-specific manual interventions;
- evidence counts by class;
- clean and one-region incremental times;
- mutation detection rate;
- candidate-only behavior coverage.

GNU hello is the first consolidation target. It must not require handwritten
proofs or repairs for thousands of individual blocks. Jq is the first
meaningful scalability target. If jq still requires hundreds of site-specific
interventions, the IR, lowering, target, or environment abstractions are not
generic enough.

After jq, use a representative PE32 3D application before attempting a full
game. Threads, scheduler choices, asynchronous APIs, SEH, and dynamic code are
separate capability profiles, not assumptions smuggled into the initial one.

## Transition From The Current Architecture

Retain and reuse:

- exact PE and reference-contract extraction;
- canonical semantic IR and state-machine generation;
- ISA corpus, Bochs, Unicorn, and hardware qualification machinery;
- source maps, candidate-only feedback, and round-trip fuzzing;
- the native C backend and reproducible candidate build;
- content-addressed Nix phase boundaries;
- external ABI, memory-footprint, callback, and resource schemas;
- strict unknown and unsupported diagnostics.

De-emphasize as primary blockers:

- per-program Lean decoding of every instruction;
- per-target custom preservation-provider closure;
- candidate-binary block equivalence;
- complete concrete response-family construction;
- universal launch-family and termination proofs;
- mandatory final whole-program bisimulation.

The existing strict proof machinery remains useful for generic kernels,
fixtures, local replacements, and optional stronger releases. It should be
retained where it catches errors economically and simplified where it exists
only to close a theorem that no longer defines primary completion.

## Decision Rule

Prefer the technique that removes the most plausible reconstruction mistakes
per unit of implementation and computation cost.

When a formal proof is simple, reusable, and local, prove it. When a mature
component must be trusted, pin and independently qualify it. When behavior is
best explored dynamically, run the statically derived model and candidates,
record reproducible evidence, and mutate the implementation to prove that the
checks detect errors. Never replace an unknown with an unrecorded assumption.
