# Stage A Internal Equivalence And 3D Application Roadmap

> **Status:** This document records the stricter mandatory-whole-program-
> theorem roadmap and is retained as formal-track design history. The primary
> project direction is now
> [high-assurance-reimplementation-direction.md](high-assurance-reimplementation-direction.md).
> Formal proofs remain important local assurance tools, but a final
> end-to-end theorem is no longer required for the primary reconstruction
> workflow.

Implementation can proceed across the versioned workstreams in
[stage-a-parallel-development.md](stage-a-parallel-development.md). This does
not split acceptance authority: all workstreams still converge on the one
Lean-checked whole-program theorem.

## Purpose

This document records two connected plans:

1. Complete the formal internal-equivalence machinery required for a Stage A
   whole-program theorem.
2. Reuse that machinery first on a representative PE32 3D application and
   then on a complete game and its libraries.

The first plan is concrete because it extends the current
`x86-pe32-relational-v3` implementation. The second is intentionally looser.
It establishes capability gates and acceptance conditions without prematurely
choosing graphics APIs, concurrency rules, or target-specific transfer
semantics before representative binaries expose the real blockers.

This is a forward plan, not a statement that the current implementation has
already achieved these guarantees. The current implementation boundary and
measured jq composition frontier remain documented in
[stage-a-relational-v3.md](stage-a-relational-v3.md).

## End Goal

The project should be able to produce an intentionally conservative,
potentially ugly C reimplementation of an opaque x86 PE32 application and its
libraries, compile it under a proof-oriented build profile, and obtain a
Lean-kernel-checked theorem that the resulting binaries have the same behavior
as the original binaries under an explicit platform profile.

The practical external boundary is exact lockstep interaction with a shared,
opaque, stateful platform oracle. The theorem should quantify over every
permitted sequence of inputs, API results, clock values, callbacks, scheduler
decisions, and other external choices. It should prove that the two systems:

- reach corresponding external interactions, returns, faults, and termination;
- produce the same canonical external interaction at each boundary;
- supply related scalar arguments, pointers, buffers, resources, and callbacks;
- consume one shared canonical result and restore the internal state relation;
- preserve the declared application and library component relations.

The oracle does not formalize Windows, libc, Direct3D, a graphics driver, or a
GPU. It represents their stateful behavior abstractly. Exact event identity and
canonical input equality ensure that the original and candidate are clients of
the same abstract transition. This gives a universally quantified contextual
equivalence theorem without requiring Stage A to implement the external
software stack.

The proved Stage B source and binaries become the conservative baseline.
Performance work, refactoring, different external protocols, and ports may be
performed afterward and validated against a full-coverage test suite derived
from that baseline. Those derivatives do not inherit the Stage A theorem unless
they are submitted to Stage A again.

## Fixed Design Decisions

The following decisions define the least-pain initial proof class:

- Stage A remains generic, binary-to-binary, and independent of source
  provenance.
- Internal paths may relate N:M finite block sequences between checked
  cutpoints.
- External interactions initially relate exactly 1:1 in the same order.
- An external event index is proof bookkeeping, not physical time.
- Reads of time, input, network data, and other nondeterministic values are
  external oracle interactions.
- Concrete addresses and handles may differ through checked canonical tokens.
- External APIs require machine-level interface schemas, not behavioral
  implementations. Those schemas explicitly classify preserved/clobbered
  registers and any exact or related-word result-register guarantees used by
  continuation invariants.
- The candidate may use proof-oriented, low-level, unattractive C, explicit
  wrappers, and narrow assembly stubs.
- Producing that candidate is an interactive synthesis and repair process, not
  a required fully automatic decompilation pass.
- Unsupported instructions, targets, callbacks, effects, schedules, or
  relations produce `incomplete`, never an approximation or waiver.
- `pass` is available only from the final whole-program theorem over the exact
  binaries. Regional, image, and local-segment certificates remain
  intermediate evidence.

## Proof Boundary

The final claim is necessarily relative to a launch and environment profile.
It should have the following meaning:

```text
for every permitted initial launch world
for every permitted shared external oracle and scheduler behavior
for every original and candidate state satisfying the entry relation
the original and candidate executions have related observable behavior
```

For a real-time graphics program, related observable behavior initially means
the same canonical window, input, clock, audio, file, network, and graphics
events with related data. If both sides use the same pinned driver and hardware
profile, equal graphics commands, shaders, resources, and presentation events
are delegated to the same implementation. A driver-independent theorem about
final pixels would require formal GPU and driver semantics and is outside this
roadmap.

The theorem does not claim that two independently launched programs observe
the same physical clock or operating-system schedule. It proves equivalence
when both are supplied the same abstract clock, inputs, external results, and
scheduler choices. This is the ordinary same-environment interpretation of
program equivalence.

## Track A: Complete Internal Equivalence

### Completion Goal

Internal-equivalence work is complete for the first practical profile when
Stage A can derive, rather than assume, a closed rooted product execution for
the full jq different-layout pair and connect every reachable internal path to
one of these checked outcomes:

- the next paired canonical external event;
- paired normal return;
- paired supported fault;
- paired termination;
- another checked internal cutpoint with an inductive invariant.

Every reachable edge must have a checked segment refinement or an explicit
fail-closed blocker. Every executable byte must remain classified, although
behavioral composition only covers code proved reachable from the declared
roots. The generated `candidatePE32ProgramsEquivalent` theorem must be the only
acceptance gate.

### Why This Work Remains Necessary

The shared external oracle removes detailed API semantics. It does not prove
that either binary reaches an API correctly. Before an external transition can
be shared, Stage A must prove that both sides:

- reach the corresponding boundary without an earlier event, return, or fault;
- satisfy exhaustive path guards;
- identify the same canonical call or callback;
- have related ABI state, arguments, pointed-to input data, and resources;
- preserve all internal state not transferred to the external component;
- resume at related continuations after the shared result.

This is the purpose of the current machine semantics, `StateRel`, paired
segments, runtime frames, invariants, product graph, and whole-program
composition work.

### Authoritative Formal Objects

The internal proof should converge on one checked path through these objects:

- `StaticProofContext` for exact PE facts, code/data maps, roots, imports,
  relocations, observations, and launch facts;
- one authoritative `StateRel` over registers, flags, x87/SIMD state as
  supported, concrete flat memory, undefined values, TLS, static mappings,
  dynamic ranges, resources, and runtime frames;
- `RelationalSegmentRefinement` for paired finite paths between cutpoints;
- a canonical rooted product graph derived from decoded exits;
- checked invariant and reachability certificates;
- a boundary outcome that distinguishes internal continuation, canonical
  external event, callback entry, return, fault, and termination;
- `WholeProgramCertificate` and `pe32ProgramsEquivalent` as the only final
  acceptance objects.

Generated JSON contracts must serialize these same proof objects. A separate
diagnostic model must not be allowed to drift from the Lean-checked model.

### Human-Guided Reimplementation Policy

Full automation of the ugly-C reimplementation is not a completion condition
for this roadmap. A small to moderate amount of human or LLM-guided judgment is
an acceptable and expected way to keep Stage B tractable. The tooling should
reduce a large binary into precise, independently checkable repair tasks rather
than attempt to infer every useful source-level decision without assistance.

Untrusted guidance may provide or revise:

- cutpoint and finite-path mappings;
- function, callback, and jump-table boundaries;
- loop invariants and bounded target inventories;
- data-layout, pointer, resource, and ABI annotations;
- external interface schemas and canonical value classifications;
- source types, control structure, helper boundaries, and explicit wrappers;
- proof-oriented compiler attributes, linker placement, and assembly stubs;
- candidate C implementations for individual cutpoint clusters;
- proposed relation witnesses and solver lemmas.

None of these proposals becomes a trusted fact merely because a human, LLM,
decompiler, linker map, debug database, or heuristic supplied it. Stage A must
reconstruct the relevant facts from the exact original and candidate binaries
and have Lean check every witness used by the final theorem. Incorrect guidance
must produce a counterexample, a rejected certificate, or `incomplete`, never a
waiver.

The ergonomic target is therefore assisted convergence:

1. Stage A emits one bounded proof frontier and a complete
   `stage-a-semantic-ir-v1` transfer inventory with explicit input, output,
   control, memory, and boundary requirements.
2. Stage B serializes that inventory as canonical `state-machine.jsonl` and
   generates a compiler-consumable C transition library from symbolic effects.
   Every generated source region binds to transfer IDs and hashes; a transfer
   without a source binding is a blocker. Original instruction-byte wrappers may
   bootstrap layout experiments, but they remain explicit incomplete fallbacks
   and do not count as semantic-C reimplementation coverage.
3. A human or LLM chooses an implementation or annotation that is likely to
   satisfy that contract.
4. Stage B rebuilds the affected candidate objects.
5. Incremental Stage A checks accept the proposal or return a more precise
   frontier.
6. The complete final proof remains reproducible without trusting the repair
   conversation or its author.

Manual assistance should improve synthesis, not replace scalable proof. The
roadmap does not accept thousands of unchecked per-block assertions, manual
runtime comparisons with the original, or a final theorem that depends on
human claims. Reusable generic machinery and interface schemas should absorb
repeated work as more applications are reimplemented.

### Internal Outcome Interface

Composition should target a small boundary interface rather than independent
status fields:

```text
Related states at a paired cutpoint
  -> paired finite internal execution
  -> internal cutpoint with successor StateRel
   | same canonical external event
   | paired callback boundary
   | paired return
   | paired fault
   | paired termination
```

External calls are strong synchronization cutpoints, but they are not the only
cutpoints. Loops, joins, internal calls, indirect dispatch, and long pure
computations still require internal cutpoints and inductive invariants.

### A1. Reconcile The Current Segment Path

Finish the in-flight generic segment work before expanding the architecture:

- support side-specific normalized original and candidate behaviors whenever
  the shared normalized fast path is unavailable;
- close relocated direct calls whose concrete pushed return addresses differ;
- retain the generic paired-memory-update and finite stack-write theorems;
- retain explicit value witnesses and shared guard proof generation;
- ensure generated contracts and Lean modules consume one certificate object;
- replay focused generic fixtures before rebuilding the affected jq chunks.

The current jq direct-call normalization failure is a generic correctness gap,
not a jq-specific transfer rule. It should be fixed and covered by a small PE32
fixture with different code layouts and mapped continuations.

### A2. One State Relation And Generic Memory Frames

Complete one compositional state relation instead of maintaining local and
whole-program proof regimes. Exact equality should be a relation atom, not an
alternate proof mode.

Required work:

- generalize paired memory updates over checked read/write footprints and
  disjointness witnesses;
- use the same theorem for stack spills, prologues, out-parameters, static data,
  dynamic allocations, pointer slots, and imported-call materialization;
- keep flat concrete x86 memory authoritative;
- carry explicit witnesses for static targets, dynamic ranges, resources, and
  bounded pointer alternatives;
- reject pointer-disjunction widening beyond the configured finite budget;
- make relational runtime call frames authoritative for nested calls and
  recursion rather than growing unbounded ESP-relative windows.

The proof generator may propose address ranges and aliases. Lean must check
that each proposal implies the concrete memory relation used by the theorem.

### A3. Paired Finite Paths

Use cutpoint clusters as the implementation and proof unit. A segment may
contain different finite block sequences on each side and should support:

- split and merged blocks;
- inverted branches;
- different prologues and epilogues;
- local instruction scheduling differences;
- compiler-generated helper blocks;
- direct calls and returns with mapped continuations;
- checked finite internal indirect targets.

Silent cycles inside a finite path remain prohibited initially. Cycles belong
in the product graph with invariants or an explicit ranking theorem.

### A4. Product Graph Completeness

Composition progress is the primary metric. Lean must derive graph coverage
from decoded behavior rather than trust a submitted edge list.

For every rooted reachable product node, check:

- all feasible decoded exits are represented;
- outgoing guards cover both sides' behavior;
- each direct destination is a valid mapped cutpoint;
- each indirect destination belongs to a checked finite target set;
- call and return transitions preserve runtime frames;
- no reachable external event, return, or fault is omitted;
- every edge has the required segment or boundary refinement;
- unreachable code is omitted only after checked reachability closure.

Reports should foreground rooted reachable nodes, feasible edges, refined
segments, unresolved indirect targets, unsupported instructions, invariant
frontiers, and boundary frontiers. Raw local-proof counts are secondary.

### A5. Loops, Joins, And Termination

Loops and control-flow joins require checked inductive invariants over the
unified state relation. Stage A should:

- synthesize candidate invariants from symbolic execution and relation facts;
- use Z3 to propose or discharge supported bitvector and memory conditions;
- have Lean replay or check the supported solver evidence;
- check SCC entry, preservation, and exit coverage;
- require ranking or another reviewed rule where termination correspondence
  cannot be obtained from lockstep/product progress;
- distinguish a proved paired infinite execution from an unresolved liveness
  obligation.

A raw solver `unsat` result or Python status must never close final acceptance.

### A6. Indirect Control And Callbacks

Classify indirect control by checked provenance:

- immutable relocation-backed code pointers;
- import thunks and imported function pointers;
- bounded jump tables;
- writable global function pointers;
- dynamic-range callback slots;
- registered external callback tokens;
- genuinely unknown targets.

Finite target sets must be reconstructed from exact bytes, mappings, and
runtime relation witnesses. Unknown or ambiguous control remains a visible
frontier. Function names and linker ranges may organize diagnostics and caches
but are not trusted composition facts.

Synchronous callbacks eventually use a mixed runtime stack containing internal
call, external-call, and callback frames. An external frame records the
pending event, paired continuation, permitted callback targets, and successor
relation. Well-bracketed callbacks are the first supported profile;
asynchronous callbacks are deferred to Track B.

The migration must remain fail closed while this stack is introduced. The
mixed-frame kernel wraps existing internal frames and checks external return
tokens and paired stack slots. The whole-program execution relation now has
explicit suspended-protocol and callback-running cases, but the corresponding
machine-call disposition remains structurally invalid. Acceptance may enable it
only after the product bisimulation checks paired protocol actions, callback
entry, nested internal/external frames, callback return, protocol resumption,
and final termination.

### A7. Lockstep External Boundary

Refactor the current paired-environment direction into one shared canonical
external transition relation. Both sides must lower to the same canonical
event before that transition is available.

A canonical event records only interface information:

- resolved provider/export or interface/method identity;
- ABI and call/return shape;
- exact scalar arguments;
- static, dynamic, resource, and callback tokens;
- canonical snapshots of input memory required by the interface schema;
- permitted output materialization locations;
- event kind and nesting information.

The shared oracle threads opaque external state and returns one canonical
result plus a successor external world. Stage A materializes that result into
related concrete states. It does not implement file, allocator, CRT, graphics,
or network behavior.

Machine-call contracts should therefore become interface schemas. They may
describe calling convention, value kinds, buffer extents, callbacks, clobbers,
and result locations. They should not grow into API-specific operational
semantics.

### A8. Component And Library Composition

Support a proof graph over application and library components:

- a reimplemented library has a certificate for declared exports, callbacks,
  TLS initializers, and reachable internal behavior;
- an unchanged pinned library may use a hash-bound identity/self-equivalence
  certificate;
- a statically linked library is ordinary internal code;
- a call between certified components is discharged by component composition;
- only transitions into unproved platform components remain oracle events.

The final certificate records exact component hashes, dependency identities,
loader assumptions, export/import bindings, and the external profile. Pinning
identifies a component; a proof certificate or an explicit platform-oracle
boundary determines its logical role.

### A9. Solver And Lean Trust Boundary

Z3 remains an automation engine. Lean remains the acceptance authority.

Stabilize a small normalized proof IR for:

- decoded instruction and path semantics;
- guards and finite target sets;
- register and memory relation witnesses;
- segment preconditions and effects;
- invariant preservation;
- SCC and reachability certificates;
- canonical event construction.

Supported solver results must be replayed by Lean bitvector reasoning, checked
through a reviewed certificate format, or checked by a verified fragment
checker. Query hashes and raw statuses are useful audit metadata but are not
proofs.

### A10. Incremental And Distributed Proof Workflow

Preserve independent cache boundaries for:

- PE extraction and exact-byte attestations;
- instruction decoding;
- mapping proposals;
- relation and invariant synthesis;
- segment certificates;
- product-graph composition;
- component composition;
- final acceptance audit.

A candidate source change should rebuild only changed candidate semantics,
affected segments, and composition descendants. Proof-only changes must not
regenerate Ghidra or Stage B skeleton artifacts. A fast local smoke check must
reject malformed hashes, schemas, unsupported instructions, graph references,
and obvious mapping gaps before Lean compilation.

Large Lean graphs remain Nix derivation DAGs scheduled by ordinary builder
configuration. Focused target-node builds support iteration; the complete
remote Nix graph and trust-zero final audit remain the release gate.

### A11. Stage B Feedback And Candidate Build Profile

The initial ugly-C implementation must be generated from, or repaired directly
against, the Stage A state-machine artifact. A decompiler export may be an
untrusted optional hint, but it is not required by `contract-guided-c` and its
absence is not a completeness blocker. The generated package must preserve the
complete transfer inventory separately from compact function metadata, bind
source regions to deterministic transfer hashes, and report unsupported,
unbound, raw-byte, or placeholder representations independently.

The generic semantic-C backend must preserve the proof IR as executable state
transitions over explicit registers, flags, memory callbacks, faults, and control
outcomes. It must not embed original instruction bytes. When the transfer summary
lacks ordering or boundary information needed to emit sound C, generation returns
`incomplete` with a reason code; Stage A must enrich the proof-derived IR rather
than allowing Stage B to guess. Human or LLM repair may replace transition
functions with lower-level C, but the source map retains the governing transfer
IDs and the compiled result still requires the final Stage A theorem.

The generated semantic-C implementation is the Stage B work surface for unknown
binaries. It includes a complete transfer descriptor inventory, a fail-closed RVA
dispatcher, a nested-frame engine for direct internal calls, generated transition
bodies, and one stable repair stub for every unsupported contract. Repair stubs
are scaffolding only: `strict_candidate` remains incomplete until all have been
replaced and all runtime bindings are closed. `state-machine-implementation.json`
hashes that source bundle and each transfer contract. Candidate provenance must
bind both this implementation manifest and `state-machine.jsonl`; copied
instruction-byte or inline-assembly source remains non-authoritative bootstrap
material and cannot be used to claim implementation coverage.

Imported calls use the same checked machine-call contract format consumed by
Stage A. Given an exact DLL/symbol identity, unambiguous cdecl or stdcall
convention, complete stack-word inventory, and supported callback/resource
shape, Stage B may generate a direct imported-call adapter automatically. The
catalog supplies code-generation data, not proof authority. Missing signatures,
zero-argument convention ambiguity, callbacks without generated thunks, ordinal
imports, or unsupported argument layouts remain explicit runtime obligations.
The generated adapter must preserve the original one-for-one external event;
the compiled adapter is accepted only when the final Stage A theorem checks it.

Once `state-machine.jsonl` exists, ordinary Stage B repair iterations use
`stage-b-generate-semantic-c` directly. The command revalidates each contract
hash and regenerates only the C implementation, dispatch, nested-frame engine,
API adapters, repair stubs, source map, and implementation manifest. It must not
repeat PE extraction, decompiler work, relational analysis, or Lean compilation.

Stage A should convert each proof frontier into a deterministic, source-mapped
repair item containing:

- original and candidate cutpoints and paths;
- violated relation or missing witness;
- expected and observed canonical effects;
- generated source location;
- likely repair class and concrete next action;
- stable identifiers for filtering and before/after diffs.

Stage B should use a pinned proof-oriented build profile:

- pinned compiler, binutils, CRT, headers, libraries, and linker;
- `-O0` as a useful default, not an unconditional requirement;
- controlled builtins, inlining, stack protection, runtime helpers, and
  unwind metadata;
- explicit fixed-width types, packing, calling conventions, and no C undefined
  behavior;
- stable section layout, function ordering, imports, and image base where
  practical;
- generated `noinline` or assembly wrappers for external and component
  boundaries;
- selective optimization or explicit operations where required to preserve the
  original external protocol.

Stage B does not execute or trace the original binary during repair. Public and
curated candidate-only runtime tests remain gated on Stage A `pass` and serve
as a red-flag check on the theorem or implementation boundary.

### Internal Fixture Gates

Before claiming the internal architecture is complete, the final theorem must
prove or fail closed on generic PE32 fixtures covering:

- identical direct loop;
- relocated direct call with different concrete return addresses;
- stack adjustment and stack read across nested internal calls;
- split and merged block paths;
- inverted conditional branch;
- loop with an inductive relation invariant;
- bounded immutable jump table;
- writable callback target with a checked finite inventory;
- paired static data and dynamically allocated memory;
- resource-valued and pointer-valued external results;
- synchronous callback nesting;
- corresponding return, supported fault, and termination;
- candidate divergence before an expected external event;
- unresolved indirect target;
- omitted reachable product edge;
- ambiguous static or dynamic address mapping;
- unsupported instruction and executable-memory write.

Positive fixtures must close `pe32ProgramsEquivalent`. Negative and unsupported
fixtures must produce `fail` or `incomplete` for the specific reason and must
never reach an acceptance theorem.

### Jq Gate

The first practical acceptance gate remains the complete jq PE32 pair. It must:

- derive reachability from the PE entry profile;
- cover every rooted reachable internal edge;
- close every supported loop, call, return, indirect target, and external
  boundary through the unified theorem;
- classify all executable bytes;
- contain no unchecked solver status, hidden assumption, or incomplete proof
  obligation;
- check `candidatePE32ProgramsEquivalent` in the pinned trust-zero Lean build;
- pass the full distributed Nix audit;
- only then run candidate-only public jq behavior tests.

Jq is an integration target, not a source of trusted semantics. Every generic
feature discovered through jq should first receive a smaller target-independent
fixture.

## Track B: Representative 3D Application To Game

### Purpose And Planning Style

Track B begins only after Track A closes jq or after the remaining jq blockers
are demonstrably unrelated to the capability under evaluation. Its milestones
are gates rather than a fixed implementation sequence. The representative 3D
application should determine which graphics, callback, SIMD, loader, and
concurrency features are actually needed before Stage A grows them.

The core remains generic. No transfer theorem may be justified only because a
particular game uses it.

### B0. Component Baseline

Before graphics work, validate application/library composition with a small
multi-PE fixture:

- one executable;
- one reimplemented DLL with exports and internal state;
- one unchanged hash-pinned DLL identity certificate;
- callbacks from a library into the executable;
- calls from both components into the shared platform oracle;
- loader bindings, relocations, and TLS initialization.

The final theorem must compose the executable and library certificates rather
than treating the reimplemented library as an unexplained external API.

### B1. Graphics Boundary Schemas

Add reusable interface schemas, without graphics behavior models, for the
features exercised by the selected representative application:

- imported graphics entrypoints;
- COM or vtable object identities and method slots;
- device, context, swap-chain, resource, and shader tokens;
- structure, array, string, and buffer arguments;
- resource creation, mapping, unmapping, update, release, and generation;
- callback registration and invocation;
- window creation and message dispatch;
- input and logical clock observations;
- presentation, audio, and other selected observable events.

Exact provider module hashes and interface identities are part of the platform
profile. Alias or forwarding rules require explicit checked declarations, not
name-based heuristics.

### B2. Representative Single-Threaded 3D Application

Select or build a nontrivial PE32 application that exercises a real pinned
graphics stack while remaining single-threaded. It should include at least:

- Win32 process and window startup;
- a message loop and well-bracketed window callback;
- logical clock and input reads;
- graphics device/context creation;
- vertex/index or equivalent geometry resources;
- texture or constant data upload;
- shader or fixed-function state setup;
- at least one draw and present per frame;
- resource teardown and normal termination;
- one application DLL boundary if practical.

Produce an intentionally proof-friendly C reimplementation and require the
whole-system theorem to establish the same canonical event trace, resource
data, callbacks, returns, and faults for every shared input and clock stream.
Rendered-pixel comparison is a candidate-only red-flag test after Stage A
passes, not a substitute for event and data equivalence.

Exit criteria:

- no graphics-specific theorem is present in the generic internal kernel;
- all graphics knowledge is confined to reusable boundary schemas and platform
  profile data;
- the executable and any reimplemented DLLs have component certificates;
- the final theorem covers startup, at least one unbounded frame loop through
  an invariant, and shutdown;
- proof iteration remains incremental and source-mapped.

### B3. Asynchronous And Concurrent Runtime

Add concurrency only after the single-threaded graphics theorem is closed.
Start with generic fixtures, then extend the representative application.

Required capabilities are likely to include:

- thread creation and exit events;
- per-thread machine state, stacks, TLS, and callback roots;
- x86 atomics and selected memory-order rules;
- synchronization objects represented by paired resource tokens;
- a shared scheduler oracle and paired scheduling choices;
- well-bracketed synchronous callbacks;
- outstanding asynchronous-operation tokens and later completion events;
- data-race detection or a fail-closed race-free profile;
- corresponding process and thread termination.

The initial profile may require matching thread topology and synchronization
protocols. It need not prove that reordered or batched concurrent designs are
equivalent. Unsupported races, executable writes, JIT code, exception paths,
or scheduler effects remain `incomplete`.

### B4. Representative Real-Time Application

Extend the 3D fixture or select a larger application that combines:

- a sustained frame loop;
- asynchronous input or window events;
- one worker thread with checked synchronization;
- streaming file or resource activity;
- audio or another time-sensitive subsystem;
- multiple library components;
- controlled startup, steady-state, device-loss/error, and shutdown paths.

The purpose is to validate that the proof model scales across real-time
subsystems and component boundaries before committing to a complete game. The
acceptance theorem still relates logical event streams, not wall-clock
performance.

### B5. Game Capability Inventory

Before changing Stage A for a chosen game, statically inventory:

- PE and DLL component graph;
- roots, exports, TLS initializers, callbacks, and thread entrypoints;
- reachable instruction, x87, SIMD, atomic, and exception forms;
- direct, indirect, COM/vtable, and dynamically loaded external targets;
- self-modifying, JIT, anti-tamper, or executable-memory behavior;
- graphics, audio, input, network, file, and timing interfaces;
- resource and callback lifecycles;
- concurrency and synchronization structure.

Classify every item as already proved, requiring a generic fixture, requiring a
new explicit platform profile, or outside the intended proof class. Do not add
game-specific semantic shortcuts.

### B6. Game Vertical Proof

Prove one end-to-end game path before broad subsystem implementation. A useful
vertical path should cover:

- process and component launch;
- initial platform and graphics setup;
- loading enough data to enter an interactive state;
- input and clock observations;
- at least one complete update/render/present iteration;
- callbacks and any required worker synchronization;
- controlled exit or return to a stable loop cutpoint.

This is not a reduced behavioral claim. It is an architectural fixture proving
that the selected roots, components, environment profile, and runtime frames
connect through the same final theorem that will later cover the complete
reachable graph.

### B7. Full Game Closure

Expand by source-mapped cutpoint clusters and component certificates until:

- every declared launch, export, callback, TLS, and thread root is covered;
- every rooted reachable product edge has a checked refinement;
- every external or component interaction lowers to the exact canonical
  lockstep protocol;
- all resource, callback, thread, and completion lifecycles are paired;
- all loops and SCCs have checked invariants and required liveness evidence;
- all executable bytes are classified;
- no unsupported instruction, target, effect, or environment frontier remains;
- the complete application-plus-libraries theorem checks under the pinned
  platform profile and exact binary hashes.

Only this final theorem permits Stage A `pass` for the game reimplementation.
Menus, gameplay modes, network paths, error paths, and shutdown behavior are
not excluded merely because a representative runtime test did not execute
them. Reachability and proof closure, not trace sampling, define completeness.

### B8. Freeze The Proved Baseline

After Stage A passes:

- record exact source, compiler, dependency, binary, contract, proof, and
  platform-profile hashes;
- preserve the conservative Stage B binary as the proved baseline;
- run candidate-only integration, rendering, audio, networking, fuzz, and
  long-duration tests as a red-flag audit;
- build the full-coverage regression suite against the reimplementation source;
- label later derivatives as either Stage A proved or test-validated descendants
  of the proved baseline.

Optimized or refactored derivatives may deliberately change API batching,
threading, data structures, language, or platform. They are outside the initial
lockstep theorem unless proved separately.

## Least-Pain Rules

Across both tracks:

- constrain the candidate before generalizing the prover;
- use exact external protocols before considering event reordering or batching;
- use one opaque shared external oracle instead of formal API implementations;
- prove and cache components rather than build one avoidably monolithic graph;
- generate stable external wrappers and ABI glue instead of fighting compiler
  substitutions at every call site;
- use cutpoint clusters, not isolated blocks, as Stage B work units;
- derive contracts and diagnostics from the same proof objects;
- optimize for human/LLM-guided repair rather than requiring autonomous source
  synthesis;
- keep original-binary analysis static during Stage B iteration;
- add a generic fixture before relying on a new capability in jq or a game;
- optimize extraction, proof DAGs, and feedback before adding unsound widening;
- preserve `incomplete` as an expected, actionable outcome.

## Explicit Non-Goals For The Initial Profiles

- arbitrary equivalence between different external API sequences;
- proving performance or physical timing equivalence;
- formal Windows, CRT, graphics-driver, or GPU implementations;
- arbitrary differing thread topologies or synchronization protocols;
- unbounded weak bisimulation for all compiler transformations;
- complete IA-32, SIMD, SEH, or system-call coverage before targets require it;
- accepting self-modifying or JIT code without an explicit executable-memory
  profile;
- deriving a proof from runtime comparison with the original binary;
- requiring fully automatic decompilation or fully automatic candidate-source
  synthesis;
- claiming that a test-validated optimized descendant retains the Stage A
  theorem.

## Roadmap Success Conditions

This roadmap succeeds when:

1. The current internal-equivalence architecture closes the complete jq
   whole-program theorem without target-specific proof rules.
2. The same kernel and shared-oracle boundary close a representative
   single-threaded PE32 3D application.
3. Generic callback, resource, component, and concurrency extensions close a
   representative real-time application.
4. A complete game and its reimplemented libraries receive one compositional
   Stage A theorem under an explicit pinned platform profile.
5. The proved conservative source is usable as the behavioral baseline for
   later test-driven optimization, refactoring, and porting.
