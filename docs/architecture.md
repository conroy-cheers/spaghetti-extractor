# Architecture And Assurance

## Objective

Produce a faithful, progressively portable reimplementation of an opaque PE32
program while minimizing silent reconstruction mistakes. Full automation is not
required: operator or LLM-guided component selection, type recovery, and source
repair are expected. The tooling must make those interventions local,
reviewable, reproducible, and testable.

## Canonical Pipeline

```text
original PE32
  -> exact static inventory and ISA requirements
  -> original-only reference contract
  -> canonical machine IR
  -> linked-library and interface recognition
  -> v2 entry, provenance, call, external-site, exception, and ISA evidence
  -> dependency-aware static authority bundle
  -> recomputing v2 final audit
  -> independent fallback implementation-coverage receipt
  -> generated baseline/interpreter
  -> semantic components with explicit boundaries
  -> portable C replacements
  -> rebuilt candidate
  -> candidate-only behavioral suites
  -> assurance report
```

The original may be parsed and disassembled statically. Repair iteration must
not execute or trace it. Candidate generation fails until static closure has no
deferred potential transfers. Runtime diagnosis begins only after that gate,
is candidate-only, and uses public or curated expectations. Runtime failures
after static closure indicate a tooling defect or an under-specified contract;
they are not the expected mechanism for discovering omitted original regions.

## Trust Boundaries

- Raw PE bytes and content hashes are authoritative inputs.
- Behavioral roots are independently re-parsed from the exact PE and include
  the executable entrypoint, exports, and immutable TLS callbacks; submitted
  reachability cannot redefine that root surface.
- Capstone, `pefile`, Ghidra, symbols, linker maps, Z3, and library matchers make
  proposals. Their output is validated structurally and fails closed.
- The compact Lean ISA model is authoritative only for the instruction forms it
  implements. It is qualified against Unicorn, Bochs, and hardware corpora;
  oracle agreement is evidence, not a candidate correctness claim.
- CBMC establishes bounded component claims under explicit finite domains. It
  does not silently generalize them.
- Source rendering and library substitutions require exact catalog/profile
  bindings and never qualify a candidate on their own.
- Operator-reviewed internal-function contracts may supply call-frame and value
  provenance for opaque linked runtimes. They must bind the exact PE, entry,
  and complete normal-control unit closure. They guide static analysis only:
  the exact machine-IR body remains the executable fallback and the contract
  has no replacement authority.
- Candidate behavior tests cannot establish exhaustive correctness, but a
  failure vetoes qualification. A statically qualified candidate that fails a
  public behavior test is a tooling defect or an under-specified contract.

## Status Vocabulary

- `complete`: every requirement in the artifact's declared scope was checked.
- `qualified`: an ISA form or other explicitly qualified capability has passed
  its declared evidence policy.
- `incomplete`: evidence is missing, unsupported, ambiguous, or out of scope.
- `violated`: evidence contradicts an expected contract or behavior.
- `not_applicable`: a checked family does not apply to this artifact.
- `pass` / `fail`: reserved for ordinary command execution and behavior-test
  cases, not static assurance claims.

No Python status field grants stronger authority than the checker named by the
artifact. Hashes bind artifacts but do not prove semantic correctness.

## Static Authority

The active static gate is the v2 authority graph. Its immutable records bind an
exact PE, machine-IR unit or event, finite alternatives, dependencies, and
explicit missing or contradictory evidence. Rooted state propagation uses
certificate-checked inductive abstract interpretation: proposal code may
synthesize invariants, but a separate checker reconstructs the exact transition,
memory-version, dependency, control-edge, root, and budget inventories before it
checks initiation and preservation. The final audit rechecks the resulting
bound receipts and is the only static input that may authorize candidate
generation. This audit is deterministic certificate checking, not a fresh
abstract interpretation of every execution path.

The older `stage-b-static-hybrid-completeness-v1` report remains useful for
proposal generation and diagnostics. It cannot authorize a candidate. In
particular, copied v1 completion fields, target inventories, ABI statuses, and
profile hashes are not authority.

Fallback coverage is deliberately separate. It checks that every unit in the
complete structural machine-IR universe has exactly one portable or machine-IR
implementation and that the selected fallback lowering exists. It has no
rooted-reachability authority; the v2 final audit independently establishes
that every transfer possible from the declared roots remains inside that
structural universe. Candidate generation requires both receipts, bound to the
same machine IR and manifest.

The v2 evidence graph is fail-closed:

1. PE entry, export, TLS, and registered callback roots receive explicit entry
   state contracts.
2. Mutable image slots are tracked point-sensitively. Unknown or aliasing
   writes taint downstream facts; they are never pooled into every root.
   Stack- and FS-relative accesses may be excluded from image-slot aliasing
   only through exact event-bound spatial facts replayed from the corresponding
   private launch-range contract. Such facts establish separation, not
   immutability of stack or TEB contents.
3. The call-summary universe contains every exact direct call target and every
   proposed finite indirect target, whether or not its call site is currently
   rooted-reachable. Declared launch entries are stable structural cutpoints;
   callback discovery may grow rooted propagation without redefining that
   inventory. Every structural unit receives a root-independent normalized
   transition/effect summary. Concrete memory ranges become sparse checked
   versions and merge nodes only where a unit actually accesses that alias
   component. An unknown or aliasing write kills the affected fact. A compact
   `all_components` scope represents a fully unknown write without serializing
   the complete component inventory at every site. Value, memory, target, call,
   callback, external-site, and resource facts inhabit one typed dependency
   graph. Each control SCC consumes only its actual dependency predecessors and
   carries a bounded invariant certificate.

   Incoming facts bind an exact transition ID, exact exit ID, and target
   cutpoint. The checker derives rooted closure from checked control edges and
   requires induction only for rooted SCCs. Disconnected structural units remain
   fully summarized without acquiring false root obligations. A reachable
   unresolved indirect exit still makes closure incomplete.

   Static target discoveries first enter a compact, non-authorizing structural
   proposal artifact. Local induction depends on that artifact, not on the
   legacy interprocedural fixed point. The exact transition inventory still
   covers every structural unit, while certificate proposal and checking are
   limited to the independently derived rooted closure. Consequently, a small
   rooted-unit count is not a completeness claim: every reachable unresolved
   target retains an `indirect_target` dependency, and adding a checked finite
   target expands the closure and invalidates the affected certificates.

   Large independently checked artifacts compose through content identities.
   Transition-witness identities bind ordered checked summary IDs rather than
   embedding the full summary payload again, and induction proposals bind a
   reconstructed dependency-graph identity. The checker rebuilds both from its
   exact Nix dependencies. Shared transition, dependency-SCC, incoming-edge,
   and memory-discharge indexes are constructed once per checker process;
   individual certificates inspect only their members and incident edges.

   Cycles are closed by checked induction, not bounded execution replay. A loop
   invariant may be proposed by static analysis, an operator, or Z3. Authority
   follows only when the checker establishes root initiation, every represented
   transition's preservation step, complete outgoing control, finite target
   bounds, and all external dependency receipts. The Lean kernel proves that
   these premises imply the invariant for every finite execution prefix, so a
   nonterminating game loop does not need to be unrolled.

   Local induction is cached independently of environment evidence. A later
   dependency-closure phase may discharge only typed nodes whose ID, kind, and
   exact transition-exit binding match a receipt from the checker that owns the
   evidence. External-site receipts are re-derived from exact machine IR,
   rooted reachability, recovered targets, and the pinned profile index.
   Callback-bearing calls require both that external-site receipt and a
   binary-bound registration/entry contract. Indirect targets, call summaries,
   resources, and callbacks without matching owner receipts remain incomplete;
   a bare list of available dependency IDs has no authority. Local induction
   and dependency closure use distinct artifact formats and content IDs. The
   final static gate accepts only the latter, preventing a cached local report
   from being mistaken for environment-closed authority.

   During migration, external-site and callback receipts still consume the
   richer legacy interprocedural proposal in the late dependency-closure phase.
   This dependency cannot invalidate local induction, and remains visible as a
   separate expensive DAG branch until those owner analyses move to typed SCC
   certificates.

   Invariant inputs may also request typed exports at named cutpoints. Export
   requests are non-authorizing and independently threaded through proposal,
   local checking, and dependency closure. A fact is emitted only when the
   checked invariant implies it. Mutable-slot, callback, and resource
   authorities can therefore migrate to exact inductive exports without
   treating analyzer proposals as globally valid facts.

   The older discovery/cold/inductive fixed-point loops temporarily remain as
   non-authorizing proposal producers for call and target facts. Their copied
   status, convergence, and replay fields cannot discharge a certificate
   dependency. They are removed as each target, call, mutable-slot, callback,
   and resource family moves to the typed checker path.
   Caller evidence is projected onto independently checked summary families.
   A value retained in a preserved register depends on that register's summary
   fact, rather than an aggregate summary which may remain incomplete because
   of unrelated memory or result effects. Aggregate call-frame identities stay
   readable during migration but cannot stand in for a more precise family
   witness. Register summaries distinguish checked preservation, checked
   clobber, and unknown relations per register. The reviewed PE32 normal-return
   premise may fill only unknown nonvolatile relations, applies to internal and
   indirect calls, and fails closed if exact machine evidence contradicts it.
4. External sites are normalized only after target recovery and are rebound to
   the exact event, ABI, arguments, effects, continuation, and selected profile.
5. Every reachable instruction form is bound to one binary-specific qualified
   ISA selection and the corresponding fallback capability.
6. Exceptional transitions use local semantic fault predicates and checked SCC
   invariants. Bounded predecessor search cannot close an exception frontier.
7. Dependent fallout is reported through `blocked_by`; progress is measured by
   unresolved certificates, SCCs, environment sites, and ISA forms.

Typed facts and dependency edges describe the current converged proposal graph.
They are not unioned with transient earlier evaluations: those evaluations are
successive approximations, not simultaneous execution alternatives. Contextual
address domains are accepted only from an explicitly scheduled and executed
checkpoint. These rules make the authority inventory independent of evaluation
history and prevent stale contextual proposals from being sealed.

Rooted graph closure and value provenance have separate authority. A recovered
indirect edge determines whether its destination is behaviorally reachable;
merely traversing that edge does not make every later machine value depend on
its target certificate. Values and effects carry the certificate only when the
indirect transition semantically produced or preserved them. This prevents an
unresolved earlier operation from contaminating otherwise independent target
facts while retaining fail-closed rooted reachability.

## Completion Criteria

A target is ready for release qualification when:

1. Every executable byte has a static classification.
2. Every required ISA form is supported and qualified.
3. Root closure contains every reachable direct, finite indirect, callback,
   call, and return transfer; its potential-transfer inventory is empty.
4. Every reachable instruction has executable semantics, and every reachable
   import or interface call has an exact machine ABI plus memory, resource,
   lifetime, and callback effects.
5. Every reachable region is implemented by portable C or the machine-IR
   fallback, with `allowDeferredPotentialTransfers = false`. A hash-bound v2
   dispatch receipt requires exactly one implementation kind and replays the
   selected interpreter lowering.
6. The v2 final audit passes, the fallback receipt is complete, and their exact
   machine-IR and manifest bindings agree.
7. Curated and upstream candidate-only suites pass under headless Wine.
8. Generated artifacts are reproducible through the pinned Nix graph.

This is an assurance claim, not a universal theorem over all executions. The
architecture intentionally prioritizes useful, localized evidence and a viable
lifting workflow over an impractical whole-program bisimulation requirement.

## Caching

The Nix graph separates extraction, ISA qualification, machine IR, component
analysis, source checks, candidate builds, and behavior suites. Original-side
artifacts should remain unchanged during source repair. Content-addressed
derivations allow local and remote builders to substitute identical work.

CA phase outputs never embed their resolved dependency store paths. Those
paths may legitimately differ between equivalent CA realizations and would
therefore make an otherwise deterministic output acquire a new content hash on
every build. Phase manifests instead record stable file/tree SHA-256 identities,
sizes, and the checked Python-module-closure manifest digest. The derivation DAG
retains the exact producing dependencies. The phase-graph fixture rejects any
manifest that leaks a `store_path` field.

The v2 static-authority graph has explicit CA phases for exact unit
preparation, base control, point-sensitive mutable-slot replay, slot promotion,
interprocedural SCC summaries, rooted closure, external-profile and site
binding, callback and launch state, ISA selection, exceptional control, static
authority, bundle closure, and final audit. Expensive mutable-slot replay is a
dependency of the smaller promotion checker, not part of it. Consequently a
promotion/checker policy change invalidates promotion and semantic descendants
without rerunning exact extraction or global replay. The Nix fixture checks
this derivation-path contract alongside profile-only and audit-only mutations.

An unchanged CA build may still print the input-addressed derivations Nix would
realize before resolving their content-addressed outputs. The operational cache
criterion is that no builders execute and the same output path is returned;
the warm DX-Ball final-audit build is the benchmark for this behavior. After
the path-free manifest migration, the three-stage DX-Ball structural-target,
induction-proposal, and local-authority chain reuses its output in roughly
1.3 seconds instead of rerunning about 52 seconds of authority checking.

Native candidate preparation emits a deterministic checked object graph, then
compiles and assembles that graph in a content-addressed realization. It does
not read generated CA outputs during Nix evaluation: CA output paths are not
known until realization, so that would create an invalid hidden IFD boundary.
The object graph retains stable per-unit compile keys for an explicit two-pass
manifest workflow if per-unit derivations become necessary. Phase-specific
Python import closures prevent unrelated generator edits from invalidating
static analysis. Computed quoted includes fail closed rather than silently
widening a dependency.

Machine-IR construction separates exact per-unit preparation from global
reachability and control finalization. The direct rooted pass prepares each
unit once; an expanded rooted pass reuses exact input-hash-bound units and only
prepares newly discovered transfers. Final manifests recompute graph-derived
facts rather than accepting cached reachability.

The direct rooted pass consumes a canonical control-disposition projection of
the selected import profiles.  That projection contains only exact fixed-arity
imports proven not to return.  Argument inventories, memory/resource effects,
callbacks, and source-profile bindings are deliberately excluded and enter at
the interprocedural/external-site phases.  Adding or repairing an ordinary
returning API contract therefore cannot invalidate the exact state machine or
machine IR; changing a no-return disposition correctly invalidates rooted
control and its descendants.

Exact stack-entry offsets have a separate finite resource budget from typed
value alternatives. A program can have many exact ESP states at a join without
requiring the pointer-provenance lattice, global-slot alternatives, or indirect
target sets to grow by the same amount. Both limits remain explicit and
fail-closed.

Analysis derivations preserve structurally valid `incomplete` artifacts so
their blocker inventories are cacheable and inspectable. Policy enforcement is
kept in a separate closure gate; an incomplete analysis must not discard hours
of extraction work, but it also must never become an executable candidate.

## Proposal Discovery And Certificate Caching

Within one immutable proposal pass, unit transfers are retained in a
bounded in-memory cache across fixed-point evaluations. Ordinary units are
keyed by their exact abstract input and local slot environment. Call-bearing
units additionally include the complete call-summary, recovered-target, and
hypothesis environment, so an evolving call contract invalidates only
call-sensitive transfers. The cache is created afresh for each legacy
discovery pass, is never serialized, and carries no authority. Accepted facts
come from typed certificate checkers, not from convergence of this proposal
graph.
Mutable-slot influence has a separate pass-scoped memo keyed only by the exact
roots, recovered control, call-result, and memory-frame projection that its
transfer function consumes. Changes confined to provenance hypotheses do not
replay that graph; changes to any mutable-analysis dependency invalidate the
memo. Within a replay, independently converged SCC summaries are also retained
under exact incoming-state, local-control, target, and consumed-call-fact keys.
A proposal pass uses the same SCC schedule while retaining finite target hints
observed before a local join. Those hints remain non-authorizing. A checked
target-expression or call-summary dependency must establish complete context
coverage before an invariant certificate can consume it. The SCC cache binds
and restores hints only to avoid repeating proposal computation.
A hit restores the checked final member states, outgoing contributions, and
the final per-unit transfers used by diagnostics and mutable-slot proposal
extraction. Finalization therefore consumes converged transfer evidence without
executing every reached unit again. Changed edges or predecessor facts
invalidate the affected SCC and descendants. These caches are intermediate
optimizations and carry no authority. The durable boundary is the
content-addressed transition summary, memory-version graph, invariant proposal,
checker receipt, and true condensation-graph descendants.

Internal-call summaries use the same dependency discipline. Callee SCCs are
cached under their local control closure, unresolved exits, call effects,
memory-write footprints, return evidence, and the exact call-boundary
projection of summaries they consume. A changed leaf invalidates that leaf and
its callers without replaying independent call chains. Prepared memory-access
facts are validated once per exact frozen inventory in the context-bound pass
workspace; the resulting typed facts are shared by call-summary and provenance
analysis instead of being revalidated independently. Whole-summary and
component caches remain pass-local proposal optimizations, while the emitted
artifact and downstream certificate checker remain unchanged.

The structural callee inventory is independent of rooted reachability.
Root-specific propagation may add registered callbacks and other event-derived
entries; those entries receive summaries, but they do not add or remove direct
structural callees merely by becoming reachable. A newly recovered indirect
target extends the structural call inventory through its explicit target
certificate and invalidates only the affected summary SCC and callers.

Structural summaries are conditional facts, not reachability claims. The typed
authority lattice starts from behavioral-entry summary nodes and follows their
actual dependencies. An incomplete unreachable structural summary remains a
diagnostic frontier, while an incomplete root or rooted callee fails closed.

Each joint fixed-point round runs dependency-scoped global-slot analysis once.
The round emits a distinct non-authorizing promotion artifact from the
just-produced stack and slot inventories; it does not replay stack-range
analysis merely to feed the next lattice iteration. The separately cached
`globalSlotAuthority` phase reconstructs the exact final inputs, independently
replays stack ranges and slot analysis, and compares the submitted analysis
byte-for-byte before those invariants can authorize any downstream artifact.
Iteration therefore avoids duplicate work without moving the authority boundary
or treating fixed-point promotion as candidate authority.

The independent replay implementation lives outside the joint fixed-point
Python closure. Checker-only changes therefore rebuild the final authority
phase without invalidating the expensive joint artifact. Provenance-alternative
and stack-offset budgets are separate bound inputs and must match the producing
analysis exactly; canonical serialized content, rather than Python container
identity, defines replay equality.

Joint convergence is extensional over the facts consumed by the next typed
analysis pass. Global-slot record identities remain part of that state because
target evidence refers to them directly. Checked stack-range record IDs and
their prior graph/call-effect hashes do not: the interprocedural adapter first
replays those records, then consumes only the accepted unit set and exact entry
offsets. Treating evidence-lineage hashes as lattice coordinates creates an
unbounded `H(previous evidence)` chain after the represented stack state has
already stabilized. The joint artifact records both semantic and full-evidence
signatures, while the final replay still binds the exact output stack artifact
to the current graph and current call-effect inventory.

Finite domains use family-specific resource bounds. Value-origin alternatives
remain capped at 32, while exact launch-relative stack states are capped at 64.
The latter are integer control states rather than possible machine values;
sharing the tighter provenance bound caused otherwise exact control-flow joins
to fail without reducing the accepted value set. Exhausting either bound still
produces `incomplete` and never widens to an arbitrary value or address.

Stack states carry exact launch-relative `ESP`, active call-frame, and optional
`EBP` offsets. The `EBP` offset is established only by replaying a represented
affine register write, is retained across calls only by a checked register
frame or ABI, and is killed by an unrepresented write. This lets ordinary
`leave` and `mov esp, ebp` epilogues compose without treating a conventional
frame pointer as a special binary pattern; an unknown frame pointer still
stops propagation as `incomplete`.

Exact direct-import events also project their state-independent machine-ABI
families before provenance replay: preserved registers and fixed stack cleanup
come from the selected import profile even when an upstream unresolved target
prevents abstract state from reaching the site. Argument-dependent memory
writes and result origins remain stateful and therefore incomplete until their
inputs are recovered. If a reached site's stateful frame disagrees with the
intrinsic ABI projection, the merged effect fails closed instead of selecting
either result. An external tail transfer with no local continuation does not
create a fictitious returning-stack obligation; its external-site contract
still governs the terminal transfer itself.

Internal return behavior is likewise a separate structural summary family.
An exact finite intraprocedural closure containing no return instruction and
ending only in checked terminal dispositions proves that the callee cannot
resume its caller, even when unrelated nested-call register or memory families
remain incomplete. Stack propagation still enters that callee but suppresses
the impossible caller continuation. Any unresolved direct or indirect exit
keeps the return family incomplete instead of being treated as non-returning.

Generated files belong under Nix outputs or ignored `build/` workspaces. Authored
intent and source belong in target bundles. Private binaries belong under the
ignored `private/` tree and must never be copied into source or target data.
