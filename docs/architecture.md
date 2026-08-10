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
explicit missing or contradictory evidence. The final audit cold-replays the
bundle and is the only static input that may authorize candidate generation.

The older `stage-b-static-hybrid-completeness-v1` report remains useful for
proposal generation and diagnostics. It cannot authorize a candidate. In
particular, copied v1 completion fields, target inventories, ABI statuses, and
profile hashes are not authority.

Fallback coverage is deliberately separate. It checks that every unit in the
exact rooted machine-IR partition has exactly one portable or machine-IR
implementation and that the selected fallback lowering exists. It does not
claim that the rooted partition is behaviorally complete; the v2 final audit
establishes that prerequisite independently. Candidate generation requires
both receipts, bound to the same machine IR and manifest.

The v2 evidence graph is fail-closed:

1. PE entry, export, TLS, and registered callback roots receive explicit entry
   state contracts.
2. Mutable image slots are tracked point-sensitively. Unknown or aliasing
   writes taint downstream facts; they are never pooled into every root.
3. Call summaries and indirect targets converge together over an SCC worklist,
   then replay from no proposal seeds. Expensive bounded-context recovery runs
   only as a checkpoint after ordinary propagation stabilizes; a checkpoint
   that discovers new driver facts resumes ordinary propagation before another
   checkpoint may authorize contextual memory evidence.
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
the warm DX-Ball final-audit build is the benchmark for this behavior.

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

Analysis derivations preserve structurally valid `incomplete` artifacts so
their blocker inventories are cacheable and inspectable. Policy enforcement is
kept in a separate closure gate; an incomplete analysis must not discard hours
of extraction work, but it also must never become an executable candidate.

Within one immutable interprocedural pass, unit transfers are retained in a
bounded in-memory cache across fixed-point evaluations. Ordinary units are
keyed by their exact abstract input and local slot environment. Call-bearing
units additionally include the complete call-summary, recovered-target, and
hypothesis environment, so an evolving call contract invalidates only
call-sensitive transfers. The cache is created afresh for each discovery,
cold, or inductive pass, is never serialized, and carries no authority; all
accepted artifacts still come from the final converged proposal graph.

Generated files belong under Nix outputs or ignored `build/` workspaces. Authored
intent and source belong in target bundles. Private binaries belong under the
ignored `private/` tree and must never be copied into source or target data.
