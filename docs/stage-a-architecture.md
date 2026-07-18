# Stage A Architecture

## Authority

Stage A has one acceptance claim: Lean checks
`StageA.GeneratedRelational.candidatePE32ProgramsEquivalent` for the exact
original and candidate PE bytes under the declared launch and external-world
profile. Only a `stage-a-relational-verdict-v1` report with
`acceptance_authority: whole_program_lean`, `verdict: pass`, and
`claim_scope.acceptance_eligible: true` may authorize a faithful
reimplementation.

Historical v2 validation and regional-refinement reports are not accepted by
the current command surface. Image, region, segment, solver, and
composition-progress certificates are intermediate evidence. Contract export
and candidate-only feedback commands are not acceptance gates.

## Python Phases

`spaghetti_extractor.stage_a_relational` is a compatibility facade. Implementation lives in
`spaghetti_extractor.relational`:

- `schema.py` parses immutable, runtime-validated artifact boundaries.
- `ir.py` validates proof, graph, acceptance, and progress records.
- `phases.py` makes decoded, state-analysis, and composition phase order
  explicit with immutable runtime-validated records.
- `contract.py` validates PE mappings, ranges, padding, imports, and machine
  call contracts.
- `extraction.py` performs exact-byte semantic extraction and emits semantic
  and memory IR. Its caches are untrusted and content-addressed.
- `analyses/` proposes control, register, stack, memory, invariant, external,
  and segment evidence. A proposal cannot close an obligation.
- `lean/` emits definitions, local segment certificates, product composition,
  and the final acceptance module.
- `build.py` validates prepared source graphs and drives the Nix derivation
  DAG.
- `executor.py` compiles/replays Lean and audits approved axioms.
- `verdict.py` alone translates a checked final theorem into acceptance.
- `pipeline.py` orchestrates the phases without owning their data models.

JSON is accepted and emitted only at explicit phase boundaries. New internal
interfaces should use frozen dataclasses or equally strict typed structures;
mutable `dict[str, Any]` remains compatibility debt and must not spread into
new phases.

The relational tests mirror these boundaries in `contract`, `state`, `lean`,
`acceptance`, and `pipeline` suites. Shared PE constructors live in
`tests/stage_a_relational_support.py`; no monolithic relational test class is
authoritative.

## Lean Modules

The reviewed kernel is split by semantic ownership:

- `Formal.lean`, `RelationalDecode.lean`, and `RelationalMachine.lean` define
  the PE32/x86 machine foundation.
- `Relational.lean` defines values, memory families, state relations, and
  region semantics.
- `RelationalInvariant.lean` defines invariant and weakest-precondition
  machinery.
- `RelationalExecution.lean` defines the relational execution/trace layer.
- `RelationalImage.lean` defines structural coverage and the intermediate
  image certificate.
- `RelationalSegment.lean`, `RelationalComposition.lean`, and
  `RelationalEnvironment.lean` define local refinement, rooted product-graph
  composition, and exact lockstep external refinement.
- `RelationalCertificates.lean` contains the whole-program certificate and
  final soundness theorem.

The console acceptance profile binds its selected launch node to a checked
`.entrypoint` root in `StaticProofContext`. A top-level return observes the
concrete EAX result as well as the relational world, and the terminal
invariant must require exact EAX identity. Returning programs therefore cannot
pass while disagreeing on their process result. External-call continuations
may recover exact or related-word result registers only from the uniquely
resolved `MachineImportCallContract`; ESP remains governed separately by the
checked stack delta and runtime-frame relation.

Generated modules contain data and compact certificates, not duplicated proof
rules. Nix derivations follow direct Lean imports so proof-only changes
invalidate only affected descendants.

## Trust And Failure

PE parsing proposals, Capstone, symbols, linker maps, Ghidra, Python analyses,
Z3 status, caches, source mappings, and human/LLM annotations are untrusted.
Lean re-parses exact bytes, checks supported instruction semantics, validates
mapping witnesses, replays supported solver evidence, checks complete rooted
product behavior, composes segment refinements, and audits the final theorem at
trust level zero.

Unsupported instructions, unresolved indirect targets, missing product edges,
unproved invariants, unknown callbacks/effects, pointer-disjunction overflow,
and absent external contracts yield `incomplete`. There are no acceptance
waivers. Runtime tests run only after Stage A passes; a public behavior failure
after a Stage A pass is a prover/toolchain defect investigation.

## Artifact Lifecycle

Prepared proof inputs are source-only and content-addressed. Nix store paths
are the authoritative compiled Lean cache for distributed builds. Local hot
loop caches belong under `${XDG_CACHE_HOME:-~/.cache}/spaghetti-extractor`, not in the source
tree. `build/` contains disposable or explicitly exported work products and
must never be an implicit proof input. Large generated Ghidra/skeleton data is
reused by content hash and regenerated only when its own inputs change.

Static behavior extraction is side-local and precedes relation synthesis. Each
binary emits a strict executable inventory, raw behavior artifact, and ISA
artifact without consuming the other binary or a relation contract. Raw
behavior artifacts bind their untrusted terms to the complete analysis-kernel
source inventory, extraction-driver source, and Lean toolchain identity. A
passing inventory is required before base or pair-supplement extraction can be
requested.

Pair analysis consumes those immutable side artifacts. Pair-specific spans are
added as explicit supplements, never hidden inside extraction, and contracted
behavior normalization runs as an exact-cover set of bounded packs. Pack
aggregation rejects missing, duplicate, overlapping, or unexpected region
outputs while preserving the contract's global region identifiers. Final Lean
modules still reconstruct these proposals from the exact PE bytes; neither a
side artifact nor a normalization pack is acceptance evidence by itself.

Contracted behavior normalization is itself an immutable pair artifact and a
separate Nix derivation. It binds the exact PE, normalized contract, side
extraction, analysis-kernel, source-generator, and Lean-toolchain identities.
Downstream register, stack, memory, graph, diagnostic, or proof-generation
changes consume this artifact and must not rerun normalization. Missing or
mismatched identities fail closed; there is no implicit normalization fallback
in the cached GNU hello analysis path.

Region-local facts form the next immutable boundary. Bounds, initial static
code-pointer slots, finite indirect-target proposals, import-register seeds,
address-separation claims, and machine-level import-call analysis are produced
from normalized behavior without importing the global register or callsite
fixed-point implementation. The region-facts artifact binds its exact PE,
contract, normalized-behavior, and reduced analysis-source identities. Changes
to global dataflow, diagnostics, graph construction, or proof generation must
therefore consume the existing artifact instead of replaying region-local
analysis.

The remaining global state analysis is transitional. Its register, callsite,
stack, static-memory, dynamic-range, and indirect-control feedback loops must be
replaced by bottom-rooted monotone propagation over stable region identities.
Once the least fixed point is independent of traversal history, SCC summaries
become immutable artifacts keyed by local transfer functions and incoming SCC
summaries. Cache entries remain untrusted proposals; Lean reconnects every
accepted claim to the exact image bytes and checked whole-program graph.
