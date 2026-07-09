# Stage A Binary Equivalence Prover

## Completion Goal

Stage A is complete when `wincr stage-a-validate` can reproducibly classify a
generic x86 32-bit PE candidate binary against an original PE binary as exactly
one of `pass`, `fail`, or `incomplete`, using report artifacts that justify the
verdict from the explicit block mapping, same-layout model, generated
obligations, SMT proof cache, Lean proof summaries, and any counterexamples or
incompleteness blockers.

The first accepted implementation must prove `pass` for nontrivial equivalent
PE32 fixtures, prove `fail` with actionable counterexamples for deliberate
mutations, and report `incomplete` rather than `pass` for unsupported
semantics, unresolved targets, missing invariants, unmodeled external
interaction, solver timeouts, or unchecked proof assumptions.

## Summary

Implement Stage A as a generic x86 32-bit PE binary-to-binary behavioral
equivalence prover. It validates that a candidate binary is equivalent to an
original binary under an explicit same-architecture, same-layout execution
model. Candidate source provenance is irrelevant.

The tool must return exactly one of:

- `pass`: every required obligation is proved equivalent for all states covered
  by proven invariants.
- `fail`: a reachable counterexample proves non-equivalence.
- `incomplete`: proof could not be closed because of unsupported semantics,
  missing invariant, unknown target, solver timeout, unmodeled external
  interaction, or unproved reachability.

External APIs are modeled as an uninterpreted environment. The prover does not
need to know what Win32 APIs do internally, but must prove both binaries perform
the same ordered external interaction with equal symbolic arguments and consume
equal symbolic responses and effects.

## Command Surface

```sh
wincr stage-a-validate \
  --original original.exe \
  --candidate candidate.exe \
  --mapping block-map.json \
  --model x86-pe32-env-v1 \
  --lean-input checked-invariant.lean \
  --out report/
```

Required inputs:

- `original.exe` and `candidate.exe`: PE32 binaries.
- `block-map.json`: explicit original-block to candidate-block mapping.
- `model`: execution model identifier.
- Optional invariant package: generated or hand-authored invariants/proofs.
- Optional layout contract: stricter same-layout assertions when available.
- Optional supplemental Lean inputs: copied into `report/lean/StageA/User/`,
  imported by the generated obligation summary, hash-bound in
  `lean/summary.json`, checked by Lean, and scanned for unchecked proof markers
  before any final `pass`.

Checked block invariants may also carry simple SMT pre-state constraints:

```json
{
  "id": "block-id",
  "invariant": {
    "checked": true,
    "constraints": [
      { "reg": "ebx", "equals": 7 },
      { "reg": "esp", "mask": "0xf", "equals": 0 }
    ]
  }
}
```

These constraints are conjoined with the local mismatch query. Malformed or
unsupported constraints are fail-closed as `incomplete`; unchecked invariants
still prevent a final `pass`.

Required outputs:

```text
report/
  verdict.json
  layout.json
  obligations.json
  proof-ir.json
  solver-evidence.jsonl
  solver-evidence-index.json
  failures/
  incomplete/
  counterexamples/
  witnesses/
  proof-cache/
  lean/
```

Validation suites may batch this command without changing the proof source:

```sh
wincr stage-a-validate-suite \
  --suite suite.json \
  --model x86-pe32-env-v1 \
  --out suite-report/
```

The suite manifest contains relative or absolute paths to `original`,
`candidate`, `mapping`, optional `invariants`, optional `layout_contract`, and
optional `lean_inputs`, and an expected verdict for each case. Each case still
writes a normal Stage A report under `suite-report/cases/<case-id>/`; the
suite-level `suite.json` only records whether those per-case verdicts matched
expectations.

For mapped direct CFG edges, Stage A emits `cfg_edge` obligations using the
`direct_cfg_edge_mapping_v1` proof rule. Conditional branches produce separate
`taken` and `fallthrough` edge obligations. A direct original edge whose target
is not mapped is `incomplete`; a concrete candidate successor mapped to a
different target block is `fail`.

For every mapped code block, Stage A also emits a `reachability` obligation.
The current implementation can close these with `entry_root_reachability_v1`,
`checked_root_reachability_v1`, or `direct_cfg_reachability_v1`. A non-entry
block that is only asserted reachable, without a checked root or proved incoming
CFG edge, is `incomplete` and cannot contribute to a final `pass`.

Output schemas:

- `verdict.json`: `pass`, `fail`, or `incomplete`; model hash; tool versions;
  obligation counts.
- `layout.json`: architecture, ABI, PE layout, section permissions, and
  global/layout compatibility.
- `obligations.json`: every block/API/callback/edge obligation with status.
- `proof-ir.json`: canonical target-neutral proof IR for loader facts,
  executable coverage, obligations, proof-cache references, and evidence
  bindings. V1 is emitted from the PE32 loader frontend and x86 semantics
  backend, but the schema is not jq-specific. The proof IR includes a compact
  `target_profile` that binds the selected model to the emitted schema names,
  loader fact format, loader profile model, ABI, and external environment
  contract before any loader-specific proof is accepted. Lean checks this
  profile so inconsistent model/schema/loader combinations cannot be hidden
  behind otherwise satisfied family profiles; the generated Lean target profile
  also names the loader-frontend and solver-backend schema slots explicitly so
  new proof families cannot bypass target-model closure by relying only on a
  status bit. The proof IR also includes a compact
  `loader_frontend_profile` that sits between target selection and
  loader-specific validation. It states which loader frontend produced the
  facts, checks the model-selected loader fact schema, verifies that original
  and candidate side facts expose the generic loader interface
  (binary hash/size, machine, bitness, image base, entrypoint, sections,
  executable spans, imports, and relocation summary), and hash-binds the
  detailed loader profile. The first implemented frontend is PE32/PE32+; adding
  a non-PE binary frontend should satisfy this profile without changing the
  target-neutral proof IR consumers.
  The proof IR also includes a compact
  `loader_profile` that summarizes the selected model, loader format, PE
  header fields, section/import signatures, relocation directory status,
  executable-section presence, and blocking layout issues. Lean checks this
  profile so a final `pass` cannot rely on uninspected PE layout/import/reloc
  facts that merely happened to be present in the JSON. The proof IR also
  includes a compact per-block `block_semantics` inventory plus a
  `closure_certificate` with
  closed-obligation, coverage, proof-cache, solver-evidence,
  evidence-backed block-equivalence, block-semantics-record,
  same-obligation artifact-binding, and hash-binding checks.
  The `coverage_profile` section is the compact Lean-facing summary of
  executable-byte classification: mapped code accounted for by block-equivalence
  obligations, verified non-code waivers, open coverage obligations, and
  original/candidate gap counts. Lean checks this profile so a final pass cannot
  hide unclassified executable bytes behind an opaque coverage boolean.
  The `proof_cache_profile` section is the compact Lean-facing summary of the
  proof-cache artifact set: proof-cache entry count, index entry count, index
  file hash binding, index payload binding, per-entry payload hash binding,
  missing or unreadable proof-cache files, duplicate proof-cache paths, and
  aggregate proof-cache gaps. Lean checks this profile so a final pass cannot
  rely on stale, missing, duplicate, or unbound proof artifacts even when the
  higher-level obligation statuses look closed.
  The `proof_rule_profile` section is the compact Lean-facing summary of model
  proof-rule closure: every obligation, proof-cache/block-semantics record, and
  solver-evidence row must use or normalize to a proof rule allowed by the
  selected model. New map generation writes the generic rule spelling; deprecated
  target-specific aliases are accepted only as compatibility input and retained
  as metadata, not as primary proof rules. Proved block obligations must agree
  with the proof artifacts that justify them.
  The `mapping_profile` section is the compact Lean-facing summary of the
  explicit block-map contract: mapped code/non-code counts, reachable blocks,
  checked roots, checked block invariants, normalized mapping proof rules,
  non-code waivers, malformed ranges, and generated-map issues. It fails closed
  when the validation report has no present mapping contract, map generation
  recorded failures or incomplete issues, block ranges or waiver ranges are
  malformed, invariants are unchecked, checked roots have unknown root kinds,
  or mapping proof rules do not normalize to the selected generic model.
  The `cfg_profile` section is the compact Lean-facing summary of recovered
  control-flow structure: block-structure blockers, direct CFG edge obligations,
  direct edge kinds, direct edge side evidence, checked indirect-target
  obligations, and the generic proof rules used for indirect targets. It fails
  closed when direct CFG edges are open, malformed, or missing side evidence,
  when block-structure blockers remain, or when checked indirect targets lack
  source/signature/original/candidate evidence.
  The `reachability_profile` section is the compact Lean-facing summary of root
  and direct-CFG reachability closure: every reachability obligation must be
  closed by a known generic rule, direct-CFG reachability must cite a proved
  `cfg_edge` obligation whose target is the reached block, proved CFG edges
  must bind proved source/target blocks, and every proved CFG target must have
  a proved reachability obligation. This keeps reachability composition in the
  generic Stage A proof layer instead of leaving it as target-specific report
  convention.
  The `abi_profile` section is the compact Lean-facing summary of static
  ABI/callsite evidence: function and callsite counts on both sides, import
  prototypes, stack/register evidence, hidden sret/out-param candidates,
  varargs candidates, recoverable function-pointer targets, and the
  original-vs-candidate ABI comparison gaps. It fails closed when ABI functions
  or callsites are missing, callsite signatures diverge, stack/register ABI
  evidence differs, varargs or hidden sret/out-param evidence is lost, or
  function-pointer target evidence is incomplete. The full ABI evidence remains
  in the contract artifact; the proof IR binds it by hash and checks the
  closure profile.
  The `instruction_semantics` section extracts the canonical decode evidence
  for every decoded-instruction-backed proof, including per-side machine,
  bitness, instruction count, normalized instruction-stream hash, instruction
  byte-list hash, and decoded byte hash bound back to the proof-cache query.
  The `instruction_profile` section is the compact Lean-facing summary of
  that decode evidence: decoded-instruction-backed record counts, status
  counts, decoded identity/import-thunk semantics counts, decode status gaps,
  hash gaps, decoded byte mismatches, and missing instruction-semantics
  records. Lean uses this profile to reject incomplete decode evidence without
  materializing every instruction-semantics record for large binaries. This
  profile is deliberately separate from the higher-level semantic claim kind:
  a block can have complete decoded-instruction evidence while its observable
  equivalence claim is discharged by a symbolic SMT proof rather than byte
  identity.
  The `proof_artifact_bindings` section gives one deterministic row per proved
  block obligation so downstream tools can inspect the exact proof-cache,
  solver-evidence, and block-semantics records used by the closure check.
  The `semantic_observables` section then normalizes those records into the
  actual per-block observable contract: decoded-instruction identity,
  symbolic observable equivalence, checked mapping assumption, or import-thunk
  signature equivalence. The `semantic_profile` section is the compact
  Lean-facing summary of those records: counts of each semantic claim kind,
  trusted-boundary kind, solver-backed symbolic claim, unknown claim, and gap.
  Lean uses that profile to reject unknown semantic claim kinds, unapproved or
  missing trusted boundaries, and mismatched claim-to-boundary pairings without
  materializing every block record for large binaries. The instruction and
  semantic profiles are checked independently so a final `pass` cannot hide
  decode/hash gaps behind a coarser semantic claim count. The
  `environment_profile` section is the compact Lean-facing summary of the
  selected external environment model, loader import signatures, import-thunk
  block-semantics records, import-thunk semantic claims, trusted import
  boundaries, import-thunk solver-evidence rows, and symbolic external claims.
  It requires `uninterpreted-external-env-v1`, matching original/candidate
  loader import signatures, import-thunk signatures on both sides, import-thunk
  signatures present in the loader import table, matching import-signature
  hashes on semantic claims, and zero environment gaps. This makes external API
  and import-thunk acceptance explicit instead of relying on dispersed semantic
  counters. The `solver_claims` section extracts just the
  symbolic local-equivalence oracle claims from those semantic records and
  requires each trusted Z3 claim to bind a solver name, SMT status, SMT query
  hash, proof rule, and semantic-observable record hash. The
  `solver_evidence_profile` section is the compact Lean-facing summary of
  solver/proof evidence: proof-cache entry count, solver-evidence entry count,
  structural/mapping/import/Z3 evidence-kind counts, trusted Z3 unsat evidence
  count, query-hash gaps, query-hash mismatches, JSONL/index file hash binding,
  per-entry evidence hashes, solver-claim gaps, and unknown or incomplete
  evidence counts. The `solver_backend_profile` section separately binds
  solver-backed evidence and solver claims to a stable backend identity
  (`stage-a-solver-backend-v1`): solver name, version, symbolic engine,
  supported SMT fragment, trust boundary, and a canonical backend hash. It is
  satisfied for structural/mapping/import proofs with no solver-backed rows,
  but trusted Z3 claims fail closed when the backend object is absent, stale,
  unknown, or mismatched between semantic claims and solver-evidence rows.
  Structural identity proofs therefore have zero solver
  claims; symbolic proofs have explicit solver claims that can fail closed
  independently of the broader semantic record or a stale solver-evidence
  inventory. The `proof_composition` section gives one row per proved block
  obligation and spells out the dependency chain that must compose for that
  local proof: proof-artifact binding, block semantics, instruction semantics
  when decoded instructions are involved, semantic observable, solver claim
  when symbolic SMT is involved, and trusted-boundary approval. The
  `proof_context` section is the run-level hash
  manifest tying the model, original/candidate inputs, mapping, invariants,
  proof cache, solver evidence, semantic inventories, solver claims, proof
  composition, and closure certificate into one checked proof package. The
  model hash is not an opaque status token: Stage A recomputes it from the
  canonical model payload, records the same hash in the proof context, and
  has Lean check the resulting `proofIrModelHashBound` predicate before a
  final `pass` is accepted. Reference-contract export emits specific
  model-hash mismatch issues if `verdict.json`, `proof-ir.json`, or the
  proof-context hash manifest was generated from a stale or different model.
  The
  `trusted_boundaries` section enumerates
  the local oracle or assumption boundary used by every semantic-observable
  claim and fails closed when a claim uses an unknown or unapproved boundary.
  The `trusted_boundary_profile` section is the compact Lean-facing closure
  layer over that inventory: it binds trusted-boundary records to semantic
  observable records, requires model boundary names to be known and unique,
  requires every record to be allowed and hash-bound, and carries the explicit
  trusted-boundary gap count into the closure certificate.
  The `profile_manifest` section enumerates every required proof-family profile
  (`target_profile`, loader, coverage, proof-cache, mapping, CFG,
  reachability, ABI, environment, instruction, semantic, solver, and
  trusted-boundary families), records each profile's schema/status/hash/check
  closure, and gives Lean a single manifest predicate that fails closed when a
  new or stale profile family is not bound into the proof package.
  Reference-contract export also treats the validation report as a coherent
  artifact bundle: standalone `layout.json`, `obligations.json`, `proof-ir.json`,
  `proof-cache/index.json`, indexed `proof-cache/*.json` payloads,
  `solver-evidence.jsonl`, `solver-evidence-index.json`, and
  `lean/summary.json` plus `lean/inputs.json`, generated
  `lean/StageA/*.lean` sources, and copied `lean/StageA/User/*.lean` sources
  must match the hashes, counts, normalized obligation rows, layout payload,
  proof-cache payloads, Lean input snapshot, Lean source manifest, and
  summaries embedded in `verdict.json`, `proof-ir.json`, and
  `lean/summary.json`. A mixed or hand-edited report directory is exported as
  `incomplete`, even if each individual profile still claims `satisfied`.
- `solver-evidence.jsonl` and `solver-evidence-index.json`: hash-bound local
  evidence inventory for structural proofs, import-thunk proofs, checked
  generated mapping rules, and trusted Z3 results.
- `failures/*.json`: reachable mismatch with pre-state, original result, and
  candidate result.
- `incomplete/*.json`: exact blocker and required next action.
- `counterexamples/*.json`: solver model normalized into executable state.
- `witnesses/*`: runnable regression cases generated from counterexamples or
  proved partitions.
- `proof-cache/*`: normalized IR hashes, SMT queries, solver results, and model
  hashes.
- `lean/*`: generated theorem stubs and checked proof summaries.

## Core Model And Obligation Graph

Build a new Stage A core around a formal x86 PE32 model:

- Parse PE32 binaries, sections, imports/exports, relocations, entrypoint, and
  executable ranges.
- Recover basic blocks, direct CFG edges, call edges, returns, external call
  sites, and candidate/original executable byte coverage.
- Require every executable byte in both binaries to be classified as code
  obligation, padding/non-code waiver, thunk/import boundary, or unsupported.
- Load `block-map.json` and fail or report incomplete on missing, duplicate,
  overlapping, or type-incompatible mappings.
- Treat source provenance as optional debug metadata only.

Obligation statuses:

- `proved`
- `failed`
- `incomplete`
- `unmapped`
- `waived_noncode`
- `out_of_model`

## Same-Layout Compatibility

Before equivalence proof, validate binary eligibility:

- Same architecture and bitness.
- Compatible calling convention model.
- Compatible PE section permissions and mapped address model.
- Compatible import boundary model.
- Compatible global/address layout when strict same-layout metadata is
  supplied.
- Compatible block entry/exit conventions for every mapped block.

If layout compatibility fails, produce `fail` when the mismatch is concrete, or
`incomplete` when required layout facts are missing.

## Symbolic IR And Local Equivalence

Translate original and candidate blocks into a normalized symbolic IR:

- Bitvector registers and flags.
- Byte-addressed memory.
- Explicit reads/writes.
- Successor relation.
- External interaction events.
- Fault/exception outcomes where modeled.
- Unsupported instructions fail closed as `incomplete`.

Use Ghidra/SLEIGH or equivalent p-code semantics as the primary instruction
semantics source, with iced-x86/objdump-style decoding as cross-checking.
Decompiler C is never proof input.

For each mapped block pair, generate an SMT query:

```text
invariant_i(state)
AND original_transition_i(state, state_o')
AND candidate_transition_i(state, state_c')
IMPLIES equivalent_observables(state_o', state_c')
```

Observable equality includes:

- registers and flags required by the model;
- explicit memory reads/writes and read-dependent memory effects; reads after a
  same-address in-block write consume the symbolic written value;
- successor/return/call target;
- external call symbol/ordinal, arguments, ordering, and symbolic response
  consumption;
- modeled fault/exception behavior.

## Reachability And Invariants

Use sound inductive invariants, not exact global reachability enumeration.

For each block `i`, maintain predicate `I_i(state)`.

Prove:

- entry roots satisfy their entry invariants;
- for each original CFG edge `i -> j`, executing block `i` from `I_i` lands in
  `I_j`;
- callback/API-created roots have explicitly modeled root invariants;
- every equivalence proof is performed under `I_i`.

V1 report generation implements this as explicit `reachability` obligations:
the PE entrypoint is a root, block mappings may provide checked root metadata
for exported/callback/fixture roots, and direct CFG edges propagate
reachability only when the corresponding edge obligation is proved.
The generated `reachability_profile` then fail-closes the run if any direct edge
is open, any reachability obligation is open, a reachability proof uses an
unknown rule, a direct reachability proof does not point at a proved edge, or a
proved edge reaches a block without a proved reachability obligation.
The generated `cfg_profile` separately fail-closes malformed CFG evidence:
unsplit block-structure blockers, open direct edge obligations, unknown direct
edge kinds, missing original/candidate edge evidence, unchecked indirect target
proof rules, or indirect target rows without source/signature/side evidence.

Counterexample handling:

- If solver finds a mismatch satisfying `I_i`, try to prove whether it is
  reachable.
- If reachable, report `fail`.
- If unreachable, refine `I_i`.
- If reachability cannot be resolved, report `incomplete`.

Manual help enters only as checked invariant lemmas or explicit assumptions.
Explicit assumptions may unblock exploration but must prevent a final `pass`.

## External Environment Model

Represent external calls as events against an uninterpreted environment:

```text
Env.call(symbol, args, env_state) -> response, env_state'
```

A block pair is equivalent across an external boundary if both:

- emit the same event at the same interaction point;
- pass equal symbolic arguments;
- receive the same symbolic response/effects;
- continue equivalently for all allowed responses.

No Win32 API internals are required for v1. Unknown external targets,
unresolved imported symbols, or unmatched external event ordering are
`incomplete` or `fail` depending on whether the mismatch is proven.

The `environment_profile` in `proof-ir.json` is the fail-closed summary for this
contract. It binds the declared environment model to loader import signatures,
import-thunk semantic records, trusted import-thunk boundaries, and symbolic
external claims. Missing import signatures, import-thunk signatures not present
in the PE import table, unsupported environment models, or mismatched
claim/boundary/evidence counts keep the proof IR incomplete.

## Lean Integration

Implement proof in two layers:

- SMT/Z3 discharges local bitvector/memory equivalence and produces
  query/result artifacts.
- Lean defines the high-level soundness theorem, invariant framework,
  environment abstraction, and proof obligations.

Lean artifacts must include:

- generated model definitions for blocks, obligations, and invariants;
- a reusable generated `StageA/ProofIR.lean` checker module containing proof
  IR count structures, closure-certificate count checks, and
  closure-certificate family checks;
- a generated `StageA/Obligations.lean` summary that instantiates the
  reusable proof-IR checker from the concrete validation report instead of
  inlining every closure predicate as an isolated Boolean;
- theorem stubs for unresolved invariants;
- checked summaries for closed invariant/equivalence obligations;
- checked proof-IR presence, proof-cache counts, solver-evidence closure, and
  hash-bound evidence predicates for `proof-ir.json`, `proof-cache/index.json`,
  `solver-evidence.jsonl`, and `solver-evidence-index.json`;
- checked target-profile predicates, so final pass is blocked when the selected
  model, schema names, loader facts, loader profile, ABI, or environment model
  are inconsistent;
- a hash-bound Lean source artifact manifest for generated `StageA/*.lean`
  modules and copied `StageA/User/*.lean` modules; a final `pass` is blocked
  if those checked source artifacts are missing or unhashable;
- checked proof-IR closure-certificate predicates, so final pass is blocked
  when proof IR records open obligations, coverage gaps, incomplete solver
  evidence, proved block-equivalence obligations without proof-cache/solver
  evidence, mismatched proof-cache/solver/block-semantics obligation binding,
  missing or incomplete block-semantics records, missing or unknown normalized
  instruction-semantics records, missing or unknown normalized
  semantic-observable records, incomplete symbolic solver claims, unapproved
  trusted-boundary claims, semantic-profile mismatches, solver-evidence-profile
  mismatches, malformed block-map entries, unchecked mapping invariants,
  unknown checked roots, unknown mapping proof rules, malformed CFG evidence,
  open CFG/reachability/ABI-callsite obligations,
  direct-CFG reachability that lacks a proved edge, missing SMT query hashes,
  incomplete proof-composition records, stale
  proof-cache binding, or incomplete proof-context binding;
- no `sorry` or unchecked assumption allowed in a final `pass`.

Initial implementation may use SMT-trusted local equivalence, but the complete
Stage A `pass` must be backed by Lean-checked global soundness over the
generated obligation statuses, canonical proof IR, and hash-bound local evidence
inventory. Z3 remains a trusted local oracle in v1, but every solver result is
made explicit in the report as a `solver_claims` record and tied to the proof
cache, semantic-observable record, SMT query, and proof IR by hash.

## Diagnostics And Witness Tests

For every `fail`, emit:

- block id and mapped candidate block;
- first mismatching observable;
- counterexample pre-state;
- original post-state/event;
- candidate post-state/event;
- minimal runnable witness test.

For every `incomplete`, emit:

- blocker category;
- exact instruction/API/edge/invariant/query involved;
- suggested next action: add mapping, add invariant lemma, model instruction,
  resolve indirect target, increase solver budget, or mark non-code waiver.

Witness tests are regression/debug artifacts, not the proof source.

## Validation Plan

Unit tests:

- PE parser rejects unsupported architectures and malformed layouts.
- Block map validation catches missing, duplicate, overlapping, and incompatible
  mappings.
- IR translation handles arithmetic, flags, stack ops, memory reads/writes,
  calls, returns, branches, and unsupported instructions.
- External environment equivalence accepts matching uninterpreted calls and
  rejects mismatched symbol/args/order.
- SMT query generation produces counterexamples for known non-equivalent block
  pairs.
- Invariant checker rejects unproved assumptions in final `pass`.

Golden binary tests:

- Identical binary vs itself: `pass`.
- Same binary relocated only within accepted layout mapping: `pass`.
- Single arithmetic mutation: `fail` with register counterexample.
- Single branch predicate mutation: `fail` with successor counterexample.
- Memory write offset mutation: `fail` with memory counterexample.
- External call argument mutation: `fail` with external-event counterexample.
- Unsupported instruction fixture: `incomplete`.
- Missing indirect target fixture: `incomplete`.
- Missing invariant fixture: `incomplete`.

Integration tests:

- Build small PE32 fixture pairs from C/asm with known mappings.
- Validate equivalent and deliberately mutated variants.
- Validate a compiler-version matrix with GCC 13 and GCC 15 PE32 fixtures,
  differing flags and optimization levels, and a normalized same-layout PE
  wrapper for compiler-version object text where linker versions would
  otherwise introduce unrelated section-layout differences.
- Confirm witness tests reproduce each failure.
- Confirm proof-cache reuse gives stable incremental results.
- Confirm no final `pass` is possible with unchecked Lean assumptions or
  unresolved SMT queries.

## Acceptance Criteria

- Stage A can prove `pass` for nontrivial equivalent PE32 fixture binaries.
- Stage A can prove `fail` with actionable counterexamples for deliberate
  mutations.
- Stage A reports `incomplete`, not `pass`, for unsupported semantics or missing
  reachability proof.
- Candidate source language/provenance is not required.
- External APIs are handled through the uninterpreted environment model.
- The final verdict is reproducible from report artifacts.

## Assumptions And Defaults

- V1 targets generic x86 32-bit PE binaries, not WinCR or Halo specifically.
- Explicit block mapping is required; automatic mapping inference is out of
  scope for v1.
- Same-layout validation is mandatory, but source-level layout metadata is
  optional.
- External APIs are uninterpreted environment interactions, not concrete Win32
  implementations.
- Reachability is handled by inductive invariants and refinement, not exact
  exhaustive state enumeration.
- The tool is fail-closed: unknowns produce `incomplete`, never `pass`.
- Lean is used for global proof structure and checked manual invariants; SMT is
  used for local automated equivalence.
