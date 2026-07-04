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
  imported by the generated obligation summary, checked by Lean, and scanned
  for unchecked proof markers before any final `pass`.

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

## Lean Integration

Implement proof in two layers:

- SMT/Z3 discharges local bitvector/memory equivalence and produces
  query/result artifacts.
- Lean defines the high-level soundness theorem, invariant framework,
  environment abstraction, and proof obligations.

Lean artifacts must include:

- generated model definitions for blocks, obligations, and invariants;
- theorem stubs for unresolved invariants;
- checked summaries for closed invariant/equivalence obligations;
- no `sorry` or unchecked assumption allowed in a final `pass`.

Initial implementation may use SMT-trusted local equivalence, but the complete
Stage A `pass` must be backed by Lean-checked global soundness over the
generated obligation statuses.

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
