# Internal Routine Contracts

Large programs with a small external API need routine-level behavior contracts.
For Halo CE-scale targets, black-box process tests are not enough to constrain
the engine. The clean-room output may therefore include sanitized internal API
contracts for original routines, data structures, and state transitions.

## Identity

Every internal routine contract has a stable public label first. Private oracle
tooling maps that label to the exact original code by module SHA256 plus RVA:

```json
{
  "label": "routine_map_header_validate_v1",
  "module_sha256": "private catalog only",
  "rva": "private catalog only",
  "calling_convention": "stdcall",
  "signature_confidence": "medium"
}
```

Public specs should use the label. The private SQLite catalog keeps the
label-to-`{module_sha256, rva}` mapping so harnesses can prove which original
binary routine produced the observed behavior.

The private dirty corpus exporter writes each `internal_routine_contract` row as
a discrete `review/internal-routine-contracts/...` packet. Its `dirty.json`
retains private identity and evidence context; its `clean-template.json` is the
human/LLM rewrite target. The public derivation stage only emits that template
after it is reviewed, marked `reviewed_public`, and checked for private leaks.

## Allowed Public Content

A sanitized internal routine contract may include:

- A human-readable `public_name` and short `purpose_summary`.
- Calling convention, inferred parameter/return shape, and confidence.
- Preconditions, postconditions, error behavior, and side effects.
- Globals, buffers, files, packets, registry keys, or platform endpoints touched
  as behavioral facts.
- Input/output fixtures captured by executing the original binary.
- State transition rules and invariants derived from observations.
- Coverage and oracle evidence labels showing which original code was exercised.

These contracts are behavioral APIs for clean-room implementers. They do not
require the clean-room runtime to preserve the same internal architecture unless
binary/internal ABI compatibility is an explicit target goal.

## Names And Descriptions

LLM-assisted names and descriptions are allowed as draft metadata when they are
derived from disassembly, imports, strings, callsite context, data references,
and dynamic observations. They must be treated as inferred annotations, not
facts, until reviewed.

Recommended fields:

- `public_name`: sanitized functional name, such as
  `map_header_validate_v1`.
- `purpose_summary`: one to three sentences describing observable behavior.
- `evidence_source`: for example `dynamic_observation`, `strings_imports`,
  `callsite_context`, `disassembly_inferred`, or `human_review`.
- `confidence`: `low`, `medium`, or `high`.
- `taint_level`: `behavioral_public`, `static_inferred_public`, or
  `private_only`.
- `review_status`: `draft`, `reviewed`, or `rejected_for_publication`.

Prefer names that describe behavior. Do not preserve decompiler-generated local
variable names, private symbol guesses, or names copied from proprietary debug
material.

## Private-Only Content

Keep the following out of public specs:

- Decompiled bodies, copied pseudocode, or instruction listings.
- Algorithm walkthroughs that mirror proprietary control flow.
- Original instruction bytes or byte dumps.
- Private harness glue that reveals expression rather than behavior.
- Detailed branch-by-branch narratives unless rewritten as observable
  preconditions, postconditions, or test vectors.

If a description cannot be separated from proprietary expression, mark the
routine contract `private_only` and publish only higher-level behavioral tests
or aggregate coverage evidence.

## Harness Relationship

Private internal harnesses execute the original PE routine identified by the
private module-hash/RVA mapping. Public tests should consume only the sanitized
contract, fixtures, and expected observations. This split lets researchers use
static analysis to discover routine boundaries while keeping clean-room
implementers focused on behavior rather than implementation expression.
