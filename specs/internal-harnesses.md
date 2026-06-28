# Internal Harness Spec

Private internal harnesses cover routines or states that process-level tests
cannot reach or cannot constrain enough. A harness target is a stable catalog
label first; private catalog data maps that label back to module SHA256 and RVA
when the target is original executable code.

The public-facing counterpart is an internal routine contract. It describes the
routine as a behavioral API: sanitized name, short purpose summary, inferred
calling convention/signature, input and output shape, preconditions,
postconditions, side effects, state transitions, fixtures, evidence source,
confidence, taint level, and review status. The private harness proves that
contract by executing the original PE routine identified by the private
module-hash/RVA mapping.

LLM-derived names and descriptions are permitted only as draft annotations.
Before publication they must be rewritten or approved as functional summaries.
Do not publish decompiler variable names, copied pseudocode, instruction
listings, or branch-by-branch implementation narratives.

Register a harness target with:

```sh
python -m haloce_catalog upsert-internal-harness \
  --db build/catalog/catalog.db \
  --target-label fn_target_state_probe_... \
  --harness-id function-state-probe \
  --harness-kind function \
  --command-template "private/harness function-state-probe" \
  --input-contract "seed deterministic game state" \
  --expected-observation "serialized behavior fixture matches observed output" \
  --risk "private original-code call glue"
```

Run a harness and record private artifacts with:

```sh
python -m haloce_catalog run-internal-harness \
  --db build/catalog/catalog.db \
  --harness-label harness_function_state_probe_... \
  --test-id function-state-probe-pass \
  --artifact-dir private/internal-harness/artifacts \
  --stdout-contains "harness-ok" \
  -- private/harness function-state-probe
```

The run command captures stdout, stderr, and a result JSON file, then records an
`internal_harness_runs` row and a linked `private_harness` oracle test case.
Externally orchestrated harnesses can use `record-internal-harness-run` with an
existing fixture or trace log.

Do not commit harness binaries, copied code, decompiler text, original assets,
algorithm walkthroughs that mirror proprietary control flow, or private harness
internals that reveal proprietary expression.
