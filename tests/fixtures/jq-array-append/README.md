# Independently edited jq append supplier

`append.c` implements the actual `jv_array_append` operation using its existing
copy/length/set dependencies. The hand-defined V5 interface generates its own
typed service/context header. The C implementation never reconstructs native
pointers. `native-bridge.c` transports values to real libjq for this executable
experiment; it is fixture code, not a portable provider or a checked heap summary.

The original oracle is jq 1.8.1 PE32 `libjq-1.dll`, with the same pinned identity as
the [concat experiment](../jq-array-concat/README.md). Append's entry is RVA
`0x287bd`; the next exported operation, concat, begins at `0x288b3`. The admitted
inputs are owned valid array/item references with array length below `INT_MAX`.
Five cases cover an empty unique destination, a retained destination, a shared
nested object, a slice and appending a value that shares the destination backing.
Comparison observes the result and retained input contents. These finite checks
do not prove complete lifetime/heap preservation or every possible input.

## Shared driver and unique-owner context

The original five-scenario driver remains available. An additional handoff reuses
the [shared driver](../jq-value-transport/README.md#reusable-comparison-driver-for-two-owned-values)
for direct JSON inputs, with the same authored append C, interface, raw-value
representation and length admission rule. It exercises unique ownership, retained
aliases and a second input sharing the first array. The complete original append
body is intercepted on source execution, including calls from JSON setup.

Use the passing retained append inputs, such as
`build/practical-lifting-2026-09-15/representation-v2/raw-supplier/inputs`, and a
current pinned jq workspace containing the allocation observer and `jq.h`:

```sh
python tests/fixtures/jq-array-append/prepare_shared_driver.py \
  /path/to/append-inputs /path/to/jq-network prepared
spaghetti-extractor component start jq array-append \
  --comparison-package prepared/array-append --output work
spaghetti-headless-wayland spaghetti-extractor component check jq array-append \
  --comparison-package work --output baseline
```

[shared-driver.c](shared-driver.c) names the actual entries and retains the original
length admission check through the driver's optional callback. It supplies the
`input_words` field before the common observation code. This wrapper accepts direct
`unique`, `unique-address`, `retained` and `aliased` modes; the original specialized
driver keeps its slice/nested-object scenarios. The revised inputs are staged and
published using the existing revision API. No manual contract hashes, new component
or new tool internals are involved.

`unique` retains no extra input references. The example confirms the array arrives
with one reference and compares result `[1,2,3]` and allocation/lifetime observations.
The separate `address` case uses `unique-address` to inspect the raw-value storage
relationship too. Temporarily retaining a copy of the array across `set`, then
consuming that extra reference with `length`, keeps the JSON result and balances
ownership. The ordinary unique case still matches; the address case reports that
the original reused its input address while the edited C returned another address.
The mismatch replays after source repair. Address equality alone establishes neither
object lifetime nor content preservation, and that extra observation is optional.

The installed handoff is retained at
`build/component-unique-driver-2026-09-24/current/checkpoint.json`. Four append cases
pass, along with one existing array-search and both existing string-split cases
using the changed common driver. Repair reuses the append baseline with zero
compiler/link/execution work. The initial attempt used an obsolete v1 fixture whose
runtime failed strict compilation; its failure is retained separately. The current
handoff starts from the later passing v2 inputs and preserves their boundary.

## Public supplier edit and consumer reuse

Run these commands in `nix develop`, inside one headless Wayland session.
For a scripted walkthrough, use `spaghetti-headless-wayland bash walkthrough.sh`
with the commands below in that script. Keep the same desktop session across
checks intended to reuse evidence: starting a new compositor changes the bound
execution environment and correctly invalidates that reuse.

From the development shell, prepare three independent packages:

```sh
supplier=$(nix build './targets#legacyPackages.x86_64-linux.targets.jq.target.array-append-comparison-package' --no-link --print-out-paths)
isolated=$(nix build './targets#legacyPackages.x86_64-linux.targets.jq.target.array-concat-isolated-comparison-package' --no-link --print-out-paths)
integrated=$(nix build './targets#legacyPackages.x86_64-linux.targets.jq.target.array-concat-integrated-comparison-package' --no-link --print-out-paths)
spaghetti-extractor component start jq array-append --comparison-package "$supplier" --output build/append-draft
spaghetti-extractor component start jq array-concat --comparison-package "$isolated" --output build/concat-isolated
spaghetti-extractor component start jq array-concat --comparison-package "$integrated" --output build/concat-integrated
spaghetti-extractor component check jq array-append --comparison-package build/append-draft --output build/append-before
spaghetti-extractor component check jq array-concat --comparison-package build/concat-isolated --output build/isolated-before
spaghetti-extractor component check jq array-concat --comparison-package build/concat-integrated --output build/integrated-before
```

Edit `build/append-draft/source/append.c`. A compatible implementation can name the
copied reference separately and handle the empty-array branch explicitly before
the general set call. Leave its interface and admitted-input assumptions unchanged.
Check the supplier, retain isolated consumer evidence, and check the integration:

```sh
spaghetti-extractor component check jq array-append --comparison-package build/append-draft --reuse-comparison build/append-before --output build/append-after
spaghetti-extractor component check jq array-concat --comparison-package build/concat-isolated --reuse-comparison build/isolated-before --output build/isolated-after
spaghetti-extractor component check jq array-concat --comparison-package build/concat-integrated --dependency-package array-append=build/append-draft --reuse-comparison build/integrated-before --output build/integrated-after
```

| Check | Result of the compatible edit |
|---|---|
| Supplier | Changed source invalidates the prior result; five cases rerun |
| Isolated consumer | Eight retained cases reused; zero compiler/link/execution/model/solver calls |
| Integrated consumer | Selected supplier source invalidates the prior result; six cases rerun |

The isolated executable has no `lifted_array_append` body. For its component-call
interval, the fixture replaces the complete original append range with an entry
jump and trap instructions, then restores the bytes. Setup/observation still use
the real library. Controlled responses validate arguments/current state and use
real array_set for successful writes. The original DLL remains a retained input;
it is the edited **authored supplier** that is excluded from this local dependency
set. The integration includes both authored functions and compares their execution
against original concat using original append.

Changing the general set index to `index + 1U` gives a meaningful negative control:
the supplier and integration report an unexpected null gap in the result. The
isolated check remains reusable because its assumed responses did not change.
That conditional evidence cannot authorize the broken selection. Repairing the
supplier restores passing comparisons; a wrong integration's retained `inputs`
still replay the old bug after repair, including the old supplier body.

## Selection and remaining scope

The shared `sdk.lifting.comparisonPackage` accepts explicit `dependencies` entries
with an existing comparison package and consumer-side fixture bridges. It copies
the selected source/interface/header inputs, excludes the supplier's standalone
driver and runtime inventory, and compiles each unit with its own generated API.
Editor commands use those same include selections. Bodies are selected explicitly
once in a flat list; nested package selections are not implicitly imported.

`--dependency-package COMPONENT=DIR` updates a selected body under exact interface,
operation-symbol and assumption equality. A stable signature alone is insufficient.
Changed contract meaning rejects with a refinement diagnostic. The integration's
bridge remains explicitly owned by the integration; replacing a supplier's local
test adapter does not silently replace that bridge.

This demonstrates local editing and accurate concrete-evidence invalidation.
The sections below cover experimental execution, optional formal checks and
finite input-domain refinement with retained excluded counterexamples. The
[shared representation](../jq-value-transport/README.md) and
[DX-Ball lifecycle](../dxball-directdraw-lifecycle/README.md) walkthroughs exercise
the same public infrastructure with different representations and interactions.
Retained results and body inventories are under
`build/practical-lifting-2026-09-15/`; no new strong qualification is claimed.

## Experimental selected-network execution

The fixture's [`experimental-policy.json`](experimental-policy.json) accepts the
exact concat/append assumptions above and requires matching full comparisons of
both selected implementations. It permits pinned original runtime dependencies.
Review that policy when the domain or required evidence changes; ordinary source
edits use the same policy without another confirmation step.

After the supplier edit and integration commands above pass:

```sh
spaghetti-extractor candidate build jq --experimental-comparison build/integrated-after --component-comparison array-append=build/append-after --experimental-policy tests/fixtures/jq-array-append/experimental-policy.json --output build/array-network
spaghetti-extractor candidate test jq --experimental-package build/array-network --output build/array-network-run
```

The build reuses the integration's actual linked binary, inventories the selected
operation symbols, and copies the bound comparison inputs, outputs and required
runtime files. The manifest requires a supplier check with the same source,
headers, operation map, interface meaning and assumptions as the selected body.
Its integration-owned bridges and standalone supplier fixtures remain separately
bound through their respective comparison receipts. A partial replay, mismatch,
missing supplier check or incompatible selection cannot satisfy admission.

The suite runs only the authored `source` branch of the retained network driver,
using the existing candidate case runner and aggregator. It compares stdout with
the retained matching source observations and checks successful exit. The prior
original/source comparisons remain separate evidence; this rerun is a regression
check of the selected binary. Both the outer suite and direct case path recheck
the experimental manifest, and the case path checks the runtime copies and exact
case/environment settings. The inherited process environment is recorded only as
a digest, consistent with the comparison workflow; execution is not hermetic.

The typed experimental manifest is rejected by qualification and implementation
selection readers, and by `NativeRealizationV2`, the reader used by the qualified
Nix suite, per-case gate and project completion path. It
does not populate `native-realization.json` or qualify a portable provider. The
executed scope is this **component network**, with real libjq dependencies; it is
not the complete jq application or a completed portable lift.

`experimental-build-costs.json` reports zero compiler/model/solver/link invocations
and records evidence retention, validation and symbol-inventory time. The run
retains ordinary candidate reports plus `experimental-run.json` with phase times,
the admitted manifest/binary and process-environment digest. The fixture policy's
formal status list describes allowed outcomes; a comparison without a requested
formal check records `not-requested`.

## Optional formal checks

Add `--local-contracts` to a concrete component check to try the existing local
memory-contract rule:

```sh
spaghetti-extractor component check jq array-concat --comparison-package build/concat-integrated --dependency-package array-append=build/append-draft --local-contracts --output build/integrated-with-contracts
```

For this stateful jq interface the rule reports **unavailable** with its supported
shape and performs no model/solver work. The six concrete cases still execute
and compare normally, and the experimental policy permits this result. This is
an executed applicability check, not a declaration that the code is outside the
supported C dialect.

For supported fixed memory-view interfaces the same option checks source memory
frames and input dependence using the existing CBMC engine. Those properties
are explicitly scoped; they do not prove original/source equivalence.
`--query-timeout SECONDS` bounds each solver query separately from compilation.
Proof files and incomplete attempts remain under the comparison's `formal/`
directory, with source/interface/tool bindings and separate phase counts.

`--reuse-comparison` carries the optional check and its deadline forward. An
unchanged completed proof is validated with the existing evidence reader and
reused alongside the separate concrete observations. Edits invalidate the
affected source proof. A solver timeout does not change matching concrete cases
into failures and may satisfy experimental policy; a retained counterexample
cannot be relabeled as a timeout or removed by omitting `--local-contracts` from
the reuse command. Exhausting an unwinding bound is reported as incomplete proof,
not as a behavioral disproof. The selected policy still rejects unclassified or
incomplete formal results.

The real jq unavailable-rule run is retained as
`build/practical-lifting-2026-09-15/experimental-network-optional-run-v1`.
Actual timeout, successful source-proof reuse and counterexample-veto regressions
use the bounded memory-view fixture in `test_practical_contracts.py`; they are
checks of the common workflow and do not supply a general jq heap proof.

## Refine the practical input domain

The comparison plans now name input words: concat's `left_length` and
`right_length`, and append's `array_length`. `input_domain.constraints` uses the
existing checked unsigned interval format. Its `argument_index` indexes these
named fixture observations, not native ABI arguments. For example, this restricts
append to an empty destination while leaving its C signature unchanged:

```json
{
  "words": ["array_length"],
  "constraints": [{"argument_index": 0, "minimum": 0, "maximum": 0}]
}
```

The shared SDK accepts `inputDomain`. It generates
`comparison-input-domain.h` for each fixture translation unit. The fixture
measures the named values before calling the component and invokes that gate;
excluded root inputs return an explicit exclusion record. A selected supplier's
bridge applies its own gate on every call, exposing a false caller assumption.
Production component declarations and implementations do not acquire extra
parameters or synthetic cutpoint APIs.

A reproducible negative experiment, starting with the current packages above:

1. Retain full supplier and integration baselines. Change append's set index to
   `index == 0U ? 0U : index + 1U` and check it with the broad domain. The empty
   destination case matches and four nonempty cases expose a null gap.
2. Edit only `input_domain.constraints[0].maximum` in the supplier draft's
   `comparison-plan.json` to zero. Check with `--reuse-comparison` pointing to
   the wrong supplier result. The outcome is `domain-limited`: one matching case,
   four excluded cases, and all four old counterexamples retained. This does not
   report the bug as repaired or satisfy experimental admission.
3. Replaying `--case 1` from the narrowed result's
   `refinement/previous/inputs` still reproduces the old mismatch under its old
   domain. Ordinary later checks retain that exclusion history.
4. Selecting the narrower supplier in the old integration rejects the changed
   contract. Explicitly adopt its `input_domain` in the integration plan's
   `dependencies` row, then check with `--dependency-package` and the old
   integration as `--reuse-comparison`. Five caller contexts violate the new
   append requirement; only concat's empty-right case avoids an append call.
5. Repair the ordinary C and restore the broad domain. Recheck supplier and
   integration against their narrowed results. Both domain relations are
   `widened`; the retained caller violations are now admitted, and all five plus
   six cases match again. The normal experimental build/run workflow then passes.

The complete public command transcript and all eight comparison results are in
`build/practical-lifting-2026-09-15/domain-refinement-v1/`. `run-experiment.py`
records the commands and the ordinary source/JSON edits used in this demonstration.

Refinement checks compare interval meanings, require unchanged named projections,
interfaces and fixture/oracle inputs, and retain old inputs and outputs for replay.
Dropping a still-admitted baseline case is rejected before compilation, including
when the domain was left unchanged. `--case` remains an explicitly partial
diagnostic. An empty exercised domain reports `empty-domain`; a fixture that
ignores its gate or reports an unjustified exclusion fails validation.

Experimental policy must explicitly accept every selected `input_domain` through
`accepted_input_domains`. A stable signature or unchanged assumption text cannot
substitute for that binding. The checked interval relation concerns the supplied
fixture observations. It does not prove the correctness of arbitrary projection
code, universal caller reachability, heap invariants, or summary composition.
Optional source-contract proofs retain their existing V5 proof domains; these
concrete fixture restrictions do not silently narrow a formal theorem. The old
isolated consumer evidence still describes its original controlled append contract
and cannot authorize a supplier with incompatible requirements.

The [shared value representation experiment](../jq-value-transport/README.md)
uses the same authored source with raw values or bounded owned handles, including
explicit replacement-group selection and mixed-representation rejection.
