# Stage A Structured Round-Trip Fuzzing Qualification Report

## Decision

The bounded `structured-spike-v1` feasibility program passed on 2026-07-22.
The structured corpus is suitable as a fast qualification layer for generic
Stage A development and for the Stage A to Stage B handoff.

This is a go decision for the initial profile, not a claim that Stage A already
models all IA-32, Windows, compiler output, or jq behavior. Unsupported
instructions and environment or control-flow forms must continue to produce
precise `incomplete` results. Phase 6 of the plan remains future capability
expansion.

Machine-readable evidence is checked in alongside this report:

- [`stage-a-round-trip-feasibility-report.json`](stage-a-round-trip-feasibility-report.json)
- [`stage-a-round-trip-qualification-evidence.json`](stage-a-round-trip-qualification-evidence.json)
- [`stage-a-round-trip-discovery-qualification.json`](stage-a-round-trip-discovery-qualification.json)
- [`stage-a-round-trip-genericity-baseline.json`](stage-a-round-trip-genericity-baseline.json)

## Qualified Pipeline

The qualification exercises three distinct paths without changing Stage A's
acceptance authority:

1. **Known relation:** deterministic semantic programs are lowered to two real
   PE32 binaries and passed through ordinary Stage A extraction, preparation,
   Lean proof construction, and final audit.
2. **Discovery:** mappings are withheld and recovered from binary and linker-map
   evidence. Recovered artifacts are untrusted proposals and must still pass
   the ordinary proof path.
3. **Opaque Stage B:** the original is consumed statically by Stage A, which
   exports an isolated state-machine bundle. Stage B consumes only that allowed
   bundle, emits ugly C, compiles it with MinGW, and returns the candidate to
   the same Stage A final-theorem path.

No corpus label, seed, source name, fixed RVA, transformation name, generator
semantic object, or private lowering metadata can authorize acceptance.

## Proof Results

The initial spike contained 24 positive and 12 negative real PE32 pairs. It
passed before corpus promotion.

The promoted Nix qualification contains 75 cases in 21 packs:

| Result | Expected | Observed |
|---|---:|---:|
| final whole-program `pass` | 50 | 50 |
| checked `violated` | 25 | 25 |
| `incomplete` | 0 | 0 |
| expectation mismatch | 0 | 0 |
| unexpected negative `pass` | 0 | 0 |

Positive acceptance requires `whole_program_lean` authority and one of these
audited final theorem identities:

- `StageA.GeneratedRelational.candidatePE32ProgramsEquivalent`
- `StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked`

The aggregate report has no proof authority. A negative `pass` is fatal.
Supported negative mutations are accepted as tests only after their mismatch
witness has been replayed against the exact bound artifacts; raw solver status
cannot produce `violated`.

There are no capability-boundary negatives in this promoted corpus. The
generic unsupported-instruction fixture separately verifies that an
unsupported semantic form produces an actionable `incomplete` result before
Lean, rather than an approximation or accidental pass.

## Stage B Boundary

The opaque Stage B integration test completed the required static round trip:

```text
opaque original PE32
  -> static Stage A state-machine bundle
  -> Stage B semantic C
  -> MinGW candidate PE32
  -> Stage A final whole-program Lean theorem
```

The generated C is intentionally conservative and compiled with
`-O0 -fomit-frame-pointer`. The provenance audit rejects generator semantics,
seeds, ground-truth maps, and private lowering metadata at the Stage B input
boundary. The original is not executed or traced by Stage B.

The final qualification run for this test passed in 185.29 seconds. This is a
representative small program, not a claim that arbitrary unknown binaries can
yet be converted to C without manual repair.

## Discovery

One case from each initial semantic family was run with mappings withheld:

- straight-line arithmetic;
- guarded branch;
- bounded loop; and
- internal call with stack memory.

All four produced deterministic proposals marked `ready_for_proof`, with no
proposal frontier. All four recovered relations were semantically different
from the generator's ground-truth relation. This is acceptable for the
discovery qualification: mapping discovery need not reconstruct source labels
or the generator's chosen relation, and its output has no proof authority.
Each proposal still requires ordinary Stage A proof validation before it can
contribute to acceptance.

## Reduction

The structure-aware reducer was qualified by regenerating and validating real
PE, map, and contract artifacts on every attempted simplification. Two runs
produce the same minimized result and preserve the selected mismatch family.

The reducer orchestration test uses a cheap checked-mismatch predicate so that
algorithmic minimization is testable without rebuilding Lean for every
attempt. The actual violation-witness checker is independently qualified by
the 25 promoted negative Nix cases. The reducer therefore does not claim that
each reduction attempt reruns Lean.

## Feasibility Gates

All declared gates passed:

| Gate | Threshold | Observed |
|---|---:|---:|
| generation plus static preflight median | less than 1 s/case | 0.514939 s |
| warm final theorem median | less than 10 s | 0.020147 s |
| unchanged proof-phase reuse | at least 90% | 100% (75/75) |
| forbidden acceptance dispatch | exactly 0 | 0 |
| generic-rule/shape growth ratio | at most 0.5 | 0.382353 |

The exact promoted corpus was regenerated locally in 38.447 seconds, or
0.512627 seconds per case. Static preflight itself had a 0.002312-second median
and 0.004454-second maximum. The regenerated corpus manifest matched the
proved corpus SHA-256:

```text
a2fa93b340e34ab0f66de55b8e190acff724a47be3b53ad10356398370b8c843
```

The unchanged full 75-case Nix qualification completed in 6.543 seconds.

## Genericity Audit

The qualification observed 34 structural shapes across eight semantic
constructors. The proof implementation contained 129 generic rules and 612
Lean constructors. Relative to the checked baseline, 34 new structural shapes
required 13 generic-rule additions, producing the 0.382353 growth ratio.

The scanner found no forbidden case-, seed-, target-, RVA-, template-, or
transformation-specific acceptance dispatch and no special-case conditionals.
These metrics are diagnostics rather than proof authority, but they guard
against passing a larger corpus by accumulating fixture recognizers.

## Build And Cache Architecture

Generated Lean modules are compiled through granular content-bound Nix
derivations. A single preparation-graph IFD barrier realizes all case
preparations before proof derivations are evaluated; a second result barrier
does the same for proof audits before pack aggregation. This preserves full
case fanout instead of serializing one generated graph at a time in the Nix
evaluator. Independent cases and packs can then be scheduled across the remote
builders.

The final report imports compact, content-bound JSON summaries rather than
retaining every proof derivation in its runtime closure. The qualified output
is 268 KiB and has two direct store references, so aggregation does not retain
or copy the complete proof DAG.

The qualification used remote-only scheduling (`--max-jobs 0`) with two cores
per job. It reached 20 concurrent Lean processes across `acacia` and `banksia`
without memory pressure. Nix store paths are the persistent proof cache.
Unchanged local realization observed 75 cache hits and no misses. The promoted
aggregate is:

```text
/nix/store/pckk6zz1d802flyqn7jvpqyb5lbyqamp-stage-a-roundtrip-promoted-qualification-check
```

## Reproduction

Run the promoted release gate through the configured remote builders:

```bash
NIX_SSHOPTS='-o IdentitiesOnly=yes -o BatchMode=yes' \
nix build --no-link .#stage-a-roundtrip-promoted-check \
  --max-jobs 0 --cores 2 \
  --builders "$(paste -sd';' nix/stage-a-builders)" \
  --option builders-use-substitutes true \
  --option substituters \
    'https://cache.corncheese.org/nix-cache https://cache.nixos.org/'
```

Run the rapid Python qualification layer:

```bash
env PYTHONPATH="$PWD:$PWD/src" pytest -q \
  tests/test_stage_a_roundtrip_fuzz_*.py \
  tests/test_stage_a_roundtrip_nix.py \
  tests/test_stage_a_lean_compact.py
```

Run the opaque Stage B proof qualification explicitly:

```bash
env PYTHONPATH="$PWD:$PWD/src" pytest -q \
  tests/test_stage_a_roundtrip_fuzz_stage_b.py \
  -k opaque
```

## Residual Work

The qualification establishes that the architecture is viable and fast for
the bounded initial semantic profile. It does not establish full jq support.
Further families must be added under Phase 6 in the order defined by the plan,
with independent positive, negative, reduction, genericity, and final-theorem
qualification before promotion.

The next breadth work should include nested calls, static writable data,
bounded indirect control, dynamic ranges, exact lockstep imports, callbacks,
additional instruction families, and controlled compiler-generated C. None of
those future capabilities may weaken the final whole-program theorem gate.
