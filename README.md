# Spaghetti Extractor

Spaghetti Extractor is a high-assurance binary reimplementation toolkit. Its
immediate consolidation target is a generated GNU `hello.exe` reimplementation
for 32-bit MinGW Windows, followed by the full `jq.exe` benchmark.

The active direction is assurance-first rather than mandatory-whole-program-
theorem-first:

1. Stage A consumes the original binary statically and emits exact contracts
   and a canonical executable machine IR.
2. Pinned x86 lifting is independently qualified with ISA corpora, emulators,
   hardware evidence where practical, differential checks, and explicit trust
   records.
3. Stage B lowers the complete IR into compiler-consumable full-machine-state
   C0 plus exact source maps and regional validation contracts.
4. Formal, solver, exhaustive, differential, fuzz, integration, and assumed
   evidence remain distinct in an auditable assurance report. Reachable unknown
   behavior still fails closed.
5. Candidate-only runtime validation begins only after complete static
   qualification, then the generated baseline acts as the oracle for
   progressive human-readable reconstruction.
6. Strict whole-program Lean theorems remain optional stronger assurance
   tracks and retain their existing `pass` and `conditional_pass` meanings.

Stage B must not execute or trace the original binary during repair iteration.
Original runtime output is not an oracle. If a candidate satisfies Stage A but
fails public behavior checks, that is a Stage A/toolchain problem to investigate.

The `experiment/source-equivalence` branch contains a deliberately separate
source-relative theorem path. It proves an exact original PE equivalent to
canonical C0 semantics and derives only a `conditional_pass` for the compiled
artifact under an explicit pinned-toolchain correctness premise. It cannot
authorize the ordinary binary-to-binary `pass`, and neither theorem verdict is
required by the primary high-assurance workflow. See
[the source-equivalence experiment](docs/stage-a-source-equivalence-experiment.md).

See
[the high-assurance reimplementation direction](docs/high-assurance-reimplementation-direction.md)
for the trust model, evidence classes, static qualification gate, progressive
reconstruction pathway, and scalability criteria.
The current GNU Hello result and its exact limitations are recorded in
[the high-assurance vertical-slice report](docs/gnu-hello-high-assurance-vertical-slice.md).

For `contract-guided-c`, `state-machine.jsonl` is the canonical generation
authority. It preserves each block pre-state, symbolic register and flag
writes, memory and external events, edge guards, control outcome, stack delta,
instruction bytes, status, and deterministic hash. `functions.json` and the
manifest contain compact references to those transfer IDs and hashes rather
than a second semantic model. Missing, unsupported, or source-unbound transfers
remain explicit completion blockers. The generated manifest also records the
proof-oriented `gnu17`, `-O0` MinGW build profile; a successful compile or link
does not imply equivalence.

Each contract-guided package also contains `semantic-c/state-machine-transfers.c`.
Those transition functions are generated from symbolic effects, not copied
instruction bytes, and form the implementation substrate for opaque binaries.
`semantic-c/state-machine-dispatch.c` composes the transitions by semantic RVA,
while `semantic-c/state-machine-repairs.c` contains compile-safe, fail-closed
stubs for contracts that still require human or LLM repair. The source map binds
every generated or repaired C symbol to the exact Stage A transfer ID and hash.
`outputs.implementation` is the authoritative contract-guided source bundle;
`outputs.bootstrap_source` is not candidate implementation evidence. The
accompanying report fails closed on external-event sequencing, x87, ambiguous
memory ordering, unsupported expressions, and ambiguous dispatch RVAs.

## Commands

Nix is the only supported build and proof execution boundary. Python commands
coordinate Nix derivations or run inside phase-scoped derivations; direct
host-side Lean compilation is test-only and cannot produce an accepted report.
The public ISA conformance command follows the same rule for its Lean, Unicorn,
and Bochs backends; `stage-a-check-isa-conformance-worker` is reserved for Nix
derivations.

Build the command suite:

```sh
nix build .#spaghetti-extractor --no-link
```

Build the GNU Hello static lifting benchmark. It emits
`usable-incomplete`: exact jump-table, typed-memory, atomic, callback, and
rooted-reachability evidence while retaining unresolved frontiers:

```sh
nix build .#stage-b-gnu-hello-lifting-evidence --no-link
```

Build the independently cached typed-C lifting workspaces and combine only
qualified regions into an override registry:

```sh
nix build .#stage-b-gnu-hello-reconstruction-registry --no-link
```

Classify application, import-thunk, linked dependency, compiler-support, and
unknown machine units using pinned public/private artifact catalogs:

```sh
nix build .#stage-b-gnu-hello-linked-islands --no-link
nix build .#stage-b-gnu-hello-library-hypotheses --no-link
nix build .#stage-b-gnu-hello-dynamic-library-requirements --no-link
nix build .#stage-b-gnu-hello-library-replacement-plan --no-link
nix build .#stage-b-jq-linked-islands --no-link
nix build .#stage-b-linked-library-analysis-smoke --no-link
```

Recognition is static-only and never authorizes replacement by library name or
byte identity. A reusable interface contract plus checked component evidence is
still required before portable C can replace an island; ambiguous and unknown
regions remain explicit machine-IR fallback. This permits old SDK, compiler,
and private-library catalogs without requiring a centralized copy of every
historical implementation. See
[the semantic component framework](docs/semantic-component-framework.md#federated-linked-library-recognition).

The generic DAG is defined in
`nix/stage-b-reconstruction-workspace.nix`. Its Python commands are phase
workers and interactive diagnostics; an accepted repository artifact is the
Nix realization. The emitted `reconstruction-status.json` tracks source-lift
coverage separately from Stage A proof or assurance verdicts.

Harder GNU Hello examples have portable implementations and candidate-only
qualification checks. They cover atomic compare-exchange, callback
registration, finite indirect dispatch, and ordered alias-sensitive memory:

```sh
nix build .#stage-b-gnu-hello-dispatch-workspace-check --no-link
nix build .#stage-b-gnu-hello-typed-memory-workspace-check --no-link
nix build .#stage-b-gnu-hello-atomic-workspace-check --no-link
nix build .#stage-b-gnu-hello-callback-workspace-check --no-link
```

Build the independent idiomatic-C GNU Hello application and its assurance
bundle:

```sh
nix build .#stage-b-gnu-hello-idiomatic-source-binding --no-link
nix build .#stage-b-gnu-hello-idiomatic-candidate --no-link
nix build .#stage-b-gnu-hello-idiomatic-functional-suite --no-link
nix build .#stage-b-gnu-hello-idiomatic-upstream-suite --no-link
nix build .#stage-b-gnu-hello-idiomatic-assurance --no-link
```

Validate the static machine-call-to-source handoff and candidate dependency
envelope separately:

```sh
nix build .#stage-b-gnu-hello-source-call-substitution-smoke --no-link
```

This closes and assigns all 41 calls in the reviewed GNU Hello application
islands, checks all 45 Clang-inventoried source calls, and rejects candidate PE
imports outside the bound 53-entry toolchain/source envelope. Its three
source-component contracts remain explicitly unqualified, so this check does
not claim source equivalence.

The static binding closes all 83 machine-IR units in the reviewed
`src/hello.o` text ranges. The other 7,778 units remain explicitly outside the
application-source scope as linked runtime and library code. The source-only
candidate passes eleven extended expected-output cases and all seven unmodified
GNU Hello 2.12.3 upstream test scripts under headless Wine. Its assurance
status is `behavior_validated` and its equivalence status
is deliberately `not_proven`; neither the static binding nor runtime suite may
authorize a machine override or a Stage A pass.

Runtime tests are candidate-only veto evidence, not an acceptance path while
rooted static control closure is incomplete.

Export the versioned schema, artifact, Lean-interface, and parallel-workstream
boundaries used by Stage A development:

```sh
spaghetti-extractor stage-a-export-interfaces --out stage-a-interfaces.json
```

Prepared proofs embed and hash the same manifest. See
[Parallel Stage A Development](docs/stage-a-parallel-development.md).

Run the compact Stage A fixture suite:

```sh
nix build .#stage-a-fixtures-check --no-link
```

Run the phase-oriented relational tests as independently cached per-case Nix
builds. The repository builders file schedules the heavy Lean suites remotely,
while `stage-a-relational-kernel-cache` supplies the source-matched compiled
static kernel to every case:

```sh
nix build .#stage-a-relational-tests --no-link \
  --builders "@$(realpath nix/stage-a-builders)" --max-jobs 0
```

GNU hello uses cached input-addressed preparation followed by a dynamically
generated Lean derivation graph. Run the two phases through the coordinator:

```sh
nix run .#stage-a-gnu-hello-proof
```

The first phase is also a normal flake check and can be built independently:

```sh
nix build .#stage-a-gnu-hello-preflight --no-link \
  --builders "@$(realpath nix/stage-a-builders)" --max-jobs 0
```

The proof app realizes that output, validates its prepared-proof hashes, and
then asks Nix to build the focused Lean launch-certificate graph remotely. GNU
hello remains incomplete, so this checks an intermediate launch certificate and
the truthful whole-program frontier; it does not claim final equivalence.

Build and validate the full Windows x86 jq alignment-pair contract:

```sh
nix build .#stage-a-jq-fixtures --no-link
nix build .#stage-a-jq-fixtures-check --no-link \
  --builders "@$(realpath nix/stage-a-builders)" --max-jobs 0
```

The jq path is split into independently cacheable derivations:
`stage-a-jq-prepared-proof` performs static extraction and prepares the proof
graph, `stage-a-jq-reference-contract` exports Stage B feedback from that graph,
and `stage-a-jq-fixtures-check` performs the lightweight acceptance audit. A
report or assertion change therefore does not repeat PE extraction or hidden
Lean compilation. The generic preparation path separates executable inventory,
side extraction, ISA extraction, normalization, dataflow, memory products,
composition, and source generation into explicit Nix dependencies. The
generated proof module graph is the finer-grained distributed Lean boundary.

Generate a relation contract with reusable machine-level external-call schemas:

```sh
spaghetti-extractor stage-a-generate-relation-contract \
  --original original.exe \
  --candidate candidate.exe \
  --mapping block-map.json \
  --external-profile profiles/pe32-kernel32-lockstep-v1.json \
  --out relation-contract.json
```

External profiles are checked theorem inputs, not trusted API implementations.
Stage A selects only declarations whose exact import identity occurs in both
binaries, validates every declaration, and still requires Lean to close each
reachable external boundary. See [profiles/README.md](profiles/README.md).

Bootstrap a jq skeleton from the Stage A contract:

```sh
nix build .#stage-b-jq-skeleton --no-link
```

Build the static jq component graph and all currently qualified operator-owned
portable-C replacements:

```sh
nix build .#stage-b-jq-component-interfaces --no-link
nix build .#stage-b-jq-component-registry --no-link
```

The registry validates twenty tracked portable-C implementations with CBMC
and at least ten candidate-only regional cases each. Fourteen have total
activation. The constant-string collection, x87 callback dispatcher, bounded
PE32 section walk, DBCS-aware Windows path scanner, and byte/wide bounded
string-length loops have checked guards and fall back to the canonical machine
IR outside their domains. Together they unconditionally replace 70 machine
units and conditionally replace another 129.
This is component-level evidence, not a whole-program jq assurance result.

After the state machine has been exported once, regenerate only the semantic-C
implementation and repair queue without repeating PE extraction, Ghidra, or
Lean work:

```sh
spaghetti-extractor stage-b-generate-semantic-c \
  --state-machine stage-b/state-machine.jsonl \
  --machine-call-catalog stage-a/relation-contract.json \
  --out-dir stage-b/semantic-c
```

The command verifies every transfer hash before writing C. It generates nested
internal-call execution automatically and can generate direct x86 import
adapters from checked machine-call contracts. The adapter catalog is an
untrusted code-generation input: final acceptance still comes only from Stage
A validating the compiled PE. The command exits incomplete while any repair
stub, unresolved indirect target, unmatched API signature, or other runtime
binding remains. `state-machine-implementation.json` exposes a separate
`strict_candidate` status; scaffolding may compile with repair slots, but a
strict candidate may contain none.

Prepare a local slice workspace from the canonical jq Stage A contract:

```sh
nix run .#spaghetti-extractor-slice -- --work-dir build/spaghetti-extractor-slices prepare jq --realize-nix
nix run .#spaghetti-extractor-slice -- --work-dir build/spaghetti-extractor-slices next jq --top-k 10
```

The ignored `build/` tree is wholly disposable scratch space. Do not keep
hand-repaired or otherwise durable Stage B source there; source that must
survive cleanup belongs in a tracked repository path.

For the hot loop, pass local candidate outputs to `spaghetti-extractor-slice check` or build
them with `spaghetti-extractor-slice build`. This avoids rebuilding Ghidra exports or Nix
candidate artifacts when only a small source slice changed.

## Current Surface

Retained:

- `src/spaghetti_extractor/relational/`: authoritative whole-program relational pipeline,
  typed artifact boundaries, analyses, Lean generation, Nix orchestration, and report
  validation. Its `api.py` module is the public Python interface.
- `src/spaghetti_extractor/contract_tools.py`: untrusted mapping proposals and reusable
  contract serialization used around the relational proof core.
- `src/spaghetti_extractor/stage_b*.py`: jq skeleton, provenance, candidate-only delta, and
  public expected-output helpers.
- `src/spaghetti_extractor/slice_loop.py`: incremental contract-first slice iteration.
- `tools/ghidra/SpaghettiExtractorStageBExport.java`: optional cold bootstrap exporter.
- `tools/stage-a-fixtures/`: compact Stage A regression fixtures.

Removed:

- runtime tracing/original-output oracle tooling;
- target-specific catalog/database/reporting stacks;
- VM and dynamic instrumentation packaging;
- sample-game and old block-recovery tooling.

## Validation Discipline

Use static qualification first. Runtime checks must not substitute for unknown
reachable transfers, control targets, or external boundaries. When Wine is
needed for candidate-only diagnostics, run it under a headless Wayland/X
session.

See
[docs/high-assurance-reimplementation-direction.md](docs/high-assurance-reimplementation-direction.md)
for the primary project direction. See
[docs/stage-a-architecture.md](docs/stage-a-architecture.md) for the strict
formal `pass` trust boundary and command authority.
The bounded structured qualification workflow and its measured result are in
[docs/stage-a-round-trip-fuzzing-plan.md](docs/stage-a-round-trip-fuzzing-plan.md)
and
[docs/stage-a-round-trip-fuzzing-report.md](docs/stage-a-round-trip-fuzzing-report.md).
