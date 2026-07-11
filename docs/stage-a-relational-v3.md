# Stage A Relational v3 Profile

## Purpose

`x86-pe32-relational-v3` is a separate proof profile for equivalent PE32/i386
programs whose code layout and instruction selection may differ. It does not
relax `x86-pe32-lean-refinement-v2`. A v3 report embeds the exact original and
candidate bytes, re-parses them in Lean, decodes every classified executable
region with the reviewed x86 semantics, and proves the declared relations.

Python, pefile, Capstone, block-map generation, decoded-semantics caches, and
SAT proof production are untrusted producers. The checked boundary is the Lean
kernel, `Formal.lean`, `Relational.lean`, and either a replayed LRAT certificate
or kernel-checked bitvector normalization for each region.

## Workflow

Project an existing complete block map into an editable relation contract:

```sh
wincr stage-a-generate-relation-contract \
  --original original.exe \
  --candidate candidate.exe \
  --mapping block-map.json \
  --out relation-contract.json
```

Prove and independently replay it:

```sh
wincr stage-a-prove \
  --model x86-pe32-relational-v3 \
  --original original.exe \
  --candidate candidate.exe \
  --relation-contract relation-contract.json \
  --out report/

wincr stage-a-check-proof --report report/
```

The dedicated aliases `stage-a-prove-relational` and
`stage-a-check-relational-proof` expose the same profile directly.

For large proofs, separate deterministic extraction from Lean compilation:

```sh
wincr stage-a-prepare-relational \
  --original original.exe \
  --candidate candidate.exe \
  --relation-contract relation-contract.json \
  --out prepared-proof/

wincr stage-a-build-relational \
  --prepared prepared-proof/ \
  --executor nix \
  --builders-file nix/stage-a-builders \
  --out report/
```

Preparation emits source only: exact PE artifacts, normalized proof IR,
generated Lean modules, their direct import graph, source hashes, estimated
resource classes, the expected final theorem, and the approved axiom set. It
rejects unsupported semantics before creating the graph and removes all
`.olean` files so an unrecorded local build cannot enter the prepared input.

The Nix executor validates the complete graph before evaluation. Independent
definition, local-proof, decode, direct-composition, structural, and closure
nodes become separate derivations using the Lean version pinned by
`flake.lock`. Builder selection is external: normal Nix configuration is used
unless `--builders-file` supplies a machines file. The evaluator does not name
or special-case any host or target binary.

The final derivation imports the generated bundle and runs Lean with
`--trust=0`, which type-checks imported modules rather than trusting remote
`.olean` files. It also rejects final-theorem dependencies outside the approved
axiom set. `nix-provenance.json` records every node store path, derivation/NAR
metadata, the evaluator and lock hashes, and the final audit output. A cached
node is reused only when its generated source, dependencies, pinned toolchain,
and evaluator are unchanged.

The build command still fails closed on the proof inventory. A checked Lean
bundle does not produce `pass` while CFG invariants, memory relations, or any
other non-local obligation remains incomplete.

## Contract

The contract explicitly names observations and environmental assumptions:

```json
{
  "format": "stage-a-relation-contract-v1",
  "environment": {"id": "adversarial-pe32-external-v1"},
  "observations": ["external_call", "external_jump", "return", "fault"],
  "memory_relation": {"mode": "identity"},
  "code_targets": [
    {"id": 0, "original_rva": 4096, "candidate_rva": 4128}
  ],
  "regions": [
    {
      "id": "entry",
      "root": true,
      "original": {"rva": 4096, "size": 7},
      "candidate": {"rva": 4128, "size": 8},
      "inputs": [{"original": "eax", "candidate": "eax"}],
      "outputs": [{"original": "eax", "candidate": "eax"}]
    }
  ],
  "padding": []
}
```

The checker rejects coverage gaps, overlaps, ambiguous register relations,
roots that do not pair the PE entrypoints, unresolved logical targets, invalid
padding, hidden environment assumptions, and unsupported memory translations
before proof production.

The exact-byte theorem checks:

- both inputs parse as PE32/i386 with valid import and relocation tables;
- every executable byte is a decoded region or verified padding;
- the paired entrypoint is a checked root and every logical target resolves;
- every recorded symbolic behavior is decoded from the embedded PE bytes;
- related arbitrary registers and memory produce related output registers,
  equal ordered memory-write traces, equal normalized control outcomes, and
  equal external API identities and arguments;
- output relations compose with region input relations in the current
  conservative profile.

Physical code addresses are normalized through `code_targets`. Imported calls
are compared by DLL and symbol or ordinal, not IAT RVA. External results are
adversarial and cannot be specialized from observations of the original. The
original binary is consumed statically only.

## Evidence And Replay

The report contains the bundled PEs, normalized contract, relational proof IR,
trusted-base declaration, diagnostics, LRAT or normalization evidence, copied
Lean semantics, generated bundle, `semantic-gaps.json`, and verdict. A fast
Capstone preflight reports unsupported instruction forms and malformed
cutpoints before generating a large Lean bundle; it can only block a proof and
is never proof authority. `stage-a-check-proof` verifies
all hashes, regenerates decoded behavior from the bundled PEs without the
iteration cache, regenerates the bundle byte-for-byte, and checks replay.

Set `WINCR_STAGE_A_RELATIONAL_CACHE` to select the untrusted decoded-semantics
cache, or to `off` to disable it. Keys include the PE hash, span, and Lean
semantics hashes. Generated decode equalities reconnect every cached term to
the exact bytes, so a bad cache entry can only make checking fail.

Prepared Nix reports additionally contain:

```text
prepared-proof/
  prepared-proof.json
  module-graph.json
  artifacts/{original,candidate}.pe
  lean/StageA/*.lean

report/
  verdict.json
  relational-proof-ir.json
  lean-audit.json
  nix-provenance.json
  lean.stdout
  lean.stderr
```

Failed Nix builds persist complete `nix.stdout`, `nix.stderr`, and an
`incomplete` verdict in the requested output directory instead of returning
only truncated downstream dependency failures.

## Current Boundaries

This first v3 implementation is a checked relational-region certificate, not
yet the final broad PE equivalence theorem. It supports arbitrary register
relations, identity-address arbitrary memory, loads, ordered stores, direct
logical targets, returns, and imported calls exposed by the existing decoder.
It deliberately reports `incomplete` for:

- translated or object-mapped data layouts;
- indirect internal target sets not reduced to explicit logical targets;
- clusters containing internal control-flow joins;
- internal-call return-address normalization across moved code;
- unsupported x86, x87, SIMD, exception, TLS, callback, or self-modifying-code
  semantics;
- a whole-program claim until concrete region transitions are connected to the
  weak-bisimulation trace theorem.

These are implementation milestones, not waivers. Do not use v3 as a final
whole-program acceptance gate until its report theorem is upgraded from
`candidateRelationalCertificate` to concrete whole-image observational
equivalence and the diverse PE corpus, including the full jq pair, passes it.
