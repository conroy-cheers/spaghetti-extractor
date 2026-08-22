# ISA Qualification

The active Lean footprint is a compact IA-32 semantic kernel:

- `SpaghettiExtractor/ISA/X87.lean`
- `SpaghettiExtractor/ISA/Bytes.lean`
- `SpaghettiExtractor/ISA/PE32.lean`
- `SpaghettiExtractor/ISA/Machine.lean`
- `SpaghettiExtractor/ISA/Decode.lean`
- `SpaghettiExtractor/ISA/Semantics.lean`
- `SpaghettiExtractor/ISA/ISAInventory.lean`
- `SpaghettiExtractor/ISA/ISAQualification.lean`
- `SpaghettiExtractor/ISA/ISAConformance.lean`
- `SpaghettiExtractor/ISA/ISAConformanceRunner.lean`

static analysis statically inventories instruction forms required by a PE. Unsupported
forms fail closed. The same strict corpus can be evaluated by Lean, Unicorn,
Bochs, and hardware-derived expected vectors.

Bochs and Unicorn are veto-only oracles. They accelerate decoder coverage,
defined-flag validation, protected-mode fault testing, addressing/prefix cases,
and x87 checks, but never close a candidate contract. Comparisons must control
CPU model, segments, memory, flags, and fault semantics, and must ignore
architecturally undefined outputs.

The Nix qualification graph shards corpora by semantic form and records tool
versions, corpus hashes, backend configuration, and observations. Any mismatch
leaves that form unqualified. Content-addressed derivations allow expensive
unchanged shards to be substituted from remote builders.

```console
spaghetti-extractor expert isa-inventory \
  --binary app.exe --inventory inventory.json --out isa.json
spaghetti-extractor expert isa-check-conformance \
  --corpus corpus.json --backend lean --out lean-report.json
nix build .#isa-kernel --no-link
```

ISA qualification establishes confidence in the machine model used by static
analysis and generation. It is not a whole-program candidate claim.

Component evidence compares compiled C against canonical machine IR or declared
candidate-only scenarios, depending on its evidence profile. This does not make
the Python evaluator or component refinement runner an ISA authority. Executable candidate
activation separately requires every exact occurrence in the checked
root-reachable behavioral projection to pass the v3 ISA qualification gate,
including its Lean backend and veto-oracle results. Unreachable structural
occurrences remain classified and fallback-capable without authorizing behavior.
