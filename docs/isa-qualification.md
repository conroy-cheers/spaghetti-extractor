# ISA Qualification

The active Lean footprint is a compact IA-32 semantic kernel:

- `StageA/X87.lean`
- `StageA/Formal.lean`
- `StageA/ISAInventory.lean`
- `StageA/ISAQualification.lean`
- `StageA/ISAConformance.lean`
- `StageA/ISAConformanceRunner.lean`

Stage A statically inventories instruction forms required by a PE. Unsupported
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
spaghetti-extractor stage-a-inventory-isa \
  --binary app.exe --inventory inventory.json --out isa.json
spaghetti-extractor stage-a-check-isa-conformance \
  --corpus corpus.json --backend lean --out lean-report.json
nix build .#isa-kernel --no-link
```

ISA qualification establishes confidence in the machine model used by static
analysis and generation. It is not a whole-program candidate claim.
