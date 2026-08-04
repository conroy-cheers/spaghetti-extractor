# Static Round-Trip Qualification

The round-trip corpus is a small, generated regression suite for the active
static reconstruction pipeline. Each case starts from a canonical semantic
program, lowers independent original and candidate PE32 artifacts, inventories
both binaries, and checks artifact binding and semantic localization.

Positive cases vary register assignment, stack spills, block splitting, branch
shape, instruction selection, function order, alignment, jumps, and
prologues/epilogues while retaining the same semantic program. Negative cases
inject one named semantic mutation and must report `violated` at that location.

The corpus is intentionally not a binary-equivalence theorem. It detects
regressions in generation, PE extraction, executable-byte classification,
artifact hashing, and violation localization.

Formats:

- `stage-a-roundtrip-corpus-v2`
- `stage-a-roundtrip-case-v2`
- `stage-a-roundtrip-case-result-v2`
- `stage-a-roundtrip-run-result-v2`

Commands:

```console
spaghetti-extractor roundtrip-generate --out build/roundtrip --count 36
spaghetti-extractor roundtrip-run \
  --corpus build/roundtrip/corpus.json --out build/roundtrip-result
nix build .#roundtrip-qualification --no-link
```

Every artifact path is contained beneath its case root and bound by size and
SHA-256. Missing artifacts, stale inventories, unsupported executable spans, or
mislocalized mutations fail closed.
