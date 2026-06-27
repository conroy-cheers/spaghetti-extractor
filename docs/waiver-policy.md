# Waiver Policy

A waiver is an auditable disposition, not missing coverage.

Allowed categories:

- `proven-padding-data`
- `unreachable-dead-code`
- `excluded-source-available-dependency`
- `excluded-installer-update-tool`
- `platform-impossible-path`
- `duplicate-compiler-runtime-thunk`
- `legally-unsafe-distributable-artifact`

Each waiver must record:

- Binary SHA256.
- Private RVA start and end.
- Category.
- Reason.
- Evidence.
- Reviewer.
- Revalidation trigger.
- A stable label when the waiver applies to a function, block, edge, data item,
  endpoint, or test-visible behavior.

Use the CLI to insert waivers:

```sh
python -m haloce_catalog add-waiver \
  --db build/catalog/catalog.db \
  --binary-sha256 <sha256> \
  --rva-start 0x1234 \
  --rva-end 0x1240 \
  --category proven-padding-data \
  --reason "alignment after function tail" \
  --evidence "Ghidra block boundary plus independent disassembly agree" \
  --reviewer "<name>" \
  --revalidation-trigger "binary hash or analysis tool version changes"
```
