# Halo CE Clean-Room Catalog

This repository builds a clean-room foundation for a future native Halo CE
runtime implementation. The first deliverable is not a port. It is a
reproducible catalog, coverage ledger, detailed interface specs, mocks, and
oracle-test scaffold measured against the original runtime binaries by module
hash and RVA.

The tooling never stores original binaries, assets, CD keys, decompiler output,
or copied pseudocode in the repo. Ghidra is used only to export metadata such as
function starts, block labels, control-flow edge labels, call refs, and data
refs. Private catalog data may retain raw module-hash/RVA mappings; specs should
use stable labels as their primary identity.

## Quick Start

Enter the dev shell:

```sh
nix develop
```

Build a catalog from the reference install tree produced by the configured
private `nix-haloce` flake input. The CLI accepts the resolved output path via
`--install-root` or `HALOCE_INSTALL_ROOT`:

```sh
python -m haloce_catalog build \
  --install-root "$HALOCE_INSTALL_ROOT" \
  --db build/catalog/catalog.db \
  --report-dir build/reports
```

Generated artifacts:

- `build/catalog/catalog.db`: canonical SQLite catalog.
- `build/reports/manifest.json`: private manifest with hashes, PE metadata, role decisions, imports/exports, sections, labels, and counts.
- `build/reports/catalog.md`: human-readable catalog summary.
- `build/reports/coverage.json`: coverage ledger summary.
- `build/reports/coverage.md`: coverage gate report.
- `build/reports/gates.json`: objective gate status.

The default build records complete PE metadata and executable section ranges.
Capstone linear block discovery is intentionally opt-in because large shipped
DLLs can make bytewise discovery slow and noisy:

```sh
python -m haloce_catalog build --static-depth included
```

Ghidra metadata import is the preferred path for authoritative functions,
blocks, edges, and data refs.

## Coverage

The required dynamic source is a DynamoRIO tracer under Wine that records
basic-block, CFG-edge, and call-edge execution for 32-bit Halo CE processes.
Stock `drcov` block coverage is useful only as a bootstrap smoke test. The
ingester maps observed modules back to cataloged binaries by SHA256 when paths
resolve, then stores private RVA mappings and report-facing labels in SQLite:

```sh
python -m haloce_catalog ingest-drcov \
  --db build/catalog/catalog.db \
  --log path/to/drcov.log \
  --test-id client-startup-smoke
```

Check the local `drrun`/`drcov` runtime:

```sh
python -m haloce_catalog doctor-drcov
```

`doctor-drcov` is only a bootstrap check. The real coverage gate requires a
32-bit Wine process proof plus dynamic block, CFG-edge, and call-edge traces
mapped to module SHA256/RVA and stable labels.

## Ghidra Metadata

Run headless analysis outside any sanitized distribution artifacts, then export
only private metadata:

```sh
analyzeHeadless "$HALOCE_GHIDRA_PROJECT_DIR" halo-catalog \
  -import haloce.exe \
  -postScript tools/ghidra/HaloCatalogExport.java build/ghidra/haloce.json <sha256>

python -m haloce_catalog import-ghidra \
  --db build/catalog/catalog.db \
  --json build/ghidra/haloce.json
```

The JSON must not contain decompiler text, instruction bytes, or original code.
Raw RVAs in this private metadata must be converted to stable labels before any
sanitized public distribution.

## Repository Map

- `src/haloce_catalog/`: catalog, coverage, report, mock, and CLI code.
- `tools/ghidra/`: headless Ghidra metadata exporter.
- `docs/`: clean-room rules, catalog model, coverage gates, and waiver policy.
- `specs/`: detailed oracle-suite and interface specifications.
- `tests/`: unit tests and local-runtime smoke checks.
