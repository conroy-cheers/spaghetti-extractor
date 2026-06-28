# Catalog Model

The canonical private catalog is SQLite. JSON and Markdown files are generated
reports, not source-of-truth data.

Specs and test reports use stable labels as their primary identity. Private
catalog rows retain module SHA256 plus RVA mappings so oracle execution can be
validated against the original binaries without forcing raw addresses into the
spec surface.

For large targets, functions can be promoted into internal routine contracts.
The public contract identity is still the stable function/data/state label; the
private catalog keeps the module-SHA256/RVA mapping needed by original-code
harnesses. A routine contract may carry a sanitized `public_name`,
`purpose_summary`, `evidence_source`, `confidence`, `taint_level`, and
`review_status` in addition to inferred signature and side-effect metadata.

`generate_reports` writes `tests.json` and `tests.md` alongside the manifest,
coverage, gate, and spec reports. The test report summarizes coverage test
runs, interface cases, data/state cases, oracle cases, internal harnesses,
mutation cases, and trace compatibility probes by label, test ID, status,
evidence, and aggregate event counts. It does not expand raw instruction-level
trace rows.

Each binary records filename, relative path, SHA256, size, PE machine,
timestamp, image base, entrypoint RVA, image size, subsystem, role, scope, and
role evidence. Role/scope policy comes from the target manifest plus generic
platform/runtime exclusions.

Each catalog database is for one target project. The `metadata` table records
`target_project_id`, `target_project_name`, `target_config_json`, and generated
JSON lists for target-specific oracle, mutation, and data-state gate
requirements. Legacy Halo databases without these keys continue to use the
Halo CE defaults.
The target manifest also owns Windows VM tracing defaults such as trace root,
runtime staging directory, staging aliases, generated guest script name,
default guest user/password, password environment variable, skip-reports
environment variable, and default trace target. Core VM tooling should read
those fields instead of branching on a particular product.

Runtime scope values:

- `included`: target runtime code that must eventually be specified and covered.
- `candidate`: shipped PE code that remains visible until tracing proves it is included or safely excluded.
- `excluded`: platform/runtime/tool/vendor/source-available code outside the clean-room implementation target.

Executable code is tracked at four levels:

- `executable_ranges`: every PE executable section range with an auditable classification.
- `executable_byte_classes`: a non-overlapping byte partition for each executable range, derived from executable sections, Ghidra/static blocks, dynamic coverage blocks, and waivers.
- `functions`: entrypoints, exports, and Ghidra-discovered routines with labels plus tags for subsystem, purity, side effects, confidence, and clean-room status.
- Internal routine contract metadata: label-first behavioral API annotations
  for routines whose behavior must be specified below the process boundary.
  Draft names/descriptions may come from static analysis or LLM assistance, but
  public reports should include only reviewed behavioral summaries.
- `basic_blocks`: static or Ghidra block identities with labels, private RVA
  ranges, and dynamic coverage mappings. The private dirty corpus expands each
  block into a discrete packet with manifest, static/dynamic context,
  block-local disassembly sliced from module objdump, instruction metadata,
  p-code status/content, data-flow/xref sidecars, decompiler availability
  status, semantic summary, and a clean rewrite template. Decompiled text is
  not fabricated; it is emitted only when a real decompiler exporter supplies
  it, otherwise explicit unavailable/error artifacts are recorded.
- `function_semantics` and `block_semantics`: private high-taint Ghidra
  semantic exports, including decompiler C, p-code, variables, inferred types,
  stack/global references, strings, callsites, and per-instruction metadata.
- `cfg_edges` and `call_edges`: static control-flow and call relationships with labels, private endpoint RVAs, and dynamic coverage mappings.
- `value_traces`: optional bounded dynamic semantic profiles grouped by
  `{test_id, module_sha256, routine_label, block_label}`.
- `static_cross_checks`: LLVM and rizin/radare2 agreement checks for cataloged PE section metadata.
- `trace_probe_results`: labeled Wine/DynamoRIO compatibility attempts with
  command, status, raw event counts, mapped counts, direct launch diagnostics,
  failures, tool versions, and provenance. These rows are diagnostic evidence
  and do not count as dynamic
  coverage.

Allowed executable-byte classifications:

- `code`
- `thunk`
- `jump/data table`
- `padding/alignment`
- `dead/unreachable`
- `source-available external`
- `excluded tool/runtime`
- `vendor/replaceable`
- `unknown`

Initial PE extraction marks included and candidate executable ranges as
`unknown` until Ghidra, independent disassembly, tracing, or waivers refine the
classification. The byte-class ledger is rebuilt automatically after catalog
builds, Ghidra imports, coverage ingests, and waiver edits. It can also be
rebuilt manually:

```sh
python -m haloce_catalog rebuild-byte-classes --db build/catalog/catalog.db
```

Reports keep unknown byte-class rows visible and fail `catalog-complete` until
they are resolved or explicitly waived.

Independent static cross-checks are recorded with:

```sh
python -m haloce_catalog cross-check-static --db build/catalog/catalog.db
```

For each included/candidate binary, `catalog-complete` requires a passing
`llvm-readobj` check and a passing rizin/radare2-family check.
