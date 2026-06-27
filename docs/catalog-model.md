# Catalog Model

The canonical private catalog is SQLite. JSON and Markdown files are generated
reports, not source-of-truth data.

Specs and test reports use stable labels as their primary identity. Private
catalog rows retain module SHA256 plus RVA mappings so oracle execution can be
validated against the original binaries without forcing raw addresses into the
spec surface.

Each binary records filename, relative path, SHA256, size, PE machine,
timestamp, image base, entrypoint RVA, image size, subsystem, role, scope, and
role evidence.

Runtime scope values:

- `included`: target runtime code for the playable client or dedicated server.
- `candidate`: shipped PE code that remains visible until tracing proves it is included or safely excluded.
- `excluded`: platform/runtime/tool/vendor/source-available code outside the clean-room implementation target.

Executable code is tracked at four levels:

- `executable_ranges`: every PE executable section range with an auditable classification.
- `functions`: entrypoints, exports, and Ghidra-discovered routines with labels plus tags for subsystem, purity, side effects, confidence, and clean-room status.
- `basic_blocks`: static or Ghidra block identities with labels, private RVA ranges, and dynamic coverage mappings.
- `cfg_edges` and `call_edges`: static control-flow and call relationships with labels, private endpoint RVAs, and dynamic coverage mappings.

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
classification. Reports keep unknown ranges visible and fail `catalog-complete`
until they are resolved.
