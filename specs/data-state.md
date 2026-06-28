# Data And State Spec

Data/state completion is tracked for known map, profile, save, packet, config,
codec, and state-machine behavior. Add each target as a `data_structures` row,
then record behavior-derived test evidence without storing original assets,
CD keys, decompiler text, or proprietary implementation expression.

```sh
python -m haloce_catalog upsert-data-structure \
  --db build/catalog/catalog.db \
  --name cache_file_header \
  --structure-kind map \
  --spec-status complete \
  --fixture-status complete \
  --description "cache-file header parse and validation behavior"

python -m haloce_catalog record-data-state-test \
  --db build/catalog/catalog.db \
  --data-structure-label data_map_cache_file_header_... \
  --case-kind malformed_input \
  --test-id cache-file-header-malformed \
  --status pass \
  --fixture-path private/fixtures/maps/cache-file-header-malformed.json \
  --evidence "original binary rejects truncated header with observed error path"
```

Required case kinds are derived from `structure_kind`:

- All structures require `fixture` and `malformed_input`.
- Map/profile/save/packet/config codecs require `round_trip`.
- State machines require `transition`.

`data-state-complete` passes only when every known structure has complete spec
and fixture status plus all required passing test-case rows.
