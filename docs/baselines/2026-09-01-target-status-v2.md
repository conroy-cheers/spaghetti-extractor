# Linked-semantic-module V2 target baseline (2026-09-01)

This snapshot was taken after running the supported repository refresh
transaction and checking repository metadata, the format registry, Python
module closures, and the target SDK.  It is a comparison baseline only.  The
artifacts below remain the authority for their own claims.

The first materialization after the generated Python module index changed was
deliberately run one target at a time.  Shell CPU timing excludes work done by
Nix builders, so elapsed time is the useful cold-path measurement here.  Peak
RSS was not available from the provisioned shell and remains telemetry rather
than an acceptance condition.

| Target | Module status | Definitions | Obligations | Frontiers | Holes | Linked-module identity | Transfer-plan identity | Cold status elapsed |
|---|---:|---:|---:|---:|---:|---|---|---:|
| GNU Hello | complete | 8,107 | 117 | 63 | 0 | `bd0469708ae9d41a9d71b4a05f0ee1cf4c565ada5cd13e3a9d99ba05a55d11c0` | `fa09ddd8be431cc611f01ef51e7ee2594c8f0f5caacabbeae33381266b0c5857` | 146.562 s |
| jq.exe | incomplete | 4,750 | 89 | 2 | 520 | `4602df77ae87802e07b78bdf251560a57e123d134ea41b2ce81edc3edd53d2ed` | `aa56900be298c1a818c9af4f95df4515c439fd7131ca7c9b781bd35c9dcfde5c` | 52.161 s |
| DXBall.exe | incomplete | 9,251 | 269 | 79 | 78 | `ed6ec242b08f5d74489b452101b32cab134895c40dbcdae28140c266b76b78f0` | `cb30a33e782e0b311f28fecc4b5e7fe80a37a6f101384dbd0c856b5d712d3e75` | 63.291 s |

Hello's `string-pointer-enabled` default is not currently realization-ready.
Its semantic module has no holes, but the configuration has the single blocker
`provider_qualification_incomplete` for
`gnu-hello.finite-selector-dispatch.portable-c`.  The faithful configuration is
independent of that unfinished overlay and remains the required fallback.

## jq.exe holes

| Code | Count |
|---|---:|
| `checked_import_code_contract_unresolved` | 265 |
| `may_reachable_symbol_has_no_provider` | 121 |
| `resolved_external_environment_incomplete` | 64 |
| `linked_import_code_protocol_missing` | 63 |
| `reachable_external_symbol_unresolved` | 6 |
| `unresolved_external_memory_write_footprint` | 1 |

The current single-image target describes `libjq-1.dll` as an external host
provider.  That is the dominant structural error: jq.exe and the pinned
libjq-1.dll built in the same derivation are one target-owned project and must
be linked and observed as two Behavioral-C modules.  The existing jq component
drafts remain separately incomplete operator work and must not be used to
paper over the missing project edge.

## DXBall.exe holes

| Code | Count |
|---|---:|
| `may_reachable_relocation_unresolved` | 19 |
| `execution_edge_outside_exact_universe` | 18 |
| `reachable_relocation_unresolved` | 18 |
| `unresolved_external_memory_write_footprint` | 6 |
| `may_reachable_symbol_has_no_provider` | 4 |
| `checked_import_code_contract_unresolved` | 3 |
| `reachable_semantic_hole` | 3 |
| `reachable_symbol_root_provenance_missing` | 2 |
| `resolved_external_environment_incomplete` | 2 |
| `linked_import_code_protocol_missing` | 2 |
| `reachable_effect_root_provenance_missing` | 1 |

The 55 relocation/edge rows are correlated symptoms around executable-section
absolute jump tables and must be fixed in the existing recovery/materialization
fixed point.  The two environment rows are the distinct contracts for
`kernel32.dll!UnhandledExceptionFilter` and `kernel32.dll!RtlUnwind`;
`RtlUnwind` must use the checked nonlocal/SEH path, not an ordinary returning
call contract.  The six write-footprint rows require exact object selectors or
bounded runtime obligations and cannot be discharged by an opaque native-call
profile.

## Reproducibility commands

```sh
nix run .#dev -- refresh
nix run .#dev -- refresh --check
nix build --no-link \
  .#checks.x86_64-linux.repository-metadata \
  .#checks.x86_64-linux.format-registry \
  .#checks.x86_64-linux.python-module-closure \
  .#checks.x86_64-linux.target-sdk
nix build --no-link --print-out-paths \
  './targets#legacyPackages.x86_64-linux.targets.gnu-hello.diagnostics.candidate-status'
nix build --no-link --print-out-paths \
  './targets#legacyPackages.x86_64-linux.targets.jq.diagnostics.candidate-status'
nix build --no-link --print-out-paths \
  './targets#legacyPackages.x86_64-linux.targets.dxball.diagnostics.candidate-status'
```
