# Halo CE Clean-Room Catalog, Spec, And Coverage Plan

## Summary

Build a clean-room port foundation by exhaustively cataloging the original Halo
CE runtime binaries, measuring coverage against the original PE code under Wine,
and producing detailed specs/tests that a later native implementation can
satisfy.

Do not round-trip Ghidra pseudocode into rebuilt binaries as a correctness gate.
Ghidra is for discovery; the oracle remains the original binary, measured by
module hash + RVA.

## Scope And Artifact Boundaries

- Target first deliverable: catalog, specs, mocks, oracle tests, and objective
  coverage reports. No native port is required in this phase.
- This stage intentionally produces a highly detailed private specification and
  test corpus. A later cleanup/sanitization stage can strip or aggregate that
  corpus into a safer public distribution.
- In scope: closed-source runtime code required for playable client and
  dedicated server behavior, especially `haloce.exe`, `haloceded.exe`, and any
  closed runtime DLL/service component proven necessary.
- Out of scope by default: source-available dependencies such as
  Chimera/Vorbis/Ogg, original assets/maps/CD keys, and
  installer/updater/uninstaller tools unless runtime tracing proves they are
  needed during gameplay/server operation.
- Detailed private corpus may contain binary hashes, raw addresses/RVAs, block
  identities, edge identities, trace mappings, harness glue, labels,
  type/interface specs, tests, mocks, fixtures derived from behavior, and
  coverage ledgers.
- Public/sanitized repo should prefer stable 1:1 labels over raw RVAs. Labels
  should be human-readable where possible, with private tooling retaining the
  binary hash + RVA mapping needed to validate against the original oracle.
- Keep private unless explicitly sanitized: decompiled bodies, copied
  pseudocode, proprietary instruction/control-flow expression inside blocks,
  original binaries, original assets, CD keys, and harness details that would
  leak expression rather than behavior.

## Catalog Model

- Canonical private catalog format: SQLite database plus generated JSON/Markdown
  reports.
- Canonical spec identity: stable labels for modules, functions, blocks, edges,
  data structures, globals, platform endpoints, and tests. Private catalog rows
  retain `{module_hash, rva}` or equivalent oracle addresses; specs/tests refer
  to labels first.
- Track binaries by filename, SHA256, PE metadata, image base, sections,
  imports, exports, resources, and in-scope/excluded role.
- Track executable code at four levels: executable byte ranges, functions, basic
  blocks, and CFG/call edges.
- Every executable byte must be classified as code, thunk, jump/data table,
  padding/alignment, dead/unreachable, source-available external, excluded
  tool/runtime, or unknown.
- Every routine gets tags for subsystem, purity/state, side effects,
  globals/data refs, platform/interface calls, inferred signature, calling
  convention, confidence, test status, and clean-room readiness.
- Use a richer taxonomy than “internal vs I/O”: pure engine logic, stateful
  engine logic, asset/map/profile codecs, platform runtime, rendering/windowing,
  input, audio/video, networking/services, auth/license, vendor/replaceable,
  mixed, and unknown.

## Tooling

- Use Ghidra headless analysis for primary function/CFG/data discovery. If
  `analyzeHeadless` is not directly on PATH, invoke Ghidra’s packaged
  `support/analyzeHeadless` or add a dev-shell wrapper.
- Use LLVM/binutils plus radare2/rizin as independent static-analysis
  cross-checks.
- Use Python with `lief`, `pefile`, `capstone`, `unicorn`, SQLite, and JSON
  tooling for catalog extraction, validation, and report generation.
- Use DynamoRIO via `drrun` for required basic-block and edge tracing under
  Wine. Stock `drcov` block coverage is acceptable only as a bootstrap smoke
  test.
- Add or build a DynamoRIO client that emits
  `{test_id, pid, module_sha256, module_name, rva_block, rva_edge_from, rva_edge_to}`.
- Use Frida and `winedbg`/GDB for targeted probes and harness bring-up, not as
  the primary bulk coverage source.
- Treat `nix-haloce` as a flake input that supplies the reference install tree
  and resource files needed for oracle and end-to-end tests. The original
  binaries/assets remain private inputs, not repo contents.

## Implementation Phases

- Phase 1: create the reproducible binary manifest from the pinned `nix-haloce`
  flake input/install output and classify all PE files.
- Phase 2: import binaries into Ghidra, export function/block/edge/data-ref
  metadata, and cross-check executable ranges with independent disassembly.
- Phase 3: build the coverage collector and prove it can map Wine execution back
  to original PE module hashes and RVAs, including dynamic basic-block, CFG
  edge, and call-edge traces for 32-bit Halo CE processes under Wine.
- Phase 4: add black-box process tests for startup, dedicated server commands,
  map discovery/loading, profiles/saves, loopback networking, config/logging,
  and representative client launch paths.
- Phase 5: add private internal-call harnesses for routines unreachable or
  underconstrained through process tests, while still executing original PE
  code.
- Phase 6: implement interface mocks/shims for Win32
  file/registry/thread/time/console, D3D/DDraw/GDI/windowing/gamma, DirectInput,
  DirectSound/WINMM, Winsock/GameSpy/Keystone, Bink, CRT/TLS/heap/runtime
  behavior.
- Phase 7: generate detailed specs and tests from observed behavior, then
  require later clean-room implementations to pass the same suite.
- Phase 8: optional cleanup/sanitization pass that removes raw RVAs, private
  trace mappings, and harness-sensitive details from any distribution intended
  to be broadly public.

## Objective Coverage Gates

- `catalog-complete`: no unknown executable bytes, no unclassified functions,
  no unlabeled functions/blocks/edges, and no unresolved dynamic module names.
- `coverage-complete`: 100% of included functions, basic blocks, CFG edges, and
  call edges are dynamically covered or explicitly waived.
- `interface-complete`: every static or dynamically observed platform endpoint
  has mocks plus success, failure, and error-path tests.
- `data-state-complete`: every known map/profile/save/packet/config structure
  and state machine has fixture, malformed-input, transition, and round-trip
  tests where applicable.
- `oracle-complete`: original binaries pass the black-box process suite and
  private harness suite.
- `mutation-effective`: representative wrong implementations, inverted branches,
  skipped external calls, corrupted serializers, bad packet codecs, and changed
  mock API behavior cause tests to fail.
- `reproducible`: reports include binary hashes, catalog version, tracer
  version, test IDs, tool versions, Nix/dev-shell provenance, and the exact
  `nix-haloce` input revision used for private reference/resource material.

## Waiver Policy

- A waiver is an auditable disposition, not missing coverage.
- Allowed waiver categories: proven padding/data, unreachable dead code,
  excluded source-available dependency, excluded installer/update tool,
  platform-impossible path, duplicate compiler/runtime thunk, or legally unsafe
  distributable artifact.
- Each waiver must record binary hash, RVA range, reason, evidence, reviewer,
  and revalidation trigger.
- Waived blocks remain visible in reports and are never counted as dynamically
  covered.

## Acceptance Criteria

- A fresh checkout plus configured private `nix-haloce` input can regenerate the
  manifest, static catalog, coverage reports, and test reports from pinned
  tools.
- The original Halo CE binaries pass the oracle suite in the declarative Wine
  prefix.
- Coverage reports prove that every in-scope routine/control-flow item is
  covered or waived.
- Clean-room implementers can work from the detailed specs/tests without reading
  private decompiler artifacts; later public distribution may require a
  sanitization pass that replaces raw oracle addresses with stable labels.
