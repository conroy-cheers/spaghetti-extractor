# Windows Clean-Room Catalog, Spec, And Coverage Plan

## Summary

Build a generic clean-room toolkit for Windows programs and libraries by
cataloging original PE runtime binaries, measuring coverage against the original
code, and producing a private dirty corpus that can be reviewed into
clean specs/tests for a later native implementation. Halo CE is the first large
target preset, not a special case in the core toolkit.

Do not round-trip Ghidra pseudocode into rebuilt binaries as a correctness gate.
Ghidra is for discovery; the oracle remains the original binary, measured by
module hash + RVA.

## Target Manifest

- Each catalog uses one TOML target manifest as policy input.
- The manifest declares project identity, install-root/provenance environment
  variables, binary role rules, trace targets, Windows VM staging names,
  oracle suites, private harness suites, mutation kinds, and data-state kind
  requirements.
- The packaged Halo CE manifest preserves the current Halo classifications and
  command defaults while allowing simpler targets to use the same toolkit.

## Scope And Artifact Boundaries

- Target first deliverable: private dirty corpus, catalog, mocks,
  oracle tests, and objective coverage reports. No native port is required in
  this phase.
- This stage intentionally produces a highly detailed private specification and
  test corpus. A later cleanup/sanitization stage rewrites or aggregates that
  corpus into a safer public distribution.
- In scope: closed-source runtime code declared by each target manifest. For
  the Halo CE preset this includes playable client and dedicated server
  behavior, especially `haloce.exe`, `haloceded.exe`, and any closed runtime
  DLL/service component proven necessary.
- Out of scope by default: source-available dependencies such as
  Chimera/Vorbis/Ogg, original assets/maps/CD keys, and
  installer/updater/uninstaller tools unless runtime tracing proves they are
  needed during gameplay/server operation.
- Detailed private corpus may contain binary hashes, raw addresses/RVAs, block
  identities, edge identities, trace mappings, harness glue, labels,
  disassembly listings, dirty routine-contract drafts, sanitized internal
  routine contracts, type/interface specs, tests, mocks, fixtures derived from
  behavior, and coverage ledgers.
- The private corpus is organized into discrete review packets. Each module,
  routine, behavior contract, observation, oracle row, interface case,
  data/state case, mutation case, and harness row should have a small dirty
  packet with raw evidence references, taint metadata, review status, and a
  clean derivation template.
- Public/sanitized repo should prefer stable 1:1 labels over raw RVAs. Labels
  should be human-readable where possible, with private tooling retaining the
  binary hash + RVA mapping needed to validate against the original oracle.
- Sanitized internal routine contracts are allowed and expected for large
  targets whose external API underconstrains behavior. They describe routines as
  behavioral APIs: inputs, outputs, preconditions, postconditions, side effects,
  state transitions, fixtures, confidence, and coverage evidence.
- LLM-derived routine names and short purpose descriptions may be used as draft
  metadata when derived from disassembly, strings/imports, callsite context, and
  dynamic observations. Publish them only as sanitized functional annotations
  with provenance, confidence, taint level, and review status.
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
- Every routine may also get a label-first internal API contract. Public
  contract identity is the stable label; private oracle identity is
  `{module_hash, rva}`. The contract may include a public name, purpose summary,
  evidence source, confidence, taint level, review status, input/output shape,
  and behavior-derived fixtures.
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
- Use DynamoRIO via Windows `bin32\drrun.exe` inside a declarative Windows VM
  for required basic-block and edge tracing of the original Halo CE runtime.
  Wine/DynamoRIO remains useful for smoke diagnostics, but is not the primary
  required coverage path. Stock `drcov` block coverage is acceptable only as a
  bootstrap smoke test.
- Add or build a DynamoRIO client that emits
  `{test_id, pid, module_sha256, module_name, rva_block, rva_edge_from, rva_edge_to}`.
- Use Frida, WinDbg, `winedbg`, and GDB for targeted probes and harness
  bring-up, not as the primary bulk coverage source.
- Treat `nix-haloce` as a flake input that supplies the reference install tree
  and resource files needed for oracle and end-to-end tests. The original
  binaries/assets remain private inputs, not repo contents.

- If running something that needs a graphical display, but there is no physical
  display present, run an offscreen Wayland or X11 compositor and point it to that.

## Implementation Phases

- Phase 1: create the reproducible binary manifest from the pinned `nix-haloce`
  flake input/install output and classify all PE files.
- Phase 2: import binaries into Ghidra, export function/block/edge/data-ref
  metadata, and cross-check executable ranges with independent disassembly.
- Phase 3: build the coverage collector and prove it can map Windows guest
  execution back to original PE module hashes and RVAs, including dynamic
  basic-block, CFG edge, and call-edge traces for 32-bit Halo CE processes
  under Windows `bin32\drrun.exe`.
- Phase 4: add black-box process tests for startup, dedicated server commands,
  map discovery/loading, profiles/saves, loopback networking, config/logging,
  and representative client launch paths.
- Phase 5: add sanitized internal routine contracts and private internal-call
  harnesses for routines unreachable or underconstrained through process tests,
  while still executing original PE code as the oracle.
- Phase 6: implement interface mocks/shims for Win32
  file/registry/thread/time/console, D3D/DDraw/GDI/windowing/gamma, DirectInput,
  DirectSound/WINMM, Winsock/GameSpy/Keystone, Bink, CRT/TLS/heap/runtime
  behavior.
- Phase 7: export the private dirty corpus as the primary review product,
  including discrete module/routine/test-surface packets and raw evidence
  sidecars where safe to copy. Internal routine contracts are exported as
  reviewable dirty packets with clean derivation templates, not only as
  routine metadata. Validate the corpus with `validate-dirty-corpus` before it
  is treated as ready for human/LLM cleanup; this check proves packet structure,
  content hashes, evidence sidecars, module/routine dossiers, and taint metadata
  are intact, while still allowing private RVAs, module hashes, disassembly, and
  harness details.
- Phase 8: derive clean specs and tests from reviewed dirty packets, removing
  raw RVAs, disassembly, private trace mappings, and harness-sensitive details
  from any distribution intended to be broadly public.
  The review promotion stage validates selected clean templates before marking
  them reviewed/public. The derivation stage only emits records marked
  reviewed/public and rejects publishable templates that still contain private
  paths, redacted private-path placeholders, raw oracle identity fields,
  disassembly references, or private harness-sensitive keys.

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
- `private-artifact-complete`: the latest private dirty corpus has module
  packets, disassembly packets, routine packets, dirty contract drafts, and
  per-row review packets plus clean derivation templates for every recorded
  behavior, internal routine contract, test, and harness surface.
- `publication-clean`: public specs only emit reviewed publication-safe
  internal routine contracts; draft and private-only material remains in the
  private dirty corpus.
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
- A reviewer can regenerate the private dirty corpus and use its discrete
  module/routine/test-surface packets as input to a human or LLM cleanup pass.
- Clean-room implementers can work from reviewed clean specs/tests without
  reading private decompiler artifacts; public distribution requires a
  sanitization pass that replaces raw oracle addresses with stable labels.
- Clean-room implementers can validate JSON-observable behavior directly from
  public `specs.json` observations, without private fixture paths or original
  oracle command lines.
- The reference target proves the reviewed dirty-corpus derivation path by
  deriving clean specs from promoted templates and running the same JSON/process
  candidate comparisons from that derived clean spec.
- For complex targets, clean-room implementers can also work from reviewed
  internal routine contracts without copying the original internal architecture
  unless internal ABI compatibility is explicitly required.
