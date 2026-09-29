# Documentation

- [DX-Ball Windows C delivery](dxball-windows-lift-delivery.md): standalone source
  handoff, final application inventory, normal execution and explicit fidelity
  limits; Windows runtimes are supported delivery dependencies.
- [DX-Ball source-program integration](dxball-standalone-integration.md): remaining
  native dependencies, unresolved C service bindings, palette/bootstrap/runtime/numeric/raster completion,
  program-owned startup/scene/gameplay/resource assembly and the concrete path from subsystem exports
  to a standalone program.
- [DX-Ball MDS stream lifecycle](dxball-mds-stream-continuation.md): playback,
  callback requeue and release; shared lifetime experiments, provider-field
  preservation, portable consumers and complete MDS integration.
- [DX-Ball MDS file/memory loader](dxball-mds-loader-continuation.md): three-level
  component composition, output publication, shared mapping/allocation lifetimes,
  portable consumers and actual music-controller integration.
- [DX-Ball MDS container parser](dxball-mds-parser-continuation.md): typed shared
  headers, checked event-component reuse, allocation and cleanup history, all
  bundled assets, portable consumers and actual loader/MIDI integration.
- [DX-Ball MDS event expansion](dxball-mds-events-continuation.md): independent
  byte-buffer conversion, partial failure writes, all bundled music blocks,
  portable consumers and composition through the real parser.
- [DX-Ball music controller](dxball-music-continuation.md): shared track ownership,
  callback-sensitive cleanup, independent portable consumers and the mapped-memory/
  MIDI backend boundary subsequently implemented in the shared environment.
- [DX-Ball file reader](dxball-file-reader-continuation.md): shared Win32 file
  scenarios, preserved failure/short-read behavior, independent lifting and
  portable source consumers.
- [DX-Ball WAV loading](dxball-wave-continuation.md): parser outputs, allocation
  and dangling slots, shared DirectSound use, portable consumer reuse and the
  file-service gap subsequently addressed by the reader continuation.
- [Shared Wine test environment](shared-wine-test-environment.md): reusable
  DirectSound/COM, files, mapped storage and queued MIDI execution, shared scenarios and observations,
  migrated consumers, independent reuse and explicit capability limits.
- [DX-Ball sound device setup](dxball-audio-setup-continuation.md): shared bank
  initialization and focus/reload, independent retry/failure/lifetime cases,
  local defect detection, portable consumer reuse and normal integration.
- [DX-Ball sound bank control](dxball-audio-continuation.md): shared playback,
  lost-buffer recovery and resource lifetime, independent historical-status and
  callback cases, portable consumer reuse and normal integration.
- [DX-Ball complete display setup](dxball-display-continuation.md): windowed and
  fullscreen initialization, explicit historical inputs, independent failure and
  callback cases, local defect detection and remaining platform-backend obligations.
- [DX-Ball application shell](dxball-application-continuation.md): portable
  startup/window dispatch, independent message and lifecycle cases, standalone
  consumers and a frame controller that survives replacement of its caller.
- [DX-Ball event memory](dxball-event-memory-continuation.md): queued events through
  live shared bytes, wrapped coordinates, callbacks and expiry, with independent
  native comparisons, local defect diagnosis and portable consumer reuse.
- [DX-Ball warning continuation](dxball-warning-continuation.md): portable warning
  operations and historical-input transport through actual lifted callers,
  source reuse, scoped normal integration and remaining event-consumer work.
- [DX-Ball warning boundary investigation](dxball-warning-boundary-investigation.md):
  native stack producers, cross-board reads and the required compatibility boundary.
- [DX-Ball gameplay scene](dxball-game-scene-continuation.md): entry, redraw and
  input through shared state, with recursive progression consumers and normal execution.
- [DX-Ball round cleanup and departure](dxball-round-cleanup-continuation.md):
  shared list disposal, callback-sensitive transitions and independent consumers.
- [DX-Ball gameplay progression](dxball-progression-continuation.md): score/life
  display, level transitions and connected cleanup/restart consumers.
- [DX-Ball powerup actions](dxball-powerups-continuation.md): temporary and live
  lists, callback-sensitive board changes and actual pickup/frame consumers.
- [DX-Ball explosion lifecycle](dxball-explosions-continuation.md): shared effect
  roots, animation/disposal and connected ball-contact/level-advance consumers.
- [DX-Ball shot lifecycle](dxball-shots-continuation.md): shared shot records,
  pair allocation, movement/removal and connected frame firing/drawing consumers.
- [DX-Ball paddle movement and drawing](dxball-paddle-continuation.md): shared
  paddle state, callback-sensitive rendering and connected pickup-driven resizing.
- [DX-Ball particle lifecycle](dxball-particles-continuation.md): linked allocation,
  movement/expiry and pixel drawing through a shared surface and connected frame.
- [DX-Ball pickup lifecycle](dxball-pickups-continuation.md): creation, collection,
  drawing and disposal through shared gameplay objects and connected frame consumers.
- [DX-Ball brick rules and effects](dxball-brick-actions-continuation.md): connected
  frame/motion/effect lifecycles, with pickup and palette discrepancies reproduced locally.
- [DX-Ball ball motion](dxball-ball-motion-continuation.md): shared allocation,
  collisions and movement, with local connected frame checks before game execution.
- [DX-Ball gameplay frame](dxball-gameplay-continuation.md): shared lists and frame
  sequencing, with an integration drawing discrepancy reduced to a local consumer.
- [DX-Ball region table](dxball-regions-continuation.md): borrowed table operations,
  direct local diagnosis and connected editor reuse on x86-64 and AArch64.
- [DX-Ball damage and presentation](dxball-damage-continuation.md): shared queues,
  mutable callbacks, local discrepancy diagnosis and a reduced live observer regression.
- [DX-Ball board rendering](dxball-board-rendering-continuation.md): full-grid
  and cell drawing through shared board/graphics boundaries and local comparisons.
- [DX-Ball board editor](dxball-board-editor-continuation.md): seven integrated
  entries, portable source consumers and the real clear/save workload.
- [DX-Ball board data](dxball-board-data-continuation.md): independent board
  collection storage, tile mapping, byte-backed state and normal-game integration.
- [DX-Ball score screen](dxball-score-scene-continuation.md): connected name input,
  shared score records, table rendering and source consumers on two architectures.
- [DX-Ball persistent scores](dxball-scores-continuation.md): independent table
  records, exact file bytes, partial I/O, ordered insertion and portable reuse.
- [DX-Ball main menu](dxball-menu-continuation.md): connected menu/dot animation,
  explicit clocks and pixel leases, normal-game integration and source reuse.
- [DX-Ball title scene](dxball-title-scene-continuation.md): connected lifecycle
  operations, real-game integration and source consumers on two architectures.
- [DX-Ball title animation](dxball-title-animation-continuation.md): connected
  scrolling, wave blits and palette cycling with integer numeric equivalence.
- [DX-Ball PCX continuation](dxball-pcx-continuation.md): buffered image/palette
  decoding, live pixel views, local editing and normal-game integration.
- [DX-Ball game-flow continuation](dxball-game-flow-continuation.md): frame/scene
  control, connected recovery, local edits and counted-input normal execution.
- [DX-Ball capture and restoration](dxball-capture-continuation.md): connected
  allocation/graphics/loader behavior, portable source reuse and live integration.
- [DX-Ball drawing continuation](dxball-drawing-continuation.md): sprite drawing,
  live font rendering and an incrementally extended portable source consumer.
- [DX-Ball sprite continuation](dxball-sprite-continuation.md): connected binary-only
  asset loading, font drawing and cleanup, portable execution, and the live-game
  host-diagnostic observation limitation.
- [Source-blind lifting trial](source-blind-lifting-trial.md): binary-only DX-Ball
  component preparation, native caller integration, local reuse, deliberate
  interaction-defect detection and portable source execution, with setup costs.
- [jq path services and source delivery](jq-path-services-continuation.md): shared
  Windows namespace contracts, real module consumers, neighboring reuse, explicit
  library reuse and clean standalone source packaging.
- [jq slice and test-runner continuation](jq-final-support-continuation.md):
  checked range refinement, normal `--run-tests` execution, neighbor reuse and
  remaining path/library delivery work.
- [jq runtime contexts and seed lifecycle](jq-runtime-contexts-continuation.md):
  shared thread state, ordered destruction and entropy interactions through the
  existing workflow, including real threaded consumers and neighboring reuse.
- [jq runtime boundary refinement](jq-runtime-boundary-continuation.md): extend two
  existing components through one apply transaction, reuse neighboring work, and
  identify remaining delivery dependencies from the link map.
- [jq program-support continuation](jq-program-support-continuation.md): UTF-8,
  source-location ownership and bytecode support, with native consumers and both
  standalone architectures retaining neighboring component work.
- [jq CLI and output-runtime continuation](jq-cli-continuation.md): real process
  replacement, shared text/binary output policy and normal execution on both
  standalone architectures, preserving neighboring component work.
- [jq shared value-runtime continuation](jq-value-runtime-continuation.md): string
  storage, hashing, object mutation and related operations; 47 native scenarios
  and normal execution on both standalone architectures, retaining prior units.
- [jq numeric value continuation](jq-number-continuation.md): decimal storage,
  cached conversions, aliases and release through the existing workflow; 53 native
  scenarios and 215 CLI plus 32 live-value cases match on both architectures.
- [jq builtin continuation](jq-builtin-continuation.md): persistent callback
  tables, native/runtime compatibility and normal-entry integration of a new
  substantial module using the existing staged assembly workflow.

- [Component assembly updates](component-assembly-updates.md): one staged action
  for sources, entry/provider changes, reversible backend retirement and program
  checks; the actual jq lifecycle refinement preserves neighboring work.

- [jq compiler IR and lifecycle continuation](jq-ir-continuation.md): shared
  instruction/state layouts, native calling conventions, portable integration
  and the subsequently resolved incremental assembly boundary-refinement gap.
- [Component workflow](component-workflow.md): start here to prepare a workspace,
  edit C, diagnose/replay differences, check consumers and export source; includes
  a runnable DX-Ball rehearsal and the inputs needed to define a new boundary.
- [Practical C modules and portable assembly](component-module-workflow.md):
  immutable tables, separate formal eligibility, grouped C entry adapters and
  local updates demonstrated through normal jq and Hello execution.
- [Compiler-backed practical C](compiler-backed-practical-c.md): ordinary C
  admission, per-configuration compiler views, generated jq frontend comparison,
  local refactoring/replay and transfer to DX-Ball.
- [jq compiler continuation](jq-compiler-lifting-continuation.md): bytecode compiler
  replacement, native and two-architecture program comparisons, and the allocator
  module/thread-state admission limit subsequently addressed below.
- [Stateful component workflow](stateful-component-workflow.md): declared module
  and thread state, shared provider selection, lifecycle assumptions, local reuse
  and the jq allocator consumer experiment.
- [jq module-loader continuation](jq-module-loader-continuation.md): recursive
  imports, metadata and source integration through existing facilities; confirmed
  Windows filesystem/text-input differences subsequently addressed below.
- [jq file-runtime continuation](jq-file-runtime-continuation.md): shared C file
  services, independently lifted file/input-state consumers, runtime alias and
  callback repairs, local reuse and two-architecture integration.
- [jq value continuation](jq-value-continuation.md): ordering/deletion and recursive
  value relations, reusable CRT sorting, shared-view behavior, local refactoring
  and native/portable program comparisons.
- [jq lifting continuation](jq-lifting-continuation.md): serializer and interpreter
  replacements through the public workflow, combined program comparisons on two
  architectures and the original generated-frontend source-profile stopping point.
- [Component boundary design](component-boundary-design.md): proposed semantic
  rules for contracts, cuts, memory, composition and reuse, with worked examples
  and explicit implementation gates.
- [Boundary design review](component-boundary-design-review.md): broad-target
  gaps, corrected open/memory/lifetime rules, capability matrix and adversarial
  examples, plus the final composition/interpretation/evolution pass; proposed
  requirements, not qualification evidence.
- [Independent portable lifting plan](independent-portable-lifting-plan.md):
  formal composition roadmap, with the subsequent practical workflow sequencing.
- [Practical subsystem and whole-target plan](whole-target-independent-lifting.md):
  delivered P1–P4 and H1–H3 operator milestones, practical standalone-source/runtime/
  portability delivery, and the separate G1–G7 strong-qualification objective.
- [Practical product delivery audit](practical-product-audit.md): current executable
  evidence, explicit delivery scopes and repository reconciliation.
- [Practical lifting workbench review](practical-lifting-workbench-review.md):
  manual boundaries, ordinary C, comparison, replay, reusable adapters and optional
  focused proofs.
- [Standalone Hello workflow](../tests/fixtures/hello-standalone/README.md): source
  assembly, runtime bindings, raw program/memory and allocation-failure comparisons, retained defect
  replay and x86-64/AArch64 execution within an explicit Windows-1252 scope.
- [Portable jq subsystem](../tests/fixtures/jq-portable/README.md): explicit source
  backend, normal CLI and live-object comparisons, local source updates with
  neighboring build reuse, and x86-64/AArch64 execution; a partial jq lift.
- [Component workspace trial](../tests/fixtures/jq-string-length/README.md): local
  boundary/dependency guidance, a previously unprepared jq operation using shared
  C services, and edit/replay/reuse through actual program execution.
- [Independent lifting experiment](baselines/2026-09-07-independent-lifting-experiment.md):
  real operation, exact inputs, boundaries, blockers and measured costs.

- [Independent component milestone audit](baselines/2026-09-14-independent-component-milestone.md):
  completed Metapad conditional network demonstration, exact evidence, costs and limits.

- [Repository milestone and goal history](current-goal.md): objective, keystone
  semantic boundary, current practical checkpoint and work queue, and later
  whole-program completion gates.
- [Interactive portable lifting roadmap](interactive-portable-lifting-roadmap.md):
  staged proof scaling, migration closure, assisted authoring, platform coverage,
  standalone export, and unfamiliar-application acceptance.
- [Architecture and assurance](architecture.md): canonical pipeline, trust
  boundaries, statuses, and completion criteria.
- [Components](components.md): exact ownership, operator-defined groups,
  portable V2 interfaces, static machine-derived refinement, machine binding, service graphs,
  activation receipts, and fallback-safe configuration.
- [Physical ABI analysis and matching](abi-analysis.md): machine call
  boundaries, pinned declarations, compatibility, and localized frontiers.
- [Checked call protocols](call-protocols.md): portable type identity, target
  layouts, physical frames, lifecycle, machine evidence, and idiomatic C views.
- [Canonical boundary schema](canonical-boundaries.md): the shared type,
  layout, evidence, lifecycle, projection, call, callback, and component model.
- [External operations](external-operations.md): imports, COM/vtable calls,
  callbacks, resources, and candidate runtime adapters.
- [ISA qualification](isa-qualification.md): compact Lean semantics and veto
  oracles.
- [Checked atomics](atomics.md): Machine IR memory actions, the PE32 WB-TSO
  profile, concurrency signatures, and the lifted-C atomic API.
- [Checked callbacks](callbacks.md): structured provider protocols, callback
  authority V4, opaque portable handles, and generational delivery semantics.
- [Native ingress and deployable PE32 modules](native-ingress.md): exact loader
  surfaces, object/data-export authority, generic ingress, outcomes/SEH, link
  receipts, and candidate-observed multi-image completion.
- [Checked boundary transducers](boundary-transducers.md): reusable interaction
  contracts, Relation IR V3, object origins, executable plans, and plan-aware
  activation.
- [Static round-trip qualification](static-roundtrip-qualification.md): small
  generated PE regressions and localized negative cases.
- [Target bundles](target-bundles.md): strict separation between reusable
  tooling, authored target intent, generated output, and private inputs.
- [Performance and invalidation](performance-and-invalidation.md): Nix-first
  workflow, v3 artifact DAG, cache boundaries, resource limits, and measured
  acceptance gates.

[REPOSITORY_MAP.md](../REPOSITORY_MAP.md) is the canonical file-by-file map.
