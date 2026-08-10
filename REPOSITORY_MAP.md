# Repository Map

This is the canonical map of Spaghetti Extractor. It describes the active
architecture only. Historical binary-equivalence and source-equivalence proof
experiments remain available in Git history and are not supported interfaces.

## Top Level

| Path | Purpose |
|---|---|
| `flake.nix`, `flake.lock` | Pinned package, checks, apps, development shell, generic Nix constructors, and validation targets. |
| `pyproject.toml` | Python package metadata, console scripts, runtime extras, Lean package data, and installed Nix evaluators. |
| `src/spaghetti_extractor/` | Reusable implementation. It must not import target bundles. |
| `nix/` | Generic content-addressed phase constructors and oracle harnesses. |
| `profiles/` | Reviewed machine ABI, import, and external-operation profiles. |
| `tools/` | Generic external tool adapters and helper assets. |
| `tests/` | Generic unit, boundary, integration, and constructor tests. |
| `targets/` | Authored validation bundles for GNU Hello, jq, and DX-Ball. |
| `docs/` | Canonical architecture and workflow documentation. |
| `private/` | Ignored operator inputs such as proprietary binaries. |
| `build/`, `outputs/`, `result*` | Ignored generated workspaces or Nix links; never source inputs. |

## Runtime Data Flow

```text
PE bytes
  -> analysis/binary_inventory.py
  -> analysis/isa_inventory.py + ISA qualification
  -> contract_tools.py / opaque_reconstruction.py
  -> stage_b_state_machine.py
  -> reconstruction_ir.py
  -> generated interpreter or C backend
  -> library/interface/component analysis
  -> component workspaces and portable source
  -> rebuilt candidate
  -> stage_b.py static assurance
  -> stage_b_functional.py candidate-only tests
```

Imports flow downward through this sequence. Target bundles invoke the generic
surface through Nix or CLI; generic modules never import `targets/`.

## Public Entrypoints

| Module | Purpose |
|---|---|
| `cli.py` | Canonical `spaghetti-extractor` command registry and exit policy. |
| `slice_loop.py` | Incremental, content-hash-cached candidate repair loop. |
| `contract_tools.py` | Stable facade over static contract generation and candidate feedback. |
| `stage_b.py` | Candidate-only provenance, static checks, failure extraction, and ranked delta explanation. |
| `__main__.py` | `python -m spaghetti_extractor`. |

The command surface is grouped into static inventory/contract commands,
ISA qualification, round trips, machine-IR generation, component lifting,
source rendering, candidate assurance, and candidate-only functional tests.

Core support modules are deliberately small:

| Module | Purpose |
|---|---|
| `__init__.py` | Package identity and version surface. |
| `errors.py` | Shared user-input and phase failure types. |
| `util.py` | Canonical JSON, hashing, and atomic artifact helpers. |
| `nix_support.py` | Nix discovery and content-addressed worker command construction. |
| `operation_provenance.py` | Provenance records shared by recovered operations and source rendering. |

## Static Analysis

`src/spaghetti_extractor/analysis/` owns original-side extraction schemas and
machine-model qualification:

| Module | Purpose |
|---|---|
| `schema.py` | Stable active model/profile identifiers and compact Lean module inventory. |
| `binary_inventory.py` | Strict PE32 executable-byte classification and cutpoint inventory. |
| `region_inventory.py` | Region extraction artifacts and bindings. |
| `cutpoints.py` | Semantic cutpoint subdivision. |
| `definedness.py` | Undefined-value and dependency-frontier analysis. |
| `instruction_support.py` | Fail-closed instruction/profile preflight. |
| `isa_inventory.py` | Required instruction-form inventory for one binary. |
| `isa_requirements.py` | Required Lean form/capability projection. |
| `isa_qualification.py` | Qualification-set validation and binding. |
| `x87_profile.py` | x87-specific static requirements and replay metadata. |

PE primitives live in `pe.py`, `stage_binary.py`, and `recursive_decode.py`.
`rooted_state_machine.py` performs rooted static control recovery.

## Reference Contracts

`_contract_tools/` is private implementation behind `contract_tools.py`:

| Module | Purpose |
|---|---|
| `common.py` | Shared types, active reference model, ranges, and issue records. |
| `map_generation.py` | Explicit block maps, padding verification, layout facts, and CFG proposals. |
| `abi.py` | Machine ABI/callsite evidence and repair clusters. |
| `symbolic_execution.py` | Bounded Z3-assisted local symbolic summaries. |
| `reference_contract.py` | Original-only contract families, semantic sidecars, reconstruction gaps, explain, diff, and smoke checks. |
| `candidate_feedback.py` | Candidate static comparison, focused checks, coverage ledger, and ranked shortfall audit. |

`opaque_reconstruction.py` converts a map-blind binary inventory into a
conservative self-map used to emit a baseline contract and state machine.
`artifact_formats.py` centralizes shared active format identifiers.

## Machine Representation And Generation

| Module | Purpose |
|---|---|
| `stage_b_state_machine.py` | Normalizes static transfer contracts into the generated baseline state machine. |
| `reconstruction_ir.py` | Prepares exact byte-bound units once, then exports byte-free canonical machine IR with freshly derived global control facts. |
| `behavioral_roots.py` | Independently parses and hash-binds PE entry, executable export, and immutable TLS callback roots. |
| `hybrid_authority_v2.py` | Immutable v2 authority records, exact bindings, finite alternatives, dependencies, and bundle closure. |
| `machine_ir_authority_v2.py` | Stable exact unit/event binding kernel shared by machine-IR extraction and downstream authority replay. |
| `analysis_schema_v2.py`, `artifact_identity_v2.py`, `artifact_projection_v2.py` | Shared v2 wire formats, canonical content identities, and independently cached artifact projections. |
| `authority_bindings_v2.py`, `authority_dependencies_v2.py`, `authority_record_core_v2.py` | Exact binary/unit/event bindings, canonical proof-dependency identities, and common immutable authority-record validation. |
| `address_expression_v2.py` | Normalized address-expression IR used by provenance and target certificates. |
| `checked_memory_access_v2.py` | Exact event-bound finite memory-address facts emitted by cold interprocedural replay. |
| `checked_memory_address_domain_v2.py` | Exhaustive bounded-context address-domain certificates for one exact memory event; these authorize conditional mutable-slot reads without turning ordinary provenance observations into coverage claims. |
| `authority_v2_cli.py` | Stable command-line adapters for emitting and validating v2 authority artifacts. |
| `control_analysis_v2.py` | Exact unit/control inventories and rooted closure, independent of legacy provenance. |
| `entry_fact_derivation_v2.py` | Immutable launch/IAT facts and fail-closed mutable-slot promotion inputs. |
| `entry_state_analysis_v2.py` | Exact PE/callback entry contracts and checked mutable-global invariants. |
| `mutable_slot_candidates_v2.py` | Stable rooted discovery of writable 32-bit image slots for point-sensitive replay. |
| `global_slot_analysis_v2.py` | Point-sensitive mutable-slot replay, taint, dominance, finite joins, and cold replay. |
| `global_slot_authority_v2.py` | Separately cached promotion of complete cold-replayed slots into typed v2 invariants. |
| `global_slot_contract_v2.py`, `global_slot_image_v2.py`, `global_slot_proposal_v2.py` | Typed mutable-slot invariants, exact image-span bindings, and non-authorizing replay proposals. |
| `interprocedural_analysis.py` | Unified SCC worklist for call summaries, value provenance, indirect targets, and dependency closure. |
| `interprocedural_phase_v2.py`, `joint_interprocedural_analysis_v2.py`, `joint_fixed_point_v2.py` | Phase adapters and the joint graph/stack/global-slot/interprocedural fixed point. |
| `stack_range_analysis_v2.py` | Checked stack-range facts and call-frame entry offsets. |
| `memory_range_invariants_v2.py` | Proposes and independently replays SCC induction facts, then exports exact event-bound static-memory ranges for alias analysis. |
| `entry_state_contract_v2.py` | Typed entry-state and launch-root authority records. |
| `indirect_target_dependency_v2.py`, `static_indirect_replay_v2.py` | Exact indirect-target dependencies and independent finite-target replay. |
| `target_cutpoint_materialization_v2.py`, `recovered_executable_data.py` | Untrusted exact-span proposals for finite control destinations plus checked executable code/data and padding separation. |
| `exception_invariants_v2.py`, `control_invariant_phase_v2.py` | Non-authorizing invariant synthesis plus independent replay of exceptional SCC and finite indirect-control certificates. |
| `exception_phase_v2.py` | Cached exceptional-control certificate phase adapter. |
| `checked_external_site_contract.py` | Canonical machine-level external call/jump contracts and exact profile matching. |
| `external_site_proposals_v2.py` | Exact-bound, untrusted external-site proposals consumed by v2 replay. |
| `external_profile_authority_v2.py` | Cold-replayed index over exact profile bytes for imports, interfaces, operations, resolvers, targets, and callbacks. |
| `isa_kernel_selection.py` | Binary-specific binding from reachable forms to qualified semantics and fallback capabilities. |
| `machine_ir_isa_catalog_v2.py`, `machine_ir_isa_requirements_v2.py`, `machine_ir_isa_selection_v2.py` | Exact machine-IR ISA inventory, required-form extraction, and binary-bound qualification selection. |
| `launch_profile_v2.py` | Conditional PE32 launch assumptions and exact static/callback root inventory. |
| `hybrid_authority_builder_v2.py` | Constructs the immutable authority bundle from independently replayed v2 records. |
| `hybrid_diagnostics_v2.py` | Collapses dependent consequences behind deterministic primary blocker IDs. |
| `static_hybrid_pipeline_v2.py` | Compatibility facade over the phase-oriented v2 analysis modules. |
| `static_hybrid_authority_v2.py` | Recomputing v2 completeness checker and dependency-aware blocker diagnostics. |
| `static_hybrid_final_audit_v2.py` | Small final replay tying the v2 bundle to exact machine IR and manifest artifacts. |
| `stage_b_candidate_authority_v2.py` | Sole candidate-generation receipt joining the passing v2 audit with fallback implementation coverage. |
| `internal_function_contracts.py` | Validates PE- and unit-bound, analysis-only call-frame/result contracts for opaque internal library functions. |
| `reconstruction_control.py` | Proposes clusters from decoded control structure. |
| `reconstruction_composition.py` | Composes compatible machine units into larger reconstruction clusters. |
| `reconstruction_contract_analysis.py` | Derives cluster inputs, outputs, effects, and frontiers. |
| `reconstruction_validation.py` | Synthesizes finite validation cases. |
| `reconstruction_assurance.py` | Aggregates reconstruction/component evidence without overstating scope. |
| `opaque_reconstruction.py` | Original-only bootstrap from static inventory. |
| `stage_b_skeleton.py` | Emits compilable scaffolds or contract-guided baseline C. |
| `stage_b_c_backend.py` | Deterministic semantic-state-machine to C lowering. |
| `stage_b_interpreter_backend.py` | Portable machine-IR interpreter generation. |
| `stage_b_interpreter_native_build.py` | Freestanding PE32 build from interpreter, engine, and runtime packages. |
| `stage_b_fallback_coverage.py` | Replays exact interpreter lowerings and portable selections and proves one implementation kind per rooted reachable unit; it has no static authority. |
| `stage_b_machine_ir_scope.py` | Fail-closed partition of executable and deferred machine-IR transfers for candidate generation. |
| `stage_b_engine_layout.py` | Structural engine layout tables. |
| `stage_b_native_engine.py` | IA-32 ABI bridge and typed x87 native operations. |
| `stage_b_native_image.py` | Derives entry, callback, relocation, import, and zero-fill inputs from a checked load-image contract. |
| `stage_b_native_runtime.py` | Candidate external runtime package. |
| `stage_b_native_binding.py` | Runtime-boundary inventory and adapters. |
| `stage_b_native_build.py` | Generic native compile/compose pipeline. |
| `stage_b_pe_composer.py` | PE image composition, anchors, and relocation checks. |
| `stage_b_typed_x87.py` | Typed, byte-free x87 replay records. |
| `stage_b_provenance.py` | Candidate source/build/output hash binding. |
| `stage_b_hybrid_completeness.py` | Legacy v1 diagnostic/proposal inventory; it cannot authorize candidate generation. |
| `recovered_executable_data.py` | Checked classification of immutable initialized data embedded in executable sections. |

`component_backend.py` contains the low-level component workspace engine.
`component_workspace.py` is the public component-oriented facade.

## Components And Portable Source

| Module | Purpose |
|---|---|
| `component_discovery.py` | Proposes coarsened component candidates. |
| `component_selection.py` | Materializes reviewed selections. |
| `semantic_components.py` | Validates hierarchical component declarations and machine boundaries. |
| `component_interface.py` | Declares and checks component interfaces/refinements. |
| `component_profile.py` | Component checker profiles and finite domains. |
| `bounded_component_contract.py` | Bounded pairwise component contracts. |
| `finite_component_contract.py` | Z3/CBMC-oriented finite component checks. |
| `finite_value_domain.py` | Explicit bounded scalar/pointer domains. |
| `region_replacement.py` | Region replacement manifests and activation rules. |
| `source_graph.py` | Source ownership and dependency graph. |
| `source_project.py` | Binds portable source projects to components and validation evidence. |
| `source_operation_catalog.py` | Non-authoritative rendering of recovered operations as C. |
| `source_call_substitution.py` | Call-frontier recognition and source-level substitution planning. |

Component checks are local and scope-bounded. Promotion requires exact hashes
and interfaces; it does not erase unresolved whole-program reconstruction gaps.

## ABI, Imports, And External Operations

| Module | Purpose |
|---|---|
| `machine_abi.py` | Machine-level calling convention data structures. |
| `import_abi.py` | Expands reviewed ABI policy against exact PE imports. |
| `machine_import_profiles.py` | Imported-call profile parsing and binding. |
| `call_arguments.py` | Argument-source recovery. |
| `internal_call_summaries.py` | Interprocedural call effect proposals. |
| `call_frame_hypotheses.py` | Typed, non-authorizing preserved-register hypotheses used by cold interprocedural replay. |
| `call_site_effects.py` | Canonical typed summaries of stack, register, result, and memory effects at call sites. |
| `callback_contracts.py` | Callback registration, ABI, lifetime, and activation protocol validation. |
| `checked_external_site_contract.py` | Canonical fail-closed machine contract shared by native external-call planning and runtime. |
| `value_provenance.py` | Static/dynamic/code/data/import/resource value origins. |
| `provenance_domain.py` | Bounded provenance joins and domains. |
| `interface_provenance.py` | Receiver, vtable, callback, out-parameter, and call-target propagation. |
| `external_operation_profiles.py` | Machine external-operation and environment contracts. |
| `external_interface_profiles.py` | Interface/vtable catalogs and call identities. |
| `external_capabilities.py` | Resolver-issued callable capability contracts. |
| `external_sites.py` | Static machine-level external call-site bindings. |
| `callable_external_runtime.py` | Candidate runtime projection for callable capabilities. |
| `external_function_ast.py` | Function declarations recovered from SDK/compiler AST JSON. |
| `external_interface_ast.py` | Interface declarations recovered from AST JSON. |
| `stage_b_api_catalog.py` | Known API signature/substitution catalog support. |

## Linked Libraries

| Module | Purpose |
|---|---|
| `linked_libraries.py` | Artifact indexing, constellation matching, hypotheses, and dynamic requirements. |
| `linked_library_contracts.py` | Reviewed linked-island and interface contracts. |

Recognition uses function/data/import constellations rather than requiring every
historical library implementation. Exact artifacts can provide strong evidence;
partial constellations remain hypotheses and do not authorize replacement.

## ISA Model And Oracles

| Module | Purpose |
|---|---|
| `isa_catalog.py` | Canonical instruction-form catalog and imported XED metadata. |
| `isa_catalog_enrichment.py` | Concrete replay and catalog enrichment. |
| `isa_semantic_forms.py` | Normalized semantic form identifiers. |
| `isa_side_adapter.py` | Connects binary requirements to qualification evidence. |
| `isa_conformance.py` | Strict corpus/report schemas and observation comparison. |
| `isa_conformance_lean.py` | Concrete evaluator over compact Lean semantics. |
| `isa_conformance_unicorn.py` | Unicorn veto oracle. |
| `isa_conformance_bochs.py` | Batched Bochs veto oracle adapter. |
| `isa_conformance_80386.py` | Hardware-derived 80386 corpus support. |
| `isa_corpus_generator.py` | Deterministic strict vector generation. |
| `isa_kernel_qualification.py` | Cross-oracle qualification aggregation. |
| `isa_campaign.py` | Coverage campaigns and missing-form prioritization. |
| `isa_cli.py` | Lower-level ISA campaign command helpers. |
| `isa_conformance_nix.py` | Nix realization, remote-builder use, and provenance copying. |
| `isa_conformance_shards.py`, `isa_conformance_worker.py`, `isa_qualification_worker.py` | Deterministic oracle sharding and isolated cached conformance/qualification workers. |
| `lean_runner.py` | Small deterministic Lean compile/run helper. |

`src/spaghetti_extractor/lean/StageA/` contains only the compact reusable ISA
kernel: `X87`, `Formal`, `ISAInventory`, `ISAQualification`, `ISAConformance`,
and `ISAConformanceRunner`. It contains no target bytes or target graph.

## Round-Trip Regression

`roundtrip_fuzz/` contains:

| Module | Purpose |
|---|---|
| `model.py` | Strict v2 corpus/case/artifact schemas. |
| `semantic.py` | Small canonical semantic program language. |
| `lowering.py` | GNU and LLVM/MSVC-style PE32 lowering. |
| `generator.py` | Positive transformations and localized negative mutations. |
| `runner.py` | Static inventory, binding, semantic-difference, and localization checks. |
| `image_contract.py` | Exact PE load-image contracts used by native composition. |

The corpus is an untrusted regression system, not a candidate equivalence claim.

## Candidate Behavior

| Module | Purpose |
|---|---|
| `stage_b_functional.py` | Curated expected-output cases and sharded candidate execution. |
| `stage_b_contract.py` | Stable re-export of candidate contract helpers. |
| `target_intent.py` | Strict authored-intent validation and generated provenance separation. |
| `ghidra.py` | Optional headless decompiler proposal exporter. |

Wine execution is candidate-only and must run headlessly. Nix constructors
enforce this with `xvfb-run` where Wine is used.

## Nix Constructors

| File | Output role |
|---|---|
| `stage-a-external-interface-profile.nix` | Pinned SDK headers through a checked machine-level interface profile. |
| `stage-a-isa-conformance.nix` | One cached Lean/Unicorn/Bochs corpus evaluation. |
| `stage-a-isa-qualification-graph.nix` | Sharded ISA evidence and qualification DAG. |
| `stage-a-isa-semantic-kernel.nix` | Stable compiled Lean semantic kernel packaged independently of target evidence. |
| `stage-a-machine-ir-isa-qualification-v2.nix` | Binary-specific machine-IR requirement, oracle, selection, and authority DAG. |
| `stage-a-roundtrip-corpus.nix` | Generated static corpus and qualification result. |
| `bochs-conformance.nix` | Pinned batched Bochs adapter. |
| `singlestep-80386-conformance.nix` | Hardware-vector corpus packaging. |
| `stage-b-component-analysis.nix` | Original inventory through component proposals. |
| `stage-b-component-discovery.nix` | Independent proposal phase. |
| `stage-b-component-selection.nix` | Authored selection materialization. |
| `stage-b-component-interfaces.nix` | Interface extraction/refinement phase. |
| `stage-b-semantic-components.nix` | Component catalog phase. |
| `stage-b-semantic-component-workspaces.nix` | Per-component workspace/check/qualification DAG. |
| `stage-b-interpreter-package.nix` | Machine-IR interpreter package. |
| `stage-b-native-object-graph.nix` | Deterministic native object graph plus a CA compile/assembly realization; avoids evaluation-time reads of CA outputs. |
| `stage-b-hybrid-candidate.nix` | Composes interpreter, native engine/runtime, cached objects, and a PE candidate. |
| `stage-b-static-hybrid-completeness.nix` | Emits the legacy cacheable v1 diagnostic/proposal report; no candidate authority. |
| `stage-b-static-hybrid-authority-v2.nix` | Content-addressed v2 evidence DAG from exact unit preparation through separately cached mutable-slot replay/promotion, SCC analysis, root/external/ISA/exception closure, and the final audit. |
| `ca-python-json-phase.nix` | Generic CA phase constructor with explicit store dependencies, schema/status checking, and phase manifests. |
| `stage-b-headless-diagnostic-run.nix` | Runs only a statically closed candidate in an isolated headless Wine session. |
| `python-module-closure.nix` | Content-addressed transitive local-Python import closure for phase-specific invalidation. |
| `python-module-index.json` | Generated checked local-import graph consumed by phase-specific Python closures. |
| `stage-b-linked-libraries.nix` | Library constellation and replacement-plan DAG. |
| `stage-b-source-call-substitutions.nix` | Call-frontier through source-binding DAG. |
| `stage-b-source-component-assurance.nix` | Source component evidence aggregation. |
| `stage-b-functional-suite.nix` | Candidate-only expected-output suite. |
| `stage-b-upstream-shell-suite.nix` | Candidate-only upstream shell tests under headless Wine. |
| `stage-b-target-intent.nix` | Validated authored target intent. |
| `callable-external-runtime-contract.py` | Deterministic runtime-contract builder invoked inside Nix. |
| `stage-a-builders`, `stage-a-lightweight-ca-builders` | Optional remote builder inventories for full and lightweight jobs. |
| `stage-a-builder-public-keys` | Trusted cache keys paired with the builder inventories. |

All reusable constructors are exposed through `flake.lib`. CA derivations are
first-class; dependency granularity, not CA mode alone, determines invalidation.

## Profiles And Catalogs

`profiles/README.md` defines profile authority and ownership. The active
reviewed profiles are:

- `i686-mingw-freestanding-c0-v1.json`
- `pe32-kernel32-callable-resolvers-v1.json`
- `pe32-kernel32-console-lockstep-v1.json`
- `pe32-kernel32-lockstep-v1.json`
- `pe32-kernel32-runtime-v1.json`
- `pe32-mingw-directx-interface-extraction-v1.json`
- `pe32-mingw-win32-function-extraction-v1.json`
- `pe32-msvcrt-lockstep-v1.json`
- `pe32-msvcrt-machine-runtime-v1.json`
- `pe32-native-callthrough-runtime-v1.json`
- `pe32-static-cutpoints-and-paired-callables-v1.json`
- `pe32-win32-system-dll-abi-policy-v1.json`
- `pe32-win32-windowing-runtime-v1.json`
- `pe32-winmm-runtime-v1.json`
- `pe32-win32-gui-launch-assumptions-v1.json`

The launch-assumption template is deliberately non-authorizing. The Nix
analysis phase binds it to the exact PE, checked static roots, and checked
callback contracts before it can contribute entry-state evidence.

`isa-catalogs/README.md` documents imported instruction catalogs;
`pe32-i686-core-smoke-v1.json` is the small reviewed smoke catalog. Larger
machine-generated catalogs belong in Nix outputs.

## Documentation

`docs/README.md` is the documentation index. The active design references are
`architecture.md`, `semantic-components.md`, `external-operations.md`,
`isa-qualification.md`, `static-roundtrip-qualification.md`, and
`target-bundles.md`. Historical plans and experiment reports remain in Git
history rather than competing with the current design.

## Validation Targets

| Target | Current role |
|---|---|
| `targets/gnu-hello/` | Small portable-C and authored-component validation bundle. |
| `targets/jq/` | Larger CLI/library/component intent benchmark and functional expectations. |
| `targets/dxball/` | Proprietary 3D-era application acquisition plus generic machine-IR and component-analysis benchmark. |

Target `default.nix` files acquire/build inputs and invoke generic constructors.
Intent JSON and source are authored. Downloaded binaries and generated analyses
must not be committed.

## Tests

Tests are phase-oriented by filename:

- `test_stage_a_isa_*`: ISA catalog, corpus, oracle, qualification, and Nix paths.
- `test_reconstruction_*`, `test_recursive_decode.py`,
  `test_rooted_state_machine.py`: static reconstruction and machine IR.
- `test_component_*`, `test_semantic_components.py`,
  `test_*component_contract.py`: component discovery/interface/source checks.
- `test_external_*`, `test_callable_external_runtime.py`,
  `test_call_arguments.py`, `test_value_provenance.py`: ABI and external calls.
- `test_linked_libraries.py`, `test_source_call_substitution.py`: library and
  source substitution.
- `test_stage_b_*`: C/interpreter/native/PE/functional/Nix integration.
- `test_target_intent.py`, `test_repository_boundaries.py`: generic/target and
  generated/authored separation.
- `pe_fixtures.py`: generic synthetic PE32 constructors only.

The canonical full gate is `nix flake check`. Focused Python runs are useful
during implementation, but Nix is the supported build and cache boundary.

## Adding A Target

1. Add `targets/<id>/target.json` and authored intent/source/tests.
2. Add a small `default.nix` that acquires/builds the target and calls generic
   constructors.
3. Add only top-level package/check exposure that is useful as a benchmark.
4. Do not add target Python or Lean modules.
5. If a reusable capability is missing, implement it under `src/`, validate it
   with a generic fixture, and then consume it from the target.

This rule keeps DX-Ball, jq, GNU Hello, and future programs as clients of one
toolkit rather than alternate architectures embedded in the repository.
