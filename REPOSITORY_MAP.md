# Repository Map

This is the canonical map of Spaghetti Extractor. It describes the active
architecture only. Historical binary-equivalence and source-equivalence proof
experiments remain available in Git history and are not supported interfaces.

## Top Level

| Path | Purpose |
|---|---|
| `flake.nix`, `flake.lock` | Target-agnostic package, checks, apps, development shell, stable target SDK, and low-level generic constructors. |
| `pyproject.toml` | Python package metadata, console scripts, runtime extras, Lean package data, and installed Nix evaluators. |
| `src/spaghetti_extractor/` | Reusable implementation. It must not import target bundles. |
| `nix/` | Generic content-addressed phase constructors and oracle harnesses. |
| `profiles/` | Reviewed machine ABI, import, and external-operation profiles. |
| `tools/` | Generic external tool adapters and helper assets. |
| `tests/` | Generic unit, boundary, integration, and constructor tests. |
| `targets/flake.nix`, `targets/flake.lock` | Independent in-tree validation-consumer flake. |
| `targets/registry.nix`, `targets/<id>/` | Explicit target registry and authored GNU Hello, jq, and DX-Ball bundles. |
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
  -> typed v3 authority graph
  -> complete interpreter/native fallback
  -> library/interface/component proposals
  -> component workspaces and portable source
  -> rebuilt candidate
  -> stage_b.py static assurance
  -> stage_b_functional.py candidate-only tests
```

Imports flow downward through this sequence. Target bundles invoke the generic
SDK through Nix; the root flake and generic modules never import `targets/`.

## Public Entrypoints

| Module | Purpose |
|---|---|
| `cli.py` | Canonical `spaghetti-extractor` command registry and exit policy. |
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
| `python_module_index.py` | Canonical local-import index plus production-root closure enforcement used by Nix and developer diagnostics. |

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
| `x87_profile.py` | x87-specific static requirements and replay metadata. |

PE primitives live in `pe.py`, `stage_binary.py`, and `recursive_decode.py`.
`rooted_state_machine.py` performs rooted static control recovery.
`stage_a_external_inputs_v3.py` is the untrusted ingestion boundary that
re-parses machine-import profiles and exact PE roots into native-v3 artifacts;
it is intentionally outside the authority kernel.

`src/spaghetti_extractor/analysis_v3/` is the authoritative typed pipeline on
the content-addressed graph:

| Module | Purpose |
|---|---|
| `_schema.py` | Strict schema, canonical identity, and dependency helpers shared by v3 records. |
| `authority_common.py`, `identities.py` | Shared authority status, issue, binding, and exact indirect-exit identities. |
| `exact_units.py` | Exact unit envelopes and projection from the canonical machine-IR universe. |
| `semantic_index.py` | Compact checked decode/control/memory index consumed after exact-unit validation. |
| `transition_records.py`, `transition_summaries.py` | Native typed transition records and one independently addressable summary per exact unit. |
| `memory_records.py`, `memory_versions.py` | Native typed memory-version, alias, merge, access, kill, and issue records. |
| `structural_targets.py` | Non-authorizing finite indirect-target proposals with explicit blockers. |
| `inductive_records.py`, `inductive.py` | Native typed invariant proposals, dependency discharge, and checked SCC induction authority. |
| `external_sites.py`, `callbacks.py` | Canonical checked external sites and callback entry/registration authority. |
| `root_closure.py`, `exceptional_transitions.py` | Launch-root closure and checked fault/exception dispositions. |
| `isa_qualification.py`, `fallback_coverage.py` | Exact reachable-form qualification and one fallback implementation disposition per structural unit. |
| `final_authority.py` | Fail-closed reduction over all authority families; copied status fields cannot authorize it. |
| `diagnostics.py` | Non-authorizing family and primary-frontier summaries over checked artifact sets and sharded bundles. |
| `source_plan.py`, `planning.py`, `graph.py` | Bounded source preparation, framework-owned structural/dependency planning, and canonical graph metadata. |
| `registry.py` | Unique, complete phase registry used to generate the v3 authority graph. |

The transition proposal layer projects exact machine-IR units directly into
checked native v3 records. No production v3 authority phase may import a v2
implementation or authorize work through a compatibility adapter.

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
| `machine_ir_authority_v2.py` | Stable exact unit/event binding kernel shared by machine-IR extraction and downstream authority replay. |
| `artifact_identity_v2.py` | Stable canonical content identities still shared by active artifact producers. |
| `artifact_set_v3.py` | Canonical manifest plus bounded compressed NDJSON packs, recursive value interning, streaming indexed reads, and structural/dependency scheduling manifests. |
| `phase_framework_v3.py` | Typed map-unit, map-SCC, and checked-reduce phase definitions with automatic dependency recording and completeness enforcement. |
| `authority_bindings_v2.py` | Exact binary/unit/event bindings and canonical JSON used at stable active wire boundaries. |
| `address_expressions.py` | Normalized address-expression IR used by provenance and target certificates. |
| `control_disposition_profile.py` | Projects full import profiles onto the stable fixed-arity no-return facts required by structural control extraction. |
| `indirect_target_dependency_v2.py`, `static_indirect_replay_v2.py` | Exact indirect-target dependencies and independent finite-target replay. |
| `target_cutpoint_materialization_v2.py`, `recovered_executable_data.py` | Untrusted exact-span proposals for finite control destinations plus checked executable code/data and padding separation. |
| `checked_external_site_contract.py` | Canonical machine-level external call/jump contracts and exact profile matching. |
| `external_site_proposals_v2.py` | Exact-bound, untrusted external-site proposals consumed by candidate diagnostics. |
| `external_profile_authority_v2.py` | Exact profile-byte index for imports, interfaces, operations, resolvers, targets, and callbacks. |
| `isa_kernel_selection.py` | Binary-specific binding from reachable forms to qualified semantics and fallback capabilities. |
| `machine_ir_isa_catalog_v2.py`, `machine_ir_isa_requirements_v2.py`, `machine_ir_isa_selection_v2.py` | Exact machine-IR ISA inventory, required-form extraction, and binary-bound qualification selection. |
| `launch_assumption_inputs_v2.py` | Content-stable, non-authorizing PE-bound assumption projection for root-independent SCC analysis. |
| `stage_b_candidate_authority_v3.py` | Sole candidate-generation receipt; independently joins checked v3 final authority with exact machine IR and complete fallback implementation coverage. |
| `reconstruction_control.py` | Proposes clusters from decoded control structure. |
| `reconstruction_composition.py` | Composes compatible machine units into larger reconstruction clusters. |
| `reconstruction_contract_analysis.py` | Derives cluster inputs, outputs, effects, and frontiers. |
| `reconstruction_validation.py` | Synthesizes finite validation cases. |
| `opaque_reconstruction.py` | Original-only bootstrap from static inventory. |
| `stage_b_c_backend.py` | Shared low-level C runtime helpers used by the active interpreter fallback. |
| `stage_b_interpreter_backend.py` | Portable machine-IR interpreter generation. |
| `stage_b_interpreter_native_build.py` | Freestanding PE32 build from interpreter, engine, and runtime packages. |
| `stage_b_fallback_coverage.py` | Replays exact interpreter lowerings and portable selections and proves one implementation kind per unit in the complete structural universe; it has no rooted-reachability authority. |
| `source_lift_audit.py` | Two-level source-lift diagnostics: a cheap source/interface iteration audit independent of v3 authority, plus a final non-authorizing join to authority diagnostics before release/runtime gates. |
| `stage_a_standard_evidence_v3.py` | Emits exact launch-root, callback, target-hint, and inductive-input proposals for native v3 checking. |
| `stage_a_exception_evidence_v3.py` | Generates instruction-bound exception classifications under a checked launch profile; terminal faults remain explicit observable outcomes. |
| `stage_a_external_site_evidence_v3.py` | Generates exact-bound machine-level external-site evidence for downstream native-v3 checking. |
| `stage_a_indexed_target_evidence_v3.py` | Checks immutable PE jump tables, finite selector guards, exact targets, and alias safety before emitting target evidence. |
| `stage_a_isa_evidence_v3.py` | Projects binary-specific oracle and Lean qualification into exact native-v3 ISA evidence. |
| `isa_frontier_report_v1.py` | Replays exact ISA requirements and selection authority into compact form-, field-, and RVA-level repair diagnostics without sharing an output identity with authority evidence. |
| `stage_a_implementation_capabilities_v3.py` | Binds fallback implementation capability IDs to the exact selected ISA forms. |
| `lift_qualification_v1.py`, `stage_b_source_qualification_v1.py`, `stage_b_runtime_qualification_v1.py` | Typed assurance-class-aware portable-lift qualification records, validation-backed source qualification, and pinned linked-runtime qualification. |
| `candidate_validation_v1.py` | Joins exact candidate-only PE32 and non-x86 behavior reports without claiming equivalence. |
| `implementation_ledger_v2.py`, `stage_b_ownership_ledger_v2.py` | Exact unit-ownership and implementation-kind ledgers for static fallback and portable replacements. |
| `lift_completion_receipt_v2.py`, `stage_b_lift_completion_v2.py` | Final completion receipts joining authority, implementation coverage, source qualification, and candidate identities. |
| `runtime_lock_v1.py` | Content-addressed toolchain, runtime, profile, and launch-assumption lock used by portable build receipts. |
| `stage_b_machine_ir_scope.py` | Fail-closed partition of executable and deferred machine-IR transfers for candidate generation. |
| `stage_b_engine_layout.py` | Structural engine layout tables. |
| `stage_b_native_engine.py` | IA-32 ABI bridge and typed x87 native operations. |
| `stage_b_native_image.py` | Derives entry, callback, relocation, import, and zero-fill inputs from a checked load-image contract. |
| `stage_b_native_runtime.py` | Candidate external runtime package. |
| `stage_b_native_diagnostic.py` | Decodes candidate-only native runtime diagnostics into source- and contract-mapped repair evidence. |
| `stage_b_native_binding.py` | Runtime-boundary inventory and adapters. |
| `stage_b_native_build.py` | Generic native compile/compose pipeline. |
| `stage_b_pe_composer.py` | PE image composition, anchors, and relocation checks. |
| `stage_b_typed_x87.py` | Typed, byte-free x87 replay records. |
| `stage_b_provenance.py` | Candidate source/build/output hash binding. |
| `stage_b_candidate_modes.py` | Stable fail-closed identifiers for static-closed and structural-diagnostic candidate builds. |
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
| `machine_abi.py` | Machine-level calling conventions and the reviewed conditional normal-return register premise. |
| `import_abi.py` | Expands reviewed ABI policy against exact PE imports. |
| `machine_import_profiles.py` | Imported-call profile parsing and binding. |
| `callback_contracts.py` | Callback registration, ABI, lifetime, and activation protocol validation. |
| `checked_external_site_contract.py` | Canonical fail-closed machine contract shared by native external-call planning and runtime. |
| `external_operation_profiles.py` | Machine external-operation and environment contracts. |
| `external_interface_profiles.py` | Interface/vtable catalogs and call identities. |
| `external_capabilities.py` | Resolver-issued callable capability contracts. |
| `external_sites.py` | Static machine-level external call-site bindings. |
| `callable_external_runtime.py` | Candidate runtime projection for callable capabilities. |
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
| `target_intent.py` | Strict authored-intent validation and generated provenance separation. |
| `ghidra.py` | Optional headless decompiler proposal exporter. |

Wine execution is candidate-only and must run headlessly. Nix constructors
enforce this with `xvfb-run` where Wine is used.

## Nix Constructors

| File | Output role |
|---|---|
| `toolkit-context.nix` | One reusable per-system source, package, kernel, oracle, and fixture context shared by the root flake and target SDK. |
| `target-sdk-v1.nix` | Stable configured target interface grouped into analysis, authority, candidate, lifting, validation, and bundle operations. |
| `flake-modules/toolkit.nix`, `flake-modules/checks.nix` | Focused `flake-parts` modules for generic packages/apps/shells and checks. |
| `stage-a-external-interface-profile.nix` | Pinned SDK headers through a checked machine-level interface profile. |
| `stage-a-isa-conformance.nix` | One cached Lean/Unicorn/Bochs corpus evaluation. |
| `stage-a-isa-qualification-graph.nix` | Sharded ISA evidence and qualification DAG. |
| `stage-a-isa-semantic-kernel.nix` | Stable compiled Lean semantic kernel packaged independently of target evidence. |
| `stage-a-isa-conformance-kernel.nix`, `stage-a-inductive-certificate-kernel.nix` | Shared compiled Lean conformance and inductive-certificate kernels reused by granular tests and target evidence. |
| `stage-a-machine-ir-isa-qualification-v2.nix` | Binary-specific machine-IR requirement, oracle, selection, and authority DAG. |
| `stage-a-roundtrip-corpus.nix` | Generated static corpus and qualification result. |
| `bochs-conformance.nix` | Pinned batched Bochs adapter. |
| `machine-import-control-profile.nix` | Content-addressed no-return import projection that isolates machine IR from ordinary API-profile edits. |
| `stage-b-component-analysis.nix` | Original inventory through component proposals. |
| `stage-b-component-discovery.nix` | Independent proposal phase. |
| `stage-b-component-selection.nix` | Authored selection materialization. |
| `stage-b-component-interfaces.nix` | Interface extraction/refinement phase. |
| `stage-b-semantic-components.nix` | Component catalog phase. |
| `stage-b-semantic-component-workspaces.nix` | Per-component workspace/check/qualification DAG. |
| `stage-b-interpreter-package.nix` | Machine-IR interpreter package. |
| `stage-b-native-object-graph.nix` | Deterministic native object graph plus a CA compile/assembly realization; avoids evaluation-time reads of CA outputs. |
| `stage-b-hybrid-candidate.nix` | Composes interpreter, native engine/runtime, cached objects, and a PE candidate. |
| `ca-python-json-phase.nix` | Generic CA phase constructor with explicit store dependencies, schema/status checking, and phase manifests. |
| `artifact-seed-v3.nix`, `artifact-set-v3.nix`, `artifact-phase-v3.nix` | Strict source-byte-bound artifact ingestion, typed streaming validation, complete checker-source provenance, and framework-owned map/reduce/SCC phase execution over bounded CA packs. |
| `analysis-v3-source-plan.nix`, `analysis-v3-machine-ir-input.nix` | One streaming dynamic-analysis preparation boundary followed by stable bucket re-interning, so one changed unit invalidates one bounded machine-IR shard without thousands of evaluator reads. |
| `analysis-v3-graph-manifest.nix`, `analysis-v3-authority.nix` | Registry-derived graph-manifest realization and the reusable fail-closed target adapter that combines exact machine IR with typed external evidence artifacts. |
| `analysis-v3-diagnostics.nix` | Non-authorizing checked-artifact summary for precise operator feedback across sharded authority families. |
| `analysis-v3-exception-evidence.nix`, `analysis-v3-external-site-evidence.nix`, `analysis-v3-indexed-target-evidence.nix`, `analysis-v3-isa-evidence.nix`, `analysis-v3-standard-evidence.nix` | Content-addressed exact-evidence providers for exception, external-call, indirect-target, ISA, launch-root, callback, and invariant families. |
| `analysis-v3-implementation-capabilities.nix` | Exact fallback-capability projection over the selected binary-specific ISA inventory. |
| `analysis-v3-isa-frontiers.nix` | Separate content-addressed ISA repair report; diagnostic changes cannot invalidate the authoritative ISA artifact or its downstream closure. |
| `analysis-v3-external-inputs.nix` | Content-addressed ingestion of exact machine-import profiles and PE/load-image roots into native-v3 input artifact sets. |
| `analysis-v3-final-authority-gate.nix` | Strict final-authority record gate used by candidate generation, target validation, and runtime suites. |
| `authority-graph-v3.nix`, `authority-graph-v3-boundaries.nix`, `authority-graph-v3-packs.nix`, `authority-resource-classes-v3.nix` | Manifest-driven v3 authority DAG, independently checked structural/dependency planning boundaries, stable schedule packs, and one shared resource policy used by dynamic preparation and standalone fixtures. |
| `test-suite.nix`, `test-suite-plan.nix`, `test-suite-shard.nix`, `test-suite-fixtures.nix` | Convention-discovered stable test shards and shared heavy fixtures; the aggregate never reruns an unchanged shard. |
| `stage-b-headless-diagnostic-run.nix` | Runs only a statically closed candidate in an isolated headless Wine session. |
| `python-module-closure.nix` | Content-addressed transitive local-Python import closure for phase-specific invalidation. |
| `python-module-index.json` | Generated checked local-import graph consumed by phase-specific Python closures. |
| `stage-b-linked-libraries.nix` | Library constellation and replacement-plan DAG. With no catalog it still classifies reviewed application ranges, import thunks, and unknown ownership without granting replacement authority. |
| `stage-b-source-call-substitutions.nix` | Call-frontier through source-binding DAG. |
| `stage-b-clang-ast-bundle.nix` | Deterministic per-translation-unit Clang AST bundle for complete source-call inventory. |
| `stage-b-source-component-assurance.nix` | Source component evidence aggregation. |
| `stage-b-source-project.nix` | Generic reviewed-source project, evidence-plan, and exact machine-unit binding constructor. |
| `stage-b-source-iteration-audit.nix` | Cheap content-addressed source/interface audit over machine IR, source bindings, linked-island coverage, candidate identity, and static import-surface drift; deliberately excludes the full authority DAG. |
| `stage-b-source-lift-audit.nix` | Final content-addressed diagnostic join between the cheap source-iteration audit and v3 authority diagnostics; remains non-authorizing and cannot replace the final authority gate. |
| `stage-b-fallback-coverage-receipt.nix` | Checks one implementation kind for every structural machine-IR unit without claiming rooted reachability. |
| `stage-b-implementation-ledger.nix`, `stage-b-lift-completion-receipt.nix` | Build exact implementation ownership ledgers and final lift-completion receipts. |
| `stage-b-portable-c-project.nix` | Reproducible PE32 and cross-architecture builds of reviewed portable C source. |
| `stage-b-runtime-lock.nix` | Materializes the exact toolchain, runtime, profile, and launch dependency lock. |
| `stage-b-source-qualification.nix` | Builds an explicit validation-backed source qualification from exact source binding, component assurance, source-call coverage, and candidate dependency evidence; it never infers semantic proof from a diagnostic audit. |
| `stage-b-runtime-qualification.nix` | Qualifies a validation-backed pinned-runtime substitution over the exact non-application unit universe. |
| `stage-b-candidate-validation.nix` | Joins exact PE32 and non-x86 candidate-only reports for the validation-qualified completion profile. |
| `stage-b-functional-suite.nix` | Candidate-only expected-output suite. |
| `stage-b-upstream-shell-suite.nix` | Candidate-only upstream shell tests under headless Wine. |
| `stage-b-target-intent.nix` | Validated authored target intent. |
| `callable-external-runtime-contract.py` | Deterministic runtime-contract builder invoked inside Nix. |
| `stage-a-builders`, `stage-a-lightweight-ca-builders` | Optional remote builder inventories for full and lightweight jobs. |
| `stage-a-builder-public-keys` | Trusted cache keys paired with the builder inventories. |

The supported consumer interface is `flake.lib.mkTargetSdkV1`; low-level
constructors are exposed under `flake.lib.unstable` for toolkit development.
CA derivations are first-class; dependency granularity, not CA mode alone,
determines invalidation.

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
- `pe32-normal-return-nonvolatile-v1.json`
- `pe32-static-cutpoints-and-paired-callables-v1.json`
- `pe32-win32-system-dll-abi-policy-v1.json`
- `pe32-win32-windowing-runtime-v1.json`
- `pe32-winmm-runtime-v1.json`
- `pe32-win32-gui-launch-assumptions-v1.json`
- `pe32-win32-console-launch-assumptions-v1.json`

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
`target-bundles.md`, and `performance-and-invalidation.md`. Historical plans and experiment reports remain in Git
history rather than competing with the current design.

## Validation Targets

| Target | Current role |
|---|---|
| `targets/gnu-hello/` | Small portable-C and authored-component validation bundle. |
| `targets/jq/` | Larger CLI/library/component intent benchmark and functional expectations. |
| `targets/dxball/` | Proprietary 3D-era application acquisition plus generic machine-IR and component-analysis benchmark. |

Target `targets/<id>/default.nix` modules acquire/build inputs and invoke generic constructors.
Intent JSON and source are authored. Downloaded binaries and generated analyses
must not be committed.

The corpus flake exports
`legacyPackages.x86_64-linux.targets.<id>.<family>.<artifact>` and
`targetChecks.<id>`. Listing the registry or artifact families does not force
the corresponding authority graph.

## Tests

`src/spaghetti_extractor/testkit/` owns convention discovery, import/resource
impact, stable shard planning, shared fixture lookup, scaffolding, environment
diagnosis, and rebuild explanations. `nix run .#test -- affected` selects only
impacted shard outputs; `nix run .#test -- full` and `nix flake check` are the
complete generic gates. Direct heavyweight tool execution in new tests is a
policy error with a fixture-based remediation.

`nix run ./targets#test -- <id>` runs the generic smoke gate and then the
consumer-owned target aggregate. `nix flake check ./targets` validates registry,
bundle, intent, and SDK-boundary contracts independently of the generic suite.

Tests are phase-oriented by filename:

- `test_stage_a_isa_*`: ISA catalog, corpus, oracle, qualification, and Nix paths.
- `test_reconstruction_*`, `test_recursive_decode.py`,
  `test_rooted_state_machine.py`: static reconstruction and machine IR.
- `test_component_*`, `test_semantic_components.py`,
  `test_*component_contract.py`: component discovery/interface/source checks.
- `test_external_*`, `test_callable_external_runtime.py`: ABI and external calls.
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
2. Add a small `targets/<id>/default.nix` accepting `{ pkgs, sdk }`, and return
   `sdk.target.bundle { ... }`.
3. Register the directory in `targets/registry.nix`; structured artifacts and
   aggregate checks are exported automatically.
4. Do not edit the root flake or add target Python, Lean, or private-constructor
   imports.
5. If a reusable capability is missing, implement it under `src/` or the SDK,
   validate it with a generic fixture, and then consume it from the target.

This rule keeps DX-Ball, jq, GNU Hello, and future programs as clients of one
toolkit rather than alternate architectures embedded in the repository.
