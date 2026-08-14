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
  -> extraction/binary_inventory.py
  -> extraction/isa_inventory.py + ISA qualification
  -> contract_tools.py / opaque_reconstruction.py
  -> stage_b_state_machine.py
  -> reconstruction_ir.py
  +-> authority_inputs/ exact-bound proposals -> authority/ checked graph
  +-> library/interface/component proposals
        -> components/ contracts, evidence, qualifications, and configuration
  +-> complete interpreter/native fallback
  -> candidate/authority/ joins final authority, exact machine IR,
     fallback coverage, and the component runtime package
  -> static-closed rebuilt candidate (or explicitly non-authorizing diagnostic)
  -> stage_b_functional.py candidate-only tests
```

Imports flow downward through this sequence. Target bundles invoke the generic
SDK through Nix; the root flake and generic modules never import `targets/`.

## Public Entrypoints

| Module | Purpose |
|---|---|
| `cli.py` | Canonical `spaghetti-extractor` command registry and exit policy. |
| `commands/` | Lazy command groups behind the literal public command manifest. Internal workers are Python functions, not hidden CLI commands. |
| `contract_tools.py` | Stable facade over static contract generation and candidate feedback. |
| `__main__.py` | `python -m spaghetti_extractor`. |

`pyproject.toml` installs three console scripts. `spaghetti-extractor` is the
production dispatcher above; `spaghetti-extractor-test` is the Nix-first test
runner used by `nix run .#test`; `spaghetti-extractor-dev` is repository
tooling used by `nix run .#dev` for impact plans, fixtures, diagnostics,
scaffolding, rebuild explanations, and metadata refresh. The latter two are
separate flake packages and are not alternate production command surfaces.

`commands/manifest.py` is the literal, sole public-command manifest. `cli.py`
loads only the selected command group; the Python module index reads the
manifest without importing command implementations. The current surface is:

| Group module | Public commands |
|---|---|
| `commands/static_analysis.py` | `stage-a-inventory-binary`, `stage-a-export-behavioral-roots`, `stage-a-export-opaque-reconstruction`, `stage-a-export-reference-contract`, `stage-a-smoke-contract`, `stage-a-explain-contract`, `stage-a-diff-contract`, `stage-a-expand-import-abi` |
| `commands/isa.py` | `stage-a-inventory-isa`, `stage-a-check-isa-conformance`, `stage-a-enrich-isa-catalog` |
| `commands/proposals.py` | `stage-a-export-ghidra-proposal` |
| `commands/roundtrip.py` | `roundtrip-generate`, `roundtrip-run` |
| `commands/reconstruction.py` | `stage-a-export-machine-ir` |
| `commands/authority.py` | `stage-b-build-candidate-authority`, `stage-b-validate-candidate-authority` |
| `commands/runtime.py` | `stage-b-generate-interpreter`, `stage-b-generate-native-engine`, `stage-b-generate-native-runtime` |
| `commands/components.py` | `stage-b-discover-components`, `stage-b-resolve-components`, `stage-b-build-component-contract`, `stage-b-package-component-source`, `stage-b-produce-component-evidence`, `stage-b-qualify-component`, `stage-b-compose-components`, `stage-b-build-component-runtime` |
| `commands/source.py` | `stage-b-render-source-operations` |
| `commands/validation.py` | `stage-b-run-functional-suite` |

`commands/common.py` owns the handler protocol. Commands not present in this
manifest are internal Python workers or retired interfaces, not hidden CLI
entrypoints.

Core support modules are deliberately small:

| Module | Purpose |
|---|---|
| `__init__.py` | Package identity and version surface. |
| `errors.py` | Shared user-input and phase failure types. |
| `util.py` | Canonical JSON, hashing, and atomic artifact helpers. |
| `nix_support.py` | Nix discovery and content-addressed worker command construction. |
| `python_module_index.py` | Canonical local-import index plus production-root closure enforcement used by Nix and developer diagnostics. |

## Package Ownership

The active pipeline packages are ownership boundaries, not migration aliases:

| Package | Owns | Dependency rule |
|---|---|---|
| `extraction/` | Static PE decoding, executable-byte/region/cutpoint inventories, definedness, ISA requirements, and non-authorizing Ghidra proposals. | Must not depend on `authority/`, `authority_inputs/`, `candidate/`, or `components/`. |
| `authority_inputs/` | Exact-bound adapters that turn profiles, PE roots, machine-IR facts, oracle results, exception classifications, target evidence, and implementation capabilities into untrusted v3 proposal artifacts. | May use record codecs needed to construct proposals, but must not depend on terminal authority/graph orchestration, candidates, or components. |
| `authority/` | Native v3 record schemas, codecs, checkers, phase registry, graph planning, diagnostics, and fail-closed final authority. | The authority kernel depends only on its own package plus `address_expressions.py`, `artifact_set_v3.py`, and `phase_framework_v3.py`; it does not call legacy analyzers. |
| `candidate/authority/` | Candidate-receipt model, canonical I/O, fresh recomputation, and the final static-closed candidate gate. | It consumes checked final authority, exact machine IR, fallback coverage, and component runtime completion; it cannot consume extraction or proposal machinery. |
| `components/` | Target-neutral intent, resolution, contracts, source binding, candidate-only evidence, qualifications, total configurations, and runtime completion. | It remains neutral to extraction, authority, authority inputs, and candidate packages so the same contracts can be composed independently. |

`tests/test_repository_boundaries.py` enforces these directions, requires every
production module to have a public-command or Nix-phase consumer, and caps the
active package modules at a reviewable size.

## Static Analysis

`src/spaghetti_extractor/extraction/` owns original-side extraction schemas and
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
`extraction/ghidra.py` is an optional, non-authorizing static proposal adapter.
It hash-binds Ghidra output to the submitted PE and never executes the original
binary. `authority_inputs/` owns the other untrusted ingestion boundaries that
re-parse machine-import profiles, exact PE roots, exception proposals, target
evidence, ISA selections, and fallback capabilities into checked-input artifact
sets.

| Authority-input module | Proposal role |
|---|---|
| `authority_inputs/external_inputs.py` | Re-parses exact profile bytes, recovers and binds PE launch roots, and projects conditional launch assumptions. |
| `authority_inputs/standard_evidence.py` | Emits target hints and inductive inputs from exact machine IR and checked roots. |
| `authority_inputs/exception_evidence.py` | Classifies instruction-bound exceptional transitions under an explicit launch profile. |
| `authority_inputs/indexed_target_evidence.py` | Rechecks immutable PE tables, bounded selectors, exact targets, and alias safety. |
| `authority_inputs/external_site_evidence.py` | Selects exact external profiles and emits replayable external-call evidence. |
| `authority_inputs/isa_evidence.py` | Binds form-scoped oracle/Lean results back to each exact machine-IR occurrence. |
| `authority_inputs/implementation_capabilities.py` | Binds checked ISA selection and fallback coverage to the actual interpreter package. |

`src/spaghetti_extractor/authority/` is the authoritative typed pipeline on
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
| `external_site_records.py`, `external_site_checker.py`, `callbacks.py` | Lightweight external-site records/codecs, the separately cached site checker, and callback entry/registration authority. |
| `external_abi.py` | Deterministic fixed-stack-ABI argument recovery used while checking exact external sites. |
| `root_closure.py`, `exceptional_transitions.py` | Launch-root closure and checked fault/exception dispositions. |
| `target_certificate_records.py`, `target_certificate_checker.py` | Lightweight target-certificate wire records/codecs and the separately loaded finite-target checker. |
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
| `candidate/authority/model.py`, `candidate/authority/io.py`, `candidate/authority/checker.py` | Sole candidate-generation receipt model, canonical serialization, and independent recomputation over checked final authority, exact machine IR, component runtime ownership, and fallback coverage. |
| `reconstruction_control.py` | Proposes clusters from decoded control structure. |
| `reconstruction_composition.py` | Composes compatible machine units into larger reconstruction clusters. |
| `reconstruction_contract_analysis.py` | Derives cluster inputs, outputs, effects, and frontiers. |
| `reconstruction_validation.py` | Synthesizes finite validation cases. |
| `opaque_reconstruction.py` | Original-only bootstrap from static inventory. |
| `stage_b_c_backend.py` | Shared low-level C runtime helpers used by the active interpreter fallback. |
| `stage_b_interpreter_backend.py` | Portable machine-IR interpreter generation. |
| `stage_b_interpreter_native_build.py` | Freestanding PE32 build from interpreter, engine, and runtime packages. |
| `stage_b_fallback_coverage.py` | Replays exact interpreter lowerings and portable selections and proves one implementation kind per unit in the complete structural universe; it has no rooted-reachability authority. |
| `components/source.py`, `components/evidence.py`, `components/qualification.py`, `components/runtime.py` | Content-bind logical C, produce candidate-only behavioral evidence, qualify exact replacements, and generate the sole executable component runtime package. |
| `authority_inputs/standard_evidence.py` | Emits exact launch-root, callback, target-hint, and inductive-input proposals for authority checking. |
| `authority_inputs/exception_evidence.py` | Generates instruction-bound exception classifications under a checked launch profile; terminal faults remain explicit observable outcomes. |
| `authority_inputs/external_site_evidence.py` | Generates exact-bound machine-level external-site evidence for downstream authority checking. |
| `authority_inputs/indexed_target_evidence.py` | Checks immutable PE jump tables, finite selector guards, exact targets, and alias safety before emitting target evidence. |
| `authority_inputs/isa_evidence.py` | Projects binary-specific oracle and Lean qualification into exact authority evidence. |
| `isa_frontier_report_v1.py` | Replays exact ISA requirements and selection authority into compact form-, field-, and RVA-level repair diagnostics without sharing an output identity with authority evidence. |
| `authority_inputs/implementation_capabilities.py` | Binds fallback implementation capability IDs to the exact selected ISA forms. |
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
| `stage_b_candidate_modes.py` | Stable fail-closed identifiers for static-closed and structural-diagnostic candidate builds. |
| `recovered_executable_data.py` | Checked classification of immutable initialized data embedded in executable sections. |

`reconstruction_plan.py` derives deterministic reconstruction clusters and
component discovery inputs from the checked machine IR.

`components/source.py` packages the exact portable files used by component
qualification and candidate source bundles. Qualification cannot outlive a
source-byte change.
The public component framework is the typed `components/` package and its
content-addressed component workflow DAG.

## Components And Portable Source

| Module | Purpose |
|---|---|
| `component_discovery.py` | Proposes coarsened component candidates. |
| `components/intent.py`, `components/model.py` | Strict authored leaves, overlapping alternative groups, and non-overlapping configurations. |
| `components/resolution.py` | Binds component selectors and groups to exact machine units. |
| `components/contracts.py` | Derives and checks one independently liftable machine boundary. |
| `components/source.py` | Packages exact portable source plus its `logical-c-v1` entry. |
| `components/evidence.py` | Runs candidate-only exhaustive finite-domain comparison against exact machine IR and localizes violations. |
| `components/qualification.py` | Binds exact candidate-only or bounded evidence without overstating its scope. |
| `components/configuration.py` | Produces total, exclusive portable-or-fallback ownership for a selected configuration. |
| `components/runtime.py` | Generates machine adapters, portable/member dispatch, and the hash-bound runtime completion package. |
| `semantic_components.py` | Validates hierarchical component declarations and machine boundaries. |
| `component_interface.py` | Declares and checks component interfaces/refinements. |
| `finite_value_domain.py` | Explicit bounded scalar/pointer domains. |
| `region_replacement.py` | Region replacement manifests and activation rules. |
| `source_operation_catalog.py` | Non-authoritative rendering of recovered operations as C. |

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
| top-level `external_sites.py` | Static machine-level external call-site proposals outside the authority package. |
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
| `extraction/ghidra.py` | Optional headless static proposal exporter; its output cannot authorize candidate generation. |

Wine execution is candidate-only and must run headlessly. Nix constructors
enforce this with `xvfb-run` where Wine is used.

## Nix Constructors

| File | Output role |
|---|---|
| `toolkit-context.nix` | One reusable per-system source, package, kernel, oracle, and fixture context shared by the root flake and target SDK. |
| `target-sdk.nix` | Stable v3 target interface and high-level `workflow.pe32` constructor for analysis, authority, components, candidates, and validation. |
| `stage-b-components.nix` | Content-addressed resolution, contract, source, evidence, qualification, configuration, and runtime-package DAG. |
| `stage-b-component-runtime-package.nix` | Generates and cross-compiles the sole executable component runtime package. |
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
| `stage-b-interpreter-package.nix` | Machine-IR interpreter package. |
| `stage-b-native-object-graph.nix` | Controlled-IFD source normalization plus independently content-addressed native objects and assembly; a changed compile bundle invalidates only its object and final package. |
| `stage-b-hybrid-candidate.nix` | Composes interpreter, native engine/runtime, cached objects, and a PE candidate. |
| `ca-python-json-phase.nix` | Generic CA phase constructor with explicit store dependencies, schema/status checking, and phase manifests. |
| `artifact-seed-v3.nix`, `artifact-set-v3.nix`, `artifact-phase-v3.nix` | Strict source-byte-bound artifact ingestion, typed streaming validation, complete checker-source provenance, and framework-owned map/reduce/SCC phase execution over bounded CA packs. |
| `authority-source-plan.nix`, `authority-machine-ir-input.nix` | One streaming dynamic-analysis preparation boundary followed by stable bucket re-interning, so one changed unit invalidates one bounded machine-IR shard without thousands of evaluator reads. |
| `authority-graph-manifest.nix`, `authority-workflow.nix` | Registry-derived graph-manifest realization and the reusable fail-closed target adapter that combines exact machine IR with typed external evidence artifacts. |
| `authority-diagnostics.nix` | Non-authorizing checked-artifact summary for precise operator feedback across sharded authority families. |
| `authority-input-exception-evidence.nix`, `authority-input-external-site-evidence.nix`, `authority-input-indexed-target-evidence.nix`, `authority-input-isa-evidence.nix`, `authority-input-standard-evidence.nix` | Content-addressed exact-evidence providers for exception, external-call, indirect-target, ISA, launch-root, callback, and invariant families. |
| `authority-input-implementation-capabilities.nix` | Exact fallback-capability projection over the selected binary-specific ISA inventory. |
| `authority-isa-frontiers.nix` | Separate content-addressed ISA repair report; diagnostic changes cannot invalidate the authoritative ISA artifact or its downstream closure. |
| `authority-input-external-inputs.nix` | Content-addressed ingestion of exact machine-import profiles and PE/load-image roots into native-v3 input artifact sets. |
| `authority-final-gate.nix` | Strict final-authority record gate used by candidate generation, target validation, and runtime suites. |
| `authority-graph-v3.nix`, `authority-graph-v3-boundaries.nix`, `authority-graph-v3-packs.nix`, `authority-resource-classes-v3.nix` | Manifest-driven v3 authority DAG, independently checked structural/dependency planning boundaries, stable schedule packs, and one shared resource policy used by dynamic preparation and standalone fixtures. |
| `test-suite.nix`, `test-suite-plan.nix`, `test-suite-shard.nix`, `test-suite-fixtures.nix`, `test-suite-manifest.json` | Static, checked stable test shards and shared heavy fixtures; Nix evaluates no dynamic test discovery and unchanged shards substitute. |
| `stage-b-headless-diagnostic-run.nix` | Runs only a statically closed candidate in an isolated headless Wine session. |
| `python-module-closure.nix` | Content-addressed transitive local-Python import closure for phase-specific invalidation. |
| `python-module-index.json` | Generated checked local-import graph consumed by phase-specific Python closures. |
| `stage-b-linked-libraries.nix` | Library constellation and replacement-plan DAG. With no catalog it still classifies reviewed application ranges, import thunks, and unknown ownership without granting replacement authority. |
| `stage-b-fallback-coverage-receipt.nix` | Checks one implementation kind for every structural machine-IR unit without claiming rooted reachability. |
| `stage-b-functional-suite.nix` | Candidate-only expected-output suite. |
| `stage-b-upstream-shell-suite.nix` | Candidate-only upstream shell tests under headless Wine. |
| `callable-external-runtime-contract.py` | Deterministic runtime-contract builder invoked inside Nix. |
| `stage-a-builders`, `stage-a-lightweight-ca-builders` | Optional remote builder inventories for full and lightweight jobs. |
| `stage-a-builder-public-keys` | Trusted cache keys paired with the builder inventories. |

The supported consumer interface is `flake.lib.mkTargetSdk`. Low-level Nix
constructors are private implementation details rather than a parallel API.
CA derivations are first-class; dependency granularity, not CA mode alone,
determines invalidation.

`nix/target-sdk.nix` returns format `spaghetti-extractor-target-sdk-v3` and
owns the generic consumer boundary: `workflow.pe32`, lower-level `analysis`,
`candidate`, `lifting`, and `validation` constructors, pinned `profiles`,
`sources`, `kernels`, `tools`, `fixtures`, and `target.bundle`/`target.registry`.
An external flake obtains it through `flake.lib.mkTargetSdk`; the independent
in-tree corpus imports this same entrypoint. Individual
`targets/<id>/default.nix` modules accept only `{ pkgs, sdk }` and may not
reach into other `nix/` constructors. Conversely, the root flake, generic Nix,
and Python package never import or name validation targets.

## Authored And Generated Data

Authored source includes Python, Lean, Nix constructors, documentation,
reviewed `profiles/*.json`, the reviewed smoke ISA catalog, tool adapters, and
target `target.json`, intent, review, portable source, and functional-suite
files. Format suffixes such as v1, v2, and v3 remain where they identify actual
wire schemas, artifact kinds, SDK contracts, or compatibility surfaces; they
are not package-generation labels.

Two checked-in files are generated repository metadata and must not be edited
by hand:

| Path | Ownership |
|---|---|
| `nix/python-module-index.json` | Generated local-import/resource graph. It is installed because production Nix closures use it. |
| `nix/test-suite-manifest.json` | Generated stable test/shard topology. It is repository-only developer metadata. |

`nix run .#dev -- refresh` regenerates both atomically, and
`nix run .#dev -- refresh --check` verifies freshness. The root check runs that
freshness check. `nix/flake-modules/`, `nix/tests/`,
`nix/test-suite-fixtures.nix`, `nix/test-suite-plan.nix`,
`nix/test-suite-shard.nix`, and `nix/test-suite.nix` are also repository-only
test/evaluation machinery excluded from the installed toolkit source.

All phase artifacts, reports, candidates, downloaded binaries, extracted
target inputs, and evaluation receipts are generated data. They belong in the
Nix store or ignored `private/`, `build/`, `outputs/`, and `result*` paths, not
in Git. Machine-generated JSON reports do not belong under `docs/`.

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
`architecture.md`, `components.md`, `external-operations.md`,
`isa-qualification.md`, `static-roundtrip-qualification.md`, and
`target-bundles.md`, and `performance-and-invalidation.md`. Historical plans
and experiment reports remain in Git history rather than competing with the
current design.

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

The root flake validates `import-smoke`, the complete `test-suite`,
`repository-metadata`, `python-module-closure`, `authority-graph-v3`,
`artifact-seed-v3`, `authority-machine-ir-input`,
`machine-import-control-profile`, `isa-kernel`,
`inductive-certificate-kernel`, `roundtrip`, `target-sdk`, and `components`.
The target flake adds `corpus-boundary` plus one regression aggregate per
registered target. Acceptance aggregates additionally require final authority
and the static-closed candidate where the target exposes them.

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

- `tests/unit/extraction/`, `tests/unit/authority_inputs/`,
  `tests/unit/authority/`, `tests/unit/candidate/`, and
  `tests/unit/components/`: package-owner unit contracts for the migrated
  pipeline.
- `tests/unit/cli/` and `tests/unit/testkit/`: the exact public command surface,
  module closure, metadata, planning, and Nix-runner behavior.
- `tests/unit/nix_v3/` and `nix/tests/`: focused Nix constructor and authority
  graph fixtures.
- `tests/integration/native/`: fixture-backed native integration; `tests/smoke/`
  and `tests/benchmark/` own their explicit suite tiers.
- `test_stage_a_isa_*`: ISA catalog, corpus, oracle, qualification, and Nix paths.
- `test_reconstruction_*`, `test_recursive_decode.py`,
  `test_rooted_state_machine.py`: static reconstruction and machine IR.
- `test_component_discovery.py`, `test_component_interface.py`, and
  `test_semantic_components.py`: generic component discovery/interface checks.
- `test_external_*`, `test_callable_external_runtime.py`: ABI and external calls.
- `test_linked_libraries.py`, `test_source_operation_catalog.py`: library
  recognition and non-authoritative source rendering.
- `test_stage_b_*`: C/interpreter/native/PE/functional/Nix integration.
- `test_repository_boundaries.py`: package direction, generic/target separation,
  documented paths, developer metadata, and removed-surface checks.
- `pe_fixtures.py`: generic synthetic PE32 constructors only.

The workflow is Nix-only. Use `nix build` for the package, `nix develop` for an
interactive environment, `nix run .#test -- smoke|affected|full|benchmark` for
generic test modes, and `nix flake check` for every root check. Use
`nix run ./targets#test -- <id>` for a target regression aggregate,
`nix run ./targets#test -- --acceptance <id>` for its strict acceptance
aggregate, and `nix flake check ./targets` for the independent corpus boundary
and all registered target regressions. Direct `python`, `unittest`, `pytest`,
`pip`, and ad hoc compiler/oracle/Wine invocations are not supported build or
test interfaces; the Nix graph supplies the exact package, fixtures, resource
classes, and cache boundaries.

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
