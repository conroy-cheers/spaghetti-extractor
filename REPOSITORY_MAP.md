# Repository Map

This is the canonical map of Spaghetti Extractor. It describes the active
architecture only. Historical binary-equivalence and source-equivalence proof
experiments remain available in Git history and are not supported interfaces.

## Top Level

| Path | Purpose |
|---|---|
| `flake.nix`, `flake.lock` | Target-agnostic package, checks, apps, development shell, stable target SDK, and low-level generic constructors. |
| `pyproject.toml` | Python package metadata, console scripts, runtime extras, and package-owned Lean/Ghidra resources. Nix owns toolkit distribution; setuptools does not duplicate its file inventory. |
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
  -> static_program/extraction.py / reconstruction/static_export.py
  -> reconstruction/state_machine.py
  -> reconstruction/ir.py
  +-> authority_inputs/ exact-bound proposals -> authority/ checked graph
  +-> library/interface/component proposals
        -> components/ contracts, evidence, qualifications, and configuration
  +-> complete interpreter/native fallback
  -> candidate/authority/ joins final authority, exact machine IR,
     fallback coverage, and the component runtime package
  -> non-executable runtime-frontier report while authority is incomplete
  -> static-closed rebuilt candidate after final authority
  -> candidate/functional.py candidate-only tests
```

Imports flow downward through this sequence. Target bundles invoke the generic
SDK through Nix; the root flake and generic modules never import `targets/`.

## Public Entrypoints

| Module | Purpose |
|---|---|
| `cli.py` | Canonical `spaghetti-extractor` command registry and exit policy. |
| `commands/` | Lazy command groups behind the literal public command manifest. Internal workers are Python functions, not hidden CLI commands. |
| `static_program/` | Original-only static contract and semantic extraction API. |
| `__main__.py` | `python -m spaghetti_extractor`. |

`pyproject.toml` installs three console scripts. `spaghetti-extractor` is the
production dispatcher above; `spaghetti-extractor-test` is the Nix-first test
runner used by `nix run .#test`; `spaghetti-extractor-dev` is repository
tooling used by `nix run .#dev` for impact plans, fixtures, diagnostics,
scaffolding, rebuild explanations, and metadata refresh. The latter two are
separate flake packages and are not alternate production command surfaces.

`commands/manifest.py` is the literal, sole command manifest. `cli.py` loads
only the selected group; the Python module index reads roles without importing
implementations. The operator surface is intentionally small:

`testkit/fixture_catalog.json` is likewise the sole authored catalog for shared
test fixtures. Python provides discovery and lookup, while Nix binds those
definitions to reproducible realizations; either side rejects metadata drift.

| Namespace | Commands |
|---|---|
| `project` | `analyze`, `status`, `check` (`--acceptance` selects the strict gate) |
| `component` | `list`, `status`, `build`, `check` with unit/group/configuration selectors |
| `candidate` | `list`, `status`, `build`, `test` |
| `expert` | Explicit low-level Stage A, ISA, reconstruction, authority, runtime, component, source, and validation leaves from `commands/*.py`. |

`commands/workflows.py` maps operator commands only to stable target-SDK Nix
attributes. `commands/common.py` owns the expert handler protocol. A low-level
leaf outside `expert` is a repository-boundary failure; retired commands are
not retained as aliases.

The status namespaces also define dependency ownership: `project status` is
authority-only, `component status` is scoped to a selected lifting unit or
configuration, and `candidate status` combines authority with one exact
configuration and its test declarations. Component failures are therefore not
in the Nix closure of project status.

Core support modules are deliberately small:

| Module | Purpose |
|---|---|
| `__init__.py` | Package identity and version surface. |
| `errors.py` | Shared user-input and phase failure types. |
| `util.py` | Canonical JSON, hashing, and atomic artifact helpers. |
| `build_support/nix_support.py` | Nix discovery and content-addressed worker command construction. |
| `build_support/python_module_index.py` | Canonical local-import index plus production-root closure enforcement used by Nix and developer diagnostics. |
| `build_support/architecture_manifest.py` | Canonical operator, authority, candidate, proposal, diagnostic, expert, and developer root roles; Nix files declare roles explicitly rather than inheriting them from filenames. |
| `build_support/lean_runner.py` | Small deterministic Lean compile/run helper. |

## Package Ownership

The active pipeline packages are ownership boundaries, not migration aliases:

| Package | Owns | Dependency rule |
|---|---|---|
| `extraction/` | Static PE decoding, executable-byte/region/cutpoint inventories, ISA requirements, and non-authorizing Ghidra proposals. | Must not depend on `authority/`, `authority_inputs/`, `candidate/`, or `components/`. |
| `authority_inputs/` | Exact-bound adapters that turn profiles, PE roots, machine-IR facts, oracle results, exception classifications, target evidence, and implementation capabilities into untrusted v3 proposal artifacts. | May use record codecs needed to construct proposals, but must not depend on terminal authority/graph orchestration, candidates, or components. |
| `authority/` | Native v3 record schemas, codecs, checkers, phase registry, graph planning, diagnostics, and fail-closed final authority. | The authority kernel depends on typed `authority_inputs/` values and `artifacts/` primitives; it does not call legacy analyzers. |
| `candidate/authority/` | Candidate-receipt model, canonical I/O, fresh recomputation, and the final static-closed candidate gate. | It consumes checked final authority, exact machine IR, fallback coverage, and component runtime completion; it cannot consume extraction or proposal machinery. |
| `candidate/` | Runtime-independent candidate planning, machine-IR fallback rendering, PE composition, component dispatch, and candidate-only diagnostics. | It consumes canonical authority and neutral schemas; it never imports proposal discovery. |
| `components/` | Target-neutral intent, resolution, contracts, source binding, candidate-only evidence, qualifications, total configurations, and runtime completion. | It remains neutral to extraction, authority, authority inputs, and candidate packages so the same contracts can be composed independently. |
| `machine_ir/` | Neutral definedness and implementation-coverage checks shared across extraction, authority adapters, and candidate construction. | It owns cross-phase machine-IR schemas/checkers so no higher layer must be imported backwards. |
| `external/` | Canonical ABI, interface, operation-profile, and external-site contract schemas plus candidate projection. | Proposal-only v2 profile/callable paths are removed; runtime construction consumes canonical v3 sites. |
| `isa/` | Catalogs, corpus/oracle adapters, qualification, kernel selection, and frontier reporting. | Oracles veto qualification but cannot authorize candidate behavior. |
| `reconstruction/` | Original-only opaque bootstrap, exact machine-IR construction, clustering, contract analysis, composition, and validation. | It proposes bounded reconstruction artifacts and has no candidate authority. |
| `static_program/` | Typed original-only PE contract, strict codec, exact extraction, and filesystem binding. | It cannot contain a candidate, binary mapping, or behavioral-reachability assertion. |
| `artifacts/` | Shared format identifiers, canonical identities, immutable artifact-set records, codecs, streaming I/O, and scheduling. | Cross-subsystem identifiers have one literal owner; JSON mappings stop at codec boundaries. |
| `pe32/` | Exact PE parsing, loader diagnostics, exports/TLS/imports, structural decode, COFF hints, roots, and cutpoint materialization. | It is the target-neutral binary substrate for extraction and candidate composition. |
| `libraries/` | Artifact parsing, constellation matching, interface assignment, refinement, and replacement planning. | Recognition is proposal evidence and never grants replacement authority by name alone. |
| `build_support/` | Nix, Lean, architecture, and generated Python-module-index support. | Build policy remains separate from binary-analysis semantics. |
| `profiles/` | Typed registry and exact-inventory validation for reusable reviewed profiles. | Every profile is catalogued with a role and validator and checked as a cached Nix authority input. |
| `target_bundles/` | Exact authored-file ownership linter for validation consumers. | Undeclared, duplicate, generated, or symlinked target assets fail closed. |

`tests/test_repository_boundaries.py` enforces these directions, requires every
production module to have a public-command or Nix-phase consumer, and caps the
active package modules at a reviewable size.

## Static Analysis

`src/spaghetti_extractor/static_program/` owns the original-only contract and
its bounded semantic extraction. Static PE, executable-byte classification,
and cutpoint recovery remain in `extraction/`:

| Module | Purpose |
|---|---|
| `schema.py` | Stable active model/profile identifiers and compact Lean module inventory. |
| `binary_inventory.py` | Strict PE32 executable-byte classification and cutpoint inventory. |
| `region_inventory.py` | Region extraction artifacts and bindings. |
| `cutpoints.py` | Semantic cutpoint subdivision. |
| `instruction_support.py` | Fail-closed instruction/profile preflight. |
| `isa_inventory.py` | Required instruction-form inventory for one binary. |
| `isa_requirements.py` | Required Lean form/capability projection. |
| `x87_profile.py` | x87-specific static requirements and replay metadata. |

PE primitives live in `pe32/pe.py`, `pe32/stage_binary.py`, and
`pe32/recursive_decode.py`.
`reconstruction/rooted_state_machine.py` performs rooted static control recovery.
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
| `authority_inputs/implementation_capabilities.py` | Projects a strict non-executable lowering capability over checked ISA selections; executable generation later rechecks the same source identities. |

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

## Static Semantics

`static_program/semantics/` contains the original-only instruction and symbolic
semantics. It accepts one exact PE and one static span at a time; there is no
candidate-binary model, block mapper, or binary-pair verdict in this layer:

| Module | Purpose |
|---|---|
| `support.py` | Shared ranges, issue records, and static extraction helpers. |
| `instruction.py`, `control.py` | Machine instruction, callsite, branch, switch, and import evidence. |
| `expressions.py`, `flags.py`, `operands.py`, `symbolic_execution.py` | Bounded symbolic state and effect summaries. |
| `transfer.py` | Original-only transfer and ordered instruction-effect export. |
| `extraction/executable_classification.py` | Executable-byte, padding, function, and basic-block classification. |

`static_program/extraction.py` and `reconstruction/static_export.py` convert a
map-blind binary inventory into an original-only contract and state machine.
The contract contains no candidate image, binary mapping, or behavioral
reachability assertion.
`artifacts/formats.py` centralizes identifiers shared across subsystem boundaries;
unique domain-local formats remain with their owner.

## Machine Representation And Generation

| Module | Purpose |
|---|---|
| `reconstruction/state_machine.py` | Normalizes static transfer contracts into the generated baseline state machine; proposal ownership is independent of candidate generation. |
| `reconstruction/ir.py`, `reconstruction/ir_model.py` | Stable exact-machine-IR facade and shared typed values. |
| `reconstruction/ir_decoding.py`, `reconstruction/ir_preparation.py`, `reconstruction/ir_evidence.py`, `reconstruction/ir_recovery.py` | Exact decoding, preparation, evidence validation, and recovered-control helpers. |
| `reconstruction/ir_materialization.py`, `reconstruction/ir_inventory.py`, `reconstruction/ir_export.py` | Semantic materialization, structural inventory, and canonical machine-IR export. |
| `pe32/behavioral_roots.py` | Independently parses and hash-binds PE entry, executable export, and immutable TLS callback roots. |
| `authority_inputs/machine_ir_authority.py` | Stable exact unit/event binding kernel shared by machine-IR extraction and downstream authority replay. |
| `artifacts/identity.py` | Stable canonical content identities shared by active artifact producers. |
| `artifacts/artifact_set.py`, `artifacts/io.py`, `artifacts/scheduling.py` | Canonical manifests, bounded compressed packs, streaming indexed reads, and structural/dependency schedules. |
| `artifacts/phases.py` | Typed map-unit, map-SCC, and checked-reduce definitions with automatic dependency recording and completeness enforcement. |
| `authority_inputs/bindings.py` | Exact binary/unit/event bindings and canonical JSON used at stable active wire boundaries. |
| `authority_inputs/address_expressions.py` | Normalized address-expression IR used by provenance and target certificates. |
| `authority_inputs/control_disposition.py` | Projects full import profiles onto fixed-arity no-return facts required by structural control extraction. |
| `authority_inputs/target_dependencies.py`, `authority_inputs/static_indirect_replay.py` | Exact indirect-target dependencies and independent finite-target replay. |
| `pe32/target_cutpoint_materialization.py`, `pe32/recovered_executable_data.py` | Untrusted exact-span proposals plus checked executable code/data and padding separation. |
| `external/contracts.py` | Canonical machine-level external call/jump contracts and exact profile matching. |
| `isa/kernel_selection.py` | Binary-specific binding from reachable forms to qualified semantics and fallback capabilities. |
| `authority_inputs/isa_catalog.py`, `authority_inputs/isa_requirements.py`, `authority_inputs/isa_selection.py` | Exact machine-IR ISA inventory, required-form extraction, and binary-bound qualification selection. |
| `authority_inputs/launch_assumptions.py` | Content-stable, non-authorizing PE-bound assumption projection for root-independent SCC analysis. |
| `candidate/authority/model.py`, `candidate/authority/io.py`, `candidate/authority/checker.py` | Sole candidate-generation receipt model, canonical serialization, and independent recomputation over checked final authority, exact machine IR, component runtime ownership, and fallback coverage. |
| `reconstruction/control.py` | Stable facade for cluster proposals from decoded control structure. |
| `reconstruction/control_common.py`, `reconstruction/control_jump_tables.py`, `reconstruction/control_reachability.py`, `reconstruction/control_clusters.py` | Shared control records, bounded jump-table recovery, structural reachability, and cluster construction. |
| `reconstruction/composition.py` | Composes compatible machine units into larger reconstruction clusters. |
| `reconstruction/contract_analysis.py` | Derives cluster inputs, outputs, effects, and frontiers. |
| `reconstruction/validation.py` | Synthesizes finite validation cases. |
| `static_program/model.py`, `static_program/codec.py`, `static_program/extraction.py` | Typed original-only static-program schema, strict parser, and exact extractor. |
| `reconstruction/static_export.py` | Original-only static-program and canonical state-machine orchestration. |
| `candidate/c_backend.py` | Shared low-level C runtime helpers used by the active interpreter fallback. |
| `candidate/c_domains.py`, `candidate/c_render.py` | Shared closed semantic domains plus expression/transition C rendering isolated from package validation. |
| `candidate/interpreter.py`, `candidate/interpreter_model.py`, `candidate/interpreter_compiler.py`, `candidate/interpreter_package.py`, `candidate/interpreter_render.py`, `candidate/interpreter_values.py` | Portable machine-IR interpreter model, lowering, rendering, packaging, and strict value decoding. |
| `candidate/build.py`, `candidate/build_model.py`, `candidate/build_validation.py`, `candidate/build_sources.py`, `candidate/build_objects.py`, `candidate/build_workflow.py`, `candidate/build_values.py` | Freestanding PE32 build facade, package validation, source/object DAG, final workflow, and strict values. |
| `machine_ir/coverage.py` | Replays exact interpreter lowerings and portable selections and proves one implementation kind per unit in the complete structural universe; it has no rooted-reachability authority. |
| `machine_ir/definedness.py` | Undefined-value and dependency-frontier analysis shared without importing extraction or candidate layers backwards. |
| `components/source.py`, `components/evidence.py`, `components/qualification.py`, `components/runtime.py` | Content-bind logical C, produce candidate-only behavioral evidence, qualify exact replacements, and generate the sole executable component runtime package. |
| `authority_inputs/standard_evidence.py` | Emits exact launch-root, callback, target-hint, and inductive-input proposals for authority checking. |
| `authority_inputs/exception_evidence.py` | Generates instruction-bound exception classifications under a checked launch profile; terminal faults remain explicit observable outcomes. |
| `authority_inputs/external_site_evidence.py` | Generates exact-bound machine-level external-site evidence for downstream authority checking. |
| `authority_inputs/indexed_target_evidence.py` | Checks immutable PE jump tables, finite selector guards, exact targets, and alias safety before emitting target evidence. |
| `authority_inputs/isa_evidence.py` | Projects binary-specific oracle and Lean qualification into exact authority evidence. |
| `isa/frontier_report_v1.py` | Replays exact ISA requirements and selection authority into compact form-, field-, and RVA-level repair diagnostics without sharing an output identity with authority evidence. |
| `authority_inputs/implementation_capabilities.py` | Binds fallback implementation capability IDs to the exact selected ISA forms. |
| `candidate/engine_layout.py` | Structural engine layout tables. |
| `candidate/engine.py`, `candidate/engine_model.py`, `candidate/engine_analysis.py`, `candidate/engine_components.py`, `candidate/engine_render.py`, `candidate/engine_x87.py`, `candidate/engine_package.py` | Candidate engine model, machine-IR analysis, component/callback synthesis, typed x87 support, rendering, and deterministic packaging. |
| `candidate/image.py` | Derives entry, callback, relocation, import, and zero-fill inputs from a checked load-image contract. |
| `candidate/runtime.py`, `candidate/runtime_model.py`, `candidate/runtime_program_validation.py`, `candidate/runtime_plan_validation.py`, `candidate/runtime_receipts.py`, `candidate/runtime_render.py`, `candidate/runtime_render_core.py`, `candidate/runtime_render_entry.py`, `candidate/runtime_values.py` | Candidate external runtime model, input validation, receipts, C rendering, and strict values. |
| `candidate/binding.py` | Runtime-boundary inventory and adapters. |
| `candidate/native_build.py` | Generic native compile/compose pipeline. |
| `candidate/pe.py`, `candidate/pe_model.py` | PE image composition plus isolated structural models, anchors, relocations, and validation helpers. |
| `candidate/x87.py` | Typed, byte-free x87 replay records. |
| `pe32/recovered_executable_data.py` | Checked classification of immutable initialized data embedded in executable sections. |

`reconstruction/plan.py` derives deterministic reconstruction clusters and
component discovery inputs from the checked machine IR.

`components/source.py` packages the exact portable files used by component
qualification and candidate source bundles. Qualification cannot outlive a
source-byte change.
The public component framework is the typed `components/` package and its
content-addressed component workflow DAG.

## Components And Portable Source

| Module | Purpose |
|---|---|
| `components/discovery.py`, `components/discovery_model.py`, `components/discovery_schema.py`, `components/discovery_checker.py`, `components/discovery_render.py` | Proposes coarsened component candidates with isolated models, schemas, checks, and rendering. |
| `components/proposal_package.py` | Writes and checks the v2 component-proposal package: compact selector index, exact unit-binding sidecar, bounded rich-record packs, selected-record lookup, and a separate complete producer audit. |
| `components/proposal_selection.py` | Resolves reviewed selectors once, verifies their rich records, and emits a canonical resolution projection whose identity excludes diagnostics and unrelated discovery proposals. |
| `components/intent.py`, `components/model.py` | Strict authored leaves, overlapping alternative groups, and non-overlapping configurations. |
| `components/resolution.py` | Binds component selectors and groups to exact machine units. |
| `components/contracts.py` | Derives and checks one independently liftable machine boundary. |
| `components/source.py` | Packages exact portable source plus its `logical-c-v1` entry. |
| `components/evidence.py` | Runs candidate-only exhaustive finite-domain comparison against exact machine IR and localizes violations. |
| `components/qualification.py` | Binds exact candidate-only or bounded evidence without overstating its scope. |
| `components/configuration.py` | Produces total, exclusive portable-or-fallback ownership for a selected configuration. |
| `components/runtime.py` | Generates machine adapters, portable/member dispatch, and the hash-bound runtime completion package. |
| `components/semantic.py`, `components/semantic_model.py` | Validates hierarchical component declarations and machine boundaries. |
| `components/interface.py`, `components/interface_schema.py` | Declares and checks component interfaces/refinements. |
| `components/region_replacement.py`, `components/region_replacement_model.py`, `components/region_replacement_schema.py`, `components/region_replacement_render.py` | Checks exact replacement ownership and renders deterministic ABI adapters. |
| `authority_inputs/finite_values.py` | Explicit bounded scalar/pointer domains. |
| `external/source_operations.py` | Non-authoritative rendering of recovered operations as C. |

Component checks are local and scope-bounded. Promotion requires exact hashes
and interfaces; it does not erase unresolved whole-program reconstruction gaps.

## ABI, Imports, And External Operations

| Module | Purpose |
|---|---|
| `external/machine_abi.py` | Machine-level calling conventions and the reviewed conditional normal-return register premise. |
| `external/import_abi.py` | Expands reviewed ABI policy against exact PE imports. |
| `external/machine_import_profiles.py` | Imported-call profile parsing and binding. |
| `external/callbacks.py` | Callback registration, source, ABI, lifetime, and activation protocol validation. |
| `external/contracts.py` | Canonical fail-closed machine contract shared by native external-call planning and runtime. |
| `external/operation_model.py`, `external/operation_profiles.py` | Typed machine external-operation/environment models plus strict parsing and validation. |
| `external/interface_profiles.py` | Interface/vtable catalogs and call identities. |
| `external/interface_ast.py` | Interface declarations recovered from AST JSON. |
| `candidate/api_catalog.py` | Known API signature/substitution catalog support. |

## Linked Libraries

| Module | Purpose |
|---|---|
| `libraries/artifact_parsers.py`, `libraries/catalog.py`, `libraries/model.py` | Historical object/archive parsing, exact artifact indexes, catalog locking, and typed library records. |
| `libraries/matching.py`, `libraries/matching_support.py`, `libraries/refinement.py` | Constellation matching, hypotheses, reviewed ownership, and dynamic requirements. |
| `libraries/interfaces.py`, `libraries/contracts.py`, `libraries/replacements.py` | Reviewed linked-island/interface contracts, qualification, and replacement plans. |

Recognition uses function/data/import constellations rather than requiring every
historical library implementation. Exact artifacts can provide strong evidence;
partial constellations remain hypotheses and do not authorize replacement.

## ISA Model And Oracles

| Module | Purpose |
|---|---|
| `isa/catalog.py`, `isa/catalog_xed.py` | Canonical instruction-form catalog plus isolated imported-XED normalization. |
| `isa/catalog_enrichment.py` | Stable catalog-enrichment facade. |
| `isa/catalog_enrichment_schema.py`, `isa/catalog_enrichment_lean.py`, `isa/catalog_enrichment_derivation.py`, `isa/catalog_enrichment_integer.py`, `isa/catalog_enrichment_x87.py`, `isa/catalog_enrichment_system.py` | Enrichment schemas, Lean mappings, derivations, integer semantics, x87 semantics, and system-form rules. |
| `isa/semantic_forms.py` | Normalized semantic form identifiers. |
| `isa/side_adapter.py` | Connects binary requirements to qualification evidence. |
| `isa/conformance.py` | Strict corpus/report schemas and observation comparison. |
| `isa/conformance_lean.py` | Concrete evaluator over compact Lean semantics. |
| `isa/conformance_unicorn.py` | Unicorn veto oracle. |
| `isa/conformance_bochs.py` | Batched Bochs veto oracle adapter. |
| `isa/corpus_generator.py`, `isa/corpus_observations.py` | Deterministic strict-vector generation plus concrete observation construction. |
| `isa/kernel_qualification.py`, `isa/kernel_qualification_oracles.py`, `isa/kernel_qualification_artifacts.py`, `isa/kernel_qualification_reports.py` | Stable qualification facade, cross-oracle checking, artifact loading, and report construction. |
| `isa/campaign.py` | Coverage campaigns and missing-form prioritization. |
| `isa/cli.py` | Lower-level ISA campaign command helpers. |
| `isa/conformance_nix.py` | Nix realization, remote-builder use, and provenance copying. |
| `isa/conformance_shards.py`, `isa/conformance_worker.py`, `isa/qualification_worker.py` | Deterministic oracle sharding and isolated cached conformance/qualification workers. |
| `build_support/lean_runner.py` | Small deterministic Lean compile/run helper. |

`src/spaghetti_extractor/lean/StageA/` contains only the compact reusable ISA
kernel. `Bytes`, `PE32`, `Machine`, `Decode`, and `Semantics` provide the stable
formal layers; `X87`, `ISAInventory`, `ISAQualification`, `ISAConformance`, and
`ISAConformanceRunner` build ISA qualification on top. It contains no target
bytes or target graph.

## Round-Trip Regression

`roundtrip_fuzz/` contains:

| Module | Purpose |
|---|---|
| `model.py` | Strict v2 corpus/case/artifact schemas. |
| `semantic.py` | Small canonical semantic program language. |
| `lowering.py` | GNU and LLVM/MSVC-style PE32 lowering. |
| `generator.py` | Positive transformations and localized negative mutations. |
| `runner.py` | Static inventory, binding, semantic-difference, and localization checks. |
| `image_model.py`, `image_parsing.py`, `image_validation.py`, `image_io.py` | Exact PE load-image model, parser, validator, and I/O used by native composition. |

The corpus is an untrusted regression system, not a candidate equivalence claim.

## Candidate Behavior

| Module | Purpose |
|---|---|
| `candidate/functional.py` | Curated expected-output cases and sharded candidate execution. |
| `extraction/ghidra.py` | Optional headless static proposal exporter; its output cannot authorize candidate generation. |

Wine execution is candidate-only and must run headlessly. Nix constructors
enforce this with `xvfb-run` where Wine is used.

## Nix Constructors

| File | Output role |
|---|---|
| `toolkit-context.nix` | One reusable per-system source, package, kernel, oracle, and fixture context shared by the root flake and target SDK. |
| `target-sdk.nix` | Stable v3 target interface and high-level `workflow.pe32` constructor for analysis, authority, components, candidates, and validation. |
| `stage-b-components.nix` | Content-addressed resolution, contract, source, evidence, qualification, configuration, and runtime-package DAG. |
| `stage-b-component-proposal-input.nix` | Controlled-IFD boundary that checks the full proposal package once, then re-interns only reviewed selectors and selected resolution fields for downstream component phases. |
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
| `stage-b-component-discovery.nix` | Independent proposal phase; publishes the bounded v2 package only after streaming every rich record through its complete integrity audit. |
| `fallback-capability-analysis.nix` | Non-executable lowering analysis projected into final static authority; emits no source or object code. |
| `stage-b-native-object-graph.nix` | Controlled-IFD source normalization plus independently content-addressed native objects and assembly; a changed compile bundle invalidates only its object and final package. |
| `stage-b-hybrid-candidate.nix` | Composes interpreter, native engine/runtime, cached objects, and a PE candidate. |
| `ca-python-json-phase.nix` | Generic CA phase constructor with explicit store dependencies, schema/status checking, and phase manifests. |
| `artifact-seed-v3.nix`, `artifact-set-v3.nix`, `artifact-phase-v3.nix` | Strict source-byte-bound artifact ingestion, typed streaming validation, complete checker-source provenance, and framework-owned map/reduce/SCC phase execution over bounded CA packs. |
| `authority-source-plan.nix`, `authority-machine-ir-input.nix` | One streaming dynamic-analysis preparation boundary followed by stable bucket re-interning, so one changed unit invalidates one bounded machine-IR shard without thousands of evaluator reads. |
| `authority-graph-manifest.nix`, `authority-workflow.nix` | Registry-derived graph-manifest realization and the reusable fail-closed target adapter that combines exact machine IR with typed external evidence artifacts. |
| `authority-diagnostics.nix` | Non-authorizing checked-artifact summary for precise operator feedback across sharded authority families. |
| `authority-input-exception-evidence.nix`, `authority-input-external-site-evidence.nix`, `authority-input-indexed-target-evidence.nix`, `authority-input-isa-evidence.nix`, `authority-input-standard-evidence.nix` | Content-addressed exact-evidence providers for exception, external-call, indirect-target, ISA, launch-root, callback, and invariant families. |
| `authority-input-implementation-capabilities.nix` | Exact, sparse fallback-capability projection over the selected binary-specific ISA inventory. Missing records remain localized incomplete authority. |
| `stage-b-interpreter-package.nix` | Generates executable fallback source only after final authority closes, then checks every generated source/header hash against the static capability analysis. |
| `authority-isa-frontiers.nix` | Separate content-addressed ISA repair report; diagnostic changes cannot invalidate the authoritative ISA artifact or its downstream closure. |
| `authority-input-external-inputs.nix` | Content-addressed ingestion of exact machine-import profiles and PE/load-image roots into native-v3 input artifact sets. |
| `authority-final-gate.nix` | Strict final-authority record gate used by candidate generation, target validation, and runtime suites. |
| `authority-graph-v3.nix`, `authority-graph-v3-boundaries.nix`, `authority-graph-v3-packs.nix`, `authority-resource-classes-v3.nix` | Manifest-driven v3 authority DAG, independently checked structural/dependency planning boundaries, stable schedule packs, and one shared resource policy used by dynamic preparation and standalone fixtures. |
| `test-suite.nix`, `test-suite-plan.nix`, `test-suite-shard.nix`, `test-suite-fixtures.nix`, `test-fixture-catalog.nix`, `generated/test-suite-manifest.json` | Static, checked stable test shards and shared heavy fixtures; Nix evaluates no dynamic test discovery and unchanged shards substitute. |
| `runtime-frontier-report.nix` | Emits a pure non-authorizing JSON projection of checked authority blockers; it cannot contain source, object code, a PE, runtime packages, or Wine. |
| `candidate-test-suite.nix` | Binds a final-authority candidate to curated expected-output cases and executes it through isolated headless Wine. |
| `python-module-closure.nix` | Content-addressed transitive local-Python import closure with an explicit checked phase role. |
| `generated/python-module-index.json` | Generated checked local-import/resource graph and role closures consumed by phase-specific Python closures. |
| `stage-b-linked-libraries.nix` | Library constellation and replacement-plan DAG. With no catalog it still classifies reviewed application ranges, import thunks, and unknown ownership without granting replacement authority. |
| `stage-b-fallback-coverage-receipt.nix` | Checks one implementation kind for every structural machine-IR unit without claiming rooted reachability. |
| `candidate-test-aggregate.nix`, `candidate-test-suite.nix` | Final-authority-gated expected-exit and bounded-liveness tests under isolated headless Wine. |
| `profile-registry-check.nix` | Exact-inventory, role, schema, and semantic validation for every reviewed reusable profile. |
| `target-bundle-lint.nix` | Exact authored-file ownership validation for every target bundle. |
| `xed-isa-catalog.nix` | Pinned deterministic XED instruction-catalog package and app. |
| `stage-a-builders`, `stage-a-lightweight-ca-builders` | Optional remote builder inventories for full and lightweight jobs. |
| `stage-a-builder-public-keys` | Trusted cache keys paired with the builder inventories. |

The supported consumer interface is `flake.lib.mkTargetSdk`. Low-level Nix
constructors are private implementation details rather than a parallel API.
CA derivations are first-class; dependency granularity, not CA mode alone,
determines invalidation.

`nix/target-sdk.nix` returns format `spaghetti-extractor-target-sdk-v3` and
owns the generic consumer boundary: `workflow.pe32`, lower-level `analysis`,
`candidate`, `lifting`, and `validation` constructors, pinned `profiles`,
`sources`, `kernels`, `tools`, `fixtures`, and
`target.pe32Bundle`/`target.registry`.
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
| `nix/generated/python-module-index.json` | Generated local-import/resource graph and explicit production-role closures. |
| `nix/generated/test-suite-manifest.json` | Generated stable test/shard topology. It is repository-only developer metadata. |

`nix run .#dev -- refresh` regenerates both atomically, and
`nix run .#dev -- refresh --check` verifies freshness. The root check runs that
freshness check. Keeping both under `nix/generated/` makes machine ownership
visible beside handwritten constructors. `nix/flake-modules/`, `nix/tests/`,
`nix/test-suite-fixtures.nix`, `nix/test-suite-plan.nix`,
`nix/test-suite-shard.nix`, and `nix/test-suite.nix` are also repository-only
test/evaluation machinery excluded from the installed toolkit source.

All phase artifacts, reports, candidates, downloaded binaries, extracted
target inputs, and evaluation receipts are generated data. They belong in the
Nix store or ignored `private/`, `build/`, `outputs/`, and `result*` paths, not
in Git. Machine-generated JSON reports do not belong under `docs/`.

## Profiles And Catalogs

`profiles/README.md` defines profile authority and ownership, while
`profiles/catalog.json` assigns every profile an exact role and validator. The
active reviewed profiles are:

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
`pe32-i686-core-smoke-v2.json` is the small reviewed smoke catalog. Larger
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

Target registration is analysis-first. A bundle may initially omit component
intent and its default configuration; extraction, authority diagnostics, and
component proposals remain available in that state. Reviewed component intent
enables the component and candidate families atomically, so the SDK never
invents a placeholder configuration or treats a proposal as operator intent.

The corpus flake exports the complete artifact family at
`legacyPackages.x86_64-linux.targets.<id>`, the supported operator tree at
`operatorTargets.<id>`, its pure discovery metadata at `operatorIndex.<id>`,
and regression/acceptance checks at `targetChecks.<id>` and
`targetAcceptanceChecks.<id>`. Listing the registry or artifact families does
not force the corresponding authority graph. Candidate builds and suites are
addressed only through the operator tree, avoiding a second public naming
scheme.

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
- `test_external_*`, `test_machine_abi.py`, `test_machine_import_profiles.py`: ABI and canonical external calls.
- `tests/unit/libraries/`, `test_source_operation_catalog.py`: library
  recognition, refinement, replacement planning, and non-authoritative source rendering.
- `tests/unit/reconstruction/control/`: jump-table recovery, rooted control,
  overlapping starts, and semantic clustering.
- `candidate/`: fallback, native runtime, PE composition, and candidate-test integration.
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
   `sdk.target.pe32Bundle { ... }`.
3. Register the directory in `targets/registry.nix`; structured artifacts and
   aggregate checks are exported automatically.
4. Do not edit the root flake or add target Python, Lean, or private-constructor
   imports.
5. If a reusable capability is missing, implement it under `src/` or the SDK,
   validate it with a generic fixture, and then consume it from the target.

This rule keeps DX-Ball, jq, GNU Hello, and future programs as clients of one
toolkit rather than alternate architectures embedded in the repository.
