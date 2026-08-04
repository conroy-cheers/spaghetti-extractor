# Spaghetti Extractor Repository Map

> **Status:** Canonical repository ownership and dependency map.
>
> This file describes what exists, why it exists, which parts are authoritative,
> and how the parts compose. Update it when adding, removing, moving, or changing
> the authority of a subsystem, public command family, generic Nix constructor,
> validation target, profile family, or test lane.

## 1. Project Shape

Spaghetti Extractor is a generic, static-first toolkit for reconstructing x86
Windows PE32 programs. The primary delivery path is a high-assurance executable
machine IR, a generated low-level candidate, and progressive replacement with
portable C. Strict binary-to-binary and source-relative Lean theorem tracks are
retained as stronger optional assurance profiles; they do not define completion
of the primary reconstruction workflow.

The repository has three deliberately different kinds of code:

1. **Generic toolkit:** installable Python, reviewed Lean kernels, reusable Nix
   constructors, schemas, profiles, and independent ISA oracles.
2. **Validation consumers:** GNU Hello, jq, and DX-Ball bundles under `targets/`.
   These may contain target-specific source, intent, adapters, and build graphs.
3. **Generated evidence:** Nix outputs and disposable local work products. These
   are not source and must not be checked into `docs/`, `src/`, or `targets/`.

The dependency rule is one-way:

```text
generic Python / Lean / Nix
             |
             v
      target bundle adapters
             |
             v
        flake composition
             |
             v
 content-addressed generated evidence
```

Generic modules must not import a target bundle. `flake.nix` is the composition
root allowed to instantiate generic constructors with target-specific inputs.
`tests/test_repository_boundaries.py` and `repository-boundaries-check` enforce
this boundary.

## 2. End-To-End Data Flow

```text
exact original PE (static input only)
  |
  +-- PE parsing, executable inventory, decoding, ABI/profile selection
  |       |
  |       +-- independent ISA qualification
  |       |     XED catalog proposal
  |       |     + Bochs veto oracle
  |       |     + Unicorn veto oracle
  |       |     + 80386 hardware corpus
  |       |     + Lean concrete semantics
  |       |
  |       +-- strict relational proof track
  |       |     mapping -> side extraction -> normalization
  |       |     -> region facts -> register replay
  |       |     -> semantic/memory/composition products
  |       |     -> generated Lean DAG -> theorem audit
  |       |
  |       +-- primary reconstruction track
  |             opaque static export -> rooted state machine
  |             -> canonical machine IR -> generated interpreter/C0
  |             -> native PE32 candidate
  |
  +-- Stage B progressive reconstruction
          component discovery and selection
          -> machine/logical interface refinement
          -> portable-C workspace and CBMC checks
          -> candidate-only regional integration
          -> qualified override registry
          -> source project and library-call substitution
          -> candidate-only functional/upstream suites
          -> auditable assurance report
```

The original binary may be parsed, decoded, and otherwise consumed statically.
It is not a runtime oracle during Stage B repair. Runtime comparison uses the
qualified IR model or generated baseline. Target acquisition checks, such as
the DX-Ball installer smoke, are target provenance tests and are not Stage B
repair evidence.

## 3. Authority And Evidence

| Class | Meaning | Examples |
| --- | --- | --- |
| Reviewed generic rule | Intended reusable semantics or validation logic | Lean kernels, schema validators, Nix constructors |
| Untrusted proposal | May guide work but cannot authorize a claim | Capstone, XED metadata, Ghidra, linker maps, Python analysis, recovered names |
| Checked formal evidence | Lean has checked the stated theorem and axiom policy | compiled `.olean` graph, final theorem audit |
| Veto evidence | Can expose a defect but cannot prove universal correctness | Bochs, Unicorn, hardware vectors, Wine behavior tests |
| Target intent | Human-reviewed selection or source scoped to one binary | `targets/*/intent`, target source, target adapters |
| Generated artifact | Immutable result bound to exact inputs | Nix derivation outputs, reports, generated Lean/C, candidates |
| Assumption | Explicitly enlarges the trusted base | pinned compiler correctness, external-environment extensionality |

Formal `pass` is reserved for the strict Stage A theorem path. High-assurance,
candidate behavior, component qualification, and source-equivalence results use
different statuses and cannot be promoted to `pass` by Python or Nix assertions.

## 4. Top-Level Directory Map

| Path | Ownership | Purpose and usefulness | Relationships |
| --- | --- | --- | --- |
| `README.md` | Generic, authored | User-facing project orientation and common commands. | Points to the primary direction and this map. |
| `REPOSITORY_MAP.md` | Generic, authored | Canonical ownership, subsystem, and dependency inventory. | Base document for repository cleanup and future architecture changes. |
| `PLAN.md` | Historical formal track | Earlier mandatory-whole-program jq workflow. | Useful command history; superseded as primary plan by the high-assurance direction. |
| `flake.nix` | Composition root | Defines packages, checks, apps, dev shell, fixtures, and target instantiations. | The only generic-to-target composition point; currently a major concentration of logic. |
| `flake.lock` | Reproducibility | Pins Nixpkgs and flake dependencies. | Defines toolchain, Lean, Wine, emulator, compiler, and library identities. |
| `pyproject.toml` | Generic packaging | Setuptools package metadata, dependencies, console scripts, packaged Lean/Nix/profile data. | Deliberately excludes `targets/`. |
| `.envrc` | Developer shell | Enters the default flake shell through direnv. | Convenience only; accepted builds still go through Nix derivations. |
| `.gitignore` | Repository hygiene | Excludes Nix/dev outputs, private inputs, caches, scratch space, and `result*`. | Enforces the generated/authored boundary locally. |
| `src/` | Generic toolkit | Installable Python, reviewed Lean, and reusable component profiles. | Must remain target-neutral. |
| `nix/` | Generic build constructors | Content-addressed analysis, proof, ISA, component, library, source, and functional DAGs. | Must not import `targets/`; instantiated by `flake.nix` or target `default.nix`. |
| `profiles/` | Generic reviewed data | ABI, import, external-operation, indirect-target, and compiler profiles. | Consumed by extraction, relation contracts, Stage B rendering, and targets. |
| `isa-catalogs/` | Generic untrusted data | Curated XED-derived instruction forms and defined-output masks. | Drives oracle cases; never closes a proof directly. |
| `tools/` | Generic external adapters | Bochs harness, XED extractor, Ghidra exporter, and small PE fixtures. | Built or invoked by Nix and Python frontends. |
| `targets/` | Validation consumers | Authored target manifests, intent, source, adapters, tests, and target Nix DAGs. | Consume generic tooling; generated target evidence stays in the Nix store. |
| `tests/` | Validation | Python unit, integration, source-shape, Lean elaboration, and Nix architecture tests. | Still contains target-specific GNU tests; this is explicit migration debt. |
| `fixtures/` | Tiny authored generic fixtures | Currently only the tiny source-equivalence state machine. | Former target fixtures moved to `targets/`; empty local directories are disposable. |
| `docs/` | Generic authored design | Normative and historical architecture, schema, qualification, and workflow documents. | Machine-generated JSON reports are forbidden here. |
| `outputs/` | Ignored generated work | Local reports from ad hoc runs. | Not an input to accepted builds; currently ignored by the user's global `out/` rule. |
| `private/` | Ignored local inputs | Private binaries, SDK/media artifacts, and VM state. | May be explicitly supplied to target builds; must never be a hidden generic input. |
| `.direnv/`, `__pycache__/` | Generated caches | Local environment and Python bytecode. | Disposable and non-authoritative. |
| `.agents/`, `.codex/` | Empty local integration points | Reserved agent/tool configuration directories. | No current project subsystem depends on them. |

## 5. Generic Python Package

The installed package is `src/spaghetti_extractor/`. Its 86 top-level modules
form the public facade and the non-relational reconstruction stack.

### 5.1 Entry Points And Shared Infrastructure

| Modules | Purpose | Consumers |
| --- | --- | --- |
| `__init__.py`, `__main__.py`, `cli.py` | Package entry and the broad `spaghetti-extractor` command facade. | Users, Nix phase wrappers, tests. |
| `slice_loop.py` | Focused `prepare/next/build/check` repair loop driven by a target-provided profile. | `spaghetti-extractor-slice`, currently jq. |
| `target_intent.py` | Typed target-bundle manifest and authored-intent validation. | `nix/stage-b-target-intent.nix`, boundary tests. |
| `artifact_formats.py` | Central artifact format identifiers. | Most producers and validators. |
| `errors.py`, `util.py`, `stage_binary.py` | Shared errors, hashing/JSON utilities, and binary input validation. | All pipeline families. |

`cli.py` is a facade, not an acceptable broad dependency for isolated Nix
phases. Phase packages use narrow wrappers and source closures.

### 5.2 PE, Static Contract, ABI, And Provenance

| Modules | Purpose and usefulness |
| --- | --- |
| `pe.py`, `recursive_decode.py` | PE32 structure access and conservative rooted instruction-view discovery. |
| `contract_tools.py`, `_contract_tools/common.py`, `_contract_tools/map_generation.py`, `_contract_tools/reference_contract.py`, `_contract_tools/abi.py`, `_contract_tools/symbolic_execution.py`, `_contract_tools/candidate_feedback.py` | Stable contract facade plus map generation, symbolic block evidence, ABI extraction, reusable reference contracts, and actionable candidate feedback. |
| `machine_abi.py`, `machine_import_profiles.py`, `import_abi.py`, `call_arguments.py`, `internal_call_summaries.py` | Machine-level call conventions, imports, argument recovery, and internal-call summaries without trusting C prototypes. |
| `finite_value_domain.py`, `provenance_domain.py`, `value_provenance.py`, `operation_provenance.py`, `interface_provenance.py` | Bounded value origins, address/target provenance, operation-table propagation, and fail-closed finite joins. |
| `external_function_ast.py`, `external_interface_ast.py`, `external_interface_profiles.py`, `external_operation_profiles.py`, `stage_b_api_catalog.py`, `callable_external_runtime.py` | Extract and normalize Win32/COM/function-table signatures, machine operations, source renderings, and candidate-side callable resolver routes. |
| `opaque_reconstruction.py`, `rooted_state_machine.py` | Static map-blind export and conservative augmentation of direct rooted control. |
| `ghidra.py` | One-time optional Ghidra bootstrap integration. Decompiler output remains private and untrusted. |

### 5.3 ISA Qualification

The `isa_*` modules form one subsystem:

- Catalog/model/generation: `isa_catalog.py`, `isa_semantic_forms.py`,
  `isa_corpus_generator.py`, `isa_catalog_enrichment.py`, `isa_campaign.py`.
- Backends: `isa_conformance.py`, `isa_conformance_lean.py`,
  `isa_conformance_unicorn.py`, `isa_conformance_bochs.py`,
  `isa_conformance_80386.py`, `isa_conformance_nix.py`.
- Selection and orchestration: `isa_cli.py`, `isa_side_adapter.py`,
  `isa_kernel_qualification.py`.

These modules compare masked concrete observations and localize unsupported or
disputed semantic forms. Oracle agreement is veto-only; Lean still owns any
formal semantic claim.

### 5.4 Machine-IR Candidate Generation

| Modules | Purpose and relationship |
| --- | --- |
| `stage_b_state_machine.py` | Converts Stage A static exports into canonical transfer JSONL. |
| `stage_b_c_backend.py`, `stage_b_typed_x87.py` | Lowers normalized transfer effects and x87 operations into generated C. |
| `stage_b_interpreter_backend.py` | Emits interpreter source and immutable program data from machine IR. |
| `stage_b_engine_layout.py`, `stage_b_native_engine.py`, `stage_b_native_binding.py` | Define the PE32 bridge, exact layout, and machine/runtime binding. |
| `stage_b_native_runtime.py`, `stage_b_native_build.py`, `stage_b_interpreter_native_build.py`, `stage_b_pe_composer.py` | Build the freestanding runtime, per-object CA graph, and final PE candidate. |
| `stage_b_reachable_slice.py` | Selects transfers only from checked rooted reachability evidence. |
| `stage_b_skeleton.py` | Generates target-neutral skeletons and contract-guided C, including only contract-backed reference data spans. |

This is the dependable, low-level baseline path. It intentionally permits ugly
full-machine-state C and does not infer that a successful compile is equivalent.

### 5.5 Candidate Feedback And Runtime Vetoes

| Modules | Purpose and relationship |
| --- | --- |
| `stage_b_contract.py` | Contract smoke, work-item extraction, coverage, focused-unit checking, and underconstraint audit. |
| `stage_b.py` | Candidate validation, crash/delta explanation, decompiler export, and source-mapped repair ranking. |
| `stage_b_provenance.py` | Content-binds candidate-only build provenance. |
| `stage_b_functional.py` | Materializes and runs curated/upstream expected-output suites without executing the original. |

These diagnostics may return `incomplete` or `violated` with source locations;
they cannot weaken Stage A or authorize a formal verdict.

### 5.6 Progressive Reconstruction And Components

| Modules | Purpose and relationship |
| --- | --- |
| `reconstruction_ir.py`, `reconstruction_control.py`, `reconstruction_contract_analysis.py`, `reconstruction_composition.py` | Sanitize machine IR, derive control/cluster contracts, and compose reconstruction evidence. |
| `reconstruction_workspace.py`, `region_replacement.py`, `reconstruction_validation.py`, `reconstruction_assurance.py` | Create typed-C workspaces, validate replacements, promote registries, and aggregate assurance. |
| `component_discovery.py`, `component_selection.py`, `semantic_components.py` | Propose an overlapping component lattice, materialize reviewed selections, and validate exact membership/coverage. |
| `component_interface.py`, `component_profile.py`, `component_workspace.py` | Refine machine boundaries to logical interfaces and create/check portable-C workspaces. |
| `bounded_component_contract.py`, `finite_component_contract.py` | Generic finite or bounded proof/checking support used by profiles. |

`src/spaghetti_extractor_component_profiles/` contains 19 independently
sourced implementation profiles:

`basename_prefix_selection_v1.py`, `bounded_last_component_v1.py`,
`bounded_pairwise_byte_compare_v1.py`, `bounded_wide_string_length_v1.py`,
`constant_buffer_write_v1.py`, `constant_string_collection_v1.py`,
`external_zero_predicate_v1.py`, `mutable_token_cursor_match_v1.py`,
`opaque_output_pipeline_v1.py`, `opaque_value_consumer_v1.py`,
`opaque_value_label_prefix_v1.py`, `opaque_value_service_prefix_v1.py`,
`optional_fp64_record_callback_v1.py`, `pe32_header_query_v1.py`,
`prefixed_unary_byte_predicate_v1.py`, `static_atomic_word_v1.py`,
`status_normalize_terminal_service_v1.py`,
`stdcall_wide_conversion_iteration_v1.py`, and
`windows_path_info_scan_v1.py`.

They cover bounded byte/string operations, path scanning, PE header queries,
callbacks, static atomics, optional FP64 callbacks, token matching, opaque
value/output services, status normalization, and Win32 conversion loops. A
profile owns generated source, adapter, cases, CBMC harness, activation domain,
and qualification scope. It must remain generic and be validated by a small
fixture before target use.

### 5.7 Library Recognition And Source Lifting

| Modules | Purpose and relationship |
| --- | --- |
| `linked_libraries.py`, `linked_library_contracts.py` | Index COFF/OMF/archive/PE artifacts, infer library constellations, classify total machine-IR ownership, and plan only qualified replacements. |
| `source_call_substitution.py`, `source_operation_catalog.py` | Classify machine call frontiers, bind callable contracts to readable source calls, inventory Clang AST calls, and audit candidate dependencies. |
| `source_graph.py`, `source_project.py` | Bind whole source projects and component evidence to exact machine units. |

Library identity is proposal evidence, not replacement authority. A reusable
machine-to-logical interface plus a qualified portable implementation is still
required. Unknown or ambiguous islands retain machine-IR fallback.

### 5.8 Source-Relative Experiment

`source_equivalence.py` and `native_source_equivalence.py` implement the
optional C0/native-source theorem experiment. The compiled result is only a
`conditional_pass` under a pinned compiler/toolchain correctness premise. This
track is useful research and assurance evidence, but it is not the primary
completion gate.

### 5.9 Structured Round-Trip Qualification

`src/spaghetti_extractor/roundtrip_fuzz/` checks that generic Stage A and Stage B
interfaces work on generated real PE32 programs without access to generator
ground truth during discovery:

- Model and generation: `model.py`, `semantic.py`, `inventory.py`,
  `generator.py`, `lowering.py`, `phase0.py`.
- Proof/discovery execution: `discovery.py`, `runner.py`, `qualification.py`,
  `image_contract.py`.
- Negative evidence and minimization: `violation.py`, `reducer.py`.
- Stage B round trip: `stage_b_roundtrip.py`, `semantic_c_mapping.py`.
- Audit/provenance: `genericity.py`, `provenance.py`, `metrics.py`.

The corpus covers equivalent transformations, deliberately incorrect mutations,
checked violation witnesses, reducer correctness, and Stage B regeneration. It
is a genericity and regression system, not an application-target proof.

## 6. Strict Relational Stage A Python

`src/spaghetti_extractor/relational/` is the strict formal pipeline. It has 96
root modules, 22 analysis modules, and 143 Lean-source emitters.

### 6.1 Public Boundary And Orchestration

- `api.py`, `interfaces.py`: stable Nix-only API and versioned parallel-work
  interfaces.
- `pipeline.py`, `nix_pipeline.py`, `build.py`, `preflight.py`,
  `preparation_cli.py`: phase ordering, Nix preparation/build, source-graph
  validation, narrow preparation worker, and cheap fail-fast checks.
- `mapping.py`, `mapping_cli.py`: untrusted static relation-map proposal.
- `contract.py`, `schema.py`, `model.py`, `ir.py`, `phases.py`: strict parsing
  and typed phase/contract records.
- `report.py`, `report_schema.py`, `diagnostics.py`, `worker_diagnostics.py`,
  `reference_contract.py`: final report audit, actionable feedback, and Stage B
  reference-contract projection.
- `artifacts.py`, `checked_artifacts.py`, `analysis_artifact.py`,
  `analysis_reference.py`: content identities and checked artifact boundaries.

### 6.2 Static And Pair Extraction

- Side-local inputs: `binary_inventory.py`, `side_extraction.py`,
  `side_extraction_artifact.py`, `side_isa_artifact.py`, `side_cli.py`.
- Pair-normalized semantics: `extraction.py`, `pair_normalization.py`,
  `pair_normalization_artifact.py`, `pair_normalization_cli.py`.
- Region-local facts: `region_facts.py`, `region_facts_artifact.py`,
  `region_facts_cli.py`.
- Semantic boundaries: `semantic_cutpoints.py`, `x86_instruction_profile.py`,
  `x87_profile.py`, `definedness.py`.

Static extraction on each binary is independent of the relation. Pair-specific
normalization consumes immutable side artifacts and is separately cached.

### 6.3 Register Dataflow And Replay

The register pipeline is deliberately split so each semantic fact is computed
once:

```text
proposal seed
  -> register_dataflow_problem.py / register_dataflow_compile.py
     / register_dataflow_problem_cli.py / register_dataflow_cli.py
  -> register_dataflow_plan_cli.py
  -> register_dataflow_packs.py / register_dataflow_worker_cli.py
  -> register_dataflow_aggregate.py / register_dataflow_aggregate_cli.py
  -> register_dataflow_solution.py / register_dataflow_solver.py
     / register_dataflow_summary.py
  -> register_replay.py / register_replay_cli.py
  -> checked replay artifact
```

Supporting modules are `register_transfer_core.py`, `register_transfer_ir.py`,
`register_dataflow_formats.py`, `register_dataflow_artifact.py`,
`register_dataflow_seed.py`, `register_dataflow_summary_format.py`,
`register_dataflow_summary_cli.py`, `register_dataflow_compare.py`, and
`register_dataflow_compare_cli.py`, `register_replay_artifact.py`, and
`register_replay_format.py`. The old observed table is only a migration oracle;
final assembly consumes checked replay.

### 6.4 Product Branches And Assembly

| Branch | Producer modules | Result |
| --- | --- | --- |
| Proposal closure | `proposal_cli.py`, `proposal_artifact.py`, `analysis.py` | Global untrusted control/register/call/memory proposals. |
| Semantic products | `semantic_products.py`, `semantic_products_artifact.py`, `semantic_products_format.py`, `semantic_products_cli.py` | Semantic IR and invariants, independent of register solving. |
| Memory products | `memory_products.py`, `memory_products_artifact.py`, `memory_products_format.py`, `memory_products_cli.py` | Memory contracts and external callsites after register replay. |
| Composition products | `composition_products.py`, `composition_products_artifact.py`, `composition_products_format.py`, `composition_products_cli.py` | Segments, product graph, ISA requirements, and proof IR. |
| Final assembly | `assembly.py`, `assembly_cli.py` | Validates identities and combines products without rerunning discovery. |

Other proof-IR support modules are `original_cutpoint_graph_ir.py`,
`direct_call_proposal_ir.py`, `runtime_frame_artifact.py`,
`runtime_value_carry_ir.py`, `stack_dynamic_control_ir.py`,
`callsite_preservation.py`, `engine_segments.py`, `full_machine_lockstep.py`,
`access_domain_receipts.py`, `isa_requirements.py`, `isa_qualification.py`,
`semantic_coverage.py`, `semantic_coverage_registry.py`, and
`cache_qualification.py`.

### 6.5 Proposal Analyses

`relational/analyses/` contains untrusted evidence synthesis, grouped as:

- Control and targets: `control.py`, `semantic_control.py`, `linked_control.py`,
  `affine_linked_control.py`, `callbacks.py`.
- Registers and fixed points: `registers.py`, `register_static.py`,
  `register_lattice.py`, `dataflow.py`, `dataflow_schedule.py`, `fixedpoint.py`.
- Stack, frames, memory, calls: `stack.py`, `frames.py`, `memory.py`,
  `callsite.py`, `external.py`, `region_local.py`.
- Composition inputs: `segments.py`, `invariants.py`, `predicates.py`, `x87.py`.

No proposal result is acceptance evidence. Unsupported operations, incomplete
closure, ambiguous targets, or exhausted finite domains remain explicit.

### 6.6 Lean Source Emitters

`relational/lean/` converts checked/proposed artifacts into binary-specific
Lean data and compact certificates. The 143 modules are organized by output:

- Foundations and shared generation: `common`, `identity`, `expressions`,
  `definitions`, `generation`, `analysis_source`, `compiler`, `scanner`,
  `axiom_audit`, `artifact_byte_packs`, `pe_byte_packs`.
- Core relational proof: `segments`, `composition`, `acceptance`,
  `acceptance_plan`, `acceptance_running`, `definedness`, `callbacks`,
  `lockstep_environment`.
- Value/control/memory authorities: modules prefixed `finite_static_word`,
  `reachable_static_pointer_slot`, `relocated_writable_static_pointer_slot`,
  `register_*`, `stack_*`, `runtime_*`, `nullable_code_pointer`,
  `original_indirect`, `control_value_provenance`, and `affine_*`.
- Internal/external calls: modules prefixed `internal_direct_call`,
  `callable_external`, `external_tail`, `canonical_external_response`,
  `static_machine_import_contracts`, and
  `universal_paired_external_environment`.
- Generated interpreter path: `interpreter.py`, `interpreter_transfer.py`,
  `interpreter_normalization.py`, `interpreter_semantic_refinement.py`,
  `interpreter_x87.py`, and the `interpreter_kernel_*` family.
- Mixed machine/source path: `interpreter_mixed_*`,
  `interpreter_original_carrier_binding`, `interpreter_native_launch`,
  `interpreter_world_bridge`, and `interpreter_whole_program_acceptance`.
- Source-relative path: `native_source_*`, `source_execution_domain`,
  `source_program_certificate`, `source_target_routing`,
  `original_execution_evidence`, and `source_equivalence_final_report`.

This directory intentionally emits target data but contains no target names.
Target-only combinations live in target adapter packages. The near one-to-one
emitter/Lean-module growth remains a proof-engineering and cleanup concern.

## 7. Reviewed Lean Kernel

`src/spaghetti_extractor/lean/StageA/` contains 262 generic Lean modules. There
is no Lake project; Nix supplies pinned Lean and compiles modules directly from
their declared imports. Generated binary-specific modules live only in Nix
outputs.

### 7.1 Foundations

- `Formal.lean`: exact PE32/x86 decoding and foundational machine semantics.
- `X87.lean`, `RelationalX87*.lean`: x87 state, decode, machine, and relational
  semantics.
- `ISAConformance.lean`, `ISAConformanceRunner.lean`, `ISAQualification.lean`,
  `RelationalISAQualification.lean`: concrete semantic execution and qualified
  form selection.
- `RelationalDecode.lean`, `RelationalMachine.lean`, `RelationalMemory.lean`,
  `RelationalExactExpr.lean`, `RelationalValueProvenance.lean`: normalized
  instruction, state, memory, expression, and origin foundations.

### 7.2 State, Execution, And Composition

- `Relational.lean`, `RelationalInvariant.lean`, `RelationalExecution.lean`,
  `RelationalImage.lean`: authoritative state relation, invariants, execution,
  and structural image coverage.
- `RelationalSegment.lean`, `RelationalCallRefinement.lean`,
  `RelationalComposition.lean`, `RelationalIndexedCertificateComposition.lean`:
  paired paths, calls, indexed product graph, and composition.
- `RelationalEnvironment.lean`, `RelationalExternalOperation.lean`,
  `RelationalLockstepEnvironment.lean`, `RelationalCallbacks.lean`:
  machine-level external calls, stateful worlds, and nested callbacks.
- `RelationalCertificates.lean`: strict whole-program certificate and final
  soundness theorem.

### 7.3 Runtime Provenance And Memory Families

The `RelationalCallableExternal*`, `RelationalControlValueProvenance`,
`RelationalRegister*`, `RelationalStack*`, `RelationalRuntime*`,
`RelationalNullableCodePointer*`, `RelationalReachableStaticPointerSlot`,
`RelationalRelocatedWritableStaticPointerSlot`, and `RelationalAffine*`
families implement checked origins, finite target sets, framed updates,
dynamic/static ranges, and indirect exits. `RelationalOriginal*` modules apply
those generic rules to original-side execution invariants and preservation.

### 7.4 Interpreter And Mixed Execution

- `RelationalInterpreter*.lean`: normalized semantic interpreter, machine/world
  bridges, exact decoding, transfer refinement, and acceptance.
- `RelationalInterpreterKernel*.lean`: compiled C interpreter kernel, ABI,
  lookup, step/run/invoke, callbacks, cdecl epilogues, operation routes,
  effects, frame checks, result encoding, and x87 execution.
- `RelationalInterpreterMixed*.lean`: finite mixtures of original-machine and
  generated/native execution, source classifier, component composition,
  launch graph, runtime foundation, and final mixed acceptance.

The kernel-operation checker family is the intended reflective consolidation:
generated artifacts provide compact route/effect/frame data and stable generic
soundness theorems check it. Several older specialized modules remain alongside
it and are candidates for consolidation after target migration.

### 7.5 Source-Relative Formal Track

`RelationalC0.lean`, `RelationalSource*.lean`, and
`RelationalNativeSource*.lean` model canonical source execution, source world,
compiler premise, response families, and conditional acceptance. This is a
separate trust profile and cannot authorize binary-to-binary `pass`.

## 8. Nix Build System

Nix is the only first-class build, proof, test, and cache boundary. Setuptools
packages Python inside Nix; Lean is compiled inside Nix; MinGW/Clang/CBMC/Wine
are phase inputs. Host-side Python and Lean runs are development tests only.

All substantial reusable derivations are content-addressed where their role
permits it. CA derivations improve substitution, but phase granularity and
source closures determine invalidation. Remote builders are selected through
`nix/stage-a-builders`, `nix/stage-a-lightweight-ca-builders`, and trusted keys
in `nix/stage-a-builder-public-keys`.

### 8.1 Generic Nix Constructors

| File | Purpose | Primary outputs/consumers |
| --- | --- | --- |
| `stage-a-lean-graph.nix` | Dynamic generated Lean module DAG, resource classes, dependency `.olean`s, final audit. | Full relational and target proof graphs. |
| `stage-a-lean-compact.nix` | One-derivation evaluator for tiny Lean graphs. | Small fixtures where scheduling overhead dominates. |
| `stage-a-relational-analysis-graph.nix` | Static/pair extraction and semantic product DAG. | Prepared proofs and jq/GNU analysis. |
| `stage-a-register-dataflow-graph.nix` | Coarse or sharded SCC register solver/replay graph. | Relational analysis. |
| `stage-a-isa-conformance.nix` | One backend/corpus conformance derivation. | ISA qualification graph. |
| `stage-a-isa-qualification-graph.nix` | Lean/Unicorn/Bochs execution, masked comparison, selection, campaign, bundle. | Exact-PE semantic qualification. |
| `stage-a-roundtrip-corpus.nix` | Generated or pinned round-trip cases, proof packs, Stage B round trips, qualification. | Genericity/fuzz campaign. |
| `stage-a-roundtrip-smoke.nix` | Cheap static-only fail-fast corpus gate. | Runs before expensive proof cases. |
| `stage-a-source-equivalence.nix` | Pinned freestanding C0 candidate and toolchain profile. | Optional source-relative experiment. |
| `stage-a-ca-derivation-smoke.nix` | Minimal CA producer/consumer capability test. | Nix infrastructure validation. |
| `bochs-conformance.nix` | Pinned headless Bochs 3.0 build and instrumentation runner. | ISA oracle shards. |
| `singlestep-80386-conformance.nix` | Imports, converts, shards, and aggregates pinned real-hardware vectors. | 80386 ISA evidence. |
| `stage-b-python-sources.nix` | Central phase-specific Python filesets. | Prevents broad source changes from invalidating unrelated Stage B phases. |
| `stage-b-component-analysis.nix` | Reusable binary-to-machine-IR/component-proposal front half. | New opaque targets and smoke fixture. |
| `stage-b-component-discovery.nix` | CA component proposal generation. | Selection. |
| `stage-b-component-selection.nix` | Resolves authored stable selections against current proposals. | Component catalogs/workspaces. |
| `stage-b-component-interfaces.nix` | Per-component machine/logical interface synthesis and checking. | Workspace qualification. |
| `stage-b-semantic-components.nix` | Validates declarations and coverage into a component catalog. | Workspace DAG. |
| `stage-b-semantic-component-workspaces.nix` | Slices, scaffolds, CBMC checks, integrations, qualification, registry. | Progressive component lifting. |
| `stage-b-reconstruction-workspace.nix` | Older cluster-oriented typed-C replacement DAG. | Regional lifting comparison path. |
| `stage-b-interpreter-package.nix` | Generates immutable interpreter package from machine IR. | Baseline and regional checks. |
| `stage-b-native-object-graph.nix` | Per-source CA compilation and final native candidate assembly. | Fast incremental candidate builds. |
| `stage-b-linked-libraries.nix` | Artifact indexes, locks, constellation inference, island classification, interface qualification, replacement plan. | Library recognition/substitution. |
| `stage-b-source-call-substitutions.nix` | Machine frontier through Clang source-call binding and dependency audit. | Whole-source projects. |
| `stage-b-source-component-assurance.nix` | Aggregates source, call, component, functional, and upstream evidence. | Target assurance report. |
| `stage-b-functional-suite.nix` | Per-case candidate-only Wine shards plus aggregate. | Curated behavior tests. |
| `stage-b-upstream-shell-suite.nix` | Per-script upstream suite shards plus aggregate. | GNU Hello and other source projects. |
| `stage-b-target-intent.nix` | Resolves target manifests and authored selectors without generated evidence. | Every validation bundle. |

Auxiliary Nix workers are `callable-external-runtime-contract.py`,
`interpreter-mixed-chunked-acceptance.py`, `stage-a-lean-term-receipts.py`,
`stage-a-proof-source-aggregate.py`, and `stage-a-semantic-coverage.py`. They are
narrow derivation workers, not public orchestration APIs. Builder policy lives
in `stage-a-builders`, `stage-a-lightweight-ca-builders`, and
`stage-a-builder-public-keys`; the two `nix/fixtures/stage-a-remote-lean-smoke/`
modules validate dependency transfer and `.olean` reuse on remote builders.

### 8.2 Flake Surface

At this snapshot the flake exposes 675 package attributes. This is an
implementation DAG, not 675 stable user APIs:

| Family | Count | Meaning |
| --- | ---: | --- |
| Stage A GNU Hello | 266 | Fine-grained target proof, extraction, source, and audit phases. |
| Stage B GNU Hello | 87 | Reconstruction, component, library, source, candidate, and behavior phases. |
| Stage A relational generic | 103 | Per-case proof tests, caches, and graph integration. |
| Stage B jq | 72 | Components, linked libraries, source project, candidate, and behavior. |
| Stage A jq | 31 | Fixture pair, extraction, proof preparation, contract, and audit. |
| Stage A round trip | 31 | Corpus generation, packs, Lean kernels, and qualification. |
| Stage A other | 32 | Generic fixtures, minimal WinAPI/exit/C0 lanes, and boundary checks. |
| Stage A ISA | 10 | Catalog, corpora, oracle reports, qualification, and cache. |
| Stage A DX-Ball | 11 | Acquisition, headless smoke, inventory, profiles, and static exports. |
| Stage B generic/other | 5 | Generic component/library smoke and tiny source candidate. |
| Stage B DX-Ball | 1 | Target operation/source catalog output. |
| Tools/apps/other | 26 | Package, narrow phase executables, Bochs, XED, and 80386 corpus tools. |

The live package inventory is always available with:

```sh
nix eval .#packages.x86_64-linux --apply builtins.attrNames --json
```

Stable reusable flake library constructors are:

`mkStageALeanGraph`, `mkStageARelationalAnalysisGraph`,
`mkStageAISAQualificationGraph`, `mkStageARoundtripCorpus`,
`mkStageARoundtripSmoke`, `mkStageASourceEquivalence`,
`mkStageBComponentAnalysis`, `mkStageBFunctionalSuite`,
`mkStageBLinkedLibraryAnalysis`, `mkStageBSourceCallSubstitutions`,
`mkStageBSourceComponentAssurance`, and `mkStageBUpstreamShellSuite`.

The ten app attributes are `default`, `spaghetti-extractor`,
`spaghetti-extractor-slice`, `stage-a-gnu-hello-proof`,
`stage-a-fixtures-root`, `stage-a-gnu-hello-fixtures-root`,
`stage-a-jq-fixtures-root`, `stage-a-minimal-hello-fixtures-root`,
`stage-a-roundtrip-spike-corpus-root`, and `stage-b-jq-skeleton-root`. The
`*-root` apps expose immutable generated artifacts for inspection; they are not
separate validation authorities.

The default dev shell supplies Python dependencies, Lean, Z3, Capstone,
Unicorn, PE tooling, cross-compilers, CBMC, Wine, and supporting build tools.

### 8.3 Narrow Phase Executables

The flake packages separate static responsibilities into
`spaghetti-extractor-mapping`, `-side`, `-normalize`, `-region-facts`,
`-proposal`, `-register-dataflow-problem`, `-dataflow-plan`, `-dataflow-worker`,
`-dataflow-aggregate`, `-dataflow-summary`, `-dataflow-compare`,
`-register-replay`, `-semantic-products`, `-memory-products`,
`-composition-products`, `-analysis`, and `-preparation`.

This boundary is valuable because changing diagnostics, a proof emitter, or a
candidate region should not invalidate PE extraction, normalization, or other
unrelated semantic work.

## 9. Public Command Families

The main CLI currently exposes more than one hundred commands. They are grouped
here by subsystem; the exact argument contract is `spaghetti-extractor --help`
and each subcommand's `--help`.

| Family | Commands |
| --- | --- |
| Interfaces and strict proof | `stage-a-export-interfaces`, `stage-a-prove`, `stage-a-prepare-relational`, `stage-a-build-relational`, `stage-a-check-proof`, `stage-a-diff-semantic-cache` |
| Static maps/contracts | `stage-a-generate-map`, `stage-a-generate-relation-contract`, `stage-a-export-reference-contract`, `stage-a-smoke-contract`, `stage-a-explain-obligations`, `stage-a-diff-obligations` |
| ISA | `stage-a-check-isa-conformance`, worker-only `stage-a-check-isa-conformance-worker`, `stage-a-inventory-isa-requirements`, `stage-a-adapt-side-isa-qualification`, `stage-a-enrich-side-isa-catalog`, `stage-a-qualify-isa-semantics`, `stage-a-normalize-isa-catalog`, `stage-a-plan-isa-qualification`, `stage-a-generate-isa-corpus`, `stage-a-build-isa-kernel-qualification`, `stage-a-select-isa-kernel-qualification`, `stage-a-import-80386-conformance` |
| Round-trip qualification | `stage-a-fuzz-generate`, `stage-a-fuzz-discover`, `stage-a-fuzz-run`, `stage-a-prepare-violation`, `stage-a-audit-violation`, `stage-a-fuzz-reduce` |
| Reconstruction export | `stage-a-export-opaque-reconstruction`, `stage-a-expand-import-abi-policy`, `stage-a-export-machine-ir`, `stage-a-qualify-reconstruction`, `stage-a-build-assurance-report` |
| Low-level Stage B | `stage-b-plan-reconstruction`, `stage-b-export-decompiler`, `stage-b-generate-skeleton`, `stage-b-generate-semantic-c`, `stage-b-augment-padding-bridges`, `stage-b-augment-rooted-views`, `stage-b-select-reachable-transfers`, `stage-b-generate-interpreter`, `stage-b-generate-native-engine`, `stage-b-generate-native-runtime` |
| Native candidate DAG | `stage-b-prepare-interpreter-native-objects`, `stage-b-compile-interpreter-native-object`, `stage-b-assemble-interpreter-native-objects`, `stage-b-build-interpreter-candidate`, `stage-a-generate-engine-segments`, `stage-b-generate-link-roots`, `stage-b-generate-candidate-provenance` |
| Contract feedback | `stage-b-check-contract`, `stage-b-audit-contract`, `stage-b-extract-work-items`, `stage-b-contract-coverage`, `stage-b-check-unit`, `stage-b-validate-candidate`, `stage-b-explain-delta`, `stage-b-diff-delta`, `stage-b-extract-candidate-crash` |
| Components | `stage-b-discover-components`, `stage-b-select-components`, `stage-b-validate-components`, `stage-b-synthesize-component-interface`, `stage-b-check-component-interface`, `stage-b-create-component-workspace`, `stage-b-create-component-slices`, `stage-b-build-regional-kernel`, `stage-b-rebind-component-workspace`, `stage-b-check-component`, `stage-b-qualify-component`, `stage-b-promote-components` |
| Older cluster replacements | `stage-b-create-replacement`, `stage-b-rebind-replacement`, `stage-b-check-replacement`, `stage-b-run-replacement-check`, `stage-b-promote-replacements`, `stage-b-reconstruction-status`, `stage-b-check-semantic-claim` |
| External operations | `stage-b-render-source-operations` |
| Library recognition | `stage-b-bind-library-artifact-inputs`, `stage-b-index-library-artifacts`, `stage-b-lock-library-catalog`, `stage-b-bind-linked-island-review`, `stage-b-match-linked-islands`, `stage-b-propose-library-evidence`, `stage-b-infer-library-hypotheses`, `stage-b-refine-linked-islands`, `stage-b-derive-dynamic-library-requirements`, `stage-b-bind-interface-contract-catalog`, `stage-b-bind-linked-interface-assignments`, `stage-b-qualify-linked-interface`, `stage-b-plan-library-replacements` |
| Source-call substitution | `stage-b-generate-call-frontier`, `stage-b-derive-static-indirect-targets`, `stage-b-bind-callable-interface-catalog`, `stage-b-bind-source-substitution-catalog`, `stage-b-bind-call-substitution-assignments`, `stage-b-propose-source-components`, `stage-b-plan-call-substitutions`, `stage-b-inventory-source-calls`, `stage-b-bind-source-call-bindings`, `stage-b-propose-source-component-bindings`, `stage-b-check-source-call-bindings`, `stage-b-audit-candidate-dependencies`, `stage-b-bind-allowed-runtime-imports` |
| Whole source projects | `stage-b-bind-source-project`, `stage-b-assess-source-project`, `stage-b-assess-source-components` |
| Candidate behavior | `stage-b-materialize-upstream-suite`, `stage-b-run-functional-suite`, `stage-b-run-functional-case`, `stage-b-aggregate-functional-cases` |
| Source-relative proof | `stage-a-prepare-source-equivalence`, `stage-a-attest-c0-compilation`, `stage-a-build-source-equivalence`, `stage-a-generate-c0-proof-sources`, `stage-a-prepare-native-source-equivalence`, `stage-a-attest-native-source-compilation` |

The separate `spaghetti-extractor-slice` command has `prepare`, `next`, `build`,
and `check` subcommands. It consumes a target-provided profile rather than
embedding target behavior in the generic package.

## 10. Profiles And Catalogs

| Path | Format and role |
| --- | --- |
| `profiles/i686-mingw-freestanding-c0-v1.json` | Pinned C0 compiler/linker profile for the conditional source theorem. |
| `profiles/pe32-kernel32-lockstep-v1.json` | Machine-level Kernel32 call and footprint contracts. |
| `profiles/pe32-kernel32-console-lockstep-v1.json` | Minimal console protocol: standard handle, WriteFile, ExitProcess. |
| `profiles/pe32-msvcrt-lockstep-v1.json` | Stateful CRT allocation, lifetime, callback, memory, and termination contracts. |
| `profiles/pe32-msvcrt-machine-runtime-v1.json` | Static machine-call analysis profile for MinGW/MSVCRT runtime sites. |
| `profiles/pe32-kernel32-callable-resolvers-v1.json` | Resolver-produced callable target profile. |
| `profiles/pe32-static-cutpoints-and-paired-callables-v1.json` | Reviewed static cutpoints and paired callable target inventory. |
| `profiles/pe32-win32-system-dll-abi-policy-v1.json` | Generic system-DLL calling convention and ABI expansion rules. |
| `profiles/pe32-mingw-win32-function-extraction-v1.json` | AST extraction spec for Win32 function signatures. |
| `profiles/pe32-mingw-directx-interface-extraction-v1.json` | AST extraction spec for legacy DirectX COM interfaces and vtables. |
| `isa-catalogs/pe32-i686-core-smoke-v1.json` | Small enriched XED inventory used to validate the complete ISA qualification DAG. |

Profiles are theorem or analysis inputs, not API implementations. Selecting an
import identity does not prove its effects; reachable sites still require ABI,
argument, footprint, world, and continuation evidence.

## 11. External Tools And Oracles

| Tool | Files | Role and trust |
| --- | --- | --- |
| Bochs executor | `tools/bochs-conformance/`, `nix/bochs-conformance.nix` | Pinned headless protected-mode single-instruction executor. Independent veto-only oracle for registers, defined flags, bounded memory, control, faults, FS, and x87. |
| Unicorn backend | `isa_conformance_unicorn.py` | Fast independent concrete ISA oracle. Veto-only. |
| 80386 corpus | `nix/singlestep-80386-conformance.nix`, `isa_conformance_80386.py` | Pinned real-hardware vectors imported and sharded through Nix. Veto-only. |
| XED extractor | `tools/xed-isa-catalog/` | Emits complete pinned Intel XED template metadata. Untrusted inventory/generation input. |
| Ghidra exporter | `tools/ghidra/SpaghettiExtractorStageBExport.java`, `ghidra.py` | Optional one-time private decompiler/p-code/bootstrap metadata. Never proof authority and not rerun for ordinary source edits. |
| PE fixtures | `tools/stage-a-fixtures/` | Tiny assembly/C fixtures and deterministic PE construction helpers for semantic/proof tests. |
| Capstone | Python dependency | Fast static disassembly and proposal generation. Lean redecodes exact bytes for formal claims. |
| Z3 | Optional `proof` dependency | Local bitvector/array automation. Raw `unsat` cannot by itself close final acceptance. |
| CBMC | Nix dev/build input | Universal bounded-C component checks against generated harnesses. Component evidence only. |
| Wine + Xvfb | Nix target/functional derivations | Candidate-only behavior and target provenance tests. Every Wine invocation must be headless. |

The Bochs guest, instrumentation plugin, protocol, and runner are one subsystem.
It boots once per batch rather than once per vector. The XED, Bochs, Unicorn,
hardware, and Lean implementations are intentionally independent enough to
expose semantic disagreements.

Within `tools/bochs-conformance/`, `build-bochs.sh` builds the pinned emulator,
`build-guest.sh` plus `guest/{boot,guest}.{S,ld}` build the controlled protected-
mode guest, `instrument.{cc,h}` and `protocol.h` implement the batch observation
channel, and `spaghetti-bochs-conformance-runner` is the host adapter.
`tools/xed-isa-catalog/main.c` is the XED metadata extractor.
`tools/stage-a-fixtures/pe32_from_text.py` constructs deterministic PE images
from the tiny `stage_a_exit.S`, `stage_a_loop.S`, `stage_a_winapi_hello.S`, and
`stage_a_hello.c` programs.

## 12. Validation Targets

Every bundle has a `spaghetti-extractor-target-bundle-v1` `target.json` with a
stable ID, display name, exact input hash, and relative paths to authored data.

### 12.1 GNU Hello

`targets/gnu-hello/` is the most complete vertical integration target and the
largest target bundle: 77 authored files and approximately 53,600 lines.

- `target.json`: bundle identity and authored paths.
- `intent/`: 10 semantic components, linked-island ownership, runtime import
  envelope, source-project binding, and source evidence.
- `source/components/`: portable implementations for atomic, dispatch, and
  alias-sensitive typed-memory examples.
- `source/idiomatic/`: independent readable GNU Hello source candidate.
- `python/spaghetti_extractor_target_gnu_hello/`: target-only Lean emitters and
  source/acceptance adapters removed from the generic package.
- `lean/StageA/GnuHelloTransferValidationRank.lean`: the one target-specific
  reviewed Lean ranking module.
- `nix/`: narrow target phase drivers and the large round-trip coordinator.
- `default.nix`: target DAG exporting static reconstruction, candidate,
  component, library, source, strict proof, and report outputs.
- `docs/high-assurance-vertical-slice.md`: target result and limitations.

GNU Hello validates broad architecture, not generic semantics by itself. Its
strict whole-program theorem remains incomplete. Its idiomatic candidate has
candidate-only behavior evidence and explicitly does not claim equivalence.
The deepest target build currently reaches the mixed-original resolver and
stops fail-closed because resolver boundaries 167 and 168 do not establish an
exact-word identity argument. This is a proof frontier, not a target-bundle or
source-closure failure.

### 12.2 jq

`targets/jq/` is the scale benchmark and next application source-lifting target.

- `intent/`: selected components, linked islands, slice-loop profile, and
  whole-source project/evidence declarations.
- `source/components/`: 20 portable components covering strings, option state,
  output routing, callbacks, path scanning, and PE queries.
- `source/idiomatic/jq_cli.c`: current readable frontend candidate.
- `tests/functional-suite.json`: curated candidate-only behavior cases.
- `tools/build-candidate.sh`: target-local incremental candidate builder.
- `default.nix`: target-intent adapter; `idiomatic.nix`: source candidate and
  headless Wine tests.

The separate flake composition still owns the large jq Stage A fixture pair,
proof preparation, component analysis, library recognition, and many Stage B
outputs. This split is transitional: target-specific jq composition still
occupies substantial `flake.nix` space even though authored data has moved.

### 12.3 DX-Ball

`targets/dxball/` is the representative legacy DirectDraw/DirectSound game and
API/interface-provenance scale target.

- `default.nix` fetches and verifies the distributable archive, installs it in
  a headless Wine session, inventories the PE/assets, performs static opaque
  export, and derives Win32/DirectX operation evidence.
- `target.json` pins the executable identity.

It currently has no authored reconstruction components or source project. Its
value is coverage pressure for COM vtables, resolver-held calls, callback and
resource provenance, legacy SDK extraction, and real-time application APIs.

## 13. Authored Versus Generated Data

### Authored And Tracked

- Generic implementation under `src/`, `nix/`, `tools/`, and `profiles/`.
- Reviewed target manifest, intent, source, target adapters, target tests, and
  target-specific docs under `targets/`.
- Tiny independent fixtures under `fixtures/`.
- Design and schema documentation under `docs/`.

### Generated And Untracked

- `build/`, `result*`, `.tmp*`, `scratch/`, local `target/`.
- `.direnv/`, `__pycache__/`, `*.pyc`.
- `private/` input media and VM state.
- local `outputs/` reports.
- all generated proposal IDs, inferred effects, coverage counts, proof results,
  candidate PEs, generated C/Lean, `.olean`s, and provenance sidecars.

Nix store outputs are the canonical generated artifacts. Generated reports
must not be copied into `docs/` or target intent. A target selector identifies
stable semantic facts; a derivation resolves it to hashes, IDs, counts, and
statuses.

## 14. Validators And Failure Modes

| Layer | Validator | Detects | Authority |
| --- | --- | --- | --- |
| Repository | `tests/test_repository_boundaries.py` | Target imports/literals in generic code, missing target inputs, generated target intent/docs. | Architecture gate. |
| Schema | `artifact_formats.py`, typed parsers, `target_intent.py`, relational `schema.py`/`ir.py` | Unknown fields, stale hashes, invalid enums, malformed references. | Structural only. |
| Static PE | `pe.py`, contract validators, side/pair artifacts | Layout, ranges, imports, relocations, executable coverage, exact bytes. | Proposal unless Lean-replayed. |
| ISA | Lean/Bochs/Unicorn/hardware qualification | Decoder/semantics disagreement and unsupported defined state. | Lean can prove; external oracles veto. |
| Dataflow | pack aggregator and linear replay | Missing/duplicate packs, wrong transfer, noncanonical or nonmonotone solution. | Checked proposal consumed by Lean. |
| Lean | generated module DAG and axiom audit | Semantic, mapping, segment, graph, environment, and theorem failures. | Sole formal `pass` authority. |
| Stage B static | machine-IR/component/interface/source/library validators | Omitted units, ambiguous ownership, stale source, uncovered calls/effects. | Reconstruction qualification evidence. |
| Stage B C | CBMC and semantic claim checker | Bounded implementation mismatch and bitvector counterexamples. | Scoped component/local evidence. |
| Runtime | headless Wine functional/upstream suites | Candidate crash or public behavior mismatch. | Veto/integration evidence only. |
| Assurance | reconstruction/source assurance aggregation | Missing evidence, assumptions, unsupported reachable behavior. | High-assurance report, never formal `pass`. |

The intended failure vocabulary is:

- `incomplete`: required evidence or supported semantics are absent or
  ambiguous; no claim is made.
- `violated`: supplied evidence or behavior contradicts the contract, ideally
  with a concrete location/counterexample.
- `not_applicable`: a checked family does not apply.
- `satisfied`/qualified: the stated scoped check is complete.
- formal `pass`: only the exact audited whole-program Lean theorem.

## 15. Test Suites

There are 567 top-level `test_*.py` files and 3,258 test methods. The
physical layout is flat even though the semantic suites are not.

### 15.1 Exhaustive Test-File Partition

Every test file belongs to one of these primary naming families:

| Pattern/family | Files | Purpose |
| --- | ---: | --- |
| `test_stage_a_relational*.py` | 201 | Relational schema, analysis, Lean kernels, graph composition, acceptance, external worlds, calls, memory, and proof fixtures. |
| Remaining `test_stage_a*.py` | 207 | Static contracts, machine IR, proof emitters, external operations, dataflow workers, and architecture tests outside the relational, GNU, ISA, round-trip, and source-relative families below. |
| `test_stage_a_gnu*.py` | 43 | GNU target driver, generated Lean adapter, source, runtime, and frontier wiring. Target-specific and still located in root `tests/`. |
| `test_stage_a_isa*.py` | 22 | Catalog, corpus, oracle backends, masked comparison, qualification, and Nix graph. |
| `test_stage_a_roundtrip*.py` | 15 | Fuzz/discovery/reducer/violation/Stage B round-trip and Nix qualification. |
| `test_stage_a_source*.py` | 13 | C0 and native-source conditional theorem path. |
| `test_stage_b*.py` | 19 | Skeleton, feedback, candidate, functional, component, library, and Nix Stage B integration. `test_stage_b.py` is still a 12,000-line concentration. |
| Other generic tests | 44 | PE, provenance, external profiles, components, linked libraries, reconstruction workspaces, source projects, CLI, target-intent parsing, and cross-cutting helpers. |
| `test_gnu_hello*.py` | 2 | GNU native-source runtime/static authority target checks. |
| `test_repository_boundaries.py` | 1 | Generic/target/generated ownership boundary. |

The rows are an exclusive first-match partition in the order shown and total
567 files. Shared fixture helpers are `contract_fixtures.py`, `pe_fixtures.py`,
and `stage_a_relational_support.py`.

### 15.2 Execution Lanes

- Fast Python gate: focused `unittest` modules inside `nix develop`.
- Generic Stage A fixture gate: `stage-a-fixtures-check`.
- Per-case relational Lean gate: `stage-a-relational-tests`, with Nix caching
  and remote builders.
- ISA gate: core smoke plus Bochs/80386 state-operation checks.
- Round-trip gate: static smoke, promoted corpus, graph smoke, and spike check.
- Target gates: jq full fixture audit, GNU preflight/proof fragments/component
  evidence, and DX-Ball acquisition/static inventory.
- Stage B behavior gates: per-case and upstream-shell candidate-only shards.

The 32 current flake checks form these exact lanes:

| Lane | Check attributes |
| --- | --- |
| Repository/package | `repository-boundaries-check`, `spaghetti-extractor` |
| Generic fixtures and graph | `stage-a-exit-behavior-smoke`, `stage-a-exit-check`, `stage-a-fixtures-check`, `stage-a-minimal-hello-check`, `stage-a-nix-graph-integration`, `stage-a-relational-tests`, `stage-a-winapi-hello-check` |
| ISA | `stage-a-isa-conformance-bochs-80386`, `stage-a-isa-conformance-state-ops`, `stage-a-isa-core-smoke-qualification` |
| Round trip | `stage-a-roundtrip-lean-graph-smoke`, `stage-a-roundtrip-promoted-check`, `stage-a-roundtrip-spike-check`, `stage-a-roundtrip-static-smoke` |
| GNU formal fragments | `stage-a-gnu-hello-preflight`, `stage-a-gnu-hello-roundtrip-external-component-proof`, `stage-a-gnu-hello-roundtrip-kernel-operation-instantiation-proof`, `stage-a-gnu-hello-roundtrip-launch-binding-proof`, `stage-a-gnu-hello-roundtrip-mixed-chunked-acceptance-proof`, `stage-a-gnu-hello-roundtrip-runtime-foundation-proof`, `stage-a-gnu-hello-roundtrip-runtime-indirect-composition-proof`, `stage-a-gnu-hello-roundtrip-smoke`, `stage-a-gnu-hello-roundtrip-x87-kernel-execution` |
| GNU reconstruction | `stage-b-gnu-hello-lifting-evidence`, `stage-b-gnu-hello-selected-component-catalog`, `stage-b-gnu-hello-semantic-components` |
| jq | `stage-a-jq-fixtures-check`, `stage-b-jq-skeleton` |
| DX-Ball | `stage-a-dxball-original-inventory`, `stage-a-dxball-original-smoke` |

All Wine checks must run under a headless X/Wayland session. Current target Nix
lanes use `xvfb-run`; adding a direct `wine` invocation without a headless
wrapper is a test-policy regression.

## 16. Documentation Map

| Document | Status and purpose |
| --- | --- |
| `docs/high-assurance-reimplementation-direction.md` | Primary project completion model, trust tradeoff, machine IR, progressive lifting, and assurance case. |
| `docs/semantic-component-framework.md` | Current component discovery/interface/workspace/CBMC/registry and linked-library framework. |
| `docs/external-operation-framework.md` | Generic imports, COM tables, resolvers, callbacks, and source-rendering boundary. |
| `docs/stage-a-architecture.md` | Normative only for strict formal `pass`; detailed phase/cache/trust architecture. |
| `docs/stage-a-relational-v3.md` | Implemented relational-v3 profile, progress, performance, and truthful blockers. |
| `docs/stage-a-isa-qualification.md` | ISA oracle and qualification architecture. |
| `docs/stage-a-parallel-development.md` | Stable interfaces and parallel workstream integration. |
| `docs/stage-a-round-trip-fuzzing-plan.md` | Completed initial structured round-trip plan plus future corpus expansion. |
| `docs/stage-a-round-trip-fuzzing-report.md` | Qualification result for that plan. |
| `docs/stage-a-round-trip-phase0-report.md` | Initial feasibility canary and performance. |
| `docs/stage-a-round-trip-schema-v1.md` | Round-trip corpus, case, result, and violation schemas. |
| `docs/stage-a-source-equivalence-experiment.md` | Optional source-relative conditional theorem. |
| `docs/stage-a-internal-equivalence-and-3d-roadmap.md` | Historical mandatory-theorem roadmap retained as formal-track design history. |
| `docs/target-bundles.md` | Normative generic/target and authored/generated boundary. |
| `targets/gnu-hello/docs/high-assurance-vertical-slice.md` | Target-specific result, counts, assumptions, and limitations. |

`docs/README.md` is the documentation index. `PLAN.md` is explicitly historical.
This status hierarchy prevents older mandatory-theorem prose from silently
overriding the current primary direction.

## 17. Current Concentrations And Cleanup Frontiers

This section records architecture debt, not merely large files.

1. **`flake.nix` is an 8,500-line composition root with 675 package outputs.**
   Generic constructors exist, but jq and GNU target wiring still occupies the
   root. Move complete target composition behind target adapters and publish a
   smaller intentional output surface. A change to one preparation-worker
   fileset currently changes the dirty flake source identity and can
   reinstantiate hundreds of otherwise unchanged jq derivations; target graph
   inputs need narrower, independently materialized source closures for CA
   reuse to be effective.
2. **`targets/gnu-hello/default.nix` is over 10,000 lines and its driver is over
   7,000 lines.** The target is now correctly isolated, but internally remains a
   monolith combining many proof generations and target checks.
3. **`src/spaghetti_extractor/lean/StageA` has 262 modules and
   `relational/lean` has 143 emitters.** Reflective checker consolidation is in
   progress; specialized pointer/call/interpreter paths still coexist with the
   generic provenance/effect abstractions.
4. **Large generic files remain:** `RelationalInterpreterKernelX87Execution.lean`,
   `RelationalComposition.lean`, `Relational.lean`, `stage_b_skeleton.py`,
   `relational/analyses/control.py`, and several acceptance/segment emitters.
5. **Tests are physically flat and target-entangled.** Forty-five GNU target
   files remain under `tests/`; target tests should move next to the target with
   reusable fixtures retained centrally. `test_stage_b.py` remains a large
   multi-subsystem suite.
6. **Two reconstruction workbench generations coexist.** The component
   framework is the stricter current path; the older cluster replacement path
   remains useful but overlaps workspace, validation, and promotion concepts.
7. **Strict theorem, source-relative theorem, and primary assurance workflows
   all share one CLI and flake.** Their statuses are separated correctly, but
   command and build surface density makes authority harder to read.
8. **Documentation still contains substantial formal-track history.** Status
   labels are present, but future cleanup should separate normative current
   docs from archived design history more visibly.
9. **Ignored workspace noise is nontrivial.** `private/`, local `outputs/`, and
   bytecode caches are not repository history, but can confuse broad inventory
   and raw-path Nix evaluation. Accepted builds must use explicit filesets.

The completed target-bundle refactor already removed the most dangerous form
of entanglement: target source, selectors, proof adapters, and candidate scripts
are no longer installed as generic toolkit modules.

## 18. Change Impact Guide

| Change | Correct home | Expected invalidation |
| --- | --- | --- |
| Generic PE/decode semantics | `src/spaghetti_extractor`, reviewed Lean, generic fixture | Affected side extraction, ISA qualification, semantic descendants. |
| New reusable API/COM operation shape | generic profile/schema and small generic fixture | Operation extraction/rendering and targets selecting it. |
| Target RVA/component/source decision | `targets/<id>/intent` or `source` | Target binding, selected component/workspace, candidate descendants only. |
| Target-only proof assembly | target `python/`, `lean/`, or `nix/` | That target's generated proof closure only. |
| New component implementation profile | `src/spaghetti_extractor_component_profiles` plus generic tests | Components selecting the profile and aggregate registries. |
| Library artifact catalog input | target/private catalog declaration through generic library DAG | Relevant index/hypothesis/island descendants, not PE extraction. |
| Diagnostic formatting | generic diagnostic module | Reports only; no semantic/proof artifacts. |
| One candidate component source edit | target source overlay/workspace | That component check, object, integration, registry, and aggregate report. |
| Lean kernel theorem | reviewed Lean module | Direct import descendants in the Nix module graph. |
| Axiom policy | audit input | Audit derivation only. |
| Runtime expected-output case | target test intent | One functional shard and aggregate. |

## 19. Maintenance Rules For This Map

When changing architecture:

1. Update the subsystem, authority, and relationship sections here in the same
   change.
2. Add or update a repository-boundary test when a rule can be automated.
3. Keep target-specific names, source, intent, adapters, and tests under
   `targets/<id>/` unless a generic fixture demonstrates reuse.
4. Keep generated evidence in Nix outputs; never paste reports into authored
   intent or documentation.
5. Expose a new flake package only when it is useful for direct development,
   CI, composition, or audit. Internal graph nodes need not all be public.
6. Add a generic Nix constructor to `flake.lib` only when at least two consumers
   or one independent smoke target establish a reusable interface.
7. Preserve explicit evidence class and verdict vocabulary when moving tools.
8. Run `repository-boundaries-check`, the affected focused Python/Lean suites,
   and the narrowest affected Nix output before broad target checks.

Snapshot inventory commands:

```sh
# Generic and target source inventory
git ls-files
find src nix profiles tools targets tests -type f

# Public CLI and flake surfaces
nix develop . --command spaghetti-extractor --help
nix eval .#packages.x86_64-linux --apply builtins.attrNames --json
nix eval .#checks.x86_64-linux --apply builtins.attrNames --json
nix eval .#apps.x86_64-linux --apply builtins.attrNames --json
nix eval .#lib --apply builtins.attrNames --json

# Architectural boundary gate
nix build .#repository-boundaries-check --no-link
```
