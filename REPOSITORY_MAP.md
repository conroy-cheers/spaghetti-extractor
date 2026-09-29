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
| `native/` | Coarse-grained PyO3 acceleration kernels for canonical artifact operations. Native code is deterministic and differential-tested; it never grants authority by itself. |
| `nix/` | Generic content-addressed phase constructors and oracle harnesses. |
| `profiles/` | Reviewed machine ABI, import, and external-operation profiles. |
| `tools/` | Generic external tool adapters and helper assets. |
| `tests/` | Generic unit, boundary, integration, and constructor tests. |
| `targets/flake.nix`, `targets/flake.lock` | Independent in-tree validation-consumer flake. |
| `targets/registry.nix`, `targets/<id>/` | Explicit target registry and authored GNU Hello, jq, and DX-Ball bundles. |
| `docs/` | Canonical architecture and workflow documentation. |
| `docs/component-workflow.md` | Operator entry guide: workspace preparation, local C editing, discrepancy replay, consumer checks, source export and manual boundary authoring with existing APIs. |
| `docs/component-module-workflow.md` | Practical C storage eligibility and reusable portable assembly bindings for grouped operations, with parser integration, local edit reuse and transfer evidence. |
| `docs/jq-lifting-continuation.md` | Source-assisted serializer and interpreter lifting trial, native and two-architecture program comparisons, and the original generated-frontend source-profile limitation. |
| `docs/compiler-backed-practical-c.md` | Compiler-backed practical admission, active-source views, jq frontend refactoring/replay and transfer through existing interfaces and assembly. |
| `docs/jq-compiler-lifting-continuation.md` | Bytecode compiler replacement through the existing workflow, two-architecture program integration, and the allocator module/thread-state admission limit. |
| `docs/stateful-component-workflow.md` | Practical state-owner declarations, shared provider selection and lifecycle observations through the jq allocator workflow. |
| `docs/jq-module-loader-continuation.md` | Module-loader replacement, native and two-architecture integration, and the shared filesystem/text-input portability stopping point. |
| `docs/jq-file-runtime-continuation.md`, `tests/fixtures/jq-file-input/`, `tests/fixtures/jq-input-stream/` | Reusable C file runtime, independent jq file/input-state components, shared stdin and callback bindings, native comparisons and two-architecture source assembly through existing tooling. |
| `docs/jq-value-continuation.md`, `tests/fixtures/jq-value-algorithms/`, `tests/fixtures/jq-value-relations/` | Value algorithms, recursive relations and object merging through existing boundaries; reusable CRT sorting, shared-view observations and native/portable source integration. |
| `docs/jq-ir-continuation.md`, `tests/fixtures/jq-compiler-ir/`, `tests/fixtures/jq-execution-lifecycle/` | Compiler instruction graphs and execution lifecycle through shared layouts and ordinary C; native/portable comparisons and the incremental assembly boundary-refinement gap. |
| `docs/call-protocols.md` | Checked semantic, layout, transport, lifecycle, evidence, and source-view model for calls and callbacks. |
| `docs/native-ingress.md` | Generic native entry, object/data-export authority, SEH outcomes, PE32 deployment, and multi-image completion contracts. |
| `docs/canonical-boundaries.md` | Shared type, data-layout, evidence, lifecycle, projection, call, callback, and component-boundary model. |
| `docs/boundary-transducers.md` | Typed relations between logical component values, machine places, object authority, and checked effects. |
| `docs/callbacks.md` | Provider-neutral callback registration, lifetime, delivery, cardinality, and invocation semantics. |
| `docs/portable-c-contextual-bisimulation.md` | Universal cutpoint proof, scaling, migration, and strong native-dispatch activation contract for ordinary Portable-C. |
| `docs/current-goal.md` | Practical operator-workflow and standalone-program milestone, current work queue, earlier scoped milestones and separate G1–G7 strong-qualification objectives. |
| `docs/behavior-faithful-component-workflow-plan.md` | Accepted implementation sequence for contract-specific resource diagnostics, reusable services, resolved composition, precise reuse, C support and bounded runtime sessions; preserves scoped original defects. |
| `docs/interactive-portable-lifting-roadmap.md` | Planned path from contextual-proof migration through assisted lifting, reusable platform contracts, standalone source export, and unfamiliar-application trials. |
| `docs/independent-portable-lifting-plan.md` | Independent-component plan and formal composition roadmap, with the subsequent practical workflow sequencing update. |
| `docs/practical-independent-lifting-design.md` | Proposed local differential validation, explicit assurance, optional proof and experimental execution design; maps the workflow onto existing component and native infrastructure. |
| `docs/practical-lifting-workbench-review.md` | Proposed restricted-C authoring workflow, concrete operator examples, incremental dependency isolation and a smaller first implementation sequence. |
| `docs/practical-lifting-validation.md` | Current G1–G6 completion audit, exact retained operator evidence, cost measurements, negative controls and outstanding authority gates. |
| `docs/practical-product-audit.md` | Requirement-by-requirement practical delivery audit, current operator/program evidence, explicit target scopes and repository validation findings. |
| `docs/jq-path-network-assessment.md`, `tests/fixtures/jq-path-network/` | Larger four-operation jq practical workflow, interpreter consumers, edit/reuse and ownership negative controls, measured costs and limitations. |
| `nix/headless-wayland.nix` | Shared isolated Weston headless desktop and Xwayland runner for Wine applications; preserves command streams, exit status and cleanup. |
| `tests/fixtures/hello-standalone/`, `tests/fixtures/portable-runtime/` | Practical standalone Hello source assembly, reusable UTF-8 arguments, Windows-1252 redirected streams and experimental UTF-8 terminal text. Normal-program/memory/failure comparisons, native console/PTY observations and retained replay; explicit runtime limits and a remaining control-character mismatch, not qualification authority. |
| `tests/fixtures/jq-portable/` | Source-assisted portable assembly of the selected jq storage/path/string subsystem, explicit unlifted runtime, import-callback identity binding, normal CLI/live-object and real allocation-failure comparisons, and public local updates on x86-64/AArch64. Partial lifting and finite evidence, not complete jq recovery. |
| `tests/fixtures/jq-string-length/` | Fresh boundary and workspace trial using existing live string services/adapters: malformed-byte and interpreter comparisons, public edit/replay/neighbor reuse, and reviewed portable source integration. |
| `src/spaghetti_extractor/operator/comparison_guidance.py` | Local workspace projection of existing interfaces, shared objects, services, assumptions, requirements and examples; generated guides and `component status --comparison-package`, without assurance authority. |
| `src/spaghetti_extractor/candidate/source_export_bindings.py` | Standalone source-handoff reader and batch use of the existing service bridge generator with explicit reviewed backend mappings; no native comparison environment or inherited qualification. |
| `nix/component-comparison-package.nix`, `src/spaghetti_extractor/components/comparison_package.py` | Concrete comparison setup exposed by `sdk.lifting.comparisonPackage`; generated component APIs, original/source execution, retained observations and replay without qualification authority. |
| `src/spaghetti_extractor/components/comparison_resources.py`, `src/spaghetti_extractor/components/comparison_resource_runtime.py` | Contract-bound reference instrumentation and observations; separates resource findings, failed premises and behavioral comparison without heap-proof authority. |
| `src/spaghetti_extractor/components/service_authoring.py`, `src/spaghetti_extractor/components/service_c.py`, `src/spaghetti_extractor/components/comparison_services.py` | Canonical reusable service declarations, generated C transport and outcome checks, and concrete service-protocol observations. |
| `src/spaghetti_extractor/components/comparison_composition.py`, `src/spaghetti_extractor/components/comparison_dependencies.py` | Transitive explicit selections, exact contract and representation requirements, deduplicated implementations, declared recursion and integration impact; no checked-summary authority. |
| `src/spaghetti_extractor/components/comparison_compile_cache.py`, `src/spaghetti_extractor/components/comparison_build.py`, `src/spaghetti_extractor/components/comparison_reuse.py` | Per-translation-unit reuse, literal include-search probes, unread-header exclusion and separately admitted observation reuse; retained objects remain experimental evidence. |
| `src/spaghetti_extractor/components/practical_contracts.py` | Optional existing read-only, mutable and shared-view/service local theorems beside finite comparisons; exact premise/source binding and independent assurance/reuse. |
| `src/spaghetti_extractor/components/partition_inventory.py`, `docs/whole-target-independent-lifting.md` | Practical stateful subsystem and whole-program acceptance plan; manual ownership audit over linked-module facts, complete Hello routine partition and visible crossings without qualification authority. |
| `docs/component-boundary-design.md` | Proposed relational contract and proof-cut design, worked counterexamples, compatibility rules and implementation acceptance gates; not proof authority. |
| `docs/component-boundary-design-review.md` | Broad-target review correcting storage, open-protocol, pending-work, nonlocal-control and history assumptions; capability matrix and finite countermodels. |
| `docs/baselines/2026-09-07-independent-lifting-experiment.md` | Exact Metapad cleanup experiment, caller contexts, proposed boundaries, current blockers and separated preparation/proof costs. |
| `docs/baselines/2026-09-14-independent-component-milestone.md` | Requirement-by-requirement completion audit for the small Metapad network: public edit/refine/reuse, exact local proof dependencies, separate runtime validation and explicit generalization/activation limits. |
| `docs/unified-behavioral-c-lifting-native-ingress-deployment-plan.md` | Authoritative ordered migration and completion contract for the behavioral-C-only deployment architecture. |
| `docs/gnu-hello-semantic-closure-tooling-gap-inventory.md` | Evidence-backed inventory of the generic analysis and realization gaps exposed by the real GNU Hello vertical slice. |
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
  -> executable-transfer-plan-v2
  -> semantic-object-v1 + qualified-platform-v1
  -> linked-semantic-module-v2 total root-provenance closure
  +-> library/interface/component proposals -> qualified semantic providers
  -> contextual-refinement-v2 for selected Portable-C operations
  -> native-realization-v2 plus portable-dispatch-link-receipt-v1
  -> candidate-observed project completion
  -> optional deployment-bound veto tests under headless Wine
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
| `component` | `list`, `status`, `build`, `start`, `check` with authored unit selectors; `start` materializes a writable checked package or transactionally adds source to existing canonical intent |
| `library` | `status`, `inspect`, `adopt`, `check` for ABI-first constellation recognition and whole-island qualification |
| `boundary` | `status`, `inspect`, `propose`, `adopt`, `check` for calls, callbacks, exports, component operations, and services addressed by stable `kind:id` subjects. |
| `candidate` | `list`, `status`, `build`, `test` |
| `expert` | Explicit low-level static analysis, ISA, reconstruction, authority, runtime, component, source, and validation leaves from `commands/*.py`. |

`commands/workflow_options.py` defines operator CLI options;
`commands/workflows.py` owns their handlers for stable target-SDK Nix artifacts
and retained practical comparison packages. `commands/common.py` owns the expert handler protocol. A low-level
leaf outside `expert` is a repository-boundary failure; retired commands are
not retained as aliases.

`components/work_package_editing.py` binds editable canonical interface, binding
and cutpoint declarations to V6 packages. `commands/component_review.py` normalizes
seed and configured-component drafts through the same codecs.
`commands/component_apply.py` applies reviewed declarations to the SDK-discovered
target indexes with stale-input checks, a shared authoring lock and rollback.
This editing path grants no proof or activation authority.
`components/bisimulation_selection.py` checks ordinary diagnostic selections and
deferred-region records within existing contextual receipts. `operator/proof_check.py`
validates and displays those results; native qualification requires a complete
check without diagnostic selection.

The status namespaces also define dependency ownership: `project status` is a
persisted non-authorizing one-subject view over the linked semantic module;
`boundary status` is a persisted aggregate over checked subjects; and component
and candidate status are local projections of one exact indexed work package,
qualification, or selection. Legacy authority diagnostics and component
failures are therefore not direct inputs to project status.
Candidate projections also expose provider-kind coverage, keeping exact
fallback-free selection distinct from portable-C replacement progress.

Core support modules are deliberately small:

| Module | Purpose |
|---|---|
| `__init__.py` | Package identity and version surface. |
| `errors.py` | Shared user-input and phase failure types. |
| `execution.py` | Dependency-free bounded process termination and pipe capture used by comparisons and candidate execution. |
| `util.py` | Canonical JSON, hashing, and atomic artifact helpers. |
| `operator/index_v1.py` | Strict pure discovery codec tying every advertised product to the V5 target SDK tree. |
| `operator/work_status.py`, `operator/projections.py` | Bounded V2 status summaries, source-bound on-demand blocker details, and local component/candidate projections. |
| `operator/source_check.py` | Non-authorizing host/PE32 compiler and C-profile feedback over canonical component source/interface packages, with source-bound error details. |
| `build_support/nix_support.py` | Nix discovery and content-addressed worker command construction. |
| `build_support/python_module_index.py` | Canonical local-import index plus production-root closure enforcement used by Nix and developer diagnostics. |
| `build_support/architecture_manifest.py` | Canonical operator, authority, candidate, proposal, diagnostic, expert, and developer root roles; Nix files declare roles explicitly rather than inheriting them from filenames. |
| `build_support/lean_runner.py` | Small deterministic Lean compile/run helper. |

## Package Ownership

The active pipeline packages are ownership boundaries, not migration aliases:

| Package | Owns | Dependency rule |
|---|---|---|
| `extraction/` | Static PE decoding, executable-byte/region/cutpoint inventories, ISA requirements, and non-authorizing Ghidra proposals. | Must not depend on `authority/`, `candidate/`, or `components/`. |
| `candidate/` | Behavioral-C generation, shared runtime and ingress planning, native linking, loader-surface composition, deployment records, and candidate-only diagnostics. | It consumes linked semantic modules and neutral schemas; it never imports proposal discovery. |
| `components/` | Target-neutral intent, portable interfaces, source binding, static machine-derived refinement, machine bindings, service graphs, dependency checks, non-authorizing work packages, provider qualification, and total implementation selection. | It remains neutral to extraction and candidate packages so the same contracts can be composed independently. |
| `transfer/runtime_abi.py` | Own the exact machine-state/runtime C ABI shared by transfer consumers, Behavioral C, and portable component compilation. | Portable compilation renders this neutral source directly and does not depend on a target-wide generated-C package. |
| `semantic_objects/` | The closed, structurally complete but non-authorizing `semantic-object-v1` checked-relocatable package, relocatable semantic declarations/effects, typed exception-transition activations, a canonical evidence catalog with exact per-definition dependencies, external and loader-service declaration digests, grouped runtime-primitive dependencies, total object-rule-to-symbol bindings, content-bound transfer/module/environment/object members, strict replay, the single same-pass native-checked production link view, and mapped-object/reference codecs. | Transfer-v2 is its only executable body language. It must not depend on components or candidates, and higher layers must not reconstruct its checked members or schedule a parallel evidence graph from independent phase inputs. Only semantic linking may turn its reachable closure into execution authority. |
| `semantic_link/` | The closed `linked-semantic-module-v2` codec/compiler, one native total root-provenance worklist with exact transfer-fact and activated-exception recomputation, retained source-fixed-point status/provenance, external-declaration and evidence-dependency cross-checks, canonical object typed views and generation policies, reachable implementation requirements, transient native-consumer views over linked tables, independent replay, status view, and an isolated speed-first performance veto. | It consumes semantic objects and link roots, never raw machine IR, x86 decoders, independent resolved-environment/object/evidence/lifecycle inputs, rebuilt environment-contract joins, parallel provider/external source maps, provider source layout, candidate implementation facts, a packaged execution-closure sidecar, or a second production fixed point. |
| `abi/` | Canonical physical ABI values, finite constraint solving, pinned declarations, and catalog binding. | Target machine ABI authority comes only from the linked semantic module; declaration data cannot authorize a target match. |
| `calls/` | Portable type graphs, target layouts, physical call frames, lifecycle facts, compiler proposals, dialect checks, and checked callback/call protocols. | Authored intent contains semantic choices only; generated transport and evidence remain content-bound and independently checked. |
| `machine_ir/` | Neutral definedness and implementation-coverage checks shared across extraction, authority adapters, and candidate construction. | It owns cross-phase machine-IR schemas/checkers so no higher layer must be imported backwards. |
| `external/` | Canonical ABI, interface, operation-profile, external-site contracts, external-environment intent compilation, non-authorizing projection, the strict resolved-environment codec, and one shared rule that binds multi-frame typed service schemas to selected import/callback contracts. | The resolved payload is a content-bound semantic-object member; semantic linking must not regain an independent environment input. Authored views authorize no machine frame unless `boundary_bindings.py` rederives one unique physical binding and every callback registration/source/type/lifetime relationship. Runtime-support imports remain separately tagged. |
| `isa/` | Catalogs, corpus/oracle adapters, qualification, kernel selection, and frontier reporting. | Oracles veto qualification but cannot authorize candidate behavior. |
| `reconstruction/` | Original-only opaque bootstrap, exact machine-IR construction, clustering, contract analysis, composition, and validation. | It proposes bounded reconstruction artifacts and has no candidate authority. |
| `static_program/` | Typed original-only PE contract, strict codec, exact extraction, and filesystem binding. | It cannot contain a candidate, binary mapping, or behavioral-reachability assertion. |
| `artifacts/` | Shared format identifiers, canonical identities, immutable artifact-set records, codecs, streaming I/O, and scheduling. | Cross-subsystem identifiers have one literal owner; JSON mappings stop at codec boundaries. |
| `pe32/` | Exact PE parsing, loader diagnostics, exports/TLS/imports, structural decode, COFF hints, roots, and cutpoint materialization. | It is the target-neutral binary substrate for extraction and candidate composition. |
| `libraries/` | Historical artifact parsing plus canonical ABI-first catalogs, target signatures, constellation hypotheses, operator selections, and structural boundary receipts. | Recognition is proposal evidence. Only an exact boundary receipt rebound through ordinary component activation can contribute to replacement authority. |
| `build_support/` | Nix, Lean, architecture, and generated Python-module-index support. | Build policy remains separate from binary-analysis semantics. |
| `profiles/` | Typed registry and exact-inventory validation for reusable reviewed profiles. | Every profile is catalogued with a role and validator and checked as a cached Nix authority input. |
| `target_bundles/` | Exact authored-file ownership linter for validation consumers. | Undeclared, duplicate, generated, or symlinked target assets fail closed. |
| `qualified_platform/` | Target-independent transfer primitive, lowering, runtime-provider, intrinsic ISA-form inventory/campaign/replay, Lean-kernel binding, independent release replay, and veto-only four-target migration-parity reduction. | The release cannot consume targets, PE occurrences, semantic objects, components, or target-local authority campaigns; migration parity is diagnostic evidence and never a platform input. |

The PyO3 package in `native/` is an implementation detail behind these Python
ownership boundaries. Calls cross the language boundary in bounded batches,
such as one complete artifact pack, rather than once per record. Python owns
schemas, phase dependencies, diagnostics, and fail-closed verdicts. A native
kernel may parse, normalize, hash, or compute a proposed fixed point, but its
result must pass the same checked Python boundary and differential corruption
tests. New Rust modules are added only for a measured dominant kernel after
algorithmic improvements have been exhausted.

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
| `isa_inventory.py` | Required instruction-form inventory for one binary. |
| `isa_requirements.py` | Required Lean form/capability projection. |
| `x87_profile.py` | x87-specific static requirements and replay metadata. |

PE primitives live in `pe32/pe.py`, `pe32/image.py`, and
`pe32/recursive_decode.py`.
`reconstruction/rooted_state_machine.py` performs rooted static control recovery.
`extraction/ghidra.py` is an optional, non-authorizing static proposal adapter.
It hash-binds Ghidra output to the submitted PE and never executes the original
binary. Neutral helpers now live directly with reconstruction, external
profiles, or qualified-platform selection; there is no `authority_inputs/`
adapter namespace.

There is no Python `authority/` package. Transfer-v2, semantic-object replay,
semantic linking, qualified providers, native realization, and independent
candidate observation own the active executable path.

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
| `reconstruction/machine_ir_bindings.py` | Stable exact unit/event binding kernel shared by machine-IR extraction and replay. |
| `artifacts/artifact_set.py`, `artifacts/io.py` | Canonical manifests, bounded compressed packs, and streaming indexed reads used inside active domain packages. |
| `reconstruction/bindings.py` | Exact binary/unit/event bindings and canonical JSON used at stable active wire boundaries. |
| `external/control_disposition.py`, `external/control_abi.py` | Project import profiles onto fixed-arity control facts and recover their checked PE32 stack arguments. |
| `reconstruction/target_dependencies.py`, `reconstruction/static_indirect_replay.py` | Exact indirect-target dependencies and independent finite-target replay. |
| `pe32/target_cutpoint_materialization.py`, `pe32/recovered_executable_data.py` | Untrusted exact-span proposals plus checked executable code/data and padding separation. |
| `external/contracts.py` | Canonical machine-level external call/jump contracts and exact profile matching. |
| `isa/kernel_selection.py` | Binary-specific binding from reachable forms to qualified semantics and fallback capabilities. |
| `qualified_platform/requirements.py`, `qualified_platform/target_selection.py` | Required-form extraction and binary-bound qualified-platform selection. |
| `reconstruction/launch_assumptions.py` | Content-stable, non-authorizing PE-bound assumption projection for root-independent SCC analysis. |
| `transfer/closure.py`, `transfer/provenance.py` | Canonical transfer-plan execution closure and typed reference provenance used by Behavioral-C acceptance and portable-lift policy. |
| `transfer/provenance_coverage.py` | Stable total-operation coverage declaration shared by qualified-platform and Behavioral-C checks without importing the reference fixed point. | It is not a second provenance implementation; closure execution remains in the canonical provenance modules, while platform qualification is insulated from callback/object-lattice implementation edits. |
| `reconstruction/control.py` | Stable facade for cluster proposals from decoded control structure. |
| `reconstruction/control_common.py`, `reconstruction/control_jump_tables.py`, `reconstruction/control_reachability.py`, `reconstruction/control_clusters.py` | Shared control records, bounded jump-table recovery, structural reachability, and cluster construction. |
| `reconstruction/composition.py` | Composes compatible machine units into larger reconstruction clusters. |
| `reconstruction/contract_analysis.py` | Derives cluster inputs, outputs, effects, and frontiers. |
| `reconstruction/validation.py` | Synthesizes finite validation cases. |
| `static_program/model.py`, `static_program/codec.py`, `static_program/extraction.py` | Typed original-only static-program schema, strict parser, and exact extractor. |
| `reconstruction/static_export.py` | Original-only static-program and canonical state-machine orchestration. |
| `components/capabilities.py`, `components/atomics.py` | Shared checked capability lifecycle plus the typed portable atomic facade. |
| `candidate/runtime_helpers.py` | Shared C helper text used by canonical transfer-plan renderers; it contains no machine-IR adapter or behavioral model. |
| `transfer/model.py`, `transfer/compiler.py`, `transfer/values.py`, `transfer/atomics.py`, `transfer/plan.py`, `transfer/evaluator.py`, `transfer/exception_projection.py` | Renderer-neutral exact transfer model, lowering, canonical executable-transfer plan codec, shared exception-record projection vocabulary, and veto-only host evaluator. |
| `candidate/build.py`, `candidate/build_model.py`, `candidate/build_validation.py`, `candidate/build_objects.py`, `candidate/build_workflow.py`, `candidate/build_values.py` | Freestanding PE32 build facade, canonical-transfer package validation, object DAG, final workflow, and strict values; it never reopens raw machine IR and receives recovered image bytes through their narrow realization contract. |
| `candidate/source_export.py` | Exports matching practical comparisons as existing V3 component source packages and a conventional C library build. Retains interfaces, contracts and compiled include closure; original runtime, application entry and service implementation are not supplied. Its provenance report grants no qualification. |
| `components/source_handoff.py`, `candidate/source_export_bindings.py` | Shared source-provenance and editable-draft reading belongs to components; candidate bindings consume it to generate executable C service bridges. Existing public reader imports remain available. |
| `components/source_dialect.py` | Practical C admission using compiler-produced storage sections, separate from the unchanged formal source profile. Immutable static tables keep their lifetime; writable storage requires explicit context. |
| `candidate/source_assembly.py` | Reviewed portable adapter sources, grouped entry mappings, replacement definitions and lifetime descriptions shared by jq and Hello source recipes; independent of comparison harness bindings. |
| `candidate/source_replacements.py` | Exact file-scoped C body retirement/restoration, preserving surrounding edits and checking legacy body hashes. |
| `candidate/source_project_apply.py` | `candidate apply`: stages source export, target assembly and optional checks; preserves the working project on failure and retains a full backup on publication. |
| `candidate/linked_skeleton_model.py`, `candidate/linked_skeleton_merge.py`, `candidate/module_composer.py` | Internal linked-payload merge primitives plus the sole public PE32 loader-surface composer. |
| `transfer/capability_analysis.py`, `machine_ir/fallback_capability.py` | Non-executable transfer-lowering analysis and strict capability identity projected into static authority without source or object bytes. |
| `machine_ir/definedness.py` | Undefined-value and dependency-frontier analysis shared without importing extraction or candidate layers backwards. |
| `components/source.py`, `components/component_c_v5.py`, `components/machine_overlay_v5.py`, `components/machine_overlay_external_v5.py` | Content-bind operation-based portable C, compile it for host and PE32, audit mutable globals, and generate direct V5 overlays plus checked external-service thunks and the sole strong module dispatch registry. |
| `components/bisimulation.py`, `components/bisimulation_refinement.py`, `components/contextual_bisimulation.py`, `components/component_exact_c_slice.py` | Plan an entry obligation plus checked acyclic or cyclic cutpoints, slice exact Behavioral-C by barrier, run partitioned shared-world contextual proofs without path enumeration, and emit strict aggregate authority. |
| `components/bisimulation_source_region_graph.py`, `components/bisimulation_source_call_check.py` | Prepare compiler-bound manual source-region graphs and service-call projections through the existing source-check product. Retain calls, cut edges, referenced storage, uncovered scope and per-region semantic bindings without granting state-transport, progress, functional-proof or activation authority. |
| `components/bisimulation_source_region_calls.py`, `components/bisimulation_source_region_transport.py`, `components/bisimulation_region_observer.py` | Check compiled manual-region call coverage, automatic-state restores, typed source-body correspondence, assertion-only exit observers and terminal regions with ordinary returns. Transport alone grants no functional authority. |
| `components/bisimulation_cleanup_contract.py`, `components/bisimulation_cleanup_inputs.py`, `components/bisimulation_cleanup_frame.py`, `components/bisimulation_cleanup_model.py`, `components/bisimulation_cleanup_template.py` | Terminal cleanup profile consumed by the public region engine: admit compiled source effects, check the original call edge and supplier domain, transport actual source cuts, and compare memory/references/services with supplier bodies absent. Concrete runtime compatibility and entry/loop/tail composition remain separate. |
| `tests/fixtures/metapad-cleanup-tail`, `tests/unit/operator/test_source_tail_check.py` | Retained exact terminal transfers and manual boundary; exercise actual source error/repair, changed supplier reuse without consumer processes, contract invalidation and public evidence binding. |
| `components/bisimulation_fresh_buffer_contract.py`, `components/bisimulation_fresh_buffer_inputs.py`, `components/bisimulation_fresh_buffer_frame.py`, `components/bisimulation_fresh_buffer_model.py`, `components/bisimulation_fresh_buffer_template.py` | Public conditional cleanup entry profile: compiled length/allocation/byte-access admission, actual original prefix and source observer transport, with full outgoing scratch view, saved frame and all eight refined loop predicates. Concrete runtime qualification and regional composition remain separate. |
| `components/bisimulation_cleanup_admission.py`, `operator/source_composition_check.py` | Public composition admission consumes validated regional receipts, extracts actual spatial premises and checks existing/proposed caller and allocator requirements without application bodies. Includes nonempty-domain evidence and independent admission-proof reuse; state composition and concrete compatibility remain explicitly incomplete. |
| `components/bisimulation_private_transport.py`, `components/bisimulation_private_transport_template.py` | Checked lowering of actual direct private-cell accessors into byte-layout tables, consumed by the public composition phase. A fixed recipe checks inductive cell/byte correspondence, arbitrary untouched storage, overlapping-cell coherence, saved-frame and partial-word transport without regional application bodies. |
| `components/bisimulation_public_transport.py` | Public composition binds actual regional memory premises and guarantees to a pointwise current-memory substitution rule. It checks the tail zero-suffix representation and all eight public predicates without application bodies or accumulated write history; object lifetime remains a separate obligation. |
| `components/bisimulation_descriptor_transport.py` | Public composition imports the actual canonical view accessors and ABI, checks live opaque-context substitution and the tail write guard, and checks scratch-grant flow over the complete covered source graph. Named runtime requirements remain unverified; revocation is distinct from physical deallocation. |
| `components/bisimulation_cleanup_source_use.py` | Checks the covered cleanup compiler graph for opaque descriptor use, supported access widths and silent failed-read exits before substituting view representations. This structural premise does not prove functional equivalence. |
| `components/bisimulation_cleanup_composition.py` | Consumes guarded regional postconditions, complete source-region ownership and private-cell layouts to check coarse cleanup control, loop ranking and normal return-frame composition. Rejects weakened scopes, hidden assumptions, interior crossings and saved-word overlap. |
| `components/bisimulation_cleanup_observations.py` | Binds checked regional service helpers and all-outcome memory guarantees to ordered event-prefix composition, including memory-fault prefixes. Concrete service and caller qualification remain separate. |
| `components/bisimulation_cleanup_summary.py` | Checks complete original-operation coverage and assembles the regional composition evidence into a conditional paired-call contract. Supports checked withdrawal of normal-frame guarantees without changing the stronger proof domain; binds exported contracts separately from implementation receipts and native activation. |
| `components/caller_definition_document.py`, `components/bisimulation_caller_definition.py`, `operator/source_operation_call_check.py` | Load finite caller definitions through the existing source-check product. Validate exact ownership and entry/call coverage, stateless interface semantics, source view permissions, checked supplier guarantees and explicit unverified runtime contracts; no caller profile or interface hash selects semantics. |
| `components/bisimulation_supplier_call.py`, `tests/fixtures/metapad-cleanup-save/caller-contract.json`, `tests/fixtures/metapad-cleanup-replace/caller-contract.json` | Instantiate mandatory supplier entry, view and private-frame checks at each actual invocation against current memory. Real save/UI callers are data definitions; fact references derive image views and shared admission without replacing the ordinary C computation. |
| `components/bisimulation_native_calls.py`, `components/bisimulation_caller_interface.py` | Shared caller ABI instantiation: validate native events and argument storage, apply selected normal-return facts, derive portable service signatures and typed projections from compiled interfaces, and check complete source view/context frames. These adapters consume checked or named premises; signatures and declarations do not grant supplier guarantees. |
| `components/bisimulation_supplier_facts.py` | Normalize supported facts from an evidence-validated paired supplier: typed entry relations, selected normal frames, current-memory/view correspondence, explicit fault and private-frame transport. Bind named runtime assumptions separately from guarantees; check the consumer service value contract and native view extents. The legacy supplier producer is still a supported-rule boundary, not a universal summary format. |
| `components/bisimulation_caller_boundary.py` | Common outer caller model over typed entry/view/service/exit definitions. Executes the actual original and authored C, checks current memory and continuation transport, proves an exhaustive/disjoint outcome partition, and emits a separately checked nonempty-entry witness. Public definitions select admission and observations; supplier/runtime authority is bound separately. SDK preparation is shared through sourceCheck; writable definition transport and the real save/UI edit/check/reuse round trip are demonstrated. Exact slices can supply presentation source maps, and ownership-only bindings are derived as explicitly incomplete bookkeeping. Consumes validated fixed-image borrowed suppliers as well as cleanup summaries. View-valued operation results and current private continuation slots are checked; the already exercised ID-31 resource prefix passes public edit/reuse checks. The untouched third-consumer and final qualification audit remain open. |
| `tests/integration/native/consumer_runtime_adapter.py`, `tests/integration/native/consumer_resource_adapter.py`, `tests/integration/native/test_consumer_runtime_adapter.py`, `tests/fixtures/metapad-consumer-runtime/` | Finite PE32/Wine comparison of both actual original callers and ordinary-C consumers through generated cleanup adapters, live native origins, the original mapped PE resources and actual EDIT-window/notice services. Exercises mutable callback state, aliases, lifetime, mode/uint32 boundaries and fault prefixes; keeps fixture-owned admission and unsupported runtime scope explicit. |
| `components/bisimulation_runtime_view_transport.py` | Relates actual production returned-view callbacks to regional accessors under explicit issued-reference and hook contracts, including null views, interior coordinates, outcomes and complete single-hook effects. Imports validate literal code without regenerating headers. |
| `tests/fixtures/metapad-authored-call/cleanup-regions.json`, `tests/unit/operator/test_source_entry_region_check.py` | One manually defined graph for the actual entry/loop/tail; public entry error/repair and scoped reuse checks. Graph feedback distinguishes reachable coverage holes from compiler records after returns. |
| `components/bisimulation_compaction_domain.py` | Share the public-memory domain between entry assertions, loop assumptions and revision-3 outgoing checks, including null-allocation pending bytes. These checks do not compose evidence or qualify runtime lifetime and service contracts. |
| `components/bisimulation_compaction_contract.py`, `components/bisimulation_compaction_inputs.py`, `components/bisimulation_compaction_model.py`, `components/bisimulation_compaction_template.py`, `components/bisimulation_compaction_check.py`, `components/bisimulation_compaction_evidence.py`, `operator/source_region_check.py` | Conditional current-memory byte-compaction region proofs from public source graphs; bind exact original slices, state transport and complete checker evidence, with explicit runtime revisions, complete Z3/SAT evidence policy, current-source proof reuse and unverified runtime/whole-component obligations. |
| `components/bisimulation_connected.py`, `components/bisimulation_execution.py`, `components/bisimulation_evidence.py`, `components/bisimulation_world_memory.py` | Render transitional connected-call admission/replay, execute solver inventories, validate bound proof evidence, and render shared-world memory fragments for the contextual proof engine. |
| `components/bisimulation_readonly_access.py`, `components/bisimulation_readonly_model.py`, `components/bisimulation_readonly_contracts.py`, `components/bisimulation_readonly_evidence.py` | Check authored GOTO transport opacity and source-bound fixed readable-view frame, input-dependence and progress obligations as auxiliary qualification evidence. A separately identified shared-state/service opacity rule admits declared views and own-context service calls without granting a frame or summary theorem. Checked image-only consumers may omit bodies; other readable worlds retain replay. |
| `components/bisimulation_exact_frame.py` | Check supplementary original physical-memory write frames in the paired GOTO model and bind retained per-segment facts. A complete frame still requires checked caller entry and transport before composition. |
| `components/bisimulation_mutable_frame.py`, `components/bisimulation_clobber_frame.py` | Check fixed writable parameter/shared-image grants and declared architectural clobbers. Shared state transports only unchanged fixed image bindings; returned-view register bases remain observable. Service-range writes obey the enclosing grant, without establishing body-free service composition. |
| `components/bisimulation_mutable_memory.py` | Model current bytes and overlapping source/service writes. Explicitly preserved physical spans bypass history only with checked write-frame obligations; read-only aliases do not imply preservation. |
| `components/bisimulation_private_frame.py` | Check bounded residual stack-write footprints with a stable cut anchor, derive their wider-entry domain, and overapproximate original caller poststate only after consuming bound supplier facts. Logical buffer permissions and allocation lifetime remain separate. |
| `components/bisimulation_readable_entry.py` | Check all paired properties and physical frames over a wider stack domain, retaining exact compiler and solver bindings. These supplementary facts require separate caller premise checks. |
| `components/bisimulation_query_evidence.py` | Own fresh deterministic proof workspaces and reuse exact compiled CBMC queries from validated prior local proofs, with tool/model/argument and retained-output checks. |
| `components/bisimulation_shared_services.py` | Check selected service argument domains and footprints against logical views, and bind local premises to exact paired-source and regenerated-overlay evidence without granting summary composition. |
| `components/bisimulation_shared_model.py` | Generate conditional local shared-view frame and input-dependence models with ordered service traces, sparse memory events and authored result aliases. These source contracts do not qualify body-free provider summaries. |
| `components/normal_exit_postconditions.py` | Check hand-authored logical view equalities against the bound contextual proof and regenerated fixed-image state/result guards. These normal-return facts are not heap invariants, body-free summaries or provider authority. |
| `components/bisimulation_readable_composition.py` | Derive fixed image-world admission from checked readable source and paired frame evidence, and require actual caller origin and empty-allocation premises before omitting callee bodies. |
| `components/bisimulation_call_entry.py` | Derives checked leaf-supplier stack domains from bound proof systems and retained evidence, then requires actual original CALL entry assertions. Reference, heap and lifecycle premises remain separate. |
| `components/bisimulation_reference_transport.py` | Canonical reference/view inspectors assembled beside raw connected overlays, with explicit compiled/included proof inputs and mandatory caller transport guards. |
| `transfer/behavioral_c_model.py`, `transfer/behavioral_c_layout.py`, `transfer/behavioral_c_render.py`, `transfer/runtime_helpers.py` | Provide the shared checked-transfer-to-C compiler used by exact proof slices and candidate Behavioral-C packages; `candidate/` retains compatibility exports only. |
| `candidate/module_runtime_plan.py`, `candidate/module_runtime_render.py`, `candidate/module_runtime_layout.py`, `candidate/runtime_canonical.py`, `candidate/runtime_sources.py` | Canonical shared-module runtime planning, transfer-derived dispatch/capability synthesis, typed layout, source rendering, and deterministic packaging. |
| `candidate/callbacks.py`, `candidate/native_ingress_plan.py` | Runtime-neutral generational callback state plus generic ingress derivation from the resolved environment and checked closure; there is no callback-specific candidate authority adapter. |
| `pe32/module_interface.py`, `semantic_objects/object_authority.py`, `semantic_objects/references.py` | Own exact entry, TLS, relocation, import, zero-fill, mapped-object authority, and checked object-relative references consumed by semantic linking, providers, native ingress, and composition. Components consume these facts but do not own them. |
| `candidate/runtime.py`, `candidate/runtime_model.py`, `candidate/runtime_program_validation.py`, `candidate/runtime_plan_validation.py`, `candidate/runtime_receipts.py`, `candidate/runtime_render.py`, `candidate/runtime_render_core.py`, `candidate/runtime_render_entry.py`, `candidate/runtime_values.py` | Candidate external runtime model, input validation, receipts, C rendering, and strict values. |
| `candidate/native_build.py` | Generic native compile/compose pipeline. |
| `transfer/x87.py` | Typed, byte-free x87 replay records shared by plan compilation, evaluation, and candidate renderers. |
| `pe32/recovered_executable_data.py` | Checked classification of immutable initialized data embedded in executable sections. |

`reconstruction/plan.py` derives deterministic reconstruction clusters and
component discovery inputs from the checked machine IR.

`components/source.py` packages the exact portable files used by component
receipts and candidate source bundles. Compile, refinement, and activation receipts
cannot outlive a source-byte change.
The public component framework is the typed `components/` package and its
content-addressed component workflow DAG.

## Components And Portable Source

| Module | Purpose |
|---|---|
| `components/discovery.py`, `components/discovery_model.py`, `components/discovery_schema.py`, `components/discovery_checker.py`, `components/discovery_render.py` | Proposes coarsened component candidates with isolated models, schemas, checks, and rendering. |
| `components/proposal_package.py` | Writes and checks the v2 component-proposal package: compact selector index, exact unit-binding sidecar, bounded rich-record packs, selected-record lookup, and a separate complete producer audit. |
| `components/lifting_intent.py`, `components/indexes_v5.py`, `components/interface_package_v5.py` | Check the sole structural lifting intent, including the explicit representation proof classification, content-bound V5 indexes, and machine-free portable interfaces. |
| `components/binding_intent.py`, `components/normalized_component.py`, `components/machine_overlay_v5.py`, `components/machine_overlay_boundaries_v5.py` | Normalize retained operator intent into format-free proof-kernel values and bind V5 operations directly to exact machine-derived semantics, services, objects, callbacks, lifecycles, and outcomes. |
| `components/machine_storage.py` | Shared register-address validation and IA-32 rendering for scalar state and borrowed view bases in machine adapters and contextual proof projections. |
| `components/source.py`, `components/component_c_v5.py`, `components/errors.py` | Package exact V3 operation-symbol source, compile host and PE32 objects, and share strict component-artifact failures. |
| `components/semantic_contract.py`, `components/component_exact_c_slice.py`, `components/bisimulation.py`, `components/bisimulation_refinement.py`, `components/contextual_bisimulation.py` | Select exact contract-bound transfer-v2 rows, emit exact Behavioral-C slices, build linear forced-cutpoint proof plans, and check independently sharded contextual equivalence against arbitrary admitted shared worlds without path enumeration or test authority. |
| `components/semantic_external_transducers.py`, `components/semantic_paths.py`, `components/refinement.py`, `components/refinement_v5.py` | Retain the exact transducer and legacy finite-path kernels for unmigrated fixtures; migrated providers cannot use them as activation authority. |
| `components/aggregate_result_binding.py`, `components/semantic_record_transducers.py` | Share compiler-checked hidden record return lowering between overlays and semantic contracts; retain complete word-record arguments and initialized result projections, rejecting incomplete transport and unsupported finite expression consumers. |
| `semantic_providers/portable_c_work_package.py`, `semantic_providers/encapsulated_owned.py` | Qualify V6 portable providers through that same refinement kernel; representation-changing providers add only a conservative total-transfer/object-alias admission receipt and image-lifetime storage adapter, never another semantic proof pipeline. |
| `components/work_package_v6.py`, `components/relation_v5.py`, `components/proof_facet.py`, `components/portable_object.py` | Emit non-authorizing V6 work packages, including optional scope-bound caller definitions for writable copying and dependency inspection; check local relations and proof facets in memory, and compile exact portable objects without a public V4/V5 reducer stack. |
| `reconstruction/finite_values.py` | Explicit bounded scalar/pointer domains. |
| `external/source_operations.py` | Non-authoritative rendering of recovered operations as C. |

Component checks are local and scope-bounded. Promotion requires exact hashes
and interfaces; it does not erase unresolved whole-program reconstruction gaps.

## ABI, Imports, And External Operations

| Module | Purpose |
|---|---|
| `abi/model.py`, `abi/solver.py`, `abi/native_solver.py` | Typed physical call-boundary values and certificates plus deterministic finite-domain solving; the bounded Rust engine accelerates equality components while Python retains unresolved-frontier classification and fallback. |
| `abi/symbols.py` | Derive proposal-level physical ABI facts only where a pinned PE32 symbol-decoration model justifies them. Machine ABI authority belongs to the linked semantic module. |
| `abi/declarations.py`, `abi/declaration_spec.py`, `abi/catalog.py` | Bind reviewed header/debug declarations to exact source and library snapshot identities, then intersect them with catalog and machine facts. |
| `external/machine_abi.py` | Machine-level calling conventions and the reviewed conditional normal-return register premise. |
| `external/import_abi.py` | Expands reviewed ABI policy against exact PE imports. |
| `external/machine_import_profiles.py` | Imported-call profile parsing and binding. |
| `external/callback_protocols.py`, `external/callbacks.py` | Canonical structured callback protocols plus the derived legacy adapter view. |
| `external/contracts.py` | Canonical fail-closed machine contract shared by native external-call planning and runtime. |
| `external/operation_model.py`, `external/operation_profiles.py` | Typed machine external-operation/environment models plus strict parsing and validation. |
| `external/interface_profiles.py` | Interface/vtable catalogs and call identities. |
| `external/interface_ast.py` | Interface declarations recovered from AST JSON. |

## Linked Libraries

| Module | Purpose |
|---|---|
| `libraries/artifact_parsers.py`, `libraries/catalog.py`, `libraries/model.py`, `libraries/matching_support.py`, `libraries/contracts.py` | Object/archive parsing, exact legacy artifact indexes and locks, normalized function fingerprints, shared machine-package loading, and the retained exact linked-island record validator used at compatibility boundaries. |
| `libraries/abi_records.py`, `libraries/abi_catalog.py`, `libraries/signature_graph.py` | Strict v3 ABI/catalog schemas, independently cached catalog search records, and exact target signature graphs. |
| `libraries/constellations.py`, `libraries/native_index.py` | Sparse ABI-partitioned constellation proposals; the optional Rust index accelerates retrieval without becoming authority. |
| `libraries/v4_identity_records.py`, `libraries/v4_matching.py`, `libraries/v4_release_set.py` | Release- and island-scoped identity hypotheses, deterministic maximum-weight matching, and strict release-set access. |
| `libraries/v4_adoption_records.py`, `libraries/v4_activation.py` | Tracked operator adoption intent and the canonical checked-island authority boundary. |
| `libraries/v4_behavior_manifest.py`, `libraries/behavior_pack_v3.py`, `libraries/component_v5.py` | Lightweight content-bound behavior declarations, checked V3 reusable packs, and direct V5 ordinary component generation. |
| `nix/library-catalog-pack.nix`, `nix/library-behavior-pack-v3.nix`, `nix/library-island-check.nix`, `nix/library-provider-binding.nix`, `nix/linked-libraries.nix`, `nix/library-status.nix` | Content-addressed catalogs and V3 behavior packs plus role-separated recognition, checked-island authority, direct binding/slice derivation, ordinary V2 semantic-provider qualification, status, and check phases. |

Recognition uses individual function ABI envelopes, normalized bytes, data,
imports, and sparse control/dependency constellations rather than requiring one
copy of every historical implementation. Immutable packs separate binary
variants, ABI profiles, and reusable behavior entries. Function matches guide
release discovery; only a complete checked island and reusable behavior pack may
generate a candidate component. Exact artifacts and adoption intents remain
non-authorizing evidence until canonical boundary and implementation checks
close.

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
| `isa/conformance_shards.py`, `isa/conformance_worker.py`, `isa/qualification_worker.py` | Deterministic oracle sharding and isolated cached conformance/qualification workers. One qualification pass emits both the full diagnostic transcript and its compact checked certificate. |
| `isa/qualification_certificate.py`, `isa/formats.py` | Closed target-independent projection of exact per-form structural/oracle status and evidence hashes from the full qualification transcript, plus its domain-owned format declaration. |
| `build_support/lean_runner.py` | Small deterministic Lean compile/run helper. |

`src/spaghetti_extractor/lean/SpaghettiExtractor/ISA/` contains only the compact reusable ISA
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

Wine applications run in a headless Wayland desktop through the shared
`spaghetti-headless-wayland` runner. This includes candidate validation and
explicitly bound original/source comparison drivers. Reuse comparisons share
one desktop session so its environment remains stable across checks.

## Nix Constructors

| File | Output role |
|---|---|
| `toolkit-context.nix` | One reusable per-system source, package, kernel, oracle, and fixture context shared by the root flake and target SDK. |
| `target-sdk.nix` | Stable v5 target interface with `environment.pe32`, high-level `workflow.pe32`, a strict pure operator index, and one exact operator product tree for analysis, lifting, semantic linking, selection, realization, and validation. |
| `component-workflow.nix` | Content-addressed direct V6 component DAG: V5 interfaces and binding intents, V3 source, V2 semantic slices, V6 operator packages, dependency closure, and direct-provider eligibility. It exposes no V4 contract, implementation, or dependency graph. |
| `component-source-check.nix` | Operator source-feedback phase depending only on the selected interface, source and compilers; incomplete machine bindings do not prevent source editing, and passing compilation grants no qualification authority. |
| `component-source-call-check.nix` | Conditional original/source caller-region proof consuming independently cached source preparation and checked supplier contracts. Public SDK `lifting.sourceCheck` and bundle `callerCompositions` wire it through `component-source-check.nix`, derive shared preparation and permit previous evidence for reuse. Remaining caller/runtime obligations do not grant activation. |
| `component-source-region-check.nix` | Conditional original/source byte-compaction region comparison consuming cached manual graph preparation; selects Z3 or Cadical and exposes exact proof import and remaining entry/runtime/coverage obligations through sourceContractCheck. |
| `component-source-composition-check.nix` | Composition admission phase over retained entry/loop/tail products; checks spatial implication and nonvacuity, reuses independent proof evidence and exposes unresolved caller, allocator and state obligations through the existing sourceContractCheck workflow. |
| `component-source-edit-check.nix` | Configured baseline/current source comparison at manual boundaries, with portability checks, exact local-query reuse and separate baseline-proof eligibility; source comparison does not import application proofs or authorize activation. |
| `component-v5-interface-package.nix`, `component-v6-work-package.nix`, `component-semantic-slice-v2.nix`, `component-exact-c-slice-v1.nix`, `component-source-package-v3.nix`, `portable-c-work-package-provider-v2.nix` | Compile the sole active portable interface and source package, project exact semantics and immutable faithful-C context from `linked-semantic-module-v2`, render component-scoped Behavioral-C proof slices, emit the non-authorizing V6 work package, and qualify direct portable providers with independently cached semantic slices and native objects. |
| `call-protocol-workflow.nix` | Builds checked typed call protocols from authored intent, target layouts, the canonical executable transfer plan, and exact machine/callback authority evidence. |
| `boundary-workbench.nix` | Unifies checked call protocols and supplied canonical boundary packages behind stable subjects and emits non-authorizing operator work status. |
| `external-environment-intent.nix`, `resolved-external-environment.nix` | Compile external-environment intent and its authority-free analysis projection, then resolve exact module, profile, boundary, and static-authority bindings. |
| `header-machine-abi-profile.nix` | Derive checked PE32 machine-call shapes from pinned public C headers through Clang and the shared content-addressed JSON phase. |
| `machine-import-effect-profile.nix` | Compose explicit native call-through effect contracts with checked header ABIs through `sdk.environment.nativeCallthroughProfile`; reject physical disagreement and retain both input bindings. |
| `external-environment-provider-v2.nix` | Qualify and package exact V2 residual external-environment definitions without turning analysis projections into authority. |
| `portable-c-work-package-provider-v2.nix` | Build receipt-bound per-component portable-C semantic providers directly from semantic slices, interface/binding intent, and source V3. |
| `qualified-runtime-provider-v2.nix` | Qualifies shared runtime definitions as explicit V2 semantic providers; runtime support never appears as an implicit fallback. |
| `executable-transfer-plan.nix` | Compiles exact checked machine IR once into the canonical renderer-neutral executable transfer plan. |
| `semantic-isa-requirements.nix` | Derives the exact target ISA occurrence inventory once for semantic-object selection against the qualified platform; legacy authority may consume but cannot regenerate it. |
| `semantic-object.nix` | Packages the exact transfer-v2 and module-interface members as one relocatable, non-authorizing semantic-object migration unit. |
| `linked-semantic-module.nix` | Links one semantic object and its roots into the total checked module closure and runs independent replay through the shared phase constructor. |
| `linked-semantic-module-performance.nix` | Runs the speed-first exact-output semantic-link veto, independently enforcing the optional full-analysis and prepared-V2-projection budgets without imposing a fixed RSS ceiling. |
| `native-realization-v2.nix` | Links the total selected provider realization and binds every selected object, runtime provider, loader surface, decoded candidate, and observed candidate hash. |
| `qualified-platform.nix` | Builds one target-independent qualified-platform release shared by every target; target occurrences are not inputs. |
| `qualified-platform-isa-campaign.nix` | Runs the singleton intrinsic-form preparation, corpus, shared Lean/Bochs/Unicorn qualification, and compact certificate production; the 17 MiB transcript stays diagnostic while platform consumers read the checked certificate. |
| `qualified-platform-migration-parity.nix` | Veto-only migration gate proving that the exact Hello, Hello-derived, jq, and DX-Ball target-local campaigns agree on every shared semantic form; it consumes compact selection certificates and is retired with those campaigns. |
| `component-lifting-intent.nix`, `component-v5-index.nix`, `component-v5-interface-package.nix`, `component-v6-work-package.nix`, `component-semantic-slice-v2.nix`, `component-source-package-v3.nix` | Compile component intent and V5 indexes, then derive source, direct semantic slices, and non-authorizing V6 operator work packages without rebuilding a parallel structural contract graph. |
| `flake-modules/toolkit.nix`, `flake-modules/checks.nix` | Focused `flake-parts` modules for generic packages/apps/shells and checks. |
| `external-interface-profile.nix` | Pinned SDK headers through a checked machine-level interface profile. |
| `isa-conformance.nix` | One cached Lean/Unicorn/Bochs corpus evaluation. |
| `isa-qualification-graph.nix` | Sharded ISA evidence and qualification DAG. |
| `isa-semantic-kernel.nix` | Stable compiled Lean semantic kernel packaged independently of target evidence. |
| `isa-conformance-kernel.nix`, `inductive-certificate-kernel.nix` | Shared compiled Lean conformance and inductive-certificate kernels reused by granular tests and target evidence. |
| `roundtrip-corpus.nix` | Generated static corpus and qualification result. |
| `bochs-conformance.nix` | Pinned batched Bochs adapter. |
| `machine-import-control-profile.nix` | Content-addressed no-return import projection that isolates machine IR from ordinary API-profile edits. |
| `component-analysis.nix` | Original inventory through component proposals. |
| `component-discovery.nix` | Independent proposal phase; publishes the bounded v2 package only after streaming every rich record through its complete integrity audit. |
| `fallback-capability-analysis.nix` | Non-executable lowering analysis projected into final static authority; emits no source or object code. |
| `generated-behavioral-c-provider-v2.nix`, `external-environment-provider-v2.nix`, `qualified-runtime-provider-v2.nix`, `semantic-provider-selection-v2.nix` | Qualify exact generated/runtime/environment implementations and make one total exclusive V2 provider selection for every active definition and residual obligation. |
| `semantic-slice-v2.nix` | Materialize one content-addressed local semantic slice for operator work and contextual refinement without re-running whole-module semantic linking. |
| `machine-import-profile-bundle.nix` | Package resolved import contracts used by the linked semantic module and its providers. |
| `behavioral-c-package.nix`, `generated-behavioral-c-provider-v2.nix`, `portable-c-work-package-provider-v2.nix`, `native-realization-v2.nix` | Package immutable Behavioral C, qualify generated and portable native objects at their provider boundaries, then render, compile, link, compose, and receipt runtime/ingress once inside the selected V2 realization. |
| `behavioral-c-differential.nix` | Veto-only generated differential cases comparing the serialized transfer-plan evaluator with compiled faithful C. |
| `pe32-module-interface.nix`, `semantic-object.nix`, `native-realization-v2.nix` | Decode exact module loader surfaces, package loader-realized object authority as semantic-object data, and derive checked native ingress from the linked semantic module inside the one native realization. |
| `pe32-single-module-project-intent.nix`, `pe32-project-load-plan.nix`, `pe32-observed-load-graph.nix`, `pe32-project-completion.nix` | Derive the automatic one-module project, check multi-image import edges, bind candidate-observed loader evidence, and close deployment-only project completion. |
| `ca-python-json-phase.nix`, `ca-json-receipt-gate.nix` | Generic deterministic CA Python phases and role-aware JSON receipt gates with explicit store dependencies, schema/status checking, and build manifests. |
| `authority-resource-classes-v3.nix` | Transitional deterministic work-class hints for shard parallelism and disk estimates; it carries no RAM quota or process memory limit. |
| `test-suite.nix`, `test-suite-plan.nix`, `test-suite-shard.nix`, `test-suite-fixtures.nix`, `test-fixture-catalog.nix`, `generated/test-suite-manifest.json` | Static, checked stable test shards and shared heavy fixtures; Nix evaluates no dynamic test discovery and unchanged shards substitute. |
| `candidate-test-suite.nix` | Binds an exact complete native realization to optional curated veto cases and executes its candidate through isolated headless Wine. |
| `python-module-closure.nix` | Derivation-free exact local-Python source view with checked phase role, source hashes, resources, and a content-addressed manifest. |
| `generated/python-module-index.json` | Generated checked local-import/resource graph and role closures consumed by phase-specific Python closures. |
| `library-recognition.nix` | Prepares target signatures, catalog matches, and call contracts before static authority and adoption decisions consume them. |
| `linked-libraries.nix` | Canonical library-recognition facade over proposal discovery, V4 release/island hypotheses, tracked adoption intents, checked-island authority, direct semantic slices, and provider inputs. |
| `library-catalog-pack.nix`, `library-behavior-pack-v3.nix`, `library-island-check.nix`, `library-provider-binding.nix`, `library-status.nix` | Immutable target-neutral catalogs and V3 behavior packs, role-separated authority/candidate phases, direct binding intent for the shared V2 provider qualifier, and compact operator status/check leaves. |
| `native-extension.nix` | Pinned PyO3 build for bounded native proposal kernels such as sparse library indexing; Python checkers retain schema and authority ownership. |
| `transfer-native-extension.nix` | Pinned PyO3 build for coarse-grained transfer fixed-point acceleration behind checked Python parity. |
| `boundary-schema-workflow.nix` | Validates canonical boundary schemas, lowers checked IA-32 frames, and compiles their portable C projections for target consumers. |
| `relation-kernel.nix` | Compiles the reusable Lean kernel for boundary relations and checked state/effect composition. |
| `candidate-test-aggregate.nix`, `candidate-test-suite.nix` | Structural-gated expected-exit and bounded-liveness tests under isolated headless Wine. |
| `profile-registry-check.nix` | Exact-inventory, role, schema, and semantic validation for every reviewed reusable profile. |
| `target-bundle-lint.nix` | Exact authored-file ownership validation for every target bundle. |
| `xed-isa-catalog.nix` | Pinned deterministic XED instruction-catalog package and app. |
| `builders.example`, `trusted-public-keys.example` | Versioned templates for ignored repository-local or XDG CA builder policy. No host inventory is tracked. |

The supported consumer interface is `flake.lib.mkTargetSdk`. Low-level Nix
constructors are private implementation details rather than a parallel API.
CA derivations are first-class; dependency granularity, not CA mode alone,
determines invalidation.

`nix/target-sdk.nix` returns format `spaghetti-extractor-target-sdk-v5` and
owns the generic consumer boundary: `environment.pe32`, `workflow.pe32`, lower-level `analysis`,
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

Three checked-in files are generated repository metadata and must not be edited
by hand:

| Path | Ownership |
|---|---|
| `nix/generated/python-module-index.json` | Generated local-import/resource graph and explicit production-role closures. |
| `nix/generated/test-suite-manifest.json` | Generated stable test/shard topology. It is repository-only developer metadata. |
| `nix/generated/format-registry.json` | Generated active/retired format ownership, codec, and role registry. |

`nix run .#dev -- refresh` regenerates the module and test metadata atomically;
`tools/generate-format-registry.py` regenerates the format registry, and
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
- `pe32-kernel32-terminated-byte-read-v1.json`
- `pe32-mingw-directx-interface-extraction-v1.json`
- `pe32-mingw-win32-function-extraction-v1.json`
- `pe32-msvcrt-lockstep-v1.json`
- `pe32-msvcrt-machine-runtime-v1.json`
- `pe32-native-callthrough-runtime-v1.json`
- `pe32-user32-resource-text-runtime-v1.json`
- `pe32-normal-return-nonvolatile-v1.json`
- `pe32-oniguruma-runtime-v1.json`
- `pe32-static-cutpoints-and-paired-callables-v1.json`
- `pe32-win32-system-dll-abi-policy-v1.json`
- `pe32-win32-windowing-runtime-v1.json`
- `pe32-winmm-runtime-v1.json`
- `pe32-win32-gui-launch-assumptions-v1.json`
- `pe32-win32-console-launch-assumptions-v1.json`
- `interaction-contracts-v1.json`

The launch-assumption template is deliberately non-authorizing. The Nix
analysis phase binds it to the exact PE, checked static roots, and checked
callback contracts before it can contribute entry-state evidence.

`isa-catalogs/README.md` documents imported instruction catalogs;
`pe32-i686-core-smoke-v2.json` is the small reviewed smoke catalog. Larger
machine-generated catalogs belong in Nix outputs.

## Documentation

`docs/README.md` is the documentation index. The active design references are
`architecture.md`, `abi-analysis.md`, `components.md`, `external-operations.md`,
`isa-qualification.md`, `atomics.md`, `static-roundtrip-qualification.md`, and
`target-bundles.md`, `library-behavior-packs.md`, and
`performance-and-invalidation.md`. Historical plans
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
intent and its default configuration; extraction, semantic-module status, and
component proposals remain available in that state. Reviewed component intent
enables the component and candidate families atomically, so the SDK never
invents a placeholder configuration or treats a proposal as operator intent.

The corpus flake exports the complete artifact family at
`legacyPackages.x86_64-linux.targets.<id>`, the supported operator tree at
`operatorTargets.<id>`, its pure discovery metadata at `operatorIndex.<id>`,
and regression/acceptance checks at `targetChecks.<id>` and
`targetAcceptanceChecks.<id>`. Listing the registry or artifact families does
not force semantic linking or native realization. Candidate builds and suites are
addressed only through the operator tree, avoiding a second public naming
scheme.

`operatorIndex.<id>` is the strict `spaghetti-extractor-operator-index-v1`
contract. It inventories exact product names for project leaves, authored
component units, canonical boundary subjects, optional library workflows, and
candidate configurations/test suites. The corresponding `operatorTargets`
tree contains those products at the same paths and has no compatibility aliases
or component-configuration namespace. Library discovery is `null` when no
catalog is configured, and the generic artifact tree omits that branch,
avoiding synthetic empty library artifacts.
The two operator list commands emit the complete validated index in JSON mode;
there are no partial documents mislabeled with the index format.

The root flake validates `import-smoke`, the complete `test-suite`,
`repository-metadata`, `python-module-closure`, `linked-semantic-module`,
`machine-import-control-profile`, `isa-kernel`,
`inductive-certificate-kernel`, `roundtrip`, `target-sdk`, and `components`.
The target flake adds `corpus-boundary` plus one regression aggregate per
registered target. Acceptance aggregates additionally require a complete exact
native realization and its checked candidate where the target exposes them.

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

- `tests/unit/extraction/`, `tests/unit/reconstruction/`,
  `tests/unit/qualified_platform/`, `tests/unit/candidate/`, and
  `tests/unit/components/`: package-owner unit contracts for the migrated
  pipeline.
- `tests/unit/cli/` and `tests/unit/testkit/`: the exact public command surface,
  module closure, metadata, planning, and Nix-runner behavior.
- `nix/tests/`: focused Nix constructor, semantic-link invalidation, and
  candidate integration fixtures.
- `tests/integration/native/`: fixture-backed native integration; `tests/smoke/`
  and `tests/benchmark/` own their explicit suite tiers.
- `test_spx_isa_*`: ISA catalog, corpus, oracle, qualification, and Nix paths.
- `test_reconstruction_*`, `test_recursive_decode.py`,
  `test_rooted_state_machine.py`: static reconstruction and machine IR.
- `test_component_discovery.py`, `test_component_interface.py`, and
  `test_semantic_components.py`: generic component discovery/interface checks.
- `test_external_*`, `test_machine_abi.py`, `test_machine_import_profiles.py`: ABI and canonical external calls.
- `tests/unit/libraries/`, `test_source_operation_catalog.py`: canonical
  ABI-first recognition, activation-boundary checks, native-index parity, plus
  isolated legacy-reader compatibility and non-authoritative source rendering.
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
