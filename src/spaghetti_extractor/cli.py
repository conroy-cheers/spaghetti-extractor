"""Public command surface for the active reconstruction workflow."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

from .analysis.binary_inventory import stage_a_inventory_binary
from .analysis.isa_inventory import write_binary_isa_inventory
from .authority_v2_cli import (
    build_base_launch_profile_v2_from_paths,
    build_candidate_authority_v2_from_paths,
    build_external_site_proposals_v2_from_paths,
    build_static_hybrid_authority_v2_from_paths,
    derive_callback_entry_contracts_v2_from_paths,
    finalize_launch_profile_v2_from_paths,
    validate_candidate_authority_v2_from_paths,
    validate_static_hybrid_authority_v2_from_paths,
)
from .behavioral_roots import generate_behavioral_roots
from .component_discovery import write_component_proposals
from .component_selection import materialize_component_declarations
from .component_workspace import (
    create_component_workspace,
    promote_qualified_components,
    qualify_component,
    rebind_component_workspace,
    run_component_source_check,
)
from .contract_tools import (
    REFERENCE_CONTRACT_MODEL_ID,
    stage_a_diff_obligations,
    stage_a_explain_obligations,
    stage_a_export_reference_contract,
    stage_a_smoke_contract,
)
from .import_abi import expand_import_abi_policy
from .external_operation_profiles import load_external_operation_profile
from .isa_catalog_enrichment import write_enriched_side_isa_catalog
from .isa_conformance_worker import run_isa_conformance_worker
from .isa_conformance_nix import stage_a_check_isa_conformance_nix
from .opaque_reconstruction import stage_a_export_opaque_reconstruction
from .reconstruction_ir import export_machine_ir_package
from .roundtrip_fuzz.generator import generate_spike_corpus
from .roundtrip_fuzz.runner import run_roundtrip_corpus
from .semantic_components import write_semantic_component_catalog
from .source_operation_catalog import render_source_operations
from .source_project import bind_source_project
from .stage_b import (
    stage_b_explain_delta,
    stage_b_validate_candidate,
)
from .stage_b_c_backend import stage_b_generate_semantic_c_from_state_machine
from .stage_b_functional import (
    StageBFunctionalInputError,
    stage_b_run_functional_suite,
)
from .stage_b_interpreter_backend import write_stage_b_interpreter_package
from .stage_b_native_engine import write_stage_b_native_engine_package
from .stage_b_native_runtime import write_stage_b_native_runtime_package
from .stage_b_provenance import StageBProvenanceInputError, stage_b_generate_candidate_provenance
from .stage_b_skeleton import stage_b_generate_skeleton
from .stage_binary import StageAInputError
from .util import write_json


Handler = Callable[[argparse.Namespace], Any]


def _path(command: argparse.ArgumentParser, name: str, **kwargs: Any) -> None:
    command.add_argument(f"--{name.replace('_', '-')}", dest=name, type=Path, **kwargs)


def _many_paths(command: argparse.ArgumentParser, name: str) -> None:
    command.add_argument(
        f"--{name.replace('_', '-')}", dest=name, type=Path, action="append", default=[]
    )


def _command(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    help_text: str,
    handler: Handler,
) -> argparse.ArgumentParser:
    parser = commands.add_parser(name, help=help_text)
    parser.set_defaults(handler=handler)
    return parser


def _build_parser(*, prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog or "spaghetti-extractor")
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = _command(
        commands,
        "stage-a-inventory-binary",
        "classify every executable byte and recover static code regions",
        lambda a: stage_a_inventory_binary(
            binary=a.binary, linker_map=a.linker_map, side="original", out=a.out
        ),
    )
    _path(inventory, "binary", required=True)
    _path(inventory, "linker_map")
    _path(inventory, "out", required=True)

    behavioral_roots = _command(
        commands,
        "stage-a-export-behavioral-roots",
        "bind PE entry, executable export, and immutable TLS callback roots",
        lambda a: write_json(a.out, generate_behavioral_roots(a.original)),
    )
    _path(behavioral_roots, "original", required=True)
    _path(behavioral_roots, "out", required=True)

    base_launch_v2 = _command(
        commands,
        "stage-a-build-base-launch-profile-v2",
        "build exact PE launch assumptions before callback-root finalization",
        lambda a: _generated_intermediate(
            build_base_launch_profile_v2_from_paths(
                original=a.original,
                behavioral_roots=a.behavioral_roots,
                assumptions=a.assumptions,
                feature_inventory=a.feature_inventory,
                out=a.out,
            ),
            artifact="base_launch_profile_v2",
        ),
    )
    _path(base_launch_v2, "original", required=True)
    _path(base_launch_v2, "behavioral_roots", required=True)
    _path(base_launch_v2, "assumptions", required=True)
    _path(base_launch_v2, "feature_inventory", required=True)
    _path(base_launch_v2, "out", required=True)

    callback_entries_v2 = _command(
        commands,
        "stage-a-derive-callback-entry-contracts-v2",
        "derive callback entry contracts from registration and strict state evidence",
        lambda a: derive_callback_entry_contracts_v2_from_paths(
            original=a.original,
            machine_ir=a.machine_ir,
            interface_provenance=a.interface_provenance,
            global_slot_invariants=a.global_slot_invariants,
            out=a.out,
        ),
    )
    _path(callback_entries_v2, "original", required=True)
    _path(callback_entries_v2, "machine_ir", required=True)
    _path(callback_entries_v2, "interface_provenance", required=True)
    _path(callback_entries_v2, "global_slot_invariants", required=True)
    _path(callback_entries_v2, "out", required=True)

    finalize_launch_v2 = _command(
        commands,
        "stage-a-finalize-launch-profile-v2",
        "bind checked event callback roots into an exact PE launch profile",
        lambda a: finalize_launch_profile_v2_from_paths(
            base_launch_profile=a.base_launch_profile,
            behavioral_roots=a.behavioral_roots,
            callback_entry_contracts=a.callback_entry_contracts,
            out=a.out,
        ),
    )
    _path(finalize_launch_v2, "base_launch_profile", required=True)
    _path(finalize_launch_v2, "behavioral_roots", required=True)
    _path(finalize_launch_v2, "callback_entry_contracts", required=True)
    _path(finalize_launch_v2, "out", required=True)

    isa_inventory = _command(
        commands,
        "stage-a-inventory-isa",
        "classify the instruction forms required by one static binary inventory",
        lambda a: write_binary_isa_inventory(
            binary=a.binary, inventory=a.inventory, scope=a.scope, out=a.out
        ),
    )
    _path(isa_inventory, "binary", required=True)
    _path(isa_inventory, "inventory", required=True)
    isa_inventory.add_argument("--scope", choices=("base", "superset"), default="superset")
    _path(isa_inventory, "out", required=True)

    opaque = _command(
        commands,
        "stage-a-export-opaque-reconstruction",
        "emit the original-only reference contract and canonical state machine",
        lambda a: stage_a_export_opaque_reconstruction(
            original=a.original, inventory=a.inventory, out=a.out
        ),
    )
    _path(opaque, "original", required=True)
    _path(opaque, "inventory", required=True)
    _path(opaque, "out", required=True)

    reference = _command(
        commands,
        "stage-a-export-reference-contract",
        "emit reusable static constraints and source-mapped transfer contracts",
        lambda a: stage_a_export_reference_contract(
            original=a.original,
            mapping=a.mapping,
            out=a.out,
            sidecar_dir=a.sidecar_dir,
            unit_contract_dir=a.unit_contract_dir,
            model=REFERENCE_CONTRACT_MODEL_ID,
        ),
    )
    _path(reference, "original", required=True)
    _path(reference, "mapping")
    _path(reference, "sidecar_dir")
    _path(reference, "unit_contract_dir")
    _path(reference, "out", required=True)

    smoke = _command(
        commands,
        "stage-a-smoke-contract",
        "run the cheap reference-contract consistency gate",
        lambda a: stage_a_smoke_contract(reference_contract=a.reference_contract, out=a.out),
    )
    _path(smoke, "reference_contract", required=True)
    _path(smoke, "out")

    explain = _command(
        commands,
        "stage-a-explain-contract",
        "explain one static contract region, family, or issue",
        lambda a: stage_a_explain_obligations(
            reference_contract=a.reference_contract, focus=a.focus, out=a.out
        ),
    )
    _path(explain, "reference_contract", required=True)
    explain.add_argument("--focus", required=True)
    _path(explain, "out")

    diff = _command(
        commands,
        "stage-a-diff-contract",
        "diff two static contract iterations",
        lambda a: stage_a_diff_obligations(before=a.before, after=a.after, out=a.out),
    )
    _path(diff, "before", required=True)
    _path(diff, "after", required=True)
    _path(diff, "out")

    import_abi = _command(
        commands,
        "stage-a-expand-import-abi",
        "bind reviewed ABI policy to exact PE imports",
        lambda a: expand_import_abi_policy(
            original_pe=a.original, policy=a.policy, out=a.out
        ),
    )
    _path(import_abi, "original", required=True)
    _path(import_abi, "policy", required=True)
    _path(import_abi, "out", required=True)

    conformance = _command(
        commands,
        "stage-a-check-isa-conformance",
        "run one ISA oracle as a cached Nix derivation",
        _run_isa_conformance_nix,
    )
    _path(conformance, "corpus", required=True)
    conformance.add_argument("--backend", choices=("lean", "unicorn", "bochs"), required=True)
    _path(conformance, "bochs_runner")
    _path(conformance, "forms_out")
    _path(conformance, "flake")
    _path(conformance, "builders_file")
    _path(conformance, "builder_trusted_public_keys_file")
    _path(conformance, "out", required=True)

    worker = _command(
        commands,
        "stage-a-check-isa-conformance-worker",
        "internal Nix worker for one concrete ISA oracle",
        _run_isa_conformance_worker,
    )
    _path(worker, "corpus", required=True)
    worker.add_argument("--backend", choices=("lean", "unicorn", "bochs"), required=True)
    _path(worker, "bochs_runner")
    _path(worker, "lean_kernel_cache")
    worker.add_argument("--lean-timeout-seconds", type=int, default=1800)
    _path(worker, "forms_out")
    _path(worker, "out", required=True)

    enrich = _command(
        commands,
        "stage-a-enrich-isa-catalog",
        "replay static encodings and derive qualification metadata",
        lambda a: write_enriched_side_isa_catalog(
            proposal=a.proposal, out=a.out, timeout_seconds=a.timeout_seconds
        ),
    )
    _path(enrich, "proposal", required=True)
    enrich.add_argument("--timeout-seconds", type=float, default=300.0)
    _path(enrich, "out", required=True)

    roundtrip_generate = _command(
        commands,
        "roundtrip-generate",
        "generate small PE32 static-analysis regression cases",
        lambda a: generate_spike_corpus(
            out=a.out,
            seed=a.seed,
            count=a.count,
            toolchain=a.toolchain,
            compiler=a.compiler,
            linker=a.linker,
            force=a.force,
        ),
    )
    _path(roundtrip_generate, "out", required=True)
    roundtrip_generate.add_argument("--seed", type=int, default=0)
    roundtrip_generate.add_argument("--count", type=int, default=36)
    roundtrip_generate.add_argument("--toolchain", choices=("gnu", "llvm-msvc"), default="gnu")
    roundtrip_generate.add_argument("--compiler")
    roundtrip_generate.add_argument("--linker")
    roundtrip_generate.add_argument("--force", action="store_true")

    roundtrip_run = _command(
        commands,
        "roundtrip-run",
        "qualify generated PE32 extraction and violation localization",
        lambda a: run_roundtrip_corpus(
            corpus=a.corpus,
            out=a.out,
            case_ids=tuple(a.case),
        ),
    )
    _path(roundtrip_run, "corpus", required=True)
    roundtrip_run.add_argument("--case", action="append", default=[])
    _path(roundtrip_run, "out", required=True)

    machine_ir = _command(
        commands,
        "stage-a-export-machine-ir",
        "export deterministic byte-free executable machine IR",
        _export_machine_ir,
    )
    _path(machine_ir, "state_machine", required=True)
    _path(machine_ir, "original", required=True)
    _path(machine_ir, "reference_contract")
    _path(machine_ir, "indirect_target_profile")
    _many_paths(machine_ir, "machine_import_profile")
    _many_paths(machine_ir, "external_interface_profile")
    _many_paths(machine_ir, "external_operation_profile")
    _path(machine_ir, "out", required=True)

    external_sites_v2 = _command(
        commands,
        "stage-a-build-external-site-proposals-v2",
        "bind normalized external-site candidates for strict v2 replay",
        lambda a: build_external_site_proposals_v2_from_paths(
            legacy_v1_diagnostic=a.legacy_v1_diagnostic,
            machine_ir=a.machine_ir,
            original=a.original,
            out=a.out,
        ),
    )
    _path(external_sites_v2, "legacy_v1_diagnostic", required=True)
    _path(external_sites_v2, "machine_ir", required=True)
    _path(external_sites_v2, "original", required=True)
    _path(external_sites_v2, "out", required=True)

    static_authority_v2 = _command(
        commands,
        "stage-a-build-static-hybrid-authority-v2",
        "build strict v2 global-slot, entry, ISA, exception, and final authority artifacts",
        lambda a: build_static_hybrid_authority_v2_from_paths(
            machine_ir=a.machine_ir,
            machine_ir_manifest=a.machine_ir_manifest,
            original=a.original,
            behavioral_roots=a.behavioral_roots,
            legacy_v1_diagnostic=a.legacy_v1_diagnostic,
            checked_external_sites=a.checked_external_sites,
            external_profile_authority=a.external_profile_authority,
            isa_requirements=a.isa_requirements,
            isa_selection_authority=a.isa_selection_authority,
            launch_profile=a.launch_profile,
            checked_exception_reports=a.checked_exception_report,
            entry_range_facts=a.entry_range_fact,
            world_range_facts=a.world_range_fact,
            machine_import_profiles=a.machine_import_profile,
            external_interface_profiles=a.external_interface_profile,
            external_operation_profiles=a.external_operation_profile,
            callable_external_profiles=a.callable_external_profile,
            internal_function_contract_profiles=a.internal_function_contract_profile,
            static_recovery_inventory=a.static_recovery_inventory,
            out=a.out,
        ),
    )
    _add_static_authority_v2_inputs(static_authority_v2)
    _path(static_authority_v2, "out", required=True)

    validate_static_authority_v2 = _command(
        commands,
        "stage-a-validate-static-hybrid-authority-v2",
        "cold-replay a strict v2 static pipeline and reject stale artifacts",
        lambda a: validate_static_hybrid_authority_v2_from_paths(
            pipeline=a.pipeline,
            machine_ir=a.machine_ir,
            machine_ir_manifest=a.machine_ir_manifest,
            original=a.original,
            behavioral_roots=a.behavioral_roots,
            legacy_v1_diagnostic=a.legacy_v1_diagnostic,
            checked_external_sites=a.checked_external_sites,
            external_profile_authority=a.external_profile_authority,
            isa_requirements=a.isa_requirements,
            isa_selection_authority=a.isa_selection_authority,
            launch_profile=a.launch_profile,
            checked_exception_reports=a.checked_exception_report,
            entry_range_facts=a.entry_range_fact,
            world_range_facts=a.world_range_fact,
            machine_import_profiles=a.machine_import_profile,
            external_interface_profiles=a.external_interface_profile,
            external_operation_profiles=a.external_operation_profile,
            callable_external_profiles=a.callable_external_profile,
            internal_function_contract_profiles=a.internal_function_contract_profile,
            static_recovery_inventory=a.static_recovery_inventory,
            out=a.out,
        ),
    )
    _path(validate_static_authority_v2, "pipeline", required=True)
    _add_static_authority_v2_inputs(validate_static_authority_v2)
    _path(validate_static_authority_v2, "out")

    candidate_authority_v2 = _command(
        commands,
        "stage-b-build-candidate-authority-v2",
        "build the strict v2 candidate-generation authority receipt",
        lambda a: build_candidate_authority_v2_from_paths(
            final_static_hybrid_audit=a.final_static_hybrid_audit,
            authority_bundle=a.authority_bundle,
            machine_ir=a.machine_ir,
            machine_ir_manifest=a.machine_ir_manifest,
            fallback_coverage_receipt=a.fallback_coverage_receipt,
            legacy_v1_diagnostics=a.legacy_v1_diagnostic,
            out=a.out,
        ),
    )
    _add_candidate_authority_v2_inputs(candidate_authority_v2)
    _path(candidate_authority_v2, "out", required=True)

    validate_candidate_authority_v2 = _command(
        commands,
        "stage-b-validate-candidate-authority-v2",
        "replay a strict v2 candidate receipt against its exact inputs",
        lambda a: validate_candidate_authority_v2_from_paths(
            receipt=a.receipt,
            final_static_hybrid_audit=a.final_static_hybrid_audit,
            authority_bundle=a.authority_bundle,
            machine_ir=a.machine_ir,
            machine_ir_manifest=a.machine_ir_manifest,
            fallback_coverage_receipt=a.fallback_coverage_receipt,
            legacy_v1_diagnostics=a.legacy_v1_diagnostic,
            out=a.out,
        ),
    )
    _path(validate_candidate_authority_v2, "receipt", required=True)
    _add_candidate_authority_v2_inputs(validate_candidate_authority_v2)
    _path(validate_candidate_authority_v2, "out")

    skeleton = _command(
        commands,
        "stage-b-generate-skeleton",
        "generate a compilable C scaffold or contract-guided baseline",
        lambda a: stage_b_generate_skeleton(
            original=a.original,
            linker_map=a.linker_map,
            reference_contract=a.reference_contract,
            out_dir=a.out,
            target_name=a.target_name,
            implementation_mode=a.mode,
            source_language="c",
        ),
    )
    _path(skeleton, "original", required=True)
    _path(skeleton, "linker_map")
    _path(skeleton, "reference_contract")
    skeleton.add_argument("--target-name", required=True)
    skeleton.add_argument(
        "--mode", choices=("scaffold", "decompiled-c", "contract-guided-c"), default="contract-guided-c"
    )
    _path(skeleton, "out", required=True)

    semantic_c = _command(
        commands,
        "stage-b-generate-semantic-c",
        "lower the canonical state machine into deterministic C",
        lambda a: stage_b_generate_semantic_c_from_state_machine(
            state_machine=a.state_machine,
            machine_call_catalog=a.machine_call_catalog,
            out_dir=a.out,
        ),
    )
    _path(semantic_c, "state_machine", required=True)
    _path(semantic_c, "machine_call_catalog")
    _path(semantic_c, "out", required=True)

    interpreter = _command(
        commands,
        "stage-b-generate-interpreter",
        "emit the portable machine-IR interpreter package",
        lambda a: write_stage_b_interpreter_package(
            state_machine=a.state_machine,
            machine_ir=a.machine_ir,
            out=a.out,
            allow_deferred_potential_transfers=a.allow_deferred_potential_transfers,
        ),
    )
    _path(interpreter, "state_machine")
    _path(interpreter, "machine_ir")
    _path(interpreter, "out", required=True)
    interpreter.add_argument(
        "--allow-deferred-potential-transfers", action="store_true"
    )

    native_engine = _command(
        commands,
        "stage-b-generate-native-engine",
        "emit PE32 ABI bridges for the generated interpreter",
        lambda a: write_stage_b_native_engine_package(
            state_machine=a.state_machine,
            machine_ir=a.machine_ir,
            entry_rva=a.entry_rva,
            callable_external_contract=a.callable_external_contract,
            allow_deferred_potential_transfers=a.allow_deferred_potential_transfers,
            out=a.out,
        ),
    )
    _path(native_engine, "state_machine")
    _path(native_engine, "machine_ir")
    native_engine.add_argument("--entry-rva", type=lambda v: int(v, 0), required=True)
    _path(native_engine, "callable_external_contract")
    _path(native_engine, "out", required=True)
    native_engine.add_argument(
        "--allow-deferred-potential-transfers", action="store_true"
    )

    native_runtime = _command(
        commands,
        "stage-b-generate-native-runtime",
        "emit the candidate-only external runtime package",
        lambda a: write_stage_b_native_runtime_package(
            interpreter_package=a.interpreter_package,
            native_engine_package=a.native_engine_package,
            external_profile=a.external_profile,
            callable_external_contract=a.callable_external_contract,
            out=a.out,
        ),
    )
    _path(native_runtime, "interpreter_package", required=True)
    _path(native_runtime, "native_engine_package", required=True)
    _path(native_runtime, "external_profile")
    _path(native_runtime, "callable_external_contract")
    _path(native_runtime, "out", required=True)

    components = _command(
        commands,
        "stage-b-build-component-catalog",
        "derive semantic component definitions from machine IR",
        lambda a: write_semantic_component_catalog(
            machine_ir=a.machine_ir,
            reconstruction_plan=a.reconstruction_plan,
            declarations=a.declarations,
            out=a.out,
        ),
    )
    _path(components, "machine_ir", required=True)
    _path(components, "reconstruction_plan", required=True)
    _path(components, "declarations", required=True)
    _path(components, "out", required=True)

    discovery = _command(
        commands,
        "stage-b-discover-components",
        "propose component coarsenings without authorizing replacement",
        lambda a: write_component_proposals(
            machine_ir=a.machine_ir,
            reconstruction_plan=a.reconstruction_plan,
            out=a.out,
            max_units=a.max_units,
            max_candidates_per_seed=a.max_candidates_per_seed,
        ),
    )
    _path(discovery, "machine_ir", required=True)
    _path(discovery, "reconstruction_plan", required=True)
    discovery.add_argument("--max-units", type=int, default=512)
    discovery.add_argument("--max-candidates-per-seed", type=int, default=12)
    _path(discovery, "out", required=True)

    selection = _command(
        commands,
        "stage-b-select-components",
        "materialize reviewed component declarations",
        lambda a: materialize_component_declarations(
            proposals=a.proposals, selection=a.selection, out=a.out
        ),
    )
    _path(selection, "proposals", required=True)
    _path(selection, "selection", required=True)
    _path(selection, "out", required=True)

    component_create = _command(
        commands,
        "stage-b-create-component",
        "create an editable portable-C component workspace",
        _create_component,
    )
    _path(component_create, "catalog")
    _path(component_create, "plan")
    _path(component_create, "machine_ir")
    _path(component_create, "component_slice")
    _path(component_create, "interpreter_package", required=True)
    _path(component_create, "interface_refinement", required=True)
    component_create.add_argument("--component-id", required=True)
    component_create.add_argument("--profile", required=True)
    _path(component_create, "out", required=True)

    component_rebind = _command(
        commands,
        "stage-b-rebind-component",
        "refresh hashes after editing portable component source",
        lambda a: rebind_component_workspace(workspace=a.workspace),
    )
    _path(component_rebind, "workspace", required=True)

    component_check = _command(
        commands,
        "stage-b-check-component",
        "run the bounded component contract checker",
        lambda a: run_component_source_check(
            workspace=a.workspace, cbmc=a.cbmc, out=a.out, timeout_seconds=a.timeout_seconds
        ),
    )
    _path(component_check, "workspace", required=True)
    component_check.add_argument("--cbmc", required=True)
    component_check.add_argument("--timeout-seconds", type=int, default=120)
    _path(component_check, "out", required=True)

    component_qualify = _command(
        commands,
        "stage-b-qualify-component",
        "bind source evidence and authorize one component replacement",
        lambda a: qualify_component(
            workspace=a.workspace, source_evidence=a.source_evidence, out=a.out
        ),
    )
    _path(component_qualify, "workspace", required=True)
    _path(component_qualify, "source_evidence", required=True)
    _path(component_qualify, "out", required=True)

    component_promote = _command(
        commands,
        "stage-b-promote-components",
        "compose qualified components into an override registry",
        lambda a: promote_qualified_components(
            workspaces=a.workspace, qualifications=a.qualification, out_dir=a.out
        ),
    )
    _many_paths(component_promote, "workspace")
    _many_paths(component_promote, "qualification")
    _path(component_promote, "out", required=True)

    source_bind = _command(
        commands,
        "stage-b-bind-source-project",
        "bind a portable source project to machine-IR components",
        _bind_source_project,
    )
    _path(source_bind, "spec", required=True)
    _path(source_bind, "source_root", required=True)
    _path(source_bind, "machine_ir", required=True)
    _path(source_bind, "out", required=True)

    render_operations = _command(
        commands,
        "stage-b-render-source-operations",
        "render recovered external operations as non-authoritative C calls",
        _render_source_operations,
    )
    _path(render_operations, "catalog", required=True)
    _path(render_operations, "operation_profile", required=True)
    _path(render_operations, "operations", required=True)
    _path(render_operations, "out", required=True)

    functional = _command(
        commands,
        "stage-b-run-functional-suite",
        "run curated candidate-only expected-output tests under headless Wine",
        lambda a: stage_b_run_functional_suite(
            candidate_command=tuple(a.candidate_command),
            candidate_binary=a.candidate_binary,
            suite=a.suite,
            out=a.out,
        ),
    )
    functional.add_argument("--candidate-command", nargs="+", required=True)
    _path(functional, "candidate_binary")
    _path(functional, "suite", required=True)
    _path(functional, "out", required=True)

    provenance = _command(
        commands,
        "stage-b-record-candidate",
        "record candidate-only source and build provenance",
        lambda a: stage_b_generate_candidate_provenance(
            target_name=a.target_name,
            candidate=a.candidate,
            skeleton_manifest=a.skeleton_manifest,
            build_target=a.build_target,
            build_compiler=a.build_compiler,
            out=a.out,
        ),
    )
    provenance.add_argument("--target-name", required=True)
    provenance.add_argument("--build-target", required=True)
    provenance.add_argument("--build-compiler", required=True)
    _path(provenance, "candidate", required=True)
    _path(provenance, "skeleton_manifest", required=True)
    _path(provenance, "out", required=True)

    validate = _command(
        commands,
        "stage-b-validate-candidate",
        "compare candidate static evidence to the reference contract",
        lambda a: stage_b_validate_candidate(
            reference_contract=a.reference_contract,
            candidate=a.candidate,
            linker_map_candidate=a.linker_map_candidate,
            skeleton_manifest=a.skeleton_manifest,
            candidate_provenance=a.candidate_provenance,
            target_name=a.target_name,
            out=a.out,
        ),
    )
    validate.add_argument("--target-name", required=True)
    _path(validate, "reference_contract", required=True)
    _path(validate, "candidate", required=True)
    _path(validate, "linker_map_candidate", required=True)
    _path(validate, "skeleton_manifest", required=True)
    _path(validate, "candidate_provenance", required=True)
    _path(validate, "out", required=True)

    delta = _command(
        commands,
        "stage-b-explain-delta",
        "rank source-mapped candidate repair items",
        _explain_delta,
    )
    _path(delta, "reference_contract", required=True)
    _path(delta, "candidate", required=True)
    _path(delta, "linker_map_candidate", required=True)
    _path(delta, "skeleton_manifest", required=True)
    _path(delta, "candidate_crash_report")
    _path(delta, "out", required=True)

    return parser


def _run_isa_conformance_nix(args: argparse.Namespace) -> dict[str, Any]:
    return stage_a_check_isa_conformance_nix(
        corpus=args.corpus,
        backend=args.backend,
        out=args.out,
        forms_out=args.forms_out,
        bochs_runner=args.bochs_runner,
        flake=args.flake,
        builders_file=args.builders_file,
        builder_trusted_public_keys_file=args.builder_trusted_public_keys_file,
    )


def _add_candidate_authority_v2_inputs(command: argparse.ArgumentParser) -> None:
    _path(command, "final_static_hybrid_audit", required=True)
    _path(command, "authority_bundle", required=True)
    _path(command, "machine_ir", required=True)
    _path(command, "machine_ir_manifest", required=True)
    _path(command, "fallback_coverage_receipt", required=True)
    _many_paths(command, "legacy_v1_diagnostic")


def _add_static_authority_v2_inputs(command: argparse.ArgumentParser) -> None:
    _path(command, "machine_ir", required=True)
    _path(command, "machine_ir_manifest", required=True)
    _path(command, "original", required=True)
    _path(command, "behavioral_roots", required=True)
    _path(command, "legacy_v1_diagnostic")
    _path(command, "checked_external_sites")
    _path(command, "external_profile_authority")
    _path(command, "isa_requirements", required=True)
    _path(command, "isa_selection_authority", required=True)
    _path(command, "launch_profile")
    _many_paths(command, "checked_exception_report")
    _many_paths(command, "entry_range_fact")
    _many_paths(command, "world_range_fact")
    _many_paths(command, "machine_import_profile")
    _many_paths(command, "external_interface_profile")
    _many_paths(command, "external_operation_profile")
    _many_paths(command, "callable_external_profile")
    _many_paths(command, "internal_function_contract_profile")
    _path(command, "static_recovery_inventory")


def _run_isa_conformance_worker(args: argparse.Namespace) -> dict[str, Any]:
    return run_isa_conformance_worker(
        corpus_path=args.corpus,
        backend=args.backend,
        out=args.out,
        bochs_runner=args.bochs_runner,
        lean_kernel_cache=args.lean_kernel_cache,
        lean_timeout_seconds=args.lean_timeout_seconds,
        forms_out=args.forms_out,
    )


def _export_machine_ir(args: argparse.Namespace) -> Any:
    package = export_machine_ir_package(
        state_machine=args.state_machine,
        original_pe=args.original,
        out=args.out,
        reference_contract=args.reference_contract,
        indirect_target_profile=args.indirect_target_profile,
        machine_import_profiles=args.machine_import_profile,
        external_interface_profiles=args.external_interface_profile,
        external_operation_profiles=args.external_operation_profile,
    )
    return package.manifest


def _create_component(args: argparse.Namespace) -> dict[str, Any]:
    return create_component_workspace(
        catalog=args.catalog,
        plan=args.plan,
        machine_ir=args.machine_ir,
        component_slice=args.component_slice,
        interpreter_package=args.interpreter_package,
        component_id=args.component_id,
        proof_profile=args.profile,
        interface_refinement=args.interface_refinement,
        out_dir=args.out,
    )


def _bind_source_project(args: argparse.Namespace) -> dict[str, Any]:
    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    return bind_source_project(
        specification=spec,
        source_root=args.source_root,
        machine_ir=args.machine_ir,
        out=args.out,
    )


def _render_source_operations(args: argparse.Namespace) -> dict[str, Any]:
    profile = load_external_operation_profile(args.operation_profile)
    operations_payload = json.loads(args.operations.read_text(encoding="utf-8"))
    operations = operations_payload.get("operations") if isinstance(operations_payload, dict) else None
    if not isinstance(operations, list):
        raise StageAInputError("operation evidence must contain an operations array")
    result = render_source_operations(
        catalog=args.catalog,
        operation_profile_sha256=profile.sha256,
        operations=operations,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _explain_delta(args: argparse.Namespace) -> dict[str, Any]:
    return stage_b_explain_delta(
        reference_contract=args.reference_contract,
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        skeleton_manifest=args.skeleton_manifest,
        candidate_crash_report=args.candidate_crash_report,
        out=args.out,
    )


def _exit_status(result: dict[str, Any]) -> int:
    status = result.get("status", result.get("verdict"))
    return 0 if status in {
        None,
        "checked",
        "complete",
        "authorized",
        "generated",
        "pass",
        "qualified",
        "ready",
        "satisfied",
        "usable-incomplete",
    } else 1


def _generated_intermediate(
    result: dict[str, Any], *, artifact: str
) -> dict[str, Any]:
    """Report successful creation when an intermediate is incomplete by design."""

    return {
        "status": "generated",
        "artifact": artifact,
        "artifact_status": result.get("status"),
        "content_sha256": result.get(
            "content_sha256", result.get("analysis_sha256")
        ),
    }


def main(argv: list[str] | None = None, *, prog: str | None = None) -> int:
    parser = _build_parser(prog=prog)
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
    except (
        OSError,
        StageAInputError,
        StageBFunctionalInputError,
        StageBProvenanceInputError,
        ValueError,
    ) as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    if isinstance(result, int):
        return result
    if isinstance(result, dict):
        print(json.dumps(result, indent=2, sort_keys=True))
        return _exit_status(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
