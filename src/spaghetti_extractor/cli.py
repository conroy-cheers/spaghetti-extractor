from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import pefile

from .artifact_formats import SEMANTIC_CLAIM_CHECK_FORMAT
from .isa_conformance import (
    ReportQualification,
    parse_isa_conformance_corpus,
    serialize_isa_conformance_report,
)
from .isa_conformance_lean import (
    lean_semantic_form_classifier_sha256,
    run_lean_isa_conformance,
    run_lean_isa_conformance_with_forms,
)
from .isa_conformance_nix import stage_a_check_isa_conformance_nix
from .isa_conformance_unicorn import run_unicorn_corpus
from .isa_conformance_bochs import run_bochs_corpus
from .isa_conformance_80386 import import_singlestep_80386_json
from .isa_cli import (
    build_isa_kernel_qualification as write_isa_kernel_qualification,
    generate_isa_corpus,
    normalize_isa_catalog,
    select_isa_kernel_qualification as write_isa_kernel_selection,
    write_isa_qualification_campaign,
)
from .isa_side_adapter import write_side_isa_qualification_inputs
from .isa_catalog_enrichment import write_enriched_side_isa_catalog
from .relational.mapping import stage_a_generate_map
from .relational.contract import stage_a_generate_relation_contract
from .relational.build import (
    stage_a_build_relational,
    stage_a_build_relational_from_nix,
)
from .relational.nix_pipeline import (
    stage_a_prepare_relational_nix,
    stage_a_prove_relational_nix,
)
from .relational.api import stage_a_check_relational_proof
from .relational.cache_qualification import diff_semantic_invalidation
from .relational.interfaces import stage_a_export_interface_manifest
from .roundtrip_fuzz.phase0 import generate_phase0_corpus
from .roundtrip_fuzz.image_contract import load_stage_a_load_image_contract
from .opaque_reconstruction import stage_a_export_opaque_reconstruction
from .import_abi import expand_import_abi_policy
from .reconstruction_ir import export_machine_ir_package
from .rooted_state_machine import (
    augment_state_machine_with_rooted_instruction_views,
)
from .reconstruction_validation import check_semantic_claim
from .reconstruction_assurance import (
    write_assurance_report,
    write_reconstruction_qualification,
)
from .reconstruction_workspace import (
    build_reconstruction_regional_kernel,
    check_reconstruction_workspace,
    create_reconstruction_workspace,
    promote_reconstruction_workspaces,
    rebind_reconstruction_workspace,
    run_reconstruction_workspace_check,
    write_reconstruction_plan,
    write_reconstruction_status,
)
from .component_workspace import (
    create_component_slice_package,
    create_component_workspace,
    promote_qualified_components,
    qualify_component,
    rebind_component_workspace,
    run_component_source_check,
)
from .semantic_components import write_semantic_component_catalog
from .component_discovery import write_component_proposals
from .component_interface import (
    synthesize_component_interface_spec,
    write_component_interface_refinement,
)
from .component_selection import materialize_component_declarations
from .source_project import (
    assess_source_components,
    assess_source_project,
    bind_source_project,
)
from .linked_libraries import (
    bind_interface_contract_catalog,
    bind_library_artifact_inputs,
    bind_linked_interface_assignments,
    bind_linked_island_review,
    derive_dynamic_library_requirements,
    index_library_artifacts,
    infer_library_hypotheses,
    lock_library_catalog,
    match_linked_islands,
    plan_library_replacements,
    propose_library_match_evidence,
    qualify_linked_interfaces,
    refine_linked_islands,
)
from .source_call_substitution import (
    audit_candidate_dependencies,
    bind_allowed_runtime_imports,
    bind_call_substitution_assignments,
    bind_callable_interface_catalog,
    bind_source_call_bindings,
    bind_source_substitution_catalog,
    check_source_call_bindings,
    derive_static_indirect_call_targets,
    generate_call_frontier,
    inventory_clang_source_calls,
    plan_call_substitutions,
    propose_source_component_artifacts,
    propose_source_component_bindings,
)
from .external_operation_profiles import load_external_operation_profile
from .source_operation_catalog import render_source_operation_rows
from .roundtrip_fuzz.generator import SPIKE_CASES, generate_spike_corpus
from .roundtrip_fuzz.discovery import (
    compare_discovery_proposals,
    discover_linker_map_pair,
)
from .roundtrip_fuzz.runner import run_roundtrip_corpus
from .roundtrip_fuzz.reducer import reduce_case_manifest
from .roundtrip_fuzz.model import load_case_manifest
from .roundtrip_fuzz.violation import (
    audit_prebuilt_checked_violation,
    prepare_checked_violation_nix_input,
)
from .relational.isa_requirements import write_isa_requirement_inventory
from .relational.isa_qualification import write_isa_semantic_qualification
from .relational.reference_contract import (
    REFERENCE_CONTRACT_MODEL_ID,
    stage_a_diff_obligations,
    stage_a_explain_obligations,
    stage_a_export_reference_contract,
    stage_a_smoke_contract,
)
from .stage_b_contract import (
    stage_b_audit_contract,
    stage_b_extract_work_items,
    stage_b_contract_coverage,
    stage_b_check_contract,
    stage_b_check_unit,
)
from .stage_binary import StageAInputError
from .util import sha256_file, write_json
from .stage_b import (
    stage_b_diff_delta,
    stage_b_explain_delta,
    stage_b_extract_candidate_crash,
    stage_b_export_decompiler,
    stage_b_validate_candidate,
)
from .stage_b_functional import (
    StageBFunctionalInputError,
    stage_b_aggregate_functional_cases,
    stage_b_materialize_upstream_suite,
    stage_b_run_functional_case,
    stage_b_run_functional_suite,
)
from .stage_b_provenance import StageBProvenanceInputError, stage_b_generate_candidate_provenance
from .stage_b_c_backend import stage_b_generate_semantic_c_from_state_machine
from .source_equivalence import (
    attest_c0_compilation,
    build_source_equivalence_report,
    generate_c0_proof_sources,
    generate_c0_source_project,
)
from .native_source_equivalence import (
    build_native_source_bundle_manifest,
    build_native_source_compilation_attestation,
)
from .stage_b_interpreter_backend import write_stage_b_interpreter_package
from .stage_b_interpreter_native_build import (
    assemble_stage_b_interpreter_native_objects,
    build_stage_b_interpreter_native_candidate,
    compile_stage_b_interpreter_native_object,
    prepare_stage_b_interpreter_native_object_graph,
)
from .stage_b_state_machine import (
    augment_state_machine_with_padding_bridges,
    write_stage_b_state_machine_from_stage_a_export,
)
from .stage_b_native_engine import write_stage_b_native_engine_package
from .stage_b_native_runtime import write_stage_b_native_runtime_package
from .stage_b_reachable_slice import write_stage_b_reachable_slice
from .stage_b_skeleton import stage_b_generate_link_roots, stage_b_generate_skeleton
from .relational.engine_segments import write_engine_segment_evidence


def main(argv: list[str] | None = None, *, prog: str | None = None) -> int:
    parser = _build_parser(prog=prog)
    args = parser.parse_args(argv)
    try:
        result = args.func(args)
    except (StageAInputError, StageBFunctionalInputError, StageBProvenanceInputError, OSError, ValueError) as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    if isinstance(result, int):
        return result
    if isinstance(result, dict):
        if not getattr(args, "quiet", False):
            _print_json(result)
        return _exit_status(result)
    return 0


def _add_nix_build_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--flake", type=Path)
    parser.add_argument(
        "--builders-file",
        type=Path,
        help=(
            "Nix machines file; when supplied, derivation builds are remote-only "
            "(--max-jobs 0)"
        ),
    )
    parser.add_argument(
        "--builder-trusted-public-keys-file",
        type=Path,
        help=(
            "newline-delimited Nix public keys used to authenticate outputs "
            "returned by remote builders"
        ),
    )


def _add_isa_kernel_qualification_arguments(
    parser: argparse.ArgumentParser, *, required: bool
) -> None:
    parser.add_argument(
        "--isa-kernel-qualification",
        type=Path,
        required=required,
        help=(
            "veto-only kernel qualification used to select every exact PE "
            "semantic form before final acceptance"
        ),
    )
    parser.add_argument(
        "--isa-semantic-kernel",
        type=Path,
        required=required,
        help=(
            "compiled semantic-kernel identity and Nix bundle provenance "
            "bound by the qualification"
        ),
    )


def _build_parser(*, prog: str | None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog or "spaghetti-extractor",
        description="Spaghetti Extractor binary reimplementation and equivalence-proof tooling.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    interfaces = subcommands.add_parser(
        "stage-a-export-interfaces",
        help="export versioned Stage A schemas and parallel workstream boundaries",
    )
    interfaces.add_argument("--out", type=Path, required=True)
    interfaces.set_defaults(
        func=lambda args: stage_a_export_interface_manifest(out=args.out)
    )

    fuzz_generate = subcommands.add_parser(
        "stage-a-fuzz-generate",
        help="generate a deterministic real-PE round-trip qualification corpus",
    )
    fuzz_generate.add_argument("--seed", type=int, default=0)
    fuzz_generate.add_argument("--count", type=int)
    fuzz_generate.add_argument(
        "--profile",
        default="phase0-winapi-lockstep-v1",
        choices=["phase0-winapi-lockstep-v1", "structured-spike-v1"],
    )
    fuzz_generate.add_argument("--external-profile", type=Path)
    fuzz_generate.add_argument(
        "--toolchain",
        choices=["gnu", "llvm-msvc"],
        default="gnu",
    )
    fuzz_generate.add_argument("--compiler")
    fuzz_generate.add_argument("--linker")
    fuzz_generate.add_argument("--force", action="store_true")
    fuzz_generate.add_argument("--out", type=Path, required=True)
    fuzz_generate.set_defaults(func=_cmd_stage_a_fuzz_generate)

    fuzz_discover = subcommands.add_parser(
        "stage-a-fuzz-discover",
        help="recover an untrusted relation proposal with generator mappings withheld",
    )
    fuzz_discover.add_argument("--original", type=Path, required=True)
    fuzz_discover.add_argument("--candidate", type=Path, required=True)
    fuzz_discover.add_argument("--linker-map-original", type=Path, required=True)
    fuzz_discover.add_argument("--linker-map-candidate", type=Path, required=True)
    fuzz_discover.add_argument(
        "--external-profile", type=Path, action="append", default=[]
    )
    fuzz_discover.add_argument(
        "--ground-truth-proposal",
        type=Path,
        help="compare only after isolated discovery; never consumed by proposal generation",
    )
    fuzz_discover.add_argument("--force", action="store_true")
    fuzz_discover.add_argument("--out", type=Path, required=True)
    fuzz_discover.set_defaults(func=_cmd_stage_a_fuzz_discover)

    fuzz_run = subcommands.add_parser(
        "stage-a-fuzz-run",
        help="run round-trip cases through public Stage A proof interfaces",
    )
    fuzz_run.add_argument("--corpus", type=Path, required=True)
    fuzz_run.add_argument(
        "--mode",
        choices=["proof-core", "discovery", "stage-b-roundtrip"],
        default="proof-core",
    )
    fuzz_run.add_argument("--case", action="append", default=[], dest="case_ids")
    fuzz_run.add_argument("--flake", type=Path)
    fuzz_run.add_argument("--builders-file", type=Path)
    _add_isa_kernel_qualification_arguments(fuzz_run, required=False)
    fuzz_run.add_argument(
        "--genericity-baseline",
        type=Path,
        help="diagnostic-only checked-in proof-core inventory used for growth metrics",
    )
    fuzz_run.add_argument(
        "--stop-after-static-preflight",
        action="store_true",
        help="stop after static proof preparation without running Lean proof or violation replay",
    )
    fuzz_run.add_argument("--out", type=Path, required=True)
    fuzz_run.set_defaults(func=_cmd_stage_a_fuzz_run)

    fuzz_prepare_violation = subcommands.add_parser(
        "stage-a-prepare-violation",
        help="prepare a checked counterexample leaf for a negative proof case",
    )
    fuzz_prepare_violation.add_argument("--case", type=Path, required=True)
    fuzz_prepare_violation.add_argument("--case-root", type=Path, required=True)
    fuzz_prepare_violation.add_argument("--prepared", type=Path, required=True)
    fuzz_prepare_violation.add_argument("--out", type=Path, required=True)
    fuzz_prepare_violation.set_defaults(func=_cmd_stage_a_prepare_violation)

    fuzz_audit_violation = subcommands.add_parser(
        "stage-a-audit-violation",
        help="audit a Nix-built checked counterexample leaf",
    )
    fuzz_audit_violation.add_argument("--case", type=Path, required=True)
    fuzz_audit_violation.add_argument("--case-root", type=Path, required=True)
    fuzz_audit_violation.add_argument("--prepared", type=Path, required=True)
    fuzz_audit_violation.add_argument("--proof-node", type=Path, required=True)
    fuzz_audit_violation.add_argument("--out", type=Path, required=True)
    fuzz_audit_violation.set_defaults(func=_cmd_stage_a_audit_violation)

    fuzz_reduce = subcommands.add_parser(
        "stage-a-fuzz-reduce",
        help="structure-reduce a case while regenerating all proof inputs",
    )
    fuzz_reduce.add_argument("--case", type=Path, required=True)
    fuzz_reduce.add_argument(
        "--predicate",
        required=True,
        help=(
            "unexpected-final-pass, expected-positive-not-accepted, "
            "expected-violated-without-checked-witness, violation-id=ID, "
            "violation-family=FAMILY, mismatch-family=FAMILY, "
            "proof-frontier=CATEGORY, crash-or-internal-exception, "
            "nondeterministic-artifact-hash, cache-key-mismatch, or "
            "phase-duration=PHASE,SECONDS"
        ),
    )
    fuzz_reduce.add_argument(
        "--mode",
        choices=["proof-core", "discovery", "stage-b-roundtrip"],
        default="proof-core",
    )
    fuzz_reduce.add_argument("--toolchain", choices=["gnu", "llvm-msvc"])
    fuzz_reduce.add_argument("--compiler")
    fuzz_reduce.add_argument("--linker")
    fuzz_reduce.add_argument("--flake", type=Path)
    fuzz_reduce.add_argument("--builders-file", type=Path)
    fuzz_reduce.add_argument("--max-accepted-steps", type=int, default=10_000)
    fuzz_reduce.add_argument("--force", action="store_true")
    fuzz_reduce.add_argument("--out", type=Path, required=True)
    fuzz_reduce.set_defaults(func=_cmd_stage_a_fuzz_reduce)

    isa_conformance = subcommands.add_parser(
        "stage-a-check-isa-conformance",
        help="run an evidence-only concrete check of the authoritative ISA semantics",
    )
    isa_conformance.add_argument("--corpus", type=Path, required=True)
    isa_conformance.add_argument(
        "--backend", choices=("lean", "unicorn", "bochs"), default="lean"
    )
    isa_conformance.add_argument(
        "--bochs-runner",
        type=Path,
        help="pinned batched Bochs runner; required when --backend=bochs",
    )
    isa_conformance.add_argument("--out", type=Path, required=True)
    isa_conformance.add_argument(
        "--forms-out",
        type=Path,
        help="write Lean-owned semantic form identities; valid only for --backend=lean",
    )
    _add_nix_build_arguments(isa_conformance)
    isa_conformance.set_defaults(func=_cmd_stage_a_check_isa_conformance)

    isa_conformance_worker = subcommands.add_parser(
        "stage-a-check-isa-conformance-worker",
        help=argparse.SUPPRESS,
    )
    isa_conformance_worker.add_argument("--corpus", type=Path, required=True)
    isa_conformance_worker.add_argument(
        "--backend", choices=("lean", "unicorn", "bochs"), required=True
    )
    isa_conformance_worker.add_argument("--bochs-runner", type=Path)
    isa_conformance_worker.add_argument("--out", type=Path, required=True)
    isa_conformance_worker.add_argument("--forms-out", type=Path)
    isa_conformance_worker.set_defaults(
        func=_cmd_stage_a_check_isa_conformance_worker
    )

    isa_requirements = subcommands.add_parser(
        "stage-a-inventory-isa-requirements",
        help=(
            "inventory exact-PE instruction forms across canonical, represented "
            "rooted, and conservative reachability scopes"
        ),
    )
    isa_requirements.add_argument("--original", type=Path, required=True)
    isa_requirements.add_argument("--candidate", type=Path, required=True)
    isa_requirements.add_argument("--relation-contract", type=Path, required=True)
    isa_requirements.add_argument("--product-graph", type=Path, required=True)
    isa_requirements.add_argument("--out", type=Path, required=True)
    isa_requirements.set_defaults(
        func=lambda args: write_isa_requirement_inventory(
            original=args.original,
            candidate=args.candidate,
            relation_contract=args.relation_contract,
            product_graph=args.product_graph,
            out=args.out,
        )
    )

    isa_side_adapter = subcommands.add_parser(
        "stage-a-adapt-side-isa-qualification",
        help=(
            "adapt one or two exact side-ISA artifacts into untrusted "
            "qualification requirements and an effect-incomplete catalog proposal"
        ),
    )
    isa_side_adapter.add_argument(
        "--side-isa",
        type=Path,
        action="append",
        required=True,
        help="side-ISA artifact; repeat once per original/candidate side",
    )
    isa_side_adapter.add_argument(
        "--binary",
        type=Path,
        action="append",
        required=True,
        help="exact binary corresponding positionally to each --side-isa",
    )
    isa_side_adapter.add_argument(
        "--requirements-out", type=Path, required=True
    )
    isa_side_adapter.add_argument("--catalog-out", type=Path, required=True)
    isa_side_adapter.set_defaults(
        func=lambda args: write_side_isa_qualification_inputs(
            side_isa_artifacts=args.side_isa,
            binaries=args.binary,
            requirements_out=args.requirements_out,
            catalog_out=args.catalog_out,
        )
    )

    isa_catalog_enrichment = subcommands.add_parser(
        "stage-a-enrich-side-isa-catalog",
        help=(
            "derive fail-closed corpus effects and masks from exact Lean-decoded "
            "side-ISA catalog encodings"
        ),
    )
    isa_catalog_enrichment.add_argument(
        "--proposal",
        type=Path,
        required=True,
        help="stage-a-side-isa-executable-catalog-proposal-v1 artifact",
    )
    isa_catalog_enrichment.add_argument("--out", type=Path, required=True)
    isa_catalog_enrichment.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="maximum Lean metadata-export runtime",
    )
    isa_catalog_enrichment.set_defaults(
        func=lambda args: write_enriched_side_isa_catalog(
            proposal=args.proposal,
            out=args.out,
            timeout_seconds=args.timeout_seconds,
        )
    )

    isa_qualification = subcommands.add_parser(
        "stage-a-qualify-isa-semantics",
        help=(
            "join exact-PE Lean semantic-form requirements to paired, "
            "veto-only Bochs and Lean conformance evidence"
        ),
    )
    isa_qualification.add_argument("--requirements", type=Path, required=True)
    isa_qualification.add_argument(
        "--evidence",
        type=Path,
        action="append",
        required=True,
        help="evidence aggregate, shard directory, or execution manifest",
    )
    isa_qualification.add_argument("--out", type=Path, required=True)
    isa_qualification.set_defaults(
        func=lambda args: write_isa_semantic_qualification(
            requirements=args.requirements,
            evidence=args.evidence,
            out=args.out,
        )
    )

    normalize_isa = subcommands.add_parser(
        "stage-a-normalize-isa-catalog",
        help="normalize and inventory pinned XED metadata without proof authority",
    )
    normalize_isa.add_argument("--catalog", type=Path, required=True)
    normalize_isa.add_argument("--out", type=Path, required=True)
    normalize_isa.set_defaults(
        func=lambda args: normalize_isa_catalog(
            catalog=args.catalog,
            out=args.out,
        )
    )

    isa_campaign = subcommands.add_parser(
        "stage-a-plan-isa-qualification",
        help=(
            "rank the complete XED profile inventory against optional "
            "kernel qualification evidence"
        ),
    )
    isa_campaign.add_argument("--catalog", type=Path, required=True)
    isa_campaign.add_argument("--qualification", type=Path)
    isa_campaign.add_argument("--selection", type=Path)
    isa_campaign.add_argument("--crosswalk", type=Path)
    isa_campaign.add_argument("--out", type=Path, required=True)
    isa_campaign.set_defaults(
        func=lambda args: write_isa_qualification_campaign(
            catalog=args.catalog,
            qualification=args.qualification,
            selection=args.selection,
            crosswalk=args.crosswalk,
            out=args.out,
        )
    )

    generate_isa = subcommands.add_parser(
        "stage-a-generate-isa-corpus",
        help="generate deterministic boundary cases from a generic enriched ISA catalog",
    )
    generate_isa.add_argument("--catalog", type=Path, required=True)
    generate_isa.add_argument("--seed", type=int, default=0)
    generate_isa.add_argument("--out", type=Path, required=True)
    generate_isa.set_defaults(
        func=lambda args: generate_isa_corpus(
            catalog=args.catalog,
            seed=args.seed,
            out=args.out,
        )
    )

    build_isa_qualification = subcommands.add_parser(
        "stage-a-build-isa-kernel-qualification",
        help=(
            "compare masked Bochs, Unicorn, and Lean observations for one "
            "semantic-kernel revision"
        ),
    )
    build_isa_qualification.add_argument("--corpus", type=Path, required=True)
    build_isa_qualification.add_argument("--lean-forms", type=Path, required=True)
    build_isa_qualification.add_argument(
        "--bochs-report", type=Path, required=True
    )
    build_isa_qualification.add_argument(
        "--unicorn-report", type=Path, required=True
    )
    build_isa_qualification.add_argument(
        "--lean-report", type=Path, required=True
    )
    build_isa_qualification.add_argument(
        "--semantic-kernel", type=Path, required=True
    )
    build_isa_qualification.add_argument("--out", type=Path, required=True)
    build_isa_qualification.add_argument("--crosswalk-out", type=Path)
    build_isa_qualification.add_argument("--generated-corpus", type=Path)
    build_isa_qualification.set_defaults(
        func=lambda args: write_isa_kernel_qualification(
            corpus=args.corpus,
            lean_forms=args.lean_forms,
            bochs_report=args.bochs_report,
            unicorn_report=args.unicorn_report,
            lean_report=args.lean_report,
            semantic_kernel=args.semantic_kernel,
            out=args.out,
            crosswalk_out=args.crosswalk_out,
            generated_corpus=args.generated_corpus,
        )
    )

    select_isa_qualification = subcommands.add_parser(
        "stage-a-select-isa-kernel-qualification",
        help=(
            "select cached kernel qualification for exact PE instruction "
            "requirements and localize any mismatch"
        ),
    )
    select_isa_qualification.add_argument(
        "--requirements", type=Path, required=True
    )
    select_isa_qualification.add_argument(
        "--qualification", type=Path, required=True
    )
    select_isa_qualification.add_argument(
        "--semantic-kernel", type=Path, required=True
    )
    select_isa_qualification.add_argument(
        "--side", choices=("original", "candidate"), required=True
    )
    select_isa_qualification.add_argument("--out", type=Path, required=True)
    select_isa_qualification.set_defaults(
        func=lambda args: write_isa_kernel_selection(
            requirements=args.requirements,
            qualification=args.qualification,
            semantic_kernel=args.semantic_kernel,
            side=args.side,
            out=args.out,
        )
    )

    import_80386 = subcommands.add_parser(
        "stage-a-import-80386-conformance",
        help="import a fail-closed PE32 subset of hardware-generated 80386 vectors",
    )
    import_80386.add_argument("--tests-json", type=Path, required=True)
    import_80386.add_argument("--metadata-csv", type=Path, required=True)
    import_80386.add_argument("--revocations", type=Path, required=True)
    import_80386.add_argument("--source-revision", required=True)
    import_80386.add_argument("--shard-index", type=int, default=0)
    import_80386.add_argument("--shard-count", type=int, default=1)
    import_80386.add_argument("--max-cases", type=int)
    import_80386.add_argument("--out", type=Path, required=True)
    import_80386.add_argument("--manifest-out", type=Path, required=True)
    import_80386.set_defaults(func=_cmd_stage_a_import_80386_conformance)

    prove = subcommands.add_parser(
        "stage-a-prove",
        help="generate and replay the whole-program v3 acceptance theorem",
    )
    prove.add_argument("--original", type=Path, required=True)
    prove.add_argument("--candidate", type=Path, required=True)
    prove.add_argument("--relation-contract", type=Path, required=True)
    _add_nix_build_arguments(prove)
    _add_isa_kernel_qualification_arguments(prove, required=True)
    prove.add_argument("--out", type=Path, required=True)
    prove.set_defaults(func=_cmd_stage_a_prove)

    prepare_relational = subcommands.add_parser(
        "stage-a-prepare-relational",
        help="extract a deterministic v3 Lean proof graph without compiling it",
    )
    prepare_relational.add_argument("--original", type=Path, required=True)
    prepare_relational.add_argument("--candidate", type=Path, required=True)
    prepare_relational.add_argument("--relation-contract", type=Path, required=True)
    _add_nix_build_arguments(prepare_relational)
    prepare_relational.add_argument("--out", type=Path, required=True)
    prepare_relational.set_defaults(func=_cmd_stage_a_prepare_relational)

    build_relational = subcommands.add_parser(
        "stage-a-build-relational",
        help="build and trust-0 audit a prepared v3 Lean proof graph",
    )
    prepared_input = build_relational.add_mutually_exclusive_group(required=True)
    prepared_input.add_argument("--prepared", type=Path)
    prepared_input.add_argument(
        "--prepared-nix-ref",
        help=(
            "Nix flake reference producing the prepared proof; it is realized "
            "before evaluating the dynamic Lean module graph"
        ),
    )
    build_relational.add_argument(
        "--prepared-subpath",
        type=Path,
        default=Path("."),
        help="prepared-proof directory below --prepared-nix-ref output",
    )
    _add_nix_build_arguments(build_relational)
    _add_isa_kernel_qualification_arguments(
        build_relational, required=False
    )
    build_relational.add_argument(
        "--target-node",
        action="append",
        help=(
            "build a prepared module-graph node and its dependency closure; repeat "
            "to schedule a node set in one Nix invocation"
        ),
    )
    build_relational.add_argument("--out", type=Path, required=True)
    build_relational.set_defaults(func=_cmd_stage_a_build_relational)

    diff_semantic_cache = subcommands.add_parser(
        "stage-a-diff-semantic-cache",
        help=(
            "verify that a prepared Lean graph mutation invalidates exactly "
            "its semantic dependency descendants"
        ),
    )
    diff_semantic_cache.add_argument(
        "--before-graph", type=Path, required=True
    )
    diff_semantic_cache.add_argument(
        "--after-graph", type=Path, required=True
    )
    diff_semantic_cache.add_argument("--out", type=Path, required=True)
    diff_semantic_cache.set_defaults(func=_cmd_stage_a_diff_semantic_cache)

    check_proof = subcommands.add_parser(
        "stage-a-check-proof",
        help="audit a Nix-built v3 whole-program proof report",
    )
    check_proof.add_argument("--report", type=Path, required=True)
    check_proof.add_argument("--original", type=Path)
    check_proof.add_argument("--candidate", type=Path)
    check_proof.add_argument("--out", type=Path)
    check_proof.set_defaults(
        func=_cmd_stage_a_check_proof,
    )

    generate_relation = subcommands.add_parser(
        "stage-a-generate-relation-contract",
        help="project a block map into an explicit v3 relation contract",
    )
    generate_relation.add_argument("--original", type=Path, required=True)
    generate_relation.add_argument("--candidate", type=Path, required=True)
    generate_relation.add_argument("--mapping", type=Path, required=True)
    generate_relation.add_argument(
        "--external-profile",
        type=Path,
        action="append",
        dest="external_profiles",
        help=(
            "versioned machine-level contracts for shared imported calls; "
            "repeat to compose disjoint profiles"
        ),
    )
    generate_relation.add_argument("--out", type=Path, required=True)
    generate_relation.set_defaults(
        func=lambda args: stage_a_generate_relation_contract(
            original=args.original,
            candidate=args.candidate,
            mapping=args.mapping,
            external_profile=args.external_profiles,
            out=args.out,
        )
    )

    generate_map = subcommands.add_parser("stage-a-generate-map", help="generate a linker-map/capstone Stage A block map")
    generate_map.add_argument("--original", type=Path, required=True)
    generate_map.add_argument("--candidate", type=Path, required=True)
    generate_map.add_argument("--linker-map-original", type=Path, required=True)
    generate_map.add_argument("--linker-map-candidate", type=Path, required=True)
    generate_map.add_argument("--out", type=Path, required=True)
    generate_map.add_argument("--layout-contract-out", type=Path)
    generate_map.add_argument("--original-flags", default="")
    generate_map.add_argument("--candidate-flags", default="")
    generate_map.add_argument("--proof-rule", default="same_source_layout_preserving_build_v1")
    generate_map.add_argument("--proof-metadata-json")
    generate_map.add_argument("--proof-metadata", type=Path)
    generate_map.set_defaults(func=_cmd_stage_a_generate_map)

    contract = subcommands.add_parser("stage-a-export-reference-contract", help="emit reusable Stage A reference contract evidence")
    contract.add_argument("--original", type=Path, required=True)
    contract.add_argument("--out", type=Path, required=True)
    contract.add_argument("--candidate", type=Path)
    contract.add_argument("--mapping", type=Path)
    contract.add_argument("--validation-report", type=Path)
    contract.add_argument("--layout-contract", type=Path)
    contract.add_argument("--sidecar-dir", type=Path)
    contract.add_argument("--unit-contract-dir", type=Path)
    contract.add_argument("--model", default=REFERENCE_CONTRACT_MODEL_ID)
    contract.set_defaults(func=_cmd_stage_a_export_reference_contract)

    opaque_export = subcommands.add_parser(
        "stage-a-export-opaque-reconstruction",
        help=(
            "emit map-blind semantic reconstruction inputs from a binary-only "
            "cutpoint inventory"
        ),
    )
    opaque_export.add_argument("--original", type=Path, required=True)
    opaque_export.add_argument("--inventory", type=Path, required=True)
    opaque_export.add_argument("--out", type=Path, required=True)
    opaque_export.set_defaults(
        func=lambda args: stage_a_export_opaque_reconstruction(
            original=args.original,
            inventory=args.inventory,
            out=args.out,
        )
    )

    import_abi = subcommands.add_parser(
        "stage-a-expand-import-abi-policy",
        help="expand reviewed DLL ABI rules into exact imports from one PE",
    )
    import_abi.add_argument("--original", type=Path, required=True)
    import_abi.add_argument("--policy", type=Path, required=True)
    import_abi.add_argument("--out", type=Path, required=True)
    import_abi.set_defaults(
        func=lambda args: expand_import_abi_policy(
            original_pe=args.original,
            policy=args.policy,
            out=args.out,
        )
    )

    machine_ir = subcommands.add_parser(
        "stage-a-export-machine-ir",
        help="sanitize a statically bound semantic state machine into byte-free IR",
    )
    machine_ir.add_argument("--state-machine", type=Path, required=True)
    machine_ir.add_argument("--original", type=Path, required=True)
    machine_ir.add_argument("--reference-contract", type=Path)
    machine_ir.add_argument("--indirect-target-profile", type=Path)
    machine_ir.add_argument(
        "--machine-import-profile",
        type=Path,
        action="append",
        default=[],
        help="exact machine-import ABI profile; may be repeated",
    )
    machine_ir.add_argument(
        "--external-interface-profile",
        type=Path,
        action="append",
        default=[],
        help="legacy v1 interface profile; may be repeated",
    )
    machine_ir.add_argument(
        "--external-operation-profile",
        type=Path,
        action="append",
        default=[],
        help="generic external-operation profile; may be repeated",
    )
    machine_ir.add_argument("--out", type=Path, required=True)
    machine_ir.set_defaults(func=_cmd_stage_a_export_machine_ir)

    qualification = subcommands.add_parser(
        "stage-a-qualify-reconstruction",
        help="reconcile static high-assurance reconstruction evidence",
    )
    qualification.add_argument("--machine-ir", type=Path, required=True)
    qualification.add_argument("--isa-evidence", type=Path, required=True)
    qualification.add_argument("--lowering-evidence", type=Path, required=True)
    qualification.add_argument("--external-protocol", type=Path, required=True)
    qualification.add_argument("--source-binding", type=Path, required=True)
    qualification.add_argument("--build-binding", type=Path, required=True)
    qualification.add_argument("--trust-assumptions", type=Path, required=True)
    qualification.add_argument("--out", type=Path, required=True)
    qualification.set_defaults(func=_cmd_stage_a_qualify_reconstruction)

    assurance = subcommands.add_parser(
        "stage-a-build-assurance-report",
        help="aggregate candidate-only high-assurance reconstruction evidence",
    )
    assurance.add_argument("--qualification", type=Path, required=True)
    assurance.add_argument("--mutation-results", type=Path, required=True)
    assurance.add_argument("--functional-results", type=Path, required=True)
    assurance.add_argument("--regional-replacements", type=Path, required=True)
    assurance.add_argument("--cache-evidence", type=Path, required=True)
    assurance.add_argument("--timing-evidence", type=Path, required=True)
    assurance.add_argument("--trust-assumptions", type=Path)
    assurance.add_argument("--out", type=Path, required=True)
    assurance.set_defaults(func=_cmd_stage_a_build_assurance_report)

    reconstruction_plan = subcommands.add_parser(
        "stage-b-plan-reconstruction",
        help="rank content-bound typed-C reconstruction clusters from machine IR",
    )
    reconstruction_plan.add_argument("--machine-ir", type=Path, required=True)
    reconstruction_plan.add_argument(
        "--signature-catalog",
        type=Path,
        help="machine-import profile graph used to type external call boundaries",
    )
    reconstruction_plan.add_argument("--out", type=Path, required=True)
    reconstruction_plan.set_defaults(func=_cmd_stage_b_plan_reconstruction)

    render_operations = subcommands.add_parser(
        "stage-b-render-source-operations",
        help=(
            "render recovered operation evidence as non-authoritative C call "
            "expressions"
        ),
    )
    render_operations.add_argument("--catalog", type=Path, required=True)
    render_operations.add_argument(
        "--operation-profile", type=Path, required=True
    )
    render_operations.add_argument(
        "--operations",
        type=Path,
        required=True,
        help="JSON array, or artifact containing an operations array",
    )
    render_operations.add_argument("--out", type=Path, required=True)
    render_operations.set_defaults(func=_cmd_stage_b_render_source_operations)

    semantic_components = subcommands.add_parser(
        "stage-b-validate-components",
        help=(
            "validate operator-defined semantic components against machine IR "
            "without generating implementations"
        ),
    )
    semantic_components.add_argument("--machine-ir", type=Path, required=True)
    semantic_components.add_argument(
        "--reconstruction-plan", type=Path, required=True
    )
    semantic_components.add_argument("--declarations", type=Path, required=True)
    semantic_components.add_argument("--linked-islands", type=Path)
    semantic_components.add_argument("--out", type=Path, required=True)
    semantic_components.set_defaults(func=_cmd_stage_b_validate_components)

    component_discovery = subcommands.add_parser(
        "stage-b-discover-components",
        help="propose deterministic overlapping semantic-component boundaries",
    )
    component_discovery.add_argument("--machine-ir", type=Path, required=True)
    component_discovery.add_argument(
        "--reconstruction-plan", type=Path, required=True
    )
    component_discovery.add_argument("--max-units", type=int, default=512)
    component_discovery.add_argument(
        "--max-candidates-per-seed", type=int, default=12
    )
    component_discovery.add_argument("--out", type=Path, required=True)
    component_discovery.set_defaults(func=_cmd_stage_b_discover_components)

    component_selection = subcommands.add_parser(
        "stage-b-select-components",
        help="materialize reviewed discovery proposals as component declarations",
    )
    component_selection.add_argument("--proposals", type=Path, required=True)
    component_selection.add_argument("--selection", type=Path, required=True)
    component_selection.add_argument("--out", type=Path, required=True)
    component_selection.set_defaults(func=_cmd_stage_b_select_components)

    source_project = subcommands.add_parser(
        "stage-b-bind-source-project",
        help="bind idiomatic source islands to exact machine-IR units",
    )
    source_project.add_argument("--machine-ir", type=Path, required=True)
    source_project.add_argument("--specification", type=Path, required=True)
    source_project.add_argument("--source-root", type=Path, required=True)
    source_project.add_argument("--linked-islands", type=Path)
    source_project.add_argument("--out", type=Path, required=True)
    source_project.set_defaults(func=_cmd_stage_b_bind_source_project)

    source_assurance = subcommands.add_parser(
        "stage-b-assess-source-project",
        help="combine static source binding with candidate-only behavior evidence",
    )
    source_assurance.add_argument("--binding", type=Path, required=True)
    source_assurance.add_argument("--candidate-binary", type=Path, required=True)
    source_assurance.add_argument("--functional-report", type=Path, required=True)
    source_assurance.add_argument("--upstream-report", type=Path)
    source_assurance.add_argument("--component-assurance", type=Path)
    source_assurance.add_argument("--out", type=Path, required=True)
    source_assurance.set_defaults(func=_cmd_stage_b_assess_source_project)

    source_component_assurance = subcommands.add_parser(
        "stage-b-assess-source-components",
        help="bind source islands to candidate-only component behavior evidence",
    )
    source_component_assurance.add_argument("--binding", type=Path, required=True)
    source_component_assurance.add_argument(
        "--source-inventory", type=Path, required=True
    )
    source_component_assurance.add_argument(
        "--source-call-report", type=Path, required=True
    )
    source_component_assurance.add_argument(
        "--functional-report", type=Path, required=True
    )
    source_component_assurance.add_argument(
        "--upstream-report", type=Path, required=True
    )
    source_component_assurance.add_argument(
        "--evidence-plan", type=Path, required=True
    )
    source_component_assurance.add_argument("--out", type=Path, required=True)
    source_component_assurance.set_defaults(
        func=_cmd_stage_b_assess_source_components
    )

    library_inputs = subcommands.add_parser(
        "stage-b-bind-library-artifact-inputs",
        help="self-bind a public/private linked-library artifact declaration",
    )
    library_inputs.add_argument("--inputs", type=Path, required=True)
    library_inputs.add_argument("--out", type=Path, required=True)
    library_inputs.set_defaults(
        func=lambda args: _write_bound_json(
            source=args.inputs,
            out=args.out,
            label="library artifact inputs",
            binder=bind_library_artifact_inputs,
        )
    )

    library_index = subcommands.add_parser(
        "stage-b-index-library-artifacts",
        help="index content-bound COFF, OMF, archive, and PE artifacts statically",
    )
    library_index.add_argument("--inputs", type=Path, required=True)
    library_index.add_argument("--artifact-root", type=Path, required=True)
    library_index.add_argument("--out", type=Path, required=True)
    library_index.set_defaults(
        func=lambda args: index_library_artifacts(
            inputs=args.inputs,
            artifact_root=args.artifact_root,
            out=args.out,
        )
    )

    library_lock = subcommands.add_parser(
        "stage-b-lock-library-catalog",
        help="lock selected immutable library indexes for reproducible matching",
    )
    library_lock.add_argument("--artifact-index", type=Path, action="append", default=[])
    library_lock.add_argument("--out", type=Path, required=True)
    library_lock.set_defaults(
        func=lambda args: lock_library_catalog(indexes=args.artifact_index, out=args.out)
    )

    linked_review = subcommands.add_parser(
        "stage-b-bind-linked-island-review",
        help="self-bind operator-reviewed application/dependency ownership ranges",
    )
    linked_review.add_argument("--review", type=Path, required=True)
    linked_review.add_argument("--out", type=Path, required=True)
    linked_review.set_defaults(
        func=lambda args: _write_bound_json(
            source=args.review,
            out=args.out,
            label="linked-island review",
            binder=bind_linked_island_review,
        )
    )

    linked_match = subcommands.add_parser(
        "stage-b-match-linked-islands",
        help="classify every machine unit and propose linked-library identities",
    )
    linked_match.add_argument("--original", type=Path, required=True)
    linked_match.add_argument("--machine-ir", type=Path, required=True)
    linked_match.add_argument("--catalog-lock", type=Path)
    linked_match.add_argument("--review", type=Path)
    linked_match.add_argument("--out", type=Path, required=True)
    linked_match.set_defaults(
        func=lambda args: match_linked_islands(
            original=args.original,
            machine_ir=args.machine_ir,
            catalog_lock=args.catalog_lock,
            review=args.review,
            out=args.out,
        )
    )

    library_evidence = subcommands.add_parser(
        "stage-b-propose-library-evidence",
        help="emit all exact target-to-library matches without selecting identity",
    )
    library_evidence.add_argument("--original", type=Path, required=True)
    library_evidence.add_argument("--machine-ir", type=Path, required=True)
    library_evidence.add_argument("--catalog-lock", type=Path, required=True)
    library_evidence.add_argument("--review", type=Path)
    library_evidence.add_argument("--out", type=Path, required=True)
    library_evidence.set_defaults(
        func=lambda args: propose_library_match_evidence(
            original=args.original,
            machine_ir=args.machine_ir,
            catalog_lock=args.catalog_lock,
            review=args.review,
            out=args.out,
        )
    )

    library_hypotheses = subcommands.add_parser(
        "stage-b-infer-library-hypotheses",
        help="infer coherent member, release, and library-family hypotheses",
    )
    library_hypotheses.add_argument("--match-evidence", type=Path, required=True)
    library_hypotheses.add_argument("--max-hypotheses", type=int, default=256)
    library_hypotheses.add_argument("--out", type=Path, required=True)
    library_hypotheses.set_defaults(
        func=lambda args: infer_library_hypotheses(
            match_evidence=args.match_evidence,
            max_hypotheses=args.max_hypotheses,
            out=args.out,
        )
    )

    linked_refine = subcommands.add_parser(
        "stage-b-refine-linked-islands",
        help="materialize ownership islands from constellation hypotheses",
    )
    linked_refine.add_argument("--original", type=Path, required=True)
    linked_refine.add_argument("--machine-ir", type=Path, required=True)
    linked_refine.add_argument("--match-evidence", type=Path, required=True)
    linked_refine.add_argument("--hypotheses", type=Path, required=True)
    linked_refine.add_argument("--review", type=Path)
    linked_refine.add_argument("--out", type=Path, required=True)
    linked_refine.set_defaults(
        func=lambda args: refine_linked_islands(
            original=args.original,
            machine_ir=args.machine_ir,
            match_evidence=args.match_evidence,
            hypotheses=args.hypotheses,
            review=args.review,
            out=args.out,
        )
    )

    dynamic_requirements = subcommands.add_parser(
        "stage-b-derive-dynamic-library-requirements",
        help="preserve exact imported identities and checked machine-call contracts",
    )
    dynamic_requirements.add_argument("--machine-ir", type=Path, required=True)
    dynamic_requirements.add_argument("--machine-import-report", type=Path)
    dynamic_requirements.add_argument("--out", type=Path, required=True)
    dynamic_requirements.set_defaults(
        func=lambda args: derive_dynamic_library_requirements(
            machine_ir=args.machine_ir,
            machine_import_report=args.machine_import_report,
            out=args.out,
        )
    )

    interface_catalog = subcommands.add_parser(
        "stage-b-bind-interface-contract-catalog",
        help="self-bind reusable component contracts and portable replacements",
    )
    interface_catalog.add_argument("--catalog", type=Path, required=True)
    interface_catalog.add_argument("--out", type=Path, required=True)
    interface_catalog.set_defaults(
        func=lambda args: _write_bound_json(
            source=args.catalog,
            out=args.out,
            label="interface contract catalog",
            binder=bind_interface_contract_catalog,
        )
    )

    interface_assignments = subcommands.add_parser(
        "stage-b-bind-linked-interface-assignments",
        help="self-bind operator-selected island-to-contract assignments",
    )
    interface_assignments.add_argument("--assignments", type=Path, required=True)
    interface_assignments.add_argument("--out", type=Path, required=True)
    interface_assignments.set_defaults(
        func=lambda args: _write_bound_json(
            source=args.assignments,
            out=args.out,
            label="linked interface assignments",
            binder=bind_linked_interface_assignments,
        )
    )

    linked_qualification = subcommands.add_parser(
        "stage-b-qualify-linked-interface",
        help="bind checked component evidence to proposed library interfaces",
    )
    linked_qualification.add_argument("--linked-islands", type=Path, required=True)
    linked_qualification.add_argument("--interface-catalog", type=Path, required=True)
    linked_qualification.add_argument("--assignments", type=Path, required=True)
    linked_qualification.add_argument("--out", type=Path, required=True)
    linked_qualification.set_defaults(
        func=lambda args: qualify_linked_interfaces(
            linked_islands=args.linked_islands,
            interface_catalog=args.interface_catalog,
            assignments=args.assignments,
            out=args.out,
        )
    )

    replacement_plan = subcommands.add_parser(
        "stage-b-plan-library-replacements",
        help="select qualified portable replacements and explicit IR fallbacks",
    )
    replacement_plan.add_argument("--linked-islands", type=Path, required=True)
    replacement_plan.add_argument("--interface-qualification", type=Path, required=True)
    replacement_plan.add_argument("--interface-catalog", type=Path, required=True)
    replacement_plan.add_argument("--dynamic-requirements", type=Path)
    replacement_plan.add_argument("--out", type=Path, required=True)
    replacement_plan.set_defaults(
        func=lambda args: plan_library_replacements(
            linked_islands=args.linked_islands,
            interface_qualification=args.interface_qualification,
            interface_catalog=args.interface_catalog,
            dynamic_requirements=args.dynamic_requirements,
            out=args.out,
        )
    )

    call_frontier = subcommands.add_parser(
        "stage-b-generate-call-frontier",
        help="classify every outgoing call from source-bound application islands",
    )

    indirect_targets = subcommands.add_parser(
        "stage-b-derive-static-indirect-targets",
        help="derive relocation-backed internal call targets from static PE evidence",
    )
    indirect_targets.add_argument("--original", type=Path, required=True)
    indirect_targets.add_argument("--machine-ir", type=Path, required=True)
    indirect_targets.add_argument("--source-binding", type=Path, required=True)
    indirect_targets.add_argument("--out", type=Path, required=True)
    indirect_targets.set_defaults(
        func=lambda args: derive_static_indirect_call_targets(
            original=args.original,
            machine_ir=args.machine_ir,
            source_binding=args.source_binding,
            out=args.out,
        )
    )
    call_frontier.add_argument("--source-binding", type=Path, required=True)
    call_frontier.add_argument("--linked-islands", type=Path, required=True)
    call_frontier.add_argument("--dynamic-requirements", type=Path, required=True)
    call_frontier.add_argument("--indirect-targets", type=Path)
    call_frontier.add_argument("--out", type=Path, required=True)
    call_frontier.set_defaults(
        func=lambda args: generate_call_frontier(
            source_binding=args.source_binding,
            linked_islands=args.linked_islands,
            dynamic_requirements=args.dynamic_requirements,
            indirect_targets=args.indirect_targets,
            out=args.out,
        )
    )

    callable_catalog = subcommands.add_parser(
        "stage-b-bind-callable-interface-catalog",
        help="self-bind reusable machine-to-logical callable contracts",
    )
    callable_catalog.add_argument("--catalog", type=Path, required=True)
    callable_catalog.add_argument("--out", type=Path, required=True)
    callable_catalog.set_defaults(
        func=lambda args: _write_bound_json(
            source=args.catalog,
            out=args.out,
            label="callable interface catalog",
            binder=bind_callable_interface_catalog,
        )
    )

    source_substitutions = subcommands.add_parser(
        "stage-b-bind-source-substitution-catalog",
        help="self-bind C implementations for qualified callable interfaces",
    )
    source_substitutions.add_argument("--catalog", type=Path, required=True)
    source_substitutions.add_argument("--out", type=Path, required=True)
    source_substitutions.set_defaults(
        func=lambda args: _write_bound_json(
            source=args.catalog,
            out=args.out,
            label="source substitution catalog",
            binder=bind_source_substitution_catalog,
        )
    )

    call_assignments = subcommands.add_parser(
        "stage-b-bind-call-substitution-assignments",
        help="self-bind operator-selected frontier-to-source substitutions",
    )
    call_assignments.add_argument("--assignments", type=Path, required=True)
    call_assignments.add_argument("--out", type=Path, required=True)
    call_assignments.set_defaults(
        func=lambda args: _write_bound_json(
            source=args.assignments,
            out=args.out,
            label="call substitution assignments",
            binder=bind_call_substitution_assignments,
        )
    )

    component_substitutions = subcommands.add_parser(
        "stage-b-propose-source-components",
        help="group each application island call frontier into a fail-closed source component",
    )
    component_substitutions.add_argument("--frontier", type=Path, required=True)
    component_substitutions.add_argument("--source-binding", type=Path, required=True)
    component_substitutions.add_argument("--interfaces-out", type=Path, required=True)
    component_substitutions.add_argument("--substitutions-out", type=Path, required=True)
    component_substitutions.add_argument("--assignments-out", type=Path, required=True)
    component_substitutions.set_defaults(
        func=lambda args: propose_source_component_artifacts(
            frontier=args.frontier,
            source_binding=args.source_binding,
            interfaces_out=args.interfaces_out,
            substitutions_out=args.substitutions_out,
            assignments_out=args.assignments_out,
        )
    )

    call_plan = subcommands.add_parser(
        "stage-b-plan-call-substitutions",
        help="require one qualified C disposition for every frontier call",
    )
    call_plan.add_argument("--frontier", type=Path, required=True)
    call_plan.add_argument("--interface-catalog", type=Path, required=True)
    call_plan.add_argument("--substitution-catalog", type=Path, required=True)
    call_plan.add_argument("--assignments", type=Path, required=True)
    call_plan.add_argument("--out", type=Path, required=True)
    call_plan.set_defaults(
        func=lambda args: plan_call_substitutions(
            frontier=args.frontier,
            interface_catalog=args.interface_catalog,
            substitution_catalog=args.substitution_catalog,
            assignments=args.assignments,
            out=args.out,
        )
    )

    source_call_inventory = subcommands.add_parser(
        "stage-b-inventory-source-calls",
        help="inventory source calls from a Clang JSON AST",
    )
    source_call_inventory.add_argument("--clang-ast", type=Path, required=True)
    source_call_inventory.add_argument("--source-root", type=Path, required=True)
    source_call_inventory.add_argument("--source-binding", type=Path, required=True)
    source_call_inventory.add_argument("--out", type=Path, required=True)
    source_call_inventory.set_defaults(func=_cmd_stage_b_inventory_source_calls)

    source_call_bindings = subcommands.add_parser(
        "stage-b-bind-source-call-bindings",
        help="self-bind source AST calls to checked call plans",
    )
    source_call_bindings.add_argument("--bindings", type=Path, required=True)
    source_call_bindings.add_argument("--out", type=Path, required=True)
    source_call_bindings.set_defaults(
        func=lambda args: _write_bound_json(
            source=args.bindings,
            out=args.out,
            label="source call bindings",
            binder=bind_source_call_bindings,
        )
    )

    component_source_bindings = subcommands.add_parser(
        "stage-b-propose-source-component-bindings",
        help="bind proposed component plans to matching Clang source definitions",
    )
    component_source_bindings.add_argument("--call-plan", type=Path, required=True)
    component_source_bindings.add_argument(
        "--source-inventory", type=Path, required=True
    )
    component_source_bindings.add_argument("--out", type=Path, required=True)
    component_source_bindings.set_defaults(
        func=lambda args: propose_source_component_bindings(
            call_plan=args.call_plan,
            source_inventory=args.source_inventory,
            out=args.out,
        )
    )

    source_call_check = subcommands.add_parser(
        "stage-b-check-source-call-bindings",
        help="reject missing, extra, or mismatched source calls",
    )
    source_call_check.add_argument("--call-plan", type=Path, required=True)
    source_call_check.add_argument("--source-inventory", type=Path, required=True)
    source_call_check.add_argument("--bindings", type=Path, required=True)
    source_call_check.add_argument("--out", type=Path, required=True)
    source_call_check.set_defaults(
        func=lambda args: check_source_call_bindings(
            call_plan=args.call_plan,
            source_inventory=args.source_inventory,
            bindings=args.bindings,
            out=args.out,
        )
    )

    dependency_audit = subcommands.add_parser(
        "stage-b-audit-candidate-dependencies",
        help="statically reject candidate imports outside the checked source envelope",
    )
    dependency_audit.add_argument("--candidate", type=Path, required=True)
    dependency_audit.add_argument("--call-plan", type=Path, required=True)
    dependency_audit.add_argument("--allowed-runtime-imports", type=Path, required=True)
    dependency_audit.add_argument("--out", type=Path, required=True)
    dependency_audit.set_defaults(func=_cmd_stage_b_audit_candidate_dependencies)

    runtime_imports = subcommands.add_parser(
        "stage-b-bind-allowed-runtime-imports",
        help="self-bind a reviewed candidate dependency envelope",
    )
    runtime_imports.add_argument("--imports", type=Path, required=True)
    runtime_imports.add_argument("--out", type=Path, required=True)
    runtime_imports.set_defaults(
        func=lambda args: _write_bound_json(
            source=args.imports,
            out=args.out,
            label="allowed runtime imports",
            binder=bind_allowed_runtime_imports,
        )
    )

    component_interface_synthesis = subcommands.add_parser(
        "stage-b-synthesize-component-interface",
        help="emit a conservative machine-shaped component interface proposal",
    )
    component_interface_synthesis.add_argument("--catalog", type=Path, required=True)
    component_interface_synthesis.add_argument("--machine-ir", type=Path, required=True)
    component_interface_synthesis.add_argument("--component-id", required=True)
    component_interface_synthesis.add_argument("--out", type=Path, required=True)
    component_interface_synthesis.set_defaults(
        func=_cmd_stage_b_synthesize_component_interface
    )

    component_interface_check = subcommands.add_parser(
        "stage-b-check-component-interface",
        help="check a structured logical interface against exact machine effects",
    )
    component_interface_check.add_argument("--catalog", type=Path, required=True)
    component_interface_check.add_argument("--machine-ir", type=Path, required=True)
    component_interface_check.add_argument("--component-id", required=True)
    component_interface_check.add_argument("--interface-spec", type=Path, required=True)
    component_interface_check.add_argument("--out", type=Path, required=True)
    component_interface_check.set_defaults(
        func=lambda args: write_component_interface_refinement(
            catalog=args.catalog,
            machine_ir=args.machine_ir,
            component_id=args.component_id,
            interface_spec=args.interface_spec,
            out=args.out,
        )
    )

    semantic_claim = subcommands.add_parser(
        "stage-b-check-semantic-claim",
        help=(
            "prove or refute an explicit normalized straight-line lifting claim; "
            "this does not claim equivalence of arbitrary C text"
        ),
    )
    semantic_claim.add_argument("--reference", type=Path, required=True)
    semantic_claim.add_argument("--proposed", type=Path, required=True)
    semantic_claim.add_argument("--input-widths", type=Path)
    semantic_claim.add_argument("--out", type=Path, required=True)
    semantic_claim.set_defaults(func=_cmd_stage_b_check_semantic_claim)

    component_create = subcommands.add_parser(
        "stage-b-create-component-workspace",
        help="create an editable portable-C workspace bound to a semantic component",
    )
    component_create.add_argument("--catalog", type=Path)
    component_create.add_argument("--plan", type=Path)
    component_create.add_argument("--machine-ir", type=Path)
    component_create.add_argument(
        "--component-slice",
        type=Path,
        help="pre-reduced immutable slice; mutually exclusive with the full inputs",
    )
    component_create.add_argument("--interpreter-package", type=Path, required=True)
    component_create.add_argument(
        "--interface-refinement", type=Path, required=True
    )
    component_create.add_argument("--component-id", required=True)
    component_create.add_argument("--proof-profile", required=True)
    component_create.add_argument("--out-dir", type=Path, required=True)
    component_create.set_defaults(
        func=lambda args: create_component_workspace(
            catalog=args.catalog,
            plan=args.plan,
            machine_ir=args.machine_ir,
            interpreter_package=args.interpreter_package,
            component_id=args.component_id,
            proof_profile=args.proof_profile,
            out_dir=args.out_dir,
            interface_refinement=args.interface_refinement,
            component_slice=args.component_slice,
        )
    )

    component_slices = subcommands.add_parser(
        "stage-b-create-component-slices",
        help="reduce immutable Stage B inputs to hash-bound per-component slices",
    )
    component_slices.add_argument("--catalog", type=Path, required=True)
    component_slices.add_argument("--plan", type=Path, required=True)
    component_slices.add_argument("--machine-ir", type=Path, required=True)
    component_slices.add_argument("--component-id", action="append", required=True)
    component_slices.add_argument("--out-dir", type=Path, required=True)
    component_slices.set_defaults(
        func=lambda args: create_component_slice_package(
            catalog=args.catalog,
            plan=args.plan,
            machine_ir=args.machine_ir,
            component_ids=args.component_id,
            out_dir=args.out_dir,
        )
    )

    regional_kernel = subcommands.add_parser(
        "stage-b-build-regional-kernel",
        help="precompile the immutable interpreter kernel used by component checks",
    )
    regional_kernel.add_argument("--interpreter-package", type=Path, required=True)
    regional_kernel.add_argument("--compiler", default="cc")
    regional_kernel.add_argument("--out-dir", type=Path, required=True)
    regional_kernel.set_defaults(
        func=lambda args: build_reconstruction_regional_kernel(
            interpreter_package=args.interpreter_package,
            compiler=args.compiler,
            out_dir=args.out_dir,
        )
    )

    component_rebind = subcommands.add_parser(
        "stage-b-rebind-component-workspace",
        help="refresh component source and refinement bindings after an edit",
    )
    component_rebind.add_argument("--workspace", type=Path, required=True)
    component_rebind.set_defaults(
        func=lambda args: rebind_component_workspace(workspace=args.workspace)
    )

    component_check = subcommands.add_parser(
        "stage-b-check-component",
        help="check editable component C with CBMC without executing the original binary",
    )
    component_check.add_argument("--workspace", type=Path, required=True)
    component_check.add_argument("--cbmc", default="cbmc")
    component_check.add_argument("--timeout-seconds", type=int, default=120)
    component_check.add_argument("--out", type=Path, required=True)
    component_check.set_defaults(
        func=lambda args: run_component_source_check(
            workspace=args.workspace,
            cbmc=args.cbmc,
            timeout_seconds=args.timeout_seconds,
            out=args.out,
        )
    )

    component_qualify = subcommands.add_parser(
        "stage-b-qualify-component",
        help="authorize a component only when source, adapter, and integration evidence close",
    )
    component_qualify.add_argument("--workspace", type=Path, required=True)
    component_qualify.add_argument("--source-evidence", type=Path, required=True)
    component_qualify.add_argument("--out", type=Path, required=True)
    component_qualify.set_defaults(
        func=lambda args: qualify_component(
            workspace=args.workspace,
            source_evidence=args.source_evidence,
            out=args.out,
        )
    )

    component_promote = subcommands.add_parser(
        "stage-b-promote-components",
        help="lower qualified components into the existing hybrid override backend",
    )
    component_promote.add_argument("--workspace", type=Path, action="append", required=True)
    component_promote.add_argument("--qualification", type=Path, action="append", required=True)
    component_promote.add_argument("--out-dir", type=Path, required=True)
    component_promote.add_argument("--linked-islands", type=Path)
    component_promote.set_defaults(
        func=lambda args: promote_qualified_components(
            workspaces=args.workspace,
            qualifications=args.qualification,
            out_dir=args.out_dir,
            linked_islands=args.linked_islands,
        )
    )

    reconstruction_create = subcommands.add_parser(
        "stage-b-create-replacement",
        help="create an editable typed-C workspace for one planned cluster",
    )
    reconstruction_create.add_argument("--plan", type=Path, required=True)
    reconstruction_create.add_argument("--machine-ir", type=Path, required=True)
    reconstruction_create.add_argument(
        "--interpreter-package", type=Path, required=True
    )
    reconstruction_selector = reconstruction_create.add_mutually_exclusive_group(
        required=True
    )
    reconstruction_selector.add_argument("--cluster-id")
    reconstruction_selector.add_argument("--entry-rva", type=_auto_int)
    reconstruction_create.add_argument("--out-dir", type=Path, required=True)
    reconstruction_create.set_defaults(
        func=lambda args: create_reconstruction_workspace(
            plan=args.plan,
            machine_ir=args.machine_ir,
            interpreter_package=args.interpreter_package,
            cluster_id=args.cluster_id,
            entry_rva=args.entry_rva,
            out_dir=args.out_dir,
        )
    )

    reconstruction_rebind = subcommands.add_parser(
        "stage-b-rebind-replacement",
        help="refresh a replacement manifest after an intentional source edit",
    )
    reconstruction_rebind.add_argument("--workspace", type=Path, required=True)
    reconstruction_rebind.set_defaults(
        func=lambda args: rebind_reconstruction_workspace(
            workspace=args.workspace
        ).to_payload()
    )

    reconstruction_check = subcommands.add_parser(
        "stage-b-check-replacement",
        help="compare candidate-only baseline and replacement observations",
    )
    reconstruction_check.add_argument("--workspace", type=Path, required=True)
    reconstruction_check.add_argument(
        "--baseline-observations", type=Path, required=True
    )
    reconstruction_check.add_argument(
        "--replacement-observations", type=Path, required=True
    )
    reconstruction_check.add_argument("--out", type=Path)
    reconstruction_check.set_defaults(
        func=lambda args: check_reconstruction_workspace(
            workspace=args.workspace,
            baseline_observations=args.baseline_observations,
            replacement_observations=args.replacement_observations,
            out=args.out,
        )
    )

    reconstruction_run = subcommands.add_parser(
        "stage-b-run-replacement-check",
        help="compile and run candidate-only regional baseline/replacement cases",
    )
    reconstruction_run.add_argument("--workspace", type=Path, required=True)
    reconstruction_run.add_argument(
        "--interpreter-package", type=Path, required=True
    )
    reconstruction_run.add_argument("--compiler", default="cc")
    reconstruction_run.add_argument(
        "--regional-kernel",
        type=Path,
        help="precompiled interpreter kernel bound to this package and compiler",
    )
    reconstruction_run.add_argument("--out-dir", type=Path, required=True)
    reconstruction_run.set_defaults(
        func=lambda args: run_reconstruction_workspace_check(
            workspace=args.workspace,
            interpreter_package=args.interpreter_package,
            compiler=args.compiler,
            out_dir=args.out_dir,
            regional_kernel=args.regional_kernel,
        )
    )

    reconstruction_promote = subcommands.add_parser(
        "stage-b-promote-replacements",
        help="combine qualified replacement workspaces into an override package",
    )
    reconstruction_promote.add_argument(
        "--workspace", type=Path, action="append", required=True
    )
    reconstruction_promote.add_argument("--out-dir", type=Path, required=True)
    reconstruction_promote.set_defaults(
        func=lambda args: promote_reconstruction_workspaces(
            workspaces=args.workspace, out_dir=args.out_dir
        )
    )

    reconstruction_status = subcommands.add_parser(
        "stage-b-reconstruction-status",
        help="report source-lifting coverage independently of proof status",
    )
    reconstruction_status.add_argument("--plan", type=Path, required=True)
    reconstruction_status.add_argument("--registry", type=Path)
    reconstruction_status.add_argument("--out", type=Path, required=True)
    reconstruction_status.set_defaults(
        func=lambda args: write_reconstruction_status(
            plan=args.plan, registry=args.registry, out=args.out
        )
    )

    smoke = subcommands.add_parser("stage-a-smoke-contract", help="run the cheap Stage A contract sanity gate")
    smoke.add_argument("--reference-contract", type=Path, required=True)
    smoke.add_argument("--out", type=Path)
    smoke.set_defaults(func=lambda args: stage_a_smoke_contract(reference_contract=args.reference_contract, out=args.out))

    contract_candidate = subcommands.add_parser(
        "stage-b-check-contract",
        help="evaluate candidate-only evidence against a Stage A reference contract",
    )
    contract_candidate.add_argument("--reference-contract", type=Path, required=True)
    contract_candidate.add_argument("--candidate", type=Path, required=True)
    contract_candidate.add_argument("--linker-map-candidate", type=Path, required=True)
    contract_candidate.add_argument("--out", type=Path, required=True)
    contract_candidate.add_argument("--model", default=REFERENCE_CONTRACT_MODEL_ID)
    contract_candidate.add_argument("--skeleton-manifest", type=Path)
    contract_candidate.set_defaults(func=_cmd_stage_b_check_contract)

    audit_shortfalls = subcommands.add_parser(
        "stage-b-audit-contract",
        help="audit underconstrained candidate repair evidence",
    )
    audit_shortfalls.add_argument("--reference-contract", type=Path, required=True)
    audit_shortfalls.add_argument("--out", type=Path, required=True)
    audit_shortfalls.add_argument("--contract-candidate-validation", type=Path)
    audit_shortfalls.add_argument("--candidate", type=Path)
    audit_shortfalls.add_argument("--linker-map-candidate", type=Path)
    audit_shortfalls.add_argument("--skeleton-manifest", type=Path)
    audit_shortfalls.add_argument("--candidate-crash-report", type=Path)
    audit_shortfalls.add_argument("--unit-contract-dir", type=Path)
    audit_shortfalls.add_argument("--target-name")
    audit_shortfalls.add_argument("--model", default=REFERENCE_CONTRACT_MODEL_ID)
    audit_shortfalls.set_defaults(func=_cmd_stage_b_audit_contract)

    work_items = subcommands.add_parser("stage-b-extract-work-items", help="extract ranked candidate repair work from a reference contract")
    work_items.add_argument("--reference-contract", type=Path, required=True)
    work_items.add_argument("--out", type=Path, required=True)
    work_items.add_argument("--unit-contract-dir", type=Path)
    work_items.set_defaults(func=_cmd_stage_b_extract_work_items)

    semantic = subcommands.add_parser("stage-b-contract-coverage", help="summarize implementable candidate contract coverage")
    semantic.add_argument("--reference-contract", type=Path, required=True)
    semantic.add_argument("--out", type=Path, required=True)
    semantic.add_argument("--unit-contract-dir", type=Path)
    semantic.set_defaults(func=_cmd_stage_b_contract_coverage)

    validate_unit = subcommands.add_parser(
        "stage-b-check-unit",
        help="run focused candidate-only contract validation for one region",
    )
    validate_unit.add_argument("--reference-contract", type=Path, required=True)
    validate_unit.add_argument("--candidate", type=Path, required=True)
    validate_unit.add_argument("--linker-map-candidate", type=Path, required=True)
    validate_unit.add_argument("--skeleton-manifest", type=Path)
    validate_unit.add_argument("--focus", required=True)
    validate_unit.add_argument("--out", type=Path, required=True)
    validate_unit.add_argument("--unit-contract-dir", type=Path)
    validate_unit.add_argument("--model", default=REFERENCE_CONTRACT_MODEL_ID)
    validate_unit.add_argument("--contract-candidate-validation", type=Path)
    validate_unit.add_argument("--no-embed-contract-candidate-validation", action="store_true")
    validate_unit.set_defaults(func=_cmd_stage_b_check_unit)

    explain = subcommands.add_parser("stage-a-explain-obligations", help="explain contract obligations by focus")
    explain.add_argument("--reference-contract", type=Path, required=True)
    explain.add_argument("--focus", required=True)
    explain.add_argument("--out", type=Path)
    explain.set_defaults(func=lambda args: stage_a_explain_obligations(reference_contract=args.reference_contract, focus=args.focus, out=args.out))

    diff = subcommands.add_parser("stage-a-diff-obligations", help="diff contract obligation sidecars")
    diff.add_argument("--before", type=Path, required=True)
    diff.add_argument("--after", type=Path, required=True)
    diff.add_argument("--out", type=Path)
    diff.set_defaults(func=lambda args: stage_a_diff_obligations(before=args.before, after=args.after, out=args.out))

    export_decompiler = subcommands.add_parser("stage-b-export-decompiler", help="run Ghidra once to bootstrap Stage B source")
    export_decompiler.add_argument("--original", type=Path, required=True)
    export_decompiler.add_argument("--target-name", required=True)
    export_decompiler.add_argument("--out", type=Path, required=True)
    export_decompiler.add_argument("--analyze-headless")
    export_decompiler.add_argument("--script-path", type=Path)
    export_decompiler.add_argument("--project-dir", type=Path)
    export_decompiler.add_argument("--project-name", default="stage-b-decompiler-export")
    export_decompiler.add_argument("--timeout-seconds", type=int)
    export_decompiler.set_defaults(func=_cmd_stage_b_export_decompiler)

    skeleton = subcommands.add_parser("stage-b-generate-skeleton", help="generate Stage B skeleton or contract-guided C")
    skeleton.add_argument("--original", type=Path, required=True)
    skeleton.add_argument("--out-dir", type=Path, required=True)
    skeleton.add_argument("--target-name", required=True)
    skeleton.add_argument("--linker-map", type=Path)
    skeleton.add_argument("--reference-contract", type=Path)
    skeleton.add_argument("--coverage-reference-contract", type=Path)
    skeleton.add_argument("--source-language", default="c", choices=["c", "rust"])
    skeleton.add_argument("--decompiler-export", type=Path)
    skeleton.add_argument("--implementation-mode", default="scaffold", choices=["scaffold", "decompiled-c", "contract-guided-c"])
    skeleton.add_argument("--runtime-entry-policy", default="bridge", choices=["bridge", "mingw-crt"])
    skeleton.add_argument("--function-name", action="append", dest="function_names")
    skeleton.set_defaults(func=_cmd_stage_b_generate_skeleton)

    semantic_c = subcommands.add_parser(
        "stage-b-generate-semantic-c",
        help="regenerate the contract-guided C work package from canonical state-machine JSONL",
    )
    semantic_c.add_argument("--state-machine", type=Path, required=True)
    semantic_c.add_argument("--out-dir", type=Path, required=True)
    semantic_c.add_argument(
        "--dialect",
        choices=["semantic-c-v1", "c0-v1"],
        default="semantic-c-v1",
    )
    semantic_c.add_argument(
        "--entry-rva",
        type=_auto_int,
        help="required for --dialect c0-v1",
    )
    semantic_c.add_argument(
        "--machine-call-catalog",
        type=Path,
        help="checked relation contract or stage-b-machine-call-catalog-v1 JSON used to emit exact import adapters",
    )
    semantic_c.set_defaults(func=_cmd_stage_b_generate_semantic_c)

    padding_bridges = subcommands.add_parser(
        "stage-b-augment-padding-bridges",
        help=(
            "add exact no-op transfer proposals for checked padding targets "
            "and validate direct-control closure"
        ),
    )
    padding_bridges.add_argument("--state-machine", type=Path, required=True)
    padding_bridges.add_argument("--original", type=Path, required=True)
    padding_bridges.add_argument("--block-map", type=Path, required=True)
    padding_bridges.add_argument("--external-profile", type=Path)
    padding_bridges.add_argument("--out", type=Path, required=True)
    padding_bridges.add_argument("--report", type=Path, required=True)
    padding_bridges.set_defaults(func=_cmd_stage_b_augment_padding_bridges)

    rooted_views = subcommands.add_parser(
        "stage-b-augment-rooted-views",
        help=(
            "iteratively add exact instruction views for rooted unresolved "
            "direct-control targets"
        ),
    )
    rooted_views.add_argument("--state-machine", type=Path, required=True)
    rooted_views.add_argument("--machine-ir-manifest", type=Path, required=True)
    rooted_views.add_argument("--original", type=Path, required=True)
    rooted_views.add_argument("--reference-contract", type=Path, required=True)
    rooted_views.add_argument("--indirect-target-profile", type=Path)
    rooted_views.add_argument(
        "--machine-import-profile",
        type=Path,
        action="append",
        default=[],
    )
    rooted_views.add_argument(
        "--external-interface-profile",
        type=Path,
        action="append",
        default=[],
    )
    rooted_views.add_argument(
        "--external-operation-profile",
        type=Path,
        action="append",
        default=[],
    )
    rooted_views.add_argument("--instruction-budget", type=int, default=65536)
    rooted_views.add_argument("--iteration-budget", type=int, default=32)
    rooted_views.add_argument("--out", type=Path, required=True)
    rooted_views.add_argument("--report", type=Path, required=True)
    rooted_views.set_defaults(func=_cmd_stage_b_augment_rooted_views)

    prepare_source = subcommands.add_parser(
        "stage-a-prepare-source-equivalence",
        help="emit canonical C0 source and Lean source-attestation inputs",
    )
    prepare_source.add_argument("--original", type=Path, required=True)
    prepare_source.add_argument("--linker-map", type=Path)
    prepare_source.add_argument("--state-machine", type=Path)
    prepare_source.add_argument("--entry-rva", type=_auto_int)
    prepare_source.add_argument("--out-dir", type=Path, required=True)
    prepare_source.set_defaults(func=_cmd_stage_a_prepare_source_equivalence)

    attest_source = subcommands.add_parser(
        "stage-a-attest-c0-compilation",
        help="bind a reproducible pinned C0 build to its source and PE output",
    )
    attest_source.add_argument("--source-manifest", type=Path, required=True)
    attest_source.add_argument("--toolchain-profile", type=Path, required=True)
    attest_source.add_argument("--candidate", type=Path, required=True)
    attest_source.add_argument(
        "--derivation", help="optional expected Nix derivation assertion"
    )
    attest_source.add_argument(
        "--nar-hash", help="optional expected Nix NAR hash assertion"
    )
    attest_source.add_argument("--out", type=Path, required=True)
    attest_source.set_defaults(func=_cmd_stage_a_attest_c0_compilation)

    build_source = subcommands.add_parser(
        "stage-a-build-source-equivalence",
        help="validate source proof and compilation evidence and emit a conditional verdict",
    )
    build_source.add_argument("--original", type=Path, required=True)
    build_source.add_argument("--source-manifest", type=Path, required=True)
    build_source.add_argument("--compilation-attestation", type=Path, required=True)
    build_source.add_argument("--lean-proof-bundle", type=Path, required=True)
    build_source.add_argument("--out", type=Path, required=True)
    build_source.set_defaults(func=_cmd_stage_a_build_source_equivalence)

    proof_source = subcommands.add_parser(
        "stage-a-generate-c0-proof-sources",
        help="emit exact PE, normalization, and conditional source theorem modules",
    )
    proof_source.add_argument("--original", type=Path, required=True)
    proof_source.add_argument("--candidate", type=Path, required=True)
    proof_source.add_argument("--state-machine", type=Path, required=True)
    proof_source.add_argument("--source-manifest", type=Path, required=True)
    proof_source.add_argument("--toolchain-profile", type=Path, required=True)
    proof_source.add_argument("--candidate-build-identity", required=True)
    proof_source.add_argument("--out-dir", type=Path, required=True)
    proof_source.set_defaults(func=_cmd_stage_a_generate_c0_proof_sources)

    native_source = subcommands.add_parser(
        "stage-a-prepare-native-source-equivalence",
        help="validate and bind a complete native-interpreter source project",
    )
    native_source.add_argument("--state-machine", type=Path, required=True)
    native_source.add_argument("--interpreter-package", type=Path, required=True)
    native_source.add_argument("--native-engine-package", type=Path, required=True)
    native_source.add_argument("--native-runtime-package", type=Path, required=True)
    native_source.add_argument("--load-image-contract", type=Path, required=True)
    native_source.add_argument("--out", type=Path, required=True)
    native_source.set_defaults(func=_cmd_stage_a_prepare_native_source_equivalence)

    native_attestation = subcommands.add_parser(
        "stage-a-attest-native-source-compilation",
        help="bind a native-interpreter source project to one exact Nix-built PE",
    )
    native_attestation.add_argument("--source-bundle", type=Path, required=True)
    native_attestation.add_argument("--native-build-manifest", type=Path, required=True)
    native_attestation.add_argument("--nix-provenance", type=Path, required=True)
    native_attestation.add_argument(
        "--tool", action="append", default=[], metavar="ROLE=PATH"
    )
    native_attestation.add_argument("--nix-store-root", type=Path, default=Path("/nix/store"))
    native_attestation.add_argument("--out", type=Path, required=True)
    native_attestation.set_defaults(func=_cmd_stage_a_attest_native_source_compilation)

    reachable_slice = subcommands.add_parser(
        "stage-b-select-reachable-transfers",
        help="select transfers only from a final-theorem-ready rooted reachability proof",
    )
    reachable_slice.add_argument("--prepared-proof", type=Path, required=True)
    reachable_slice.add_argument("--product-graph", type=Path, required=True)
    reachable_slice.add_argument(
        "--whole-program-acceptance", type=Path, required=True
    )
    reachable_slice.add_argument("--state-machine", type=Path, required=True)
    reachable_slice.add_argument("--out-dir", type=Path, required=True)
    reachable_slice.set_defaults(
        func=lambda args: write_stage_b_reachable_slice(
            prepared_proof=args.prepared_proof,
            product_graph=args.product_graph,
            whole_program_acceptance=args.whole_program_acceptance,
            state_machine=args.state_machine,
            out_dir=args.out_dir,
        )
    )

    interpreter = subcommands.add_parser(
        "stage-b-generate-interpreter",
        help="generate the stable semantic-IR interpreter and immutable program data",
    )
    interpreter_input = interpreter.add_mutually_exclusive_group(required=True)
    interpreter_input.add_argument("--state-machine", type=Path)
    interpreter_input.add_argument("--machine-ir", type=Path)
    interpreter.add_argument("--out-dir", type=Path, required=True)
    interpreter.set_defaults(
        func=lambda args: write_stage_b_interpreter_package(
            state_machine=args.state_machine,
            machine_ir=args.machine_ir,
            out=args.out_dir,
        )
    )

    native_engine = subcommands.add_parser(
        "stage-b-generate-native-engine",
        help="generate the hash-bound PE32 bridge for a semantic interpreter",
    )
    native_engine_input = native_engine.add_mutually_exclusive_group(required=True)
    native_engine_input.add_argument("--state-machine", type=Path)
    native_engine_input.add_argument("--machine-ir", type=Path)
    native_engine.add_argument("--entry-rva", type=_auto_int, required=True)
    native_engine.add_argument(
        "--load-image-contract",
        type=Path,
        help="derive exact import-IAT and TLS-callback ABI evidence",
    )
    native_engine.add_argument(
        "--reference-contract",
        type=Path,
        help="bind relocation evidence to the exact Stage A reference contract",
    )
    native_engine.add_argument("--callback-rva", type=_auto_int, action="append", default=[])
    native_engine.add_argument("--callable-external-contract", type=Path)
    native_engine.add_argument("--out-dir", type=Path, required=True)
    native_engine.set_defaults(
        func=_cmd_stage_b_generate_native_engine
    )

    native_runtime = subcommands.add_parser(
        "stage-b-generate-native-runtime",
        help="bind interpreter and native-engine packages into a fail-closed runtime",
    )
    native_runtime.add_argument("--interpreter-package", type=Path, required=True)
    native_runtime.add_argument("--native-engine-package", type=Path, required=True)
    native_runtime.add_argument("--external-profile", type=Path)
    native_runtime.add_argument("--callable-external-contract", type=Path)
    native_runtime.add_argument("--out-dir", type=Path, required=True)
    native_runtime.set_defaults(
        func=lambda args: write_stage_b_native_runtime_package(
            interpreter_package=args.interpreter_package,
            native_engine_package=args.native_engine_package,
            external_profile=args.external_profile,
            callable_external_contract=args.callable_external_contract,
            out=args.out_dir,
        )
    )

    native_object_graph = subcommands.add_parser(
        "stage-b-prepare-interpreter-native-objects",
        help="prepare the deterministic per-source native candidate compile graph",
    )
    native_object_graph.add_argument("--interpreter-package", type=Path, required=True)
    native_object_graph.add_argument("--native-engine-package", type=Path, required=True)
    native_object_graph.add_argument("--native-runtime-package", type=Path, required=True)
    native_object_graph.add_argument("--region-override-package", type=Path)
    native_object_graph.add_argument("--compiler", default="i686-w64-mingw32-gcc")
    native_object_graph.add_argument("--entry-symbol", default="stage_b_payload_entry")
    native_object_graph.add_argument("--diagnostic-failure-trap", action="store_true")
    native_object_graph.add_argument("--out-dir", type=Path, required=True)
    native_object_graph.set_defaults(
        func=lambda args: prepare_stage_b_interpreter_native_object_graph(
            interpreter_package=args.interpreter_package,
            native_engine_package=args.native_engine_package,
            native_runtime_package=args.native_runtime_package,
            region_override_package=args.region_override_package,
            compiler=args.compiler,
            entry_symbol=args.entry_symbol,
            diagnostic_failure_trap=args.diagnostic_failure_trap,
            out_dir=args.out_dir,
        )
    )

    native_object = subcommands.add_parser(
        "stage-b-compile-interpreter-native-object",
        help="compile one content-bound unit from a prepared native object graph",
    )
    native_object.add_argument("--graph", type=Path, required=True)
    native_object.add_argument("--unit-id", required=True)
    native_object.add_argument("--out-dir", type=Path, required=True)
    native_object.set_defaults(
        func=lambda args: compile_stage_b_interpreter_native_object(
            graph=args.graph,
            unit_id=args.unit_id,
            out_dir=args.out_dir,
        )
    )

    native_objects = subcommands.add_parser(
        "stage-b-assemble-interpreter-native-objects",
        help="assemble complete checked native object shards without recompiling them",
    )
    native_objects.add_argument("--graph", type=Path, required=True)
    native_objects.add_argument(
        "--object-package", type=Path, action="append", required=True
    )
    native_objects.add_argument("--out-dir", type=Path, required=True)
    native_objects.set_defaults(
        func=lambda args: assemble_stage_b_interpreter_native_objects(
            graph=args.graph,
            object_packages=args.object_package,
            out_dir=args.out_dir,
        )
    )

    interpreter_candidate = subcommands.add_parser(
        "stage-b-build-interpreter-candidate",
        help="compile and compose a freestanding PE32 semantic-interpreter candidate",
    )
    interpreter_candidate.add_argument("--interpreter-package", type=Path, required=True)
    interpreter_candidate.add_argument("--native-engine-package", type=Path, required=True)
    interpreter_candidate.add_argument("--native-runtime-package", type=Path, required=True)
    interpreter_candidate.add_argument(
        "--region-override-package",
        type=Path,
        help="optional content-bound regional replacement package",
    )
    interpreter_candidate.add_argument("--load-image-contract", type=Path, required=True)
    interpreter_candidate.add_argument(
        "--anchor-manifest",
        type=Path,
        help="optional checked anchor override; otherwise derive roots from linked symbols",
    )
    interpreter_candidate.add_argument("--compiler", default="i686-w64-mingw32-gcc")
    interpreter_candidate.add_argument("--entry-symbol", default="stage_b_payload_entry")
    interpreter_candidate.add_argument("--payload-rva", type=_auto_int)
    interpreter_candidate.add_argument("--diagnostic-failure-trap", action="store_true")
    interpreter_candidate.add_argument(
        "--precompiled-objects",
        type=Path,
        help="complete object package emitted by the native object graph",
    )
    interpreter_candidate.add_argument("--out-dir", type=Path, required=True)
    interpreter_candidate.set_defaults(
        func=lambda args: build_stage_b_interpreter_native_candidate(
            interpreter_package=args.interpreter_package,
            native_engine_package=args.native_engine_package,
            native_runtime_package=args.native_runtime_package,
            region_override_package=args.region_override_package,
            load_image_contract=args.load_image_contract,
            anchor_manifest=args.anchor_manifest,
            compiler=args.compiler,
            entry_symbol=args.entry_symbol,
            payload_rva=args.payload_rva,
            diagnostic_failure_trap=args.diagnostic_failure_trap,
            precompiled_objects=args.precompiled_objects,
            out_dir=args.out_dir,
        )
    )

    engine_segments = subcommands.add_parser(
        "stage-a-generate-engine-segments",
        help="bind semantic transfers to exact interpreter data and candidate kernel bytes",
    )
    engine_segments.add_argument("--semantic-transfers", type=Path, required=True)
    engine_segments.add_argument("--interpreter-program", type=Path, required=True)
    engine_segments.add_argument("--interpreter-package", type=Path, required=True)
    engine_segments.add_argument("--candidate", type=Path, required=True)
    engine_segments.add_argument("--linker-map", type=Path, required=True)
    engine_segments.add_argument("--engine-layout", type=Path, required=True)
    engine_segments.add_argument(
        "--kernel-callback-plan",
        type=Path,
        help="optional exact finite target inventory for candidate indirect calls",
    )
    engine_segments.add_argument("--product-cutpoint", type=_auto_int, action="append", default=[])
    engine_segments.add_argument("--out", type=Path, required=True)
    engine_segments.set_defaults(func=_cmd_stage_a_generate_engine_segments)

    roots = subcommands.add_parser("stage-b-generate-link-roots", help="generate linker root flags for a candidate object")
    roots.add_argument("--original", type=Path, required=True)
    roots.add_argument("--object-file", type=Path, required=True)
    roots.add_argument("--out", type=Path, required=True)
    roots.add_argument("--nm", default="llvm-nm")
    roots.add_argument("--linker-map-original", type=Path)
    roots.add_argument("--reference-contract", type=Path)
    roots.add_argument("--skeleton-functions", type=Path)
    roots.set_defaults(func=_cmd_stage_b_generate_link_roots)

    provenance = subcommands.add_parser("stage-b-generate-candidate-provenance", help="record candidate-only Stage B provenance")
    provenance.add_argument("--target-name", required=True)
    provenance.add_argument("--skeleton-manifest", type=Path, required=True)
    provenance.add_argument("--candidate", type=Path, required=True)
    provenance.add_argument("--build-target", required=True)
    provenance.add_argument("--build-compiler", required=True)
    provenance.add_argument("--out", type=Path, required=True)
    provenance.add_argument("--functional-report", type=Path)
    provenance.add_argument("--build-output")
    provenance.add_argument("--build-report", type=Path)
    provenance.add_argument("--target-closure-manifest", type=Path)
    provenance.add_argument("--fixed-up-source", action="append", default=[], type=Path)
    provenance.set_defaults(func=_cmd_stage_b_generate_candidate_provenance)

    materialize = subcommands.add_parser("stage-b-materialize-upstream-suite", help="materialize public expected-output cases")
    materialize.add_argument("--target-name", required=True)
    materialize.add_argument("--suite-source", type=Path, required=True)
    materialize.add_argument("--source-revision", required=True)
    materialize.add_argument("--cases", type=Path, required=True)
    materialize.add_argument("--out", type=Path, required=True)
    materialize.add_argument("--suite-scope", default="full", choices=["full", "subset"])
    materialize.set_defaults(func=_cmd_stage_b_materialize_upstream_suite)

    functional = subcommands.add_parser("stage-b-run-functional-suite", help="run candidate-only public expected-output checks")
    functional.add_argument("--suite", type=Path, required=True)
    functional.add_argument("--out", type=Path, required=True)
    functional.add_argument("--candidate-binary", type=Path)
    functional.add_argument("--timeout-seconds", type=float, default=30.0)
    functional.add_argument("--strip-stderr-line-regex", action="append", default=[])
    functional.add_argument("candidate_command", nargs=argparse.REMAINDER)
    functional.set_defaults(func=_cmd_stage_b_run_functional_suite)

    functional_case = subcommands.add_parser(
        "stage-b-run-functional-case",
        help="run one candidate-only expected-output case as a cacheable shard",
    )
    functional_case.add_argument("--suite", type=Path, required=True)
    functional_case.add_argument("--case-id", required=True)
    functional_case.add_argument("--out", type=Path, required=True)
    functional_case.add_argument("--candidate-binary", type=Path)
    functional_case.add_argument("--timeout-seconds", type=float, default=30.0)
    functional_case.add_argument("--strip-stderr-line-regex", action="append", default=[])
    functional_case.add_argument("candidate_command", nargs=argparse.REMAINDER)
    functional_case.set_defaults(func=_cmd_stage_b_run_functional_case)

    functional_aggregate = subcommands.add_parser(
        "stage-b-aggregate-functional-cases",
        help="validate and aggregate independently cached functional-case reports",
    )
    functional_aggregate.add_argument("--suite", type=Path, required=True)
    functional_aggregate.add_argument("--case-report", type=Path, action="append", required=True)
    functional_aggregate.add_argument("--out", type=Path, required=True)
    functional_aggregate.set_defaults(
        func=lambda args: stage_b_aggregate_functional_cases(
            suite=args.suite,
            case_reports=args.case_report,
            out=args.out,
        )
    )

    crash = subcommands.add_parser("stage-b-extract-candidate-crash", help="summarize a candidate-only Wine crash from functional output")
    crash.add_argument("--functional-report", type=Path, required=True)
    crash.add_argument("--out", type=Path, required=True)
    crash.add_argument("--candidate", type=Path)
    crash.add_argument("--target-name")
    crash.add_argument("--diagnostic-functional-report", type=Path)
    crash.set_defaults(func=_cmd_stage_b_extract_candidate_crash)

    validate_candidate = subcommands.add_parser("stage-b-validate-candidate", help="validate Stage B candidate provenance and Stage A contract compliance")
    validate_candidate.add_argument("--candidate", type=Path, required=True)
    validate_candidate.add_argument("--linker-map-candidate", type=Path, required=True)
    validate_candidate.add_argument("--skeleton-manifest", type=Path, required=True)
    validate_candidate.add_argument("--candidate-provenance", type=Path, required=True)
    validate_candidate.add_argument("--target-name", required=True)
    validate_candidate.add_argument("--out", type=Path, required=True)
    validate_candidate.add_argument("--reference-contract", type=Path, required=True)
    validate_candidate.add_argument("--functional-report", type=Path)
    validate_candidate.add_argument("--model", default=REFERENCE_CONTRACT_MODEL_ID)
    validate_candidate.add_argument("--require-functional-evidence", action="store_true")
    validate_candidate.set_defaults(func=_cmd_stage_b_validate_candidate)

    delta = subcommands.add_parser("stage-b-explain-delta", help="rank candidate-only Stage B repair items against a Stage A contract")
    delta.add_argument("--reference-contract", type=Path, required=True)
    delta.add_argument("--candidate", type=Path, required=True)
    delta.add_argument("--linker-map-candidate", type=Path, required=True)
    delta.add_argument("--skeleton-manifest", type=Path, required=True)
    delta.add_argument("--out", type=Path, required=True)
    delta.add_argument("--unit-contract-dir", type=Path)
    delta.add_argument("--candidate-crash-report", type=Path)
    delta.add_argument("--candidate-probe-report", type=Path)
    delta.add_argument("--functional-report", type=Path)
    delta.add_argument("--candidate-module", action="append", default=[])
    delta.add_argument("--model", default=REFERENCE_CONTRACT_MODEL_ID)
    delta.add_argument("--contract-candidate-validation", type=Path)
    delta.add_argument("--focus")
    delta.add_argument("--focused-only", action="store_true")
    delta.add_argument("--no-embed-contract-candidate-validation", action="store_true")
    delta.set_defaults(func=_cmd_stage_b_explain_delta)

    delta_diff = subcommands.add_parser("stage-b-diff-delta", help="diff two Stage B delta reports")
    delta_diff.add_argument("--before", type=Path, required=True)
    delta_diff.add_argument("--after", type=Path, required=True)
    delta_diff.add_argument("--out", type=Path, required=True)
    delta_diff.set_defaults(func=lambda args: stage_b_diff_delta(before=args.before, after=args.after, out=args.out))

    return parser


def _cmd_stage_a_prove(args: Any) -> dict[str, Any]:
    return stage_a_prove_relational_nix(
        original=args.original,
        candidate=args.candidate,
        relation_contract=args.relation_contract,
        flake=args.flake,
        builders_file=args.builders_file,
        isa_kernel_qualification=args.isa_kernel_qualification,
        isa_semantic_kernel=args.isa_semantic_kernel,
        builder_trusted_public_keys_file=(
            args.builder_trusted_public_keys_file
        ),
        out=args.out,
    )


def _cmd_stage_a_prepare_relational(args: Any) -> dict[str, Any]:
    return stage_a_prepare_relational_nix(
        original=args.original,
        candidate=args.candidate,
        relation_contract=args.relation_contract,
        flake=args.flake,
        builders_file=args.builders_file,
        builder_trusted_public_keys_file=(
            args.builder_trusted_public_keys_file
        ),
        out=args.out,
    )


def _cmd_stage_a_fuzz_generate(args: Any) -> dict[str, Any]:
    if args.profile == "phase0-winapi-lockstep-v1":
        count = 1 if args.count is None else args.count
        if args.seed != 0 or count != 1:
            raise StageAInputError(
                "the Phase 0 canary requires --seed 0 --count 1"
            )
        if args.external_profile is None:
            raise StageAInputError(
                "the Phase 0 canary requires --external-profile"
            )
        return generate_phase0_corpus(
            out=args.out,
            external_profile=args.external_profile,
            toolchain=args.toolchain,
            compiler=args.compiler,
            linker=args.linker,
            force=args.force,
        )
    if args.external_profile is not None:
        raise StageAInputError(
            "structured-spike-v1 has no imports and does not accept --external-profile"
        )
    return generate_spike_corpus(
        out=args.out,
        seed=args.seed,
        count=SPIKE_CASES if args.count is None else args.count,
        toolchain=args.toolchain,
        compiler=args.compiler,
        linker=args.linker,
        force=args.force,
    )


def _cmd_stage_a_fuzz_run(args: Any) -> dict[str, Any]:
    return run_roundtrip_corpus(
        corpus=args.corpus,
        mode=args.mode,
        out=args.out,
        flake=args.flake,
        builders_file=args.builders_file,
        isa_kernel_qualification=args.isa_kernel_qualification,
        isa_semantic_kernel=args.isa_semantic_kernel,
        case_ids=args.case_ids,
        stop_after_static_preflight=args.stop_after_static_preflight,
        genericity_baseline=args.genericity_baseline,
    )


def _cmd_stage_a_prepare_violation(args: Any) -> dict[str, Any]:
    return prepare_checked_violation_nix_input(
        case=load_case_manifest(args.case),
        case_root=args.case_root,
        prepared=args.prepared,
        out=args.out,
    )


def _cmd_stage_a_audit_violation(args: Any) -> dict[str, Any]:
    result = audit_prebuilt_checked_violation(
        case=load_case_manifest(args.case),
        case_root=args.case_root,
        prepared=args.prepared,
        proof_node=args.proof_node,
        out=args.out,
    )
    return {
        **result,
        "status": "checked",
        "violation_status": result.get("status"),
    }


def _cmd_stage_a_fuzz_discover(args: Any) -> dict[str, Any]:
    result = discover_linker_map_pair(
        original=args.original,
        candidate=args.candidate,
        linker_map_original=args.linker_map_original,
        linker_map_candidate=args.linker_map_candidate,
        external_profiles=args.external_profile,
        out=args.out,
        force=args.force,
    )
    if args.ground_truth_proposal is not None:
        comparison = compare_discovery_proposals(
            recovered=args.out / "recovered-proposal.json",
            ground_truth=args.ground_truth_proposal,
            out=args.out / "ground-truth-comparison.json",
        )
        result = {**result, "ground_truth_comparison": comparison}
    return result


def _cmd_stage_a_fuzz_reduce(args: Any) -> dict[str, Any]:
    return reduce_case_manifest(
        case=args.case,
        predicate=args.predicate,
        out=args.out,
        mode=args.mode,
        toolchain=args.toolchain,
        compiler=args.compiler,
        linker=args.linker,
        flake=args.flake,
        builders_file=args.builders_file,
        max_accepted_steps=args.max_accepted_steps,
        force=args.force,
    )


def _cmd_stage_a_build_relational(args: Any) -> dict[str, Any]:
    common = {
        "flake": args.flake,
        "builders_file": args.builders_file,
        "builder_trusted_public_keys_file": (
            args.builder_trusted_public_keys_file
        ),
        "target_nodes": args.target_node,
        "isa_kernel_qualification": args.isa_kernel_qualification,
        "isa_semantic_kernel": args.isa_semantic_kernel,
        "out": args.out,
    }
    if args.prepared_nix_ref is not None:
        return stage_a_build_relational_from_nix(
            prepared_nix_ref=args.prepared_nix_ref,
            prepared_subpath=args.prepared_subpath,
            **common,
        )
    if args.prepared_subpath != Path("."):
        raise StageAInputError(
            "--prepared-subpath is valid only with --prepared-nix-ref"
        )
    return stage_a_build_relational(prepared=args.prepared, **common)


def _cmd_stage_a_diff_semantic_cache(args: Any) -> dict[str, Any]:
    before = json.loads(args.before_graph.read_text(encoding="utf-8"))
    after = json.loads(args.after_graph.read_text(encoding="utf-8"))
    report = diff_semantic_invalidation(before, after).payload()
    write_json(args.out, report)
    return report


def _cmd_stage_a_check_isa_conformance(args: Any) -> dict[str, Any]:
    return stage_a_check_isa_conformance_nix(
        corpus=args.corpus,
        backend=args.backend,
        bochs_runner=args.bochs_runner,
        out=args.out,
        forms_out=args.forms_out,
        flake=args.flake,
        builders_file=args.builders_file,
        builder_trusted_public_keys_file=(
            args.builder_trusted_public_keys_file
        ),
    )


def _cmd_stage_a_check_isa_conformance_worker(
    args: Any,
) -> dict[str, Any]:
    payload = json.loads(args.corpus.read_text(encoding="utf-8"))
    corpus = parse_isa_conformance_corpus(payload)
    if args.backend == "lean":
        if args.forms_out is None:
            report = run_lean_isa_conformance(corpus)
        else:
            report, semantic_forms = run_lean_isa_conformance_with_forms(corpus)
            expected_case_ids = {case.id for case in corpus.cases}
            missing_case_ids = sorted(expected_case_ids - set(semantic_forms))
            unexpected_case_ids = sorted(set(semantic_forms) - expected_case_ids)
            if missing_case_ids or unexpected_case_ids:
                observations_by_id = {
                    observation.case_id: observation
                    for observation in report.observations
                }
                missing_details = sorted(
                    {
                        observations_by_id[case_id].detail
                        for case_id in missing_case_ids
                        if case_id in observations_by_id
                        and observations_by_id[case_id].detail
                    }
                )
                raise StageAInputError(
                    "Lean semantic-form classification was incomplete: "
                    f"missing={len(missing_case_ids)} "
                    f"{missing_case_ids[:8]!r}; "
                    f"unexpected={len(unexpected_case_ids)} "
                    f"{unexpected_case_ids[:8]!r}; "
                    f"details={missing_details[:4]!r}"
                )
            write_json(
                args.forms_out,
                {
                    "format": "stage-a-lean-isa-semantic-forms-v1",
                    "corpus_id": corpus.id,
                    "classifier_sha256": (
                        lean_semantic_form_classifier_sha256()
                    ),
                    "cases": [
                        {
                            "case_id": case.id,
                            "semantic_form": semantic_forms[case.id],
                        }
                        for case in corpus.cases
                    ],
                    "trust": {
                        "role": "isa_conformance_evidence_only",
                        "proof_authority": False,
                        "closes_stage_a_proof": False,
                    },
                },
            )
    elif args.backend == "unicorn":
        if args.forms_out is not None:
            raise StageAInputError("--forms-out is valid only with --backend=lean")
        report = run_unicorn_corpus(corpus)
    elif args.backend == "bochs":
        if args.forms_out is not None:
            raise StageAInputError("--forms-out is valid only with --backend=lean")
        if args.bochs_runner is None:
            raise StageAInputError(
                "--bochs-runner is required when --backend=bochs"
            )
        report = run_bochs_corpus(corpus, runner=args.bochs_runner)
    else:
        raise StageAInputError(f"unsupported ISA conformance backend {args.backend!r}")
    serialized = serialize_isa_conformance_report(report, corpus=corpus)
    write_json(args.out, serialized)
    if report.qualification is ReportQualification.QUALIFIED:
        status = "pass"
    elif report.qualification is ReportQualification.VETOED:
        status = "fail"
    else:
        status = "incomplete"
    result = {
        "format": "stage-a-isa-conformance-check-v1",
        "status": status,
        "qualification": report.qualification.value,
        "backend": report.backend.id,
        "counts": {
            "cases": report.counts.cases,
            "matched": report.counts.matched,
            "mismatched": report.counts.mismatched,
            "unsupported": report.counts.unsupported,
            "errors": report.counts.errors,
        },
        "out": str(args.out),
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }
    if args.forms_out is not None:
        result["forms_out"] = str(args.forms_out)
        result["forms_sha256"] = sha256_file(args.forms_out)
    return result


def _cmd_stage_a_import_80386_conformance(args: Any) -> dict[str, Any]:
    imported = import_singlestep_80386_json(
        tests_json=args.tests_json,
        metadata_csv=args.metadata_csv,
        revocations=args.revocations,
        source_revision=args.source_revision,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
        max_cases=args.max_cases,
    )
    corpus = imported.corpus.to_payload()
    write_json(args.out, corpus)
    manifest = dict(imported.manifest)
    manifest["outputs"] = {
        "corpus": str(args.out),
        "manifest": str(args.manifest_out),
    }
    write_json(args.manifest_out, manifest)
    return {
        "format": "stage-a-sst80386-import-result-v1",
        "status": "complete",
        "corpus_id": imported.corpus.id,
        "counts": imported.manifest["counts"],
        "out": str(args.out),
        "manifest_out": str(args.manifest_out),
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


def _cmd_stage_a_check_proof(args: Any) -> dict[str, Any]:
    verdict_path = args.report / "verdict.json"
    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {verdict_path}: {exc}") from exc
    if verdict.get("profile") != "x86-pe32-lean-relational-v3":
        raise StageAInputError(
            "stage-a-check-proof accepts only relational v3 reports"
        )
    if verdict.get("format") != "stage-a-relational-nix-build-v1":
        raise StageAInputError(
            "stage-a-check-proof accepts only Nix-built relational reports"
        )
    for supplied, side in (
        (args.original, "original"),
        (args.candidate, "candidate"),
    ):
        if supplied is None:
            continue
        expected = verdict.get(side, {}).get("sha256")
        if expected is None or sha256_file(supplied) != expected:
            raise StageAInputError(
                f"supplied {side} binary does not match the Nix proof report"
            )
    return stage_a_check_relational_proof(report=args.report, out=args.out)


def _cmd_stage_a_generate_map(args: Any) -> dict[str, Any]:
    return stage_a_generate_map(
        original=args.original,
        candidate=args.candidate,
        linker_map_original=args.linker_map_original,
        linker_map_candidate=args.linker_map_candidate,
        out=args.out,
        layout_contract_out=args.layout_contract_out,
        original_flags=args.original_flags,
        candidate_flags=args.candidate_flags,
        proof_rule=args.proof_rule,
        proof_metadata=_json_object_arg(args.proof_metadata_json, args.proof_metadata),
    )


def _cmd_stage_a_export_reference_contract(args: Any) -> dict[str, Any]:
    contract = stage_a_export_reference_contract(
        original=args.original,
        out=args.out,
        candidate=args.candidate,
        mapping=args.mapping,
        validation_report=args.validation_report,
        layout_contract=args.layout_contract,
        sidecar_dir=args.sidecar_dir,
        unit_contract_dir=args.unit_contract_dir,
        model=args.model,
    )
    return {
        "format": "stage-a-reference-contract-export-v1",
        "status": contract.get("status"),
        "out": str(args.out),
        "sha256": sha256_file(args.out),
        "model": contract.get("model"),
        "counts": contract.get("counts", {}),
    }


def _cmd_stage_b_check_contract(args: Any) -> dict[str, Any]:
    return stage_b_check_contract(
        reference_contract=args.reference_contract,
        indirect_target_profile=args.indirect_target_profile,
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        out=args.out,
        model=args.model,
        skeleton_manifest=args.skeleton_manifest,
    )


def _cmd_stage_a_export_machine_ir(args: Any) -> dict[str, Any]:
    package = export_machine_ir_package(
        state_machine=args.state_machine,
        original_pe=args.original,
        reference_contract=args.reference_contract,
        indirect_target_profile=args.indirect_target_profile,
        machine_import_profiles=args.machine_import_profile,
        external_interface_profiles=args.external_interface_profile,
        external_operation_profiles=args.external_operation_profile,
        out=args.out,
    )
    return {
        "format": "stage-a-machine-ir-export-result-v1",
        "status": package.status,
        "units": package.unit_count,
        "issues": package.issue_count,
        "manifest": str(package.manifest),
        "machine_ir": str(package.machine_ir),
    }


def _cmd_stage_b_check_semantic_claim(args: Any) -> dict[str, Any]:
    widths = (
        None
        if args.input_widths is None
        else _json_file(args.input_widths, "semantic claim input widths")
    )
    if widths is not None and not isinstance(widths, dict):
        raise ValueError("semantic claim input widths must be a JSON object")
    result = check_semantic_claim(
        _json_file(args.reference, "reference semantic claim"),
        _json_file(args.proposed, "proposed semantic claim"),
        input_widths=widths,
    )
    payload = {
        "format": SEMANTIC_CLAIM_CHECK_FORMAT,
        **result.to_payload(),
    }
    write_json(args.out, payload)
    return payload


def _cmd_stage_b_plan_reconstruction(args: Any) -> dict[str, Any]:
    payload = write_reconstruction_plan(
        machine_ir=args.machine_ir,
        signature_catalog=args.signature_catalog,
        out=args.out,
    )
    return {
        "format": payload["format"],
        "status": payload["status"],
        "out": str(args.out),
        "plan_sha256": payload["plan_sha256"],
        "counts": payload["counts"],
        "control_analysis": {
            "status": payload["control_analysis"].get("status"),
            "reachability_status": payload["control_analysis"].get(
                "reachability_status"
            ),
            "exact_reachable_units": payload["control_analysis"].get(
                "exact_reachable_units"
            ),
            "potential_units": payload["control_analysis"].get("potential_units"),
            "unresolved_frontiers": len(
                payload["control_analysis"].get("frontiers", [])
            ),
        },
    }


def _cmd_stage_b_render_source_operations(args: Any) -> dict[str, Any]:
    profile = load_external_operation_profile(args.operation_profile)
    payload = _json_file(args.operations, "source-operation evidence")
    rows = payload.get("operations") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise StageAInputError(
            "source-operation evidence must be an array or contain an operations array"
        )
    report = render_source_operation_rows(
        catalog=args.catalog,
        operation_profile_sha256=profile.sha256,
        operation_evidence_rows=rows,
    )
    write_json(args.out, report)
    return report


def _cmd_stage_b_validate_components(args: Any) -> dict[str, Any]:
    payload = write_semantic_component_catalog(
        machine_ir=args.machine_ir,
        reconstruction_plan=args.reconstruction_plan,
        declarations=args.declarations,
        linked_islands=args.linked_islands,
        out=args.out,
    )
    return {
        "format": "stage-b-semantic-component-validation-result-v1",
        "status": (
            "checked" if payload["definition_status"] == "valid" else "violated"
        ),
        "catalog_status": payload["status"],
        "definition_status": payload["definition_status"],
        "assurance_status": payload["assurance_status"],
        "out": str(args.out),
        "catalog_sha256": payload["catalog_sha256"],
        "counts": payload["counts"],
    }


def _cmd_stage_b_discover_components(args: Any) -> dict[str, Any]:
    payload = write_component_proposals(
        machine_ir=args.machine_ir,
        reconstruction_plan=args.reconstruction_plan,
        max_units=args.max_units,
        max_candidates_per_seed=args.max_candidates_per_seed,
        out=args.out,
    )
    return {
        "format": "stage-b-component-discovery-result-v1",
        "status": "generated",
        "proposal_status": payload["status"],
        "proposal_set_sha256": payload["proposal_set_sha256"],
        "proposals": len(payload["proposals"]),
        "issues": len(payload["issues"]),
        "out": str(args.out),
    }


def _cmd_stage_b_select_components(args: Any) -> dict[str, Any]:
    payload = materialize_component_declarations(
        proposals=args.proposals,
        selection=args.selection,
        out=args.out,
    )
    return {
        "format": "stage-b-component-selection-result-v1",
        "status": "generated",
        "components": len(payload["components"]),
        "out": str(args.out),
    }


def _cmd_stage_b_bind_source_project(args: Any) -> dict[str, Any]:
    payload = bind_source_project(
        machine_ir=args.machine_ir,
        specification=args.specification,
        source_root=args.source_root,
        linked_islands=args.linked_islands,
        out=args.out,
    )
    return {
        "format": "stage-b-source-project-binding-result-v1",
        "status": "complete",
        "binding_status": payload["status"],
        "program_id": payload["program_id"],
        "islands": len(payload["islands"]),
        "source_bound_units": payload["coverage"]["source_bound_units"],
        "out": str(args.out),
    }


def _cmd_stage_b_assess_source_project(args: Any) -> dict[str, Any]:
    payload = assess_source_project(
        binding=args.binding,
        candidate_binary=args.candidate_binary,
        functional_report=args.functional_report,
        upstream_report=args.upstream_report,
        component_assurance=args.component_assurance,
        out=args.out,
    )
    return {
        "format": "stage-b-source-project-assessment-result-v1",
        "status": "pass" if payload["status"] == "behavior_validated" else "fail",
        "assurance_status": payload["status"],
        "equivalence_status": payload["equivalence_status"],
        "program_id": payload["program_id"],
        "out": str(args.out),
    }


def _cmd_stage_b_assess_source_components(args: Any) -> dict[str, Any]:
    payload = assess_source_components(
        binding=args.binding,
        source_inventory=args.source_inventory,
        source_call_report=args.source_call_report,
        functional_report=args.functional_report,
        upstream_report=args.upstream_report,
        evidence_plan=args.evidence_plan,
        out=args.out,
    )
    return {
        "format": "stage-b-source-component-assessment-result-v1",
        "status": (
            "pass" if payload["status"] == "behavior_validated" else "fail"
        ),
        "assurance_status": payload["status"],
        "equivalence_status": payload["equivalence_status"],
        "program_id": payload["program_id"],
        "components": payload["counts"]["components"],
        "out": str(args.out),
    }


def _cmd_stage_b_synthesize_component_interface(args: Any) -> dict[str, Any]:
    payload = synthesize_component_interface_spec(
        catalog=args.catalog,
        machine_ir=args.machine_ir,
        component_id=args.component_id,
    )
    write_json(args.out, payload)
    return {
        "format": "stage-b-component-interface-synthesis-result-v1",
        "status": "generated",
        "component_id": payload["component_id"],
        "interface_spec_sha256": payload["interface_spec_sha256"],
        "out": str(args.out),
    }


def _cmd_stage_a_qualify_reconstruction(args: Any) -> dict[str, Any]:
    assumptions = _json_file(args.trust_assumptions, "trust assumptions")
    if not isinstance(assumptions, list):
        raise ValueError("trust assumptions must be a JSON array")
    payload = write_reconstruction_qualification(
        args.out,
        machine_ir=_json_file(args.machine_ir, "machine IR evidence"),
        isa_evidence=_json_file(args.isa_evidence, "ISA evidence"),
        lowering_evidence=_json_file(args.lowering_evidence, "lowering evidence"),
        external_protocol=_json_file(args.external_protocol, "external protocol evidence"),
        source_binding=_json_file(args.source_binding, "source binding"),
        build_binding=_json_file(args.build_binding, "build binding"),
        trust_assumptions=assumptions,
    )
    return {
        "format": "stage-a-reconstruction-qualification-result-v1",
        "status": payload["status"],
        "out": str(args.out),
        "content_sha256": payload["content_sha256"],
        "counts": payload["counts"],
    }


def _cmd_stage_a_build_assurance_report(args: Any) -> dict[str, Any]:
    assumptions = None
    if args.trust_assumptions is not None:
        assumptions = _json_file(args.trust_assumptions, "trust assumptions")
        if not isinstance(assumptions, list):
            raise ValueError("trust assumptions must be a JSON array")
    payload = write_assurance_report(
        args.out,
        reconstruction_qualification=_json_file(args.qualification, "qualification"),
        mutation_results=_json_file(args.mutation_results, "mutation results"),
        functional_results=_json_file(args.functional_results, "functional results"),
        regional_replacements=_json_file(
            args.regional_replacements, "regional replacement results"
        ),
        cache_evidence=_json_file(args.cache_evidence, "cache evidence"),
        timing_evidence=_json_file(args.timing_evidence, "timing evidence"),
        trust_assumptions=assumptions,
    )
    return {
        "format": "stage-a-assurance-report-result-v1",
        "status": payload["status"],
        "out": str(args.out),
        "content_sha256": payload["content_sha256"],
        "counts": payload["counts"],
    }


def _cmd_stage_b_audit_contract(args: Any) -> dict[str, Any]:
    return stage_b_audit_contract(
        reference_contract=args.reference_contract,
        out=args.out,
        contract_candidate_validation=args.contract_candidate_validation,
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        skeleton_manifest=args.skeleton_manifest,
        candidate_crash_report=args.candidate_crash_report,
        unit_contract_dir=args.unit_contract_dir,
        target_name=args.target_name,
        model=args.model,
    )


def _cmd_stage_b_extract_work_items(args: Any) -> dict[str, Any]:
    return stage_b_extract_work_items(
        reference_contract=args.reference_contract,
        out=args.out,
        unit_contract_dir=args.unit_contract_dir,
    )


def _cmd_stage_b_contract_coverage(args: Any) -> dict[str, Any]:
    return stage_b_contract_coverage(
        reference_contract=args.reference_contract,
        out=args.out,
        unit_contract_dir=args.unit_contract_dir,
    )


def _cmd_stage_b_check_unit(args: Any) -> dict[str, Any]:
    return stage_b_check_unit(
        reference_contract=args.reference_contract,
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        skeleton_manifest=args.skeleton_manifest,
        focus=args.focus,
        out=args.out,
        unit_contract_dir=args.unit_contract_dir,
        model=args.model,
        contract_candidate_validation=args.contract_candidate_validation,
        embed_contract_candidate_validation=not args.no_embed_contract_candidate_validation,
    )


def _cmd_stage_b_export_decompiler(args: Any) -> dict[str, Any]:
    return stage_b_export_decompiler(
        original=args.original,
        target_name=args.target_name,
        out=args.out,
        analyze_headless=args.analyze_headless,
        script_path=args.script_path,
        project_dir=args.project_dir,
        project_name=args.project_name,
        timeout_seconds=args.timeout_seconds,
    )


def _cmd_stage_b_generate_skeleton(args: Any) -> dict[str, Any]:
    return stage_b_generate_skeleton(
        original=args.original,
        out_dir=args.out_dir,
        target_name=args.target_name,
        linker_map=args.linker_map,
        reference_contract=args.reference_contract,
        coverage_reference_contract=args.coverage_reference_contract,
        source_language=args.source_language,
        decompiler_export=args.decompiler_export,
        implementation_mode=args.implementation_mode,
        runtime_entry_policy=args.runtime_entry_policy,
        function_names=args.function_names,
    )


def _cmd_stage_b_generate_semantic_c(args: Any) -> dict[str, Any]:
    if args.dialect == "c0-v1":
        if args.entry_rva is None:
            raise StageAInputError("--entry-rva is required with --dialect c0-v1")
        if args.machine_call_catalog is not None:
            raise StageAInputError(
                "--machine-call-catalog is not consumed by canonical C0 v1"
            )
        return generate_c0_source_project(
            state_machine=args.state_machine,
            entry_rva=args.entry_rva,
            out_dir=args.out_dir,
        )
    report = stage_b_generate_semantic_c_from_state_machine(
        state_machine=args.state_machine,
        out_dir=args.out_dir,
        machine_call_catalog=args.machine_call_catalog,
    )
    return {
        "format": "stage-b-semantic-c-generation-v1",
        "status": report.get("status"),
        "state_machine": report.get("state_machine"),
        "counts": report.get("counts"),
        "repair_stub_count": report.get("repair_stub_count"),
        "runtime_obligation_count": report.get("runtime_obligation_count"),
        "api_adapters": report.get("api_adapters"),
        "strict_candidate": report.get("strict_candidate"),
        "reason_counts": report.get("reason_counts"),
        "dispatch": report.get("dispatch"),
        "report": report.get("report"),
        "artifacts": report.get("artifacts"),
    }


def _cmd_stage_b_augment_padding_bridges(args: Any) -> dict[str, Any]:
    result = augment_state_machine_with_padding_bridges(
        state_machine=args.state_machine,
        original_pe=args.original,
        block_map=args.block_map,
        external_profile=args.external_profile,
        out=args.out,
    )
    payload = {
        "format": "stage-b-padding-bridge-augmentation-v1",
        "status": "complete",
        "state_machine": {
            "path": str(result.path),
            "sha256": result.sha256,
        },
        "counts": {
            "input_transfers": result.input_transfer_count,
            "padding_bridges": result.padding_bridge_count,
            "output_transfers": result.output_transfer_count,
            "terminating_transfers": len(result.terminating_transfer_rvas),
        },
        "bridged_rvas": list(result.bridged_rvas),
        "terminating_transfer_rvas": list(result.terminating_transfer_rvas),
        "trust": {
            "proposal_authority": False,
            "lean_exact_decode_required": True,
            "lean_semantic_normalization_required": True,
            "executes_original_binary": False,
        },
    }
    write_json(args.report, payload)
    return payload


def _cmd_stage_b_augment_rooted_views(args: Any) -> dict[str, Any]:
    return augment_state_machine_with_rooted_instruction_views(
        state_machine=args.state_machine,
        machine_ir_manifest=args.machine_ir_manifest,
        original_pe=args.original,
        reference_contract=args.reference_contract,
        indirect_target_profile=args.indirect_target_profile,
        machine_import_profiles=args.machine_import_profile,
        external_interface_profiles=args.external_interface_profile,
        external_operation_profiles=args.external_operation_profile,
        instruction_budget=args.instruction_budget,
        iteration_budget=args.iteration_budget,
        out=args.out,
        report=args.report,
    )


def _cmd_stage_a_prepare_source_equivalence(args: Any) -> dict[str, Any]:
    # PE parsing is deliberately static. It rejects accidental non-PE inputs
    # without executing or tracing the original.
    try:
        pe = pefile.PE(data=args.original.read_bytes(), fast_load=True)
    except (OSError, pefile.PEFormatError) as exc:
        raise StageAInputError(f"original is not a PE: {exc}") from exc
    if int(pe.FILE_HEADER.Machine) != 0x14C or int(pe.OPTIONAL_HEADER.Magic) != 0x10B:
        raise StageAInputError("source equivalence currently requires an i386 PE32 original")
    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    state_machine = args.state_machine
    if state_machine is None:
        if args.linker_map is None:
            raise StageAInputError(
                "--linker-map is required when --state-machine is omitted"
            )
        args.out_dir.mkdir(parents=True, exist_ok=True)
        mapping = args.out_dir / "original-self-map.json"
        mapped = stage_a_generate_map(
            original=args.original,
            candidate=args.original,
            linker_map_original=args.linker_map,
            linker_map_candidate=args.linker_map,
            out=mapping,
            original_flags="source-equivalence-original",
            candidate_flags="source-equivalence-static-reference",
        )
        if mapped.get("status") != "pass":
            raise StageAInputError("Stage A could not map the source original to itself")
        reference = args.out_dir / "reference-contract.json"
        stage_a_export_reference_contract(
            original=args.original,
            out=reference,
            mapping=mapping,
            sidecar_dir=args.out_dir,
            unit_contract_dir=args.out_dir,
        )
        state_machine = args.out_dir / "state-machine.jsonl"
        write_stage_b_state_machine_from_stage_a_export(
            reference_contract=reference,
            semantic_transfer_contracts=(
                args.out_dir / "semantic-transfer-contracts.jsonl"
            ),
            original_pe=args.original,
            out=state_machine,
        )
    elif args.linker_map is not None:
        raise StageAInputError("--linker-map and --state-machine are mutually exclusive")
    if args.entry_rva is not None and args.entry_rva != entry_rva:
        raise StageAInputError("declared entry RVA differs from the original PE")
    result = generate_c0_source_project(
        state_machine=state_machine,
        entry_rva=entry_rva,
        out_dir=args.out_dir,
    )
    result["original"] = {
        "path": args.original.name,
        "sha256": sha256_file(args.original),
    }
    return result


def _cmd_stage_a_attest_c0_compilation(args: Any) -> dict[str, Any]:
    return attest_c0_compilation(
        source_manifest=args.source_manifest,
        toolchain_profile=args.toolchain_profile,
        candidate=args.candidate,
        derivation=args.derivation,
        nar_hash=args.nar_hash,
        out=args.out,
    )


def _cmd_stage_a_build_source_equivalence(args: Any) -> dict[str, Any]:
    return build_source_equivalence_report(
        original=args.original,
        source_manifest=args.source_manifest,
        compilation_attestation=args.compilation_attestation,
        lean_proof_bundle=args.lean_proof_bundle,
        out=args.out,
    )


def _cmd_stage_a_generate_c0_proof_sources(args: Any) -> dict[str, Any]:
    return generate_c0_proof_sources(
        original=args.original,
        candidate=args.candidate,
        state_machine=args.state_machine,
        source_manifest=args.source_manifest,
        toolchain_profile=args.toolchain_profile,
        candidate_build_identity=args.candidate_build_identity,
        out_dir=args.out_dir,
    )


def _cmd_stage_a_prepare_native_source_equivalence(args: Any) -> dict[str, Any]:
    payload = build_native_source_bundle_manifest(
        state_machine=args.state_machine,
        interpreter_package=args.interpreter_package,
        native_engine_package=args.native_engine_package,
        native_runtime_package=args.native_runtime_package,
        load_image_contract=args.load_image_contract,
    )
    write_json(args.out, payload)
    return payload


def _cmd_stage_a_attest_native_source_compilation(args: Any) -> dict[str, Any]:
    tools: dict[str, Path] = {}
    for value in args.tool:
        if "=" not in value:
            raise StageAInputError("--tool must use ROLE=PATH syntax")
        role, raw_path = value.split("=", 1)
        role = role.strip()
        if not role or role in tools:
            raise StageAInputError("--tool roles must be nonempty and unique")
        tools[role] = Path(raw_path)
    try:
        provenance = json.loads(args.nix_provenance.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StageAInputError(f"invalid Nix provenance JSON: {exc}") from exc
    if not isinstance(provenance, dict):
        raise StageAInputError("Nix provenance must be a JSON object")
    payload = build_native_source_compilation_attestation(
        source_bundle_manifest=args.source_bundle,
        native_build_manifest=args.native_build_manifest,
        nix_provenance=provenance,
        additional_tools=tools,
        nix_store_root=args.nix_store_root,
    )
    write_json(args.out, payload)
    return payload


def _cmd_stage_b_generate_link_roots(args: Any) -> dict[str, Any]:
    return stage_b_generate_link_roots(
        original=args.original,
        object_file=args.object_file,
        out=args.out,
        nm=args.nm,
        linker_map_original=args.linker_map_original,
        reference_contract=args.reference_contract,
        skeleton_functions=args.skeleton_functions,
    )


def _cmd_stage_b_generate_candidate_provenance(args: Any) -> dict[str, Any]:
    return stage_b_generate_candidate_provenance(
        target_name=args.target_name,
        skeleton_manifest=args.skeleton_manifest,
        candidate=args.candidate,
        build_target=args.build_target,
        build_compiler=args.build_compiler,
        out=args.out,
        functional_report=args.functional_report,
        build_output=args.build_output,
        build_report=args.build_report,
        target_closure_manifest=args.target_closure_manifest,
        fixed_up_sources=args.fixed_up_source,
    )


def _cmd_stage_b_materialize_upstream_suite(args: Any) -> dict[str, Any]:
    return stage_b_materialize_upstream_suite(
        target_name=args.target_name,
        suite_source=args.suite_source,
        source_revision=args.source_revision,
        cases=args.cases,
        out=args.out,
        suite_scope=args.suite_scope,
    )


def _cmd_stage_b_run_functional_suite(args: Any) -> dict[str, Any]:
    command = _stage_b_candidate_command(args.candidate_command, "stage-b-run-functional-suite")
    return stage_b_run_functional_suite(
        suite=args.suite,
        candidate_command=tuple(command),
        out=args.out,
        timeout_seconds=args.timeout_seconds,
        candidate_binary=args.candidate_binary,
        strip_stderr_line_regexes=tuple(args.strip_stderr_line_regex),
    )


def _cmd_stage_b_run_functional_case(args: Any) -> dict[str, Any]:
    command = _stage_b_candidate_command(args.candidate_command, "stage-b-run-functional-case")
    return stage_b_run_functional_case(
        suite=args.suite,
        case_id=args.case_id,
        candidate_command=tuple(command),
        out=args.out,
        timeout_seconds=args.timeout_seconds,
        candidate_binary=args.candidate_binary,
        strip_stderr_line_regexes=tuple(args.strip_stderr_line_regex),
    )


def _stage_b_candidate_command(values: Any, command_name: str) -> list[str]:
    command = list(values or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise StageBFunctionalInputError(
            f"{command_name} requires a candidate command after --"
        )
    return command


def _cmd_stage_b_extract_candidate_crash(args: Any) -> dict[str, Any]:
    return stage_b_extract_candidate_crash(
        functional_report=args.functional_report,
        out=args.out,
        candidate=args.candidate,
        target_name=args.target_name,
        diagnostic_functional_report=args.diagnostic_functional_report,
    )


def _cmd_stage_b_validate_candidate(args: Any) -> dict[str, Any]:
    return stage_b_validate_candidate(
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        skeleton_manifest=args.skeleton_manifest,
        candidate_provenance=args.candidate_provenance,
        target_name=args.target_name,
        out=args.out,
        functional_report=args.functional_report,
        reference_contract=args.reference_contract,
        model=args.model,
        require_functional_evidence=args.require_functional_evidence,
    )


def _cmd_stage_b_explain_delta(args: Any) -> dict[str, Any]:
    return stage_b_explain_delta(
        reference_contract=args.reference_contract,
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        skeleton_manifest=args.skeleton_manifest,
        out=args.out,
        unit_contract_dir=args.unit_contract_dir,
        candidate_crash_report=args.candidate_crash_report,
        candidate_probe_report=args.candidate_probe_report,
        functional_report=args.functional_report,
        candidate_modules=_candidate_modules(args.candidate_module),
        model=args.model,
        contract_candidate_validation=args.contract_candidate_validation,
        focus=args.focus,
        focused_only=args.focused_only,
        embed_contract_candidate_validation=not args.no_embed_contract_candidate_validation,
    )


def _cmd_stage_b_generate_native_engine(args: Any) -> dict[str, Any]:
    callback_targets: list[int | dict[str, Any]] = list(args.callback_rva)
    import_iat_vas: dict[tuple[str, str | int], int] | None = None
    base_relocation_evidence: dict[str, Any] | None = None
    if args.load_image_contract is not None:
        if args.reference_contract is None:
            raise ValueError(
                "--reference-contract is required with --load-image-contract"
            )
        contract = load_stage_a_load_image_contract(args.load_image_contract)
        if args.entry_rva != contract.identity.entry_rva:
            raise ValueError(
                "native-engine entry RVA differs from the load-image contract"
            )
        import_iat_vas = {}
        for descriptor in contract.imports:
            for cell in descriptor.cells:
                identity: str | int
                if cell.symbol is not None:
                    identity = cell.symbol
                elif cell.ordinal is not None:
                    identity = cell.ordinal
                else:
                    raise ValueError("load-image import cell has no identity")
                key = (descriptor.dll.lower(), identity)
                value = contract.identity.preferred_base + cell.iat_rva
                previous = import_iat_vas.setdefault(key, value)
                if previous != value:
                    raise ValueError(
                        f"load-image contract has ambiguous IAT cells for {key!r}"
                    )
        tls_rvas = set()
        if contract.tls is not None:
            for callback in contract.tls.callbacks:
                tls_rvas.add(callback.rva)
                callback_targets.append(
                    {
                        "rva": callback.rva,
                        "kind": "tls_callback",
                        "stack_cleanup_bytes": 12,
                    }
                )
        duplicate_tls = sorted(tls_rvas.intersection(args.callback_rva))
        if duplicate_tls:
            raise ValueError(
                "TLS callback RVAs must not also be passed via --callback-rva: "
                + ", ".join(f"{rva:#x}" for rva in duplicate_tls)
            )
        relocation_rows = []
        for block in contract.relocations:
            for relocation in block.relocations:
                if (
                    relocation.target_rva is None
                    or relocation.preferred_value is None
                    or relocation.width == 0
                ):
                    continue
                relocation_rows.append(
                    {
                        "source_rva": relocation.target_rva,
                        "type": relocation.type,
                        "kind": relocation.kind,
                        "width": relocation.width,
                        "preferred_value": relocation.preferred_value,
                    }
                )
        base_relocation_evidence = {
            "format": "stage-b-pe32-base-relocation-evidence-v1",
            "complete": contract.completeness.complete,
            "pe_sha256": contract.identity.pe_sha256,
            "reference_contract_sha256": sha256_file(args.reference_contract),
            "image_base": contract.identity.preferred_base,
            "relocations": relocation_rows,
        }
    return write_stage_b_native_engine_package(
        state_machine=args.state_machine,
        machine_ir=args.machine_ir,
        entry_rva=args.entry_rva,
        callback_targets=callback_targets,
        import_iat_vas=import_iat_vas,
        base_relocation_evidence=base_relocation_evidence,
        callable_external_contract=args.callable_external_contract,
        out=args.out_dir,
    )


def _cmd_stage_a_generate_engine_segments(args: Any) -> dict[str, Any]:
    evidence = write_engine_segment_evidence(
        semantic_transfers=args.semantic_transfers,
        interpreter_program_manifest=args.interpreter_program,
        interpreter_package_manifest=args.interpreter_package,
        candidate_pe=args.candidate,
        linker_map=args.linker_map,
        engine_layout=args.engine_layout,
        kernel_callback_plan=args.kernel_callback_plan,
        product_cutpoints=args.product_cutpoint,
        out=args.out,
    )
    return evidence.to_payload()


def _auto_int(value: str) -> int:
    try:
        result = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from exc
    if not 0 <= result < 2**32:
        raise argparse.ArgumentTypeError("integer must fit in an unsigned 32-bit value")
    return result


def _cmd_stage_b_inventory_source_calls(args: Any) -> dict[str, Any]:
    binding = _json_file(args.source_binding, "source-project binding")
    if not isinstance(binding, dict):
        raise ValueError("source-project binding must be a JSON object")
    sources = binding.get("sources")
    if not isinstance(sources, list):
        raise ValueError("source-project binding omits its source inventory")
    return inventory_clang_source_calls(
        ast_json=args.clang_ast,
        source_root=args.source_root,
        source_hashes=sources,
        project_symbols=[
            island["source_symbol"]
            for island in binding.get("islands", [])
            if isinstance(island, dict) and isinstance(island.get("source_symbol"), str)
        ],
        out=args.out,
    )


def _cmd_stage_b_audit_candidate_dependencies(args: Any) -> dict[str, Any]:
    payload = _json_file(args.allowed_runtime_imports, "allowed runtime imports")
    if isinstance(payload, dict):
        bound = bind_allowed_runtime_imports(payload)
        supplied_hash = payload.get("envelope_sha256")
        if supplied_hash is not None and supplied_hash != bound["envelope_sha256"]:
            raise ValueError("allowed runtime imports hash is stale")
        imports = bound["imports"]
        envelope_sha256 = bound["envelope_sha256"]
    else:
        imports = payload
        envelope_sha256 = None
    if not isinstance(imports, list):
        raise ValueError("allowed runtime imports must be an array or contain one")
    return audit_candidate_dependencies(
        candidate=args.candidate,
        call_plan=args.call_plan,
        allowed_runtime_imports=imports,
        allowed_runtime_imports_sha256=envelope_sha256,
        out=args.out,
    )


def _json_object_arg(text: str | None, path: Path | None) -> dict[str, Any] | None:
    if text and path is not None:
        raise ValueError("provide --proof-metadata-json or --proof-metadata, not both")
    if path is not None:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    elif text:
        payload = json.loads(text)
    else:
        return None
    if not isinstance(payload, dict):
        raise ValueError("proof metadata must be a JSON object")
    return payload


def _json_file(path: Path, description: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read {description}: {exc}") from exc


def _write_bound_json(
    *,
    source: Path,
    out: Path,
    label: str,
    binder: Any,
) -> dict[str, Any]:
    payload = _json_file(source, label)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    bound = binder(payload)
    write_json(out, bound)
    return bound


def _candidate_modules(values: list[str]) -> list[dict[str, Any]] | None:
    modules: list[dict[str, Any]] = []
    for value in values:
        text = value.strip()
        if text.startswith("{"):
            payload = json.loads(text)
        else:
            payload = {}
            for part in text.split(","):
                if not part:
                    continue
                if "=" not in part:
                    raise ValueError(f"--candidate-module fields must use key=value or JSON object syntax: {value!r}")
                key, field_value = part.split("=", 1)
                payload[key.strip().replace("-", "_")] = field_value.strip()
        if not isinstance(payload, dict):
            raise ValueError("--candidate-module must be a JSON object")
        modules.append(payload)
    return modules or None


def _exit_status(result: dict[str, Any]) -> int:
    status = result.get("status", result.get("verdict"))
    verdict = result.get("verdict", status)
    if status in {
        "pass",
        "passed",
        "generated",
        "candidate-generated",
        "prepared",
        "analyzed",
        "checked",
        "complete",
        "detected",
        "recovered",
        "reduced",
        "ready",
        "bound",
        "indexed",
        "locked",
        "classified",
        "satisfied",
        "qualified",
        "conditional_pass",
    }:
        return 0
    if verdict == "pass":
        return 0
    return 1


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))
