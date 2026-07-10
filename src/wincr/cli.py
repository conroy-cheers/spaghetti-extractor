from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .stage_a import (
    STAGE_A_MODEL_ID,
    StageAInputError,
    stage_a_check_proof,
    stage_a_audit_contract_shortfalls,
    stage_a_diff_obligations,
    stage_a_explain_obligations,
    stage_a_export_reference_contract,
    stage_a_extract_work_items,
    stage_a_generate_map,
    stage_a_semantic_coverage,
    stage_a_smoke_contract,
    stage_a_validate,
    stage_a_validate_contract_candidate,
    stage_a_validate_suite,
    stage_a_validate_unit,
)
from .stage_b import (
    stage_b_diff_delta,
    stage_b_explain_delta,
    stage_b_extract_candidate_crash,
    stage_b_export_decompiler,
    stage_b_validate_candidate,
)
from .stage_b_functional import (
    StageBFunctionalInputError,
    stage_b_materialize_upstream_suite,
    stage_b_run_functional_suite,
)
from .stage_b_provenance import StageBProvenanceInputError, stage_b_generate_candidate_provenance
from .stage_b_skeleton import stage_b_generate_link_roots, stage_b_generate_skeleton


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


def _build_parser(*, prog: str | None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog or "wincr",
        description="Windows PE Stage A/B reimplementation tooling.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser("stage-a-validate", help="validate a PE32 binary pair against a block map")
    validate.add_argument("--original", type=Path, required=True)
    validate.add_argument("--candidate", type=Path, required=True)
    validate.add_argument("--mapping", type=Path, required=True)
    validate.add_argument("--model", default=STAGE_A_MODEL_ID)
    validate.add_argument("--out", type=Path, required=True)
    validate.add_argument("--invariants", type=Path)
    validate.add_argument("--layout-contract", type=Path)
    validate.add_argument("--lean-input", action="append", default=[], type=Path)
    validate.set_defaults(func=_cmd_stage_a_validate)

    prove = subcommands.add_parser("stage-a-prove", help="generate and check an exact-byte Stage A refinement proof")
    prove.add_argument("--original", type=Path, required=True)
    prove.add_argument("--candidate", type=Path, required=True)
    prove.add_argument("--mapping", type=Path, required=True)
    prove.add_argument("--model", default=STAGE_A_MODEL_ID)
    prove.add_argument("--out", type=Path, required=True)
    prove.add_argument("--invariants", type=Path)
    prove.add_argument("--layout-contract", type=Path)
    prove.add_argument("--lean-input", action="append", default=[], type=Path)
    prove.set_defaults(func=_cmd_stage_a_validate)

    check_proof = subcommands.add_parser("stage-a-check-proof", help="independently rebuild and check a Stage A formal proof bundle")
    check_proof.add_argument("--report", type=Path, required=True)
    check_proof.add_argument("--original", type=Path)
    check_proof.add_argument("--candidate", type=Path)
    check_proof.add_argument("--out", type=Path)
    check_proof.set_defaults(
        func=lambda args: stage_a_check_proof(
            report=args.report,
            original=args.original,
            candidate=args.candidate,
            out=args.out,
        )
    )

    suite = subcommands.add_parser("stage-a-validate-suite", help="run a Stage A validation suite manifest")
    suite.add_argument("--suite", type=Path, required=True)
    suite.add_argument("--out", type=Path, required=True)
    suite.add_argument("--model")
    suite.set_defaults(func=lambda args: stage_a_validate_suite(suite=args.suite, out=args.out, model=args.model))

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
    contract.add_argument("--model", default=STAGE_A_MODEL_ID)
    contract.set_defaults(func=_cmd_stage_a_export_reference_contract)

    smoke = subcommands.add_parser("stage-a-smoke-contract", help="run the cheap Stage A contract sanity gate")
    smoke.add_argument("--reference-contract", type=Path, required=True)
    smoke.add_argument("--out", type=Path)
    smoke.set_defaults(func=lambda args: stage_a_smoke_contract(reference_contract=args.reference_contract, out=args.out))

    contract_candidate = subcommands.add_parser("stage-a-validate-contract-candidate", help="validate a candidate against a reference contract")
    contract_candidate.add_argument("--reference-contract", type=Path, required=True)
    contract_candidate.add_argument("--candidate", type=Path, required=True)
    contract_candidate.add_argument("--linker-map-candidate", type=Path, required=True)
    contract_candidate.add_argument("--out", type=Path, required=True)
    contract_candidate.add_argument("--model", default=STAGE_A_MODEL_ID)
    contract_candidate.add_argument("--skeleton-manifest", type=Path)
    contract_candidate.set_defaults(func=_cmd_stage_a_validate_contract_candidate)

    audit_shortfalls = subcommands.add_parser(
        "stage-a-audit-contract-shortfalls",
        help="audit underconstrained Stage A generated-candidate contract evidence",
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
    audit_shortfalls.add_argument("--model", default=STAGE_A_MODEL_ID)
    audit_shortfalls.set_defaults(func=_cmd_stage_a_audit_contract_shortfalls)

    work_items = subcommands.add_parser("stage-a-extract-work-items", help="extract ranked unit work from a reference contract")
    work_items.add_argument("--reference-contract", type=Path, required=True)
    work_items.add_argument("--out", type=Path, required=True)
    work_items.add_argument("--unit-contract-dir", type=Path)
    work_items.set_defaults(func=_cmd_stage_a_extract_work_items)

    semantic = subcommands.add_parser("stage-a-semantic-coverage", help="summarize implementable unit-contract coverage")
    semantic.add_argument("--reference-contract", type=Path, required=True)
    semantic.add_argument("--out", type=Path, required=True)
    semantic.add_argument("--unit-contract-dir", type=Path)
    semantic.set_defaults(func=_cmd_stage_a_semantic_coverage)

    validate_unit = subcommands.add_parser("stage-a-validate-unit", help="run focused Stage A contract validation for one region")
    validate_unit.add_argument("--reference-contract", type=Path, required=True)
    validate_unit.add_argument("--candidate", type=Path, required=True)
    validate_unit.add_argument("--linker-map-candidate", type=Path, required=True)
    validate_unit.add_argument("--skeleton-manifest", type=Path)
    validate_unit.add_argument("--focus", required=True)
    validate_unit.add_argument("--out", type=Path, required=True)
    validate_unit.add_argument("--unit-contract-dir", type=Path)
    validate_unit.add_argument("--model", default=STAGE_A_MODEL_ID)
    validate_unit.add_argument("--contract-candidate-validation", type=Path)
    validate_unit.add_argument("--no-embed-contract-candidate-validation", action="store_true")
    validate_unit.set_defaults(func=_cmd_stage_a_validate_unit)

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
    validate_candidate.add_argument("--reference-contract", type=Path)
    validate_candidate.add_argument("--original", type=Path)
    validate_candidate.add_argument("--linker-map-original", type=Path)
    validate_candidate.add_argument("--functional-report", type=Path)
    validate_candidate.add_argument("--original-flags", default="")
    validate_candidate.add_argument("--candidate-flags", default="")
    validate_candidate.add_argument("--model", default=STAGE_A_MODEL_ID)
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
    delta.add_argument("--model", default=STAGE_A_MODEL_ID)
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


def _cmd_stage_a_validate(args: Any) -> dict[str, Any]:
    return stage_a_validate(
        original=args.original,
        candidate=args.candidate,
        mapping=args.mapping,
        model=args.model,
        out=args.out,
        invariants=args.invariants,
        layout_contract=args.layout_contract,
        lean_inputs=args.lean_input,
    )


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
    return stage_a_export_reference_contract(
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


def _cmd_stage_a_validate_contract_candidate(args: Any) -> dict[str, Any]:
    return stage_a_validate_contract_candidate(
        reference_contract=args.reference_contract,
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        out=args.out,
        model=args.model,
        skeleton_manifest=args.skeleton_manifest,
    )


def _cmd_stage_a_audit_contract_shortfalls(args: Any) -> dict[str, Any]:
    return stage_a_audit_contract_shortfalls(
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


def _cmd_stage_a_extract_work_items(args: Any) -> dict[str, Any]:
    return stage_a_extract_work_items(
        reference_contract=args.reference_contract,
        out=args.out,
        unit_contract_dir=args.unit_contract_dir,
    )


def _cmd_stage_a_semantic_coverage(args: Any) -> dict[str, Any]:
    return stage_a_semantic_coverage(
        reference_contract=args.reference_contract,
        out=args.out,
        unit_contract_dir=args.unit_contract_dir,
    )


def _cmd_stage_a_validate_unit(args: Any) -> dict[str, Any]:
    return stage_a_validate_unit(
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
    command = list(args.candidate_command or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise StageBFunctionalInputError("stage-b-run-functional-suite requires a candidate command after --")
    return stage_b_run_functional_suite(
        suite=args.suite,
        candidate_command=tuple(command),
        out=args.out,
        timeout_seconds=args.timeout_seconds,
        candidate_binary=args.candidate_binary,
        strip_stderr_line_regexes=tuple(args.strip_stderr_line_regex),
    )


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
        original=args.original,
        candidate=args.candidate,
        linker_map_original=args.linker_map_original,
        linker_map_candidate=args.linker_map_candidate,
        skeleton_manifest=args.skeleton_manifest,
        candidate_provenance=args.candidate_provenance,
        target_name=args.target_name,
        out=args.out,
        functional_report=args.functional_report,
        reference_contract=args.reference_contract,
        original_flags=args.original_flags,
        candidate_flags=args.candidate_flags,
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
    if status in {"pass", "passed", "generated", "complete", "detected"}:
        return 0
    if verdict == "pass":
        return 0
    return 1


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))
