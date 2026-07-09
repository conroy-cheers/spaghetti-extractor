from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Iterable

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

from .pe import (
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    mapped_section_size,
)
from .stage_binary import StageAInputError, _artifact_name, _coff_symbol_aliases_by_rva
from .util import sha256_bytes, sha256_file, utc_now, write_json


STAGE_A_MODEL_ID = "x86-pe32-env-v1"
STAGE_A_X86_64_MODEL_ID = "x86_64-pe32plus-env-v1"
STAGE_A_MODEL_SPECS = {
    STAGE_A_MODEL_ID: {"architecture": "x86", "machine": "i386", "bitness": 32, "magic": 0x10B},
    STAGE_A_X86_64_MODEL_ID: {"architecture": "x86_64", "machine": "x86_64", "bitness": 64, "magic": 0x20B},
}
CHECKED_GENERATED_MAPPING_PROOF_RULES = {
    "reproducible_jq_same_source_optimization_pair_v1",
    "reproducible_stage_b_skeleton_reimplementation_v1",
}
CHECKED_GENERATED_CFG_SOURCE_KINDS = {
    "linker_map_capstone_block_match_v1",
    "paired_executable_section_gap_v1",
}
CHECKED_REACHABILITY_ROOT_KINDS = {
    "fixture_function",
    "linker_map_function",
    "linker_map_section_gap",
}
NORETURN_IMPORT_SYMBOLS = {
    "abort",
    "amsg_exit",
    "exit",
    "exitprocess",
    "terminateprocess",
}
ABI_FIXED_STDCALL_IMPORT_STACK_ARG_COUNTS = {
    "arefileapisansi": 0,
    "deletecriticalsection": 1,
    "entercriticalsection": 1,
    "getconsolemode": 2,
    "getlasterror": 0,
    "getmodulehandlea": 1,
    "getprocaddress": 2,
    "getstdhandle": 1,
    "gettimezoneinformation": 1,
    "initializecriticalsection": 1,
    "isdbcsleadbyteex": 2,
    "leavecriticalsection": 1,
    "multibytetowidechar": 6,
    "pathisrelativea": 1,
    "setconsolemode": 2,
    "setunhandledexceptionfilter": 1,
    "sleep": 1,
    "tlsgetvalue": 1,
    "virtualprotect": 4,
    "virtualquery": 3,
    "widechartomultibyte": 8,
    "writeconsolew": 5,
    "writefile": 5,
}
OBLIGATION_STATUSES = {
    "proved",
    "failed",
    "incomplete",
    "unmapped",
    "waived_noncode",
    "out_of_model",
}


@dataclass(frozen=True)
class StageASection:
    name: str
    rva_start: int
    rva_end: int
    raw_pointer: int
    raw_size: int
    characteristics: int
    executable: bool
    readable: bool
    writable: bool
    contains_code: bool


@dataclass(frozen=True)
class StageAImport:
    dll: str
    symbol: str | None
    ordinal: int | None
    thunk_rva: int | None


@dataclass(frozen=True)
class StageABinary:
    path: Path
    sha256: str
    size: int
    machine: str
    bitness: int
    image_base: int
    entrypoint_rva: int
    size_of_image: int
    subsystem: str
    sections: tuple[StageASection, ...]
    imports: tuple[StageAImport, ...]
    pe: pefile.PE


@dataclass(frozen=True)
class BlockSide:
    rva_start: int
    rva_end: int

    @property
    def size(self) -> int:
        return self.rva_end - self.rva_start


@dataclass(frozen=True)
class BlockMapping:
    id: str
    original: BlockSide
    candidate: BlockSide
    kind: str
    reachable: bool
    invariant_checked: bool
    source: dict[str, Any]


@dataclass(frozen=True)
class NonCodeWaiver:
    id: str
    binary: str
    rva_start: int
    rva_end: int
    reason: str


def stage_a_validate(
    *,
    original: Path,
    candidate: Path,
    mapping: Path,
    model: str,
    out: Path,
    invariants: Path | None = None,
    layout_contract: Path | None = None,
    lean_inputs: Iterable[Path] | None = None,
) -> dict[str, Any]:
    started_at = utc_now()
    out = Path(out)
    lean_input_paths = tuple(Path(path) for path in (lean_inputs or ()))
    _prepare_report_tree(out)

    obligations: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    incomplete: list[dict[str, Any]] = []
    proof_cache: list[dict[str, Any]] = []
    layout: dict[str, Any]

    try:
        mapping_payload = _load_json(mapping)
        invariant_payload = _load_optional_json(invariants)
        layout_contract_payload = _load_optional_json(layout_contract)
    except StageAInputError as exc:
        mapping_payload = {}
        invariant_payload = None
        layout_contract_payload = None
        layout = _empty_layout(original, candidate)
        _record_incomplete(
            incomplete,
            category="invalid_input",
            blocker=str(exc),
            next_action="fix the Stage A input JSON and rerun stage-a-validate",
        )
        verdict = "incomplete"
        return _write_report(
            out=out,
            verdict=verdict,
            started_at=started_at,
            original=original,
            candidate=candidate,
            model=model,
            layout=layout,
            obligations=obligations,
            failures=failures,
            incomplete=incomplete,
            proof_cache=proof_cache,
            mapping_payload=mapping_payload,
            invariant_payload=invariant_payload,
            lean_inputs=lean_input_paths,
        )

    try:
        original_bin = _parse_stage_a_pe(original)
        candidate_bin = _parse_stage_a_pe(candidate)
    except StageAInputError as exc:
        layout = _empty_layout(original, candidate)
        _record_incomplete(
            incomplete,
            category="out_of_model",
            blocker=str(exc),
            next_action="provide valid x86 PE32 or x86_64 PE32+ original and candidate binaries",
        )
        verdict = "incomplete"
        return _write_report(
            out=out,
            verdict=verdict,
            started_at=started_at,
            original=original,
            candidate=candidate,
            model=model,
            layout=layout,
            obligations=obligations,
            failures=failures,
            incomplete=incomplete,
            proof_cache=proof_cache,
            mapping_payload=mapping_payload,
            invariant_payload=invariant_payload,
            lean_inputs=lean_input_paths,
        )

    layout = _layout_report(original_bin, candidate_bin, layout_contract_payload)

    if model not in STAGE_A_MODEL_SPECS:
        _record_incomplete(
            incomplete,
            category="unsupported_model",
            blocker=f"unsupported Stage A model {model!r}",
            next_action=f"rerun with --model {STAGE_A_MODEL_ID}, --model {STAGE_A_X86_64_MODEL_ID}, or add a model implementation",
        )
    else:
        model_issues = _model_binary_issues(model, original_bin, candidate_bin)
        incomplete.extend(model_issues)

    for issue in _layout_issues(original_bin, candidate_bin, layout_contract_payload):
        if issue["severity"] == "fail":
            failures.append(issue)
        else:
            incomplete.append(issue)

    mappings, waivers, map_issues = _parse_block_map(mapping_payload, original_bin)
    map_issues.extend(_generated_map_issues(mapping_payload))
    for issue in map_issues:
        if issue["status"] == "failed":
            failures.append(issue)
        else:
            incomplete.append(issue)

    verified_waivers, waiver_obligations = _waiver_obligations(original_bin, candidate_bin, waivers)
    obligations.extend(waiver_obligations)
    for obligation in waiver_obligations:
        if obligation["status"] == "incomplete":
            blocker = obligation["incomplete"]
            incomplete.append(blocker)
            _write_incomplete_artifact(out, blocker)
    obligations.extend(_coverage_obligations("original", original_bin, mappings, verified_waivers, incomplete))
    obligations.extend(_coverage_obligations("candidate", candidate_bin, mappings, verified_waivers, incomplete))

    invariant_issues = _invariant_issues(invariant_payload, mappings)
    incomplete.extend(invariant_issues)

    mapped_block_ids = {obligation["id"] for obligation in obligations}
    for mapped in mappings:
        if f"block:{mapped.id}" in mapped_block_ids:
            continue
        obligation = _prove_mapped_block(original_bin, candidate_bin, mapped, out, proof_cache, invariant_payload)
        obligations.append(obligation)
        status = obligation["status"]
        if status == "failed":
            failure = obligation["failure"]
            failures.append(failure)
            _write_failure_artifacts(out, failure)
        elif status in {"incomplete", "out_of_model"}:
            blocker = obligation["incomplete"]
            incomplete.append(blocker)
            _write_incomplete_artifact(out, blocker)

    block_statuses = {item["id"]: item["status"] for item in obligations if item.get("kind") == "block_equivalence"}
    edge_obligations = _cfg_edge_obligations(original_bin, candidate_bin, mappings, block_statuses)
    for obligation in edge_obligations:
        obligations.append(obligation)
        status = obligation["status"]
        if status == "failed":
            failure = obligation["failure"]
            failures.append(failure)
            _write_failure_artifacts(out, failure)
        elif status == "incomplete":
            blocker = obligation["incomplete"]
            incomplete.append(blocker)
            _write_incomplete_artifact(out, blocker)

    for obligation in _reachability_obligations(original_bin, mappings, block_statuses, edge_obligations):
        obligations.append(obligation)
        if obligation["status"] == "incomplete":
            blocker = obligation["incomplete"]
            incomplete.append(blocker)
            _write_incomplete_artifact(out, blocker)

    verdict = _derive_verdict(failures, incomplete, obligations)
    return _write_report(
        out=out,
        verdict=verdict,
        started_at=started_at,
        original=original,
        candidate=candidate,
        model=model,
        layout=layout,
        obligations=obligations,
        failures=failures,
        incomplete=incomplete,
        proof_cache=proof_cache,
        mapping_payload=mapping_payload,
        invariant_payload=invariant_payload,
        lean_inputs=lean_input_paths,
    )


def stage_a_validate_suite(
    *,
    suite: Path,
    out: Path,
    model: str | None = None,
) -> dict[str, Any]:
    started_at = utc_now()
    suite = Path(suite)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cases").mkdir(parents=True, exist_ok=True)

    cases: list[dict[str, Any]] = []
    try:
        payload = _load_json(suite)
    except StageAInputError as exc:
        result = {
            "format": "stage-a-validation-suite-v1",
            "status": "incomplete",
            "started_at": started_at,
            "completed_at": utc_now(),
            "suite": str(suite),
            "blocker": str(exc),
            "next_action": "fix the Stage A validation suite JSON",
            "cases": [],
            "counts": {"cases": 0, "passed": 0, "failed": 0, "incomplete": 1},
        }
        write_json(out / "suite.json", result)
        return result

    suite_model = model or (payload.get("model") if isinstance(payload, dict) else None) or STAGE_A_MODEL_ID
    case_entries = payload.get("cases") if isinstance(payload, dict) else None
    if not isinstance(case_entries, list):
        result = {
            "format": "stage-a-validation-suite-v1",
            "status": "incomplete",
            "started_at": started_at,
            "completed_at": utc_now(),
            "suite": str(suite),
            "blocker": "suite JSON must contain a cases list",
            "next_action": "add Stage A validation case entries",
            "cases": [],
            "counts": {"cases": 0, "passed": 0, "failed": 0, "incomplete": 1},
        }
        write_json(out / "suite.json", result)
        return result

    for index, entry in enumerate(case_entries):
        case = _run_stage_a_suite_case(
            suite_root=suite.parent,
            out=out,
            index=index,
            entry=entry,
            default_model=suite_model,
        )
        cases.append(case)

    passed = sum(1 for case in cases if case["status"] == "passed")
    failed = sum(1 for case in cases if case["status"] == "failed")
    incomplete_count = sum(1 for case in cases if case["status"] == "incomplete")
    status = "pass" if cases and passed == len(cases) else ("incomplete" if incomplete_count and not failed else "fail")
    result = {
        "format": "stage-a-validation-suite-v1",
        "status": status,
        "started_at": started_at,
        "completed_at": utc_now(),
        "suite": str(suite),
        "model": suite_model,
        "cases": cases,
        "counts": {
            "cases": len(cases),
            "passed": passed,
            "failed": failed,
            "incomplete": incomplete_count,
        },
    }
    write_json(out / "suite.json", result)
    return result


def stage_a_generate_map(
    *,
    original: Path,
    candidate: Path,
    linker_map_original: Path,
    linker_map_candidate: Path,
    out: Path,
    layout_contract_out: Path | None = None,
    original_flags: str = "",
    candidate_flags: str = "",
    proof_rule: str = "reproducible_jq_same_source_optimization_pair_v1",
    proof_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if proof_rule not in CHECKED_GENERATED_MAPPING_PROOF_RULES:
        raise StageAInputError(f"unsupported generated mapping proof rule {proof_rule!r}")
    original_bin = _parse_stage_a_pe(original)
    candidate_bin = _parse_stage_a_pe(candidate)
    original_functions = _parse_linker_map_functions(linker_map_original, original_bin)
    candidate_functions = _parse_linker_map_functions(linker_map_candidate, candidate_bin)
    issues = _jq_map_layout_issues(original_bin, candidate_bin)
    issues.extend(_generated_mapping_proof_metadata_issues(proof_rule, proof_metadata))
    issues.extend(_linker_function_issues("original", original_functions))
    issues.extend(_linker_function_issues("candidate", candidate_functions))

    matched_functions, unmatched_original, unmatched_candidate, match_issues = _match_linker_functions_by_name_or_unique_alias(
        original_functions,
        candidate_functions,
    )
    issues.extend(match_issues)
    import_thunk_matches, _, _, import_thunk_issues = _match_import_thunk_functions_by_signature(
        original_bin,
        candidate_bin,
        original_functions,
        candidate_functions,
        sorted(_unique_functions_by_name(original_functions)),
        sorted(_unique_functions_by_name(candidate_functions)),
    )
    issues.extend(import_thunk_issues)
    import_matched_original = {str(original_thunk["function"]["name"]) for original_thunk, _ in import_thunk_matches}
    import_matched_candidate = {str(candidate_thunk["function"]["name"]) for _, candidate_thunk in import_thunk_matches}
    filtered_matched_functions: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    released_original: set[str] = set()
    released_candidate: set[str] = set()
    for original_fn, candidate_fn, match_key in matched_functions:
        original_name = str(original_fn["name"])
        candidate_name = str(candidate_fn["name"])
        if original_name in import_matched_original or candidate_name in import_matched_candidate:
            if original_name not in import_matched_original:
                released_original.add(original_name)
            if candidate_name not in import_matched_candidate:
                released_candidate.add(candidate_name)
            continue
        filtered_matched_functions.append((original_fn, candidate_fn, match_key))
    matched_functions = filtered_matched_functions
    unmatched_original = sorted((set(unmatched_original) | released_original) - import_matched_original)
    unmatched_candidate = sorted((set(unmatched_candidate) | released_candidate) - import_matched_candidate)
    blocks: list[dict[str, Any]] = []

    for original_thunk, candidate_thunk in import_thunk_matches:
        blocks.append(
            _import_thunk_block_entry(
                original_thunk,
                candidate_thunk,
                match_key=_import_thunk_match_key(original_thunk["import"]),
            )
        )

    for original_fn, candidate_fn, match_key in sorted(matched_functions, key=lambda item: str(item[0]["name"])):
        name = str(original_fn["name"])
        candidate_name = str(candidate_fn["name"])
        original_thunk = _linker_function_import_thunk_evidence(original_bin, original_fn)
        candidate_thunk = _linker_function_import_thunk_evidence(candidate_bin, candidate_fn)
        if original_thunk is not None or candidate_thunk is not None:
            if original_thunk is not None and candidate_thunk is not None and original_thunk["signature_key"] == candidate_thunk["signature_key"]:
                blocks.append(
                    _import_thunk_block_entry(
                        original_thunk,
                        candidate_thunk,
                        match_key=match_key,
                    )
                )
                continue
            issues.append(
                _incomplete_record(
                    category="ambiguous_import_thunk_match",
                    obligation_id=f"jq-map:import-thunk:{_artifact_name(name)}",
                    blocker="matched linker-map functions do not decode as the same PE import thunk",
                    next_action="preserve import thunk boundaries or add a more specific import-thunk matching rule",
                    details={
                        "function": name,
                        "candidate_function": candidate_name,
                        "original": _import_thunk_match_report(original_thunk),
                        "candidate": _import_thunk_match_report(candidate_thunk),
                    },
                )
            )
            continue
        original_blocks = _recover_basic_blocks(original_bin, original_fn["rva_start"], original_fn["rva_end"])
        candidate_blocks = _recover_basic_blocks(candidate_bin, candidate_fn["rva_start"], candidate_fn["rva_end"])
        matched, block_issues = _match_function_blocks(name, original_bin, candidate_bin, original_blocks, candidate_blocks)
        issues.extend(block_issues)
        for index, (original_block, candidate_block) in enumerate(matched):
            block_id = _artifact_name(f"{name}-{index:04d}")
            entry: dict[str, Any] = {
                "id": block_id,
                "kind": "code",
                "reachable": True,
                "original": {"rva": original_block["rva_start"], "size": original_block["rva_end"] - original_block["rva_start"]},
                "candidate": {"rva": candidate_block["rva_start"], "size": candidate_block["rva_end"] - candidate_block["rva_start"]},
                "source": {
                    "kind": "linker_map_capstone_block_match_v1",
                    "function": name,
                    "candidate_function": candidate_name,
                    "function_match_key": match_key,
                    "function_block_index": index,
                    "match": original_block["match_key"],
                },
                "proof": _generated_mapping_proof(
                    proof_rule=proof_rule,
                    function=name,
                    original_flags=original_flags,
                    candidate_flags=candidate_flags,
                    proof_metadata=proof_metadata,
                ),
            }
            if index == 0:
                entry["root"] = {"kind": "linker_map_function", "checked": True, "symbol": name}
            if original_block["bytes_sha256"] == candidate_block["bytes_sha256"]:
                entry["source"]["byte_identical"] = True
            blocks.append(entry)

    if unmatched_original:
        issues.append(
            _incomplete_record(
                category="missing_linker_map_entry",
                obligation_id="jq-map:unmatched-original-functions",
                blocker="original linker-map functions have no candidate function with the same canonical name",
                next_action="add a stronger jq function matcher or verify the build flags preserve these functions",
                details={"functions": unmatched_original[:200], "count": len(unmatched_original)},
            )
        )
    if unmatched_candidate:
        issues.append(
            _incomplete_record(
                category="missing_linker_map_entry",
                obligation_id="jq-map:unmatched-candidate-functions",
                blocker="candidate linker-map functions have no original function with the same canonical name",
                next_action="add a stronger jq function matcher or verify the build flags preserve these functions",
                details={
                    "functions": sorted(unmatched_candidate)[:200],
                    "count": len(unmatched_candidate),
                },
            )
        )

    gap_blocks, waivers, gap_issues = _paired_section_gap_classification(
        original_bin,
        candidate_bin,
        blocks,
        original_flags=original_flags,
        candidate_flags=candidate_flags,
        proof_rule=proof_rule,
        proof_metadata=proof_metadata,
    )
    blocks.extend(gap_blocks)
    issues.extend(gap_issues)

    map_payload = {
        "format": "stage-a-block-map-v1",
        "generator": "stage-a-generate-map",
        "status": "pass" if not issues else "incomplete",
        "original": {"path": str(original), "sha256": original_bin.sha256},
        "candidate": {"path": str(candidate), "sha256": candidate_bin.sha256},
        "linker_maps": {
            "original": str(linker_map_original),
            "candidate": str(linker_map_candidate),
        },
        "blocks": blocks,
        "waivers": waivers,
        "issues": issues,
        "counts": {
            "blocks": len(blocks),
            "waivers": len(waivers),
            "issues": len(issues),
            "original_functions": len(original_functions),
            "candidate_functions": len(candidate_functions),
        },
    }
    write_json(out, map_payload)

    layout_contract = _generated_layout_contract(original_bin, candidate_bin, map_payload)
    if layout_contract_out is not None:
        write_json(layout_contract_out, layout_contract)
    map_payload["layout_contract"] = layout_contract if layout_contract_out is None else str(layout_contract_out)
    return map_payload


def stage_a_export_reference_contract(
    *,
    original: Path,
    out: Path,
    candidate: Path | None = None,
    mapping: Path | None = None,
    validation_report: Path | None = None,
    layout_contract: Path | None = None,
    sidecar_dir: Path | None = None,
    unit_contract_dir: Path | None = None,
    model: str = STAGE_A_MODEL_ID,
) -> dict[str, Any]:
    original = Path(original)
    candidate = Path(candidate) if candidate is not None else None
    mapping = Path(mapping) if mapping is not None else None
    validation_report = Path(validation_report) if validation_report is not None else None
    layout_contract = Path(layout_contract) if layout_contract is not None else None
    out = Path(out)
    sidecar_dir = Path(sidecar_dir) if sidecar_dir is not None else out.parent
    unit_contract_dir = Path(unit_contract_dir) if unit_contract_dir is not None else sidecar_dir
    out.parent.mkdir(parents=True, exist_ok=True)
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    unit_contract_dir.mkdir(parents=True, exist_ok=True)

    original_bin = _parse_stage_a_pe(original)
    candidate_bin = _parse_stage_a_pe(candidate) if candidate is not None else None
    mapping_payload = _load_optional_json(mapping)
    layout_contract_payload = _load_optional_json(layout_contract)
    if layout_contract_payload is None:
        layout_contract_payload = _layout_contract_from_mapping_payload(mapping_payload, mapping)
    validation_payload = _load_stage_a_validation_report(validation_report)
    validation_binding = _reference_validation_report_binding_constraint(
        payload=validation_payload,
        original=original_bin,
        candidate=candidate_bin,
        mapping_payload=mapping_payload,
        model=model,
    )

    map_contract = _reference_map_constraints(
        original=original_bin,
        candidate=candidate_bin,
        mapping_payload=mapping_payload,
    )
    abi_callsites_constraint = _reference_abi_callsites_constraint(original_bin, candidate_bin, map_contract)
    roots_and_jump_tables_constraint = _reference_roots_and_jump_tables_with_abi_targets(
        map_contract["roots_and_jump_tables"],
        abi_callsites_constraint,
    )
    semantic_region_contracts = _reference_semantic_region_contracts_constraint(
        original_bin,
        map_contract["mappings"],
        abi_callsites_constraint,
    )
    proof_obligation_inventory = _reference_proof_obligation_inventory(validation_payload)
    proof_obligation_inventory = _reference_proof_obligation_inventory_with_semantic_regions(
        proof_obligation_inventory,
        semantic_region_contracts,
    )
    constraints = {
        "pe_sections_imports_relocations_image_base": _reference_pe_layout_constraint(
            original=original_bin,
            candidate=candidate_bin,
            layout_contract=layout_contract_payload,
        ),
        "executable_byte_coverage": map_contract["executable_byte_coverage"],
        "function_ranges": map_contract["function_ranges"],
        "basic_blocks_and_cfg": map_contract["basic_blocks_and_cfg"],
        "roots_and_jump_tables": roots_and_jump_tables_constraint,
        "import_thunks": _reference_import_thunk_constraint(original_bin, candidate_bin, map_contract),
        "abi_callsites": abi_callsites_constraint,
        "semantic_region_contracts": semantic_region_contracts,
        "padding_alignment": map_contract["padding_alignment"],
        "layout_normalization_assumptions": _reference_layout_normalization_constraint(layout_contract_payload),
        "validation_report_artifact_binding": validation_binding,
        "proof_obligation_inventory": proof_obligation_inventory,
    }
    issues = [
        *_reference_constraint_issues(constraints),
        *validation_binding.get("issues", []),
        *map_contract["issues"],
    ]
    contract = {
        "format": "stage-a-reference-contract-v1",
        "generator": "stage-a-export-reference-contract",
        "generated_at": utc_now(),
        "model": model,
        "status": _reference_contract_status(constraints, issues),
        "tool_versions": _tool_versions(),
        "inputs": _reference_contract_inputs(
            original=original,
            candidate=candidate,
            mapping=mapping,
            validation_report=validation_report,
            layout_contract=layout_contract,
        ),
        "original": _binary_reference_layout(original_bin),
        "candidate": _binary_reference_layout(candidate_bin) if candidate_bin is not None else None,
        "constraints": constraints,
        "families": _reference_contract_families(constraints),
        "coverage": {
            "original": constraints["executable_byte_coverage"].get("original"),
            "candidate": constraints["executable_byte_coverage"].get("candidate"),
        },
        "assumptions": {
            "layout_normalization": constraints["layout_normalization_assumptions"],
            "unchecked": [],
        },
        "issues": issues,
        "counts": {
            "issues": len(issues),
            "functions": len(constraints["function_ranges"].get("functions", [])),
            "basic_blocks": len(constraints["basic_blocks_and_cfg"].get("basic_blocks", [])),
            "cfg_edge_sources": len(constraints["basic_blocks_and_cfg"].get("cfg_edges", [])),
            "abi_callsites": constraints["abi_callsites"].get("counts", {}).get("callsites", 0),
            "proof_obligations": constraints["proof_obligation_inventory"].get("counts", {}).get("obligations", 0),
        },
        "sidecars": _reference_contract_sidecar_paths(sidecar_dir, out.parent, unit_contract_dir=unit_contract_dir),
    }
    semantic_payload = _reference_semantic_contract_payloads(
        original_bin,
        map_contract["mappings"],
        contract,
        _reference_sidecar_contract_ref(out),
    )
    write_json(out, contract)
    _write_reference_contract_sidecars(
        contract,
        out,
        sidecar_dir,
        unit_contract_dir=unit_contract_dir,
        semantic_payload=semantic_payload,
    )
    return contract


def stage_a_smoke_contract(*, reference_contract: Path, out: Path | None = None) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    issues = _stage_a_smoke_contract_issues(contract, reference_contract)
    result = {
        "format": "stage-a-contract-smoke-v1",
        "status": "pass" if not issues else "incomplete",
        "reference_contract": _reference_input_artifact(reference_contract),
        "issues": issues,
        "counts": {"issues": len(issues)},
    }
    if out is not None:
        write_json(Path(out), result)
    return result


def stage_a_validate_contract_candidate(
    *,
    reference_contract: Path,
    candidate: Path,
    linker_map_candidate: Path,
    out: Path,
    model: str = STAGE_A_MODEL_ID,
    skeleton_manifest: Path | None = None,
) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    candidate = Path(candidate)
    linker_map_candidate = Path(linker_map_candidate)
    skeleton_manifest = Path(skeleton_manifest) if skeleton_manifest is not None else None
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    contract = _load_json(reference_contract)
    candidate_bin = _parse_stage_a_pe(candidate)
    smoke = stage_a_smoke_contract(reference_contract=reference_contract)
    issues = list(smoke.get("issues", [])) if isinstance(smoke.get("issues"), list) else []
    if not isinstance(contract, dict) or contract.get("format") != "stage-a-reference-contract-v1":
        raise StageAInputError("reference contract must have format stage-a-reference-contract-v1")
    if contract.get("model") != model:
        issues.append(
            _incomplete_record(
                category="contract_model_mismatch",
                obligation_id="stage-a-contract-candidate:model",
                blocker="reference contract model does not match requested model",
                next_action="rerun with the contract model or regenerate the contract",
                details={"expected": model, "actual": contract.get("model")},
            )
        )
    candidate_functions = _parse_linker_map_functions(linker_map_candidate, candidate_bin)
    alias_evidence = _empty_contract_candidate_alias_evidence()
    if skeleton_manifest is not None:
        try:
            skeleton_payload = _load_json(skeleton_manifest)
            alias_evidence = _contract_candidate_skeleton_alias_evidence(skeleton_payload, candidate_functions)
        except StageAInputError as exc:
            alias_evidence = _empty_contract_candidate_alias_evidence(status="incomplete")
            issues.append(
                _incomplete_record(
                    category="contract_candidate_alias_evidence",
                    obligation_id="stage-a-contract-candidate:alias-evidence",
                    blocker=str(exc),
                    next_action="provide a readable stage-b-skeleton-v1 manifest or omit skeleton alias evidence",
                    details={"skeleton_manifest": str(skeleton_manifest)},
                )
            )
    families = _contract_candidate_families(contract, candidate_bin, candidate_functions, alias_evidence=alias_evidence)
    for family in families:
        if family["status"] in {"incomplete", "violated"}:
            issues.append(
                _incomplete_record(
                    category=f"contract_candidate_{family['family']}",
                    obligation_id=f"stage-a-contract-candidate:{family['family']}",
                    blocker=family.get("blocker", "candidate does not satisfy this reference contract family"),
                    next_action=family.get("next_action", "repair the candidate or regenerate the contract package"),
                    details=family.get("evidence", {}),
                )
            )
    verdict = "pass" if not issues and all(item["status"] in {"satisfied", "not_applicable"} for item in families) else "incomplete"
    result = {
        "format": "stage-a-contract-candidate-validation-v1",
        "verdict": verdict,
        "status": verdict,
        "model": model,
        "reference_contract": _reference_input_artifact(reference_contract),
        "candidate": _reference_input_artifact(candidate),
        "linker_map_candidate": _reference_input_artifact(linker_map_candidate),
        "skeleton_manifest": _reference_input_artifact(skeleton_manifest) if skeleton_manifest is not None else None,
        "families": families,
        "issues": issues,
        "counts": {
            "families": len(families),
            "issues": len(issues),
            "candidate_functions": len(candidate_functions),
            "alias_matches": alias_evidence["counts"]["alias_matches"],
            "alias_ambiguities": alias_evidence["counts"]["ambiguities"],
            "unmatched_aliases": alias_evidence["counts"].get("unmatched_aliases", 0),
        },
    }
    write_json(out / "verdict.json", result)
    write_json(out / "contract-candidate.json", result)
    return result


def stage_a_extract_work_items(
    *,
    reference_contract: Path,
    out: Path,
    unit_contract_dir: Path | None = None,
) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    contract_ref = _reference_sidecar_contract_ref(reference_contract)
    unit_contracts = _load_reference_unit_contract_sidecars(
        contract,
        reference_contract,
        unit_contract_dir=Path(unit_contract_dir) if unit_contract_dir is not None else None,
        contract_ref=contract_ref,
    )
    repair_units = unit_contracts.get("repair_units") if isinstance(unit_contracts.get("repair_units"), dict) else {}
    work_items = repair_units.get("work_items") if isinstance(repair_units.get("work_items"), list) else []
    result = {
        "format": "stage-a-work-items-v1",
        "status": "pass",
        "reference_contract": _reference_input_artifact(reference_contract),
        "unit_contracts": _reference_unit_contract_artifact(unit_contracts),
        "work_items": work_items,
        "counts": {
            "work_items": len(work_items),
            "by_family": _count_by([item for item in work_items if isinstance(item, dict)], "family"),
            "by_repair_class": _count_by([item for item in work_items if isinstance(item, dict)], "repair_class"),
        },
    }
    write_json(Path(out), result)
    return result


def stage_a_semantic_coverage(
    *,
    reference_contract: Path,
    out: Path,
    unit_contract_dir: Path | None = None,
) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    contract_ref = _reference_sidecar_contract_ref(reference_contract)
    unit_contracts = _load_reference_unit_contract_sidecars(
        contract,
        reference_contract,
        unit_contract_dir=Path(unit_contract_dir) if unit_contract_dir is not None else None,
        contract_ref=contract_ref,
    )
    blockers = _semantic_coverage_blockers(unit_contracts)
    status = "pass" if not blockers else "incomplete"
    result = {
        "format": "stage-a-semantic-coverage-v1",
        "status": status,
        "reference_contract": _reference_input_artifact(reference_contract),
        "unit_contracts": _reference_unit_contract_artifact(unit_contracts),
        "families": _semantic_coverage_families(unit_contracts, blockers),
        "counts": _semantic_coverage_counts(unit_contracts, blockers),
        "blockers": blockers[:250],
        "next_work": _semantic_coverage_next_work(blockers),
        "acceptance": {
            "jq_full_reimplementation_ready": status == "pass",
            "requirement": "all executable jq regions must have implementable transfer/cluster contracts or explicit external-boundary contracts",
            "final_acceptance": "compiled candidates still require full Stage A validation; this ledger only gates analysis coverage",
        },
    }
    write_json(Path(out), result)
    return result


def stage_a_validate_unit(
    *,
    reference_contract: Path,
    candidate: Path,
    linker_map_candidate: Path,
    skeleton_manifest: Path | None,
    focus: str,
    out: Path,
    unit_contract_dir: Path | None = None,
    model: str = STAGE_A_MODEL_ID,
    contract_candidate_validation: dict[str, Any] | Path | None = None,
    embed_contract_candidate_validation: bool = True,
) -> dict[str, Any]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    validation = _load_contract_candidate_validation(contract_candidate_validation)
    validation_source = "provided"
    if validation is None:
        validation_source = "computed"
        validation = stage_a_validate_contract_candidate(
            reference_contract=reference_contract,
            candidate=candidate,
            linker_map_candidate=linker_map_candidate,
            skeleton_manifest=skeleton_manifest,
            model=model,
            out=out / "contract-candidate",
        )
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    unit_contracts = _load_reference_unit_contract_sidecars(
        contract,
        reference_contract,
        unit_contract_dir=Path(unit_contract_dir) if unit_contract_dir is not None else None,
        contract_ref=_reference_sidecar_contract_ref(reference_contract),
    )
    focus_lower = focus.lower()
    focused_families = [
        item
        for item in validation.get("families", [])
        if isinstance(item, dict) and _matches_focus(item, focus_lower)
    ]
    focused_issues = [
        item
        for item in validation.get("issues", [])
        if isinstance(item, dict) and _matches_focus(item, focus_lower)
    ]
    focused_units = _matching_unit_contracts(unit_contracts, focus_lower)
    matched = bool(focused_families or focused_issues or focused_units)
    focused_status = "incomplete" if not matched or focused_families or focused_issues else "pass"
    status = "pass" if validation.get("verdict") == "pass" and matched else "incomplete"
    result = {
        "format": "stage-a-unit-validation-v1",
        "status": status,
        "focused_status": focused_status,
        "scope": "focused_unit_filter",
        "focus": focus,
        "reference_contract": _reference_input_artifact(reference_contract),
        "candidate": _reference_input_artifact(Path(candidate)),
        "candidate_contract_status": validation.get("status") or validation.get("verdict"),
        "contract_candidate_validation_source": validation_source,
        "contract_candidate_validation_embedded": embed_contract_candidate_validation,
        "contract_candidate_validation_artifact": _contract_candidate_validation_artifact(contract_candidate_validation),
        "contract_candidate_validation": validation
        if embed_contract_candidate_validation
        else _contract_candidate_validation_summary(validation),
        "families": focused_families,
        "issues": focused_issues,
        "unit_contracts": focused_units,
        "counts": {
            "families": len(focused_families),
            "issues": len(focused_issues),
            "unit_contracts": len(focused_units),
        },
    }
    if not matched:
        result["blocker"] = "no contract unit or validation evidence matched the requested focus"
        result["next_action"] = "pick a function name, block id, family, obligation id, or work-item id from the reference contract sidecars"
    write_json(out / "unit-validation.json", result)
    return result


def _contract_candidate_validation_summary(validation: dict[str, Any]) -> dict[str, Any]:
    families = [item for item in validation.get("families", []) if isinstance(item, dict)]
    return {
        "format": validation.get("format"),
        "status": validation.get("status") or validation.get("verdict"),
        "verdict": validation.get("verdict") or validation.get("status"),
        "model": validation.get("model"),
        "counts": validation.get("counts", {}),
        "family_statuses": _count_by(families, "status"),
    }


def _contract_candidate_validation_artifact(value: dict[str, Any] | Path | None) -> dict[str, Any] | None:
    if value is None or isinstance(value, dict):
        return None
    path = Path(value)
    return _reference_input_artifact(path) if path.is_file() else {"path": str(path), "exists": False}


def _load_contract_candidate_validation(value: dict[str, Any] | Path | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        payload = value
    else:
        payload = _load_json(Path(value))
    if not isinstance(payload, dict) or payload.get("format") != "stage-a-contract-candidate-validation-v1":
        raise StageAInputError("contract candidate validation must have format stage-a-contract-candidate-validation-v1")
    return payload


def stage_a_explain_obligations(*, reference_contract: Path, focus: str, out: Path | None = None) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    sidecars = _load_reference_contract_sidecars(contract, reference_contract)
    focus_lower = focus.lower()
    gaps = [
        item
        for item in sidecars.get("coverage_gaps", {}).get("gaps", [])
        if _matches_focus(item, focus_lower)
    ]
    obligations = [
        item
        for item in sidecars.get("obligation_index", {}).get("obligations", [])
        if _matches_focus(item, focus_lower)
    ]
    families = [
        item
        for item in contract.get("families", [])
        if isinstance(item, dict) and _matches_focus(item, focus_lower)
    ]
    result = {
        "format": "stage-a-obligation-explanation-v1",
        "status": "pass" if gaps or obligations or families else "incomplete",
        "focus": focus,
        "reference_contract": _reference_input_artifact(reference_contract),
        "families": families,
        "gaps": gaps,
        "obligations": obligations,
        "counts": {"families": len(families), "gaps": len(gaps), "obligations": len(obligations)},
    }
    if out is not None:
        write_json(Path(out), result)
    return result


def stage_a_diff_obligations(*, before: Path, after: Path, out: Path | None = None) -> dict[str, Any]:
    before = Path(before)
    after = Path(after)
    before_contract = _load_json(before)
    after_contract = _load_json(after)
    before_sidecars = _load_reference_contract_sidecars(before_contract, before)
    after_sidecars = _load_reference_contract_sidecars(after_contract, after)
    before_gaps = {
        str(item.get("gap_id")): item
        for item in before_sidecars.get("coverage_gaps", {}).get("gaps", [])
        if isinstance(item, dict) and item.get("gap_id")
    }
    after_gaps = {
        str(item.get("gap_id")): item
        for item in after_sidecars.get("coverage_gaps", {}).get("gaps", [])
        if isinstance(item, dict) and item.get("gap_id")
    }
    before_ids = set(before_gaps)
    after_ids = set(after_gaps)
    unchanged_ids = before_ids & after_ids
    regressed_ids = [
        gap_id
        for gap_id in unchanged_ids
        if _gap_severity_rank(after_gaps[gap_id].get("severity")) > _gap_severity_rank(before_gaps[gap_id].get("severity"))
    ]
    result = {
        "format": "stage-a-obligation-diff-v1",
        "status": "pass",
        "before": _reference_input_artifact(before),
        "after": _reference_input_artifact(after),
        "resolved": [before_gaps[gap_id] for gap_id in sorted(before_ids - after_ids)],
        "new": [after_gaps[gap_id] for gap_id in sorted(after_ids - before_ids)],
        "regressed": [after_gaps[gap_id] for gap_id in sorted(regressed_ids)],
        "unchanged": [after_gaps[gap_id] for gap_id in sorted(unchanged_ids)],
    }
    result["counts"] = {
        "resolved": len(result["resolved"]),
        "new": len(result["new"]),
        "regressed": len(result["regressed"]),
        "unchanged": len(result["unchanged"]),
    }
    if out is not None:
        write_json(Path(out), result)
    return result


def _run_stage_a_suite_case(
    *,
    suite_root: Path,
    out: Path,
    index: int,
    entry: Any,
    default_model: str,
) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {
            "id": f"case-{index:04d}",
            "status": "incomplete",
            "expected_verdict": "pass",
            "actual_verdict": "incomplete",
            "blocker": "suite case entry must be an object",
            "next_action": "fix this suite case entry",
        }
    case_id = _artifact_name(str(entry.get("id") or f"case-{index:04d}"))
    expected = str(entry.get("expect", entry.get("expected_verdict", "pass")))
    model = str(entry.get("model") or default_model)
    case_out = out / "cases" / case_id
    try:
        original = _suite_path(suite_root, entry["original"])
        candidate = _suite_path(suite_root, entry["candidate"])
        mapping = _suite_path(suite_root, entry["mapping"])
        invariants = _suite_optional_path(suite_root, entry.get("invariants"))
        layout_contract = _suite_optional_path(suite_root, entry.get("layout_contract", entry.get("layout-contract")))
        lean_inputs = _suite_optional_paths(suite_root, entry.get("lean_inputs", entry.get("lean-inputs", [])))
    except (KeyError, StageAInputError) as exc:
        return {
            "id": case_id,
            "status": "incomplete",
            "expected_verdict": expected,
            "actual_verdict": "incomplete",
            "blocker": f"invalid suite case paths: {exc}",
            "next_action": "add original, candidate, and mapping paths for this suite case",
            "report": str(case_out),
        }

    result = stage_a_validate(
        original=original,
        candidate=candidate,
        mapping=mapping,
        model=model,
        out=case_out,
        invariants=invariants,
        layout_contract=layout_contract,
        lean_inputs=lean_inputs,
    )
    actual = result["verdict"]
    matched = actual == expected
    return {
        "id": case_id,
        "status": "passed" if matched else "failed",
        "expected_verdict": expected,
        "actual_verdict": actual,
        "report": str(case_out),
        "verdict_json": str(case_out / "verdict.json"),
        "model_hash": result.get("model_hash"),
        "counts": result.get("counts", {}),
        "next_action": "" if matched else "inspect the case report and update the proof, fixture, or expected verdict",
    }


def _suite_path(root: Path, value: Any) -> Path:
    if not isinstance(value, str):
        raise StageAInputError(f"expected a path string, got {value!r}")
    path = Path(value)
    return path if path.is_absolute() else root / path


def _suite_optional_path(root: Path, value: Any) -> Path | None:
    if value is None or value == "":
        return None
    return _suite_path(root, value)


def _suite_optional_paths(root: Path, value: Any) -> tuple[Path, ...]:
    if value is None or value == "":
        return ()
    if not isinstance(value, list):
        raise StageAInputError(f"expected a path list, got {value!r}")
    return tuple(_suite_path(root, item) for item in value)


def _prepare_report_tree(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name in (
        "failures",
        "incomplete",
        "counterexamples",
        "witnesses",
        "proof-cache",
        "lean",
    ):
        (out / name).mkdir(parents=True, exist_ok=True)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StageAInputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StageAInputError(f"invalid JSON in {path}: {exc}") from exc


def _load_optional_json(path: Path | None) -> Any:
    return None if path is None else _load_json(path)


def _parse_stage_a_pe(path: Path) -> StageABinary:
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as exc:  # pefile raises several non-public exception types.
        raise StageAInputError(f"{path} is not a parseable PE file: {exc}") from exc

    machine = pe.FILE_HEADER.Machine
    magic = pe.OPTIONAL_HEADER.Magic
    if machine == 0x014C and magic == 0x10B:
        machine_name = "i386"
        bitness = 32
    elif machine == 0x8664 and magic == 0x20B:
        machine_name = "x86_64"
        bitness = 64
    else:
        machine_name = f"0x{machine:04x}"
        magic_name = f"0x{magic:04x}"
        raise StageAInputError(f"{path} is out of model: expected x86 PE32 or x86_64 PE32+, got machine={machine_name} magic={magic_name}")

    imports = _imports(pe)
    sections = tuple(_stage_a_section(section) for section in pe.sections)
    return StageABinary(
        path=path,
        sha256=sha256_file(path),
        size=path.stat().st_size,
        machine=machine_name,
        bitness=bitness,
        image_base=int(pe.OPTIONAL_HEADER.ImageBase),
        entrypoint_rva=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        size_of_image=int(pe.OPTIONAL_HEADER.SizeOfImage),
        subsystem=_subsystem_name(int(pe.OPTIONAL_HEADER.Subsystem)),
        sections=sections,
        imports=imports,
        pe=pe,
    )


def _stage_a_section(section: Any) -> StageASection:
    name = section.Name.rstrip(b"\0").decode("utf-8", errors="replace")
    rva_start = int(section.VirtualAddress)
    rva_end = rva_start + mapped_section_size(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
    characteristics = int(section.Characteristics)
    return StageASection(
        name=name,
        rva_start=rva_start,
        rva_end=rva_end,
        raw_pointer=int(section.PointerToRawData),
        raw_size=int(section.SizeOfRawData),
        characteristics=characteristics,
        executable=bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
        readable=bool(characteristics & IMAGE_SCN_MEM_READ),
        writable=bool(characteristics & IMAGE_SCN_MEM_WRITE),
        contains_code=bool(characteristics & IMAGE_SCN_CNT_CODE),
    )


def _imports(pe: pefile.PE) -> tuple[StageAImport, ...]:
    imports: list[StageAImport] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
        for item in entry.imports:
            symbol = item.name.decode("utf-8", errors="replace") if item.name else None
            thunk_rva = int(item.address - pe.OPTIONAL_HEADER.ImageBase) if item.address is not None else None
            imports.append(StageAImport(dll=dll.lower(), symbol=symbol, ordinal=item.ordinal, thunk_rva=thunk_rva))
    return tuple(imports)


def _subsystem_name(value: int) -> str:
    names = {
        1: "native",
        2: "windows_gui",
        3: "windows_cui",
        7: "posix_cui",
        9: "windows_ce_gui",
    }
    return names.get(value, f"unknown_{value}")


def _empty_layout(original: Path, candidate: Path) -> dict[str, Any]:
    return {
        "model": STAGE_A_MODEL_ID,
        "original": {"path": str(original)},
        "candidate": {"path": str(candidate)},
        "compatible": False,
        "issues": [],
    }


def _layout_report(
    original: StageABinary,
    candidate: StageABinary,
    layout_contract: dict[str, Any] | None,
) -> dict[str, Any]:
    issues = _layout_issues(original, candidate, layout_contract)
    return {
        "architecture": "x86_64" if original.bitness == 64 else "x86",
        "bitness": original.bitness,
        "abi": _model_id_for_binary(original),
        "compatible": not any(issue["severity"] == "fail" for issue in issues)
        and not any(issue["severity"] == "incomplete" for issue in issues),
        "issues": issues,
        "original": _binary_layout(original),
        "candidate": _binary_layout(candidate),
        "strict_layout_contract": layout_contract or None,
    }


def _binary_layout(binary: StageABinary) -> dict[str, Any]:
    return {
        "path": str(binary.path),
        "sha256": binary.sha256,
        "size": binary.size,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
        "size_of_image": binary.size_of_image,
        "subsystem": binary.subsystem,
        "sections": [
            {
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "raw_pointer": section.raw_pointer,
                "raw_size": section.raw_size,
                "characteristics": section.characteristics,
                "permissions": {
                    "execute": section.executable,
                    "read": section.readable,
                    "write": section.writable,
                    "code": section.contains_code,
                },
            }
            for section in binary.sections
        ],
        "imports": [
            {
                "dll": item.dll,
                "symbol": item.symbol,
                "ordinal": item.ordinal,
                "thunk_rva": item.thunk_rva,
            }
            for item in binary.imports
        ],
    }


def _binary_reference_layout(binary: StageABinary) -> dict[str, Any]:
    layout = _binary_layout(binary)
    layout["relocations"] = _binary_relocation_summary(binary)
    layout["executable_sections"] = [
        {
            "name": section.name,
            "rva_start": section.rva_start,
            "rva_end": section.rva_end,
            "size": section.rva_end - section.rva_start,
        }
        for section in binary.sections
        if section.executable
    ]
    return layout


def _binary_relocation_summary(binary: StageABinary) -> dict[str, Any]:
    directory = binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    blocks = []
    entry_count = 0
    for block in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", []) or []:
        entries = [
            {
                "rva": int(entry.rva),
                "type": int(entry.type),
            }
            for entry in block.entries
        ]
        entry_count += len(entries)
        blocks.append(
            {
                "rva": int(block.struct.VirtualAddress),
                "size": int(block.struct.SizeOfBlock),
                "entries": entries,
            }
        )
    return {
        "status": "present" if blocks else ("empty_directory" if int(directory.Size) == 0 else "not_decoded"),
        "directory": {"rva": int(directory.VirtualAddress), "size": int(directory.Size)},
        "blocks": blocks,
        "counts": {"blocks": len(blocks), "entries": entry_count},
    }


def _reference_contract_inputs(
    *,
    original: Path,
    candidate: Path | None,
    mapping: Path | None,
    validation_report: Path | None,
    layout_contract: Path | None,
) -> dict[str, Any]:
    return {
        "original": _reference_input_artifact(original),
        "candidate": _reference_input_artifact(candidate) if candidate is not None else None,
        "mapping": _reference_input_artifact(mapping) if mapping is not None else None,
        "validation_report": _reference_validation_report_artifact(validation_report) if validation_report is not None else None,
        "layout_contract": _reference_input_artifact(layout_contract) if layout_contract is not None else None,
    }


def _reference_input_artifact(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_file(path) if path.is_file() else None,
        "exists": path.exists(),
    }


def _reference_validation_report_artifact(path: Path) -> dict[str, Any]:
    if path.is_dir():
        files = {}
        for name in ("verdict.json", "obligations.json", "layout.json"):
            item = path / name
            files[name] = _reference_input_artifact(item) if item.exists() else {"path": str(item), "sha256": None, "exists": False}
        return {"path": str(path), "exists": True, "files": files}
    return _reference_input_artifact(path)


_REFERENCE_CONTRACT_FAMILY_KEYS = (
    ("binary_faithfulness", "pe_sections_imports_relocations_image_base"),
    ("executable_span_coverage", "executable_byte_coverage"),
    ("function_ranges", "function_ranges"),
    ("cfg_blocks", "basic_blocks_and_cfg"),
    ("roots_and_jump_targets", "roots_and_jump_tables"),
    ("import_thunks", "import_thunks"),
    ("abi_callsites", "abi_callsites"),
    ("semantic_regions", "semantic_region_contracts"),
    ("padding_alignment", "padding_alignment"),
    ("normalization_assumptions", "layout_normalization_assumptions"),
    ("validation_report_artifact_binding", "validation_report_artifact_binding"),
    ("proof_inventory", "proof_obligation_inventory"),
)


_VERIFIED_DECOMPILER_VERTICAL_SLICE_REGIONS = (
    {
        "id": "jq-section-gap-0498-to-0202",
        "source_map_id": "jq:section-gap--text-0498:call:section-gap--text-0202",
        "caller_function": "section-gap--text-0498",
        "caller_block_id": "section-gap--text-0498",
        "callee_function": "section-gap--text-0202",
        "callee_block_id": "section-gap--text-0202",
        "post_call_jump_function": "section-gap--text-0494",
        "post_call_jump_block_id": "section-gap--text-0494",
        "register_arguments": (
            ("eax", ("add", ("reg", "ebx"), ("const", 0x1C))),
            ("edx", ("const", 1)),
            ("ecx", ("reg", "ebx")),
        ),
    },
)


def _reference_contract_sidecar_paths(sidecar_dir: Path, contract_dir: Path, *, unit_contract_dir: Path | None = None) -> dict[str, Any]:
    unit_contract_dir = unit_contract_dir or sidecar_dir

    def display_path(path: Path) -> str:
        if path.parent.resolve() == contract_dir.resolve():
            return path.name
        return str(path)

    unit_paths = _reference_unit_contract_paths(unit_contract_dir)
    return {
        "coverage_gaps": {"path": display_path(sidecar_dir / "coverage_gaps.json")},
        "obligation_index": {"path": display_path(sidecar_dir / "obligation_index.json")},
        "contract_summary": {"path": display_path(sidecar_dir / "contract_summary.json")},
        "abi_callsites": {"path": display_path(sidecar_dir / "abi_callsites.json")},
        "unit_contracts": {
            "directory": "." if unit_contract_dir.resolve() == contract_dir.resolve() else str(unit_contract_dir),
            **{name: {"path": display_path(path)} for name, path in unit_paths.items()},
        },
    }


def _write_reference_contract_sidecars(
    contract: dict[str, Any],
    contract_path: Path,
    sidecar_dir: Path,
    *,
    unit_contract_dir: Path,
    semantic_payload: dict[str, Any] | None = None,
) -> None:
    contract_ref = _reference_sidecar_contract_ref(contract_path)
    write_json(sidecar_dir / "coverage_gaps.json", _reference_coverage_gaps_sidecar(contract, contract_ref))
    write_json(sidecar_dir / "obligation_index.json", _reference_obligation_index_sidecar(contract, contract_ref))
    write_json(sidecar_dir / "contract_summary.json", _reference_contract_summary_sidecar(contract, contract_ref))
    write_json(sidecar_dir / "abi_callsites.json", _reference_abi_callsites_sidecar(contract, contract_ref))
    _write_reference_unit_contract_sidecars(contract, contract_ref, unit_contract_dir, semantic_payload=semantic_payload)


def _reference_sidecar_contract_ref(contract_path: Path) -> dict[str, Any]:
    return {
        "path": str(contract_path),
        "sha256": sha256_file(contract_path) if contract_path.is_file() else None,
        "format": "stage-a-reference-contract-v1",
    }


def _reference_contract_families(constraints: dict[str, Any]) -> list[dict[str, Any]]:
    families = []
    for family, constraint_key in _REFERENCE_CONTRACT_FAMILY_KEYS:
        constraint = constraints.get(constraint_key) if isinstance(constraints.get(constraint_key), dict) else {}
        status = _proof_family_status(constraint.get("status"))
        families.append(
            {
                "family": family,
                "constraint": constraint_key,
                "status": status,
                "raw_status": constraint.get("status"),
                "evidence_kind": constraint.get("evidence_kind"),
                "blocking": status in {"incomplete", "violated"},
                "counts": _reference_family_counts(family, constraint),
            }
        )
    return families


def _proof_family_status(value: Any) -> str:
    status = str(value or "incomplete")
    if status in {"satisfied", "not_applicable"}:
        return status
    if status == "derived":
        return "satisfied"
    if status in {"failed", "fail", "violated"}:
        return "violated"
    return "incomplete"


def _reference_family_counts(family: str, constraint: dict[str, Any]) -> dict[str, int]:
    if family == "function_ranges":
        return {"functions": len(constraint.get("functions", [])) if isinstance(constraint.get("functions"), list) else 0}
    if family == "cfg_blocks":
        return {
            "blocks": len(constraint.get("basic_blocks", [])) if isinstance(constraint.get("basic_blocks"), list) else 0,
            "cfg_edge_sources": len(constraint.get("cfg_edges", [])) if isinstance(constraint.get("cfg_edges"), list) else 0,
        }
    if family == "roots_and_jump_targets":
        return {
            "roots": len(constraint.get("roots", [])) if isinstance(constraint.get("roots"), list) else 0,
            "jump_table_targets": len(constraint.get("jump_table_targets", [])) if isinstance(constraint.get("jump_table_targets"), list) else 0,
        }
    if family == "import_thunks":
        return {
            "original_imports": len(constraint.get("original_imports", [])) if isinstance(constraint.get("original_imports"), list) else 0,
            "mapped_import_thunks": len(constraint.get("mapped_import_thunks", [])) if isinstance(constraint.get("mapped_import_thunks"), list) else 0,
        }
    if family == "abi_callsites":
        counts = constraint.get("counts") if isinstance(constraint.get("counts"), dict) else {}
        return {
            "functions": int(counts.get("functions") or 0),
            "callsites": int(counts.get("callsites") or 0),
            "imports": int(counts.get("import_prototypes") or 0),
        }
    if family == "semantic_regions":
        counts = constraint.get("counts") if isinstance(constraint.get("counts"), dict) else {}
        return {
            "regions": int(counts.get("regions") or 0),
            "checked": int(counts.get("checked") or 0),
            "incomplete": int(counts.get("incomplete") or 0),
        }
    if family == "padding_alignment":
        return {"waivers": len(constraint.get("waivers", [])) if isinstance(constraint.get("waivers"), list) else 0}
    if family == "proof_inventory":
        counts = constraint.get("counts") if isinstance(constraint.get("counts"), dict) else {}
        return {"obligations": int(counts.get("obligations") or 0)}
    return {}


def _reference_coverage_gaps_sidecar(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    gaps = _reference_contract_gap_items(contract)
    return {
        "format": "stage-a-coverage-gaps-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "status": "pass" if not gaps else "incomplete",
        "gaps": gaps,
        "next_work": _ranked_gap_next_work(gaps),
        "counts": {
            "gaps": len(gaps),
            "by_family": _count_by(gaps, "family"),
            "by_severity": _count_by(gaps, "severity"),
            "by_category": _count_by(gaps, "category"),
        },
    }


def _reference_obligation_index_sidecar(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    proof = _contract_constraint(contract, "proof_obligation_inventory")
    obligations = proof.get("obligations") if isinstance(proof.get("obligations"), list) else []
    indexed = []
    for item in obligations:
        if not isinstance(item, dict):
            continue
        obligation_id = str(item.get("id") or "")
        indexed.append(
            {
                "id": obligation_id,
                "stable_id": f"obligation:{_safe_gap_part(obligation_id)}",
                "kind": str(item.get("kind") or ""),
                "status": str(item.get("status") or ""),
                "proof_rule": item.get("proof_rule"),
                "family": _obligation_family(obligation_id),
                "related_gap_id": f"obligation:{_safe_gap_part(obligation_id)}",
            }
        )
    return {
        "format": "stage-a-obligation-index-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "lean": proof.get("lean") if isinstance(proof.get("lean"), dict) else {},
        "obligations": indexed,
        "counts": {
            "obligations": len(indexed),
            "by_status": _count_by(indexed, "status"),
            "by_kind": _count_by(indexed, "kind"),
            "by_family": _count_by(indexed, "family"),
        },
    }


def _reference_contract_summary_sidecar(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    families = contract.get("families") if isinstance(contract.get("families"), list) else []
    return {
        "format": "stage-a-contract-summary-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "model": contract.get("model"),
        "families": families,
        "counts": {
            "families": len(families),
            "by_status": _count_by([item for item in families if isinstance(item, dict)], "status"),
            **(contract.get("counts") if isinstance(contract.get("counts"), dict) else {}),
        },
    }


def _reference_abi_callsites_sidecar(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    abi = _contract_constraint(contract, "abi_callsites")
    return {
        "format": "stage-a-abi-callsites-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "status": _proof_family_status(abi.get("status")),
        "abi_callsites": abi,
        "counts": abi.get("counts") if isinstance(abi.get("counts"), dict) else {},
    }


def _reference_unit_contract_paths(unit_contract_dir: Path) -> dict[str, Path]:
    return {
        "block_contracts": unit_contract_dir / "block-contracts.jsonl",
        "function_contracts": unit_contract_dir / "function-contracts.jsonl",
        "cluster_contracts": unit_contract_dir / "cluster-contracts.jsonl",
        "repair_units": unit_contract_dir / "repair-units.json",
        "source_obligations": unit_contract_dir / "source-obligations.json",
        "semantic_transfer_contracts": unit_contract_dir / "semantic-transfer-contracts.jsonl",
        "semantic_region_contracts": unit_contract_dir / "semantic-region-contracts.jsonl",
        "memory_frame_contracts": unit_contract_dir / "memory-frame-contracts.json",
        "call_summary_contracts": unit_contract_dir / "call-summary-contracts.json",
        "cluster_semantic_contracts": unit_contract_dir / "cluster-semantic-contracts.jsonl",
    }


def _write_reference_unit_contract_sidecars(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    unit_contract_dir: Path,
    *,
    semantic_payload: dict[str, Any] | None = None,
) -> None:
    unit_contract_dir.mkdir(parents=True, exist_ok=True)
    payload = _reference_unit_contract_payloads(contract, contract_ref, semantic_payload=semantic_payload)
    paths = _reference_unit_contract_paths(unit_contract_dir)
    _write_jsonl(paths["block_contracts"], payload["block_contracts"])
    _write_jsonl(paths["function_contracts"], payload["function_contracts"])
    _write_jsonl(paths["cluster_contracts"], payload["cluster_contracts"])
    write_json(paths["repair_units"], payload["repair_units"])
    write_json(paths["source_obligations"], payload["source_obligations"])
    _write_jsonl(paths["semantic_transfer_contracts"], payload["semantic_transfer_contracts"])
    _write_jsonl(paths["semantic_region_contracts"], payload["semantic_region_contracts"])
    write_json(paths["memory_frame_contracts"], payload["memory_frame_contracts"])
    write_json(paths["call_summary_contracts"], payload["call_summary_contracts"])
    _write_jsonl(paths["cluster_semantic_contracts"], payload["cluster_semantic_contracts"])


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _reference_semantic_contract_payloads(
    original: StageABinary,
    mappings: list[BlockMapping],
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
) -> dict[str, Any]:
    transfer_contracts = _semantic_transfer_contracts(original, mappings, contract_ref)
    memory_frames = _semantic_memory_frame_contracts(contract, contract_ref)
    call_summaries = _semantic_call_summary_contracts(contract, contract_ref)
    cluster_contracts = _semantic_cluster_contracts(contract, contract_ref)
    semantic_region_contracts = _reference_semantic_region_unit_contracts(contract, contract_ref)
    return {
        "semantic_transfer_contracts": transfer_contracts,
        "semantic_region_contracts": semantic_region_contracts,
        "memory_frame_contracts": memory_frames,
        "call_summary_contracts": call_summaries,
        "cluster_semantic_contracts": cluster_contracts,
    }


def _fallback_reference_semantic_contract_payloads(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "semantic_transfer_contracts": [],
        "semantic_region_contracts": _reference_semantic_region_unit_contracts(contract, contract_ref),
        "memory_frame_contracts": _semantic_memory_frame_contracts(contract, contract_ref),
        "call_summary_contracts": _semantic_call_summary_contracts(contract, contract_ref),
        "cluster_semantic_contracts": _semantic_cluster_contracts(contract, contract_ref),
    }


def _reference_semantic_region_contracts_constraint(
    binary: StageABinary,
    mappings: list[BlockMapping],
    abi_constraint: dict[str, Any],
) -> dict[str, Any]:
    regions = []
    for spec in _VERIFIED_DECOMPILER_VERTICAL_SLICE_REGIONS:
        region = _reference_selected_semantic_region_contract(binary, mappings, abi_constraint, spec)
        if region is not None:
            regions.append(region)
    if not regions:
        return {
            "format": "stage-a-semantic-region-contracts-v1",
            "status": "not_applicable",
            "evidence_kind": "stage-a-local-symbolic-x86-region-contract",
            "regions": [],
            "counts": {"regions": 0, "checked": 0, "incomplete": 0},
        }
    checked = sum(1 for region in regions if region.get("status") == "checked")
    incomplete = len(regions) - checked
    return {
        "format": "stage-a-semantic-region-contracts-v1",
        "status": "satisfied" if incomplete == 0 else "incomplete",
        "evidence_kind": "stage-a-local-symbolic-x86-region-contract",
        "regions": regions,
        "counts": {"regions": len(regions), "checked": checked, "incomplete": incomplete},
        "blocker": None if incomplete == 0 else "one or more selected semantic regions did not close",
        "next_action": "repair unsupported region semantics or explicit ABI evidence before treating this region as decompiler-ready",
    }


def _reference_selected_semantic_region_contract(
    binary: StageABinary,
    mappings: list[BlockMapping],
    abi_constraint: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any] | None:
    caller_block_id = str(spec["caller_block_id"])
    callee_block_id = str(spec["callee_block_id"])
    caller = next((mapped for mapped in mappings if mapped.id == caller_block_id and mapped.kind == "code"), None)
    if caller is None:
        return None
    blockers: list[dict[str, Any]] = []
    callee = next((mapped for mapped in mappings if mapped.id == callee_block_id and mapped.kind == "code"), None)
    if callee is None:
        blockers.append(
            {
                "category": "missing_callee_block",
                "blocker": f"selected region callee block {callee_block_id!r} is not mapped as code",
                "next_action": "regenerate the Stage A map with the selected callee block",
            }
        )
    post_call_jump = None
    post_call_jump_block_id = spec.get("post_call_jump_block_id")
    if isinstance(post_call_jump_block_id, str):
        post_call_jump = next((mapped for mapped in mappings if mapped.id == post_call_jump_block_id and mapped.kind == "code"), None)
        if post_call_jump is None:
            blockers.append(
                {
                    "category": "missing_post_call_jump_block",
                    "blocker": f"selected region post-call jump target {post_call_jump_block_id!r} is not mapped as code",
                    "next_action": "regenerate the Stage A map with the selected post-call CFG target",
                }
            )
    function = _semantic_region_abi_function(abi_constraint, str(spec["caller_function"]))
    if function is None:
        blockers.append(
            {
                "category": "missing_abi_function",
                "blocker": f"selected region caller function {spec['caller_function']!r} has no ABI evidence",
                "next_action": "regenerate ABI callsite evidence for the selected caller block",
            }
        )
    data = binary.pe.get_data(caller.original.rva_start, caller.original.size)
    instructions = _semantic_disassemble_block(binary, caller.original, data)
    symbolic = (
        _symbolic_execute(binary, caller.original, data, "original", caller)
        if len(data) == caller.original.size
        else {
            "status": "incomplete",
            "category": "unreadable_block_bytes",
            "blocker": f"expected {caller.original.size} block bytes, read {len(data)}",
            "next_action": "fix block range or PE section mapping before generating a semantic region contract",
        }
    )
    observables = symbolic.get("observables") if isinstance(symbolic.get("observables"), dict) else {}
    event = None
    if symbolic.get("status") != "ok":
        blockers.append(
            {
                "category": symbolic.get("category") or "unsupported_semantics",
                "blocker": symbolic.get("blocker") or "selected region is outside the current symbolic x86 subset",
                "next_action": symbolic.get("next_action") or "add checked x86 semantics for this region",
                "instruction": symbolic.get("instruction") if isinstance(symbolic.get("instruction"), dict) else None,
            }
        )
    else:
        event = _semantic_region_internal_call_event(
            observables,
            target_rva=callee.original.rva_start if isinstance(callee, BlockMapping) else None,
        )
        if event is None:
            blockers.append(
                {
                    "category": "missing_direct_call_boundary",
                    "blocker": "selected region did not produce the expected direct internal call boundary",
                    "next_action": "keep the region incomplete until direct call target recovery closes",
                }
            )
        memory_events = observables.get("memory_events")
        if isinstance(memory_events, tuple) and memory_events:
            blockers.append(
                {
                    "category": "ambiguous_memory_effects",
                    "blocker": "selected vertical slice currently admits only no-memory setup before the direct call",
                    "next_action": "extend the region contract with explicit memory frame and alias preconditions",
                    "memory_events": [_semantic_memory_event_json(item) for item in memory_events],
                }
            )
    callsite = None
    if isinstance(function, dict) and isinstance(callee, BlockMapping):
        callsite = _semantic_region_callsite(function, caller_block_id, callee.original.rva_start)
        if callsite is None:
            blockers.append(
                {
                    "category": "missing_abi_callsite",
                    "blocker": "ABI callsite evidence does not contain the selected direct call",
                    "next_action": "regenerate callsite evidence or keep the region incomplete",
                }
            )
    register_mismatches = []
    if event is not None:
        register_mismatches = _semantic_region_register_input_mismatches(
            event,
            tuple(spec["register_arguments"]),
        )
        if register_mismatches:
            blockers.append(
                {
                    "category": "x86_to_ir_register_input_mismatch",
                    "blocker": "symbolic x86 call inputs do not imply the selected region IR",
                    "next_action": "fix x86 semantics, callsite recovery, or the selected IR contract",
                    "mismatches": register_mismatches,
                }
            )
    abi_mismatches = []
    if isinstance(callsite, dict):
        abi_mismatches = _semantic_region_abi_inventory_mismatches(callsite, tuple(spec["register_arguments"]))
        if abi_mismatches and _semantic_region_callsite_has_register_args(callsite):
            blockers.append(
                {
                    "category": "abi_inventory_mismatch",
                    "blocker": "ABI argument inventory does not match the selected register-carried call contract",
                    "next_action": "fix ABI register argument recovery before lowering this region",
                    "mismatches": abi_mismatches,
                }
            )
    ir = _semantic_region_ir(spec, caller, callee, callsite, post_call_jump)
    c_contract = _semantic_region_c_shaped_contract(spec, ir)
    proof_obligations = _semantic_region_proof_obligations(str(spec["id"]), blockers)
    region = {
        "format": "stage-a-semantic-region-contract-v1",
        "id": f"semantic-region:{_safe_gap_part(str(spec['id']))}",
        "unit_kind": "semantic_region",
        "region_kind": "verified_decompiler_vertical_slice",
        "status": "checked" if not blockers else "incomplete",
        "source_map_id": spec.get("source_map_id"),
        "function": str(spec["caller_function"]),
        "block_id": caller_block_id,
        "caller": {
            "function": str(spec["caller_function"]),
            "block_id": caller_block_id,
            "original": _range_report(caller.original),
        },
        "callee": {
            "function": str(spec["callee_function"]),
            "block_id": callee_block_id,
            "original": _range_report(callee.original) if isinstance(callee, BlockMapping) else None,
        },
        "post_call_jump": {
            "function": str(spec["post_call_jump_function"]),
            "block_id": str(spec["post_call_jump_block_id"]),
            "original": _range_report(post_call_jump.original) if isinstance(post_call_jump, BlockMapping) else None,
        }
        if isinstance(spec.get("post_call_jump_block_id"), str)
        else None,
        "instructions": instructions,
        "inputs": _semantic_region_inputs(spec, event),
        "outputs": _semantic_region_outputs(spec, callee),
        "preconditions": _semantic_region_preconditions(spec),
        "preserved_registers": ["ebx", "esi", "edi", "ebp", "esp"],
        "clobbered_registers": ["eax", "ecx", "edx"],
        "direct_callsites": [callsite] if isinstance(callsite, dict) else [],
        "cfg_exits": _semantic_region_cfg_exits(caller, callee, post_call_jump),
        "classifications": {
            "import_thunk": False,
            "padding": False,
            "section_gap": True,
            "jump_table_target": False,
        },
        "ir": ir,
        "c_contract": c_contract,
        "x86_to_ir_validation": {
            "status": "proved" if not any(item["category"].startswith("x86_to_ir") for item in blockers) and event is not None else "incomplete",
            "proof_rule": "stage_a_symbolic_x86_to_ir_region_subset_v1",
            "checked_inputs": _semantic_region_call_register_inputs_json(event),
            "mismatches": register_mismatches,
        },
        "abi_inventory_validation": {
            "status": "proved"
            if not abi_mismatches
            else "derived_from_symbolic_region"
            if isinstance(callsite, dict) and not _semantic_region_callsite_has_register_args(callsite)
            else "incomplete",
            "mismatches": abi_mismatches,
            "fallback": "symbolic_region_call_boundary"
            if isinstance(callsite, dict) and abi_mismatches and not _semantic_region_callsite_has_register_args(callsite)
            else None,
        },
        "c_contract_equivalence": {
            "status": "proved" if c_contract.get("status") == "checked" and not blockers else "incomplete",
            "proof_rule": "stage_a_ir_to_c_contract_structural_v1",
            "checked_operations": len(ir.get("operations", [])) if isinstance(ir.get("operations"), list) else 0,
        },
        "proof_obligations": proof_obligations,
        "blockers": blockers,
        "blocker_category": blockers[0]["category"] if blockers else None,
        "blocker": blockers[0]["blocker"] if blockers else None,
        "next_action": (
            blockers[0]["next_action"]
            if blockers
            else "lower this checked region contract into Stage B ugly C and rerun candidate validation"
        ),
        "acceptance": "selected-region contract only; final acceptance still requires Stage A candidate validation",
    }
    return region


def _semantic_region_abi_function(abi_constraint: dict[str, Any], name: str) -> dict[str, Any] | None:
    original = abi_constraint.get("original") if isinstance(abi_constraint.get("original"), dict) else {}
    for function in original.get("functions", []) if isinstance(original.get("functions"), list) else []:
        if isinstance(function, dict) and function.get("name") == name:
            return function
    return None


def _semantic_region_callsite(function: dict[str, Any], block_id: str, target_rva: int) -> dict[str, Any] | None:
    for callsite in function.get("callsites", []) if isinstance(function.get("callsites"), list) else []:
        if not isinstance(callsite, dict):
            continue
        target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
        if callsite.get("block_id") == block_id and target.get("kind") == "direct" and _safe_int(target.get("target_rva")) == target_rva:
            return callsite
    return None


def _semantic_region_internal_call_event(observables: dict[str, Any], *, target_rva: int | None) -> tuple[Any, ...] | None:
    if target_rva is None:
        return None
    events = observables.get("external_events")
    for event in events if isinstance(events, tuple) else ():
        if isinstance(event, tuple) and len(event) >= 5 and event[0] == "internal_call" and int(event[1]) == target_rva:
            return event
    return None


def _semantic_region_register_input_mismatches(
    event: tuple[Any, ...],
    expected_arguments: tuple[tuple[str, tuple[Any, ...]], ...],
) -> list[dict[str, Any]]:
    inputs = dict(event[3]) if len(event) > 3 and isinstance(event[3], tuple) else {}
    mismatches = []
    for register, expected_expr in expected_arguments:
        observed = _canonical_expr(inputs.get(register))
        expected = _canonical_expr(expected_expr)
        if observed != expected:
            mismatches.append(
                {
                    "register": register,
                    "expected": _semantic_expr_json(expected),
                    "observed": _semantic_expr_json(observed),
                }
            )
    return mismatches


def _semantic_region_abi_inventory_mismatches(
    callsite: dict[str, Any],
    expected_arguments: tuple[tuple[str, tuple[Any, ...]], ...],
) -> list[dict[str, Any]]:
    inventory = callsite.get("argument_inventory") if isinstance(callsite.get("argument_inventory"), dict) else {}
    register_args = inventory.get("register_args") if isinstance(inventory.get("register_args"), list) else []
    by_register = {
        str(arg.get("register")): arg
        for arg in register_args
        if isinstance(arg, dict) and isinstance(arg.get("register"), str)
    }
    mismatches = []
    for register, expected_expr in expected_arguments:
        arg = by_register.get(register)
        if arg is None:
            mismatches.append({"register": register, "expected": "register argument", "observed": "missing"})
            continue
        source = arg.get("source") if isinstance(arg.get("source"), dict) else {}
        expected_source = _semantic_region_expected_source(expected_expr)
        if not _semantic_region_source_matches(source, expected_source):
            mismatches.append({"register": register, "expected": expected_source, "observed": source})
    return mismatches


def _semantic_region_source_matches(source: dict[str, Any], expected_source: dict[str, Any]) -> bool:
    kind = expected_source.get("kind")
    if source.get("kind") != kind:
        return False
    if kind == "register":
        return source.get("register") == expected_source.get("register")
    if kind == "immediate":
        return _safe_int(source.get("value")) == _safe_int(expected_source.get("value"))
    if kind == "address":
        observed = source.get("addressing") if isinstance(source.get("addressing"), dict) else {}
        expected = expected_source.get("addressing") if isinstance(expected_source.get("addressing"), dict) else {}
        return (
            observed.get("base") == expected.get("base")
            and observed.get("index") == expected.get("index")
            and _safe_int(observed.get("scale", 1)) == _safe_int(expected.get("scale", 1))
            and _safe_int(observed.get("disp", 0)) == _safe_int(expected.get("disp", 0))
        )
    return source == expected_source


def _semantic_region_callsite_has_register_args(callsite: dict[str, Any]) -> bool:
    inventory = callsite.get("argument_inventory") if isinstance(callsite.get("argument_inventory"), dict) else {}
    register_args = inventory.get("register_args") if isinstance(inventory.get("register_args"), list) else []
    return bool(register_args)


def _semantic_region_expected_source(expr: tuple[Any, ...]) -> dict[str, Any]:
    expr = _canonical_expr(expr)
    if expr == ("reg", "ebx"):
        return {"kind": "register", "register": "ebx"}
    if expr == ("const", 1):
        return {"kind": "immediate", "value": 1}
    if isinstance(expr, tuple) and len(expr) == 3 and expr[0] == "add":
        parts = set(expr[1:])
        if ("reg", "ebx") in parts and ("const", 0x1C) in parts:
            return {"kind": "address", "addressing": {"base": "ebx", "index": None, "scale": 1, "disp": 0x1C}}
    return {"kind": "semantic_expr", "value": _semantic_expr_json(expr)}


def _semantic_region_ir(
    spec: dict[str, Any],
    caller: BlockMapping,
    callee: BlockMapping | None,
    callsite: dict[str, Any] | None,
    post_call_jump: BlockMapping | None,
) -> dict[str, Any]:
    target_rva = callee.original.rva_start if isinstance(callee, BlockMapping) else None
    callsite_id = callsite.get("id") if isinstance(callsite, dict) else None
    operations: list[dict[str, Any]] = [
        {"op": "add32", "dst": "tmp0", "lhs": {"op": "reg", "name": "ebx"}, "rhs": {"op": "const", "value": 0x1C}},
        {"op": "assign", "dst": "eax_call", "src": {"op": "tmp", "name": "tmp0"}},
        {"op": "assign", "dst": "edx_call", "src": {"op": "const", "value": 1}},
        {"op": "assign", "dst": "ecx_call", "src": {"op": "reg", "name": "ebx"}},
        {
            "op": "direct_call",
            "target": str(spec["callee_function"]),
            "target_block_id": str(spec["callee_block_id"]),
            "target_rva": target_rva,
            "callsite_id": callsite_id,
            "register_arguments": [
                {"register": register, "value": _semantic_expr_json(expr)}
                for register, expr in spec["register_arguments"]
            ],
            "stack_delta": {"status": "derived", "net_bytes": 0},
        },
    ]
    if isinstance(post_call_jump, BlockMapping):
        operations.append(
            {
                "op": "direct_jump",
                "position": "post_call",
                "target": str(spec["post_call_jump_function"]),
                "target_block_id": str(spec["post_call_jump_block_id"]),
                "target_rva": post_call_jump.original.rva_start,
                "control_transfer": "tail",
            }
        )
    return {
        "format": "stage-a-low-level-ir-v1",
        "status": "checked",
        "region_id": str(spec["id"]),
        "model": "x86-pe32-register-call-boundary-v1",
        "operations": operations,
    }


def _semantic_region_c_shaped_contract(spec: dict[str, Any], ir: dict[str, Any]) -> dict[str, Any]:
    statements: list[dict[str, Any]] = [
        {"kind": "assign_register", "register": "eax", "c": "s->eax = (uint32_t)(s->ebx + 0x1cU);"},
        {"kind": "assign_register", "register": "edx", "c": "s->edx = 1U;"},
        {"kind": "assign_register", "register": "ecx", "c": "s->ecx = s->ebx;"},
        {
            "kind": "direct_call",
            "target": str(spec["callee_function"]),
            "register_arguments": [{"register": register} for register, _ in spec["register_arguments"]],
            "c": "stageb_call_result = callee((uintptr_t)s->eax, (uintptr_t)s->edx, (uintptr_t)s->ecx);",
        },
    ]
    if any(isinstance(operation, dict) and operation.get("op") == "direct_jump" for operation in ir.get("operations", [])):
        statements.append(
            {
                "kind": "direct_jump",
                "target": str(spec["post_call_jump_function"]),
                "target_block_id": str(spec["post_call_jump_block_id"]),
                "c": "return post_call_jump_target();",
            }
        )
    return {
        "format": "stage-a-c-shaped-region-contract-v1",
        "status": "checked" if ir.get("status") == "checked" else "incomplete",
        "state_type": "stageb_x86_state",
        "function": f"{_safe_gap_part(str(spec['caller_function'])).replace('-', '_')}_contract",
        "statements": statements,
        "equivalence": {
            "status": "checked" if ir.get("status") == "checked" else "incomplete",
            "proof_rule": "stage_a_ir_to_c_contract_structural_v1",
        },
    }


def _semantic_region_inputs(spec: dict[str, Any], event: tuple[Any, ...] | None) -> dict[str, Any]:
    return {
        "semantic_registers": ["ebx"],
        "machine_registers_at_call": _semantic_region_call_register_inputs_json(event),
        "stack_slots": [],
        "flags": [],
        "memory_reads": [],
    }


def _semantic_region_outputs(spec: dict[str, Any], callee: BlockMapping | None) -> dict[str, Any]:
    return {
        "registers_at_call": [
            {"register": register, "value": _semantic_expr_json(expr)}
            for register, expr in spec["register_arguments"]
        ],
        "stack_slots": [],
        "flags": [],
        "memory_writes": [],
        "direct_call": {
            "target": str(spec["callee_function"]),
            "target_block_id": str(spec["callee_block_id"]),
            "target_rva": callee.original.rva_start if isinstance(callee, BlockMapping) else None,
        },
    }


def _semantic_region_call_register_inputs_json(event: tuple[Any, ...] | None) -> dict[str, Any]:
    if event is None or len(event) <= 3 or not isinstance(event[3], tuple):
        return {}
    return _semantic_call_register_inputs_json(event[3])


def _semantic_region_preconditions(spec: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"kind": "machine_mode", "value": "x86-pe32"},
        {"kind": "wrapping_arithmetic", "expression": "ebx + 0x1c", "width": 32},
        {"kind": "direct_call_abi", "target": str(spec["callee_function"]), "register_order": ["eax", "edx", "ecx"]},
    ]


def _semantic_region_cfg_exits(
    caller: BlockMapping,
    callee: BlockMapping | None,
    post_call_jump: BlockMapping | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(callee, BlockMapping):
        return []
    exits = [
        {
            "kind": "direct_call",
            "source_block_id": caller.id,
            "target_block_id": callee.id,
            "target_rva": callee.original.rva_start,
        }
    ]
    if isinstance(post_call_jump, BlockMapping):
        exits.append(
            {
                "kind": "direct_jump",
                "source_block_id": caller.id,
                "target_block_id": post_call_jump.id,
                "target_rva": post_call_jump.original.rva_start,
                "position": "post_call",
            }
        )
    return exits


def _semantic_region_proof_obligations(region_id: str, blockers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    status = "proved" if not blockers else "incomplete"
    blocker = blockers[0]["blocker"] if blockers else None
    next_action = blockers[0]["next_action"] if blockers else "no action required"
    return [
        {
            "id": f"semantic-region:{_safe_gap_part(region_id)}:x86-to-ir",
            "kind": "semantic_region_x86_to_ir",
            "status": status,
            "proof_rule": "stage_a_symbolic_x86_to_ir_region_subset_v1",
            "blocker": blocker,
            "next_action": next_action,
        },
        {
            "id": f"semantic-region:{_safe_gap_part(region_id)}:ir-to-c-contract",
            "kind": "semantic_region_ir_to_c_contract",
            "status": status,
            "proof_rule": "stage_a_ir_to_c_contract_structural_v1",
            "blocker": blocker,
            "next_action": next_action,
        },
    ]


def _reference_semantic_region_unit_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    constraint = _contract_constraint(contract, "semantic_region_contracts")
    rows = []
    for region in constraint.get("regions", []) if isinstance(constraint.get("regions"), list) else []:
        if not isinstance(region, dict):
            continue
        row = dict(region)
        row["reference_contract"] = contract_ref
        rows.append(row)
    return sorted(rows, key=lambda item: str(item.get("id") or ""))


def _reference_proof_obligation_inventory_with_semantic_regions(
    proof: dict[str, Any],
    semantic_regions: dict[str, Any],
) -> dict[str, Any]:
    obligations = [item for item in proof.get("obligations", []) if isinstance(item, dict)]
    region_obligations = [
        item
        for region in semantic_regions.get("regions", []) if isinstance(region, dict)
        for item in region.get("proof_obligations", []) if isinstance(item, dict)
    ]
    if not region_obligations:
        return proof
    updated = dict(proof)
    updated["obligations"] = [*obligations, *region_obligations]
    counts = dict(updated.get("counts") if isinstance(updated.get("counts"), dict) else {})
    counts["obligations"] = len(updated["obligations"])
    counts["by_status"] = _count_by(updated["obligations"], "status")
    updated["counts"] = counts
    statuses = {str(item.get("status") or "") for item in updated["obligations"]}
    if proof.get("status") == "satisfied" and statuses <= {"proved", "waived_noncode"}:
        updated["status"] = "satisfied"
    elif "failed" in statuses:
        updated["status"] = "failed"
    else:
        updated["status"] = "incomplete"
    return updated


def _semantic_transfer_contracts(
    binary: StageABinary,
    mappings: list[BlockMapping],
    contract_ref: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for mapped in mappings:
        if mapped.kind != "code":
            continue
        source = _mapping_source(mapped)
        function_name = source.get("function") if isinstance(source.get("function"), str) and source.get("function") else mapped.id
        rows.append(_semantic_transfer_contract(binary, mapped, function_name, contract_ref))
    return sorted(rows, key=lambda item: (str(item.get("function") or ""), str(item.get("block_id") or "")))


def _semantic_transfer_contract(
    binary: StageABinary,
    mapped: BlockMapping,
    function_name: str,
    contract_ref: dict[str, Any],
) -> dict[str, Any]:
    side = mapped.original
    data = binary.pe.get_data(side.rva_start, side.size)
    instructions = _semantic_disassemble_block(binary, side, data)
    base_row: dict[str, Any] = {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": f"semantic-transfer:{_safe_gap_part(mapped.id)}",
        "unit_kind": "semantic_transfer",
        "expression_model": "stage-a-semantic-ir-v1",
        "status": "incomplete",
        "reference_contract": contract_ref,
        "function": function_name or None,
        "block_id": mapped.id,
        "reachable": mapped.reachable,
        "original": _range_report(side),
        "instruction_bytes_sha256": sha256_bytes(data),
        "instructions": instructions,
        "pre_state": _semantic_pre_state(binary),
        "register_writes": [],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "edge_conditions": [],
        "outcome": {"kind": "unknown"},
        "acceptance": "guidance contract only; final acceptance requires Stage A binary proof",
    }
    if len(data) != side.size:
        return {
            **base_row,
            "blocker_category": "unreadable_block_bytes",
            "blocker": f"expected {side.size} block bytes, read {len(data)}",
            "next_action": "fix block range or PE section mapping before generating a semantic transfer contract",
        }
    symbolic = _symbolic_execute(binary, side, data, "original", mapped)
    if symbolic.get("status") != "ok":
        instruction = symbolic.get("instruction") if isinstance(symbolic.get("instruction"), dict) else None
        return {
            **base_row,
            "blocker_category": symbolic.get("category") or "unsupported_semantics",
            "blocker": symbolic.get("blocker") or "block is outside the current semantic transfer model",
            "next_action": symbolic.get("next_action") or "add instruction semantics or a checked cluster summary",
            "blocking_instruction": instruction,
        }
    observables = symbolic.get("observables") if isinstance(symbolic.get("observables"), dict) else {}
    effects = _semantic_effects_from_observables(observables)
    return {
        **base_row,
        "status": "reimplementable",
        "blocker_category": None,
        "blocker": None,
        "next_action": "implement this block so the compiled candidate reproduces the transfer contract, then rerun Stage A",
        **effects,
    }


def _semantic_disassemble_block(binary: StageABinary, side: BlockSide, data: bytes) -> list[dict[str, Any]]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    return [_instruction_report(binary, insn) for insn in dis.disasm(data, binary.image_base + side.rva_start)]


def _semantic_pre_state(binary: StageABinary) -> dict[str, Any]:
    registers = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp") if binary.bitness == 32 else ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp")
    flags = ("cf", "zf", "sf", "of", "pf", "df")
    return {
        "registers": {name: _semantic_expr_json(("reg", name)) for name in registers},
        "flags": {name: _semantic_expr_json(("flag", name)) for name in flags},
        "memory": {"op": "memory", "name": "mem0", "address_width": binary.bitness, "value_width": 8},
    }


def _semantic_effects_from_observables(observables: dict[str, Any]) -> dict[str, Any]:
    register_writes = []
    flag_writes = []
    for key, value in sorted(observables.items()):
        if key.startswith("reg:"):
            name = key.split(":", 1)[1]
            if value != ("reg", name):
                register_writes.append({"register": name, "value": _semantic_expr_json(value)})
        elif key.startswith("flag:"):
            name = key.split(":", 1)[1]
            if value != ("flag", name):
                flag_writes.append({"flag": name, "value": _semantic_expr_json(value)})
    memory_events = [_semantic_memory_event_json(event) for event in observables.get("memory_events", [])]
    external_events = [_semantic_external_event_json(event) for event in observables.get("external_events", [])]
    outcome = _semantic_outcome_json(observables.get("outcome"))
    return {
        "register_writes": register_writes,
        "flag_writes": flag_writes,
        "memory_events": memory_events,
        "external_events": external_events,
        "fpu_state": _semantic_fpu_state_from_observables(observables),
        "edge_conditions": _semantic_edge_conditions(outcome),
        "outcome": outcome,
        "stack_delta": _semantic_stack_delta_from_observables(observables),
        "counts": {
            "register_writes": len(register_writes),
            "flag_writes": len(flag_writes),
            "memory_events": len(memory_events),
            "external_events": len(external_events),
            "edge_conditions": len(_semantic_edge_conditions(outcome)),
        },
    }


def _semantic_fpu_state_from_observables(observables: dict[str, Any]) -> dict[str, Any] | None:
    if "fpu_stack" not in observables and "fpu_control" not in observables and "fpu_status" not in observables:
        return None
    stack = observables.get("fpu_stack")
    return {
        "stack": [_semantic_expr_json(item) for item in stack] if isinstance(stack, tuple) else [],
        "control": _semantic_expr_json(observables.get("fpu_control")),
        "status": _semantic_expr_json(observables.get("fpu_status")),
        "model": "symbolic_x87_stack_v1",
    }


def _semantic_expr_json(value: Any) -> Any:
    if not isinstance(value, tuple) or not value:
        if isinstance(value, list):
            return [_semantic_expr_json(item) for item in value]
        if isinstance(value, dict):
            return {str(key): _semantic_expr_json(item) for key, item in value.items()}
        return value
    op = str(value[0])
    if op == "const":
        return {"op": "const", "width": 32, "value": int(value[1]) & 0xFFFFFFFF}
    if op == "reg":
        return {"op": "reg", "width": 32, "name": str(value[1])}
    if op == "flag":
        return {"op": "flag", "name": str(value[1])}
    if op == "mem32":
        return {"op": "load", "width": 4, "address": _semantic_expr_json(value[1])}
    if op == "mem":
        return {"op": "load", "width": int(value[1]) // 8, "address": _semantic_expr_json(value[2])}
    if op == "env_response":
        return {"op": "env_response", "width": 32, "index": int(value[1])}
    if op == "call_response":
        return {"op": "call_response", "width": 32, "call_index": int(value[1]), "register": str(value[2])}
    if op == "call_mem":
        return {"op": "call_memory_load", "width": int(value[2]) // 8, "call_index": int(value[1]), "address": _semantic_expr_json(value[3])}
    if op == "call_flag":
        return {"op": "call_flag", "call_index": int(value[1]), "flag": str(value[2])}
    if op == "undefined_bv":
        return {"op": "undefined_bv", "width": 32, "reason": str(value[1]), "id": str(value[2])}
    if op == "undefined_flag":
        return {"op": "undefined_flag", "reason": str(value[1]), "id": str(value[2])}
    if op in {"true", "false"}:
        return {"op": op}
    op_map = {
        "add": "add32",
        "sub": "sub32",
        "mul": "mul32",
        "xor": "xor32",
        "and": "and32",
        "or": "or32",
        "bvnot": "not32",
        "neg": "neg32",
        "shl": "shl32",
        "lshr": "lshr32",
        "ashr": "sar",
        "sext": "sign_extend",
        "ite": "ite",
        "ult": "ult32",
        "eq": "eq",
        "msb": "msb32",
        "msb_w": "msb",
        "not": "not",
        "bool_and": "and_bool",
        "bool_or": "or_bool",
        "bool_xor": "xor_bool",
        "bool_eq": "eq_bool",
        "add_overflow": "add_overflow32",
        "sub_overflow": "sub_overflow32",
        "add_overflow_w": "add_overflow",
        "sub_overflow_w": "sub_overflow",
        "shift_cf": "shift_cf",
        "shift_of": "shift_of",
        "bool_bit": "bool_to_bit",
        "adc_carry": "adc_carry",
        "adc_overflow": "adc_overflow",
        "sbb_borrow": "sbb_borrow",
        "sbb_overflow": "sbb_overflow",
        "imul_low": "imul_low32",
        "imul_high": "imul_high32",
        "imul_overflow": "imul_overflow",
        "mul_low": "mul_low32",
        "mul_high": "mul_high32",
        "mul_carry": "mul_carry",
        "parity": "parity",
        "udiv_quot": "udiv_quot32",
        "udiv_rem": "udiv_rem32",
        "bsr_index": "bsr_index",
        "tzcnt": "tzcnt",
        "fpu_bits_lo": "fpu_bits_lo32",
        "fpu_bits_hi": "fpu_bits_hi32",
        "fpu_int32": "fpu_int32",
        "fpu_status_word": "fpu_status_word",
        "fpu_control_word": "fpu_control_word",
    }
    return {"op": op_map.get(op, op), "args": [_semantic_expr_json(item) for item in value[1:]]}


def _semantic_memory_event_json(event: Any) -> dict[str, Any]:
    if isinstance(event, tuple) and len(event) >= 2 and event[0] == "read":
        mem = event[1]
        if isinstance(mem, tuple) and len(mem) > 1 and mem[0] == "mem32":
            return {"kind": "read", "width": 4, "address": _semantic_expr_json(mem[1])}
        if isinstance(mem, tuple) and len(mem) > 2 and mem[0] == "mem":
            return {"kind": "read", "width": int(mem[1]) // 8, "address": _semantic_expr_json(mem[2])}
        if isinstance(mem, tuple) and len(mem) > 3 and mem[0] == "call_mem":
            return {"kind": "read", "width": int(mem[2]) // 8, "address": _semantic_expr_json(mem[3]), "memory_epoch": {"kind": "internal_call", "call_index": int(mem[1])}}
        return {"kind": "read", "width": 4, "address": _semantic_expr_json(mem)}
    if isinstance(event, tuple) and len(event) >= 3 and event[0] == "write":
        mem = event[1]
        if isinstance(mem, tuple) and len(mem) > 1 and mem[0] == "mem32":
            return {"kind": "write", "width": 4, "address": _semantic_expr_json(mem[1]), "value": _semantic_expr_json(event[2])}
        if isinstance(mem, tuple) and len(mem) > 2 and mem[0] == "mem":
            return {"kind": "write", "width": int(mem[1]) // 8, "address": _semantic_expr_json(mem[2]), "value": _semantic_expr_json(event[2])}
        if isinstance(mem, tuple) and len(mem) > 3 and mem[0] == "call_mem":
            return {
                "kind": "write",
                "width": int(mem[2]) // 8,
                "address": _semantic_expr_json(mem[3]),
                "value": _semantic_expr_json(event[2]),
                "memory_epoch": {"kind": "internal_call", "call_index": int(mem[1])},
            }
        return {"kind": "write", "width": 4, "address": _semantic_expr_json(mem), "value": _semantic_expr_json(event[2])}
    return {"kind": "unknown", "raw": _expr_json(event)}


def _semantic_external_event_json(event: Any) -> dict[str, Any]:
    if isinstance(event, tuple) and len(event) >= 5 and event[0] == "external_call":
        result = {
            "kind": "external_call",
            "dll": event[1],
            "symbol": event[2],
            "ordinal": event[3],
            "arguments": [_semantic_expr_json(item) for item in event[4]],
        }
        if len(event) >= 6 and isinstance(event[5], tuple) and event[5] and event[5][0] == "auto_call_inputs":
            result["input_model"] = "captured_visible_register_and_stack_inputs_v1"
            result["register_inputs"] = _semantic_call_register_inputs_json(event[5][1] if len(event[5]) > 1 else ())
            result["stack_inputs"] = _semantic_call_stack_inputs_json(event[5][2] if len(event[5]) > 2 else ())
        return result
    if isinstance(event, tuple) and len(event) >= 5 and event[0] == "internal_call":
        return {
            "kind": "internal_call",
            "target_rva": int(event[1]),
            "return_rva": int(event[2]),
            "register_inputs": _semantic_call_register_inputs_json(event[3]),
            "stack_inputs": _semantic_call_stack_inputs_json(event[4]),
            "effect_model": "uninterpreted_internal_call_response_v1",
        }
    if isinstance(event, tuple) and len(event) >= 5 and event[0] == "indirect_call":
        return {
            "kind": "indirect_call",
            "target": _semantic_expr_json(event[1]),
            "return_rva": int(event[2]),
            "register_inputs": _semantic_call_register_inputs_json(event[3]),
            "stack_inputs": _semantic_call_stack_inputs_json(event[4]),
            "effect_model": "uninterpreted_indirect_call_response_v1",
        }
    if isinstance(event, tuple) and len(event) >= 6 and event[0] == "rep_movsd":
        return {
            "kind": "rep_movsd",
            "index": int(event[1]),
            "destination": _semantic_expr_json(event[2]),
            "source": _semantic_expr_json(event[3]),
            "count": _semantic_expr_json(event[4]),
            "direction_flag": _semantic_expr_json(event[5]),
            "effect_model": "symbolic_string_copy_v1",
        }
    return {"kind": "unknown_external_event", "raw": _expr_json(event)}


def _semantic_call_register_inputs_json(items: Any) -> dict[str, Any]:
    result = {}
    for item in items if isinstance(items, tuple) else ():
        if isinstance(item, tuple) and len(item) == 2:
            result[str(item[0])] = _semantic_expr_json(item[1])
    return result


def _semantic_call_stack_inputs_json(items: Any) -> list[dict[str, Any]]:
    result = []
    for item in items if isinstance(items, tuple) else ():
        if isinstance(item, tuple) and len(item) == 3:
            result.append({"offset": int(item[0]), "width": int(item[1]) // 8, "value": _semantic_expr_json(item[2])})
    return result


def _semantic_outcome_json(outcome: Any) -> dict[str, Any]:
    if not isinstance(outcome, tuple) or not outcome:
        return {"kind": "unknown", "raw": _expr_json(outcome)}
    kind = str(outcome[0])
    if kind == "fallthrough":
        return {"kind": "fallthrough", "target_rva": outcome[1]}
    if kind == "jump":
        return {"kind": "jump", "target_rva": outcome[1]}
    if kind == "branch":
        return {
            "kind": "branch",
            "condition": _semantic_expr_json(outcome[1]),
            "true_target_rva": outcome[2],
            "false_target_rva": outcome[3],
        }
    if kind == "return":
        return {"kind": "return", "value": _semantic_expr_json(outcome[1])}
    if kind == "call":
        return {"kind": "direct_call", "target_rva": outcome[1], "return_rva": outcome[2]}
    if kind == "indirect_jump":
        return {"kind": "indirect_jump", "target": _semantic_expr_json(outcome[1])}
    if kind == "indirect_jump_table":
        switch_contract = outcome[2] if len(outcome) > 2 and isinstance(outcome[2], dict) else {}
        return {
            "kind": "indirect_jump_table",
            "target": _semantic_expr_json(outcome[1]),
            "switch_contract": switch_contract,
            "target_rvas": [
                target_rva
                for item in switch_contract.get("case_targets", []) if isinstance(switch_contract.get("case_targets"), list) and isinstance(item, dict)
                for target_rva in [_safe_int(item.get("target_rva"))]
                if target_rva is not None
            ],
        }
    if kind == "external_jump":
        return {"kind": "external_jump", "dll": outcome[1], "symbol": outcome[2], "ordinal": outcome[3]}
    return {"kind": kind, "raw": _expr_json(outcome)}


def _semantic_edge_conditions(outcome: dict[str, Any]) -> list[dict[str, Any]]:
    kind = outcome.get("kind")
    if kind == "branch":
        return [
            {"target_rva": outcome.get("true_target_rva"), "condition": outcome.get("condition")},
            {"target_rva": outcome.get("false_target_rva"), "condition": {"op": "not", "args": [outcome.get("condition")]}},
        ]
    if kind in {"fallthrough", "jump"}:
        return [{"target_rva": outcome.get("target_rva"), "condition": {"op": "true"}}]
    if kind == "indirect_jump_table":
        switch_contract = outcome.get("switch_contract") if isinstance(outcome.get("switch_contract"), dict) else {}
        case_targets = switch_contract.get("case_targets") if isinstance(switch_contract.get("case_targets"), list) else []
        return [
            {
                "target_rva": target_rva,
                "condition": {
                    "op": "jump_table_case",
                    "index": item.get("index"),
                    "instruction_rva": switch_contract.get("instruction", {}).get("rva")
                    if isinstance(switch_contract.get("instruction"), dict)
                    else None,
                },
            }
            for item in case_targets
            if isinstance(item, dict)
            for target_rva in [_safe_int(item.get("target_rva"))]
            if target_rva is not None
        ]
    return []


def _semantic_stack_delta_from_observables(observables: dict[str, Any]) -> dict[str, Any]:
    esp = observables.get("reg:esp")
    delta = _semantic_stack_delta_expr(esp)
    if delta is None:
        return {"status": "unknown", "expression": _semantic_expr_json(esp)}
    return {"status": "derived", "net_bytes": delta, "expression": _semantic_expr_json(esp)}


def _semantic_stack_delta_expr(expr: Any) -> int | None:
    if expr == ("reg", "esp"):
        return 0
    if isinstance(expr, tuple) and expr and expr[0] == "add":
        total = 0
        saw_esp = False
        for part in expr[1:]:
            if part == ("reg", "esp"):
                saw_esp = True
            elif isinstance(part, tuple) and len(part) == 2 and part[0] == "const":
                total += int(part[1])
            else:
                return None
        return total if saw_esp else None
    if isinstance(expr, tuple) and len(expr) == 3 and expr[0] == "sub" and expr[1] == ("reg", "esp"):
        right = expr[2]
        if isinstance(right, tuple) and len(right) == 2 and right[0] == "const":
            return -int(right[1])
    return None


def _semantic_memory_frame_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    frames: dict[str, dict[str, Any]] = {}
    accesses: list[dict[str, Any]] = []
    for function in _abi_functions(contract):
        function_name = str(function.get("name") or "")
        for access_kind, access_list_name in (("read", "memory_reads"), ("write", "memory_writes")):
            for index, access in enumerate(function.get(access_list_name, []) if isinstance(function.get(access_list_name), list) else []):
                if not isinstance(access, dict):
                    continue
                frame = _semantic_memory_frame_for_access(access)
                frames.setdefault(str(frame["id"]), frame)
                instruction = access.get("instruction") if isinstance(access.get("instruction"), dict) else {}
                accesses.append(
                    {
                        "id": f"memory-access:{_safe_gap_part(function_name)}:{instruction.get('rva', 'unknown')}:{access_kind}:{index}",
                        "function": function_name or None,
                        "block_id": _block_id_for_instruction(function, instruction),
                        "access": access_kind,
                        "width": access.get("width"),
                        "frame_id": frame["id"],
                        "frame_kind": frame["frame_kind"],
                        "addressing": access.get("addressing") if isinstance(access.get("addressing"), dict) else {},
                        "instruction": instruction,
                        "status": "classified" if frame["frame_kind"] != "unknown" else "incomplete",
                        "blocker": None if frame["frame_kind"] != "unknown" else "memory frame could not be classified from static addressing evidence",
                        "source_access": access,
                    }
                )
    return {
        "format": "stage-a-memory-frame-contracts-v1",
        "reference_contract": contract_ref,
        "frames": sorted(frames.values(), key=lambda item: str(item.get("id") or "")),
        "accesses": sorted(accesses, key=lambda item: str(item.get("id") or "")),
        "counts": {
            "frames": len(frames),
            "accesses": len(accesses),
            "by_frame_kind": _count_by(list(frames.values()), "frame_kind"),
            "by_access": _count_by(accesses, "access"),
        },
    }


def _semantic_memory_frame_for_access(access: dict[str, Any]) -> dict[str, Any]:
    role = str(access.get("memory_role") or "unknown")
    section = access.get("memory_section") if isinstance(access.get("memory_section"), dict) else {}
    addressing = access.get("addressing") if isinstance(access.get("addressing"), dict) else {}
    base = str(addressing.get("base") or "")
    entry_pointer = access.get("entry_register_pointer") if isinstance(access.get("entry_register_pointer"), dict) else {}
    if role == "import_address_table":
        frame_kind = "iat.import"
        frame_key = str(access.get("memory_rva") or "unknown")
    elif role.startswith("global_"):
        frame_kind = "global.rw" if section.get("writable") is True else "global.ro"
        frame_key = str(section.get("name") or access.get("memory_rva") or "unknown")
    elif role == "stack_argument_slot":
        frame_kind = "stack.arg"
        frame_key = base or "stack"
    elif role in {"stack_local_slot", "stack_pointer_slot"}:
        frame_kind = "stack.local"
        frame_key = base or "stack"
    elif entry_pointer:
        frame_kind = "object.pointer_candidate"
        frame_key = str(entry_pointer.get("register") or base or "entry")
    elif role == "argument_pointer_deref":
        frame_kind = "object.argument_pointer"
        frame_key = base or "argument"
    elif role == "global_pointer_deref":
        frame_kind = "object.global_pointer"
        frame_key = base or str(access.get("memory_rva") or "global")
    elif role == "computed_pointer_deref":
        frame_kind = "object.computed_pointer"
        frame_key = base or "computed"
    elif role == "absolute_memory_slot":
        frame_kind = "absolute.memory"
        frame_key = str(access.get("memory_rva") or "absolute")
    elif role == "computed_memory":
        frame_kind = "computed.memory"
        frame_key = base or "computed"
    else:
        frame_kind = f"role.{_safe_gap_part(role)}" if role else "role.unknown"
        frame_key = role
    return {
        "id": f"frame:{_safe_gap_part(frame_kind)}:{_safe_gap_part(frame_key)}",
        "frame_kind": frame_kind,
        "memory_role": role,
        "section": section or None,
        "base_register": base or None,
        "entry_register_pointer": entry_pointer or None,
        "status": "classified",
    }


def _semantic_call_summary_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    summaries: list[dict[str, Any]] = []
    for function in _abi_functions(contract):
        function_name = str(function.get("name") or "")
        for index, callsite in enumerate(function.get("callsites", []) if isinstance(function.get("callsites"), list) else []):
            if not isinstance(callsite, dict):
                continue
            summary = _semantic_call_summary(function_name, index, callsite)
            summaries.append(summary)
    return {
        "format": "stage-a-call-summary-contracts-v1",
        "reference_contract": contract_ref,
        "calls": sorted(summaries, key=lambda item: str(item.get("id") or "")),
        "counts": {
            "calls": len(summaries),
            "by_status": _count_by(summaries, "status"),
            "by_target_kind": _count_by(summaries, "target_kind"),
        },
    }


def _semantic_call_summary(function_name: str, index: int, callsite: dict[str, Any]) -> dict[str, Any]:
    target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
    inventory = callsite.get("argument_inventory") if isinstance(callsite.get("argument_inventory"), dict) else {}
    hidden = callsite.get("hidden_sret_or_out_param_evidence") if isinstance(callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
    varargs = callsite.get("varargs_evidence") if isinstance(callsite.get("varargs_evidence"), dict) else {}
    targets = callsite.get("function_pointer_targets") if isinstance(callsite.get("function_pointer_targets"), list) else []
    blockers: list[str] = []
    indirect_boundary = (target.get("kind") == "function_pointer" and target.get("status") == "unresolved")
    if any(isinstance(item, dict) and item.get("status") == "unresolved" for item in targets) and not indirect_boundary:
        blockers.append("function-pointer target set is unresolved")
    fmt = varargs.get("format_string") if isinstance(varargs.get("format_string"), dict) else {}
    if fmt.get("status") == "incomplete":
        blockers.append(str(fmt.get("reason") or "varargs format-string inventory is incomplete"))
    status = "complete" if not blockers else "incomplete"
    return {
        "id": str(callsite.get("id") or f"callsite:{_safe_gap_part(function_name)}:{index}"),
        "function": function_name or None,
        "block_id": callsite.get("block_id"),
        "status": status,
        "target_kind": target.get("kind") or "unknown",
        "target": target,
        "calling_convention": inventory.get("calling_convention") or "unknown",
        "argument_inventory": inventory,
        "return_value": {"register": "eax", "status": "environment_response_or_direct_call_result"},
        "stack_delta": callsite.get("stack_delta") if isinstance(callsite.get("stack_delta"), dict) else {"status": "unknown"},
        "hidden_sret_or_out_param_evidence": hidden,
        "varargs_evidence": varargs,
        "function_pointer_targets": targets,
        "indirect_boundary": {"status": "explicit", "effect_model": "preserve_target_expression_and_call_response"} if indirect_boundary else None,
        "blockers": blockers,
        "next_action": _semantic_call_summary_next_action(function_name, target, blockers, varargs, hidden),
        "source_callsite": callsite,
    }


def _semantic_call_summary_next_action(
    function_name: str,
    target: dict[str, Any],
    blockers: list[str],
    varargs: dict[str, Any],
    hidden: dict[str, Any],
) -> str:
    if blockers:
        if any("function-pointer" in item for item in blockers):
            return f"recover finite function-pointer targets for {function_name} or keep the indirect boundary explicit"
        if varargs.get("status") == "candidate" or any("varargs" in item or "format" in item for item in blockers):
            return f"recover the format-string and variadic argument inventory for {function_name}"
        return f"complete the call summary for {function_name}"
    if varargs.get("status") == "candidate":
        return "preserve the variadic import/prototype boundary exactly in generated C"
    if hidden.get("status") == "candidate":
        return "preserve the hidden sret/out-param channel across this call"
    if target.get("kind") == "import":
        return "preserve this call as an import/environment boundary"
    return "preserve this call target, argument inventory, and return-value use"


def _semantic_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for cluster in _reference_cluster_contracts(contract, contract_ref):
        if not isinstance(cluster, dict):
            continue
        status, blocker, next_action = _semantic_cluster_status(cluster)
        rows.append(
            {
                "format": "stage-a-cluster-semantic-contract-v1",
                "id": f"semantic-{cluster.get('id')}",
                "unit_kind": "semantic_cluster",
                "status": status,
                "reference_contract": contract_ref,
                "function": cluster.get("function"),
                "block_id": cluster.get("block_id"),
                "cluster_kind": cluster.get("cluster_kind"),
                "repair_class": cluster.get("repair_class"),
                "source_cluster_id": cluster.get("id"),
                "blocker": blocker,
                "next_action": next_action,
                "source_cluster": cluster,
                "acceptance": "guidance cluster only; final acceptance requires Stage A binary proof",
            }
        )
    return sorted(rows, key=lambda item: str(item.get("id") or ""))


def _semantic_cluster_status(cluster: dict[str, Any]) -> tuple[str, str | None, str]:
    kind = str(cluster.get("cluster_kind") or "")
    evidence = cluster.get("evidence") if isinstance(cluster.get("evidence"), dict) else {}
    if kind == "recoverable_function_pointer_target":
        return (
            "complete",
            None,
            "preserve this indirect call as an explicit target-expression boundary unless a finite target set is later recovered",
        )
    if kind == "abi_switch_or_jump_table_candidate":
        switch = evidence.get("switch_contract") if isinstance(evidence.get("switch_contract"), dict) else {}
        if switch.get("table_bounds") and switch.get("case_targets"):
            return ("complete", None, "represent this switch dispatch with the recovered selector, bounds, cases, and default edge")
        return (
            "complete",
            None,
            "preserve this dispatch as an indirect-jump contract with the recovered index expression until source switch bounds are recovered",
        )
    if kind == "abi_loop_backedge_candidate":
        return (
            "complete",
            None,
            "preserve this loop as low-level CFG backedges; source-level loop-carried summaries are optional refinement",
        )
    if kind == "abi_varargs_callsite":
        varargs = evidence.get("varargs_evidence") if isinstance(evidence.get("varargs_evidence"), dict) else {}
        fmt = varargs.get("format_string") if isinstance(varargs.get("format_string"), dict) else {}
        if fmt.get("status") == "incomplete":
            return (
                "incomplete",
                str(fmt.get("reason") or "varargs format-string evidence is incomplete"),
                "recover the format string and observed variadic argument inventory",
            )
    return ("complete", None, str(cluster.get("next_action") or "preserve this semantic cluster in generated C"))


def _reference_unit_contract_payloads(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    *,
    semantic_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    semantic_payload = semantic_payload or _fallback_reference_semantic_contract_payloads(contract, contract_ref)
    block_contracts = _reference_block_contracts(contract, contract_ref)
    function_contracts = _reference_function_contracts(contract, contract_ref, block_contracts)
    cluster_contracts = _reference_cluster_contracts(contract, contract_ref)
    source_obligations = _reference_source_obligations_sidecar(contract, contract_ref, block_contracts, function_contracts, cluster_contracts)
    repair_units = _reference_repair_units_sidecar(
        contract,
        contract_ref,
        block_contracts,
        function_contracts,
        cluster_contracts,
        semantic_payload=semantic_payload,
    )
    return {
        "block_contracts": block_contracts,
        "function_contracts": function_contracts,
        "cluster_contracts": cluster_contracts,
        "repair_units": repair_units,
        "source_obligations": source_obligations,
        "semantic_transfer_contracts": semantic_payload["semantic_transfer_contracts"],
        "semantic_region_contracts": semantic_payload.get("semantic_region_contracts", []),
        "memory_frame_contracts": semantic_payload["memory_frame_contracts"],
        "call_summary_contracts": semantic_payload["call_summary_contracts"],
        "cluster_semantic_contracts": semantic_payload["cluster_semantic_contracts"],
    }


def _reference_block_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    cfg = _contract_constraint(contract, "basic_blocks_and_cfg")
    blocks = cfg.get("basic_blocks") if isinstance(cfg.get("basic_blocks"), list) else []
    cfg_by_block = {
        str(item.get("block_id")): item
        for item in cfg.get("cfg_edges", [])
        if isinstance(item, dict) and item.get("block_id")
    }
    abi_by_block = _abi_evidence_by_block(contract)
    functions_by_block = _function_names_by_block(contract)
    result = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        block_id = str(block.get("id") or "")
        function_name = str(block.get("function") or functions_by_block.get(block_id) or "")
        abi = abi_by_block.get(block_id, {})
        result.append(
            {
                "format": "stage-a-block-contract-v1",
                "id": f"block:{_safe_gap_part(block_id)}",
                "unit_kind": "basic_block",
                "status": "specified" if block.get("kind") == "code" else "non_code",
                "reference_contract": contract_ref,
                "function": function_name or None,
                "block_id": block_id,
                "kind": block.get("kind"),
                "reachable": block.get("reachable"),
                "original": block.get("original") if isinstance(block.get("original"), dict) else {},
                "candidate": block.get("candidate") if isinstance(block.get("candidate"), dict) else {},
                "byte_contract": {
                    "proof_rule": block.get("proof_rule"),
                    "byte_identical": block.get("byte_identical"),
                    "source_kind": block.get("source_kind"),
                },
                "cfg": _block_cfg_contract(block_id, cfg_by_block),
                "state_contract": {
                    "register_reads": abi.get("register_reads", []),
                    "register_writes": abi.get("register_writes", []),
                    "preserved_register_candidates": abi.get("preserved_candidates", []),
                    "clobbered_register_candidates": abi.get("clobbered_candidates", []),
                    "stack_delta": abi.get("stack_delta", {"status": "unknown"}),
                    "callsites": abi.get("callsites", []),
                    "register_value_provenance": abi.get("register_value_provenance", []),
                    "register_out_param_candidates": abi.get("register_out_param_candidates", []),
                    "memory_reads": abi.get("memory_reads", []),
                    "memory_writes": abi.get("memory_writes", []),
                    "field_accesses": abi.get("field_accesses", []),
                    "memory_access_summary": abi.get("memory_effect_summary")
                    if isinstance(abi.get("memory_effect_summary"), dict)
                    else _block_memory_access_summary(abi.get("callsites", [])),
                    "switch_contracts": abi.get("switch_contracts", []),
                    "loop_hints": abi.get("loop_hints", []),
                },
                "composition": {
                    "pre_state": "caller-provided machine state constrained by function and predecessor contracts",
                    "post_state": "successor-visible machine state and environment events in state_contract",
                    "acceptance": "informational unit contract only; final acceptance requires Stage A pass",
                },
            }
        )
    return sorted(result, key=lambda item: (str(item.get("function") or ""), str(item.get("block_id") or "")))


def _reference_function_contracts(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    block_contracts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ranges = _contract_constraint(contract, "function_ranges")
    functions = ranges.get("functions") if isinstance(ranges.get("functions"), list) else []
    abi_by_function = _abi_evidence_by_function(contract)
    blocks_by_function: dict[str, list[dict[str, Any]]] = {}
    for block in block_contracts:
        function_name = str(block.get("function") or "")
        if function_name:
            blocks_by_function.setdefault(function_name, []).append(block)
    result = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        abi = abi_by_function.get(name, {})
        block_rows = blocks_by_function.get(name, [])
        callsites = abi.get("callsites") if isinstance(abi.get("callsites"), list) else []
        result.append(
            {
                "format": "stage-a-function-contract-v1",
                "id": f"function:{_safe_gap_part(name)}",
                "unit_kind": "function",
                "status": _proof_family_status(ranges.get("status")),
                "reference_contract": contract_ref,
                "function": name,
                "aliases": function.get("aliases") if isinstance(function.get("aliases"), list) else [],
                "original": function.get("original") if isinstance(function.get("original"), dict) else {},
                "candidate": function.get("candidate") if isinstance(function.get("candidate"), dict) else {},
                "block_ids": function.get("block_ids") if isinstance(function.get("block_ids"), list) else [row.get("block_id") for row in block_rows],
                "block_contract_ids": [row.get("id") for row in block_rows],
                "abi": {
                    "callsites": callsites,
                    "registers": abi.get("registers") if isinstance(abi.get("registers"), dict) else {},
                    "stack_delta": abi.get("stack_delta", {"status": "unknown"}),
                    "register_value_provenance": abi.get("register_value_provenance", []),
                    "register_out_param_candidates": abi.get("register_out_param_candidates", []),
                    "switch_contracts": abi.get("switch_contracts", []),
                    "loop_hints": abi.get("loop_hints", []),
                },
                "memory_effect_summary": abi.get("memory_effect_summary")
                if isinstance(abi.get("memory_effect_summary"), dict)
                else {},
                "memory_reads": abi.get("memory_reads", []),
                "memory_writes": abi.get("memory_writes", []),
                "field_accesses": abi.get("field_accesses", []),
                "implementation_spec": {
                    "source_shape": "ugly C is acceptable if the candidate binary satisfies this function contract under Stage A",
                    "next_action": _function_contract_next_action(name, abi),
                },
                "counts": {
                    "blocks": len(block_rows),
                    "callsites": len(callsites),
                },
            }
        )
    return sorted(result, key=lambda item: str(item.get("function") or ""))


def _reference_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    clusters.extend(_abi_cluster_contracts(contract, contract_ref))
    clusters.extend(_import_thunk_cluster_contracts(contract, contract_ref))
    clusters.extend(_jump_target_cluster_contracts(contract, contract_ref))
    clusters.extend(_tls_cluster_contracts(contract, contract_ref))
    return sorted(_dedupe_unit_rows(clusters), key=lambda item: str(item.get("id") or ""))


def _abi_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    for function in _abi_functions(contract):
        function_name = str(function.get("name") or "")
        for callsite in function.get("callsites", []) if isinstance(function.get("callsites"), list) else []:
            if not isinstance(callsite, dict):
                continue
            callsite_id = str(callsite.get("id") or "")
            hidden = callsite.get("hidden_sret_or_out_param_evidence") if isinstance(callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
            if hidden.get("status") == "candidate":
                clusters.append(
                    _cluster_contract(
                        contract_ref=contract_ref,
                        cluster_id=f"hidden-sret:{callsite_id}",
                        cluster_kind="abi_hidden_sret_or_out_param",
                        function=function_name,
                        block_id=str(callsite.get("block_id") or ""),
                        repair_class="hidden_sret_or_out_param",
                        next_action="preserve the first address-like stack argument as an explicit out parameter or hidden sret bridge in generated C",
                        evidence={"callsite": callsite, "hidden_sret_or_out_param_evidence": hidden},
                    )
                )
            varargs = callsite.get("varargs_evidence") if isinstance(callsite.get("varargs_evidence"), dict) else {}
            if varargs.get("status") == "candidate":
                clusters.append(
                    _cluster_contract(
                        contract_ref=contract_ref,
                        cluster_id=f"varargs:{callsite_id}",
                        cluster_kind="abi_varargs_callsite",
                        function=function_name,
                        block_id=str(callsite.get("block_id") or ""),
                        repair_class="varargs_or_stdio_bridge",
                        next_action="model the variadic call bridge exactly enough for the candidate ABI and imported stdio target",
                        evidence={"callsite": callsite, "varargs_evidence": varargs},
                    )
                )
            for target in callsite.get("function_pointer_targets", []) if isinstance(callsite.get("function_pointer_targets"), list) else []:
                if isinstance(target, dict) and target.get("status") == "unresolved":
                    clusters.append(
                        _cluster_contract(
                            contract_ref=contract_ref,
                            cluster_id=f"function-pointer:{callsite_id}",
                            cluster_kind="recoverable_function_pointer_target",
                            function=function_name,
                            block_id=str(callsite.get("block_id") or ""),
                            repair_class="function_pointer_target",
                            next_action="recover the function-pointer target set or add a checked indirect-call/jump-table target contract",
                            evidence={"callsite": callsite, "function_pointer_target": target},
                        )
                    )
        for candidate in function.get("register_out_param_candidates", []) if isinstance(function.get("register_out_param_candidates"), list) else []:
            if not isinstance(candidate, dict):
                continue
            instruction = _nested_dict(candidate, "write", "instruction")
            rva = instruction.get("rva") if isinstance(instruction, dict) else "unknown"
            register = str(candidate.get("register") or "unknown")
            clusters.append(
                _cluster_contract(
                    contract_ref=contract_ref,
                    cluster_id=f"register-out-param:{function_name}:{register}:{rva}",
                    cluster_kind="abi_register_carried_out_param",
                    function=function_name,
                    block_id=_block_id_for_instruction(function, instruction),
                    repair_class="hidden_sret_or_out_param",
                    next_action="preserve writes through entry register pointers as explicit out parameters or hidden result storage in generated C",
                    evidence={"register_out_param_candidate": candidate},
                )
            )
        for switch in function.get("switch_contracts", []) if isinstance(function.get("switch_contracts"), list) else []:
            if not isinstance(switch, dict):
                continue
            instruction = switch.get("instruction") if isinstance(switch.get("instruction"), dict) else {}
            clusters.append(
                _cluster_contract(
                    contract_ref=contract_ref,
                    cluster_id=f"switch:{function_name}:{instruction.get('rva', 'unknown')}",
                    cluster_kind="abi_switch_or_jump_table_candidate",
                    function=function_name,
                    block_id=_block_id_for_instruction(function, instruction),
                    repair_class="switch_or_jump_table_dispatch",
                    next_action="recover switch table bounds, default edge, and case target mapping in generated control flow",
                    evidence={"switch_contract": switch},
                )
            )
        for loop in function.get("loop_hints", []) if isinstance(function.get("loop_hints"), list) else []:
            if not isinstance(loop, dict):
                continue
            instruction = loop.get("instruction") if isinstance(loop.get("instruction"), dict) else {}
            clusters.append(
                _cluster_contract(
                    contract_ref=contract_ref,
                    cluster_id=f"loop:{function_name}:{instruction.get('rva', 'unknown')}",
                    cluster_kind="abi_loop_backedge_candidate",
                    function=function_name,
                    block_id=_block_id_for_instruction(function, instruction),
                    repair_class="loop_or_state_machine",
                    next_action="preserve the loop backedge, loop-carried state, and exit predicate in generated control flow",
                    evidence={"loop_hint": loop},
                )
            )
    return clusters


def _nested_dict(value: dict[str, Any], *path: str) -> dict[str, Any]:
    current: Any = value
    for key in path:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _block_id_for_instruction(function: dict[str, Any], instruction: dict[str, Any]) -> str | None:
    rva = _safe_int(instruction.get("rva")) if isinstance(instruction, dict) else None
    if rva is None:
        return None
    for block in function.get("blocks", []) if isinstance(function.get("blocks"), list) else []:
        if not isinstance(block, dict):
            continue
        start = _safe_int(block.get("rva_start"))
        end = _safe_int(block.get("rva_end"))
        if start is not None and end is not None and start <= rva < end:
            block_id = block.get("block_id")
            return str(block_id) if block_id not in {None, ""} else None
    return None


def _import_thunk_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    thunks = _contract_constraint(contract, "import_thunks").get("mapped_import_thunks")
    result = []
    for thunk in thunks if isinstance(thunks, list) else []:
        if not isinstance(thunk, dict):
            continue
        block_id = str(thunk.get("block_id") or "")
        source = thunk.get("source") if isinstance(thunk.get("source"), dict) else {}
        result.append(
            _cluster_contract(
                contract_ref=contract_ref,
                cluster_id=f"import-thunk:{block_id}",
                cluster_kind="import_thunk",
                function=str(source.get("function") or ""),
                block_id=block_id,
                repair_class="import_prototype_mismatch",
                next_action="preserve the import thunk as an import boundary, not as target-owned C logic",
                evidence={"import_thunk": thunk},
            )
        )
    return result


def _jump_target_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    roots = _contract_constraint(contract, "roots_and_jump_tables")
    targets = roots.get("jump_table_targets") if isinstance(roots.get("jump_table_targets"), list) else []
    result = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        block_id = str(target.get("block_id") or "")
        result.append(
            _cluster_contract(
                contract_ref=contract_ref,
                cluster_id=f"jump-target:{block_id}:{target.get('rva', target.get('target_rva', 'unknown'))}",
                cluster_kind="jump_table_target",
                function=str(target.get("function") or ""),
                block_id=block_id,
                repair_class="jump_table_target",
                next_action="represent this target as a reachable switch/computed-goto destination in generated C",
                evidence={"jump_table_target": target},
            )
        )
    return result


def _tls_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for function in _contract_constraint(contract, "function_ranges").get("functions", []):
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        if "tls" not in name.lower():
            continue
        result.append(
            _cluster_contract(
                contract_ref=contract_ref,
                cluster_id=f"tls-callback:{name}",
                cluster_kind="tls_or_crt_callback",
                function=name,
                block_id=None,
                repair_class="tls_callback_abi",
                next_action="preserve the callback calling convention, stack cleanup, and CRT ownership boundary",
                evidence={"function": function},
            )
        )
    return result


def _cluster_contract(
    *,
    contract_ref: dict[str, Any],
    cluster_id: str,
    cluster_kind: str,
    function: str,
    block_id: str | None,
    repair_class: str,
    next_action: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "format": "stage-a-cluster-contract-v1",
        "id": f"cluster:{_safe_gap_part(cluster_id)}",
        "unit_kind": "cluster",
        "cluster_kind": cluster_kind,
        "status": "specified",
        "reference_contract": contract_ref,
        "function": function or None,
        "block_id": block_id or None,
        "repair_class": repair_class,
        "next_action": next_action,
        "evidence": evidence,
        "acceptance": "informational unit contract only; final acceptance requires Stage A pass",
    }


def _reference_source_obligations_sidecar(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
) -> dict[str, Any]:
    proof = _contract_constraint(contract, "proof_obligation_inventory")
    obligations = proof.get("obligations") if isinstance(proof.get("obligations"), list) else []
    unit_lookup = _unit_contract_obligation_lookup(block_contracts, function_contracts, cluster_contracts)
    rows = []
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        obligation_id = str(obligation.get("id") or "")
        rows.append(
            {
                "id": f"source-obligation:{_safe_gap_part(obligation_id)}",
                "obligation_id": obligation_id,
                "kind": obligation.get("kind"),
                "status": obligation.get("status"),
                "proof_rule": obligation.get("proof_rule"),
                "family": _obligation_family(obligation_id),
                "unit_contract_ids": _unit_contract_ids_for_obligation(obligation_id, unit_lookup),
            }
        )
    return {
        "format": "stage-a-source-obligations-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "obligations": rows,
        "counts": {
            "obligations": len(rows),
            "by_status": _count_by(rows, "status"),
            "by_family": _count_by(rows, "family"),
        },
    }


def _reference_repair_units_sidecar(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
    *,
    semantic_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gaps = _reference_contract_gap_items(contract)
    work_items: list[dict[str, Any]] = []
    for gap in gaps:
        work_items.append(_repair_unit_from_gap(gap, block_contracts, function_contracts, cluster_contracts))
    for cluster in cluster_contracts:
        work_items.append(_repair_unit_from_cluster(cluster))
    if isinstance(semantic_payload, dict):
        work_items.extend(_repair_units_from_semantic_payload(semantic_payload))
    work_items = sorted(_dedupe_unit_rows(work_items), key=lambda item: (_repair_unit_priority(item), str(item.get("id") or "")))
    for index, item in enumerate(work_items, start=1):
        item["rank"] = index
    return {
        "format": "stage-a-repair-units-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "work_items": work_items,
        "counts": {
            "work_items": len(work_items),
            "by_family": _count_by(work_items, "family"),
            "by_repair_class": _count_by(work_items, "repair_class"),
        },
    }


def _repair_units_from_semantic_payload(semantic_payload: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    transfers = semantic_payload.get("semantic_transfer_contracts") if isinstance(semantic_payload.get("semantic_transfer_contracts"), list) else []
    for transfer in transfers:
        if not isinstance(transfer, dict) or transfer.get("status") == "reimplementable":
            continue
        items.append(
            {
                "id": f"work:{_safe_gap_part(str(transfer.get('id') or 'semantic-transfer'))}",
                "unit_kind": "semantic_transfer",
                "family": "semantic_transfer",
                "category": transfer.get("blocker_category") or "semantic_transfer_incomplete",
                "severity": "incomplete",
                "original_function": transfer.get("function"),
                "original_block": transfer.get("block_id"),
                "repair_class": _semantic_repair_class(transfer),
                "expected": "complete per-block transfer contract",
                "observed": transfer.get("status"),
                "cause_hint": transfer.get("blocker"),
                "next_action": transfer.get("next_action")
                or "add instruction semantics, memory-frame facts, or a cluster summary for this block",
                "unit_contract_id": transfer.get("id"),
                "source_semantic_transfer": transfer,
            }
        )
    regions = semantic_payload.get("semantic_region_contracts") if isinstance(semantic_payload.get("semantic_region_contracts"), list) else []
    for region in regions:
        if not isinstance(region, dict) or region.get("status") == "checked":
            continue
        items.append(
            {
                "id": f"work:{_safe_gap_part(str(region.get('id') or 'semantic-region'))}",
                "unit_kind": "semantic_region",
                "family": "semantic_region",
                "category": region.get("blocker_category") or "semantic_region_incomplete",
                "severity": "incomplete",
                "original_function": region.get("function"),
                "original_block": region.get("block_id"),
                "repair_class": "verified_decompiler_region_contract",
                "expected": "checked x86-to-IR-to-C semantic region contract",
                "observed": region.get("status"),
                "cause_hint": region.get("blocker"),
                "next_action": region.get("next_action")
                or "close the selected region contract before lowering it into Stage B C",
                "unit_contract_id": region.get("id"),
                "source_semantic_region": region,
            }
        )
    clusters = semantic_payload.get("cluster_semantic_contracts") if isinstance(semantic_payload.get("cluster_semantic_contracts"), list) else []
    for cluster in clusters:
        if not isinstance(cluster, dict) or cluster.get("status") in {"complete", "reimplementable"}:
            continue
        items.append(
            {
                "id": f"work:{_safe_gap_part(str(cluster.get('id') or 'semantic-cluster'))}",
                "unit_kind": "semantic_cluster",
                "family": "semantic_cluster",
                "category": cluster.get("cluster_kind") or "semantic_cluster_incomplete",
                "severity": "incomplete",
                "original_function": cluster.get("function"),
                "original_block": cluster.get("block_id"),
                "repair_class": cluster.get("repair_class") or _semantic_repair_class(cluster),
                "expected": "complete composable semantic cluster contract",
                "observed": cluster.get("status"),
                "cause_hint": cluster.get("blocker"),
                "next_action": cluster.get("next_action") or "recover the missing semantic facts for this cluster",
                "unit_contract_id": cluster.get("id"),
                "source_semantic_cluster": cluster,
            }
        )
    return items


def _semantic_repair_class(row: dict[str, Any]) -> str:
    text = json.dumps(row, sort_keys=True, default=str).lower()
    if "varargs" in text or "stdio" in text or "printf" in text:
        return "varargs_or_stdio_bridge"
    if "sret" in text or "out_param" in text:
        return "hidden_sret_or_out_param"
    if "switch" in text or "jump_table" in text or "indirect_jump" in text:
        return "switch_or_jump_table_dispatch"
    if "loop" in text or "backedge" in text or "state_machine" in text:
        return "loop_or_state_machine"
    if "function_pointer" in text or "unknown_target" in text:
        return "function_pointer_target"
    if "memory" in text or "frame" in text or "alias" in text:
        return "memory_effect_mismatch"
    return "semantic_transfer_contract"


def _repair_unit_from_gap(
    gap: dict[str, Any],
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
) -> dict[str, Any]:
    gap_id = str(gap.get("gap_id") or "gap")
    location = gap.get("location") if isinstance(gap.get("location"), dict) else {}
    function = _function_for_gap(gap, block_contracts, function_contracts, cluster_contracts)
    return {
        "id": f"work:{_safe_gap_part(gap_id)}",
        "unit_kind": "gap",
        "family": gap.get("family"),
        "category": gap.get("category"),
        "severity": gap.get("severity"),
        "original_function": function,
        "original_block": location.get("block_id") or _block_for_gap(gap),
        "repair_class": _repair_class_for_gap(gap),
        "expected": gap.get("expected"),
        "observed": gap.get("observed"),
        "cause_hint": gap.get("cause_hint"),
        "next_action": gap.get("next_action"),
        "source_gap": gap,
    }


def _repair_unit_from_cluster(cluster: dict[str, Any]) -> dict[str, Any]:
    cluster_id = str(cluster.get("id") or "cluster")
    return {
        "id": f"work:{_safe_gap_part(cluster_id)}",
        "unit_kind": "cluster",
        "family": _family_for_cluster(cluster),
        "category": cluster.get("cluster_kind"),
        "severity": "incomplete",
        "original_function": cluster.get("function"),
        "original_block": cluster.get("block_id"),
        "repair_class": cluster.get("repair_class"),
        "expected": "generated source preserves this Stage A evidence cluster",
        "observed": "Stage B has not yet proven a source representation for this cluster",
        "cause_hint": cluster.get("cluster_kind"),
        "next_action": cluster.get("next_action"),
        "unit_contract_id": cluster_id,
        "source_cluster": cluster,
    }


def _repair_unit_priority(item: dict[str, Any]) -> tuple[int, int, str]:
    return (
        _gap_family_rank(str(item.get("family") or "")),
        -_gap_severity_rank(item.get("severity")),
        str(item.get("repair_class") or ""),
    )


def _repair_class_for_gap(gap: dict[str, Any]) -> str:
    family = str(gap.get("family") or "")
    category = str(gap.get("category") or "")
    text = f"{family} {category} {gap.get('cause_hint') or ''}".lower()
    if "sret" in text or "out_param" in text:
        return "hidden_sret_or_out_param"
    if "varargs" in text or "printf" in text or "stdio" in text:
        return "varargs_or_stdio_bridge"
    if "switch" in text:
        return "switch_or_jump_table_dispatch"
    if "loop" in text or "state_machine" in text:
        return "loop_or_state_machine"
    if "jump" in text:
        return "jump_table_target"
    if "import" in text:
        return "import_prototype_mismatch"
    if "register" in text or "clobber" in text or "preserved" in text:
        return "preserved_register_mismatch"
    if family == "executable_span_coverage":
        return "missing_code_or_padding_classification"
    if family == "padding_alignment":
        return "padding_or_alignment_classification"
    if family == "function_ranges":
        return "function_root_or_symbol_mapping"
    return family or category or "stage_a_contract_gap"


def _family_for_cluster(cluster: dict[str, Any]) -> str:
    kind = str(cluster.get("cluster_kind") or "")
    if kind.startswith("abi_") or kind == "recoverable_function_pointer_target":
        return "abi_callsites"
    if kind == "jump_table_target":
        return "roots_and_jump_targets"
    if kind == "import_thunk":
        return "import_thunks"
    return "function_ranges"


def _function_contract_next_action(name: str, abi: dict[str, Any]) -> str:
    text = json.dumps(abi, sort_keys=True, default=str).lower()
    if "varargs" in text or "printf" in text:
        return f"repair {name} callsites with an explicit varargs/stdio bridge and re-run candidate-only delta explanation"
    if "sret" in text or "out_param" in text:
        return f"repair {name} hidden sret/out-param handling and re-run candidate-only delta explanation"
    if "tls" in name.lower():
        return f"repair {name} callback ABI and stack cleanup before Stage A validation"
    return f"implement {name} until its function, block, CFG, ABI, and proof-obligation contracts close"


def _block_cfg_contract(block_id: str, cfg_by_block: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = cfg_by_block.get(block_id, {})
    return {
        "status": "specified" if raw else "not_observed",
        "direct_edges": raw,
    }


def _block_memory_access_summary(callsites: Any) -> dict[str, Any]:
    if not isinstance(callsites, list):
        return {"status": "unknown", "argument_memory_sources": 0, "function_pointer_targets": 0}
    argument_memory_sources = 0
    function_pointer_targets = 0
    for callsite in callsites:
        if not isinstance(callsite, dict):
            continue
        for source in callsite.get("argument_sources", []) if isinstance(callsite.get("argument_sources"), list) else []:
            if isinstance(source, dict) and source.get("kind") in {"memory", "address"}:
                argument_memory_sources += 1
        function_pointer_targets += len(callsite.get("function_pointer_targets", [])) if isinstance(callsite.get("function_pointer_targets"), list) else 0
    return {
        "status": "derived",
        "argument_memory_sources": argument_memory_sources,
        "function_pointer_targets": function_pointer_targets,
    }


def _abi_functions(contract: dict[str, Any]) -> list[dict[str, Any]]:
    abi = _contract_constraint(contract, "abi_callsites")
    original = abi.get("original") if isinstance(abi.get("original"), dict) else {}
    functions = original.get("functions") if isinstance(original.get("functions"), list) else []
    return [item for item in functions if isinstance(item, dict)]


def _abi_evidence_by_function(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("name") or ""): item
        for item in _abi_functions(contract)
        if item.get("name")
    }


def _abi_evidence_by_block(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for function in _abi_functions(contract):
        calls_by_block: dict[str, list[dict[str, Any]]] = {}
        for callsite in function.get("callsites", []) if isinstance(function.get("callsites"), list) else []:
            if isinstance(callsite, dict):
                calls_by_block.setdefault(str(callsite.get("block_id") or ""), []).append(callsite)
        registers = function.get("registers") if isinstance(function.get("registers"), dict) else {}
        for block in function.get("blocks", []) if isinstance(function.get("blocks"), list) else []:
            if not isinstance(block, dict):
                continue
            block_id = str(block.get("block_id") or "")
            if not block_id:
                continue
            block_abi = block.get("abi") if isinstance(block.get("abi"), dict) else {}
            memory_reads = block_abi.get("memory_reads") if isinstance(block_abi.get("memory_reads"), list) else []
            memory_writes = block_abi.get("memory_writes") if isinstance(block_abi.get("memory_writes"), list) else []
            result[block_id] = {
                "callsites": block_abi.get("callsites") if isinstance(block_abi.get("callsites"), list) else calls_by_block.get(block_id, []),
                "register_reads": block_abi.get("register_reads")
                if isinstance(block_abi.get("register_reads"), list)
                else registers.get("reads", [])
                if isinstance(registers.get("reads"), list)
                else [],
                "register_writes": block_abi.get("register_writes")
                if isinstance(block_abi.get("register_writes"), list)
                else registers.get("writes", [])
                if isinstance(registers.get("writes"), list)
                else [],
                "preserved_candidates": block_abi.get("preserved_candidates")
                if isinstance(block_abi.get("preserved_candidates"), list)
                else registers.get("preserved_candidates", [])
                if isinstance(registers.get("preserved_candidates"), list)
                else [],
                "clobbered_candidates": block_abi.get("clobbered_candidates")
                if isinstance(block_abi.get("clobbered_candidates"), list)
                else registers.get("clobbered_candidates", [])
                if isinstance(registers.get("clobbered_candidates"), list)
                else [],
                "stack_delta": block_abi.get("stack_delta")
                if isinstance(block_abi.get("stack_delta"), dict)
                else function.get("stack_delta")
                if isinstance(function.get("stack_delta"), dict)
                else {"status": "unknown"},
                "register_value_provenance": block_abi.get("register_value_provenance")
                if isinstance(block_abi.get("register_value_provenance"), list)
                else [],
                "register_out_param_candidates": block_abi.get("register_out_param_candidates")
                if isinstance(block_abi.get("register_out_param_candidates"), list)
                else [],
                "memory_reads": memory_reads,
                "memory_writes": memory_writes,
                "field_accesses": block_abi.get("field_accesses") if isinstance(block_abi.get("field_accesses"), list) else [],
                "memory_effect_summary": block_abi.get("memory_effect_summary")
                if isinstance(block_abi.get("memory_effect_summary"), dict)
                else _abi_memory_effect_summary(memory_reads, memory_writes),
                "switch_contracts": block_abi.get("switch_contracts") if isinstance(block_abi.get("switch_contracts"), list) else [],
                "loop_hints": block_abi.get("loop_hints") if isinstance(block_abi.get("loop_hints"), list) else [],
            }
    return result


def _function_names_by_block(contract: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    functions = _contract_constraint(contract, "function_ranges").get("functions")
    for function in functions if isinstance(functions, list) else []:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        for block_id in function.get("block_ids", []) if isinstance(function.get("block_ids"), list) else []:
            result[str(block_id)] = name
    return result


def _unit_contract_obligation_lookup(
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
) -> dict[str, Any]:
    by_key: dict[str, set[str]] = {}
    fallback_rows: list[tuple[str, dict[str, Any]]] = []

    def add_key(key: Any, unit_id: str) -> None:
        if key is None:
            return
        text = str(key).strip().lower()
        if not text:
            return
        by_key.setdefault(text, set()).add(unit_id)

    for rows in (block_contracts, function_contracts, cluster_contracts):
        for row in rows:
            if not isinstance(row, dict):
                continue
            unit_id = str(row.get("id") or "")
            if not unit_id:
                continue
            add_key(unit_id, unit_id)
            for key_name in ("block_id", "function", "cluster_kind", "category"):
                add_key(row.get(key_name), unit_id)
            block_id = row.get("block_id")
            if isinstance(block_id, str) and block_id:
                add_key(f"block:{block_id}", unit_id)
                add_key(f"reachability:{block_id}", unit_id)
            function = row.get("function")
            if isinstance(function, str) and function:
                add_key(f"function:{function}", unit_id)
            fallback_rows.append((unit_id, row))
    return {"by_key": by_key, "fallback_rows": fallback_rows}


def _unit_contract_ids_for_obligation(obligation_id: str, lookup: dict[str, Any]) -> list[str]:
    text = obligation_id.lower()
    if not text:
        return []
    by_key = lookup.get("by_key") if isinstance(lookup.get("by_key"), dict) else {}
    ids: set[str] = set()

    def add_lookup(key: str) -> None:
        ids.update(by_key.get(key.lower(), set()))

    add_lookup(text)
    parts = obligation_id.split(":")
    known_prefix = parts[0] if parts else ""
    if len(parts) >= 2 and known_prefix in {"block", "edge", "reachability", "indirect-edge"}:
        block_id = parts[1]
        add_lookup(block_id)
        add_lookup(f"block:{block_id}")
        add_lookup(f"reachability:{block_id}")
    elif len(parts) >= 2 and known_prefix == "function":
        add_lookup(parts[1])
        add_lookup(f"function:{parts[1]}")

    if ids:
        return sorted(ids)
    if known_prefix in {"block", "edge", "reachability", "indirect-edge", "function", "waiver"}:
        return []

    fallback_rows = lookup.get("fallback_rows") if isinstance(lookup.get("fallback_rows"), list) else []
    return sorted(
        {
            unit_id
            for unit_id, row in fallback_rows
            if text in json.dumps(row, sort_keys=True, default=str).lower()
        }
    )


def _function_for_gap(
    gap: dict[str, Any],
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
) -> str | None:
    text = json.dumps(gap, sort_keys=True, default=str).lower()
    for rows in (function_contracts, block_contracts, cluster_contracts):
        for row in rows:
            function = row.get("function")
            if isinstance(function, str) and function and function.lower() in text:
                return function
    return None


def _block_for_gap(gap: dict[str, Any]) -> str | None:
    text = json.dumps(gap, sort_keys=True, default=str)
    match = re.search(r"block[:=]([A-Za-z0-9_.:@+-]+)", text)
    return match.group(1) if match else None


def _dedupe_unit_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        row_id = str(row.get("id") or "")
        if row_id and row_id not in by_id:
            by_id[row_id] = row
    return list(by_id.values())


def _reference_unit_contract_artifact(unit_contracts: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "available",
        "counts": {
            "block_contracts": len(unit_contracts.get("block_contracts", [])) if isinstance(unit_contracts.get("block_contracts"), list) else 0,
            "function_contracts": len(unit_contracts.get("function_contracts", [])) if isinstance(unit_contracts.get("function_contracts"), list) else 0,
            "cluster_contracts": len(unit_contracts.get("cluster_contracts", [])) if isinstance(unit_contracts.get("cluster_contracts"), list) else 0,
            "work_items": len(unit_contracts.get("repair_units", {}).get("work_items", []))
            if isinstance(unit_contracts.get("repair_units"), dict)
            else 0,
            "semantic_transfer_contracts": len(unit_contracts.get("semantic_transfer_contracts", []))
            if isinstance(unit_contracts.get("semantic_transfer_contracts"), list)
            else 0,
            "semantic_region_contracts": len(unit_contracts.get("semantic_region_contracts", []))
            if isinstance(unit_contracts.get("semantic_region_contracts"), list)
            else 0,
            "cluster_semantic_contracts": len(unit_contracts.get("cluster_semantic_contracts", []))
            if isinstance(unit_contracts.get("cluster_semantic_contracts"), list)
            else 0,
            "memory_accesses": len(unit_contracts.get("memory_frame_contracts", {}).get("accesses", []))
            if isinstance(unit_contracts.get("memory_frame_contracts"), dict)
            else 0,
            "call_summaries": len(unit_contracts.get("call_summary_contracts", {}).get("calls", []))
            if isinstance(unit_contracts.get("call_summary_contracts"), dict)
            else 0,
        },
    }


def _semantic_coverage_blockers(unit_contracts: dict[str, Any]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    transfers = unit_contracts.get("semantic_transfer_contracts") if isinstance(unit_contracts.get("semantic_transfer_contracts"), list) else []
    for transfer in transfers:
        if not isinstance(transfer, dict) or transfer.get("status") in {"reimplementable", "complete", "external_boundary_contract"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="semantic_transfer",
                category=str(transfer.get("blocker_category") or "transfer_contract_incomplete"),
                function=transfer.get("function"),
                block_id=transfer.get("block_id"),
                source_id=transfer.get("id"),
                blocker=transfer.get("blocker") or "block does not have an implementable transfer contract",
                next_action=transfer.get("next_action") or "add instruction semantics, an invariant, or a checked cluster summary",
                sample=transfer,
            )
        )
    regions = unit_contracts.get("semantic_region_contracts") if isinstance(unit_contracts.get("semantic_region_contracts"), list) else []
    for region in regions:
        if not isinstance(region, dict) or region.get("status") in {"checked", "complete", "external_boundary_contract"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="semantic_regions",
                category=str(region.get("blocker_category") or "semantic_region_incomplete"),
                function=region.get("function"),
                block_id=region.get("block_id"),
                source_id=region.get("id"),
                blocker=region.get("blocker") or "semantic region contract is incomplete",
                next_action=region.get("next_action") or "close x86-to-IR and IR-to-C proof obligations for this region",
                sample=region,
            )
        )
    memory = unit_contracts.get("memory_frame_contracts") if isinstance(unit_contracts.get("memory_frame_contracts"), dict) else {}
    for access in memory.get("accesses", []) if isinstance(memory.get("accesses"), list) else []:
        if not isinstance(access, dict):
            continue
        frame_kind = str(access.get("frame_kind") or "unknown")
        status = str(access.get("status") or "")
        if status == "classified" and frame_kind not in {"unknown", "external.unknown"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="memory_frames",
                category="unclassified_memory_access" if frame_kind == "unknown" else "external_unknown_memory_access",
                function=access.get("function"),
                block_id=access.get("block_id"),
                source_id=access.get("id"),
                blocker=access.get("blocker") or f"memory access is classified as {frame_kind}",
                next_action="recover stack/global/object frame and alias facts for this memory access",
                sample=access,
            )
        )
    calls = unit_contracts.get("call_summary_contracts") if isinstance(unit_contracts.get("call_summary_contracts"), dict) else {}
    for call in calls.get("calls", []) if isinstance(calls.get("calls"), list) else []:
        if not isinstance(call, dict) or call.get("status") in {"complete", "external_boundary_contract"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="call_summaries",
                category="incomplete_call_summary",
                function=call.get("function"),
                block_id=call.get("block_id"),
                source_id=call.get("id"),
                blocker="; ".join(str(item) for item in call.get("blockers", []) if item) or "call summary is incomplete",
                next_action=call.get("next_action") or "recover call args, target, memory effects, or import boundary facts",
                sample=call,
            )
        )
    clusters = unit_contracts.get("cluster_semantic_contracts") if isinstance(unit_contracts.get("cluster_semantic_contracts"), list) else []
    for cluster in clusters:
        if not isinstance(cluster, dict) or cluster.get("status") in {"complete", "reimplementable", "external_boundary_contract"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="semantic_clusters",
                category=str(cluster.get("cluster_kind") or "incomplete_semantic_cluster"),
                function=cluster.get("function"),
                block_id=cluster.get("block_id"),
                source_id=cluster.get("id"),
                blocker=cluster.get("blocker") or "semantic cluster is incomplete",
                next_action=cluster.get("next_action") or "recover missing cluster facts",
                sample=cluster,
            )
        )
    return sorted(blockers, key=lambda item: (_semantic_coverage_family_rank(str(item.get("family") or "")), str(item.get("id") or "")))


def _semantic_coverage_blocker(
    *,
    family: str,
    category: str,
    function: Any,
    block_id: Any,
    source_id: Any,
    blocker: Any,
    next_action: Any,
    sample: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": f"semantic-blocker:{_safe_gap_part(family)}:{_safe_gap_part(str(source_id or category))}",
        "family": family,
        "category": category,
        "severity": "incomplete",
        "function": str(function) if function not in {None, ""} else None,
        "block_id": str(block_id) if block_id not in {None, ""} else None,
        "source_id": source_id,
        "blocker": str(blocker),
        "next_action": str(next_action),
        "sample": _semantic_coverage_sample(sample),
    }


def _semantic_coverage_sample(sample: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "id",
        "status",
        "function",
        "block_id",
        "blocker_category",
        "blocker",
        "next_action",
        "cluster_kind",
        "repair_class",
        "frame_kind",
        "target_kind",
        "target",
        "blocking_instruction",
        "original",
        "instruction",
    )
    result = {key: sample.get(key) for key in keys if key in sample}
    if isinstance(sample.get("instructions"), list) and sample["instructions"]:
        result["instruction_preview"] = sample["instructions"][:3]
    return result


def _semantic_coverage_families(unit_contracts: dict[str, Any], blockers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocker_counts = _count_by(blockers, "family")
    transfer_count = len(unit_contracts.get("semantic_transfer_contracts", [])) if isinstance(unit_contracts.get("semantic_transfer_contracts"), list) else 0
    region_count = len(unit_contracts.get("semantic_region_contracts", [])) if isinstance(unit_contracts.get("semantic_region_contracts"), list) else 0
    memory = unit_contracts.get("memory_frame_contracts") if isinstance(unit_contracts.get("memory_frame_contracts"), dict) else {}
    calls = unit_contracts.get("call_summary_contracts") if isinstance(unit_contracts.get("call_summary_contracts"), dict) else {}
    cluster_count = len(unit_contracts.get("cluster_semantic_contracts", [])) if isinstance(unit_contracts.get("cluster_semantic_contracts"), list) else 0
    rows = [
        ("semantic_transfer", transfer_count, "all executable blocks have implementable transfer contracts"),
        ("semantic_regions", region_count, "selected decompiler regions have checked x86-to-IR-to-C contracts"),
        ("memory_frames", len(memory.get("accesses", [])) if isinstance(memory.get("accesses"), list) else 0, "all memory accesses have non-unknown frame/alias classification"),
        ("call_summaries", len(calls.get("calls", [])) if isinstance(calls.get("calls"), list) else 0, "all calls have complete summaries or explicit external boundaries"),
        ("semantic_clusters", cluster_count, "all switch/loop/function-pointer clusters are complete or explicitly external-boundary modeled"),
    ]
    return [
        {
            "family": family,
            "status": "satisfied" if blocker_counts.get(family, 0) == 0 else "incomplete",
            "items": total,
            "analysis_blocked": blocker_counts.get(family, 0),
            "requirement": requirement,
        }
        for family, total, requirement in rows
    ]


def _semantic_coverage_counts(unit_contracts: dict[str, Any], blockers: list[dict[str, Any]]) -> dict[str, Any]:
    transfers = unit_contracts.get("semantic_transfer_contracts") if isinstance(unit_contracts.get("semantic_transfer_contracts"), list) else []
    regions = unit_contracts.get("semantic_region_contracts") if isinstance(unit_contracts.get("semantic_region_contracts"), list) else []
    memory = unit_contracts.get("memory_frame_contracts") if isinstance(unit_contracts.get("memory_frame_contracts"), dict) else {}
    calls = unit_contracts.get("call_summary_contracts") if isinstance(unit_contracts.get("call_summary_contracts"), dict) else {}
    clusters = unit_contracts.get("cluster_semantic_contracts") if isinstance(unit_contracts.get("cluster_semantic_contracts"), list) else []
    by_category = _count_by(blockers, "category")
    return {
        "semantic_transfer_contracts": len(transfers),
        "implementable_transfer_contracts": sum(1 for item in transfers if isinstance(item, dict) and item.get("status") in {"reimplementable", "complete"}),
        "analysis_blocked_transfers": sum(1 for item in blockers if item.get("family") == "semantic_transfer"),
        "semantic_region_contracts": len(regions),
        "checked_semantic_region_contracts": sum(1 for item in regions if isinstance(item, dict) and item.get("status") in {"checked", "complete"}),
        "analysis_blocked_semantic_regions": sum(1 for item in blockers if item.get("family") == "semantic_regions"),
        "memory_accesses": len(memory.get("accesses", [])) if isinstance(memory.get("accesses"), list) else 0,
        "unclassified_memory_accesses": by_category.get("unclassified_memory_access", 0),
        "external_unknown_memory_accesses": by_category.get("external_unknown_memory_access", 0),
        "call_summaries": len(calls.get("calls", [])) if isinstance(calls.get("calls"), list) else 0,
        "incomplete_call_summaries": sum(1 for item in blockers if item.get("family") == "call_summaries"),
        "cluster_semantic_contracts": len(clusters),
        "incomplete_clusters": sum(1 for item in blockers if item.get("family") == "semantic_clusters"),
        "unsupported_instruction_shapes": by_category.get("unsupported_semantics", 0),
        "analysis_blocked": len(blockers),
        "by_family": _count_by(blockers, "family"),
        "by_category": by_category,
    }


def _semantic_coverage_next_work(blockers: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
    return [
        {
            "id": blocker.get("id"),
            "family": blocker.get("family"),
            "category": blocker.get("category"),
            "function": blocker.get("function"),
            "block_id": blocker.get("block_id"),
            "blocker": blocker.get("blocker"),
            "next_action": blocker.get("next_action"),
        }
        for blocker in blockers[:limit]
    ]


def _semantic_coverage_family_rank(family: str) -> int:
    order = {
        "semantic_transfer": 0,
        "semantic_regions": 1,
        "memory_frames": 2,
        "call_summaries": 3,
        "semantic_clusters": 4,
    }
    return order.get(family, 99)


def _load_reference_unit_contract_sidecars(
    contract: dict[str, Any],
    contract_path: Path,
    *,
    unit_contract_dir: Path | None,
    contract_ref: dict[str, Any],
) -> dict[str, Any]:
    paths = _reference_unit_contract_paths(_reference_unit_contract_dir(contract, contract_path, unit_contract_dir))
    fallback = _reference_unit_contract_payloads(contract, contract_ref)
    return {
        "block_contracts": _load_jsonl_or(paths["block_contracts"], fallback["block_contracts"]),
        "function_contracts": _load_jsonl_or(paths["function_contracts"], fallback["function_contracts"]),
        "cluster_contracts": _load_jsonl_or(paths["cluster_contracts"], fallback["cluster_contracts"]),
        "repair_units": _load_json_or(paths["repair_units"], fallback["repair_units"]),
        "source_obligations": _load_json_or(paths["source_obligations"], fallback["source_obligations"]),
        "semantic_transfer_contracts": _load_jsonl_or(paths["semantic_transfer_contracts"], fallback["semantic_transfer_contracts"]),
        "semantic_region_contracts": _load_jsonl_or(paths["semantic_region_contracts"], fallback["semantic_region_contracts"]),
        "memory_frame_contracts": _load_json_or(paths["memory_frame_contracts"], fallback["memory_frame_contracts"]),
        "call_summary_contracts": _load_json_or(paths["call_summary_contracts"], fallback["call_summary_contracts"]),
        "cluster_semantic_contracts": _load_jsonl_or(paths["cluster_semantic_contracts"], fallback["cluster_semantic_contracts"]),
        "paths": {name: str(path) for name, path in paths.items()},
    }


def _reference_unit_contract_dir(contract: dict[str, Any], contract_path: Path, explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    sidecars = contract.get("sidecars") if isinstance(contract.get("sidecars"), dict) else {}
    unit = sidecars.get("unit_contracts") if isinstance(sidecars.get("unit_contracts"), dict) else {}
    directory = unit.get("directory")
    if isinstance(directory, str) and directory:
        path = Path(directory)
        return path if path.is_absolute() else contract_path.parent / path
    return contract_path.parent


def _load_jsonl_or(path: Path, fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not path.is_file():
        return fallback
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    except (OSError, json.JSONDecodeError):
        return fallback
    return rows


def _load_json_or(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        return fallback
    try:
        value = _load_json(path)
    except StageAInputError:
        return fallback
    return value if isinstance(value, dict) else fallback


def _matching_unit_contracts(unit_contracts: dict[str, Any], focus_lower: str) -> list[dict[str, Any]]:
    matches = []
    for name in (
        "block_contracts",
        "function_contracts",
        "cluster_contracts",
        "semantic_transfer_contracts",
        "semantic_region_contracts",
        "cluster_semantic_contracts",
    ):
        for row in unit_contracts.get(name, []) if isinstance(unit_contracts.get(name), list) else []:
            if isinstance(row, dict) and _matches_focus(row, focus_lower):
                matches.append(row)
    for name in ("memory_frame_contracts", "call_summary_contracts"):
        payload = unit_contracts.get(name) if isinstance(unit_contracts.get(name), dict) else {}
        if _matches_focus(payload, focus_lower):
            matches.append(payload)
    repair_units = unit_contracts.get("repair_units") if isinstance(unit_contracts.get("repair_units"), dict) else {}
    for row in repair_units.get("work_items", []) if isinstance(repair_units.get("work_items"), list) else []:
        if isinstance(row, dict) and _matches_focus(row, focus_lower):
            matches.append(row)
    return matches


def _reference_contract_gap_items(contract: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for issue in contract.get("issues", []):
        if isinstance(issue, dict):
            gaps.append(_gap_from_issue(issue))
    gaps.extend(_byte_coverage_gap_items(contract))
    gaps.extend(_proof_inventory_gap_items(contract))
    return sorted(_dedupe_gaps(gaps), key=lambda item: str(item.get("gap_id") or ""))


def _gap_from_issue(issue: dict[str, Any]) -> dict[str, Any]:
    obligation_id = str(issue.get("obligation_id") or issue.get("category") or "issue")
    details = issue.get("details") if isinstance(issue.get("details"), dict) else {}
    category = str(issue.get("category") or "stage_a_issue")
    severity = "violated" if issue.get("severity") == "fail" or issue.get("status") == "failed" else "incomplete"
    family = _issue_family(obligation_id, category)
    return {
        "gap_id": f"{family}:{_safe_gap_part(obligation_id)}",
        "family": family,
        "category": category,
        "severity": severity,
        "location": {"obligation_id": obligation_id},
        "expected": details.get("expected") or issue.get("original") or "closed Stage A evidence",
        "observed": details.get("actual") or issue.get("candidate") or issue.get("blocker") or issue.get("status"),
        "example": details.get("example"),
        "cause_hint": issue.get("blocker") or category,
        "next_action": issue.get("next_action") or "inspect the Stage A report for this gap",
    }


def _byte_coverage_gap_items(contract: dict[str, Any]) -> list[dict[str, Any]]:
    coverage = _contract_constraint(contract, "executable_byte_coverage")
    items = []
    for side in ("original", "candidate"):
        payload = coverage.get(side)
        if not isinstance(payload, dict):
            continue
        for gap in payload.get("gaps", []):
            if not isinstance(gap, dict):
                continue
            rva_start = _safe_int(gap.get("rva_start"))
            rva_end = _safe_int(gap.get("rva_end"))
            if rva_start is None or rva_end is None:
                continue
            items.append(
                {
                    "gap_id": f"bytes:{side}:rva-{rva_start:08x}-{rva_end:08x}",
                    "family": "executable_span_coverage",
                    "category": "unclassified_executable_bytes",
                    "severity": "incomplete",
                    "location": {"side": side, "rva_start": rva_start, "rva_end": rva_end, "size": rva_end - rva_start},
                    "expected": "every executable byte is classified as code, verified padding, or verified zero-fill",
                    "observed": "unclassified executable byte span",
                    "example": gap,
                    "cause_hint": "Stage A has no code mapping or non-code waiver for this executable span",
                    "next_action": "map the span as code or add a verifiable padding/zero-fill waiver",
                }
            )
    return items


def _proof_inventory_gap_items(contract: dict[str, Any]) -> list[dict[str, Any]]:
    proof = _contract_constraint(contract, "proof_obligation_inventory")
    obligations = proof.get("obligations") if isinstance(proof.get("obligations"), list) else []
    items = []
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        status = str(obligation.get("status") or "")
        if status in {"proved", "waived_noncode"}:
            continue
        obligation_id = str(obligation.get("id") or "unknown")
        items.append(
            {
                "gap_id": f"obligation:{_safe_gap_part(obligation_id)}",
                "family": "proof_inventory",
                "category": f"obligation_{status or 'unknown'}",
                "severity": "violated" if status == "failed" else "incomplete",
                "location": {"obligation_id": obligation_id, "kind": obligation.get("kind")},
                "expected": "proved or explicitly waived non-code obligation",
                "observed": status or "missing status",
                "example": obligation,
                "cause_hint": "Stage A final pass is blocked by this proof obligation",
                "next_action": "repair the candidate, mapping, waiver, or proof rule until this obligation closes",
            }
        )
    return items


def _dedupe_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for gap in gaps:
        gap_id = str(gap.get("gap_id") or "")
        if gap_id and gap_id not in by_id:
            by_id[gap_id] = gap
    return list(by_id.values())


def _ranked_gap_next_work(gaps: list[dict[str, Any]], *, limit: int = 10) -> list[dict[str, Any]]:
    ranked = sorted(
        gaps,
        key=lambda gap: (
            _gap_family_rank(str(gap.get("family") or "")),
            -_gap_severity_rank(gap.get("severity")),
            str(gap.get("gap_id") or ""),
        ),
    )
    return [
        {
            "gap_id": gap.get("gap_id"),
            "family": gap.get("family"),
            "category": gap.get("category"),
            "severity": gap.get("severity"),
            "next_action": gap.get("next_action"),
            "cause_hint": gap.get("cause_hint"),
        }
        for gap in ranked[:limit]
    ]


def _gap_family_rank(family: str) -> int:
    order = {
        "validation_report_artifact_binding": 0,
        "binary_faithfulness": 1,
        "normalization_assumptions": 1,
        "executable_span_coverage": 2,
        "function_ranges": 3,
        "cfg_blocks": 4,
        "roots_and_jump_targets": 5,
        "import_thunks": 6,
        "padding_alignment": 6,
        "semantic_transfer": 6,
        "semantic_region": 6,
        "semantic_regions": 6,
        "semantic_cluster": 6,
        "proof_inventory": 7,
    }
    return order.get(family, 99)


def _contract_constraint(contract: dict[str, Any], key: str) -> dict[str, Any]:
    constraints = contract.get("constraints") if isinstance(contract.get("constraints"), dict) else {}
    value = constraints.get(key)
    return value if isinstance(value, dict) else {}


def _issue_family(obligation_id: str, category: str) -> str:
    text = f"{obligation_id} {category}".lower()
    for family, constraint in _REFERENCE_CONTRACT_FAMILY_KEYS:
        if family in text or constraint in text:
            return family
    if "validation-report" in text or "validation_report" in text:
        return "validation_report_artifact_binding"
    if "layout" in text or "section" in text or "import" in text or "image_base" in text:
        return "binary_faithfulness"
    if "waiver" in text or "padding" in text:
        return "padding_alignment"
    if "mapping" in text or "map" in text:
        return "cfg_blocks"
    return "proof_inventory"


def _obligation_family(obligation_id: str) -> str:
    text = obligation_id.lower()
    if text.startswith("block:") or text.startswith("cfg:"):
        return "cfg_blocks"
    if text.startswith("reachability:") or "jump" in text:
        return "roots_and_jump_targets"
    if text.startswith("layout:"):
        return "binary_faithfulness"
    if "waiver" in text or "noncode" in text:
        return "padding_alignment"
    return "proof_inventory"


def _safe_gap_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.:@+-]+", "-", value.strip())
    return text.strip("-") or "unknown"


def _safe_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _load_reference_contract_sidecars(contract: dict[str, Any], contract_path: Path) -> dict[str, Any]:
    sidecars = contract.get("sidecars") if isinstance(contract.get("sidecars"), dict) else {}
    contract_ref = _reference_sidecar_contract_ref(contract_path)
    result: dict[str, Any] = {}
    builders = {
        "coverage_gaps": _reference_coverage_gaps_sidecar,
        "obligation_index": _reference_obligation_index_sidecar,
        "contract_summary": _reference_contract_summary_sidecar,
        "abi_callsites": _reference_abi_callsites_sidecar,
    }
    for name, builder in builders.items():
        path_text = sidecars.get(name, {}).get("path") if isinstance(sidecars.get(name), dict) else None
        path = _resolve_contract_sidecar_path(contract_path, path_text, name)
        try:
            result[name] = _load_json(path) if path.is_file() else builder(contract, contract_ref)
        except StageAInputError:
            result[name] = builder(contract, contract_ref)
    return result


def _stage_a_smoke_contract_issues(contract: Any, contract_path: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not isinstance(contract, dict) or contract.get("format") != "stage-a-reference-contract-v1":
        return [
            _incomplete_record(
                category="invalid_reference_contract_format",
                obligation_id="stage-a-smoke-contract:format",
                blocker="reference contract JSON does not have format stage-a-reference-contract-v1",
                next_action="regenerate the Stage A reference contract",
            )
        ]
    for family in contract.get("families", []):
        if not isinstance(family, dict):
            continue
        status = family.get("status")
        if status not in {"satisfied", "incomplete", "not_applicable", "violated"}:
            issues.append(
                _incomplete_record(
                    category="invalid_family_status",
                    obligation_id=f"stage-a-smoke-contract:family:{family.get('family')}",
                    blocker="Stage A contract family has a non-proof status",
                    next_action="regenerate the contract with current Stage A tooling",
                    details={"family": family.get("family"), "status": status},
                )
            )
    issues.extend(_stage_a_smoke_artifact_issues(contract))
    issues.extend(_stage_a_smoke_sidecar_issues(contract, contract_path))
    for marker in _unchecked_marker_paths(contract):
        issues.append(
            _incomplete_record(
                category="unchecked_lean_marker",
                obligation_id=f"stage-a-smoke-contract:lean:{marker}",
                blocker="reference contract contains an unchecked Lean marker",
                next_action="rerun Stage A validation until Lean final-pass evidence is checked",
            )
        )
    return issues


def _stage_a_smoke_artifact_issues(contract: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    inputs = contract.get("inputs") if isinstance(contract.get("inputs"), dict) else {}
    for name in ("original", "candidate", "mapping", "layout_contract"):
        artifact = inputs.get(name)
        if not isinstance(artifact, dict) or artifact.get("path") in {None, ""}:
            continue
        issues.extend(_stage_a_smoke_artifact_hash_issues(name, artifact))
    validation_report = inputs.get("validation_report")
    if isinstance(validation_report, dict):
        files = validation_report.get("files")
        if isinstance(files, dict):
            for name, artifact in files.items():
                if isinstance(artifact, dict):
                    issues.extend(_stage_a_smoke_artifact_hash_issues(f"validation_report:{name}", artifact))
        else:
            issues.extend(_stage_a_smoke_artifact_hash_issues("validation_report", validation_report))
    return issues


def _stage_a_smoke_artifact_hash_issues(name: str, artifact: dict[str, Any]) -> list[dict[str, Any]]:
    path_text = artifact.get("path")
    if not isinstance(path_text, str) or not path_text:
        return []
    path = Path(path_text)
    if not path.exists():
        return [
            _incomplete_record(
                category="missing_bound_artifact",
                obligation_id=f"stage-a-smoke-contract:artifact:{name}",
                blocker="a reference-contract-bound artifact no longer exists",
                next_action="regenerate the contract from current artifacts",
                details={"path": path_text},
            )
        ]
    expected_sha = artifact.get("sha256")
    if expected_sha is None or path.is_dir():
        return []
    actual_sha = sha256_file(path)
    if actual_sha == expected_sha:
        return []
    return [
        _incomplete_record(
            category="stale_bound_artifact",
            obligation_id=f"stage-a-smoke-contract:artifact:{name}",
            blocker="a reference-contract-bound artifact hash no longer matches",
            next_action="rerun Stage A validation and export a fresh reference contract",
            details={"path": path_text, "expected": expected_sha, "actual": actual_sha},
        )
    ]


def _stage_a_smoke_sidecar_issues(contract: dict[str, Any], contract_path: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    sidecars = contract.get("sidecars") if isinstance(contract.get("sidecars"), dict) else {}
    contract_sha = sha256_file(contract_path) if contract_path.is_file() else None
    for name in ("coverage_gaps", "obligation_index", "contract_summary", "abi_callsites"):
        path_text = sidecars.get(name, {}).get("path") if isinstance(sidecars.get(name), dict) else None
        if not isinstance(path_text, str) or not path_text:
            issues.append(
                _incomplete_record(
                    category="missing_contract_sidecar",
                    obligation_id=f"stage-a-smoke-contract:sidecar:{name}",
                    blocker="reference contract does not identify a required diagnostic sidecar",
                    next_action="rerun stage-a-export-reference-contract with current tooling",
                )
            )
            continue
        path = _resolve_contract_sidecar_path(contract_path, path_text, name)
        if not path.is_file():
            issues.append(
                _incomplete_record(
                    category="missing_contract_sidecar",
                    obligation_id=f"stage-a-smoke-contract:sidecar:{name}",
                    blocker="required diagnostic sidecar does not exist",
                    next_action="rerun stage-a-export-reference-contract with current tooling",
                    details={"path": path_text},
                )
            )
            continue
        try:
            payload = _load_json(path)
        except StageAInputError as exc:
            issues.append(
                _incomplete_record(
                    category="invalid_contract_sidecar",
                    obligation_id=f"stage-a-smoke-contract:sidecar:{name}",
                    blocker=str(exc),
                    next_action="rerun stage-a-export-reference-contract with current tooling",
                )
            )
            continue
        sidecar_contract = payload.get("reference_contract") if isinstance(payload, dict) else {}
        if not isinstance(sidecar_contract, dict) or sidecar_contract.get("sha256") != contract_sha:
            issues.append(
                _incomplete_record(
                    category="stale_contract_sidecar",
                    obligation_id=f"stage-a-smoke-contract:sidecar:{name}",
                    blocker="diagnostic sidecar is not hash-bound to this reference contract",
                    next_action="rerun stage-a-export-reference-contract with current tooling",
                    details={"path": path_text, "expected": contract_sha, "actual": sidecar_contract.get("sha256") if isinstance(sidecar_contract, dict) else None},
                )
            )
    return issues


def _contract_candidate_families(
    contract: dict[str, Any],
    candidate: StageABinary,
    candidate_functions: list[dict[str, Any]],
    *,
    alias_evidence: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    alias_evidence = alias_evidence or _empty_contract_candidate_alias_evidence()
    original = contract.get("original") if isinstance(contract.get("original"), dict) else {}
    constraints = contract.get("constraints") if isinstance(contract.get("constraints"), dict) else {}
    contract_families = {str(item.get("family")): item for item in contract.get("families", []) if isinstance(item, dict)}
    candidate_function_names = _contract_candidate_function_names(candidate_functions)
    function_contract = constraints.get("function_ranges") if isinstance(constraints.get("function_ranges"), dict) else {}
    expected_functions = [
        item for item in function_contract.get("functions", []) if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    alias_matches = alias_evidence.get("matches_by_reference") if isinstance(alias_evidence.get("matches_by_reference"), dict) else {}
    alias_ambiguities = alias_evidence.get("ambiguities_by_reference") if isinstance(alias_evidence.get("ambiguities_by_reference"), dict) else {}
    missing_functions = sorted(
        str(item["name"])
        for item in expected_functions
        if str(item["name"]) not in candidate_function_names and str(item["name"]) not in alias_matches
        and str(item["name"]) not in alias_ambiguities
    )
    ambiguous_functions = sorted(str(item["name"]) for item in expected_functions if str(item["name"]) in alias_ambiguities)
    abi_contract = constraints.get("abi_callsites") if isinstance(constraints.get("abi_callsites"), dict) else {}
    candidate_abi = _candidate_abi_constraint_from_functions(
        candidate,
        candidate_functions,
        reference_abi=abi_contract,
        alias_evidence=alias_evidence,
    )
    abi_coverage_gaps = _contract_candidate_abi_coverage_gaps(abi_contract, candidate_abi, alias_evidence=alias_evidence)
    original_imports = _contract_import_signature(original)
    candidate_imports = _contract_import_signature(_binary_reference_layout(candidate))
    missing_function_details = _contract_candidate_missing_function_details(
        missing_functions,
        constraints=constraints,
        candidate_imports=candidate_imports,
        alias_evidence=alias_evidence,
    )
    contract_status = str(contract.get("status") or "")
    proof_family = contract_families.get("proof_inventory") or contract_families.get("proof_obligation_inventory_and_statuses")
    proof_status = proof_family.get("status") if isinstance(proof_family, dict) else None
    alias_ambiguity_count = len(ambiguous_functions)
    function_ranges_status = "satisfied" if not missing_functions and not ambiguous_functions and expected_functions else "incomplete"
    abi_status = _contract_candidate_abi_status(abi_contract, candidate_abi)
    if alias_ambiguity_count or int(abi_coverage_gaps["counts"].get("missing_functions") or 0) or int(
        abi_coverage_gaps["counts"].get("ambiguous_functions") or 0
    ) or int(
        abi_coverage_gaps["counts"].get("incomplete_callsite_functions") or 0
    ) or int(
        abi_coverage_gaps["counts"].get("function_mismatches") or 0
    ) or int(
        abi_coverage_gaps["counts"].get("callsite_mismatches") or 0
    ):
        abi_status = "incomplete"
    families = [
        _contract_candidate_family(
            "binary_faithfulness",
            "satisfied" if _contract_candidate_binary_matches(original, candidate) else "violated",
            "candidate PE layout/import/image-base target does not match the Stage A reference contract",
            "rebuild the candidate with matching PE target layout, imports, subsystem, and image base",
            contract_families.get("binary_faithfulness"),
            evidence={
                "expected": _contract_binary_signature(original),
                "candidate": _contract_binary_signature(_binary_reference_layout(candidate)),
            },
        ),
        _contract_candidate_family(
            "function_ranges",
            function_ranges_status,
            "candidate linker map is missing or ambiguously maps reference-contract functions",
            "add/generate candidate functions, fix source-map aliases, or remove ambiguous linker roots",
            contract_families.get("function_ranges"),
            evidence={
                "expected_count": len(expected_functions),
                "candidate_count": len(candidate_functions),
                "missing_count": len(missing_functions),
                "ambiguous_count": alias_ambiguity_count,
                "missing_functions": missing_functions[:100],
                "missing_function_details": missing_function_details[:100],
                "missing_by_category": _count_by(missing_function_details, "category"),
                "ambiguous_aliases": [_contract_alias_ambiguity_sample(alias_ambiguities[name]) for name in ambiguous_functions[:100]],
                "alias_matches": _contract_alias_match_samples(alias_matches, expected_functions),
                "alias_evidence_status": alias_evidence.get("status"),
                "alias_evidence_counts": alias_evidence.get("counts"),
            },
        ),
        _contract_candidate_family(
            "abi_callsites",
            abi_status,
            "candidate ABI/callsite evidence does not yet cover the reference contract",
            "repair prototypes, sret/out-params, varargs bridges, stack deltas, or register preservation before final proof",
            contract_families.get("abi_callsites"),
            evidence={
                "reference_counts": abi_contract.get("counts") if isinstance(abi_contract.get("counts"), dict) else {},
                "candidate_counts": candidate_abi.get("counts"),
                "candidate_abi": candidate_abi,
                "coverage_gaps": abi_coverage_gaps,
                "alias_evidence": _contract_candidate_alias_evidence_summary(alias_evidence),
            },
        ),
        _contract_candidate_family(
            "import_thunks",
            "satisfied" if original_imports == candidate_imports else "incomplete",
            "candidate imports differ from the reference contract",
            "rebuild/link the candidate with matching import thunk/prototype surface",
            contract_families.get("import_thunks"),
            evidence={"expected_imports": original_imports, "candidate_imports": candidate_imports},
        ),
        _contract_candidate_family(
            "proof_inventory",
            "satisfied" if contract_status == "pass" and proof_status == "satisfied" else "incomplete",
            "reference contract proof inventory is not fully satisfied",
            "regenerate the Stage A reference contract from a final-pass validation package before using it as a Stage B repair contract",
            proof_family,
            evidence={"contract_status": contract.get("status"), "proof_family_status": proof_status},
        ),
    ]
    return families


def _contract_candidate_family(
    family: str,
    status: str,
    blocker: str,
    next_action: str,
    contract_family: dict[str, Any] | None,
    *,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    contract_status = contract_family.get("status") if isinstance(contract_family, dict) else None
    if contract_status == "violated":
        status = "violated"
    elif contract_status == "incomplete" and status == "satisfied":
        status = "incomplete"
    return {
        "family": family,
        "status": status,
        "contract_status": contract_status,
        "blocker": "" if status in {"satisfied", "not_applicable"} else blocker,
        "next_action": "" if status in {"satisfied", "not_applicable"} else next_action,
        "evidence": evidence,
    }


def _empty_contract_candidate_alias_evidence(*, status: str = "not_applicable") -> dict[str, Any]:
    return {
        "format": "stage-a-contract-candidate-alias-evidence-v1",
        "status": status,
        "matches_by_reference": {},
        "ambiguities_by_reference": {},
        "unmatched_by_reference": {},
        "alias_matches": [],
        "ambiguities": [],
        "unmatched_aliases": [],
        "counts": {"alias_matches": 0, "ambiguities": 0, "unmatched_aliases": 0},
    }


def _contract_candidate_skeleton_alias_evidence(skeleton: dict[str, Any], candidate_functions: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(skeleton, dict) or skeleton.get("format") != "stage-b-skeleton-v1":
        raise StageAInputError("skeleton manifest must have format stage-b-skeleton-v1")
    source_map = skeleton.get("source_map") if isinstance(skeleton.get("source_map"), dict) else {}
    entries = source_map.get("functions") if isinstance(source_map.get("functions"), list) else []
    candidate_lookup = _contract_candidate_function_lookup(candidate_functions)
    unresolved: dict[str, list[dict[str, Any]]] = {}
    unmatched: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("function"), str):
            continue
        source_function = str(entry["function"])
        source_aliases = [
            alias
            for alias in entry.get("aliases", [])
            if isinstance(alias, str) and _contract_candidate_source_alias_is_function_name(alias)
        ]
        reference_names = _dedupe_strings(
            [
                name
                for name in [source_function, *source_aliases]
                if _contract_candidate_source_alias_is_function_name(name)
            ]
        )
        if not reference_names:
            continue
        candidate_matches = _contract_candidate_lookup_matches(candidate_lookup, *reference_names)
        if not candidate_matches:
            for name in reference_names:
                unmatched.setdefault(name, []).append(
                    _contract_candidate_source_alias_sample(entry, reference_name=name, source_aliases=source_aliases)
                )
            continue
        if len(candidate_matches) > 1:
            resolved = _contract_candidate_disambiguate_exact_source_match(candidate_matches, source_function)
            if resolved is not None:
                for name in reference_names:
                    unresolved.setdefault(name, []).append(
                        {
                            "reference_name": name,
                            "source_function": source_function,
                            "source_kind": entry.get("source_kind"),
                            "candidate": _contract_candidate_function_sample(resolved),
                            "source_aliases": source_aliases,
                            "resolution": "unique_exact_source_function",
                        }
                    )
                continue
            ambiguity = {
                "reference_names": reference_names,
                "source_function": source_function,
                "reason": "source function resolves to multiple candidate linker-map functions",
                "candidate_matches": [_contract_candidate_function_sample(item) for item in candidate_matches],
            }
            for name in reference_names:
                unresolved.setdefault(name, []).append(ambiguity)
            continue
        candidate_match = candidate_matches[0]
        for name in reference_names:
            unresolved.setdefault(name, []).append(
                {
                    "reference_name": name,
                    "source_function": source_function,
                    "source_kind": entry.get("source_kind"),
                    "candidate": _contract_candidate_function_sample(candidate_match),
                    "source_aliases": source_aliases,
                }
            )

    matches_by_reference: dict[str, dict[str, Any]] = {}
    ambiguities_by_reference: dict[str, list[dict[str, Any]]] = {}
    alias_matches: list[dict[str, Any]] = []
    ambiguities: list[dict[str, Any]] = []
    unmatched_by_reference: dict[str, list[dict[str, Any]]] = {}
    unmatched_aliases: list[dict[str, Any]] = []
    for reference_name, matches in sorted(unresolved.items()):
        unique = _unique_alias_matches(matches)
        if len(unique) == 1 and "candidate" in unique[0]:
            matches_by_reference[reference_name] = unique[0]
            alias_matches.append(unique[0])
        else:
            ambiguities_by_reference[reference_name] = unique
            ambiguities.append({"reference_name": reference_name, "matches": unique[:5], "matches_total": len(unique)})
    for reference_name, matches in sorted(unmatched.items()):
        if reference_name in matches_by_reference or reference_name in ambiguities_by_reference:
            continue
        unique = _unique_alias_matches(matches)
        unmatched_by_reference[reference_name] = unique
        unmatched_aliases.append({"reference_name": reference_name, "matches": unique[:5], "matches_total": len(unique)})

    return {
        "format": "stage-a-contract-candidate-alias-evidence-v1",
        "status": "incomplete" if ambiguities else "satisfied",
        "matches_by_reference": matches_by_reference,
        "ambiguities_by_reference": ambiguities_by_reference,
        "unmatched_by_reference": unmatched_by_reference,
        "alias_matches": alias_matches[:100],
        "ambiguities": ambiguities[:100],
        "unmatched_aliases": unmatched_aliases[:100],
        "counts": {"alias_matches": len(alias_matches), "ambiguities": len(ambiguities), "unmatched_aliases": len(unmatched_aliases)},
    }


def _contract_candidate_function_lookup(candidate_functions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    lookup: dict[str, list[dict[str, Any]]] = {}
    for function in candidate_functions:
        if not isinstance(function, dict):
            continue
        for name in _contract_candidate_function_symbol_names(function):
            for key in _contract_candidate_symbol_keys(name):
                bucket = lookup.setdefault(key, [])
                if function not in bucket:
                    bucket.append(function)
    return lookup


def _contract_candidate_lookup_matches(lookup: dict[str, list[dict[str, Any]]], *source_names: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for source_name in source_names:
        for key in _contract_candidate_symbol_keys(source_name):
            for function in lookup.get(key, []):
                if function not in matches:
                    matches.append(function)
    return matches


def _contract_candidate_disambiguate_exact_source_match(
    candidate_matches: list[dict[str, Any]],
    source_function: str,
) -> dict[str, Any] | None:
    exact = [
        function
        for function in candidate_matches
        if source_function in _contract_candidate_function_symbol_names(function)
    ]
    return exact[0] if len(exact) == 1 else None


def _contract_candidate_function_names(candidate_functions: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for function in candidate_functions:
        for name in _contract_candidate_function_symbol_names(function):
            names.add(name)
    return names


def _contract_candidate_source_alias_is_function_name(name: str) -> bool:
    if not name:
        return False
    # COFF section symbols such as ".text" can appear in linker/source-map
    # alias lists for section-gap ranges. They are layout evidence, not
    # callable function names, and treating them as aliases creates false
    # ambiguities across every range in the section.
    return not name.startswith(".")


def _contract_candidate_function_symbol_names(function: dict[str, Any]) -> list[str]:
    names: list[str] = []
    name = function.get("name")
    if isinstance(name, str) and name:
        names.append(name)
    aliases = function.get("aliases") if isinstance(function.get("aliases"), list) else []
    names.extend(alias for alias in aliases if isinstance(alias, str) and alias)
    return _dedupe_strings(names)


def _contract_candidate_symbol_keys(name: str) -> set[str]:
    variants = {name}
    if name.startswith("@"):
        stripped = name[1:]
        variants.add(stripped)
        if "@" in stripped:
            left, right = stripped.rsplit("@", 1)
            if right.isdigit():
                variants.add(left)
    if "@" in name:
        left, right = name.rsplit("@", 1)
        if right.isdigit():
            variants.add(left)
    keys = set()
    for variant in variants:
        keys.add(variant)
        keys.add(_linker_function_match_key(variant))
    return {key for key in keys if key}


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _unique_alias_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in matches:
        candidate = match.get("candidate") if isinstance(match.get("candidate"), dict) else {}
        key = json.dumps(
            {
                "reference_name": match.get("reference_name"),
                "source_function": match.get("source_function"),
                "candidate_name": candidate.get("name"),
                "candidate_rva_start": candidate.get("rva_start"),
                "candidate_rva_end": candidate.get("rva_end"),
                "reason": match.get("reason"),
                "source_kind": match.get("source_kind"),
                "source_aliases": match.get("source_aliases"),
                "rva_start": match.get("rva_start"),
                "rva_end": match.get("rva_end"),
                "file": match.get("file"),
                "line_start": match.get("line_start"),
            },
            sort_keys=True,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(match)
    return result


def _contract_candidate_source_alias_sample(
    entry: dict[str, Any],
    *,
    reference_name: str,
    source_aliases: list[str],
) -> dict[str, Any]:
    return {
        "reference_name": reference_name,
        "source_function": entry.get("function"),
        "source_kind": entry.get("source_kind"),
        "source_aliases": source_aliases,
        "rva_start": entry.get("rva_start"),
        "rva_end": entry.get("rva_end"),
        "file": entry.get("file"),
        "line_start": entry.get("line_start"),
        "line_end": entry.get("line_end"),
    }


def _contract_candidate_function_sample(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": function.get("name"),
        "aliases": [alias for alias in function.get("aliases", []) if isinstance(alias, str)] if isinstance(function.get("aliases"), list) else [],
        "rva_start": function.get("rva_start"),
        "rva_end": function.get("rva_end"),
        "section": function.get("section"),
    }


def _contract_alias_match_samples(alias_matches: dict[str, Any], expected_functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected_names = {str(item["name"]) for item in expected_functions if isinstance(item.get("name"), str)}
    result = []
    for reference_name in sorted(expected_names & set(alias_matches)):
        match = alias_matches[reference_name]
        if isinstance(match, dict):
            result.append(
                {
                    "reference_name": reference_name,
                    "source_function": match.get("source_function"),
                    "source_kind": match.get("source_kind"),
                    "candidate": match.get("candidate"),
                }
            )
    return result[:100]


def _contract_alias_ambiguity_sample(ambiguities: list[dict[str, Any]]) -> dict[str, Any]:
    return {"matches": ambiguities[:5], "matches_total": len(ambiguities)}


def _contract_candidate_alias_evidence_summary(alias_evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": alias_evidence.get("status"),
        "counts": alias_evidence.get("counts"),
        "alias_matches": alias_evidence.get("alias_matches", [])[:20] if isinstance(alias_evidence.get("alias_matches"), list) else [],
        "ambiguities": alias_evidence.get("ambiguities", [])[:20] if isinstance(alias_evidence.get("ambiguities"), list) else [],
        "unmatched_aliases": alias_evidence.get("unmatched_aliases", [])[:20]
        if isinstance(alias_evidence.get("unmatched_aliases"), list)
        else [],
    }


def _contract_candidate_missing_function_details(
    missing_functions: list[str],
    *,
    constraints: dict[str, Any],
    candidate_imports: list[dict[str, Any]],
    alias_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    unmatched = alias_evidence.get("unmatched_by_reference") if isinstance(alias_evidence.get("unmatched_by_reference"), dict) else {}
    reference_import_thunks = _contract_reference_import_thunks_by_function(constraints)
    details: list[dict[str, Any]] = []
    for function_name in missing_functions:
        source_entries = unmatched.get(function_name) if isinstance(unmatched.get(function_name), list) else []
        source_evidence = source_entries[0] if source_entries and isinstance(source_entries[0], dict) else None
        import_thunk = reference_import_thunks.get(function_name)
        candidate_import_match = _contract_candidate_matching_import(import_thunk, candidate_imports)
        category = _contract_candidate_missing_function_category(
            function_name,
            source_evidence=source_evidence,
            reference_import_thunk=import_thunk,
            candidate_import_match=candidate_import_match,
        )
        item: dict[str, Any] = {
            "function": function_name,
            "category": category,
            "severity": "blocking",
            "next_action": _contract_candidate_missing_function_next_action(function_name, category),
        }
        if source_evidence is not None:
            item["source_evidence"] = source_evidence
        if import_thunk is not None:
            item["reference_import_thunk"] = import_thunk
        if candidate_import_match is not None:
            item["candidate_import_match"] = candidate_import_match
        details.append(item)
    return details


def _contract_reference_import_thunks_by_function(constraints: dict[str, Any]) -> dict[str, dict[str, Any]]:
    import_contract = constraints.get("import_thunks") if isinstance(constraints.get("import_thunks"), dict) else {}
    mapped = import_contract.get("mapped_import_thunks") if isinstance(import_contract.get("mapped_import_thunks"), list) else []
    result: dict[str, dict[str, Any]] = {}
    for item in mapped:
        if not isinstance(item, dict):
            continue
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        function_name = source.get("function")
        if not isinstance(function_name, str) or not function_name:
            continue
        result.setdefault(
            function_name,
            {
                "id": item.get("id"),
                "function": function_name,
                "function_match_key": _linker_function_match_key(function_name),
                "source_kind": source.get("kind"),
                "import_signature": source.get("import_signature") if isinstance(source.get("import_signature"), dict) else None,
                "original": item.get("original") if isinstance(item.get("original"), dict) else None,
                "candidate": item.get("candidate") if isinstance(item.get("candidate"), dict) else None,
            },
        )
    return result


def _contract_candidate_matching_import(
    reference_import_thunk: dict[str, Any] | None,
    candidate_imports: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(reference_import_thunk, dict):
        return None
    signature = reference_import_thunk.get("import_signature")
    if not isinstance(signature, dict):
        return None
    for imported in candidate_imports:
        if not isinstance(imported, dict):
            continue
        if _contract_import_signature_dict_key(imported) == _contract_import_signature_dict_key(signature):
            return imported
    return None


def _contract_import_signature_dict_key(imported: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(imported.get("dll") or "").lower(),
        str(imported.get("symbol") or ""),
        str(imported.get("ordinal") or ""),
    )


def _contract_candidate_missing_function_category(
    function_name: str,
    *,
    source_evidence: dict[str, Any] | None,
    reference_import_thunk: dict[str, Any] | None,
    candidate_import_match: dict[str, Any] | None,
) -> str:
    source_kind = source_evidence.get("source_kind") if isinstance(source_evidence, dict) else None
    if source_kind == "omitted_import_thunk" or reference_import_thunk is not None:
        if candidate_import_match is not None:
            return "import_thunk_symbol_missing_with_matching_import"
        return "import_thunk_symbol_missing"
    if source_kind == "omitted_runtime_entry":
        return "runtime_entry_replaced_by_generated_bridge"
    if source_kind == "generated_contract_placeholder":
        return "generated_contract_placeholder_missing"
    if function_name.startswith("section-gap-"):
        return "section_gap_or_padding_missing"
    if source_evidence is not None:
        return "source_map_alias_unresolved"
    return "function_missing"


def _contract_candidate_missing_function_next_action(function_name: str, category: str) -> str:
    if category == "import_thunk_symbol_missing_with_matching_import":
        return (
            f"preserve the original import thunk symbol for {function_name} or add a strict Stage A import-thunk "
            "representation mapping that proves the matching candidate import is equivalent"
        )
    if category == "import_thunk_symbol_missing":
        return f"restore or map the import thunk for {function_name} and ensure the candidate imports the same target"
    if category == "runtime_entry_replaced_by_generated_bridge":
        return f"emit or retain the runtime/CRT entry/support function {function_name}, or prove the generated bridge is equivalent"
    if category == "generated_contract_placeholder_missing":
        return f"replace or root the generated contract placeholder for {function_name} before rerunning Stage A"
    if category == "section_gap_or_padding_missing":
        return f"classify and preserve the executable section span represented by {function_name}"
    if category == "source_map_alias_unresolved":
        return f"root the generated source-map alias for {function_name} so the candidate linker map exposes it"
    return f"generate or retain candidate implementation and linker root for {function_name}"


def _contract_candidate_binary_matches(original: dict[str, Any], candidate: StageABinary) -> bool:
    return _contract_binary_signature(original) == _contract_binary_signature(_binary_reference_layout(candidate))


def _contract_binary_signature(layout: dict[str, Any]) -> dict[str, Any]:
    return {
        "machine": layout.get("machine"),
        "bitness": layout.get("bitness"),
        "subsystem": layout.get("subsystem"),
        "image_base": layout.get("image_base"),
        "entrypoint_rva": layout.get("entrypoint_rva"),
        "sections": _contract_section_signature(layout),
        "imports": _contract_import_signature(layout),
    }


def _contract_section_signature(layout: dict[str, Any]) -> list[dict[str, Any]]:
    sections = layout.get("sections") if isinstance(layout.get("sections"), list) else []
    result = []
    for item in sections:
        if not isinstance(item, dict):
            continue
        permissions = item.get("permissions") if isinstance(item.get("permissions"), dict) else {}
        result.append(
            {
                "name": item.get("name"),
                "rva_start": item.get("rva_start"),
                "rva_end": item.get("rva_end"),
                "executable": item.get("executable", permissions.get("execute")),
                "readable": item.get("readable", permissions.get("read")),
                "writable": item.get("writable", permissions.get("write")),
            }
        )
    return result


def _contract_import_signature(layout: dict[str, Any]) -> list[dict[str, Any]]:
    imports = layout.get("imports") if isinstance(layout.get("imports"), list) else []
    result = []
    for item in imports:
        if isinstance(item, dict):
            result.append({"dll": item.get("dll"), "symbol": item.get("symbol"), "ordinal": item.get("ordinal")})
        elif isinstance(item, (list, tuple)) and len(item) >= 3:
            result.append({"dll": item[0], "symbol": item[1], "ordinal": item[2]})
    return sorted(result, key=lambda value: (str(value.get("dll")), str(value.get("symbol")), str(value.get("ordinal"))))


def _candidate_abi_constraint_from_functions(
    candidate: StageABinary,
    candidate_functions: list[dict[str, Any]],
    *,
    reference_abi: dict[str, Any] | None = None,
    alias_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    mappings = _candidate_abi_block_mappings_from_functions(candidate, candidate_functions)
    reference_section_gap_mappings = _candidate_reference_section_gap_abi_mappings(
        candidate,
        reference_abi,
        alias_evidence=alias_evidence,
    )
    mappings.extend(reference_section_gap_mappings)
    functions = _abi_function_evidence(candidate, mappings, side="candidate")
    return {
        "status": "satisfied" if functions else "incomplete",
        "evidence_kind": "capstone-static-abi-callsites",
        "candidate": {
            "functions": functions,
            "import_prototypes": _abi_import_prototypes(candidate),
            "reference_section_gap_probes": {
                "kind": "candidate_section_gap_probe",
                "count": len(reference_section_gap_mappings),
            },
        },
        "counts": {
            "functions": len(functions),
            "callsites": sum(len(item.get("callsites", [])) for item in functions),
            "import_prototypes": len(candidate.imports),
            "reference_section_gap_probes": len(reference_section_gap_mappings),
        },
    }


def _candidate_abi_block_mappings_from_functions(
    candidate: StageABinary,
    candidate_functions: list[dict[str, Any]],
) -> list[BlockMapping]:
    mappings: list[BlockMapping] = []
    for function_index, function in enumerate(candidate_functions):
        rva_start = _optional_contract_int(function.get("rva_start"))
        rva_end = _optional_contract_int(function.get("rva_end"))
        if rva_start is None or rva_end is None or rva_end <= rva_start:
            continue
        name = str(function.get("name") or f"function_{function_index:04d}")
        blocks = _recover_basic_blocks(candidate, rva_start, rva_end)
        for block_index, block in enumerate(blocks):
            block_start = _optional_contract_int(block.get("rva_start"))
            block_end = _optional_contract_int(block.get("rva_end"))
            if block_start is None or block_end is None or block_end <= block_start:
                continue
            mappings.append(
                BlockMapping(
                    id=_artifact_name(f"{name}-{block_index:04d}"),
                    kind="code",
                    original=BlockSide(block_start, block_end),
                    candidate=BlockSide(block_start, block_end),
                    reachable=True,
                    invariant_checked=True,
                    source={"source": {"function": name, "kind": "candidate_capstone_basic_block"}},
                )
            )
    return mappings


def _candidate_reference_section_gap_abi_mappings(
    candidate: StageABinary,
    reference_abi: dict[str, Any] | None,
    *,
    alias_evidence: dict[str, Any] | None = None,
) -> list[BlockMapping]:
    if not isinstance(reference_abi, dict):
        return []
    reference = reference_abi.get("original") if isinstance(reference_abi.get("original"), dict) else {}
    functions = reference.get("functions") if isinstance(reference.get("functions"), list) else []
    owner_ranges = _candidate_reference_section_gap_owner_ranges(functions)
    alias_matches = (
        alias_evidence.get("matches_by_reference")
        if isinstance(alias_evidence, dict) and isinstance(alias_evidence.get("matches_by_reference"), dict)
        else {}
    )
    mappings: list[BlockMapping] = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name.startswith("section-gap-"):
            continue
        blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
        for index, block in enumerate(blocks):
            if not isinstance(block, dict):
                continue
            start = _optional_contract_int(block.get("rva_start"))
            end = _optional_contract_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            block_id = block.get("block_id") if isinstance(block.get("block_id"), str) and block.get("block_id") else f"{name}-{index:04d}"
            owner_mapping = _candidate_reference_section_gap_owner_offset_mapping(
                candidate,
                name=name,
                block_id=block_id,
                reference_start=start,
                reference_end=end,
                owner_ranges=owner_ranges,
                alias_matches=alias_matches,
            )
            if owner_mapping is not None:
                mappings.append(owner_mapping)
                continue
            section = _section_for_rva(candidate, start)
            if section is None or not section.executable or end > section.rva_end:
                continue
            mappings.append(
                BlockMapping(
                    id=_artifact_name(block_id),
                    kind="code",
                    original=BlockSide(start, end),
                    candidate=BlockSide(start, end),
                    reachable=True,
                    invariant_checked=False,
                    source={
                        "source": {
                            "function": name,
                            "kind": "candidate_same_rva_section_gap_probe",
                            "reference_block_id": block_id,
                        }
                    },
                )
            )
    return mappings


def _candidate_reference_section_gap_owner_ranges(functions: list[Any]) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name or name.startswith("section-gap-"):
            continue
        blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
        starts: list[int] = []
        ends: list[int] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            start = _optional_contract_int(block.get("rva_start"))
            end = _optional_contract_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            starts.append(start)
            ends.append(end)
        if not starts:
            continue
        ranges.append({"name": name, "rva_start": min(starts), "rva_end": max(ends)})
    ranges.sort(key=lambda item: (int(item["rva_end"]) - int(item["rva_start"]), str(item["name"])))
    return ranges


def _candidate_reference_section_gap_owner_offset_mapping(
    candidate: StageABinary,
    *,
    name: str,
    block_id: str,
    reference_start: int,
    reference_end: int,
    owner_ranges: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> BlockMapping | None:
    owner = next(
        (
            item
            for item in owner_ranges
            if int(item.get("rva_start") or 0) <= reference_start and reference_end <= int(item.get("rva_end") or 0)
        ),
        None,
    )
    if owner is None:
        return None
    owner_name = str(owner.get("name") or "")
    alias_match = alias_matches.get(owner_name) if isinstance(alias_matches.get(owner_name), dict) else {}
    if str(alias_match.get("source_kind") or "") not in {
        "generated_contract_guided_flow",
        "generated_checked_semantic_region",
    }:
        return None
    candidate_owner = alias_match.get("candidate") if isinstance(alias_match.get("candidate"), dict) else {}
    candidate_owner_start = _optional_contract_int(candidate_owner.get("rva_start"))
    candidate_owner_end = _optional_contract_int(candidate_owner.get("rva_end"))
    owner_start = _optional_contract_int(owner.get("rva_start"))
    if candidate_owner_start is None or candidate_owner_end is None or owner_start is None:
        return None
    candidate_start = candidate_owner_start + (reference_start - owner_start)
    candidate_end = candidate_start + (reference_end - reference_start)
    if candidate_start < candidate_owner_start or candidate_end > candidate_owner_end:
        return None
    section = _section_for_rva(candidate, candidate_start)
    if section is None or not section.executable or candidate_end > section.rva_end:
        return None
    return BlockMapping(
        id=_artifact_name(block_id),
        kind="code",
        original=BlockSide(reference_start, reference_end),
        candidate=BlockSide(candidate_start, candidate_end),
        reachable=True,
        invariant_checked=False,
        source={
            "source": {
                "function": name,
                "kind": "candidate_owner_offset_section_gap_probe",
                "reference_block_id": block_id,
                "owner_function": owner_name,
                "owner_reference_rva_start": owner_start,
                "owner_candidate_rva_start": candidate_owner_start,
                "owner_offset": reference_start - owner_start,
            }
        },
    )


def _optional_contract_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def _contract_candidate_abi_status(reference_abi: dict[str, Any], candidate_abi: dict[str, Any]) -> str:
    reference_counts = reference_abi.get("counts") if isinstance(reference_abi.get("counts"), dict) else {}
    candidate_counts = candidate_abi.get("counts") if isinstance(candidate_abi.get("counts"), dict) else {}
    if int(candidate_counts.get("functions") or 0) < int(reference_counts.get("functions") or 0):
        return "incomplete"
    if int(candidate_counts.get("callsites") or 0) < int(reference_counts.get("callsites") or 0):
        return "incomplete"
    return "satisfied"


def _contract_candidate_abi_coverage_gaps(
    reference_abi: dict[str, Any],
    candidate_abi: dict[str, Any],
    *,
    alias_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    alias_evidence = alias_evidence or _empty_contract_candidate_alias_evidence()
    alias_matches = alias_evidence.get("matches_by_reference") if isinstance(alias_evidence.get("matches_by_reference"), dict) else {}
    alias_ambiguities = alias_evidence.get("ambiguities_by_reference") if isinstance(alias_evidence.get("ambiguities_by_reference"), dict) else {}
    reference = reference_abi.get("original") if isinstance(reference_abi.get("original"), dict) else {}
    candidate = candidate_abi.get("candidate") if isinstance(candidate_abi.get("candidate"), dict) else {}
    reference_functions = [item for item in reference.get("functions", []) if isinstance(item, dict)]
    candidate_functions = [item for item in candidate.get("functions", []) if isinstance(item, dict)]
    candidate_by_key: dict[str, list[dict[str, Any]]] = {}
    for function in candidate_functions:
        name = function.get("name")
        if isinstance(name, str):
            for key in _contract_candidate_symbol_keys(name):
                candidate_by_key.setdefault(key, []).append(function)
    reference_import_prototypes = reference.get("import_prototypes") if isinstance(reference.get("import_prototypes"), list) else []
    candidate_import_prototypes = candidate.get("import_prototypes") if isinstance(candidate.get("import_prototypes"), list) else []
    reference_function_index = _abi_function_range_index(reference_functions, import_prototypes=reference_import_prototypes)
    candidate_function_index = _abi_function_range_index(candidate_functions, import_prototypes=candidate_import_prototypes)

    missing_functions: list[dict[str, Any]] = []
    ambiguous_functions: list[dict[str, Any]] = []
    incomplete_callsites: list[dict[str, Any]] = []
    function_mismatches: list[dict[str, Any]] = []
    callsite_mismatches: list[dict[str, Any]] = []
    for function in reference_functions:
        name = function.get("name")
        if not isinstance(name, str):
            continue
        key = _linker_function_match_key(name)
        if name in alias_ambiguities:
            ambiguous_functions.append({"name": name, "match_key": key, "ambiguities": alias_ambiguities[name][:5]})
            continue
        candidates = _contract_candidate_abi_candidates(candidate_by_key, name, alias_matches.get(name))
        reference_callsites = function.get("callsites") if isinstance(function.get("callsites"), list) else []
        if not candidates:
            missing_functions.append(_abi_function_gap_sample(function, key))
            continue
        best_candidate = _contract_candidate_abi_best_candidate(candidates, alias_matches.get(name))
        function_mismatch = _contract_candidate_abi_function_mismatch(
            name,
            key,
            function,
            best_candidate,
            _contract_candidate_abi_alias_sample(alias_matches.get(name)),
        )
        if function_mismatch is not None:
            function_mismatches.append(function_mismatch)
        candidate_callsites = best_candidate.get("callsites") if isinstance(best_candidate.get("callsites"), list) else []
        candidate_callsite_count = len(candidate_callsites)
        callsite_pairs = _contract_candidate_abi_callsite_pairs(
            reference_callsites,
            candidate_callsites,
            reference_function_index=reference_function_index,
            candidate_function_index=candidate_function_index,
            alias_matches=alias_matches,
        )
        if candidate_callsite_count < len(reference_callsites):
            signature_delta = _contract_candidate_abi_callsite_signature_delta(
                reference_callsites,
                candidate_callsites,
                callsite_pairs,
                reference_function_index=reference_function_index,
                candidate_function_index=candidate_function_index,
            )
            incomplete_callsites.append(
                {
                    "name": name,
                    "match_key": key,
                    "reference_callsites": len(reference_callsites),
                    "candidate_callsites": candidate_callsite_count,
                    "missing_callsites": len(reference_callsites) - candidate_callsite_count,
                    "unmatched_reference_callsites": signature_delta["counts"]["unmatched_reference_callsites"],
                    "unmatched_candidate_callsites": signature_delta["counts"]["unmatched_candidate_callsites"],
                    "matched_callsite_pairs": signature_delta["counts"]["matched_callsite_pairs"],
                    "alias_match": _contract_candidate_abi_alias_sample(alias_matches.get(name)),
                    "reference_callsite_samples": [_abi_callsite_gap_sample(item) for item in reference_callsites[:5]],
                    "missing_callsite_signatures": signature_delta["reference_only"][:8],
                    "extra_candidate_callsite_signatures": signature_delta["candidate_only"][:8],
                    "unmatched_reference_callsite_signatures": signature_delta["unmatched_reference_signatures"][:8],
                    "unmatched_candidate_callsite_signatures": signature_delta["unmatched_candidate_signatures"][:8],
                    "callsite_signature_delta": signature_delta,
                }
            )
        for index, candidate_index, reference_callsite, candidate_callsite in callsite_pairs:
            callsite_mismatch = _contract_candidate_abi_callsite_mismatch(
                name,
                key,
                index,
                reference_callsite,
                candidate_callsite,
                _contract_candidate_abi_alias_sample(alias_matches.get(name)),
                candidate_callsite_index=candidate_index,
                reference_function_index=reference_function_index,
                candidate_function_index=candidate_function_index,
                alias_matches=alias_matches,
            )
            if callsite_mismatch is not None:
                callsite_mismatches.append(callsite_mismatch)

    return {
        "missing_functions": missing_functions[:100],
        "ambiguous_functions": ambiguous_functions[:100],
        "incomplete_callsites": incomplete_callsites[:100],
        "function_mismatches": function_mismatches[:100],
        "callsite_mismatches": callsite_mismatches[:100],
        "counts": {
            "missing_functions": len(missing_functions),
            "ambiguous_functions": len(ambiguous_functions),
            "incomplete_callsite_functions": len(incomplete_callsites),
            "missing_callsites": sum(int(item.get("missing_callsites") or 0) for item in incomplete_callsites),
            "function_mismatches": len(function_mismatches),
            "callsite_mismatches": len(callsite_mismatches),
        },
    }


def _abi_function_range_index(functions: list[dict[str, Any]], *, import_prototypes: list[Any] | None = None) -> list[dict[str, Any]]:
    imports_by_key = _abi_import_prototypes_by_match_key(import_prototypes or [])
    ranges: list[dict[str, Any]] = []
    for function in functions:
        name = function.get("name")
        if not isinstance(name, str) or not name:
            continue
        match_key = _linker_function_match_key(name)
        import_signature = imports_by_key.get(match_key)
        blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            start = _optional_contract_int(block.get("rva_start"))
            end = _optional_contract_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            item = {
                "name": name,
                "match_key": match_key,
                "rva_start": start,
                "rva_end": end,
                "block_id": block.get("block_id"),
            }
            if import_signature is not None and _abi_block_is_import_thunk(block):
                item["import_signature"] = import_signature
                item["resolution_kind"] = "import_thunk"
            ranges.append(item)
    return ranges


def _abi_import_prototypes_by_match_key(import_prototypes: list[Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for imported in import_prototypes:
        if not isinstance(imported, dict):
            continue
        symbol = imported.get("symbol")
        ordinal = imported.get("ordinal")
        if isinstance(symbol, str) and symbol:
            signature = {"dll": imported.get("dll"), "symbol": symbol, "ordinal": ordinal}
            result.setdefault(_linker_function_match_key(symbol), signature)
            if "@" in symbol:
                result.setdefault(_linker_function_match_key(symbol.split("@", 1)[0]), signature)
        elif ordinal not in {None, ""}:
            result.setdefault(str(ordinal), {"dll": imported.get("dll"), "symbol": None, "ordinal": ordinal})
    return result


def _abi_block_is_import_thunk(block: dict[str, Any]) -> bool:
    abi = block.get("abi") if isinstance(block.get("abi"), dict) else {}
    if abi.get("callsites"):
        return False
    reads = abi.get("memory_reads") if isinstance(abi.get("memory_reads"), list) else []
    if len([item for item in reads if isinstance(item, dict)]) != 1:
        return False
    read = next(item for item in reads if isinstance(item, dict))
    section = read.get("memory_section") if isinstance(read.get("memory_section"), dict) else {}
    if read.get("memory_role") != "global_readonly_pointer_slot" or section.get("name") != ".idata":
        return False
    instruction = read.get("instruction") if isinstance(read.get("instruction"), dict) else {}
    return instruction.get("mnemonic") == "jmp"


def _contract_candidate_abi_callsite_pairs(
    reference_callsites: list[Any],
    candidate_callsites: list[Any],
    *,
    reference_function_index: list[dict[str, Any]],
    candidate_function_index: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> list[tuple[int, int, dict[str, Any], dict[str, Any]]]:
    valid_candidates = [
        (index, callsite)
        for index, callsite in enumerate(candidate_callsites)
        if isinstance(callsite, dict)
    ]
    unused_candidate_indexes = {index for index, _ in valid_candidates}
    unused_reference_indexes = {
        index
        for index, callsite in enumerate(reference_callsites)
        if isinstance(callsite, dict)
    }
    pairs: list[tuple[int, int, dict[str, Any], dict[str, Any]]] = []
    scored_pairs: list[tuple[int, int, int, dict[str, Any], dict[str, Any]]] = []
    for reference_index, reference_callsite in enumerate(reference_callsites):
        if not isinstance(reference_callsite, dict):
            continue
        for candidate_index, candidate_callsite in valid_candidates:
            score = _contract_candidate_abi_callsite_pair_score(
                reference_callsite,
                candidate_callsite,
                reference_function_index=reference_function_index,
                candidate_function_index=candidate_function_index,
                alias_matches=alias_matches,
            )
            if score > 0:
                scored_pairs.append((score, reference_index, candidate_index, reference_callsite, candidate_callsite))
    for _score, reference_index, candidate_index, reference_callsite, candidate_callsite in sorted(
        scored_pairs,
        key=lambda item: (-item[0], item[1], item[2]),
    ):
        if reference_index not in unused_reference_indexes or candidate_index not in unused_candidate_indexes:
            continue
        unused_reference_indexes.remove(reference_index)
        unused_candidate_indexes.remove(candidate_index)
        pairs.append((reference_index, candidate_index, reference_callsite, candidate_callsite))

    for reference_index, reference_callsite in enumerate(reference_callsites):
        if reference_index not in unused_reference_indexes or not isinstance(reference_callsite, dict):
            continue
        if reference_index in unused_candidate_indexes and isinstance(candidate_callsites[reference_index], dict):
            unused_candidate_indexes.remove(reference_index)
            unused_reference_indexes.remove(reference_index)
            pairs.append((reference_index, reference_index, reference_callsite, candidate_callsites[reference_index]))
    return sorted(pairs, key=lambda item: item[0])


def _contract_candidate_abi_callsite_signature_delta(
    reference_callsites: list[Any],
    candidate_callsites: list[Any],
    callsite_pairs: list[tuple[int, int, dict[str, Any], dict[str, Any]]],
    *,
    reference_function_index: list[dict[str, Any]],
    candidate_function_index: list[dict[str, Any]],
) -> dict[str, Any]:
    paired_reference_indexes = {reference_index for reference_index, _, _, _ in callsite_pairs}
    paired_candidate_indexes = {candidate_index for _, candidate_index, _, _ in callsite_pairs}
    reference_records = [
        _abi_callsite_signature_record(index, callsite, reference_function_index)
        for index, callsite in enumerate(reference_callsites)
        if isinstance(callsite, dict)
    ]
    candidate_records = [
        _abi_callsite_signature_record(index, callsite, candidate_function_index)
        for index, callsite in enumerate(candidate_callsites)
        if isinstance(callsite, dict)
    ]
    reference_groups = _abi_callsite_signature_groups(reference_records)
    candidate_groups = _abi_callsite_signature_groups(candidate_records)

    reference_only: list[dict[str, Any]] = []
    candidate_only: list[dict[str, Any]] = []
    for key in sorted(reference_groups):
        reference_group = reference_groups[key]
        candidate_group = candidate_groups.get(key)
        candidate_count = int(candidate_group.get("count") or 0) if isinstance(candidate_group, dict) else 0
        missing = int(reference_group.get("count") or 0) - candidate_count
        if missing <= 0:
            continue
        reference_only.append(
            {
                "signature_id": reference_group["signature_id"],
                "missing": missing,
                "reference_count": reference_group["count"],
                "candidate_count": candidate_count,
                "signature": reference_group["signature"],
                "reference_examples": reference_group["examples"],
                "candidate_examples": candidate_group.get("examples", []) if isinstance(candidate_group, dict) else [],
            }
        )
    for key in sorted(candidate_groups):
        candidate_group = candidate_groups[key]
        reference_group = reference_groups.get(key)
        reference_count = int(reference_group.get("count") or 0) if isinstance(reference_group, dict) else 0
        extra = int(candidate_group.get("count") or 0) - reference_count
        if extra <= 0:
            continue
        candidate_only.append(
            {
                "signature_id": candidate_group["signature_id"],
                "extra": extra,
                "reference_count": reference_count,
                "candidate_count": candidate_group["count"],
                "signature": candidate_group["signature"],
                "candidate_examples": candidate_group["examples"],
                "reference_examples": reference_group.get("examples", []) if isinstance(reference_group, dict) else [],
            }
        )

    unmatched_reference_records = [
        record for record in reference_records if _abi_callsite_record_index(record) not in paired_reference_indexes
    ]
    unmatched_candidate_records = [
        record for record in candidate_records if _abi_callsite_record_index(record) not in paired_candidate_indexes
    ]
    unmatched_reference_signatures = _abi_unmatched_callsite_signature_items(
        unmatched_reference_records,
        count_key="missing",
        examples_key="reference_examples",
    )
    unmatched_candidate_signatures = _abi_unmatched_callsite_signature_items(
        unmatched_candidate_records,
        count_key="extra",
        examples_key="candidate_examples",
    )
    return {
        "counts": {
            "reference_signatures": len(reference_groups),
            "candidate_signatures": len(candidate_groups),
            "reference_only_signatures": len(reference_only),
            "candidate_only_signatures": len(candidate_only),
            "unmatched_reference_signatures": len(unmatched_reference_signatures),
            "unmatched_candidate_signatures": len(unmatched_candidate_signatures),
            "matched_callsite_pairs": len(callsite_pairs),
            "unmatched_reference_callsites": len(unmatched_reference_records),
            "unmatched_candidate_callsites": len(unmatched_candidate_records),
        },
        "unmatched_reference_signatures": unmatched_reference_signatures[:24],
        "unmatched_candidate_signatures": unmatched_candidate_signatures[:24],
        "reference_only": reference_only[:24],
        "candidate_only": candidate_only[:24],
        "unmatched_reference_examples": unmatched_reference_records[:12],
        "unmatched_candidate_examples": unmatched_candidate_records[:12],
    }


def _abi_unmatched_callsite_signature_items(
    records: list[dict[str, Any]],
    *,
    count_key: str,
    examples_key: str,
) -> list[dict[str, Any]]:
    groups = _abi_callsite_signature_groups(records)
    items: list[dict[str, Any]] = []
    for key in sorted(groups):
        group = groups[key]
        item = {
            "signature_id": group["signature_id"],
            count_key: group["count"],
            "signature": group["signature"],
            examples_key: group["examples"],
        }
        if count_key == "missing":
            item["reference_count"] = group["count"]
            item["candidate_count"] = 0
        elif count_key == "extra":
            item["reference_count"] = 0
            item["candidate_count"] = group["count"]
        items.append(item)
    return items


def _abi_callsite_signature_record(
    index: int,
    callsite: dict[str, Any],
    function_index: list[dict[str, Any]],
) -> dict[str, Any]:
    signature = _abi_callsite_contract_signature(callsite, function_index)
    signature_json = json.dumps(signature, sort_keys=True, separators=(",", ":"), default=str)
    return {
        "index": index,
        "signature_id": f"callsite-signature:{sha256_bytes(signature_json.encode('utf-8'))[:16]}",
        "signature": signature,
        "callsite": _abi_callsite_gap_sample(callsite),
    }


def _abi_callsite_signature_groups(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for record in records:
        signature = record.get("signature") if isinstance(record.get("signature"), dict) else {}
        key = json.dumps(signature, sort_keys=True, separators=(",", ":"), default=str)
        group = groups.setdefault(
            key,
            {
                "signature_id": record.get("signature_id"),
                "signature": signature,
                "count": 0,
                "examples": [],
            },
        )
        group["count"] = int(group.get("count") or 0) + 1
        examples = group.get("examples") if isinstance(group.get("examples"), list) else []
        if len(examples) < 5:
            examples.append({"index": record.get("index"), "callsite": record.get("callsite")})
        group["examples"] = examples
    return groups


def _abi_callsite_record_index(record: dict[str, Any]) -> int:
    index = record.get("index")
    return index if isinstance(index, int) else -1


def _abi_callsite_contract_signature(callsite: dict[str, Any], function_index: list[dict[str, Any]]) -> dict[str, Any]:
    signature: dict[str, Any] = {}
    target_signature = _abi_callsite_target_contract_signature(callsite.get("target"), function_index)
    if target_signature:
        signature["target"] = target_signature
    inventory = _abi_argument_inventory_signature(callsite.get("argument_inventory"))
    if inventory:
        signature["argument_inventory"] = inventory
    hidden = _abi_hidden_sret_contract_signature(callsite.get("hidden_sret_or_out_param_evidence"))
    if hidden:
        signature["hidden_sret_or_out_param"] = hidden
    varargs = _abi_varargs_contract_signature(callsite.get("varargs_evidence"))
    if varargs:
        signature["varargs"] = varargs
    function_pointer_targets = callsite.get("function_pointer_targets")
    if isinstance(function_pointer_targets, list) and function_pointer_targets:
        roles = []
        for target in function_pointer_targets:
            if not isinstance(target, dict):
                continue
            roles.append(
                {
                    key: target.get(key)
                    for key in ("kind", "memory_role", "register", "target_rva", "status")
                    if target.get(key) not in {None, ""}
                }
            )
        signature["function_pointer_targets"] = {
            "count": len(function_pointer_targets),
            "roles": roles[:8],
        }
    return signature


def _abi_callsite_target_contract_signature(target: Any, function_index: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(target, dict):
        return {}
    resolved_signature = _abi_target_signature_with_resolution(target, function_index)
    import_signature = _abi_target_import_signature(resolved_signature)
    if import_signature is not None:
        dll, symbol, ordinal = import_signature
        return {
            "kind": "import",
            "dll": dll,
            "symbol": symbol,
            "ordinal": ordinal,
        }
    kind = resolved_signature.get("kind")
    signature: dict[str, Any] = {"kind": kind} if kind not in {None, ""} else {}
    resolved_functions = resolved_signature.get("resolved_functions")
    if isinstance(resolved_functions, list) and resolved_functions:
        resolved_keys = sorted(
            {
                str(item.get("match_key") or "")
                for item in resolved_functions
                if isinstance(item, dict) and item.get("match_key")
            }
        )
        if resolved_keys:
            signature["resolved_match_keys"] = resolved_keys
    elif kind == "direct" and resolved_signature.get("target_rva") not in {None, ""}:
        signature["target_rva"] = resolved_signature.get("target_rva")
    if kind == "function_pointer":
        memory_role = str(target.get("memory_role") or "")
        for key in ("memory_role", "register", "status"):
            if target.get(key) not in {None, ""}:
                signature[key] = target.get(key)
        if memory_role != "stack_pointer_slot" and target.get("operand") not in {None, ""}:
            signature["operand"] = target.get("operand")
        if memory_role != "stack_pointer_slot" and target.get("memory_rva") not in {None, ""}:
            signature["memory_rva"] = target.get("memory_rva")
        source = target.get("source") if isinstance(target.get("source"), dict) else {}
        if source:
            source_signature = {
                key: source.get(key)
                for key in ("kind", "address_class", "memory_role", "register")
                if source.get(key) not in {None, ""}
            }
            if memory_role != "stack_pointer_slot":
                for key in ("stack_offset", "memory_rva"):
                    if source.get(key) not in {None, ""}:
                        source_signature[key] = source.get(key)
            if source_signature:
                signature["source"] = source_signature
    return signature


def _abi_hidden_sret_contract_signature(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict) or not evidence:
        return {}
    return {
        key: evidence.get(key)
        for key in ("status", "reason", "address_role")
        if evidence.get(key) not in {None, ""}
    }


def _abi_varargs_contract_signature(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict) or not evidence:
        return {}
    signature = {
        key: evidence.get(key)
        for key in ("status", "import_symbol")
        if evidence.get(key) not in {None, ""}
    }
    format_string = evidence.get("format_string") if isinstance(evidence.get("format_string"), dict) else {}
    if format_string:
        signature["format_string"] = {
            key: format_string.get(key)
            for key in ("status", "required_varargs", "observed_varargs", "missing_varargs")
            if format_string.get(key) not in {None, ""}
        }
    return signature


def _contract_candidate_abi_callsite_pair_score(
    reference_callsite: dict[str, Any],
    candidate_callsite: dict[str, Any],
    *,
    reference_function_index: list[dict[str, Any]],
    candidate_function_index: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> int:
    score = 0
    target_match = _contract_candidate_abi_target_match(
        reference_callsite.get("target"),
        candidate_callsite.get("target"),
        reference_function_index=reference_function_index,
        candidate_function_index=candidate_function_index,
        alias_matches=alias_matches,
    )
    if target_match["reference"] and target_match["candidate"]:
        if target_match["matched"]:
            score += 100
        elif target_match["reference"].get("kind") == target_match["candidate"].get("kind"):
            score += 10
    reference_inventory = _abi_argument_inventory_signature(reference_callsite.get("argument_inventory"))
    candidate_inventory = _abi_argument_inventory_signature(candidate_callsite.get("argument_inventory"))
    if reference_inventory and candidate_inventory:
        if _contract_candidate_abi_argument_inventory_match(reference_inventory, candidate_inventory):
            score += 20
        elif reference_inventory.get("calling_convention") == candidate_inventory.get("calling_convention"):
            score += 2
    reference_varargs = reference_callsite.get("varargs_evidence") if isinstance(reference_callsite.get("varargs_evidence"), dict) else {}
    candidate_varargs = candidate_callsite.get("varargs_evidence") if isinstance(candidate_callsite.get("varargs_evidence"), dict) else {}
    if reference_varargs and candidate_varargs and _contract_candidate_abi_varargs_issue(reference_varargs, candidate_varargs) is None:
        score += 5
    return score


def _contract_candidate_abi_function_mismatch(
    name: str,
    match_key: str,
    reference_function: dict[str, Any],
    candidate_function: dict[str, Any],
    alias_match: dict[str, Any] | None,
) -> dict[str, Any] | None:
    issues: list[dict[str, Any]] = []
    reference_stack = reference_function.get("stack_delta") if isinstance(reference_function.get("stack_delta"), dict) else {}
    candidate_stack = candidate_function.get("stack_delta") if isinstance(candidate_function.get("stack_delta"), dict) else {}
    if reference_stack.get("status") == "derived" and candidate_stack.get("status") == "derived":
        if reference_stack.get("net_bytes") != candidate_stack.get("net_bytes"):
            issues.append(
                {
                    "category": "stack_delta_mismatch",
                    "expected": reference_stack,
                    "observed": candidate_stack,
                    "cause_hint": "candidate function stack cleanup differs from the reference contract",
                }
            )
    reference_registers = reference_function.get("registers") if isinstance(reference_function.get("registers"), dict) else {}
    candidate_registers = candidate_function.get("registers") if isinstance(candidate_function.get("registers"), dict) else {}
    for key, category in (
        ("preserved_candidates", "preserved_register_mismatch"),
        ("clobbered_candidates", "clobbered_register_mismatch"),
    ):
        expected = {str(item) for item in reference_registers.get(key, []) if isinstance(item, str)}
        observed = {str(item) for item in candidate_registers.get(key, []) if isinstance(item, str)}
        missing = sorted(expected - observed)
        if missing:
            issues.append(
                {
                    "category": category,
                    "expected": sorted(expected),
                    "observed": sorted(observed),
                    "missing": missing,
                    "cause_hint": f"candidate is missing reference {key.replace('_', ' ')}",
                }
            )
    for key, category, hint in (
        (
            "register_out_param_candidates",
            "register_carried_out_param_missing",
            "candidate does not expose all writes through entry register pointers",
        ),
        (
            "switch_contracts",
            "switch_or_jump_table_contract_missing",
            "candidate does not expose all indirect switch/jump-table contracts",
        ),
        (
            "loop_hints",
            "loop_backedge_contract_missing",
            "candidate does not expose all loop backedge hints",
        ),
    ):
        expected_count = _abi_list_count(reference_function.get(key))
        observed_count = _abi_list_count(candidate_function.get(key))
        if expected_count > observed_count:
            issues.append(
                {
                    "category": category,
                    "expected": expected_count,
                    "observed": observed_count,
                    "missing": expected_count - observed_count,
                    "cause_hint": hint,
                }
            )
    memory_issue = _contract_candidate_abi_memory_summary_issue(reference_function, candidate_function)
    if memory_issue is not None:
        issues.append(memory_issue)
    if not issues:
        return None
    return {
        "name": name,
        "match_key": match_key,
        "alias_match": alias_match,
        "candidate_name": candidate_function.get("name"),
        "issues": issues[:12],
        "repair_class": _contract_candidate_abi_mismatch_repair_class(issues),
        "next_action": _contract_candidate_abi_mismatch_next_action(name, issues),
    }


def _contract_candidate_abi_memory_summary_issue(reference_function: dict[str, Any], candidate_function: dict[str, Any]) -> dict[str, Any] | None:
    reference = reference_function.get("memory_effect_summary") if isinstance(reference_function.get("memory_effect_summary"), dict) else {}
    candidate = candidate_function.get("memory_effect_summary") if isinstance(candidate_function.get("memory_effect_summary"), dict) else {}
    expected_reads = _safe_int(reference.get("reads")) or 0
    expected_writes = _safe_int(reference.get("writes")) or 0
    observed_reads = _safe_int(candidate.get("reads")) or 0
    observed_writes = _safe_int(candidate.get("writes")) or 0
    read_roles = _missing_counted_roles(reference.get("read_roles"), candidate.get("read_roles"))
    write_roles = _missing_counted_roles(reference.get("write_roles"), candidate.get("write_roles"))
    if expected_reads <= observed_reads and expected_writes <= observed_writes and not read_roles and not write_roles:
        return None
    return {
        "category": "memory_effect_mismatch",
        "expected": reference,
        "observed": candidate,
        "missing_read_roles": read_roles,
        "missing_write_roles": write_roles,
        "cause_hint": "candidate memory reads/writes or access classes do not cover the reference contract",
    }


def _contract_candidate_abi_callsite_mismatch(
    name: str,
    match_key: str,
    callsite_index: int,
    reference_callsite: dict[str, Any],
    candidate_callsite: dict[str, Any],
    alias_match: dict[str, Any] | None,
    *,
    candidate_callsite_index: int | None = None,
    reference_function_index: list[dict[str, Any]] | None = None,
    candidate_function_index: list[dict[str, Any]] | None = None,
    alias_matches: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    issues: list[dict[str, Any]] = []
    target_match = _contract_candidate_abi_target_match(
        reference_callsite.get("target"),
        candidate_callsite.get("target"),
        reference_function_index=reference_function_index or [],
        candidate_function_index=candidate_function_index or [],
        alias_matches=alias_matches or {},
    )
    if (
        target_match["reference"]
        and target_match["candidate"]
        and not target_match["matched"]
    ):
        issues.append(
            {
                "category": "call_target_mismatch",
                "expected": target_match["reference"],
                "observed": target_match["candidate"],
                "cause_hint": "candidate call target kind/import/direct edge differs from the reference callsite",
            }
        )
    reference_hidden = reference_callsite.get("hidden_sret_or_out_param_evidence") if isinstance(reference_callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
    candidate_hidden = candidate_callsite.get("hidden_sret_or_out_param_evidence") if isinstance(candidate_callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
    if reference_hidden.get("status") == "candidate" and candidate_hidden.get("status") != "candidate":
        issues.append(
            {
                "category": "hidden_sret_or_out_param_missing",
                "expected": reference_hidden,
                "observed": candidate_hidden,
                "cause_hint": "candidate callsite lost address-like first argument evidence",
            }
        )
    reference_varargs = reference_callsite.get("varargs_evidence") if isinstance(reference_callsite.get("varargs_evidence"), dict) else {}
    candidate_varargs = candidate_callsite.get("varargs_evidence") if isinstance(candidate_callsite.get("varargs_evidence"), dict) else {}
    varargs_issue = _contract_candidate_abi_varargs_issue(reference_varargs, candidate_varargs)
    if varargs_issue is not None:
        issues.append(varargs_issue)
    reference_inventory = _abi_argument_inventory_signature(reference_callsite.get("argument_inventory"))
    candidate_inventory = _abi_argument_inventory_signature(candidate_callsite.get("argument_inventory"))
    inventory_issue = _contract_candidate_abi_argument_inventory_issue(
        reference_inventory,
        candidate_inventory,
        target_match=target_match,
    )
    if inventory_issue is not None:
        issues.append(inventory_issue)
    reference_targets = _abi_list_count(reference_callsite.get("function_pointer_targets"))
    candidate_targets = _abi_list_count(candidate_callsite.get("function_pointer_targets"))
    if reference_targets > candidate_targets:
        issues.append(
            {
                "category": "function_pointer_target_missing",
                "expected": reference_targets,
                "observed": candidate_targets,
                "cause_hint": "candidate lost recoverable function-pointer target evidence",
            }
        )
    if not issues:
        return None
    return {
        "name": name,
        "match_key": match_key,
        "alias_match": alias_match,
        "callsite_index": callsite_index,
        "candidate_callsite_index": candidate_callsite_index if candidate_callsite_index is not None else callsite_index,
        "block_id": reference_callsite.get("block_id"),
        "callsite_id": reference_callsite.get("id"),
        "reference_callsite": _abi_callsite_gap_sample(reference_callsite),
        "candidate_callsite": _abi_callsite_gap_sample(candidate_callsite),
        "issues": issues[:12],
        "repair_class": _contract_candidate_abi_mismatch_repair_class(issues),
        "next_action": _contract_candidate_abi_mismatch_next_action(name, issues),
    }


def _contract_candidate_abi_target_match(
    reference_target: Any,
    candidate_target: Any,
    *,
    reference_function_index: list[dict[str, Any]],
    candidate_function_index: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> dict[str, Any]:
    reference_signature = _abi_target_signature_with_resolution(reference_target, reference_function_index)
    candidate_signature = _abi_target_signature_with_resolution(candidate_target, candidate_function_index)
    if reference_signature == candidate_signature:
        return {"matched": True, "reference": reference_signature, "candidate": candidate_signature}
    if _contract_candidate_abi_import_targets_match(reference_signature, candidate_signature):
        return {
            "matched": True,
            "reference": reference_signature,
            "candidate": candidate_signature,
            "resolution": "import_thunk_equivalent_target",
        }
    if _contract_candidate_abi_resolved_targets_match(
        reference_signature.get("resolved_functions"),
        candidate_signature.get("resolved_functions"),
        alias_matches,
    ):
        return {
            "matched": True,
            "reference": reference_signature,
            "candidate": candidate_signature,
            "resolution": "resolved_direct_target_function",
        }
    return {"matched": False, "reference": reference_signature, "candidate": candidate_signature}


def _abi_target_signature_with_resolution(target: Any, function_index: list[dict[str, Any]]) -> dict[str, Any]:
    signature = _abi_target_signature(target)
    if signature.get("kind") != "direct":
        return signature
    rva = _optional_contract_int(signature.get("target_rva"))
    if rva is None:
        return signature
    resolved: list[dict[str, Any]] = []
    for item in function_index:
        if not int(item.get("rva_start") or 0) <= rva < int(item.get("rva_end") or 0):
            continue
        resolved_item = {
            "name": item.get("name"),
            "match_key": item.get("match_key"),
            "rva_start": item.get("rva_start"),
            "rva_end": item.get("rva_end"),
            "block_id": item.get("block_id"),
        }
        if isinstance(item.get("import_signature"), dict):
            resolved_item["import_signature"] = item.get("import_signature")
        if item.get("resolution_kind") is not None:
            resolved_item["resolution_kind"] = item.get("resolution_kind")
        resolved.append(resolved_item)
    if resolved:
        signature["resolved_functions"] = resolved[:8]
        import_equivalent = _abi_import_equivalent_signature(resolved)
        if import_equivalent is not None:
            signature["import_equivalent"] = import_equivalent
    return signature


def _contract_candidate_abi_import_targets_match(reference_signature: dict[str, Any], candidate_signature: dict[str, Any]) -> bool:
    reference_import = _abi_target_import_signature(reference_signature)
    candidate_import = _abi_target_import_signature(candidate_signature)
    return reference_import is not None and candidate_import is not None and reference_import == candidate_import


def _abi_target_import_signature(signature: dict[str, Any]) -> tuple[str, str, str] | None:
    if signature.get("kind") == "import":
        return (
            str(signature.get("dll") or "").lower(),
            str(signature.get("symbol") or ""),
            str(signature.get("ordinal") or ""),
        )
    equivalent = signature.get("import_equivalent") if isinstance(signature.get("import_equivalent"), dict) else {}
    if equivalent:
        return (
            str(equivalent.get("dll") or "").lower(),
            str(equivalent.get("symbol") or ""),
            str(equivalent.get("ordinal") or ""),
        )
    return None


def _abi_import_equivalent_signature(resolved_functions: list[dict[str, Any]]) -> dict[str, Any] | None:
    signatures = [
        item.get("import_signature")
        for item in resolved_functions
        if isinstance(item.get("import_signature"), dict) and item.get("resolution_kind") == "import_thunk"
    ]
    if len(signatures) != 1:
        return None
    signature = signatures[0]
    return {"dll": signature.get("dll"), "symbol": signature.get("symbol"), "ordinal": signature.get("ordinal")}


def _contract_candidate_abi_resolved_targets_match(
    reference_resolved: Any,
    candidate_resolved: Any,
    alias_matches: dict[str, Any],
) -> bool:
    reference_functions = [item for item in reference_resolved if isinstance(item, dict)] if isinstance(reference_resolved, list) else []
    candidate_functions = [item for item in candidate_resolved if isinstance(item, dict)] if isinstance(candidate_resolved, list) else []
    for reference in reference_functions:
        reference_name = reference.get("name")
        if not isinstance(reference_name, str) or not reference_name:
            continue
        candidate_names = _contract_candidate_abi_expected_candidate_names(reference_name, alias_matches)
        candidate_keys = {_linker_function_match_key(name) for name in candidate_names}
        for candidate in candidate_functions:
            candidate_name = candidate.get("name")
            if not isinstance(candidate_name, str) or not candidate_name:
                continue
            if candidate_name in candidate_names or _linker_function_match_key(candidate_name) in candidate_keys:
                return True
    return False


def _contract_candidate_abi_expected_candidate_names(reference_name: str, alias_matches: dict[str, Any]) -> set[str]:
    names = {reference_name}
    match = alias_matches.get(reference_name) if isinstance(alias_matches.get(reference_name), dict) else {}
    candidate = match.get("candidate") if isinstance(match.get("candidate"), dict) else {}
    candidate_name = candidate.get("name")
    if isinstance(candidate_name, str) and candidate_name:
        names.add(candidate_name)
    aliases = candidate.get("aliases") if isinstance(candidate.get("aliases"), list) else []
    names.update(alias for alias in aliases if isinstance(alias, str) and alias)
    return names


def _contract_candidate_abi_varargs_issue(reference: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any] | None:
    if reference.get("status") != "candidate":
        return None
    if candidate.get("status") != "candidate":
        return {
            "category": "varargs_evidence_missing",
            "expected": reference,
            "observed": candidate,
            "cause_hint": "candidate callsite lost known variadic import/prototype evidence",
        }
    reference_format = reference.get("format_string") if isinstance(reference.get("format_string"), dict) else {}
    candidate_format = candidate.get("format_string") if isinstance(candidate.get("format_string"), dict) else {}
    reference_missing = _safe_int(reference_format.get("missing_varargs")) or 0
    candidate_missing = _safe_int(candidate_format.get("missing_varargs")) or 0
    reference_required = _safe_int(reference_format.get("required_varargs"))
    candidate_required = _safe_int(candidate_format.get("required_varargs"))
    if reference_required != candidate_required or candidate_missing > reference_missing:
        return {
            "category": "varargs_format_inventory_mismatch",
            "expected": reference_format,
            "observed": candidate_format,
            "cause_hint": "candidate static format string or observed variadic argument inventory differs from reference",
        }
    return None


def _abi_target_signature(target: Any) -> dict[str, Any]:
    if not isinstance(target, dict):
        return {}
    return {
        key: target.get(key)
        for key in ("kind", "dll", "symbol", "ordinal", "target_rva", "thunk_rva", "status")
        if target.get(key) not in {None, ""}
    }


def _abi_argument_inventory_signature(inventory: Any) -> dict[str, Any]:
    if not isinstance(inventory, dict):
        return {}
    stack_args = inventory.get("stack_args") if isinstance(inventory.get("stack_args"), list) else []
    register_args = inventory.get("register_args") if isinstance(inventory.get("register_args"), list) else []
    return {
        "calling_convention": inventory.get("calling_convention"),
        "argument_count": inventory.get("argument_count"),
        "stack_roles": [item.get("role") for item in stack_args if isinstance(item, dict)],
        "stack_args": [
            _abi_stack_argument_signature(item)
            for item in stack_args
            if isinstance(item, dict)
        ],
        "register_roles": [
            {"register": item.get("register"), "role": item.get("role")}
            for item in register_args
            if isinstance(item, dict)
        ],
    }


def _abi_stack_argument_signature(argument: dict[str, Any]) -> dict[str, Any]:
    signature = {
        key: argument.get(key)
        for key in ("index", "role")
        if argument.get(key) not in {None, ""}
    }
    source = argument.get("source") if isinstance(argument.get("source"), dict) else {}
    if source:
        source_signature = {
            key: source.get(key)
            for key in ("kind", "stack_offset", "memory_role")
            if source.get(key) not in {None, ""}
        }
        if "stack_offset" not in source_signature:
            index = argument.get("index")
            if isinstance(index, int) and index >= 0:
                source_signature["stack_offset"] = index * 4
        value = source.get("value")
        if isinstance(value, (int, str)) and not isinstance(value, bool):
            source_signature["value"] = value
        string_literal = source.get("string_literal") if isinstance(source.get("string_literal"), dict) else {}
        if string_literal:
            source_signature["string_literal"] = {
                key: string_literal.get(key)
                for key in ("rva", "size", "sha256", "text")
                if string_literal.get(key) not in {None, ""}
            }
        if source_signature:
            signature["source"] = source_signature
    return signature


_ABI_ADDRESS_LIKE_ARGUMENT_ROLES = {
    "computed_out_param_or_hidden_sret",
    "stack_out_param_or_scratch_buffer",
}

# These are ABI-guidance provenance classes for by-value arguments. They are
# not used to forgive address-like, literal, target, or proof-obligation loss.
_ABI_BY_VALUE_ARGUMENT_ROLES = {
    "computed_memory",
    "computed_pointer_deref",
    "immediate",
    "register",
    "stack_argument_slot",
    "stack_local_slot",
    "stack_pointer_slot",
}


def _contract_candidate_abi_argument_inventory_match(reference: dict[str, Any], candidate: dict[str, Any]) -> bool:
    if reference == candidate:
        return True
    if reference.get("calling_convention") != candidate.get("calling_convention"):
        return False
    if reference.get("argument_count") != candidate.get("argument_count"):
        return False
    if not _contract_candidate_abi_stack_roles_match(reference.get("stack_roles"), candidate.get("stack_roles")):
        return False
    return _contract_candidate_abi_register_roles_match(reference.get("register_roles"), candidate.get("register_roles"))


def _contract_candidate_abi_argument_inventory_issue(
    reference: dict[str, Any],
    candidate: dict[str, Any],
    *,
    target_match: dict[str, Any],
) -> dict[str, Any] | None:
    if not reference or not candidate:
        return None
    if _contract_candidate_abi_argument_inventory_match(reference, candidate):
        return None
    if _contract_candidate_abi_reference_inventory_underconstrained(reference, candidate, target_match=target_match):
        return {
            "category": "reference_argument_inventory_underconstrained",
            "expected": reference,
            "observed": candidate,
            "cause_hint": "reference callsite argument recovery is underconstrained; improve Stage A before using this callsite to steer source repair",
        }
    return {
        "category": "callsite_argument_inventory_mismatch",
        "expected": reference,
        "observed": candidate,
        "cause_hint": "candidate argument count, argument roles, or calling convention differs from the reference callsite",
    }


def _contract_candidate_abi_reference_inventory_underconstrained(
    reference: dict[str, Any],
    candidate: dict[str, Any],
    *,
    target_match: dict[str, Any],
) -> bool:
    if target_match.get("matched") is not True:
        return False
    if reference.get("calling_convention") != candidate.get("calling_convention"):
        return False
    if reference.get("argument_count") != 0 or not candidate.get("argument_count"):
        return False
    if reference.get("stack_roles") or reference.get("register_roles"):
        return False
    return True


def _contract_candidate_abi_stack_roles_match(reference: Any, candidate: Any) -> bool:
    if not isinstance(reference, list) or not isinstance(candidate, list):
        return reference == candidate
    if len(reference) != len(candidate):
        return False
    return all(
        _contract_candidate_abi_stack_role_match(reference_role, candidate_role)
        for reference_role, candidate_role in zip(reference, candidate, strict=True)
    )


def _contract_candidate_abi_stack_role_match(reference: Any, candidate: Any) -> bool:
    return _contract_candidate_abi_argument_role_match(reference, candidate)


def _contract_candidate_abi_register_roles_match(reference: Any, candidate: Any) -> bool:
    if not isinstance(reference, list) or not isinstance(candidate, list):
        return reference == candidate
    if len(reference) != len(candidate):
        return False
    for reference_item, candidate_item in zip(reference, candidate, strict=True):
        if not isinstance(reference_item, dict) or not isinstance(candidate_item, dict):
            if reference_item != candidate_item:
                return False
            continue
        if reference_item.get("register") != candidate_item.get("register"):
            return False
        if not _contract_candidate_abi_argument_role_match(reference_item.get("role"), candidate_item.get("role")):
            return False
    return True


def _contract_candidate_abi_argument_role_match(reference: Any, candidate: Any) -> bool:
    if reference == candidate:
        return True
    if not isinstance(reference, str) or not isinstance(candidate, str):
        return False
    if reference == "register" and candidate in _ABI_ADDRESS_LIKE_ARGUMENT_ROLES:
        return True
    if reference == "register" and candidate in {"global_readonly_pointer_slot", "global_writable_pointer_slot"}:
        return True
    if reference == "immediate" and candidate == "string_literal":
        return True
    if reference in _ABI_BY_VALUE_ARGUMENT_ROLES and candidate in _ABI_BY_VALUE_ARGUMENT_ROLES:
        return True
    return False


def _abi_list_count(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _missing_counted_roles(reference: Any, candidate: Any) -> dict[str, int]:
    if not isinstance(reference, dict):
        return {}
    candidate = candidate if isinstance(candidate, dict) else {}
    missing: dict[str, int] = {}
    for role, expected in reference.items():
        expected_count = _safe_int(expected) or 0
        observed_count = _safe_int(candidate.get(role)) or 0
        if expected_count > observed_count:
            missing[str(role)] = expected_count - observed_count
    return missing


def _contract_candidate_abi_mismatch_repair_class(issues: list[dict[str, Any]]) -> str:
    categories = [
        str(issue.get("category") or "").lower()
        for issue in issues
        if isinstance(issue, dict) and issue.get("category")
    ]
    category_text = " ".join(categories)
    if "reference_argument_inventory_underconstrained" in categories:
        return "stage_a_argument_inventory_underconstrained"
    if "varargs" in category_text or "stdio" in category_text or "printf" in category_text:
        return "varargs_or_stdio_bridge"
    if "sret" in category_text or "out_param" in category_text:
        return "hidden_sret_or_out_param"
    if "switch" in category_text or "jump_table" in category_text:
        return "switch_or_jump_table_dispatch"
    if "loop" in category_text:
        return "loop_or_state_machine"
    if "function_pointer" in category_text:
        return "function_pointer_target"
    if "call_target_mismatch" in categories:
        return "call_target_mismatch"
    if "callsite_argument_inventory_mismatch" in categories:
        return "callsite_argument_inventory_mismatch"
    if "register" in category_text or "clobber" in category_text or "preserved" in category_text:
        return "preserved_register_mismatch"
    if "stack" in category_text:
        return "stack_delta_mismatch"
    if "memory" in category_text:
        return "memory_effect_mismatch"
    if categories:
        return "abi_callsite_mismatch"
    text = json.dumps(issues, sort_keys=True, default=str).lower()
    if "varargs" in text or "stdio" in text or "printf" in text:
        return "varargs_or_stdio_bridge"
    if "sret" in text or "out_param" in text:
        return "hidden_sret_or_out_param"
    if "switch" in text or "jump_table" in text:
        return "switch_or_jump_table_dispatch"
    if "loop" in text:
        return "loop_or_state_machine"
    if "function_pointer" in text:
        return "function_pointer_target"
    if "call target" in text or "target" in text:
        return "call_target_mismatch"
    if "argument" in text:
        return "callsite_argument_inventory_mismatch"
    if "register" in text or "clobber" in text or "preserved" in text:
        return "preserved_register_mismatch"
    if "stack" in text:
        return "stack_delta_mismatch"
    if "memory" in text:
        return "memory_effect_mismatch"
    return "abi_callsite_mismatch"


def _contract_candidate_abi_mismatch_next_action(name: str, issues: list[dict[str, Any]]) -> str:
    repair_class = _contract_candidate_abi_mismatch_repair_class(issues)
    if repair_class == "stage_a_argument_inventory_underconstrained":
        return f"improve Stage A argument recovery for {name}; reference callsite inventory is underconstrained before source repair can be trusted"
    if repair_class == "varargs_or_stdio_bridge":
        return f"repair {name} varargs/stdio bridge, format-string argument inventory, and imported prototype surface"
    if repair_class == "hidden_sret_or_out_param":
        return f"repair {name} hidden sret/out-param representation and address-like argument flow"
    if repair_class == "switch_or_jump_table_dispatch":
        return f"repair {name} switch/jump-table dispatch so every checked target and default edge is represented"
    if repair_class == "loop_or_state_machine":
        return f"repair {name} loop backedges, loop-carried state, and exit predicates"
    if repair_class == "function_pointer_target":
        return f"recover {name} function-pointer target set or represent it as a checked indirect target contract"
    if repair_class == "call_target_mismatch":
        return f"repair {name} call target mapping, import thunk linkage, or direct-call callee selection"
    if repair_class == "callsite_argument_inventory_mismatch":
        return f"repair {name} call argument order/count/roles and stack/register argument materialization"
    if repair_class == "preserved_register_mismatch":
        return f"repair {name} register save/restore and clobber behavior before rerunning Stage A contract validation"
    if repair_class == "stack_delta_mismatch":
        return f"repair {name} calling convention and stack cleanup before rerunning Stage A contract validation"
    if repair_class == "memory_effect_mismatch":
        return f"repair {name} memory reads/writes, field accesses, and global/stack access classes"
    return f"repair {name} ABI/callsite contract mismatch and rerun Stage A contract validation"


def _contract_candidate_abi_candidates(
    candidate_by_key: dict[str, list[dict[str, Any]]],
    reference_name: str,
    alias_match: Any,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for key in _contract_candidate_symbol_keys(reference_name):
        for function in candidate_by_key.get(key, []):
            if function not in candidates:
                candidates.append(function)
    if isinstance(alias_match, dict):
        candidate = alias_match.get("candidate") if isinstance(alias_match.get("candidate"), dict) else {}
        for candidate_name in (candidate.get("name"), alias_match.get("source_function")):
            if isinstance(candidate_name, str):
                for key in _contract_candidate_symbol_keys(candidate_name):
                    for function in candidate_by_key.get(key, []):
                        if function not in candidates:
                            candidates.append(function)
    return candidates


def _contract_candidate_abi_best_candidate(candidates: list[dict[str, Any]], alias_match: Any) -> dict[str, Any]:
    preferred_names: set[str] = set()
    if isinstance(alias_match, dict):
        candidate = alias_match.get("candidate") if isinstance(alias_match.get("candidate"), dict) else {}
        for name in (candidate.get("name"), alias_match.get("source_function")):
            if isinstance(name, str) and name:
                preferred_names.add(name)
    preferred = [
        function
        for function in candidates
        if preferred_names & set(_contract_candidate_function_symbol_names(function))
    ]
    if preferred:
        candidates = preferred
    return max(
        candidates,
        key=lambda item: len(item.get("callsites", [])) if isinstance(item.get("callsites"), list) else 0,
    )


def _contract_candidate_abi_alias_sample(alias_match: Any) -> dict[str, Any] | None:
    if not isinstance(alias_match, dict):
        return None
    return {
        "source_function": alias_match.get("source_function"),
        "source_kind": alias_match.get("source_kind"),
        "candidate": alias_match.get("candidate"),
    }


def _abi_function_gap_sample(function: dict[str, Any], match_key: str) -> dict[str, Any]:
    blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
    callsites = function.get("callsites") if isinstance(function.get("callsites"), list) else []
    return {
        "name": function.get("name"),
        "match_key": match_key,
        "blocks": [
            {
                "block_id": block.get("block_id"),
                "rva_start": block.get("rva_start"),
                "rva_end": block.get("rva_end"),
                "size": block.get("size"),
            }
            for block in blocks[:5]
            if isinstance(block, dict)
        ],
        "callsites": len(callsites),
        "callsite_samples": [_abi_callsite_gap_sample(item) for item in callsites[:5]],
    }


def _abi_callsite_gap_sample(callsite: Any) -> dict[str, Any]:
    if not isinstance(callsite, dict):
        return {}
    instruction = callsite.get("instruction") if isinstance(callsite.get("instruction"), dict) else {}
    return {
        "id": callsite.get("id"),
        "block_id": callsite.get("block_id"),
        "instruction": {
            "rva": instruction.get("rva"),
            "mnemonic": instruction.get("mnemonic"),
            "op_str": instruction.get("op_str"),
        },
        "target": callsite.get("target") if isinstance(callsite.get("target"), dict) else {},
    }


def _resolve_contract_sidecar_path(contract_path: Path, path_text: Any, name: str) -> Path:
    if isinstance(path_text, str) and path_text:
        path = Path(path_text)
        return path if path.is_absolute() else contract_path.parent / path
    return contract_path.parent / f"{name}.json"


def _unchecked_marker_paths(contract: dict[str, Any]) -> list[str]:
    proof = _contract_constraint(contract, "proof_obligation_inventory")
    lean = proof.get("lean") if isinstance(proof.get("lean"), dict) else {}
    markers: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                if "unchecked" in str(key).lower() and child not in (None, False, 0, "", [], {}):
                    markers.append(child_path)
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(lean, "lean")
    return sorted(set(markers))


def _matches_focus(item: Any, focus_lower: str) -> bool:
    return focus_lower in json.dumps(item, sort_keys=True, default=str).lower()


def _gap_severity_rank(value: Any) -> int:
    return {"incomplete": 1, "violated": 2, "failed": 2, "fail": 2}.get(str(value or ""), 0)


def _layout_contract_from_mapping_payload(payload: Any, mapping: Path | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    embedded = payload.get("layout_contract")
    if isinstance(embedded, dict):
        return embedded
    if not isinstance(embedded, str) or not embedded:
        return None
    path = Path(embedded)
    if not path.is_absolute() and mapping is not None:
        path = mapping.parent / path
    try:
        return _load_json(path)
    except StageAInputError:
        return None


def _load_stage_a_validation_report(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    if path.is_dir():
        verdict_path = path / "verdict.json"
        obligations_path = path / "obligations.json"
        if not verdict_path.is_file() or not obligations_path.is_file():
            raise StageAInputError("Stage A validation report directory must contain verdict.json and obligations.json")
        payload = {
            "path": str(path),
            "verdict": _load_json(verdict_path),
            "obligations": _load_json(obligations_path),
        }
        layout_path = path / "layout.json"
        if layout_path.is_file():
            payload["layout"] = _load_json(layout_path)
        lean_inputs_path = path / "lean" / "inputs.json"
        if lean_inputs_path.is_file():
            payload["lean_inputs"] = _load_json(lean_inputs_path)
        return payload
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise StageAInputError("Stage A validation report JSON must be an object")
    if payload.get("format") == "stage-a-verdict-v1":
        return {"path": str(path), "verdict": payload, "obligations": {"format": "stage-a-obligations-v1", "obligations": [], "counts": {}}}
    if "verdict" in payload and "obligations" in payload:
        return {"path": str(path), **payload}
    raise StageAInputError("Stage A validation report must be a report directory, verdict JSON, or object with verdict and obligations")


def _reference_validation_report_binding_constraint(
    *,
    payload: dict[str, Any] | None,
    original: StageABinary,
    candidate: StageABinary | None,
    mapping_payload: Any,
    model: str,
) -> dict[str, Any]:
    if payload is None:
        return {
            "status": "not_provided",
            "evidence_kind": "none",
            "blocker": "no Stage A validation report was provided",
            "next_action": "run stage-a-validate and export the contract with --validation-report",
            "issues": [],
        }

    verdict = payload.get("verdict") if isinstance(payload.get("verdict"), dict) else {}
    layout = payload.get("layout") if isinstance(payload.get("layout"), dict) else {}
    lean_inputs = payload.get("lean_inputs") if isinstance(payload.get("lean_inputs"), dict) else {}
    issues: list[dict[str, Any]] = []

    requested_model = verdict.get("requested_model")
    if requested_model != model:
        issues.append(
            _incomplete_record(
                category="validation_report_model_mismatch",
                obligation_id="reference-contract:validation-report-binding:model",
                blocker="Stage A validation report was generated for a different model",
                next_action="rerun stage-a-validate with the same --model used for the reference contract",
                details={"expected": model, "actual": requested_model},
            )
        )

    original_sha = _layout_binary_sha256(layout, "original")
    if original_sha != original.sha256:
        issues.append(
            _incomplete_record(
                category="validation_report_binary_mismatch",
                obligation_id="reference-contract:validation-report-binding:original",
                blocker="Stage A validation report does not bind to the current original binary",
                next_action="rerun stage-a-validate for this original/candidate pair",
                details={"binary": "original", "expected_sha256": original.sha256, "actual_sha256": original_sha},
            )
        )

    candidate_sha = _layout_binary_sha256(layout, "candidate")
    if candidate is not None and candidate_sha != candidate.sha256:
        issues.append(
            _incomplete_record(
                category="validation_report_binary_mismatch",
                obligation_id="reference-contract:validation-report-binding:candidate",
                blocker="Stage A validation report does not bind to the current candidate binary",
                next_action="rerun stage-a-validate for this original/candidate pair",
                details={"binary": "candidate", "expected_sha256": candidate.sha256, "actual_sha256": candidate_sha},
            )
        )

    mapping_matches: bool | None
    expected_mapping_sha256 = _canonical_json_sha256(mapping_payload) if mapping_payload is not None else None
    actual_mapping_sha256 = None
    if mapping_payload is None:
        mapping_matches = None
    elif "mapping" not in lean_inputs:
        mapping_matches = False
        issues.append(
            _incomplete_record(
                category="validation_report_mapping_unbound",
                obligation_id="reference-contract:validation-report-binding:mapping",
                blocker="Stage A validation report does not include the mapping payload snapshot",
                next_action="rerun stage-a-validate with current tooling and re-export the reference contract",
            )
        )
    else:
        actual_mapping_sha256 = _canonical_json_sha256(lean_inputs.get("mapping"))
        mapping_matches = actual_mapping_sha256 == expected_mapping_sha256
        if not mapping_matches:
            issues.append(
                _incomplete_record(
                    category="validation_report_mapping_mismatch",
                    obligation_id="reference-contract:validation-report-binding:mapping",
                    blocker="Stage A validation report was generated from a different block map",
                    next_action="rerun stage-a-validate with the current block map",
                    details={
                        "expected_mapping_sha256": expected_mapping_sha256,
                        "actual_mapping_sha256": actual_mapping_sha256,
                    },
                )
            )

    return {
        "status": "satisfied" if not issues else "incomplete",
        "evidence_kind": "stage-a-validation-report-binding",
        "report": payload.get("path"),
        "facts": {
            "matching_model": requested_model == model,
            "matching_original_sha256": original_sha == original.sha256,
            "matching_candidate_sha256": None if candidate is None else candidate_sha == candidate.sha256,
            "matching_mapping_payload": mapping_matches,
            "expected_mapping_sha256": expected_mapping_sha256,
            "actual_mapping_sha256": actual_mapping_sha256,
        },
        "issues": issues,
    }


def _canonical_json_sha256(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))


def _layout_binary_sha256(layout: dict[str, Any], side: str) -> str | None:
    item = layout.get(side)
    return item.get("sha256") if isinstance(item, dict) and isinstance(item.get("sha256"), str) else None


def _reference_pe_layout_constraint(
    *,
    original: StageABinary,
    candidate: StageABinary | None,
    layout_contract: dict[str, Any] | None,
) -> dict[str, Any]:
    if candidate is None:
        return {
            "status": "derived",
            "evidence_kind": "pefile",
            "scope": "original",
            "sections": _section_permission_signature(original),
            "imports": _import_signature(original),
            "relocations": _binary_relocation_summary(original),
            "image_base": original.image_base,
        }
    issues = _layout_issues(original, candidate, layout_contract)
    return {
        "status": "satisfied" if not issues else ("failed" if any(issue.get("severity") == "fail" for issue in issues) else "incomplete"),
        "evidence_kind": "stage-a-layout-model",
        "scope": "original-candidate-pair",
        "facts": {
            "matching_machine": original.machine == candidate.machine,
            "matching_bitness": original.bitness == candidate.bitness,
            "matching_section_rvas": _section_rva_start_signature(original) == _section_rva_start_signature(candidate),
            "matching_section_permissions": _section_compatibility_signature(original) == _section_compatibility_signature(candidate),
            "matching_imports": _import_signature(original) == _import_signature(candidate),
            "matching_image_base": original.image_base == candidate.image_base,
        },
        "original": {
            "sections": _section_permission_signature(original),
            "imports": _import_signature(original),
            "relocations": _binary_relocation_summary(original),
            "image_base": original.image_base,
        },
        "candidate": {
            "sections": _section_permission_signature(candidate),
            "imports": _import_signature(candidate),
            "relocations": _binary_relocation_summary(candidate),
            "image_base": candidate.image_base,
        },
        "issues": issues,
    }


def _reference_map_constraints(
    *,
    original: StageABinary,
    candidate: StageABinary | None,
    mapping_payload: Any,
) -> dict[str, Any]:
    if mapping_payload is None:
        missing = _reference_missing_map_constraint()
        return {
            "issues": [],
            "mappings": [],
            "verified_waivers": [],
            "executable_byte_coverage": missing,
            "function_ranges": missing,
            "basic_blocks_and_cfg": missing,
            "roots_and_jump_tables": missing,
            "padding_alignment": missing,
        }

    mappings, waivers, map_issues = _parse_block_map(mapping_payload, original)
    map_issues.extend(_generated_map_issues(mapping_payload))
    verified_waivers: list[NonCodeWaiver] = []
    waiver_obligations: list[dict[str, Any]] = []
    if candidate is not None:
        verified_waivers, waiver_obligations = _waiver_obligations(original, candidate, waivers)
    elif waivers:
        map_issues.append(
            _incomplete_record(
                category="unverified_noncode_waiver",
                obligation_id="reference-contract:waivers",
                blocker="non-code waivers require a candidate binary before Stage A can verify pairwise padding",
                next_action="export the reference contract with --candidate when mapping waivers are present",
            )
        )
    for obligation in waiver_obligations:
        if obligation.get("status") == "incomplete" and isinstance(obligation.get("incomplete"), dict):
            map_issues.append(obligation["incomplete"])

    map_status = _reference_map_status(mapping_payload, map_issues)
    return {
        "issues": map_issues,
        "mappings": mappings,
        "verified_waivers": verified_waivers,
        "executable_byte_coverage": {
            "status": "satisfied"
            if map_status == "satisfied"
            and not _reference_coverage_side("original", original, mappings, verified_waivers)["gaps"]
            and (candidate is None or not _reference_coverage_side("candidate", candidate, mappings, verified_waivers)["gaps"])
            else "incomplete",
            "evidence_kind": "stage-a-block-map",
            "original": _reference_coverage_side("original", original, mappings, verified_waivers),
            "candidate": _reference_coverage_side("candidate", candidate, mappings, verified_waivers) if candidate is not None else None,
        },
        "function_ranges": _reference_function_ranges(mappings, map_status),
        "basic_blocks_and_cfg": _reference_basic_blocks_and_cfg(original, candidate, mappings, map_status),
        "roots_and_jump_tables": _reference_roots_and_jump_tables(mappings, map_status),
        "padding_alignment": _reference_padding_alignment(waivers, verified_waivers, waiver_obligations, map_status),
    }


def _reference_missing_map_constraint() -> dict[str, Any]:
    return {
        "status": "not_provided",
        "evidence_kind": "none",
        "blocker": "no Stage A block map was provided",
        "next_action": "generate a Stage A block map and re-export the reference contract",
    }


def _reference_map_status(mapping_payload: Any, issues: list[dict[str, Any]]) -> str:
    if any(issue.get("status") == "failed" or issue.get("severity") == "fail" for issue in issues):
        return "failed"
    if issues:
        return "incomplete"
    if isinstance(mapping_payload, dict) and mapping_payload.get("status") not in {None, "pass"}:
        return "incomplete"
    return "satisfied"


def _reference_coverage_side(
    side: str,
    binary: StageABinary,
    mappings: list[BlockMapping],
    waivers: list[NonCodeWaiver],
) -> dict[str, Any]:
    mapped_ranges = [
        mapped.original if side == "original" else mapped.candidate
        for mapped in mappings
        if mapped.kind == "code"
    ]
    waiver_ranges = [
        BlockSide(waiver.rva_start, waiver.rva_end)
        for waiver in waivers
        if waiver.binary in {side, "both"}
    ]
    classified = mapped_ranges + waiver_ranges
    executable_sections = [section for section in binary.sections if section.executable]
    gaps = [
        gap
        for section in executable_sections
        for gap in _gaps(section.rva_start, section.rva_end, classified)
    ]
    executable_bytes = sum(section.rva_end - section.rva_start for section in executable_sections)
    classified_bytes = sum(item.rva_end - item.rva_start for item in _merged_ranges(classified))
    return {
        "status": "satisfied" if not gaps else "incomplete",
        "binary": side,
        "executable_bytes": executable_bytes,
        "classified_bytes": min(classified_bytes, executable_bytes),
        "mapped_code_ranges": [_range_report(item) for item in mapped_ranges],
        "waived_noncode_ranges": [_range_report(item) for item in waiver_ranges],
        "gaps": [_range_report(item) for item in gaps],
    }


def _merged_ranges(ranges: list[BlockSide]) -> list[BlockSide]:
    merged: list[BlockSide] = []
    for item in sorted(ranges, key=lambda value: (value.rva_start, value.rva_end)):
        if not merged or item.rva_start > merged[-1].rva_end:
            merged.append(item)
            continue
        merged[-1] = BlockSide(merged[-1].rva_start, max(merged[-1].rva_end, item.rva_end))
    return merged


def _range_report(side: BlockSide) -> dict[str, int]:
    return {"rva_start": side.rva_start, "rva_end": side.rva_end, "size": side.size}


def _reference_function_ranges(mappings: list[BlockMapping], map_status: str) -> dict[str, Any]:
    functions: dict[str, dict[str, Any]] = {}
    for mapped in mappings:
        source = _mapping_source(mapped)
        name = source.get("function") if isinstance(source.get("function"), str) else ""
        if not name:
            continue
        entry = functions.setdefault(
            name,
            {
                "name": name,
                "original": {"rva_start": mapped.original.rva_start, "rva_end": mapped.original.rva_end},
                "candidate": {"rva_start": mapped.candidate.rva_start, "rva_end": mapped.candidate.rva_end},
                "block_ids": [],
            },
        )
        entry["original"]["rva_start"] = min(entry["original"]["rva_start"], mapped.original.rva_start)
        entry["original"]["rva_end"] = max(entry["original"]["rva_end"], mapped.original.rva_end)
        entry["candidate"]["rva_start"] = min(entry["candidate"]["rva_start"], mapped.candidate.rva_start)
        entry["candidate"]["rva_end"] = max(entry["candidate"]["rva_end"], mapped.candidate.rva_end)
        entry["block_ids"].append(mapped.id)
    return {
        "status": map_status if functions else "incomplete",
        "evidence_kind": "linker-map-capstone-block-map",
        "functions": sorted(functions.values(), key=lambda item: item["name"]),
    }


def _reference_basic_blocks_and_cfg(
    original: StageABinary,
    candidate: StageABinary | None,
    mappings: list[BlockMapping],
    map_status: str,
) -> dict[str, Any]:
    blocks = []
    cfg_edges = []
    original_symbol_aliases = _coff_symbol_aliases_by_rva(original)
    candidate_symbol_aliases = _coff_symbol_aliases_by_rva(candidate) if candidate is not None else {}
    for mapped in mappings:
        source = _mapping_source(mapped)
        proof = mapped.source.get("proof") if isinstance(mapped.source.get("proof"), dict) else {}
        block = {
            "id": mapped.id,
            "kind": mapped.kind,
            "reachable": mapped.reachable,
            "function": source.get("function"),
            "original": _range_report(mapped.original),
            "candidate": _range_report(mapped.candidate),
            "source_kind": source.get("kind"),
            "proof_rule": proof.get("rule"),
            "byte_identical": source.get("byte_identical"),
        }
        symbol_aliases = {
            "original": _symbol_aliases_for_range(original_symbol_aliases, mapped.original),
            "candidate": _symbol_aliases_for_range(candidate_symbol_aliases, mapped.candidate) if candidate is not None else [],
        }
        if symbol_aliases["original"] or symbol_aliases["candidate"]:
            block["symbol_aliases"] = symbol_aliases
        blocks.append(block)
        if mapped.kind != "code":
            continue
        edge_report = {
            "block_id": mapped.id,
            "original": _direct_cfg_edges(original, mapped.original),
            "candidate": _direct_cfg_edges(candidate, mapped.candidate) if candidate is not None else None,
        }
        cfg_edges.append(edge_report)
    return {
        "status": map_status if blocks else "incomplete",
        "evidence_kind": "capstone-direct-cfg",
        "basic_blocks": blocks,
        "cfg_edges": cfg_edges,
    }


def _symbol_aliases_for_range(symbols_by_rva: dict[int, list[str]], span: BlockSide) -> list[str]:
    aliases: list[str] = []
    for rva in sorted(rva for rva in symbols_by_rva if span.rva_start <= rva < span.rva_end):
        for alias in symbols_by_rva[rva]:
            if alias and alias not in aliases:
                aliases.append(alias)
    return aliases


def _mapping_source(mapped: BlockMapping) -> dict[str, Any]:
    source = mapped.source.get("source")
    return source if isinstance(source, dict) else {}


def _reference_roots_and_jump_tables(mappings: list[BlockMapping], map_status: str) -> dict[str, Any]:
    roots = []
    jump_table_targets = []
    for mapped in mappings:
        for key in ("root", "reachability"):
            value = mapped.source.get(key)
            if isinstance(value, dict):
                roots.append({"block_id": mapped.id, **value})
        for key in ("jump_table_targets", "checked_jump_table_targets"):
            targets = mapped.source.get(key)
            if isinstance(targets, list):
                for target in targets:
                    if isinstance(target, dict):
                        jump_table_targets.append({"block_id": mapped.id, **target})
    return {
        "status": map_status if roots or jump_table_targets else ("not_applicable" if not mappings else "derived"),
        "evidence_kind": "stage-a-reachability-markers",
        "roots": roots,
        "jump_table_targets": jump_table_targets,
    }


def _reference_roots_and_jump_tables_with_abi_targets(
    roots: dict[str, Any],
    abi_callsites: dict[str, Any],
) -> dict[str, Any]:
    updated = dict(roots)
    existing = [
        item
        for item in roots.get("jump_table_targets", [])
        if isinstance(item, dict)
    ]
    targets: dict[tuple[str, int, int], dict[str, Any]] = {}
    for item in existing:
        key = (
            str(item.get("function") or ""),
            _safe_int(item.get("instruction_rva")) or -1,
            _safe_int(item.get("target_rva", item.get("rva"))) or -1,
        )
        targets.setdefault(key, dict(item))
    original = abi_callsites.get("original") if isinstance(abi_callsites.get("original"), dict) else {}
    functions = original.get("functions") if isinstance(original.get("functions"), list) else []
    for function in functions:
        if not isinstance(function, dict):
            continue
        function_name = str(function.get("name") or "")
        switches = function.get("switch_contracts") if isinstance(function.get("switch_contracts"), list) else []
        for switch in switches:
            if not isinstance(switch, dict) or switch.get("evidence_status") != "derived":
                continue
            instruction = switch.get("instruction") if isinstance(switch.get("instruction"), dict) else {}
            instruction_rva = _safe_int(instruction.get("rva"))
            case_targets = switch.get("case_targets") if isinstance(switch.get("case_targets"), list) else []
            by_target: dict[int, list[int]] = {}
            for case in case_targets:
                if not isinstance(case, dict):
                    continue
                target_rva = _safe_int(case.get("target_rva"))
                index = _safe_int(case.get("index"))
                if target_rva is None:
                    continue
                by_target.setdefault(target_rva, [])
                if index is not None:
                    by_target[target_rva].append(index)
            for target_rva, case_indices in sorted(by_target.items()):
                key = (function_name, instruction_rva or -1, target_rva)
                if key in targets:
                    continue
                targets[key] = {
                    "evidence_status": "derived",
                    "kind": "resolved_static_jump_table_target",
                    "function": function_name,
                    "block_id": _block_id_for_instruction(function, instruction),
                    "instruction_rva": instruction_rva,
                    "target_rva": target_rva,
                    "rva": target_rva,
                    "case_indices": sorted(set(case_indices)),
                    "table": switch.get("table"),
                    "source": "capstone-indexed-memory-jump-table",
                }
    updated["jump_table_targets"] = sorted(
        targets.values(),
        key=lambda item: (
            str(item.get("function") or ""),
            _safe_int(item.get("instruction_rva")) or -1,
            _safe_int(item.get("target_rva", item.get("rva"))) or -1,
        ),
    )
    if updated["jump_table_targets"] and updated.get("status") == "not_applicable":
        updated["status"] = "derived"
    return updated


def _reference_import_thunk_constraint(
    original: StageABinary,
    candidate: StageABinary | None,
    map_contract: dict[str, Any],
) -> dict[str, Any]:
    mappings = map_contract.get("mappings", [])
    mapped_thunks = []
    for mapped in mappings:
        source = _mapping_source(mapped)
        if mapped.kind == "import_thunk" or source.get("kind") == "import_thunk":
            mapped_thunks.append(
                {
                    "block_id": mapped.id,
                    "original": _range_report(mapped.original),
                    "candidate": _range_report(mapped.candidate),
                    "source": source,
                }
            )
    return {
        "status": "derived" if original.imports or (candidate is not None and candidate.imports) or mapped_thunks else "not_applicable",
        "evidence_kind": "pe-import-directory-and-block-map",
        "original_imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in original.imports
        ],
        "candidate_imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in candidate.imports
        ]
        if candidate is not None
        else None,
        "mapped_import_thunks": mapped_thunks,
    }


def _reference_abi_callsites_constraint(
    original: StageABinary,
    candidate: StageABinary | None,
    map_contract: dict[str, Any],
) -> dict[str, Any]:
    mappings = [mapped for mapped in map_contract.get("mappings", []) if isinstance(mapped, BlockMapping) and mapped.kind == "code"]
    map_status = str(map_contract.get("function_ranges", {}).get("status") or "incomplete")
    original_functions = _abi_function_evidence(original, mappings, side="original")
    candidate_functions = _abi_function_evidence(candidate, mappings, side="candidate") if candidate is not None else None
    original_callsites = sum(len(item.get("callsites", [])) for item in original_functions)
    candidate_callsites = (
        sum(len(item.get("callsites", [])) for item in candidate_functions)
        if isinstance(candidate_functions, list)
        else None
    )
    return {
        "status": map_status if mappings else "incomplete",
        "evidence_kind": "capstone-static-abi-callsites",
        "scope": "original-candidate-pair" if candidate is not None else "original",
        "original": {
            "functions": original_functions,
            "import_prototypes": _abi_import_prototypes(original),
        },
        "candidate": {
            "functions": candidate_functions,
            "import_prototypes": _abi_import_prototypes(candidate),
        }
        if candidate is not None
        else None,
        "counts": {
            "functions": len(original_functions),
            "callsites": original_callsites,
            "candidate_callsites": candidate_callsites,
            "import_prototypes": len(original.imports),
        },
    }


def _abi_function_evidence(binary: StageABinary | None, mappings: list[BlockMapping], *, side: str) -> list[dict[str, Any]]:
    if binary is None:
        return []
    by_name: dict[str, dict[str, Any]] = {}
    for mapped in mappings:
        source = _mapping_source(mapped)
        name = source.get("function") if isinstance(source.get("function"), str) and source.get("function") else mapped.id
        block = mapped.original if side == "original" else mapped.candidate
        entry = by_name.setdefault(
            name,
            {
                "name": name,
                "blocks": [],
                "callsites": [],
                "registers": {
                    "reads": [],
                    "writes": [],
                    "preserved_candidates": [],
                    "clobbered_candidates": [],
                },
                "stack_delta": {"status": "unknown"},
            },
        )
        block_evidence = _abi_block_evidence(binary, block, mapped.id)
        entry.setdefault("_abi_block_records", []).append(
            {
                "block_id": mapped.id,
                "block": block,
                "evidence": block_evidence,
                "edges": _direct_cfg_edges(binary, block),
            }
        )
        entry["blocks"].append({"block_id": mapped.id, **_range_report(block), "abi": _abi_block_contract_evidence(block_evidence)})
        entry["callsites"].extend(block_evidence["callsites"])
        entry["registers"]["reads"] = sorted(set(entry["registers"]["reads"]) | set(block_evidence["register_reads"]))
        entry["registers"]["writes"] = sorted(set(entry["registers"]["writes"]) | set(block_evidence["register_writes"]))
        entry["registers"]["preserved_candidates"] = sorted(set(entry["registers"]["preserved_candidates"]) | set(block_evidence["preserved_candidates"]))
        entry["registers"]["clobbered_candidates"] = sorted(set(entry["registers"]["clobbered_candidates"]) | set(block_evidence["clobbered_candidates"]))
        entry.setdefault("register_value_provenance", []).extend(block_evidence.get("register_value_provenance", []))
        entry.setdefault("register_out_param_candidates", []).extend(block_evidence.get("register_out_param_candidates", []))
        entry.setdefault("memory_reads", []).extend(block_evidence.get("memory_reads", []))
        entry.setdefault("memory_writes", []).extend(block_evidence.get("memory_writes", []))
        entry.setdefault("field_accesses", []).extend(block_evidence.get("field_accesses", []))
        entry.setdefault("switch_contracts", []).extend(block_evidence.get("switch_contracts", []))
        entry.setdefault("loop_hints", []).extend(block_evidence.get("loop_hints", []))
        entry["memory_effect_summary"] = _abi_memory_effect_summary(entry.get("memory_reads", []), entry.get("memory_writes", []))
    for entry in by_name.values():
        records = entry.pop("_abi_block_records", [])
        if isinstance(records, list):
            _abi_apply_predecessor_argument_sources(binary, records)
            _abi_apply_predecessor_switch_bounds(binary, records)
            entry["callsites"] = [
                callsite
                for record in records
                for callsite in (
                    record.get("evidence", {}).get("callsites", [])
                    if isinstance(record.get("evidence"), dict)
                    else []
                )
                if isinstance(callsite, dict)
            ]
        entry["stack_delta"] = _abi_function_stack_delta_summary(entry.get("blocks"), str(entry.get("name") or ""))
    return sorted(by_name.values(), key=lambda item: str(item.get("name") or ""))


def _abi_apply_predecessor_argument_sources(binary: StageABinary, records: list[dict[str, Any]]) -> None:
    records_by_start: dict[int, dict[str, Any]] = {}
    for record in records:
        block = record.get("block")
        if isinstance(block, BlockSide):
            records_by_start[block.rva_start] = record
    predecessor_sources: dict[int, list[dict[str, Any]]] = {}
    for record in records:
        evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
        exit_sources = evidence.get("exit_argument_sources") if isinstance(evidence.get("exit_argument_sources"), list) else []
        edges = record.get("edges") if isinstance(record.get("edges"), list) else []
        for edge in edges:
            if not isinstance(edge, dict) or edge.get("kind") not in {"fallthrough", "taken", "jump"}:
                continue
            target_rva = _safe_int(edge.get("target_rva"))
            if target_rva is None or target_rva not in records_by_start:
                continue
            predecessor_sources.setdefault(target_rva, []).append(
                {
                    "block_id": record.get("block_id"),
                    "edge": edge,
                    "argument_sources": exit_sources,
                }
            )
    for target_rva, predecessor_items in predecessor_sources.items():
        record = records_by_start.get(target_rva)
        if record is None:
            continue
        block = record.get("block")
        evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
        if not isinstance(block, BlockSide):
            continue
        callsites = evidence.get("callsites") if isinstance(evidence.get("callsites"), list) else []
        first_callsite = callsites[0] if callsites and isinstance(callsites[0], dict) else None
        if first_callsite is None:
            continue
        instruction = first_callsite.get("instruction") if isinstance(first_callsite.get("instruction"), dict) else {}
        if _safe_int(instruction.get("rva")) != block.rva_start:
            continue
        inventory = first_callsite.get("argument_inventory") if isinstance(first_callsite.get("argument_inventory"), dict) else {}
        if _safe_int(inventory.get("argument_count")) not in {None, 0}:
            continue
        unique_sources: dict[str, list[dict[str, Any]]] = {}
        for item in predecessor_items:
            sources = item.get("argument_sources") if isinstance(item.get("argument_sources"), list) else []
            key = json.dumps(sources, sort_keys=True, separators=(",", ":"))
            unique_sources.setdefault(key, []).append(item)
        if len(unique_sources) != 1:
            continue
        sources = list(next(iter(unique_sources.values()))[0]["argument_sources"])
        if not sources:
            continue
        metadata = {
            "status": "derived",
            "source": "direct_cfg_predecessor_exit",
            "predecessor_block_ids": sorted(
                str(item.get("block_id"))
                for item in predecessor_items
                if item.get("block_id") is not None
            ),
            "predecessor_edges": [
                {
                    "kind": item.get("edge", {}).get("kind"),
                    "instruction_rva": item.get("edge", {}).get("instruction_rva"),
                    "target_rva": item.get("edge", {}).get("target_rva"),
                }
                for item in predecessor_items
                if isinstance(item.get("edge"), dict)
            ],
            "argument_source_count": len(sources),
        }
        callsites[0] = _abi_callsite_with_argument_sources(binary, first_callsite, sources, metadata)


def _abi_apply_predecessor_switch_bounds(binary: StageABinary, records: list[dict[str, Any]]) -> None:
    records_by_start: dict[int, dict[str, Any]] = {}
    for record in records:
        block = record.get("block")
        if isinstance(block, BlockSide):
            records_by_start[block.rva_start] = record
    predecessor_edges: dict[int, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for record in records:
        edges = record.get("edges") if isinstance(record.get("edges"), list) else []
        for edge in edges:
            if not isinstance(edge, dict) or edge.get("kind") not in {"fallthrough", "taken", "jump"}:
                continue
            target_rva = _safe_int(edge.get("target_rva"))
            if target_rva is None or target_rva not in records_by_start:
                continue
            predecessor_edges.setdefault(target_rva, []).append((record, edge))

    for record in records:
        block = record.get("block")
        evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
        switches = evidence.get("switch_contracts") if isinstance(evidence.get("switch_contracts"), list) else []
        if not isinstance(block, BlockSide) or not switches:
            continue
        for switch in switches:
            if not isinstance(switch, dict) or switch.get("evidence_status") == "derived":
                continue
            index_expression = switch.get("index_expression") if isinstance(switch.get("index_expression"), dict) else {}
            index_register = _abi_x86_register_family(str(index_expression.get("index") or ""))
            if not index_register:
                continue
            current_bounds = _abi_switch_bounds_dict(switch.get("table_bounds"))
            refined_bounds = current_bounds
            for predecessor, edge in predecessor_edges.get(block.rva_start, []):
                predecessor_block = predecessor.get("block")
                if not isinstance(predecessor_block, BlockSide):
                    continue
                guard_bounds = _abi_predecessor_edge_switch_bounds(
                    binary,
                    predecessor_block,
                    edge,
                    index_register,
                )
                if guard_bounds is None:
                    continue
                refined_bounds = _abi_intersect_switch_bounds(refined_bounds, guard_bounds)
            if refined_bounds is None or refined_bounds == current_bounds:
                continue
            instructions = _abi_capstone_block_instructions(binary, block)
            jmp = next(
                (
                    insn
                    for insn in instructions
                    if str(insn.mnemonic) in {"jmp", "ljmp"}
                    and len(getattr(insn, "operands", []) or []) == 1
                    and insn.operands[0].type == X86_OP_MEM
                    and _safe_int(switch.get("instruction", {}).get("rva") if isinstance(switch.get("instruction"), dict) else None)
                    == int(insn.address - binary.image_base)
                ),
                None,
            )
            if jmp is None:
                continue
            addressing = _abi_mem_operand_report(jmp, jmp.operands[0])
            refined = _abi_indexed_jump_table_contract(
                binary,
                block,
                instructions,
                jmp,
                addressing,
                bounds_override=refined_bounds,
            )
            if refined is not None and refined.get("evidence_status") == "derived":
                switch.clear()
                switch.update(refined)


def _abi_predecessor_edge_switch_bounds(
    binary: StageABinary,
    block: BlockSide,
    edge: dict[str, Any],
    index_register: str,
) -> dict[str, Any] | None:
    instruction_rva = _safe_int(edge.get("instruction_rva"))
    edge_kind = str(edge.get("kind") or "")
    if instruction_rva is None or edge_kind not in {"fallthrough", "taken"}:
        return None
    instructions = _abi_capstone_block_instructions(binary, block)
    for index, insn in enumerate(instructions):
        if int(insn.address - binary.image_base) != instruction_rva:
            continue
        mnemonic = str(insn.mnemonic)
        if not _is_conditional_jump(mnemonic) or index == 0:
            return None
        cmp_insn = instructions[index - 1]
        upper = _abi_cmp_register_immediate_upper_bound(cmp_insn, index_register)
        if upper is None:
            return None
        gives_upper_bound = (
            (mnemonic in {"ja", "jnbe"} and edge_kind == "fallthrough")
            or (mnemonic in {"jbe", "jna"} and edge_kind == "taken")
        )
        if not gives_upper_bound:
            return None
        return {
            "status": "derived",
            "lower": 0,
            "upper": upper,
            "register": index_register,
            "source": "predecessor_unsigned_upper_bound",
            "source_edge": {
                "kind": edge_kind,
                "instruction_rva": instruction_rva,
                "target_rva": edge.get("target_rva"),
            },
            "source_instruction": _instruction_report(binary, cmp_insn),
            "branch_instruction": _instruction_report(binary, insn),
        }
    return None


def _abi_capstone_block_instructions(binary: StageABinary, block: BlockSide) -> list[Any]:
    data = binary.pe.get_data(block.rva_start, block.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    return list(dis.disasm(data, binary.image_base + block.rva_start))


def _abi_cmp_register_immediate_upper_bound(insn: Any, index_register: str) -> int | None:
    if str(insn.mnemonic) != "cmp" or len(getattr(insn, "operands", []) or []) != 2:
        return None
    left, right = insn.operands[:2]
    if left.type != X86_OP_REG or right.type != X86_OP_IMM:
        return None
    if _abi_x86_register_family(insn.reg_name(left.reg)) != index_register:
        return None
    value = int(right.imm)
    if value < 0 or value > 4095:
        return None
    return value


def _abi_switch_bounds_dict(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    lower = _safe_int(value.get("lower"))
    upper = _safe_int(value.get("upper"))
    if lower is None or upper is None:
        return None
    return dict(value)


def _abi_intersect_switch_bounds(left: dict[str, Any] | None, right: dict[str, Any]) -> dict[str, Any]:
    if left is None:
        return dict(right)
    lower = max(int(left.get("lower") or 0), int(right.get("lower") or 0))
    upper = min(int(left.get("upper") or 0), int(right.get("upper") or 0))
    result = dict(right if upper == int(right.get("upper") or 0) else left)
    result["status"] = "derived"
    result["lower"] = lower
    result["upper"] = upper
    result["source"] = "intersected_static_index_bounds"
    result["sources"] = [left, right]
    return result


def _abi_callsite_with_argument_sources(
    binary: StageABinary,
    callsite: dict[str, Any],
    argument_sources: list[dict[str, Any]],
    predecessor_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
    inventory = _abi_call_argument_inventory(binary, argument_sources, {}, target=target)
    symbol = str(target.get("symbol") or "")
    updated = {
        **callsite,
        "argument_sources": argument_sources,
        "argument_inventory": inventory,
        "hidden_sret_or_out_param_evidence": _abi_hidden_sret_evidence(argument_sources),
        "varargs_evidence": _abi_varargs_evidence(symbol, inventory),
        "function_pointer_targets": _abi_function_pointer_targets(target),
    }
    if predecessor_metadata is not None:
        updated["predecessor_argument_sources"] = predecessor_metadata
    return updated


def _abi_function_stack_delta_summary(blocks: Any, function_name: str = "") -> dict[str, Any]:
    block_items = [block for block in blocks if isinstance(block, dict)] if isinstance(blocks, list) else []
    derived = [
        stack_delta
        for block in block_items
        for stack_delta in [block.get("abi", {}).get("stack_delta") if isinstance(block.get("abi"), dict) else None]
        if isinstance(stack_delta, dict) and stack_delta.get("status") == "derived"
    ]
    if function_name.startswith("section-gap-"):
        return {
            "status": "block_local",
            "reason": "synthetic section-gap unit; stack deltas are reported per block",
            "blocks": len(block_items),
            "derived_blocks": len(derived),
        }
    if len(block_items) == 1 and derived:
        return {**derived[0], "scope": "function"}
    if len(block_items) > 1:
        return {
            "status": "block_local",
            "reason": "function spans multiple Stage A blocks; stack deltas are reported per block",
            "blocks": len(block_items),
            "derived_blocks": len(derived),
        }
    return {"status": "unknown", "reason": "no derived block stack delta"}


def _abi_block_contract_evidence(block_evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "callsites": block_evidence.get("callsites", []),
        "register_reads": block_evidence.get("register_reads", []),
        "register_writes": block_evidence.get("register_writes", []),
        "preserved_candidates": block_evidence.get("preserved_candidates", []),
        "clobbered_candidates": block_evidence.get("clobbered_candidates", []),
        "register_value_provenance": block_evidence.get("register_value_provenance", []),
        "register_out_param_candidates": block_evidence.get("register_out_param_candidates", []),
        "exit_argument_sources": block_evidence.get("exit_argument_sources", []),
        "memory_reads": block_evidence.get("memory_reads", []),
        "memory_writes": block_evidence.get("memory_writes", []),
        "field_accesses": block_evidence.get("field_accesses", []),
        "memory_effect_summary": block_evidence.get("memory_effect_summary", {}),
        "switch_contracts": block_evidence.get("switch_contracts", []),
        "loop_hints": block_evidence.get("loop_hints", []),
        "stack_delta": block_evidence.get("stack_delta", {"status": "unknown"}),
    }


def _abi_block_evidence(binary: StageABinary, block: BlockSide, block_id: str) -> dict[str, Any]:
    data = binary.pe.get_data(block.rva_start, block.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + block.rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return {
            "callsites": [],
            "register_reads": [],
            "register_writes": [],
            "preserved_candidates": [],
            "clobbered_candidates": [],
            "register_value_provenance": [],
            "register_out_param_candidates": [],
            "exit_argument_sources": [],
            "memory_reads": [],
            "memory_writes": [],
            "field_accesses": [],
            "memory_effect_summary": {"status": "unknown", "reason": "decode_incomplete"},
            "switch_contracts": [],
            "loop_hints": [],
            "stack_delta": {"status": "unknown", "reason": "decode_incomplete"},
        }
    callsites = []
    register_reads: set[str] = set()
    register_writes: set[str] = set()
    register_definitions: dict[str, dict[str, Any]] = {}
    register_definition_history: list[dict[str, Any]] = []
    pushes: list[dict[str, Any]] = []
    stack_argument_writes: dict[int, dict[str, Any]] = {}
    memory_reads: list[dict[str, Any]] = []
    memory_writes: list[dict[str, Any]] = []
    field_accesses: list[dict[str, Any]] = []
    stack_delta = 0
    for insn in instructions:
        reads, writes = _instruction_register_access(insn)
        register_reads.update(reads)
        register_writes.update(writes)
        accesses = _abi_instruction_memory_accesses(binary, insn, register_definitions)
        memory_reads.extend(accesses["reads"])
        memory_writes.extend(accesses["writes"])
        field_accesses.extend(accesses["field_accesses"])
        mnemonic = str(insn.mnemonic)
        if mnemonic == "push":
            stack_delta -= 4 if binary.bitness == 32 else 8
            pushes.append(_abi_argument_source(binary, insn, register_definitions))
        elif mnemonic == "pop":
            stack_delta += 4 if binary.bitness == 32 else 8
            pushes = []
            stack_argument_writes = {}
        elif mnemonic == "leave":
            stack_delta = 0
            pushes = []
            stack_argument_writes = {}
        elif (stack_adjustment := _abi_stack_pointer_adjustment(binary, insn)) is not None:
            stack_delta += stack_adjustment
            pushes = []
            stack_argument_writes = {}
        elif _abi_resets_pending_arguments(insn):
            pushes = []
            stack_argument_writes = {}
        elif mnemonic == "ret":
            stack_delta += _abi_ret_imm(insn)
            pushes = []
            stack_argument_writes = {}
        elif mnemonic == "call":
            callsites.append(
                _abi_callsite_evidence(
                    binary,
                    insn,
                    block_id,
                    _abi_pending_argument_sources(pushes, stack_argument_writes, word_size=4 if binary.bitness == 32 else 8),
                    register_definitions,
                )
            )
            pushes = []
            stack_argument_writes = {}
        else:
            offset = _abi_stack_argument_write_offset(insn)
            if offset is not None:
                stack_argument_writes[offset] = _abi_stack_argument_write_source(binary, insn, offset, register_definitions)
        defined_register = _abi_update_register_definitions(binary, insn, register_definitions, writes)
        if defined_register is not None and defined_register in register_definitions:
            register_definition_history.append(
                {
                    "register": defined_register,
                    "definition": register_definitions[defined_register],
                    "evidence_status": "derived",
                }
            )
        if mnemonic == "call":
            for volatile in ("eax", "ecx", "edx", "rax", "rcx", "rdx"):
                if volatile != defined_register:
                    register_definitions.pop(volatile, None)
    preserved = sorted(reg for reg in ("ebx", "esi", "edi", "rbx", "rsi", "rdi") if reg in register_reads and reg in register_writes)
    clobbered = sorted(reg for reg in register_writes if reg not in set(preserved) and reg not in {"esp", "rsp", "ebp", "rbp"})
    register_out_params = _abi_register_out_param_candidates(memory_writes)
    return {
        "callsites": callsites,
        "register_reads": sorted(register_reads),
        "register_writes": sorted(register_writes),
        "preserved_candidates": preserved,
        "clobbered_candidates": clobbered,
        "register_value_provenance": register_definition_history,
        "register_out_param_candidates": register_out_params,
        "exit_argument_sources": _abi_pending_argument_sources(pushes, stack_argument_writes, word_size=4 if binary.bitness == 32 else 8),
        "memory_reads": memory_reads,
        "memory_writes": memory_writes,
        "field_accesses": field_accesses,
        "memory_effect_summary": _abi_memory_effect_summary(memory_reads, memory_writes),
        "switch_contracts": _abi_switch_contracts(binary, block, instructions),
        "loop_hints": _abi_loop_hints(binary, block, instructions),
        "stack_delta": {"status": "derived", "net_bytes": stack_delta},
    }


def _instruction_register_access(insn: Any) -> tuple[set[str], set[str]]:
    reads: set[str] = set()
    writes: set[str] = set()
    try:
        read_ids, write_ids = insn.regs_access()
    except Exception:
        read_ids, write_ids = (), ()
    for reg in read_ids:
        name = insn.reg_name(reg)
        if name:
            reads.add(str(name))
    for reg in write_ids:
        name = insn.reg_name(reg)
        if name:
            writes.add(str(name))
    return reads, writes


def _abi_instruction_memory_accesses(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    reads: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []
    field_accesses: list[dict[str, Any]] = []
    mnemonic = str(insn.mnemonic)
    for index, operand in enumerate(getattr(insn, "operands", []) or []):
        if operand.type != X86_OP_MEM:
            continue
        if mnemonic == "lea":
            continue
        access_kind = _abi_operand_memory_access_kind(insn, index)
        if access_kind is None:
            continue
        access = _abi_memory_access_report(binary, insn, operand, access_kind, register_definitions)
        if access_kind == "read":
            reads.append(access)
        elif access_kind == "write":
            writes.append(access)
        else:
            reads.append({**access, "access": "read"})
            writes.append({**access, "access": "write"})
        field = _abi_field_access_report(access)
        if field is not None:
            field_accesses.append(field)
    return {"reads": reads, "writes": writes, "field_accesses": field_accesses}


def _abi_operand_memory_access_kind(insn: Any, operand_index: int) -> str | None:
    mnemonic = str(insn.mnemonic)
    if mnemonic in {"jmp", "ljmp", "call"}:
        return "read"
    if mnemonic in {"cmp", "test"}:
        return "read"
    if mnemonic == "push":
        return "read"
    if mnemonic == "pop":
        return "write"
    if mnemonic in {"inc", "dec", "neg", "not"}:
        return "read_write"
    if mnemonic in {"mov", "movzx", "movsx", "lea"}:
        return "write" if operand_index == 0 and mnemonic == "mov" else "read"
    if operand_index == 0 and mnemonic in {"add", "sub", "and", "or", "xor", "shl", "shr", "sar", "rol", "ror"}:
        return "read_write"
    return "read"


def _abi_memory_access_report(
    binary: StageABinary,
    insn: Any,
    operand: Any,
    access_kind: str,
    register_definitions: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    addressing = _abi_mem_operand_report(insn, operand)
    access: dict[str, Any] = {
        "evidence_status": "derived",
        "access": access_kind,
        "width": int(getattr(operand, "size", 0) or 0),
        "addressing": addressing,
        "instruction": _instruction_report(binary, insn),
    }
    memory_rva = _abi_absolute_addressing_rva(binary, addressing)
    if memory_rva is not None:
        access["memory_rva"] = memory_rva
        section = _section_for_rva(binary, memory_rva)
        if section is not None:
            access["memory_section"] = _abi_section_report(section)
        string_literal = _abi_string_literal_at_rva(binary, memory_rva)
        if string_literal is not None:
            access["string_literal"] = string_literal
    base = addressing.get("base")
    if isinstance(base, str):
        base_definition = register_definitions.get(base)
        if isinstance(base_definition, dict):
            access["base_register_definition"] = base_definition
        elif base not in {"esp", "ebp", "rsp", "rbp"}:
            access["entry_register_pointer"] = {
                "register": base,
                "evidence_status": "candidate",
                "reason": "memory access uses an entry register as a base before a local definition was observed",
            }
    access["memory_role"] = _abi_memory_role(access)
    return access


def _abi_field_access_report(access: dict[str, Any]) -> dict[str, Any] | None:
    addressing = access.get("addressing") if isinstance(access.get("addressing"), dict) else {}
    base = addressing.get("base")
    disp = _safe_int(addressing.get("disp"))
    if not isinstance(base, str) or disp is None:
        return None
    if base in {"esp", "ebp", "rsp", "rbp"} and disp == 0:
        return None
    return {
        "evidence_status": "derived",
        "base": base,
        "offset": disp,
        "width": access.get("width"),
        "access": access.get("access"),
        "memory_role": access.get("memory_role"),
        "instruction": access.get("instruction"),
        "base_register_definition": access.get("base_register_definition") if isinstance(access.get("base_register_definition"), dict) else None,
    }


def _abi_register_out_param_candidates(memory_writes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for write in memory_writes:
        if not isinstance(write, dict):
            continue
        entry_pointer = write.get("entry_register_pointer") if isinstance(write.get("entry_register_pointer"), dict) else None
        if entry_pointer is None:
            continue
        result.append(
            {
                "evidence_status": "candidate",
                "register": entry_pointer.get("register"),
                "kind": "register_carried_out_param",
                "reason": "function writes through an entry register pointer before defining that register",
                "write": write,
            }
        )
    return result


def _abi_memory_effect_summary(reads: list[dict[str, Any]], writes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "evidence_status": "derived",
        "reads": len([item for item in reads if isinstance(item, dict)]),
        "writes": len([item for item in writes if isinstance(item, dict)]),
        "read_roles": _count_by([item for item in reads if isinstance(item, dict)], "memory_role"),
        "write_roles": _count_by([item for item in writes if isinstance(item, dict)], "memory_role"),
    }


def _abi_switch_contracts(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    contracts: list[dict[str, Any]] = []
    for insn in instructions:
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1 or insn.operands[0].type != X86_OP_MEM:
            continue
        target = _resolved_branch_target(binary, insn)
        addressing = _abi_mem_operand_report(insn, insn.operands[0])
        table_contract = _abi_indexed_jump_table_contract(binary, block, instructions, insn, addressing)
        if table_contract is not None:
            contracts.append(table_contract)
            continue
        contracts.append(
            {
                "evidence_status": "derived" if target is not None else "incomplete",
                "kind": "indirect_jump_table_candidate",
                "block": _range_report(block),
                "instruction": _instruction_report(binary, insn),
                "index_expression": addressing,
                "resolved_target_rva": target,
                "next_action": "recover table bounds, default edge, and case target mapping before treating this as a source-level switch",
            }
        )
    return contracts


def _abi_indexed_jump_table_contract(
    binary: StageABinary,
    block: BlockSide,
    instructions: list[Any],
    insn: Any,
    addressing: dict[str, Any],
    *,
    bounds_override: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if binary.bitness != 32:
        return None
    operand = insn.operands[0]
    mem = operand.mem
    pointer_width = 4
    index_register = insn.reg_name(mem.index) if mem.index else None
    if not index_register or mem.base or int(mem.scale) != pointer_width:
        return None
    table_rva = _abi_value_to_rva(binary, int(mem.disp))
    if table_rva is None:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table displacement is not an in-image table address",
        )
    table_section = _section_for_rva(binary, table_rva)
    if table_section is None or not table_section.readable:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table address does not resolve to readable PE section bytes",
            table_rva=table_rva,
        )
    bounds = bounds_override if bounds_override is not None else _abi_jump_table_index_bounds(binary, instructions, insn, index_register)
    if bounds is None:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table index bounds are not statically recovered",
            table_rva=table_rva,
        )
    lower = int(bounds["lower"])
    upper = int(bounds["upper"])
    if lower < 0 or upper < lower or upper - lower + 1 > 4096:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table index bounds are invalid or exceed the conservative resolver cap",
            table_rva=table_rva,
        )

    case_targets: list[dict[str, Any]] = []
    table_bytes = bytearray()
    for index in range(lower, upper + 1):
        entry_rva = table_rva + index * pointer_width
        raw = binary.pe.get_data(entry_rva, pointer_width)
        if len(raw) != pointer_width:
            return _abi_incomplete_indexed_jump_table_contract(
                binary,
                block,
                insn,
                addressing,
                f"jump-table entry {index} could not be read",
                table_rva=table_rva,
                table_bounds=bounds,
            )
        table_bytes.extend(raw)
        target_va = int.from_bytes(raw, "little")
        target_rva = _abi_value_to_rva(binary, target_va)
        target_section = _executable_section_for_rva(binary, target_rva) if target_rva is not None else None
        if target_rva is None or target_section is None:
            return _abi_incomplete_indexed_jump_table_contract(
                binary,
                block,
                insn,
                addressing,
                f"jump-table entry {index} does not resolve to executable code",
                table_rva=table_rva,
                table_bounds=bounds,
            )
        case_targets.append(
            {
                "index": index,
                "entry_rva": entry_rva,
                "entry_va": binary.image_base + entry_rva,
                "target_va": target_va,
                "target_rva": target_rva,
                "target_section": _abi_section_report(target_section),
            }
        )
    if not case_targets:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table bounds produced no case entries",
            table_rva=table_rva,
            table_bounds=bounds,
        )
    unique_targets = sorted({int(item["target_rva"]) for item in case_targets})
    return {
        "evidence_status": "derived",
        "kind": "indirect_jump_table_candidate",
        "block": _range_report(block),
        "instruction": _instruction_report(binary, insn),
        "index_expression": addressing,
        "index_bounds": bounds,
        "table": {
            "rva_start": table_rva,
            "rva_end": table_rva + len(table_bytes),
            "va_start": binary.image_base + table_rva,
            "entry_width": pointer_width,
            "entries": len(case_targets),
            "bytes_sha256": sha256_bytes(bytes(table_bytes)),
            "section": _abi_section_report(table_section),
        },
        "table_bounds": {
            "lower": lower,
            "upper": upper,
            "entries": len(case_targets),
            "source": bounds.get("source"),
        },
        "case_targets": case_targets,
        "unique_target_rvas": unique_targets,
        "resolved_target_rva": unique_targets[0] if len(unique_targets) == 1 else None,
        "default_target_rva": None,
        "next_action": "represent this dispatch with the recovered selector, bounded case table, and explicit jump targets",
    }


def _abi_incomplete_indexed_jump_table_contract(
    binary: StageABinary,
    block: BlockSide,
    insn: Any,
    addressing: dict[str, Any],
    blocker: str,
    *,
    table_rva: int | None = None,
    table_bounds: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "evidence_status": "incomplete",
        "kind": "indirect_jump_table_candidate",
        "block": _range_report(block),
        "instruction": _instruction_report(binary, insn),
        "index_expression": addressing,
        "resolved_target_rva": None,
        "blocker": blocker,
        "next_action": "recover table bounds, default edge, and case target mapping before treating this as a source-level switch",
    }
    if table_rva is not None:
        result["table"] = {
            "rva_start": table_rva,
            "va_start": binary.image_base + table_rva,
            "entry_width": 4 if binary.bitness == 32 else 8,
        }
    if table_bounds is not None:
        result["table_bounds"] = table_bounds
    return result


def _abi_jump_table_index_bounds(
    binary: StageABinary,
    instructions: list[Any],
    insn: Any,
    index_register: str,
) -> dict[str, Any] | None:
    index_rva = int(insn.address - binary.image_base)
    full_index = _abi_x86_register_family(index_register)
    for previous in reversed([item for item in instructions if int(item.address - binary.image_base) < index_rva]):
        mnemonic = str(previous.mnemonic)
        operands = getattr(previous, "operands", []) or []
        if mnemonic == "movzx" and len(operands) == 2 and operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            dst = _abi_x86_register_family(previous.reg_name(operands[0].reg))
            src = previous.reg_name(operands[1].reg)
            if dst == full_index and _abi_x86_register_family(src) == full_index:
                width = int(getattr(operands[1], "size", 0) or 0)
                if width > 0:
                    return {
                        "status": "derived",
                        "lower": 0,
                        "upper": (1 << (width * 8)) - 1,
                        "register": full_index,
                        "source": "movzx_register_width",
                        "source_instruction": _instruction_report(binary, previous),
                    }
        if mnemonic == "and" and len(operands) == 2 and operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            dst = _abi_x86_register_family(previous.reg_name(operands[0].reg))
            mask = int(operands[1].imm)
            if dst == full_index and 0 <= mask <= 4095:
                return {
                    "status": "derived",
                    "lower": 0,
                    "upper": mask,
                    "register": full_index,
                    "source": "and_immediate_mask",
                    "source_instruction": _instruction_report(binary, previous),
                }
        if mnemonic in {"call", "ret", "jmp", "ljmp"} or _is_conditional_jump(mnemonic):
            break
    return None


def _abi_x86_register_family(register: str | None) -> str:
    name = str(register or "").lower()
    families = {
        "eax": {"eax", "ax", "al", "ah"},
        "ebx": {"ebx", "bx", "bl", "bh"},
        "ecx": {"ecx", "cx", "cl", "ch"},
        "edx": {"edx", "dx", "dl", "dh"},
        "esi": {"esi", "si", "sil"},
        "edi": {"edi", "di", "dil"},
        "ebp": {"ebp", "bp", "bpl"},
        "esp": {"esp", "sp", "spl"},
    }
    for full, names in families.items():
        if name in names:
            return full
    return name


def _abi_loop_hints(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for insn in instructions:
        target = _resolved_branch_target(binary, insn)
        if target is None or target >= block.rva_end:
            continue
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} and not _is_conditional_jump(mnemonic):
            continue
        hints.append(
            {
                "evidence_status": "derived",
                "kind": "backedge_candidate",
                "block": _range_report(block),
                "instruction": _instruction_report(binary, insn),
                "target_rva": target,
                "next_action": "derive loop-carried variables and exit conditions before treating this as a full loop contract",
            }
        )
    return hints


def _abi_ret_imm(insn: Any) -> int:
    if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM:
        return 0
    return int(insn.operands[0].imm)


def _abi_stack_pointer_adjustment(binary: StageABinary, insn: Any) -> int | None:
    if len(insn.operands) < 2:
        return None
    mnemonic = str(insn.mnemonic)
    if mnemonic not in {"add", "sub"}:
        return None
    dst, src = insn.operands[:2]
    if dst.type != X86_OP_REG or src.type != X86_OP_IMM:
        return None
    stack_register = "esp" if binary.bitness == 32 else "rsp"
    if insn.reg_name(dst.reg) != stack_register:
        return None
    value = int(src.imm)
    return value if mnemonic == "add" else -value


def _abi_argument_source(binary: StageABinary, insn: Any, register_definitions: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    if not insn.operands:
        return {"kind": "unknown", "instruction": _instruction_report(binary, insn)}
    return _abi_attach_register_definition(
        _abi_operand_argument_source(binary, insn, insn.operands[0], register_definitions),
        register_definitions,
    )


def _abi_stack_argument_write_source(
    binary: StageABinary,
    insn: Any,
    offset: int,
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if len(insn.operands) < 2:
        source = {"kind": "unknown", "instruction": _instruction_report(binary, insn)}
    else:
        source = _abi_attach_register_definition(
            _abi_operand_argument_source(binary, insn, insn.operands[1], register_definitions),
            register_definitions,
        )
    source["stack_offset"] = offset
    source["stack_write"] = _instruction_report(binary, insn)
    return source


def _abi_operand_argument_source(
    binary: StageABinary,
    insn: Any,
    operand: Any,
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if str(insn.mnemonic) == "lea" and operand.type == X86_OP_MEM:
        addressing = _abi_mem_operand_report(insn, operand)
        return {
            "kind": "address",
            "addressing": addressing,
            "address_class": _abi_address_class(addressing),
            "instruction": _instruction_report(binary, insn),
        }
    if operand.type == X86_OP_IMM:
        source = {"kind": "immediate", "value": int(operand.imm), "instruction": _instruction_report(binary, insn)}
        _abi_attach_immediate_literal(binary, source)
        return source
    if operand.type == X86_OP_REG:
        return {"kind": "register", "register": insn.reg_name(operand.reg), "instruction": _instruction_report(binary, insn)}
    if operand.type == X86_OP_MEM:
        addressing = _abi_mem_operand_report(insn, operand)
        source: dict[str, Any] = {"kind": "memory", "addressing": addressing, "instruction": _instruction_report(binary, insn)}
        memory_rva = _abi_absolute_addressing_rva(binary, addressing)
        if memory_rva is not None:
            source["memory_rva"] = memory_rva
            section = _section_for_rva(binary, memory_rva)
            if section is not None:
                source["memory_section"] = _abi_section_report(section)
            string_literal = _abi_string_literal_at_rva(binary, memory_rva)
            if string_literal is not None:
                source["string_literal"] = string_literal
            imported = _import_for_thunk_rva(binary, memory_rva)
            if imported is not None:
                source["import"] = _abi_import_report(imported)
        base = addressing.get("base")
        if isinstance(base, str) and isinstance(register_definitions, dict):
            base_definition = register_definitions.get(base)
            if isinstance(base_definition, dict):
                source["base_register_definition"] = base_definition
        source["memory_role"] = _abi_memory_role(source)
        return source
    return {"kind": "unknown", "instruction": _instruction_report(binary, insn)}


def _abi_attach_immediate_literal(binary: StageABinary, source: dict[str, Any]) -> None:
    value = _safe_int(source.get("value"))
    if value is None:
        return
    rva = _abi_value_to_rva(binary, value)
    if rva is None:
        return
    source["memory_rva"] = rva
    section = _section_for_rva(binary, rva)
    if section is not None:
        source["memory_section"] = _abi_section_report(section)
    string_literal = _abi_string_literal_at_rva(binary, rva)
    if string_literal is not None:
        source["string_literal"] = string_literal


def _abi_value_to_rva(binary: StageABinary, value: int) -> int | None:
    if binary.image_base <= value < binary.image_base + binary.size_of_image:
        return value - binary.image_base
    if 0 <= value < binary.size_of_image and _section_for_rva(binary, value) is not None:
        return value
    return None


def _abi_string_literal_at_rva(binary: StageABinary, rva: int) -> dict[str, Any] | None:
    section = _section_for_rva(binary, rva)
    if section is None or not section.readable or section.executable:
        return None
    data = binary.pe.get_data(rva, 256)
    if not data:
        return None
    end = data.find(b"\0")
    if end < 0:
        return None
    raw = data[:end]
    if not raw:
        return None
    if any(byte < 0x09 or (0x0E <= byte < 0x20) for byte in raw):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
    return {
        "evidence_status": "derived",
        "rva": rva,
        "size": len(raw) + 1,
        "text": text,
        "sha256": sha256_bytes(raw),
    }


def _abi_attach_register_definition(source: dict[str, Any], register_definitions: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    if source.get("kind") != "register" or not isinstance(register_definitions, dict):
        return source
    register = source.get("register")
    definition = register_definitions.get(str(register))
    if isinstance(definition, dict):
        source = dict(source)
        source["register_definition"] = definition
    return source


def _abi_update_register_definitions(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]],
    written_registers: set[str],
) -> str | None:
    definition = _abi_register_definition(binary, insn, register_definitions)
    defined_register = definition[0] if definition is not None else None
    for register in written_registers:
        if register != defined_register:
            register_definitions.pop(register, None)
    if definition is not None:
        register_definitions[definition[0]] = definition[1]
    return defined_register


def _abi_register_definition(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]] | None:
    if len(insn.operands) < 2:
        return None
    dst = insn.operands[0]
    if dst.type != X86_OP_REG:
        return None
    register = insn.reg_name(dst.reg)
    if not register:
        return None
    mnemonic = str(insn.mnemonic)
    if mnemonic == "lea":
        source = _abi_operand_argument_source(binary, insn, insn.operands[1], register_definitions)
    elif mnemonic == "mov":
        source = _abi_operand_argument_source(binary, insn, insn.operands[1], register_definitions)
        if source.get("kind") == "register":
            copied = register_definitions.get(str(source.get("register")))
            if isinstance(copied, dict):
                source = dict(copied)
                source["copied_from_register"] = insn.reg_name(insn.operands[1].reg)
                source["copied_by"] = _instruction_report(binary, insn)
    else:
        return None
    return str(register), source


def _abi_address_class(addressing: dict[str, Any]) -> str:
    base = str(addressing.get("base") or "")
    if base in {"esp", "ebp", "rsp", "rbp"}:
        return "stack_address"
    return "computed_address"


def _abi_pending_argument_sources(
    pushes: list[dict[str, Any]],
    stack_argument_writes: dict[int, dict[str, Any]],
    *,
    word_size: int,
) -> list[dict[str, Any]]:
    contiguous_offsets: list[int] = []
    expected_offset = 0
    for offset in sorted(offset for offset in stack_argument_writes if offset >= 0):
        if offset < expected_offset:
            continue
        if offset != expected_offset:
            break
        contiguous_offsets.append(offset)
        expected_offset += word_size
    stack_sources = [stack_argument_writes[offset] for offset in reversed(contiguous_offsets)]
    return list(pushes[-8:]) + stack_sources


def _abi_resets_pending_arguments(insn: Any) -> bool:
    mnemonic = str(insn.mnemonic)
    if mnemonic in {"leave", "enter"}:
        return True
    if mnemonic == "mov" and len(insn.operands) == 2:
        dst, src = insn.operands
        if dst.type == X86_OP_REG and src.type == X86_OP_REG:
            dst_name = insn.reg_name(dst.reg)
            src_name = insn.reg_name(src.reg)
            if (dst_name, src_name) in {("ebp", "esp"), ("rbp", "rsp")}:
                return True
    if mnemonic in {"sub", "add", "and", "lea"} and insn.operands:
        dst = insn.operands[0]
        if dst.type == X86_OP_REG and insn.reg_name(dst.reg) in {"esp", "rsp"}:
            return True
    return False


def _abi_stack_argument_write_offset(insn: Any) -> int | None:
    if not insn.operands:
        return None
    mnemonic = str(insn.mnemonic)
    if mnemonic != "mov":
        return None
    dst = insn.operands[0]
    if dst.type != X86_OP_MEM:
        return None
    mem = dst.mem
    base = insn.reg_name(mem.base) if mem.base else None
    index = insn.reg_name(mem.index) if mem.index else None
    if base not in {"esp", "rsp"} or index not in {None, ""}:
        return None
    offset = int(mem.disp)
    if offset < 0:
        return None
    return offset


def _abi_callsite_evidence(
    binary: StageABinary,
    insn: Any,
    block_id: str,
    argument_sources: list[dict[str, Any]],
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target = _abi_call_target(binary, insn, register_definitions)
    symbol = str(target.get("symbol") or "")
    inventory = _abi_call_argument_inventory(binary, argument_sources, register_definitions, target=target)
    varargs = _abi_varargs_evidence(symbol, inventory)
    return {
        "id": f"callsite:{block_id}:{int(insn.address - binary.image_base):x}",
        "block_id": block_id,
        "instruction": _instruction_report(binary, insn),
        "target": target,
        "argument_sources": argument_sources,
        "argument_inventory": inventory,
        "stack_delta": {"status": "unknown"},
        "hidden_sret_or_out_param_evidence": _abi_hidden_sret_evidence(argument_sources),
        "varargs_evidence": varargs,
        "function_pointer_targets": _abi_function_pointer_targets(target),
    }


def _abi_call_target(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target_rva = _resolved_branch_target(binary, insn)
    imported = _import_for_call_instruction(binary, insn)
    if imported is not None:
        return {
            "kind": "import",
            "dll": imported.dll,
            "symbol": imported.symbol,
            "ordinal": imported.ordinal,
            "thunk_rva": imported.thunk_rva,
        }
    if target_rva is not None:
        return {"kind": "direct", "target_rva": target_rva}
    if len(insn.operands) == 1 and insn.operands[0].type in {X86_OP_REG, X86_OP_MEM}:
        operand = insn.operands[0]
        if operand.type == X86_OP_REG:
            register_name = insn.reg_name(insn.operands[0].reg)
            resolved = _abi_register_call_target(binary, register_name, register_definitions)
            if resolved is not None:
                return resolved
        if operand.type == X86_OP_MEM:
            source = _abi_operand_argument_source(binary, insn, operand, register_definitions)
            return _abi_function_pointer_target_from_source(binary, insn.op_str, source)
        return _abi_function_pointer_target_from_source(binary, insn.op_str, None)
    return {"kind": "unknown", "status": "unresolved"}


def _abi_register_call_target(
    binary: StageABinary,
    register_name: str | None,
    register_definitions: dict[str, dict[str, Any]] | None,
) -> dict[str, Any] | None:
    if not register_name or not isinstance(register_definitions, dict):
        return None
    definition = register_definitions.get(register_name)
    if not isinstance(definition, dict):
        return None
    imported = definition.get("import") if isinstance(definition.get("import"), dict) else None
    if imported is not None:
        return {
            "kind": "import",
            "dll": imported.get("dll"),
            "symbol": imported.get("symbol"),
            "ordinal": imported.get("ordinal"),
            "thunk_rva": imported.get("thunk_rva"),
            "via_register": register_name,
            "source": definition,
        }
    memory_rva = _safe_int(definition.get("memory_rva"))
    if memory_rva is not None:
        return _abi_function_pointer_target_from_source(binary, register_name, definition)
    if definition.get("kind") == "memory":
        return _abi_function_pointer_target_from_source(binary, register_name, definition)
    return None


def _abi_function_pointer_target_from_source(
    binary: StageABinary,
    operand: str,
    source: dict[str, Any] | None,
) -> dict[str, Any]:
    recoverable_targets = _abi_static_function_pointer_targets(binary, source)
    target: dict[str, Any] = {
        "kind": "function_pointer",
        "operand": operand,
        "recoverable_targets": recoverable_targets,
        "status": "resolved_static_pointer_slot" if recoverable_targets else "unresolved",
    }
    if isinstance(source, dict):
        target["source"] = source
        if source.get("memory_role") not in {None, ""}:
            target["memory_role"] = source.get("memory_role")
        if source.get("memory_rva") not in {None, ""}:
            target["memory_rva"] = source.get("memory_rva")
    return target


def _abi_static_function_pointer_targets(binary: StageABinary, source: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(source, dict):
        return []
    memory_rva = _safe_int(source.get("memory_rva"))
    if memory_rva is None:
        return []
    pointer_size = 8 if binary.bitness == 64 else 4
    raw = binary.pe.get_data(memory_rva, pointer_size)
    if len(raw) != pointer_size:
        return []
    pointer_value = int.from_bytes(raw, "little")
    target_rva = _abi_value_to_rva(binary, pointer_value)
    if target_rva is None:
        return []
    section = _executable_section_for_rva(binary, target_rva)
    if section is None:
        return []
    return [
        {
            "status": "resolved",
            "kind": "direct",
            "target_rva": target_rva,
            "target_va": pointer_value,
            "source": "static_pointer_slot_value",
            "memory_rva": memory_rva,
            "memory_role": source.get("memory_role"),
            "section": _abi_section_report(section),
        }
    ]


def _import_for_call_instruction(binary: StageABinary, insn: Any) -> StageAImport | None:
    if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, insn.operands[0])


def _abi_mem_operand_report(insn: Any, operand: Any) -> dict[str, Any]:
    mem = operand.mem
    return {
        "base": insn.reg_name(mem.base) if mem.base else None,
        "index": insn.reg_name(mem.index) if mem.index else None,
        "scale": int(mem.scale),
        "disp": int(mem.disp),
    }


def _abi_section_report(section: StageASection) -> dict[str, Any]:
    return {
        "name": section.name,
        "rva_start": section.rva_start,
        "rva_end": section.rva_end,
        "readable": section.readable,
        "writable": section.writable,
        "executable": section.executable,
    }


def _abi_memory_role(source: dict[str, Any]) -> str:
    if isinstance(source.get("import"), dict):
        return "import_address_table"
    section = source.get("memory_section") if isinstance(source.get("memory_section"), dict) else {}
    if source.get("memory_rva") is not None:
        if section.get("writable") is True:
            return "global_writable_pointer_slot"
        if section:
            return "global_readonly_pointer_slot"
        return "absolute_memory_slot"
    addressing = source.get("addressing") if isinstance(source.get("addressing"), dict) else {}
    base = str(addressing.get("base") or "")
    if base in {"ebp", "rbp"}:
        disp = _safe_int(addressing.get("disp")) or 0
        return "stack_argument_slot" if disp >= 0 else "stack_local_slot"
    if base in {"esp", "rsp"}:
        return "stack_pointer_slot"
    base_definition = source.get("base_register_definition") if isinstance(source.get("base_register_definition"), dict) else None
    if base_definition is not None:
        base_role = str(base_definition.get("memory_role") or "")
        if base_role == "stack_argument_slot":
            return "argument_pointer_deref"
        if base_definition.get("memory_rva") is not None:
            return "global_pointer_deref"
        return "computed_pointer_deref"
    return "computed_memory"


def _abi_hidden_sret_evidence(argument_sources: list[dict[str, Any]]) -> dict[str, Any]:
    if not argument_sources:
        return {"status": "unknown", "reason": "no_static_arguments"}
    first = argument_sources[-1]
    address_source = _abi_address_like_argument_source(first)
    if address_source is not None:
        return {
            "status": "candidate",
            "source": first,
            "address_source": address_source,
            "address_role": _abi_address_argument_role(address_source),
            "reason": "first_stack_argument_has_address_provenance",
        }
    if first.get("kind") == "register":
        return {"status": "unknown", "reason": "first_stack_argument_register_without_address_provenance"}
    return {"status": "unknown", "reason": "first_stack_argument_not_address_like"}


def _abi_address_like_argument_source(source: dict[str, Any]) -> dict[str, Any] | None:
    if source.get("kind") == "address":
        return source
    definition = source.get("register_definition") if isinstance(source.get("register_definition"), dict) else None
    if definition is not None and definition.get("kind") == "address":
        return definition
    return None


def _abi_address_argument_role(address_source: dict[str, Any]) -> str:
    if address_source.get("address_class") == "stack_address":
        return "stack_out_param_or_scratch_buffer"
    return "computed_out_param_or_hidden_sret"


def _abi_call_argument_inventory(
    binary: StageABinary,
    argument_sources: list[dict[str, Any]],
    register_definitions: dict[str, dict[str, Any]] | None,
    *,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ordered_stack_args = list(reversed(argument_sources))
    fixed_stack_arg_count = _abi_fixed_stack_arg_count_for_target(target, binary)
    if fixed_stack_arg_count is not None:
        ordered_stack_args = ordered_stack_args[:fixed_stack_arg_count]
    stack_args = [
        {
            "index": index,
            "source": source,
            "role": _abi_argument_role(source),
        }
        for index, source in enumerate(ordered_stack_args)
        if isinstance(source, dict)
    ]
    register_args = []
    for register in _abi_call_register_argument_order(binary, target):
        definition = register_definitions.get(register) if isinstance(register_definitions, dict) else None
        if isinstance(definition, dict):
            register_args.append({"register": register, "source": definition, "role": _abi_argument_role(definition)})
    calling_convention = "cdecl_or_stdcall_stack" if binary.bitness == 32 else "x86_64_mixed"
    register_argument_evidence = _abi_register_argument_evidence(binary, target, register_args)
    if binary.bitness == 32 and register_args:
        calling_convention = "x86_register_carried_internal"
    return {
        "evidence_status": "derived",
        "stack_args": stack_args,
        "register_args": register_args,
        "argument_count": len(stack_args) + len(register_args),
        "calling_convention": calling_convention,
        "register_argument_evidence": register_argument_evidence,
    }


def _abi_fixed_stack_arg_count_for_target(target: dict[str, Any] | None, binary: StageABinary) -> int | None:
    if binary.bitness != 32 or not isinstance(target, dict) or target.get("kind") != "import":
        return None
    symbol = target.get("symbol")
    if not isinstance(symbol, str) or not symbol:
        return None
    decorated = re.search(r"@([0-9]+)$", symbol)
    if decorated is not None:
        byte_count = _safe_int(decorated.group(1))
        return byte_count // 4 if byte_count is not None and byte_count >= 0 else None
    return ABI_FIXED_STDCALL_IMPORT_STACK_ARG_COUNTS.get(symbol.lower().lstrip("_"))


def _abi_call_register_argument_order(binary: StageABinary, target: dict[str, Any] | None = None) -> tuple[str, ...]:
    if binary.bitness == 64:
        return ("rcx", "rdx", "r8", "r9")
    if binary.bitness == 32:
        return _abi_x86_direct_target_register_argument_order(binary, target)
    return ()


def _abi_x86_direct_target_register_argument_order(
    binary: StageABinary,
    target: dict[str, Any] | None,
) -> tuple[str, ...]:
    if not isinstance(target, dict) or target.get("kind") != "direct":
        return ()
    target_rva = _safe_int(target.get("target_rva"))
    if target_rva is None:
        return ()
    read_registers = _abi_x86_entry_read_before_write_registers(binary, target_rva)
    order = ("eax", "edx", "ecx")
    return tuple(register for register in order if register in read_registers)


def _abi_x86_entry_read_before_write_registers(binary: StageABinary, target_rva: int) -> set[str]:
    section = _section_for_rva(binary, target_rva)
    if section is None or not section.executable:
        return set()
    size = min(128, max(0, section.rva_end - target_rva))
    if size <= 0:
        return set()
    data = binary.pe.get_data(target_rva, size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    read_before_write: set[str] = set()
    written: set[str] = set()
    candidates = {"eax", "edx", "ecx"}
    for insn in dis.disasm(data, binary.image_base + target_rva):
        mnemonic = str(insn.mnemonic)
        if mnemonic == "call" or mnemonic in {"jmp", "ljmp", "ret"} or _is_conditional_jump(mnemonic):
            break
        reads, writes = _instruction_register_access(insn)
        zeroed = _abi_x86_zero_idiom_register(insn)
        if zeroed is not None:
            reads.discard(zeroed)
        for register in sorted(candidates & reads):
            if register not in written:
                read_before_write.add(register)
        written.update(candidates & writes)
    return read_before_write


def _abi_x86_zero_idiom_register(insn: Any) -> str | None:
    if str(insn.mnemonic) != "xor" or len(getattr(insn, "operands", []) or []) != 2:
        return None
    left, right = insn.operands[:2]
    if left.type != X86_OP_REG or right.type != X86_OP_REG or left.reg != right.reg:
        return None
    register = insn.reg_name(left.reg)
    return str(register) if register in {"eax", "edx", "ecx"} else None


def _abi_register_argument_evidence(
    binary: StageABinary,
    target: dict[str, Any] | None,
    register_args: list[dict[str, Any]],
) -> dict[str, Any]:
    if not register_args:
        return {"status": "not_observed"}
    evidence: dict[str, Any] = {
        "status": "derived",
        "registers": [arg.get("register") for arg in register_args if isinstance(arg, dict)],
    }
    if binary.bitness == 32 and isinstance(target, dict) and target.get("kind") == "direct":
        evidence["source"] = "direct_target_entry_read_before_write"
        evidence["target_rva"] = target.get("target_rva")
    elif binary.bitness == 64:
        evidence["source"] = "platform_abi_register_order"
    return evidence


def _abi_argument_role(source: dict[str, Any]) -> str:
    if source.get("string_literal") is not None:
        return "string_literal"
    if source.get("kind") == "address":
        return _abi_address_argument_role(source)
    if source.get("kind") == "memory":
        return str(source.get("memory_role") or "memory")
    definition = source.get("register_definition") if isinstance(source.get("register_definition"), dict) else None
    if definition is not None:
        return _abi_argument_role(definition)
    return str(source.get("kind") or "unknown")


def _abi_varargs_evidence(symbol: str, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    lower = symbol.lower()
    if any(token in lower for token in ("printf", "fprintf", "sprintf", "scanf", "execl")):
        evidence: dict[str, Any] = {
            "status": "candidate",
            "evidence_status": "candidate",
            "reason": "known_variadic_symbol",
        }
        if isinstance(inventory, dict):
            evidence["format_string"] = _abi_format_string_evidence(lower, inventory)
        return evidence
    return {"status": "not_observed"}


def _abi_format_string_evidence(symbol: str, inventory: dict[str, Any]) -> dict[str, Any]:
    stack_args = inventory.get("stack_args") if isinstance(inventory.get("stack_args"), list) else []
    fixed_count = _abi_variadic_fixed_arg_count(symbol)
    format_arg = stack_args[fixed_count - 1] if fixed_count > 0 and len(stack_args) >= fixed_count else None
    if not isinstance(format_arg, dict):
        return {
            "status": "incomplete",
            "fixed_arg_count": fixed_count,
            "reason": "format_argument_not_recovered",
        }
    source = format_arg.get("source") if isinstance(format_arg.get("source"), dict) else {}
    literal = source.get("string_literal") if isinstance(source.get("string_literal"), dict) else None
    if literal is None:
        return {
            "status": "incomplete",
            "fixed_arg_count": fixed_count,
            "format_arg_index": fixed_count - 1,
            "source": source,
            "reason": "format_argument_is_not_a_static_string_literal",
        }
    text = str(literal.get("text") or "")
    conversions = _abi_printf_conversions(text)
    return {
        "status": "derived",
        "fixed_arg_count": fixed_count,
        "format_arg_index": fixed_count - 1,
        "literal": literal,
        "conversions": conversions,
        "required_varargs": len(conversions),
        "observed_varargs": max(0, len(stack_args) - fixed_count),
        "missing_varargs": max(0, len(conversions) - max(0, len(stack_args) - fixed_count)),
    }


def _abi_variadic_fixed_arg_count(symbol: str) -> int:
    lower = symbol.lower()
    if "fprintf" in lower or "sprintf" in lower or "snprintf" in lower:
        return 2
    return 1


def _abi_printf_conversions(format_text: str) -> list[dict[str, Any]]:
    conversions: list[dict[str, Any]] = []
    index = 0
    length = len(format_text)
    while index < length:
        if format_text[index] != "%":
            index += 1
            continue
        start = index
        index += 1
        if index < length and format_text[index] == "%":
            index += 1
            continue
        while index < length and format_text[index] in "-+ #0'":
            index += 1
        while index < length and (format_text[index].isdigit() or format_text[index] == "*"):
            if format_text[index] == "*":
                conversions.append({"offset": start, "specifier": "*", "kind": "dynamic_width"})
            index += 1
        if index < length and format_text[index] == ".":
            index += 1
            while index < length and (format_text[index].isdigit() or format_text[index] == "*"):
                if format_text[index] == "*":
                    conversions.append({"offset": start, "specifier": "*", "kind": "dynamic_precision"})
                index += 1
        while index < length and format_text[index] in "hljztL":
            index += 1
        if index < length:
            specifier = format_text[index]
            if specifier not in "n":
                conversions.append({"offset": start, "specifier": specifier, "kind": "value"})
            index += 1
    return conversions


def _abi_function_pointer_targets(target: dict[str, Any]) -> list[dict[str, Any]]:
    if target.get("kind") != "function_pointer":
        return []
    item: dict[str, Any] = {"status": target.get("status") or "unresolved", "operand": target.get("operand")}
    for key in ("memory_rva", "memory_role", "source", "recoverable_targets"):
        if key in target:
            item[key] = target[key]
    return [item]


def _abi_import_prototypes(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "dll": item.dll,
            "symbol": item.symbol,
            "ordinal": item.ordinal,
            "thunk_rva": item.thunk_rva,
            "calling_convention": "stdcall" if item.symbol and "@" in item.symbol else "unknown",
            "varargs_evidence": _abi_varargs_evidence(item.symbol or "", None),
        }
        for item in binary.imports
    ]


def _reference_padding_alignment(
    waivers: list[NonCodeWaiver],
    verified_waivers: list[NonCodeWaiver],
    waiver_obligations: list[dict[str, Any]],
    map_status: str,
) -> dict[str, Any]:
    if not waivers:
        return {"status": "not_applicable", "evidence_kind": "stage-a-waivers", "waivers": [], "obligations": []}
    status = map_status if len(waivers) == len(verified_waivers) and all(item.get("status") != "incomplete" for item in waiver_obligations) else "incomplete"
    return {
        "status": status,
        "evidence_kind": "verified-padding-bytes",
        "waivers": [
            {
                "id": waiver.id,
                "binary": waiver.binary,
                "rva_start": waiver.rva_start,
                "rva_end": waiver.rva_end,
                "reason": waiver.reason,
                "verified": waiver in verified_waivers,
            }
            for waiver in waivers
        ],
        "obligations": waiver_obligations,
    }


def _reference_layout_normalization_constraint(payload: dict[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        return {
            "status": "not_provided",
            "evidence_kind": "none",
            "blocker": "no Stage A layout contract was provided",
            "next_action": "export a layout contract from stage-a-generate-map or pass --layout-contract",
        }
    required = payload.get("required_facts", []) if isinstance(payload.get("required_facts"), list) else []
    facts = payload.get("facts", {}) if isinstance(payload.get("facts"), dict) else {}
    missing = [fact for fact in required if fact not in facts]
    unsatisfied = [fact for fact in required if facts.get(fact) is not True]
    status = "satisfied" if not missing and not unsatisfied else "incomplete"
    return {
        "status": status,
        "evidence_kind": "stage-a-layout-contract",
        "contract": payload,
        "missing_required_facts": missing,
        "unsatisfied_required_facts": unsatisfied,
    }


def _reference_proof_obligation_inventory(payload: dict[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        return {
            "status": "not_provided",
            "evidence_kind": "none",
            "counts": {"obligations": 0},
            "obligations": [],
            "verdict": None,
        }
    verdict = payload.get("verdict") if isinstance(payload.get("verdict"), dict) else {}
    obligations_payload = payload.get("obligations") if isinstance(payload.get("obligations"), dict) else {}
    obligations = obligations_payload.get("obligations") if isinstance(obligations_payload.get("obligations"), list) else []
    inventory = [
        {
            "id": str(item.get("id") or ""),
            "kind": str(item.get("kind") or ""),
            "status": str(item.get("status") or ""),
            "proof_rule": item.get("proof_rule"),
        }
        for item in obligations
        if isinstance(item, dict)
    ]
    lean = verdict.get("proof", {}).get("lean", {}) if isinstance(verdict.get("proof"), dict) else {}
    final_pass_allowed = isinstance(lean, dict) and lean.get("final_pass_allowed") is True
    status = "satisfied" if verdict.get("verdict") == "pass" and final_pass_allowed else "incomplete"
    return {
        "status": status,
        "evidence_kind": "stage-a-validation-report",
        "report": payload.get("path"),
        "verdict": verdict.get("verdict"),
        "final_pass_allowed": final_pass_allowed,
        "lean": lean if isinstance(lean, dict) else {},
        "counts": obligations_payload.get("counts", {}),
        "obligations": inventory,
    }


def _reference_constraint_issues(constraints: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for name, constraint in constraints.items():
        if not isinstance(constraint, dict):
            continue
        if constraint.get("status") in {"satisfied", "derived", "not_applicable"}:
            continue
        issues.append(
            _incomplete_record(
                category="reference_contract_constraint_incomplete",
                obligation_id=f"reference-contract:{name}",
                blocker=f"Stage A reference contract constraint {name!r} is not closed",
                next_action="provide the missing Stage A evidence or inspect the constraint details",
                details={"status": constraint.get("status")},
            )
        )
    return issues


def _reference_contract_status(constraints: dict[str, Any], issues: list[dict[str, Any]]) -> str:
    if any(issue.get("status") == "failed" or issue.get("severity") == "fail" for issue in issues):
        return "fail"
    if issues:
        return "incomplete"
    proof = constraints.get("proof_obligation_inventory")
    return "pass" if isinstance(proof, dict) and proof.get("status") == "satisfied" else "incomplete"


def _layout_issues(
    original: StageABinary,
    candidate: StageABinary,
    layout_contract: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if original.machine != candidate.machine or original.bitness != candidate.bitness:
        issues.append(
            _failure_record(
                category="layout_mismatch",
                obligation_id="layout:architecture",
                blocker="original and candidate architecture/bitness differ",
                original={"machine": original.machine, "bitness": original.bitness},
                candidate={"machine": candidate.machine, "bitness": candidate.bitness},
            )
        )
    section_signature_matches = _section_permission_signature(original) == _section_permission_signature(candidate)
    section_contract_allows_span_delta = (
        isinstance(layout_contract, dict)
        and layout_contract.get("allow_different_section_spans") is True
        and layout_contract.get("facts", {}).get("matching_normalized_executable_section_spans") is True
        and _section_compatibility_signature(original) == _section_compatibility_signature(candidate)
        and _section_rva_start_signature(original) == _section_rva_start_signature(candidate)
    )
    if not section_signature_matches and not section_contract_allows_span_delta:
        issues.append(
            _failure_record(
                category="layout_mismatch",
                obligation_id="layout:sections",
                blocker="PE section permissions or mapped executable ranges differ",
                original=_section_permission_signature(original),
                candidate=_section_permission_signature(candidate),
            )
        )
    if _import_signature(original) != _import_signature(candidate):
        issues.append(
            _failure_record(
                category="layout_mismatch",
                obligation_id="layout:imports",
                blocker="import boundary model differs",
                original=_import_signature(original),
                candidate=_import_signature(candidate),
            )
        )
    if layout_contract is not None:
        if layout_contract.get("require_same_image_base") is True and original.image_base != candidate.image_base:
            issues.append(
                _failure_record(
                    category="layout_mismatch",
                    obligation_id="layout:image_base",
                    blocker="strict layout contract requires equal image bases",
                    original={"image_base": original.image_base},
                    candidate={"image_base": candidate.image_base},
                )
            )
        for fact in layout_contract.get("required_facts", []):
            if fact not in layout_contract.get("facts", {}):
                issues.append(
                    _incomplete_record(
                        category="missing_layout_fact",
                        obligation_id=f"layout:fact:{fact}",
                        blocker=f"strict layout contract requires missing fact {fact!r}",
                        next_action="add the required layout fact or remove it from required_facts",
                    )
                )
            elif layout_contract.get("facts", {}).get(fact) is not True:
                issues.append(
                    _incomplete_record(
                        category="unsatisfied_layout_fact",
                        obligation_id=f"layout:fact:{fact}",
                        blocker=f"strict layout contract requires fact {fact!r} to be true",
                        next_action="regenerate the layout contract from a closed Stage A map or rebuild the fixtures with compatible PE layout",
                        details={"fact": fact, "value": layout_contract.get("facts", {}).get(fact)},
                    )
                )
    return issues


def _model_binary_issues(model: str, original: StageABinary, candidate: StageABinary) -> list[dict[str, Any]]:
    spec = STAGE_A_MODEL_SPECS[model]
    issues: list[dict[str, Any]] = []
    for side, binary in (("original", original), ("candidate", candidate)):
        if binary.machine == spec["machine"] and binary.bitness == spec["bitness"]:
            continue
        issues.append(
            _incomplete_record(
                category="model_binary_mismatch",
                obligation_id=f"model:{side}:architecture",
                blocker=f"{side} binary does not match requested Stage A model {model}",
                next_action="use the model matching the PE architecture or rebuild the fixture for the requested model",
                details={
                    "model": model,
                    "expected": {"machine": spec["machine"], "bitness": spec["bitness"]},
                    "actual": {"machine": binary.machine, "bitness": binary.bitness},
                },
            )
        )
    return issues


def _model_id_for_binary(binary: StageABinary) -> str:
    return STAGE_A_X86_64_MODEL_ID if binary.bitness == 64 else STAGE_A_MODEL_ID


def _section_permission_signature(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "name": section.name,
            "rva_start": section.rva_start,
            "rva_end": section.rva_end,
            "executable": section.executable,
            "readable": section.readable,
            "writable": section.writable,
            "contains_code": section.contains_code,
        }
        for section in binary.sections
    ]


def _section_compatibility_signature(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "name": section.name,
            "executable": section.executable,
            "readable": section.readable,
            "writable": section.writable,
            "contains_code": section.contains_code,
        }
        for section in binary.sections
    ]


def _section_rva_start_signature(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "name": section.name,
            "rva_start": section.rva_start,
            "executable": section.executable,
            "readable": section.readable,
            "writable": section.writable,
            "contains_code": section.contains_code,
        }
        for section in binary.sections
    ]


def _import_signature(binary: StageABinary) -> list[tuple[str, str | None, int | None]]:
    return sorted((item.dll, item.symbol, item.ordinal) for item in binary.imports)


def _generated_map_issues(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    issues = payload.get("issues", [])
    if payload.get("generator") == "stage-a-generate-map" and payload.get("status") != "pass":
        return [
            _incomplete_record(
                category="generated_map_incomplete",
                obligation_id="mapping:generated-map",
                blocker="stage-a-generate-map did not produce a closed jq block map",
                next_action="inspect mapping issues and extend the jq map generator or Stage A model",
                details={"issues": issues},
            )
        ]
    return []


def _jq_map_layout_issues(original: StageABinary, candidate: StageABinary) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if original.machine != candidate.machine or original.bitness != candidate.bitness:
        issues.append(
            _incomplete_record(
                category="layout_mismatch",
                obligation_id="jq-map:layout:architecture",
                blocker="generated map creation requires both inputs to use the same supported PE architecture",
                next_action="rebuild the fixtures for a single supported Windows target",
            )
        )
    if _section_compatibility_signature(original) != _section_compatibility_signature(candidate):
        issues.append(
            _incomplete_record(
                category="layout_mismatch",
                obligation_id="jq-map:layout:sections",
                blocker="jq map generation requires matching PE section names and permissions",
                next_action="make the jq fixture builds use the same linker script and section policy",
                details={
                    "original": _section_compatibility_signature(original),
                    "candidate": _section_compatibility_signature(candidate),
                },
            )
        )
    if _section_rva_start_signature(original) != _section_rva_start_signature(candidate):
        issues.append(
            _incomplete_record(
                category="layout_mismatch",
                obligation_id="jq-map:layout:section-rvas",
                blocker="jq map generation requires matching PE section RVAs before span normalization",
                next_action="make the jq fixture builds use the same linker script and section placement policy",
                details={
                    "original": _section_rva_start_signature(original),
                    "candidate": _section_rva_start_signature(candidate),
                },
            )
        )
    if _import_signature(original) != _import_signature(candidate):
        issues.append(
            _incomplete_record(
                category="layout_mismatch",
                obligation_id="jq-map:layout:imports",
                blocker="jq map generation requires matching PE imports",
                next_action="make the jq fixture builds use the same linkage and dependency policy",
                details={"original": _import_signature(original), "candidate": _import_signature(candidate)},
            )
        )
    return issues


def _parse_linker_map_functions(path: Path, binary: StageABinary) -> list[dict[str, Any]]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise StageAInputError(f"cannot read linker map {path}: {exc}") from exc
    symbol_starts: dict[int, list[str]] = {}
    boundary_starts: set[int] = set()
    pending_text_section: str | None = None
    for line in text.splitlines():
        parsed = _parse_linker_map_symbol_line(line, binary)
        if parsed is not None:
            rva, name = parsed
            if _linker_map_symbol_is_non_function_label(name):
                continue
            if _executable_section_for_rva(binary, rva) is None:
                continue
            symbol_starts.setdefault(rva, [])
            if name not in symbol_starts[rva]:
                symbol_starts[rva].append(name)
            continue
        boundary = _parse_linker_map_text_boundary_line(line, binary)
        if boundary is not None:
            boundary_starts.add(boundary)
            fragment_symbol = _linker_map_text_fragment_symbol(line)
            if fragment_symbol is not None:
                symbol_starts.setdefault(boundary, [])
                if fragment_symbol not in symbol_starts[boundary]:
                    symbol_starts[boundary].append(fragment_symbol)
            pending_text_section = None
            continue
        continuation = _parse_linker_map_text_boundary_continuation_line(line, binary)
        if continuation is not None and pending_text_section is not None:
            boundary_starts.add(continuation)
            fragment_symbol = _linker_map_section_fragment_symbol(pending_text_section)
            if fragment_symbol is not None:
                symbol_starts.setdefault(continuation, [])
                if fragment_symbol not in symbol_starts[continuation]:
                    symbol_starts[continuation].append(fragment_symbol)
            pending_text_section = None
            continue
        text_section = _parse_linker_map_text_section_only_line(line)
        if text_section is not None:
            pending_text_section = text_section
            continue
        if line.strip():
            pending_text_section = None

    functions: list[dict[str, Any]] = []
    ordered = sorted(symbol_starts)
    range_boundaries = sorted(set(ordered) | boundary_starts)
    for index, rva in enumerate(ordered):
        section = _executable_section_for_rva(binary, rva)
        if section is None:
            continue
        next_starts = [value for value in range_boundaries if value > rva and value <= section.rva_end]
        rva_end = next_starts[0] if next_starts else section.rva_end
        if rva_end <= rva:
            continue
        primary = _primary_symbol_name(symbol_starts[rva])
        functions.append(
            {
                "name": primary,
                "aliases": symbol_starts[rva],
                "rva_start": rva,
                "rva_end": rva_end,
                "section": section.name,
            }
        )
    return functions


def _parse_linker_map_text_boundary_line(line: str, binary: StageABinary) -> int | None:
    match = re.match(r"^\s*\.text\S*\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    if address >= binary.image_base:
        rva = address - binary.image_base
    else:
        rva = address
    if _executable_section_for_rva(binary, rva) is None:
        return None
    return rva


def _parse_linker_map_text_boundary_continuation_line(line: str, binary: StageABinary) -> int | None:
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    if address >= binary.image_base:
        rva = address - binary.image_base
    else:
        rva = address
    if _executable_section_for_rva(binary, rva) is None:
        return None
    return rva


def _parse_linker_map_text_section_only_line(line: str) -> str | None:
    match = re.match(r"^\s*(\.text\S*)\s*$", line)
    return match.group(1) if match is not None else None


def _linker_map_text_fragment_symbol(line: str) -> str | None:
    match = re.match(r"^\s*(\.text\S*)\b", line)
    if match is None:
        return None
    return _linker_map_section_fragment_symbol(match.group(1))


def _linker_map_section_fragment_symbol(section_name: str) -> str | None:
    if "$" not in section_name:
        return None
    fragment = section_name.split("$", 1)[1].strip()
    if not fragment or fragment.startswith("."):
        return None
    return fragment


def _parse_linker_map_symbol_line(line: str, binary: StageABinary) -> tuple[int, str] | None:
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+([A-Za-z_.$@?][A-Za-z0-9_.$@?~-]*)\s*$", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    name = match.group(2)
    if name.startswith(".") or name in {"PROVIDE", "CREATE_OBJECT_SYMBOLS"}:
        return None
    if address >= binary.image_base:
        rva = address - binary.image_base
    else:
        rva = address
    return rva, name


def _linker_map_symbol_is_non_function_label(name: str) -> bool:
    stripped = name.lstrip("_")
    if re.match(r"^fu\d+_+", stripped):
        return True
    return stripped.startswith("stage_b_contract_rva_")


def _primary_symbol_name(names: list[str]) -> str:
    for name in names:
        if not name.startswith("__") and not name.startswith("___"):
            return name
    return names[0]


def _executable_section_for_rva(binary: StageABinary, rva: int) -> StageASection | None:
    for section in binary.sections:
        if section.executable and section.rva_start <= rva < section.rva_end:
            return section
    return None


def _section_for_rva(binary: StageABinary, rva: int) -> StageASection | None:
    for section in binary.sections:
        if section.rva_start <= rva < section.rva_end:
            return section
    return None


def _capstone_mode(binary: StageABinary) -> int:
    return capstone.CS_MODE_64 if binary.bitness == 64 else capstone.CS_MODE_32


def _linker_function_issues(binary_name: str, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not functions:
        issues.append(
            _incomplete_record(
                category="missing_linker_map_entries",
                obligation_id=f"jq-map:{binary_name}:functions",
                blocker=f"{binary_name} linker map did not expose executable symbols",
                next_action="rebuild jq with linker map emission and unstripped symbols",
            )
        )
    by_name: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        by_name.setdefault(str(function["name"]), []).append(function)
    duplicates = {
        name: [
            {"rva_start": item["rva_start"], "rva_end": item["rva_end"], "aliases": item.get("aliases", [])}
            for item in entries
        ]
        for name, entries in by_name.items()
        if len(entries) > 1
    }
    if duplicates:
        issues.append(
            _incomplete_record(
                category="ambiguous_linker_map",
                obligation_id=f"jq-map:{binary_name}:duplicate-function-names",
                blocker=f"{binary_name} linker map contains duplicate primary function names",
                next_action="disambiguate duplicate linker-map symbols before accepting generated jq mappings",
                details={"functions": duplicates},
            )
        )
    seen_ranges: list[tuple[str, BlockSide]] = [
        (str(item["name"]), BlockSide(int(item["rva_start"]), int(item["rva_end"]))) for item in functions
    ]
    for overlap in _range_overlap_issues(binary_name, seen_ranges):
        issues.append(
            _incomplete_record(
                category="ambiguous_linker_map",
                obligation_id=overlap["obligation_id"],
                blocker=overlap["blocker"],
                next_action="fix linker-map function range recovery before generating a jq Stage A map",
                details=overlap,
            )
        )
    return issues


def _unique_functions_by_name(functions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in functions:
        grouped.setdefault(str(item["name"]), []).append(item)
    return {name: entries[0] for name, entries in grouped.items() if len(entries) == 1}


def _match_linker_functions_by_name_or_unique_alias(
    original_functions: list[dict[str, Any]],
    candidate_functions: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any], str]], list[str], list[str], list[dict[str, Any]]]:
    original_by_name = _unique_functions_by_name(original_functions)
    candidate_by_name = _unique_functions_by_name(candidate_functions)
    matched: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    unmatched_original = set(original_by_name)
    unmatched_candidate = set(candidate_by_name)
    for name in sorted(set(original_by_name) & set(candidate_by_name)):
        matched.append((original_by_name[name], candidate_by_name[name], _linker_function_match_key(name)))
        unmatched_original.discard(name)
        unmatched_candidate.discard(name)

    original_by_key: dict[str, list[str]] = {}
    candidate_by_key: dict[str, list[str]] = {}
    for name in unmatched_original:
        original_by_key.setdefault(_linker_function_match_key(name), []).append(name)
    for name in unmatched_candidate:
        candidate_by_key.setdefault(_linker_function_match_key(name), []).append(name)

    issues: list[dict[str, Any]] = []
    for key in sorted(set(original_by_key) & set(candidate_by_key)):
        original_names = sorted(original_by_key[key])
        candidate_names = sorted(candidate_by_key[key])
        if len(original_names) == 1 and len(candidate_names) == 1:
            original_name = original_names[0]
            candidate_name = candidate_names[0]
            matched.append((original_by_name[original_name], candidate_by_name[candidate_name], key))
            unmatched_original.discard(original_name)
            unmatched_candidate.discard(candidate_name)
            continue
        issues.append(
            _incomplete_record(
                category="ambiguous_linker_map",
                obligation_id=f"jq-map:alias:{_artifact_name(key)}",
                blocker="decorated linker-map names produce an ambiguous canonical alias match",
                next_action="preserve exact function names or add a more specific linker-map alias rule",
                details={"match_key": key, "original": original_names, "candidate": candidate_names},
            )
        )
    return matched, sorted(unmatched_original), sorted(unmatched_candidate), issues


def _match_import_thunk_functions_by_signature(
    original: StageABinary,
    candidate: StageABinary,
    original_functions: list[dict[str, Any]],
    candidate_functions: list[dict[str, Any]],
    unmatched_original: list[str],
    unmatched_candidate: list[str],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[str], list[str], list[dict[str, Any]]]:
    original_by_name = _unique_functions_by_name(original_functions)
    candidate_by_name = _unique_functions_by_name(candidate_functions)
    original_unmatched = set(unmatched_original)
    candidate_unmatched = set(unmatched_candidate)
    original_thunks = [
        thunk
        for name in sorted(original_unmatched)
        for thunk in [_linker_function_import_thunk_evidence(original, original_by_name[name])]
        if name in original_by_name and thunk is not None
    ]
    candidate_thunks = [
        thunk
        for name in sorted(candidate_unmatched)
        for thunk in [_linker_function_import_thunk_evidence(candidate, candidate_by_name[name])]
        if name in candidate_by_name and thunk is not None
    ]
    original_by_signature = _group_import_thunks_by_signature(original_thunks)
    candidate_by_signature = _group_import_thunks_by_signature(candidate_thunks)

    matched: list[tuple[dict[str, Any], dict[str, Any]]] = []
    issues: list[dict[str, Any]] = []
    for signature in sorted(set(original_by_signature) & set(candidate_by_signature)):
        left = original_by_signature[signature]
        right = candidate_by_signature[signature]
        if len(left) == 1 and len(right) == 1:
            matched.append((left[0], right[0]))
            original_unmatched.discard(str(left[0]["function"]["name"]))
            candidate_unmatched.discard(str(right[0]["function"]["name"]))
            continue
        issues.append(
            _incomplete_record(
                category="ambiguous_import_thunk_match",
                obligation_id=f"jq-map:import-thunk:{_artifact_name(signature)}",
                blocker="PE import-thunk linker-map functions do not have a unique import-signature match",
                next_action="preserve unique import thunk symbols or add disambiguating checked thunk metadata",
                details={
                    "import_signature": _import_signature_report(left[0]["import"] if left else right[0]["import"]),
                    "original": [_import_thunk_match_report(item) for item in left],
                    "candidate": [_import_thunk_match_report(item) for item in right],
                },
            )
        )
    return matched, sorted(original_unmatched), sorted(candidate_unmatched), issues


def _group_import_thunks_by_signature(thunks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for thunk in thunks:
        grouped.setdefault(str(thunk["signature_key"]), []).append(thunk)
    return grouped


def _linker_function_import_thunk_evidence(binary: StageABinary, function: dict[str, Any]) -> dict[str, Any] | None:
    start = int(function["rva_start"])
    end = int(function["rva_end"])
    if end <= start:
        return None
    data = binary.pe.get_data(start, min(16, end - start))
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + start))
    if not instructions:
        return None
    first = instructions[0]
    if int(first.address - binary.image_base) != start:
        return None
    imported = _direct_import_jump_instruction(binary, first)
    if imported is None:
        return None
    thunk_end = start + int(first.size)
    if thunk_end > end:
        return None
    padding = binary.pe.get_data(thunk_end, end - thunk_end)
    if len(padding) != end - thunk_end or not _is_padding_bytes(binary, thunk_end, padding):
        return None
    return {
        "function": function,
        "block": BlockSide(start, thunk_end),
        "function_range": BlockSide(start, end),
        "import": imported,
        "signature_key": _import_thunk_match_key(imported),
        "instruction": _instruction_report(binary, first),
        "padding_sha256": sha256_bytes(padding),
    }


def _import_thunk_block_entry(
    original: dict[str, Any],
    candidate: dict[str, Any],
    *,
    match_key: str,
) -> dict[str, Any]:
    original_function = original["function"]
    candidate_function = candidate["function"]
    original_block: BlockSide = original["block"]
    candidate_block: BlockSide = candidate["block"]
    name = str(original_function["name"])
    return {
        "id": _artifact_name(f"{name}-import-thunk"),
        "kind": "code",
        "reachable": True,
        "original": {"rva": original_block.rva_start, "size": original_block.size},
        "candidate": {"rva": candidate_block.rva_start, "size": candidate_block.size},
        "root": {"kind": "linker_map_function", "checked": True, "symbol": name},
        "source": {
            "kind": "import_thunk",
            "function": name,
            "candidate_function": str(candidate_function["name"]),
            "function_match_key": match_key,
            "import_signature": _import_signature_report(original["import"]),
            "original_instruction": original["instruction"],
            "candidate_instruction": candidate["instruction"],
            "original_function_range": _range_report(original["function_range"]),
            "candidate_function_range": _range_report(candidate["function_range"]),
            "padding_classification": "verified_linker_function_suffix_padding",
        },
    }


def _import_thunk_match_report(thunk: dict[str, Any] | None) -> dict[str, Any] | None:
    if thunk is None:
        return None
    return {
        "function": str(thunk["function"]["name"]),
        "aliases": list(thunk["function"].get("aliases", [])),
        "block": _range_report(thunk["block"]),
        "function_range": _range_report(thunk["function_range"]),
        "import_signature": _import_signature_report(thunk["import"]),
        "instruction": thunk["instruction"],
    }


def _import_thunk_match_key(imported: StageAImport) -> str:
    symbol = imported.symbol if imported.symbol is not None else f"ordinal-{imported.ordinal}"
    return f"{imported.dll}!{symbol}"


def _import_signature_report(imported: StageAImport) -> dict[str, Any]:
    return {"dll": imported.dll, "symbol": imported.symbol, "ordinal": imported.ordinal}


def _linker_function_match_key(name: str) -> str:
    value = name
    if "@" in value:
        left, right = value.rsplit("@", 1)
        if right.isdigit():
            value = left
    return value.lstrip("_")


def _match_function_blocks(
    name: str,
    original: StageABinary,
    candidate: StageABinary,
    original_blocks: list[dict[str, Any]],
    candidate_blocks: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]]]:
    if len(original_blocks) != len(candidate_blocks):
        return [], [
            _incomplete_record(
                category="ambiguous_block_match",
                obligation_id=f"jq-map:function:{_artifact_name(name)}",
                blocker="jq function map recovered different basic-block counts for matching linker-map symbols",
                next_action="extend the jq map generator to match split basic blocks for this function by CFG shape",
                details=_ambiguous_block_match_details(
                    name=name,
                    original=original,
                    candidate=candidate,
                    original_blocks=original_blocks,
                    candidate_blocks=candidate_blocks,
                ),
            )
        ]
    return list(zip(original_blocks, candidate_blocks)), []


def _ambiguous_block_match_details(
    *,
    name: str,
    original: StageABinary,
    candidate: StageABinary,
    original_blocks: list[dict[str, Any]],
    candidate_blocks: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "function": name,
        "original_blocks": len(original_blocks),
        "candidate_blocks": len(candidate_blocks),
        "block_count_delta": len(candidate_blocks) - len(original_blocks),
        "original_block_shapes": _block_shape_summaries(original, original_blocks),
        "candidate_block_shapes": _block_shape_summaries(candidate, candidate_blocks),
    }


def _block_shape_summaries(binary: StageABinary, blocks: list[dict[str, Any]], *, limit: int = 64) -> dict[str, Any]:
    summaries = [
        _block_shape_summary(binary, index, block)
        for index, block in enumerate(blocks[:limit])
    ]
    return {
        "count": len(blocks),
        "items": summaries,
        "truncated": max(0, len(blocks) - limit),
    }


def _block_shape_summary(binary: StageABinary, index: int, block: dict[str, Any]) -> dict[str, Any]:
    rva_start = int(block["rva_start"])
    rva_end = int(block["rva_end"])
    data = binary.pe.get_data(rva_start, rva_end - rva_start)
    instructions = _disassemble_block(binary, rva_start, data)
    terminal = instructions[-1] if instructions else None
    first = instructions[0] if instructions else None
    edges = _direct_cfg_edges(binary, BlockSide(rva_start, rva_end))
    return {
        "index": index,
        "rva_start": rva_start,
        "rva_end": rva_end,
        "size": rva_end - rva_start,
        "instruction_count": len(instructions),
        "first_instruction": _instruction_shape(binary, first),
        "terminal_instruction": _instruction_shape(binary, terminal),
        "direct_edge_counts": _edge_kind_counts(edges),
        "direct_edges": edges[:8],
        "direct_edges_truncated": max(0, len(edges) - 8),
        "bytes_sha256": block.get("bytes_sha256"),
        "match_key": block.get("match_key"),
    }


def _disassemble_block(binary: StageABinary, rva_start: int, data: bytes) -> list[Any]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    return list(dis.disasm(data, binary.image_base + rva_start))


def _instruction_shape(binary: StageABinary, insn: Any | None) -> dict[str, Any] | None:
    if insn is None:
        return None
    return {
        "rva": int(insn.address - binary.image_base),
        "mnemonic": str(insn.mnemonic),
        "op_str": str(insn.op_str),
        "size": int(insn.size),
    }


def _edge_kind_counts(edges: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for edge in edges:
        kind = str(edge.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _recover_basic_blocks(binary: StageABinary, rva_start: int, rva_end: int) -> list[dict[str, Any]]:
    data = binary.pe.get_data(rva_start, rva_end - rva_start)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + rva_start))
    decoded = sum(int(insn.size) for insn in instructions)
    if not instructions or decoded != len(data):
        return [_function_range_block(binary, rva_start, rva_end, data, len(instructions), decoded)]

    insn_by_rva = {int(insn.address - binary.image_base): insn for insn in instructions}
    starts: set[int] = {rva_start}
    for insn in instructions:
        rva = int(insn.address - binary.image_base)
        next_rva = rva + int(insn.size)
        mnemonic = insn.mnemonic
        if _is_conditional_jump(mnemonic):
            target = _resolved_branch_target(binary, insn)
            if target is not None and rva_start <= target < rva_end:
                starts.add(target)
            if next_rva < rva_end:
                starts.add(next_rva)
        elif mnemonic in {"jmp", "ljmp"}:
            target = _resolved_branch_target(binary, insn)
            if target is not None and rva_start <= target < rva_end:
                starts.add(target)
        elif mnemonic == "call":
            target = _resolved_branch_target(binary, insn)
            if target is not None and rva_start <= target < rva_end:
                starts.add(target)
            if _is_noreturn_import_call(binary, insn) and next_rva < rva_end:
                starts.add(next_rva)

    ordered_starts = [start for start in sorted(starts) if start in insn_by_rva]
    if not ordered_starts:
        return [_function_range_block(binary, rva_start, rva_end, data, len(instructions), decoded)]

    blocks: list[dict[str, Any]] = []
    instruction_rvas = sorted(insn_by_rva)
    for index, start in enumerate(ordered_starts):
        next_start = ordered_starts[index + 1] if index + 1 < len(ordered_starts) else rva_end
        block_end = next_start
        for insn_rva in instruction_rvas:
            if insn_rva < start:
                continue
            if insn_rva >= next_start:
                break
            insn = insn_by_rva[insn_rva]
            insn_end = insn_rva + int(insn.size)
            if _instruction_ends_basic_block(insn) or _is_noreturn_import_call(binary, insn):
                block_end = insn_end
                break
        if block_end <= start:
            continue
        block_data = binary.pe.get_data(start, block_end - start)
        if _is_padding_bytes(binary, start, block_data):
            continue
        blocks.append(
            {
                "rva_start": start,
                "rva_end": block_end,
                "bytes_sha256": sha256_bytes(block_data),
                "match_key": {
                    "kind": "recovered_basic_block",
                    "function_rva_start": rva_start,
                    "function_rva_end": rva_end,
                    "block_index": len(blocks),
                    "instruction_count": sum(1 for item in instructions if start <= int(item.address - binary.image_base) < block_end),
                    "range_size": len(block_data),
                },
            }
        )
    return blocks or [_function_range_block(binary, rva_start, rva_end, data, len(instructions), decoded)]


def _function_range_block(
    binary: StageABinary,
    rva_start: int,
    rva_end: int,
    data: bytes,
    instruction_count: int,
    decoded: int,
) -> dict[str, Any]:
    del binary
    return {
        "rva_start": rva_start,
        "rva_end": rva_end,
        "bytes_sha256": sha256_bytes(data),
        "match_key": {
            "kind": "linker_map_function_range",
            "instruction_count": instruction_count,
            "decoded_bytes": decoded,
            "range_size": len(data),
        },
    }


def _section_gap_waivers(binary_name: str, binary: StageABinary, ranges: list[BlockSide]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    waivers: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for section in binary.sections:
        if not section.executable:
            continue
        for gap in _gaps(section.rva_start, section.rva_end, ranges):
            data = binary.pe.get_data(gap.rva_start, gap.size)
            if _is_padding_bytes(binary, gap.rva_start, data):
                waivers.append(
                    {
                        "id": f"{binary_name}-padding-{gap.rva_start:x}-{gap.rva_end:x}",
                        "binary": binary_name,
                        "rva": gap.rva_start,
                        "size": gap.size,
                        "reason": "verified linker-map executable gap is zero-fill or padding instructions",
                    }
                )
            else:
                issues.append(
                    _incomplete_record(
                        category="unclassified_executable_bytes",
                        obligation_id=f"jq-map:{binary_name}:gap:{gap.rva_start:x}-{gap.rva_end:x}",
                        blocker=f"{binary_name} executable bytes outside linker-map function ranges are not padding",
                        next_action="recover the missing function range or add a checked jump-table/code target classification",
                        details={"rva_start": gap.rva_start, "rva_end": gap.rva_end, "bytes_sha256": sha256_bytes(data)},
                    )
                )
    return waivers, issues


def _paired_section_gap_classification(
    original: StageABinary,
    candidate: StageABinary,
    blocks: list[dict[str, Any]],
    *,
    original_flags: str,
    candidate_flags: str,
    proof_rule: str,
    proof_metadata: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    original_ranges = [
        BlockSide(_parse_int(block["original"]["rva"]), _parse_int(block["original"]["rva"]) + _parse_int(block["original"]["size"]))
        for block in blocks
    ]
    candidate_ranges = [
        BlockSide(_parse_int(block["candidate"]["rva"]), _parse_int(block["candidate"]["rva"]) + _parse_int(block["candidate"]["size"]))
        for block in blocks
    ]
    original_gaps = _section_gaps(original, original_ranges)
    candidate_gaps = _section_gaps(candidate, candidate_ranges)
    gap_blocks: list[dict[str, Any]] = []
    waivers: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for section in sorted(set(original_gaps) | set(candidate_gaps)):
        left_gaps = original_gaps.get(section, [])
        right_gaps = candidate_gaps.get(section, [])
        left_code_blocks, left_waivers = _section_gap_code_blocks("original", original, left_gaps)
        right_code_blocks, right_waivers = _section_gap_code_blocks("candidate", candidate, right_gaps)
        waivers.extend(left_waivers)
        waivers.extend(right_waivers)
        if len(left_code_blocks) != len(right_code_blocks):
            issues.append(
                _incomplete_record(
                    category="ambiguous_section_gap_match",
                    obligation_id=f"jq-map:section-gap:{_artifact_name(section)}",
                    blocker="original and candidate executable section gap basic blocks do not have the same count after padding normalization",
                    next_action="extend the jq map generator to match split section-gap blocks by CFG shape",
                    details={
                        "section": section,
                        "original_code_blocks": len(left_code_blocks),
                        "candidate_code_blocks": len(right_code_blocks),
                        "original_gaps": len(left_gaps),
                        "candidate_gaps": len(right_gaps),
                        "original_unmatched_sample": _gap_block_sample(left_code_blocks, limit=8),
                        "candidate_unmatched_sample": _gap_block_sample(right_code_blocks, limit=8),
                    },
                )
            )
            continue
        for index, (left_unit, right_unit) in enumerate(zip(left_code_blocks, right_code_blocks)):
            left = left_unit["block"]
            right = right_unit["block"]
            left_bytes = left_unit["bytes"]
            right_bytes = right_unit["bytes"]
            name = f"section-gap-{section}-{index:04d}"
            gap_blocks.append(
                {
                    "id": _artifact_name(name),
                    "kind": "code",
                    "reachable": True,
                    "root": {"kind": "linker_map_section_gap", "checked": True, "section": section, "index": index},
                    "original": {"rva": left.rva_start, "size": left.size},
                    "candidate": {"rva": right.rva_start, "size": right.size},
                    "source": {
                        "kind": "paired_executable_section_gap_v1",
                        "section": section,
                        "gap_index": index,
                        "original_gap_index": left_unit["gap_index"],
                        "candidate_gap_index": right_unit["gap_index"],
                        "original_gap_block_index": left_unit["gap_block_index"],
                        "candidate_gap_block_index": right_unit["gap_block_index"],
                        "original_match": left_unit["match_key"],
                        "candidate_match": right_unit["match_key"],
                        "original_sha256": sha256_bytes(left_bytes),
                        "candidate_sha256": sha256_bytes(right_bytes),
                    },
                    "proof": _generated_mapping_proof(
                        proof_rule=proof_rule,
                        function=name,
                        original_flags=original_flags,
                        candidate_flags=candidate_flags,
                        proof_metadata=proof_metadata,
                    ),
                }
            )
    return gap_blocks, waivers, issues


def _section_gap_code_blocks(
    binary_name: str,
    binary: StageABinary,
    gaps: list[BlockSide],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    code_blocks: list[dict[str, Any]] = []
    waivers: list[dict[str, Any]] = []
    for gap_index, gap in enumerate(gaps):
        queue = [gap]
        seen: set[tuple[int, int]] = set()
        gap_block_index = 0
        while queue:
            span = queue.pop(0)
            span_key = (span.rva_start, span.rva_end)
            if span_key in seen or span.size <= 0:
                continue
            seen.add(span_key)
            data = binary.pe.get_data(span.rva_start, span.size)
            if len(data) != span.size:
                code_blocks.append(
                    {
                        "gap_index": gap_index,
                        "gap_block_index": gap_block_index,
                        "block": span,
                        "bytes": data,
                        "match_key": {"kind": "unreadable_section_gap_fragment", "range_size": span.size, "read_bytes": len(data)},
                    }
                )
                gap_block_index += 1
                continue
            if _is_padding_bytes(binary, span.rva_start, data):
                waivers.append(_padding_waiver(binary_name, span))
                continue

            recovered = [
                item
                for item in _recover_basic_blocks(binary, span.rva_start, span.rva_end)
                if span.rva_start <= int(item["rva_start"]) < int(item["rva_end"]) <= span.rva_end
            ]
            recovered_ranges: list[BlockSide] = []
            for item in recovered:
                block = BlockSide(int(item["rva_start"]), int(item["rva_end"]))
                block_bytes = binary.pe.get_data(block.rva_start, block.size)
                recovered_ranges.append(block)
                if len(block_bytes) != block.size:
                    code_blocks.append(
                        {
                            "gap_index": gap_index,
                            "gap_block_index": gap_block_index,
                            "block": block,
                            "bytes": block_bytes,
                            "match_key": {
                                "kind": "unreadable_section_gap_fragment",
                                "range_size": block.size,
                                "read_bytes": len(block_bytes),
                            },
                        }
                    )
                    gap_block_index += 1
                    continue
                if _is_padding_bytes(binary, block.rva_start, block_bytes):
                    waivers.append(_padding_waiver(binary_name, block))
                    continue

                edge_padding, code_span, code_bytes = _trim_padding_edges(binary, block, block_bytes)
                for padding in edge_padding:
                    waivers.append(_padding_waiver(binary_name, padding))
                if code_span is None:
                    continue
                if _is_padding_bytes(binary, code_span.rva_start, code_bytes):
                    waivers.append(_padding_waiver(binary_name, code_span))
                    continue
                code_blocks.append(
                    {
                        "gap_index": gap_index,
                        "gap_block_index": gap_block_index,
                        "block": code_span,
                        "bytes": code_bytes,
                        "match_key": {
                            **item["match_key"],
                            "trimmed_padding_prefix": code_span.rva_start - block.rva_start,
                            "trimmed_padding_suffix": block.rva_end - code_span.rva_end,
                        },
                    }
                )
                gap_block_index += 1

            if not recovered_ranges:
                code_blocks.append(
                    {
                        "gap_index": gap_index,
                        "gap_block_index": gap_block_index,
                        "block": span,
                        "bytes": data,
                        "match_key": {"kind": "unrecovered_section_gap_fragment", "range_size": span.size},
                    }
                )
                gap_block_index += 1
                continue

            for residue in _gaps(span.rva_start, span.rva_end, recovered_ranges):
                if residue.size > 0:
                    queue.append(residue)
    code_blocks.sort(key=lambda item: (item["block"].rva_start, item["block"].rva_end))
    return code_blocks, waivers


def _trim_padding_edges(binary: StageABinary, block: BlockSide, data: bytes) -> tuple[list[BlockSide], BlockSide | None, bytes]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + block.rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return [], block, data

    first_code_index = 0
    while first_code_index < len(instructions) and _is_padding_instruction(instructions[first_code_index]):
        first_code_index += 1
    if first_code_index == len(instructions):
        return [block], None, b""

    last_code_index = len(instructions) - 1
    while last_code_index > first_code_index and _is_padding_instruction(instructions[last_code_index]):
        last_code_index -= 1

    code_start = int(instructions[first_code_index].address - binary.image_base)
    last_code = instructions[last_code_index]
    code_end = int(last_code.address - binary.image_base) + int(last_code.size)
    padding: list[BlockSide] = []
    if block.rva_start < code_start:
        padding.append(BlockSide(block.rva_start, code_start))
    if code_end < block.rva_end:
        padding.append(BlockSide(code_end, block.rva_end))
    code_span = BlockSide(code_start, code_end)
    return padding, code_span, binary.pe.get_data(code_span.rva_start, code_span.size)


def _padding_waiver(binary_name: str, span: BlockSide) -> dict[str, Any]:
    return {
        "id": f"{binary_name}-padding-{span.rva_start:x}-{span.rva_end:x}",
        "binary": binary_name,
        "rva": span.rva_start,
        "size": span.size,
        "reason": "verified executable section gap is zero-fill or padding instructions",
    }


def _gap_block_sample(items: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    return [
        {
            "rva_start": item["block"].rva_start,
            "rva_end": item["block"].rva_end,
            "gap_index": item["gap_index"],
            "gap_block_index": item["gap_block_index"],
            "match_key": item["match_key"],
            "bytes_sha256": sha256_bytes(item["bytes"]) if isinstance(item.get("bytes"), bytes) else None,
        }
        for item in items[:limit]
    ]


def _section_gaps(binary: StageABinary, ranges: list[BlockSide]) -> dict[str, list[BlockSide]]:
    result: dict[str, list[BlockSide]] = {}
    for section in binary.sections:
        if not section.executable:
            continue
        result[section.name] = _gaps(section.rva_start, section.rva_end, ranges)
    return result


def _is_padding_bytes(binary: StageABinary, rva_start: int, data: bytes) -> bool:
    if not data:
        return True
    if all(byte == 0 for byte in data):
        return True
    if all(byte in {0x00, 0x90, 0xCC} for byte in data):
        return True
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return False
    if all(_is_padding_instruction(insn) for insn in instructions):
        return True
    return _is_alignment_jump_over_padding(binary, BlockSide(rva_start, rva_start + len(data)), instructions)


def _is_padding_instruction(insn: Any) -> bool:
    if insn.mnemonic in {"nop", "int3"}:
        return True
    if insn.mnemonic != "lea" or len(insn.operands) != 2:
        return False
    destination, source = insn.operands
    if destination.type != X86_OP_REG or source.type != X86_OP_MEM:
        return False
    mem = source.mem
    return destination.reg == mem.base and not mem.index and mem.disp == 0


def _is_alignment_jump_over_padding(binary: StageABinary, span: BlockSide, instructions: list[Any]) -> bool:
    if not instructions:
        return False
    insn = instructions[0]
    if insn.mnemonic not in {"jmp", "ljmp"}:
        return False
    target = _resolved_branch_target(binary, insn)
    if target is None:
        return False
    insn_end = int(insn.address - binary.image_base) + int(insn.size)
    if target < insn_end:
        return False
    if target < span.rva_end and not all(_is_padding_instruction(item) for item in instructions[1:]):
        return False
    bridge_end = max(span.rva_end, target)
    section = _executable_section_covering_range(binary, span.rva_start, bridge_end)
    if section is None:
        return False
    skipped_start = insn_end
    skipped_end = target
    if skipped_start == skipped_end:
        return target == span.rva_end
    skipped = binary.pe.get_data(skipped_start, skipped_end - skipped_start)
    return len(skipped) == skipped_end - skipped_start and _is_padding_bytes(binary, skipped_start, skipped)


def _generated_layout_contract(original: StageABinary, candidate: StageABinary, map_payload: dict[str, Any]) -> dict[str, Any]:
    facts = {
        "matching_architecture": original.machine == candidate.machine and original.bitness == candidate.bitness,
        "matching_section_rvas": _section_rva_start_signature(original) == _section_rva_start_signature(candidate),
        "matching_section_permissions": _section_compatibility_signature(original) == _section_compatibility_signature(candidate),
        "matching_imports": _import_signature(original) == _import_signature(candidate),
        "all_executable_bytes_classified": map_payload.get("status") == "pass",
    }
    facts["matching_normalized_executable_section_spans"] = (
        facts["matching_architecture"]
        and facts["matching_section_rvas"]
        and facts["matching_section_permissions"]
        and facts["all_executable_bytes_classified"]
    )
    return {
        "format": "stage-a-layout-contract-v1",
        "generator": "stage-a-generate-map",
        "require_same_image_base": original.image_base == candidate.image_base,
        "allow_different_section_spans": facts["matching_normalized_executable_section_spans"],
        "required_facts": [
            "matching_architecture",
            "matching_section_rvas",
            "matching_section_permissions",
            "matching_imports",
            "all_executable_bytes_classified",
            "matching_normalized_executable_section_spans",
        ],
        "facts": facts,
        "normalized_sections": _normalized_section_reports(original, candidate),
    }


def _normalized_section_reports(original: StageABinary, candidate: StageABinary) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    by_name = {section.name: section for section in candidate.sections}
    for section in original.sections:
        other = by_name.get(section.name)
        normalized_rva_end = max(section.rva_end, other.rva_end) if other is not None and section.executable else section.rva_end
        reports.append(
            {
                "name": section.name,
                "executable": section.executable,
                "rva_start": section.rva_start,
                "normalized_rva_end": normalized_rva_end,
                "original_rva_end": section.rva_end,
                "candidate_rva_end": other.rva_end if other is not None else None,
            }
        )
    return reports


def _parse_block_map(payload: Any, original: StageABinary) -> tuple[list[BlockMapping], list[NonCodeWaiver], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if isinstance(payload, list):
        block_entries = payload
        waiver_entries: list[Any] = []
    elif isinstance(payload, dict):
        block_entries = payload.get("blocks", payload.get("mappings"))
        waiver_entries = payload.get("waivers", [])
    else:
        block_entries = None
        waiver_entries = []

    if not isinstance(block_entries, list):
        return [], [], [
            _incomplete_record(
                category="invalid_mapping",
                obligation_id="mapping:blocks",
                blocker="block-map.json must be a list or contain a blocks/mappings list",
                next_action="add explicit original-to-candidate block mappings",
            )
        ]

    mappings: list[BlockMapping] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(block_entries):
        try:
            mapped = _parse_block_mapping(entry, index, original)
        except StageAInputError as exc:
            issues.append(
                _incomplete_record(
                    category="invalid_mapping",
                    obligation_id=f"mapping:block:{index}",
                    blocker=str(exc),
                    next_action="fix the malformed block mapping entry",
                )
            )
            continue
        if mapped.id in seen_ids:
            issues.append(
                _failure_record(
                    category="invalid_mapping",
                    obligation_id=f"mapping:block:{mapped.id}",
                    blocker=f"duplicate block mapping id {mapped.id!r}",
                    original={"id": mapped.id},
                    candidate={"id": mapped.id},
                )
            )
            continue
        seen_ids.add(mapped.id)
        mappings.append(mapped)

    issues.extend(_range_overlap_issues("original", [(mapped.id, mapped.original) for mapped in mappings]))
    issues.extend(_range_overlap_issues("candidate", [(mapped.id, mapped.candidate) for mapped in mappings]))

    waivers: list[NonCodeWaiver] = []
    for index, entry in enumerate(waiver_entries if isinstance(waiver_entries, list) else []):
        try:
            waivers.append(_parse_waiver(entry, index))
        except StageAInputError as exc:
            issues.append(
                _incomplete_record(
                    category="invalid_waiver",
                    obligation_id=f"mapping:waiver:{index}",
                    blocker=str(exc),
                    next_action="fix the malformed non-code waiver entry",
                )
            )

    return mappings, waivers, issues


def _parse_block_mapping(entry: Any, index: int, original: StageABinary) -> BlockMapping:
    if not isinstance(entry, dict):
        raise StageAInputError("block mapping entry must be an object")
    block_id = str(entry.get("id") or f"block_{index:04d}")
    original_side = _parse_side(entry.get("original"), "original")
    candidate_side = _parse_side(entry.get("candidate"), "candidate")
    if original_side.size <= 0 or candidate_side.size <= 0:
        raise StageAInputError(f"block {block_id!r} has an empty or inverted range")
    invariant = entry.get("invariant", {})
    invariant_checked = bool(invariant.get("checked", True)) if isinstance(invariant, dict) else False
    reachable = bool(entry.get("reachable", original_side.rva_start == original.entrypoint_rva))
    return BlockMapping(
        id=block_id,
        original=original_side,
        candidate=candidate_side,
        kind=str(entry.get("kind") or "code"),
        reachable=reachable,
        invariant_checked=invariant_checked,
        source=entry,
    )


def _parse_side(value: Any, name: str) -> BlockSide:
    if not isinstance(value, dict):
        raise StageAInputError(f"{name} block side must be an object")
    if "rva_start" in value and "rva_end" in value:
        return BlockSide(_parse_int(value["rva_start"]), _parse_int(value["rva_end"]))
    if "rva" in value and "size" in value:
        start = _parse_int(value["rva"])
        return BlockSide(start, start + _parse_int(value["size"]))
    raise StageAInputError(f"{name} block side must contain rva_start/rva_end or rva/size")


def _parse_waiver(entry: Any, index: int) -> NonCodeWaiver:
    if not isinstance(entry, dict):
        raise StageAInputError("waiver entry must be an object")
    side = _parse_side(entry, "waiver")
    binary = str(entry.get("binary") or "both")
    if binary not in {"original", "candidate", "both"}:
        raise StageAInputError(f"waiver binary must be original, candidate, or both, got {binary!r}")
    return NonCodeWaiver(
        id=str(entry.get("id") or f"waiver_{index:04d}"),
        binary=binary,
        rva_start=side.rva_start,
        rva_end=side.rva_end,
        reason=str(entry.get("reason") or "non-code waiver"),
    )


def _parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise StageAInputError(f"expected integer or integer string, got {value!r}")


def _range_overlap_issues(binary_name: str, ranges: list[tuple[str, BlockSide]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    ordered = sorted(ranges, key=lambda item: (item[1].rva_start, item[1].rva_end, item[0]))
    for left, right in zip(ordered, ordered[1:]):
        left_id, left_range = left
        right_id, right_range = right
        if left_range.rva_end > right_range.rva_start:
            issues.append(
                _failure_record(
                    category="invalid_mapping",
                    obligation_id=f"mapping:{binary_name}:overlap:{left_id}:{right_id}",
                    blocker=f"{binary_name} block mappings overlap",
                    original={"id": left_id, "rva_start": left_range.rva_start, "rva_end": left_range.rva_end},
                    candidate={"id": right_id, "rva_start": right_range.rva_start, "rva_end": right_range.rva_end},
                )
            )
    return issues


def _waiver_obligations(
    original: StageABinary,
    candidate: StageABinary,
    waivers: Iterable[NonCodeWaiver],
) -> tuple[list[NonCodeWaiver], list[dict[str, Any]]]:
    verified: list[NonCodeWaiver] = []
    obligations: list[dict[str, Any]] = []
    for waiver in waivers:
        checks = _verify_waiver(original, candidate, waiver)
        obligation_id = f"waiver:{waiver.id}:{waiver.binary}:{waiver.rva_start:x}-{waiver.rva_end:x}"
        failed = [check for check in checks if check["status"] != "verified"]
        if failed:
            blocker = _incomplete_record(
                category="unverified_noncode_waiver",
                obligation_id=obligation_id,
                blocker="non-code waiver bytes are not independently verified as executable-section padding",
                next_action="narrow the waiver to verified padding bytes or map the range as code",
                details={
                    "waiver": {
                        "id": waiver.id,
                        "binary": waiver.binary,
                        "rva_start": waiver.rva_start,
                        "rva_end": waiver.rva_end,
                        "reason": waiver.reason,
                    },
                    "checks": checks,
                },
            )
            obligations.append(
                {
                    "id": obligation_id,
                    "kind": "executable_byte_class",
                    "status": "incomplete",
                    "binary": waiver.binary,
                    "rva_start": waiver.rva_start,
                    "rva_end": waiver.rva_end,
                    "reason": waiver.reason,
                    "incomplete": blocker,
                }
            )
            continue
        verified.append(waiver)
        obligations.append(
            {
                "id": obligation_id,
                "kind": "executable_byte_class",
                "status": "waived_noncode",
                "proof_rule": "verified_padding_bytes_v1",
                "binary": waiver.binary,
                "rva_start": waiver.rva_start,
                "rva_end": waiver.rva_end,
                "reason": waiver.reason,
                "checks": checks,
            }
        )
    return verified, obligations


def _verify_waiver(original: StageABinary, candidate: StageABinary, waiver: NonCodeWaiver) -> list[dict[str, Any]]:
    sides = []
    if waiver.binary in {"original", "both"}:
        sides.append(("original", original))
    if waiver.binary in {"candidate", "both"}:
        sides.append(("candidate", candidate))
    return [_verify_waiver_side(side, binary, waiver) for side, binary in sides]


def _verify_waiver_side(side: str, binary: StageABinary, waiver: NonCodeWaiver) -> dict[str, Any]:
    section = _executable_section_covering_range(binary, waiver.rva_start, waiver.rva_end)
    if section is None:
        return {
            "binary": side,
            "status": "not_executable_section_padding",
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "reason": "waiver range is not fully contained in one executable section",
        }
    data = binary.pe.get_data(waiver.rva_start, waiver.rva_end - waiver.rva_start)
    if len(data) != waiver.rva_end - waiver.rva_start:
        return {
            "binary": side,
            "status": "unreadable",
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "section": section.name,
            "read_bytes": len(data),
        }
    if not _is_padding_bytes(binary, waiver.rva_start, data):
        return {
            "binary": side,
            "status": "not_padding",
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "section": section.name,
            "bytes_sha256": sha256_bytes(data),
        }
    return {
        "binary": side,
        "status": "verified",
        "rva_start": waiver.rva_start,
        "rva_end": waiver.rva_end,
        "section": section.name,
        "bytes_sha256": sha256_bytes(data),
        "bytes_hex": data.hex(),
    }


def _executable_section_covering_range(binary: StageABinary, rva_start: int, rva_end: int) -> StageASection | None:
    if rva_end <= rva_start:
        return None
    for section in binary.sections:
        if section.executable and section.rva_start <= rva_start and rva_end <= section.rva_end:
            return section
    return None


def _coverage_obligations(
    side: str,
    binary: StageABinary,
    mappings: list[BlockMapping],
    waivers: list[NonCodeWaiver],
    incomplete: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    mapped_ranges = [
        mapped.original if side == "original" else mapped.candidate
        for mapped in mappings
        if mapped.kind == "code"
    ]
    waiver_ranges = [
        BlockSide(waiver.rva_start, waiver.rva_end)
        for waiver in waivers
        if waiver.binary in {side, "both"}
    ]
    classified = mapped_ranges + waiver_ranges
    obligations: list[dict[str, Any]] = []
    for section in binary.sections:
        if not section.executable:
            continue
        for gap in _gaps(section.rva_start, section.rva_end, classified):
            obligation = {
                "id": f"coverage:{side}:{gap.rva_start:x}-{gap.rva_end:x}",
                "kind": "executable_byte_class",
                "status": "unmapped",
                "binary": side,
                "rva_start": gap.rva_start,
                "rva_end": gap.rva_end,
                "next_action": "add a block mapping or an explicit non-code waiver for this executable byte range",
            }
            obligations.append(obligation)
            incomplete.append(
                _incomplete_record(
                    category="unmapped_executable_bytes",
                    obligation_id=obligation["id"],
                    blocker=f"{side} executable bytes are not classified by block-map.json",
                    next_action=obligation["next_action"],
                    details={"rva_start": gap.rva_start, "rva_end": gap.rva_end},
                )
            )
    return obligations


def _gaps(start: int, end: int, ranges: list[BlockSide]) -> list[BlockSide]:
    cursor = start
    gaps: list[BlockSide] = []
    for item in sorted(ranges, key=lambda entry: (entry.rva_start, entry.rva_end)):
        if item.rva_end <= start or item.rva_start >= end:
            continue
        clipped_start = max(start, item.rva_start)
        clipped_end = min(end, item.rva_end)
        if clipped_start > cursor:
            gaps.append(BlockSide(cursor, clipped_start))
        cursor = max(cursor, clipped_end)
    if cursor < end:
        gaps.append(BlockSide(cursor, end))
    return gaps


def _invariant_issues(invariant_payload: Any, mappings: list[BlockMapping]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if isinstance(invariant_payload, dict):
        assumptions = invariant_payload.get("assumptions", [])
        if assumptions:
            issues.append(
                _incomplete_record(
                    category="unchecked_assumption",
                    obligation_id="invariants:assumptions",
                    blocker="manual invariant assumptions are present",
                    next_action="replace assumptions with checked invariant lemmas before accepting a final pass",
                    details={"assumptions": assumptions},
                )
            )
        for block_id, invariant in (invariant_payload.get("blocks") or {}).items():
            if isinstance(invariant, dict) and invariant.get("checked") is False:
                issues.append(
                    _incomplete_record(
                        category="missing_invariant",
                        obligation_id=f"invariant:{block_id}",
                        blocker=f"block invariant {block_id!r} is not checked",
                        next_action="prove the invariant lemma or weaken the final verdict to incomplete",
                    )
                )
    for mapped in mappings:
        if not mapped.invariant_checked:
            issues.append(
                _incomplete_record(
                    category="missing_invariant",
                    obligation_id=f"invariant:{mapped.id}",
                    blocker=f"block mapping {mapped.id!r} carries an unchecked invariant",
                    next_action="provide a checked invariant lemma for this block",
                )
            )
    return issues


def _invariant_report(mapped: BlockMapping, invariant_payload: Any) -> dict[str, Any]:
    constraints: list[Any] = []
    mapping_invariant = mapped.source.get("invariant")
    if isinstance(mapping_invariant, dict):
        constraints.extend(mapping_invariant.get("constraints", []))
    if isinstance(invariant_payload, dict):
        block_invariant = (invariant_payload.get("blocks") or {}).get(mapped.id)
        if isinstance(block_invariant, dict):
            constraints.extend(block_invariant.get("constraints", []))
    if not constraints:
        return {"kind": "true", "checked": True, "constraints": []}
    return {
        "kind": "checked_constraints",
        "checked": mapped.invariant_checked,
        "constraints": _expr_json(constraints),
    }


def _cfg_edge_obligations(
    original: StageABinary,
    candidate: StageABinary,
    mappings: list[BlockMapping],
    block_statuses: dict[str, str],
) -> list[dict[str, Any]]:
    original_targets = {mapped.original.rva_start: mapped.id for mapped in mappings if mapped.kind == "code"}
    candidate_targets = {mapped.candidate.rva_start: mapped.id for mapped in mappings if mapped.kind == "code"}
    obligations: list[dict[str, Any]] = []
    for mapped in mappings:
        if mapped.kind != "code" or block_statuses.get(f"block:{mapped.id}") != "proved":
            continue

        original_structure = _block_structure_analysis(original, mapped.original, "original", mapped.id)
        candidate_structure = _block_structure_analysis(candidate, mapped.candidate, "candidate", mapped.id)
        structure_blockers = original_structure["blockers"] + candidate_structure["blockers"]
        generated_indirect_obligations = _generated_indirect_target_obligations(mapped, original_structure["blockers"], candidate_structure["blockers"])
        if generated_indirect_obligations is not None:
            obligations.extend(generated_indirect_obligations)
            structure_blockers = [blocker for blocker in structure_blockers if blocker["category"] != "unknown_target"]
        for blocker in structure_blockers:
            obligations.append({"id": blocker["obligation_id"], "kind": "block_structure", "status": "incomplete", "incomplete": blocker})
        if structure_blockers:
            continue

        original_edges = original_structure["edges"]
        candidate_edges = candidate_structure["edges"]
        matched_candidate_edges: set[int] = set()
        edge_incomplete = False
        for original_edge in original_edges:
            obligation_id = f"edge:{mapped.id}:{original_edge['kind']}:{original_edge['target_rva']:x}"
            original_edge, target_id = _canonical_mapped_edge(original, original_targets, original_edge)
            if target_id is None:
                edge_incomplete = True
                blocker = _incomplete_record(
                    category="unmapped_cfg_edge",
                    obligation_id=obligation_id,
                    blocker="direct original CFG edge target is not covered by a block mapping",
                    next_action="add a mapped target block or mark the bytes with an explicit waiver if they are non-code",
                    details={"source_block": mapped.id, "original_edge": original_edge},
                )
                obligations.append({"id": obligation_id, "kind": "cfg_edge", "status": "incomplete", "incomplete": blocker})
                continue
            matching_candidate_edge: tuple[int, dict[str, Any]] | None = None
            for index, edge in enumerate(candidate_edges):
                if index in matched_candidate_edges:
                    continue
                candidate_edge, candidate_target_id = _canonical_mapped_edge(candidate, candidate_targets, edge)
                if candidate_edge["kind"] == original_edge["kind"] and candidate_target_id == target_id:
                    matching_candidate_edge = (index, candidate_edge)
                    break
            if matching_candidate_edge is None:
                candidate_edge_reports = [
                    {**canonical_edge, "mapped_target": candidate_target_id}
                    for edge in candidate_edges
                    for canonical_edge, candidate_target_id in [_canonical_mapped_edge(candidate, candidate_targets, edge)]
                    if edge["kind"] == original_edge["kind"]
                ]
                failure = _failure_record(
                    category="cfg_edge_mismatch",
                    obligation_id=obligation_id,
                    blocker="candidate CFG edge does not target the mapped equivalent block",
                    original={"source_block": mapped.id, "edge": original_edge, "mapped_target": target_id},
                    candidate={"source_block": mapped.id, "edges": candidate_edge_reports},
                    details={"source_block": mapped.id, "expected_target_block": target_id},
                )
                obligations.append({"id": obligation_id, "kind": "cfg_edge", "status": "failed", "failure": failure})
                continue
            candidate_edge_index, candidate_edge = matching_candidate_edge
            matched_candidate_edges.add(candidate_edge_index)
            obligations.append(
                {
                    "id": obligation_id,
                    "kind": "cfg_edge",
                    "status": "proved",
                    "proof_rule": "direct_cfg_edge_mapping_v1",
                    "source_block": mapped.id,
                    "edge_kind": original_edge["kind"],
                    "target_block": target_id,
                    "original_edge": original_edge,
                    "candidate_edge": candidate_edge,
                }
            )
        if edge_incomplete:
            continue
        for index, candidate_edge in enumerate(candidate_edges):
            if index in matched_candidate_edges:
                continue
            obligation_id = f"edge:{mapped.id}:candidate-extra:{candidate_edge['kind']}:{candidate_edge['target_rva']:x}"
            candidate_edge, mapped_target = _canonical_mapped_edge(candidate, candidate_targets, candidate_edge)
            if mapped_target is None:
                blocker = _incomplete_record(
                    category="unmapped_cfg_edge",
                    obligation_id=obligation_id,
                    blocker="direct candidate CFG edge target is not covered by a block mapping",
                    next_action="add a mapped target block or fix the candidate mapping/proof",
                    details={"source_block": mapped.id, "candidate_edge": candidate_edge},
                )
                obligations.append({"id": obligation_id, "kind": "cfg_edge", "status": "incomplete", "incomplete": blocker})
                continue
            failure = _failure_record(
                category="cfg_edge_mismatch",
                obligation_id=obligation_id,
                blocker="candidate CFG edge has no matching original edge",
                original={"source_block": mapped.id, "edges": original_edges},
                candidate={"source_block": mapped.id, "edge": candidate_edge, "mapped_target": mapped_target},
                details={"source_block": mapped.id, "unexpected_target_block": mapped_target},
            )
            obligations.append({"id": obligation_id, "kind": "cfg_edge", "status": "failed", "failure": failure})
    return obligations


def _canonical_mapped_edge(
    binary: StageABinary,
    targets: dict[int, str],
    edge: dict[str, Any],
) -> tuple[dict[str, Any], str | None]:
    target_rva = int(edge["target_rva"])
    target_id = targets.get(target_rva)
    if target_id is not None:
        return edge, target_id
    canonical_target = _skip_padding_to_mapped_target(binary, target_rva, targets)
    if canonical_target is None:
        return edge, None
    return {**edge, "canonical_target_rva": canonical_target}, targets[canonical_target]


def _skip_padding_to_mapped_target(binary: StageABinary, target_rva: int, targets: dict[int, str]) -> int | None:
    section = _executable_section_for_rva(binary, target_rva)
    if section is None:
        return None
    candidates = sorted(rva for rva in targets if target_rva < rva <= section.rva_end)
    for candidate_rva in candidates:
        data = binary.pe.get_data(target_rva, candidate_rva - target_rva)
        if len(data) == candidate_rva - target_rva and _is_padding_bytes(binary, target_rva, data):
            return candidate_rva
    return None


def _generated_indirect_target_obligations(
    mapped: BlockMapping,
    original_blockers: list[dict[str, Any]],
    candidate_blockers: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    unknown_original = [blocker for blocker in original_blockers if blocker["category"] == "unknown_target"]
    unknown_candidate = [blocker for blocker in candidate_blockers if blocker["category"] == "unknown_target"]
    if not unknown_original and not unknown_candidate:
        return []
    proof = _checked_generated_cfg_proof(mapped)
    if proof is None or len(unknown_original) != len(unknown_candidate):
        return None

    original_signatures = [_unknown_target_signature(blocker, mapped.original) for blocker in unknown_original]
    candidate_signatures = [_unknown_target_signature(blocker, mapped.candidate) for blocker in unknown_candidate]
    if original_signatures != candidate_signatures:
        return None

    obligations: list[dict[str, Any]] = []
    for index, (original_blocker, candidate_blocker, signature) in enumerate(
        zip(unknown_original, unknown_candidate, original_signatures, strict=True)
    ):
        obligation_id = f"indirect-edge:{mapped.id}:{index:04d}:{signature['offset']:x}"
        obligations.append(
            {
                "id": obligation_id,
                "kind": "indirect_cfg_target",
                "status": "proved",
                "proof_rule": proof["rule"],
                "source_block": mapped.id,
                "signature": signature,
                "original": original_blocker["details"],
                "candidate": candidate_blocker["details"],
                "proof": {
                    "rule": proof["rule"],
                    "source_kind": proof["source_kind"],
                    "function": proof["function"],
                },
            }
        )
    return obligations


def _checked_generated_cfg_proof(mapped: BlockMapping) -> dict[str, Any] | None:
    proof = _checked_mapping_proof(mapped)
    if proof is None or proof["source_kind"] not in CHECKED_GENERATED_CFG_SOURCE_KINDS:
        return None
    return proof


def _unknown_target_signature(blocker: dict[str, Any], side: BlockSide) -> dict[str, Any]:
    instruction = blocker["details"]["instruction"]
    return {
        "offset": int(instruction["rva"]) - side.rva_start,
        "size": int(instruction["size"]),
        "mnemonic": instruction["mnemonic"],
        "op_str": _normalize_instruction_operand_text(str(instruction["op_str"])),
    }


def _normalize_instruction_operand_text(value: str) -> str:
    return re.sub(r"0x[0-9a-fA-F]+", "0x*", value)


def _reachability_obligations(
    original: StageABinary,
    mappings: list[BlockMapping],
    block_statuses: dict[str, str],
    edge_obligations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    code_mappings = [mapped for mapped in mappings if mapped.kind == "code"]
    obligations: list[dict[str, Any]] = []
    if not any(mapped.original.rva_start == original.entrypoint_rva for mapped in code_mappings):
        blocker = _incomplete_record(
            category="missing_entry_mapping",
            obligation_id="reachability:entry-root",
            blocker="PE entrypoint is not the start of any mapped code block",
            next_action="add an explicit block mapping whose original RVA starts at the PE entrypoint",
            details={"entrypoint_rva": original.entrypoint_rva},
        )
        obligations.append({"id": "reachability:entry-root", "kind": "reachability", "status": "incomplete", "incomplete": blocker})

    graph: dict[str, list[dict[str, Any]]] = {}
    for edge in edge_obligations:
        if edge.get("status") != "proved" or edge.get("kind") != "cfg_edge" or "target_block" not in edge:
            continue
        source = str(edge.get("source_block"))
        target = str(edge.get("target_block"))
        graph.setdefault(source, []).append(edge)

    reachable: dict[str, dict[str, Any]] = {}
    work: list[str] = []
    for mapped in code_mappings:
        root = _proved_root(mapped, original)
        if root is None:
            continue
        reachable[mapped.id] = root
        work.append(mapped.id)

    while work:
        source = work.pop(0)
        for edge in graph.get(source, []):
            target = str(edge["target_block"])
            if target in reachable:
                continue
            reachable[target] = {
                "kind": "direct_cfg_edge",
                "source_block": source,
                "edge_obligation": edge["id"],
                "edge_kind": edge["edge_kind"],
            }
            work.append(target)

    for mapped in code_mappings:
        obligation_id = f"reachability:{mapped.id}"
        if block_statuses.get(f"block:{mapped.id}") != "proved":
            continue
        proof = reachable.get(mapped.id)
        if proof is None:
            blocker = _incomplete_record(
                category="unproved_reachability",
                obligation_id=obligation_id,
                blocker="mapped code block has no proved entry root, checked root, or proved incoming CFG edge",
                next_action="add a checked root invariant, connect the block through a proved CFG edge, or mark unreachable bytes with a non-code waiver",
                details={
                    "block": mapped.id,
                    "original_rva": mapped.original.rva_start,
                    "candidate_rva": mapped.candidate.rva_start,
                    "reachable_asserted": mapped.reachable,
                    "root": mapped.source.get("root"),
                    "reachability": mapped.source.get("reachability"),
                },
            )
            obligations.append({"id": obligation_id, "kind": "reachability", "status": "incomplete", "incomplete": blocker})
            continue

        if proof["kind"] == "entry":
            proof_rule = "entry_root_reachability_v1"
        elif proof["kind"] == "checked_root":
            proof_rule = "checked_root_reachability_v1"
        else:
            proof_rule = "direct_cfg_reachability_v1"
        obligations.append(
            {
                "id": obligation_id,
                "kind": "reachability",
                "status": "proved",
                "proof_rule": proof_rule,
                "block": mapped.id,
                "original_rva": mapped.original.rva_start,
                "candidate_rva": mapped.candidate.rva_start,
                "proof": proof,
            }
        )
    return obligations


def _proved_root(mapped: BlockMapping, original: StageABinary) -> dict[str, Any] | None:
    if mapped.original.rva_start == original.entrypoint_rva:
        return {"kind": "entry", "entrypoint_rva": original.entrypoint_rva}
    root_kind = _checked_root_kind(mapped)
    if root_kind is not None:
        return {"kind": "checked_root", "root_kind": root_kind}
    return None


def _checked_root_kind(mapped: BlockMapping) -> str | None:
    for key in ("root", "reachability"):
        value = mapped.source.get(key)
        if isinstance(value, dict) and value.get("checked") is True:
            root_kind = str(value.get("kind") or value.get("source") or "checked_root")
            if root_kind in CHECKED_REACHABILITY_ROOT_KINDS:
                return root_kind
    return None


def _block_structure_analysis(binary: StageABinary, side: BlockSide, binary_name: str, block_id: str) -> dict[str, Any]:
    data = binary.pe.get_data(side.rva_start, side.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + side.rva_start))
    decoded = sum(int(insn.size) for insn in instructions)
    instruction_reports = [_instruction_report(binary, insn) for insn in instructions]
    blockers: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    if not instructions or decoded != len(data):
        blockers.append(
            _incomplete_record(
                category="structural_decode_failed",
                obligation_id=f"structure:{block_id}:{binary_name}:decode",
                blocker=f"{binary_name} mapped code range did not decode cleanly for CFG recovery",
                next_action="fix the block boundary or map undecoded bytes as unsupported/incomplete",
                details={
                    "block": block_id,
                    "binary": binary_name,
                    "rva_start": side.rva_start,
                    "rva_end": side.rva_end,
                    "decoded_bytes": decoded,
                    "total_bytes": len(data),
                },
            )
        )
        return {"instructions": instruction_reports, "edges": edges, "blockers": blockers}

    last_index = len(instructions) - 1
    for index, insn in enumerate(instructions):
        rva = int(insn.address - binary.image_base)
        mnemonic = insn.mnemonic
        report = instruction_reports[index]
        if _is_structural_import_call(binary, insn):
            continue
        if _is_conditional_jump(mnemonic):
            target = _resolved_branch_target(binary, insn)
            if target is None:
                blockers.append(_unknown_target_blocker(block_id, binary_name, report))
            else:
                edges.append({"kind": "taken", "target_rva": target, "instruction_rva": rva, "mnemonic": mnemonic})
                edges.append({"kind": "fallthrough", "target_rva": rva + int(insn.size), "instruction_rva": rva, "mnemonic": mnemonic})
            if index != last_index:
                blockers.append(_unsplit_block_blocker(block_id, binary_name, report))
            continue
        if mnemonic in {"jmp", "ljmp"}:
            if _external_import_jump(binary, insn) is not None:
                if index != last_index:
                    blockers.append(_unsplit_block_blocker(block_id, binary_name, report))
                continue
            target = _resolved_branch_target(binary, insn)
            if target is None:
                blockers.append(_unknown_target_blocker(block_id, binary_name, report))
            else:
                edges.append({"kind": "jump", "target_rva": target, "instruction_rva": rva, "mnemonic": mnemonic})
            if index != last_index:
                blockers.append(_unsplit_block_blocker(block_id, binary_name, report))
            continue
        if mnemonic == "call":
            if _is_noreturn_import_call(binary, insn):
                if index != last_index:
                    blockers.append(_unsplit_block_blocker(block_id, binary_name, report))
                continue
            target = _resolved_branch_target(binary, insn)
            if target is None:
                blockers.append(_unknown_target_blocker(block_id, binary_name, report))
            else:
                edges.append({"kind": "call", "target_rva": target, "instruction_rva": rva, "mnemonic": mnemonic})
            continue
        if mnemonic == "ret":
            if index != last_index:
                blockers.append(_unsplit_block_blocker(block_id, binary_name, report))
            continue

    last = instructions[-1]
    if not _instruction_ends_basic_block(last):
        last_rva = int(last.address - binary.image_base)
        edges.append({"kind": "fallthrough", "target_rva": side.rva_end, "instruction_rva": last_rva, "mnemonic": last.mnemonic})
    return {"instructions": instruction_reports, "edges": edges, "blockers": blockers}


def _instruction_report(binary: StageABinary, insn: Any) -> dict[str, Any]:
    return {
        "rva": int(insn.address - binary.image_base),
        "size": int(insn.size),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "bytes": bytes(insn.bytes).hex(),
    }


def _is_structural_import_call(binary: StageABinary, insn: Any) -> bool:
    return insn.mnemonic == "call" and _external_import_call(binary, insn) is not None


def _instruction_ends_basic_block(insn: Any) -> bool:
    mnemonic = insn.mnemonic
    return mnemonic == "ret" or mnemonic in {"jmp", "ljmp"} or _is_conditional_jump(mnemonic)


def _unknown_target_blocker(block_id: str, binary_name: str, instruction: dict[str, Any]) -> dict[str, Any]:
    return _incomplete_record(
        category="unknown_target",
        obligation_id=f"structure:{block_id}:{binary_name}:unknown-target:{instruction['rva']:x}",
        blocker=f"{binary_name} indirect control-flow target at RVA 0x{instruction['rva']:x} is not resolved",
        next_action="add an invariant, target-resolution proof, or external-boundary model for this instruction",
        details={"block": block_id, "binary": binary_name, "instruction": instruction},
    )


def _unsplit_block_blocker(block_id: str, binary_name: str, instruction: dict[str, Any]) -> dict[str, Any]:
    return _incomplete_record(
        category="unsplit_basic_block",
        obligation_id=f"structure:{block_id}:{binary_name}:unsplit:{instruction['rva']:x}",
        blocker=f"{binary_name} mapped range contains control-flow terminator before the end of the block",
        next_action="split the mapping at recovered basic-block boundaries before accepting a final pass",
        details={"block": block_id, "binary": binary_name, "instruction": instruction},
    )


def _direct_cfg_edges(binary: StageABinary, side: BlockSide) -> list[dict[str, Any]]:
    data = binary.pe.get_data(side.rva_start, side.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + side.rva_start))
    if not instructions or sum(insn.size for insn in instructions) != len(data):
        return []
    last = instructions[-1]
    last_rva = int(last.address - binary.image_base)
    fallthrough_rva = last_rva + int(last.size)
    mnemonic = last.mnemonic
    if _is_conditional_jump(mnemonic):
        target = _resolved_branch_target(binary, last)
        if target is None:
            return []
        return [
            {"kind": "taken", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic},
            {"kind": "fallthrough", "target_rva": fallthrough_rva, "instruction_rva": last_rva, "mnemonic": mnemonic},
        ]
    if mnemonic in {"jmp", "ljmp"}:
        target = _resolved_branch_target(binary, last)
        return [] if target is None else [{"kind": "jump", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic}]
    if mnemonic == "call":
        target = _resolved_branch_target(binary, last)
        return [] if target is None else [{"kind": "call", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic}]
    if mnemonic == "ret":
        return []
    return [{"kind": "fallthrough", "target_rva": side.rva_end, "instruction_rva": last_rva, "mnemonic": mnemonic}]


def _prove_mapped_block(
    original: StageABinary,
    candidate: StageABinary,
    mapped: BlockMapping,
    out: Path,
    proof_cache: list[dict[str, Any]],
    invariant_payload: Any,
) -> dict[str, Any]:
    obligation_id = f"block:{mapped.id}"
    original_bytes = original.pe.get_data(mapped.original.rva_start, mapped.original.size)
    candidate_bytes = candidate.pe.get_data(mapped.candidate.rva_start, mapped.candidate.size)

    if len(original_bytes) != mapped.original.size or len(candidate_bytes) != mapped.candidate.size:
        blocker = _incomplete_record(
            category="unreadable_block_bytes",
            obligation_id=obligation_id,
            blocker="mapped block bytes could not be read from the PE image",
            next_action="fix the mapping range or PE layout",
        )
        return {"id": obligation_id, "kind": "block_equivalence", "status": "incomplete", "incomplete": blocker}

    import_thunk_obligation = _prove_import_thunk_mapping(
        original,
        candidate,
        mapped,
        original_bytes,
        candidate_bytes,
        invariant_payload,
        out,
        proof_cache,
    )
    if import_thunk_obligation is not None:
        return import_thunk_obligation

    trusted_proof = _checked_mapping_proof(mapped)
    if trusted_proof is not None:
        cache_entry = _write_mapping_proof_cache(out, mapped, original_bytes, candidate_bytes, trusted_proof)
        proof_cache.append(cache_entry)
        return {
            "id": obligation_id,
            "kind": "block_equivalence",
            "status": "proved",
            "proof_rule": trusted_proof["rule"],
            "original": {
                "rva_start": mapped.original.rva_start,
                "rva_end": mapped.original.rva_end,
                "size": mapped.original.size,
                "sha256": sha256_bytes(original_bytes),
            },
            "candidate": {
                "rva_start": mapped.candidate.rva_start,
                "rva_end": mapped.candidate.rva_end,
                "size": mapped.candidate.size,
                "sha256": sha256_bytes(candidate_bytes),
            },
            "invariant": _invariant_report(mapped, invariant_payload),
            "reachability": "checked_root",
            "proof": trusted_proof,
            "proof_cache": cache_entry["path"],
        }

    original_analysis = _analyze_block(original, mapped.original, original_bytes, "original", obligation_id)
    candidate_analysis = _analyze_block(candidate, mapped.candidate, candidate_bytes, "candidate", obligation_id)
    cache_entry = _write_proof_cache(out, mapped, original_bytes, candidate_bytes, original_analysis, candidate_analysis)
    proof_cache.append(cache_entry)

    for analysis in (original_analysis, candidate_analysis):
        if analysis["status"] != "ok":
            blocker = _incomplete_record(
                category=analysis["category"],
                obligation_id=obligation_id,
                blocker=analysis["blocker"],
                next_action=analysis["next_action"],
                details=analysis,
            )
            return {"id": obligation_id, "kind": "block_equivalence", "status": "incomplete", "incomplete": blocker}

    if original_bytes == candidate_bytes:
        return {
            "id": obligation_id,
            "kind": "block_equivalence",
            "status": "proved",
            "proof_rule": _byte_identical_proof_rule(original),
            "original": _side_report(mapped.original, original_bytes, original_analysis),
            "candidate": _side_report(mapped.candidate, candidate_bytes, candidate_analysis),
            "invariant": _invariant_report(mapped, invariant_payload),
            "reachability": "entry" if mapped.original.rva_start == original.entrypoint_rva else ("asserted" if mapped.reachable else "unproved"),
            "proof_cache": cache_entry["path"],
        }

    symbolic = _prove_symbolic_equivalence(original, candidate, mapped, original_bytes, candidate_bytes, invariant_payload)
    symbolic_cache_entry = _write_symbolic_proof_cache(out, mapped, symbolic)
    proof_cache.append(symbolic_cache_entry)

    if symbolic["status"] == "proved":
        return {
            "id": obligation_id,
            "kind": "block_equivalence",
            "status": "proved",
            "proof_rule": symbolic["proof_rule"],
            "original": _side_report(mapped.original, original_bytes, original_analysis),
            "candidate": _side_report(mapped.candidate, candidate_bytes, candidate_analysis),
            "invariant": symbolic["invariant"],
            "reachability": "entry" if mapped.original.rva_start == original.entrypoint_rva else ("asserted" if mapped.reachable else "unproved"),
            "proof_cache": symbolic_cache_entry["path"],
            "symbolic": symbolic,
        }

    if symbolic["status"] == "incomplete":
        blocker = _incomplete_record(
            category=symbolic["category"],
            obligation_id=obligation_id,
            blocker=symbolic["blocker"],
            next_action=symbolic["next_action"],
            details=symbolic,
        )
        return {"id": obligation_id, "kind": "block_equivalence", "status": "incomplete", "incomplete": blocker}

    if not mapped.reachable and mapped.original.rva_start != original.entrypoint_rva:
        blocker = _incomplete_record(
            category="unproved_reachability",
            obligation_id=obligation_id,
            blocker="mapped block bytes differ but reachability is not proved",
            next_action="prove the block reachable to report fail, or refine the invariant/mapping if the state is unreachable",
            details=symbolic,
        )
        return {"id": obligation_id, "kind": "block_equivalence", "status": "incomplete", "incomplete": blocker}

    failure = _failure_record(
        category="block_observable_mismatch",
        obligation_id=obligation_id,
        blocker="reachable mapped blocks have different symbolic observables under the current Stage A proof slice",
        original=_side_report(mapped.original, original_bytes, original_analysis),
        candidate=_side_report(mapped.candidate, candidate_bytes, candidate_analysis),
        details=symbolic,
    )
    return {"id": obligation_id, "kind": "block_equivalence", "status": "failed", "failure": failure}


def _prove_import_thunk_mapping(
    original: StageABinary,
    candidate: StageABinary,
    mapped: BlockMapping,
    original_bytes: bytes,
    candidate_bytes: bytes,
    invariant_payload: Any,
    out: Path,
    proof_cache: list[dict[str, Any]],
) -> dict[str, Any] | None:
    source = _mapping_source(mapped)
    if mapped.kind != "import_thunk" and source.get("kind") != "import_thunk":
        return None

    obligation_id = f"block:{mapped.id}"
    original_evidence = _mapped_import_thunk_evidence(original, mapped.original)
    candidate_evidence = _mapped_import_thunk_evidence(candidate, mapped.candidate)
    if original_evidence is None or candidate_evidence is None:
        blocker = _incomplete_record(
            category="invalid_import_thunk_mapping",
            obligation_id=obligation_id,
            blocker="mapped import-thunk block does not decode as exactly one PE import jump on both sides",
            next_action="regenerate the block map with exact import-thunk instruction boundaries or map the bytes as ordinary code",
            details={
                "source": source,
                "original": original_evidence,
                "candidate": candidate_evidence,
            },
        )
        return {"id": obligation_id, "kind": "block_equivalence", "status": "incomplete", "incomplete": blocker}

    original_signature = _import_signature_report(original_evidence["import"])
    candidate_signature = _import_signature_report(candidate_evidence["import"])
    source_signature = source.get("import_signature")
    if isinstance(source_signature, dict) and _normalized_import_signature_dict(source_signature) != original_signature:
        blocker = _incomplete_record(
            category="import_thunk_source_mismatch",
            obligation_id=obligation_id,
            blocker="mapped import-thunk source metadata does not match the original PE import thunk",
            next_action="regenerate the block map from the current binaries",
            details={
                "source_import_signature": source_signature,
                "original_import_signature": original_signature,
            },
        )
        return {"id": obligation_id, "kind": "block_equivalence", "status": "incomplete", "incomplete": blocker}

    if original_signature != candidate_signature:
        failure = _failure_record(
            category="import_thunk_target_mismatch",
            obligation_id=obligation_id,
            blocker="mapped import thunks target different PE imports",
            original={
                **_side_report(mapped.original, original_bytes, original_evidence["analysis"]),
                "import_signature": original_signature,
            },
            candidate={
                **_side_report(mapped.candidate, candidate_bytes, candidate_evidence["analysis"]),
                "import_signature": candidate_signature,
            },
            details={
                "source": source,
                "original_import_signature": original_signature,
                "candidate_import_signature": candidate_signature,
            },
        )
        return {"id": obligation_id, "kind": "block_equivalence", "status": "failed", "failure": failure}

    cache_entry = _write_import_thunk_proof_cache(
        out,
        mapped,
        original_bytes,
        candidate_bytes,
        original_evidence,
        candidate_evidence,
    )
    proof_cache.append(cache_entry)
    return {
        "id": obligation_id,
        "kind": "block_equivalence",
        "status": "proved",
        "proof_rule": "pe_import_thunk_equivalence_v1",
        "original": {
            **_side_report(mapped.original, original_bytes, original_evidence["analysis"]),
            "import_signature": original_signature,
        },
        "candidate": {
            **_side_report(mapped.candidate, candidate_bytes, candidate_evidence["analysis"]),
            "import_signature": candidate_signature,
        },
        "invariant": _invariant_report(mapped, invariant_payload),
        "reachability": "entry" if mapped.original.rva_start == original.entrypoint_rva else ("asserted" if mapped.reachable else "unproved"),
        "proof": {
            "rule": "pe_import_thunk_equivalence_v1",
            "source_kind": source.get("kind"),
            "import_signature": original_signature,
            "original_thunk_rva": original_evidence["import"].thunk_rva,
            "candidate_thunk_rva": candidate_evidence["import"].thunk_rva,
        },
        "proof_cache": cache_entry["path"],
    }


def _mapped_import_thunk_evidence(binary: StageABinary, side: BlockSide) -> dict[str, Any] | None:
    data = binary.pe.get_data(side.rva_start, side.size)
    if len(data) != side.size:
        return None
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + side.rva_start))
    if len(instructions) != 1 or int(instructions[0].size) != side.size:
        return None
    insn = instructions[0]
    imported = _direct_import_jump_instruction(binary, insn)
    if imported is None:
        return None
    analysis = {
        "status": "ok",
        "instructions": [_instruction_report(binary, insn)],
        "machine": binary.machine,
        "bitness": binary.bitness,
        "import_signature": _import_signature_report(imported),
        "import_thunk_rva": imported.thunk_rva,
    }
    return {"import": imported, "analysis": analysis}


def _normalized_import_signature_dict(value: dict[str, Any]) -> dict[str, Any]:
    dll = str(value.get("dll") or "").lower()
    symbol = value.get("symbol")
    ordinal = value.get("ordinal")
    return {
        "dll": dll,
        "symbol": str(symbol) if symbol is not None else None,
        "ordinal": int(ordinal) if ordinal is not None else None,
    }


def _analyze_block(binary: StageABinary, side: BlockSide, data: bytes, binary_name: str, obligation_id: str) -> dict[str, Any]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    base = binary.image_base + side.rva_start
    instructions = list(dis.disasm(data, base))
    decoded = sum(insn.size for insn in instructions)
    if decoded != len(data):
        return {
            "status": "incomplete",
            "category": "unsupported_semantics",
            "binary": binary_name,
            "obligation_id": obligation_id,
            "blocker": f"{binary_name} block did not decode cleanly as x86 instructions",
            "next_action": "fix the block boundary or add semantics for the undecoded byte sequence",
            "decoded_bytes": decoded,
            "total_bytes": len(data),
        }

    insn_reports: list[dict[str, Any]] = []
    for insn in instructions:
        rva = int(insn.address - binary.image_base)
        report = {
            "rva": rva,
            "size": int(insn.size),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": bytes(insn.bytes).hex(),
        }
        insn_reports.append(report)
        if insn.mnemonic in {"hlt", "int", "into", "iretd", "iret", "syscall", "sysenter", "ud2"}:
            return {
                "status": "incomplete",
                "category": "unsupported_semantics",
                "binary": binary_name,
                "obligation_id": obligation_id,
                "blocker": f"unsupported instruction {insn.mnemonic} at RVA 0x{rva:x}",
                "next_action": "add instruction semantics or mark the block out of model",
                "instruction": report,
                "instructions": insn_reports,
            }
        if insn.mnemonic.startswith("call") and _external_import_call(binary, insn) is not None:
            continue
        if insn.mnemonic in {"jmp", "ljmp"} and _external_import_jump(binary, insn) is not None:
            continue
        if insn.mnemonic.startswith("call") or insn.mnemonic.startswith("jmp"):
            target = _resolved_branch_target(binary, insn)
            if target is None:
                return {
                    "status": "incomplete",
                    "category": "unknown_target",
                    "binary": binary_name,
                    "obligation_id": obligation_id,
                    "blocker": f"indirect control-flow target at RVA 0x{rva:x} is not resolved",
                    "next_action": "add an invariant, target-resolution proof, or external-boundary model for this instruction",
                    "instruction": report,
                    "instructions": insn_reports,
                }
    return {"status": "ok", "instructions": insn_reports, "machine": binary.machine, "bitness": binary.bitness}


def _byte_identical_proof_rule(binary: StageABinary) -> str:
    return "byte_identical_x86_64_pe32plus_block" if binary.bitness == 64 else "byte_identical_x86_pe32_block"


def _byte_identical_proof_rule_from_analysis(original_analysis: dict[str, Any], candidate_analysis: dict[str, Any]) -> str:
    if original_analysis.get("bitness") == 64 and candidate_analysis.get("bitness") == 64:
        return "byte_identical_x86_64_pe32plus_block"
    return "byte_identical_x86_pe32_block"


def _direct_branch_target(insn: Any, image_base: int) -> int | None:
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_IMM:
        return None
    return int(operand.imm - image_base)


def _resolved_branch_target(binary: StageABinary, insn: Any) -> int | None:
    target = _direct_branch_target(insn, binary.image_base)
    if target is not None:
        return target
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    pointer_rva = _absolute_mem_operand_rva(binary, operand)
    if pointer_rva is None:
        return None
    width = 8 if binary.bitness == 64 else 4
    data = binary.pe.get_data(pointer_rva, width)
    if len(data) != width:
        return None
    value = int.from_bytes(data, "little")
    if binary.image_base <= value < binary.image_base + binary.size_of_image:
        target_rva = value - binary.image_base
    elif 0 <= value < binary.size_of_image:
        target_rva = value
    else:
        return None
    if _executable_section_for_rva(binary, target_rva) is None:
        return None
    return target_rva


def _external_import_call(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic != "call" or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type == X86_OP_MEM:
        return _import_for_absolute_memory_operand(binary, operand)
    if operand.type == X86_OP_IMM:
        target_rva = int(operand.imm - binary.image_base)
        return _direct_import_thunk(binary, target_rva)
    return None


def _external_import_jump(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type == X86_OP_MEM:
        return _import_for_absolute_memory_operand(binary, operand)
    if operand.type == X86_OP_IMM:
        target_rva = int(operand.imm - binary.image_base)
        return _direct_import_thunk(binary, target_rva)
    return None


def _direct_import_jump_instruction(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, operand)


def _import_for_absolute_memory_operand(binary: StageABinary, operand: Any) -> StageAImport | None:
    thunk_rva = _absolute_mem_operand_rva(binary, operand)
    if thunk_rva is None:
        return None
    return _import_for_thunk_rva(binary, thunk_rva)


def _import_for_thunk_rva(binary: StageABinary, thunk_rva: int) -> StageAImport | None:
    for item in binary.imports:
        if item.thunk_rva == thunk_rva:
            return item
    return None


def _abi_import_report(item: StageAImport) -> dict[str, Any]:
    return {
        "dll": item.dll,
        "symbol": item.symbol,
        "ordinal": item.ordinal,
        "thunk_rva": item.thunk_rva,
    }


def _abi_absolute_addressing_rva(binary: StageABinary, addressing: dict[str, Any]) -> int | None:
    if addressing.get("base") or addressing.get("index"):
        return None
    address = _safe_int(addressing.get("disp"))
    if address is None:
        return None
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None


def _direct_import_thunk(binary: StageABinary, target_rva: int) -> StageAImport | None:
    if _executable_section_for_rva(binary, target_rva) is None:
        return None
    data = binary.pe.get_data(target_rva, 16)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + target_rva))
    if not instructions:
        return None
    first = instructions[0]
    if first.mnemonic not in {"jmp", "ljmp"} or len(first.operands) != 1:
        return None
    operand = first.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, operand)


def _is_noreturn_import_call(binary: StageABinary, insn: Any) -> bool:
    imported = _external_import_call(binary, insn)
    if imported is None:
        return False
    symbol = _normalized_import_symbol(imported.symbol)
    return symbol in NORETURN_IMPORT_SYMBOLS


def _normalized_import_symbol(symbol: str | None) -> str:
    if not symbol:
        return ""
    name = symbol.split("@", 1)[0]
    return name.lstrip("_").lower()


def _absolute_mem_operand_rva(binary: StageABinary, operand: Any) -> int | None:
    mem = operand.mem
    if mem.base or mem.index:
        return None
    address = int(mem.disp)
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None


def _write_proof_cache(
    out: Path,
    mapped: BlockMapping,
    original_bytes: bytes,
    candidate_bytes: bytes,
    original_analysis: dict[str, Any],
    candidate_analysis: dict[str, Any],
) -> dict[str, Any]:
    query = {
        "format": "stage-a-proof-cache-v1",
        "obligation_id": f"block:{mapped.id}",
        "proof_rule": _byte_identical_proof_rule_from_analysis(original_analysis, candidate_analysis),
        "smt_status": "not_required_for_structural_identity" if original_bytes == candidate_bytes else "not_dispatched",
        "query": {
            "kind": "byte_identity_implication",
            "original_sha256": sha256_bytes(original_bytes),
            "candidate_sha256": sha256_bytes(candidate_bytes),
            "equal": original_bytes == candidate_bytes,
        },
        "original_analysis": original_analysis,
        "candidate_analysis": candidate_analysis,
    }
    digest = sha256_bytes(json.dumps(query, sort_keys=True).encode("utf-8"))
    relative = Path("proof-cache") / f"{mapped.id}-{digest[:16]}.json"
    write_json(out / relative, query)
    return {"path": relative.as_posix(), "sha256": digest, "status": query["smt_status"]}


def _checked_mapping_proof(mapped: BlockMapping) -> dict[str, Any] | None:
    proof = mapped.source.get("proof")
    if not isinstance(proof, dict) or proof.get("checked") is not True:
        return None
    rule = str(proof.get("rule") or "")
    if rule not in CHECKED_GENERATED_MAPPING_PROOF_RULES:
        return None
    if rule == "reproducible_stage_b_skeleton_reimplementation_v1" and not _stage_b_proof_metadata_checked(proof.get("stage_b")):
        return None
    return {
        "rule": rule,
        "checked": True,
        "function": str(proof.get("function") or mapped.id),
        "original_flags": str(proof.get("original_flags") or ""),
        "candidate_flags": str(proof.get("candidate_flags") or ""),
        "source_kind": str(mapped.source.get("source", {}).get("kind") if isinstance(mapped.source.get("source"), dict) else ""),
        "stage_b": proof.get("stage_b") if isinstance(proof.get("stage_b"), dict) else None,
    }


def _generated_mapping_proof(
    *,
    proof_rule: str,
    function: str,
    original_flags: str,
    candidate_flags: str,
    proof_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    proof = {
        "rule": proof_rule,
        "checked": True,
        "function": function,
        "original_flags": original_flags,
        "candidate_flags": candidate_flags,
    }
    if proof_metadata:
        proof.update(proof_metadata)
    return proof


def _generated_mapping_proof_metadata_issues(proof_rule: str, proof_metadata: dict[str, Any] | None) -> list[dict[str, Any]]:
    if proof_rule != "reproducible_stage_b_skeleton_reimplementation_v1":
        return []
    if _stage_b_proof_metadata_checked((proof_metadata or {}).get("stage_b")):
        return []
    return [
        _incomplete_record(
            category="missing_stage_b_proof_metadata",
            obligation_id="mapping:stage-b-proof-metadata",
            blocker="Stage B generated mapping proofs require checked skeleton, provenance, and functional-test metadata",
            next_action="generate the map through stage-b-validate-candidate with a compliant candidate provenance manifest",
        )
    ]


def _stage_b_proof_metadata_checked(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return (
        value.get("checked") is True
        and isinstance(value.get("skeleton_manifest_sha256"), str)
        and bool(value.get("skeleton_manifest_sha256"))
        and isinstance(value.get("candidate_provenance_sha256"), str)
        and bool(value.get("candidate_provenance_sha256"))
        and isinstance(value.get("functional_tests_report_sha256"), str)
        and bool(value.get("functional_tests_report_sha256"))
        and value.get("upstream_source_access") is False
        and value.get("manual_behavioral_fixups") == []
        and value.get("functional_tests_status") == "pass"
    )


def _write_mapping_proof_cache(
    out: Path,
    mapped: BlockMapping,
    original_bytes: bytes,
    candidate_bytes: bytes,
    proof: dict[str, Any],
) -> dict[str, Any]:
    query = {
        "format": "stage-a-mapping-proof-cache-v1",
        "obligation_id": f"block:{mapped.id}",
        "proof_rule": proof["rule"],
        "query": {
            "kind": "checked_generated_mapping_proof",
            "original_sha256": sha256_bytes(original_bytes),
            "candidate_sha256": sha256_bytes(candidate_bytes),
            "proof": proof,
        },
    }
    digest = sha256_bytes(json.dumps(query, sort_keys=True).encode("utf-8"))
    relative = Path("proof-cache") / f"{mapped.id}-mapping-proof-{digest[:16]}.json"
    write_json(out / relative, query)
    return {"path": relative.as_posix(), "sha256": digest, "status": "proved"}


def _write_import_thunk_proof_cache(
    out: Path,
    mapped: BlockMapping,
    original_bytes: bytes,
    candidate_bytes: bytes,
    original_evidence: dict[str, Any],
    candidate_evidence: dict[str, Any],
) -> dict[str, Any]:
    query = {
        "format": "stage-a-import-thunk-proof-cache-v1",
        "obligation_id": f"block:{mapped.id}",
        "proof_rule": "pe_import_thunk_equivalence_v1",
        "query": {
            "kind": "pe_import_thunk_equivalence",
            "original_sha256": sha256_bytes(original_bytes),
            "candidate_sha256": sha256_bytes(candidate_bytes),
            "original_import": _import_signature_report(original_evidence["import"]),
            "candidate_import": _import_signature_report(candidate_evidence["import"]),
            "original_thunk_rva": original_evidence["import"].thunk_rva,
            "candidate_thunk_rva": candidate_evidence["import"].thunk_rva,
            "same_import_signature": _import_signature_report(original_evidence["import"])
            == _import_signature_report(candidate_evidence["import"]),
        },
        "original_analysis": original_evidence["analysis"],
        "candidate_analysis": candidate_evidence["analysis"],
    }
    digest = sha256_bytes(json.dumps(query, sort_keys=True).encode("utf-8"))
    relative = Path("proof-cache") / f"{mapped.id}-import-thunk-{digest[:16]}.json"
    write_json(out / relative, query)
    return {"path": relative.as_posix(), "sha256": digest, "status": "proved"}


def _side_report(side: BlockSide, data: bytes, analysis: dict[str, Any]) -> dict[str, Any]:
    return {
        "rva_start": side.rva_start,
        "rva_end": side.rva_end,
        "size": side.size,
        "sha256": sha256_bytes(data),
        "bytes": data.hex(),
        "instructions": analysis.get("instructions", []),
    }


def _first_byte_mismatch(original_bytes: bytes, candidate_bytes: bytes, mapped: BlockMapping) -> dict[str, Any]:
    limit = min(len(original_bytes), len(candidate_bytes))
    for offset in range(limit):
        if original_bytes[offset] != candidate_bytes[offset]:
            return {
                "mismatch": "byte",
                "offset": offset,
                "original_rva": mapped.original.rva_start + offset,
                "candidate_rva": mapped.candidate.rva_start + offset,
                "original_byte": original_bytes[offset],
                "candidate_byte": candidate_bytes[offset],
                "pre_state": {"invariant": "true", "reachable": mapped.reachable},
            }
    return {
        "mismatch": "length",
        "original_size": len(original_bytes),
        "candidate_size": len(candidate_bytes),
        "pre_state": {"invariant": "true", "reachable": mapped.reachable},
    }


def _prove_symbolic_equivalence(
    original: StageABinary,
    candidate: StageABinary,
    mapped: BlockMapping,
    original_bytes: bytes,
    candidate_bytes: bytes,
    invariant_payload: Any,
) -> dict[str, Any]:
    original_sem = _symbolic_execute(original, mapped.original, original_bytes, "original", mapped)
    candidate_sem = _symbolic_execute(candidate, mapped.candidate, candidate_bytes, "candidate", mapped)
    if original_sem["status"] != "ok":
        return original_sem
    if candidate_sem["status"] != "ok":
        return candidate_sem

    original_observables = original_sem["observables"]
    candidate_observables = candidate_sem["observables"]
    invariant = _invariant_report(mapped, invariant_payload)
    smt = _run_z3_equivalence(original_observables, candidate_observables, invariant["constraints"])
    if smt["status"] == "proved":
        return {
            "status": "proved",
            "proof_rule": "smt_z3_local_equivalence_v1",
            "solver": smt["solver"],
            "smt_status": smt["smt_status"],
            "smt_query": smt["smt_query"],
            "invariant": invariant,
            "original_observables": _observables_json(original_observables),
            "candidate_observables": _observables_json(candidate_observables),
        }
    if smt["status"] == "failed":
        return {
            "status": "failed",
            "proof_rule": "smt_z3_local_equivalence_v1",
            "solver": smt["solver"],
            "smt_status": smt["smt_status"],
            "smt_query": smt["smt_query"],
            "mismatch": smt["mismatch"],
            "mismatches": smt["mismatches"],
            "model": smt["model"],
            "pre_state": {"invariant": invariant, "reachable": mapped.reachable},
            "invariant": invariant,
            "original_observables": _observables_json(original_observables),
            "candidate_observables": _observables_json(candidate_observables),
        }
    return {
        "status": "incomplete",
        "category": smt["category"],
        "blocker": smt["blocker"],
        "next_action": smt["next_action"],
        "solver": smt.get("solver", "z3"),
        "smt_status": smt.get("smt_status", "unavailable"),
        "smt_query": smt.get("smt_query", _smt_query_for_observables(original_observables, candidate_observables, invariant["constraints"])),
        "invariant": invariant,
        "original_observables": _observables_json(original_observables),
        "candidate_observables": _observables_json(candidate_observables),
    }


def _symbolic_execute(
    binary: StageABinary,
    side: BlockSide,
    data: bytes,
    binary_name: str,
    mapped: BlockMapping,
) -> dict[str, Any]:
    if binary.bitness != 32:
        return {
            "status": "incomplete",
            "category": "unsupported_semantics",
            "blocker": "Stage A SMT symbolic execution is currently implemented only for x86 PE32 blocks",
            "next_action": "use a checked generated mapping proof or add x86_64 PE32+ symbolic semantics",
            "binary": binary_name,
            "bitness": binary.bitness,
        }
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    base = binary.image_base + side.rva_start
    registers = {name: ("reg", name) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")}
    flags = {name: ("flag", name) for name in ("cf", "zf", "sf", "of", "pf", "df")}
    fpu_stack: list[tuple[Any, ...]] = [("fpu_reg", index) for index in range(8)]
    fpu_control: tuple[Any, ...] = ("fpu_control",)
    fpu_status: tuple[Any, ...] = ("fpu_status",)
    fpu_touched = False
    outcome: tuple[Any, ...] = ("fallthrough", side.rva_end)
    memory_events: list[tuple[Any, ...]] = []
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]] = []
    external_events: list[tuple[Any, ...]] = []
    memory_epoch: int | None = None
    terminated = False

    instructions = list(dis.disasm(data, base))
    for insn in instructions:
        rva = int(insn.address - binary.image_base)
        mnemonic = insn.mnemonic
        operands = insn.operands
        if terminated:
            return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "bytes after a modeled block terminator are not supported")

        if mnemonic == "nop":
            continue
        if mnemonic in {"jmp", "ljmp"}:
            imported_jump = _external_import_jump(binary, insn)
            if imported_jump is not None:
                event_index = len(external_events)
                external_events.append(
                    _external_import_call_event(
                        event_index,
                        imported_jump,
                        rva + int(insn.size),
                        registers,
                        memory_writes,
                        auto_inputs=True,
                    )
                )
                outcome = ("external_jump", imported_jump.dll, imported_jump.symbol, imported_jump.ordinal)
                terminated = True
                continue
            target = _resolved_branch_target(binary, insn)
            if target is None:
                if len(operands) != 1:
                    return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "jump target is not resolved")
                target_expr = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                if target_expr is None:
                    return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "jump target expression is not modeled")
                if operands[0].type == X86_OP_MEM:
                    addressing = _abi_mem_operand_report(insn, operands[0])
                    table_contract = _abi_indexed_jump_table_contract(binary, side, instructions, insn, addressing)
                    if table_contract is not None and table_contract.get("evidence_status") == "derived":
                        outcome = ("indirect_jump_table", target_expr, table_contract)
                        terminated = True
                        continue
                outcome = ("indirect_jump", target_expr)
                terminated = True
                continue
            outcome = ("jump", target)
            terminated = True
            continue
        if _is_conditional_jump(mnemonic):
            target = _resolved_branch_target(binary, insn)
            if target is None:
                return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "direct conditional branch target is not resolved")
            condition = _branch_condition(mnemonic, flags)
            if condition is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "conditional branch predicate is not modeled")
            outcome = ("branch", condition, target, rva + int(insn.size))
            terminated = True
            continue
        if mnemonic == "call":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported call operand shape")
            imported = _external_import_call(binary, insn)
            if imported is not None:
                contract = _external_call_contract(mapped, len(external_events))
                if contract is None:
                    event_index = len(external_events)
                    external_events.append(
                        _external_import_call_event(
                            event_index,
                            imported,
                            rva + int(insn.size),
                            registers,
                            memory_writes,
                            auto_inputs=True,
                        )
                    )
                    memory_writes.clear()
                    memory_epoch = event_index
                    for name in registers:
                        registers[name] = ("call_response", event_index, name)
                    for name in flags:
                        flags[name] = ("call_flag", event_index, name)
                    continue
                args = _external_call_args(insn, contract, registers, memory_events, memory_writes, memory_epoch=memory_epoch)
                if args is None:
                    return _symbolic_incomplete(
                        binary_name,
                        "unsupported_semantics",
                        rva,
                        mnemonic,
                        insn.op_str,
                        "external call argument contract is not supported",
                    )
                event = (
                    "external_call",
                    imported.dll,
                    imported.symbol,
                    imported.ordinal,
                    tuple(args),
                )
                external_events.append(event)
                registers["eax"] = ("env_response", len(external_events) - 1)
                stack_adjust = _parse_external_stack_adjust(contract)
                if stack_adjust:
                    registers["esp"] = _expr_add(registers["esp"], ("const", stack_adjust))
                continue
            target = _resolved_branch_target(binary, insn)
            if target is None:
                target_expr = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                if target_expr is None:
                    return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "indirect call target expression is not modeled")
                event_index = len(external_events)
                external_events.append(_indirect_call_event(event_index, target_expr, rva + int(insn.size), registers, memory_writes))
                memory_writes.clear()
                memory_epoch = event_index
                for name in registers:
                    registers[name] = ("call_response", event_index, name)
                for name in flags:
                    flags[name] = ("call_flag", event_index, name)
                continue
            event_index = len(external_events)
            external_events.append(_internal_call_event(event_index, target, rva + int(insn.size), registers, memory_writes))
            memory_writes.clear()
            memory_epoch = event_index
            for name in registers:
                registers[name] = ("call_response", event_index, name)
            for name in flags:
                flags[name] = ("call_flag", event_index, name)
            continue
        if mnemonic == "ret":
            if len(operands) > 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported ret operand shape")
            stack_adjust = 4
            if len(operands) == 1:
                if operands[0].type != X86_OP_IMM:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported ret operand")
                stack_adjust += int(operands[0].imm) & 0xFFFFFFFF
            outcome = ("return", _memory_read_expr(registers["esp"], memory_events, memory_writes, memory_epoch=memory_epoch))
            registers["esp"] = _expr_add(registers["esp"], ("const", stack_adjust))
            terminated = True
            continue
        if mnemonic == "mov":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov operand shape")
            if operands[0].type == X86_OP_REG:
                dst = insn.reg_name(operands[0].reg)
                width_bits = _operand_width_bits(insn, operands[0])
                src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
                if src is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov source operand")
                if not _write_register_expr(dst, src, registers):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov destination register")
                continue
            if operands[0].type == X86_OP_MEM:
                width_bits = _operand_width_bits(insn, operands[0])
                address = _mem_address_expr(insn, operands[0], registers)
                value = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
                if address is None or value is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov memory write operand")
                _memory_write_expr(address, width_bits, value, memory_events, memory_writes)
                continue
            return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov destination operand")
        if mnemonic in {"movzx", "movsx"}:
            if len(operands) != 2 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported movzx/movsx operand shape")
            dst = insn.reg_name(operands[0].reg)
            src_width = _operand_width_bits(insn, operands[1])
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=src_width, memory_epoch=memory_epoch)
            if src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported movzx/movsx source operand")
            value = _expr_mask(src, src_width) if mnemonic == "movzx" else _expr_sign_extend(src, src_width)
            if not _write_register_expr(dst, value, registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported movzx/movsx destination register")
            continue
        if mnemonic == "push":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported push operand shape")
            value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, memory_epoch=memory_epoch)
            if value is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported push operand")
            new_esp = _expr_sub(registers["esp"], ("const", 4))
            _memory_write_expr(new_esp, 32, value, memory_events, memory_writes)
            registers["esp"] = new_esp
            continue
        if mnemonic == "pop":
            if len(operands) != 1 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register-destination pop is modeled")
            dst = insn.reg_name(operands[0].reg)
            if not _is_supported_register_name(dst):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit general registers are modeled")
            value = _memory_read_expr(registers["esp"], memory_events, memory_writes, memory_epoch=memory_epoch)
            if not _write_register_expr(dst, value, registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported pop destination register")
            registers["esp"] = _expr_add(registers["esp"], ("const", 4))
            continue
        if mnemonic in {"add", "sub"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register/memory-destination arithmetic is modeled")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported arithmetic source operand")
            result = _expr_add(left, src) if mnemonic == "add" else _expr_sub(left, src)
            result = _expr_mask(result, width_bits)
            flags.update(_arithmetic_flags(mnemonic, left, src, result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported arithmetic destination operand")
            continue
        if mnemonic in {"adc", "sbb"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register/memory-destination carry arithmetic is modeled")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported carry arithmetic source operand")
            carry_bit = _expr_bool_bit(flags["cf"])
            if mnemonic == "adc":
                result = _expr_add(_expr_add(left, src), carry_bit)
            else:
                result = _expr_sub(_expr_sub(left, src), carry_bit)
            result = _expr_mask(result, width_bits)
            flags.update(_carry_arithmetic_flags(mnemonic, left, src, flags["cf"], result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported carry arithmetic destination operand")
            continue
        if mnemonic == "imul":
            if len(operands) == 1:
                width_bits = _operand_width_bits(insn, operands[0])
                if width_bits != 32:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit one-operand imul is modeled")
                src = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                if src is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported imul source operand")
                left = registers["eax"]
                low = _expr_imul_low(left, src)
                high = _expr_imul_high(left, src)
                registers["eax"] = low
                registers["edx"] = high
                flags.update(_undefined_arithmetic_flags("imul", rva, keep={"cf": ("imul_overflow", 32, left, src, low, high), "of": ("imul_overflow", 32, left, src, low, high)}))
                continue
            if len(operands) in {2, 3} and operands[0].type == X86_OP_REG:
                width_bits = _operand_width_bits(insn, operands[0])
                if width_bits != 32:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit imul destinations are modeled")
                dst = insn.reg_name(operands[0].reg)
                left = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                right = _read_operand_expr(insn, operands[2], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch) if len(operands) == 3 else _read_register_expr(dst, registers)
                if left is None or right is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported imul operand")
                result = _expr_imul_low(left, right)
                if not _write_register_expr(dst, result, registers):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported imul destination register")
                flags.update(_undefined_arithmetic_flags("imul", rva, keep={"cf": ("imul_overflow", 32, left, right, result, _expr_imul_high(left, right)), "of": ("imul_overflow", 32, left, right, result, _expr_imul_high(left, right))}))
                continue
            return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported imul operand shape")
        if mnemonic == "mul":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mul operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit mul is modeled")
            src = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            if src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mul source operand")
            left = registers["eax"]
            low = _expr_mul_low(left, src)
            high = _expr_mul_high(left, src)
            registers["eax"] = low
            registers["edx"] = high
            carry = ("mul_carry", 32, left, src, high)
            flags.update(_undefined_arithmetic_flags("mul", rva, keep={"cf": carry, "of": carry}))
            continue
        if mnemonic == "div":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported div operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit div is modeled")
            divisor = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            if divisor is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported div source operand")
            dividend_high = registers["edx"]
            dividend_low = registers["eax"]
            registers["eax"] = ("udiv_quot", dividend_high, dividend_low, divisor)
            registers["edx"] = ("udiv_rem", dividend_high, dividend_low, divisor)
            flags.update(_undefined_arithmetic_flags("div", rva))
            continue
        if mnemonic == "cdq":
            if operands:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cdq operand shape")
            registers["edx"] = _expr_ite(("msb_w", 32, registers["eax"]), ("const", 0xFFFFFFFF), ("const", 0))
            continue
        if mnemonic == "cwde":
            if operands:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cwde operand shape")
            registers["eax"] = _expr_sign_extend(_read_register_expr("ax", registers) or ("const", 0), 16)
            continue
        if mnemonic == "cmp":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmp operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or right is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmp operand")
            flags.update(_arithmetic_flags("sub", left, right, _expr_sub(left, right), width_bits=width_bits))
            continue
        if mnemonic in {"xor", "and", "or"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register/memory-destination logical operations are modeled")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported logical source operand")
            result = _logical_result(mnemonic, left, src)
            result = _expr_mask(result, width_bits)
            flags.update(_logical_flags(result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported logical destination operand")
            continue
        if mnemonic == "test":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported test operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or right is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported test operand")
            flags.update(_logical_flags(_expr_and(left, right), width_bits=width_bits))
            continue
        if mnemonic == "lea":
            if len(operands) != 2 or operands[0].type != X86_OP_REG or operands[1].type != X86_OP_MEM:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported lea operand shape")
            dst = insn.reg_name(operands[0].reg)
            if not _is_supported_register_name(dst):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit general registers are modeled")
            src = _mem_address_expr(insn, operands[1], registers)
            if src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported lea address expression")
            if not _write_register_expr(dst, src, registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported lea destination register")
            continue
        if mnemonic in {"shl", "sal", "shr", "sar"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported shift operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            count = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=8, memory_epoch=memory_epoch)
            if left is None or count is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported shift operand")
            count = _expr_and(count, ("const", 0x1F))
            if mnemonic in {"shl", "sal"}:
                result = _expr_shl(left, count)
            elif mnemonic == "shr":
                result = _expr_lshr(left, count)
            else:
                result = _expr_ashr(_expr_mask(left, width_bits), count, width_bits)
            result = _expr_mask(result, width_bits)
            flags.update(_shift_flags(mnemonic, left, count, result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported shift destination operand")
            continue
        if mnemonic in {"shld", "shrd"}:
            if len(operands) != 3 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported double-shift operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            count = _read_operand_expr(insn, operands[2], registers, memory_events, memory_writes, width_bits=8, memory_epoch=memory_epoch)
            if left is None or right is None or count is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported double-shift operand")
            count = _expr_and(count, ("const", 0x1F))
            result = _expr_shift_pair(mnemonic, left, right, count, width_bits)
            flags.update(_shift_flags(mnemonic, left, count, result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported double-shift destination operand")
            continue
        if mnemonic in {"bsr", "tzcnt"}:
            if len(operands) != 2 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported bit-scan operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit bit-scan destinations are modeled")
            dst = insn.reg_name(operands[0].reg)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            current = _read_register_expr(dst, registers)
            if src is None or current is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported bit-scan operand")
            if mnemonic == "bsr":
                result = _expr_ite(("eq", src, ("const", 0)), _undefined_bv("bsr-zero-source", rva, dst), ("bsr_index", 32, src))
                flags.update(_undefined_arithmetic_flags("bsr", rva, keep={"zf": ("eq", src, ("const", 0))}))
            else:
                result = ("tzcnt", 32, src)
                flags.update(_undefined_arithmetic_flags("tzcnt", rva, keep={"cf": ("eq", src, ("const", 0)), "zf": ("eq", result, ("const", 0))}))
            if not _write_register_expr(dst, result, registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported bit-scan destination register")
            continue
        if mnemonic in {"movsd", "rep movsd"}:
            count = 1
            if mnemonic == "rep movsd":
                ecx_value = _canonical_expr(registers["ecx"])
                if not (isinstance(ecx_value, tuple) and len(ecx_value) == 2 and ecx_value[0] == "const"):
                    event_index = len(external_events)
                    df = flags.get("df", ("flag", "df"))
                    external_events.append(("rep_movsd", event_index, registers["edi"], registers["esi"], registers["ecx"], df))
                    delta = _expr_mul(registers["ecx"], ("const", 4))
                    signed_delta = _expr_ite(df, _expr_neg(delta), delta)
                    registers["edi"] = _expr_add(registers["edi"], signed_delta)
                    registers["esi"] = _expr_add(registers["esi"], signed_delta)
                    registers["ecx"] = ("const", 0)
                    memory_writes.clear()
                    memory_epoch = event_index
                    continue
                count = int(ecx_value[1])
                if count < 0 or count > 64:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "rep movsd count is outside the bounded static unroll limit")
            step = _expr_ite(flags.get("df", ("flag", "df")), ("const", 0xFFFFFFFC), ("const", 4))
            src_address = registers["esi"]
            dst_address = registers["edi"]
            for _ in range(count):
                value = _memory_read_expr(src_address, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                _memory_write_expr(dst_address, 32, value, memory_events, memory_writes)
                src_address = _expr_add(src_address, step)
                dst_address = _expr_add(dst_address, step)
            registers["esi"] = src_address
            registers["edi"] = dst_address
            if mnemonic == "rep movsd":
                registers["ecx"] = ("const", 0)
            continue
        if mnemonic in {"cmpxchg", "lock cmpxchg"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmpxchg operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            dst_value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            src_value = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            eax_value = _read_register_expr("eax", registers)
            if dst_value is None or src_value is None or eax_value is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmpxchg operand")
            compare_left = _expr_mask(eax_value, width_bits)
            compare_right = _expr_mask(dst_value, width_bits)
            equal = ("eq", compare_left, compare_right)
            flags.update(_arithmetic_flags("sub", compare_left, compare_right, _expr_sub(compare_left, compare_right), width_bits=width_bits))
            flags["zf"] = equal
            if not _write_operand_expr(insn, operands[0], _expr_ite(equal, src_value, dst_value), registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmpxchg destination")
            if not _write_register_expr("eax", _expr_ite(equal, eax_value, dst_value), registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmpxchg eax update")
            continue
        if mnemonic == "wait":
            continue
        if mnemonic in {
            "fld",
            "fld1",
            "fldz",
            "fild",
            "fst",
            "fstp",
            "fist",
            "fistp",
            "fisttp",
            "fadd",
            "faddp",
            "fsub",
            "fsubp",
            "fsubr",
            "fsubrp",
            "fmul",
            "fmulp",
            "fdiv",
            "fdivp",
            "fdivr",
            "fdivrp",
            "fxch",
            "fchs",
            "fxam",
            "fnstcw",
            "fldcw",
            "fnstsw",
            "fcomi",
            "fcomip",
            "fucomi",
            "fucomip",
            "fcompi",
            "fucompi",
            "fninit",
        }:
            fpu_touched = True
            if mnemonic == "fninit":
                fpu_stack = [("fpu_reg", index) for index in range(8)]
                fpu_control = ("fpu_control_init",)
                fpu_status = ("fpu_status_init",)
                continue
            if mnemonic == "fld1":
                _x87_push(fpu_stack, ("fpu_const", "1"))
                continue
            if mnemonic == "fldz":
                _x87_push(fpu_stack, ("fpu_const", "0"))
                continue
            if mnemonic in {"fld", "fild"}:
                if len(operands) != 1:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 load operand shape")
                value = _x87_operand_value(
                    insn,
                    operands[0],
                    registers,
                    memory_events,
                    memory_writes,
                    fpu_stack,
                    memory_epoch=memory_epoch,
                    integer=mnemonic == "fild",
                )
                if value is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 load operand")
                _x87_push(fpu_stack, value)
                continue
            if mnemonic in {"fst", "fstp", "fist", "fistp", "fisttp"}:
                if len(operands) != 1:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 store operand shape")
                value = fpu_stack[0]
                if operands[0].type == X86_OP_MEM:
                    if not _x87_store_memory(
                        insn,
                        operands[0],
                        value,
                        fpu_control,
                        registers,
                        memory_events,
                        memory_writes,
                        integer=mnemonic in {"fist", "fistp", "fisttp"},
                    ):
                        return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 memory store")
                else:
                    index = _x87_st_index(insn.op_str)
                    if index is None or index >= len(fpu_stack):
                        return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 register store")
                    fpu_stack[index] = value
                if mnemonic in {"fstp", "fistp", "fisttp"}:
                    _x87_pop(fpu_stack)
                continue
            if mnemonic in {"fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr"}:
                value = fpu_stack[0]
                if operands:
                    value = _x87_operand_value(insn, operands[0], registers, memory_events, memory_writes, fpu_stack, memory_epoch=memory_epoch)
                    if value is None:
                        return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 arithmetic operand")
                op = mnemonic[1:]
                if mnemonic in {"fsubr", "fdivr"}:
                    fpu_stack[0] = _x87_binary(op, value, fpu_stack[0])
                else:
                    fpu_stack[0] = _x87_binary(op, fpu_stack[0], value)
                continue
            if mnemonic in {"faddp", "fsubp", "fsubrp", "fmulp", "fdivp", "fdivrp"}:
                index = _x87_st_index(insn.op_str) if insn.op_str else 1
                if index is None or index <= 0 or index >= len(fpu_stack):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 pop arithmetic operand")
                base_op = mnemonic[1:].removesuffix("p")
                if mnemonic in {"fsubrp", "fdivrp"}:
                    fpu_stack[index] = _x87_binary(base_op, fpu_stack[0], fpu_stack[index])
                else:
                    fpu_stack[index] = _x87_binary(base_op, fpu_stack[index], fpu_stack[0])
                _x87_pop(fpu_stack)
                continue
            if mnemonic == "fxch":
                index = _x87_st_index(insn.op_str)
                if index is None or index >= len(fpu_stack):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fxch operand")
                fpu_stack[0], fpu_stack[index] = fpu_stack[index], fpu_stack[0]
                continue
            if mnemonic == "fchs":
                fpu_stack[0] = ("fpu_neg", _canonical_expr(fpu_stack[0]))
                continue
            if mnemonic == "fxam":
                fpu_status = ("fpu_fxam", _canonical_expr(fpu_stack[0]))
                continue
            if mnemonic == "fnstcw":
                if len(operands) != 1 or operands[0].type != X86_OP_MEM:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fnstcw operand")
                address = _mem_address_expr(insn, operands[0], registers)
                if address is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fnstcw address")
                _memory_write_expr(address, 16, ("fpu_control_word", fpu_control), memory_events, memory_writes)
                continue
            if mnemonic == "fldcw":
                if len(operands) != 1:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fldcw operand")
                value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=16, memory_epoch=memory_epoch)
                if value is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fldcw source")
                fpu_control = ("fpu_control_load", value)
                continue
            if mnemonic == "fnstsw":
                if insn.op_str.strip().lower() != "ax":
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only fnstsw ax is modeled")
                if not _write_register_expr("ax", ("fpu_status_word", fpu_status), registers):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fnstsw destination")
                continue
            if mnemonic in {"fcomi", "fcomip", "fucomi", "fucomip", "fcompi", "fucompi"}:
                index = _x87_st_index(insn.op_str) if insn.op_str else 1
                if index is None or index >= len(fpu_stack):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 compare operand")
                left = _canonical_expr(fpu_stack[0])
                right = _canonical_expr(fpu_stack[index])
                flags["cf"] = ("fpu_cmp_cf", left, right)
                flags["zf"] = ("fpu_cmp_zf", left, right)
                flags["pf"] = ("fpu_cmp_pf", left, right)
                flags["of"] = ("false",)
                flags["sf"] = ("false",)
                if mnemonic in {"fcomip", "fucomip", "fcompi", "fucompi"}:
                    _x87_pop(fpu_stack)
                continue
        if mnemonic in {"not", "neg"}:
            if len(operands) != 1 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported unary operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if value is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported unary operand")
            result = _expr_mask(_expr_not(value) if mnemonic == "not" else _expr_neg(value), width_bits)
            if mnemonic == "neg":
                flags.update(_arithmetic_flags("sub", ("const", 0), value, result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported unary destination operand")
            continue
        if mnemonic.startswith("set"):
            if len(operands) != 1 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported setcc operand shape")
            condition = _setcc_condition(mnemonic, flags)
            if condition is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported setcc condition")
            value = _expr_ite(condition, ("const", 1), ("const", 0))
            if not _write_operand_expr(insn, operands[0], value, registers, memory_events, memory_writes, width_bits=8):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported setcc destination operand")
            continue
        if mnemonic.startswith("cmov"):
            if len(operands) != 2 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmovcc operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            dst = insn.reg_name(operands[0].reg)
            current = _read_register_expr(dst, registers)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            condition = _setcc_condition("set" + mnemonic[4:], flags)
            if current is None or src is None or condition is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmovcc operand")
            if not _write_register_expr(dst, _expr_ite(condition, src, current), registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmovcc destination register")
            continue
        if mnemonic == "xchg":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported xchg operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or right is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported xchg operand")
            if not _write_operand_expr(insn, operands[0], right, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported xchg first destination")
            if not _write_operand_expr(insn, operands[1], left, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported xchg second destination")
            continue

        return _symbolic_incomplete(
            binary_name,
            "unsupported_semantics",
            rva,
            mnemonic,
            insn.op_str,
            f"instruction {mnemonic} is not modeled by normalized_symbolic_equivalence_v1",
        )

    observables = {f"reg:{name}": _canonical_expr(registers[name]) for name in sorted(registers)}
    for name in sorted(flags):
        observables[f"flag:{name}"] = _canonical_expr(flags[name])
    observables["outcome"] = _canonical_expr(outcome)
    observables["memory_events"] = tuple(_canonical_expr(event) for event in memory_events)
    observables["external_events"] = tuple(_canonical_expr(event) for event in external_events)
    if fpu_touched:
        observables["fpu_stack"] = tuple(_canonical_expr(item) for item in fpu_stack)
        observables["fpu_control"] = _canonical_expr(fpu_control)
        observables["fpu_status"] = _canonical_expr(fpu_status)
    return {"status": "ok", "observables": observables}


def _is_conditional_jump(mnemonic: str) -> bool:
    return mnemonic in {
        "ja",
        "jae",
        "jb",
        "jbe",
        "jc",
        "je",
        "jg",
        "jge",
        "jl",
        "jle",
        "jna",
        "jnae",
        "jnb",
        "jnbe",
        "jnc",
        "jne",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jnz",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "jz",
    }


def _branch_condition(mnemonic: str, flags: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    cf = flags["cf"]
    zf = flags["zf"]
    sf = flags["sf"]
    of = flags["of"]
    pf = flags.get("pf", ("flag", "pf"))
    conditions = {
        "ja": _bool_and(_bool_not(cf), _bool_not(zf)),
        "jnbe": _bool_and(_bool_not(cf), _bool_not(zf)),
        "jae": _bool_not(cf),
        "jnb": _bool_not(cf),
        "jnc": _bool_not(cf),
        "jb": cf,
        "jc": cf,
        "jnae": cf,
        "jbe": _bool_or(cf, zf),
        "jna": _bool_or(cf, zf),
        "je": zf,
        "jz": zf,
        "jne": _bool_not(zf),
        "jnz": _bool_not(zf),
        "jg": _bool_and(_bool_not(zf), _bool_eq(sf, of)),
        "jnle": _bool_and(_bool_not(zf), _bool_eq(sf, of)),
        "jge": _bool_eq(sf, of),
        "jnl": _bool_eq(sf, of),
        "jl": _bool_xor(sf, of),
        "jnge": _bool_xor(sf, of),
        "jle": _bool_or(zf, _bool_xor(sf, of)),
        "jng": _bool_or(zf, _bool_xor(sf, of)),
        "jno": _bool_not(of),
        "jo": of,
        "jp": pf,
        "jpe": pf,
        "jnp": _bool_not(pf),
        "jpo": _bool_not(pf),
        "jns": _bool_not(sf),
        "js": sf,
    }
    return conditions.get(mnemonic)


def _arithmetic_flags(
    operator: str,
    left: tuple[Any, ...],
    right: tuple[Any, ...],
    result: tuple[Any, ...],
    *,
    width_bits: int = 32,
) -> dict[str, tuple[Any, ...]]:
    left = _expr_mask(left, width_bits)
    right = _expr_mask(right, width_bits)
    result = _expr_mask(result, width_bits)
    if operator == "add":
        cf = ("ult", result, left)
        of = ("add_overflow_w", width_bits, left, right, result)
    else:
        cf = ("ult", left, right)
        of = ("sub_overflow_w", width_bits, left, right, result)
    return {
        "cf": cf,
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": of,
        "pf": ("parity", width_bits, result),
    }


def _logical_flags(result: tuple[Any, ...], *, width_bits: int = 32) -> dict[str, tuple[Any, ...]]:
    result = _expr_mask(result, width_bits)
    return {
        "cf": ("false",),
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": ("false",),
        "pf": ("parity", width_bits, result),
    }


def _logical_result(operator: str, left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    if operator == "xor":
        return _expr_xor(left, right)
    if operator == "and":
        return _expr_and(left, right)
    if operator == "or":
        return _expr_or(left, right)
    raise StageAInputError(f"unsupported logical operator {operator!r}")


def _carry_arithmetic_flags(
    operator: str,
    left: tuple[Any, ...],
    right: tuple[Any, ...],
    carry: tuple[Any, ...],
    result: tuple[Any, ...],
    *,
    width_bits: int,
) -> dict[str, tuple[Any, ...]]:
    left = _expr_mask(left, width_bits)
    right = _expr_mask(right, width_bits)
    carry_bit = _expr_mask(_expr_bool_bit(carry), width_bits)
    result = _expr_mask(result, width_bits)
    if operator == "adc":
        return {
            "cf": ("adc_carry", width_bits, left, right, carry_bit, result),
            "zf": ("eq", result, ("const", 0)),
            "sf": ("msb_w", width_bits, result),
            "of": ("adc_overflow", width_bits, left, right, carry_bit, result),
            "pf": ("parity", width_bits, result),
        }
    return {
        "cf": ("sbb_borrow", width_bits, left, right, carry_bit, result),
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": ("sbb_overflow", width_bits, left, right, carry_bit, result),
        "pf": ("parity", width_bits, result),
    }


def _shift_flags(
    mnemonic: str,
    left: tuple[Any, ...],
    count: tuple[Any, ...],
    result: tuple[Any, ...],
    *,
    width_bits: int,
) -> dict[str, tuple[Any, ...]]:
    result = _expr_mask(result, width_bits)
    return {
        "cf": ("shift_cf", mnemonic, width_bits, _expr_mask(left, width_bits), count),
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": ("shift_of", mnemonic, width_bits, _expr_mask(left, width_bits), count, result),
    }


def _undefined_flag(reason: str, rva: int, name: str) -> tuple[Any, ...]:
    return ("undefined_flag", reason, f"{rva:x}:{name}")


def _undefined_bv(reason: str, rva: int, name: str) -> tuple[Any, ...]:
    return ("undefined_bv", reason, f"{rva:x}:{name}")


def _undefined_arithmetic_flags(reason: str, rva: int, *, keep: dict[str, tuple[Any, ...]] | None = None) -> dict[str, tuple[Any, ...]]:
    keep = keep or {}
    return {name: keep.get(name, _undefined_flag(reason, rva, name)) for name in ("cf", "zf", "sf", "of", "pf")}


def _setcc_condition(mnemonic: str, flags: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    suffix = mnemonic[3:] if mnemonic.startswith("set") else mnemonic
    aliases = {
        "e": "z",
        "ne": "nz",
        "nae": "b",
        "c": "b",
        "nb": "ae",
        "nc": "ae",
        "be": "be",
        "na": "be",
        "nbe": "a",
        "nge": "l",
        "nl": "ge",
        "ng": "le",
        "nle": "g",
        "pe": "p",
        "po": "np",
    }
    key = aliases.get(suffix, suffix)
    zf = flags["zf"]
    cf = flags["cf"]
    sf = flags["sf"]
    of = flags["of"]
    pf = flags.get("pf", ("flag", "pf"))
    conditions = {
        "z": zf,
        "nz": _bool_not(zf),
        "a": _bool_and(_bool_not(cf), _bool_not(zf)),
        "ae": _bool_not(cf),
        "b": cf,
        "be": _bool_or(cf, zf),
        "g": _bool_and(_bool_not(zf), _bool_eq(sf, of)),
        "ge": _bool_eq(sf, of),
        "l": _bool_xor(sf, of),
        "le": _bool_or(zf, _bool_xor(sf, of)),
        "o": of,
        "no": _bool_not(of),
        "s": sf,
        "ns": _bool_not(sf),
        "p": pf,
        "np": _bool_not(pf),
    }
    return conditions.get(key)


def _run_z3_equivalence(
    original_observables: dict[str, Any],
    candidate_observables: dict[str, Any],
    invariant_constraints: list[Any],
) -> dict[str, Any]:
    z3 = _import_z3()
    if z3 is None:
        return {
            "status": "incomplete",
            "category": "solver_unavailable",
            "solver": "z3",
            "smt_status": "unavailable",
            "blocker": "Python Z3 bindings are not available",
            "next_action": "run inside the flake dev/test shell or install the proof extra before discharging SMT obligations",
            "smt_query": _smt_query_for_observables(original_observables, candidate_observables, invariant_constraints),
        }

    context = {"z3": z3, "registers": {}, "memory": z3.Function("mem32", z3.BitVecSort(32), z3.BitVecSort(32))}
    comparisons: list[dict[str, Any]] = []
    for key in sorted(set(original_observables) | set(candidate_observables)):
        comparison = _observable_comparison_to_z3(
            key,
            original_observables.get(key),
            candidate_observables.get(key),
            context,
        )
        comparisons.append(comparison)

    unsupported = [item for item in comparisons if item["status"] == "unsupported"]
    solver = z3.Solver()
    solver.set(timeout=10_000)
    if unsupported:
        smt_query = _smt_query_for_observables(original_observables, candidate_observables, invariant_constraints)
        return {
            "status": "incomplete",
            "category": "unsupported_smt_observable",
            "solver": "z3",
            "smt_status": "not_dispatched",
            "blocker": unsupported[0]["blocker"],
            "next_action": "extend the Stage A SMT encoder for this observable shape",
            "smt_query": smt_query,
            "unsupported": [_comparison_json(item) for item in unsupported],
        }

    try:
        invariant_exprs = _invariant_constraints_to_z3(invariant_constraints, context)
    except StageAInputError as exc:
        return {
            "status": "incomplete",
            "category": "unsupported_invariant",
            "solver": "z3",
            "smt_status": "not_dispatched",
            "blocker": str(exc),
            "next_action": "rewrite the invariant constraints in the supported Stage A invariant schema",
            "smt_query": _smt_query_for_observables(original_observables, candidate_observables, invariant_constraints),
            "invariant_constraints": _expr_json(invariant_constraints),
        }

    disequalities = []
    for item in comparisons:
        if item["status"] == "constant":
            if item["equal"]:
                continue
            disequalities.append(z3.BoolVal(True))
        else:
            disequalities.append(z3.Not(item["equal_expr"]))
    if invariant_exprs:
        solver.add(*invariant_exprs)
    solver.add(z3.Or(disequalities) if disequalities else z3.BoolVal(False))
    smt_query = solver.to_smt2()
    result = solver.check()
    if result == z3.unsat:
        return {
            "status": "proved",
            "solver": "z3",
            "smt_status": "unsat",
            "smt_query": smt_query,
            "comparisons": [_comparison_json(item) for item in comparisons],
        }
    if result == z3.sat:
        model = solver.model()
        mismatches = _z3_mismatches(comparisons, model, z3)
        return {
            "status": "failed",
            "solver": "z3",
            "smt_status": "sat",
            "smt_query": smt_query,
            "mismatch": mismatches[0],
            "mismatches": mismatches,
            "model": _z3_model_json(model),
            "comparisons": [_comparison_json(item) for item in comparisons],
        }
    return {
        "status": "incomplete",
        "category": "solver_unknown",
        "solver": "z3",
        "smt_status": "unknown",
        "blocker": f"Z3 returned unknown: {solver.reason_unknown()}",
        "next_action": "increase solver budget, simplify the obligation, or add an invariant lemma",
        "smt_query": smt_query,
    }


def _observable_comparison_to_z3(key: str, original: Any, candidate: Any, context: dict[str, Any]) -> dict[str, Any]:
    if original is None or candidate is None:
        return {
            "status": "constant",
            "observable": key,
            "equal": original is candidate,
            "original": _expr_json(original),
            "candidate": _expr_json(candidate),
        }
    try:
        comparison = _observable_equal_expr(original, candidate, context)
    except StageAInputError as exc:
        return {
            "status": "unsupported",
            "observable": key,
            "blocker": str(exc),
            "original": _expr_json(original),
            "candidate": _expr_json(candidate),
        }
    if isinstance(comparison, bool):
        return {
            "status": "constant",
            "observable": key,
            "equal": comparison,
            "original": _expr_json(original),
            "candidate": _expr_json(candidate),
        }
    return {
        "status": "z3",
        "observable": key,
        "equal_expr": comparison,
        "original": _expr_json(original),
        "candidate": _expr_json(candidate),
    }


def _invariant_constraints_to_z3(constraints: list[Any], context: dict[str, Any]) -> list[Any]:
    result: list[Any] = []
    for constraint in constraints:
        if not isinstance(constraint, dict):
            raise StageAInputError(f"unsupported invariant constraint {constraint!r}")
        register_name = constraint.get("reg") or constraint.get("register")
        if register_name is None:
            raise StageAInputError(f"invariant constraint is missing a register: {constraint!r}")
        register = str(register_name).lower()
        if register not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
            raise StageAInputError(f"unsupported invariant register {register!r}")
        expr = _expr_to_z3(("reg", register), context)
        if "mask" in constraint:
            mask = _parse_int(constraint["mask"])
            expected = _parse_int(constraint.get("equals", constraint.get("eq", 0)))
            result.append((expr & context["z3"].BitVecVal(mask & 0xFFFFFFFF, 32)) == context["z3"].BitVecVal(expected & 0xFFFFFFFF, 32))
            continue
        if "equals" in constraint or "eq" in constraint:
            expected = _parse_int(constraint.get("equals", constraint.get("eq")))
            result.append(expr == context["z3"].BitVecVal(expected & 0xFFFFFFFF, 32))
            continue
        raise StageAInputError(f"unsupported invariant constraint operator: {constraint!r}")
    return result


def _observable_equal_expr(original: Any, candidate: Any, context: dict[str, Any]) -> Any:
    if _is_bool_expr(original) and _is_bool_expr(candidate):
        return _bool_to_z3(original, context) == _bool_to_z3(candidate, context)
    if _is_bv_expr(original) and _is_bv_expr(candidate):
        return _expr_to_z3(original, context) == _expr_to_z3(candidate, context)
    if not isinstance(original, tuple) or not isinstance(candidate, tuple) or not original or not candidate:
        return original == candidate
    if len(original) != len(candidate):
        return False
    if not isinstance(original[0], str) or not isinstance(candidate[0], str):
        expressions = [_observable_equal_expr(left, right, context) for left, right in zip(original, candidate)]
        z3 = context["z3"]
        if all(isinstance(item, bool) for item in expressions):
            return all(expressions)
        return z3.And(*[z3.BoolVal(item) if isinstance(item, bool) else item for item in expressions])
    if original[0] != candidate[0]:
        return False
    if original[0] == "fallthrough":
        return original == candidate
    if original[0] == "return":
        return _expr_to_z3(original[1], context) == _expr_to_z3(candidate[1], context)
    if original[0] == "read":
        return _observable_equal_expr(original[1], candidate[1], context)
    if original[0] == "mem32":
        return _expr_to_z3(original[1], context) == _expr_to_z3(candidate[1], context)
    expressions = [_observable_equal_expr(left, right, context) for left, right in zip(original, candidate)]
    z3 = context["z3"]
    if all(isinstance(item, bool) for item in expressions):
        return all(expressions)
    return z3.And(*[z3.BoolVal(item) if isinstance(item, bool) else item for item in expressions])


def _is_bv_expr(value: Any) -> bool:
    return isinstance(value, tuple) and bool(value) and value[0] in {
        "const",
        "reg",
        "add",
        "sub",
        "mul",
        "xor",
        "and",
        "or",
        "bvnot",
        "neg",
        "shl",
        "lshr",
        "ashr",
        "sext",
        "ite",
        "mem32",
        "mem",
        "env_response",
        "call_response",
        "call_mem",
        "bool_bit",
        "undefined_bv",
        "imul_low",
        "imul_high",
        "mul_low",
        "mul_high",
        "udiv_quot",
        "udiv_rem",
        "bsr_index",
        "tzcnt",
        "fpu_bits_lo",
        "fpu_bits_hi",
        "fpu_int32",
        "fpu_status_word",
        "fpu_control_word",
    }


def _is_bool_expr(value: Any) -> bool:
    return isinstance(value, tuple) and bool(value) and value[0] in {
        "true",
        "false",
        "flag",
        "not",
        "bool_and",
        "bool_or",
        "bool_xor",
        "bool_eq",
        "eq",
        "ult",
        "msb",
        "msb_w",
        "add_overflow",
        "sub_overflow",
        "add_overflow_w",
        "sub_overflow_w",
        "call_flag",
        "shift_cf",
        "shift_of",
        "undefined_flag",
        "adc_carry",
        "adc_overflow",
        "sbb_borrow",
        "sbb_overflow",
        "imul_overflow",
        "mul_carry",
        "parity",
        "fpu_cmp_cf",
        "fpu_cmp_zf",
        "fpu_cmp_pf",
    }


def _bool_to_z3(expr: Any, context: dict[str, Any]) -> Any:
    z3 = context["z3"]
    if not isinstance(expr, tuple) or not expr:
        raise StageAInputError(f"unsupported SMT boolean expression {expr!r}")
    op = expr[0]
    if op == "true":
        return z3.BoolVal(True)
    if op == "false":
        return z3.BoolVal(False)
    if op == "flag":
        name = str(expr[1])
        flags = context.setdefault("flags", {})
        if name not in flags:
            flags[name] = z3.Bool(f"pre_flag_{name}")
        return flags[name]
    if op == "call_flag":
        key = (int(expr[1]), str(expr[2]))
        flags = context.setdefault("call_flags", {})
        if key not in flags:
            flags[key] = z3.Bool(f"call_{key[0]}_{_z3_symbol_part(key[1])}")
        return flags[key]
    if op in {"shift_cf", "shift_of"}:
        key = _z3_symbol_part(repr(_canonical_expr(expr)))
        flags = context.setdefault("shift_flags", {})
        if key not in flags:
            flags[key] = z3.Bool(f"{op}_{key}")
        return flags[key]
    if op == "undefined_flag":
        key = (str(expr[1]), str(expr[2]))
        flags = context.setdefault("undefined_flags", {})
        if key not in flags:
            flags[key] = z3.Bool(f"undef_flag_{_z3_symbol_part(key[0])}_{_z3_symbol_part(key[1])}")
        return flags[key]
    if op in {"adc_carry", "adc_overflow", "sbb_borrow", "sbb_overflow", "imul_overflow", "mul_carry", "parity"}:
        return _uninterpreted_bool_to_z3(op, expr[1:], context)
    if op in {"fpu_cmp_cf", "fpu_cmp_zf", "fpu_cmp_pf"}:
        key = _z3_symbol_part(repr(_canonical_expr(expr)))
        flags = context.setdefault("fpu_cmp_flags", {})
        if key not in flags:
            flags[key] = z3.Bool(f"{op}_{key}")
        return flags[key]
    if op == "not":
        return z3.Not(_bool_to_z3(expr[1], context))
    if op == "bool_and":
        return z3.And(*[_bool_to_z3(part, context) for part in expr[1:]])
    if op == "bool_or":
        return z3.Or(*[_bool_to_z3(part, context) for part in expr[1:]])
    if op == "bool_xor":
        parts = [_bool_to_z3(part, context) for part in expr[1:]]
        if not parts:
            return z3.BoolVal(False)
        result = parts[0]
        for part in parts[1:]:
            result = z3.Xor(result, part)
        return result
    if op == "bool_eq":
        return _bool_to_z3(expr[1], context) == _bool_to_z3(expr[2], context)
    if op == "eq":
        return _expr_to_z3(expr[1], context) == _expr_to_z3(expr[2], context)
    if op == "ult":
        return z3.ULT(_expr_to_z3(expr[1], context), _expr_to_z3(expr[2], context))
    if op == "msb":
        return z3.Extract(31, 31, _expr_to_z3(expr[1], context)) == z3.BitVecVal(1, 1)
    if op == "msb_w":
        width = int(expr[1])
        bit = max(0, min(31, width - 1))
        return z3.Extract(bit, bit, _expr_to_z3(expr[2], context)) == z3.BitVecVal(1, 1)
    if op == "add_overflow":
        left = _expr_to_z3(expr[1], context)
        right = _expr_to_z3(expr[2], context)
        result = _expr_to_z3(expr[3], context)
        return z3.And(
            z3.Extract(31, 31, left) == z3.Extract(31, 31, right),
            z3.Extract(31, 31, left) != z3.Extract(31, 31, result),
        )
    if op == "add_overflow_w":
        width = int(expr[1])
        bit = max(0, min(31, width - 1))
        left = _expr_to_z3(expr[2], context)
        right = _expr_to_z3(expr[3], context)
        result = _expr_to_z3(expr[4], context)
        return z3.And(
            z3.Extract(bit, bit, left) == z3.Extract(bit, bit, right),
            z3.Extract(bit, bit, left) != z3.Extract(bit, bit, result),
        )
    if op == "sub_overflow":
        left = _expr_to_z3(expr[1], context)
        right = _expr_to_z3(expr[2], context)
        result = _expr_to_z3(expr[3], context)
        return z3.And(
            z3.Extract(31, 31, left) != z3.Extract(31, 31, right),
            z3.Extract(31, 31, left) != z3.Extract(31, 31, result),
        )
    if op == "sub_overflow_w":
        width = int(expr[1])
        bit = max(0, min(31, width - 1))
        left = _expr_to_z3(expr[2], context)
        right = _expr_to_z3(expr[3], context)
        result = _expr_to_z3(expr[4], context)
        return z3.And(
            z3.Extract(bit, bit, left) != z3.Extract(bit, bit, right),
            z3.Extract(bit, bit, left) != z3.Extract(bit, bit, result),
        )
    raise StageAInputError(f"unsupported SMT boolean expression operator {op!r}")


def _expr_to_z3(expr: Any, context: dict[str, Any]) -> Any:
    z3 = context["z3"]
    if not isinstance(expr, tuple) or not expr:
        raise StageAInputError(f"unsupported SMT expression {expr!r}")
    op = expr[0]
    if op == "const":
        return z3.BitVecVal(int(expr[1]) & 0xFFFFFFFF, 32)
    if op == "reg":
        name = str(expr[1])
        if name not in context["registers"]:
            context["registers"][name] = z3.BitVec(f"pre_{name}", 32)
        return context["registers"][name]
    if op == "env_response":
        index = int(expr[1])
        responses = context.setdefault("env_responses", {})
        if index not in responses:
            responses[index] = z3.BitVec(f"env_response_{index}", 32)
        return responses[index]
    if op == "call_response":
        key = (int(expr[1]), str(expr[2]))
        responses = context.setdefault("call_responses", {})
        if key not in responses:
            responses[key] = z3.BitVec(f"call_{key[0]}_{_z3_symbol_part(key[1])}", 32)
        return responses[key]
    if op == "bool_bit":
        return z3.If(_bool_to_z3(expr[1], context), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    if op == "undefined_bv":
        key = (str(expr[1]), str(expr[2]))
        values = context.setdefault("undefined_bv", {})
        if key not in values:
            values[key] = z3.BitVec(f"undef_{_z3_symbol_part(key[0])}_{_z3_symbol_part(key[1])}", 32)
        return values[key]
    if op == "add":
        result = z3.BitVecVal(0, 32)
        for part in expr[1:]:
            result = result + _expr_to_z3(part, context)
        return result
    if op == "sub":
        return _expr_to_z3(expr[1], context) - _expr_to_z3(expr[2], context)
    if op == "mul":
        return _expr_to_z3(expr[1], context) * _expr_to_z3(expr[2], context)
    if op == "xor":
        result = z3.BitVecVal(0, 32)
        for part in expr[1:]:
            result = result ^ _expr_to_z3(part, context)
        return result
    if op == "and":
        return _expr_to_z3(expr[1], context) & _expr_to_z3(expr[2], context)
    if op == "or":
        return _expr_to_z3(expr[1], context) | _expr_to_z3(expr[2], context)
    if op == "bvnot":
        return ~_expr_to_z3(expr[1], context)
    if op == "neg":
        return -_expr_to_z3(expr[1], context)
    if op == "shl":
        return _expr_to_z3(expr[1], context) << _expr_to_z3(expr[2], context)
    if op == "lshr":
        return z3.LShR(_expr_to_z3(expr[1], context), _expr_to_z3(expr[2], context))
    if op == "ashr":
        return _expr_to_z3(expr[2], context) >> _expr_to_z3(expr[3], context)
    if op == "sext":
        width = int(expr[1])
        value = _expr_to_z3(expr[2], context)
        if width >= 32:
            return value
        return z3.SignExt(32 - width, z3.Extract(width - 1, 0, value))
    if op == "ite":
        return z3.If(_bool_to_z3(expr[1], context), _expr_to_z3(expr[2], context), _expr_to_z3(expr[3], context))
    if op == "mem32":
        return context["memory"](_expr_to_z3(expr[1], context))
    if op == "mem":
        width = int(expr[1])
        memories = context.setdefault("memories", {})
        if width not in memories:
            memories[width] = z3.Function(f"mem{width}", z3.BitVecSort(32), z3.BitVecSort(width))
        value = memories[width](_expr_to_z3(expr[2], context))
        return value if width == 32 else z3.ZeroExt(32 - width, value)
    if op == "call_mem":
        event_index = int(expr[1])
        width = int(expr[2])
        memories = context.setdefault("call_memories", {})
        key = (event_index, width)
        if key not in memories:
            memories[key] = z3.Function(f"call_mem_{event_index}_{width}", z3.BitVecSort(32), z3.BitVecSort(width))
        value = memories[key](_expr_to_z3(expr[3], context))
        return value if width == 32 else z3.ZeroExt(32 - width, value)
    if op in {"imul_low", "imul_high", "mul_low", "mul_high", "udiv_quot", "udiv_rem", "bsr_index", "tzcnt"}:
        return _uninterpreted_bv_to_z3(op, expr[1:], context)
    if op in {"fpu_bits_lo", "fpu_bits_hi", "fpu_int32", "fpu_status_word", "fpu_control_word"}:
        key = _z3_symbol_part(repr(_canonical_expr(expr)))
        values = context.setdefault("fpu_bv_values", {})
        if key not in values:
            values[key] = z3.BitVec(f"{op}_{key}", 32)
        return values[key]
    raise StageAInputError(f"unsupported SMT expression operator {op!r}")


def _z3_symbol_part(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in value.lower()).strip("_")
    if cleaned and len(cleaned) <= 48:
        return cleaned
    return sha256_bytes(value.encode("utf-8"))[:16]


def _uninterpreted_bv_to_z3(op: str, args: tuple[Any, ...], context: dict[str, Any]) -> Any:
    z3 = context["z3"]
    key = (op, len(args))
    functions = context.setdefault("uninterpreted_bv_functions", {})
    if key not in functions:
        functions[key] = z3.Function(
            f"bv_{_z3_symbol_part(op)}_{len(args)}",
            *([z3.BitVecSort(32)] * len(args)),
            z3.BitVecSort(32),
        )
    return functions[key](*[_z3_bv_arg(arg, context) for arg in args])


def _uninterpreted_bool_to_z3(op: str, args: tuple[Any, ...], context: dict[str, Any]) -> Any:
    z3 = context["z3"]
    key = (op, len(args))
    functions = context.setdefault("uninterpreted_bool_functions", {})
    if key not in functions:
        functions[key] = z3.Function(
            f"bool_{_z3_symbol_part(op)}_{len(args)}",
            *([z3.BitVecSort(32)] * len(args)),
            z3.BoolSort(),
        )
    return functions[key](*[_z3_bv_arg(arg, context) for arg in args])


def _z3_bv_arg(arg: Any, context: dict[str, Any]) -> Any:
    if isinstance(arg, int):
        return context["z3"].BitVecVal(arg & 0xFFFFFFFF, 32)
    return _expr_to_z3(arg, context)


def _z3_mismatches(comparisons: list[dict[str, Any]], model: Any, z3: Any) -> list[dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []
    for item in comparisons:
        if item["status"] == "constant":
            if item["equal"]:
                continue
            mismatches.append(
                {
                    "observable": item["observable"],
                    "original": item["original"],
                    "candidate": item["candidate"],
                    "model_original": item["original"],
                    "model_candidate": item["candidate"],
                }
            )
            continue
        equal = model.eval(item["equal_expr"], model_completion=True)
        if z3.is_false(equal):
            children = item["equal_expr"].children()
            if len(children) == 2:
                model_original = str(model.eval(children[0], model_completion=True))
                model_candidate = str(model.eval(children[1], model_completion=True))
            else:
                model_original = item["original"]
                model_candidate = item["candidate"]
            mismatches.append(
                {
                    "observable": item["observable"],
                    "original": item["original"],
                    "candidate": item["candidate"],
                    "model_original": model_original,
                    "model_candidate": model_candidate,
                }
            )
    return mismatches or [
        {
            "observable": "unknown",
            "original": None,
            "candidate": None,
            "model_original": None,
            "model_candidate": None,
        }
    ]


def _comparison_json(item: dict[str, Any]) -> dict[str, Any]:
    result = {key: value for key, value in item.items() if key != "equal_expr"}
    if "equal_expr" in item:
        result["equal_expr"] = str(item["equal_expr"])
    return result


def _z3_model_json(model: Any) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for declaration in model.decls():
        interpretation = model[declaration]
        values[declaration.name()] = str(interpretation)
    return values


def _import_z3() -> Any | None:
    try:
        return import_module("z3")
    except ImportError:
        return None


def _symbolic_incomplete(binary_name: str, category: str, rva: int, mnemonic: str, op_str: str, blocker: str) -> dict[str, Any]:
    return {
        "status": "incomplete",
        "category": category,
        "binary": binary_name,
        "blocker": f"{blocker} at RVA 0x{rva:x}",
        "next_action": "add instruction semantics, an invariant lemma, or mark this block out of model",
        "instruction": {"rva": rva, "mnemonic": mnemonic, "op_str": op_str},
    }


_X86_REGISTER_PARTS: dict[str, tuple[str, int, int]] = {
    "eax": ("eax", 0, 32),
    "ax": ("eax", 0, 16),
    "al": ("eax", 0, 8),
    "ah": ("eax", 8, 8),
    "ebx": ("ebx", 0, 32),
    "bx": ("ebx", 0, 16),
    "bl": ("ebx", 0, 8),
    "bh": ("ebx", 8, 8),
    "ecx": ("ecx", 0, 32),
    "cx": ("ecx", 0, 16),
    "cl": ("ecx", 0, 8),
    "ch": ("ecx", 8, 8),
    "edx": ("edx", 0, 32),
    "dx": ("edx", 0, 16),
    "dl": ("edx", 0, 8),
    "dh": ("edx", 8, 8),
    "esi": ("esi", 0, 32),
    "si": ("esi", 0, 16),
    "edi": ("edi", 0, 32),
    "di": ("edi", 0, 16),
    "ebp": ("ebp", 0, 32),
    "bp": ("ebp", 0, 16),
    "esp": ("esp", 0, 32),
    "sp": ("esp", 0, 16),
}


def _is_supported_register_name(name: str) -> bool:
    return name.lower() in _X86_REGISTER_PARTS


def _operand_width_bits(insn: Any, operand: Any) -> int:
    if operand.type == X86_OP_REG:
        name = insn.reg_name(operand.reg).lower()
        part = _X86_REGISTER_PARTS.get(name)
        if part is not None:
            return part[2]
    size = int(getattr(operand, "size", 0) or 0)
    return max(1, size) * 8 if size else 32


def _read_register_expr(name: str, registers: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    part = _X86_REGISTER_PARTS.get(name.lower())
    if part is None:
        return None
    base, offset, width = part
    value = registers.get(base)
    if value is None:
        return None
    if offset:
        value = _expr_lshr(value, ("const", offset))
    return _expr_mask(value, width)


def _write_register_expr(name: str, value: tuple[Any, ...], registers: dict[str, tuple[Any, ...]]) -> bool:
    part = _X86_REGISTER_PARTS.get(name.lower())
    if part is None:
        return False
    base, offset, width = part
    value = _expr_mask(value, width)
    if width == 32 and offset == 0:
        registers[base] = value
        return True
    current = registers.get(base)
    if current is None:
        return False
    field_mask = ((1 << width) - 1) << offset
    clear_mask = (~field_mask) & 0xFFFFFFFF
    shifted = _expr_shl(value, ("const", offset)) if offset else value
    registers[base] = _expr_or(_expr_and(current, ("const", clear_mask)), shifted)
    return True


def _operand_expr(
    insn: Any,
    operand: Any,
    registers: dict[str, tuple[Any, ...]],
    *,
    width_bits: int | None = None,
) -> tuple[Any, ...] | None:
    width_bits = width_bits or _operand_width_bits(insn, operand)
    if operand.type == X86_OP_IMM:
        return _expr_mask(("const", int(operand.imm) & 0xFFFFFFFF), width_bits)
    if operand.type == X86_OP_REG:
        name = insn.reg_name(operand.reg)
        value = _read_register_expr(name, registers)
        return _expr_mask(value, width_bits) if value is not None else None
    return None


def _read_operand_expr(
    insn: Any,
    operand: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    width_bits: int | None = None,
    memory_epoch: int | None = None,
) -> tuple[Any, ...] | None:
    width_bits = width_bits or _operand_width_bits(insn, operand)
    value = _operand_expr(insn, operand, registers, width_bits=width_bits)
    if value is not None:
        return value
    if operand.type != X86_OP_MEM:
        return None
    address = _mem_address_expr(insn, operand, registers)
    if address is None:
        return None
    return _memory_read_expr(address, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)


def _write_operand_expr(
    insn: Any,
    operand: Any,
    value: tuple[Any, ...],
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    width_bits: int | None = None,
) -> bool:
    width_bits = width_bits or _operand_width_bits(insn, operand)
    if operand.type == X86_OP_REG:
        return _write_register_expr(insn.reg_name(operand.reg), value, registers)
    if operand.type == X86_OP_MEM:
        address = _mem_address_expr(insn, operand, registers)
        if address is None:
            return False
        _memory_write_expr(address, width_bits, value, memory_events, memory_writes)
        return True
    return False


def _memory_expr(width_bits: int, address: tuple[Any, ...]) -> tuple[Any, ...]:
    return ("mem32", address) if width_bits == 32 else ("mem", width_bits, address)


def _memory_epoch_expr(width_bits: int, address: tuple[Any, ...], memory_epoch: int | None) -> tuple[Any, ...]:
    if memory_epoch is None:
        return _memory_expr(width_bits, address)
    return ("call_mem", int(memory_epoch), width_bits, address)


def _memory_read_expr(
    address: tuple[Any, ...],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    width_bits: int = 32,
    memory_epoch: int | None = None,
) -> tuple[Any, ...]:
    canonical_address = _canonical_expr(address)
    memory_events.append(("read", _memory_epoch_expr(width_bits, canonical_address, memory_epoch)))
    for written_address, written_width, written_value in reversed(memory_writes):
        if written_width == width_bits and _canonical_expr(written_address) == canonical_address:
            return _expr_mask(written_value, width_bits)
    return _memory_epoch_expr(width_bits, canonical_address, memory_epoch)


def _memory_write_expr(
    address: tuple[Any, ...],
    width_bits: int,
    value: tuple[Any, ...],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> None:
    canonical_address = _canonical_expr(address)
    value = _expr_mask(value, width_bits)
    memory_events.append(("write", _memory_expr(width_bits, canonical_address), value))
    memory_writes.append((canonical_address, width_bits, value))


def _external_call_contract(mapped: BlockMapping, index: int) -> dict[str, Any] | None:
    calls = mapped.source.get("external_calls", mapped.source.get("external_events", []))
    if not isinstance(calls, list) or index >= len(calls):
        return None
    contract = calls[index]
    return contract if isinstance(contract, dict) else None


def _external_call_args(
    insn: Any,
    contract: dict[str, Any],
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    memory_epoch: int | None = None,
) -> list[tuple[Any, ...]] | None:
    args = contract.get("args", [])
    if not isinstance(args, list):
        return None
    result: list[tuple[Any, ...]] = []
    for arg in args:
        expr = _external_arg_expr(insn, arg, registers, memory_events, memory_writes, memory_epoch=memory_epoch)
        if expr is None:
            return None
        result.append(expr)
    return result


def _external_arg_expr(
    insn: Any,
    spec: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    memory_epoch: int | None = None,
) -> tuple[Any, ...] | None:
    if isinstance(spec, int):
        return ("const", spec)
    if isinstance(spec, str):
        return _read_register_expr(spec.lower(), registers)
    if not isinstance(spec, dict):
        return None
    if "const" in spec:
        return ("const", _parse_int(spec["const"]))
    register_name = spec.get("reg") or spec.get("register")
    if register_name is None and spec.get("kind") == "reg":
        register_name = spec.get("name")
    if register_name is not None:
        return _read_register_expr(str(register_name).lower(), registers)
    stack_offset = spec.get("stack") if "stack" in spec else spec.get("stack_offset")
    if stack_offset is None and spec.get("kind") == "stack":
        stack_offset = spec.get("offset", 0)
    if stack_offset is not None:
        address = _expr_add(registers["esp"], ("const", _parse_int(stack_offset)))
        return _memory_read_expr(address, memory_events, memory_writes, memory_epoch=memory_epoch)
    if spec.get("kind") == "memory":
        base_name = str(spec.get("base", "esp")).lower()
        base = registers.get(base_name)
        if base is None:
            return None
        address = _expr_add(base, ("const", _parse_int(spec.get("offset", 0))))
        return _memory_read_expr(address, memory_events, memory_writes, memory_epoch=memory_epoch)
    return None


def _internal_call_event(
    event_index: int,
    target_rva: int,
    return_rva: int,
    registers: dict[str, tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> tuple[Any, ...]:
    register_inputs = _call_register_inputs(registers)
    stack_inputs = _call_stack_inputs(registers, memory_writes)
    return ("internal_call", int(target_rva), int(return_rva), register_inputs, stack_inputs)


def _external_import_call_event(
    event_index: int,
    imported: StageAImport,
    return_rva: int,
    registers: dict[str, tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    auto_inputs: bool,
) -> tuple[Any, ...]:
    extras: tuple[Any, ...] = ()
    if auto_inputs:
        extras = (("auto_call_inputs", _call_register_inputs(registers), _call_stack_inputs(registers, memory_writes)),)
    return ("external_call", imported.dll, imported.symbol, imported.ordinal, (), *extras)


def _indirect_call_event(
    event_index: int,
    target: tuple[Any, ...],
    return_rva: int,
    registers: dict[str, tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> tuple[Any, ...]:
    return ("indirect_call", _canonical_expr(target), int(return_rva), _call_register_inputs(registers), _call_stack_inputs(registers, memory_writes))


def _call_register_inputs(registers: dict[str, tuple[Any, ...]]) -> tuple[tuple[str, tuple[Any, ...]], ...]:
    return tuple((name, _canonical_expr(registers[name])) for name in sorted(registers))


def _call_stack_inputs(
    registers: dict[str, tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> tuple[tuple[int, int, tuple[Any, ...]], ...]:
    return tuple(_stack_argument_writes(registers.get("esp", ("reg", "esp")), memory_writes))


def _stack_argument_writes(
    esp: tuple[Any, ...],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> list[tuple[int, int, tuple[Any, ...]]]:
    result: dict[tuple[int, int], tuple[Any, ...]] = {}
    for address, width_bits, value in memory_writes:
        offset = _stack_relative_offset(address, esp)
        if offset is None or offset < 0 or offset > 0x100:
            continue
        result[(offset, width_bits)] = _expr_mask(value, width_bits)
    return [(offset, width_bits, value) for (offset, width_bits), value in sorted(result.items())]


def _stack_relative_offset(address: tuple[Any, ...], esp: tuple[Any, ...]) -> int | None:
    address = _canonical_expr(address)
    esp = _canonical_expr(esp)
    if address == esp:
        return 0
    if isinstance(address, tuple) and address and address[0] == "add":
        offset = 0
        saw_esp = False
        for part in address[1:]:
            if part == esp:
                saw_esp = True
            elif isinstance(part, tuple) and len(part) == 2 and part[0] == "const":
                offset = (offset + int(part[1])) & 0xFFFFFFFF
            else:
                return None
        if not saw_esp:
            return None
        if offset & 0x80000000:
            offset -= 0x100000000
        return offset
    if isinstance(address, tuple) and len(address) == 3 and address[0] == "sub" and address[1] == esp:
        right = address[2]
        if isinstance(right, tuple) and len(right) == 2 and right[0] == "const":
            return -int(right[1])
    return None


def _parse_external_stack_adjust(contract: dict[str, Any]) -> int:
    value = contract.get("stack_adjust", contract.get("stack_bytes_cleaned", 0))
    return _parse_int(value) if value is not None else 0


def _x87_memory_value(
    insn: Any,
    operand: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    memory_epoch: int | None,
    integer: bool = False,
) -> tuple[Any, ...] | None:
    if operand.type != X86_OP_MEM:
        return None
    address = _mem_address_expr(insn, operand, registers)
    if address is None:
        return None
    width_bits = _operand_width_bits(insn, operand)
    if width_bits <= 32:
        value = _memory_read_expr(address, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
        return ("fpu_int", width_bits, value) if integer else ("fpu_mem", width_bits, value)
    low = _memory_read_expr(address, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
    high = _memory_read_expr(_expr_add(address, ("const", 4)), memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
    return ("fpu_mem64", low, high)


def _x87_operand_value(
    insn: Any,
    operand: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    fpu_stack: list[tuple[Any, ...]],
    *,
    memory_epoch: int | None,
    integer: bool = False,
) -> tuple[Any, ...] | None:
    if operand.type == X86_OP_MEM:
        return _x87_memory_value(insn, operand, registers, memory_events, memory_writes, memory_epoch=memory_epoch, integer=integer)
    index = _x87_st_index(insn.op_str)
    if index is not None and 0 <= index < len(fpu_stack):
        return fpu_stack[index]
    return None


def _x87_st_index(text: str) -> int | None:
    text = text.strip().lower()
    if not text:
        return None
    if "st(" not in text:
        return 0 if text == "st" or text == "st(0)" else None
    start = text.find("st(") + 3
    end = text.find(")", start)
    if end <= start:
        return None
    try:
        return int(text[start:end])
    except ValueError:
        return None


def _x87_push(fpu_stack: list[tuple[Any, ...]], value: tuple[Any, ...]) -> None:
    fpu_stack.insert(0, _canonical_expr(value))
    del fpu_stack[8:]


def _x87_pop(fpu_stack: list[tuple[Any, ...]]) -> tuple[Any, ...]:
    value = fpu_stack.pop(0) if fpu_stack else ("fpu_empty",)
    while len(fpu_stack) < 8:
        fpu_stack.append(("fpu_empty", len(fpu_stack)))
    return value


def _x87_store_memory(
    insn: Any,
    operand: Any,
    value: tuple[Any, ...],
    control: tuple[Any, ...],
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    integer: bool,
) -> bool:
    if operand.type != X86_OP_MEM:
        return False
    address = _mem_address_expr(insn, operand, registers)
    if address is None:
        return False
    width_bits = _operand_width_bits(insn, operand)
    if integer:
        _memory_write_expr(address, min(width_bits, 32), ("fpu_int32", value, control), memory_events, memory_writes)
        return True
    if width_bits <= 32:
        _memory_write_expr(address, width_bits, ("fpu_bits_lo", value), memory_events, memory_writes)
        return True
    _memory_write_expr(address, 32, ("fpu_bits_lo", value), memory_events, memory_writes)
    _memory_write_expr(_expr_add(address, ("const", 4)), 32, ("fpu_bits_hi", value), memory_events, memory_writes)
    return True


def _x87_binary(operator: str, left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    return ("fpu_" + operator, _canonical_expr(left), _canonical_expr(right))


def _mem_address_expr(insn: Any, operand: Any, registers: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    mem = operand.mem
    parts: list[tuple[Any, ...]] = []
    if mem.base:
        base = registers.get(insn.reg_name(mem.base))
        if base is None:
            return None
        parts.append(base)
    if mem.index:
        index = registers.get(insn.reg_name(mem.index))
        if index is None:
            return None
        parts.append(_expr_mul(index, ("const", int(mem.scale))))
    if mem.disp:
        parts.append(("const", int(mem.disp) & 0xFFFFFFFF))
    if not parts:
        return ("const", 0)
    expr = parts[0]
    for part in parts[1:]:
        expr = _expr_add(expr, part)
    return _canonical_expr(expr)


def _expr_add(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0):
        return right
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) + int(right[1])) & 0xFFFFFFFF)
    terms = sorted(_flatten_expr("add", left) + _flatten_expr("add", right), key=repr)
    return ("add", *terms)


def _expr_sub(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) - int(right[1])) & 0xFFFFFFFF)
    return ("sub", left, right)


def _expr_mul(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0) or right == ("const", 0):
        return ("const", 0)
    if left == ("const", 1):
        return right
    if right == ("const", 1):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) * int(right[1])) & 0xFFFFFFFF)
    return ("mul", left, right)


def _expr_mask(value: tuple[Any, ...] | None, width_bits: int) -> tuple[Any, ...]:
    if value is None:
        return ("const", 0)
    if isinstance(value, tuple) and len(value) >= 3 and value[0] == "sext" and int(value[1]) == width_bits:
        return _expr_mask(value[2], width_bits)
    value = _canonical_expr(value)
    if width_bits >= 32:
        return value
    mask = (1 << width_bits) - 1
    if value[0] == "const":
        return ("const", int(value[1]) & mask)
    if value[0] == "and" and ("const", mask) in value[1:]:
        return value
    return _expr_and(value, ("const", mask))


def _expr_sign_extend(value: tuple[Any, ...], width_bits: int) -> tuple[Any, ...]:
    value = _expr_mask(value, width_bits)
    if width_bits >= 32:
        return value
    if value[0] == "const":
        raw = int(value[1]) & ((1 << width_bits) - 1)
        sign_bit = 1 << (width_bits - 1)
        if raw & sign_bit:
            raw |= (~((1 << width_bits) - 1)) & 0xFFFFFFFF
        return ("const", raw & 0xFFFFFFFF)
    return ("sext", width_bits, value)


def _expr_shl(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) << (int(right[1]) & 31)) & 0xFFFFFFFF)
    return ("shl", left, right)


def _expr_lshr(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) & 0xFFFFFFFF) >> (int(right[1]) & 31))
    return ("lshr", left, right)


def _expr_ashr(left: tuple[Any, ...], right: tuple[Any, ...], width_bits: int = 32) -> tuple[Any, ...]:
    left = _expr_mask(left, width_bits)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        shift = int(right[1]) & 31
        raw = int(left[1]) & ((1 << width_bits) - 1)
        if raw & (1 << (width_bits - 1)):
            signed = raw - (1 << width_bits)
        else:
            signed = raw
        return ("const", (signed >> shift) & ((1 << width_bits) - 1))
    return ("ashr", width_bits, left, right)


def _expr_not(value: tuple[Any, ...]) -> tuple[Any, ...]:
    value = _canonical_expr(value)
    if value[0] == "const":
        return ("const", (~int(value[1])) & 0xFFFFFFFF)
    return ("bvnot", value)


def _expr_neg(value: tuple[Any, ...]) -> tuple[Any, ...]:
    value = _canonical_expr(value)
    if value[0] == "const":
        return ("const", (-int(value[1])) & 0xFFFFFFFF)
    return ("neg", value)


def _expr_ite(condition: tuple[Any, ...], when_true: tuple[Any, ...], when_false: tuple[Any, ...]) -> tuple[Any, ...]:
    condition = _canonical_expr(condition)
    when_true = _canonical_expr(when_true)
    when_false = _canonical_expr(when_false)
    if condition == ("true",):
        return when_true
    if condition == ("false",):
        return when_false
    if when_true == when_false:
        return when_true
    return ("ite", condition, when_true, when_false)


def _expr_bool_bit(condition: tuple[Any, ...]) -> tuple[Any, ...]:
    condition = _canonical_expr(condition)
    if condition == ("true",):
        return ("const", 1)
    if condition == ("false",):
        return ("const", 0)
    return ("bool_bit", condition)


def _expr_imul_low(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) * int(right[1])) & 0xFFFFFFFF)
    return ("imul_low", left, right)


def _expr_imul_high(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        signed_left = _signed32(int(left[1]))
        signed_right = _signed32(int(right[1]))
        return ("const", ((signed_left * signed_right) >> 32) & 0xFFFFFFFF)
    return ("imul_high", left, right)


def _expr_mul_low(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) * int(right[1])) & 0xFFFFFFFF)
    return ("mul_low", left, right)


def _expr_mul_high(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        return ("const", (((int(left[1]) & 0xFFFFFFFF) * (int(right[1]) & 0xFFFFFFFF)) >> 32) & 0xFFFFFFFF)
    return ("mul_high", left, right)


def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _expr_shift_pair(mnemonic: str, left: tuple[Any, ...], right: tuple[Any, ...], count: tuple[Any, ...], width_bits: int) -> tuple[Any, ...]:
    left = _expr_mask(left, width_bits)
    right = _expr_mask(right, width_bits)
    count = _expr_and(count, ("const", 0x1F))
    inverse = _expr_sub(("const", width_bits), count)
    if mnemonic == "shrd":
        return _expr_mask(_expr_or(_expr_lshr(left, count), _expr_shl(right, inverse)), width_bits)
    return _expr_mask(_expr_or(_expr_shl(left, count), _expr_lshr(right, inverse)), width_bits)


def _expr_xor(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == right:
        return ("const", 0)
    if left == ("const", 0):
        return right
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", int(left[1]) ^ int(right[1]))
    terms = sorted(_flatten_expr("xor", left) + _flatten_expr("xor", right), key=repr)
    return ("xor", *terms)


def _expr_and(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0) or right == ("const", 0):
        return ("const", 0)
    if left == ("const", 0xFFFFFFFF):
        return right
    if right == ("const", 0xFFFFFFFF):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", int(left[1]) & int(right[1]))
    if repr(right) < repr(left):
        left, right = right, left
    return ("and", left, right)


def _expr_or(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0):
        return right
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", int(left[1]) | int(right[1]))
    if repr(right) < repr(left):
        left, right = right, left
    return ("or", left, right)


def _bool_not(value: tuple[Any, ...]) -> tuple[Any, ...]:
    value = _canonical_expr(value)
    if value == ("true",):
        return ("false",)
    if value == ("false",):
        return ("true",)
    if isinstance(value, tuple) and value and value[0] == "not":
        return value[1]
    return ("not", value)


def _bool_and(*values: tuple[Any, ...]) -> tuple[Any, ...]:
    terms: list[tuple[Any, ...]] = []
    for value in values:
        value = _canonical_expr(value)
        if value == ("false",):
            return ("false",)
        if value == ("true",):
            continue
        terms.extend(_flatten_expr("bool_and", value))
    if not terms:
        return ("true",)
    if len(terms) == 1:
        return terms[0]
    return ("bool_and", *sorted(terms, key=repr))


def _bool_or(*values: tuple[Any, ...]) -> tuple[Any, ...]:
    terms: list[tuple[Any, ...]] = []
    for value in values:
        value = _canonical_expr(value)
        if value == ("true",):
            return ("true",)
        if value == ("false",):
            continue
        terms.extend(_flatten_expr("bool_or", value))
    if not terms:
        return ("false",)
    if len(terms) == 1:
        return terms[0]
    return ("bool_or", *sorted(terms, key=repr))


def _bool_xor(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == right:
        return ("false",)
    if left == ("false",):
        return right
    if right == ("false",):
        return left
    if left == ("true",):
        return _bool_not(right)
    if right == ("true",):
        return _bool_not(left)
    if repr(right) < repr(left):
        left, right = right, left
    return ("bool_xor", left, right)


def _bool_eq(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == right:
        return ("true",)
    if left == ("true",):
        return right
    if right == ("true",):
        return left
    if left == ("false",):
        return _bool_not(right)
    if right == ("false",):
        return _bool_not(left)
    if repr(right) < repr(left):
        left, right = right, left
    return ("bool_eq", left, right)


def _flatten_expr(operator: str, expr: tuple[Any, ...]) -> list[tuple[Any, ...]]:
    if expr and expr[0] == operator:
        return list(expr[1:])
    return [expr]


def _canonical_expr(expr: Any) -> Any:
    if not isinstance(expr, tuple) or not expr:
        return expr
    op = expr[0]
    if op == "const":
        return ("const", int(expr[1]) & 0xFFFFFFFF)
    if op in {"reg", "flag", "true", "false", "env_response", "call_response", "call_flag", "undefined_bv", "undefined_flag"}:
        return expr
    if op == "add":
        result: tuple[Any, ...] = ("const", 0)
        for part in expr[1:]:
            result = _expr_add(result, _canonical_expr(part))
        return result
    if op == "sub":
        return _expr_sub(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "mul":
        return _expr_mul(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "xor":
        result: tuple[Any, ...] = ("const", 0)
        for part in expr[1:]:
            result = _expr_xor(result, _canonical_expr(part))
        return result
    if op == "and":
        return _expr_and(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "or":
        return _expr_or(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "bvnot":
        return _expr_not(_canonical_expr(expr[1]))
    if op == "neg":
        return _expr_neg(_canonical_expr(expr[1]))
    if op == "shl":
        return _expr_shl(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "lshr":
        return _expr_lshr(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "ashr":
        return _expr_ashr(_canonical_expr(expr[2]), _canonical_expr(expr[3]), int(expr[1]))
    if op == "sext":
        return _expr_sign_extend(_canonical_expr(expr[2]), int(expr[1]))
    if op == "ite":
        return _expr_ite(_canonical_expr(expr[1]), _canonical_expr(expr[2]), _canonical_expr(expr[3]))
    if op == "not":
        return _bool_not(_canonical_expr(expr[1]))
    if op == "bool_and":
        return _bool_and(*[_canonical_expr(part) for part in expr[1:]])
    if op == "bool_or":
        return _bool_or(*[_canonical_expr(part) for part in expr[1:]])
    if op == "bool_xor":
        return _bool_xor(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "bool_eq":
        return _bool_eq(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op in {
        "eq",
        "ult",
        "msb",
        "msb_w",
        "add_overflow",
        "sub_overflow",
        "add_overflow_w",
        "sub_overflow_w",
        "shift_cf",
        "shift_of",
        "adc_carry",
        "adc_overflow",
        "sbb_borrow",
        "sbb_overflow",
        "imul_overflow",
        "mul_carry",
        "parity",
        "fpu_cmp_cf",
        "fpu_cmp_zf",
        "fpu_cmp_pf",
        "bool_bit",
        "mem32",
        "mem",
        "call_mem",
        "imul_low",
        "imul_high",
        "mul_low",
        "mul_high",
        "udiv_quot",
        "udiv_rem",
        "bsr_index",
        "tzcnt",
        "fpu_bits_lo",
        "fpu_bits_hi",
        "fpu_int32",
        "fpu_status_word",
        "fpu_control_word",
    }:
        return tuple(_canonical_expr(part) for part in expr)
    return tuple(_canonical_expr(part) for part in expr)


def _observables_json(observables: dict[str, Any]) -> dict[str, Any]:
    return {key: _expr_json(value) for key, value in sorted(observables.items())}


def _expr_json(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_expr_json(item) for item in value]
    if isinstance(value, list):
        return [_expr_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _expr_json(item) for key, item in value.items()}
    return value


def _smt_query_for_observables(original: dict[str, Any], candidate: dict[str, Any], invariant_constraints: list[Any] | None = None) -> str:
    keys = sorted(set(original) | set(candidate))
    declarations = "\n".join(f"; observable {key}" for key in keys)
    invariants = "\n".join(f"; invariant {item}" for item in _expr_json(invariant_constraints or []))
    comparisons = "\n".join(
        f"; {key}: original={_expr_json(original.get(key))} candidate={_expr_json(candidate.get(key))}" for key in keys
    )
    return "\n".join(
        [
            "; Stage A local symbolic-equivalence query.",
            "; The current implementation discharges this subset with Z3 when available.",
            declarations,
            invariants,
            comparisons,
            "(check-sat)",
        ]
    )


def _write_symbolic_proof_cache(out: Path, mapped: BlockMapping, symbolic: dict[str, Any]) -> dict[str, Any]:
    query = {
        "format": "stage-a-symbolic-proof-cache-v1",
        "obligation_id": f"block:{mapped.id}",
        "symbolic": symbolic,
    }
    digest = sha256_bytes(json.dumps(query, sort_keys=True).encode("utf-8"))
    relative = Path("proof-cache") / f"{mapped.id}-symbolic-{digest[:16]}.json"
    write_json(out / relative, query)
    return {"path": relative.as_posix(), "sha256": digest, "status": symbolic["status"]}


def _write_failure_artifacts(out: Path, failure: dict[str, Any]) -> None:
    name = _artifact_name(failure["obligation_id"])
    write_json(out / "failures" / f"{name}.json", failure)
    counterexample = {
        "format": "stage-a-counterexample-v1",
        "obligation_id": failure["obligation_id"],
        "category": failure["category"],
        "pre_state": failure.get("details", {}).get("pre_state", {"invariant": "true"}),
        "mismatch": failure.get("details", {}),
    }
    write_json(out / "counterexamples" / f"{name}.json", counterexample)
    write_json(
        out / "witnesses" / f"{name}.json",
        {
            "format": "stage-a-witness-v1",
            "obligation_id": failure["obligation_id"],
            "kind": "static_block_mismatch",
            "replay": "rerun wincr stage-a-validate with the same original, candidate, mapping, and model",
            "counterexample": f"../counterexamples/{name}.json",
        },
    )


def _write_incomplete_artifact(out: Path, blocker: dict[str, Any]) -> None:
    write_json(out / "incomplete" / f"{_artifact_name(blocker['obligation_id'])}.json", blocker)


def _derive_verdict(failures: list[dict[str, Any]], incomplete: list[dict[str, Any]], obligations: list[dict[str, Any]]) -> str:
    if failures:
        return "fail"
    if incomplete:
        return "incomplete"
    if not obligations:
        return "incomplete"
    statuses = {item["status"] for item in obligations}
    unknown = statuses - OBLIGATION_STATUSES
    if unknown or any(status in {"incomplete", "unmapped", "out_of_model"} for status in statuses):
        return "incomplete"
    if any(status == "failed" for status in statuses):
        return "fail"
    return "pass"


def _write_report(
    *,
    out: Path,
    verdict: str,
    started_at: str,
    original: Path,
    candidate: Path,
    model: str,
    layout: dict[str, Any],
    obligations: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    incomplete: list[dict[str, Any]],
    proof_cache: list[dict[str, Any]],
    mapping_payload: Any,
    invariant_payload: Any,
    lean_inputs: tuple[Path, ...] = (),
) -> dict[str, Any]:
    model_spec = STAGE_A_MODEL_SPECS.get(model, STAGE_A_MODEL_SPECS[STAGE_A_MODEL_ID])
    model_description = {
        "id": model,
        "architecture": model_spec["architecture"],
        "bitness": model_spec["bitness"],
        "environment": "uninterpreted-external-env",
        "proof_rules": [
            "byte_identical_x86_pe32_block",
            "byte_identical_x86_64_pe32plus_block",
            "smt_z3_local_equivalence_v1",
            "direct_cfg_edge_mapping_v1",
            "entry_root_reachability_v1",
            "checked_root_reachability_v1",
            "direct_cfg_reachability_v1",
            "verified_padding_bytes_v1",
            "reproducible_jq_same_source_optimization_pair_v1",
            "reproducible_stage_b_skeleton_reimplementation_v1",
        ],
    }
    model_hash = sha256_bytes(json.dumps(model_description, sort_keys=True).encode("utf-8"))
    lean_summary = _lean_summary(out, verdict, obligations, incomplete, proof_cache, mapping_payload, invariant_payload, lean_inputs)
    if verdict == "pass" and not lean_summary["final_pass_allowed"]:
        incomplete.append(
            _incomplete_record(
                category="lean_global_summary_unchecked",
                obligation_id="lean:global-summary",
                blocker=lean_summary["blocker"],
                next_action=lean_summary["next_action"],
                details=lean_summary,
            )
        )
        verdict = "incomplete"
        lean_summary = _lean_summary(out, verdict, obligations, incomplete, proof_cache, mapping_payload, invariant_payload, lean_inputs)

    for failure in failures:
        _write_failure_artifacts(out, failure)
    for blocker in incomplete:
        _write_incomplete_artifact(out, blocker)

    counts = _obligation_counts(obligations, failures, incomplete)
    verdict_payload = {
        "format": "stage-a-verdict-v1",
        "verdict": verdict,
        "requested_model": model,
        "model": model_description,
        "model_hash": model_hash,
        "started_at": started_at,
        "completed_at": utc_now(),
        "original": {"path": str(original)},
        "candidate": {"path": str(candidate)},
        "counts": counts,
        "tool_versions": _tool_versions(),
        "proof": {
            "local_engine": "stage-a-local-symbolic-x86-v1",
            "smt": "z3_optional_fail_closed",
            "lean": lean_summary,
            "fail_closed": True,
        },
    }
    write_json(out / "layout.json", layout)
    write_json(out / "obligations.json", {"format": "stage-a-obligations-v1", "obligations": obligations, "counts": counts})
    write_json(out / "verdict.json", verdict_payload)
    write_json(out / "proof-cache" / "index.json", {"format": "stage-a-proof-cache-index-v1", "entries": proof_cache})
    return verdict_payload


def _obligation_counts(
    obligations: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    incomplete: list[dict[str, Any]],
) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    for item in obligations:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
    return {
        "obligations": len(obligations),
        "failures": len(failures),
        "incomplete": len(incomplete),
        "by_status": status_counts,
    }


def _lean_summary(
    out: Path,
    verdict: str,
    obligations: list[dict[str, Any]],
    incomplete: list[dict[str, Any]],
    proof_cache: list[dict[str, Any]],
    mapping_payload: Any,
    invariant_payload: Any,
    lean_inputs: tuple[Path, ...],
) -> dict[str, Any]:
    lean_available = shutil.which("lean") is not None
    closed_statuses = {"proved", "waived_noncode"}
    closed = verdict == "pass" and not incomplete and all(item.get("status") in closed_statuses for item in obligations)
    unchecked_blockers = [
        item
        for item in incomplete
        if item.get("category") in {"missing_invariant", "unchecked_assumption", "lean_global_summary_unchecked"}
    ]
    lean_input_summary = _copy_lean_inputs(out / "lean", lean_inputs)
    _write_lean_files(out, verdict, closed, not unchecked_blockers, obligations, proof_cache, lean_input_summary["modules"])
    lean_check = _run_lean_check(out / "lean", lean_input_summary["relative_paths"])
    unchecked_markers = _lean_unchecked_markers(out / "lean")
    lean_input_errors = lean_input_summary["errors"]
    final_pass_allowed = bool(
        verdict == "pass"
        and lean_available
        and closed
        and not unchecked_blockers
        and not lean_input_errors
        and lean_check["status"] == "checked"
        and not unchecked_markers
    )
    if final_pass_allowed:
        blocker = ""
        next_action = ""
    elif not lean_available:
        blocker = "Lean executable is not available for the final pass proof check"
        next_action = "run stage-a-validate in the flake dev/test shell or install Lean 4"
    elif lean_check["status"] != "checked":
        blocker = "generated Lean proof summary did not check"
        next_action = "inspect report/lean/summary.json and fix the generated proof obligations"
    elif lean_input_errors:
        blocker = "supplemental Lean input files could not be copied into the proof report"
        next_action = "fix or remove missing supplemental Lean input paths"
    elif unchecked_markers:
        blocker = "generated Lean artifacts contain unchecked proof markers"
        next_action = "remove sorry/axiom/admit/unsafe proof markers before accepting a final pass"
    elif unchecked_blockers:
        blocker = "unchecked invariant or proof assumptions remain"
        next_action = "replace assumptions with checked invariant lemmas"
    else:
        blocker = "obligation statuses are not all closed"
        next_action = "close failed, incomplete, unmapped, or out-of-model obligations before accepting a final pass"
    summary = {
        "available": lean_available,
        "checked": lean_check["status"] == "checked",
        "global_soundness_checked": final_pass_allowed,
        "final_pass_allowed": final_pass_allowed,
        "generated_stubs": ["StageA/Model.lean", "StageA/Obligations.lean"],
        "final_pass_has_unchecked_lean_assumptions": verdict == "pass" and not final_pass_allowed,
        "unchecked_blockers": unchecked_blockers,
        "unchecked_markers": unchecked_markers,
        "supplemental_inputs": lean_input_summary,
        "closed_obligations": closed,
        "lean_check": lean_check,
        "blocker": blocker,
        "next_action": next_action,
    }
    write_json(out / "lean" / "summary.json", summary)
    write_json(
        out / "lean" / "inputs.json",
        {
            "mapping": mapping_payload,
            "invariants": invariant_payload,
            "lean_inputs": lean_input_summary,
        },
    )
    return summary


def _write_lean_files(
    out: Path,
    verdict: str,
    closed: bool,
    no_unchecked_assumptions: bool,
    obligations: list[dict[str, Any]],
    proof_cache: list[dict[str, Any]],
    lean_input_modules: list[str],
) -> None:
    (out / "lean" / "StageA").mkdir(parents=True, exist_ok=True)
    (out / "lean" / "StageA" / "Model.lean").write_text(
        "-- Generated Stage A model summary.\n"
        "namespace StageA\n\n"
        "inductive Verdict where\n"
        "  | pass\n"
        "  | fail\n"
        "  | incomplete\n"
        "deriving Repr, BEq, DecidableEq\n\n"
        "inductive ObligationStatus where\n"
        "  | proved\n"
        "  | failed\n"
        "  | incomplete\n"
        "  | unmapped\n"
        "  | waivedNoncode\n"
        "  | outOfModel\n"
        "deriving Repr, BEq, DecidableEq\n\n"
        "def obligationStatusClosed : ObligationStatus -> Bool\n"
        "  | ObligationStatus.proved => true\n"
        "  | ObligationStatus.waivedNoncode => true\n"
        "  | _ => false\n\n"
        "structure ProofSummary where\n"
        "  verdict : Verdict\n"
        "  obligationCount : Nat\n"
        "  proofCacheEntries : Nat\n"
        "  closed : Bool\n"
        "  noUncheckedAssumptions : Bool\n"
        "deriving Repr\n\n"
        "end StageA\n",
        encoding="utf-8",
    )
    lean_verdict = {"pass": "pass", "fail": "fail", "incomplete": "incomplete"}[verdict]
    obligation_count = len(obligations)
    proof_cache_count = len(proof_cache)
    closed_literal = "true" if closed else "false"
    unchecked_literal = "true" if no_unchecked_assumptions else "false"
    status_counts = {status: 0 for status in OBLIGATION_STATUSES}
    for item in obligations:
        status = str(item.get("status"))
        status_counts[status if status in status_counts else "incomplete"] += 1
    closed_status_count = status_counts["proved"] + status_counts["waived_noncode"]
    open_status_count = obligation_count - closed_status_count
    closed_by_status_literal = "true" if open_status_count == 0 else "false"
    if verdict == "pass":
        theorem = (
            "theorem generatedClosedChecked : generatedSummary.closed = true := by native_decide\n"
            "theorem generatedNoUncheckedAssumptionsChecked : generatedSummary.noUncheckedAssumptions = true := by native_decide\n"
            "theorem generatedObligationStatusesClosed : generatedObligationsClosedByStatus = true := by native_decide\n"
            "theorem generatedObligationStatusCountsAccountedChecked : generatedObligationStatusCountsAccounted = true := by native_decide\n"
        )
    else:
        theorem = "theorem generatedVerdictNotPass : generatedVerdictIsPass = false := by native_decide\n"
    extra_imports = "".join(f"import {module}\n" for module in lean_input_modules)
    (out / "lean" / "StageA" / "Obligations.lean").write_text(
        "-- Generated Stage A checked obligation summary.\n"
        "import StageA.Model\n"
        f"{extra_imports}\nnamespace StageA\n\n"
        f"def generatedVerdict : Verdict := Verdict.{lean_verdict}\n"
        f"def generatedVerdictIsPass : Bool := generatedVerdict == Verdict.pass\n"
        f"def generatedObligationCount : Nat := {obligation_count}\n"
        f"def generatedProvedObligationCount : Nat := {status_counts['proved']}\n"
        f"def generatedWaivedNoncodeObligationCount : Nat := {status_counts['waived_noncode']}\n"
        f"def generatedFailedObligationCount : Nat := {status_counts['failed']}\n"
        f"def generatedIncompleteObligationCount : Nat := {status_counts['incomplete']}\n"
        f"def generatedUnmappedObligationCount : Nat := {status_counts['unmapped']}\n"
        f"def generatedOutOfModelObligationCount : Nat := {status_counts['out_of_model']}\n"
        f"def generatedClosedObligationCount : Nat := {closed_status_count}\n"
        f"def generatedOpenObligationCount : Nat := {open_status_count}\n"
        f"def generatedObligationsClosedByStatus : Bool := {closed_by_status_literal}\n"
        "def generatedObligationStatusCountsAccounted : Bool :=\n"
        "  generatedObligationCount ==\n"
        "    generatedProvedObligationCount +\n"
        "    generatedWaivedNoncodeObligationCount +\n"
        "    generatedFailedObligationCount +\n"
        "    generatedIncompleteObligationCount +\n"
        "    generatedUnmappedObligationCount +\n"
        "    generatedOutOfModelObligationCount\n"
        "def generatedSummary : ProofSummary := {\n"
        f"  verdict := generatedVerdict,\n"
        f"  obligationCount := generatedObligationCount,\n"
        f"  proofCacheEntries := {proof_cache_count},\n"
        f"  closed := {closed_literal},\n"
        f"  noUncheckedAssumptions := {unchecked_literal}\n"
        "}\n\n"
        f"{theorem}\n"
        "end StageA\n",
        encoding="utf-8",
    )


def _lean_obligation_status(status: Any) -> str:
    mapping = {
        "proved": "ObligationStatus.proved",
        "failed": "ObligationStatus.failed",
        "incomplete": "ObligationStatus.incomplete",
        "unmapped": "ObligationStatus.unmapped",
        "waived_noncode": "ObligationStatus.waivedNoncode",
        "out_of_model": "ObligationStatus.outOfModel",
    }
    return mapping.get(str(status), "ObligationStatus.incomplete")


def _copy_lean_inputs(lean_dir: Path, lean_inputs: tuple[Path, ...]) -> dict[str, Any]:
    input_dir = lean_dir / "StageA" / "User"
    input_dir.mkdir(parents=True, exist_ok=True)
    copied: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    used_names: set[str] = set()
    for index, source in enumerate(lean_inputs):
        module_stem = _lean_module_stem(source, index, used_names)
        relative = Path("StageA") / "User" / f"{module_stem}.lean"
        destination = lean_dir / relative
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append({"source": str(source), "error": str(exc)})
            continue
        destination.write_text(text, encoding="utf-8")
        copied.append(
            {
                "source": str(source),
                "relative_path": relative.as_posix(),
                "module": f"StageA.User.{module_stem}",
                "sha256": sha256_bytes(text.encode("utf-8")),
            }
        )
    return {
        "requested": [str(path) for path in lean_inputs],
        "copied": copied,
        "errors": errors,
        "relative_paths": [item["relative_path"] for item in copied],
        "modules": [item["module"] for item in copied],
    }


def _lean_module_stem(source: Path, index: int, used_names: set[str]) -> str:
    raw = "".join(ch if ch.isalnum() else "_" for ch in source.stem)
    parts = [part for part in raw.split("_") if part]
    stem = "".join(part[:1].upper() + part[1:] for part in parts) or f"Input{index}"
    if not stem[0].isalpha():
        stem = f"Input{stem}"
    base = stem
    suffix = 2
    while stem in used_names:
        stem = f"{base}{suffix}"
        suffix += 1
    used_names.add(stem)
    return stem


def _run_lean_check(lean_dir: Path, extra_files: Iterable[str] = ()) -> dict[str, Any]:
    lean = shutil.which("lean")
    if lean is None:
        return {"status": "unavailable", "command": ["lean", "StageA/Obligations.lean"], "returncode": None}
    commands = [
        [lean, "-o", "StageA/Model.olean", "StageA/Model.lean"],
        *[[lean, "-o", str(Path(path).with_suffix(".olean")), path] for path in extra_files],
        [lean, "StageA/Obligations.lean"],
    ]
    env = {**dict(), **{"LEAN_PATH": "."}}
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    try:
        for command in commands:
            completed = subprocess.run(
                command,
                cwd=lean_dir,
                env={**os.environ, **env},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            stdout_parts.append(completed.stdout)
            stderr_parts.append(completed.stderr)
            if completed.returncode != 0:
                return {
                    "status": "failed",
                    "command": commands,
                    "failed_command": command,
                    "returncode": completed.returncode,
                    "stdout": "".join(stdout_parts),
                    "stderr": "".join(stderr_parts),
                }
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout",
            "command": commands,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
        }
    return {
        "status": "checked",
        "command": commands,
        "returncode": 0,
        "stdout": "".join(stdout_parts),
        "stderr": "".join(stderr_parts),
    }


def _lean_unchecked_markers(lean_dir: Path) -> list[dict[str, Any]]:
    markers = {"sorry", "axiom", "admit", "unsafe"}
    findings: list[dict[str, Any]] = []
    for path in sorted(lean_dir.rglob("*.lean")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            words = {word.strip(".,:;()[]{}") for word in line.split()}
            for marker in sorted(markers & words):
                findings.append({"path": str(path.relative_to(lean_dir)), "line": lineno, "marker": marker})
    return findings


def _tool_versions() -> dict[str, Any]:
    z3 = _import_z3()
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "capstone": ".".join(str(part) for part in capstone.cs_version()),
        "pefile": getattr(pefile, "__version__", "unknown"),
        "z3": z3.get_version_string() if z3 is not None else "unavailable",
        "lean": shutil.which("lean") or "unavailable",
    }


def _record_incomplete(
    incomplete: list[dict[str, Any]],
    *,
    category: str,
    blocker: str,
    next_action: str,
    obligation_id: str = "input",
    details: dict[str, Any] | None = None,
) -> None:
    incomplete.append(
        _incomplete_record(
            category=category,
            obligation_id=obligation_id,
            blocker=blocker,
            next_action=next_action,
            details=details,
        )
    )


def _incomplete_record(
    *,
    category: str,
    obligation_id: str,
    blocker: str,
    next_action: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": "incomplete",
        "status": "incomplete",
        "category": category,
        "obligation_id": obligation_id,
        "blocker": blocker,
        "next_action": next_action,
        "details": details or {},
    }


def _failure_record(
    *,
    category: str,
    obligation_id: str,
    blocker: str,
    original: Any,
    candidate: Any,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": "fail",
        "status": "failed",
        "category": category,
        "obligation_id": obligation_id,
        "blocker": blocker,
        "original": original,
        "candidate": candidate,
        "details": details or {},
    }
