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
from .util import sha256_bytes, sha256_file, utc_now, write_json


STAGE_A_MODEL_ID = "x86-pe32-env-v1"
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


class StageAInputError(ValueError):
    pass


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
            next_action="provide valid x86 PE32 original and candidate binaries",
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

    if model != STAGE_A_MODEL_ID:
        _record_incomplete(
            incomplete,
            category="unsupported_model",
            blocker=f"unsupported Stage A model {model!r}",
            next_action=f"rerun with --model {STAGE_A_MODEL_ID} or add a model implementation",
        )

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

    obligations.extend(_waiver_obligations(waivers))
    obligations.extend(_coverage_obligations("original", original_bin, mappings, waivers, incomplete))
    obligations.extend(_coverage_obligations("candidate", candidate_bin, mappings, waivers, incomplete))

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
) -> dict[str, Any]:
    original_bin = _parse_stage_a_pe(original)
    candidate_bin = _parse_stage_a_pe(candidate)
    original_functions = _parse_linker_map_functions(linker_map_original, original_bin)
    candidate_functions = _parse_linker_map_functions(linker_map_candidate, candidate_bin)
    issues = _jq_map_layout_issues(original_bin, candidate_bin)
    issues.extend(_linker_function_issues("original", original_functions))
    issues.extend(_linker_function_issues("candidate", candidate_functions))

    original_by_name = _unique_functions_by_name(original_functions)
    candidate_by_name = _unique_functions_by_name(candidate_functions)
    blocks: list[dict[str, Any]] = []
    unmatched_original: list[str] = []
    unmatched_candidate = set(candidate_by_name)

    for name in sorted(original_by_name):
        original_fn = original_by_name[name]
        candidate_fn = candidate_by_name.get(name)
        if candidate_fn is None:
            unmatched_original.append(name)
            continue
        unmatched_candidate.discard(name)
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
                "root": {"kind": "linker_map_function", "checked": True, "symbol": name}
                if index == 0
                else {"kind": "recovered_cfg_block", "checked": True, "symbol": name},
                "original": {"rva": original_block["rva_start"], "size": original_block["rva_end"] - original_block["rva_start"]},
                "candidate": {"rva": candidate_block["rva_start"], "size": candidate_block["rva_end"] - candidate_block["rva_start"]},
                "source": {
                    "kind": "linker_map_capstone_block_match_v1",
                    "function": name,
                    "function_block_index": index,
                    "match": original_block["match_key"],
                },
                "proof": {
                    "rule": "reproducible_jq_same_source_optimization_pair_v1",
                    "checked": True,
                    "function": name,
                    "original_flags": original_flags,
                    "candidate_flags": candidate_flags,
                },
            }
            if original_block["bytes_sha256"] == candidate_block["bytes_sha256"]:
                entry["source"]["byte_identical"] = True
            blocks.append(entry)

    if unmatched_original:
        issues.append(
            _incomplete_record(
                category="missing_linker_map_entry",
                obligation_id="jq-map:unmatched-original-functions",
                blocker="original linker-map functions have no candidate function with the same name",
                next_action="add a stronger jq function matcher or verify the build flags preserve these functions",
                details={"functions": unmatched_original[:200], "count": len(unmatched_original)},
            )
        )
    if unmatched_candidate:
        issues.append(
            _incomplete_record(
                category="missing_linker_map_entry",
                obligation_id="jq-map:unmatched-candidate-functions",
                blocker="candidate linker-map functions have no original function with the same name",
                next_action="add a stronger jq function matcher or verify the build flags preserve these functions",
                details={"functions": sorted(unmatched_candidate)[:200], "count": len(unmatched_candidate)},
            )
        )

    gap_blocks, waivers, gap_issues = _paired_section_gap_classification(
        original_bin,
        candidate_bin,
        blocks,
        original_flags=original_flags,
        candidate_flags=candidate_flags,
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
    if machine != 0x014C or magic != 0x10B:
        machine_name = f"0x{machine:04x}"
        magic_name = f"0x{magic:04x}"
        raise StageAInputError(f"{path} is out of model: expected x86 PE32, got machine={machine_name} magic={magic_name}")

    imports = _imports(pe)
    sections = tuple(_stage_a_section(section) for section in pe.sections)
    return StageABinary(
        path=path,
        sha256=sha256_file(path),
        size=path.stat().st_size,
        machine="i386",
        bitness=32,
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
        "architecture": "x86",
        "bitness": 32,
        "abi": "x86-pe32-env-v1",
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
        and _section_compatibility_signature(original) == _section_compatibility_signature(candidate)
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
    return issues


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
                blocker="jq map generation requires both inputs to be x86 PE32 binaries",
                next_action="rebuild the jq fixtures for i686-w64-mingw32",
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
    for line in text.splitlines():
        parsed = _parse_linker_map_symbol_line(line, binary)
        if parsed is None:
            continue
        rva, name = parsed
        if _executable_section_for_rva(binary, rva) is None:
            continue
        symbol_starts.setdefault(rva, [])
        if name not in symbol_starts[rva]:
            symbol_starts[rva].append(name)

    functions: list[dict[str, Any]] = []
    ordered = sorted(symbol_starts)
    for index, rva in enumerate(ordered):
        section = _executable_section_for_rva(binary, rva)
        if section is None:
            continue
        next_starts = [value for value in ordered[index + 1 :] if value > rva and value <= section.rva_end]
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


def _match_function_blocks(
    name: str,
    original: StageABinary,
    candidate: StageABinary,
    original_blocks: list[dict[str, Any]],
    candidate_blocks: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]]]:
    del original, candidate
    if len(original_blocks) != 1 or len(candidate_blocks) != 1:
        return [], [
            _incomplete_record(
                category="ambiguous_block_match",
                obligation_id=f"jq-map:function:{_artifact_name(name)}",
                blocker="jq function map expected exactly one recovered function block per linker-map symbol",
                next_action="extend the jq map generator to match split basic blocks for this function",
                details={"function": name, "original_blocks": len(original_blocks), "candidate_blocks": len(candidate_blocks)},
            )
        ]
    return [(original_blocks[0], candidate_blocks[0])], []


def _recover_basic_blocks(binary: StageABinary, rva_start: int, rva_end: int) -> list[dict[str, Any]]:
    data = binary.pe.get_data(rva_start, rva_end - rva_start)
    dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + rva_start))
    decoded = sum(int(insn.size) for insn in instructions)
    match_key = {
        "kind": "linker_map_function_range",
        "instruction_count": len(instructions),
        "decoded_bytes": decoded,
        "range_size": len(data),
    }
    return [
        {
            "rva_start": rva_start,
            "rva_end": rva_end,
            "bytes_sha256": sha256_bytes(data),
            "match_key": match_key,
        }
    ]


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
        if len(left_gaps) != len(right_gaps):
            issues.append(
                _incomplete_record(
                    category="ambiguous_section_gap_match",
                    obligation_id=f"jq-map:section-gap:{_artifact_name(section)}",
                    blocker="original and candidate executable section gaps do not have the same count",
                    next_action="extend the jq map generator to match section gaps by content or CFG",
                    details={"section": section, "original_gaps": len(left_gaps), "candidate_gaps": len(right_gaps)},
                )
            )
            continue
        for index, (left, right) in enumerate(zip(left_gaps, right_gaps)):
            left_bytes = original.pe.get_data(left.rva_start, left.size)
            right_bytes = candidate.pe.get_data(right.rva_start, right.size)
            left_padding = _is_padding_bytes(original, left.rva_start, left_bytes)
            right_padding = _is_padding_bytes(candidate, right.rva_start, right_bytes)
            if left_padding and right_padding:
                waivers.extend(
                    [
                        {
                            "id": f"original-padding-{left.rva_start:x}-{left.rva_end:x}",
                            "binary": "original",
                            "rva": left.rva_start,
                            "size": left.size,
                            "reason": "verified executable section gap is zero-fill or padding instructions",
                        },
                        {
                            "id": f"candidate-padding-{right.rva_start:x}-{right.rva_end:x}",
                            "binary": "candidate",
                            "rva": right.rva_start,
                            "size": right.size,
                            "reason": "verified executable section gap is zero-fill or padding instructions",
                        },
                    ]
                )
                continue
            if not left_padding and not right_padding:
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
                            "original_sha256": sha256_bytes(left_bytes),
                            "candidate_sha256": sha256_bytes(right_bytes),
                        },
                        "proof": {
                            "rule": "reproducible_jq_same_source_optimization_pair_v1",
                            "checked": True,
                            "function": name,
                            "original_flags": original_flags,
                            "candidate_flags": candidate_flags,
                        },
                    }
                )
                continue
            issues.append(
                _incomplete_record(
                    category="ambiguous_section_gap_match",
                    obligation_id=f"jq-map:section-gap:{_artifact_name(section)}:{index}",
                    blocker="one executable section gap is padding and the paired gap is code",
                    next_action="recover a stronger mapping for this section gap",
                    details={
                        "section": section,
                        "index": index,
                        "original": {"rva_start": left.rva_start, "rva_end": left.rva_end, "padding": left_padding},
                        "candidate": {"rva_start": right.rva_start, "rva_end": right.rva_end, "padding": right_padding},
                    },
                )
            )
    return gap_blocks, waivers, issues


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
    dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    instructions = list(dis.disasm(data, binary.image_base + rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return False
    return all(insn.mnemonic in {"nop", "int3"} for insn in instructions)


def _generated_layout_contract(original: StageABinary, candidate: StageABinary, map_payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": "stage-a-layout-contract-v1",
        "generator": "stage-a-generate-map",
        "require_same_image_base": original.image_base == candidate.image_base,
        "allow_different_section_spans": True,
        "required_facts": [
            "matching_architecture",
            "matching_section_permissions",
            "matching_imports",
            "all_executable_bytes_classified",
        ],
        "facts": {
            "matching_architecture": original.machine == candidate.machine and original.bitness == candidate.bitness,
            "matching_section_permissions": _section_compatibility_signature(original) == _section_compatibility_signature(candidate),
            "matching_imports": _import_signature(original) == _import_signature(candidate),
            "all_executable_bytes_classified": map_payload.get("status") == "pass",
        },
    }


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


def _waiver_obligations(waivers: Iterable[NonCodeWaiver]) -> list[dict[str, Any]]:
    return [
        {
            "id": f"waiver:{waiver.id}:{waiver.binary}:{waiver.rva_start:x}-{waiver.rva_end:x}",
            "kind": "executable_byte_class",
            "status": "waived_noncode",
            "binary": waiver.binary,
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "reason": waiver.reason,
        }
        for waiver in waivers
    ]


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
        if _checked_mapping_proof(mapped) is not None:
            continue
        original_edges = _direct_cfg_edges(original, mapped.original)
        candidate_edges = _direct_cfg_edges(candidate, mapped.candidate)
        for original_edge in original_edges:
            obligation_id = f"edge:{mapped.id}:{original_edge['kind']}:{original_edge['target_rva']:x}"
            target_id = original_targets.get(original_edge["target_rva"])
            if target_id is None:
                blocker = _incomplete_record(
                    category="unmapped_cfg_edge",
                    obligation_id=obligation_id,
                    blocker="direct original CFG edge target is not covered by a block mapping",
                    next_action="add a mapped target block or mark the bytes with an explicit waiver if they are non-code",
                    details={"source_block": mapped.id, "original_edge": original_edge},
                )
                obligations.append({"id": obligation_id, "kind": "cfg_edge", "status": "incomplete", "incomplete": blocker})
                continue
            matching_candidate_edges = [
                edge
                for edge in candidate_edges
                if edge["kind"] == original_edge["kind"] and candidate_targets.get(edge["target_rva"]) == target_id
            ]
            if not matching_candidate_edges:
                candidate_edge_reports = [
                    {**edge, "mapped_target": candidate_targets.get(edge["target_rva"])}
                    for edge in candidate_edges
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
                    "candidate_edge": matching_candidate_edges[0],
                }
            )
    return obligations


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
        if edge.get("status") != "proved":
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
            return str(value.get("kind") or value.get("source") or "checked_root")
    return None


def _direct_cfg_edges(binary: StageABinary, side: BlockSide) -> list[dict[str, Any]]:
    data = binary.pe.get_data(side.rva_start, side.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + side.rva_start))
    if not instructions or sum(insn.size for insn in instructions) != len(data):
        return []
    last = instructions[-1]
    last_rva = int(last.address - binary.image_base)
    fallthrough_rva = last_rva + int(last.size)
    mnemonic = last.mnemonic
    if _is_conditional_jump(mnemonic):
        target = _direct_branch_target(last, binary.image_base)
        if target is None:
            return []
        return [
            {"kind": "taken", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic},
            {"kind": "fallthrough", "target_rva": fallthrough_rva, "instruction_rva": last_rva, "mnemonic": mnemonic},
        ]
    if mnemonic in {"jmp", "ljmp"}:
        target = _direct_branch_target(last, binary.image_base)
        return [] if target is None else [{"kind": "jump", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic}]
    if mnemonic == "call":
        target = _direct_branch_target(last, binary.image_base)
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
            "proof_rule": "byte_identical_x86_pe32_block",
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


def _analyze_block(binary: StageABinary, side: BlockSide, data: bytes, binary_name: str, obligation_id: str) -> dict[str, Any]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
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
        if insn.mnemonic.startswith("call") or insn.mnemonic.startswith("jmp"):
            target = _direct_branch_target(insn, binary.image_base)
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
    return {"status": "ok", "instructions": insn_reports}


def _direct_branch_target(insn: Any, image_base: int) -> int | None:
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_IMM:
        return None
    return int(operand.imm - image_base)


def _external_import_call(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic != "call" or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    thunk_rva = _absolute_mem_operand_rva(binary, operand)
    if thunk_rva is None:
        return None
    for item in binary.imports:
        if item.thunk_rva == thunk_rva:
            return item
    return None


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
        "proof_rule": "byte_identical_x86_pe32_block",
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
    if rule != "reproducible_jq_same_source_optimization_pair_v1":
        return None
    return {
        "rule": rule,
        "checked": True,
        "function": str(proof.get("function") or mapped.id),
        "original_flags": str(proof.get("original_flags") or ""),
        "candidate_flags": str(proof.get("candidate_flags") or ""),
        "source_kind": str(mapped.source.get("source", {}).get("kind") if isinstance(mapped.source.get("source"), dict) else ""),
    }


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
    dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    dis.detail = True
    base = binary.image_base + side.rva_start
    registers = {name: ("reg", name) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")}
    flags = {name: ("flag", name) for name in ("cf", "zf", "sf", "of")}
    outcome: tuple[Any, ...] = ("fallthrough", side.rva_end)
    memory_events: list[tuple[Any, ...]] = []
    memory_writes: list[tuple[tuple[Any, ...], tuple[Any, ...]]] = []
    external_events: list[tuple[Any, ...]] = []
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
            target = _direct_branch_target(insn, binary.image_base)
            if target is None:
                return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "direct jump target is not resolved")
            outcome = ("jump", target)
            terminated = True
            continue
        if _is_conditional_jump(mnemonic):
            target = _direct_branch_target(insn, binary.image_base)
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
                    return _symbolic_incomplete(
                        binary_name,
                        "unmodeled_external_interaction",
                        rva,
                        mnemonic,
                        insn.op_str,
                        "external call arguments are not declared in the block mapping",
                    )
                args = _external_call_args(insn, contract, registers, memory_events, memory_writes)
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
            target = _direct_branch_target(insn, binary.image_base)
            if target is None:
                return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "indirect call target is not resolved")
            outcome = ("call", target, rva + int(insn.size))
            terminated = True
            continue
        if mnemonic == "ret":
            if len(operands) > 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported ret operand shape")
            stack_adjust = 4
            if len(operands) == 1:
                if operands[0].type != X86_OP_IMM:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported ret operand")
                stack_adjust += int(operands[0].imm) & 0xFFFFFFFF
            outcome = ("return", _memory_read_expr(registers["esp"], memory_events, memory_writes))
            registers["esp"] = _expr_add(registers["esp"], ("const", stack_adjust))
            terminated = True
            continue
        if mnemonic == "mov":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov operand shape")
            if operands[0].type == X86_OP_REG:
                dst = insn.reg_name(operands[0].reg)
                if dst not in registers:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit general registers are modeled")
                src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes)
                if src is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov source operand")
                registers[dst] = src
                continue
            if operands[0].type == X86_OP_MEM:
                if getattr(operands[0], "size", 4) != 4:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit memory writes are modeled")
                address = _mem_address_expr(insn, operands[0], registers)
                value = _operand_expr(insn, operands[1], registers)
                if address is None or value is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov memory write operand")
                address = _canonical_expr(address)
                memory_events.append(("write", ("mem32", address), value))
                memory_writes.append((address, value))
                continue
            return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov destination operand")
        if mnemonic == "push":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported push operand shape")
            value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes)
            if value is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported push operand")
            new_esp = _expr_sub(registers["esp"], ("const", 4))
            memory_events.append(("write", ("mem32", new_esp), value))
            memory_writes.append((_canonical_expr(new_esp), value))
            registers["esp"] = new_esp
            continue
        if mnemonic == "pop":
            if len(operands) != 1 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register-destination pop is modeled")
            dst = insn.reg_name(operands[0].reg)
            if dst not in registers:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit general registers are modeled")
            value = _memory_read_expr(registers["esp"], memory_events, memory_writes)
            registers[dst] = value
            registers["esp"] = _expr_add(registers["esp"], ("const", 4))
            continue
        if mnemonic in {"add", "sub"}:
            if len(operands) != 2 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register-destination arithmetic is modeled")
            dst = insn.reg_name(operands[0].reg)
            if dst not in registers:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit general registers are modeled")
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes)
            if src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported arithmetic source operand")
            left = registers[dst]
            result = _expr_add(left, src) if mnemonic == "add" else _expr_sub(left, src)
            flags.update(_arithmetic_flags(mnemonic, left, src, result))
            registers[dst] = result
            continue
        if mnemonic == "cmp":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmp operand shape")
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes)
            if left is None or right is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmp operand")
            flags.update(_arithmetic_flags("sub", left, right, _expr_sub(left, right)))
            continue
        if mnemonic in {"xor", "and", "or"}:
            if len(operands) != 2 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register-destination logical operations are modeled")
            dst = insn.reg_name(operands[0].reg)
            if dst not in registers:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit general registers are modeled")
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes)
            if src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported logical source operand")
            left = registers[dst]
            result = _logical_result(mnemonic, left, src)
            flags.update(_logical_flags(result))
            registers[dst] = result
            continue
        if mnemonic == "test":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported test operand shape")
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes)
            if left is None or right is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported test operand")
            flags.update(_logical_flags(_expr_and(left, right)))
            continue
        if mnemonic == "lea":
            if len(operands) != 2 or operands[0].type != X86_OP_REG or operands[1].type != X86_OP_MEM:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported lea operand shape")
            dst = insn.reg_name(operands[0].reg)
            if dst not in registers:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit general registers are modeled")
            src = _mem_address_expr(insn, operands[1], registers)
            if src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported lea address expression")
            registers[dst] = src
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
        "jns": _bool_not(sf),
        "js": sf,
    }
    return conditions.get(mnemonic)


def _arithmetic_flags(operator: str, left: tuple[Any, ...], right: tuple[Any, ...], result: tuple[Any, ...]) -> dict[str, tuple[Any, ...]]:
    if operator == "add":
        cf = ("ult", result, left)
        of = ("add_overflow", left, right, result)
    else:
        cf = ("ult", left, right)
        of = ("sub_overflow", left, right, result)
    return {
        "cf": cf,
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb", result),
        "of": of,
    }


def _logical_flags(result: tuple[Any, ...]) -> dict[str, tuple[Any, ...]]:
    return {
        "cf": ("false",),
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb", result),
        "of": ("false",),
    }


def _logical_result(operator: str, left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    if operator == "xor":
        return _expr_xor(left, right)
    if operator == "and":
        return _expr_and(left, right)
    if operator == "or":
        return _expr_or(left, right)
    raise StageAInputError(f"unsupported logical operator {operator!r}")


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
        "mem32",
        "env_response",
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
        "add_overflow",
        "sub_overflow",
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
    if op == "add_overflow":
        left = _expr_to_z3(expr[1], context)
        right = _expr_to_z3(expr[2], context)
        result = _expr_to_z3(expr[3], context)
        return z3.And(
            z3.Extract(31, 31, left) == z3.Extract(31, 31, right),
            z3.Extract(31, 31, left) != z3.Extract(31, 31, result),
        )
    if op == "sub_overflow":
        left = _expr_to_z3(expr[1], context)
        right = _expr_to_z3(expr[2], context)
        result = _expr_to_z3(expr[3], context)
        return z3.And(
            z3.Extract(31, 31, left) != z3.Extract(31, 31, right),
            z3.Extract(31, 31, left) != z3.Extract(31, 31, result),
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
    if op == "mem32":
        return context["memory"](_expr_to_z3(expr[1], context))
    raise StageAInputError(f"unsupported SMT expression operator {op!r}")


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


def _operand_expr(insn: Any, operand: Any, registers: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    if operand.type == X86_OP_IMM:
        return ("const", int(operand.imm) & 0xFFFFFFFF)
    if operand.type == X86_OP_REG:
        name = insn.reg_name(operand.reg)
        return registers.get(name)
    return None


def _read_operand_expr(
    insn: Any,
    operand: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], tuple[Any, ...]]],
) -> tuple[Any, ...] | None:
    value = _operand_expr(insn, operand, registers)
    if value is not None:
        return value
    if operand.type != X86_OP_MEM:
        return None
    if getattr(operand, "size", 4) != 4:
        return None
    address = _mem_address_expr(insn, operand, registers)
    if address is None:
        return None
    return _memory_read_expr(address, memory_events, memory_writes)


def _memory_read_expr(
    address: tuple[Any, ...],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], tuple[Any, ...]]],
) -> tuple[Any, ...]:
    canonical_address = _canonical_expr(address)
    memory_events.append(("read", ("mem32", canonical_address)))
    for written_address, written_value in reversed(memory_writes):
        if _canonical_expr(written_address) == canonical_address:
            return written_value
    return ("mem32", canonical_address)


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
    memory_writes: list[tuple[tuple[Any, ...], tuple[Any, ...]]],
) -> list[tuple[Any, ...]] | None:
    args = contract.get("args", [])
    if not isinstance(args, list):
        return None
    result: list[tuple[Any, ...]] = []
    for arg in args:
        expr = _external_arg_expr(insn, arg, registers, memory_events, memory_writes)
        if expr is None:
            return None
        result.append(expr)
    return result


def _external_arg_expr(
    insn: Any,
    spec: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], tuple[Any, ...]]],
) -> tuple[Any, ...] | None:
    if isinstance(spec, int):
        return ("const", spec)
    if isinstance(spec, str):
        return registers.get(spec.lower())
    if not isinstance(spec, dict):
        return None
    if "const" in spec:
        return ("const", _parse_int(spec["const"]))
    register_name = spec.get("reg") or spec.get("register")
    if register_name is None and spec.get("kind") == "reg":
        register_name = spec.get("name")
    if register_name is not None:
        return registers.get(str(register_name).lower())
    stack_offset = spec.get("stack") if "stack" in spec else spec.get("stack_offset")
    if stack_offset is None and spec.get("kind") == "stack":
        stack_offset = spec.get("offset", 0)
    if stack_offset is not None:
        address = _expr_add(registers["esp"], ("const", _parse_int(stack_offset)))
        return _memory_read_expr(address, memory_events, memory_writes)
    if spec.get("kind") == "memory":
        base_name = str(spec.get("base", "esp")).lower()
        base = registers.get(base_name)
        if base is None:
            return None
        address = _expr_add(base, ("const", _parse_int(spec.get("offset", 0))))
        return _memory_read_expr(address, memory_events, memory_writes)
    return None


def _parse_external_stack_adjust(contract: dict[str, Any]) -> int:
    value = contract.get("stack_adjust", contract.get("stack_bytes_cleaned", 0))
    return _parse_int(value) if value is not None else 0


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
    if op in {"reg", "flag", "true", "false", "env_response"}:
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
    if op in {"eq", "ult", "msb", "add_overflow", "sub_overflow"}:
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


def _artifact_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value).strip("-") or "artifact"


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
    model_description = {
        "id": STAGE_A_MODEL_ID,
        "architecture": "x86",
        "bitness": 32,
        "environment": "uninterpreted-external-env",
        "proof_rules": [
            "byte_identical_x86_pe32_block",
            "smt_z3_local_equivalence_v1",
            "direct_cfg_edge_mapping_v1",
            "entry_root_reachability_v1",
            "checked_root_reachability_v1",
            "direct_cfg_reachability_v1",
            "reproducible_jq_same_source_optimization_pair_v1",
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
    lean_statuses = ", ".join(_lean_obligation_status(item.get("status")) for item in obligations)
    if lean_statuses:
        lean_status_list = f"[{lean_statuses}]"
    else:
        lean_status_list = "[]"
    if verdict == "pass":
        theorem = (
            "theorem generatedClosedChecked : generatedSummary.closed = true := by native_decide\n"
            "theorem generatedNoUncheckedAssumptionsChecked : generatedSummary.noUncheckedAssumptions = true := by native_decide\n"
            "theorem generatedObligationStatusesClosed : generatedObligationsClosedByStatus = true := by native_decide\n"
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
        f"def generatedObligationStatuses : List ObligationStatus := {lean_status_list}\n"
        "def generatedObligationsClosedByStatus : Bool := generatedObligationStatuses.all obligationStatusClosed\n"
        "def generatedSummary : ProofSummary := {\n"
        f"  verdict := generatedVerdict,\n"
        f"  obligationCount := {obligation_count},\n"
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
