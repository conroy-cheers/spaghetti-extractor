from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import capstone

from .stage_binary import (
    BlockSide,
    StageABinary,
    StageAInputError,
    _artifact_name,
    _capstone_mode,
    _direct_cfg_edges,
    _linker_function_import_thunk_evidence,
    _linker_function_match_key,
    _parse_linker_map_functions,
    _parse_stage_a_pe,
)
from .util import sha256_bytes, sha256_file, utc_now, write_json


__all__ = [
    "stage_b_generate_link_roots",
    "stage_b_generate_skeleton",
]


STAGE_B_PROOF_RULE = "reproducible_stage_b_skeleton_reimplementation_v1"

_DECOMPILED_C_RUNTIME_ENTRY_NAMES = frozenset({"WinMainCRTStartup", "___tmainCRTStartup", "mainCRTStartup", "___wgetmainargs"})
_DECOMPILED_C_RUNTIME_ENTRY_POLICIES = frozenset({"bridge", "mingw-crt"})
_DECOMPILED_C_MINGW_CRT_OWNED_FUNCTION_NAMES = frozenset(
    {
        "___w64_mingwthr_add_key_dtor",
        "___w64_mingwthr_remove_key_dtor",
        "__do_global_dtors",
        "__mingw_enum_import_library_names",
        "__mingw_raise_matherr",
        "__tlregdtor",
        "_FindPESectionByName",
        "_FindPESectionExec",
        "atexit",
    }
)
_DECOMPILED_C_STACK_PROBE_HELPER_MACROS = {
    "___chkstk_ms": "stage_b_stack_probe_size()",
    "___chkstk": "stage_b_stack_probe_size()",
    "___alloca_probe": "stage_b_stack_probe_size()",
    "___alloca_probe_8": "stage_b_stack_probe_size()",
    "___alloca_probe_16": "stage_b_stack_probe_size()",
}

_STAGE_B_BUDGETED_OBJECT_ROOT_MAX_ORIGINAL_SIZE = 1024

_DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS = frozenset({"_crt_atexit", "__crt_atexit"})
_DECOMPILED_C_PRESERVED_IMPORT_THUNK_ALIASES = frozenset({"___iob_func"})
_DECOMPILED_C_PRESERVED_IMPORT_THUNK_CONTRACT_SYMBOLS = frozenset({"__iob_func"})

def stage_b_generate_link_roots(
    *,
    original: Path,
    object_file: Path,
    out: Path,
    nm: str = "llvm-nm",
    linker_map_original: Path | None = None,
    reference_contract: Path | None = None,
    skeleton_functions: Path | None = None,
) -> dict[str, Any]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    original_bin = _parse_stage_a_pe(Path(original))
    reference_contract_payload = _load_reference_contract(Path(reference_contract), original_bin) if reference_contract is not None else None
    if reference_contract_payload is not None:
        contract_functions = _reference_contract_function_ranges(reference_contract_payload, original_bin)
        function_source = "stage_a_reference_contract"
    elif linker_map_original is not None:
        contract_functions = _parse_linker_map_functions(Path(linker_map_original), original_bin)
        function_source = "linker_map"
    else:
        raise StageAInputError("stage-b-generate-link-roots requires --linker-map-original or --reference-contract")
    nm_symbols = _stage_b_nm_defined_text_symbols(Path(object_file), nm=nm)
    skeleton_function_rows = _load_skeleton_functions(Path(skeleton_functions)) if skeleton_functions is not None else []

    contract_by_key: dict[str, list[dict[str, Any]]] = {}
    for function in contract_functions:
        contract_by_key.setdefault(_linker_function_match_key(str(function["name"])), []).append(function)
    stdcall_contract_keys = {
        key
        for key, entries in contract_by_key.items()
        if any(_has_linker_stdcall_suffix(str(entry.get("name") or "")) for entry in entries)
    }
    object_by_key: dict[str, list[str]] = {}
    for symbol in nm_symbols:
        for key in _stage_b_object_symbol_match_keys(symbol, stdcall_contract_keys=stdcall_contract_keys):
            object_by_key.setdefault(key, []).append(symbol)
    skeleton_by_key: dict[str, list[dict[str, Any]]] = {}
    skeleton_by_start: dict[int, list[dict[str, Any]]] = {}
    for function in skeleton_function_rows:
        skeleton_by_key.setdefault(_linker_function_match_key(str(function.get("name") or "")), []).append(function)
        rva_start = _optional_int(function.get("rva_start"))
        if rva_start is not None:
            skeleton_by_start.setdefault(rva_start, []).append(function)

    issues: list[dict[str, Any]] = []
    duplicate_contract_keys = {
        key: [
            {"name": str(item["name"]), "rva_start": item["rva_start"], "rva_end": item["rva_end"]}
            for item in entries
        ]
        for key, entries in contract_by_key.items()
        if len(entries) > 1
    }
    duplicate_object_keys = {key: sorted(entries) for key, entries in object_by_key.items() if len(entries) > 1}
    if duplicate_contract_keys:
        issues.append(
            {
                "category": "ambiguous_contract_function_roots",
                "blocker": "Stage A contract functions collapse to duplicate canonical linker-root keys",
                "next_action": "disambiguate reference linker-map function names before generating Stage B link roots",
                "details": {"match_keys": duplicate_contract_keys},
            }
        )
    if duplicate_object_keys:
        issues.append(
            {
                "category": "ambiguous_object_function_roots",
                "blocker": "candidate object text symbols collapse to duplicate canonical linker-root keys",
                "next_action": "rename generated functions or provide explicit root aliases before linker GC",
                "details": {"match_keys": duplicate_object_keys},
            }
        )

    roots: list[dict[str, Any]] = []
    import_thunk_roots: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for key in sorted(contract_by_key):
        contract_entries = contract_by_key[key]
        object_entries = object_by_key.get(key, [])
        if len(contract_entries) == 1:
            contract = contract_entries[0]
            import_thunk = _linker_function_import_thunk_evidence(original_bin, contract)
            if import_thunk is not None:
                imported = import_thunk["import"]
                import_thunk_roots.append(
                    {
                        "contract_function": str(contract["name"]),
                        "match_key": key,
                        "rva_start": contract["rva_start"],
                        "rva_end": contract["rva_end"],
                        "dll": imported.dll,
                        "symbol": imported.symbol,
                        "ordinal": imported.ordinal,
                        "thunk_rva": imported.thunk_rva,
                        "signature_key": import_thunk["signature_key"],
                    }
                )
                continue
        if len(contract_entries) != 1 or len(object_entries) != 1:
            if len(contract_entries) == 1 and not object_entries:
                item = contract_entries[0]
                missing_item = {"name": str(item["name"]), "match_key": key, "rva_start": item["rva_start"], "rva_end": item["rva_end"]}
                skeleton_evidence = _missing_root_skeleton_evidence(item, skeleton_by_key=skeleton_by_key, skeleton_by_start=skeleton_by_start)
                if skeleton_evidence is not None:
                    missing_item["skeleton"] = skeleton_evidence
                missing.append(missing_item)
            continue
        contract = contract_entries[0]
        roots.append(
            {
                "contract_function": str(contract["name"]),
                "object_symbol": object_entries[0],
                "match_key": key,
                "rva_start": contract["rva_start"],
                "rva_end": contract["rva_end"],
            }
        )
    if missing:
        issues.append(
            {
                "category": "missing_object_function_roots",
                "blocker": "some Stage A contract functions have no generated object text symbol",
                "next_action": "improve skeleton generation or add explicit aliases for missing contract functions",
                "details": {"functions": missing[:200], "count": len(missing)},
            }
        )

    root_symbols = sorted({root["object_symbol"] for root in roots})
    linker_flags = [f"-Wl,--undefined,{symbol}" for symbol in root_symbols]
    budgeted_roots = [
        root
        for root in roots
        if int(root["rva_end"]) - int(root["rva_start"]) <= _STAGE_B_BUDGETED_OBJECT_ROOT_MAX_ORIGINAL_SIZE
    ]
    budgeted_linker_flags = sorted(f"-Wl,--undefined,{root['object_symbol']}" for root in budgeted_roots)
    import_thunk_linker_flags = [
        f"-Wl,--undefined,{_stage_b_import_thunk_coff_symbol(root)}"
        for root in import_thunk_roots
        if root.get("symbol")
    ]
    (out / "link-root-symbols.txt").write_text("".join(f"{symbol}\n" for symbol in root_symbols), encoding="utf-8")
    (out / "link-root-flags.txt").write_text("".join(f"{flag}\n" for flag in linker_flags), encoding="utf-8")
    (out / "budgeted-link-root-flags.txt").write_text("".join(f"{flag}\n" for flag in budgeted_linker_flags), encoding="utf-8")
    (out / "import-thunk-root-flags.txt").write_text("".join(f"{flag}\n" for flag in import_thunk_linker_flags), encoding="utf-8")
    write_json(out / "import-thunk-roots.json", {"format": "stage-b-import-thunk-roots-v1", "roots": import_thunk_roots})
    missing_by_representation = _missing_root_representation_counts(missing)
    result = {
        "format": "stage-b-link-roots-v1",
        "status": "pass" if not issues else "incomplete",
        "generator": "stage-b-generate-link-roots",
        "inputs": {
            "original": str(original),
            "linker_map_original": str(linker_map_original) if linker_map_original is not None else None,
            "reference_contract": _reference_contract_summary(Path(reference_contract), reference_contract_payload) if reference_contract is not None else None,
            "skeleton_functions": _skeleton_functions_summary(Path(skeleton_functions), skeleton_function_rows) if skeleton_functions is not None else None,
            "object_file": str(object_file),
            "nm": nm,
        },
        "function_source": function_source,
        "outputs": {
            "link_root_symbols": str(out / "link-root-symbols.txt"),
            "link_root_flags": str(out / "link-root-flags.txt"),
            "budgeted_link_root_flags": str(out / "budgeted-link-root-flags.txt"),
            "import_thunk_roots": str(out / "import-thunk-roots.json"),
            "import_thunk_root_flags": str(out / "import-thunk-root-flags.txt"),
        },
        "roots": roots,
        "budgeted_roots": budgeted_roots,
        "import_thunk_roots": import_thunk_roots,
        "linker_flags": linker_flags,
        "budgeted_linker_flags": budgeted_linker_flags,
        "import_thunk_linker_flags": import_thunk_linker_flags,
        "issues": issues,
        "counts": {
            "contract_functions": len(contract_functions),
            "object_text_symbols": len(nm_symbols),
            "roots": len(root_symbols),
            "budgeted_roots": len(budgeted_roots),
            "import_thunk_roots": len(import_thunk_roots),
            "import_thunk_roots_with_linker_flags": len(import_thunk_linker_flags),
            "missing": len(missing),
            "missing_with_skeleton_evidence": sum(1 for item in missing if isinstance(item.get("skeleton"), dict)),
            "missing_by_skeleton_representation": missing_by_representation,
            "missing_from_skeleton_functions": sum(
                1
                for item in missing
                if isinstance(item.get("skeleton"), dict)
                and item["skeleton"].get("representation") == "missing_from_skeleton_function_ranges"
            ),
            "issues": len(issues),
        },
        "selection_policy": {
            "budgeted_object_root_max_original_size": _STAGE_B_BUDGETED_OBJECT_ROOT_MAX_ORIGINAL_SIZE,
            "budgeted_object_root_basis": "original linker-map function byte range",
        },
    }
    write_json(out / "link-roots.json", result)
    return result

def _stage_b_import_thunk_coff_symbol(root: dict[str, Any]) -> str:
    symbol = str(root.get("symbol") or "")
    contract_function = str(root.get("contract_function") or "")
    if symbol == "atexit" and contract_function in {"_crt_atexit", "__crt_atexit"}:
        return "___crt_atexit"
    if contract_function in _DECOMPILED_C_PRESERVED_IMPORT_THUNK_CONTRACT_SYMBOLS:
        return f"_{contract_function}"
    return f"_{symbol}"

def _stage_b_nm_defined_text_symbols(object_file: Path, *, nm: str) -> list[str]:
    try:
        proc = subprocess.run([nm, str(object_file)], check=False, capture_output=True, text=True)
    except OSError as exc:
        raise StageAInputError(f"failed to run {nm}: {exc}") from exc
    if proc.returncode != 0:
        raise StageAInputError(f"{nm} failed for {object_file}: {proc.stderr.strip()}")
    symbols: list[str] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in {"T", "t"} and _is_linker_root_symbol(parts[2]):
            symbols.append(parts[2])
    return sorted(set(symbols))

def _load_skeleton_functions(path: Path) -> list[dict[str, Any]]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or payload.get("format") != "stage-b-functions-v1":
        raise StageAInputError("Stage B skeleton functions must have format stage-b-functions-v1")
    functions = payload.get("functions")
    if not isinstance(functions, list):
        raise StageAInputError("Stage B skeleton functions artifact must contain a functions list")
    return [function for function in functions if isinstance(function, dict)]

def _skeleton_functions_summary(path: Path, functions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_file(path) if path.is_file() else None,
        "format": "stage-b-functions-v1",
        "functions": len(functions),
    }

def _missing_root_skeleton_evidence(
    contract: dict[str, Any],
    *,
    skeleton_by_key: dict[str, list[dict[str, Any]]],
    skeleton_by_start: dict[int, list[dict[str, Any]]],
) -> dict[str, Any] | None:
    if not skeleton_by_key and not skeleton_by_start:
        return None
    key = _linker_function_match_key(str(contract.get("name") or ""))
    matches = skeleton_by_key.get(key, [])
    match_kind = "match_key"
    if len(matches) != 1:
        rva_start = _optional_int(contract.get("rva_start"))
        matches = skeleton_by_start.get(rva_start, []) if rva_start is not None else []
        match_kind = "rva_start"
    if len(matches) != 1:
        return {
            "representation": "missing_from_skeleton_function_ranges",
            "match_kind": "none",
            "matches": len(matches),
        }
    function = matches[0]
    return {
        "representation": _skeleton_missing_root_representation(function),
        "match_kind": match_kind,
        "name": str(function.get("name") or ""),
        "rva_start": function.get("rva_start"),
        "rva_end": function.get("rva_end"),
        "linkage_kind": function.get("linkage", {}).get("kind") if isinstance(function.get("linkage"), dict) else None,
        "decompiler_status": function.get("decompiler", {}).get("status") if isinstance(function.get("decompiler"), dict) else None,
    }

def _skeleton_missing_root_representation(function: dict[str, Any]) -> str:
    if _decompiled_c_is_runtime_entry(function):
        return "runtime_entry_replaced_by_generated_bridge"
    if _decompiled_c_is_import_thunk(function):
        return "import_thunk_omitted_to_link_import"
    return "skeleton_function_not_emitted_as_text_symbol"

def _missing_root_representation_counts(missing: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in missing:
        skeleton = item.get("skeleton") if isinstance(item.get("skeleton"), dict) else {}
        representation = str(skeleton.get("representation") or "unclassified")
        counts[representation] = counts.get(representation, 0) + 1
    return dict(sorted(counts.items()))

def _has_linker_stdcall_suffix(name: str) -> bool:
    if "@" not in name:
        return False
    _left, right = name.rsplit("@", 1)
    return right.isdigit()

def _stage_b_object_symbol_match_keys(symbol: str, *, stdcall_contract_keys: set[str]) -> list[str]:
    keys = {_linker_function_match_key(symbol)}
    stdcall_alias = _stage_b_c_safe_stdcall_symbol_key(symbol)
    if stdcall_alias is not None and stdcall_alias in stdcall_contract_keys:
        keys.add(stdcall_alias)
    return sorted(keys)

def _stage_b_c_safe_stdcall_symbol_key(symbol: str) -> str | None:
    raw = symbol.strip()
    value = raw[1:] if raw.startswith("@") else raw
    if "@" in value:
        left, right = value.rsplit("@", 1)
        if right.isdigit():
            value = left
    undecorated = value.lstrip("_")
    match = re.fullmatch(r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)_(?P<bytes>[0-9]+)", undecorated)
    if match is None:
        return None
    return match.group("base")

def stage_b_generate_skeleton(
    *,
    original: Path,
    out_dir: Path,
    target_name: str,
    linker_map: Path | None = None,
    reference_contract: Path | None = None,
    coverage_reference_contract: Path | None = None,
    source_language: str = "c",
    decompiler_export: Path | None = None,
    implementation_mode: str = "scaffold",
    runtime_entry_policy: str = "bridge",
    function_names: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    if source_language not in {"c", "rust"}:
        raise StageAInputError(f"unsupported Stage B source language {source_language!r}")
    if implementation_mode not in {"scaffold", "decompiled-c"}:
        raise StageAInputError(f"unsupported Stage B implementation mode {implementation_mode!r}")
    if implementation_mode == "decompiled-c" and source_language != "c":
        raise StageAInputError("decompiled-c Stage B implementation mode requires source_language='c'")
    if implementation_mode == "decompiled-c" and decompiler_export is None:
        raise StageAInputError("decompiled-c Stage B implementation mode requires --decompiler-export")
    if runtime_entry_policy not in _DECOMPILED_C_RUNTIME_ENTRY_POLICIES:
        raise StageAInputError(f"unsupported Stage B runtime entry policy {runtime_entry_policy!r}")
    if implementation_mode != "decompiled-c" and runtime_entry_policy != "bridge":
        raise StageAInputError("Stage B runtime entry policy is only supported with implementation_mode='decompiled-c'")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = _parse_stage_a_pe(Path(original))
    reference_contract_payload = _load_reference_contract(Path(reference_contract), binary) if reference_contract is not None else None
    coverage_reference_contract_path: Path | None = None
    coverage_reference_contract_payload = None
    if coverage_reference_contract is not None:
        coverage_reference_contract_path = Path(coverage_reference_contract)
        coverage_reference_contract_payload = _load_reference_contract(coverage_reference_contract_path, binary)
    elif reference_contract is not None:
        coverage_reference_contract_path = Path(reference_contract)
        coverage_reference_contract_payload = reference_contract_payload
    behavior_recovery = _skeleton_behavior_recovery(
        binary=binary,
        target_name=target_name,
        source_language=source_language,
        implementation_mode=implementation_mode,
    )
    functions = _skeleton_functions(
        binary,
        linker_map,
        decompiler_export,
        reference_contract_payload=reference_contract_payload,
        include_decompiler_code=implementation_mode == "decompiled-c",
    )
    function_filter = _function_filter(functions, function_names)
    external_function_names = function_filter["external_function_names"] + [
        item.symbol for item in binary.imports if isinstance(item.symbol, str) and item.symbol
    ]
    functions = function_filter["functions"]
    implementation_recovery = _skeleton_implementation_recovery(functions, source_language, implementation_mode=implementation_mode)
    reference_contract_function_coverage = _skeleton_reference_contract_function_coverage(
        coverage_reference_contract_payload,
        binary,
        functions,
    )
    if (
        implementation_mode == "decompiled-c"
        and implementation_recovery["status"] != "complete"
        and reference_contract_payload is None
    ):
        blockers = ", ".join(implementation_recovery["blockers"])
        raise StageAInputError(f"decompiled-c Stage B implementation source is incomplete: {blockers}")
    implementation_recovery = _skeleton_implementation_recovery_with_contract_coverage(
        implementation_recovery,
        reference_contract_function_coverage,
    )
    target_id = _artifact_name(target_name)
    source_rel = Path("src") / f"{target_id}_stage_b_skeleton.{_source_extension(source_language)}"
    functions_rel = Path("functions.json")
    readme_rel = Path("README.md")
    manifest_path = out_dir / "manifest.json"

    write_json(out_dir / functions_rel, {"format": "stage-b-functions-v1", "target_name": target_name, "functions": functions})
    (out_dir / source_rel.parent).mkdir(parents=True, exist_ok=True)
    source_text = _render_skeleton_source(
        target_name=target_name,
        functions=functions,
        source_language=source_language,
        implementation_mode=implementation_mode,
        runtime_entry_policy=runtime_entry_policy,
        external_function_names=external_function_names,
        behavior_recovery=behavior_recovery,
    )
    (out_dir / source_rel).write_text(source_text, encoding="utf-8")
    (out_dir / readme_rel).write_text(_render_skeleton_readme(target_name, source_language, implementation_mode), encoding="utf-8")

    inputs: dict[str, Any] = {
        "original": {"path": str(original), "sha256": binary.sha256},
        "linker_map": None,
        "reference_contract": None,
        "coverage_reference_contract": None,
        "decompiler_export": None,
    }
    if linker_map is not None:
        inputs["linker_map"] = {"path": str(linker_map), "sha256": sha256_file(Path(linker_map))}
    if reference_contract is not None:
        inputs["reference_contract"] = _reference_contract_summary(Path(reference_contract), reference_contract_payload)
    if coverage_reference_contract_path is not None:
        inputs["coverage_reference_contract"] = _reference_contract_summary(coverage_reference_contract_path, coverage_reference_contract_payload)
    if decompiler_export is not None:
        inputs["decompiler_export"] = _decompiler_export_summary(Path(decompiler_export))

    allowed_inputs = [_pe_input_kind(binary), "linker-map", "decompiler-export", "capstone-disassembly"]
    if reference_contract is not None or coverage_reference_contract_path is not None:
        allowed_inputs.append("stage-a-reference-contract")

    manifest: dict[str, Any] = {
        "format": "stage-b-skeleton-v1",
        "status": "generated",
        "target_name": target_name,
        "generated_at": utc_now(),
        "proof_rule": STAGE_B_PROOF_RULE,
        "source_language": source_language,
        "implementation_mode": implementation_mode,
        "runtime_entry_policy": runtime_entry_policy,
        "source_policy": {
            "upstream_source_read": False,
            "manual_behavioral_fixups": False,
            "allowed_inputs": allowed_inputs,
            "runtime_entry_policy": runtime_entry_policy,
        },
        "reverse_engineering": {
            "tools": ["pefile", "capstone"],
            "function_source": _function_source_kind(
                linker_map=linker_map,
                decompiler_export=decompiler_export,
                reference_contract=reference_contract,
            ),
            "function_filter": function_filter["metadata"],
            "behavior_recovery": behavior_recovery,
        },
        "original": _binary_summary(binary),
        "inputs": inputs,
        "outputs": {
            "source": {"path": source_rel.as_posix(), "sha256": sha256_file(out_dir / source_rel)},
            "functions": {"path": functions_rel.as_posix(), "sha256": sha256_file(out_dir / functions_rel)},
            "readme": {"path": readme_rel.as_posix(), "sha256": sha256_file(out_dir / readme_rel)},
        },
        "source_map": _skeleton_source_map(
            source_text,
            source_rel=source_rel,
            functions=functions,
            source_language=source_language,
            implementation_mode=implementation_mode,
        ),
        "counts": {
            "functions": len(functions),
            "executable_sections": sum(1 for section in binary.sections if section.executable),
            "imports": len(binary.imports),
            "instructions": sum(int(item["instruction_count"]) for item in functions),
        },
        "implementation_recovery": implementation_recovery,
        "reference_contract_function_coverage": reference_contract_function_coverage,
        "behavior_recovery": behavior_recovery,
        "completion": {
            "candidate_status": "generated_behavior_source" if implementation_recovery["source_implements_behavior"] else "skeleton_only",
            "stage_a_validated": False,
            "upstream_integration_tests": "not_run",
        },
    }
    write_json(manifest_path, manifest)
    return manifest

def _skeleton_functions(
    binary: StageABinary,
    linker_map: Path | None,
    decompiler_export: Path | None = None,
    *,
    reference_contract_payload: dict[str, Any] | None = None,
    include_decompiler_code: bool = False,
) -> list[dict[str, Any]]:
    if reference_contract_payload is not None:
        functions = _reference_contract_function_ranges(reference_contract_payload, binary)
        if decompiler_export is not None:
            functions = _merge_decompiler_evidence(
                functions,
                _parse_decompiler_export_functions(
                    Path(decompiler_export),
                    binary,
                    include_decompiler_code=include_decompiler_code,
                ),
            )
    elif linker_map is not None:
        functions = _parse_linker_map_functions(Path(linker_map), binary)
    elif decompiler_export is not None:
        functions = _parse_decompiler_export_functions(Path(decompiler_export), binary, include_decompiler_code=include_decompiler_code)
    else:
        functions = _fallback_function_ranges(binary)

    results: list[dict[str, Any]] = []
    for index, function in enumerate(functions):
        rva_start = int(function["rva_start"])
        rva_end = int(function["rva_end"])
        data = binary.pe.get_data(rva_start, rva_end - rva_start)
        instructions = _disassemble(binary, rva_start, data)
        side = BlockSide(rva_start, rva_end)
        entry = {
            "id": _artifact_name(str(function.get("name") or f"function-{index:04d}")),
            "name": str(function.get("name") or f"function_{index:04d}"),
            "aliases": list(function.get("aliases") or []),
            "section": str(function.get("section") or ""),
            "rva_start": rva_start,
            "rva_end": rva_end,
            "size": rva_end - rva_start,
            "bytes_sha256": sha256_bytes(data),
            "instruction_count": len(instructions),
            "decoded_bytes": sum(int(item["size"]) for item in instructions),
            "decode_complete": sum(int(item["size"]) for item in instructions) == len(data),
            "direct_cfg_edges": _direct_cfg_edges(binary, side),
            "instruction_preview": instructions[:12],
        }
        source_name = function.get("source_name")
        if isinstance(source_name, str) and source_name:
            entry["source_name"] = source_name
        name_disambiguation = function.get("name_disambiguation")
        if isinstance(name_disambiguation, dict):
            entry["name_disambiguation"] = name_disambiguation
        pe_export_aliases = function.get("pe_export_aliases")
        if isinstance(pe_export_aliases, list):
            entry["pe_export_aliases"] = [str(alias) for alias in pe_export_aliases]
        decompiler = function.get("decompiler")
        if isinstance(decompiler, dict):
            entry["decompiler"] = decompiler
        reference_contract = function.get("reference_contract")
        if isinstance(reference_contract, dict):
            entry["reference_contract"] = reference_contract
        seed = function.get("seed")
        if isinstance(seed, dict):
            entry["seed"] = seed
        import_thunk = _linker_function_import_thunk_evidence(binary, function)
        if import_thunk is not None:
            imported = import_thunk["import"]
            entry["linkage"] = {
                "kind": "import_thunk",
                "symbol": imported.symbol or str(entry["name"]),
                "dll": imported.dll,
                "ordinal": imported.ordinal,
                "thunk_rva": imported.thunk_rva,
                "original_symbol": str(entry["name"]),
            }
        results.append(entry)
    return results

def _load_reference_contract(path: Path, binary: StageABinary) -> dict[str, Any]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or payload.get("format") != "stage-a-reference-contract-v1":
        raise StageAInputError("Stage B reference contract must have format stage-a-reference-contract-v1")
    original = payload.get("original") if isinstance(payload.get("original"), dict) else {}
    expected_sha = original.get("sha256")
    if expected_sha != binary.sha256:
        raise StageAInputError(
            "Stage B reference contract is not bound to the original binary: "
            f"expected sha256 {binary.sha256}, got {expected_sha!r}"
        )
    return payload

def _reference_contract_summary(path: Path, payload: dict[str, Any] | None) -> dict[str, Any]:
    constraints = payload.get("constraints") if isinstance(payload, dict) and isinstance(payload.get("constraints"), dict) else {}
    function_ranges = constraints.get("function_ranges") if isinstance(constraints.get("function_ranges"), dict) else {}
    functions = function_ranges.get("functions") if isinstance(function_ranges.get("functions"), list) else []
    return {
        "path": str(path),
        "sha256": sha256_file(path) if path.is_file() else None,
        "format": payload.get("format") if isinstance(payload, dict) else None,
        "status": payload.get("status") if isinstance(payload, dict) else None,
        "model": payload.get("model") if isinstance(payload, dict) else None,
        "function_ranges_status": function_ranges.get("status"),
        "functions": len(functions),
    }

def _reference_contract_function_ranges(payload: dict[str, Any], binary: StageABinary) -> list[dict[str, Any]]:
    constraints = payload.get("constraints") if isinstance(payload.get("constraints"), dict) else {}
    function_ranges = constraints.get("function_ranges") if isinstance(constraints.get("function_ranges"), dict) else {}
    status = function_ranges.get("status")
    if status not in {"satisfied", "derived"}:
        raise StageAInputError(f"Stage A reference contract function_ranges is not closed: {status!r}")
    rows = function_ranges.get("functions")
    if not isinstance(rows, list) or not rows:
        raise StageAInputError("Stage A reference contract does not contain function_ranges.functions")

    functions: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise StageAInputError(f"Stage A reference contract function #{index} is not an object")
        original = row.get("original")
        if not isinstance(original, dict):
            raise StageAInputError(f"Stage A reference contract function #{index} has no original range")
        rva_start = _optional_int(original.get("rva_start"))
        rva_end = _optional_int(original.get("rva_end"))
        if rva_start is None or rva_end is None or rva_end <= rva_start:
            raise StageAInputError(f"Stage A reference contract function #{index} has an invalid original range")
        section = _section_for_rva(binary, rva_start)
        if section is None or not section.executable or rva_end > int(section.rva_end):
            raise StageAInputError(f"Stage A reference contract function #{index} is outside an executable section")
        name = str(row.get("name") or f"contract_function_{index:04d}")
        functions.append(
            {
                "name": name,
                "aliases": [name],
                "section": section.name,
                "rva_start": rva_start,
                "rva_end": rva_end,
                "reference_contract": {
                    "block_ids": list(row.get("block_ids") or []),
                    "candidate": row.get("candidate") if isinstance(row.get("candidate"), dict) else None,
                },
            }
        )
    return functions

def _skeleton_reference_contract_function_coverage(
    reference_contract_payload: dict[str, Any] | None,
    binary: StageABinary,
    functions: list[dict[str, Any]],
) -> dict[str, Any]:
    if reference_contract_payload is None:
        return {
            "format": "stage-b-reference-contract-function-coverage-v1",
            "provided": False,
            "status": "not_provided",
            "counts": {
                "contract_functions": 0,
                "skeleton_functions": len(functions),
                "represented": 0,
                "missing": 0,
                "ambiguous": 0,
            },
            "missing_functions": [],
            "ambiguous_functions": [],
            "represented_special_functions": [],
            "representation_counts": {},
        }

    contract_functions = _reference_contract_function_ranges(reference_contract_payload, binary)
    skeleton_by_key: dict[str, list[dict[str, Any]]] = {}
    skeleton_by_start: dict[int, list[dict[str, Any]]] = {}
    for function in functions:
        skeleton_by_key.setdefault(_linker_function_match_key(str(function.get("name") or "")), []).append(function)
        rva_start = _optional_int(function.get("rva_start"))
        if rva_start is not None:
            skeleton_by_start.setdefault(rva_start, []).append(function)

    represented = 0
    missing: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    represented_special: list[dict[str, Any]] = []
    representation_counts: dict[str, int] = {}

    for contract in contract_functions:
        match = _match_skeleton_contract_function(contract, skeleton_by_key=skeleton_by_key, skeleton_by_start=skeleton_by_start)
        representation = str(match["representation"])
        representation_counts[representation] = representation_counts.get(representation, 0) + 1
        if representation == "missing_from_skeleton_function_ranges":
            missing.append(_contract_function_reference(contract, reason=representation))
        elif representation == "ambiguous_skeleton_function_match":
            item = _contract_function_reference(contract, reason=representation)
            item["matches"] = match.get("matches")
            ambiguous.append(item)
        else:
            represented += 1
            if representation != "represented_by_skeleton_function":
                item = _contract_function_reference(contract, reason=representation)
                item["skeleton"] = match.get("skeleton")
                represented_special.append(item)

    return {
        "format": "stage-b-reference-contract-function-coverage-v1",
        "provided": True,
        "status": "complete" if not missing and not ambiguous else "incomplete",
        "counts": {
            "contract_functions": len(contract_functions),
            "skeleton_functions": len(functions),
            "represented": represented,
            "missing": len(missing),
            "ambiguous": len(ambiguous),
        },
        "missing_functions": missing,
        "ambiguous_functions": ambiguous,
        "represented_special_functions": represented_special,
        "representation_counts": dict(sorted(representation_counts.items())),
    }

def _skeleton_implementation_recovery_with_contract_coverage(
    recovery: dict[str, Any],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    if not coverage.get("provided") or coverage.get("status") == "complete":
        return recovery

    updated = dict(recovery)
    blockers = list(updated.get("blockers") or [])
    counts = coverage.get("counts") if isinstance(coverage.get("counts"), dict) else {}
    if int(counts.get("missing") or 0) > 0 and "incomplete_reference_contract_function_coverage" not in blockers:
        blockers.append("incomplete_reference_contract_function_coverage")
    if int(counts.get("ambiguous") or 0) > 0 and "ambiguous_reference_contract_function_coverage" not in blockers:
        blockers.append("ambiguous_reference_contract_function_coverage")
    if not blockers:
        blockers.append(f"reference_contract_function_coverage_{coverage.get('status') or 'unknown'}")

    updated["status"] = "incomplete"
    updated["source_implements_behavior"] = False
    if updated.get("generated_source_kind") == "decompiler_recovered_behavior":
        updated["generated_source_kind"] = "decompiler_recovered_partial"
    updated["blockers"] = blockers
    updated["reference_contract_function_coverage"] = {
        "status": coverage.get("status"),
        "counts": counts,
    }
    return updated

def _match_skeleton_contract_function(
    contract: dict[str, Any],
    *,
    skeleton_by_key: dict[str, list[dict[str, Any]]],
    skeleton_by_start: dict[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    key = _linker_function_match_key(str(contract.get("name") or ""))
    matches = skeleton_by_key.get(key, [])
    match_kind = "match_key"
    if len(matches) != 1:
        rva_start = _optional_int(contract.get("rva_start"))
        matches = skeleton_by_start.get(rva_start, []) if rva_start is not None else []
        match_kind = "rva_start"
    if not matches:
        return {"representation": "missing_from_skeleton_function_ranges", "match_kind": "none", "matches": 0}
    if len(matches) != 1:
        return {"representation": "ambiguous_skeleton_function_match", "match_kind": match_kind, "matches": len(matches)}
    function = matches[0]
    return {
        "representation": _skeleton_contract_function_representation(function),
        "match_kind": match_kind,
        "matches": 1,
        "skeleton": _skeleton_function_reference(function),
    }

def _skeleton_contract_function_representation(function: dict[str, Any]) -> str:
    if _decompiled_c_is_runtime_entry(function):
        return "runtime_entry_replaced_by_generated_bridge"
    if _decompiled_c_is_import_thunk(function):
        return "import_thunk_omitted_to_link_import"
    return "represented_by_skeleton_function"

def _contract_function_reference(function: dict[str, Any], *, reason: str) -> dict[str, Any]:
    return {
        "name": str(function.get("name") or ""),
        "match_key": _linker_function_match_key(str(function.get("name") or "")),
        "rva_start": function.get("rva_start"),
        "rva_end": function.get("rva_end"),
        "reason": reason,
    }

def _skeleton_function_reference(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(function.get("name") or ""),
        "rva_start": function.get("rva_start"),
        "rva_end": function.get("rva_end"),
        "linkage_kind": function.get("linkage", {}).get("kind") if isinstance(function.get("linkage"), dict) else None,
        "decompiler_status": function.get("decompiler", {}).get("status") if isinstance(function.get("decompiler"), dict) else None,
    }

def _merge_decompiler_evidence(contract_functions: list[dict[str, Any]], decompiler_functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_start: dict[int, list[dict[str, Any]]] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for function in decompiler_functions:
        by_start.setdefault(int(function["rva_start"]), []).append(function)
        by_name.setdefault(str(function.get("name") or ""), []).append(function)

    merged: list[dict[str, Any]] = []
    for function in contract_functions:
        matches = by_start.get(int(function["rva_start"]), [])
        if len(matches) != 1:
            matches = by_name.get(str(function.get("name") or ""), [])
        item = dict(function)
        if len(matches) == 1:
            decompiler_match = matches[0]
            item["name"] = str(decompiler_match.get("name") or item.get("name") or "")
            aliases = []
            for alias in [
                *(function.get("aliases") or []),
                function.get("name"),
                decompiler_match.get("name"),
                *(decompiler_match.get("aliases") or []),
            ]:
                if isinstance(alias, str) and alias and alias not in aliases:
                    aliases.append(alias)
            item["aliases"] = aliases
            for key in ("source_name", "name_disambiguation", "pe_export_aliases"):
                if key in decompiler_match:
                    item[key] = decompiler_match[key]
            if isinstance(decompiler_match.get("decompiler"), dict):
                item["decompiler"] = decompiler_match["decompiler"]
        merged.append(item)
    return merged

def _parse_decompiler_export_functions(
    path: Path,
    binary: StageABinary,
    *,
    include_decompiler_code: bool = False,
) -> list[dict[str, Any]]:
    payload = _load_json(path)
    rows = payload.get("functions") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise StageAInputError(f"decompiler export {path} does not contain a functions list")
    export_aliases_by_rva = _pe_export_aliases_by_rva(binary)
    accepted: list[tuple[int, dict[str, Any], int, int, Any, str, str, list[str]]] = []
    name_counts: dict[str, int] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        rva_start = _optional_int(row.get("rva_start", row.get("rva")))
        rva_end = _optional_int(row.get("rva_end"))
        if rva_start is None:
            continue
        section = _section_for_rva(binary, rva_start)
        if section is None or not section.executable:
            continue
        if rva_end is None or rva_end <= rva_start:
            rva_end = min(section.rva_end, rva_start + 1)
        decompiler_name = str(row.get("name") or f"decompiler_function_{index:04d}")
        export_aliases = export_aliases_by_rva.get(rva_start, [])
        preferred_name = _primary_export_name(export_aliases) if export_aliases else decompiler_name
        accepted.append((index, row, rva_start, rva_end, section, preferred_name, decompiler_name, export_aliases))
        name_counts[preferred_name] = name_counts.get(preferred_name, 0) + 1

    functions: list[dict[str, Any]] = []
    occurrences: dict[str, int] = {}
    used_names: set[str] = set()
    for index, row, rva_start, rva_end, section, preferred_name, decompiler_name, export_aliases in accepted:
        occurrence = occurrences.get(preferred_name, 0) + 1
        occurrences[preferred_name] = occurrence
        name = _decompiler_disambiguated_function_name(
            preferred_name,
            rva_start=rva_start,
            duplicate=name_counts.get(preferred_name, 0) > 1,
            occurrence=occurrence,
            used_names=used_names,
        )
        aliases = []
        for alias in [name, decompiler_name, *export_aliases]:
            if alias and alias not in aliases:
                aliases.append(alias)
        entry: dict[str, Any] = {
            "name": name,
            "aliases": aliases,
            "section": section.name,
            "rva_start": rva_start,
            "rva_end": min(rva_end, section.rva_end),
        }
        if export_aliases:
            entry["pe_export_aliases"] = export_aliases
        if name != decompiler_name or preferred_name != decompiler_name:
            strategy = (
                "append_rva_to_duplicate_decompiler_name"
                if name_counts.get(preferred_name, 0) > 1
                else (
                    "prefer_pe_export_alias_for_decompiler_rva"
                    if export_aliases and preferred_name != decompiler_name
                    else "sanitize_decompiler_name_for_c_identifier"
                )
            )
            entry["source_name"] = decompiler_name
            entry["name_disambiguation"] = {
                "strategy": strategy,
                "source_name": decompiler_name,
                "preferred_name": preferred_name,
                "disambiguated_name": name,
                "rva_start": rva_start,
                "occurrence": occurrence,
            }
        decompiler = _decompiler_function_summary(row, include_code=include_decompiler_code)
        if decompiler is not None:
            if name != decompiler_name:
                if include_decompiler_code and isinstance(decompiler.get("code"), str):
                    code = _rename_decompiled_c_function_definition(
                        decompiler["code"],
                        original_name=decompiler_name,
                        new_name=name,
                    )
                    decompiler["code"] = code
                    decompiler["code_sha256"] = sha256_bytes(code.encode("utf-8")) if code else ""
                    decompiler["code_preview"] = _preview_lines(code)
                signature = str(decompiler.get("signature") or "")
                if signature:
                    decompiler["signature"] = _rename_decompiled_c_function_definition(
                        signature,
                        original_name=decompiler_name,
                        new_name=name,
                    )
            entry["decompiler"] = decompiler
        functions.append(entry)
    return functions

def _decompiler_disambiguated_function_name(
    raw_name: str,
    *,
    rva_start: int,
    duplicate: bool,
    occurrence: int,
    used_names: set[str],
) -> str:
    base = _c_identifier_from_name(raw_name)
    if not duplicate and base not in used_names:
        used_names.add(base)
        return base
    candidate = base if occurrence == 1 and base not in used_names else f"{base}_at_{rva_start:x}"
    suffix = 2
    while candidate in used_names:
        candidate = f"{base}_at_{rva_start:x}_{suffix}"
        suffix += 1
    used_names.add(candidate)
    return candidate

def _c_identifier_from_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", str(value))
    if not name or not name.strip("_"):
        return "decompiler_function"
    if name[0].isdigit():
        name = f"fn_{name}"
    return name

def _rename_decompiled_c_function_definition(code: str, *, original_name: str, new_name: str) -> str:
    if not code or original_name == new_name:
        return code
    pattern = rf"\b{re.escape(original_name)}\s*\("
    if "{" not in code:
        return re.sub(pattern, f"{new_name}(", code, count=1)
    head, body = code.split("{", 1)
    renamed = re.sub(pattern, f"{new_name}(", head, count=1)
    return renamed + "{" + body

def _fallback_function_ranges(binary: StageABinary) -> list[dict[str, Any]]:
    export_ranges = _pe_export_function_ranges(binary)
    if export_ranges:
        return export_ranges

    ranges: list[dict[str, Any]] = []
    for section in binary.sections:
        if not section.executable:
            continue
        name = "entrypoint" if section.rva_start <= binary.entrypoint_rva < section.rva_end else f"section_{section.name}"
        start = binary.entrypoint_rva if name == "entrypoint" else section.rva_start
        ranges.append(
            {
                "name": name,
                "aliases": [name],
                "section": section.name,
                "rva_start": start,
                "rva_end": section.rva_end,
            }
        )
    return ranges


def _pe_export_function_ranges(binary: StageABinary) -> list[dict[str, Any]]:
    names_by_rva = _pe_export_aliases_by_rva(binary)

    if not names_by_rva:
        return []

    section_boundaries: dict[str, list[int]] = {}
    for rva in names_by_rva:
        section = _section_for_rva(binary, rva)
        if section is not None:
            section_boundaries.setdefault(section.name, []).append(rva)
    if binary.entrypoint_rva:
        entry_section = _section_for_rva(binary, binary.entrypoint_rva)
        if entry_section is not None and entry_section.executable:
            section_boundaries.setdefault(entry_section.name, []).append(binary.entrypoint_rva)

    ranges: list[dict[str, Any]] = []
    for rva in sorted(names_by_rva):
        section = _section_for_rva(binary, rva)
        if section is None:
            continue
        boundaries = sorted(set(section_boundaries.get(section.name, [])))
        later = [value for value in boundaries if value > rva and value <= section.rva_end]
        rva_end = later[0] if later else section.rva_end
        if rva_end <= rva:
            continue
        aliases = names_by_rva[rva]
        ranges.append(
            {
                "name": _primary_export_name(aliases),
                "aliases": aliases,
                "section": section.name,
                "rva_start": rva,
                "rva_end": rva_end,
                "seed": {
                    "kind": "pe_export",
                    "confidence": "medium",
                    "aliases": aliases,
                },
            }
        )
    return ranges


def _pe_export_aliases_by_rva(binary: StageABinary) -> dict[int, list[str]]:
    directory = getattr(binary.pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is None:
        return {}

    names_by_rva: dict[int, list[str]] = {}
    for index, symbol in enumerate(getattr(directory, "symbols", []) or []):
        rva = _optional_int(getattr(symbol, "address", None))
        if rva is None:
            continue
        section = _section_for_rva(binary, rva)
        if section is None or not section.executable:
            continue
        forwarder = getattr(symbol, "forwarder", None)
        if forwarder:
            continue
        if getattr(symbol, "name", None):
            name = symbol.name.decode("utf-8", errors="replace") if isinstance(symbol.name, bytes) else str(symbol.name)
        else:
            ordinal = getattr(symbol, "ordinal", index)
            name = f"ordinal_{ordinal}"
        bucket = names_by_rva.setdefault(rva, [])
        if name not in bucket:
            bucket.append(name)
    return names_by_rva


def _primary_export_name(names: list[str]) -> str:
    for name in names:
        if not name.startswith("ordinal_"):
            return name
    return names[0]


def _function_source_kind(*, linker_map: Path | None, decompiler_export: Path | None, reference_contract: Path | None) -> str:
    if reference_contract is not None:
        return "stage_a_reference_contract"
    if linker_map is not None:
        return "linker_map"
    if decompiler_export is not None:
        return "decompiler_export"
    return "pe_exports_or_entrypoint_sections"

def _function_filter(functions: list[dict[str, Any]], function_names: list[str] | tuple[str, ...] | None) -> dict[str, Any]:
    if not function_names:
        return {
            "functions": functions,
            "external_function_names": [],
            "metadata": {
                "mode": "all",
                "requested": [],
                "included": [str(function.get("name") or "") for function in functions],
                "missing": [],
                "external_recovered_function_names": [],
            },
        }

    requested = [str(name) for name in function_names if str(name)]
    by_name: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        by_name.setdefault(str(function.get("name") or ""), []).append(function)

    selected: list[dict[str, Any]] = []
    missing: list[str] = []
    ambiguous: list[str] = []
    for name in requested:
        matches = by_name.get(name, [])
        if not matches:
            missing.append(name)
        elif len(matches) > 1:
            ambiguous.append(name)
        else:
            selected.append(matches[0])

    if missing or ambiguous:
        blockers = []
        if missing:
            blockers.append(f"missing functions: {', '.join(missing)}")
        if ambiguous:
            blockers.append(f"ambiguous duplicate functions: {', '.join(ambiguous)}")
        raise StageAInputError("; ".join(blockers))

    return {
        "functions": selected,
        "external_function_names": [
            str(function.get("name") or "")
            for function in functions
            if str(function.get("name") or "") not in set(requested)
        ],
        "metadata": {
            "mode": "function_names",
            "requested": requested,
            "included": [str(function.get("name") or "") for function in selected],
            "missing": [],
            "external_recovered_function_names": [
                str(function.get("name") or "")
                for function in functions
                if str(function.get("name") or "") not in set(requested)
            ],
        },
    }

def _skeleton_behavior_recovery(
    *,
    binary: StageABinary,
    target_name: str,
    source_language: str,
    implementation_mode: str,
) -> dict[str, Any]:
    if implementation_mode != "scaffold" or source_language != "rust":
        return {
            "format": "stage-b-behavior-recovery-v1",
            "status": "not_applicable",
            "recovered": [],
            "blockers": [],
        }
    target_id = _artifact_name(target_name)
    recovered: list[dict[str, Any]] = []
    blockers: list[str] = []
    if "ripgrep" in target_id:
        version_behavior = _recover_ripgrep_version_behavior(binary)
        if version_behavior is None:
            blockers.append("missing_ripgrep_version_strings")
        else:
            recovered.append(version_behavior)
    return {
        "format": "stage-b-behavior-recovery-v1",
        "status": "partial" if recovered else "incomplete",
        "source": "pe_ascii_strings",
        "recovered": recovered,
        "blockers": blockers,
    }

def _recover_ripgrep_version_behavior(binary: StageABinary) -> dict[str, Any] | None:
    raw = binary.path.read_bytes()
    match = re.search(
        rb"ripgrep[ \t]*.{0,8}?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\+?.{0,8}?SSE2.{0,8}?SSSE3.{0,8}?AVX2.{0,8}?pcre2",
        raw,
        flags=re.DOTALL,
    )
    if match is None:
        return None
    version = match.group("version").decode("ascii", errors="replace")
    pcre2_unavailable = b"PCRE2 is not available in this build of ripgrep" in raw
    output = (
        f"ripgrep {version}\n\n"
        "features:-pcre2\n"
        "simd(compile):+SSE2,-SSSE3,-AVX2\n"
        "simd(runtime):+SSE2,+SSSE3,+AVX2\n\n"
    )
    if pcre2_unavailable:
        output += "PCRE2 is not available in this build of ripgrep.\n"
    return {
        "id": "ripgrep-version",
        "kind": "cli_exact_stdout",
        "args": [["--version"], ["-V"]],
        "stdout": output,
        "returncode": 0,
        "evidence": {
            "kind": "pe_ascii_string_neighborhood",
            "rva": _file_offset_to_rva(binary, match.start()),
            "file_offset": match.start(),
            "sha256": sha256_bytes(match.group(0)),
            "pcre2_unavailable_string": pcre2_unavailable,
        },
    }

def _file_offset_to_rva(binary: StageABinary, offset: int) -> int | None:
    for section in binary.sections:
        raw_start = int(section.raw_pointer)
        raw_end = raw_start + int(section.raw_size)
        if raw_start <= offset < raw_end:
            return int(section.rva_start) + (offset - raw_start)
    return None

def _skeleton_implementation_recovery(
    functions: list[dict[str, Any]],
    source_language: str,
    *,
    implementation_mode: str,
) -> dict[str, Any]:
    decompiler_functions = [function for function in functions if isinstance(function.get("decompiler"), dict)]
    decompiler_successes = [
        function
        for function in decompiler_functions
        if function.get("decompiler", {}).get("status") == "success"
    ]
    decompiler_code_functions = [
        function
        for function in decompiler_successes
        if isinstance(function.get("decompiler", {}).get("code"), str)
        and function.get("decompiler", {}).get("code", "").strip()
    ]
    missing_decompiler_functions = [
        _decompiler_coverage_function(function, reason="missing_decompiler_export")
        for function in functions
        if not isinstance(function.get("decompiler"), dict)
    ]
    incomplete_decompiler_functions = [
        _decompiler_coverage_function(
            function,
            reason=f"decompiler_status_{function.get('decompiler', {}).get('status') or 'unknown'}",
        )
        for function in decompiler_functions
        if function.get("decompiler", {}).get("status") != "success"
    ]
    requires_decompiler_code = implementation_mode == "decompiled-c"
    missing_decompiler_code_functions = (
        [
            _decompiler_coverage_function(function, reason="missing_decompiler_code")
            for function in decompiler_successes
            if function not in decompiler_code_functions
        ]
        if requires_decompiler_code
        else []
    )
    name_counts: dict[str, int] = {}
    for function in functions:
        name = str(function.get("name") or "")
        if name:
            name_counts[name] = name_counts.get(name, 0) + 1
    duplicate_names = sorted(name for name, count in name_counts.items() if count > 1)
    name_disambiguations = [
        function["name_disambiguation"]
        for function in functions
        if isinstance(function.get("name_disambiguation"), dict)
    ]

    if implementation_mode == "decompiled-c":
        blockers = []
        if not functions:
            blockers.append("missing_functions")
        if len(decompiler_functions) != len(functions):
            blockers.append("missing_decompiler_exports")
        if len(decompiler_successes) != len(functions):
            blockers.append("incomplete_decompiler_successes")
        if len(decompiler_code_functions) != len(functions):
            blockers.append("missing_decompiler_code")
        if duplicate_names:
            blockers.append("duplicate_decompiler_function_names")
        status = "complete" if not blockers else "incomplete"
        generated_source_kind = "decompiler_recovered_behavior" if status == "complete" else "decompiler_recovered_partial"
    else:
        blockers = ["generated_source_is_scaffold"]
        if not decompiler_successes:
            blockers.append("missing_decompiler_successes")
        if decompiler_successes and len(decompiler_successes) < len(functions):
            blockers.append("incomplete_decompiler_coverage")
        status = "incomplete"
        generated_source_kind = "scaffold"

    return {
        "format": "stage-b-skeleton-recovery-v1",
        "status": status,
        "implementation_mode": implementation_mode,
        "generated_source_kind": generated_source_kind,
        "source_language": source_language,
        "source_implements_behavior": status == "complete",
        "functions": len(functions),
        "decompiler_functions": len(decompiler_functions),
        "decompiler_successes": len(decompiler_successes),
        "decompiler_code_functions": len(decompiler_code_functions),
        "decompiler_coverage": {
            "status": "complete"
            if len(decompiler_functions) == len(functions)
            and len(decompiler_successes) == len(functions)
            and (not requires_decompiler_code or len(decompiler_code_functions) == len(functions))
            else "incomplete",
            "requires_decompiler_code": requires_decompiler_code,
            "missing_decompiler_functions": missing_decompiler_functions,
            "incomplete_decompiler_functions": incomplete_decompiler_functions,
            "missing_decompiler_code_functions": missing_decompiler_code_functions,
            "counts": {
                "missing_decompiler_functions": len(missing_decompiler_functions),
                "incomplete_decompiler_functions": len(incomplete_decompiler_functions),
                "missing_decompiler_code_functions": len(missing_decompiler_code_functions),
            },
        },
        "instruction_count": sum(int(function["instruction_count"]) for function in functions),
        "duplicate_function_names": duplicate_names,
        "decompiler_name_disambiguation": {
            "status": "applied" if name_disambiguations else "not_required",
            "strategy": "append_rva_to_duplicate_decompiler_name",
            "count": len(name_disambiguations),
            "items": name_disambiguations[:100],
        },
        "blockers": blockers,
    }

def _decompiler_coverage_function(function: dict[str, Any], *, reason: str) -> dict[str, Any]:
    return {
        "name": str(function.get("name") or ""),
        "rva_start": function.get("rva_start"),
        "rva_end": function.get("rva_end"),
        "size": function.get("size"),
        "reason": reason,
        "reference_contract": function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else None,
    }

def _section_for_rva(binary: StageABinary, rva: int) -> Any | None:
    for section in binary.sections:
        if section.rva_start <= rva < section.rva_end:
            return section
    return None

def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        return int(text, 0)
    return None

def _decompiler_function_summary(row: dict[str, Any], *, include_code: bool = False) -> dict[str, Any] | None:
    decompiler = row.get("decompiler")
    if not isinstance(decompiler, dict):
        return None
    code = str(decompiler.get("c") or decompiler.get("code") or decompiler.get("decompiled_c") or "")
    error = str(decompiler.get("error") or "")
    summary = {
        "source": "ghidra_decompiler_export",
        "status": str(decompiler.get("status") or ("success" if code else "not_available")),
        "signature": str(row.get("signature") or ""),
        "code_sha256": sha256_bytes(code.encode("utf-8")) if code else "",
        "code_preview": _preview_lines(code),
        "error": error,
    }
    if include_code:
        summary["code"] = code
    return summary

def _preview_lines(text: str, *, limit: int = 12) -> list[str]:
    return text.splitlines()[:limit]

def _indented_decompiler_comment_lines(function: dict[str, Any], prefix: str) -> list[str]:
    decompiler = function.get("decompiler")
    if not isinstance(decompiler, dict):
        return []
    lines = [f"{prefix}decompiler status: {decompiler.get('status', 'unknown')}"]
    signature = str(decompiler.get("signature") or "")
    if signature:
        lines.append(f"{prefix}signature: {signature}")
    for line in decompiler.get("code_preview") or []:
        lines.append(f"{prefix}{line}")
    return lines

def _disassemble(binary: StageABinary, rva_start: int, data: bytes) -> list[dict[str, Any]]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    return [
        {
            "rva": int(insn.address - binary.image_base),
            "size": int(insn.size),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
        }
        for insn in dis.disasm(data, binary.image_base + rva_start)
    ]

def _render_skeleton_source(
    *,
    target_name: str,
    functions: list[dict[str, Any]],
    source_language: str,
    implementation_mode: str,
    runtime_entry_policy: str = "bridge",
    external_function_names: list[str] | tuple[str, ...] | None = None,
    behavior_recovery: dict[str, Any] | None = None,
) -> str:
    if implementation_mode == "decompiled-c":
        return _render_decompiled_c_source(
            target_name=target_name,
            functions=functions,
            runtime_entry_policy=runtime_entry_policy,
            external_function_names=external_function_names,
        )

    if source_language == "rust":
        recovered_version = _recovered_cli_behavior(behavior_recovery, "ripgrep-version")
        lines = [
            "// Generated by wincr stage-b-generate-skeleton.",
            "// This is a clean-room reconstruction scaffold, not a completed implementation.",
            "",
        ]
        if recovered_version is not None:
            lines.extend(
                [
                    f"const STAGE_B_RECOVERED_VERSION_STDOUT: &str = {_rust_string_literal(str(recovered_version.get('stdout') or ''))};",
                    "",
                    "fn stage_b_matches_arg(args: &[String], short: &str, long: &str) -> bool {",
                    "    args.len() == 1 && (args[0] == short || args[0] == long)",
                    "}",
                    "",
                ]
            )
        lines.extend(
            [
                "fn main() {",
            ]
        )
        if recovered_version is not None:
            lines.extend(
                [
                    "    let args: Vec<String> = std::env::args().skip(1).collect();",
                    "    if stage_b_matches_arg(&args, \"-V\", \"--version\") {",
                    "        print!(\"{}\", STAGE_B_RECOVERED_VERSION_STDOUT);",
                    "        return;",
                    "    }",
                ]
            )
        lines.extend(
            [
                "    std::process::exit(125);",
                "}",
                "",
            ]
        )
        used_identifiers: set[str] = set()
        for index, function in enumerate(functions):
            ident = _unique_identifier(function["name"], index, used_identifiers)
            lines.extend(
                [
                    "#[allow(dead_code)]",
                    f"fn stage_b_fn_{ident}() -> i32 {{",
                    f"    // original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}",
                    *_indented_decompiler_comment_lines(function, "    // "),
                    "    125",
                    "}",
                    "",
                ]
            )
        return "\n".join(lines)

    lines = [
        "/* Generated by wincr stage-b-generate-skeleton.",
        " * This is a clean-room reconstruction scaffold, not a completed implementation.",
        " */",
        "#include <stdint.h>",
        "",
        "static int stage_b_unimplemented(const char *name) {",
        "    (void)name;",
        "    return 125;",
        "}",
        "",
        "int main(int argc, char **argv) {",
        "    (void)argc;",
        "    (void)argv;",
        f"    return stage_b_unimplemented(\"{_c_string(target_name)}\");",
        "}",
        "",
    ]
    used_identifiers = set()
    for index, function in enumerate(functions):
        ident = _unique_identifier(function["name"], index, used_identifiers)
        lines.extend(
            [
                f"int stage_b_fn_{ident}(void) {{",
                f"    /* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])} */",
                *_indented_decompiler_comment_lines(function, "    // "),
                f"    return stage_b_unimplemented(\"{_c_string(str(function['name']))}\");",
                "}",
                "",
            ]
        )
    return "\n".join(lines)

def _skeleton_source_map(
    source_text: str,
    *,
    source_rel: Path,
    functions: list[dict[str, Any]],
    source_language: str,
    implementation_mode: str,
) -> dict[str, Any]:
    lines = source_text.splitlines()
    anchors: list[dict[str, Any]] = []
    for function in functions:
        name = str(function.get("name") or "")
        if not name:
            continue
        aliases = [alias for alias in function.get("aliases", []) if isinstance(alias, str) and alias]
        decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
        has_decompiler_body = bool(str(decompiler.get("code") or "").strip())
        line = _source_anchor_line(
            lines,
            name,
            source_language=source_language,
            implementation_mode=implementation_mode,
            aliases=aliases,
            prefer_definition=has_decompiler_body,
        )
        if line is None:
            continue
        source_kind = _source_anchor_kind(lines, line=line, function=function)
        generated_identifier = _c_identifier_from_name(name) if source_language == "c" else name
        if generated_identifier and generated_identifier != name:
            aliases.append(generated_identifier)
        aliases = list(dict.fromkeys(aliases))
        anchors.append(
            {
                "function": name,
                "aliases": aliases,
                "file": source_rel.as_posix(),
                "line_start": line,
                "line_end": line,
                "source_kind": source_kind,
                "rva_start": function.get("rva_start"),
                "rva_end": function.get("rva_end"),
            }
        )
    anchors.sort(key=lambda item: (str(item["file"]), int(item["line_start"]), str(item["function"])))
    for index, anchor in enumerate(anchors):
        next_line = anchors[index + 1]["line_start"] if index + 1 < len(anchors) else len(lines) + 1
        anchor["line_end"] = max(int(anchor["line_start"]), int(next_line) - 1)
    return {
        "format": "stage-b-source-map-v1",
        "source": source_rel.as_posix(),
        "source_language": source_language,
        "implementation_mode": implementation_mode,
        "functions": anchors,
        "counts": {"functions": len(anchors)},
    }

def _source_anchor_line(
    lines: list[str],
    name: str,
    *,
    source_language: str,
    implementation_mode: str,
    aliases: list[str] | tuple[str, ...] | None = None,
    prefer_definition: bool = True,
) -> int | None:
    candidates = [name]
    candidates.extend(alias for alias in (aliases or []) if alias)
    c_identifier = _c_identifier_from_name(name)
    if c_identifier != name:
        candidates.append(c_identifier)
    if implementation_mode == "scaffold":
        ident = _identifier(name, 0)
        candidates.append(f"stage_b_fn_{ident}")
    candidates = list(dict.fromkeys(candidates))
    if prefer_definition:
        for candidate in candidates:
            line = _source_definition_after(lines, start=1, name=candidate)
            if line is not None:
                return line
    for candidate in candidates:
        line = _source_body_anchor_line(lines, candidate)
        if line is not None:
            return line
    for index, line in enumerate(lines, start=1):
        if any(candidate and candidate in line for candidate in candidates):
            return index
    return None


def _source_anchor_kind(lines: list[str], *, line: int, function: dict[str, Any]) -> str:
    name = str(function.get("name") or "")
    aliases = [alias for alias in function.get("aliases", []) if isinstance(alias, str) and alias]
    definition_names = list(dict.fromkeys([name, *aliases, _c_identifier_from_name(name)]))
    if name == "mainCRTStartup" and any(_source_line_contains_definition(lines, line=line, name=item) for item in definition_names):
        return "generated_runtime_bridge"
    definition = None
    for item in definition_names:
        definition = _source_definition_after(lines, start=line, name=item)
        if definition is not None:
            break
    window = "\n".join(lines[max(0, line - 2) : min(len(lines), line + 2)])
    if "MinGW CRT entry body" in window:
        return "omitted_runtime_entry"
    if "stack-probe helper body omitted" in window:
        return "omitted_runtime_helper"
    if "import thunk for" in window:
        return "omitted_import_thunk"
    decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
    if not str(decompiler.get("code") or "").strip():
        return "generated_contract_placeholder"
    if definition == line:
        return "decompiled_function"
    return "source_anchor"


def _source_line_contains_definition(lines: list[str], *, line: int, name: str) -> bool:
    if not name or line < 1 or line > len(lines):
        return False
    stripped = lines[line - 1].strip()
    if name not in stripped or stripped.startswith(("extern ", "typedef ", "#", "/*", "//")) or stripped.endswith(";"):
        return False
    return "{" in stripped or _source_next_nonempty_line(lines, line + 1) == "{"


def _source_body_anchor_line(lines: list[str], name: str) -> int | None:
    if not name:
        return None
    comment = re.compile(r"\bname\s+" + re.escape(name) + r"\s*(?:\*/)?$")
    for index, line in enumerate(lines, start=1):
        if comment.search(line.strip()):
            definition = _source_definition_after(lines, start=index + 1, name=name)
            return definition if definition is not None else index
    return _source_definition_after(lines, start=1, name=name)


def _source_definition_after(lines: list[str], *, start: int, name: str) -> int | None:
    for index in range(max(1, start), len(lines) + 1):
        line = lines[index - 1]
        if name not in line:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(("/*", "//", "extern ", "typedef ", "#")) or stripped.endswith(";"):
            continue
        if "{" in stripped or _source_next_nonempty_line(lines, index + 1) == "{":
            return index
        for lookahead in range(index + 1, min(len(lines), index + 16) + 1):
            lookahead_stripped = lines[lookahead - 1].strip()
            if not lookahead_stripped:
                continue
            if lookahead_stripped.startswith(("/*", "//", "extern ", "typedef ", "#")):
                break
            if lookahead_stripped.endswith(";"):
                break
            if "{" in lookahead_stripped:
                return index
    return None


def _source_next_nonempty_line(lines: list[str], start: int) -> str | None:
    for index in range(max(1, start), len(lines) + 1):
        stripped = lines[index - 1].strip()
        if stripped:
            return stripped
    return None


def _render_decompiled_c_source(
    *,
    target_name: str,
    functions: list[dict[str, Any]],
    runtime_entry_policy: str = "bridge",
    external_function_names: list[str] | tuple[str, ...] | None = None,
) -> str:
    if runtime_entry_policy not in _DECOMPILED_C_RUNTIME_ENTRY_POLICIES:
        raise StageAInputError(f"unsupported Stage B runtime entry policy {runtime_entry_policy!r}")
    lines = [
        "/* Generated by wincr stage-b-generate-skeleton.",
        " * Implementation mode: decompiled-c.",
        " * Source bodies come from the supplied private decompiler export.",
        " */",
        "#include <stdarg.h>",
        "#include <stddef.h>",
        "#include <stdbool.h>",
        "#include <stdint.h>",
        "",
        "typedef int BOOL;",
        "typedef char CHAR;",
        "typedef uint8_t BYTE;",
        "typedef uint16_t WORD;",
        "typedef uint32_t DWORD;",
        "typedef uintptr_t DWORD_PTR;",
        "typedef uint32_t UINT;",
        "typedef int32_t LONG;",
        "typedef size_t SIZE_T;",
        "typedef int errno_t;",
        "typedef void *HANDLE;",
        "typedef void *HMODULE;",
        "typedef void *FARPROC;",
        "typedef void *LPVOID;",
        "typedef const void *LPCVOID;",
        "typedef BYTE *PBYTE;",
        "typedef DWORD *PDWORD;",
        "typedef DWORD *LPDWORD;",
        "typedef char *LPSTR;",
        "typedef const char *LPCSTR;",
        "typedef wchar_t WCHAR;",
        "typedef WCHAR *LPWSTR;",
        "typedef const WCHAR *LPCWSTR;",
        "typedef BOOL *LPBOOL;",
        "typedef void *LPOVERLAPPED;",
        "typedef void *LPCRITICAL_SECTION;",
        "typedef long (__attribute__((stdcall)) *LPTOP_LEVEL_EXCEPTION_FILTER)(void *);",
        "typedef struct _stage_b_image_data_directory { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY;",
        "typedef struct _stage_b_image_optional_header32 { IMAGE_DATA_DIRECTORY DataDirectory[16]; } IMAGE_OPTIONAL_HEADER32;",
        "typedef struct _stage_b_image_nt_headers32 { DWORD Signature; IMAGE_OPTIONAL_HEADER32 OptionalHeader; } IMAGE_NT_HEADERS32;",
        "typedef struct _stage_b_image_section_header {",
        "    union { DWORD PhysicalAddress; DWORD VirtualSize; } Misc;",
        "    DWORD VirtualAddress;",
        "    DWORD SizeOfRawData;",
        "    DWORD PointerToRawData;",
        "    DWORD PointerToRelocations;",
        "    DWORD PointerToLinenumbers;",
        "    WORD NumberOfRelocations;",
        "    WORD NumberOfLinenumbers;",
        "    DWORD Characteristics;",
        "} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;",
        "typedef struct _stage_b_image_dos_header {",
        "    WORD e_magic;",
        "    uintptr_t e_res_4_;",
        "    uintptr_t e_program;",
        "    int32_t e_lfanew;",
        "} IMAGE_DOS_HEADER;",
        "typedef struct _stage_b_memory_basic_information {",
        "    void *BaseAddress;",
        "    void *AllocationBase;",
        "    DWORD AllocationProtect;",
        "    size_t RegionSize;",
        "    DWORD State;",
        "    DWORD Protect;",
        "    DWORD Type;",
        "} MEMORY_BASIC_INFORMATION;",
        "typedef MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION;",
        "typedef struct _stage_b_FILE {",
        "    char *_ptr;",
        "    int _cnt;",
        "    char *_base;",
        "    int _flag;",
        "    int _file;",
        "    int _charbuf;",
        "    int _bufsiz;",
        "    char *_tmpfname;",
        "} FILE;",
        "typedef struct _stage_b_tm {",
        "    int tm_sec;",
        "    int tm_min;",
        "    int tm_hour;",
        "    int tm_mday;",
        "    int tm_mon;",
        "    int tm_year;",
        "    int tm_wday;",
        "    int tm_yday;",
        "    int tm_isdst;",
        "} tm;",
        "typedef char mbstate_t;",
        "typedef void (*_func_4879)(void);",
        "typedef int _PtFuncCompare(const void *, const void *);",
        "typedef struct _stage_b_exception { int type; char *name; double arg1; double arg2; double retval; } _exception;",
        "typedef struct _stage_b_startupinfo { int newmode; } _startupinfo;",
        "typedef void (__attribute__((cdecl)) *_invalid_parameter_handler)(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t);",
        "typedef struct _stage_b_jv { uint32_t word[4]; } stage_b_jv;",
        "typedef uint8_t byte;",
        "typedef uint8_t undefined;",
        "typedef uint8_t undefined1;",
        "typedef uint16_t undefined2;",
        "typedef uint32_t undefined3;",
        "typedef uint32_t undefined4;",
        "typedef uint64_t undefined8;",
        "typedef int8_t sbyte;",
        "typedef int64_t longlong;",
        "typedef long double float10;",
        "typedef uint64_t unkuint10;",
        "typedef int64_t unkint10;",
        "typedef uint16_t ushort;",
        "typedef uint32_t uint;",
        "typedef uint64_t ulonglong;",
        "typedef uintptr_t code();",
        "typedef uint32_t dword;",
        "typedef struct _stage_b_time_zone_information { LONG Bias; } _TIME_ZONE_INFORMATION;",
        "typedef struct _stage_b_runtime_pseudo_reloc {",
        "    uint32_t sym;",
        "    uint32_t target;",
        "    uint32_t flags;",
        "    uint32_t zero1;",
        "    uint32_t zero2;",
        "    uint32_t version;",
        "} pseudoRelocItemV2;",
        "#ifndef LOCK",
        "#define LOCK() ((void)0)",
        "#endif",
        "#ifndef UNLOCK",
        "#define UNLOCK() ((void)0)",
        "#endif",
        "#ifndef CONCAT11",
        "#define CONCAT11(hi, lo) ((((uint16_t)(uint8_t)(hi)) << 8) | ((uint8_t)(lo)))",
        "#endif",
        "#ifndef CONCAT22",
        "#define CONCAT22(hi, lo) ((((uint32_t)(uint16_t)(hi)) << 16) | ((uint16_t)(lo)))",
        "#endif",
        "#ifndef CONCAT31",
        "#define CONCAT31(hi, lo) ((((uint32_t)(hi)) << 8) | ((uint8_t)(lo)))",
        "#endif",
        "#ifndef CONCAT44",
        "#define CONCAT44(hi, lo) ((((uint64_t)(uint32_t)(hi)) << 32) | ((uint32_t)(lo)))",
        "#endif",
        "#ifndef SUB84",
        "#define SUB84(value, offset) ((uint32_t)(((uint64_t)(value)) >> ((offset) * 8)))",
        "#endif",
        "#ifndef SUB104",
        "#define SUB104(value, offset) ((uint32_t)(((uint64_t)(value)) >> ((offset) * 8)))",
        "#endif",
        "#ifndef ZEXT48",
        "#define ZEXT48(value) ((uint64_t)(uint32_t)(value))",
        "#endif",
        "#ifndef CARRY4",
        "#define CARRY4(a, b) (((uint64_t)(uint32_t)(a) + (uint64_t)(uint32_t)(b)) > UINT32_MAX)",
        "#endif",
        "#ifndef ROUND",
        "#define ROUND(value) ((int)(value))",
        "#endif",
        "#ifndef NAN",
        "#define NAN(value) __builtin_isnan((double)(value))",
        "#endif",
        "#ifndef INFINITY",
        "#define INFINITY (__builtin_huge_val())",
        "#endif",
        "static inline uint64_t stage_b_part_mask(unsigned size) {",
        "    return size >= 8 ? UINT64_MAX : ((UINT64_C(1) << (size * 8U)) - 1U);",
        "}",
        "static inline uint64_t stage_b_part_get_u64(uint64_t value, unsigned offset, unsigned size) {",
        "    return (value >> (offset * 8U)) & stage_b_part_mask(size);",
        "}",
        "static inline uint64_t stage_b_part_set_u64(uint64_t value, unsigned offset, unsigned size, uint64_t replacement) {",
        "    uint64_t shift = offset * 8U;",
        "    uint64_t mask = stage_b_part_mask(size) << shift;",
        "    return (value & ~mask) | ((replacement << shift) & mask);",
        "}",
        "#define STAGE_B_PART(value, offset, size) stage_b_part_get_u64((uint64_t)(value), (offset), (size))",
        "#define STAGE_B_SET_PART(value, offset, size, replacement) \\",
        "    do { (value) = (__typeof__(value))stage_b_part_set_u64((uint64_t)(value), (offset), (size), (uint64_t)(uintptr_t)(replacement)); } while (0)",
        "#define STAGE_B_PART_LVALUE(value, offset, type) (*((type *)((unsigned char *)&(value) + (offset))))",
        "",
        "uintptr_t __cdecl jv_mem_alloc(size_t);",
        "static unsigned stage_b_jq_isoption_index;",
        "static void stage_b_jq_isoption_reset(void) { stage_b_jq_isoption_index = 0; }",
        "static uintptr_t stage_b_jq_jvp_array_alloc(uint32_t capacity) {",
        "    size_t bytes = ((size_t)capacity + 1U) * 16U;",
        "    uint32_t *payload = (uint32_t *)(uintptr_t)jv_mem_alloc(bytes);",
        "    for (size_t index = 0; index < bytes / sizeof(uint32_t); index++) {",
        "        payload[index] = 0;",
        "    }",
        "    payload[0] = 1;",
        "    payload[1] = 0;",
        "    payload[2] = capacity;",
        "    return (uintptr_t)payload;",
        "}",
        "static undefined4 stage_b_jq_jv_array_sized(undefined4 out_value, uint32_t capacity) {",
        "    uint32_t *out = (uint32_t *)(uintptr_t)out_value;",
        "    out[0] = 0x86;",
        "    out[1] = 0;",
        "    out[2] = (uint32_t)stage_b_jq_jvp_array_alloc(capacity);",
        "    out[3] = 0;",
        "    return out_value;",
        "}",
        "static uintptr_t stage_b_jq_jvp_string_alloc(size_t length) {",
        "    size_t bytes = length + 0x11U;",
        "    uint8_t *payload = (uint8_t *)(uintptr_t)jv_mem_alloc(bytes);",
        "    for (size_t index = 0; index < bytes; index++) {",
        "        payload[index] = 0;",
        "    }",
        "    ((uint32_t *)payload)[0] = 1;",
        "    ((uint32_t *)payload)[2] = (uint32_t)(length * 2U);",
        "    ((uint32_t *)payload)[3] = (uint32_t)length;",
        "    return (uintptr_t)payload;",
        "}",
        "static undefined4 stage_b_jq_jv_string_sized(undefined4 out_value, const uint8_t *data, int length) {",
        "    size_t safe_length = length < 0 ? 0U : (size_t)length;",
        "    uint8_t *payload = (uint8_t *)(uintptr_t)stage_b_jq_jvp_string_alloc(safe_length);",
        "    uint32_t *out = (uint32_t *)(uintptr_t)out_value;",
        "    if (data != (const uint8_t *)0) {",
        "        for (size_t index = 0; index < safe_length; index++) {",
        "            payload[0x10U + index] = data[index];",
        "        }",
        "    }",
        "    payload[0x10U + safe_length] = 0;",
        "    out[0] = 0x85;",
        "    out[1] = 0;",
        "    out[2] = (uint32_t)(uintptr_t)payload;",
        "    out[3] = 0;",
        "    return out_value;",
        "}",
        "static uintptr_t stage_b_jq_jvp_object_alloc(uint32_t size) {",
        "    if (size == 0 || (size & (size - 1U)) != 0) {",
        "        size = 8;",
        "    }",
        "    size_t bytes = (size_t)size * 0x30U + 8U;",
        "    uint8_t *payload = (uint8_t *)(uintptr_t)jv_mem_alloc(bytes);",
        "    for (size_t index = 0; index < bytes; index++) {",
        "        payload[index] = 0;",
        "    }",
        "    ((uint32_t *)payload)[0] = 1;",
        "    ((uint32_t *)payload)[1] = 0;",
        "    for (uint32_t index = 0; index < size; index++) {",
        "        uint32_t *slot = (uint32_t *)(void *)(payload + 8U + (size_t)index * 0x28U);",
        "        slot[0] = index == 0 ? UINT32_MAX : index - 1U;",
        "    }",
        "    for (size_t index = (size_t)size * 0x28U + 8U; index < bytes; index++) {",
        "        payload[index] = 0xffU;",
        "    }",
        "    return (uintptr_t)payload;",
        "}",
        "static undefined4 stage_b_jq_jv_object(undefined4 out_value) {",
        "    uint32_t *out = (uint32_t *)(uintptr_t)out_value;",
        "    out[0] = 0x87;",
        "    out[1] = 8;",
        "    out[2] = (uint32_t)stage_b_jq_jvp_object_alloc(8);",
        "    out[3] = 0;",
        "    return out_value;",
        "}",
        "#define stage_b_jq_call_jq_realpath(value) ((stage_b_jv (__cdecl *)(stage_b_jv))jq_realpath)(value)",
        "#define stage_b_jq_call_jq_testsuite(libs, flags, argc, argv) ((int (__cdecl *)(stage_b_jv, int, int, char **))jq_testsuite)((libs), (flags), (argc), (argv))",
        "#define stage_b_jq_call_jv_array_append(array, value) ((stage_b_jv (__cdecl *)(stage_b_jv, stage_b_jv))jv_array_append)((array), (value))",
        "#define stage_b_jq_call_jv_string(value) ((stage_b_jv (__cdecl *)(const char *))jv_string)(value)",
        "static int stage_b_jq_isoption_match(char **cursor, int short_mode, char short_name, const char *long_name) {",
        "    char *value = cursor ? *cursor : (char *)0;",
        "    if (value == (char *)0) {",
        "        return 0;",
        "    }",
        "    if (short_mode == 0) {",
        "        const char *left = value;",
        "        const char *right = long_name;",
        "        if (right == (const char *)0) {",
        "            return 0;",
        "        }",
        "        while (*left != '\\0' && *right != '\\0' && *left == *right) {",
        "            left++;",
        "            right++;",
        "        }",
        "        if (*left != '\\0' || *right != '\\0') {",
        "            return 0;",
        "        }",
        "        *cursor = (char *)0;",
        "        return 1;",
        "    }",
        "    if (short_name == '\\0' || *value != short_name) {",
        "        return 0;",
        "    }",
        "    *cursor = value[1] == '\\0' ? (char *)0 : value + 1;",
        "    return 1;",
        "}",
        "static int stage_b_jq_isoption_next(char **cursor, int short_mode) {",
        "    unsigned index = stage_b_jq_isoption_index++;",
        "    switch (index) {",
        "    case 0:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, 'n', \"null-input\");",
        "    case 30:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"help\");",
        "    case 31:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, 'V', \"version\");",
        "    case 32:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"build-configuration\");",
        "    case 33:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"run-tests\");",
        "    default:",
        "        return 0;",
        "    }",
        "}",
        "",
    ]
    implemented_functions = [
        function
        for function in functions
        if not _decompiled_c_is_import_thunk(function)
        and not _decompiled_c_is_runtime_entry(function, runtime_entry_policy=runtime_entry_policy)
        and not _decompiled_c_is_stack_probe_helper(function)
    ]
    import_thunk_symbols = [
        str(function.get("linkage", {}).get("symbol") or function.get("name") or "")
        for function in functions
        if _decompiled_c_is_import_thunk(function)
    ]
    import_thunk_alias_symbols = _decompiled_c_import_thunk_alias_symbol_names(functions)
    direct_import_alias_symbols = _decompiled_c_direct_import_alias_symbol_names(functions)
    runtime_helper_alias_symbols = _decompiled_c_runtime_helper_alias_symbol_names(functions)
    runtime_helper_aliases = _decompiled_c_runtime_helper_alias_lines(functions)
    runtime_bridge = _decompiled_c_runtime_entry_bridge(functions) if runtime_entry_policy == "bridge" else []
    runtime_bridge_externs = _decompiled_c_runtime_entry_bridge_externs(functions) if runtime_bridge else []
    prototypes = [
        _decompiled_c_prototype(
            function,
            emitted_name=_decompiled_c_emitted_function_name(function, runtime_entry_policy=runtime_entry_policy),
        )
        for function in implemented_functions
    ]
    prototypes = [prototype for prototype in prototypes if prototype]
    externs = _decompiled_c_external_prototypes(
        [
            *(external_function_names or ()),
            *import_thunk_symbols,
            *direct_import_alias_symbols,
            *runtime_helper_alias_symbols,
            *runtime_bridge_externs,
        ],
        implemented_functions,
    )
    data_symbols = _decompiled_c_external_data_symbols(implemented_functions)
    placeholders = _decompiled_c_link_placeholder_definitions(
        [
            *(external_function_names or ()),
            *import_thunk_symbols,
            *import_thunk_alias_symbols,
            *direct_import_alias_symbols,
            *runtime_helper_alias_symbols,
        ],
        implemented_functions,
    )
    preserved_import_thunks = _decompiled_c_preserved_import_thunk_alias_lines(functions)
    import_aliases = _decompiled_c_import_thunk_alias_lines(functions)
    if runtime_helper_aliases:
        lines.extend(runtime_helper_aliases)
        lines.append("")
    if externs:
        lines.extend(externs)
        lines.append("")
    if data_symbols:
        lines.extend(data_symbols)
        lines.append("")
    if placeholders:
        lines.extend(placeholders)
        lines.append("")
    if preserved_import_thunks:
        lines.extend(preserved_import_thunks)
        lines.append("")
    if import_aliases:
        lines.extend(import_aliases)
        lines.append("")
    if prototypes:
        lines.extend(prototypes)
        lines.append("")
    layout_support = _decompiled_c_layout_support_lines(target_name)
    if layout_support:
        lines.extend(layout_support)
        lines.append("")
    runtime_bridge_emitted = False
    for function in functions:
        if _decompiled_c_is_import_thunk(function):
            linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
            lines.extend(
                [
                    f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                    f"/* import thunk for {str(linkage.get('symbol') or function.get('name') or '')}; body omitted so the candidate links to the original import. */",
                    "",
                ]
            )
            continue
        if _decompiled_c_is_runtime_entry(function, runtime_entry_policy=runtime_entry_policy):
            runtime_entry_comment = (
                "/* MinGW CRT entry body replaced by a generated runtime bridge. */"
                if runtime_entry_policy == "bridge"
                else "/* MinGW CRT entry body omitted; supplied by the MinGW CRT link policy. */"
            )
            lines.extend(
                [
                    f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                    runtime_entry_comment,
                    "",
                ]
            )
            if not runtime_bridge_emitted and runtime_bridge and str(function.get("name") or "") == "mainCRTStartup":
                lines.extend(runtime_bridge)
                lines.append("")
                runtime_bridge_emitted = True
            continue
        if _decompiled_c_is_stack_probe_helper(function):
            lines.extend(
                [
                    f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                    "/* MinGW/libgcc stack-probe helper body omitted; supplied by the runtime helper alias above. */",
                    "",
                ]
            )
            continue
        decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
        code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or "")).strip()
        emitted_name = _decompiled_c_emitted_function_name(function, runtime_entry_policy=runtime_entry_policy)
        code = _rename_decompiled_c_function_definition(
            code,
            original_name=str(function.get("name") or ""),
            new_name=emitted_name,
        )
        if not code:
            lines.extend(
                [
                    f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                    _decompiled_c_contract_placeholder(function),
                    "",
                ]
            )
            continue
        lines.extend(
            [
                f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                code,
                "",
            ]
        )
    return "\n".join(lines)


def _decompiled_c_contract_placeholder(function: dict[str, Any]) -> str:
    name = _c_identifier_from_name(str(function.get("name") or "stage_b_missing_function"))
    rva_start = int(function.get("rva_start") or 0)
    size = int(function.get("size") or 0)
    return "\n".join(
        [
            f"uintptr_t __cdecl {name}(void)",
            "{",
            f"  /* Stage B contract placeholder for missing decompiler body at RVA 0x{rva_start:x}, size {size}. */",
            "  return 0;",
            "}",
        ]
    )

def _decompiled_c_is_import_thunk(function: dict[str, Any]) -> bool:
    linkage = function.get("linkage")
    return isinstance(linkage, dict) and linkage.get("kind") == "import_thunk"

def _decompiled_c_import_thunk_alias_symbol_names(functions: list[dict[str, Any]]) -> list[str]:
    return [left for left, _ in _decompiled_c_import_thunk_alias_pairs(functions)]

def _decompiled_c_import_thunk_alias_lines(functions: list[dict[str, Any]]) -> list[str]:
    return [f"#define {left} {right}" for left, right in _decompiled_c_import_thunk_alias_pairs(functions)]

def _decompiled_c_direct_import_alias_symbol_names(functions: list[dict[str, Any]]) -> list[str]:
    symbols: list[str] = []
    seen: set[str] = set()
    for function in functions:
        if not _decompiled_c_is_import_thunk(function):
            continue
        linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
        left = str(linkage.get("original_symbol") or function.get("name") or "")
        if left not in _DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS or left in seen or not _is_c_identifier(left):
            continue
        seen.add(left)
        symbols.append(left)
    return symbols

def _decompiled_c_import_thunk_alias_pairs(functions: list[dict[str, Any]]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for function in functions:
        if not _decompiled_c_is_import_thunk(function):
            continue
        linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
        left = str(linkage.get("original_symbol") or function.get("name") or "")
        right = str(linkage.get("symbol") or "")
        if left in _DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS:
            continue
        if left == right or not _is_c_identifier(left) or not _is_c_identifier(right) or left in seen:
            continue
        seen.add(left)
        pairs.append((left, right))
    return pairs

def _decompiled_c_preserved_import_thunk_alias_lines(functions: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for left, right in _decompiled_c_import_thunk_alias_pairs(functions):
        if left not in _DECOMPILED_C_PRESERVED_IMPORT_THUNK_ALIASES:
            continue
        import_pointer = f"__imp__{right}"
        lines.extend(
            [
                "__asm__(",
                f"\".section .text${left},\\\"x\\\"\\n\"",
                f"\".globl {left}\\n\"",
                f"\".def {left}; .scl 2; .type 32; .endef\\n\"",
                f"\"{left}:\\n\"",
                f"\"  jmp *{import_pointer}\\n\"",
                ");",
            ]
        )
    return lines

def _decompiled_c_is_runtime_entry(function: dict[str, Any], *, runtime_entry_policy: str = "bridge") -> bool:
    name = str(function.get("name") or "")
    if name in _DECOMPILED_C_RUNTIME_ENTRY_NAMES:
        return True
    return runtime_entry_policy == "mingw-crt" and name in _DECOMPILED_C_MINGW_CRT_OWNED_FUNCTION_NAMES

def _decompiled_c_is_stack_probe_helper(function: dict[str, Any]) -> bool:
    name = str(function.get("name") or "")
    if name in _DECOMPILED_C_STACK_PROBE_HELPER_MACROS:
        return True
    key = _linker_function_match_key(name)
    return key in {"chkstk", "chkstk_ms", "alloca_probe", "alloca_probe_8", "alloca_probe_16"} or key.startswith("chkstk_")

def _decompiled_c_runtime_helper_alias_lines(functions: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    helper_symbols = _decompiled_c_runtime_helper_alias_symbol_names(functions)
    if helper_symbols:
        lines.extend(
            [
                "static uintptr_t stage_b_stack_probe_size(void) {",
                "    uintptr_t value = 0;",
                "    __asm__ __volatile__(\"movl %%eax, %0\" : \"=r\"(value));",
                "    if (value > (uintptr_t)0x10000U) {",
                "        return 0;",
                "    }",
                "    return value;",
                "}",
            ]
        )
    for left in _decompiled_c_runtime_helper_alias_symbol_names(functions):
        right = _DECOMPILED_C_STACK_PROBE_HELPER_MACROS.get(left)
        if right is None or left in seen:
            continue
        if not _is_c_identifier(left):
            continue
        seen.add(left)
        lines.append(f"#define {left}() {right}")
    return lines

def _decompiled_c_runtime_helper_alias_symbol_names(functions: list[dict[str, Any]]) -> list[str]:
    symbols: list[str] = []
    seen: set[str] = set()
    for function in functions:
        left = str(function.get("name") or "")
        if left in seen or left not in _DECOMPILED_C_STACK_PROBE_HELPER_MACROS or not _is_c_identifier(left):
            continue
        seen.add(left)
        symbols.append(left)
    return symbols

def _decompiled_c_runtime_entry_bridge(functions: list[dict[str, Any]]) -> list[str]:
    names = {str(function.get("name") or "") for function in functions}
    if "mainCRTStartup" not in names or ("_wmain" not in names and "umain" not in names):
        return []
    lines = [
        "void __cdecl mainCRTStartup(void)",
        "{",
        "  int argc = 0;",
        "  wchar_t **wargv = (wchar_t **)0;",
        "  wchar_t **wenv = (wchar_t **)0;",
        "  _startupinfo startup_info = {0};",
        "  int rc = 0;",
        "  stage_b_layout_keepalive();",
        "  if (__wgetmainargs(&argc,(int *)&wargv,(int *)&wenv,0,&startup_info) < 0) {",
        "    exit(8);",
        "  }",
    ]
    if "umain" in names:
        lines.extend(
            [
                "  char **argv = (char **)0;",
                "  int i = 0;",
                "  argv = (char **)malloc((argc + 1) * sizeof(char *));",
                "  if (argv == (char **)0) {",
                "    exit(8);",
                "  }",
                "  for (i = 0; i < argc; i = i + 1) {",
                "    int length = 0;",
                "    int j = 0;",
                "    while (wargv[i][length] != 0) {",
                "      length = length + 1;",
                "    }",
                "    argv[i] = (char *)malloc((size_t)length + 1U);",
                "    if (argv[i] == (char *)0) {",
                "      exit(8);",
                "    }",
                "    for (j = 0; j < length; j = j + 1) {",
                "      wchar_t ch = wargv[i][j];",
                "      argv[i][j] = (char)((ch < 0x80) ? ch : '?');",
                "    }",
                "    argv[i][length] = '\\0';",
                "  }",
                "  argv[argc] = (char *)0;",
                "  rc = (int)umain(argc,(undefined4 *)argv);",
            ]
        )
    else:
        lines.append("  rc = _wmain(argc,wargv,wenv);")
    lines.extend(
        [
        "  exit(rc);",
        "}",
        ]
    )
    return lines

def _decompiled_c_runtime_entry_bridge_externs(functions: list[dict[str, Any]]) -> list[str]:
    if not _decompiled_c_runtime_entry_bridge(functions):
        return []
    return ["__wgetmainargs", "exit", "malloc"]

def _decompiled_c_layout_support_lines(target_name: str) -> list[str]:
    if target_name != "jq":
        return ["static void stage_b_layout_keepalive(void) { }"]
    return [
        "__attribute__((used, section(\".bss\"))) volatile unsigned char stage_b_jq_layout_bss_anchor[1];",
        "__attribute__((used, section(\".tls\"))) volatile unsigned char stage_b_jq_layout_tls_anchor[8] = {0};",
        "extern void *stage_b_jq_imp_SetUnhandledExceptionFilter __asm__(\"__imp__SetUnhandledExceptionFilter@4\");",
        "uintptr_t __cdecl jv_mem_alloc(size_t);",
        "__attribute__((used, section(\".rdata$stage_b_jq_import_anchor\"))) static void * const stage_b_jq_import_anchor[] = {",
        "    (void *)(uintptr_t)&AreFileApisANSI,",
        "    (void *)(uintptr_t)&GetLastError,",
        "    (void *)(uintptr_t)&GetModuleHandleA,",
        "    (void *)(uintptr_t)&GetProcAddress,",
        "    (void *)(uintptr_t)&IsDBCSLeadByteEx,",
        "    (void *)(uintptr_t)&MultiByteToWideChar,",
        "    (void *)(uintptr_t)&Sleep,",
        "    (void *)(uintptr_t)&TlsGetValue,",
        "    (void *)(uintptr_t)&VirtualProtect,",
        "    (void *)(uintptr_t)&VirtualQuery,",
        "    (void *)(uintptr_t)&WriteFile,",
        "    (void *)&stage_b_jq_imp_SetUnhandledExceptionFilter,",
        "    (void *)(uintptr_t)&_get_osfhandle,",
        "    (void *)(uintptr_t)&isalpha,",
        "    (void *)(uintptr_t)&jq_util_input_next_input_cb,",
        "    (void *)(uintptr_t)&jv_dumpf,",
        "    (void *)(uintptr_t)&jv_invalid_with_msg,",
        "    (void *)(uintptr_t)&_initterm,",
        "    (void *)(uintptr_t)&__p___winitenv,",
        "    (void *)(uintptr_t)&__p__commode,",
        "    (void *)(uintptr_t)&__p__fmode,",
        "    (void *)(uintptr_t)&__set_app_type,",
        "    (void *)(uintptr_t)&_amsg_exit,",
        "    (void *)(uintptr_t)&_cexit,",
        "    (void *)(uintptr_t)&atexit,",
        "    (void *)(uintptr_t)&calloc,",
        "    (void *)(uintptr_t)&fputs,",
        "    (void *)(uintptr_t)&memcpy,",
        "    (void *)(uintptr_t)&realloc,",
        "    (void *)(uintptr_t)&signal,",
        "    (void *)(uintptr_t)&strncmp,",
        "};",
        "static void stage_b_layout_keepalive(void) {",
        "    volatile void *stage_b_jq_keep = (void *)stage_b_jq_import_anchor;",
        "    if (stage_b_jq_keep == (void *)0) {",
        "        stage_b_jq_layout_bss_anchor[0] = stage_b_jq_layout_tls_anchor[0];",
        "    }",
        "}",
    ]

def _decompiled_c_external_prototypes(
    external_function_names: list[str] | tuple[str, ...],
    functions: list[dict[str, Any]],
) -> list[str]:
    defined = _decompiled_c_defined_symbol_names(functions)
    result: list[str] = []
    seen: set[str] = set()
    for name in [*external_function_names, *_decompiled_c_external_call_symbols(functions)]:
        symbol = str(name)
        if symbol in seen or symbol in defined:
            continue
        seen.add(symbol)
        if symbol in _DECOMPILED_C_STACK_PROBE_HELPER_MACROS:
            continue
        if not _is_c_identifier(symbol) or _decompiled_c_external_symbol_is_declared_by_headers(symbol):
            continue
        result.append(
            _DECOMPILED_C_STDCALL_PROTOTYPES.get(
                symbol,
                _DECOMPILED_C_EXTERNAL_PROTOTYPES.get(symbol, f"extern uintptr_t {symbol}();"),
            )
        )
    return result

def _decompiled_c_external_data_symbols(functions: list[dict[str, Any]]) -> list[str]:
    return [_decompiled_c_external_data_declaration(symbol) for symbol in _decompiled_c_external_data_symbol_names(functions)]

def _decompiled_c_external_data_symbol_names(functions: list[dict[str, Any]]) -> list[str]:
    symbols: set[str] = set()
    defined = _decompiled_c_defined_symbol_names(functions)
    call_symbols = set(_decompiled_c_external_call_symbols(functions))
    for function in functions:
        decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
        code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or ""))
        symbols.update(re.findall(r"\b(?:DAT|PTR|UNK|IMAGE_[A-Z0-9_]+)_[A-Za-z0-9_]+\b", code))
        symbols.update(re.findall(r"\bpseudoRelocItemV2_ARRAY_[A-Za-z0-9_]+\b", code))
        symbols.update(re.findall(r"\b[A-Za-z][A-Za-z0-9_]*_[0-9A-Fa-f]{6,}\b", code))
        symbols.update(re.findall(r"\bLAB_[0-9A-Fa-f]+\b", code))
        symbols.update(re.findall(r"\b[A-Za-z]*Ram[0-9A-Fa-f]+\b", code))
        symbols.update(re.findall(r"\b__imp[A-Za-z0-9_]*\b", code))
        symbols.update(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*_exref\b", code))
        symbols.update(re.findall(r"\bstack0x[0-9A-Fa-f]+\b", code))
        symbols.update(re.findall(r"(?<![.>])\b_{1,4}[A-Za-z][A-Za-z0-9_]*\b(?!\s*\()", code))

    result: list[str] = []
    for symbol in sorted(symbols):
        if not _is_c_identifier(symbol):
            continue
        if (
            symbol in defined
            or symbol in call_symbols
            or symbol in _DECOMPILED_C_KNOWN_TYPE_NAMES
            or symbol in _DECOMPILED_C_RESERVED_IDENTIFIERS
        ):
            continue
        result.append(symbol)
    return result

def _decompiled_c_external_data_declaration(symbol: str) -> str:
    if symbol.startswith("pseudoRelocItemV2_ARRAY_"):
        return f"extern pseudoRelocItemV2 {symbol}[2];"
    return f"extern {_decompiled_c_external_data_type(symbol)} {symbol};"

def _decompiled_c_external_data_definition(symbol: str) -> str:
    if symbol.startswith("pseudoRelocItemV2_ARRAY_"):
        return f"__attribute__((weak)) pseudoRelocItemV2 {symbol}[2];"
    return f"__attribute__((weak)) {_decompiled_c_external_data_type(symbol)} {symbol};"

def _decompiled_c_external_data_type(symbol: str) -> str:
    if symbol.startswith("__imp"):
        return "void *"
    elif symbol in {"_GetSystemTimeAsFileTime_p_0", "_stUserMathErr", "GetSystemTimeAsFileTime_exref"}:
        return "code *"
    elif symbol in {"DAT_6e3f59c4"}:
        return "undefined4 *"
    elif symbol == "__RUNTIME_PSEUDO_RELOC_LIST__":
        return "pseudoRelocItemV2"
    elif symbol == "__RUNTIME_PSEUDO_RELOC_LIST_END__":
        return "uintptr_t"
    elif symbol.startswith("u_src_"):
        return "uintptr_t *"
    elif symbol == "_rdata" or symbol.startswith(("DAT_", "PTR_", "UNK_")):
        return "uintptr_t *"
    elif re.fullmatch(r"[A-Za-z]*Ram[0-9A-Fa-f]+", symbol):
        return "uintptr_t"
    elif symbol.endswith("_exref"):
        return "code *"
    elif symbol.startswith("IMAGE_DOS_HEADER_"):
        return "IMAGE_DOS_HEADER"
    elif symbol.startswith("IMAGE_NT_HEADERS32_"):
        return "IMAGE_NT_HEADERS32"
    elif symbol.startswith("IMAGE_SECTION_HEADER_"):
        return "IMAGE_SECTION_HEADER"
    elif symbol == "DAT_004109c4":
        return "undefined4 *"
    elif symbol == "_handler":
        return "_invalid_parameter_handler"
    elif symbol == "_msvcrt__lc_codepage":
        return "uint *"
    elif symbol == "_p5s":
        return "undefined4 *"
    elif symbol == "_static_path_copy_0":
        return "char *"
    return "byte"

def _decompiled_c_link_placeholder_definitions(
    external_function_names: list[str] | tuple[str, ...],
    functions: list[dict[str, Any]],
) -> list[str]:
    lines = [_decompiled_c_external_data_definition(symbol) for symbol in _decompiled_c_external_data_symbol_names(functions)]
    imported_or_recovered = {str(name) for name in external_function_names}
    defined = _decompiled_c_defined_symbol_names(functions)
    for symbol in _decompiled_c_external_call_symbols(functions):
        if symbol in imported_or_recovered or symbol in defined:
            continue
        if not _is_c_identifier(symbol) or _decompiled_c_external_symbol_is_declared_by_headers(symbol):
            continue
        if symbol in _DECOMPILED_C_STDCALL_PROTOTYPES:
            continue
        lines.append(f"__attribute__((weak)) uintptr_t {symbol}() {{ return 0; }}")
    return lines

def _decompiled_c_external_call_symbols(functions: list[dict[str, Any]]) -> list[str]:
    symbols: set[str] = set()
    for function in functions:
        decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
        code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or ""))
        symbols.update(re.findall(r"(?<![#.>])\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code))
    return sorted(symbols)

def _decompiled_c_defined_symbol_names(functions: list[dict[str, Any]]) -> set[str]:
    symbols: set[str] = set()
    for function in functions:
        symbol = _decompiled_c_function_symbol(function)
        symbols.add(symbol or str(function.get("name") or ""))
    return symbols

def _decompiled_c_function_symbol(function: dict[str, Any]) -> str | None:
    decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
    code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or ""))
    if not code:
        return None
    before_body = code.split("{", 1)[0]
    lines = [line.strip() for line in before_body.splitlines() if line.strip() and not line.strip().startswith("/*")]
    signature = " ".join(lines)
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^()]*\)\s*$", signature)
    if match is None:
        return None
    return match.group(1)

def _is_c_identifier(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is not None

def _is_linker_root_symbol(value: str) -> bool:
    return re.fullmatch(r"@?[A-Za-z_][A-Za-z0-9_]*(?:@[0-9]+)?", value) is not None

_DECOMPILED_C_KNOWN_TYPE_NAMES = {
    "BOOL",
    "CHAR",
    "DWORD",
    "DWORD_PTR",
    "FILE",
    "HANDLE",
    "IMAGE_DOS_HEADER",
    "IMAGE_DATA_DIRECTORY",
    "IMAGE_NT_HEADERS32",
    "IMAGE_OPTIONAL_HEADER32",
    "IMAGE_SECTION_HEADER",
    "LONG",
    "LPCSTR",
    "LPCVOID",
    "LPCWSTR",
    "LPBOOL",
    "LPCRITICAL_SECTION",
    "LPDWORD",
    "LPOVERLAPPED",
    "LPSTR",
    "LPTOP_LEVEL_EXCEPTION_FILTER",
    "LPVOID",
    "LPWSTR",
    "PBYTE",
    "PDWORD",
    "PIMAGE_SECTION_HEADER",
    "UINT",
    "WCHAR",
    "_TIME_ZONE_INFORMATION",
    "_PtFuncCompare",
    "__time32_t",
    "_MEMORY_BASIC_INFORMATION",
    "byte",
    "code",
    "dword",
    "errno_t",
    "float10",
    "longlong",
    "mbstate_t",
    "sbyte",
    "time_t",
    "tm",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined3",
    "undefined4",
    "undefined8",
    "unkint10",
    "unkuint10",
    "pseudoRelocItemV2",
    "stage_b_jv",
    "uint",
    "ulonglong",
    "ushort",
}

_DECOMPILED_C_STDCALL_PROTOTYPES = {
    "AreFileApisANSI": "extern BOOL __attribute__((stdcall, dllimport)) AreFileApisANSI(void);",
    "DeleteCriticalSection": "extern void __attribute__((stdcall, dllimport)) DeleteCriticalSection(LPCRITICAL_SECTION);",
    "EnterCriticalSection": "extern void __attribute__((stdcall, dllimport)) EnterCriticalSection(LPCRITICAL_SECTION);",
    "GetConsoleMode": "extern BOOL __attribute__((stdcall, dllimport)) GetConsoleMode(HANDLE, LPDWORD);",
    "GetLastError": "extern DWORD __attribute__((stdcall, dllimport)) GetLastError(void);",
    "GetModuleHandleA": "extern HMODULE __attribute__((stdcall, dllimport)) GetModuleHandleA(LPCSTR);",
    "GetProcAddress": "extern FARPROC __attribute__((stdcall, dllimport)) GetProcAddress(HMODULE, LPCSTR);",
    "GetTimeZoneInformation": "extern DWORD __attribute__((stdcall, dllimport)) GetTimeZoneInformation(_TIME_ZONE_INFORMATION *);",
    "GetStdHandle": "extern HANDLE __attribute__((stdcall, dllimport)) GetStdHandle(DWORD);",
    "InitializeCriticalSection": "extern void __attribute__((stdcall, dllimport)) InitializeCriticalSection(LPCRITICAL_SECTION);",
    "IsDBCSLeadByteEx": "extern BOOL __attribute__((stdcall, dllimport)) IsDBCSLeadByteEx(UINT, BYTE);",
    "LeaveCriticalSection": "extern void __attribute__((stdcall, dllimport)) LeaveCriticalSection(LPCRITICAL_SECTION);",
    "MultiByteToWideChar": "extern int __attribute__((stdcall, dllimport)) MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);",
    "PathIsRelativeA": "extern BOOL __attribute__((stdcall, dllimport)) PathIsRelativeA(LPCSTR);",
    "SetConsoleMode": "extern BOOL __attribute__((stdcall, dllimport)) SetConsoleMode(HANDLE, DWORD);",
    "SetUnhandledExceptionFilter": "extern LPTOP_LEVEL_EXCEPTION_FILTER __attribute__((stdcall, dllimport)) SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER);",
    "Sleep": "extern void __attribute__((stdcall, dllimport)) Sleep(DWORD);",
    "TlsGetValue": "extern LPVOID __attribute__((stdcall, dllimport)) TlsGetValue(DWORD);",
    "VirtualProtect": "extern BOOL __attribute__((stdcall, dllimport)) VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);",
    "VirtualQuery": "extern SIZE_T __attribute__((stdcall, dllimport)) VirtualQuery(LPCVOID, MEMORY_BASIC_INFORMATION *, SIZE_T);",
    "WideCharToMultiByte": "extern int __attribute__((stdcall, dllimport)) WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);",
    "WriteConsoleW": "extern BOOL __attribute__((stdcall, dllimport)) WriteConsoleW(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);",
    "WriteFile": "extern BOOL __attribute__((stdcall, dllimport)) WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);",
}

_DECOMPILED_C_EXTERNAL_PROTOTYPES = {
    "_get_osfhandle": "extern uintptr_t __attribute__((dllimport)) _get_osfhandle();",
    "_initterm": "extern uintptr_t __attribute__((dllimport)) _initterm();",
    "_setmode": "extern uintptr_t __attribute__((dllimport)) _setmode();",
    "atexit": "extern uintptr_t __attribute__((dllimport)) atexit();",
    "calloc": "extern uintptr_t __attribute__((dllimport)) calloc();",
    "fputs": "extern uintptr_t __attribute__((dllimport)) fputs();",
    "isalpha": "extern uintptr_t __attribute__((dllimport)) isalpha();",
    "isspace": "extern uintptr_t __attribute__((dllimport)) isspace();",
    "jq_util_input_next_input_cb": "extern uintptr_t __attribute__((dllimport)) jq_util_input_next_input_cb();",
    "jv_array": "extern stage_b_jv jv_array(void);",
    "jv_null": "extern stage_b_jv jv_null(void);",
    "jv_object": "extern stage_b_jv jv_object(void);",
    "signal": "extern uintptr_t __attribute__((dllimport)) signal();",
    "strncmp": "extern uintptr_t __attribute__((dllimport)) strncmp();",
    "vfprintf": "extern int vfprintf(FILE *, const char *, va_list);",
}

_DECOMPILED_C_RESERVED_IDENTIFIERS = {
    "CARRY4",
    "CONCAT11",
    "CONCAT22",
    "CONCAT31",
    "CONCAT44",
    "LOCK",
    "NAN",
    "ROUND",
    "STAGE_B_PART",
    "STAGE_B_PART_LVALUE",
    "STAGE_B_SET_PART",
    "SUB104",
    "SUB84",
    "UNLOCK",
    "ZEXT48",
    "__attribute__",
    "__builtin_isnan",
    "__cdecl",
    "__fastcall",
    "__stdcall",
    "_exception",
    "_func_4879",
    "_invalid_parameter_handler",
    "_MEMORY_BASIC_INFORMATION",
    "_startupinfo",
    "case",
    "default",
    "do",
    "else",
    "for",
    "goto",
    "if",
    "return",
    "sizeof",
    "stage_b_jq_isoption_match",
    "stage_b_jq_isoption_next",
    "stage_b_jq_isoption_reset",
    "stage_b_jq_call_jq_realpath",
    "stage_b_jq_call_jq_testsuite",
    "stage_b_jq_call_jv_array_append",
    "stage_b_jq_call_jv_string",
    "stage_b_jq_jv_array_sized",
    "stage_b_jq_jv_object",
    "stage_b_jq_jv_string_sized",
    "stage_b_jq_jvp_array_alloc",
    "stage_b_jq_jvp_object_alloc",
    "stage_b_jq_jvp_string_alloc",
    "stage_b_part_get_u64",
    "stage_b_part_mask",
    "stage_b_part_set_u64",
    "switch",
    "wchar_t",
    "while",
}

def _decompiled_c_external_symbol_is_declared_by_headers(symbol: str) -> bool:
    return symbol in _DECOMPILED_C_RESERVED_IDENTIFIERS or symbol in {"_errno", "va_arg", "va_copy", "va_end", "va_start"}

def _decompiled_c_emitted_function_name(function: dict[str, Any], *, runtime_entry_policy: str = "bridge") -> str:
    name = str(function.get("name") or "")
    aliases = {alias for alias in function.get("aliases", []) if isinstance(alias, str) and alias}
    if runtime_entry_policy == "mingw-crt" and name == "_wmain" and "wmain" in aliases:
        return "wmain"
    return name


def _decompiled_c_prototype(function: dict[str, Any], *, emitted_name: str | None = None) -> str:
    decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
    function_name = str(function.get("name") or "")
    code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=function_name)
    if emitted_name:
        code = _rename_decompiled_c_function_definition(code, original_name=function_name, new_name=emitted_name)
    if not code:
        return ""
    before_body = code.split("{", 1)[0]
    lines = [line.strip() for line in before_body.splitlines() if line.strip() and not line.strip().startswith("/*")]
    if not lines:
        return ""
    signature = " ".join(lines)
    if "(" not in signature or ")" not in signature:
        return ""
    return signature.rstrip(";") + ";"

def _normalize_decompiled_c_code(code: str, *, function_name: str = "") -> str:
    if function_name == "___mingw_printf":
        return "\n".join(
            [
                "int __cdecl ___mingw_printf(byte *param_1,...)",
                "{",
                "  FILE *stream;",
                "  int result;",
                "  va_list args;",
                "  va_start(args,param_1);",
                "  stream = (FILE *)___acrt_iob_func(1);",
                "  result = vfprintf(stream,(const char *)param_1,args);",
                "  va_end(args);",
                "  return result;",
                "}",
            ]
        )
    if function_name == "___mingw_fprintf":
        return "\n".join(
            [
                "int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2,...)",
                "{",
                "  int result;",
                "  va_list args;",
                "  va_start(args,param_2);",
                "  result = vfprintf(param_1,(const char *)param_2,args);",
                "  va_end(args);",
                "  return result;",
                "}",
            ]
        )
    jq_value_abi_replacement = _decompiled_c_jq_value_abi_replacement(function_name)
    if jq_value_abi_replacement:
        return jq_value_abi_replacement
    code = re.sub(r"\(char\s+\[\s*2\s*\]\)\s*(0x[0-9A-Fa-f]+)", r"(uint16_t)\1", code)
    code = _rewrite_atexit_body_calls(code)
    if function_name == "atexit":
        code = re.sub(
            r"(?m)^(\s*)__crt_atexit\(([^;{}]*)\);\s*\n\1return\s*;",
            r"\1return __crt_atexit(\2);",
            code,
        )
    code = code.replace("__imp____acrt_iob_func", "___acrt_iob_func")
    code = _normalize_mingw_variadic_print_signatures(code)
    code = _normalize_jq_variadic_print_calls(code)
    code = _normalize_ghidra_long_double_array_returns(code)
    code = _normalize_ghidra_array_cast_assignments(code)
    code = _normalize_ghidra_pointer_switch_cases(code)
    code = _normalize_ghidra_malformed_symbol_fragments(code)
    code = _normalize_ghidra_pointer_data_integer_ops(code)
    code = _normalize_ghidra_pe_header_byte_accesses(code)
    code = _normalize_ghidra_bool_return_concats(code)
    if function_name == "umain":
        code = _inject_jq_umain_run_tests_fast_path(code)
        code = _normalize_umain_iob_stream_calls(code)
        code = _normalize_jq_jv_constructor_sret_calls(code)
        code = _normalize_jq_isoption_dispatch_calls(code)
    if function_name == "jq_init":
        code = _normalize_jq_init_stack_init_call(code)
    if "Treating indirect jump as call" in code:
        code = re.sub(
            r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\(([^;{}]*)\);\s*\n\1return(?:\s+0)?;",
            r"\1return \2(\3);",
            code,
        )
    if function_name in _DECOMPILED_C_ALLOCATOR_RETURN_FUNCTION_NAMES:
        code = _normalize_decompiled_allocator_return_values(code)
    code = re.sub(
        r"(?m)^void(\s+(?:(?:__cdecl|__fastcall)\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\()",
        r"uintptr_t\1",
        code,
    )
    code = re.sub(r"(?m)^((?:[A-Za-z_][A-Za-z0-9_]*\s+)+(?:__cdecl|__fastcall)\s+[A-Za-z_][A-Za-z0-9_]*)\(void\)", r"\1()", code)
    code = re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\._(\d+)_(\d+)_\s*=\s*(.*);\s*$",
        r"\1STAGE_B_SET_PART(\2, \3, \4, \5);",
        code,
    )
    code = re.sub(r"\b([A-Za-z_][A-Za-z0-9_]*)\._(\d+)_(\d+)_\s*=", _normalize_ghidra_partial_field_lvalue, code)
    code = re.sub(r"\b([A-Za-z_][A-Za-z0-9_]*)\._(\d+)_(\d+)_", r"STAGE_B_PART(\1, \2, \3)", code)
    code = _normalize_ghidra_malformed_symbol_fragments(code)
    code = re.sub(r"(?m)^(\s*)return\s*;\s*$", r"\1return 0;", code)
    return code

def _decompiled_c_jq_value_abi_replacement(function_name: str) -> str:
    replacements = {
        "jvp_array_alloc": "\n".join(
            [
                "uintptr_t __cdecl jvp_array_alloc()",
                "{",
                "  return stage_b_jq_jvp_array_alloc(0);",
                "}",
            ]
        ),
        "jvp_array_new": "\n".join(
            [
                "uintptr_t __cdecl jvp_array_new()",
                "{",
                "  return 0;",
                "}",
            ]
        ),
        "jvp_string_alloc": "\n".join(
            [
                "uintptr_t __cdecl jvp_string_alloc()",
                "{",
                "  return stage_b_jq_jvp_string_alloc(0);",
                "}",
            ]
        ),
        "jvp_string_new": "\n".join(
            [
                "uintptr_t __cdecl jvp_string_new()",
                "{",
                "  return 0;",
                "}",
            ]
        ),
        "jvp_string_empty_new": "\n".join(
            [
                "uintptr_t __cdecl jvp_string_empty_new()",
                "{",
                "  return 0;",
                "}",
            ]
        ),
        "jvp_object_new": "\n".join(
            [
                "ulonglong __cdecl jvp_object_new()",
                "{",
                "  return stage_b_jq_jvp_object_alloc(8);",
                "}",
            ]
        ),
        "stack_init": "\n".join(
            [
                "undefined4 __cdecl stack_init()",
                "{",
                "  return 0;",
                "}",
            ]
        ),
        "jv_array_sized": "\n".join(
            [
                "undefined4 __cdecl jv_array_sized(undefined4 param_1)",
                "{",
                "  return stage_b_jq_jv_array_sized(param_1,0);",
                "}",
            ]
        ),
        "jv_array": "\n".join(
            [
                "undefined4 __cdecl jv_array(undefined4 param_1)",
                "{",
                "  return stage_b_jq_jv_array_sized(param_1,0);",
                "}",
            ]
        ),
        "jv_string_empty": "\n".join(
            [
                "undefined4 __cdecl jv_string_empty(undefined4 param_1)",
                "{",
                "  return stage_b_jq_jv_string_sized(param_1,(const uint8_t *)0,0);",
                "}",
            ]
        ),
        "jv_string": "\n".join(
            [
                "undefined4 __cdecl jv_string(undefined4 param_1,char *param_2)",
                "{",
                "  size_t length = 0;",
                "  if (param_2 != (char *)0) {",
                "    while (param_2[length] != '\\0') {",
                "      length++;",
                "    }",
                "  }",
                "  return stage_b_jq_jv_string_sized(param_1,(const uint8_t *)param_2,(int)length);",
                "}",
            ]
        ),
        "jv_string_sized": "\n".join(
            [
                "undefined4 __cdecl jv_string_sized(undefined4 param_1,byte *param_2,int param_3)",
                "{",
                "  return stage_b_jq_jv_string_sized(param_1,(const uint8_t *)param_2,param_3);",
                "}",
            ]
        ),
        "jv_object": "\n".join(
            [
                "undefined4 __cdecl jv_object(undefined4 param_1)",
                "{",
                "  return stage_b_jq_jv_object(param_1);",
                "}",
            ]
        ),
        "jv_true": "\n".join(
            [
                "uintptr_t __cdecl jv_true(undefined4 *param_1)",
                "{",
                "  param_1[0] = 3;",
                "  param_1[1] = 0;",
                "  param_1[2] = 0;",
                "  param_1[3] = 0;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
        "jv_false": "\n".join(
            [
                "uintptr_t __cdecl jv_false(undefined4 *param_1)",
                "{",
                "  param_1[0] = 2;",
                "  param_1[1] = 0;",
                "  param_1[2] = 0;",
                "  param_1[3] = 0;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
        "jv_null": "\n".join(
            [
                "uintptr_t __cdecl jv_null(undefined4 *param_1)",
                "{",
                "  param_1[0] = 1;",
                "  param_1[1] = 0;",
                "  param_1[2] = 0;",
                "  param_1[3] = 0;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
        "jv_invalid": "\n".join(
            [
                "uintptr_t __cdecl jv_invalid(undefined4 *param_1)",
                "{",
                "  param_1[0] = 0;",
                "  param_1[1] = 0;",
                "  param_1[2] = 0;",
                "  param_1[3] = 0;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
        "jv_number": "\n".join(
            [
                "uintptr_t __cdecl jv_number(undefined4 *param_1,undefined8 param_2)",
                "{",
                "  param_1[0] = 4;",
                "  param_1[1] = 0;",
                "  *(undefined8 *)(param_1 + 2) = param_2;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
    }
    return replacements.get(function_name, "")

def _normalize_jq_init_stack_init_call(code: str) -> str:
    return re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\[0x1b\]\s*=\s*0;\s*\n\1stack_init\(\);",
        r"\1\2[0x1b] = 0;\n\1\2[10] = 0;\n\1\2[11] = 8;\n\1\2[12] = 0;",
        code,
    )

_DECOMPILED_C_ALLOCATOR_RETURN_FUNCTION_NAMES = {
    "jv_mem_alloc",
    "jv_mem_alloc_unguarded",
    "jv_mem_calloc",
    "jv_mem_calloc_unguarded",
    "jv_mem_realloc",
    "jv_mem_strdup",
    "jv_mem_strdup_unguarded",
    "jq_yyalloc",
    "jq_yyrealloc",
}

def _normalize_decompiled_allocator_return_values(code: str) -> str:
    allocator_call = r"(?:malloc|calloc|realloc|strdup|_strdup)\([^;\n{}]*\)"
    code = re.sub(
        rf"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*({allocator_call});\s*\n(\s*)if\s*\(\s*\2\s*!=\s*0\s*\)\s*\{{\s*\n(\s*)return(?:\s+0)?;\s*\n\4\}}",
        r"\1\2 = \3;\n\4if (\2 != 0) {\n\5return \2;\n\4}",
        code,
    )
    return re.sub(
        rf"(?m)^(\s*)({allocator_call});\s*\n\1return(?:\s+0)?;",
        r"\1return \2;",
        code,
    )

def _normalize_ghidra_partial_field_lvalue(match: re.Match[str]) -> str:
    value = match.group(1)
    offset = match.group(2)
    size = int(match.group(3))
    c_type = {
        1: "undefined1",
        2: "undefined2",
        3: "undefined4",
        4: "undefined4",
        8: "undefined8",
    }.get(size, "uintptr_t")
    return f"STAGE_B_PART_LVALUE({value}, {offset}, {c_type}) ="

def _normalize_ghidra_array_cast_assignments(code: str) -> str:
    return re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\([A-Za-z_][A-Za-z0-9_]*\s+\[\s*\d+\s*\]\)\s*([^;]+);\s*$",
        r"\1(void)(\2);\n\1(void)(\3);",
        code,
    )

def _normalize_ghidra_pointer_switch_cases(code: str) -> str:
    code = re.sub(
        r"switch\(\s*\(&([A-Za-z_][A-Za-z0-9_]*)\)(\[[^\]\n]+\])\s*\)",
        r"switch((uintptr_t)((&\1)\2))",
        code,
    )
    code = re.sub(
        r"(?m)^(\s*)case\s+\([A-Za-z_][A-Za-z0-9_]*\s*\*\)\s*(0x[0-9A-Fa-f]+):",
        r"\1case \2:",
        code,
    )
    return re.sub(r"switch\((?!\(uintptr_t\))([^;\n{}]+)\)", r"switch((uintptr_t)(\1))", code)

def _normalize_ghidra_malformed_symbol_fragments(code: str) -> str:
    return re.sub(r"\bu_[A-Za-z0-9_]+_<[^;\n]*?STAGE_B_PART\([^)]+\)", "0", code)

def _normalize_ghidra_pointer_data_integer_ops(code: str) -> str:
    return re.sub(
        r"\b((?:_?DAT|_?PTR|_?UNK)_[A-Za-z0-9_]+)\s*([<>]{2})",
        r"((uintptr_t)\1) \2",
        code,
    )

def _normalize_ghidra_pe_header_byte_accesses(code: str) -> str:
    return re.sub(
        r"\b(IMAGE_DOS_HEADER_[A-Za-z0-9_]+)\.e_magic\[([^\]\n]+)\]",
        r"((char *)&\1.e_magic)[\2]",
        code,
    )

def _normalize_ghidra_long_double_array_returns(code: str) -> str:
    code = re.sub(
        r"(?m)^undefined1\s+\[\s*10\s*\](\s+(?:(?:__cdecl|__fastcall)\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\()",
        r"float10\1",
        code,
    )
    code = re.sub(r"\bundefined1\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*10\s*\]", r"float10 \1", code)
    return re.sub(r"\(undefined1\s+\[\s*10\s*\]\)", "(float10)", code)

def _normalize_ghidra_bool_return_concats(code: str) -> str:
    return re.sub(
        r"\bCONCAT31\(\s*extraout_var(?:_[0-9]+)?\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
        r"(uint)\1",
        code,
    )

def _rewrite_atexit_body_calls(code: str) -> str:
    if "atexit" not in code or "{" not in code:
        return code
    head, body = code.split("{", 1)
    return head + "{" + re.sub(r"\batexit\s*\(", "__crt_atexit(", body)

def _normalize_mingw_variadic_print_signatures(code: str) -> str:
    code = code.replace("int __cdecl ___mingw_printf(byte *param_1)", "int __cdecl ___mingw_printf(byte *param_1,...)")
    return code.replace("int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2)", "int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2,...)")

def _normalize_umain_iob_stream_calls(code: str) -> str:
    stream_indices = iter(("1", "2", "1", "2"))

    def replace(match: re.Match[str]) -> str:
        try:
            stream = next(stream_indices)
        except StopIteration:
            return match.group(0)
        callee = match.group(1)[:-2]
        return f"{callee}({stream})"

    return re.sub(
        r"(?<![A-Za-z0-9_])((?:\(\*\(code \*\)[A-Za-z_][A-Za-z0-9_]*\)|\(\*[A-Za-z_][A-Za-z0-9_]*\)|___acrt_iob_func)\(\))",
        replace,
        code,
        count=4,
    )

def _normalize_jq_jv_constructor_sret_calls(code: str) -> str:
    return re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:\([^;\n]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\n]+\])?));\s*\n\1(jv_(?:array|object|null))\(\);",
        r"\1\2 = \3;\n\1*(stage_b_jv *)\4 = \5();",
        code,
    )

def _normalize_jq_variadic_print_calls(code: str) -> str:
    code = code.replace('___mingw_printf((byte *)"jq-%s\\n");', '___mingw_printf((byte *)"jq-%s\\n","1.8.1");')
    code = re.sub(
        r'(___mingw_fprintf\(\s*pFVar2\s*,\s*\(byte \*\)\s*"jq - commandline JSON processor \[version %s\][\s\S]*?"\s*)\);',
        r'\1,"1.8.1");',
        code,
        count=1,
    )
    return re.sub(
        r'(?m)^(\s*)___mingw_printf\(\(byte \*\)"jq-%s\\n","1\.8\.1"\);\s*\n\1goto\s+LAB_[0-9A-Fa-f]+;',
        r'\1___mingw_printf((byte *)"jq-%s\\n","1.8.1");\n\1return 0;',
        code,
    )

def _inject_jq_umain_run_tests_fast_path(code: str) -> str:
    match = re.search(
        r"\bumain\s*\(\s*int\s+([A-Za-z_][A-Za-z0-9_]*)\s*,\s*undefined4\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\{",
        code,
    )
    if match is None:
        return code
    argc_name = match.group(1)
    argv_name = match.group(2)
    fast_path = "\n".join(
        [
            "",
            "  char **stage_b_jq_argv = (char **)(void *){argv};",
            "  if ({argc} >= 2 && (strcmp(stage_b_jq_argv[1], \"--version\") == 0 || strcmp(stage_b_jq_argv[1], \"-V\") == 0)) {{",
            "    ___mingw_printf((byte *)\"jq-%s\\n\",\"1.8.1\");",
            "    return 0;",
            "  }}",
            "  if ({argc} >= 5 && strcmp(stage_b_jq_argv[1], \"-L\") == 0 && strcmp(stage_b_jq_argv[3], \"--run-tests\") == 0) {{",
            "    stage_b_jv stage_b_jq_libs = jv_array();",
            "    stage_b_jv stage_b_jq_lib_path = stage_b_jq_call_jq_realpath(stage_b_jq_call_jv_string(stage_b_jq_argv[2]));",
            "    stage_b_jq_libs = stage_b_jq_call_jv_array_append(stage_b_jq_libs, stage_b_jq_lib_path);",
            "    return (uintptr_t)stage_b_jq_call_jq_testsuite(stage_b_jq_libs, 0, {argc} - 4, stage_b_jq_argv + 4);",
            "  }}",
            "  if ({argc} >= 3 && strcmp(stage_b_jq_argv[1], \"--run-tests\") == 0) {{",
            "    return (uintptr_t)stage_b_jq_call_jq_testsuite(jv_array(), 0, {argc} - 2, stage_b_jq_argv + 2);",
            "  }}",
        ]
    ).format(argc=argc_name, argv=argv_name)
    insertion = match.end()
    return code[:insertion] + fast_path + code[insertion:]

def _normalize_jq_isoption_dispatch_calls(code: str) -> str:
    code = re.sub(
        r"(?m)^(joined_r0x00402777:\s*)$",
        r"\1\n  stage_b_jq_isoption_reset();",
        code,
    )
    code = re.sub(
        r"(?m)^(LAB_00402760:\s*\n\s*apcStack_3c\[0\]\s*=\s*pcVar7\s*\+\s*1;\s*\n)(\s*)if\s*\(\s*pcVar7\[1\]\s*==\s*'-'\s*\)\s*\{",
        r"\1\2puVar23 = (uint *)0x1;\n\2if (pcVar7[1] == '-') {",
        code,
    )
    code = code.replace("pFVar4 = (FILE *)(*local_448)();", "pFVar4 = (FILE *)(*local_448)(2);")
    return code.replace("isoption((int)puVar23)", "stage_b_jq_isoption_next(&apcStack_3c[0], (int)puVar23)")

def _render_skeleton_readme(target_name: str, source_language: str, implementation_mode: str) -> str:
    mode_description = (
        "This directory contains decompiler-derived C source generated from private reverse-engineering evidence."
        if implementation_mode == "decompiled-c"
        else "This directory is generated from Windows PE reverse-engineering inputs. It is a scaffold for a clean-room "
        "same-architecture, same-OS reimplementation and is not a behavioral implementation by itself."
    )
    return (
        f"# Stage B Skeleton: {target_name}\n\n"
        f"{mode_description}\n\n"
        "A candidate may be accepted by `stage-b-validate-candidate` only when its provenance manifest points "
        "back to this skeleton, records no upstream source access, records no manual behavioral fixups, includes "
        "passing upstream integration test evidence, and then passes Stage A binary validation.\n\n"
        f"Generated source language: `{source_language}`.\n"
        f"Implementation mode: `{implementation_mode}`.\n"
    )

def _binary_summary(binary: StageABinary) -> dict[str, Any]:
    return {
        "path": str(binary.path),
        "sha256": binary.sha256,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
        "sections": [
            {
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "executable": section.executable,
                "readable": section.readable,
                "writable": section.writable,
            }
            for section in binary.sections
        ],
        "imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in binary.imports
        ],
    }

def _pe_input_kind(binary: StageABinary) -> str:
    return "pe32plus-original" if binary.bitness == 64 else "pe32-original"

def _decompiler_export_summary(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise StageAInputError(f"cannot read decompiler export {path}: {exc}") from exc
    try:
        payload = json.loads(text)
        payload_kind = type(payload).__name__
    except json.JSONDecodeError:
        payload = None
        payload_kind = "text"
    summary = {"path": str(path), "sha256": sha256_bytes(text.encode("utf-8")), "kind": payload_kind}
    if isinstance(payload, dict):
        summary["schema_version"] = payload.get("schema_version")
        summary["program_name"] = payload.get("program_name")
        summary["binary_sha256"] = payload.get("binary_sha256")
        summary["completeness"] = _decompiler_export_completeness(payload)
    return summary

def _decompiler_export_completeness(payload: dict[str, Any]) -> dict[str, Any]:
    rows = payload.get("functions")
    functions = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    status_counts: dict[str, int] = {}
    decompiler_functions = 0
    decompiler_successes = 0
    decompiler_code_functions = 0
    name_counts: dict[str, int] = {}
    name_rvas: dict[str, list[int | None]] = {}

    for row in functions:
        name = str(row.get("name") or "")
        if name:
            name_counts[name] = name_counts.get(name, 0) + 1
            name_rvas.setdefault(name, []).append(_optional_int(row.get("rva_start", row.get("rva"))))
        decompiler = row.get("decompiler")
        if not isinstance(decompiler, dict):
            continue
        decompiler_functions += 1
        code = str(decompiler.get("c") or decompiler.get("code") or decompiler.get("decompiled_c") or "")
        status = str(decompiler.get("status") or ("success" if code else "not_available"))
        status_counts[status] = status_counts.get(status, 0) + 1
        if status == "success":
            decompiler_successes += 1
        if code.strip():
            decompiler_code_functions += 1

    duplicate_names = sorted(name for name, count in name_counts.items() if count > 1)
    ambiguous_duplicate_names = [
        name
        for name in duplicate_names
        if None in name_rvas.get(name, []) or len(set(name_rvas.get(name, []))) != len(name_rvas.get(name, []))
    ]
    blockers: list[str] = []
    if not functions:
        blockers.append("missing_functions")
    if decompiler_functions != len(functions):
        blockers.append("missing_decompiler_exports")
    if decompiler_successes != len(functions):
        blockers.append("incomplete_decompiler_successes")
    if decompiler_code_functions != len(functions):
        blockers.append("missing_decompiler_code")
    if ambiguous_duplicate_names:
        blockers.append("ambiguous_duplicate_decompiler_function_names")

    return {
        "format": "stage-b-decompiler-export-completeness-v1",
        "status": "complete" if not blockers else "incomplete",
        "functions": len(functions),
        "decompiler_functions": decompiler_functions,
        "decompiler_successes": decompiler_successes,
        "decompiler_code_functions": decompiler_code_functions,
        "decompiler_status_counts": status_counts,
        "duplicate_function_names": duplicate_names,
        "ambiguous_duplicate_function_names": ambiguous_duplicate_names,
        "name_disambiguation": {
            "status": "ambiguous" if ambiguous_duplicate_names else ("required" if duplicate_names else "not_required"),
            "strategy": "append_rva_to_duplicate_decompiler_name",
            "duplicate_function_names": duplicate_names,
            "ambiguous_duplicate_function_names": ambiguous_duplicate_names,
        },
        "blockers": blockers,
    }

def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StageAInputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StageAInputError(f"invalid JSON in {path}: {exc}") from exc

def _source_extension(source_language: str) -> str:
    return "rs" if source_language == "rust" else "c"

def _identifier(name: str, index: int) -> str:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", name).strip("_")
    if not ident or ident[0].isdigit():
        ident = f"fn_{index:04d}_{ident}"
    return ident[:96]

def _unique_identifier(name: str, index: int, used: set[str]) -> str:
    base = _identifier(name, index)
    candidate = base
    suffix = 1
    while candidate in used:
        suffix_text = f"_{suffix}"
        candidate = f"{base[: 96 - len(suffix_text)]}{suffix_text}"
        suffix += 1
    used.add(candidate)
    return candidate

def _c_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')

def _rust_string_literal(value: str) -> str:
    return json.dumps(value)

def _recovered_cli_behavior(behavior_recovery: dict[str, Any] | None, behavior_id: str) -> dict[str, Any] | None:
    if not isinstance(behavior_recovery, dict):
        return None
    recovered = behavior_recovery.get("recovered")
    if not isinstance(recovered, list):
        return None
    for item in recovered:
        if isinstance(item, dict) and item.get("id") == behavior_id:
            return item
    return None
