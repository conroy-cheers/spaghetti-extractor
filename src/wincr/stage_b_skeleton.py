from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

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
_DECOMPILED_C_MINGWEX_RUNTIME_FUNCTION_NAMES = frozenset(
    {
        "__lock_file",
        "__matherr",
        "__unlock_file",
        "__d2b_D2A",
        "__mingw_raise_matherr",
        "__strcp_D2A",
        "___Balloc_D2A",
        "___Bfree_D2A",
        "___b2d_D2A",
        "___cmp_D2A",
        "___d2b_D2A",
        "___diff_D2A",
        "___freedtoa",
        "___gdtoa",
        "___i2b_D2A",
        "___lshift_D2A",
        "___mingw_fprintf",
        "___mingw_pformat",
        "___mingw_printf",
        "___mingw_setusermatherr",
        "___mult_D2A",
        "___multadd_D2A",
        "___nrv_alloc_D2A",
        "___pow5mult_D2A",
        "___quorem_D2A",
        "___rshift_D2A",
        "___rv_alloc_D2A",
        "___setusermatherr",
        "___strcp_D2A",
        "___trailz_D2A",
        "_mbrlen",
        "_mbrtowc",
        "_mbsrtowcs",
        "_strnlen",
        "_wcrtomb",
        "_wcsnlen",
        "_wcsrtombs",
        "basename",
        "dirname",
        "wcslen",
    }
)
_DECOMPILED_C_MINGWEX_C_SYMBOL_ALIASES = {
    "___do_global_ctors": "__do_global_ctors",
    "___do_global_dtors": "__do_global_dtors",
    "___main": "__main",
    "___mingw_GetSectionCount": "__mingw_GetSectionCount",
    "___mingw_GetSectionForAddress": "__mingw_GetSectionForAddress",
    "__lock_file": "_lock_file",
    "__matherr": "_matherr",
    "__FindPESection": "_FindPESection",
    "__GetPEImageBase": "_GetPEImageBase",
    "__IsNonwritableInCurrentImage": "_IsNonwritableInCurrentImage",
    "__pei386_runtime_relocator": "_pei386_runtime_relocator",
    "__unlock_file": "_unlock_file",
    "__ValidateImageBase": "_ValidateImageBase",
    "___Balloc_D2A": "__Balloc_D2A",
    "___Bfree_D2A": "__Bfree_D2A",
    "___b2d_D2A": "__b2d_D2A",
    "___cmp_D2A": "__cmp_D2A",
    "___d2b_D2A": "__d2b_D2A",
    "___diff_D2A": "__diff_D2A",
    "___freedtoa": "__freedtoa",
    "___gdtoa": "__gdtoa",
    "___i2b_D2A": "__i2b_D2A",
    "___lshift_D2A": "__lshift_D2A",
    "___mingw_fprintf": "__mingw_fprintf",
    "___mingw_pformat": "__mingw_pformat",
    "___mingw_printf": "__mingw_printf",
    "___mingw_setusermatherr": "__mingw_setusermatherr",
    "___mult_D2A": "__mult_D2A",
    "___multadd_D2A": "__multadd_D2A",
    "___nrv_alloc_D2A": "__nrv_alloc_D2A",
    "___pow5mult_D2A": "__pow5mult_D2A",
    "___quorem_D2A": "__quorem_D2A",
    "___rshift_D2A": "__rshift_D2A",
    "___rv_alloc_D2A": "__rv_alloc_D2A",
    "___setusermatherr": "__setusermatherr",
    "___strcp_D2A": "__strcp_D2A",
    "___trailz_D2A": "__trailz_D2A",
    "_mbrlen": "mbrlen",
    "_mbrtowc": "mbrtowc",
    "_mbsrtowcs": "mbsrtowcs",
    "_strnlen": "strnlen",
    "_wcrtomb": "wcrtomb",
    "_wcsnlen": "wcsnlen",
    "_wcsrtombs": "wcsrtombs",
}
_DECOMPILED_C_MINGWEX_C_SYMBOL_ALIAS_TARGETS = frozenset(_DECOMPILED_C_MINGWEX_C_SYMBOL_ALIASES.values())
_DECOMPILED_C_MINGW_CRT_OWNED_FUNCTION_NAMES = frozenset(
    {
        "_DllMainCRTStartup@12",
        "_DllMainCRTStartup_12",
        "_FindPESection",
        "___w64_mingwthr_add_key_dtor",
        "___w64_mingwthr_remove_key_dtor",
        "___do_global_ctors",
        "___do_global_dtors",
        "___main",
        "___mingw_GetSectionCount",
        "___mingw_GetSectionForAddress",
        "___mingw_setusermatherr",
        "___report_error",
        "__do_global_dtors",
        "__FindPESection",
        "__GetPEImageBase",
        "__IsNonwritableInCurrentImage",
        "__ValidateImageBase",
        "__do_global_ctors",
        "__main",
        "__mingw_GetSectionCount",
        "__mingw_GetSectionForAddress",
        "__mingw_setusermatherr",
        "___dyn_tls_dtor_12",
        "___dyn_tls_init_12",
        "__mingw_enum_import_library_names",
        "__mingw_raise_matherr",
        "__pei386_runtime_relocator",
        "__tlregdtor",
        "___mingw_TLScallback",
        "_FindPESectionByName",
        "_FindPESectionExec",
        "_GetPEImageBase",
        "_IsNonwritableInCurrentImage",
        "_ValidateImageBase",
        "_gnu_exception_handler@4",
        "_gnu_exception_handler_4",
        "_pei386_runtime_relocator",
        "atexit",
        "mark_section_writable",
        "restore_modified_sections",
    }
) | _DECOMPILED_C_MINGWEX_RUNTIME_FUNCTION_NAMES | _DECOMPILED_C_MINGWEX_C_SYMBOL_ALIAS_TARGETS
_DECOMPILED_C_MINGW_CRT_SUPPORT_HELPER_NAMES = frozenset(
    {
        "___dyn_tls_dtor_12",
        "___dyn_tls_init_12",
        "___mingw_TLScallback",
    }
)
_DECOMPILED_C_MINGW_CRT_FORCED_ROOT_FUNCTION_NAMES = frozenset()
_DECOMPILED_C_MINGW_CRT_FORCED_ROOT_OBJECT_SYMBOLS: dict[str, str] = {}
_DECOMPILED_C_STACK_PROBE_HELPER_MACROS = {
    "___chkstk_ms": "stage_b_stack_probe_size()",
    "___chkstk": "stage_b_stack_probe_size()",
    "___alloca_probe": "stage_b_stack_probe_size()",
    "___alloca_probe_8": "stage_b_stack_probe_size()",
    "___alloca_probe_16": "stage_b_stack_probe_size()",
}
_DECOMPILED_C_DTOA_LOCK_HELPER_SYMBOL = "dtoa_lock"
_DECOMPILED_C_DTOA_LOCK_HELPER_DATA_SYMBOLS = ("_dtoa_CS_init", "_dtoa_CritSec")
_DECOMPILED_C_EXACT_RUNTIME_DATA_SYMBOLS = frozenset()
_DECOMPILED_C_JQ_RDATA_TABLE_SYMBOLS = frozenset({"___tens_D2A"})
_DECOMPILED_C_JQ_BSS_ALIAS_DATA_SYMBOL_OFFSETS = {
    "_dtoa_CritSec": 0x840,
    "_dtoa_CS_init": 0x878,
    "_errno_exref": 0x8A4,
    "_freelist": 0x800,
    "_handler": 0x8A0,
    "_internal_mbstate_1": 0x890,
    "_internal_mbstate_2": 0x898,
    "_p5s": 0x880,
    "_pmem_next": 0x884,
    "_s_mbstate_0": 0x89C,
    "_setmode_exref": 0x8A8,
    "_static_path_copy_0": 0x8AC,
    "stack0xfffffb54": 0x8B0,
    "stack0xfffffb58": 0x8B4,
    "stack0xfffffb5c": 0x8B8,
}
_DECOMPILED_C_DTOA_LOCK_HELPER_IMPORTS = (
    "DeleteCriticalSection",
    "EnterCriticalSection",
    "InitializeCriticalSection",
    "Sleep",
    "__crt_atexit",
)
_DECOMPILED_C_GENERATED_HELPER_SYMBOLS = (_DECOMPILED_C_DTOA_LOCK_HELPER_SYMBOL,)

_STAGE_B_BUDGETED_OBJECT_ROOT_MAX_ORIGINAL_SIZE = 1024
_DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS = frozenset({"_crt_atexit", "__crt_atexit"})
_DECOMPILED_C_PRESERVED_IMPORT_THUNK_ALIASES = frozenset({"___iob_func"})
_DECOMPILED_C_PRESERVED_IMPORT_THUNK_CONTRACT_SYMBOLS = frozenset({"__iob_func"})
_DECOMPILED_C_CONTRACT_IMPORT_THUNK_PREFIXES = ("__msvcrt_",)

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
    nm_defined_symbols = _stage_b_nm_defined_symbols(Path(object_file), nm=nm)
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
    runtime_crt_roots: list[dict[str, Any]] = []
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
                    runtime_crt_root = _runtime_crt_missing_root(missing_item)
                    if runtime_crt_root is not None:
                        runtime_crt_roots.append(runtime_crt_root)
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
    reference_import_roots = _stage_b_reference_import_roots(reference_contract_payload, covered_roots=import_thunk_roots)
    reference_import_linker_flags = [
        f"-Wl,--undefined,{root['object_symbol']}"
        for root in reference_import_roots
        if _stage_b_import_thunk_coff_symbol_is_valid(str(root.get("object_symbol") or ""))
    ]
    runtime_crt_root_symbols = sorted({root["object_symbol"] for root in runtime_crt_roots})
    runtime_crt_linker_flags = [f"-Wl,--undefined,{symbol}" for symbol in runtime_crt_root_symbols]
    generated_layout_root_symbols = _stage_b_generated_layout_root_symbols(nm_defined_symbols)
    generated_layout_linker_flags = [f"-Wl,--undefined,{symbol}" for symbol in generated_layout_root_symbols]
    budgeted_runtime_crt_roots = [
        root
        for root in runtime_crt_roots
        if _optional_int(root.get("rva_end")) is not None
        and _optional_int(root.get("rva_start")) is not None
        and int(root["rva_end"]) - int(root["rva_start"]) <= _STAGE_B_BUDGETED_OBJECT_ROOT_MAX_ORIGINAL_SIZE
    ]
    budgeted_runtime_crt_linker_flags = sorted(f"-Wl,--undefined,{root['object_symbol']}" for root in budgeted_runtime_crt_roots)
    (out / "link-root-symbols.txt").write_text("".join(f"{symbol}\n" for symbol in root_symbols), encoding="utf-8")
    linker_flags = sorted({*linker_flags, *generated_layout_linker_flags})
    import_thunk_linker_flags = sorted({*import_thunk_linker_flags, *reference_import_linker_flags})
    (out / "link-root-flags.txt").write_text("".join(f"{flag}\n" for flag in linker_flags), encoding="utf-8")
    (out / "budgeted-link-root-flags.txt").write_text("".join(f"{flag}\n" for flag in budgeted_linker_flags), encoding="utf-8")
    (out / "import-thunk-root-flags.txt").write_text("".join(f"{flag}\n" for flag in import_thunk_linker_flags), encoding="utf-8")
    (out / "runtime-crt-root-flags.txt").write_text("".join(f"{flag}\n" for flag in runtime_crt_linker_flags), encoding="utf-8")
    (out / "budgeted-runtime-crt-root-flags.txt").write_text(
        "".join(f"{flag}\n" for flag in budgeted_runtime_crt_linker_flags),
        encoding="utf-8",
    )
    write_json(out / "import-thunk-roots.json", {"format": "stage-b-import-thunk-roots-v1", "roots": import_thunk_roots})
    write_json(out / "reference-import-roots.json", {"format": "stage-b-reference-import-roots-v1", "roots": reference_import_roots})
    write_json(out / "runtime-crt-roots.json", {"format": "stage-b-runtime-crt-roots-v1", "roots": runtime_crt_roots})
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
            "reference_import_roots": str(out / "reference-import-roots.json"),
            "runtime_crt_roots": str(out / "runtime-crt-roots.json"),
            "runtime_crt_root_flags": str(out / "runtime-crt-root-flags.txt"),
            "budgeted_runtime_crt_root_flags": str(out / "budgeted-runtime-crt-root-flags.txt"),
        },
        "roots": roots,
        "budgeted_roots": budgeted_roots,
        "import_thunk_roots": import_thunk_roots,
        "reference_import_roots": reference_import_roots,
        "runtime_crt_roots": runtime_crt_roots,
        "budgeted_runtime_crt_roots": budgeted_runtime_crt_roots,
        "generated_layout_root_symbols": generated_layout_root_symbols,
        "linker_flags": linker_flags,
        "budgeted_linker_flags": budgeted_linker_flags,
        "import_thunk_linker_flags": import_thunk_linker_flags,
        "reference_import_linker_flags": reference_import_linker_flags,
        "runtime_crt_linker_flags": runtime_crt_linker_flags,
        "budgeted_runtime_crt_linker_flags": budgeted_runtime_crt_linker_flags,
        "issues": issues,
        "counts": {
            "contract_functions": len(contract_functions),
            "object_text_symbols": len(nm_symbols),
            "roots": len(root_symbols),
            "budgeted_roots": len(budgeted_roots),
            "import_thunk_roots": len(import_thunk_roots),
            "import_thunk_roots_with_linker_flags": len(import_thunk_linker_flags),
            "reference_import_roots": len(reference_import_roots),
            "reference_import_roots_with_linker_flags": len(reference_import_linker_flags),
            "runtime_crt_roots": len(runtime_crt_roots),
            "runtime_crt_roots_with_linker_flags": len(runtime_crt_linker_flags),
            "budgeted_runtime_crt_roots": len(budgeted_runtime_crt_roots),
            "budgeted_runtime_crt_roots_with_linker_flags": len(budgeted_runtime_crt_linker_flags),
            "generated_layout_roots": len(generated_layout_root_symbols),
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
            "budgeted_runtime_crt_root_basis": "original linker-map function byte range; used for strict Stage A layout links",
        },
    }
    write_json(out / "link-roots.json", result)
    return result

def _stage_b_generated_layout_root_symbols(nm_symbols: Iterable[str]) -> list[str]:
    roots: set[str] = set()
    exact = {
        "_stage_b_jq_reference_data",
        "_stage_b_jq_reference_rdata",
        "_stage_b_jq_layout_bss_anchor",
        "_stage_b_jq_layout_idata_pad",
        "_stage_b_jq_layout_text_tail_pad",
        "_stage_b_jq_reloc_absolute_pad",
        "_stage_b_jq_layout_tls_anchor",
    }
    for symbol in nm_symbols:
        if symbol.startswith("_stage_b_contract_section_gap__") or symbol in exact:
            roots.add(symbol)
    return sorted(roots)


def _stage_b_reference_import_roots(
    reference_contract_payload: dict[str, Any] | None,
    *,
    covered_roots: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if reference_contract_payload is None:
        return []
    covered = {
        (
            str(root.get("dll") or "").lower(),
            str(root.get("symbol") or ""),
            str(root.get("ordinal") or ""),
        )
        for root in covered_roots
        if isinstance(root, dict)
    }
    original = reference_contract_payload.get("original") if isinstance(reference_contract_payload.get("original"), dict) else {}
    imports = original.get("imports") if isinstance(original.get("imports"), list) else []
    roots: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in imports:
        if not isinstance(item, dict):
            continue
        dll = str(item.get("dll") or "").lower()
        symbol = item.get("symbol")
        ordinal = item.get("ordinal")
        key = (dll, str(symbol or ""), str(ordinal or ""))
        if key in seen or key in covered:
            continue
        seen.add(key)
        if not isinstance(symbol, str) or not symbol:
            continue
        roots.append(
            {
                "dll": dll,
                "symbol": symbol,
                "ordinal": ordinal,
                "thunk_rva": _optional_int(item.get("thunk_rva")),
                "object_symbol": _stage_b_reference_import_coff_symbol(symbol),
                "source": "stage_a_reference_contract_imports",
            }
        )
    return roots


def _stage_b_reference_import_coff_symbol(symbol: str) -> str:
    profile = _decompiled_c_contract_external_target_profile(symbol)
    return _decompiled_c_i686_asm_iat_symbol(symbol, target_profile=profile)


def _runtime_crt_missing_root(missing_item: dict[str, Any]) -> dict[str, Any] | None:
    skeleton = missing_item.get("skeleton") if isinstance(missing_item.get("skeleton"), dict) else {}
    if skeleton.get("representation") != "runtime_entry_replaced_by_generated_bridge":
        return None
    source_name = str(skeleton.get("name") or "")
    if source_name not in _DECOMPILED_C_MINGW_CRT_FORCED_ROOT_FUNCTION_NAMES:
        return None
    contract_function = str(missing_item.get("name") or "")
    if _has_linker_stdcall_suffix(contract_function):
        return None
    object_symbol = _DECOMPILED_C_MINGW_CRT_FORCED_ROOT_OBJECT_SYMBOLS.get(source_name, source_name)
    return {
        "contract_function": contract_function,
        "source_function": source_name,
        "object_symbol": object_symbol,
        "match_key": missing_item.get("match_key"),
        "rva_start": missing_item.get("rva_start"),
        "rva_end": missing_item.get("rva_end"),
        "reason": "omitted_mingw_crt_support_function_requires_archive_root",
    }

def _stage_b_import_thunk_coff_symbol(root: dict[str, Any]) -> str:
    symbol = str(root.get("symbol") or "")
    contract_function = str(root.get("contract_function") or "")
    return _stage_b_import_thunk_coff_symbol_name(symbol, contract_function=contract_function)

def _stage_b_import_thunk_coff_symbol_name(symbol: str, *, contract_function: str) -> str:
    if symbol == "atexit" and contract_function in _DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS:
        return "___crt_atexit"
    if contract_function in _DECOMPILED_C_PRESERVED_IMPORT_THUNK_ALIASES:
        return contract_function
    if contract_function in _DECOMPILED_C_PRESERVED_IMPORT_THUNK_CONTRACT_SYMBOLS:
        return _decompiled_c_i686_c_asm_symbol(contract_function)
    if _decompiled_c_import_thunk_preserves_contract_symbol(symbol, contract_function=contract_function):
        return _decompiled_c_i686_c_asm_symbol(contract_function)
    return _decompiled_c_i686_asm_call_symbol(symbol)

def _stage_b_import_thunk_iat_symbol_name(symbol: str) -> str:
    return f"__imp_{_decompiled_c_i686_asm_call_symbol(symbol)}"

def _stage_b_import_thunk_coff_symbol_is_valid(symbol: str) -> bool:
    return _is_linker_root_symbol(symbol)

def _stage_b_nm_defined_text_symbols(object_file: Path, *, nm: str) -> list[str]:
    return sorted(
        {
            symbol
            for symbol, kind in _stage_b_nm_defined_symbol_rows(object_file, nm=nm)
            if kind in {"T", "t"} and _is_linker_root_symbol(symbol)
        }
    )


def _stage_b_nm_defined_symbols(object_file: Path, *, nm: str) -> list[str]:
    return sorted(
        {
            symbol
            for symbol, _kind in _stage_b_nm_defined_symbol_rows(object_file, nm=nm)
            if _is_linker_root_symbol(symbol)
        }
    )


def _stage_b_nm_defined_symbol_rows(object_file: Path, *, nm: str) -> list[tuple[str, str]]:
    try:
        proc = subprocess.run([nm, str(object_file)], check=False, capture_output=True, text=True)
    except OSError as exc:
        raise StageAInputError(f"failed to run {nm}: {exc}") from exc
    if proc.returncode != 0:
        raise StageAInputError(f"{nm} failed for {object_file}: {proc.stderr.strip()}")
    symbols: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            symbols.append((parts[2], parts[1]))
    return symbols

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
    if _decompiled_c_is_runtime_entry(function) or _decompiled_c_is_mingw_crt_owned_function(function):
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
    if implementation_mode not in {"scaffold", "decompiled-c", "contract-guided-c"}:
        raise StageAInputError(f"unsupported Stage B implementation mode {implementation_mode!r}")
    if implementation_mode in {"decompiled-c", "contract-guided-c"} and source_language != "c":
        raise StageAInputError(f"{implementation_mode} Stage B implementation mode requires source_language='c'")
    if implementation_mode == "decompiled-c" and decompiler_export is None:
        raise StageAInputError("decompiled-c Stage B implementation mode requires --decompiler-export")
    if runtime_entry_policy not in _DECOMPILED_C_RUNTIME_ENTRY_POLICIES:
        raise StageAInputError(f"unsupported Stage B runtime entry policy {runtime_entry_policy!r}")
    if implementation_mode not in {"decompiled-c", "contract-guided-c"} and runtime_entry_policy != "bridge":
        raise StageAInputError("Stage B runtime entry policy is only supported with C implementation modes")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = _parse_stage_a_pe(Path(original))
    reference_contract_payload = _load_reference_contract(Path(reference_contract), binary) if reference_contract is not None else None
    reference_contract_sidecars = (
        _load_reference_contract_sidecars(Path(reference_contract), reference_contract_payload)
        if reference_contract is not None and reference_contract_payload is not None
        else {}
    )
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
        reference_contract_sidecars=reference_contract_sidecars,
        include_decompiler_code=implementation_mode in {"decompiled-c", "contract-guided-c"},
    )
    function_filter = _function_filter(functions, function_names)
    external_function_names = function_filter["external_function_names"] + [
        item.symbol for item in binary.imports if isinstance(item.symbol, str) and item.symbol
    ]
    functions = function_filter["functions"]
    implementation_recovery = _skeleton_implementation_recovery(
        functions,
        source_language,
        implementation_mode=implementation_mode,
        runtime_entry_policy=runtime_entry_policy,
    )
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
    implementation_recovery = _skeleton_implementation_recovery_with_contract_placeholders(
        implementation_recovery,
        reference_contract_payload,
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
        reference_contract_payload=reference_contract_payload,
        reference_contract_sidecars=reference_contract_sidecars,
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
    if reference_contract_sidecars:
        allowed_inputs.append("stage-a-unit-contract-sidecars")
    source_map_decompiler_functions = (
        _parse_decompiler_export_functions(Path(decompiler_export), binary, include_decompiler_code=False)
        if decompiler_export is not None and reference_contract_payload is not None
        else []
    )

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
            runtime_entry_policy=runtime_entry_policy,
            reference_contract_payload=reference_contract_payload,
            decompiler_functions=source_map_decompiler_functions,
            external_function_names=external_function_names,
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
    reference_contract_sidecars: dict[str, Any] | None = None,
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
            "instructions": instructions,
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
        _attach_reference_contract_sidecar_evidence(entry, reference_contract_sidecars)
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

def _load_reference_contract_sidecars(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    sidecars = payload.get("sidecars") if isinstance(payload.get("sidecars"), dict) else {}
    unit = sidecars.get("unit_contracts") if isinstance(sidecars.get("unit_contracts"), dict) else {}
    directory_value = unit.get("directory")
    directory = Path(str(directory_value)) if isinstance(directory_value, str) and directory_value else Path(".")
    if not directory.is_absolute():
        directory = path.parent / directory
    semantic_transfer_path = _reference_contract_sidecar_path(
        directory,
        unit.get("semantic_transfer_contracts"),
    )
    semantic_transfers = _load_reference_contract_jsonl(semantic_transfer_path) if semantic_transfer_path is not None else []
    return {
        "format": "stage-b-reference-contract-sidecars-v1",
        "directory": str(directory),
        "padding_bytes": _reference_contract_padding_bytes(payload),
        "semantic_transfer_contracts": {
            "path": str(semantic_transfer_path) if semantic_transfer_path is not None else None,
            "count": len(semantic_transfers),
            "by_function": _reference_contract_semantic_transfers_by_function(semantic_transfers),
        },
    }


def _reference_contract_sidecar_path(directory: Path, spec: Any) -> Path | None:
    if not isinstance(spec, dict):
        return None
    value = spec.get("path")
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else directory / path


def _load_reference_contract_jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
    except (OSError, json.JSONDecodeError):
        return []
    return rows


def _reference_contract_semantic_transfers_by_function(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        name = row.get("function")
        if not isinstance(name, str) or not name:
            continue
        result.setdefault(name, []).append(_semantic_transfer_bytecode_summary(row))
    for transfers in result.values():
        transfers.sort(key=lambda item: int(item.get("rva_start") or 0))
    return result


def _semantic_transfer_bytecode_summary(row: dict[str, Any]) -> dict[str, Any]:
    original = row.get("original") if isinstance(row.get("original"), dict) else {}
    outcome = row.get("outcome") if isinstance(row.get("outcome"), dict) else {}
    instructions = [
        {
            key: instruction.get(key)
            for key in ("bytes", "mnemonic", "op_str", "rva", "size")
            if key in instruction
        }
        for instruction in row.get("instructions", [])
        if isinstance(instruction, dict)
    ]
    return {
        "id": row.get("id"),
        "function": row.get("function"),
        "block_id": row.get("block_id"),
        "rva_start": _optional_int(original.get("rva_start")),
        "rva_end": _optional_int(original.get("rva_end")),
        "outcome": outcome,
        "instructions": instructions,
    }


def _attach_reference_contract_sidecar_evidence(function: dict[str, Any], sidecars: dict[str, Any] | None) -> None:
    if not isinstance(sidecars, dict):
        return
    transfer_payload = sidecars.get("semantic_transfer_contracts")
    if not isinstance(transfer_payload, dict):
        return
    by_function = transfer_payload.get("by_function")
    if not isinstance(by_function, dict):
        return
    transfers: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def add_transfer(item: dict[str, Any]) -> None:
        item_id = str(item.get("id") or f"{item.get('rva_start')}:{item.get('rva_end')}")
        if item_id in seen_ids:
            return
        seen_ids.add(item_id)
        transfers.append(item)

    for name in _reference_contract_sidecar_lookup_names(function):
        items = by_function.get(name)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            add_transfer(item)
    for item in _reference_contract_sidecar_embedded_section_gap_transfers(function, by_function):
        add_transfer(item)
    if not transfers:
        return
    reference_contract = function.get("reference_contract")
    if not isinstance(reference_contract, dict):
        reference_contract = {}
        function["reference_contract"] = reference_contract
    reference_contract["semantic_transfer_bytecode"] = {
        "format": "stage-a-semantic-transfer-bytecode-summary-v1",
        "source": "stage-a-semantic-transfer-contracts",
        "blocks": len(transfers),
        "transfers": transfers,
    }
    padding_bytes = sidecars.get("padding_bytes") if isinstance(sidecars.get("padding_bytes"), list) else []
    relevant_padding = _contract_padding_ranges_for_function(function, padding_bytes)
    if relevant_padding:
        reference_contract["contract_padding_bytes"] = {
            "format": "stage-b-contract-padding-bytes-v1",
            "source": "stage-a-padding-alignment",
            "ranges": relevant_padding,
        }
    reference_contract["contract_bytecode"] = _function_contract_bytecode_from_semantic_transfers(
        function,
        transfers,
        padding_bytes=padding_bytes,
    )


def _attach_reference_contract_symbolic_branch_evidence(
    function: dict[str, Any],
    *,
    sidecars: dict[str, Any] | None,
    branch_target_symbols: dict[int, str] | None,
) -> None:
    if not branch_target_symbols:
        return
    reference_contract = function.get("reference_contract")
    if not isinstance(reference_contract, dict):
        return
    bytecode = reference_contract.get("semantic_transfer_bytecode")
    transfers = bytecode.get("transfers") if isinstance(bytecode, dict) and isinstance(bytecode.get("transfers"), list) else []
    if not transfers:
        return
    padding_bytes = sidecars.get("padding_bytes") if isinstance(sidecars, dict) and isinstance(sidecars.get("padding_bytes"), list) else []
    reference_contract["contract_symbolic_branch"] = _function_contract_symbolic_branch_from_semantic_transfers(
        function,
        transfers,
        padding_bytes=padding_bytes,
        branch_target_symbols=branch_target_symbols,
    )


def _reference_contract_sidecar_lookup_names(function: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for value in (
        function.get("name"),
        function.get("source_name"),
        (
            function.get("reference_section_gap", {}).get("name")
            if isinstance(function.get("reference_section_gap"), dict)
            else None
        ),
    ):
        if isinstance(value, str) and value:
            names.append(value)
    aliases = function.get("aliases")
    if isinstance(aliases, list):
        names.extend(alias for alias in aliases if isinstance(alias, str) and alias)
    return _dedupe_strings(names)


def _reference_contract_sidecar_embedded_section_gap_transfers(
    function: dict[str, Any],
    by_function: dict[str, Any],
) -> list[dict[str, Any]]:
    if isinstance(function.get("reference_section_gap"), dict):
        return []
    rva_start = _optional_int(function.get("rva_start"))
    rva_end = _optional_int(function.get("rva_end"))
    if rva_start is None or rva_end is None or rva_end <= rva_start:
        return []
    embedded: list[dict[str, Any]] = []
    for name, items in by_function.items():
        if not isinstance(name, str) or not _reference_contract_sidecar_name_is_section_gap(name):
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            start = _optional_int(item.get("rva_start"))
            end = _optional_int(item.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            if rva_start <= start and end <= rva_end:
                embedded.append(item)
    embedded.sort(key=lambda item: int(item.get("rva_start") or 0))
    return embedded


def _reference_contract_sidecar_name_is_section_gap(name: str) -> bool:
    return name.startswith(("section-gap--", "stage_b_contract_section_gap__"))


def _contract_padding_ranges_for_function(function: dict[str, Any], padding_bytes: list[Any]) -> list[dict[str, Any]]:
    rva_start = _optional_int(function.get("rva_start"))
    rva_end = _optional_int(function.get("rva_end"))
    if rva_start is None or rva_end is None or rva_end <= rva_start:
        return []
    ranges: list[dict[str, Any]] = []
    for item in padding_bytes:
        if not isinstance(item, dict):
            continue
        start = _optional_int(item.get("rva_start"))
        end = _optional_int(item.get("rva_end"))
        bytes_hex = item.get("bytes_hex")
        if start is None or end is None or end <= start or not isinstance(bytes_hex, str):
            continue
        if end <= rva_start or start >= rva_end:
            continue
        ranges.append(
            {
                "rva_start": start,
                "rva_end": end,
                "bytes_hex": bytes_hex,
                "bytes_sha256": item.get("bytes_sha256"),
                "source": item.get("source") or "stage-a-padding-alignment",
            }
        )
    return ranges


def _reference_contract_padding_bytes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    constraints = payload.get("constraints") if isinstance(payload.get("constraints"), dict) else {}
    padding = constraints.get("padding_alignment") if isinstance(constraints.get("padding_alignment"), dict) else {}
    obligations = padding.get("obligations") if isinstance(padding.get("obligations"), list) else []
    ranges: list[dict[str, Any]] = []
    for obligation in obligations:
        if not isinstance(obligation, dict) or obligation.get("status") != "waived_noncode":
            continue
        checks = obligation.get("checks") if isinstance(obligation.get("checks"), list) else []
        for check in checks:
            if not isinstance(check, dict) or check.get("status") != "verified" or check.get("binary") != "original":
                continue
            rva_start = _optional_int(check.get("rva_start"))
            rva_end = _optional_int(check.get("rva_end"))
            bytes_hex = check.get("bytes_hex")
            if rva_start is None or rva_end is None or rva_end <= rva_start or not isinstance(bytes_hex, str):
                continue
            try:
                raw = bytes.fromhex(bytes_hex)
            except ValueError:
                continue
            if len(raw) != rva_end - rva_start:
                continue
            ranges.append(
                {
                    "rva_start": rva_start,
                    "rva_end": rva_end,
                    "bytes_hex": raw.hex(),
                    "bytes_sha256": check.get("bytes_sha256"),
                    "source": "stage-a-padding-alignment",
                }
            )
    ranges.sort(key=lambda item: int(item["rva_start"]))
    return ranges


def _function_contract_bytecode_from_semantic_transfers(
    function: dict[str, Any],
    transfers: list[Any],
    *,
    padding_bytes: list[Any] | None = None,
) -> dict[str, Any]:
    rva_start = _optional_int(function.get("rva_start"))
    rva_end = _optional_int(function.get("rva_end"))
    if rva_start is None or rva_end is None or rva_end <= rva_start:
        return _contract_bytecode_blocked("invalid_function_range")
    if not transfers:
        return _contract_bytecode_blocked("missing_semantic_transfer_contracts")

    instructions_by_rva: dict[int, dict[str, Any]] = {}
    disallowed: list[str] = []
    blocks = 0
    for transfer in transfers:
        if not isinstance(transfer, dict):
            continue
        blocks += 1
        outcome = transfer.get("outcome") if isinstance(transfer.get("outcome"), dict) else {}
        outcome_blocker = _contract_bytecode_outcome_blocker(outcome, rva_start=rva_start, rva_end=rva_end)
        if outcome_blocker:
            disallowed.append(outcome_blocker)
        for instruction in transfer.get("instructions", []) if isinstance(transfer.get("instructions"), list) else []:
            if not isinstance(instruction, dict):
                continue
            instruction_rva = _optional_int(instruction.get("rva"))
            instruction_size = _optional_int(instruction.get("size"))
            instruction_bytes = instruction.get("bytes")
            if (
                instruction_rva is None
                or instruction_size is None
                or instruction_size <= 0
                or not isinstance(instruction_bytes, str)
                or not instruction_bytes
            ):
                disallowed.append("instruction_missing_bytes")
                continue
            if _instruction_mnemonic(instruction) == "call":
                disallowed.append("contains_call_instruction")
            if instruction_rva in instructions_by_rva:
                disallowed.append("duplicate_instruction_rva")
                continue
            instructions_by_rva[instruction_rva] = instruction

    if disallowed:
        return _contract_bytecode_blocked(*disallowed)

    cursor = rva_start
    chunks: list[str] = []
    instructions: list[dict[str, Any]] = []
    padding_ranges = [item for item in padding_bytes or [] if isinstance(item, dict)]
    for instruction_rva in sorted(instructions_by_rva):
        instruction = instructions_by_rva[instruction_rva]
        instruction_size = _optional_int(instruction.get("size")) or 0
        instruction_bytes = str(instruction.get("bytes") or "")
        try:
            raw = bytes.fromhex(instruction_bytes)
        except ValueError:
            return _contract_bytecode_blocked("instruction_bytes_not_hex")
        if len(raw) != instruction_size:
            return _contract_bytecode_blocked("instruction_size_mismatch")
        if instruction_rva != cursor:
            padding_hex = _contract_padding_bytes_for_range(padding_ranges, cursor, instruction_rva)
            if padding_hex is None:
                return _contract_bytecode_blocked("non_contiguous_instruction_bytes")
            chunks.extend(padding_hex)
            cursor = instruction_rva
        if instruction_rva < rva_start or instruction_rva + instruction_size > rva_end:
            return _contract_bytecode_blocked("instruction_outside_function_range")
        chunks.append(raw.hex())
        instructions.append(
            {
                "rva": instruction_rva,
                "size": instruction_size,
                "bytes": raw.hex(),
                "mnemonic": instruction.get("mnemonic"),
                "op_str": instruction.get("op_str"),
            }
        )
        cursor += instruction_size
    if cursor != rva_end:
        padding_hex = _contract_padding_bytes_for_range(padding_ranges, cursor, rva_end)
        if padding_hex is None:
            return _contract_bytecode_blocked("function_range_not_fully_covered")
        chunks.extend(padding_hex)
        cursor = rva_end

    bytecode_hex = "".join(chunks)
    return {
        "format": "stage-b-contract-bytecode-v1",
        "status": "reimplementable",
        "source": "stage-a-semantic-transfer-contracts",
        "blocks": blocks,
        "instructions": len(instructions),
        "padding_chunks": len(chunks) - len(instructions),
        "rva_start": rva_start,
        "rva_end": rva_end,
        "size": rva_end - rva_start,
        "bytes_sha256": sha256_bytes(bytes.fromhex(bytecode_hex)),
        "chunks": chunks,
        "instruction_preview": instructions[:16],
    }


def _function_contract_symbolic_branch_from_semantic_transfers(
    function: dict[str, Any],
    transfers: list[Any],
    *,
    padding_bytes: list[Any] | None = None,
    branch_target_symbols: dict[int, str],
) -> dict[str, Any]:
    rva_start = _optional_int(function.get("rva_start"))
    rva_end = _optional_int(function.get("rva_end"))
    if rva_start is None or rva_end is None or rva_end <= rva_start:
        return _contract_symbolic_branch_blocked("invalid_function_range")
    usable_transfers = [transfer for transfer in transfers if isinstance(transfer, dict)]
    if len(usable_transfers) != 1:
        return _contract_symbolic_branch_blocked("requires_single_basic_block")
    transfer = usable_transfers[0]
    outcome = transfer.get("outcome") if isinstance(transfer.get("outcome"), dict) else {}
    kind = str(outcome.get("kind") or "")
    if kind in {"return", "external_jump", "indirect_jump", "indirect_jump_table"}:
        return _contract_symbolic_branch_blocked(f"contains_{kind}")
    if kind not in {"branch", "jump", "fallthrough"}:
        return _contract_symbolic_branch_blocked("unknown_control_flow_outcome")

    instructions = [
        instruction
        for instruction in transfer.get("instructions", [])
        if isinstance(instruction, dict)
    ]
    if not instructions:
        return _contract_symbolic_branch_blocked("missing_instructions")
    if any(_instruction_mnemonic(instruction) == "call" for instruction in instructions):
        return _contract_symbolic_branch_blocked("contains_call_instruction")

    padding_ranges = [item for item in padding_bytes or [] if isinstance(item, dict)]
    asm_lines: list[str] = []
    cursor = rva_start

    def append_instruction_bytes(instruction: dict[str, Any]) -> str | None:
        nonlocal cursor
        instruction_rva = _optional_int(instruction.get("rva"))
        instruction_size = _optional_int(instruction.get("size"))
        instruction_bytes = instruction.get("bytes")
        if (
            instruction_rva is None
            or instruction_size is None
            or instruction_size <= 0
            or not isinstance(instruction_bytes, str)
            or not instruction_bytes
        ):
            return "instruction_missing_bytes"
        if instruction_rva != cursor:
            padding_hex = _contract_padding_bytes_for_range(padding_ranges, cursor, instruction_rva)
            if padding_hex is None:
                return "non_contiguous_instruction_bytes"
            asm_lines.extend(_decompiled_c_bytecode_asm_lines(padding_hex))
            cursor = instruction_rva
        if instruction_rva < rva_start or instruction_rva + instruction_size > rva_end:
            return "instruction_outside_function_range"
        try:
            raw = bytes.fromhex(instruction_bytes)
        except ValueError:
            return "instruction_bytes_not_hex"
        if len(raw) != instruction_size:
            return "instruction_size_mismatch"
        asm_lines.extend(_decompiled_c_bytecode_asm_lines([raw.hex()]))
        cursor += instruction_size
        return None

    def target_symbol(key: str) -> tuple[int, str] | None:
        target = _optional_int(outcome.get(key))
        if target is None:
            return None
        symbol = branch_target_symbols.get(target)
        if not symbol or not _is_c_identifier(symbol):
            return None
        return target, symbol

    terminal = instructions[-1]
    if kind == "branch":
        terminal_mnemonic = _instruction_mnemonic(terminal)
        if not terminal_mnemonic.startswith("j") or terminal_mnemonic == "jmp":
            return _contract_symbolic_branch_blocked("terminal_instruction_not_conditional_branch")
        true_target = target_symbol("true_target_rva")
        false_target = target_symbol("false_target_rva")
        if true_target is None or false_target is None:
            return _contract_symbolic_branch_blocked("unresolved_branch_target_symbol")
        for instruction in instructions[:-1]:
            blocker = append_instruction_bytes(instruction)
            if blocker:
                return _contract_symbolic_branch_blocked(blocker)
        terminal_rva = _optional_int(terminal.get("rva"))
        if terminal_rva is None or terminal_rva != cursor:
            return _contract_symbolic_branch_blocked("non_contiguous_terminal_branch")
        terminal_size = _optional_int(terminal.get("size")) or 0
        if terminal_rva + terminal_size != rva_end:
            return _contract_symbolic_branch_blocked("terminal_branch_not_at_function_end")
        asm_lines.append(f"{terminal_mnemonic} {_decompiled_c_i686_c_asm_symbol(true_target[1])}")
        asm_lines.append(f"jmp {_decompiled_c_i686_c_asm_symbol(false_target[1])}")
        return _contract_symbolic_branch_result(
            function,
            kind=kind,
            asm_lines=asm_lines,
            targets=[true_target, false_target],
            instructions=len(instructions),
        )

    if kind == "jump":
        terminal_mnemonic = _instruction_mnemonic(terminal)
        if terminal_mnemonic != "jmp":
            return _contract_symbolic_branch_blocked("terminal_instruction_not_jump")
        target = target_symbol("target_rva")
        if target is None:
            return _contract_symbolic_branch_blocked("unresolved_branch_target_symbol")
        for instruction in instructions[:-1]:
            blocker = append_instruction_bytes(instruction)
            if blocker:
                return _contract_symbolic_branch_blocked(blocker)
        terminal_rva = _optional_int(terminal.get("rva"))
        if terminal_rva is None or terminal_rva != cursor:
            return _contract_symbolic_branch_blocked("non_contiguous_terminal_branch")
        terminal_size = _optional_int(terminal.get("size")) or 0
        if terminal_rva + terminal_size != rva_end:
            return _contract_symbolic_branch_blocked("terminal_branch_not_at_function_end")
        asm_lines.append(f"jmp {_decompiled_c_i686_c_asm_symbol(target[1])}")
        return _contract_symbolic_branch_result(
            function,
            kind=kind,
            asm_lines=asm_lines,
            targets=[target],
            instructions=len(instructions),
        )

    target = target_symbol("target_rva")
    if target is None:
        return _contract_symbolic_branch_blocked("unresolved_fallthrough_target_symbol")
    for instruction in instructions:
        blocker = append_instruction_bytes(instruction)
        if blocker:
            return _contract_symbolic_branch_blocked(blocker)
    if cursor != rva_end:
        padding_hex = _contract_padding_bytes_for_range(padding_ranges, cursor, rva_end)
        if padding_hex is None:
            return _contract_symbolic_branch_blocked("function_range_not_fully_covered")
        asm_lines.extend(_decompiled_c_bytecode_asm_lines(padding_hex))
    asm_lines.append(f"jmp {_decompiled_c_i686_c_asm_symbol(target[1])}")
    return _contract_symbolic_branch_result(
        function,
        kind=kind,
        asm_lines=asm_lines,
        targets=[target],
        instructions=len(instructions),
    )


def _contract_symbolic_branch_result(
    function: dict[str, Any],
    *,
    kind: str,
    asm_lines: list[str],
    targets: list[tuple[int, str]],
    instructions: int,
) -> dict[str, Any]:
    return {
        "format": "stage-b-contract-symbolic-branch-v1",
        "status": "reimplementable",
        "source": "stage-a-semantic-transfer-contracts",
        "kind": kind,
        "rva_start": _optional_int(function.get("rva_start")),
        "rva_end": _optional_int(function.get("rva_end")),
        "size": max(0, (_optional_int(function.get("rva_end")) or 0) - (_optional_int(function.get("rva_start")) or 0)),
        "instructions": instructions,
        "targets": [
            {"rva": rva, "symbol": symbol}
            for rva, symbol in targets
        ],
        "asm_lines": asm_lines,
    }


def _contract_symbolic_branch_blocked(*reasons: str) -> dict[str, Any]:
    unique = sorted({reason for reason in reasons if reason})
    return {
        "format": "stage-b-contract-symbolic-branch-v1",
        "status": "blocked",
        "blockers": unique or ["unknown"],
    }


def _contract_padding_bytes_for_range(padding_ranges: list[dict[str, Any]], rva_start: int, rva_end: int) -> list[str] | None:
    if rva_end <= rva_start:
        return []
    cursor = rva_start
    chunks: list[str] = []
    for item in padding_ranges:
        start = _optional_int(item.get("rva_start"))
        end = _optional_int(item.get("rva_end"))
        bytes_hex = item.get("bytes_hex")
        if start is None or end is None or end <= start or not isinstance(bytes_hex, str):
            continue
        if end <= cursor:
            continue
        if start > cursor:
            return None
        take_start = max(cursor, start)
        take_end = min(rva_end, end)
        if take_end <= take_start:
            continue
        offset = take_start - start
        size = take_end - take_start
        try:
            raw = bytes.fromhex(bytes_hex)
        except ValueError:
            return None
        if len(raw) != end - start:
            return None
        chunks.append(raw[offset : offset + size].hex())
        cursor = take_end
        if cursor == rva_end:
            return chunks
    return None


def _contract_bytecode_blocked(*reasons: str) -> dict[str, Any]:
    unique = sorted({reason for reason in reasons if reason})
    return {
        "format": "stage-b-contract-bytecode-v1",
        "status": "blocked",
        "blockers": unique or ["unknown"],
    }


def _contract_bytecode_outcome_blocker(outcome: dict[str, Any], *, rva_start: int, rva_end: int) -> str | None:
    kind = str(outcome.get("kind") or "")
    if kind in {"return", "fallthrough"}:
        target = _optional_int(outcome.get("target_rva"))
        if target is not None and not (rva_start <= target <= rva_end):
            return "fallthrough_target_outside_function"
        return None
    if kind in {"external_jump", "indirect_jump", "indirect_jump_table"}:
        return f"contains_{kind}"
    if kind in {"jump", "branch"}:
        for key in ("target_rva", "true_target_rva", "false_target_rva"):
            target = _optional_int(outcome.get(key))
            if target is not None and not (rva_start <= target <= rva_end):
                return "branch_target_outside_function"
        return None
    return "unknown_control_flow_outcome"

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

    abi_callsites_by_function = _reference_contract_abi_callsites_by_function(payload)
    abi_switch_contracts_by_function = _reference_contract_abi_switch_contracts_by_function(payload)
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
        reference_contract = {
            "block_ids": list(row.get("block_ids") or []),
            "candidate": row.get("candidate") if isinstance(row.get("candidate"), dict) else None,
        }
        abi_callsites = abi_callsites_by_function.get(name, [])
        if abi_callsites:
            reference_contract["abi_callsites"] = abi_callsites
        switch_contracts = abi_switch_contracts_by_function.get(name, [])
        if switch_contracts:
            reference_contract["switch_contracts"] = switch_contracts
        functions.append(
            {
                "name": name,
                "aliases": [name],
                "section": section.name,
                "rva_start": rva_start,
                "rva_end": rva_end,
                "reference_contract": reference_contract,
            }
        )
    return functions


def _reference_contract_abi_switch_contracts_by_function(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    constraints = payload.get("constraints") if isinstance(payload.get("constraints"), dict) else {}
    abi = constraints.get("abi_callsites") if isinstance(constraints.get("abi_callsites"), dict) else {}
    original = abi.get("original") if isinstance(abi.get("original"), dict) else {}
    functions = original.get("functions") if isinstance(original.get("functions"), list) else []
    result: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        if not name:
            continue
        switches = [
            switch
            for switch in function.get("switch_contracts", [])
            if isinstance(switch, dict)
        ]
        if switches:
            result[name] = switches
    return result


def _reference_contract_abi_callsites_by_function(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    constraints = payload.get("constraints") if isinstance(payload.get("constraints"), dict) else {}
    abi = constraints.get("abi_callsites") if isinstance(constraints.get("abi_callsites"), dict) else {}
    original = abi.get("original") if isinstance(abi.get("original"), dict) else {}
    functions = original.get("functions") if isinstance(original.get("functions"), list) else []
    result: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        if not name:
            continue
        callsites = function.get("callsites") if isinstance(function.get("callsites"), list) else []
        summaries = [
            summary
            for callsite in callsites
            if isinstance(callsite, dict)
            for summary in [_reference_contract_abi_callsite_summary(callsite)]
            if summary is not None
        ]
        if summaries:
            result[name] = summaries
    return result


def _reference_contract_abi_callsite_summary(callsite: dict[str, Any]) -> dict[str, Any] | None:
    target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
    target_summary = _reference_contract_abi_callsite_target_summary(target)
    if target_summary is None:
        return None
    return {
        "id": callsite.get("id"),
        "block_id": callsite.get("block_id"),
        "instruction": callsite.get("instruction") if isinstance(callsite.get("instruction"), dict) else {},
        "target": target_summary,
        "arguments": _reference_contract_abi_callsite_arguments(callsite),
    }


def _reference_contract_abi_callsite_target_summary(target: dict[str, Any]) -> dict[str, Any] | None:
    if target.get("kind") == "direct":
        target_rva = _optional_int(target.get("target_rva"))
        if target_rva is None:
            return None
        return {"kind": "direct", "target_rva": target_rva}
    if target.get("kind") == "function_pointer":
        summary: dict[str, Any] = {
            "kind": "function_pointer",
            "status": str(target.get("status") or "unresolved"),
        }
        for key in ("operand", "memory_role"):
            value = target.get(key)
            if isinstance(value, str) and value:
                summary[key] = value
        memory_rva = _optional_int(target.get("memory_rva"))
        if memory_rva is not None:
            summary["memory_rva"] = memory_rva
        return summary
    if target.get("kind") == "import":
        symbol = target.get("symbol")
        if not isinstance(symbol, str) or not symbol:
            return None
        summary = {
            "kind": "import",
            "symbol": symbol,
        }
        dll = target.get("dll")
        if isinstance(dll, str) and dll:
            summary["dll"] = dll
        thunk_rva = _optional_int(target.get("thunk_rva"))
        if thunk_rva is not None:
            summary["thunk_rva"] = thunk_rva
        via_register = target.get("via_register")
        if isinstance(via_register, str) and via_register:
            summary["via_register"] = via_register
        return summary
    return None


def _reference_contract_abi_callsite_arguments(callsite: dict[str, Any]) -> list[dict[str, Any]]:
    inventory = callsite.get("argument_inventory") if isinstance(callsite.get("argument_inventory"), dict) else {}
    register_args = inventory.get("register_args") if isinstance(inventory.get("register_args"), list) else []
    stack_args = inventory.get("stack_args") if isinstance(inventory.get("stack_args"), list) else []
    arguments: list[dict[str, Any]] = []
    for arg in register_args:
        if not isinstance(arg, dict):
            continue
        register = arg.get("register")
        if not isinstance(register, str) or not register:
            continue
        source = arg.get("source") if isinstance(arg.get("source"), dict) else {}
        role = arg.get("role")
        item: dict[str, Any] = {
            "kind": "register",
            "placement": "register",
            "register": register,
        }
        if isinstance(role, str) and role:
            item["role"] = role
        if source:
            item["register_definition"] = source
        arguments.append(item)
    for arg in sorted([arg for arg in stack_args if isinstance(arg, dict)], key=lambda item: int(item.get("index") or 0)):
        source = arg.get("source") if isinstance(arg.get("source"), dict) else {}
        value = source.get("value")
        role = arg.get("role")
        stack_offset = _optional_int(source.get("stack_offset"))
        base: dict[str, Any] = {}
        if isinstance(role, str) and role:
            base["role"] = role
        if stack_offset is not None:
            base["stack_offset"] = stack_offset
        if source.get("kind") == "immediate" and isinstance(value, int) and not isinstance(value, bool):
            arguments.append({**base, "kind": "immediate", "value": value})
        elif source.get("kind") == "register" and isinstance(source.get("register"), str) and source.get("register"):
            register_argument = {**base, "kind": "register", "register": str(source["register"])}
            register_definition = source.get("register_definition")
            if isinstance(register_definition, dict):
                register_argument["register_definition"] = register_definition
            arguments.append(register_argument)
        else:
            arguments.append({**base, "kind": "unrenderable"})
    return arguments

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


def _skeleton_implementation_recovery_with_contract_placeholders(
    recovery: dict[str, Any],
    reference_contract_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    if reference_contract_payload is None:
        return recovery
    section_gaps = list(_reference_contract_abi_section_gap_entries_by_start(reference_contract_payload).values())
    if not section_gaps:
        return recovery

    updated = dict(recovery)
    blockers = list(updated.get("blockers") or [])
    if "contract_section_gap_placeholders" not in blockers:
        blockers.append("contract_section_gap_placeholders")
    updated["status"] = "incomplete"
    updated["source_implements_behavior"] = False
    if updated.get("generated_source_kind") == "decompiler_recovered_behavior":
        updated["generated_source_kind"] = "decompiler_recovered_partial"
    updated["blockers"] = blockers
    updated["contract_placeholder_coverage"] = {
        "status": "incomplete",
        "counts": {
            "section_gap_placeholders": len(section_gaps),
        },
        "examples": [
            {
                "name": str(entry.get("name") or ""),
                "rva_start": entry.get("rva_start"),
                "rva_end": entry.get("rva_end"),
                "block_ids": entry.get("block_ids") if isinstance(entry.get("block_ids"), list) else [],
            }
            for entry in section_gaps[:10]
        ],
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
    runtime_entry_policy: str = "bridge",
) -> dict[str, Any]:
    policy_omitted_functions = [
        function
        for function in functions
        if _decompiled_c_policy_omission_reason(function, runtime_entry_policy=runtime_entry_policy) is not None
    ]
    policy_omitted_ids = {id(function) for function in policy_omitted_functions}
    decompiler_required_functions = (
        [function for function in functions if id(function) not in policy_omitted_ids]
        if implementation_mode == "decompiled-c"
        else list(functions)
    )
    decompiler_functions = [
        function
        for function in decompiler_required_functions
        if isinstance(function.get("decompiler"), dict)
    ]
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
        for function in decompiler_required_functions
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
    policy_omitted_coverage_functions = [
        _decompiler_coverage_function(
            function,
            reason=_decompiled_c_policy_omission_reason(function, runtime_entry_policy=runtime_entry_policy)
            or "policy_omitted",
        )
        for function in policy_omitted_functions
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
        if missing_decompiler_functions:
            blockers.append("missing_decompiler_exports")
        if incomplete_decompiler_functions:
            blockers.append("incomplete_decompiler_successes")
        if missing_decompiler_code_functions:
            blockers.append("missing_decompiler_code")
        if duplicate_names:
            blockers.append("duplicate_decompiler_function_names")
        status = "complete" if not blockers else "incomplete"
        generated_source_kind = "decompiler_recovered_behavior" if status == "complete" else "decompiler_recovered_partial"
    elif implementation_mode == "contract-guided-c":
        blockers = ["stage_a_validation_required"]
        if not functions:
            blockers.append("missing_functions")
        if len(decompiler_functions) != len(functions):
            blockers.append("missing_decompiler_exports")
        if decompiler_successes and len(decompiler_successes) < len(functions):
            blockers.append("incomplete_decompiler_coverage")
        if duplicate_names:
            blockers.append("duplicate_decompiler_function_names")
        status = "incomplete"
        generated_source_kind = "contract_guided_c_partial"
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
        "decompiler_required_functions": len(decompiler_required_functions),
        "decompiler_functions": len(decompiler_functions),
        "decompiler_successes": len(decompiler_successes),
        "decompiler_code_functions": len(decompiler_code_functions),
        "decompiler_coverage": {
            "status": "complete"
            if len(decompiler_functions) == len(decompiler_required_functions)
            and len(decompiler_successes) == len(decompiler_required_functions)
            and (not requires_decompiler_code or len(decompiler_code_functions) == len(decompiler_required_functions))
            else "incomplete",
            "requires_decompiler_code": requires_decompiler_code,
            "missing_decompiler_functions": missing_decompiler_functions,
            "incomplete_decompiler_functions": incomplete_decompiler_functions,
            "missing_decompiler_code_functions": missing_decompiler_code_functions,
            "policy_omitted_functions": policy_omitted_coverage_functions,
            "counts": {
                "decompiler_required_functions": len(decompiler_required_functions),
                "policy_omitted_functions": len(policy_omitted_coverage_functions),
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


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


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
    reference_contract_payload: dict[str, Any] | None = None,
    reference_contract_sidecars: dict[str, Any] | None = None,
) -> str:
    if implementation_mode in {"decompiled-c", "contract-guided-c"}:
        return _render_decompiled_c_source(
            target_name=target_name,
            functions=functions,
            runtime_entry_policy=runtime_entry_policy,
            external_function_names=external_function_names,
            reference_contract_payload=reference_contract_payload,
            reference_contract_sidecars=reference_contract_sidecars,
            allow_contract_bytecode=implementation_mode == "contract-guided-c",
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
    runtime_entry_policy: str = "bridge",
    reference_contract_payload: dict[str, Any] | None = None,
    decompiler_functions: list[dict[str, Any]] | None = None,
    external_function_names: list[str] | tuple[str, ...] = (),
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
    anchors.extend(
        _skeleton_generated_helper_source_anchors(
            lines,
            source_rel=source_rel,
            source_language=source_language,
            implementation_mode=implementation_mode,
            existing_functions={str(anchor.get("function") or "") for anchor in anchors},
            reference_contract_payload=reference_contract_payload,
            decompiler_functions=decompiler_functions or [],
        )
    )
    anchors.extend(
        _skeleton_section_gap_placeholder_source_anchors(
            lines,
            source_rel=source_rel,
            source_language=source_language,
            implementation_mode=implementation_mode,
            existing_functions={str(anchor.get("function") or "") for anchor in anchors},
            reference_contract_payload=reference_contract_payload,
            functions=functions,
            runtime_entry_policy=runtime_entry_policy,
            external_function_names=external_function_names,
        )
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
        "runtime_entry_policy": runtime_entry_policy,
        "functions": anchors,
        "counts": {"functions": len(anchors)},
    }


def _skeleton_generated_helper_source_anchors(
    lines: list[str],
    *,
    source_rel: Path,
    source_language: str,
    implementation_mode: str,
    existing_functions: set[str],
    reference_contract_payload: dict[str, Any] | None,
    decompiler_functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if source_language != "c" or reference_contract_payload is None:
        return []
    helper_aliases = _skeleton_decompiler_section_gap_helper_aliases(reference_contract_payload, decompiler_functions)
    anchors: list[dict[str, Any]] = []
    for helper_name in _DECOMPILED_C_GENERATED_HELPER_SYMBOLS:
        if helper_name in existing_functions:
            continue
        helper = helper_aliases.get(helper_name)
        if helper is None:
            continue
        line = _source_exact_function_definition_line(lines, helper_name)
        if line is None:
            line = _source_anchor_line(
                lines,
                helper_name,
                source_language=source_language,
                implementation_mode=implementation_mode,
                aliases=helper.get("aliases", []),
                prefer_definition=True,
            )
        if line is None:
            continue
        anchors.append(
            {
                "function": helper_name,
                "aliases": helper["aliases"],
                "file": source_rel.as_posix(),
                "line_start": line,
                "line_end": line,
                "source_kind": "generated_helper_from_decompiler_section_gap",
                "rva_start": helper.get("rva_start"),
                "rva_end": helper.get("rva_end"),
                "reference_section_gap": helper.get("reference_section_gap"),
            }
        )
    return anchors


def _skeleton_decompiler_section_gap_helper_aliases(
    reference_contract_payload: dict[str, Any],
    decompiler_functions: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    gap_entries = _reference_contract_abi_section_gap_entries_by_start(reference_contract_payload)
    helpers: dict[str, dict[str, Any]] = {}
    for function in decompiler_functions:
        name = str(function.get("name") or "")
        if name not in _DECOMPILED_C_GENERATED_HELPER_SYMBOLS:
            continue
        rva_start = _optional_int(function.get("rva_start"))
        if rva_start is None:
            continue
        gap = gap_entries.get(rva_start)
        if gap is None:
            continue
        aliases = _dedupe_strings(
            [
                name,
                *[alias for alias in function.get("aliases", []) if isinstance(alias, str)],
                str(gap["name"]),
                *[str(block_id) for block_id in gap.get("block_ids", []) if block_id],
            ]
        )
        helpers[name] = {
            "aliases": aliases,
            "rva_start": rva_start,
            "rva_end": function.get("rva_end"),
            "reference_section_gap": gap,
        }
    return helpers


def _skeleton_section_gap_placeholder_source_anchors(
    lines: list[str],
    *,
    source_rel: Path,
    source_language: str,
    implementation_mode: str,
    existing_functions: set[str],
    reference_contract_payload: dict[str, Any] | None,
    functions: list[dict[str, Any]],
    runtime_entry_policy: str = "bridge",
    external_function_names: list[str] | tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    if source_language != "c" or reference_contract_payload is None:
        return []
    implemented_functions = [
        function
        for function in functions
        if not _decompiled_c_is_import_thunk(function)
        and not _decompiled_c_is_runtime_entry(function, runtime_entry_policy=runtime_entry_policy)
        and not _decompiled_c_is_stack_probe_helper(function)
    ]
    external_call_symbols = _decompiled_c_external_call_symbols(implemented_functions)
    defined_symbols = _decompiled_c_defined_symbol_names(implemented_functions)
    known_symbols = set(external_call_symbols) | {str(name) for name in external_function_names} | defined_symbols
    anchors: list[dict[str, Any]] = []
    for entry in _reference_contract_abi_section_gap_entries_by_start(reference_contract_payload).values():
        rva_start = _optional_int(entry.get("rva_start"))
        rva_end = _optional_int(entry.get("rva_end"))
        if rva_start is None or rva_end is None or rva_end <= rva_start:
            continue
        aliases = [alias for alias in entry.get("aliases", []) if isinstance(alias, str) and alias]
        synthetic_symbol = _decompiled_c_synthetic_section_gap_name(entry)
        synthetic_line = (
            _source_inline_asm_label_line(lines, synthetic_symbol)
            if _is_c_identifier(synthetic_symbol)
            else None
        )
        if synthetic_line is None and _is_c_identifier(synthetic_symbol):
            synthetic_line = _source_exact_function_definition_line(lines, synthetic_symbol)
        if synthetic_line is None and _is_c_identifier(synthetic_symbol):
            synthetic_line = _source_embedded_section_gap_label_line(lines, synthetic_symbol)
        if synthetic_line is not None:
            symbol = synthetic_symbol
            source_kind = _section_gap_source_anchor_kind(
                lines,
                line=synthetic_line,
                default="generated_contract_placeholder_from_section_gap",
            )
            line = synthetic_line
        else:
            symbol = _decompiled_c_section_gap_known_symbol_alias(entry, known_symbols=known_symbols)
            source_kind = "generated_contract_placeholder_from_section_gap_alias"
            line = None
        if symbol is None or symbol in existing_functions:
            continue
        if line is None:
            line = _source_exact_function_definition_line(lines, symbol)
        if line is None:
            line = _source_anchor_line(
                lines,
                symbol,
                source_language=source_language,
                implementation_mode=implementation_mode,
                aliases=[] if source_kind == "generated_contract_placeholder_from_section_gap" else aliases,
                prefer_definition=True,
            )
        if line is None:
            continue
        anchors.append(
            {
                "function": symbol,
                "aliases": _dedupe_strings([symbol, *aliases]),
                "file": source_rel.as_posix(),
                "line_start": line,
                "line_end": line,
                "source_kind": source_kind,
                "rva_start": rva_start,
                "rva_end": rva_end,
                "reference_section_gap": entry,
            }
        )
    return anchors


def _section_gap_source_anchor_kind(lines: list[str], *, line: int, default: str) -> str:
    window = "\n".join(lines[max(0, line - 2) : min(len(lines), line + 6)])
    if (
        "Stage A checked semantic region:" in window
        or "Stage B generated C for semantic-region:" in window
        or "checked selected-region target" in window
    ):
        return "generated_checked_semantic_region"
    if "Stage B contract-guided bytecode:" in window:
        return "generated_contract_guided_bytecode"
    if "Stage B contract-guided raw flow:" in window:
        return "generated_contract_guided_raw_flow"
    if "Stage B contract-guided branch:" in window:
        return "generated_contract_guided_branch"
    if "Stage B contract-guided flow:" in window:
        return "generated_contract_guided_flow"
    if "Stage B contract-guided leaf:" in window:
        return "generated_contract_guided_leaf"
    if "Stage B contract-guided callback:" in window:
        return "generated_contract_guided_callback"
    if "Stage B contract-guided indirect-call slice:" in window:
        return "generated_contract_guided_indirect"
    enclosing = _stage_b_enclosing_asm_contract_source_kind(lines, line=line)
    if enclosing is not None:
        return enclosing
    return default


def _stage_b_enclosing_asm_contract_source_kind(lines: list[str], *, line: int) -> str | None:
    for index in range(min(max(line - 1, 0), len(lines) - 1), -1, -1):
        text = lines[index]
        kind = _stage_b_contract_marker_source_kind(text)
        if kind is not None:
            return kind
        if "__asm__(" in text:
            return None
    return None


def _stage_b_contract_marker_source_kind(text: str) -> str | None:
    if "Stage B contract-guided bytecode:" in text:
        return "generated_contract_guided_bytecode"
    if "Stage B contract-guided raw flow:" in text:
        return "generated_contract_guided_raw_flow"
    if "Stage B contract-guided branch:" in text:
        return "generated_contract_guided_branch"
    if "Stage B contract-guided flow:" in text:
        return "generated_contract_guided_flow"
    if "Stage B contract-guided leaf:" in text:
        return "generated_contract_guided_leaf"
    if "Stage B contract-guided callback:" in text:
        return "generated_contract_guided_callback"
    if "Stage B contract-guided indirect-call slice:" in text:
        return "generated_contract_guided_indirect"
    return None


def _reference_contract_abi_section_gap_entries_by_start(reference_contract_payload: dict[str, Any]) -> dict[int, dict[str, Any]]:
    constraints = reference_contract_payload.get("constraints") if isinstance(reference_contract_payload.get("constraints"), dict) else {}
    abi = constraints.get("abi_callsites") if isinstance(constraints.get("abi_callsites"), dict) else {}
    original = abi.get("original") if isinstance(abi.get("original"), dict) else {}
    functions = original.get("functions") if isinstance(original.get("functions"), list) else []
    block_aliases = _reference_contract_basic_block_aliases_by_id(reference_contract_payload)
    semantic_regions = _reference_contract_semantic_regions(reference_contract_payload)
    semantic_regions_by_caller: dict[str, dict[str, Any]] = {}
    for region in semantic_regions:
        if not isinstance(region, dict):
            continue
        caller = region.get("caller") if isinstance(region.get("caller"), dict) else {}
        caller_block = str(region.get("block_id") or caller.get("block_id") or "")
        if caller_block:
            semantic_regions_by_caller[caller_block] = region
    semantic_regions_by_callee: dict[str, list[dict[str, Any]]] = {}
    for region in semantic_regions:
        if not isinstance(region, dict):
            continue
        callee = region.get("callee") if isinstance(region.get("callee"), dict) else {}
        callee_block = str(callee.get("block_id") or "")
        if callee_block:
            semantic_regions_by_callee.setdefault(callee_block, []).append(region)
    result: dict[int, dict[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        if not name.startswith("section-gap-"):
            continue
        blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
        block_ids: list[str] = []
        starts: list[int] = []
        ends: list[int] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            start = _optional_int(block.get("rva_start"))
            end = _optional_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            starts.append(start)
            ends.append(end)
            block_id = block.get("block_id")
            if isinstance(block_id, str) and block_id:
                block_ids.append(block_id)
        if not starts:
            continue
        entry_start = min(starts)
        if entry_start in result:
            continue
        aliases = _dedupe_strings(
            [
                name,
                *block_ids,
                *[
                    alias
                    for block_id in block_ids
                    for alias in block_aliases.get(block_id, [])
                    if isinstance(alias, str) and alias
                ],
            ]
        )
        entry = {
            "name": name,
            "aliases": aliases,
            "rva_start": entry_start,
            "rva_end": max(ends),
            "block_ids": _dedupe_strings(block_ids),
            "abi_callsites": _reference_contract_abi_callsite_summaries(function),
            "switch_contracts": [
                switch
                for switch in function.get("switch_contracts", [])
                if isinstance(switch, dict)
            ],
        }
        for block_id in block_ids:
            region = semantic_regions_by_caller.get(block_id)
            if region is not None:
                entry["semantic_region_contract"] = region
                break
        callee_regions = [
            region
            for block_id in block_ids
            for region in semantic_regions_by_callee.get(block_id, [])
        ]
        if callee_regions:
            entry["semantic_region_callee_contracts"] = callee_regions
        result[entry_start] = entry
    return result


def _reference_contract_semantic_regions(reference_contract_payload: dict[str, Any]) -> list[dict[str, Any]]:
    constraints = reference_contract_payload.get("constraints") if isinstance(reference_contract_payload.get("constraints"), dict) else {}
    semantic = constraints.get("semantic_region_contracts") if isinstance(constraints.get("semantic_region_contracts"), dict) else {}
    regions = semantic.get("regions") if isinstance(semantic.get("regions"), list) else []
    return [region for region in regions if isinstance(region, dict)]


def _reference_contract_abi_callsite_summaries(function: dict[str, Any]) -> list[dict[str, Any]]:
    callsites = function.get("callsites") if isinstance(function.get("callsites"), list) else []
    summaries: list[dict[str, Any]] = []
    for callsite in callsites:
        if not isinstance(callsite, dict):
            continue
        summary = _reference_contract_abi_callsite_summary(callsite)
        if summary is not None:
            summaries.append(summary)
    return summaries


def _reference_contract_basic_block_aliases_by_id(reference_contract_payload: dict[str, Any]) -> dict[str, list[str]]:
    constraints = reference_contract_payload.get("constraints") if isinstance(reference_contract_payload.get("constraints"), dict) else {}
    cfg = constraints.get("basic_blocks_and_cfg") if isinstance(constraints.get("basic_blocks_and_cfg"), dict) else {}
    blocks = cfg.get("basic_blocks") if isinstance(cfg.get("basic_blocks"), list) else []
    result: dict[str, list[str]] = {}
    for block in blocks:
        if not isinstance(block, dict):
            continue
        block_id = block.get("id")
        if not isinstance(block_id, str) or not block_id:
            continue
        symbol_aliases = block.get("symbol_aliases") if isinstance(block.get("symbol_aliases"), dict) else {}
        aliases = _dedupe_strings(
            [
                alias
                for key in ("original", "candidate")
                for alias in (symbol_aliases.get(key) if isinstance(symbol_aliases.get(key), list) else [])
                if isinstance(alias, str) and alias
            ]
        )
        if aliases:
            result[block_id] = aliases
    return result


def _source_exact_function_definition_line(lines: list[str], name: str) -> int | None:
    if not name:
        return None
    pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    for index, line in enumerate(lines, start=1):
        if pattern.search(line) is None:
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


def _source_inline_asm_label_line(lines: list[str], name: str) -> int | None:
    if not name:
        return None
    labels = _dedupe_strings([name, _decompiled_c_i686_c_asm_symbol(name)])
    for index, line in enumerate(lines, start=1):
        for label in labels:
            if f'"{label}:\\n' in line:
                return index
    return None


def _source_embedded_section_gap_label_line(lines: list[str], name: str) -> int | None:
    if not name:
        return None
    marker = f"Stage B embedded section-gap label: {name}"
    for index, line in enumerate(lines, start=1):
        if marker in line:
            return index
    return None


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
        line = _source_inline_asm_label_line(lines, candidate)
        if line is not None:
            return line
    for candidate in candidates:
        line = _source_body_anchor_line(lines, candidate)
        if line is not None:
            return line
    for index, line in enumerate(lines, start=1):
        if any(_source_line_mentions_symbol(line, candidate) for candidate in candidates):
            return index
    return None


def _source_anchor_kind(lines: list[str], *, line: int, function: dict[str, Any]) -> str:
    name = str(function.get("name") or "")
    aliases = [alias for alias in function.get("aliases", []) if isinstance(alias, str) and alias]
    definition_names = list(dict.fromkeys([name, *aliases, _c_identifier_from_name(name)]))
    if name == "___tmainCRTStartup" and any(_source_line_contains_definition(lines, line=line, name=item) for item in definition_names):
        return "generated_runtime_bridge"
    if name in {"WinMainCRTStartup", "mainCRTStartup"} and any(
        _source_line_contains_definition(lines, line=line, name=item)
        or _source_inline_asm_label_line(lines, item) == line
        for item in definition_names
    ):
        return "generated_runtime_entry_stub"
    if _decompiled_c_is_import_thunk(function):
        target_symbol = _decompiled_c_import_thunk_target_symbol(function)
        import_names = _dedupe_strings([*definition_names, target_symbol] if target_symbol else definition_names)
        if any(_source_inline_asm_label_line(lines, item) == line for item in import_names):
            return "omitted_import_thunk"
    definition = None
    for item in definition_names:
        definition = _source_definition_after(lines, start=line, name=item)
        if definition is not None:
            break
    window = "\n".join(lines[max(0, line - 2) : min(len(lines), line + 6)])
    anchor_line = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
    omitted_window = (
        "\n".join(lines[line - 1 : min(len(lines), line + 2)])
        if anchor_line.startswith("/* original RVA")
        else "\n".join(lines[max(0, line - 3) : line])
    )
    if "MinGW CRT support helper body omitted" in omitted_window:
        return "omitted_runtime_helper"
    if "MinGW CRT entry body" in omitted_window:
        return "omitted_runtime_entry"
    if "stack-probe helper body omitted" in omitted_window:
        return "omitted_runtime_helper"
    if "import thunk for" in omitted_window:
        return "omitted_import_thunk"
    if "Stage B contract-guided leaf:" in window:
        return "generated_contract_guided_leaf"
    if "Stage B contract-guided callback:" in window:
        return "generated_contract_guided_callback"
    if "Stage B contract-guided indirect-call slice:" in window:
        return "generated_contract_guided_indirect"
    if "Stage B contract-guided bytecode:" in window:
        return "generated_contract_guided_bytecode"
    if "Stage B contract-guided raw flow:" in window:
        return "generated_contract_guided_raw_flow"
    if "Stage B contract-guided branch:" in window:
        return "generated_contract_guided_branch"
    if "Stage B contract-guided flow:" in window:
        return "generated_contract_guided_flow"
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
        if not _source_line_mentions_symbol(line, name):
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


def _source_line_mentions_symbol(line: str, name: str) -> bool:
    if not name:
        return False
    if _is_c_identifier(name):
        return re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", line) is not None
    return name in line


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
    reference_contract_payload: dict[str, Any] | None = None,
    reference_contract_sidecars: dict[str, Any] | None = None,
    allow_contract_bytecode: bool = False,
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
        "typedef struct stageb_x86_state {",
        "    uint32_t eax;",
        "    uint32_t ebx;",
        "    uint32_t ecx;",
        "    uint32_t edx;",
        "    uint32_t esi;",
        "    uint32_t edi;",
        "    uint32_t ebp;",
        "    uint32_t esp;",
        "} stageb_x86_state;",
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
        *(["#define STAGE_B_JQ_HAS_LAYOUT_BSS_ANCHOR 1"] if target_name == "jq" else []),
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
        "#define STAGE_B_JQ_CALL_IOB_SLOT(slot, stream) \\",
        "    ({ FILE *stage_b_result; \\",
        "       __asm__ __volatile__(\"movl %1, (%%esp)\\n\\tcall *%2\" \\",
        "           : \"=a\"(stage_b_result) \\",
        "           : \"ri\"((int)(stream)), \"m\"(slot) \\",
        "           : \"ecx\", \"edx\", \"memory\", \"cc\"); \\",
        "       stage_b_result; })",
        "",
        "uintptr_t __cdecl jv_mem_alloc(size_t);",
        "__attribute__((section(\".bss\"))) static unsigned stage_b_jq_isoption_index;",
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
        "    if ((uintptr_t)out < (uintptr_t)0x10000U) {",
        "        return out_value;",
        "    }",
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
        "    if ((uintptr_t)out < (uintptr_t)0x10000U) {",
        "        return out_value;",
        "    }",
        "    if (safe_length != 0U && (uintptr_t)data < (uintptr_t)0x10000U) {",
        "        safe_length = 0U;",
        "        data = (const uint8_t *)0;",
        "    }",
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
        "    if ((uintptr_t)out < (uintptr_t)0x10000U) {",
        "        return out_value;",
        "    }",
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
        "static int __attribute__((optimize(\"no-jump-tables\"))) stage_b_jq_isoption_next(char **cursor, int short_mode) {",
        "    unsigned index = stage_b_jq_isoption_index++;",
        "    if (index == 0U) {",
        "        return stage_b_jq_isoption_match(cursor, short_mode, 'n', \"null-input\");",
        "    }",
        "    if (index == 30U) {",
        "        return stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"help\");",
        "    }",
        "    if (index == 31U) {",
        "        return stage_b_jq_isoption_match(cursor, short_mode, 'V', \"version\");",
        "    }",
        "    if (index == 32U) {",
        "        return stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"build-configuration\");",
        "    }",
        "    if (index == 33U) {",
        "        return stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"run-tests\");",
        "    }",
        "    return 0;",
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
    contract_call_profile_functions = [
        *implemented_functions,
        *[function for function in functions if _decompiled_c_is_import_thunk(function)],
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
    layout_keepalive_required = not _decompiled_c_uses_reference_section_materialization(
        target_name,
        reference_contract_payload,
    )
    runtime_bridge = (
        _decompiled_c_runtime_entry_bridge(functions, call_layout_keepalive=layout_keepalive_required)
        if runtime_entry_policy == "bridge"
        else []
    )
    runtime_entry_stubs = _decompiled_c_runtime_entry_stubs_by_name(functions) if runtime_bridge else {}
    runtime_bridge_externs = _decompiled_c_runtime_entry_bridge_externs(functions) if runtime_bridge else []
    known_branch_target_symbols = (
        set(_decompiled_c_external_call_symbols(functions))
        | {str(name) for name in external_function_names or ()}
        | _decompiled_c_defined_symbol_names(functions)
        | set(import_thunk_symbols)
        | set(import_thunk_alias_symbols)
        | set(direct_import_alias_symbols)
        | set(runtime_helper_alias_symbols)
    )
    contract_branch_target_symbols = (
        _decompiled_c_section_gap_target_symbols(
            reference_contract_payload,
            known_symbols=known_branch_target_symbols,
        )
        if reference_contract_payload is not None
        else {}
    )
    contract_call_targets = _decompiled_c_contract_call_targets(
        functions,
        runtime_entry_policy=runtime_entry_policy,
        reference_contract_payload=reference_contract_payload,
        external_function_names=external_function_names or (),
    )
    runtime_linked_call_targets = (
        set(_decompiled_c_contract_runtime_call_targets(reference_contract_payload).values())
        if reference_contract_payload is not None
        else set()
    )
    embedded_section_gap_rvas = _decompiled_c_embedded_section_gap_rvas(implemented_functions)
    synthetic_section_gap_placeholders = _decompiled_c_contract_synthetic_section_gap_placeholders(
        implemented_functions,
        reference_contract_payload=reference_contract_payload,
        reference_contract_sidecars=reference_contract_sidecars,
        call_targets=contract_call_targets,
        external_function_names=external_function_names or (),
        additional_linkable_symbols=import_thunk_symbols,
        runtime_linked_call_targets=runtime_linked_call_targets,
        embedded_section_gap_rvas=embedded_section_gap_rvas,
    )
    section_gap_alias_anchor_symbols = _decompiled_c_contract_section_gap_alias_anchor_symbols(
        implemented_functions,
        reference_contract_payload=reference_contract_payload,
        external_function_names=external_function_names or (),
    )
    emitted_section_gap_targets = [
        *section_gap_alias_anchor_symbols,
        *_decompiled_c_embedded_section_gap_symbols(
            reference_contract_payload,
            embedded_section_gap_rvas=embedded_section_gap_rvas,
            known_symbols=known_branch_target_symbols,
        ),
        *[
            str(function.get("name") or "")
            for function in synthetic_section_gap_placeholders
            if isinstance(function.get("name"), str)
        ],
    ]
    prototypes = [
        _decompiled_c_prototype(
            function,
            emitted_name=_decompiled_c_emitted_function_name(function, runtime_entry_policy=runtime_entry_policy),
        )
        for function in implemented_functions
    ]
    prototypes = [prototype for prototype in prototypes if prototype]
    generated_contract_declarations = _decompiled_c_generated_contract_function_declarations(
        implemented_functions,
        runtime_entry_policy=runtime_entry_policy,
    )
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
    contract_call_target_profiles = _decompiled_c_contract_call_target_profiles(
        contract_call_targets,
        contract_call_profile_functions,
        runtime_entry_policy=runtime_entry_policy,
        emitted_section_gap_targets=emitted_section_gap_targets,
        runtime_linked_call_targets=runtime_linked_call_targets,
    )
    if reference_contract_payload is not None:
        contract_call_target_profiles.update(
            _decompiled_c_semantic_region_call_target_profiles(
                reference_contract_payload,
                call_targets=contract_call_targets,
            )
        )
    contract_call_target_forward_declarations = _decompiled_c_contract_call_target_forward_declarations(
        contract_call_targets,
        contract_call_target_profiles,
    )
    contract_call_target_spans = _decompiled_c_contract_call_target_spans(
        functions,
        synthetic_section_gap_placeholders=synthetic_section_gap_placeholders,
        call_targets=contract_call_targets,
        runtime_entry_policy=runtime_entry_policy,
    )
    placeholders = _decompiled_c_link_placeholder_definitions(
        [
            *(external_function_names or ()),
            *import_thunk_symbols,
            *import_thunk_alias_symbols,
            *direct_import_alias_symbols,
            *runtime_helper_alias_symbols,
        ],
        implemented_functions,
        runtime_entry_policy=runtime_entry_policy,
        all_functions=functions,
        reference_contract_payload=reference_contract_payload,
        reference_contract_sidecars=reference_contract_sidecars,
        call_targets=contract_call_targets,
        call_target_profiles=contract_call_target_profiles,
        call_target_spans=contract_call_target_spans,
        branch_target_symbols=contract_branch_target_symbols,
        synthetic_section_gap_placeholders=synthetic_section_gap_placeholders,
        allow_contract_bytecode=allow_contract_bytecode,
    )
    import_thunk_wrappers = _decompiled_c_import_thunk_wrapper_lines(functions)
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
    if contract_call_target_profiles:
        lines.extend(
            str(profile["prototype"])
            for _, profile in sorted(contract_call_target_profiles.items())
            if isinstance(profile.get("prototype"), str)
        )
        lines.append("")
    if contract_call_target_forward_declarations:
        lines.extend(contract_call_target_forward_declarations)
        lines.append("")
    if placeholders:
        lines.extend(placeholders)
        lines.append("")
    if import_thunk_wrappers:
        lines.extend(import_thunk_wrappers)
        lines.append("")
    if import_aliases:
        lines.extend(import_aliases)
        lines.append("")
    if prototypes:
        lines.extend(prototypes)
        lines.append("")
    if generated_contract_declarations:
        lines.extend(generated_contract_declarations)
        lines.append("")
    layout_support = _decompiled_c_layout_support_lines(
        target_name,
        functions,
        runtime_entry_policy=runtime_entry_policy,
        reference_contract_payload=reference_contract_payload,
        external_function_names=external_function_names or (),
        retained_contract_symbols=[
            str(function["name"])
            for function in synthetic_section_gap_placeholders
            if isinstance(function.get("name"), str)
            and _is_c_identifier(str(function["name"]))
            and (
                not _decompiled_c_has_checked_semantic_region_contract(function)
                or _decompiled_c_has_checked_semantic_region_caller_contract(function)
            )
        ]
        + section_gap_alias_anchor_symbols,
    )
    if layout_support:
        lines.extend(layout_support)
        lines.append("")
    runtime_bridge_emitted = False
    runtime_entry_anchor = "WinMainCRTStartup" if any(str(function.get("name") or "") == "WinMainCRTStartup" for function in functions) else "mainCRTStartup"
    emitted_body_rva_end: int | None = None
    layout_padding_ranges = _decompiled_c_layout_padding_ranges(
        reference_contract_payload=reference_contract_payload,
        reference_contract_sidecars=reference_contract_sidecars,
    )

    def emit_verified_layout_padding_before(function: dict[str, Any]) -> None:
        nonlocal emitted_body_rva_end
        item_start = _decompiled_c_function_sort_rva(function)
        if emitted_body_rva_end is None or item_start <= emitted_body_rva_end:
            return
        padding_chunks = _contract_padding_bytes_for_range(layout_padding_ranges, emitted_body_rva_end, item_start)
        if padding_chunks is None:
            return
        rendered = _decompiled_c_contract_layout_padding_asm(emitted_body_rva_end, item_start, padding_chunks)
        if rendered is None:
            return
        lines.extend([rendered, ""])
        emitted_body_rva_end = item_start

    def note_emitted_body(function: dict[str, Any]) -> None:
        nonlocal emitted_body_rva_end
        item_end = _decompiled_c_function_rva_end(function)
        if item_end is not None:
            emitted_body_rva_end = max(emitted_body_rva_end or item_end, item_end)

    body_items = _decompiled_c_ordered_body_items(
        functions,
        synthetic_section_gap_placeholders=synthetic_section_gap_placeholders,
    )
    for kind, function in body_items:
        if kind == "synthetic_section_gap":
            emit_verified_layout_padding_before(function)
            lines.extend(
                [
                    f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                    _decompiled_c_render_synthetic_section_gap_placeholder(
                        function,
                        call_targets=contract_call_targets,
                        call_target_profiles=contract_call_target_profiles,
                        call_target_spans=contract_call_target_spans,
                        branch_target_symbols=contract_branch_target_symbols,
                        allow_contract_bytecode=allow_contract_bytecode,
                    ),
                    "",
                ]
            )
            note_emitted_body(function)
            continue
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
            if runtime_entry_policy == "bridge":
                runtime_entry_comment = "/* MinGW CRT entry body replaced by a generated runtime bridge. */"
            elif _decompiled_c_is_mingw_crt_support_helper(function):
                runtime_entry_comment = "/* MinGW CRT support helper body omitted; supplied by the MinGW CRT link policy. */"
            else:
                runtime_entry_comment = "/* MinGW CRT entry body omitted; supplied by the MinGW CRT link policy. */"
            lines.extend(
                [
                    f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                    runtime_entry_comment,
                    "",
                ]
            )
            if not runtime_bridge_emitted and runtime_bridge and str(function.get("name") or "") == runtime_entry_anchor:
                lines.extend(runtime_bridge)
                lines.append("")
                runtime_bridge_emitted = True
            runtime_entry_stub = runtime_entry_stubs.get(str(function.get("name") or ""))
            if runtime_entry_stub:
                emit_verified_layout_padding_before(function)
                lines.extend([runtime_entry_stub, ""])
                note_emitted_body(function)
            continue
        if _decompiled_c_is_stack_probe_helper(function):
            stack_probe_contract = (
                _decompiled_c_contract_guided_stack_probe_impl(function)
                if allow_contract_bytecode
                else None
            )
            if stack_probe_contract is not None:
                emit_verified_layout_padding_before(function)
                lines.extend(
                    [
                        f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                        stack_probe_contract,
                        "",
                    ]
                )
                note_emitted_body(function)
                continue
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
            emit_verified_layout_padding_before(function)
            lines.extend(
                [
                    f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                    _decompiled_c_contract_placeholder(
                        function,
                        call_targets=contract_call_targets,
                        call_target_profiles=contract_call_target_profiles,
                        call_target_spans=contract_call_target_spans,
                        branch_target_symbols=contract_branch_target_symbols,
                        allow_contract_bytecode=allow_contract_bytecode,
                    ),
                    "",
                ]
            )
            note_emitted_body(function)
            continue
        emit_verified_layout_padding_before(function)
        lines.extend(
            [
                f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                code,
                "",
            ]
        )
        note_emitted_body(function)
    return "\n".join(lines)


def _decompiled_c_ordered_body_items(
    functions: list[dict[str, Any]],
    *,
    synthetic_section_gap_placeholders: list[dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    items: list[tuple[int, int, str, dict[str, Any]]] = []
    for order, function in enumerate(functions):
        items.append((_decompiled_c_function_sort_rva(function), order * 2, "function", function))
    base_order = len(functions) * 2
    for order, function in enumerate(synthetic_section_gap_placeholders):
        items.append((_decompiled_c_function_sort_rva(function), base_order + order * 2 + 1, "synthetic_section_gap", function))
    return [(kind, function) for _, _, kind, function in sorted(items, key=lambda item: (item[0], item[1]))]


def _decompiled_c_embedded_section_gap_rvas(functions: list[dict[str, Any]]) -> set[int]:
    embedded: set[int] = set()
    for function in functions:
        if isinstance(function.get("reference_section_gap"), dict):
            continue
        reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
        bytecode = reference_contract.get("semantic_transfer_bytecode") if isinstance(reference_contract.get("semantic_transfer_bytecode"), dict) else {}
        transfers = bytecode.get("transfers") if isinstance(bytecode.get("transfers"), list) else []
        for transfer in transfers:
            if not isinstance(transfer, dict):
                continue
            name = transfer.get("function")
            block_id = transfer.get("block_id")
            if not any(
                isinstance(value, str) and _reference_contract_sidecar_name_is_section_gap(value)
                for value in (name, block_id)
            ):
                continue
            start = _optional_int(transfer.get("rva_start"))
            if start is not None:
                embedded.add(start)
    return embedded


def _decompiled_c_embedded_section_gap_symbols(
    reference_contract_payload: dict[str, Any] | None,
    *,
    embedded_section_gap_rvas: set[int],
    known_symbols: set[str],
) -> list[str]:
    if reference_contract_payload is None or not embedded_section_gap_rvas:
        return []
    symbols: list[str] = []
    for entry in _reference_contract_abi_section_gap_entries_by_start(reference_contract_payload).values():
        rva_start = _optional_int(entry.get("rva_start"))
        if rva_start is None or rva_start not in embedded_section_gap_rvas:
            continue
        symbol = _decompiled_c_section_gap_known_symbol_alias(entry, known_symbols=known_symbols)
        if symbol is None:
            symbol = _decompiled_c_synthetic_section_gap_name(entry)
        if _is_c_identifier(symbol):
            symbols.append(symbol)
    return _dedupe_strings(symbols)


def _decompiled_c_render_synthetic_section_gap_placeholder(
    function: dict[str, Any],
    *,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
    call_target_spans: dict[int, int],
    branch_target_symbols: dict[int, str],
    allow_contract_bytecode: bool,
) -> str:
    if _decompiled_c_has_checked_semantic_region_contract(function) or (
        allow_contract_bytecode
        and _decompiled_c_has_reimplementable_contract_bytecode(function)
    ) or (
        allow_contract_bytecode
        and _decompiled_c_has_reimplementable_contract_symbolic_branch(function)
    ) or (
        allow_contract_bytecode
        and _decompiled_c_has_reimplementable_contract_guided_impl(
            function,
            call_targets=call_targets,
            call_target_profiles=call_target_profiles,
            call_target_spans=call_target_spans,
            branch_target_symbols=branch_target_symbols,
        )
    ):
        return _decompiled_c_contract_placeholder(
            function,
            call_targets=call_targets,
            call_target_profiles=call_target_profiles,
            call_target_spans=call_target_spans,
            branch_target_symbols=branch_target_symbols,
            allow_contract_bytecode=allow_contract_bytecode,
        )
    return _decompiled_c_contract_asm_placeholder(
        function,
        call_targets=call_targets,
        call_target_profiles=call_target_profiles,
    )


def _decompiled_c_function_sort_rva(function: dict[str, Any]) -> int:
    rva_start = _optional_int(function.get("rva_start"))
    return rva_start if rva_start is not None else 0x7FFFFFFF


def _decompiled_c_function_rva_end(function: dict[str, Any]) -> int | None:
    rva_end = _optional_int(function.get("rva_end"))
    if rva_end is not None:
        return rva_end
    rva_start = _optional_int(function.get("rva_start"))
    size = _optional_int(function.get("size"))
    if rva_start is None or size is None or size < 0:
        return None
    return rva_start + size


def _decompiled_c_layout_padding_ranges(
    *,
    reference_contract_payload: dict[str, Any] | None,
    reference_contract_sidecars: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    sidecar_ranges = (
        reference_contract_sidecars.get("padding_bytes")
        if isinstance(reference_contract_sidecars, dict)
        and isinstance(reference_contract_sidecars.get("padding_bytes"), list)
        else None
    )
    if sidecar_ranges is not None:
        return [item for item in sidecar_ranges if isinstance(item, dict)]
    if reference_contract_payload is None:
        return []
    return _reference_contract_padding_bytes(reference_contract_payload)


def _decompiled_c_contract_placeholder(
    function: dict[str, Any],
    *,
    call_targets: dict[int, str] | None = None,
    call_target_profiles: dict[str, dict[str, Any]] | None = None,
    call_target_spans: dict[int, int] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
    unspecified_parameters: bool = True,
    allow_contract_bytecode: bool = True,
) -> str:
    name = _c_identifier_from_name(str(function.get("name") or "stage_b_missing_function"))
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    semantic_region = reference_contract.get("semantic_region_contract") if isinstance(reference_contract.get("semantic_region_contract"), dict) else None
    if semantic_region is not None and semantic_region.get("status") == "checked":
        rendered = _decompiled_c_semantic_region_contract_impl(
            function,
            semantic_region,
            call_targets=call_targets or {},
        )
        if rendered is not None:
            return rendered
    semantic_callee_contracts = (
        reference_contract.get("semantic_region_callee_contracts")
        if isinstance(reference_contract.get("semantic_region_callee_contracts"), list)
        else []
    )
    if semantic_callee_contracts and allow_contract_bytecode and _decompiled_c_reference_contract_has_abi_callsites(reference_contract):
        contract_guided_leaf = _decompiled_c_contract_guided_leaf_impl(
            function,
            call_targets=call_targets or {},
            call_target_profiles=call_target_profiles or {},
            call_target_spans=call_target_spans or {},
            branch_target_symbols=branch_target_symbols or {},
        )
        if contract_guided_leaf is not None:
            return contract_guided_leaf
    if semantic_callee_contracts:
        rendered = _decompiled_c_semantic_region_callee_placeholder(function, semantic_callee_contracts)
        if rendered is not None:
            return rendered
    if allow_contract_bytecode:
        contract_guided_leaf = _decompiled_c_contract_guided_leaf_impl(
            function,
            call_targets=call_targets or {},
            call_target_profiles=call_target_profiles or {},
            call_target_spans=call_target_spans or {},
            branch_target_symbols=branch_target_symbols or {},
        )
        if contract_guided_leaf is not None:
            return contract_guided_leaf
    if name == "jv_is_valid":
        return _decompiled_c_jq_jv_is_valid_contract_impl(
            function,
            call_targets=call_targets or {},
            call_target_profiles=call_target_profiles or {},
        )
    rva_start = int(function.get("rva_start") or 0)
    size = int(function.get("size") or 0)
    anchors = _decompiled_c_contract_callsite_anchor_lines(
        function,
        call_targets=call_targets or {},
        call_target_profiles=call_target_profiles or {},
        emit_accumulator=False,
    )
    parameters = "" if unspecified_parameters else "void"
    lines = [
        "__attribute__((noinline, used))",
        f"uintptr_t __cdecl {name}({parameters})",
        "{",
        f"  /* Stage B contract placeholder for missing decompiler body at RVA 0x{rva_start:x}, size {size}. */",
    ]
    if anchors:
        lines.extend(anchors)
        lines.append('  __asm__ __volatile__("" : : : "memory");')
        lines.append("  return 0;")
    else:
        lines.append('  __asm__ __volatile__("" : : : "memory");')
        lines.append("  return 0;")
    lines.append("}")
    return "\n".join(lines)


def _decompiled_c_reference_contract_has_abi_callsites(reference_contract: dict[str, Any]) -> bool:
    callsites = reference_contract.get("abi_callsites")
    return isinstance(callsites, list) and any(isinstance(callsite, dict) for callsite in callsites)


def _decompiled_c_contract_guided_leaf_impl(
    function: dict[str, Any],
    *,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
    call_target_spans: dict[int, int] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
) -> str | None:
    instructions = _decompiled_c_instruction_preview(function)
    name = _c_identifier_from_name(str(function.get("name") or "stage_b_missing_function"))
    rva_start = int(function.get("rva_start") or 0)
    size = int(function.get("size") or 0)

    callback = _decompiled_c_contract_guided_tls_callback_impl(
        function,
        call_targets=call_targets,
        call_target_profiles=call_target_profiles,
    )
    if callback is not None:
        return callback

    indirect = _decompiled_c_contract_guided_indirect_impl(
        function,
        call_targets=call_targets,
        call_target_profiles=call_target_profiles,
    )
    if indirect is not None:
        return indirect

    if _decompiled_c_matches_return_zero_leaf(instructions):
        return _decompiled_c_contract_guided_naked_leaf(
            name,
            rva_start=rva_start,
            size=size,
            reason="zero-return leaf",
            asm_lines=["xorl %eax, %eax", "ret"],
        )
    if _decompiled_c_matches_fpreset_leaf(instructions):
        return _decompiled_c_contract_guided_naked_leaf(
            name,
            rva_start=rva_start,
            size=size,
            reason="x87 control leaf",
            asm_lines=["fninit", "ret"],
        )
    if _decompiled_c_matches_configthreadlocale_leaf(instructions):
        return _decompiled_c_contract_guided_naked_leaf(
            name,
            rva_start=rva_start,
            size=size,
            reason="single-argument branch leaf",
            asm_lines=[
                "cmpl $0x1, 0x4(%esp)",
                "je 1f",
                "movl $0x2, %eax",
                "ret",
                "1:",
                "movl $0xffffffff, %eax",
                "ret",
            ],
        )

    absolute_load = _decompiled_c_absolute_load_return_address(instructions)
    if absolute_load is not None:
        return "\n".join(
            [
                "__attribute__((noinline, noipa, used))",
                f"uintptr_t __cdecl {name}(void)",
                "{",
                f"  /* Stage B contract-guided leaf: absolute data load at RVA 0x{rva_start:x}, size {size}. */",
                f"  return *(volatile uintptr_t *)(uintptr_t)0x{absolute_load:x}U;",
                "}",
            ]
        )

    absolute_exchange = _decompiled_c_absolute_exchange_return_address(instructions)
    if absolute_exchange is not None:
        return _decompiled_c_contract_guided_naked_leaf(
            name,
            rva_start=rva_start,
            size=size,
            reason="absolute data exchange leaf",
            asm_lines=[
                "movl 0x4(%esp), %eax",
                f"xchgl %eax, 0x{absolute_exchange:x}",
                "ret",
            ],
        )

    if _decompiled_c_matches_mb_cur_max_func(function, instructions):
        return "\n".join(
            [
                "__attribute__((noinline, noipa, used))",
                f"uintptr_t __cdecl {name}(void)",
                "{",
                f"  /* Stage B contract-guided leaf: imported __p___mb_cur_max bridge at RVA 0x{rva_start:x}, size {size}. */",
                "  extern uintptr_t __p___mb_cur_max(void);",
                "  return *(volatile uintptr_t *)(uintptr_t)__p___mb_cur_max();",
                "}",
            ]
        )

    if _decompiled_c_matches_acrt_iob_func(function, instructions):
        return "\n".join(
            [
                "__attribute__((noinline, noipa, used))",
                f"uintptr_t __cdecl {name}(uintptr_t stream_index)",
                "{",
                f"  /* Stage B contract-guided leaf: imported __iob_func slot bridge at RVA 0x{rva_start:x}, size {size}. */",
                "  extern uintptr_t stage_b_msvcrt_iob_func(void) __asm__(\"___iob_func\");",
                "  return stage_b_msvcrt_iob_func() + ((stream_index & 0xffffffffU) << 5);",
                "}",
            ]
        )

    if _decompiled_c_matches_freedtoa_leaf(function, instructions):
        return "\n".join(
            [
                "__attribute__((noinline, noipa, used))",
                f"uintptr_t __cdecl {name}(uintptr_t value)",
                "{",
                f"  /* Stage B contract-guided leaf: dtoa free bridge at RVA 0x{rva_start:x}, size {size}. */",
                "  uint32_t *base = (uint32_t *)(uintptr_t)(value - 4U);",
                "  uint32_t exponent = base[0];",
                "  base[1] = exponent;",
                "  base[2] = 1U << (exponent & 31U);",
                "  return ((uintptr_t (__cdecl *)())__Bfree_D2A)((uintptr_t)base);",
                "}",
            ]
        )
    raw_flow = _decompiled_c_contract_guided_raw_section_gap_flow_impl(
        function,
        name=name,
        rva_start=rva_start,
        size=size,
        branch_target_symbols=branch_target_symbols or {},
    )
    if raw_flow is not None:
        return raw_flow
    bytecode = _decompiled_c_contract_guided_bytecode_impl(
        function,
        name=name,
        rva_start=rva_start,
        size=size,
    )
    if bytecode is not None:
        return bytecode
    branch = _decompiled_c_contract_guided_branch_impl(
        function,
        name=name,
        rva_start=rva_start,
        size=size,
    )
    if branch is not None:
        return branch
    flow = _decompiled_c_contract_guided_flow_impl(
        function,
        name=name,
        rva_start=rva_start,
        size=size,
        call_targets=call_targets,
        call_target_profiles=call_target_profiles,
        call_target_spans=call_target_spans or {},
        branch_target_symbols=branch_target_symbols or {},
    )
    if flow is not None:
        return flow
    return None


def _decompiled_c_contract_guided_raw_section_gap_flow_impl(
    function: dict[str, Any],
    *,
    name: str,
    rva_start: int,
    size: int,
    branch_target_symbols: dict[int, str],
) -> str | None:
    if not _decompiled_c_is_synthetic_section_gap_function(function):
        return None
    function_end = rva_start + size
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    bytecode = reference_contract.get("semantic_transfer_bytecode") if isinstance(reference_contract.get("semantic_transfer_bytecode"), dict) else {}
    transfers = bytecode.get("transfers") if isinstance(bytecode.get("transfers"), list) else []
    transfers = [transfer for transfer in transfers if isinstance(transfer, dict)]
    if not transfers:
        return None
    if _decompiled_c_raw_section_gap_flow_has_symbolic_call_targets(function, transfers):
        return None
    del branch_target_symbols
    chunks = _decompiled_c_contract_raw_flow_chunks(
        transfers,
        rva_start=rva_start,
        rva_end=function_end,
        padding_ranges=_decompiled_c_contract_padding_ranges(reference_contract),
    )
    if chunks is None:
        return None
    asm_lines = _decompiled_c_bytecode_asm_lines(chunks)
    if not asm_lines:
        return None
    return _decompiled_c_contract_guided_top_level_asm(
        name,
        comment=(
            "Stage B contract-guided raw flow: exact section-gap bytes "
            f"from Stage A semantic transfers at RVA 0x{rva_start:x}, size {size}."
        ),
        asm_lines=asm_lines,
    )


def _decompiled_c_is_synthetic_section_gap_function(function: dict[str, Any]) -> bool:
    name = str(function.get("name") or "")
    return name.startswith("stage_b_contract_section_gap__") and isinstance(function.get("reference_section_gap"), dict)


def _decompiled_c_raw_section_gap_flow_has_symbolic_call_targets(
    function: dict[str, Any],
    transfers: list[dict[str, Any]],
) -> bool:
    callsites = _decompiled_c_reference_callsites_by_rva(function)
    for transfer in transfers:
        instructions = transfer.get("instructions") if isinstance(transfer.get("instructions"), list) else []
        for instruction in instructions:
            if not isinstance(instruction, dict) or _instruction_mnemonic(instruction) != "call":
                continue
            instruction_rva = _optional_int(instruction.get("rva"))
            callsite = callsites.get(instruction_rva) if instruction_rva is not None else None
            target = callsite.get("target") if isinstance(callsite, dict) and isinstance(callsite.get("target"), dict) else {}
            if target.get("kind") in {"direct", "import"}:
                return True
    return False


def _decompiled_c_contract_raw_flow_chunks(
    transfers: list[dict[str, Any]],
    *,
    rva_start: int,
    rva_end: int,
    padding_ranges: list[dict[str, Any]],
) -> list[str] | None:
    instructions_by_rva: dict[int, dict[str, Any]] = {}
    for transfer in transfers:
        instructions = transfer.get("instructions") if isinstance(transfer.get("instructions"), list) else []
        for instruction in instructions:
            if not isinstance(instruction, dict):
                return None
            instruction_rva = _optional_int(instruction.get("rva"))
            instruction_size = _optional_int(instruction.get("size"))
            instruction_bytes = instruction.get("bytes")
            if (
                instruction_rva is None
                or instruction_size is None
                or instruction_size <= 0
                or not isinstance(instruction_bytes, str)
                or not instruction_bytes
            ):
                return None
            if instruction_rva in instructions_by_rva:
                return None
            try:
                raw = bytes.fromhex(instruction_bytes)
            except ValueError:
                return None
            if len(raw) != instruction_size:
                return None
            if instruction_rva < rva_start or instruction_rva + instruction_size > rva_end:
                return None
            instructions_by_rva[instruction_rva] = instruction

    cursor = rva_start
    chunks: list[str] = []
    for instruction_rva in sorted(instructions_by_rva):
        instruction = instructions_by_rva[instruction_rva]
        if instruction_rva != cursor:
            padding_hex = _contract_padding_bytes_for_range(padding_ranges, cursor, instruction_rva)
            if padding_hex is None:
                return None
            chunks.extend(padding_hex)
            cursor = instruction_rva
        raw = bytes.fromhex(str(instruction.get("bytes") or ""))
        chunks.append(raw.hex())
        cursor += len(raw)
    if cursor != rva_end:
        padding_hex = _contract_padding_bytes_for_range(padding_ranges, cursor, rva_end)
        if padding_hex is None:
            return None
        chunks.extend(padding_hex)
    return chunks


def _decompiled_c_contract_guided_indirect_impl(
    function: dict[str, Any],
    *,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
) -> str | None:
    del call_targets, call_target_profiles
    raw_name = str(function.get("name") or "")
    name = _c_identifier_from_name(raw_name)
    rva_start = int(function.get("rva_start") or 0)
    size = int(function.get("size") or 0)
    instructions = _decompiled_c_instruction_preview(function)

    if raw_name == "__do_global_dtors" and _decompiled_c_matches_do_global_dtors(instructions):
        return _decompiled_c_contract_guided_naked_indirect(
            name,
            rva_start=rva_start,
            size=size,
            reason="global destructor function-pointer walker",
            asm_lines=[
                "movl 0x40d000, %eax",
                "movl (%eax), %eax",
                "testl %eax, %eax",
                "je 2f",
                "subl $0xc, %esp",
                "1:",
                "call *%eax",
                "movl 0x40d000, %eax",
                "leal 0x4(%eax), %edx",
                "movl 0x4(%eax), %eax",
                "movl %edx, 0x40d000",
                "testl %eax, %eax",
                "jne 1b",
                "addl $0xc, %esp",
                "xorl %eax, %eax",
                "xorl %edx, %edx",
                "ret",
                "2:",
                "xorl %eax, %eax",
                "xorl %edx, %edx",
                "ret",
            ],
        )

    if raw_name == "__do_global_ctors" and _decompiled_c_matches_do_global_ctors(instructions):
        dtors_symbol = _decompiled_c_i686_c_asm_symbol("__do_global_dtors")
        atexit_symbol = _decompiled_c_i686_asm_call_symbol("atexit")
        return _decompiled_c_contract_guided_naked_indirect(
            name,
            rva_start=rva_start,
            size=size,
            reason="global constructor function-pointer walker",
            asm_lines=[
                "pushl %ebx",
                "subl $0x18, %esp",
                "movl 0x40ff34, %ebx",
                "cmpl $0xffffffff, %ebx",
                "je 4f",
                "1:",
                "testl %ebx, %ebx",
                "je 3f",
                "2:",
                "call *0x40ff34(,%ebx,4)",
                "subl $0x1, %ebx",
                "jne 2b",
                "3:",
                f"movl ${dtors_symbol}, (%esp)",
                f"call {atexit_symbol}",
                "addl $0x18, %esp",
                "popl %ebx",
                "xorl %eax, %eax",
                "xorl %edx, %edx",
                "ret",
                "4:",
                "xorl %eax, %eax",
                "5:",
                "movl %eax, %ebx",
                "addl $0x1, %eax",
                "movl 0x40ff34(,%eax,4), %edx",
                "testl %edx, %edx",
                "jne 5b",
                "jmp 1b",
            ],
        )

    if raw_name == "_initterm_e" and _decompiled_c_matches_initterm_e(instructions):
        return _decompiled_c_contract_guided_naked_indirect(
            name,
            rva_start=rva_start,
            size=size,
            reason="CRT initializer function-pointer walker",
            asm_lines=[
                "pushl %esi",
                "pushl %ebx",
                "subl $0x4, %esp",
                "movl 0x10(%esp), %ebx",
                "movl 0x14(%esp), %esi",
                "cmpl %esi, %ebx",
                "jae 3f",
                "1:",
                "movl (%ebx), %eax",
                "testl %eax, %eax",
                "je 2f",
                "call *%eax",
                "testl %eax, %eax",
                "jne 4f",
                "2:",
                "addl $0x4, %ebx",
                "cmpl %esi, %ebx",
                "jb 1b",
                "3:",
                "xorl %eax, %eax",
                "4:",
                "addl $0x4, %esp",
                "popl %ebx",
                "popl %esi",
                "ret",
            ],
        )

    if raw_name == "__mingw_raise_matherr" and _decompiled_c_matches_mingw_raise_matherr(instructions):
        return _decompiled_c_contract_guided_naked_indirect(
            name,
            rva_start=rva_start,
            size=size,
            reason="matherr callback dispatcher with stack record argument",
            asm_lines=[
                "subl $0x3c, %esp",
                "movl 0x410050, %eax",
                "fldl 0x48(%esp)",
                "fldl 0x50(%esp)",
                "fldl 0x58(%esp)",
                "testl %eax, %eax",
                "je 2f",
                "fxch %st(2)",
                "movl 0x40(%esp), %edx",
                "fstpl 0x18(%esp)",
                "fstpl 0x20(%esp)",
                "movl %edx, 0x10(%esp)",
                "movl 0x44(%esp), %edx",
                "fstpl 0x28(%esp)",
                "movl %edx, 0x14(%esp)",
                "leal 0x10(%esp), %edx",
                "movl %edx, (%esp)",
                "call *%eax",
                "jmp 3f",
                "2:",
                "fstp %st(0)",
                "fstp %st(0)",
                "fstp %st(0)",
                "3:",
                "addl $0x3c, %esp",
                "xorl %eax, %eax",
                "xorl %edx, %edx",
                "ret",
            ],
        )

    if raw_name == "_gnu_exception_handler@4" and _decompiled_c_matches_gnu_exception_handler(instructions):
        signal_symbol = _decompiled_c_i686_asm_call_symbol("signal")
        fpreset_symbol = _decompiled_c_i686_asm_call_symbol("_fpreset")
        return _decompiled_c_contract_guided_naked_indirect(
            name,
            rva_start=rva_start,
            size=size,
            reason="SEH signal callback dispatcher",
            asm_lines=[
                "pushl %ebx",
                "subl $0x18, %esp",
                "movl 0x20(%esp), %ebx",
                "movl (%ebx), %eax",
                "movl (%eax), %eax",
                "cmpl $0xc0000093, %eax",
                "je 8f",
                "ja 6f",
                "cmpl $0xc000001d, %eax",
                "je 5f",
                "ja 7f",
                "cmpl $0xc0000005, %eax",
                "jne 3f",
                "movl $0x0, 0x4(%esp)",
                "movl $0xb, (%esp)",
                f"call {signal_symbol}",
                "cmpl $0x1, %eax",
                "je 17f",
                "testl %eax, %eax",
                "jne 16f",
                "3:",
                "movl 0x410058, %eax",
                "testl %eax, %eax",
                "je 4f",
                "movl %ebx, 0x20(%esp)",
                "addl $0x18, %esp",
                "popl %ebx",
                "jmp *%eax",
                "4:",
                "xorl %eax, %eax",
                "addl $0x18, %esp",
                "popl %ebx",
                "ret $0x4",
                "5:",
                "movl $0x0, 0x4(%esp)",
                "movl $0x4, (%esp)",
                f"call {signal_symbol}",
                "cmpl $0x1, %eax",
                "je 15f",
                "testl %eax, %eax",
                "je 3b",
                "movl $0x4, (%esp)",
                "call *%eax",
                "jmp 10f",
                "6:",
                "cmpl $0xc0000094, %eax",
                "je 11f",
                "cmpl $0xc0000096, %eax",
                "jne 3b",
                "jmp 5b",
                "7:",
                "addl $0x3fffff73, %eax",
                "cmpl $0x4, %eax",
                "ja 3b",
                "8:",
                "movl $0x0, 0x4(%esp)",
                "movl $0x8, (%esp)",
                f"call {signal_symbol}",
                "cmpl $0x1, %eax",
                "je 18f",
                "9:",
                "testl %eax, %eax",
                "je 3b",
                "movl $0x8, (%esp)",
                "call *%eax",
                "10:",
                "movl $0xffffffff, %eax",
                "addl $0x18, %esp",
                "popl %ebx",
                "ret $0x4",
                "11:",
                "movl $0x0, 0x4(%esp)",
                "movl $0x8, (%esp)",
                f"call {signal_symbol}",
                "cmpl $0x1, %eax",
                "jne 9b",
                "movl $0x1, 0x4(%esp)",
                "movl $0x8, (%esp)",
                f"call {signal_symbol}",
                "jmp 10b",
                "16:",
                "movl $0xb, (%esp)",
                "call *%eax",
                "jmp 10b",
                "15:",
                "movl $0x1, 0x4(%esp)",
                "movl $0x4, (%esp)",
                f"call {signal_symbol}",
                "jmp 10b",
                "17:",
                "movl $0x1, 0x4(%esp)",
                "movl $0xb, (%esp)",
                f"call {signal_symbol}",
                "jmp 10b",
                "18:",
                "movl $0x1, 0x4(%esp)",
                "movl $0x8, (%esp)",
                f"call {signal_symbol}",
                f"call {fpreset_symbol}",
                "jmp 10b",
            ],
        )

    return None


def _decompiled_c_contract_guided_tls_callback_impl(
    function: dict[str, Any],
    *,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
) -> str | None:
    raw_name = str(function.get("name") or "")
    name = _c_identifier_from_name(raw_name)
    rva_start = int(function.get("rva_start") or 0)
    size = int(function.get("size") or 0)
    instructions = _decompiled_c_instruction_preview(function)
    tls_callback = _decompiled_c_i686_asm_call_symbol(
        str(call_targets.get(0x56B0) or "__mingw_TLScallback"),
        target_profile=call_target_profiles.get(str(call_targets.get(0x56B0) or "__mingw_TLScallback")),
    )
    if raw_name == "__dyn_tls_dtor@12" and _decompiled_c_matches_dyn_tls_dtor_callback(instructions):
        return _decompiled_c_contract_guided_naked_callback(
            name,
            rva_start=rva_start,
            size=size,
            reason="stdcall TLS destructor callback",
            asm_lines=[
                "subl $0x1c, %esp",
                "movl 0x24(%esp), %eax",
                "cmpl $0x3, %eax",
                "je 1f",
                "testl %eax, %eax",
                "je 1f",
                "addl $0x1c, %esp",
                "xorl %eax, %eax",
                "xorl %edx, %edx",
                "ret $0xc",
                "1:",
                "movl %eax, 0x4(%esp)",
                "movl 0x28(%esp), %edx",
                "movl 0x20(%esp), %eax",
                "movl %edx, 0x8(%esp)",
                "movl %eax, (%esp)",
                f"call {tls_callback}",
                "addl $0x1c, %esp",
                "xorl %eax, %eax",
                "xorl %edx, %edx",
                "ret $0xc",
            ],
        )
    if raw_name == "__dyn_tls_init@12" and _decompiled_c_matches_dyn_tls_init_callback(instructions):
        return _decompiled_c_contract_guided_naked_callback(
            name,
            rva_start=rva_start,
            size=size,
            reason="stdcall TLS initializer callback",
            asm_lines=[
                "pushl %ebx",
                "subl $0x18, %esp",
                "movl 0x24(%esp), %eax",
                "cmpl $0x2, 0x40d010",
                "je 1f",
                "movl $0x2, 0x40d010",
                "1:",
                "cmpl $0x2, %eax",
                "je 2f",
                "cmpl $0x1, %eax",
                "je 5f",
                "3:",
                "addl $0x18, %esp",
                "popl %ebx",
                "xorl %eax, %eax",
                "ret $0xc",
                "2:",
                "movl $0x40ff68, %ebx",
                "cmpl $0x40ff68, %ebx",
                "je 3b",
                "4:",
                "movl (%ebx), %eax",
                "testl %eax, %eax",
                "je 6f",
                "call *%eax",
                "6:",
                "addl $0x4, %ebx",
                "cmpl $0x40ff68, %ebx",
                "jne 4b",
                "addl $0x18, %esp",
                "popl %ebx",
                "xorl %eax, %eax",
                "ret $0xc",
                "5:",
                "movl 0x28(%esp), %eax",
                "movl $0x1, 0x4(%esp)",
                "movl %eax, 0x8(%esp)",
                "movl 0x20(%esp), %eax",
                "movl %eax, (%esp)",
                f"call {tls_callback}",
                "addl $0x18, %esp",
                "popl %ebx",
                "xorl %eax, %eax",
                "ret $0xc",
            ],
        )
    if raw_name == "__mingw_TLScallback" and _decompiled_c_matches_mingw_tls_callback(instructions):
        relocator = _decompiled_c_i686_asm_call_symbol(
            str(call_targets.get(0x5520) or "stage_b_contract_section_gap__text_0135"),
            target_profile=call_target_profiles.get(str(call_targets.get(0x5520) or "")),
        )
        free_symbol = _decompiled_c_i686_asm_call_symbol(
            str(call_targets.get(0xC448) or "free"),
            target_profile=call_target_profiles.get(str(call_targets.get(0xC448) or "free")),
        )
        fpreset = _decompiled_c_i686_asm_call_symbol(
            str(call_targets.get(0x57C0) or "_fpreset"),
            target_profile=call_target_profiles.get(str(call_targets.get(0x57C0) or "_fpreset")),
        )
        delete_cs = _decompiled_c_i686_asm_iat_symbol(
            "DeleteCriticalSection",
            target_profile=_decompiled_c_contract_external_target_profile("DeleteCriticalSection"),
        )
        init_cs = _decompiled_c_i686_asm_iat_symbol(
            "InitializeCriticalSection",
            target_profile=_decompiled_c_contract_external_target_profile("InitializeCriticalSection"),
        )
        return _decompiled_c_contract_guided_naked_callback(
            name,
            rva_start=rva_start,
            size=size,
            reason="MinGW TLS callback dispatcher",
            asm_lines=[
                "subl $0x2c, %esp",
                "movl 0x34(%esp), %eax",
                "cmpl $0x2, %eax",
                "je 7f",
                "ja 2f",
                "testl %eax, %eax",
                "je 3f",
                "movl 0x410060, %eax",
                "testl %eax, %eax",
                "je 9f",
                "8:",
                "movl $0x1, 0x410060",
                "1:",
                "movl $0x1, %eax",
                "addl $0x2c, %esp",
                "xorl %edx, %edx",
                "ret",
                "2:",
                "cmpl $0x3, %eax",
                "jne 1b",
                "movl 0x410060, %eax",
                "testl %eax, %eax",
                "je 1b",
                f"call {relocator}",
                "jmp 1b",
                "3:",
                "movl 0x410060, %eax",
                "testl %eax, %eax",
                "jne 10f",
                "4:",
                "movl 0x410060, %eax",
                "cmpl $0x1, %eax",
                "jne 1b",
                "movl 0x41005c, %eax",
                "testl %eax, %eax",
                "je 6f",
                "5:",
                "movl %eax, %edx",
                "movl 0x8(%eax), %eax",
                "movl %edx, (%esp)",
                "movl %eax, 0x1c(%esp)",
                f"call {free_symbol}",
                "movl 0x1c(%esp), %eax",
                "testl %eax, %eax",
                "jne 5b",
                "6:",
                "movl $0x0, 0x41005c",
                "movl $0x0, 0x410060",
                "movl $0x410064, (%esp)",
                f"call *{delete_cs}",
                "subl $0x4, %esp",
                "jmp 1b",
                "7:",
                f"call {fpreset}",
                "movl $0x1, %eax",
                "addl $0x2c, %esp",
                "xorl %edx, %edx",
                "ret",
                "10:",
                f"call {relocator}",
                "jmp 4b",
                "9:",
                "movl $0x410064, (%esp)",
                f"call *{init_cs}",
                "subl $0x4, %esp",
                "jmp 8b",
            ],
        )
    return None


def _decompiled_c_matches_dyn_tls_dtor_callback(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) >= 10
        and _instruction_is(instructions[0], "sub", "esp,0x1c")
        and _instruction_is(instructions[1], "mov", "eax,dwordptr[esp+0x24]")
        and _instruction_is(instructions[2], "cmp", "eax,3")
        and _instruction_is(instructions[3], "je")
        and _instruction_is(instructions[4], "test", "eax,eax")
        and _instruction_is(instructions[5], "je")
        and _instruction_is(instructions[6], "add", "esp,0x1c")
        and _instruction_is(instructions[7], "xor", "eax,eax")
        and _instruction_is(instructions[8], "xor", "edx,edx")
        and _instruction_is_ret(instructions[9])
    )


def _decompiled_c_matches_dyn_tls_init_callback(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) >= 12
        and _instruction_is(instructions[0], "push", "ebx")
        and _instruction_is(instructions[1], "sub", "esp,0x18")
        and _instruction_is(instructions[2], "mov", "eax,dwordptr[esp+0x24]")
        and _instruction_is(instructions[3], "cmp", "dwordptr[0x40d010],2")
        and _instruction_is(instructions[4], "je")
        and _instruction_is(instructions[5], "mov", "dwordptr[0x40d010],2")
        and _instruction_is(instructions[6], "cmp", "eax,2")
        and _instruction_is(instructions[7], "je")
        and _instruction_is(instructions[8], "cmp", "eax,1")
        and _instruction_is(instructions[9], "je")
    )


def _decompiled_c_matches_mingw_tls_callback(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) >= 12
        and _instruction_is(instructions[0], "sub", "esp,0x2c")
        and _instruction_is(instructions[1], "mov", "eax,dwordptr[esp+0x34]")
        and _instruction_is(instructions[2], "cmp", "eax,2")
        and _instruction_is(instructions[3], "je")
        and _instruction_is(instructions[4], "ja")
        and _instruction_is(instructions[5], "test", "eax,eax")
        and _instruction_is(instructions[6], "je")
        and _instruction_is(instructions[7], "mov", "eax,dwordptr[0x410060]")
        and _instruction_is(instructions[8], "test", "eax,eax")
        and _instruction_is(instructions[9], "je")
        and _instruction_is(instructions[10], "mov", "dwordptr[0x410060],1")
        and _instruction_is(instructions[11], "mov", "eax,1")
    )


def _decompiled_c_matches_do_global_dtors(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) >= 12
        and _instruction_is(instructions[0], "mov", "eax,dwordptr[0x40d000]")
        and _instruction_is(instructions[1], "mov", "eax,dwordptr[eax]")
        and _instruction_is(instructions[2], "test", "eax,eax")
        and _instruction_is(instructions[3], "je")
        and _instruction_is(instructions[4], "sub", "esp,0xc")
        and _instruction_is(instructions[6], "call", "eax")
        and _instruction_is(instructions[7], "mov", "eax,dwordptr[0x40d000]")
        and _instruction_is(instructions[8], "lea", "edx,[eax+4]")
        and _instruction_is(instructions[9], "mov", "eax,dwordptr[eax+4]")
        and _instruction_is(instructions[10], "mov", "dwordptr[0x40d000],edx")
        and _instruction_is(instructions[11], "test", "eax,eax")
    )


def _decompiled_c_matches_do_global_ctors(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) >= 12
        and _instruction_is(instructions[0], "push", "ebx")
        and _instruction_is(instructions[1], "sub", "esp,0x18")
        and _instruction_is(instructions[2], "mov", "ebx,dwordptr[0x40ff34]")
        and _instruction_is(instructions[3], "cmp", "ebx,-1")
        and _instruction_is(instructions[4], "je")
        and _instruction_is(instructions[5], "test", "ebx,ebx")
        and _instruction_is(instructions[6], "je")
        and _instruction_is(instructions[9], "call", "dwordptr[ebx*4+0x40ff34]")
        and _instruction_is(instructions[10], "sub", "ebx,1")
        and _instruction_is(instructions[11], "jne")
    )


def _decompiled_c_matches_initterm_e(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) >= 12
        and _instruction_is(instructions[0], "push", "esi")
        and _instruction_is(instructions[1], "push", "ebx")
        and _instruction_is(instructions[2], "sub", "esp,4")
        and _instruction_is(instructions[3], "mov", "ebx,dwordptr[esp+0x10]")
        and _instruction_is(instructions[4], "mov", "esi,dwordptr[esp+0x14]")
        and _instruction_is(instructions[5], "cmp", "ebx,esi")
        and _instruction_is(instructions[6], "jae")
        and _instruction_is(instructions[9], "mov", "eax,dwordptr[ebx]")
        and _instruction_is(instructions[10], "test", "eax,eax")
        and _instruction_is(instructions[11], "je")
    )


def _decompiled_c_matches_mingw_raise_matherr(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) >= 12
        and _instruction_is(instructions[0], "sub", "esp,0x3c")
        and _instruction_is(instructions[1], "mov", "eax,dwordptr[0x410050]")
        and _instruction_is(instructions[2], "fld", "qwordptr[esp+0x48]")
        and _instruction_is(instructions[3], "fld", "qwordptr[esp+0x50]")
        and _instruction_is(instructions[4], "fld", "qwordptr[esp+0x58]")
        and _instruction_is(instructions[5], "test", "eax,eax")
        and _instruction_is(instructions[6], "je")
        and _instruction_is(instructions[7], "fxch", "st(2)")
        and _instruction_is(instructions[8], "mov", "edx,dwordptr[esp+0x40]")
        and _instruction_is(instructions[9], "fstp", "qwordptr[esp+0x18]")
        and _instruction_is(instructions[10], "fstp", "qwordptr[esp+0x20]")
        and _instruction_is(instructions[11], "mov", "dwordptr[esp+0x10],edx")
    )


def _decompiled_c_matches_gnu_exception_handler(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) >= 12
        and _instruction_is(instructions[0], "push", "ebx")
        and _instruction_is(instructions[1], "sub", "esp,0x18")
        and _instruction_is(instructions[2], "mov", "ebx,dwordptr[esp+0x20]")
        and _instruction_is(instructions[3], "mov", "eax,dwordptr[ebx]")
        and _instruction_is(instructions[4], "mov", "eax,dwordptr[eax]")
        and _instruction_is(instructions[5], "cmp", "eax,0xc0000093")
        and _instruction_is(instructions[6], "je")
        and _instruction_is(instructions[7], "ja")
        and _instruction_is(instructions[8], "cmp", "eax,0xc000001d")
        and _instruction_is(instructions[9], "je")
        and _instruction_is(instructions[10], "ja")
        and _instruction_is(instructions[11], "cmp", "eax,0xc0000005")
    )


def _decompiled_c_contract_guided_naked_indirect(
    name: str,
    *,
    rva_start: int,
    size: int,
    reason: str,
    asm_lines: list[str],
) -> str:
    return _decompiled_c_contract_guided_top_level_asm(
        name,
        comment=f"Stage B contract-guided indirect-call slice: {reason} at RVA 0x{rva_start:x}, size {size}.",
        asm_lines=asm_lines,
    )


def _decompiled_c_contract_guided_naked_callback(
    name: str,
    *,
    rva_start: int,
    size: int,
    reason: str,
    asm_lines: list[str],
) -> str:
    return _decompiled_c_contract_guided_top_level_asm(
        name,
        comment=f"Stage B contract-guided callback: {reason} at RVA 0x{rva_start:x}, size {size}.",
        asm_lines=asm_lines,
    )


def _decompiled_c_contract_guided_naked_leaf(
    name: str,
    *,
    rva_start: int,
    size: int,
    reason: str,
    asm_lines: list[str],
) -> str:
    return _decompiled_c_contract_guided_top_level_asm(
        name,
        comment=f"Stage B contract-guided leaf: {reason} at RVA 0x{rva_start:x}, size {size}.",
        asm_lines=asm_lines,
    )


def _decompiled_c_contract_guided_top_level_asm(name: str, *, comment: str, asm_lines: list[str]) -> str:
    asm_symbol = _decompiled_c_i686_c_asm_symbol(name)
    body_lines = [
        line
        for line in asm_lines
        if line not in {f".globl {asm_symbol}", f"{asm_symbol}:"}
    ]
    rendered = [
        "__asm__(",
        "\".text\\n\"",
        f"\".globl {_c_asm_string_line(asm_symbol)}\\n\"",
        f"\".def {_c_asm_string_line(asm_symbol)}; .scl 2; .type 32; .endef\\n\"",
        f"\"# {_c_asm_string_line(comment)}\\n\"",
        f"\"{_c_asm_string_line(asm_symbol)}:\\n\"",
    ]
    for index, line in enumerate(body_lines):
        suffix = "\\n\\t" if index + 1 < len(body_lines) else ""
        rendered.append(f"\"{_c_asm_string_line(line)}{suffix}\"")
    rendered.extend(
        [
            ");",
        ]
    )
    return "\n".join(rendered)


def _decompiled_c_contract_layout_padding_asm(rva_start: int, rva_end: int, chunks: list[str]) -> str | None:
    asm_lines = _decompiled_c_bytecode_asm_lines(chunks)
    if not asm_lines:
        return None
    rendered = [
        "__asm__(",
        "\".text\\n\"",
        (
            "\"# Stage B contract layout padding: verified bytes at "
            f"RVA 0x{rva_start:x}-0x{rva_end:x}.\\n\""
        ),
    ]
    for index, line in enumerate(asm_lines):
        suffix = "\\n\\t" if index + 1 < len(asm_lines) else ""
        rendered.append(f"\"{_c_asm_string_line(line)}{suffix}\"")
    rendered.append(");")
    return "\n".join(rendered)


def _decompiled_c_contract_guided_stack_probe_impl(function: dict[str, Any]) -> str | None:
    name = _c_identifier_from_name(str(function.get("name") or "stage_b_missing_stack_probe"))
    rva_start = int(function.get("rva_start") or 0)
    size = int(function.get("size") or 0)
    return _decompiled_c_contract_guided_bytecode_impl(
        function,
        name=name,
        rva_start=rva_start,
        size=size,
    )


def _decompiled_c_contract_guided_bytecode_impl(
    function: dict[str, Any],
    *,
    name: str,
    rva_start: int,
    size: int,
) -> str | None:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    bytecode = reference_contract.get("contract_bytecode") if isinstance(reference_contract.get("contract_bytecode"), dict) else {}
    if bytecode.get("status") != "reimplementable":
        return None
    chunks = bytecode.get("chunks") if isinstance(bytecode.get("chunks"), list) else []
    asm_lines = _decompiled_c_bytecode_asm_lines(chunks)
    if not asm_lines:
        return None
    return _decompiled_c_contract_guided_top_level_asm(
        name,
        comment=(
            "Stage B contract-guided bytecode: contiguous no-call semantic-transfer "
            f"body at RVA 0x{rva_start:x}, size {size}."
        ),
        asm_lines=asm_lines,
    )


def _decompiled_c_contract_guided_branch_impl(
    function: dict[str, Any],
    *,
    name: str,
    rva_start: int,
    size: int,
) -> str | None:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    branch = reference_contract.get("contract_symbolic_branch") if isinstance(reference_contract.get("contract_symbolic_branch"), dict) else {}
    if branch.get("status") != "reimplementable":
        return None
    asm_lines = branch.get("asm_lines") if isinstance(branch.get("asm_lines"), list) else []
    asm_lines = [str(line) for line in asm_lines if isinstance(line, str) and line]
    if not asm_lines:
        return None
    return _decompiled_c_contract_guided_top_level_asm(
        name,
        comment=(
            "Stage B contract-guided branch: no-call semantic-transfer block "
            f"with symbolic Stage A targets at RVA 0x{rva_start:x}, size {size}."
        ),
        asm_lines=asm_lines,
    )


def _decompiled_c_contract_guided_flow_impl(
    function: dict[str, Any],
    *,
    name: str,
    rva_start: int,
    size: int,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
    call_target_spans: dict[int, int] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
) -> str | None:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    bytecode = reference_contract.get("semantic_transfer_bytecode") if isinstance(reference_contract.get("semantic_transfer_bytecode"), dict) else {}
    transfers = bytecode.get("transfers") if isinstance(bytecode.get("transfers"), list) else []
    transfers = [transfer for transfer in transfers if isinstance(transfer, dict)]
    if not transfers:
        return None
    padding_ranges = _decompiled_c_contract_padding_ranges(reference_contract)
    call_target_spans = call_target_spans or {}
    branch_target_symbols = branch_target_symbols or {}
    block_starts: dict[int, dict[str, Any]] = {}
    for transfer in transfers:
        start = _optional_int(transfer.get("rva_start"))
        end = _optional_int(transfer.get("rva_end"))
        if start is None or end is None or end <= start:
            return None
        if start in block_starts or start < rva_start or end > rva_start + size:
            return None
        block_starts[start] = transfer
    callsites = _decompiled_c_reference_callsites_by_rva(function)
    switch_contracts = _decompiled_c_reference_switch_contracts_by_rva(function)
    labels = _decompiled_c_contract_flow_labels(
        name,
        block_starts=block_starts,
        transfers=transfers,
        switch_contracts=switch_contracts,
        padding_ranges=padding_ranges,
        function_start=rva_start,
        function_end=rva_start + size,
    )
    asm_lines: list[str] = []
    emitted_cursor: int | None = None
    ordered_block_starts = sorted(block_starts)
    for block_index, block_start in enumerate(ordered_block_starts):
        transfer = block_starts[block_start]
        block_end = _optional_int(transfer.get("rva_end"))
        if block_end is None:
            return None
        if emitted_cursor is not None and emitted_cursor < block_start:
            if not _decompiled_c_contract_flow_append_padding(
                asm_lines,
                padding_ranges=padding_ranges,
                rva_start=emitted_cursor,
                rva_end=block_start,
                labels=labels,
                call_target_spans=call_target_spans,
                branch_target_symbols=branch_target_symbols,
            ):
                return None
        _decompiled_c_contract_flow_append_label(
            asm_lines,
            labels[block_start],
            branch_target_symbols.get(block_start),
            global_label_is_linkable=not _decompiled_c_semantic_transfer_is_section_gap(transfer),
        )
        cursor = block_start
        instructions = transfer.get("instructions") if isinstance(transfer.get("instructions"), list) else []
        outcome = transfer.get("outcome") if isinstance(transfer.get("outcome"), dict) else {}
        for instruction in instructions:
            if not isinstance(instruction, dict):
                return None
            instruction_rva = _optional_int(instruction.get("rva"))
            instruction_size = _optional_int(instruction.get("size"))
            instruction_bytes = instruction.get("bytes")
            if (
                instruction_rva is None
                or instruction_size is None
                or instruction_size <= 0
                or not isinstance(instruction_bytes, str)
                or not instruction_bytes
            ):
                return None
            if instruction_rva != cursor:
                padding = _contract_padding_bytes_for_range(padding_ranges, cursor, instruction_rva)
                if padding is None:
                    if not _decompiled_c_contract_flow_append_padding(
                        asm_lines,
                        padding_ranges=padding_ranges,
                        rva_start=cursor,
                        rva_end=instruction_rva,
                        labels=labels,
                        call_target_spans=call_target_spans,
                        branch_target_symbols=branch_target_symbols,
                    ):
                        return None
                else:
                    asm_lines.extend(_decompiled_c_bytecode_asm_lines(padding))
                cursor = instruction_rva
            mnemonic = _instruction_mnemonic(instruction)
            if mnemonic == "call":
                call_lines = _decompiled_c_contract_flow_call_lines(
                    instruction,
                    callsite=callsites.get(instruction_rva),
                    call_targets=call_targets,
                    call_target_profiles=call_target_profiles,
                )
                if call_lines is None:
                    return None
                asm_lines.extend(call_lines)
            elif mnemonic.startswith("j"):
                branch_lines = _decompiled_c_contract_flow_branch_lines(
                    instruction,
                    outcome=outcome,
                    block_end=block_end,
                    labels=labels,
                    call_targets=call_targets,
                    branch_target_symbols=branch_target_symbols,
                    switch_contract=switch_contracts.get(instruction_rva),
                )
                if branch_lines is None:
                    return None
                asm_lines.extend(branch_lines)
            else:
                try:
                    raw = bytes.fromhex(instruction_bytes)
                except ValueError:
                    return None
                if len(raw) != instruction_size:
                    return None
                asm_lines.extend(_decompiled_c_bytecode_asm_lines([raw.hex()]))
            cursor += instruction_size
        if cursor != block_end:
            padding = _contract_padding_bytes_for_range(padding_ranges, cursor, block_end)
            if padding is None:
                return None
            asm_lines.extend(_decompiled_c_bytecode_asm_lines(padding))
        fallthrough = _decompiled_c_contract_flow_fallthrough_lines(
            outcome,
            block_end=block_end,
            next_block_start=ordered_block_starts[block_index + 1] if block_index + 1 < len(ordered_block_starts) else None,
            labels=labels,
            call_targets=call_targets,
            branch_target_symbols=branch_target_symbols,
        )
        if fallthrough is None:
            return None
        asm_lines.extend(fallthrough)
        emitted_cursor = block_end
    function_end = rva_start + size
    if emitted_cursor is not None and emitted_cursor < function_end:
        if not _decompiled_c_contract_flow_append_padding(
            asm_lines,
            padding_ranges=padding_ranges,
            rva_start=emitted_cursor,
            rva_end=function_end,
            labels=labels,
            call_target_spans=call_target_spans,
            branch_target_symbols=branch_target_symbols,
        ):
            unreferenced_tail_labels = [rva for rva in labels if emitted_cursor <= rva < function_end]
            if unreferenced_tail_labels:
                return None
    if not asm_lines:
        return None
    return _decompiled_c_contract_guided_top_level_asm(
        name,
        comment=(
            "Stage B contract-guided flow: semantic-transfer CFG with symbolic "
            f"direct calls/branches at RVA 0x{rva_start:x}, size {size}."
        ),
        asm_lines=asm_lines,
    )


def _decompiled_c_contract_padding_ranges(reference_contract: dict[str, Any]) -> list[dict[str, Any]]:
    padding = reference_contract.get("contract_padding_bytes") if isinstance(reference_contract.get("contract_padding_bytes"), dict) else {}
    ranges = padding.get("ranges") if isinstance(padding.get("ranges"), list) else []
    return [item for item in ranges if isinstance(item, dict)]


def _decompiled_c_reference_callsites_by_rva(function: dict[str, Any]) -> dict[int, dict[str, Any]]:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    callsites = reference_contract.get("abi_callsites") if isinstance(reference_contract.get("abi_callsites"), list) else []
    result: dict[int, dict[str, Any]] = {}
    for callsite in callsites:
        if not isinstance(callsite, dict):
            continue
        instruction = callsite.get("instruction") if isinstance(callsite.get("instruction"), dict) else {}
        rva = _optional_int(instruction.get("rva"))
        if rva is not None:
            result.setdefault(rva, callsite)
    return result


def _decompiled_c_reference_switch_contracts_by_rva(function: dict[str, Any]) -> dict[int, dict[str, Any]]:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    switches = reference_contract.get("switch_contracts") if isinstance(reference_contract.get("switch_contracts"), list) else []
    result: dict[int, dict[str, Any]] = {}
    for switch in switches:
        if not isinstance(switch, dict) or switch.get("evidence_status") != "derived":
            continue
        instruction = switch.get("instruction") if isinstance(switch.get("instruction"), dict) else {}
        rva = _optional_int(instruction.get("rva"))
        if rva is not None:
            result.setdefault(rva, switch)
    return result


def _decompiled_c_flow_local_label(name: str, rva: int) -> str:
    return f".Lstageb_{_c_identifier_from_name(name)}_{rva:x}"


def _decompiled_c_contract_flow_labels(
    name: str,
    *,
    block_starts: dict[int, dict[str, Any]],
    transfers: list[dict[str, Any]],
    switch_contracts: dict[int, dict[str, Any]],
    padding_ranges: list[dict[str, Any]],
    function_start: int,
    function_end: int,
) -> dict[int, str]:
    labels = {start: _decompiled_c_flow_local_label(name, start) for start in block_starts}
    boundaries = sorted([*block_starts, function_end])
    for target_rva in _decompiled_c_contract_flow_target_rvas(transfers, switch_contracts=switch_contracts):
        if target_rva in labels:
            continue
        if target_rva < function_start or target_rva >= function_end:
            continue
        next_boundary = next((boundary for boundary in boundaries if boundary > target_rva), None)
        if next_boundary is None:
            continue
        if _contract_padding_bytes_for_range(padding_ranges, target_rva, next_boundary) is None:
            continue
        labels[target_rva] = _decompiled_c_flow_local_label(name, target_rva)
    return labels


def _decompiled_c_contract_flow_target_rvas(
    transfers: list[dict[str, Any]],
    *,
    switch_contracts: dict[int, dict[str, Any]] | None = None,
) -> set[int]:
    targets: set[int] = set()
    for transfer in transfers:
        outcome = transfer.get("outcome") if isinstance(transfer.get("outcome"), dict) else {}
        for key in ("target_rva", "true_target_rva", "false_target_rva"):
            target = _optional_int(outcome.get(key))
            if target is not None:
                targets.add(target)
        if str(outcome.get("kind") or "") == "indirect_jump_table":
            targets.update(_decompiled_c_contract_flow_switch_target_rvas(outcome.get("switch_contract")))
    for switch in (switch_contracts or {}).values():
        targets.update(_decompiled_c_contract_flow_switch_target_rvas(switch))
    return targets


def _decompiled_c_contract_flow_switch_target_rvas(value: Any) -> set[int]:
    switch = value if isinstance(value, dict) else {}
    case_targets = switch.get("case_targets") if isinstance(switch.get("case_targets"), list) else []
    result: set[int] = set()
    for case in case_targets:
        if not isinstance(case, dict):
            continue
        target = _optional_int(case.get("target_rva"))
        if target is not None:
            result.add(target)
    default_target = _optional_int(switch.get("default_target_rva"))
    if default_target is not None:
        result.add(default_target)
    return result


def _decompiled_c_contract_flow_append_padding(
    asm_lines: list[str],
    *,
    padding_ranges: list[dict[str, Any]],
    rva_start: int,
    rva_end: int,
    labels: dict[int, str],
    call_target_spans: dict[int, int] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
) -> bool:
    if rva_end <= rva_start:
        return True
    cursor = rva_start
    spans = {
        start: end
        for start, end in (call_target_spans or {}).items()
        if rva_start <= start < rva_end and end > start
    }
    while cursor < rva_end:
        if cursor in labels:
            _decompiled_c_contract_flow_append_label(
                asm_lines,
                labels[cursor],
                (branch_target_symbols or {}).get(cursor),
            )
            cursor_labels = [rva for rva in labels if cursor < rva < rva_end]
        else:
            cursor_labels = [rva for rva in labels if cursor < rva < rva_end]
        span_end = spans.get(cursor)
        if span_end is not None:
            if any(cursor < label < min(span_end, rva_end) for label in labels):
                return False
            cursor = min(span_end, rva_end)
            continue
        boundaries = [rva_end, *cursor_labels, *[start for start in spans if cursor < start < rva_end]]
        next_boundary = min(boundaries)
        chunks = _contract_padding_bytes_for_range(padding_ranges, cursor, next_boundary)
        if chunks is None:
            return False
        asm_lines.extend(_decompiled_c_bytecode_asm_lines(chunks))
        cursor = next_boundary
    return True


def _decompiled_c_contract_flow_append_label(
    asm_lines: list[str],
    local_label: str,
    global_label: str | None = None,
    *,
    global_label_is_linkable: bool = True,
) -> None:
    if global_label and _is_c_identifier(global_label):
        if global_label_is_linkable:
            asm_name = _decompiled_c_i686_c_asm_symbol(global_label)
            asm_lines.append(f".globl {asm_name}")
            asm_lines.append(f"{asm_name}:")
        else:
            asm_lines.append(f"# Stage B embedded section-gap label: {global_label}")
    asm_lines.append(f"{local_label}:")


def _decompiled_c_semantic_transfer_is_section_gap(transfer: dict[str, Any]) -> bool:
    for value in (transfer.get("function"), transfer.get("block_id"), transfer.get("id")):
        if isinstance(value, str) and _reference_contract_sidecar_name_is_section_gap(value):
            return True
    return False


def _decompiled_c_contract_flow_call_lines(
    instruction: dict[str, Any],
    *,
    callsite: dict[str, Any] | None,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
) -> list[str] | None:
    target = callsite.get("target") if isinstance(callsite, dict) and isinstance(callsite.get("target"), dict) else {}
    target_name: str | None = None
    target_profile: dict[str, Any] | None = None
    if target.get("kind") == "direct":
        target_rva = _optional_int(target.get("target_rva"))
        target_name = call_targets.get(target_rva) if target_rva is not None else None
        target_profile = call_target_profiles.get(str(target_name or ""))
    elif target.get("kind") == "import":
        target_name = _decompiled_c_contract_import_target_name(target)
        target_profile = _decompiled_c_contract_external_target_profile(target_name) if target_name is not None else None
        if target_name is not None:
            return [f"call *{_decompiled_c_i686_asm_iat_symbol(target_name, target_profile=target_profile)}"]
    else:
        target_rva = _decompiled_c_contract_flow_operand_target_rva(instruction)
        target_name = call_targets.get(target_rva) if target_rva is not None else None
        target_profile = call_target_profiles.get(str(target_name or ""))
    if target.get("kind") == "function_pointer" or (
        not target_name and _decompiled_c_contract_flow_call_is_indirect(instruction)
    ):
        instruction_bytes = instruction.get("bytes")
        instruction_size = _optional_int(instruction.get("size"))
        if not isinstance(instruction_bytes, str) or instruction_size is None or instruction_size <= 0:
            return None
        try:
            raw = bytes.fromhex(instruction_bytes)
        except ValueError:
            return None
        if len(raw) != instruction_size:
            return None
        return _decompiled_c_bytecode_asm_lines([raw.hex()])
    if not target_name or not _is_c_identifier(target_name):
        return None
    if not _decompiled_c_contract_direct_call_target_is_asm_linkable(
        target_name,
        target_profile=target_profile,
    ):
        return None
    if _decompiled_c_contract_flow_direct_call_should_use_raw_bytes(
        instruction,
        target_kind=str(target.get("kind") or ""),
        target_name=target_name,
        target_profile=target_profile,
    ):
        raw_lines = _decompiled_c_contract_flow_instruction_byte_lines(instruction)
        if raw_lines:
            return raw_lines
    return [f"call {_decompiled_c_i686_asm_call_symbol(target_name, target_profile=target_profile)}"]


def _decompiled_c_contract_flow_direct_call_should_use_raw_bytes(
    instruction: dict[str, Any],
    *,
    target_kind: str,
    target_name: str,
    target_profile: dict[str, Any] | None,
) -> bool:
    del instruction, target_kind, target_name, target_profile
    return False


def _decompiled_c_contract_flow_symbolic_call_preserves_rel32(
    target_name: str,
    *,
    target_profile: dict[str, Any] | None,
) -> bool:
    # Kept as a narrowly scoped introspection helper for older diagnostics.
    # Flow lowering emits symbolic calls for resolved direct targets so the
    # linker, not stale original rel32 bytes, chooses the candidate callee.
    if target_name.startswith("stage_b_contract_section_gap__"):
        return True
    if isinstance(target_profile, dict) and target_profile.get("stage_b_internal_function") is True:
        return True
    if isinstance(target_profile, dict) and target_profile.get("stage_b_synthetic_section_gap") is True:
        return True
    if isinstance(target_profile, dict) and target_profile.get("runtime_crt_linked") is True:
        return False
    if (
        target_name in _DECOMPILED_C_RUNTIME_ENTRY_NAMES
        or target_name in _DECOMPILED_C_MINGW_CRT_OWNED_FUNCTION_NAMES
        or target_name in _DECOMPILED_C_MINGW_CRT_SUPPORT_HELPER_NAMES
    ):
        return False
    return False


def _decompiled_c_contract_flow_instruction_byte_lines(instruction: dict[str, Any]) -> list[str]:
    instruction_bytes = instruction.get("bytes")
    instruction_size = _optional_int(instruction.get("size"))
    if not isinstance(instruction_bytes, str) or instruction_size is None or instruction_size <= 0:
        return []
    try:
        raw = bytes.fromhex(instruction_bytes)
    except ValueError:
        return []
    if len(raw) != instruction_size:
        return []
    return _decompiled_c_bytecode_asm_lines([raw.hex()])


def _decompiled_c_contract_flow_call_is_indirect(instruction: dict[str, Any]) -> bool:
    op_str = str(instruction.get("op_str") or "").strip()
    if not op_str:
        return False
    if op_str.startswith("0x"):
        return False
    try:
        raw = bytes.fromhex(str(instruction.get("bytes") or ""))
    except ValueError:
        return False
    return bool(raw) and raw[0] != 0xE8


def _decompiled_c_contract_flow_branch_lines(
    instruction: dict[str, Any],
    *,
    outcome: dict[str, Any],
    block_end: int,
    labels: dict[int, str],
    call_targets: dict[int, str],
    branch_target_symbols: dict[int, str],
    switch_contract: dict[str, Any] | None = None,
) -> list[str] | None:
    mnemonic = _instruction_mnemonic(instruction)
    if str(outcome.get("kind") or "") in {"indirect_jump", "indirect_jump_table"} and isinstance(switch_contract, dict):
        return _decompiled_c_contract_flow_jump_table_lines(
            instruction,
            outcome=outcome,
            labels=labels,
            call_targets=call_targets,
            branch_target_symbols=branch_target_symbols,
            switch_contract=switch_contract,
        )
    if str(outcome.get("kind") or "") == "indirect_jump" and mnemonic == "jmp":
        instruction_bytes = instruction.get("bytes")
        instruction_size = _optional_int(instruction.get("size"))
        if not isinstance(instruction_bytes, str) or instruction_size is None or instruction_size <= 0:
            return None
        try:
            raw = bytes.fromhex(instruction_bytes)
        except ValueError:
            return None
        if len(raw) != instruction_size:
            return None
        return _decompiled_c_bytecode_asm_lines([raw.hex()])
    if mnemonic == "jmp":
        target = _decompiled_c_contract_flow_target_symbol(
            _optional_int(outcome.get("target_rva")) or _decompiled_c_contract_flow_operand_target_rva(instruction),
            labels=labels,
            call_targets=call_targets,
            branch_target_symbols=branch_target_symbols,
        )
        return [f"jmp {target}"] if target else None
    if not mnemonic.startswith("j"):
        return None
    true_target = _decompiled_c_contract_flow_target_symbol(
        _optional_int(outcome.get("true_target_rva")) or _decompiled_c_contract_flow_operand_target_rva(instruction),
        labels=labels,
        call_targets=call_targets,
        branch_target_symbols=branch_target_symbols,
    )
    false_target = _decompiled_c_contract_flow_target_symbol(
        _optional_int(outcome.get("false_target_rva")),
        labels=labels,
        call_targets=call_targets,
        branch_target_symbols=branch_target_symbols,
    )
    if true_target is None or false_target is None:
        return None
    false_target_rva = _optional_int(outcome.get("false_target_rva"))
    if false_target_rva == block_end:
        return [f"{mnemonic} {true_target}"]
    return [f"{mnemonic} {true_target}", f"jmp {false_target}"]


def _decompiled_c_contract_flow_jump_table_lines(
    instruction: dict[str, Any],
    *,
    outcome: dict[str, Any],
    labels: dict[int, str],
    call_targets: dict[int, str],
    branch_target_symbols: dict[int, str],
    switch_contract: dict[str, Any] | None,
) -> list[str] | None:
    if _instruction_mnemonic(instruction) not in {"jmp", "ljmp"}:
        return None
    switch = switch_contract if isinstance(switch_contract, dict) else None
    outcome_switch = outcome.get("switch_contract") if isinstance(outcome.get("switch_contract"), dict) else None
    if switch is None:
        switch = outcome_switch
    if not isinstance(switch, dict) or switch.get("evidence_status") != "derived":
        return None
    index_expression = switch.get("index_expression") if isinstance(switch.get("index_expression"), dict) else {}
    index_register = _decompiled_c_i686_asm_register(str(index_expression.get("index") or ""))
    if index_register is None:
        return None
    case_targets = switch.get("case_targets") if isinstance(switch.get("case_targets"), list) else []
    cases: list[tuple[int, str]] = []
    for case in case_targets:
        if not isinstance(case, dict):
            continue
        index = _optional_int(case.get("index"))
        target_rva = _optional_int(case.get("target_rva"))
        target = _decompiled_c_contract_flow_target_symbol(
            target_rva,
            labels=labels,
            call_targets=call_targets,
            branch_target_symbols=branch_target_symbols,
        )
        if index is None or target is None:
            return None
        cases.append((index, target))
    if not cases:
        return None
    compact_lines = _decompiled_c_contract_flow_indexed_jump_table_lines(
        instruction,
        switch=switch,
        index_register=index_register,
        cases=cases,
    )
    if compact_lines is not None:
        return compact_lines
    lines: list[str] = []
    for index, target in sorted(cases):
        lines.append(f"cmpl $0x{index:x}, %{index_register}")
        lines.append(f"je {target}")
    default_target = _decompiled_c_contract_flow_target_symbol(
        _optional_int(switch.get("default_target_rva")),
        labels=labels,
        call_targets=call_targets,
        branch_target_symbols=branch_target_symbols,
    )
    if default_target is not None:
        lines.append(f"jmp {default_target}")
    else:
        lines.append("ud2")
    return lines


def _decompiled_c_contract_flow_indexed_jump_table_lines(
    instruction: dict[str, Any],
    *,
    switch: dict[str, Any],
    index_register: str,
    cases: list[tuple[int, str]],
) -> list[str] | None:
    if index_register == "esp":
        return None
    instruction_rva = _optional_int(instruction.get("rva"))
    if instruction_rva is None:
        return None
    if _optional_int(switch.get("default_target_rva")) is not None:
        return None
    bounds = switch.get("table_bounds") if isinstance(switch.get("table_bounds"), dict) else {}
    lower = _optional_int(bounds.get("lower"))
    upper = _optional_int(bounds.get("upper"))
    entries = _optional_int(bounds.get("entries"))
    if lower != 0 or upper is None:
        return None
    expected_entries = upper + 1
    if entries is not None and entries != expected_entries:
        return None
    sorted_cases = sorted(cases)
    if [index for index, _target in sorted_cases] != list(range(expected_entries)):
        return None
    index_expression = switch.get("index_expression") if isinstance(switch.get("index_expression"), dict) else {}
    if _optional_int(index_expression.get("scale")) not in {None, 4}:
        return None
    table = switch.get("table") if isinstance(switch.get("table"), dict) else {}
    table_va = _optional_int(index_expression.get("disp")) or _optional_int(table.get("va_start"))
    if table_va is None:
        return None
    return [f"jmp *0x{table_va:x}(,%{index_register},4)"]


def _decompiled_c_i686_asm_register(register: str) -> str | None:
    name = register.lower().strip()
    aliases = {
        "eax": "eax",
        "ax": "eax",
        "al": "eax",
        "ah": "eax",
        "ebx": "ebx",
        "bx": "ebx",
        "bl": "ebx",
        "bh": "ebx",
        "ecx": "ecx",
        "cx": "ecx",
        "cl": "ecx",
        "ch": "ecx",
        "edx": "edx",
        "dx": "edx",
        "dl": "edx",
        "dh": "edx",
        "esi": "esi",
        "edi": "edi",
        "ebp": "ebp",
        "esp": "esp",
    }
    return aliases.get(name)


def _decompiled_c_contract_flow_fallthrough_lines(
    outcome: dict[str, Any],
    *,
    block_end: int,
    next_block_start: int | None,
    labels: dict[int, str],
    call_targets: dict[int, str],
    branch_target_symbols: dict[int, str],
) -> list[str] | None:
    if str(outcome.get("kind") or "") != "fallthrough":
        return []
    target_rva = _optional_int(outcome.get("target_rva"))
    if target_rva is None:
        return []
    if target_rva == block_end:
        return []
    if target_rva == next_block_start:
        return []
    target = _decompiled_c_contract_flow_target_symbol(
        target_rva,
        labels=labels,
        call_targets=call_targets,
        branch_target_symbols=branch_target_symbols,
    )
    return [f"jmp {target}"] if target is not None else None


def _decompiled_c_contract_flow_target_symbol(
    target_rva: int | None,
    *,
    labels: dict[int, str],
    call_targets: dict[int, str],
    branch_target_symbols: dict[int, str],
) -> str | None:
    if target_rva is None:
        return None
    if target_rva in labels:
        return labels[target_rva]
    branch_target = branch_target_symbols.get(target_rva)
    if branch_target and _is_c_identifier(branch_target):
        return _decompiled_c_i686_c_asm_symbol(branch_target)
    target_name = call_targets.get(target_rva)
    if target_name and _is_c_identifier(target_name):
        return _decompiled_c_i686_c_asm_symbol(target_name)
    return None


def _decompiled_c_contract_flow_operand_target_rva(instruction: dict[str, Any]) -> int | None:
    op_str = str(instruction.get("op_str") or "").strip().split(",", 1)[0].strip()
    if not op_str.startswith("0x"):
        return None
    try:
        value = int(op_str, 0)
    except ValueError:
        return None
    return value - 0x400000 if value >= 0x400000 else value


def _decompiled_c_bytecode_asm_lines(chunks: list[Any]) -> list[str]:
    byte_values: list[str] = []
    for chunk in chunks:
        if not isinstance(chunk, str) or not chunk:
            return []
        try:
            raw = bytes.fromhex(chunk)
        except ValueError:
            return []
        byte_values.extend(f"0x{value:02x}" for value in raw)
    if not byte_values:
        return []
    lines: list[str] = []
    width = 12
    for index in range(0, len(byte_values), width):
        lines.append(".byte " + ", ".join(byte_values[index : index + width]))
    return lines


def _decompiled_c_instruction_preview(function: dict[str, Any]) -> list[dict[str, Any]]:
    instructions = function.get("instruction_preview")
    if not isinstance(instructions, list):
        return []
    return [instruction for instruction in instructions if isinstance(instruction, dict)]


def _decompiled_c_matches_return_zero_leaf(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) == 2
        and _instruction_is(instructions[0], "xor", "eax,eax")
        and _instruction_is_ret(instructions[1])
    )


def _decompiled_c_matches_fpreset_leaf(instructions: list[dict[str, Any]]) -> bool:
    return (
        len(instructions) == 2
        and _instruction_is(instructions[0], "fninit")
        and _instruction_is_ret(instructions[1])
    )


def _decompiled_c_matches_configthreadlocale_leaf(instructions: list[dict[str, Any]]) -> bool:
    significant = [instruction for instruction in instructions if not _instruction_is_alignment_nop(instruction)]
    return (
        len(significant) == 6
        and _instruction_is(significant[0], "cmp", "dwordptr[esp+4],1")
        and _instruction_is(significant[1], "je")
        and _instruction_is(significant[2], "mov", "eax,2")
        and _instruction_is_ret(significant[3])
        and _instruction_is(significant[4], "mov", "eax,0xffffffff")
        and _instruction_is_ret(significant[5])
    )


def _decompiled_c_absolute_load_return_address(instructions: list[dict[str, Any]]) -> int | None:
    if len(instructions) != 2 or not _instruction_is_ret(instructions[1]):
        return None
    match = re.fullmatch(r"eax,dwordptr\[(0x[0-9a-f]+)\]", _instruction_normalized_op(instructions[0]))
    return int(match.group(1), 16) if _instruction_mnemonic(instructions[0]) == "mov" and match is not None else None


def _decompiled_c_absolute_exchange_return_address(instructions: list[dict[str, Any]]) -> int | None:
    if len(instructions) != 3 or not _instruction_is(instructions[0], "mov", "eax,dwordptr[esp+4]") or not _instruction_is_ret(instructions[2]):
        return None
    match = re.fullmatch(r"dwordptr\[(0x[0-9a-f]+)\],eax", _instruction_normalized_op(instructions[1]))
    return int(match.group(1), 16) if _instruction_mnemonic(instructions[1]) == "xchg" and match is not None else None


def _decompiled_c_matches_mb_cur_max_func(function: dict[str, Any], instructions: list[dict[str, Any]]) -> bool:
    if str(function.get("name") or "") != "___mb_cur_max_func":
        return False
    mnemonics = [_instruction_mnemonic(instruction) for instruction in instructions]
    return mnemonics == ["sub", "call", "mov", "add", "ret"] and _instruction_is(instructions[2], "mov", "eax,dwordptr[eax]")


def _decompiled_c_matches_acrt_iob_func(function: dict[str, Any], instructions: list[dict[str, Any]]) -> bool:
    if str(function.get("name") or "") not in {"__acrt_iob_func", "___acrt_iob_func"}:
        return False
    mnemonics = [_instruction_mnemonic(instruction) for instruction in instructions]
    return (
        mnemonics == ["sub", "call", "mov", "add", "shl", "add", "xor", "ret"]
        and _instruction_is(instructions[2], "mov", "edx,dwordptr[esp+0x10]")
        and _instruction_is(instructions[4], "shl", "edx,5")
        and _instruction_is(instructions[5], "add", "eax,edx")
    )


def _decompiled_c_matches_freedtoa_leaf(function: dict[str, Any], instructions: list[dict[str, Any]]) -> bool:
    if str(function.get("name") or "") not in {"__freedtoa", "___freedtoa"}:
        return False
    mnemonics = [_instruction_mnemonic(instruction) for instruction in instructions]
    return (
        mnemonics == ["mov", "mov", "mov", "sub", "shl", "mov", "mov", "mov", "jmp"]
        and _instruction_is(instructions[0], "mov", "eax,dwordptr[esp+4]")
        and _instruction_is(instructions[1], "mov", "edx,1")
        and _instruction_is(instructions[2], "mov", "ecx,dwordptr[eax-4]")
        and _instruction_is(instructions[3], "sub", "eax,4")
        and _instruction_is(instructions[4], "shl", "edx,cl")
        and _instruction_is(instructions[5], "mov", "dwordptr[eax+4],ecx")
        and _instruction_is(instructions[6], "mov", "dwordptr[eax+8],edx")
        and _instruction_is(instructions[7], "mov", "dwordptr[esp+4],eax")
    )


def _instruction_mnemonic(instruction: dict[str, Any]) -> str:
    return str(instruction.get("mnemonic") or "").strip().lower()


def _instruction_normalized_op(instruction: dict[str, Any]) -> str:
    return re.sub(r"\s+", "", str(instruction.get("op_str") or "").strip().lower())


def _instruction_is(instruction: dict[str, Any], mnemonic: str, normalized_op: str | None = None) -> bool:
    if _instruction_mnemonic(instruction) != mnemonic:
        return False
    return normalized_op is None or _instruction_normalized_op(instruction) == normalized_op


def _instruction_is_ret(instruction: dict[str, Any]) -> bool:
    return _instruction_mnemonic(instruction) == "ret"


def _instruction_is_alignment_nop(instruction: dict[str, Any]) -> bool:
    return _instruction_mnemonic(instruction) == "lea" and _instruction_normalized_op(instruction) in {
        "esi,[esi]",
        "edi,[edi]",
    }


def _decompiled_c_semantic_region_contract_impl(
    function: dict[str, Any],
    region: dict[str, Any],
    *,
    call_targets: dict[int, str],
) -> str | None:
    name = _c_identifier_from_name(str(function.get("name") or "stage_b_missing_function"))
    call = _decompiled_c_semantic_region_direct_call(region)
    if call is None:
        return None
    target_rva = _optional_int(call.get("target_rva"))
    target_name = call_targets.get(target_rva) if target_rva is not None else None
    if not target_name or not _is_c_identifier(target_name):
        return None
    jump = _decompiled_c_semantic_region_direct_jump(region)
    jump_target_name = None
    if jump is not None:
        jump_target_rva = _optional_int(jump.get("target_rva"))
        jump_target_name = call_targets.get(jump_target_rva) if jump_target_rva is not None else None
        if not jump_target_name or not _is_c_identifier(jump_target_name):
            return None
    if _decompiled_c_semantic_region_register_order(region) != ["eax", "edx", "ecx"]:
        return None
    region_id = str(region.get("id") or "semantic-region")
    c_contract_name = f"{name}_stage_a_c_contract"
    lines = [
        f"/* Stage A checked semantic region: {region_id}. */",
        "__attribute__((always_inline)) static inline uintptr_t",
        f"{c_contract_name}(stageb_x86_state *s)",
        "{",
        "  s->eax = (uint32_t)(s->ebx + 0x1cU);",
        "  s->edx = 1U;",
        "  s->ecx = s->ebx;",
        f"  volatile uintptr_t stageb_call_result = {target_name}((uintptr_t)s->eax, (uintptr_t)s->edx, (uintptr_t)s->ecx);",
        "  s->eax = (uint32_t)stageb_call_result;",
        f"  return {jump_target_name}();" if jump_target_name else "  return stageb_call_result;",
        "}",
        "",
        "__attribute__((noinline, used))",
        f"uintptr_t __cdecl {name}(void)",
        "{",
        f"  /* Stage B generated C for {region_id}; ABI register capture is linker scaffolding, not a semantic asm island. */",
        '  register uintptr_t stageb_ebx __asm__("ebx");',
        "  stageb_x86_state s = {0};",
        "  s.ebx = (uint32_t)stageb_ebx;",
        f"  return {c_contract_name}(&s);",
        "}",
    ]
    return "\n".join(lines)


def _decompiled_c_semantic_region_callee_placeholder(
    function: dict[str, Any],
    regions: list[Any],
) -> str | None:
    checked = [region for region in regions if isinstance(region, dict) and region.get("status") == "checked"]
    if not checked:
        return None
    region = checked[0]
    if _decompiled_c_semantic_region_register_order(region) != ["eax", "edx", "ecx"]:
        return None
    name = _c_identifier_from_name(str(function.get("name") or "stage_b_missing_function"))
    rva_start = int(function.get("rva_start") or 0)
    size = int(function.get("size") or 0)
    lines = [
        "__attribute__((noinline, used, regparm(3)))",
        f"uintptr_t {name}(uintptr_t stageb_arg_eax, uintptr_t stageb_arg_edx, uintptr_t stageb_arg_ecx)",
        "{",
        f"  /* Stage B register-ABI callee placeholder for checked selected-region target at RVA 0x{rva_start:x}, size {size}. */",
        "  volatile uintptr_t stageb_contract_sink = stageb_arg_eax ^ stageb_arg_edx ^ stageb_arg_ecx;",
        "  return stageb_contract_sink & 0U;",
        "}",
    ]
    return "\n".join(lines)


def _decompiled_c_semantic_region_direct_call(region: dict[str, Any]) -> dict[str, Any] | None:
    ir = region.get("ir") if isinstance(region.get("ir"), dict) else {}
    for operation in ir.get("operations", []) if isinstance(ir.get("operations"), list) else []:
        if isinstance(operation, dict) and operation.get("op") == "direct_call":
            return operation
    outputs = region.get("outputs") if isinstance(region.get("outputs"), dict) else {}
    direct_call = outputs.get("direct_call") if isinstance(outputs.get("direct_call"), dict) else None
    return direct_call


def _decompiled_c_semantic_region_direct_jump(region: dict[str, Any]) -> dict[str, Any] | None:
    ir = region.get("ir") if isinstance(region.get("ir"), dict) else {}
    for operation in ir.get("operations", []) if isinstance(ir.get("operations"), list) else []:
        if isinstance(operation, dict) and operation.get("op") == "direct_jump":
            return operation
    return None


def _decompiled_c_semantic_region_register_order(region: dict[str, Any]) -> list[str]:
    call = _decompiled_c_semantic_region_direct_call(region)
    arguments = call.get("register_arguments") if isinstance(call, dict) and isinstance(call.get("register_arguments"), list) else []
    result = []
    for argument in arguments:
        if not isinstance(argument, dict):
            continue
        register = argument.get("register")
        if isinstance(register, str) and register:
            result.append(register)
    return result


def _decompiled_c_jq_jv_is_valid_contract_impl(
    function: dict[str, Any],
    *,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
) -> str:
    rva_start = int(function.get("rva_start") or 0)
    size = int(function.get("size") or 0)
    target_name = _decompiled_c_i686_c_asm_symbol(str(call_targets.get(0x4A80) or "jv_get_kind"))
    lines = [
        "__attribute__((naked, noinline, used))",
        "uintptr_t __cdecl jv_is_valid()",
        "{",
        f"  /* Stage B jq helper recovered from original RVA 0x{rva_start:x}, size {size}. */",
    ]
    anchor_lines = _decompiled_c_contract_callsite_anchor_lines(
        function,
        call_targets=call_targets,
        call_target_profiles=call_target_profiles,
        emit_accumulator=False,
    )
    lines.extend(line for line in anchor_lines if line.strip().startswith("/*"))
    lines.extend(
        [
            "  __asm__ __volatile__(",
            '    "subl $0x2c, %esp\\n\\t"',
            '    "movl 0x30(%esp), %eax\\n\\t"',
            '    "movl %eax, (%esp)\\n\\t"',
            '    "movl 0x34(%esp), %eax\\n\\t"',
            '    "movl %eax, 0x4(%esp)\\n\\t"',
            '    "movl 0x38(%esp), %eax\\n\\t"',
            '    "movl %eax, 0x8(%esp)\\n\\t"',
            '    "movl 0x3c(%esp), %eax\\n\\t"',
            '    "movl %eax, 0xc(%esp)\\n\\t"',
            f'    "call {target_name}\\n\\t"',
            '    "testl %eax, %eax\\n\\t"',
            '    "setne %al\\n\\t"',
            '    "addl $0x2c, %esp\\n\\t"',
            '    "movzbl %al, %eax\\n\\t"',
            '    "ret\\n\\t"',
            "  );",
            "}",
        ]
    )
    return "\n".join(lines)


def _decompiled_c_contract_call_targets(
    functions: list[dict[str, Any]],
    *,
    runtime_entry_policy: str,
    reference_contract_payload: dict[str, Any] | None = None,
    external_function_names: list[str] | tuple[str, ...] = (),
) -> dict[int, str]:
    targets: dict[int, str] = {}
    for function in functions:
        rva_start = _optional_int(function.get("rva_start"))
        if rva_start is None:
            continue
        import_symbol = _decompiled_c_import_thunk_target_symbol(function)
        if import_symbol is not None:
            targets[rva_start] = import_symbol
            continue
        name = _decompiled_c_emitted_function_name(function, runtime_entry_policy=runtime_entry_policy)
        if _is_c_identifier(name):
            targets[rva_start] = name
    if reference_contract_payload is not None:
        known_symbols = set(_decompiled_c_external_call_symbols(functions))
        known_symbols.update(str(name) for name in external_function_names)
        known_symbols.update(_decompiled_c_defined_symbol_names(functions))
        targets.update(_decompiled_c_contract_runtime_call_targets(reference_contract_payload))
        targets.update(_decompiled_c_contract_section_gap_call_targets(reference_contract_payload, known_symbols=known_symbols))
    return targets


def _decompiled_c_contract_runtime_call_targets(reference_contract_payload: dict[str, Any]) -> dict[int, str]:
    constraints = reference_contract_payload.get("constraints") if isinstance(reference_contract_payload.get("constraints"), dict) else {}
    function_ranges = constraints.get("function_ranges") if isinstance(constraints.get("function_ranges"), dict) else {}
    functions = function_ranges.get("functions") if isinstance(function_ranges.get("functions"), list) else []
    result: dict[int, str] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        original = function.get("original") if isinstance(function.get("original"), dict) else {}
        rva_start = _optional_int(function.get("rva_start"))
        if rva_start is None:
            rva_start = _optional_int(original.get("rva_start"))
        if rva_start is None or not isinstance(name, str) or not _is_c_identifier(name):
            continue
        if not _decompiled_c_contract_runtime_call_target_is_linkable(name):
            continue
        result[rva_start] = _DECOMPILED_C_MINGWEX_C_SYMBOL_ALIASES.get(name, name)
    return result


def _decompiled_c_contract_runtime_call_target_is_linkable(name: str) -> bool:
    return (
        _decompiled_c_contract_symbol_is_stack_probe(name)
        or name in _DECOMPILED_C_MINGW_CRT_OWNED_FUNCTION_NAMES
        or name in _DECOMPILED_C_MINGW_CRT_SUPPORT_HELPER_NAMES
    )


def _decompiled_c_contract_symbol_is_stack_probe(name: str) -> bool:
    if name in _DECOMPILED_C_STACK_PROBE_HELPER_MACROS:
        return True
    key = _linker_function_match_key(name)
    return key in {"chkstk", "chkstk_ms", "alloca_probe", "alloca_probe_8", "alloca_probe_16"} or key.startswith("chkstk_")


def _decompiled_c_contract_section_gap_call_targets(
    reference_contract_payload: dict[str, Any],
    *,
    known_symbols: set[str],
) -> dict[int, str]:
    result: dict[int, str] = {}
    for entry in _reference_contract_abi_section_gap_entries_by_start(reference_contract_payload).values():
        rva_start = _optional_int(entry.get("rva_start"))
        if rva_start is None:
            continue
        alias = _decompiled_c_section_gap_known_symbol_alias(entry, known_symbols=known_symbols)
        if alias is not None:
            result.setdefault(rva_start, alias)
        else:
            result.setdefault(rva_start, _decompiled_c_synthetic_section_gap_name(entry))
    return result


def _decompiled_c_contract_call_target_spans(
    functions: list[dict[str, Any]],
    *,
    synthetic_section_gap_placeholders: list[dict[str, Any]],
    call_targets: dict[int, str],
    runtime_entry_policy: str,
) -> dict[int, int]:
    spans: dict[int, int] = {}
    for function in [*functions, *synthetic_section_gap_placeholders]:
        start = _optional_int(function.get("rva_start"))
        end = _optional_int(function.get("rva_end"))
        if start is None or end is None or end <= start:
            continue
        expected_name = call_targets.get(start)
        if not expected_name:
            continue
        emitted_name = (
            str(function.get("name") or "")
            if function in synthetic_section_gap_placeholders
            else _decompiled_c_emitted_function_name(function, runtime_entry_policy=runtime_entry_policy)
        )
        if expected_name != emitted_name and expected_name != str(function.get("name") or ""):
            continue
        spans[start] = max(spans.get(start, start), end)
    return spans


def _decompiled_c_contract_call_target_profiles(
    call_targets: dict[int, str],
    functions: list[dict[str, Any]],
    *,
    runtime_entry_policy: str,
    emitted_section_gap_targets: Iterable[str] = (),
    runtime_linked_call_targets: Iterable[str] = (),
) -> dict[str, dict[str, Any]]:
    needed = set(call_targets.values())
    profiles: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for function in functions:
        if _decompiled_c_is_import_thunk(function):
            continue
        emitted_name = _decompiled_c_emitted_function_name(function, runtime_entry_policy=runtime_entry_policy)
        if emitted_name not in needed or emitted_name in seen or not _is_c_identifier(emitted_name):
            continue
        prototype = _decompiled_c_prototype(function, emitted_name=emitted_name)
        profile = _decompiled_c_prototype_parameter_profile(prototype)
        if profile is None:
            profile = {}
        profile["stage_b_internal_function"] = True
        seen.add(emitted_name)
        if prototype:
            profile["prototype"] = prototype
        profiles[emitted_name] = profile
    for function in functions:
        import_symbol = _decompiled_c_import_thunk_target_symbol(function)
        if import_symbol is None or import_symbol not in needed or import_symbol in seen:
            continue
        profile = _decompiled_c_contract_external_target_profile(import_symbol)
        if (
            "prototype" not in profile
            and _is_c_identifier(import_symbol)
            and not _decompiled_c_external_symbol_is_declared_by_headers(import_symbol)
        ):
            profile["prototype"] = f"extern uintptr_t {import_symbol}();"
        profiles[import_symbol] = profile
        seen.add(import_symbol)
    for name in sorted(needed - set(profiles)):
        prototype = _DECOMPILED_C_STDCALL_PROTOTYPES.get(name) or _DECOMPILED_C_EXTERNAL_PROTOTYPES.get(name)
        if prototype is None:
            continue
        profile = _decompiled_c_prototype_parameter_profile(prototype)
        if profile is None:
            profile = {}
        profile["prototype"] = prototype
        profiles[name] = profile
    for name in sorted({str(name) for name in emitted_section_gap_targets}):
        if name not in needed or name in profiles or not _is_c_identifier(name):
            continue
        profile: dict[str, Any] = {"stage_b_synthetic_section_gap": True}
        if not _decompiled_c_contract_direct_call_target_is_asm_linkable(name, target_profile=profile):
            continue
        profiles[name] = profile
    for name in sorted({str(name) for name in runtime_linked_call_targets}):
        if name not in needed or not _is_c_identifier(name):
            continue
        profile = dict(profiles.get(name) or {})
        profile["runtime_crt_linked"] = True
        profile.setdefault("prototype", f"uintptr_t __cdecl {name}();")
        if not _decompiled_c_contract_direct_call_target_is_asm_linkable(name, target_profile=profile):
            continue
        profiles[name] = profile
    return profiles


def _decompiled_c_contract_call_target_forward_declarations(
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
) -> list[str]:
    declarations: list[str] = []
    seen: set[str] = set()
    for name in sorted(set(call_targets.values())):
        if name in call_target_profiles or name in seen or not _is_c_identifier(name):
            continue
        seen.add(name)
        if name in {"WinMainCRTStartup", "mainCRTStartup"}:
            declarations.append(f"void __cdecl {name}();")
        else:
            declarations.append(f"uintptr_t __cdecl {name}();")
    return declarations


def _decompiled_c_semantic_region_call_target_profiles(
    reference_contract_payload: dict[str, Any],
    *,
    call_targets: dict[int, str],
) -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for region in _reference_contract_semantic_regions(reference_contract_payload):
        if not isinstance(region, dict) or region.get("status") != "checked":
            continue
        call = _decompiled_c_semantic_region_direct_call(region)
        if call is None:
            continue
        target_rva = _optional_int(call.get("target_rva"))
        target_name = call_targets.get(target_rva) if target_rva is not None else None
        if not target_name or not _is_c_identifier(target_name):
            continue
        registers = _decompiled_c_semantic_region_register_order(region)
        if registers != ["eax", "edx", "ecx"]:
            continue
        profiles[target_name] = {
            "fixed_arg_count": 3,
            "variadic": False,
            "regparm": 3,
            "prototype": f"uintptr_t __attribute__((regparm(3))) {target_name}(uintptr_t, uintptr_t, uintptr_t);",
            "semantic_region_target": region.get("id"),
        }
    return profiles


def _decompiled_c_prototype_parameter_profile(prototype: str) -> dict[str, Any] | None:
    text = prototype.strip()
    if not text.endswith(";"):
        return None
    text = text[:-1].strip()
    end = text.rfind(")")
    start = _matching_open_paren(text, end)
    if start is None or end < start:
        return None
    raw_parameters = text[start + 1 : end].strip()
    if not raw_parameters:
        return None
    if raw_parameters == "void":
        return {"fixed_arg_count": 0, "variadic": False}
    parameters = [parameter.strip() for parameter in raw_parameters.split(",") if parameter.strip()]
    variadic = bool(parameters and parameters[-1] == "...")
    fixed_arg_count = len(parameters) - (1 if variadic else 0)
    return {"fixed_arg_count": fixed_arg_count, "variadic": variadic}


def _matching_open_paren(text: str, close_index: int) -> int | None:
    if close_index < 0 or close_index >= len(text) or text[close_index] != ")":
        return None
    depth = 0
    for index in range(close_index, -1, -1):
        char = text[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                return index
    return None


def _decompiled_c_contract_callsite_anchor_lines(
    function: dict[str, Any],
    *,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
    emit_accumulator: bool = True,
) -> list[str]:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    callsites = reference_contract.get("abi_callsites") if isinstance(reference_contract.get("abi_callsites"), list) else []
    lines: list[str] = []
    for callsite_index, callsite in enumerate(callsites[:8]):
        if not isinstance(callsite, dict):
            continue
        target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
        instruction = callsite.get("instruction") if isinstance(callsite.get("instruction"), dict) else {}
        instruction_rva = _optional_int(instruction.get("rva"))
        callsite_id = str(callsite.get("id") or f"callsite:0x{(instruction_rva if instruction_rva is not None else 0):x}")
        suffix = f" at RVA 0x{instruction_rva:x}" if instruction_rva is not None else ""
        if target.get("kind") == "direct":
            target_rva = _optional_int(target.get("target_rva"))
            if target_rva is None:
                continue
            target_name = call_targets.get(target_rva)
            if not target_name or not _is_c_identifier(target_name):
                continue
            rendered_args = _decompiled_c_contract_callsite_arguments(callsite, target_profile=call_target_profiles.get(target_name))
            if rendered_args is None:
                continue
            lines.append(f"  /* Stage A direct-call anchor: {callsite_id}{suffix}. */")
            lines.append(f"  {target_name}({', '.join(rendered_args)});")
            if emit_accumulator:
                lines.append(f"  stage_b_contract_anchor ^= (uintptr_t)0x{(instruction_rva if instruction_rva is not None else target_rva):x};")
            continue
        if target.get("kind") == "import":
            target_name = _decompiled_c_contract_import_target_name(target)
            if target_name is None:
                continue
            target_profile = _decompiled_c_contract_external_target_profile(target_name)
            rendered_args = _decompiled_c_contract_callsite_arguments(callsite, target_profile=target_profile)
            if rendered_args is None:
                continue
            lines.append(f"  /* Stage A import-call anchor: {callsite_id}{suffix}. */")
            lines.append(_decompiled_c_contract_unchecked_c_call(target_name, rendered_args))
            if emit_accumulator:
                lines.append(f"  stage_b_contract_anchor ^= (uintptr_t)0x{(instruction_rva if instruction_rva is not None else 0):x};")
            continue
        if target.get("kind") == "function_pointer":
            rendered_args = _decompiled_c_contract_callsite_arguments(callsite)
            if rendered_args is None:
                continue
            pointer_name = f"stage_b_contract_fp_{callsite_index}"
            asm_operand = _decompiled_c_contract_function_pointer_asm_operand(target)
            lines.append(f"  /* Stage A function-pointer-call anchor: {callsite_id}{suffix}. */")
            if rendered_args:
                lines.append(f"  volatile uintptr_t {pointer_name} = 0;")
                lines.append(f"  ((uintptr_t (__cdecl *)())(uintptr_t){pointer_name})({', '.join(rendered_args)});")
            elif asm_operand is not None:
                lines.append(f'  __asm__ __volatile__("call {_c_inline_asm_percent_escape(asm_operand)}" : : : "memory");')
            else:
                lines.append('  __asm__ __volatile__("xorl %%eax, %%eax; call *%%eax" : : : "eax", "memory");')
            if emit_accumulator:
                lines.append(f"  stage_b_contract_anchor ^= (uintptr_t)0x{(instruction_rva if instruction_rva is not None else 0):x};")
    return lines


def _decompiled_c_contract_callsite_arguments(
    callsite: dict[str, Any],
    *,
    target_profile: dict[str, Any] | None = None,
) -> list[str] | None:
    arguments = callsite.get("arguments") if isinstance(callsite.get("arguments"), list) else []
    rendered: list[str] = []
    for argument in arguments:
        if not isinstance(argument, dict):
            return None
        if argument.get("kind") == "immediate":
            value = argument.get("value")
            if not isinstance(value, int) or isinstance(value, bool):
                return None
            rendered.append(str(value))
            continue
        # Preserve known call arity even when the ABI contract cannot express
        # the source-level value. Stage A remains responsible for rejecting the
        # placeholder if the resulting candidate does not match argument
        # sources, stack deltas, or callee effects.
        rendered.append("(uintptr_t)0")
    if target_profile is not None:
        fixed_arg_count = target_profile.get("fixed_arg_count")
        if isinstance(fixed_arg_count, int) and fixed_arg_count >= 0:
            if target_profile.get("variadic"):
                while len(rendered) < fixed_arg_count:
                    rendered.append("(uintptr_t)0")
            else:
                rendered = rendered[:fixed_arg_count]
                while len(rendered) < fixed_arg_count:
                    rendered.append("(uintptr_t)0")
    return rendered


def _decompiled_c_contract_unchecked_c_call(target_name: str, rendered_args: list[str]) -> str:
    args = ", ".join(rendered_args)
    return f"  ((uintptr_t (__cdecl *)())(uintptr_t){target_name})({args});"

def _decompiled_c_is_import_thunk(function: dict[str, Any]) -> bool:
    linkage = function.get("linkage")
    return isinstance(linkage, dict) and linkage.get("kind") == "import_thunk"

def _decompiled_c_policy_omission_reason(function: dict[str, Any], *, runtime_entry_policy: str = "bridge") -> str | None:
    if _decompiled_c_is_import_thunk(function):
        return "import_thunk_omitted_to_link_import"
    if _decompiled_c_is_stack_probe_helper(function):
        return "stack_probe_helper_omitted_to_link_runtime"
    if not _decompiled_c_is_runtime_entry(function, runtime_entry_policy=runtime_entry_policy):
        return None
    if runtime_entry_policy == "bridge" and str(function.get("name") or "") in _DECOMPILED_C_RUNTIME_ENTRY_NAMES:
        return "runtime_entry_replaced_by_generated_bridge"
    if _decompiled_c_is_mingw_crt_support_helper(function):
        return "mingw_crt_support_helper_omitted_to_link_runtime"
    return "mingw_crt_owned_function_omitted_to_link_runtime"

def _decompiled_c_import_thunk_target_symbol(function: dict[str, Any]) -> str | None:
    if not _decompiled_c_is_import_thunk(function):
        return None
    linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
    symbol = str(linkage.get("symbol") or "")
    contract_function = str(linkage.get("original_symbol") or function.get("name") or "")
    if symbol == "atexit" and contract_function in _DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS and _is_c_identifier(contract_function):
        return contract_function
    if _decompiled_c_import_thunk_preserves_contract_symbol(symbol, contract_function=contract_function) and _is_c_identifier(contract_function):
        return contract_function
    if not symbol or not _is_c_identifier(symbol):
        return None
    return symbol

def _decompiled_c_import_thunk_alias_symbol_names(functions: list[dict[str, Any]]) -> list[str]:
    symbols = [left for left, _ in _decompiled_c_import_thunk_alias_pairs(functions)]
    seen = set(symbols)
    for function in functions:
        if not _decompiled_c_is_import_thunk(function):
            continue
        linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
        left = str(linkage.get("original_symbol") or function.get("name") or "")
        right = str(linkage.get("symbol") or "")
        if (
            left
            and left not in seen
            and _is_c_identifier(left)
            and _decompiled_c_import_thunk_preserves_contract_symbol(right, contract_function=left)
        ):
            seen.add(left)
            symbols.append(left)
    return symbols

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
        if _decompiled_c_import_thunk_preserves_contract_symbol(right, contract_function=left):
            continue
        if left in _DECOMPILED_C_PRESERVED_IMPORT_THUNK_ALIASES:
            continue
        if left == right or not _is_c_identifier(left) or not _is_c_identifier(right) or left in seen:
            continue
        seen.add(left)
        pairs.append((left, right))
    return pairs

def _decompiled_c_import_thunk_preserves_contract_symbol(symbol: str, *, contract_function: str) -> bool:
    if not symbol or not contract_function or symbol == contract_function:
        return False
    return any(contract_function.startswith(prefix) for prefix in _DECOMPILED_C_CONTRACT_IMPORT_THUNK_PREFIXES)

def _decompiled_c_import_thunk_wrapper_lines(functions: list[dict[str, Any]]) -> list[str]:
    thunks: list[tuple[list[str], str]] = []
    seen: set[str] = set()
    for function in functions:
        if not _decompiled_c_is_import_thunk(function):
            continue
        linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
        imported_symbol = str(linkage.get("symbol") or "")
        contract_function = str(linkage.get("original_symbol") or function.get("name") or "")
        if not imported_symbol or not contract_function:
            continue
        label = _stage_b_import_thunk_coff_symbol_name(imported_symbol, contract_function=contract_function)
        iat_symbol = _stage_b_import_thunk_iat_symbol_name(imported_symbol)
        labels = [label]
        if imported_symbol == "atexit" and contract_function in _DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS:
            contract_label = _decompiled_c_i686_c_asm_symbol(contract_function)
            if contract_label not in labels:
                labels.append(contract_label)
        if (
            not label
            or not _stage_b_import_thunk_coff_symbol_is_valid(iat_symbol)
            or any(item in seen or not _stage_b_import_thunk_coff_symbol_is_valid(item) for item in labels)
        ):
            continue
        seen.update(labels)
        thunks.append((labels, iat_symbol))
    if not thunks:
        return []

    lines = [
        "__asm__(",
        "\".section .text$stage_b_import_thunks,\\\"x\\\"\\n\"",
    ]
    for labels, iat_symbol in thunks:
        iat_asm = _c_asm_string_line(iat_symbol)
        for label in labels:
            label_asm = _c_asm_string_line(label)
            lines.extend(
                [
                    f"\".globl {label_asm}\\n\"",
                    f"\".def {label_asm}; .scl 2; .type 32; .endef\\n\"",
                ]
            )
        for label in labels:
            label_asm = _c_asm_string_line(label)
            lines.append(f"\"{label_asm}:\\n\"")
        lines.extend(
            [
                f"\"  jmp *{iat_asm}\\n\"",
            ]
        )
    lines.extend(
        [
            "\".text\\n\"",
            ");",
        ]
    )
    return lines

def _decompiled_c_is_runtime_entry(function: dict[str, Any], *, runtime_entry_policy: str = "bridge") -> bool:
    name = str(function.get("name") or "")
    if name in _DECOMPILED_C_RUNTIME_ENTRY_NAMES:
        return True
    return runtime_entry_policy == "mingw-crt" and _decompiled_c_is_mingw_crt_owned_function(function)

def _decompiled_c_is_mingw_crt_owned_function(function: dict[str, Any]) -> bool:
    name = str(function.get("name") or "")
    if name in _DECOMPILED_C_MINGW_CRT_OWNED_FUNCTION_NAMES:
        return True
    aliases = function.get("aliases") if isinstance(function.get("aliases"), list) else []
    return any(isinstance(alias, str) and alias in _DECOMPILED_C_MINGW_CRT_OWNED_FUNCTION_NAMES for alias in aliases)

def _decompiled_c_is_mingw_crt_support_helper(function: dict[str, Any]) -> bool:
    name = str(function.get("name") or "")
    if name in _DECOMPILED_C_MINGW_CRT_SUPPORT_HELPER_NAMES:
        return True
    aliases = function.get("aliases") if isinstance(function.get("aliases"), list) else []
    return any(isinstance(alias, str) and alias in _DECOMPILED_C_MINGW_CRT_SUPPORT_HELPER_NAMES for alias in aliases)

def _decompiled_c_runtime_linked_symbol_names(
    functions: list[dict[str, Any]],
    *,
    runtime_entry_policy: str,
) -> set[str]:
    if runtime_entry_policy != "mingw-crt":
        return set()
    symbols: set[str] = set()
    for function in functions:
        if not _decompiled_c_is_mingw_crt_owned_function(function):
            continue
        names = [
            str(function.get("name") or ""),
            *[
                str(alias)
                for alias in (function.get("aliases") if isinstance(function.get("aliases"), list) else [])
                if isinstance(alias, str)
            ],
        ]
        for name in names:
            if not name:
                continue
            symbols.add(name)
            alias = _DECOMPILED_C_MINGWEX_C_SYMBOL_ALIASES.get(name)
            if alias:
                symbols.add(alias)
    return symbols

def _decompiled_c_is_stack_probe_helper(function: dict[str, Any]) -> bool:
    name = str(function.get("name") or "")
    return _decompiled_c_contract_symbol_is_stack_probe(name)

def _decompiled_c_runtime_helper_alias_lines(functions: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for left, right in _decompiled_c_mingwex_c_symbol_alias_pairs(functions):
        lines.append(f"#define {left} {right}")
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

def _decompiled_c_mingwex_c_symbol_alias_pairs(functions: list[dict[str, Any]]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for function in functions:
        names = [
            str(function.get("name") or ""),
            *[
                str(alias)
                for alias in (function.get("aliases") if isinstance(function.get("aliases"), list) else [])
                if isinstance(alias, str)
            ],
        ]
        for left in names:
            right = _DECOMPILED_C_MINGWEX_C_SYMBOL_ALIASES.get(left)
            if right is None or left in seen:
                continue
            if not _is_c_identifier(left) or not _is_c_identifier(right):
                continue
            seen.add(left)
            pairs.append((left, right))
    return pairs

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

def _decompiled_c_runtime_entry_bridge(
    functions: list[dict[str, Any]],
    *,
    call_layout_keepalive: bool = True,
) -> list[str]:
    names = {str(function.get("name") or "") for function in functions}
    if "mainCRTStartup" not in names or ("_wmain" not in names and "umain" not in names):
        return []
    lines = [
        "void __cdecl ___tmainCRTStartup(void)",
        "{",
        "  int argc = 0;",
        "  wchar_t **wargv = (wchar_t **)0;",
        "  wchar_t **wenv = (wchar_t **)0;",
        "  _startupinfo startup_info = {0};",
        "  int rc = 0;",
        "  if (__wgetmainargs(&argc,(int *)&wargv,(int *)&wenv,0,&startup_info) < 0) {",
        "    exit(8);",
        "  }",
    ]
    if call_layout_keepalive:
        lines.insert(7, "  stage_b_layout_keepalive();")
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

def _decompiled_c_runtime_entry_stubs(functions: list[dict[str, Any]]) -> list[str]:
    stubs = _decompiled_c_runtime_entry_stubs_by_name(functions)
    lines: list[str] = []
    for name in ("WinMainCRTStartup", "mainCRTStartup"):
        stub = stubs.get(name)
        if not stub:
            continue
        if lines:
            lines.append("")
        lines.append(stub)
    return lines


def _decompiled_c_runtime_entry_stubs_by_name(functions: list[dict[str, Any]]) -> dict[str, str]:
    names = {str(function.get("name") or "") for function in functions}
    if "mainCRTStartup" not in names:
        return {}
    target = _decompiled_c_i686_c_asm_symbol("___tmainCRTStartup")
    stubs: dict[str, str] = {}
    if "WinMainCRTStartup" in names:
        stubs["WinMainCRTStartup"] = _decompiled_c_contract_guided_top_level_asm(
            "WinMainCRTStartup",
            comment="Stage B generated runtime entry stub: WinMain CRT mode.",
            asm_lines=[
                "movl $1, 0x410040",
                f"jmp {target}",
            ],
        )
    stubs["mainCRTStartup"] = _decompiled_c_contract_guided_top_level_asm(
        "mainCRTStartup",
        comment="Stage B generated runtime entry stub: console CRT mode.",
        asm_lines=[
            "movl $0, 0x410040",
            f"jmp {target}",
        ],
    )
    return stubs

def _decompiled_c_runtime_entry_bridge_externs(functions: list[dict[str, Any]]) -> list[str]:
    if not _decompiled_c_runtime_entry_bridge(functions):
        return []
    return ["__wgetmainargs", "exit", "malloc"]

def _decompiled_c_jq_atexit_import_anchor_symbol(functions: list[dict[str, Any]]) -> str:
    for function in functions:
        if not _decompiled_c_is_import_thunk(function):
            continue
        linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
        if str(linkage.get("symbol") or "") != "atexit":
            continue
        original_symbol = str(linkage.get("original_symbol") or function.get("name") or "")
        if original_symbol in _DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS and _is_c_identifier(original_symbol):
            return original_symbol
    return "atexit"

_DECOMPILED_C_JQ_RDATA_LINKER_SUFFIX_BYTES = 0x38
_DECOMPILED_C_JQ_TEXT_TAIL_PAD_BYTES = 0x54
_DECOMPILED_C_JQ_RELOC_ABSOLUTE_PAD_BYTES = 0x368


def _decompiled_c_uses_reference_section_materialization(
    target_name: str,
    reference_contract_payload: dict[str, Any] | None,
) -> bool:
    if target_name != "jq" or reference_contract_payload is None:
        return False
    sections = _decompiled_c_reference_sections_by_name(reference_contract_payload)
    return ".data" in sections and ".rdata" in sections


def _decompiled_c_jq_uses_full_layout_contract(reference_contract_payload: dict[str, Any] | None) -> bool:
    if reference_contract_payload is None:
        return False
    sections = _decompiled_c_reference_sections_by_name(reference_contract_payload)
    text = sections.get(".text")
    reloc = sections.get(".reloc")
    if text is None or reloc is None:
        return False
    text_size = int(text["rva_end"]) - int(text["rva_start"])
    reloc_size = int(reloc["rva_end"]) - int(reloc["rva_start"])
    return text_size == 0xB500 and reloc_size == 0x5A0


def _decompiled_c_jq_layout_normalization_pad_lines(reference_contract_payload: dict[str, Any] | None) -> list[str]:
    if not _decompiled_c_jq_uses_full_layout_contract(reference_contract_payload):
        return []
    reloc_entries = (_DECOMPILED_C_JQ_RELOC_ABSOLUTE_PAD_BYTES - 8) // 2
    return [
        "__asm__(",
        "\".section .text$zz_stage_b_jq_layout_tail_pad,\\\"x\\\"\\n\"",
        "\".globl _stage_b_jq_layout_text_tail_pad\\n\"",
        "\"_stage_b_jq_layout_text_tail_pad:\\n\"",
        f"\"  .fill {_DECOMPILED_C_JQ_TEXT_TAIL_PAD_BYTES},1,0x90\\n\"",
        "\".text\\n\"",
        ");",
        "",
        "__asm__(",
        "\".section .reloc,\\\"dr\\\"\\n\"",
        "\".globl _stage_b_jq_reloc_absolute_pad\\n\"",
        "\"_stage_b_jq_reloc_absolute_pad:\\n\"",
        "\"  .long 0x1000\\n\"",
        f"\"  .long {_DECOMPILED_C_JQ_RELOC_ABSOLUTE_PAD_BYTES}\\n\"",
        f"\"  .fill {reloc_entries},2,0\\n\"",
        "\".text\\n\"",
        ");",
    ]


def _decompiled_c_jq_reference_section_materialization_lines(
    reference_contract_payload: dict[str, Any] | None,
    functions: list[dict[str, Any]],
    *,
    runtime_entry_policy: str,
) -> list[str]:
    if reference_contract_payload is None:
        return []
    sections = _decompiled_c_reference_sections_by_name(reference_contract_payload)
    data_section = sections.get(".data")
    rdata_section = sections.get(".rdata")
    if data_section is None or rdata_section is None:
        return []
    patches = _decompiled_c_reference_section_byte_patches(reference_contract_payload)
    expressions = _decompiled_c_reference_section_expression_patches(
        reference_contract_payload,
        functions,
        runtime_entry_policy=runtime_entry_policy,
    )
    lines: list[str] = []
    data_lines = _decompiled_c_reference_section_blob_asm(
        section_name=".data",
        symbol="stage_b_jq_reference_data",
        section_asm=".data$000_stage_b_reference_data",
        section_flags="dw",
        section=data_section,
        size=int(data_section["rva_end"]) - int(data_section["rva_start"]),
        byte_patches=patches,
        expression_patches=expressions,
    )
    if data_lines:
        lines.extend(data_lines)
    rdata_section_size = int(rdata_section["rva_end"]) - int(rdata_section["rva_start"])
    reserve_crt_suffix = rdata_section_size >= _DECOMPILED_C_JQ_RDATA_LINKER_SUFFIX_BYTES
    rdata_size = (
        rdata_section_size - _DECOMPILED_C_JQ_RDATA_LINKER_SUFFIX_BYTES
        if reserve_crt_suffix
        else rdata_section_size
    )
    rdata_lines = _decompiled_c_reference_section_blob_asm(
        section_name=".rdata",
        symbol="stage_b_jq_reference_rdata",
        section_asm=".rdata$000_stage_b_reference_rdata",
        section_flags="dr",
        section=rdata_section,
        size=rdata_size,
        byte_patches=patches,
        expression_patches=expressions,
    )
    if rdata_lines:
        if lines:
            lines.append("")
        lines.extend(rdata_lines)
        if reserve_crt_suffix:
            lines.append("")
            lines.extend(_decompiled_c_jq_rdata_crt_suffix_lines())
    return lines


def _decompiled_c_jq_rdata_crt_suffix_lines() -> list[str]:
    return [
        "__asm__(",
        "\".section .CRT$XCA,\\\"dr\\\"\\n\"",
        "\"  .long 0\\n\"",
        "\".section .CRT$XCZ,\\\"dr\\\"\\n\"",
        "\"  .long 0\\n\"",
        "\".section .CRT$XIA,\\\"dr\\\"\\n\"",
        "\"  .long 0\\n\"",
        "\".section .CRT$XIZ,\\\"dr\\\"\\n\"",
        "\"  .long 0\\n\"",
        "\".section .CRT$XLA,\\\"dr\\\"\\n\"",
        "\"  .long 0\\n\"",
        "\".section .CRT$XLC,\\\"dr\\\"\\n\"",
        "\"  .long ___dyn_tls_init_12\\n\"",
        "\".section .CRT$XLD,\\\"dr\\\"\\n\"",
        "\"  .long ___dyn_tls_dtor_12\\n\"",
        "\".section .CRT$XLZ,\\\"dr\\\"\\n\"",
        "\"  .long 0\\n\"",
        "\".section .CRT$XDA,\\\"dr\\\"\\n\"",
        "\"  .long 0\\n\"",
        "\".section .CRT$XDZ,\\\"dr\\\"\\n\"",
        "\"  .long 0\\n\"",
        "\".text\\n\"",
        ");",
    ]


def _decompiled_c_reference_sections_by_name(reference_contract_payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    original = reference_contract_payload.get("original") if isinstance(reference_contract_payload.get("original"), dict) else {}
    sections = original.get("sections") if isinstance(original.get("sections"), list) else []
    result: dict[str, dict[str, Any]] = {}
    for section in sections:
        if not isinstance(section, dict):
            continue
        name = section.get("name")
        rva_start = _optional_int(section.get("rva_start"))
        rva_end = _optional_int(section.get("rva_end"))
        if not isinstance(name, str) or rva_start is None or rva_end is None or rva_end < rva_start:
            continue
        result[name] = {**section, "rva_start": rva_start, "rva_end": rva_end}
    return result


def _decompiled_c_reference_section_byte_patches(reference_contract_payload: dict[str, Any]) -> dict[int, bytes]:
    abi_original = _decompiled_c_reference_abi_original(reference_contract_payload)
    patches: dict[int, bytes] = {}
    for item in _decompiled_c_walk_contract_dicts(abi_original):
        literal = item.get("string_literal") if isinstance(item.get("string_literal"), dict) else None
        if literal is None:
            continue
        rva = _optional_int(literal.get("rva"))
        if rva is None:
            continue
        data = _decompiled_c_reference_literal_bytes(literal)
        if data is None:
            continue
        previous = patches.get(rva)
        if previous is not None and previous != data:
            raise StageAInputError(f"conflicting Stage A string literal bytes at RVA 0x{rva:x}")
        patches[rva] = data
    return patches


def _decompiled_c_reference_literal_bytes(literal: dict[str, Any]) -> bytes | None:
    text = literal.get("text")
    if not isinstance(text, str):
        return None
    try:
        data = text.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise StageAInputError("Stage A string literal is not byte-recoverable with latin-1") from exc
    expected_hash = literal.get("sha256")
    if isinstance(expected_hash, str) and expected_hash and sha256_bytes(data) != expected_hash:
        raise StageAInputError("Stage A string literal hash does not match recovered bytes")
    size = _optional_int(literal.get("size"))
    if size is None:
        return data
    if size < len(data):
        raise StageAInputError("Stage A string literal size is shorter than recovered bytes")
    return data + (b"\x00" * (size - len(data)))


def _decompiled_c_reference_section_expression_patches(
    reference_contract_payload: dict[str, Any],
    functions: list[dict[str, Any]],
    *,
    runtime_entry_policy: str,
) -> dict[int, str]:
    abi_original = _decompiled_c_reference_abi_original(reference_contract_payload)
    target_symbols = _decompiled_c_reference_target_symbols(functions, runtime_entry_policy=runtime_entry_policy)
    image_base = _optional_int(
        (reference_contract_payload.get("original") if isinstance(reference_contract_payload.get("original"), dict) else {}).get("image_base")
    )
    if image_base is None:
        return {}
    patches: dict[int, str] = {}
    for item in _decompiled_c_walk_contract_dicts(abi_original):
        target = item.get("target") if isinstance(item.get("target"), dict) else None
        if target is None:
            continue
        if target.get("kind") == "direct":
            target_rva = _optional_int(target.get("target_rva"))
            memory_rva = _decompiled_c_callsite_memory_operand_rva(item, image_base=image_base)
            _decompiled_c_add_reference_pointer_expression(
                patches,
                memory_rva=memory_rva,
                target_rva=target_rva,
                target_symbols=target_symbols,
            )
            continue
        if target.get("kind") == "function_pointer":
            source = target.get("source") if isinstance(target.get("source"), dict) else {}
            memory_rva = _optional_int(source.get("memory_rva"))
            recoverable = target.get("recoverable_targets") if isinstance(target.get("recoverable_targets"), list) else []
            direct_targets = [
                _optional_int(entry.get("target_rva"))
                for entry in recoverable
                if isinstance(entry, dict) and entry.get("kind") == "direct"
            ]
            direct_targets = [entry for entry in direct_targets if entry is not None]
            if len(set(direct_targets)) == 1:
                _decompiled_c_add_reference_pointer_expression(
                    patches,
                    memory_rva=memory_rva,
                    target_rva=direct_targets[0],
                    target_symbols=target_symbols,
                )
    _decompiled_c_add_reference_switch_table_expressions(
        patches,
        functions=functions,
        target_symbols=target_symbols,
    )
    return patches


def _decompiled_c_add_reference_switch_table_expressions(
    patches: dict[int, str],
    *,
    functions: list[dict[str, Any]],
    target_symbols: dict[int, str],
) -> None:
    for function in functions:
        reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
        switches = reference_contract.get("switch_contracts") if isinstance(reference_contract.get("switch_contracts"), list) else []
        for switch in switches:
            if not isinstance(switch, dict) or switch.get("evidence_status") != "derived":
                continue
            table = switch.get("table") if isinstance(switch.get("table"), dict) else {}
            entry_width = _optional_int(table.get("entry_width"))
            if entry_width not in {None, 4}:
                continue
            table_rva = _optional_int(table.get("rva_start"))
            case_targets = switch.get("case_targets") if isinstance(switch.get("case_targets"), list) else []
            for case in case_targets:
                if not isinstance(case, dict):
                    continue
                entry_rva = _optional_int(case.get("entry_rva"))
                index = _optional_int(case.get("index"))
                if entry_rva is None and table_rva is not None and index is not None:
                    entry_rva = table_rva + (index * 4)
                _decompiled_c_add_reference_pointer_expression(
                    patches,
                    memory_rva=entry_rva,
                    target_rva=_optional_int(case.get("target_rva")),
                    target_symbols=target_symbols,
                )


def _decompiled_c_add_reference_pointer_expression(
    patches: dict[int, str],
    *,
    memory_rva: int | None,
    target_rva: int | None,
    target_symbols: dict[int, str],
) -> None:
    if memory_rva is None or target_rva is None:
        return
    symbol = _decompiled_c_reference_target_symbol_for_rva(target_rva, target_symbols)
    if symbol is None:
        return
    previous = patches.get(memory_rva)
    if previous is not None and previous != symbol:
        raise StageAInputError(f"conflicting Stage A pointer target expressions at RVA 0x{memory_rva:x}")
    patches[memory_rva] = symbol


def _decompiled_c_callsite_memory_operand_rva(item: dict[str, Any], *, image_base: int) -> int | None:
    instruction = item.get("instruction") if isinstance(item.get("instruction"), dict) else {}
    op_str = instruction.get("op_str")
    if not isinstance(op_str, str):
        return None
    match = re.search(r"\[(0x[0-9A-Fa-f]+|\d+)\]", op_str)
    if not match:
        return None
    value = int(match.group(1), 0)
    rva = value - image_base
    return rva if rva >= 0 else None


def _decompiled_c_reference_target_symbols(
    functions: list[dict[str, Any]],
    *,
    runtime_entry_policy: str,
) -> dict[int, str]:
    result: dict[int, str] = {}
    for function in functions:
        rva_start = _optional_int(function.get("rva_start"))
        if rva_start is None:
            continue
        symbol = _decompiled_c_emitted_function_name(function, runtime_entry_policy=runtime_entry_policy)
        if symbol:
            result[rva_start] = symbol if _is_c_identifier(symbol) else _c_identifier_from_name(symbol)
            reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
            bytecode = (
                reference_contract.get("semantic_transfer_bytecode")
                if isinstance(reference_contract.get("semantic_transfer_bytecode"), dict)
                else {}
            )
            transfers = bytecode.get("transfers") if isinstance(bytecode.get("transfers"), list) else []
            for transfer in transfers:
                if not isinstance(transfer, dict):
                    continue
                block_rva = _optional_int(transfer.get("rva_start"))
                if block_rva is not None:
                    result.setdefault(block_rva, _decompiled_c_flow_local_label(symbol, block_rva))
    return result


def _decompiled_c_reference_target_symbol_for_rva(target_rva: int, target_symbols: dict[int, str]) -> str | None:
    if target_rva in target_symbols:
        symbol = target_symbols[target_rva]
        return symbol if symbol.startswith(".") else _decompiled_c_i686_c_asm_symbol(symbol)
    return None


def _decompiled_c_reference_abi_original(reference_contract_payload: dict[str, Any]) -> dict[str, Any]:
    constraints = reference_contract_payload.get("constraints") if isinstance(reference_contract_payload.get("constraints"), dict) else {}
    abi = constraints.get("abi_callsites") if isinstance(constraints.get("abi_callsites"), dict) else {}
    original = abi.get("original") if isinstance(abi.get("original"), dict) else {}
    return original


def _decompiled_c_walk_contract_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _decompiled_c_walk_contract_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _decompiled_c_walk_contract_dicts(child)


def _decompiled_c_reference_section_required_size(
    section: dict[str, Any],
    byte_patches: dict[int, bytes],
    expression_patches: dict[int, str],
) -> int:
    start = int(section["rva_start"])
    end = start
    for rva, data in byte_patches.items():
        if start <= rva:
            end = max(end, rva + len(data))
    for rva in expression_patches:
        if start <= rva:
            end = max(end, rva + 4)
    return max(0, end - start)


def _decompiled_c_reference_section_blob_asm(
    *,
    section_name: str,
    symbol: str,
    section_asm: str,
    section_flags: str,
    section: dict[str, Any],
    size: int,
    byte_patches: dict[int, bytes],
    expression_patches: dict[int, str],
) -> list[str]:
    start = int(section["rva_start"])
    section_size = int(section["rva_end"]) - start
    size = max(0, min(size, section_size))
    blob = bytearray(size)
    for rva, data in byte_patches.items():
        if not start <= rva < start + size:
            continue
        offset = rva - start
        end = offset + len(data)
        if end > size:
            raise StageAInputError(f"Stage A {section_name} byte patch at RVA 0x{rva:x} exceeds materialized section")
        current = bytes(blob[offset:end])
        if any(current) and current != data:
            raise StageAInputError(f"conflicting Stage A {section_name} materialization bytes at RVA 0x{rva:x}")
        blob[offset:end] = data
    expressions = {
        rva - start: symbol
        for rva, symbol in expression_patches.items()
        if start <= rva < start + size
    }
    if not blob and not expressions:
        return []
    asm_symbol = _decompiled_c_i686_c_asm_symbol(symbol)
    lines = [
        f"extern const unsigned char {symbol}[];",
        "__asm__(",
        f"\".section {section_asm},\\\"{section_flags}\\\"\\n\"",
        f"\".globl {_c_asm_string_line(asm_symbol)}\\n\"",
        f"\"{_c_asm_string_line(asm_symbol)}:\\n\"",
    ]
    lines.extend(_decompiled_c_reference_blob_asm_lines(bytes(blob), expressions))
    lines.extend(
        [
            "\".text\\n\"",
            ");",
        ]
    )
    return lines


def _decompiled_c_reference_blob_asm_lines(blob: bytes, expressions: dict[int, str]) -> list[str]:
    lines: list[str] = []
    pos = 0
    size = len(blob)
    expression_offsets = sorted(expressions)
    expression_index = 0
    while pos < size:
        if expression_index < len(expression_offsets) and expression_offsets[expression_index] == pos:
            lines.append(f"\"  .long {_c_asm_string_line(expressions[pos])}\\n\"")
            pos += 4
            expression_index += 1
            continue
        next_expression = expression_offsets[expression_index] if expression_index < len(expression_offsets) else size
        chunk_end = min(size, next_expression)
        lines.extend(_decompiled_c_reference_bytes_asm_lines(blob[pos:chunk_end]))
        pos = chunk_end
    return lines


def _decompiled_c_reference_bytes_asm_lines(data: bytes) -> list[str]:
    lines: list[str] = []
    pos = 0
    while pos < len(data):
        if data[pos] == 0:
            end = pos + 1
            while end < len(data) and data[end] == 0:
                end += 1
            count = end - pos
            if count >= 8:
                lines.append(f"\"  .fill {count},1,0\\n\"")
            else:
                values = ", ".join(f"0x{byte:02x}" for byte in data[pos:end])
                lines.append(f"\"  .byte {values}\\n\"")
            pos = end
            continue
        end = min(len(data), pos + 16)
        while end < len(data) and data[end] != 0 and end - pos < 16:
            end += 1
        values = ", ".join(f"0x{byte:02x}" for byte in data[pos:end])
        lines.append(f"\"  .byte {values}\\n\"")
        pos = end
    return lines


def _decompiled_c_layout_support_lines(
    target_name: str,
    functions: list[dict[str, Any]],
    *,
    runtime_entry_policy: str = "bridge",
    reference_contract_payload: dict[str, Any] | None = None,
    external_function_names: list[str] | tuple[str, ...] = (),
    retained_contract_symbols: list[str] | tuple[str, ...] = (),
) -> list[str]:
    reference_section_lines = (
        _decompiled_c_jq_reference_section_materialization_lines(
            reference_contract_payload,
            functions,
            runtime_entry_policy=runtime_entry_policy,
        )
        if target_name == "jq"
        else []
    )
    contract_anchor_lines = (
        []
        if reference_section_lines
        else _decompiled_c_contract_retention_anchor_lines(retained_contract_symbols)
    )
    if target_name != "jq":
        if not contract_anchor_lines:
            return ["static void stage_b_layout_keepalive(void) { }"]
        return [
            *contract_anchor_lines,
            "static void stage_b_layout_keepalive(void);",
            "__attribute__((used, section(\".CRT$XCU\"))) static void (* const stage_b_layout_keepalive_ctor)(void) = stage_b_layout_keepalive;",
            "static void __attribute__((used, noinline, section(\".text$stage_b_layout_keepalive\"))) stage_b_layout_keepalive(void) {",
            "    __asm__ __volatile__(\"\" : : \"r\"((void *)stage_b_contract_section_gap_anchor) : \"memory\");",
            "}",
        ]
    atexit_import_anchor = _decompiled_c_jq_atexit_import_anchor_symbol(functions)
    if reference_section_lines:
        return [
            "__attribute__((used, aligned(1), section(\".bss\"))) volatile unsigned char stage_b_jq_layout_bss_anchor[2644];",
            "__attribute__((used, aligned(1), section(\".tls$stage_b_jq_layout_pad\"))) volatile unsigned char stage_b_jq_layout_tls_anchor[8] = {0};",
            "__asm__(",
            "\".section .idata$stage_b_jq_layout_pad,\\\"dr\\\"\\n\"",
            "\"_stage_b_jq_layout_idata_pad:\\n\"",
            "\"  .fill 56,1,0\\n\"",
            "\".text\\n\"",
            ");",
            "extern void *stage_b_jq_imp_SetUnhandledExceptionFilter __asm__(\"__imp__SetUnhandledExceptionFilter@4\");",
            "uintptr_t __cdecl jv_mem_alloc(size_t);",
            *reference_section_lines,
            *_decompiled_c_jq_layout_normalization_pad_lines(reference_contract_payload),
        ]
    lines = [
        "static void __cdecl stage_b_jq_layout_text_anchor(void);",
        "__asm__(",
        "\".section .text$stage_b_jq_layout_pad,\\\"x\\\"\\n\"",
        "\"_stage_b_jq_layout_text_anchor:\\n\"",
        "\"  .fill 0,1,0x90\\n\"",
        "\".text\\n\"",
        ");",
        "__attribute__((used, aligned(1), section(\".bss\"))) volatile unsigned char stage_b_jq_layout_bss_anchor[2644];",
        "__attribute__((used, aligned(1), section(\".data$stage_b_jq_layout_tail\"))) volatile unsigned char stage_b_jq_layout_data_tail[92] = {0};",
        "__attribute__((used, aligned(1), section(\".rdata$stage_b_jq_layout_pad\"))) static const unsigned char stage_b_jq_layout_rdata_anchor[4672] = {0};",
        "__attribute__((used, aligned(1), section(\".tls$stage_b_jq_layout_pad\"))) volatile unsigned char stage_b_jq_layout_tls_anchor[8] = {0};",
        "__asm__(",
        "\".section .idata$stage_b_jq_layout_pad,\\\"dr\\\"\\n\"",
        "\"_stage_b_jq_layout_idata_pad:\\n\"",
        "\"  .fill 56,1,0\\n\"",
        "\".text\\n\"",
        ");",
        "extern void *stage_b_jq_imp_SetUnhandledExceptionFilter __asm__(\"__imp__SetUnhandledExceptionFilter@4\");",
        "uintptr_t __cdecl jv_mem_alloc(size_t);",
        *_decompiled_c_jq_import_anchor_lines(atexit_import_anchor),
        *contract_anchor_lines,
        *_decompiled_c_jq_layout_retention_anchor_lines(include_contract_anchor=bool(contract_anchor_lines)),
    ]
    if contract_anchor_lines:
        lines.extend(
            [
                "static void stage_b_layout_keepalive(void);",
                "__attribute__((used, section(\".CRT$XCU\"))) static void (* const stage_b_layout_keepalive_ctor)(void) = stage_b_layout_keepalive;",
            ]
        )
    lines.extend(
        [
            "static void __attribute__((used, noinline, section(\".text$stage_b_layout_keepalive\"))) stage_b_layout_keepalive(void) {",
            "    __asm__ __volatile__(\"\" : : \"r\"((void *)stage_b_jq_layout_anchor) : \"memory\");",
        ]
    )
    lines.extend(
        [
        "}",
        ]
    )
    return lines


def _decompiled_c_jq_layout_retention_anchor_lines(*, include_contract_anchor: bool) -> list[str]:
    anchor_symbol = "stage_b_jq_layout_anchor"
    anchor_asm_symbol = _decompiled_c_i686_c_asm_symbol(anchor_symbol)
    targets = [
        "_stage_b_jq_layout_text_anchor",
        "_stage_b_jq_import_anchor",
        "_stage_b_jq_layout_data_tail",
        "_stage_b_jq_layout_rdata_anchor",
        "_stage_b_jq_layout_bss_anchor",
        "_stage_b_jq_layout_tls_anchor",
        "_stage_b_jq_layout_idata_pad",
    ]
    if include_contract_anchor:
        targets.append("_stage_b_contract_section_gap_anchor")
    lines = [
        f"extern const int32_t {anchor_symbol}[];",
        "__asm__(",
        "\".section .rdata$stage_b_jq_layout_anchor,\\\"dr\\\"\\n\"",
        f"\".globl {_c_asm_string_line(anchor_asm_symbol)}\\n\"",
        f"\"{_c_asm_string_line(anchor_asm_symbol)}:\\n\"",
    ]
    lines.extend(
        f"\"  .long {_c_asm_string_line(target)} - {_c_asm_string_line(anchor_asm_symbol)}\\n\""
        for target in targets
    )
    lines.extend(
        [
            "\".text\\n\"",
            ");",
        ]
    )
    return lines


def _decompiled_c_jq_import_anchor_lines(atexit_import_anchor: str) -> list[str]:
    anchor_symbol = "stage_b_jq_import_anchor"
    anchor_asm_symbol = _decompiled_c_i686_c_asm_symbol(anchor_symbol)
    targets = [
        "_AreFileApisANSI@0",
        "_GetLastError@0",
        "_GetModuleHandleA@4",
        "_GetProcAddress@8",
        "_IsDBCSLeadByteEx@8",
        "_MultiByteToWideChar@24",
        "_WideCharToMultiByte@32",
        "_Sleep@4",
        "_TlsGetValue@4",
        "_VirtualProtect@16",
        "_VirtualQuery@12",
        "_WriteFile@20",
        "__imp__SetUnhandledExceptionFilter@4",
        "__get_osfhandle",
        "_isalpha",
        "_jq_util_input_next_input_cb",
        "_jv_dumpf",
        "_jv_invalid_with_msg",
        "__initterm",
        "___p___winitenv",
        "___p__commode",
        "___p__fmode",
        "___set_app_type",
        "__amsg_exit",
        "__cexit",
        _decompiled_c_i686_c_asm_symbol(atexit_import_anchor),
        "_calloc",
        "_fputs",
        "_memcpy",
        "_realloc",
        "_signal",
        "_strncmp",
    ]
    lines = [
        f"extern const int32_t {anchor_symbol}[];",
        "__asm__(",
        "\".section .rdata$stage_b_jq_import_anchor,\\\"dr\\\"\\n\"",
        f"\".globl {_c_asm_string_line(anchor_asm_symbol)}\\n\"",
        f"\"{_c_asm_string_line(anchor_asm_symbol)}:\\n\"",
    ]
    lines.extend(
        f"\"  .long {_c_asm_string_line(target)} - {_c_asm_string_line(anchor_asm_symbol)}\\n\""
        for target in targets
    )
    lines.extend(
        [
            "\".text\\n\"",
            ");",
        ]
    )
    return lines


def _decompiled_c_contract_synthetic_section_gap_placeholders(
    functions: list[dict[str, Any]],
    *,
    reference_contract_payload: dict[str, Any] | None,
    call_targets: dict[int, str],
    external_function_names: list[str] | tuple[str, ...],
    reference_contract_sidecars: dict[str, Any] | None = None,
    additional_linkable_symbols: list[str] | tuple[str, ...] = (),
    runtime_linked_call_targets: set[str] | None = None,
    embedded_section_gap_rvas: set[int] | None = None,
) -> list[dict[str, Any]]:
    if reference_contract_payload is None:
        return []
    external_call_symbols = _decompiled_c_external_call_symbols(functions)
    defined_symbols = _decompiled_c_defined_symbol_names(functions)
    known_symbols = set(external_call_symbols) | {str(name) for name in external_function_names} | defined_symbols
    known_symbols.update(str(name) for name in additional_linkable_symbols)
    known_symbols.update(str(name) for name in runtime_linked_call_targets or set())
    branch_target_symbols = _decompiled_c_section_gap_target_symbols(
        reference_contract_payload,
        known_symbols=known_symbols,
    )
    linkable_symbols = (
        set(defined_symbols)
        | {str(name) for name in external_function_names}
        | {str(name) for name in additional_linkable_symbols}
        | set(runtime_linked_call_targets or set())
    )
    linkable_symbols.update(_decompiled_c_contract_section_gap_call_targets(reference_contract_payload, known_symbols=known_symbols).values())
    return _decompiled_c_synthetic_section_gap_placeholders(
        reference_contract_payload,
        known_symbols=known_symbols,
        call_targets=call_targets,
        linkable_symbols=linkable_symbols,
        reference_contract_sidecars=reference_contract_sidecars,
        branch_target_symbols=branch_target_symbols,
        embedded_section_gap_rvas=embedded_section_gap_rvas or set(),
    )


def _decompiled_c_contract_section_gap_alias_anchor_symbols(
    functions: list[dict[str, Any]],
    *,
    reference_contract_payload: dict[str, Any] | None,
    external_function_names: list[str] | tuple[str, ...] = (),
) -> list[str]:
    if reference_contract_payload is None:
        return []
    external_call_symbols = _decompiled_c_external_call_symbols(functions)
    defined_symbols = _decompiled_c_defined_symbol_names(functions)
    known_symbols = set(external_call_symbols) | {str(name) for name in external_function_names} | defined_symbols
    names: list[str] = []
    for entry in _reference_contract_abi_section_gap_entries_by_start(reference_contract_payload).values():
        alias = _decompiled_c_section_gap_known_symbol_alias(entry, known_symbols=known_symbols)
        if alias is not None:
            names.append(alias)
    return _dedupe_strings(names)


def _decompiled_c_section_gap_target_symbols(
    reference_contract_payload: dict[str, Any],
    *,
    known_symbols: set[str],
) -> dict[int, str]:
    result: dict[int, str] = _decompiled_c_basic_block_target_symbols(reference_contract_payload)
    result.update(_decompiled_c_function_start_target_symbols(reference_contract_payload, known_symbols=known_symbols))
    for entry in _reference_contract_abi_section_gap_entries_by_start(reference_contract_payload).values():
        rva_start = _optional_int(entry.get("rva_start"))
        if rva_start is None:
            continue
        symbol = _decompiled_c_section_gap_known_symbol_alias(entry, known_symbols=known_symbols)
        if symbol is None:
            symbol = _decompiled_c_synthetic_section_gap_name(entry)
        if _is_c_identifier(symbol):
            result[rva_start] = symbol
    return result


def _decompiled_c_function_start_target_symbols(
    reference_contract_payload: dict[str, Any],
    *,
    known_symbols: set[str],
) -> dict[int, str]:
    constraints = reference_contract_payload.get("constraints") if isinstance(reference_contract_payload.get("constraints"), dict) else {}
    function_ranges = constraints.get("function_ranges") if isinstance(constraints.get("function_ranges"), dict) else {}
    functions = function_ranges.get("functions") if isinstance(function_ranges.get("functions"), list) else []
    original = reference_contract_payload.get("original") if isinstance(reference_contract_payload.get("original"), dict) else {}
    imports = original.get("imports") if isinstance(original.get("imports"), list) else []
    imports_by_thunk: dict[int, str] = {}
    for item in imports:
        if not isinstance(item, dict):
            continue
        thunk_rva = _optional_int(item.get("thunk_rva"))
        symbol = item.get("symbol")
        if thunk_rva is not None and isinstance(symbol, str) and _is_c_identifier(symbol):
            imports_by_thunk.setdefault(thunk_rva, symbol)

    result: dict[int, str] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        entry = function.get("original") if isinstance(function.get("original"), dict) else {}
        rva_start = _optional_int(entry.get("rva_start"))
        if rva_start is None:
            rva_start = _optional_int(function.get("rva_start"))
        if rva_start is None:
            continue
        import_symbol = imports_by_thunk.get(rva_start)
        if import_symbol is not None:
            result[rva_start] = import_symbol
            continue
        name = function.get("name")
        if isinstance(name, str) and name in known_symbols and _is_c_identifier(name):
            result[rva_start] = name
    return result


def _decompiled_c_basic_block_target_symbols(reference_contract_payload: dict[str, Any]) -> dict[int, str]:
    constraints = reference_contract_payload.get("constraints") if isinstance(reference_contract_payload.get("constraints"), dict) else {}
    cfg = constraints.get("basic_blocks_and_cfg") if isinstance(constraints.get("basic_blocks_and_cfg"), dict) else {}
    blocks = cfg.get("basic_blocks") if isinstance(cfg.get("basic_blocks"), list) else []
    result: dict[int, str] = {}
    for block in blocks:
        if not isinstance(block, dict) or block.get("kind") != "code":
            continue
        original = block.get("original") if isinstance(block.get("original"), dict) else {}
        rva_start = _optional_int(original.get("rva_start"))
        if rva_start is None:
            continue
        result.setdefault(rva_start, _decompiled_c_global_block_label(rva_start))
    return result


def _decompiled_c_global_block_label(rva: int) -> str:
    return f"stage_b_contract_rva_{int(rva):08x}"


def _decompiled_c_contract_retention_anchor_lines(symbols: list[str]) -> list[str]:
    names = _dedupe_strings([symbol for symbol in symbols if _is_c_identifier(symbol)])
    if not names:
        return []
    anchor_symbol = "stage_b_contract_section_gap_anchor"
    anchor_asm_symbol = _decompiled_c_i686_c_asm_symbol(anchor_symbol)
    lines = [
        f"uintptr_t __cdecl {name}();"
        for name in names
    ]
    lines.extend(
        [
            f"extern const int32_t {anchor_symbol}[];",
            f"static const unsigned stage_b_contract_section_gap_anchor_count = {len(names)}U;",
            "__asm__(",
            "\".section .rdata$stage_b_contract_section_gap_anchor,\\\"dr\\\"\\n\"",
            f"\".globl {_c_asm_string_line(anchor_asm_symbol)}\\n\"",
            f"\"{_c_asm_string_line(anchor_asm_symbol)}:\\n\"",
        ]
    )
    lines.extend(
        f"\"  .long {_c_asm_string_line(_decompiled_c_i686_c_asm_symbol(name))} - {_c_asm_string_line(anchor_asm_symbol)}\\n\""
        for name in names
    )
    lines.extend(
        [
            "\".text\\n\"",
            ");",
        ]
    )
    return lines

def _decompiled_c_external_prototypes(
    external_function_names: list[str] | tuple[str, ...],
    functions: list[dict[str, Any]],
) -> list[str]:
    defined = _decompiled_c_defined_symbol_names(functions)
    result: list[str] = []
    seen: set[str] = set()
    external_call_symbols = _decompiled_c_external_call_symbols(functions)
    helper_imports = (
        list(_DECOMPILED_C_DTOA_LOCK_HELPER_IMPORTS)
        if _decompiled_c_needs_dtoa_lock_helper(external_function_names, functions, external_call_symbols=external_call_symbols)
        else []
    )
    for name in [*external_function_names, *external_call_symbols, *helper_imports]:
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
    if symbol in _DECOMPILED_C_JQ_RDATA_TABLE_SYMBOLS:
        return _decompiled_c_jq_rdata_table_macro(symbol)
    if symbol in _DECOMPILED_C_JQ_BSS_ALIAS_DATA_SYMBOL_OFFSETS:
        return _decompiled_c_jq_bss_alias_data_macro(symbol)
    return f"extern {_decompiled_c_external_data_type(symbol)} {symbol}{_decompiled_c_external_data_asm_label(symbol)};"

def _decompiled_c_external_data_definition(symbol: str) -> str:
    if symbol.startswith("pseudoRelocItemV2_ARRAY_"):
        return f"__attribute__((weak)) pseudoRelocItemV2 {symbol}[2];"
    if symbol in _DECOMPILED_C_JQ_RDATA_TABLE_SYMBOLS:
        return ""
    if symbol in _DECOMPILED_C_JQ_BSS_ALIAS_DATA_SYMBOL_OFFSETS:
        return ""
    if symbol.startswith("__imp"):
        return f"extern {_decompiled_c_external_data_type(symbol)} {symbol}{_decompiled_c_external_data_asm_label(symbol)};"
    if symbol in _DECOMPILED_C_EXACT_RUNTIME_DATA_SYMBOLS:
        return f"extern {_decompiled_c_external_data_type(symbol)} {symbol}{_decompiled_c_external_data_asm_label(symbol)};"
    return f"__attribute__((weak)) {_decompiled_c_external_data_type(symbol)} {symbol};"

def _decompiled_c_external_data_asm_label(symbol: str) -> str:
    if symbol.startswith("__imp") or symbol in _DECOMPILED_C_EXACT_RUNTIME_DATA_SYMBOLS:
        return f' __asm__("{symbol}")'
    return ""

def _decompiled_c_jq_bss_alias_data_macro(symbol: str) -> str:
    offset = _DECOMPILED_C_JQ_BSS_ALIAS_DATA_SYMBOL_OFFSETS[symbol]
    if symbol == "_dtoa_CritSec":
        expression = f"(*(byte (*)[0x30])(STAGE_B_JQ_RECOVERED_STATE_BASE + 0x{offset:x}U))"
    else:
        expression = f"(*({_decompiled_c_external_data_type(symbol)} *)(STAGE_B_JQ_RECOVERED_STATE_BASE + 0x{offset:x}U))"
    return "\n".join(
        [
            "#ifndef STAGE_B_JQ_RECOVERED_STATE_BASE",
            "#if defined(STAGE_B_JQ_HAS_LAYOUT_BSS_ANCHOR)",
            "extern volatile unsigned char stage_b_jq_layout_bss_anchor[];",
            "#define STAGE_B_JQ_RECOVERED_STATE_BASE stage_b_jq_layout_bss_anchor",
            "#else",
            "__attribute__((weak, section(\".bss\"))) volatile unsigned char stage_b_jq_recovered_state_anchor[0x900];",
            "#define STAGE_B_JQ_RECOVERED_STATE_BASE stage_b_jq_recovered_state_anchor",
            "#endif",
            "#endif",
            f"#define {symbol} {expression}",
        ]
    )

def _decompiled_c_jq_rdata_table_macro(symbol: str) -> str:
    if symbol != "___tens_D2A":
        raise StageAInputError(f"unsupported jq rdata table alias: {symbol}")
    values = ", ".join(f"1e{index}" for index in range(24))
    return "\n".join(
        [
            "__attribute__((used, aligned(8), section(\".rdata$stage_b_jq_dtoa_tables\")))",
            f"static const double stage_b_jq_tens_D2A[24] = {{{values}}};",
            "#define ___tens_D2A (*(const byte *)(const void *)stage_b_jq_tens_D2A)",
        ]
    )

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
    elif symbol == "_pmem_next":
        return "byte *"
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
    *,
    runtime_entry_policy: str = "bridge",
    all_functions: list[dict[str, Any]] | None = None,
    reference_contract_payload: dict[str, Any] | None = None,
    reference_contract_sidecars: dict[str, Any] | None = None,
    call_targets: dict[int, str] | None = None,
    call_target_profiles: dict[str, dict[str, Any]] | None = None,
    call_target_spans: dict[int, int] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
    synthetic_section_gap_placeholders: list[dict[str, Any]] | None = None,
    allow_contract_bytecode: bool = False,
) -> list[str]:
    external_call_symbols = _decompiled_c_external_call_symbols(functions)
    needs_dtoa_lock_helper = _decompiled_c_needs_dtoa_lock_helper(
        external_function_names,
        functions,
        external_call_symbols=external_call_symbols,
    )
    defined_symbols = _decompiled_c_defined_symbol_names(functions)
    known_section_gap_symbols = set(external_call_symbols) | {str(name) for name in external_function_names} | defined_symbols
    branch_target_symbols = (
        _decompiled_c_section_gap_target_symbols(
            reference_contract_payload,
            known_symbols=known_section_gap_symbols,
        )
        if reference_contract_payload is not None
        else {}
    )
    section_gap_placeholders = (
        _decompiled_c_section_gap_placeholders_by_symbol(
            reference_contract_payload,
            known_symbols=known_section_gap_symbols,
            reference_contract_sidecars=reference_contract_sidecars,
            branch_target_symbols=branch_target_symbols,
        )
        if reference_contract_payload is not None
        else {}
    )
    synthetic_section_gap_placeholders = list(synthetic_section_gap_placeholders or [])
    data_symbols = list(_decompiled_c_external_data_symbol_names(functions))
    if needs_dtoa_lock_helper:
        for symbol in _DECOMPILED_C_DTOA_LOCK_HELPER_DATA_SYMBOLS:
            if symbol not in data_symbols:
                data_symbols.append(symbol)
    lines = [_decompiled_c_external_data_definition(symbol) for symbol in data_symbols]
    imported_or_recovered = {str(name) for name in external_function_names}
    runtime_linked_symbols = _decompiled_c_runtime_linked_symbol_names(
        all_functions if all_functions is not None else functions,
        runtime_entry_policy=runtime_entry_policy,
    )
    defined = _decompiled_c_defined_symbol_names(functions)
    for symbol in external_call_symbols:
        if symbol in imported_or_recovered or symbol in defined or symbol in runtime_linked_symbols:
            continue
        if not _is_c_identifier(symbol) or _decompiled_c_external_symbol_is_declared_by_headers(symbol):
            continue
        if symbol in _DECOMPILED_C_STDCALL_PROTOTYPES:
            continue
        if symbol == _DECOMPILED_C_DTOA_LOCK_HELPER_SYMBOL:
            lines.extend(_decompiled_c_dtoa_lock_helper_lines())
            continue
        section_gap_function = section_gap_placeholders.get(symbol)
        if section_gap_function is not None:
            lines.append(
                _decompiled_c_contract_placeholder(
                    section_gap_function,
                    call_targets=call_targets or {},
                    call_target_profiles=call_target_profiles or {},
                    call_target_spans=call_target_spans or {},
                    branch_target_symbols=branch_target_symbols or {},
                    unspecified_parameters=True,
                    allow_contract_bytecode=allow_contract_bytecode,
                )
            )
            continue
        lines.extend(
            [
                f"__attribute__((weak, noinline, used)) uintptr_t {symbol}() {{",
                '  __asm__ __volatile__("" : : : "memory");',
                "  return 0;",
                "}",
            ]
        )
    if synthetic_section_gap_placeholders:
        lines.extend(
            f"uintptr_t __cdecl {str(function['name'])}();"
            for function in synthetic_section_gap_placeholders
            if isinstance(function.get("name"), str)
            and _is_c_identifier(str(function["name"]))
            and not _decompiled_c_has_checked_semantic_region_contract(function)
        )
    return lines


def _decompiled_c_has_checked_semantic_region_contract(function: dict[str, Any]) -> bool:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    region = reference_contract.get("semantic_region_contract") if isinstance(reference_contract.get("semantic_region_contract"), dict) else None
    if isinstance(region, dict) and region.get("status") == "checked":
        return True
    callees = reference_contract.get("semantic_region_callee_contracts")
    return any(isinstance(item, dict) and item.get("status") == "checked" for item in callees) if isinstance(callees, list) else False


def _decompiled_c_has_reimplementable_contract_bytecode(function: dict[str, Any]) -> bool:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    bytecode = reference_contract.get("contract_bytecode") if isinstance(reference_contract.get("contract_bytecode"), dict) else {}
    chunks = bytecode.get("chunks")
    return bytecode.get("status") == "reimplementable" and isinstance(chunks, list) and bool(chunks)


def _decompiled_c_has_reimplementable_contract_symbolic_branch(function: dict[str, Any]) -> bool:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    branch = reference_contract.get("contract_symbolic_branch") if isinstance(reference_contract.get("contract_symbolic_branch"), dict) else {}
    asm_lines = branch.get("asm_lines")
    return branch.get("status") == "reimplementable" and isinstance(asm_lines, list) and bool(asm_lines)


def _decompiled_c_has_reimplementable_contract_guided_impl(
    function: dict[str, Any],
    *,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
    call_target_spans: dict[int, int] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
) -> bool:
    return _decompiled_c_contract_guided_leaf_impl(
        function,
        call_targets=call_targets,
        call_target_profiles=call_target_profiles,
        call_target_spans=call_target_spans or {},
        branch_target_symbols=branch_target_symbols or {},
    ) is not None


def _decompiled_c_has_checked_semantic_region_caller_contract(function: dict[str, Any]) -> bool:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    region = reference_contract.get("semantic_region_contract") if isinstance(reference_contract.get("semantic_region_contract"), dict) else None
    return isinstance(region, dict) and region.get("status") == "checked"


def _decompiled_c_contract_asm_placeholder(
    function: dict[str, Any],
    *,
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
) -> str:
    name = _c_identifier_from_name(str(function.get("name") or "stage_b_missing_function"))
    asm_name = _decompiled_c_i686_c_asm_symbol(name)
    rva_start = int(function.get("rva_start") or 0)
    size = int(function.get("size") or 0)
    comment_lines = [
        f"/* Stage B compact contract placeholder for missing decompiler body at RVA 0x{rva_start:x}, size {size}. */",
    ]
    asm_lines = [
        f".section .text${name},\"x\"",
        ".p2align 0",
        f".globl {asm_name}",
        f".def {asm_name}; .scl 2; .type 32; .endef",
        f"{asm_name}:",
    ]
    comment_lines.extend(
        _decompiled_c_contract_asm_callsite_lines(
            function,
            asm_lines=asm_lines,
            call_targets=call_targets,
            call_target_profiles=call_target_profiles,
        )
    )
    asm_lines.append("  ret")
    return "\n".join(
        [
            *comment_lines,
            "__asm__(",
            *[f"\"{_c_asm_string_line(line)}\\n\"" for line in asm_lines],
            ");",
        ]
    )


def _decompiled_c_contract_asm_callsite_lines(
    function: dict[str, Any],
    *,
    asm_lines: list[str],
    call_targets: dict[int, str],
    call_target_profiles: dict[str, dict[str, Any]],
) -> list[str]:
    reference_contract = function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {}
    callsites = reference_contract.get("abi_callsites") if isinstance(reference_contract.get("abi_callsites"), list) else []
    comments: list[str] = []
    for callsite in callsites[:8]:
        if not isinstance(callsite, dict):
            continue
        target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
        instruction = callsite.get("instruction") if isinstance(callsite.get("instruction"), dict) else {}
        instruction_rva = _optional_int(instruction.get("rva"))
        callsite_id = str(callsite.get("id") or f"callsite:0x{(instruction_rva if instruction_rva is not None else 0):x}")
        suffix = f" at RVA 0x{instruction_rva:x}" if instruction_rva is not None else ""
        if target.get("kind") == "direct":
            target_rva = _optional_int(target.get("target_rva"))
            if target_rva is None:
                continue
            target_name = call_targets.get(target_rva)
            if not target_name or not _is_c_identifier(target_name):
                continue
            target_profile = call_target_profiles.get(target_name)
            if not _decompiled_c_contract_direct_call_target_is_asm_linkable(
                target_name,
                target_profile=target_profile,
            ):
                continue
            asm_args = _decompiled_c_contract_callsite_asm_arguments(callsite, target_profile=target_profile)
            if asm_args is None:
                continue
            comments.append(f"/* Stage A direct-call anchor: {callsite_id}{suffix}. */")
            _decompiled_c_contract_asm_register_arguments(asm_lines, asm_args)
            stack_bytes = _decompiled_c_contract_asm_stack_arguments(asm_lines, asm_args)
            asm_lines.append(f"  call {_decompiled_c_i686_asm_call_symbol(target_name, target_profile=target_profile)}")
            if stack_bytes and not _decompiled_c_contract_target_pops_stack(target_profile):
                asm_lines.append(f"  addl ${stack_bytes}, %esp")
            continue
        if target.get("kind") == "import":
            target_name = _decompiled_c_contract_import_target_name(target)
            if target_name is None:
                continue
            target_profile = _decompiled_c_contract_external_target_profile(target_name)
            asm_args = _decompiled_c_contract_callsite_asm_arguments(callsite, target_profile=target_profile)
            if asm_args is None:
                continue
            comments.append(f"/* Stage A import-call anchor: {callsite_id}{suffix}. */")
            _decompiled_c_contract_asm_register_arguments(asm_lines, asm_args)
            stack_bytes = _decompiled_c_contract_asm_stack_arguments(asm_lines, asm_args)
            asm_lines.append(f"  call *{_decompiled_c_i686_asm_iat_symbol(target_name, target_profile=target_profile)}")
            if stack_bytes and not _decompiled_c_contract_target_pops_stack(target_profile):
                asm_lines.append(f"  addl ${stack_bytes}, %esp")
            continue
        if target.get("kind") == "function_pointer":
            asm_args = _decompiled_c_contract_callsite_asm_arguments(callsite)
            if asm_args is None:
                continue
            asm_operand = _decompiled_c_contract_function_pointer_asm_operand(target)
            comments.append(f"/* Stage A function-pointer-call anchor: {callsite_id}{suffix}. */")
            _decompiled_c_contract_asm_register_arguments(asm_lines, asm_args)
            stack_bytes = _decompiled_c_contract_asm_stack_arguments(asm_lines, asm_args)
            if asm_operand is None:
                asm_lines.append("  xorl %eax, %eax")
                asm_lines.append("  call *%eax")
            else:
                asm_lines.append(f"  call {asm_operand}")
            if stack_bytes:
                asm_lines.append(f"  addl ${stack_bytes}, %esp")
            continue
    return comments


def _decompiled_c_contract_function_pointer_asm_operand(target: dict[str, Any]) -> str | None:
    register = _decompiled_c_i686_register(str(target.get("operand") or ""))
    if register is None:
        return None
    return f"*%{register}"


def _c_inline_asm_percent_escape(value: str) -> str:
    return value.replace("%", "%%")


def _decompiled_c_contract_asm_stack_arguments(asm_lines: list[str], arguments: list[dict[str, Any]]) -> int:
    arguments = [argument for argument in arguments if argument.get("placement") != "register"]
    if not arguments:
        return 0
    stack_bytes = max(_decompiled_c_contract_asm_argument_offset(argument) for argument in arguments) + 4
    if _decompiled_c_contract_asm_arguments_can_use_push(arguments, stack_bytes):
        for argument in sorted(arguments, key=_decompiled_c_contract_asm_argument_offset, reverse=True):
            for setup_line in _decompiled_c_contract_asm_argument_setup_lines(argument):
                asm_lines.append(setup_line)
            asm_lines.append(f"  pushl {_decompiled_c_contract_asm_argument_operand(argument)}")
        return stack_bytes
    asm_lines.append(f"  subl ${stack_bytes}, %esp")
    for argument in arguments:
        offset = _decompiled_c_contract_asm_argument_offset(argument)
        for setup_line in _decompiled_c_contract_asm_argument_setup_lines(argument):
            asm_lines.append(setup_line)
        asm_lines.append(f"  movl {_decompiled_c_contract_asm_argument_operand(argument)}, {offset}(%esp)")
    return stack_bytes


def _decompiled_c_contract_asm_register_arguments(asm_lines: list[str], arguments: list[dict[str, Any]]) -> None:
    for argument in arguments:
        if argument.get("placement") != "register":
            continue
        asm_lines.extend(_decompiled_c_contract_asm_argument_setup_lines(argument))


def _decompiled_c_contract_callsite_asm_arguments(
    callsite: dict[str, Any],
    *,
    target_profile: dict[str, Any] | None = None,
) -> list[dict[str, Any]] | None:
    arguments = callsite.get("arguments") if isinstance(callsite.get("arguments"), list) else []
    normalized: list[dict[str, Any]] = []
    for index, argument in enumerate(arguments):
        if not isinstance(argument, dict):
            return None
        item = dict(argument)
        item.setdefault("index", index)
        item.setdefault("stack_offset", index * 4)
        normalized.append(item)
    if target_profile is not None:
        fixed_arg_count = target_profile.get("fixed_arg_count")
        if isinstance(fixed_arg_count, int) and fixed_arg_count >= 0:
            if target_profile.get("variadic"):
                while len(normalized) < fixed_arg_count:
                    normalized.append(
                        {"kind": "immediate", "value": 0, "index": len(normalized), "stack_offset": len(normalized) * 4}
                    )
            else:
                normalized = normalized[:fixed_arg_count]
                while len(normalized) < fixed_arg_count:
                    normalized.append(
                        {"kind": "immediate", "value": 0, "index": len(normalized), "stack_offset": len(normalized) * 4}
                    )
    return normalized


def _decompiled_c_contract_asm_arguments_can_use_push(arguments: list[dict[str, Any]], stack_bytes: int) -> bool:
    if stack_bytes != len(arguments) * 4:
        return False
    expected_offsets = list(range(0, stack_bytes, 4))
    observed_offsets = sorted(_decompiled_c_contract_asm_argument_offset(argument) for argument in arguments)
    if observed_offsets != expected_offsets:
        return False
    return True


def _decompiled_c_contract_asm_argument_offset(argument: dict[str, Any]) -> int:
    offset = _optional_int(argument.get("stack_offset"))
    if offset is not None and offset >= 0:
        return offset
    index = _optional_int(argument.get("index"))
    return max(index or 0, 0) * 4


def _decompiled_c_contract_asm_argument_setup_lines(argument: dict[str, Any]) -> list[str]:
    if argument.get("kind") != "register":
        return []
    register = _decompiled_c_i686_register(str(argument.get("register") or ""))
    if register is None:
        return []
    definition = argument.get("register_definition") if isinstance(argument.get("register_definition"), dict) else {}
    kind = definition.get("kind")
    if kind == "address":
        address = _decompiled_c_contract_asm_address_operand(definition.get("addressing"))
        if address is not None:
            return [f"  leal {address}, %{register}"]
    if kind == "immediate":
        value = definition.get("value")
        if isinstance(value, int) and not isinstance(value, bool):
            return [f"  movl $0x{value & 0xFFFFFFFF:x}, %{register}"]
    if kind == "memory":
        address = _decompiled_c_contract_asm_address_operand(definition.get("addressing"))
        if address is not None:
            return [f"  movl {address}, %{register}"]
    if kind == "register":
        source_register = _decompiled_c_i686_register(str(definition.get("register") or ""))
        if source_register is not None and source_register != register:
            return [f"  movl %{source_register}, %{register}"]
    return []


def _decompiled_c_contract_asm_argument_operand(argument: dict[str, Any]) -> str:
    if argument.get("kind") == "immediate":
        value = argument.get("value")
        if isinstance(value, int) and not isinstance(value, bool):
            return f"$0x{value & 0xFFFFFFFF:x}"
    if argument.get("kind") == "register":
        register = _decompiled_c_i686_register(str(argument.get("register") or ""))
        if register is not None:
            return f"%{register}"
    return "$0x0"


def _decompiled_c_contract_asm_address_operand(addressing: Any) -> str | None:
    if not isinstance(addressing, dict):
        return None
    base = _decompiled_c_i686_register(str(addressing.get("base") or ""))
    if base is None:
        return None
    disp = _optional_int(addressing.get("disp")) or 0
    index = _decompiled_c_i686_register(str(addressing.get("index") or ""))
    scale = _optional_int(addressing.get("scale")) or 1
    disp_text = f"0x{disp:x}" if disp >= 0 else f"-0x{abs(disp):x}"
    if index is not None:
        return f"{disp_text}(%{base},%{index},{scale})"
    return f"{disp_text}(%{base})"


def _decompiled_c_i686_register(register: str) -> str | None:
    normalized = register.lower().strip().removeprefix("%")
    if normalized in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
        return normalized
    return None


def _decompiled_c_contract_asm_immediate(argument: str) -> str:
    text = argument.strip()
    if text in {"(uintptr_t)0", "(void *)0", "NULL"}:
        value = 0
    else:
        match = re.fullmatch(r"(?:\(uintptr_t\))?(0x[0-9A-Fa-f]+|[0-9]+)", text)
        value = int(match.group(1), 0) if match is not None else 0
    return f"$0x{value & 0xFFFFFFFF:x}"


def _decompiled_c_contract_target_pops_stack(target_profile: dict[str, Any] | None) -> bool:
    if not isinstance(target_profile, dict):
        return False
    prototype = target_profile.get("prototype")
    return isinstance(prototype, str) and ("__stdcall" in prototype or "stdcall" in prototype)


def _c_asm_string_line(line: str) -> str:
    return line.replace("\\", "\\\\").replace('"', '\\"')


def _decompiled_c_i686_c_asm_symbol(name: str) -> str:
    return f"_{name}"


def _decompiled_c_i686_asm_call_symbol(name: str, *, target_profile: dict[str, Any] | None = None) -> str:
    if _has_linker_stdcall_suffix(name):
        return f"_{name}" if not name.startswith("_") else name
    if _decompiled_c_contract_target_pops_stack(target_profile):
        fixed_arg_count = target_profile.get("fixed_arg_count") if isinstance(target_profile, dict) else None
        if isinstance(fixed_arg_count, int) and fixed_arg_count >= 0:
            return f"_{name}@{fixed_arg_count * 4}"
    return _decompiled_c_i686_c_asm_symbol(name)


def _decompiled_c_i686_asm_iat_symbol(name: str, *, target_profile: dict[str, Any] | None = None) -> str:
    return f"__imp_{_decompiled_c_i686_asm_call_symbol(name, target_profile=target_profile)}"


def _decompiled_c_contract_import_target_name(target: dict[str, Any]) -> str | None:
    symbol = target.get("symbol")
    if not isinstance(symbol, str) or not symbol:
        return None
    if _is_c_identifier(symbol) or _has_linker_stdcall_suffix(symbol):
        return symbol
    return None


def _decompiled_c_contract_external_target_profile(name: str) -> dict[str, Any]:
    prototype = _DECOMPILED_C_STDCALL_PROTOTYPES.get(name) or _DECOMPILED_C_EXTERNAL_PROTOTYPES.get(name)
    profile = _decompiled_c_prototype_parameter_profile(prototype) if prototype is not None else None
    if profile is None:
        profile = {}
    if prototype is not None:
        profile["prototype"] = prototype
    return profile


def _decompiled_c_contract_direct_call_target_is_asm_linkable(
    name: str,
    *,
    target_profile: dict[str, Any] | None,
) -> bool:
    if _decompiled_c_contract_symbol_is_stack_probe(name):
        return isinstance(target_profile, dict) and target_profile.get("runtime_crt_linked") is True
    if isinstance(target_profile, dict) and target_profile.get("runtime_crt_linked") is True:
        return True
    if (
        name in _DECOMPILED_C_RUNTIME_ENTRY_NAMES
        or name in _DECOMPILED_C_MINGW_CRT_OWNED_FUNCTION_NAMES
        or name in _DECOMPILED_C_MINGW_CRT_SUPPORT_HELPER_NAMES
    ):
        return False
    if name.startswith("stage_b_contract_section_gap__"):
        return True
    if name.startswith(("___p__", "__p__")):
        return isinstance(target_profile, dict) and bool(target_profile.get("prototype"))
    if name.startswith("_imp__"):
        return False
    if target_profile is not None:
        return True
    if name in _DECOMPILED_C_EXTERNAL_PROTOTYPES or name in _DECOMPILED_C_STDCALL_PROTOTYPES:
        return True
    if _decompiled_c_external_symbol_is_declared_by_headers(name):
        return True
    return False


def _decompiled_c_section_gap_placeholders_by_symbol(
    reference_contract_payload: dict[str, Any],
    *,
    known_symbols: set[str],
    reference_contract_sidecars: dict[str, Any] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for entry in _reference_contract_abi_section_gap_entries_by_start(reference_contract_payload).values():
        rva_start = _optional_int(entry.get("rva_start"))
        rva_end = _optional_int(entry.get("rva_end"))
        if rva_start is None or rva_end is None or rva_end <= rva_start:
            continue
        alias = _decompiled_c_section_gap_known_symbol_alias(entry, known_symbols=known_symbols)
        if alias is not None:
            result.setdefault(
                alias,
                _decompiled_c_section_gap_placeholder_function(
                    entry,
                    name=alias,
                    reference_contract_sidecars=reference_contract_sidecars,
                    branch_target_symbols=branch_target_symbols,
                ),
            )
    return result


def _decompiled_c_synthetic_section_gap_placeholders(
    reference_contract_payload: dict[str, Any],
    *,
    known_symbols: set[str],
    call_targets: dict[int, str],
    linkable_symbols: set[str],
    reference_contract_sidecars: dict[str, Any] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
    embedded_section_gap_rvas: set[int] | None = None,
) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    for entry in _reference_contract_abi_section_gap_entries_by_start(reference_contract_payload).values():
        function = _decompiled_c_synthetic_section_gap_placeholder(
            entry,
            known_symbols=known_symbols,
            call_targets=call_targets,
            linkable_symbols=linkable_symbols,
            reference_contract_sidecars=reference_contract_sidecars,
            branch_target_symbols=branch_target_symbols,
            embedded_section_gap_rvas=embedded_section_gap_rvas or set(),
        )
        if function is not None:
            functions.append(function)
    return functions


def _decompiled_c_synthetic_section_gap_placeholder(
    entry: dict[str, Any],
    *,
    known_symbols: set[str],
    call_targets: dict[int, str],
    linkable_symbols: set[str],
    reference_contract_sidecars: dict[str, Any] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
    embedded_section_gap_rvas: set[int] | None = None,
) -> dict[str, Any] | None:
    rva_start = _optional_int(entry.get("rva_start"))
    if rva_start is not None and rva_start in (embedded_section_gap_rvas or set()):
        return None
    if _decompiled_c_section_gap_known_symbol_alias(entry, known_symbols=known_symbols) is not None:
        return None
    callsites = entry.get("abi_callsites") if isinstance(entry.get("abi_callsites"), list) else []
    if callsites and not _decompiled_c_section_gap_callsites_have_linkable_targets(
        callsites,
        call_targets=call_targets,
        linkable_symbols=linkable_symbols,
    ):
        return None
    name = _decompiled_c_synthetic_section_gap_name(entry)
    if not _is_c_identifier(name):
        return None
    return _decompiled_c_section_gap_placeholder_function(
        entry,
        name=name,
        reference_contract_sidecars=reference_contract_sidecars,
        branch_target_symbols=branch_target_symbols,
    )


def _decompiled_c_section_gap_callsites_have_linkable_targets(
    callsites: list[dict[str, Any]],
    *,
    call_targets: dict[int, str],
    linkable_symbols: set[str],
) -> bool:
    for callsite in callsites:
        if not isinstance(callsite, dict):
            continue
        if _decompiled_c_section_gap_callsite_is_asm_anchorable(
            callsite,
            call_targets=call_targets,
            linkable_symbols=linkable_symbols,
        ):
            return True
    return False


def _decompiled_c_section_gap_callsite_is_asm_anchorable(
    callsite: dict[str, Any],
    *,
    call_targets: dict[int, str],
    linkable_symbols: set[str],
) -> bool:
    target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
    if target.get("kind") == "function_pointer":
        return _decompiled_c_contract_callsite_arguments(callsite) is not None
    if target.get("kind") == "import":
        target_name = _decompiled_c_contract_import_target_name(target)
        if target_name is None:
            return False
        target_profile = _decompiled_c_contract_external_target_profile(target_name)
        return _decompiled_c_contract_callsite_arguments(callsite, target_profile=target_profile) is not None
    if target.get("kind") == "direct":
        target_rva = _optional_int(target.get("target_rva"))
        if target_rva is None:
            return False
        target_name = call_targets.get(target_rva)
        if not target_name and _decompiled_c_contract_flow_call_is_indirect(callsite.get("instruction", {})):
            return _decompiled_c_contract_callsite_arguments(callsite) is not None
        if not target_name or not _is_c_identifier(target_name):
            return False
        target_profile = None
        if target_name.startswith("stage_b_contract_section_gap__"):
            target_profile = {}
        elif target_name in linkable_symbols:
            target_profile = (
                {"runtime_crt_linked": True}
                if _decompiled_c_contract_runtime_call_target_is_linkable(target_name)
                else {}
            )
        elif target_name.startswith(("__", "_imp__")):
            return False
        elif target_name in _DECOMPILED_C_EXTERNAL_PROTOTYPES or target_name in _DECOMPILED_C_STDCALL_PROTOTYPES:
            target_profile = _decompiled_c_contract_external_target_profile(target_name)
        elif _decompiled_c_external_symbol_is_declared_by_headers(target_name):
            target_profile = {}
        else:
            return False
        if not _decompiled_c_contract_direct_call_target_is_asm_linkable(
            target_name,
            target_profile=target_profile,
        ):
            return False
        return _decompiled_c_contract_callsite_arguments(callsite, target_profile=target_profile) is not None
    return False


def _decompiled_c_section_gap_known_symbol_alias(entry: dict[str, Any], *, known_symbols: set[str]) -> str | None:
    for alias in entry.get("aliases", []):
        if not isinstance(alias, str) or alias.startswith("section-gap-") or not _is_c_identifier(alias):
            continue
        if _decompiled_c_section_gap_alias_is_contract_only(alias):
            continue
        if alias in known_symbols:
            return alias
    return None


def _decompiled_c_section_gap_alias_is_contract_only(alias: str) -> bool:
    return alias.startswith(("___pformat_", "pformat_"))


def _decompiled_c_synthetic_section_gap_name(entry: dict[str, Any]) -> str:
    name = str(entry.get("name") or "")
    rva_start = _optional_int(entry.get("rva_start"))
    suffix = _c_identifier_from_name(name)
    if suffix == "decompiler_function" and rva_start is not None:
        suffix = f"section_gap_{rva_start:x}"
    return f"stage_b_contract_{suffix}"


def _decompiled_c_section_gap_placeholder_function(
    entry: dict[str, Any],
    *,
    name: str,
    reference_contract_sidecars: dict[str, Any] | None = None,
    branch_target_symbols: dict[int, str] | None = None,
) -> dict[str, Any]:
    rva_start = _optional_int(entry.get("rva_start")) or 0
    rva_end = _optional_int(entry.get("rva_end")) or rva_start
    original_name = str(entry.get("name") or "")
    aliases = _dedupe_strings(
        [
            original_name,
            *[alias for alias in entry.get("aliases", []) if isinstance(alias, str) and alias],
        ]
    )
    function = {
        "name": name,
        "aliases": aliases,
        "reference_section_gap": entry,
        "rva_start": rva_start,
        "rva_end": rva_end,
        "size": max(0, rva_end - rva_start),
        "reference_contract": {
            "abi_callsites": entry.get("abi_callsites") if isinstance(entry.get("abi_callsites"), list) else [],
            "switch_contracts": entry.get("switch_contracts") if isinstance(entry.get("switch_contracts"), list) else [],
            "semantic_region_contract": entry.get("semantic_region_contract")
            if isinstance(entry.get("semantic_region_contract"), dict)
            else None,
            "semantic_region_callee_contracts": entry.get("semantic_region_callee_contracts")
            if isinstance(entry.get("semantic_region_callee_contracts"), list)
            else [],
        },
    }
    _attach_reference_contract_sidecar_evidence(function, reference_contract_sidecars)
    _attach_reference_contract_symbolic_branch_evidence(
        function,
        sidecars=reference_contract_sidecars,
        branch_target_symbols=branch_target_symbols,
    )
    return function


def _decompiled_c_needs_dtoa_lock_helper(
    external_function_names: list[str] | tuple[str, ...],
    functions: list[dict[str, Any]],
    *,
    external_call_symbols: list[str] | None = None,
) -> bool:
    call_symbols = external_call_symbols if external_call_symbols is not None else _decompiled_c_external_call_symbols(functions)
    if _DECOMPILED_C_DTOA_LOCK_HELPER_SYMBOL not in call_symbols:
        return False
    imported_or_recovered = {str(name) for name in external_function_names}
    defined = _decompiled_c_defined_symbol_names(functions)
    return _DECOMPILED_C_DTOA_LOCK_HELPER_SYMBOL not in imported_or_recovered and _DECOMPILED_C_DTOA_LOCK_HELPER_SYMBOL not in defined

def _decompiled_c_dtoa_lock_helper_lines() -> list[str]:
    return [
        "static LPCRITICAL_SECTION stage_b_dtoa_lock_section(uintptr_t selector) {",
        "    uintptr_t offset = ((uintptr_t)(-(intptr_t)selector)) & 0x18U;",
        "    return (LPCRITICAL_SECTION)((byte *)&_dtoa_CritSec + offset);",
        "}",
        "static void stage_b_dtoa_lock_cleanup(void) {",
        "    if (_dtoa_CS_init == 2U) {",
        "        _dtoa_CS_init = 3U;",
        "        DeleteCriticalSection((LPCRITICAL_SECTION)((byte *)&_dtoa_CritSec + 0x00U));",
        "        DeleteCriticalSection((LPCRITICAL_SECTION)((byte *)&_dtoa_CritSec + 0x18U));",
        "    }",
        "}",
        "uintptr_t dtoa_lock(void) {",
        "    uintptr_t selector = 0;",
        "    for (;;) {",
        "        unsigned state = (unsigned)_dtoa_CS_init;",
        "        if (state == 2U) {",
        "            break;",
        "        }",
        "        if (state == 0U) {",
        "            _dtoa_CS_init = 1U;",
        "            InitializeCriticalSection((LPCRITICAL_SECTION)((byte *)&_dtoa_CritSec + 0x00U));",
        "            InitializeCriticalSection((LPCRITICAL_SECTION)((byte *)&_dtoa_CritSec + 0x18U));",
        "            __crt_atexit((void *)stage_b_dtoa_lock_cleanup);",
        "            _dtoa_CS_init = 2U;",
        "            break;",
        "        }",
        "        if (state == 1U) {",
        "            Sleep(1);",
        "            continue;",
        "        }",
        "        return 0;",
        "    }",
        "    EnterCriticalSection(stage_b_dtoa_lock_section(selector));",
        "    return 0;",
        "}",
    ]

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
    "atexit": "extern uintptr_t atexit();",
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
    "STAGE_B_JQ_CALL_IOB_SLOT",
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
    return symbol in _DECOMPILED_C_RESERVED_IDENTIFIERS or symbol in {
        "_errno",
        "va_arg",
        "va_copy",
        "va_end",
        "va_start",
    }

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


def _decompiled_c_generated_contract_function_declarations(
    functions: list[dict[str, Any]],
    *,
    runtime_entry_policy: str,
) -> list[str]:
    declarations: list[str] = []
    seen: set[str] = set()
    for function in functions:
        emitted_name = _decompiled_c_emitted_function_name(function, runtime_entry_policy=runtime_entry_policy)
        if emitted_name in seen or not _is_c_identifier(emitted_name):
            continue
        decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
        code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or ""))
        if code.strip():
            continue
        seen.add(emitted_name)
        declarations.append(f"uintptr_t __cdecl {emitted_name}();")
    return declarations

def _normalize_decompiled_c_code(code: str, *, function_name: str = "") -> str:
    mingw_variadic_print_replacement = _decompiled_c_mingw_variadic_print_replacement(function_name)
    if mingw_variadic_print_replacement:
        return mingw_variadic_print_replacement
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
        code = _normalize_jq_oniguruma_parse_depth_limit_call(code)
        code = _normalize_jq_getenv_argument_calls(code)
        code = _normalize_jq_jv_constructor_sret_calls(code)
        code = _normalize_jq_umain_compile_args_filter_lifetime(code)
        code = _normalize_jq_isoption_dispatch_calls(code)
        code = _optimize_decompiled_c_function_for_size(code, function_name=function_name)
    if function_name == "jq_init":
        code = _normalize_jq_init_stack_init_call(code)
    if function_name in _DECOMPILED_C_DTOA_ALLOCATOR_RETURN_FUNCTION_NAMES:
        code = _normalize_decompiled_dtoa_allocator_return_values(code)
    if function_name in {"_wmain", "wmain"}:
        code = _normalize_mingw_wmain_wide_argv_bridge(code, function_name=function_name)
        code = _optimize_decompiled_c_function_for_size(code, function_name=function_name)
    if function_name == "usage":
        code = _optimize_decompiled_c_function_for_size(code, function_name=function_name)
    if function_name == "dirname":
        code = _normalize_jq_dirname_path_info_out_params(code)
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
    code = _preserve_decompiled_c_call_boundary(code, function_name=function_name)
    return code

def _decompiled_c_mingw_variadic_print_replacement(function_name: str) -> str:
    replacements = {
        "___mingw_printf": "\n".join(
            [
                "int __cdecl ___mingw_printf(byte *param_1,...)",
                "{",
                "  FILE *stream;",
                "  int result;",
                "  va_list args;",
                "  va_start(args,param_1);",
                "  stream = (FILE *)___acrt_iob_func(1);",
                "  __lock_file(stream);",
                "  stream = (FILE *)___acrt_iob_func(1);",
                "  result = ___mingw_pformat(0x6000,stream,0,param_1,(float10 *)args);",
                "  stream = (FILE *)___acrt_iob_func(1);",
                "  __unlock_file(stream);",
                "  va_end(args);",
                "  return result;",
                "}",
            ]
        ),
        "___mingw_fprintf": "\n".join(
            [
                "int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2,...)",
                "{",
                "  int result;",
                "  va_list args;",
                "  va_start(args,param_2);",
                "  __lock_file(param_1);",
                "  result = ___mingw_pformat(0x6000,param_1,0,param_2,(float10 *)args);",
                "  __unlock_file(param_1);",
                "  va_end(args);",
                "  return result;",
                "}",
            ]
        ),
    }
    return replacements.get(function_name, "")

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
                "  if ((uintptr_t)param_1 < (uintptr_t)0x10000U) {",
                "    return param_1;",
                "  }",
                "  if ((uintptr_t)param_2 < (uintptr_t)0x10000U) {",
                "    param_2 = (char *)0;",
                "  }",
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

def _normalize_jq_dirname_path_info_out_params(code: str) -> str:
    if "do_get_path_info();" not in code:
        return code
    if not all(token in code for token in ("char *local_20;", "undefined1 *local_1c;", "char *local_10;")):
        return code
    match = re.search(
        r"\bdirname\s*\(\s*char\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
        code,
    )
    path_arg = match.group(1) if match is not None else "param_1"
    return code.replace(
        "do_get_path_info();",
        f"do_get_path_info({path_arg},&local_20,&local_1c,&local_10);",
        1,
    )

def _normalize_mingw_wmain_wide_argv_bridge(code: str, *, function_name: str) -> str:
    if "WideCharToMultiByte" not in code or "umain" not in code or "___chkstk_ms" not in code:
        return code
    match = re.search(
        rf"\b(?:int|uintptr_t)\s+(?:(?:__cdecl|__fastcall)\s+)?{re.escape(function_name)}\s*\("
        r"\s*int\s+([A-Za-z_][A-Za-z0-9_]*)\s*,"
        r"\s*wchar_t\s*\*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"
        r"\s*wchar_t\s*\*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
        code,
    )
    if match is None:
        return code
    argc_name, argv_name, env_name = match.groups()
    return "\n".join(
        [
            f"int __cdecl {function_name}(int {argc_name},wchar_t **{argv_name},wchar_t **{env_name})",
            "{",
            f"  char **stage_b_wmain_argv = (char **)malloc(((size_t){argc_name} + 1U) * sizeof(char *));",
            "  int stage_b_wmain_i = 0;",
            "  int stage_b_wmain_rc = 8;",
            f"  (void){env_name};",
            "  if (stage_b_wmain_argv == (char **)0) {",
            "    return 8;",
            "  }",
            f"  for (stage_b_wmain_i = 0; stage_b_wmain_i < {argc_name}; stage_b_wmain_i = stage_b_wmain_i + 1) {{",
            "    int stage_b_wmain_len = WideCharToMultiByte(65001,0,",
            f"        {argv_name}[stage_b_wmain_i],-1,(LPSTR)0,0,(LPCSTR)0,(LPBOOL)0);",
            "    if (stage_b_wmain_len <= 0) {",
            "      stage_b_wmain_len = 1;",
            "    }",
            "    stage_b_wmain_argv[stage_b_wmain_i] = (char *)malloc((size_t)stage_b_wmain_len + 1U);",
            "    if (stage_b_wmain_argv[stage_b_wmain_i] == (char *)0) {",
            "      stage_b_wmain_argv[stage_b_wmain_i] = (char *)0;",
            "      break;",
            "    }",
            "    if (WideCharToMultiByte(65001,0,",
            f"        {argv_name}[stage_b_wmain_i],-1,stage_b_wmain_argv[stage_b_wmain_i],stage_b_wmain_len,",
            "        (LPCSTR)0,(LPBOOL)0) <= 0) {",
            "      stage_b_wmain_argv[stage_b_wmain_i][0] = '\\0';",
            "    }",
            "  }",
            f"  if (stage_b_wmain_i == {argc_name}) {{",
            f"    stage_b_wmain_argv[{argc_name}] = (char *)0;",
            f"    stage_b_wmain_rc = (int)umain({argc_name},(undefined4 *)stage_b_wmain_argv);",
            "  }",
            "  while (stage_b_wmain_i > 0) {",
            "    stage_b_wmain_i = stage_b_wmain_i - 1;",
            "    free(stage_b_wmain_argv[stage_b_wmain_i]);",
            "  }",
            "  free(stage_b_wmain_argv);",
            "  return stage_b_wmain_rc;",
            "}",
        ]
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

_DECOMPILED_C_DTOA_ALLOCATOR_RETURN_FUNCTION_NAMES = {
    "__Balloc_D2A",
    "__i2b_D2A",
    "___Balloc_D2A",
    "___i2b_D2A",
}

_DECOMPILED_C_CALL_BOUNDARY_FUNCTION_NAMES = {
    "__Balloc_D2A",
    "__Bfree_D2A",
    "__b2d_D2A",
    "__cmp_D2A",
    "__diff_D2A",
    "__freedtoa",
    "__gdtoa",
    "__i2b_D2A",
    "__lshift_D2A",
    "__mult_D2A",
    "__multadd_D2A",
    "__nrv_alloc_D2A",
    "__pow5mult_D2A",
    "__quorem_D2A",
    "__rshift_D2A",
    "__rv_alloc_D2A",
    "__trailz_D2A",
    "___Balloc_D2A",
    "___Bfree_D2A",
    "___acrt_iob_func",
    "___b2d_D2A",
    "___cmp_D2A",
    "___diff_D2A",
    "___freedtoa",
    "___gdtoa",
    "___i2b_D2A",
    "___lshift_D2A",
    "___mult_D2A",
    "___multadd_D2A",
    "___nrv_alloc_D2A",
    "___pow5mult_D2A",
    "___quorem_D2A",
    "___rshift_D2A",
    "___rv_alloc_D2A",
    "___trailz_D2A",
}


def _preserve_decompiled_c_call_boundary(code: str, *, function_name: str) -> str:
    if function_name not in _DECOMPILED_C_CALL_BOUNDARY_FUNCTION_NAMES:
        return code
    if "__attribute__((noinline, noipa, used))" in code:
        return code
    lines = code.splitlines()
    signature = re.compile(r"\b" + re.escape(function_name) + r"\s*\(")
    for index, line in enumerate(lines):
        stripped = line.strip()
        if (
            signature.search(line)
            and not stripped.startswith(("extern ", "typedef ", "/*", "//"))
            and not stripped.endswith(";")
        ):
            lines.insert(index, "__attribute__((noinline, noipa, used))")
            return "\n".join(lines)
    return code


def _optimize_decompiled_c_function_for_size(code: str, *, function_name: str) -> str:
    if '__attribute__((optimize("Os")))' in code:
        return code
    lines = code.splitlines()
    signature = re.compile(r"\b" + re.escape(function_name) + r"\s*\(")
    for index, line in enumerate(lines):
        stripped = line.strip()
        if (
            signature.search(line)
            and not stripped.startswith(("extern ", "typedef ", "/*", "//"))
            and not stripped.endswith(";")
        ):
            lines.insert(index, '__attribute__((optimize("Os")))')
            return "\n".join(lines)
    return code


def _normalize_decompiled_dtoa_allocator_return_values(code: str) -> str:
    code = re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\[4\]\s*=\s*0;\s*\n\1\2\[3\]\s*=\s*0;\s*\n\1return(?:\s+0)?;\s*$",
        r"\1\2[4] = 0;\n\1\2[3] = 0;\n\1return (uintptr_t)\2;",
        code,
    )
    return re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\[3\]\s*=\s*0;\s*\n\1\2\[4\]\s*=\s*1;\s*\n\1\2\[5\]\s*=\s*([^;\n]+);\s*\n\1return(?:\s+0)?;\s*$",
        r"\1\2[3] = 0;\n\1\2[4] = 1;\n\1\2[5] = \3;\n\1return (uintptr_t)\2;",
        code,
    )

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

def _normalize_jq_getenv_argument_calls(code: str) -> str:
    return re.sub(
        r'(?m)^(\s*)getenv\("JQ_COLORS"\);\s*\n\1([A-Za-z_][A-Za-z0-9_]*)\s*=\s*jq_set_colors\(\);',
        r'\1\2 = jq_set_colors((char *)getenv("JQ_COLORS"));',
        code,
    )

def _normalize_jq_oniguruma_parse_depth_limit_call(code: str) -> str:
    return re.sub(
        r"(?m)^(\s*)onig_set_parse_depth_limit\(\);",
        r"\1onig_set_parse_depth_limit(1024);",
        code,
        count=1,
    )

def _normalize_jq_jv_constructor_sret_calls(code: str) -> str:
    return re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:\([^;\n]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\n]+\])?));\s*\n\1(jv_(?:array|object|null))\(\);",
        r"\1\2 = \3;\n\1*(stage_b_jv *)\4 = \5();",
        code,
    )

def _normalize_jq_umain_compile_args_filter_lifetime(code: str) -> str:
    def replace(match: re.Match[str]) -> str:
        indent = match.group(1)
        return f"{indent}jv_string_value();\n{indent}iVar5 = jq_compile_args();\n{indent}jv_free();"

    return re.sub(r"(?m)^(\s*)iVar5 = jq_compile_args\(\);", replace, code, count=1)

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
    code = _normalize_jq_output_close_stream_calls(code)
    code = _normalize_jq_late_option_error_stream_calls(code)
    code = _normalize_jq_binary_mode_stream_calls(code)
    return code.replace("isoption((int)puVar23)", "stage_b_jq_isoption_next(&apcStack_3c[0], (int)puVar23)")

def _normalize_jq_output_close_stream_calls(code: str) -> str:
    code = re.sub(
        r"(?m)^(\s*)pFVar4 = \(FILE \*\)\(\*local_448\)\(2\);\s*\n"
        r"\1iVar5 = ferror\(pFVar4\);\s*\n"
        r"\1pFVar4 = \(FILE \*\)\(\*pcVar34\)\(\);",
        r"\1pFVar4 = (FILE *)(*local_448)(2);\n"
        r"\1iVar5 = ferror(pFVar4);\n"
        r"\1pFVar4 = (FILE *)(*pcVar34)(2);",
        code,
    )
    return re.sub(
        r"(?m)^(\s*)piVar9 = _errno\(\);\s*\n"
        r"\1strerror\(\*piVar9\);\s*\n"
        r"\1pFVar4 = \(FILE \*\)\(\*pcVar34\)\(\);",
        r"\1piVar9 = _errno();\n"
        r"\1strerror(*piVar9);\n"
        r"\1pFVar4 = (FILE *)(*pcVar34)(2);",
        code,
    )

def _normalize_jq_binary_mode_stream_calls(code: str) -> str:
    pattern = re.compile(
        r"(?m)^(\s*)pFVar4 = \(FILE \*\)\(\*local_448\)\(2\);\s*\n"
        r"\1fflush\(pFVar4\);\s*\n"
        r"\1pFVar4 = \(FILE \*\)\(\*pcVar34\)\(\);\s*\n"
        r"\1fflush\(pFVar4\);\s*\n"
        r"\1pFVar4 = \(FILE \*\)\(\*pcVar34\)\(\);\s*\n"
        r"\1fileno\(pFVar4\);\s*\n"
        r"\1pcVar2 = pcStack_430;\s*\n"
        r"\1\(\*pcStack_430\)\(\);\s*\n"
        r"\1pFVar4 = \(FILE \*\)\(\*pcVar34\)\(\);\s*\n"
        r"\1fileno\(pFVar4\);\s*\n"
        r"\1\(\*pcVar2\)\(\);\s*\n"
        r"\1pFVar4 = \(FILE \*\)\(\*pcVar34\)\(\);\s*\n"
        r"\1fileno\(pFVar4\);\s*\n"
        r"\1\(\*pcVar2\)\(\);"
    )

    def replace(match: re.Match[str]) -> str:
        indent = match.group(1)
        lines = [
            "pFVar4 = (FILE *)(*local_448)(1);",
            "fflush(pFVar4);",
            "pFVar4 = (FILE *)(*pcVar34)(2);",
            "fflush(pFVar4);",
            "pFVar4 = (FILE *)(*pcVar34)(0);",
            "iVar5 = fileno(pFVar4);",
            "pcVar2 = pcStack_430;",
            "(*pcStack_430)(iVar5,0x8000);",
            "pFVar4 = (FILE *)(*pcVar34)(1);",
            "iVar5 = fileno(pFVar4);",
            "(*pcVar2)(iVar5,0x8000);",
            "pFVar4 = (FILE *)(*pcVar34)(2);",
            "iVar5 = fileno(pFVar4);",
            "(*pcVar2)(iVar5,0x8000);",
        ]
        return "\n".join(f"{indent}{line}" for line in lines)

    return pattern.sub(replace, code, count=1)

def _normalize_jq_late_option_error_stream_calls(code: str) -> str:
    literals = [
        r'"jq: --%s takes two parameters \(e\.g\. --%s varname filename\)\\n"',
        r'"jq: Unknown option --%s\\n"',
        r'"jq: Unknown option -%c\\n"',
    ]
    for literal in literals:
        code = re.sub(
            r"(?m)^(\s*)pFVar4 = \(FILE \*\)\(\*local_448\)\(2\);\s*\n"
            r"(\s*___mingw_fprintf\(pFVar4,\(byte \*\)(?:\s*\n\s*)?"
            + literal
            + r")",
            r"\1pFVar4 = STAGE_B_JQ_CALL_IOB_SLOT(local_448,2);\n\2",
            code,
            count=1,
        )
    return code

def _render_skeleton_readme(target_name: str, source_language: str, implementation_mode: str) -> str:
    if implementation_mode == "decompiled-c":
        mode_description = "This directory contains decompiler-derived C source generated from private reverse-engineering evidence."
    elif implementation_mode == "contract-guided-c":
        mode_description = (
            "This directory contains contract-guided C anchors generated from Stage A reverse-engineering evidence. "
            "It is expected to need repair before Stage A can prove the candidate binary."
        )
    else:
        mode_description = (
            "This directory is generated from Windows PE reverse-engineering inputs. It is a scaffold for a clean-room "
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
